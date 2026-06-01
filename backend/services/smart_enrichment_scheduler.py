# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Smart Enrichment Scheduler

Priority-based enrichment engine that:
- Prioritizes IOCs by severity and context
- Auto-triggers enrichment on smart events (feed reappearance, cache expiring)
- Rate-limit aware scheduling with backoff
- Continuous health monitoring
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class EnrichmentTriggerType(str, Enum):
    """Types of enrichment triggers"""
    MANUAL = "manual"                    # User requested
    AUTO_INITIAL = "auto_initial"        # First ingestion
    FEED_REAPPEAR = "feed_reappear"      # Reappeared in threat feed
    SCHEDULED = "scheduled"              # Scheduled re-enrichment
    INVESTIGATION = "investigation"       # Part of investigation
    CACHE_EXPIRY = "cache_expiry"        # Cache about to expire
    SEVERITY_ESCALATION = "severity_escalation"  # Severity was escalated


class QueueStatus(str, Enum):
    """Enrichment queue item status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PriorityFactors:
    """Breakdown of priority calculation factors"""
    severity_score: int = 0      # Based on IOC severity
    cache_score: int = 0         # Based on cache state
    feed_score: int = 0          # Based on feed reappearance
    investigation_score: int = 0  # Based on investigation context
    recency_score: int = 0       # Based on age

    @property
    def total(self) -> int:
        return (self.severity_score + self.cache_score + self.feed_score +
                self.investigation_score + self.recency_score)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity_score,
            "cache_state": self.cache_score,
            "feed_reappear": self.feed_score,
            "investigation": self.investigation_score,
            "recency": self.recency_score,
            "total": self.total
        }


class EnrichmentPriorityCalculator:
    """
    Calculates enrichment priority based on multiple factors.
    Lower priority number = higher priority (processed first).
    """

    # Severity to priority mapping (1 = highest priority)
    SEVERITY_PRIORITY = {
        "critical": 1,
        "high": 2,
        "medium": 4,
        "low": 6,
        "unknown": 5
    }

    # Cache state adjustments
    CACHE_EXPIRED_BOOST = -2      # Expired cache = higher priority
    CACHE_EXPIRING_SOON_BOOST = -1  # Expiring within 24h

    # Context adjustments
    FEED_REAPPEAR_BOOST = -1      # Recently reappeared in feed
    ACTIVE_INVESTIGATION_BOOST = -2  # Part of active investigation

    @classmethod
    def calculate(
        cls,
        ioc_severity: str,
        cache_expires_at: Optional[datetime] = None,
        feed_reappeared: bool = False,
        in_active_investigation: bool = False,
        last_enriched_at: Optional[datetime] = None
    ) -> tuple[int, PriorityFactors]:
        """
        Calculate enrichment priority for an IOC.

        Returns:
            tuple of (priority, factors) where:
            - priority: 1-10 (1 = highest)
            - factors: breakdown of scoring
        """
        factors = PriorityFactors()

        # Base priority from severity
        base_priority = cls.SEVERITY_PRIORITY.get(ioc_severity.lower(), 5)
        factors.severity_score = base_priority

        # Cache state adjustment
        if cache_expires_at:
            now = datetime.utcnow()
            if cache_expires_at.replace(tzinfo=None) <= now:
                factors.cache_score = cls.CACHE_EXPIRED_BOOST
            elif cache_expires_at.replace(tzinfo=None) <= now + timedelta(hours=24):
                factors.cache_score = cls.CACHE_EXPIRING_SOON_BOOST

        # Feed reappearance boost
        if feed_reappeared:
            factors.feed_score = cls.FEED_REAPPEAR_BOOST

        # Active investigation boost
        if in_active_investigation:
            factors.investigation_score = cls.ACTIVE_INVESTIGATION_BOOST

        # Recency adjustment (older = slightly lower priority)
        if last_enriched_at:
            days_since = (datetime.utcnow() - last_enriched_at.replace(tzinfo=None)).days
            if days_since > 30:
                factors.recency_score = 1  # Slightly lower priority if very old

        # Calculate final priority (clamp to 1-10)
        final_priority = base_priority + factors.cache_score + factors.feed_score + \
                        factors.investigation_score + factors.recency_score
        final_priority = max(1, min(10, final_priority))

        return final_priority, factors


class RateLimitManager:
    """
    Manages rate limits for enrichment providers.
    Tracks usage and implements backoff strategies.
    """

    # Default backoff times (in seconds)
    INITIAL_BACKOFF = 60
    MAX_BACKOFF = 3600  # 1 hour max

    def __init__(self):
        self.db = None

    def _get_db(self):
        if self.db is None:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    self.db = postgres_db
            except Exception as e:
                logger.error(f"Failed to get database connection: {e}")
        return self.db

    async def can_enrich(self, provider: str) -> bool:
        """Check if provider allows more requests right now"""
        db = self._get_db()
        if not db or not db.pool:
            return True  # Allow if no DB (fail open)

        try:
            async with db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT minute_requests, daily_requests, minute_limit, daily_limit,
                           minute_reset_at, day_reset_at, backoff_until
                    FROM integration_rate_limits
                    WHERE integration_id = $1
                    """,
                    provider
                )

                if not row:
                    return True  # No rate limit tracking = allow

                now = datetime.utcnow()

                # Check backoff
                if row['backoff_until'] and row['backoff_until'].replace(tzinfo=None) > now:
                    logger.debug(f"Provider {provider} in backoff until {row['backoff_until']}")
                    return False

                # Reset counters if needed
                minute_requests = row['minute_requests']
                daily_requests = row['daily_requests']

                if row['minute_reset_at'] and row['minute_reset_at'].replace(tzinfo=None) <= now:
                    minute_requests = 0

                if row['day_reset_at'] and row['day_reset_at'].replace(tzinfo=None) <= now:
                    daily_requests = 0

                # Check limits
                if minute_requests >= row['minute_limit']:
                    logger.debug(f"Provider {provider} at minute limit ({minute_requests}/{row['minute_limit']})")
                    return False

                if daily_requests >= row['daily_limit']:
                    logger.debug(f"Provider {provider} at daily limit ({daily_requests}/{row['daily_limit']})")
                    return False

                return True

        except Exception as e:
            logger.error(f"Rate limit check failed for {provider}: {e}")
            return True  # Fail open

    async def record_request(self, provider: str, success: bool, response_time_ms: int = 0):
        """Record an API request for rate limiting"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                now = datetime.utcnow()

                await conn.execute(
                    """
                    INSERT INTO integration_rate_limits (
                        integration_id, minute_requests, daily_requests,
                        minute_reset_at, day_reset_at, success_count, error_count,
                        avg_response_time_ms, updated_at
                    ) VALUES ($1, 1, 1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (integration_id) DO UPDATE SET
                        minute_requests = CASE
                            WHEN integration_rate_limits.minute_reset_at <= $7
                            THEN 1
                            ELSE integration_rate_limits.minute_requests + 1
                        END,
                        daily_requests = CASE
                            WHEN integration_rate_limits.day_reset_at <= $7
                            THEN 1
                            ELSE integration_rate_limits.daily_requests + 1
                        END,
                        minute_reset_at = CASE
                            WHEN integration_rate_limits.minute_reset_at <= $7
                            THEN $2
                            ELSE integration_rate_limits.minute_reset_at
                        END,
                        day_reset_at = CASE
                            WHEN integration_rate_limits.day_reset_at <= $7
                            THEN $3
                            ELSE integration_rate_limits.day_reset_at
                        END,
                        success_count = integration_rate_limits.success_count + $4,
                        error_count = integration_rate_limits.error_count + $5,
                        avg_response_time_ms = COALESCE(
                            (integration_rate_limits.avg_response_time_ms + $6) / 2,
                            $6
                        ),
                        updated_at = $7
                    """,
                    provider,
                    now + timedelta(minutes=1),  # minute_reset_at
                    now + timedelta(days=1),     # day_reset_at
                    1 if success else 0,
                    0 if success else 1,
                    response_time_ms,
                    now
                )

        except Exception as e:
            logger.error(f"Failed to record rate limit for {provider}: {e}")

    async def record_rate_limit_error(self, provider: str):
        """Record a 429 rate limit error and calculate backoff"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                now = datetime.utcnow()

                # Get current consecutive 429 count
                row = await conn.fetchrow(
                    "SELECT consecutive_429_count FROM integration_rate_limits WHERE integration_id = $1",
                    provider
                )

                consecutive = (row['consecutive_429_count'] if row else 0) + 1

                # Exponential backoff
                backoff_seconds = min(self.INITIAL_BACKOFF * (2 ** (consecutive - 1)), self.MAX_BACKOFF)
                backoff_until = now + timedelta(seconds=backoff_seconds)

                await conn.execute(
                    """
                    INSERT INTO integration_rate_limits (
                        integration_id, last_429_error, consecutive_429_count, backoff_until
                    ) VALUES ($1, $2, $3, $4)
                    ON CONFLICT (integration_id) DO UPDATE SET
                        last_429_error = $2,
                        consecutive_429_count = $3,
                        backoff_until = $4,
                        updated_at = $2
                    """,
                    provider, now, consecutive, backoff_until
                )

                logger.warning(f"Rate limit error for {provider}, backoff until {backoff_until} ({backoff_seconds}s)")

        except Exception as e:
            logger.error(f"Failed to record rate limit error for {provider}: {e}")

    async def clear_backoff(self, provider: str):
        """Clear backoff after successful request"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE integration_rate_limits
                    SET consecutive_429_count = 0, backoff_until = NULL
                    WHERE integration_id = $1
                    """,
                    provider
                )
        except Exception as e:
            logger.error(f"Failed to clear backoff for {provider}: {e}")

    async def get_next_available_time(self, provider: str) -> Optional[datetime]:
        """Get the next time when this provider will be available"""
        db = self._get_db()
        if not db or not db.pool:
            return datetime.utcnow()

        try:
            async with db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT backoff_until, minute_reset_at, day_reset_at,
                           minute_requests, daily_requests, minute_limit, daily_limit
                    FROM integration_rate_limits
                    WHERE integration_id = $1
                    """,
                    provider
                )

                if not row:
                    return datetime.utcnow()

                now = datetime.utcnow()

                # Check backoff first
                if row['backoff_until'] and row['backoff_until'].replace(tzinfo=None) > now:
                    return row['backoff_until'].replace(tzinfo=None)

                # Check minute limit
                if row['minute_requests'] >= row['minute_limit']:
                    return row['minute_reset_at'].replace(tzinfo=None)

                # Check daily limit
                if row['daily_requests'] >= row['daily_limit']:
                    return row['day_reset_at'].replace(tzinfo=None)

                return now

        except Exception as e:
            logger.error(f"Failed to get next available time for {provider}: {e}")
            return datetime.utcnow()


class SmartEnrichmentScheduler:
    """
    Main scheduler for smart enrichment operations.

    Runs background tasks to:
    - Process high-priority IOCs
    - Detect feed reappearances
    - Trigger cache expiry enrichments
    - Monitor enrichment health
    """

    def __init__(self):
        self.db = None
        self.rate_limit_manager = RateLimitManager()
        self.running = False
        self._tasks: List[asyncio.Task] = []

        # Configuration
        self.high_priority_interval = 30      # Process high priority every 30s
        self.feed_detection_interval = 300    # Check feed reappearances every 5min
        self.cache_expiry_interval = 3600     # Check cache expiry every hour
        self.health_monitoring_interval = 300  # Health check every 5min
        self.max_concurrent_enrichments = 5

    def _get_db(self):
        if self.db is None:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    self.db = postgres_db
            except Exception as e:
                logger.error(f"Failed to get database connection: {e}")
        return self.db

    async def start(self):
        """Start the smart enrichment scheduler"""
        if self.running:
            logger.warning("Smart enrichment scheduler already running")
            return

        self.running = True
        logger.info("[SMART] Starting Smart Enrichment Scheduler...")

        # Start background tasks
        self._tasks = [
            asyncio.create_task(self._high_priority_loop()),
            asyncio.create_task(self._feed_detection_loop()),
            asyncio.create_task(self._cache_expiry_loop()),
            asyncio.create_task(self._health_monitoring_loop()),
        ]

        logger.info("[OK] Smart Enrichment Scheduler started")

    async def stop(self):
        """Stop the scheduler"""
        self.running = False

        for task in self._tasks:
            task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks = []
        logger.info("Smart Enrichment Scheduler stopped")

    # ========================================================================
    # QUEUE MANAGEMENT
    # ========================================================================

    async def queue_enrichment(
        self,
        ioc_value: str,
        ioc_type: str,
        trigger_type: EnrichmentTriggerType = EnrichmentTriggerType.MANUAL,
        trigger_source: Optional[str] = None,
        priority_override: Optional[int] = None,
        target_providers: Optional[List[str]] = None,
        delay_seconds: int = 0
    ) -> Optional[str]:
        """
        Add an IOC to the enrichment queue with priority calculation.

        Returns queue entry ID if successful.
        """
        db = self._get_db()
        if not db or not db.pool:
            logger.error("Cannot queue enrichment: database not connected")
            return None

        try:
            # Calculate priority
            priority, factors = await self._calculate_priority_for_ioc(ioc_value, ioc_type)

            if priority_override is not None:
                priority = priority_override

            scheduled_for = datetime.utcnow() + timedelta(seconds=delay_seconds)

            async with db.tenant_acquire() as conn:
                # Check if already in queue (pending or processing)
                existing = await conn.fetchrow(
                    """
                    SELECT id, calculated_priority FROM enrichment_priority_queue
                    WHERE ioc_value = $1 AND ioc_type = $2
                    AND status IN ('pending', 'processing')
                    """,
                    ioc_value, ioc_type
                )

                if existing:
                    # Update priority if new priority is higher (lower number)
                    if priority < existing['calculated_priority']:
                        await conn.execute(
                            """
                            UPDATE enrichment_priority_queue
                            SET calculated_priority = $1, priority_factors = $2, updated_at = NOW()
                            WHERE id = $3
                            """,
                            priority, json.dumps(factors.to_dict()), existing['id']
                        )
                    queue_id = str(existing['id'])
                else:
                    # Insert new entry
                    row = await conn.fetchrow(
                        """
                        INSERT INTO enrichment_priority_queue (
                            ioc_value, ioc_type, calculated_priority, priority_factors,
                            trigger_type, trigger_source, target_providers, scheduled_for, status
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
                        RETURNING id
                        """,
                        ioc_value,
                        ioc_type,
                        priority,
                        json.dumps(factors.to_dict()),
                        trigger_type.value,
                        trigger_source,
                        target_providers,
                        scheduled_for
                    )
                    queue_id = str(row['id']) if row else None

                logger.debug(f"Queued enrichment for {ioc_value} ({ioc_type}) with priority {priority}")
                return queue_id

        except Exception as e:
            logger.error(f"Failed to queue enrichment for {ioc_value}: {e}")
            return None

    async def _calculate_priority_for_ioc(
        self,
        ioc_value: str,
        ioc_type: str
    ) -> tuple[int, PriorityFactors]:
        """Calculate priority for an IOC by looking up context"""
        db = self._get_db()

        severity = "medium"
        cache_expires_at = None
        feed_reappeared = False
        in_investigation = False
        last_enriched_at = None

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Get IOC info
                    ioc_row = await conn.fetchrow(
                        """
                        SELECT severity, last_enriched_at, feed_last_seen_at, feed_occurrences
                        FROM iocs WHERE ioc_value = $1 AND ioc_type = $2
                        """,
                        ioc_value, ioc_type
                    )

                    if ioc_row:
                        severity = ioc_row['severity'] or "medium"
                        last_enriched_at = ioc_row['last_enriched_at']

                        # Check feed reappearance
                        if ioc_row['feed_last_seen_at'] and ioc_row['feed_occurrences']:
                            days_since = (datetime.utcnow() - ioc_row['feed_last_seen_at'].replace(tzinfo=None)).days
                            if days_since < 7 and ioc_row['feed_occurrences'] > 1:
                                feed_reappeared = True

                    # Get cache expiry
                    cache_row = await conn.fetchrow(
                        """
                        SELECT MIN(expires_at) as earliest_expiry
                        FROM enrichment_cache
                        WHERE ioc_value = $1 AND ioc_type = $2 AND expires_at > NOW()
                        """,
                        ioc_value, ioc_type
                    )

                    if cache_row and cache_row['earliest_expiry']:
                        cache_expires_at = cache_row['earliest_expiry']

                    # Check if in active investigation
                    inv_row = await conn.fetchrow(
                        """
                        SELECT 1 FROM investigations i
                        JOIN alerts a ON i.alert_id = a.id
                        WHERE a.raw_event::text ILIKE $1
                        AND i.state IN ('NEW', 'ENRICHING', 'AI_TRIAGE_L1', 'AI_TRIAGE_L2', 'AWAITING_HUMAN', 'IN_PROGRESS')
                        LIMIT 1
                        """,
                        f"%{ioc_value}%"
                    )
                    in_investigation = inv_row is not None

            except Exception as e:
                logger.error(f"Error calculating priority context: {e}")

        return EnrichmentPriorityCalculator.calculate(
            ioc_severity=severity,
            cache_expires_at=cache_expires_at,
            feed_reappeared=feed_reappeared,
            in_active_investigation=in_investigation,
            last_enriched_at=last_enriched_at
        )

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get current enrichment queue statistics"""
        db = self._get_db()
        if not db or not db.pool:
            return {"error": "Database not connected"}

        try:
            async with db.tenant_acquire() as conn:
                stats = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE status = 'pending') as pending,
                        COUNT(*) FILTER (WHERE status = 'processing') as processing,
                        COUNT(*) FILTER (WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '1 hour') as completed_1h,
                        COUNT(*) FILTER (WHERE status = 'failed' AND updated_at > NOW() - INTERVAL '1 hour') as failed_1h,
                        AVG(calculated_priority) FILTER (WHERE status = 'pending') as avg_pending_priority,
                        MIN(calculated_priority) FILTER (WHERE status = 'pending') as highest_priority
                    FROM enrichment_priority_queue
                    """
                )

                # Priority distribution
                priority_dist = await conn.fetch(
                    """
                    SELECT calculated_priority, COUNT(*) as count
                    FROM enrichment_priority_queue
                    WHERE status = 'pending'
                    GROUP BY calculated_priority
                    ORDER BY calculated_priority
                    """
                )

                # Trigger distribution
                trigger_dist = await conn.fetch(
                    """
                    SELECT trigger_type, COUNT(*) as count
                    FROM enrichment_priority_queue
                    WHERE status = 'pending'
                    GROUP BY trigger_type
                    """
                )

                return {
                    "pending": stats['pending'] or 0,
                    "processing": stats['processing'] or 0,
                    "completed_last_hour": stats['completed_1h'] or 0,
                    "failed_last_hour": stats['failed_1h'] or 0,
                    "avg_pending_priority": round(float(stats['avg_pending_priority'] or 5), 1),
                    "highest_priority": stats['highest_priority'] or 10,
                    "by_priority": {r['calculated_priority']: r['count'] for r in priority_dist},
                    "by_trigger": {r['trigger_type']: r['count'] for r in trigger_dist}
                }

        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {"error": str(e)}

    # ========================================================================
    # BACKGROUND LOOPS
    # ========================================================================

    async def _high_priority_loop(self):
        """Process high-priority enrichments"""
        from services.postgres_db import set_platform_admin_mode

        while self.running:
            try:
                set_platform_admin_mode(True)
                try:
                    await self._process_pending_enrichments()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"High priority loop error: {e}")

            await asyncio.sleep(self.high_priority_interval)

    async def _feed_detection_loop(self):
        """Detect IOCs that have reappeared in threat feeds"""
        from services.postgres_db import set_platform_admin_mode

        while self.running:
            try:
                set_platform_admin_mode(True)
                try:
                    await self._detect_feed_reappearances()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"Feed detection loop error: {e}")

            await asyncio.sleep(self.feed_detection_interval)

    async def _cache_expiry_loop(self):
        """Queue enrichments for IOCs with expiring cache"""
        from services.postgres_db import set_platform_admin_mode

        while self.running:
            try:
                set_platform_admin_mode(True)
                try:
                    await self._queue_cache_expiry_enrichments()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"Cache expiry loop error: {e}")

            await asyncio.sleep(self.cache_expiry_interval)

    async def _health_monitoring_loop(self):
        """Collect and store enrichment health metrics"""
        from services.postgres_db import set_platform_admin_mode

        while self.running:
            try:
                set_platform_admin_mode(True)
                try:
                    await self._collect_health_metrics()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"Health monitoring loop error: {e}")

            await asyncio.sleep(self.health_monitoring_interval)

    # ========================================================================
    # PROCESSING LOGIC
    # ========================================================================

    async def _process_pending_enrichments(self):
        """Process pending enrichment queue items"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                # Get highest priority pending items
                items = await conn.fetch(
                    """
                    SELECT id, ioc_value, ioc_type, trigger_type, target_providers
                    FROM enrichment_priority_queue
                    WHERE status = 'pending'
                    AND scheduled_for <= NOW()
                    ORDER BY calculated_priority ASC, created_at ASC
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                    """,
                    self.max_concurrent_enrichments
                )

                if not items:
                    return

                for item in items:
                    await self._process_single_enrichment(conn, item)

        except Exception as e:
            logger.error(f"Failed to process pending enrichments: {e}")

    async def _process_single_enrichment(self, conn, item: dict):
        """Process a single enrichment queue item"""
        try:
            # Mark as processing
            await conn.execute(
                """
                UPDATE enrichment_priority_queue
                SET status = 'processing', last_attempt_at = NOW(), attempts = attempts + 1
                WHERE id = $1
                """,
                item['id']
            )

            # Get threat intel service
            from services.threat_intel_service import get_threat_intel_service, IOCType, EnrichmentTrigger

            service = get_threat_intel_service()

            # Convert trigger type
            trigger_map = {
                'manual': EnrichmentTrigger.MANUAL,
                'auto_initial': EnrichmentTrigger.AUTO_INITIAL,
                'feed_reappear': EnrichmentTrigger.FEED_REAPPEAR,
                'scheduled': EnrichmentTrigger.SCHEDULED,
                'investigation': EnrichmentTrigger.INVESTIGATION,
                'cache_expiry': EnrichmentTrigger.SCHEDULED,
                'severity_escalation': EnrichmentTrigger.MANUAL
            }
            trigger = trigger_map.get(item['trigger_type'], EnrichmentTrigger.SCHEDULED)

            # Perform enrichment
            report = await service.enrich_ioc(
                value=item['ioc_value'],
                ioc_type=IOCType(item['ioc_type']),
                providers=item['target_providers'],
                force_refresh=(item['trigger_type'] == 'cache_expiry'),
                trigger=trigger
            )

            # Mark as completed
            await conn.execute(
                """
                UPDATE enrichment_priority_queue
                SET status = 'completed', completed_at = NOW(), updated_at = NOW()
                WHERE id = $1
                """,
                item['id']
            )

            logger.debug(f"Successfully enriched {item['ioc_value']} ({item['ioc_type']})")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Enrichment failed for {item['ioc_value']}: {error_msg}")

            # Check if max attempts reached
            await conn.execute(
                """
                UPDATE enrichment_priority_queue
                SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
                    last_error = $2,
                    scheduled_for = NOW() + INTERVAL '5 minutes',
                    updated_at = NOW()
                WHERE id = $1
                """,
                item['id'],
                error_msg[:500]
            )

    async def _detect_feed_reappearances(self):
        """Detect IOCs that have reappeared in threat feeds and queue them"""
        # IMPORTANT: IOCs from threat feeds (URLhaus, MalwareBazaar, etc.) should NOT
        # be re-enriched via external APIs like VirusTotal. Threat feed data is
        # authoritative - they already have reputation data from the feed itself.
        # This prevents burning API quota on 10,000+ feed IOCs.
        logger.debug("Feed reappearance detection skipped - threat feed IOCs are not enriched via APIs")
        return

    async def _queue_cache_expiry_enrichments(self):
        """Queue enrichments for IOCs with cache expiring soon"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                # Find IOCs with cache expiring in the next 24 hours
                # SKIP threat feed IOCs - they should not be enriched via external APIs
                expiring = await conn.fetch(
                    """
                    SELECT DISTINCT c.ioc_value, c.ioc_type, i.severity
                    FROM enrichment_cache c
                    JOIN iocs i ON c.ioc_value = i.ioc_value AND c.ioc_type = i.ioc_type
                    WHERE c.expires_at BETWEEN NOW() AND NOW() + INTERVAL '24 hours'
                    AND i.severity IN ('medium', 'high', 'critical')
                    AND i.source_type != 'threat_feed'
                    AND i.feed_name IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM enrichment_priority_queue q
                        WHERE q.ioc_value = c.ioc_value
                        AND q.ioc_type = c.ioc_type
                        AND q.status IN ('pending', 'processing')
                    )
                    LIMIT 100
                    """
                )

                for ioc in expiring:
                    await self.queue_enrichment(
                        ioc_value=ioc['ioc_value'],
                        ioc_type=ioc['ioc_type'],
                        trigger_type=EnrichmentTriggerType.CACHE_EXPIRY
                    )

                if expiring:
                    logger.info(f"Queued {len(expiring)} IOCs for re-enrichment (cache expiring)")

        except Exception as e:
            logger.error(f"Cache expiry queue failed: {e}")

    async def _collect_health_metrics(self):
        """Collect and store enrichment health metrics"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                now = datetime.utcnow()
                hour_start = now.replace(minute=0, second=0, microsecond=0)

                # Get provider-level metrics
                provider_metrics = await conn.fetch(
                    """
                    SELECT
                        r.integration_id as provider,
                        r.avg_response_time_ms,
                        CASE WHEN r.success_count + r.error_count > 0
                             THEN (r.success_count::float / (r.success_count + r.error_count) * 100)
                             ELSE 100 END as success_rate,
                        r.error_count,
                        r.daily_requests,
                        r.daily_limit,
                        CASE WHEN r.daily_limit > 0
                             THEN ((r.daily_limit - r.daily_requests)::float / r.daily_limit * 100)
                             ELSE 100 END as quota_remaining_percent
                    FROM integration_rate_limits r
                    """
                )

                # Get cache metrics per provider
                cache_metrics = await conn.fetch(
                    """
                    SELECT provider,
                           SUM(hit_count) as hits,
                           COUNT(*) as entries
                    FROM enrichment_cache
                    WHERE expires_at > NOW()
                    GROUP BY provider
                    """
                )
                cache_by_provider = {r['provider']: r for r in cache_metrics}

                # Get queue stats
                queue_stats = await conn.fetchrow(
                    """
                    SELECT COUNT(*) FILTER (WHERE status = 'pending') as pending_size,
                           AVG(EXTRACT(EPOCH FROM (NOW() - created_at)))
                               FILTER (WHERE status = 'pending') as avg_wait_seconds
                    FROM enrichment_priority_queue
                    """
                )

                # Insert metrics for each provider
                for pm in provider_metrics:
                    cache_data = cache_by_provider.get(pm['provider'], {})

                    await conn.execute(
                        """
                        INSERT INTO enrichment_health_metrics (
                            provider, measurement_time,
                            avg_response_time_ms, success_rate, error_count,
                            requests_today, quota_remaining_percent,
                            cache_hit_count, pending_queue_size, avg_queue_wait_seconds
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        ON CONFLICT (provider, measurement_time) DO UPDATE SET
                            avg_response_time_ms = $3,
                            success_rate = $4,
                            error_count = $5,
                            requests_today = $6,
                            quota_remaining_percent = $7,
                            cache_hit_count = $8,
                            pending_queue_size = $9,
                            avg_queue_wait_seconds = $10
                        """,
                        pm['provider'],
                        hour_start,
                        pm['avg_response_time_ms'],
                        pm['success_rate'],
                        pm['error_count'],
                        pm['daily_requests'],
                        pm['quota_remaining_percent'],
                        cache_data.get('hits', 0),
                        queue_stats['pending_size'] or 0,
                        queue_stats['avg_wait_seconds']
                    )

                logger.debug("Collected enrichment health metrics")

        except Exception as e:
            logger.error(f"Health metrics collection failed: {e}")

    async def get_health_summary(self) -> Dict[str, Any]:
        """Get overall enrichment health summary"""
        db = self._get_db()
        if not db or not db.pool:
            return {"error": "Database not connected"}

        try:
            async with db.tenant_acquire() as conn:
                # Latest metrics per provider
                latest = await conn.fetch(
                    """
                    SELECT DISTINCT ON (provider)
                        provider, measurement_time,
                        avg_response_time_ms, success_rate,
                        requests_today, quota_remaining_percent,
                        pending_queue_size
                    FROM enrichment_health_metrics
                    ORDER BY provider, measurement_time DESC
                    """
                )

                # Rate limit status
                rate_limits = await conn.fetch(
                    """
                    SELECT integration_id,
                           minute_requests, minute_limit,
                           daily_requests, daily_limit,
                           backoff_until
                    FROM integration_rate_limits
                    """
                )

                # Calculate overall health score
                total_success_rate = sum(r['success_rate'] or 100 for r in latest) / max(len(latest), 1)
                providers_in_backoff = sum(1 for r in rate_limits if r['backoff_until'] and r['backoff_until'].replace(tzinfo=None) > datetime.utcnow())

                health_score = 100
                issues = []

                if total_success_rate < 95:
                    health_score -= 20
                    issues.append(f"Low success rate: {total_success_rate:.1f}%")

                if providers_in_backoff > 0:
                    health_score -= 10 * providers_in_backoff
                    issues.append(f"{providers_in_backoff} provider(s) in rate limit backoff")

                queue_stats = await self.get_queue_stats()
                if queue_stats.get('pending', 0) > 100:
                    health_score -= 10
                    issues.append(f"Large queue backlog: {queue_stats['pending']} pending")

                return {
                    "health_score": max(0, health_score),
                    "issues": issues,
                    "providers": {r['provider']: {
                        "success_rate": float(r['success_rate'] or 100),
                        "avg_response_ms": r['avg_response_time_ms'],
                        "quota_remaining_pct": float(r['quota_remaining_percent'] or 100),
                        "requests_today": r['requests_today'] or 0
                    } for r in latest},
                    "rate_limits": {r['integration_id']: {
                        "minute": f"{r['minute_requests']}/{r['minute_limit']}",
                        "daily": f"{r['daily_requests']}/{r['daily_limit']}",
                        "in_backoff": r['backoff_until'] is not None and r['backoff_until'].replace(tzinfo=None) > datetime.utcnow()
                    } for r in rate_limits},
                    "queue": queue_stats
                }

        except Exception as e:
            logger.error(f"Failed to get health summary: {e}")
            return {"health_score": 0, "error": str(e)}


# ============================================================================
# SINGLETON
# ============================================================================

_smart_enrichment_scheduler: Optional[SmartEnrichmentScheduler] = None


def get_smart_enrichment_scheduler() -> SmartEnrichmentScheduler:
    """Get the global smart enrichment scheduler instance"""
    global _smart_enrichment_scheduler
    if _smart_enrichment_scheduler is None:
        _smart_enrichment_scheduler = SmartEnrichmentScheduler()
    return _smart_enrichment_scheduler
