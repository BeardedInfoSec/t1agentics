# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Threat Intelligence Service

Centralized threat intel management:
- IOC storage and retrieval
- Enrichment from multiple sources
- Correlation across alerts/investigations
- Reputation tracking over time
- Caching to reduce API calls
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from pydantic import BaseModel, Field
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS
# ============================================================================

class IOCType(str, Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    USERNAME = "username"
    HOSTNAME = "hostname"
    FILE_PATH = "file_path"
    CVE = "cve"
    MITRE_ATTACK = "mitre_attack"


class IOCSourceType(str, Enum):
    """How the IOC was discovered/ingested"""
    MANUAL = "manual"              # User manually submitted via UI
    AI_AGENT = "ai_agent"          # AI agent discovered/submitted during investigation
    EVENT = "event"                # Extracted from an alert/event
    INVESTIGATION = "investigation"  # Extracted during investigation analysis
    THREAT_FEED = "threat_feed"    # Ingested from external threat intel feed


class EnrichmentTrigger(str, Enum):
    """What triggered the enrichment of an IOC"""
    MANUAL = "manual"              # User requested enrichment
    AUTO_INITIAL = "auto_initial"  # Auto-enriched on first ingestion
    FEED_REAPPEAR = "feed_reappear"  # Re-enriched because IOC reappeared in threat feed
    SCHEDULED = "scheduled"        # Scheduled re-enrichment
    INVESTIGATION = "investigation"  # Enriched as part of investigation


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReputationVerdict(str, Enum):
    """IOC reputation verdicts"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class IOC(BaseModel):
    """Indicator of Compromise"""
    value: str
    type: IOCType
    severity: Optional[ThreatSeverity] = ThreatSeverity.UNKNOWN
    verdict: Optional[ReputationVerdict] = ReputationVerdict.UNKNOWN
    confidence: Optional[float] = Field(default=None, ge=0, le=100)

    # Tracking
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrences: int = 1

    # Legacy source field
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    # NEW: Enhanced source tracking
    source_type: Optional[IOCSourceType] = None  # How the IOC was discovered
    source_id: Optional[str] = None              # Reference ID (alert_id, investigation_id, user_id, feed_id)
    feed_name: Optional[str] = None              # Name of threat feed if source_type='threat_feed'
    ingested_at: Optional[datetime] = None       # When IOC was first ingested from feed

    # NEW: Enrichment tracking for smart re-enrichment
    last_enriched_at: Optional[datetime] = None
    enrichment_trigger: Optional[EnrichmentTrigger] = None
    feed_last_seen_at: Optional[datetime] = None  # Last time this IOC appeared in any threat feed
    feed_occurrences: int = 0                     # How many times seen across threat feeds

    # Related entities
    alert_ids: List[str] = Field(default_factory=list)
    investigation_ids: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class EnrichmentResult(BaseModel):
    """Result from an enrichment source"""
    ioc_value: str
    ioc_type: IOCType
    provider: str

    # Results
    verdict: ReputationVerdict = ReputationVerdict.UNKNOWN
    threat_score: Optional[int] = Field(default=None, ge=0, le=100)
    confidence: Optional[float] = Field(default=None, ge=0, le=1)

    # Details
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)

    # Metadata
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    cached: bool = False
    cache_age_seconds: Optional[int] = None

    class Config:
        use_enum_values = True


class ProviderStatus(BaseModel):
    """Status of an enrichment provider call"""
    provider_id: str
    provider_name: str
    status: str  # 'success', 'cached', 'failed', 'error', 'skipped', 'rate_limited', 'no_data'
    message: Optional[str] = None
    response_time_ms: Optional[int] = None
    cached: bool = False
    has_data: bool = False


class ThreatIntelReport(BaseModel):
    """Consolidated threat intel report for an IOC"""
    ioc: IOC
    enrichments: List[EnrichmentResult] = Field(default_factory=list)

    # Aggregated scores
    consensus_verdict: ReputationVerdict = ReputationVerdict.UNKNOWN
    consensus_score: Optional[int] = None
    sources_checked: int = 0
    sources_flagged: int = 0

    # Provider status tracking - shows which integrations were called and their results
    provider_status: List[ProviderStatus] = Field(default_factory=list)

    # Related context
    related_iocs: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# SERVICE
# ============================================================================

class ThreatIntelService:
    """
    Threat Intelligence Service

    Manages IOC storage, enrichment, and correlation.
    """

    # Cache TTL in days by IOC type (base TTL)
    # Set to 30 days to reduce API calls - IOCs rarely change reputation quickly
    CACHE_TTL_DAYS = {
        IOCType.IP: 30,
        IOCType.DOMAIN: 30,
        IOCType.URL: 30,
        IOCType.HASH_MD5: 30,
        IOCType.HASH_SHA1: 30,
        IOCType.HASH_SHA256: 30,
        IOCType.EMAIL: 14,
        IOCType.CVE: 90,
    }

    # Provider-specific TTL overrides (multiplier applied to base TTL)
    # Values > 1.0 extend TTL, values < 1.0 shorten TTL
    PROVIDER_TTL_MULTIPLIERS = {
        'virustotal': 1.5,      # Most reliable, cache longer
        'malwarebazaar': 1.5,   # Highly reliable for hashes
        'greynoise': 2.0,       # Stable classifications, cache longer
        'abuseipdb': 0.75,      # Community-driven, refresh more often
        'otx': 0.75,            # Community intel, refresh more often
        'shodan': 1.0,          # Standard TTL
        'ipinfo': 1.0,          # Geolocation data is stable
        'urlhaus': 1.0,         # Standard TTL
    }

    # Confidence-based TTL adjustments
    # High confidence results are cached longer, low confidence refreshed sooner
    CONFIDENCE_TTL_MULTIPLIERS = {
        'high': 1.5,      # confidence >= 0.8
        'medium': 1.0,    # confidence 0.5-0.8
        'low': 0.5,       # confidence < 0.5
    }

    # Verdict-based TTL adjustments
    # Malicious verdicts are cached longer (more stable classification)
    VERDICT_TTL_MULTIPLIERS = {
        'malicious': 1.5,   # Keep malicious verdicts longer
        'suspicious': 1.0,  # Standard TTL
        'clean': 0.75,      # Refresh clean verdicts more often (might become malicious)
        'unknown': 0.5,     # Refresh unknowns frequently
    }

    def __init__(self):
        self.db = None
        self._enrichment_providers: Dict[str, Any] = {}

    def calculate_smart_ttl(
        self,
        ioc_type: IOCType,
        provider: str,
        verdict: ReputationVerdict,
        confidence: Optional[float] = None
    ) -> int:
        """
        Calculate smart TTL based on IOC type, provider, verdict, and confidence.

        Returns TTL in days, applying multipliers for:
        - Base TTL by IOC type
        - Provider reliability
        - Confidence level
        - Verdict type
        """
        # Get base TTL for this IOC type
        base_ttl = self.CACHE_TTL_DAYS.get(
            IOCType(ioc_type) if isinstance(ioc_type, str) else ioc_type,
            7  # Default 7 days
        )

        # Apply provider multiplier
        provider_mult = self.PROVIDER_TTL_MULTIPLIERS.get(provider.lower(), 1.0)

        # Apply confidence multiplier
        confidence_mult = 1.0
        if confidence is not None:
            if confidence >= 0.8:
                confidence_mult = self.CONFIDENCE_TTL_MULTIPLIERS['high']
            elif confidence >= 0.5:
                confidence_mult = self.CONFIDENCE_TTL_MULTIPLIERS['medium']
            else:
                confidence_mult = self.CONFIDENCE_TTL_MULTIPLIERS['low']

        # Apply verdict multiplier
        verdict_str = verdict.value if isinstance(verdict, ReputationVerdict) else verdict
        verdict_mult = self.VERDICT_TTL_MULTIPLIERS.get(verdict_str, 1.0)

        # Calculate final TTL
        final_ttl = base_ttl * provider_mult * confidence_mult * verdict_mult

        # Ensure minimum 1 day, maximum 180 days
        final_ttl = max(1, min(180, int(final_ttl)))

        logger.debug(
            f"Smart TTL calculated: base={base_ttl}, provider_mult={provider_mult}, "
            f"conf_mult={confidence_mult}, verdict_mult={verdict_mult}, final={final_ttl}"
        )

        return final_ttl

    def _get_db(self):
        """Get database connection"""
        if self.db is None:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    self.db = postgres_db
            except Exception as e:
                logger.error(f"Failed to connect to database: {e}")
        return self.db

    # ========================================================================
    # IOC MANAGEMENT
    # ========================================================================

    async def add_ioc(
        self,
        value: str,
        ioc_type: IOCType,
        source: Optional[str] = None,
        severity: Optional[ThreatSeverity] = None,
        tags: Optional[List[str]] = None,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        # NEW: Enhanced source tracking parameters
        source_type: Optional[IOCSourceType] = None,
        source_id: Optional[str] = None,
        feed_name: Optional[str] = None,
        is_from_feed: bool = False,  # Indicates this is a feed ingestion (for smart re-enrichment)
        reputation: Optional[str] = None,  # Reputation/verdict: 'clean', 'suspicious', 'malicious', 'unknown'
        # ADDED 2026-01-21: Auto-enrichment option
        auto_enrich: bool = False,  # If True, queue IOC for enrichment after adding
        enrich_priority: str = 'normal'  # 'high', 'normal', 'low' - controls enrichment queue priority
    ) -> IOC:
        """
        Add or update an IOC in the database.

        If IOC exists, updates last_seen and increments occurrences.
        For feed ingestions (is_from_feed=True), also tracks feed appearances
        for smart re-enrichment logic.

        UPDATED 2026-01-21: Added auto_enrich option to ensure IOCs get enriched
        when added. This prevents IOCs from being stored without enrichment data.
        """
        db = self._get_db()
        now = datetime.utcnow()
        tags = tags or []

        # Infer source_type if not provided
        if source_type is None:
            if is_from_feed or feed_name:
                source_type = IOCSourceType.THREAT_FEED
            elif alert_id:
                source_type = IOCSourceType.EVENT
                source_id = source_id or alert_id
            elif investigation_id:
                source_type = IOCSourceType.INVESTIGATION
                source_id = source_id or investigation_id

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Check if IOC exists
                    existing = await conn.fetchrow(
                        """
                        SELECT * FROM iocs
                        WHERE ioc_value = $1 AND ioc_type = $2
                        """,
                        value, ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                    )

                    if existing:
                        # Update existing IOC
                        # For feed ingestions, update feed tracking fields
                        # Use ARRAY(SELECT DISTINCT ...) to deduplicate tags
                        if is_from_feed:
                            await conn.execute(
                                """
                                UPDATE iocs SET
                                    last_seen = $1,
                                    occurrences = occurrences + 1,
                                    tags = ARRAY(SELECT DISTINCT unnest(array_cat(tags, $2::text[]))),
                                    severity = COALESCE($3, severity),
                                    source = COALESCE($4, source),
                                    feed_last_seen_at = $1,
                                    feed_occurrences = COALESCE(feed_occurrences, 0) + 1,
                                    reputation = COALESCE($7, reputation)
                                WHERE ioc_value = $5 AND ioc_type = $6
                                """,
                                now,
                                tags,
                                severity.value if severity else None,
                                source,
                                value,
                                ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                                reputation
                            )
                        else:
                            await conn.execute(
                                """
                                UPDATE iocs SET
                                    last_seen = $1,
                                    occurrences = occurrences + 1,
                                    tags = ARRAY(SELECT DISTINCT unnest(array_cat(tags, $2::text[]))),
                                    severity = COALESCE($3, severity),
                                    source = COALESCE($4, source),
                                    reputation = COALESCE($7, reputation)
                                WHERE ioc_value = $5 AND ioc_type = $6
                                """,
                                now,
                                tags,
                                severity.value if severity else None,
                                source,
                                value,
                                ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                                reputation
                            )

                        # Return updated IOC
                        row = await conn.fetchrow(
                            "SELECT * FROM iocs WHERE ioc_value = $1 AND ioc_type = $2",
                            value, ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                        )
                    else:
                        # Insert new IOC with source tracking fields
                        from middleware.tenant_middleware import get_current_tenant_id
                        try:
                            current_tid = get_current_tenant_id()
                        except Exception:
                            from config.constants import PLATFORM_OWNER_TENANT_ID
                            current_tid = PLATFORM_OWNER_TENANT_ID
                        default_tenant = uuid.UUID(current_tid)
                        row = await conn.fetchrow(
                            """
                            INSERT INTO iocs (
                                ioc_value, ioc_type, severity, source, tags,
                                first_seen, last_seen, occurrences,
                                source_type, source_id, feed_name, ingested_at,
                                feed_last_seen_at, feed_occurrences, reputation,
                                tenant_id
                            ) VALUES ($1, $2, $3, $4, $5, $6, $6, 1,
                                      $7, $8, $9, $10, $11, $12, $13, $14)
                            RETURNING *
                            """,
                            value,
                            ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                            severity.value if severity else 'unknown',
                            source,
                            tags,
                            now,
                            source_type.value if source_type else None,
                            source_id,
                            feed_name,
                            now if is_from_feed else None,  # ingested_at
                            now if is_from_feed else None,  # feed_last_seen_at
                            1 if is_from_feed else 0,       # feed_occurrences
                            reputation or 'unknown',        # reputation (default to 'unknown')
                            default_tenant                  # tenant_id
                        )

                    # Track feed appearance if this is from a feed
                    if is_from_feed and feed_name:
                        await self._track_feed_appearance(conn, value, ioc_type, feed_name)

                    ioc = self._row_to_ioc(row)

                    # ADDED 2026-01-21: Auto-enrich if requested
                    # This ensures IOCs don't slip through without enrichment data
                    if auto_enrich:
                        await self._queue_ioc_for_enrichment(
                            value=value,
                            ioc_type=ioc_type,
                            priority=enrich_priority,
                            source=source
                        )

                    return ioc

            except Exception as e:
                logger.error(f"Failed to add IOC: {e}")
                raise

        # Fallback to memory (for testing)
        return IOC(
            value=value,
            type=ioc_type,
            severity=severity or ThreatSeverity.UNKNOWN,
            source=source,
            tags=tags,
            first_seen=now,
            last_seen=now,
            occurrences=1,
            source_type=source_type,
            source_id=source_id,
            feed_name=feed_name,
            ingested_at=now if is_from_feed else None,
            feed_last_seen_at=now if is_from_feed else None,
            feed_occurrences=1 if is_from_feed else 0
        )

    async def _track_feed_appearance(
        self,
        conn,
        ioc_value: str,
        ioc_type: IOCType,
        feed_id: str
    ) -> None:
        """Track IOC appearance in a specific feed for smart re-enrichment"""
        try:
            from middleware.tenant_middleware import get_current_tenant_id
            import uuid as _uuid
            try:
                tid = _uuid.UUID(get_current_tenant_id())
            except Exception:
                from config.constants import PLATFORM_OWNER_TENANT_ID
                tid = _uuid.UUID(PLATFORM_OWNER_TENANT_ID)

            await conn.execute(
                """
                INSERT INTO ioc_feed_appearances (ioc_value, ioc_type, feed_id, tenant_id)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (ioc_value, ioc_type, feed_id, tenant_id) DO UPDATE SET
                    last_seen_in_feed = CURRENT_TIMESTAMP,
                    times_seen = ioc_feed_appearances.times_seen + 1
                """,
                ioc_value,
                ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                feed_id,
                tid
            )
        except Exception as e:
            logger.warning(f"Failed to track feed appearance: {e}")

    async def _queue_ioc_for_enrichment(
        self,
        value: str,
        ioc_type: IOCType,
        priority: str = 'normal',
        source: Optional[str] = None
    ) -> None:
        """
        Queue an IOC for enrichment.

        ADDED 2026-01-21: This method ensures IOCs get enriched by adding them
        to the enrichment queue. This prevents IOCs from being stored without
        enrichment data.

        Args:
            value: IOC value
            ioc_type: Type of IOC
            priority: 'high', 'normal', or 'low'
            source: Source of the IOC (for logging)
        """
        try:
            db = self._get_db()
            if not db or not db.pool:
                logger.warning("Database not available for IOC enrichment queue")
                return

            # Map priority to numeric value
            priority_map = {'high': 1, 'normal': 5, 'low': 10}
            priority_val = priority_map.get(priority, 5)

            async with db.tenant_acquire() as conn:
                # Add to enrichment queue table
                await conn.execute(
                    """
                    INSERT INTO enrichment_queue (
                        ioc_value, ioc_type, priority, status, created_at, source
                    ) VALUES ($1, $2, $3, 'pending', NOW(), $4)
                    ON CONFLICT (ioc_value, ioc_type) DO UPDATE SET
                        priority = LEAST(enrichment_queue.priority, $3),
                        status = CASE
                            WHEN enrichment_queue.status = 'completed' THEN 'pending'
                            ELSE enrichment_queue.status
                        END,
                        updated_at = NOW()
                    """,
                    value,
                    ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                    priority_val,
                    source
                )

            logger.debug(f"[ENRICH_QUEUE] Queued {ioc_type} '{value[:50]}' for enrichment (priority={priority})")

        except Exception as e:
            # Don't fail the add_ioc operation if queue fails
            logger.warning(f"Failed to queue IOC for enrichment: {e}")

    @staticmethod
    def _normalize_ioc_type(ioc_type: str, ioc_value: str) -> str:
        """Normalise legacy ioc_type values (e.g. bare 'hash') to valid IOCType."""
        if ioc_type == "hash":
            vlen = len(ioc_value)
            if vlen == 32:
                return "hash_md5"
            elif vlen == 40:
                return "hash_sha1"
            elif vlen == 64:
                return "hash_sha256"
            return "hash_sha256"  # fallback for unknown hash length
        return ioc_type

    def _row_to_ioc(self, row) -> IOC:
        """Convert a database row to an IOC object"""
        return IOC(
            value=row['ioc_value'],
            type=self._normalize_ioc_type(row['ioc_type'], row['ioc_value']),
            severity=row['severity'] or 'unknown',
            verdict=row.get('reputation') or 'unknown',
            confidence=float(row['confidence']) if row.get('confidence') else None,
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            occurrences=row['occurrences'],
            source=row.get('source'),
            tags=row.get('tags') or [],
            source_type=row.get('source_type'),
            source_id=row.get('source_id'),
            feed_name=row.get('feed_name'),
            ingested_at=row.get('ingested_at'),
            last_enriched_at=row.get('last_enriched_at'),
            enrichment_trigger=row.get('enrichment_trigger'),
            feed_last_seen_at=row.get('feed_last_seen_at'),
            feed_occurrences=row.get('feed_occurrences') or 0
        )

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal (RFC1918, loopback, link-local)"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False
            # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:  # Localhost
                return True
            if octets[0] == 169 and octets[1] == 254:  # Link-local
                return True
            return False
        except:
            return False

    async def _check_whitelist(self, ioc_value: str, ioc_type: IOCType) -> bool:
        """Check if an IOC is on the whitelist"""
        db = self._get_db()
        if not db or not db.pool:
            return False

        try:
            async with db.tenant_acquire() as conn:
                # Check exact match first
                row = await conn.fetchrow(
                    """
                    SELECT 1 FROM ioc_whitelist
                    WHERE ioc_value = $1
                      AND (ioc_type = $2 OR $2 IS NULL)
                      AND (expires_at IS NULL OR expires_at > NOW())
                      AND is_pattern = FALSE
                    LIMIT 1
                    """,
                    ioc_value,
                    ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                )

                if row:
                    return True

                # Check pattern matches
                patterns = await conn.fetch(
                    """
                    SELECT ioc_value, pattern_type FROM ioc_whitelist
                    WHERE is_pattern = TRUE
                      AND (ioc_type = $1 OR $1 IS NULL)
                      AND (expires_at IS NULL OR expires_at > NOW())
                    """,
                    ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                )

                for pattern in patterns:
                    if pattern['pattern_type'] == 'prefix':
                        if ioc_value.startswith(pattern['ioc_value']):
                            return True
                    elif pattern['pattern_type'] == 'suffix':
                        if ioc_value.endswith(pattern['ioc_value']):
                            return True
                    elif pattern['pattern_type'] == 'contains':
                        if pattern['ioc_value'] in ioc_value:
                            return True
                    elif pattern['pattern_type'] == 'regex':
                        import re
                        try:
                            if re.match(pattern['ioc_value'], ioc_value):
                                return True
                        except:
                            pass

                return False

        except Exception as e:
            logger.error(f"Whitelist check error: {e}")
            return False

    async def get_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """Get an IOC by value (and optionally type)"""
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    if ioc_type:
                        row = await conn.fetchrow(
                            "SELECT * FROM iocs WHERE ioc_value = $1 AND ioc_type = $2",
                            value, ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                        )
                    else:
                        row = await conn.fetchrow(
                            "SELECT * FROM iocs WHERE ioc_value = $1",
                            value
                        )

                    if row:
                        return self._row_to_ioc(row)
            except Exception as e:
                logger.error(f"Failed to get IOC: {e}")

        return None

    async def search_iocs(
        self,
        query: Optional[str] = None,
        ioc_type: Optional[IOCType] = None,
        severity: Optional[ThreatSeverity] = None,
        verdict: Optional[ReputationVerdict] = None,
        tags: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[IOC], int]:
        """Search IOCs with filters"""
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Build query
                    conditions = []
                    params = []
                    param_idx = 1

                    if query:
                        conditions.append(f"ioc_value ILIKE ${param_idx}")
                        params.append(f"%{query}%")
                        param_idx += 1

                    if ioc_type:
                        conditions.append(f"ioc_type = ${param_idx}")
                        params.append(ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type)
                        param_idx += 1

                    if severity:
                        conditions.append(f"severity = ${param_idx}")
                        params.append(severity.value if isinstance(severity, ThreatSeverity) else severity)
                        param_idx += 1

                    if verdict:
                        conditions.append(f"reputation = ${param_idx}")
                        params.append(verdict.value if isinstance(verdict, ReputationVerdict) else verdict)
                        param_idx += 1

                    if tags:
                        conditions.append(f"tags && ${param_idx}::text[]")
                        params.append(tags)
                        param_idx += 1

                    if since:
                        conditions.append(f"last_seen >= ${param_idx}")
                        params.append(since)
                        param_idx += 1

                    where_clause = " AND ".join(conditions) if conditions else "TRUE"

                    # Get count
                    count = await conn.fetchval(
                        f"SELECT COUNT(*) FROM iocs WHERE {where_clause}",
                        *params
                    )

                    # Get results
                    params.extend([limit, offset])
                    rows = await conn.fetch(
                        f"""
                        SELECT id, ioc_value, ioc_type, severity, reputation,
                               confidence, first_seen, last_seen, occurrences,
                               source, tags, feed_name, feed_last_seen_at,
                               source_type, source_id, ingested_at,
                               last_enriched_at, enrichment_trigger,
                               feed_occurrences, tenant_id
                        FROM iocs
                        WHERE {where_clause}
                        ORDER BY last_seen DESC
                        LIMIT ${param_idx} OFFSET ${param_idx + 1}
                        """,
                        *params
                    )

                    iocs = [self._row_to_ioc(row) for row in rows]

                    return iocs, count

            except Exception as e:
                logger.error(f"Failed to search IOCs: {e}")

        return [], 0

    # ========================================================================
    # ENRICHMENT CACHE
    # ========================================================================

    async def get_cached_enrichment(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        provider: str
    ) -> Optional[EnrichmentResult]:
        """
        Get cached enrichment result if not expired.

        Also checks if the threat feed has reported this IOC more recently
        than the cache - if so, the cache is considered stale.
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Join with iocs table to check feed_last_seen_at
                    row = await conn.fetchrow(
                        """
                        SELECT c.*, i.feed_last_seen_at
                        FROM enrichment_cache c
                        LEFT JOIN iocs i ON c.ioc_value = i.ioc_value AND c.ioc_type = i.ioc_type
                        WHERE c.ioc_value = $1 AND c.ioc_type = $2 AND c.provider = $3
                          AND (c.expires_at IS NULL OR c.expires_at > NOW())
                        """,
                        ioc_value,
                        ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
                        provider
                    )

                    if row:
                        cached_at = row['cached_at'].replace(tzinfo=None) if row['cached_at'] else None
                        feed_last_seen = row['feed_last_seen_at'].replace(tzinfo=None) if row['feed_last_seen_at'] else None

                        # Check if threat feed has newer data than our cache
                        if cached_at and feed_last_seen and feed_last_seen > cached_at:
                            logger.info(f"[CACHE STALE] {provider}: Feed reported {ioc_value[:50]} at {feed_last_seen}, cache is from {cached_at}")
                            return None  # Cache is stale, force re-enrichment

                        # Update hit count
                        await conn.execute(
                            """
                            UPDATE enrichment_cache
                            SET hit_count = hit_count + 1, last_accessed_at = NOW()
                            WHERE id = $1
                            """,
                            row['id']
                        )

                        cache_age = (datetime.utcnow() - cached_at).total_seconds() if cached_at else 0

                        # Handle raw_data - it might be a dict (JSONB) or a string (if double-serialized)
                        raw_data = row['enrichment_data'] or {}
                        if isinstance(raw_data, str):
                            try:
                                raw_data = json.loads(raw_data)
                            except (json.JSONDecodeError, TypeError):
                                raw_data = {}

                        return EnrichmentResult(
                            ioc_value=row['ioc_value'],
                            ioc_type=row['ioc_type'],
                            provider=row['provider'],
                            verdict=ReputationVerdict.MALICIOUS if row['is_malicious'] else ReputationVerdict.CLEAN,
                            threat_score=row['threat_score'],
                            confidence=float(row['confidence']) if row['confidence'] else None,
                            raw_data=raw_data,
                            enriched_at=row['cached_at'],
                            cached=True,
                            cache_age_seconds=int(cache_age)
                        )

            except Exception as e:
                logger.error(f"Failed to get cached enrichment: {e}")

        return None

    async def cache_enrichment(
        self,
        result: EnrichmentResult,
        ttl_days: Optional[int] = None,
        use_smart_ttl: bool = True
    ) -> bool:
        """
        Cache an enrichment result with smart TTL calculation.

        Args:
            result: The enrichment result to cache
            ttl_days: Override TTL in days (if None, uses smart calculation)
            use_smart_ttl: If True and ttl_days is None, use smart TTL based on
                          provider, confidence, and verdict
        """
        db = self._get_db()

        # Determine TTL using smart calculation or fallback to base
        if ttl_days is None:
            if use_smart_ttl:
                ttl_days = self.calculate_smart_ttl(
                    ioc_type=result.ioc_type,
                    provider=result.provider,
                    verdict=result.verdict,
                    confidence=result.confidence
                )
            else:
                ttl_days = self.CACHE_TTL_DAYS.get(
                    IOCType(result.ioc_type) if isinstance(result.ioc_type, str) else result.ioc_type,
                    7
                )

        expires_at = datetime.utcnow() + timedelta(days=ttl_days)
        logger.debug(f"Caching {result.provider} result for {result.ioc_value} with TTL={ttl_days} days")

        if db and db.pool:
            try:
                # Get tenant_id for RLS compliance
                from middleware.tenant_middleware import get_optional_tenant_id
                tenant_id_str = get_optional_tenant_id()
                if not tenant_id_str:
                    from config.constants import PLATFORM_OWNER_TENANT_ID
                    tenant_id_str = PLATFORM_OWNER_TENANT_ID
                tenant_uuid = uuid.UUID(tenant_id_str)

                async with db.tenant_acquire() as conn:
                    raw_data_json = result.raw_data if isinstance(result.raw_data, str) else json.dumps(result.raw_data)

                    await conn.execute(
                        """
                        INSERT INTO enrichment_cache (
                            ioc_type, ioc_value, provider, enrichment_data,
                            is_malicious, threat_score, confidence,
                            cached_at, expires_at, tenant_id
                        ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NOW(), $8, $9)
                        ON CONFLICT (ioc_type, ioc_value, provider, tenant_id) DO UPDATE SET
                            enrichment_data = $4::jsonb,
                            is_malicious = $5,
                            threat_score = $6,
                            confidence = $7,
                            cached_at = NOW(),
                            expires_at = $8,
                            hit_count = enrichment_cache.hit_count + 1
                        """,
                        result.ioc_type.value if isinstance(result.ioc_type, IOCType) else result.ioc_type,
                        result.ioc_value,
                        result.provider,
                        raw_data_json,
                        result.verdict == ReputationVerdict.MALICIOUS,
                        result.threat_score,
                        result.confidence,
                        expires_at,
                        tenant_uuid
                    )
                    return True

            except Exception as e:
                logger.error(f"Failed to cache enrichment: {e}")

        return False

    # ========================================================================
    # ENRICHMENT EXECUTION
    # ========================================================================

    async def enrich_ioc(
        self,
        value: str,
        ioc_type: IOCType,
        providers: Optional[List[str]] = None,
        force_refresh: bool = False,
        trigger: Optional[EnrichmentTrigger] = None,
        skip_whitelist_check: bool = False
    ) -> ThreatIntelReport:
        """
        Enrich an IOC using configured providers.

        Uses cache unless force_refresh=True.
        Checks whitelist before enriching unless skip_whitelist_check=True.

        Args:
            value: The IOC value
            ioc_type: The type of IOC
            providers: Optional list of specific providers to use
            force_refresh: If True, bypass cache
            trigger: What triggered this enrichment (for tracking)
            skip_whitelist_check: If True, skip whitelist check
        """
        # Check for private/internal IPs - NEVER enrich these externally
        if ioc_type == IOCType.IP:
            if self._is_private_ip(value):
                logger.info(f"Skipping enrichment for private/internal IP: {value}")
                ioc = IOC(value=value, type=ioc_type)
                return ThreatIntelReport(
                    ioc=ioc,
                    enrichments=[],
                    overall_verdict=ReputationVerdict.UNKNOWN,
                    confidence=100.0,
                    severity=ThreatSeverity.UNKNOWN,
                    risk_score=0.0,
                    summary=f"Private/internal IP - not sent to external threat intel services",
                    recommendations=["Internal IP addresses are not enriched via external services"],
                    generated_at=datetime.utcnow()
                )

        # Check whitelist first (unless skipped)
        if not skip_whitelist_check:
            is_whitelisted = await self._check_whitelist(value, ioc_type)
            if is_whitelisted:
                logger.info(f"Skipping enrichment for whitelisted IOC: {value}")
                # Return a minimal report indicating whitelist status
                ioc = await self.get_ioc(value, ioc_type)
                if not ioc:
                    ioc = IOC(value=value, type=ioc_type)
                return ThreatIntelReport(
                    ioc=ioc,
                    enrichments=[],
                    overall_verdict=ReputationVerdict.CLEAN,
                    confidence=100.0,
                    severity=ThreatSeverity.UNKNOWN,
                    risk_score=0.0,
                    summary=f"IOC is whitelisted - enrichment skipped",
                    recommendations=["This IOC is on the whitelist and was not enriched"],
                    generated_at=datetime.utcnow()
                )

        # Get or create IOC record
        ioc = await self.get_ioc(value, ioc_type)
        if not ioc:
            ioc = await self.add_ioc(value, ioc_type)
            # New IOC - mark trigger as auto_initial if not specified
            if trigger is None:
                trigger = EnrichmentTrigger.AUTO_INITIAL

        # Default trigger if not specified
        if trigger is None:
            trigger = EnrichmentTrigger.MANUAL

        enrichments = []
        provider_statuses = []  # Track status of each provider call
        import time

        # Get available providers for this IOC type
        available_providers = await self._get_providers_for_type(ioc_type)
        print(f"[THREAT_INTEL] Available providers for {ioc_type}: {available_providers}")
        if providers:
            available_providers = [p for p in available_providers if p in providers]

        print(f"[THREAT_INTEL] Will use providers: {available_providers}")

        # Get provider display names from registry
        from integrations.registry.integration_registry import get_registry
        registry = get_registry()

        # Enrich from each provider
        for provider in available_providers:
            # Get provider display name
            integration = registry.get(provider)
            provider_name = integration.name if integration else provider

            start_time = time.time()

            # Check cache first (freshness check) - unless force_refresh
            if not force_refresh:
                cached = await self.get_cached_enrichment(value, ioc_type, provider)
                if cached:
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    print(f"[CACHE HIT] {provider}: Using cached enrichment for {value[:50]} (age: {cached.cache_age_seconds}s)")
                    enrichments.append(cached)
                    provider_statuses.append(ProviderStatus(
                        provider_id=provider,
                        provider_name=provider_name,
                        status='cached',
                        message=f'Using cached data (age: {cached.cache_age_seconds}s)',
                        response_time_ms=elapsed_ms,
                        cached=True,
                        has_data=True
                    ))
                    continue

            # Execute enrichment (cache miss or force refresh)
            try:
                result = await self._execute_enrichment(value, ioc_type, provider)
                elapsed_ms = int((time.time() - start_time) * 1000)

                if result:
                    # Cache the result
                    await self.cache_enrichment(result)
                    enrichments.append(result)
                    provider_statuses.append(ProviderStatus(
                        provider_id=provider,
                        provider_name=provider_name,
                        status='success',
                        message='Enrichment successful',
                        response_time_ms=elapsed_ms,
                        cached=False,
                        has_data=True
                    ))
                elif force_refresh:
                    # Force refresh failed (e.g., circuit breaker) - try to use cached data as fallback
                    cached = await self.get_cached_enrichment(value, ioc_type, provider)
                    if cached:
                        print(f"[FALLBACK CACHE] {provider}: Enrichment failed, using cached data for {value[:50]}")
                        enrichments.append(cached)
                        provider_statuses.append(ProviderStatus(
                            provider_id=provider,
                            provider_name=provider_name,
                            status='rate_limited',
                            message='Rate limited, using cached data',
                            response_time_ms=elapsed_ms,
                            cached=True,
                            has_data=True
                        ))
                    else:
                        provider_statuses.append(ProviderStatus(
                            provider_id=provider,
                            provider_name=provider_name,
                            status='rate_limited',
                            message='Rate limited, no cached data available',
                            response_time_ms=elapsed_ms,
                            cached=False,
                            has_data=False
                        ))
                else:
                    # No result and not force refresh
                    provider_statuses.append(ProviderStatus(
                        provider_id=provider,
                        provider_name=provider_name,
                        status='no_data',
                        message='No data returned from provider',
                        response_time_ms=elapsed_ms,
                        cached=False,
                        has_data=False
                    ))
            except Exception as e:
                elapsed_ms = int((time.time() - start_time) * 1000)
                error_msg = str(e)
                logger.error(f"Enrichment failed for {provider}: {e}")

                # Determine error type
                status = 'error'
                if '429' in error_msg or 'rate' in error_msg.lower() or 'quota' in error_msg.lower():
                    status = 'rate_limited'
                elif '401' in error_msg or '403' in error_msg or 'auth' in error_msg.lower():
                    status = 'auth_error'
                elif 'timeout' in error_msg.lower():
                    status = 'timeout'

                # If force_refresh failed, try to use cached data as fallback
                if force_refresh:
                    try:
                        cached = await self.get_cached_enrichment(value, ioc_type, provider)
                        if cached:
                            print(f"[FALLBACK CACHE] {provider}: Exception during enrichment, using cached data for {value[:50]}")
                            enrichments.append(cached)
                            provider_statuses.append(ProviderStatus(
                                provider_id=provider,
                                provider_name=provider_name,
                                status=status,
                                message=f'{error_msg[:100]}... (using cached data)',
                                response_time_ms=elapsed_ms,
                                cached=True,
                                has_data=True
                            ))
                            continue
                    except Exception:
                        pass

                provider_statuses.append(ProviderStatus(
                    provider_id=provider,
                    provider_name=provider_name,
                    status=status,
                    message=error_msg[:200],
                    response_time_ms=elapsed_ms,
                    cached=False,
                    has_data=False
                ))

        # Build report with provider status
        report = self._build_threat_report(ioc, enrichments)
        report.provider_status = provider_statuses

        # Update IOC with aggregated data and enrichment tracking
        await self._update_ioc_from_enrichments(ioc, enrichments, trigger)

        return report

    async def bulk_enrich(
        self,
        iocs: List[Tuple[str, IOCType]],
        providers: Optional[List[str]] = None,
        max_concurrent: int = 5
    ) -> List[ThreatIntelReport]:
        """Bulk enrich multiple IOCs with concurrency control"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def enrich_with_limit(value: str, ioc_type: IOCType):
            async with semaphore:
                return await self.enrich_ioc(value, ioc_type, providers)

        tasks = [enrich_with_limit(v, t) for v, t in iocs]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def _get_providers_for_type(self, ioc_type: IOCType) -> List[str]:
        """
        Dynamically discover available enrichment providers for an IOC type.

        This checks the integration registry for integrations that have
        actions matching the IOC type's observable_type, then cross-references
        with the database to check if they're enabled.
        """
        try:
            from integrations.registry.integration_registry import get_registry, IntegrationType

            registry = get_registry()

            # Map IOCType to observable_type values used in integration definitions
            ioc_to_observable = {
                IOCType.IP: ['ip', 'ipv4', 'ipv6'],
                IOCType.DOMAIN: ['domain', 'hostname'],
                IOCType.URL: ['url'],
                IOCType.HASH_MD5: ['hash', 'file_hash', 'md5'],
                IOCType.HASH_SHA1: ['hash', 'file_hash', 'sha1'],
                IOCType.HASH_SHA256: ['hash', 'file_hash', 'sha256'],
                IOCType.EMAIL: ['email'],
                IOCType.CVE: ['cve'],
            }

            target_observables = ioc_to_observable.get(ioc_type, [])
            providers = []

            # Get user-configured integrations from connect_instances (T1 Connect)
            db = self._get_db()
            enabled_integration_ids = set()
            if db and db.pool:
                try:
                    async with db.tenant_acquire() as conn:
                        # Query connect_instances joined with connector_definitions for category
                        rows = await conn.fetch("""
                            SELECT ci.connector_id, cd.category
                            FROM connect_instances ci
                            JOIN connector_definitions cd ON ci.connector_id = cd.id
                            WHERE ci.enabled = true
                              AND cd.category IN ('threat_intel', 'enrichment', 'sandbox')
                        """)
                        enabled_integration_ids = {row['connector_id'] for row in rows}
                        if enabled_integration_ids:
                            logger.info(f"[DISCOVERY] Configured integrations: {list(enabled_integration_ids)}")
                except Exception as e:
                    logger.warning(f"Could not query configured integrations: {e}")

            # Only use integrations the user has explicitly configured in the DB
            if not enabled_integration_ids:
                logger.info(f"[DISCOVERY] No integrations configured -- enrichment requires configured providers")
                return []

            # Match configured integrations against registry actions
            for int_type in [IntegrationType.THREAT_INTEL, IntegrationType.ENRICHMENT, IntegrationType.SANDBOX]:
                for integration in registry.list(integration_type=int_type, enabled_only=False):
                    if integration.id not in enabled_integration_ids:
                        continue

                    for action in integration.actions:
                        obs_type = getattr(action, 'observable_type', None)
                        if obs_type:
                            obs_type_str = obs_type.value if hasattr(obs_type, 'value') else str(obs_type)
                            if obs_type_str in target_observables:
                                providers.append(integration.id)
                                break

            logger.info(f"[DISCOVERY] Found {len(providers)} configured providers for {ioc_type}: {providers}")
            return providers

        except Exception as e:
            logger.error(f"Error discovering providers for {ioc_type}: {e}")
            # Fallback to empty list - no hardcoded defaults
            return []

    async def _execute_urlscan_with_submit(
        self,
        value: str,
        ioc_type: IOCType
    ) -> Optional[EnrichmentResult]:
        """
        Execute URLScan enrichment with auto-submit if no existing scans found.

        Flow:
        1. Search for existing scans
        2. If no results, submit URL for scanning
        3. Wait for scan to complete (poll for result)
        4. Return the scan result
        """
        import asyncio
        from integrations.engines.execution_engine import get_execution_engine, ExecutionRequest, ExecutionContext

        engine = get_execution_engine()
        provider = 'urlscan'

        print(f"[URLSCAN] Starting enrichment with auto-submit for {value[:50]}...")

        # Step 1: Search for existing scans
        search_result = await engine.execute(ExecutionRequest(
            integration_id=provider,
            action_id="search_url",
            input_payload={"url": value},
            context=ExecutionContext(actor_id="threat_intel_service", actor_type="automation")
        ))

        if search_result.success and search_result.data:
            results = search_result.data.get('results', [])
            if results:
                print(f"[URLSCAN] Found {len(results)} existing scans")
                return self._parse_urlscan(value, ioc_type, search_result.data)

        # Step 2: No existing scans - submit for scanning
        print(f"[URLSCAN] No existing scans found, submitting URL for scanning...")

        submit_result = await engine.execute(ExecutionRequest(
            integration_id=provider,
            action_id="submit_scan",
            input_payload={"url": value, "visibility": "public"},
            context=ExecutionContext(actor_id="threat_intel_service", actor_type="automation")
        ))

        if not submit_result.success:
            print(f"[URLSCAN] Submit failed: {submit_result.error}")
            # Return unknown result - couldn't scan
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='urlscan',
                verdict=ReputationVerdict.UNKNOWN,
                threat_score=10,
                confidence=0.1,
                raw_data={"error": str(submit_result.error), "submitted": False},
                tags=['submit_failed']
            )

        # Get the scan UUID from submit response
        scan_uuid = submit_result.data.get('uuid')
        scan_api_url = submit_result.data.get('api')
        result_url = submit_result.data.get('result')

        if not scan_uuid:
            print(f"[URLSCAN] No UUID in submit response: {submit_result.data}")
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='urlscan',
                verdict=ReputationVerdict.UNKNOWN,
                threat_score=10,
                confidence=0.1,
                raw_data=submit_result.data,
                tags=['no_uuid_returned']
            )

        print(f"[URLSCAN] Scan submitted, UUID: {scan_uuid}, result URL: {result_url}")

        # Step 3: Poll for scan completion - wait up to ~25 seconds with multiple attempts
        # URLScan typically completes in 10-20 seconds
        poll_intervals = [3, 5, 7, 10]  # Wait 3s, then 5s, then 7s, then 10s = 25s total max

        for attempt, wait_time in enumerate(poll_intervals, 1):
            await asyncio.sleep(wait_time)
            print(f"[URLSCAN] Polling attempt {attempt}/{len(poll_intervals)} for scan {scan_uuid}...")

            result_response = await engine.execute(ExecutionRequest(
                integration_id=provider,
                action_id="get_result",
                input_payload={"uuid": scan_uuid},
                context=ExecutionContext(actor_id="threat_intel_service", actor_type="automation")
            ))

            if result_response.success and result_response.data:
                # Check if scan is actually complete (has page data or verdicts)
                if result_response.data.get('page') or result_response.data.get('verdicts'):
                    print(f"[URLSCAN] Scan completed on attempt {attempt}!")
                    return self._parse_urlscan_result(value, ioc_type, result_response.data, scan_uuid, result_url)
                else:
                    print(f"[URLSCAN] Scan not ready yet (attempt {attempt})")
            elif result_response.error:
                # 404 means scan still processing
                error_str = str(result_response.error).lower()
                if '404' in error_str or 'not found' in error_str:
                    print(f"[URLSCAN] Scan still processing (attempt {attempt})")
                else:
                    print(f"[URLSCAN] Error polling: {result_response.error}")

        # If we get here, scan didn't complete in time - return with link to check later
        print(f"[URLSCAN] Scan still in progress after polling - returning with link")
        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='urlscan',
            verdict=ReputationVerdict.UNKNOWN,
            threat_score=10,
            confidence=0.3,
            raw_data={
                "scan_uuid": scan_uuid,
                "result_url": result_url,
                "api_url": f"https://urlscan.io/api/v1/result/{scan_uuid}/",
                "status": "scan_pending",
                "message": "Scan submitted but taking longer than usual. Check result URL.",
                "results": []
            },
            tags=['scan_submitted', 'pending', f'result:{result_url}']
        )

    def _parse_urlscan_result(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any],
        scan_uuid: str,
        result_url: str
    ) -> EnrichmentResult:
        """Parse URLScan scan result (from get_result endpoint)"""
        verdicts = raw_data.get('verdicts', {})
        overall = verdicts.get('overall', {})
        urlscan_verdict = verdicts.get('urlscan', {})

        tags = []
        categories = []

        # Check verdicts
        is_malicious = overall.get('malicious', False) or urlscan_verdict.get('malicious', False)
        malicious_score = overall.get('score', 0)

        # Get categories from engines
        engines = verdicts.get('engines', {})
        for engine_name, engine_data in engines.items():
            if isinstance(engine_data, dict):
                for cat in engine_data.get('categories', []):
                    if cat not in categories:
                        categories.append(cat)

        # Get page info
        page = raw_data.get('page', {})
        page_title = page.get('title', '')
        page_server = page.get('server', '')

        # Check for phishing indicators
        is_phishing = False
        task = raw_data.get('task', {})
        task_tags = task.get('tags', [])
        for tag in task_tags:
            tag_lower = tag.lower()
            if 'phishing' in tag_lower:
                is_phishing = True
            if tag not in tags:
                tags.append(tag)

        # Determine verdict
        if is_malicious or is_phishing:
            verdict = ReputationVerdict.MALICIOUS
            threat_score = max(70, malicious_score) if malicious_score else 75
        elif malicious_score > 0:
            verdict = ReputationVerdict.SUSPICIOUS
            threat_score = max(40, malicious_score)
        else:
            verdict = ReputationVerdict.CLEAN
            threat_score = 10

        # Add scan info to tags
        tags.append('fresh_scan')
        if result_url:
            tags.append(f"result:{result_url}")

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='urlscan',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.85,  # High confidence for fresh scan
            raw_data=raw_data,
            tags=tags[:15],
            categories=categories[:5]
        )

    async def _execute_enrichment(
        self,
        value: str,
        ioc_type: IOCType,
        provider: str
    ) -> Optional[EnrichmentResult]:
        """
        Execute enrichment using the integration execution engine.

        DYNAMIC DISCOVERY: Instead of hardcoded mappings, this finds the right
        action by looking at the integration's actions and their observable_type.
        """
        # Special handling for URLScan URL enrichment - auto-submit if no existing scans
        if provider == 'urlscan' and ioc_type == IOCType.URL:
            try:
                return await self._execute_urlscan_with_submit(value, ioc_type)
            except Exception as e:
                logger.error(f"URLScan auto-submit failed: {e}")
                # Fall through to normal enrichment

        try:
            from integrations.engines.execution_engine import get_execution_engine, ExecutionRequest, ExecutionContext
            from integrations.registry.integration_registry import get_registry

            engine = get_execution_engine()
            registry = get_registry()

            # Map IOCType to observable_type values
            ioc_to_observable = {
                IOCType.IP: ['ip', 'ipv4', 'ipv6'],
                IOCType.DOMAIN: ['domain', 'hostname'],
                IOCType.URL: ['url'],
                IOCType.HASH_MD5: ['hash', 'file_hash', 'md5'],
                IOCType.HASH_SHA1: ['hash', 'file_hash', 'sha1'],
                IOCType.HASH_SHA256: ['hash', 'file_hash', 'sha256'],
                IOCType.EMAIL: ['email'],
                IOCType.CVE: ['cve'],
            }

            target_observables = ioc_to_observable.get(ioc_type, [])

            print(f"[THREAT_INTEL] _execute_enrichment called for provider={provider}, ioc_type={ioc_type}")

            # Get the integration (provider IS the integration_id in our dynamic system)
            integration = registry.get(provider)
            if not integration:
                print(f"[THREAT_INTEL] Integration {provider} not found in registry")
                return None

            # Check if user has this integration configured and enabled in T1 Connect
            # Also fetch credential to inject auth
            db = self._get_db()
            is_enabled = False
            if db and db.pool:
                try:
                    async with db.tenant_acquire() as conn:
                        row = await conn.fetchrow(
                            """SELECT ci.enabled, ci.credential_id, cc.auth_type, cc.encrypted_data,
                                      cd.auth_config
                               FROM connect_instances ci
                               LEFT JOIN connect_credentials cc ON ci.credential_id = cc.id
                               LEFT JOIN connector_definitions cd ON ci.connector_id = cd.id
                               WHERE ci.connector_id = $1""",
                            provider
                        )
                        is_enabled = bool(row and row['enabled'])

                        # Inject credential into integration for execution engine
                        if is_enabled and row and row['encrypted_data']:
                            try:
                                from services.connect_service import get_connect_service
                                svc = get_connect_service()
                                secret_data = svc._decrypt_dict(row['encrypted_data'])
                                auth_config = row['auth_config'] if row['auth_config'] else {}
                                if isinstance(auth_config, str):
                                    import json as _json
                                    auth_config = _json.loads(auth_config)
                                auth_headers = svc._build_auth_headers(
                                    row['auth_type'], auth_config, secret_data
                                )
                                # Store resolved headers on integration for _inject_auth
                                integration.auth_config = {
                                    **integration.auth_config,
                                    '_resolved_headers': auth_headers,
                                }
                            except Exception as e:
                                logger.warning(f"Could not resolve credential for {provider}: {e}")
                except Exception as e:
                    logger.warning(f"Could not check enabled status for {provider}: {e}")

            if not is_enabled:
                logger.debug(f"Integration {provider} not configured or not enabled")
                return None

            # Mark integration as enabled in registry so execution engine allows it
            integration.enabled = True

            # Find the matching action by observable_type
            action_id = None
            matching_action = None
            for action in integration.actions:
                obs_type = getattr(action, 'observable_type', None)
                if obs_type:
                    # Handle both enum and string comparison
                    obs_type_str = obs_type.value if hasattr(obs_type, 'value') else str(obs_type)
                    if obs_type_str in target_observables:
                        # Prefer read_only/investigate actions
                        action_type = getattr(action, 'action_type', None)
                        read_only = getattr(action, 'read_only', False)
                        if action_type == 'investigate' or read_only:
                            action_id = action.id
                            matching_action = action
                            break
                        elif action_id is None:
                            # Take first match if no investigate action found
                            action_id = action.id
                            matching_action = action

            if not action_id:
                print(f"[THREAT_INTEL] No matching action found for {provider} with observable {target_observables}")
                return None

            print(f"[THREAT_INTEL] Found action {action_id} for {provider}")

            # Build input payload dynamically from action parameters
            input_payload = self._build_input_payload_dynamic(value, ioc_type, matching_action, provider)
            print(f"[THREAT_INTEL] Input payload: {input_payload}")

            # Execute
            print(f"[THREAT_INTEL] Executing {provider}/{action_id}")
            result = await engine.execute(ExecutionRequest(
                integration_id=provider,
                action_id=action_id,
                input_payload=input_payload,
                context=ExecutionContext(
                    actor_id="threat_intel_service",
                    actor_type="automation"
                )
            ))
            print(f"[THREAT_INTEL] Result: success={result.success}, error={result.error}, has_data={result.data is not None}")

            if result.success and result.data:
                # Parse result into EnrichmentResult
                print(f"[THREAT_INTEL] {provider}: Parsing result data (keys: {list(result.data.keys()) if isinstance(result.data, dict) else 'not dict'})")
                parsed = self._parse_enrichment_result(
                    value, ioc_type, provider, result.data
                )
                if parsed:
                    print(f"[THREAT_INTEL] {provider}: Parsed result verdict={parsed.verdict}, score={parsed.threat_score}")
                return parsed
            else:
                print(f"[THREAT_INTEL] Execution failed or no data: {result.error}")

        except Exception as e:
            import traceback
            logger.error(f"Enrichment execution error for {provider}: {e}")
            logger.error(traceback.format_exc())

        return None

    def _normalize_domain_for_rdap(self, domain: str) -> str:
        """
        Normalize domain for RDAP lookup.
        RDAP requires base domain (e.g., youtube.com, not www.youtube.com).
        """
        # Remove protocol if accidentally included
        if domain.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc or domain

        # Strip common subdomains
        prefixes_to_strip = ['www.', 'mail.', 'ftp.', 'm.', 'www1.', 'www2.']
        for prefix in prefixes_to_strip:
            if domain.lower().startswith(prefix):
                domain = domain[len(prefix):]

        # For multi-level subdomains, try to get the base domain
        # e.g., "sub.sub2.example.com" -> "example.com"
        parts = domain.split('.')
        if len(parts) > 2:
            # Check for known public suffixes that have two parts (e.g., co.uk)
            two_part_tlds = {'co.uk', 'com.au', 'co.nz', 'co.jp', 'org.uk', 'net.au'}
            if len(parts) >= 3:
                potential_tld = '.'.join(parts[-2:])
                if potential_tld.lower() in two_part_tlds:
                    # Keep last 3 parts for two-part TLDs
                    return '.'.join(parts[-3:])
            # Otherwise keep last 2 parts (base domain + TLD)
            return '.'.join(parts[-2:])

        return domain

    def _build_input_payload_dynamic(
        self,
        value: str,
        ioc_type: IOCType,
        action: Any,
        integration_id: str
    ) -> Dict[str, Any]:
        """
        Build input payload DYNAMICALLY from action parameter definitions.

        This reads the action's parameters and intelligently maps the IOC value
        to the correct parameter name based on the parameter's 'contains' hints.
        """
        payload = {}

        # Get parameters from action
        parameters = getattr(action, 'parameters', []) or []
        if hasattr(action, 'input_schema') and action.input_schema:
            # Try to get from input_schema if parameters not directly available
            schema_props = action.input_schema.get('properties', {})
            if schema_props and not parameters:
                parameters = [{'name': k, 'required': k in action.input_schema.get('required', [])}
                             for k in schema_props.keys()]

        # IOC type to potential parameter name hints
        ioc_param_hints = {
            IOCType.IP: ['ip', 'ipaddress', 'ip_address', 'ipAddress', 'address'],
            IOCType.DOMAIN: ['domain', 'hostname', 'host', 'fqdn'],
            IOCType.URL: ['url', 'uri', 'link'],
            IOCType.HASH_MD5: ['hash', 'md5', 'file_hash', 'filehash'],
            IOCType.HASH_SHA1: ['hash', 'sha1', 'file_hash', 'filehash'],
            IOCType.HASH_SHA256: ['hash', 'sha256', 'file_hash', 'filehash'],
            IOCType.EMAIL: ['email', 'mail', 'address'],
            IOCType.CVE: ['cve', 'vulnerability', 'vuln'],
        }

        hints = ioc_param_hints.get(ioc_type, ['value'])
        primary_param_set = False

        for param in parameters:
            param_name = param.get('name') if isinstance(param, dict) else getattr(param, 'name', None)
            if not param_name:
                continue

            param_required = param.get('required', False) if isinstance(param, dict) else getattr(param, 'required', False)
            param_default = param.get('default') if isinstance(param, dict) else getattr(param, 'default', None)
            param_contains = param.get('contains', []) if isinstance(param, dict) else getattr(param, 'contains', [])

            # Check if this parameter matches our IOC type
            param_name_lower = param_name.lower()

            # Check for value_template (e.g., "page.url:{value}" for search queries)
            value_template = param.get('value_template') if isinstance(param, dict) else getattr(param, 'value_template', None)

            # Match by 'contains' field hints (e.g., ["ip", "ipv6"])
            if param_contains:
                for hint in hints:
                    if hint.lower() in [c.lower() for c in param_contains]:
                        # Apply value_template if defined
                        if value_template:
                            payload[param_name] = value_template.replace('{value}', value)
                        else:
                            payload[param_name] = value
                        primary_param_set = True
                        break

            # Match by parameter name
            if not primary_param_set:
                for hint in hints:
                    if hint.lower() in param_name_lower or param_name_lower in hint.lower():
                        payload[param_name] = value
                        primary_param_set = True
                        break

            # Apply default value if parameter not set (for both required and optional with defaults)
            if param_name not in payload and param_default is not None:
                payload[param_name] = param_default

        # Fallback: if no parameter matched, use first required parameter or 'value'
        if not primary_param_set:
            for param in parameters:
                param_name = param.get('name') if isinstance(param, dict) else getattr(param, 'name', None)
                param_required = param.get('required', False) if isinstance(param, dict) else getattr(param, 'required', False)
                if param_required and param_name:
                    payload[param_name] = value
                    break
            else:
                payload['value'] = value

        # Auto-encode URL parameters for APIs that require base64-encoded URLs (e.g., VirusTotal)
        for param in parameters:
            param_name = param.get('name') if isinstance(param, dict) else getattr(param, 'name', None)
            auto_encode = param.get('auto_encode') if isinstance(param, dict) else getattr(param, 'auto_encode', None)

            if auto_encode == 'base64_url' and param_name not in payload:
                # Find the source URL value and base64 encode it
                url_value = payload.get('url') or payload.get('uri') or value
                if url_value and ioc_type == IOCType.URL:
                    import base64
                    # VirusTotal uses URL-safe base64 without padding
                    encoded = base64.urlsafe_b64encode(url_value.encode()).decode().rstrip('=')
                    payload[param_name] = encoded

        # Special handling for VirusTotal URL lookups - generate url_id from url
        if integration_id == 'virustotal' and ioc_type == IOCType.URL and 'url_id' not in payload:
            url_value = payload.get('url') or value
            if url_value:
                import base64
                # VirusTotal requires URL-safe base64 without padding for URL lookups
                encoded = base64.urlsafe_b64encode(url_value.encode()).decode().rstrip('=')
                payload['url_id'] = encoded

        # NOTE: url_encoded removed -- no connector endpoint uses {url_encoded}
        # and it was polluting GET query strings as an extra parameter

        # Special handling for RDAP domain lookups - normalize domain (strip www., subdomains)
        if integration_id.startswith('rdap_') and ioc_type == IOCType.DOMAIN:
            domain_value = payload.get('domain') or value
            if domain_value:
                # Strip www. prefix and get base domain for RDAP
                normalized = self._normalize_domain_for_rdap(domain_value)
                payload['domain'] = normalized
                print(f"[RDAP] Normalized domain: {domain_value} -> {normalized}")

        print(f"[DYNAMIC_PAYLOAD] Built payload for {integration_id}: {payload}")
        return payload

    def _parse_enrichment_result(
        self,
        value: str,
        ioc_type: IOCType,
        provider: str,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse raw API response into EnrichmentResult"""
        # Provider-specific parsing (key is integration_id)
        # Also support aliases for backwards compatibility
        parsers = {
            'virustotal': self._parse_virustotal,
            'virustotal_v3': self._parse_virustotal,  # Same parser for v3
            'abuseipdb': self._parse_abuseipdb,
            'shodan': self._parse_shodan,
            'greynoise': self._parse_greynoise,
            'ipinfo': self._parse_ipinfo,
            'urlhaus': self._parse_urlhaus,
            'malwarebazaar': self._parse_malwarebazaar,
            'otx': self._parse_otx,
            'alienvault_otx': self._parse_otx,  # Alias
            'urlscan': self._parse_urlscan,
            'urlscan_io': self._parse_urlscan,  # Alias
            'rdap_arin': self._parse_rdap,
            'rdap_verisign': self._parse_rdap,
        }

        if provider in parsers:
            return parsers[provider](value, ioc_type, raw_data)

        # Generic parsing - try to extract common fields intelligently
        return self._parse_generic(value, ioc_type, provider, raw_data)

    def _parse_generic(
        self,
        value: str,
        ioc_type: IOCType,
        provider: str,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """
        Generic parser that tries to extract threat information from unknown integrations.
        Looks for common field patterns in the response.
        """
        # Common field names for threat scoring
        score_fields = ['score', 'threat_score', 'risk_score', 'confidence', 'rating', 'risk']
        malicious_fields = ['malicious', 'is_malicious', 'bad', 'dangerous', 'threat']
        verdict_fields = ['verdict', 'classification', 'category', 'reputation', 'status']

        threat_score = None
        verdict = ReputationVerdict.UNKNOWN
        tags = []

        # Flatten nested data for easier searching
        def search_dict(d, depth=0):
            if depth > 3:  # Limit recursion
                return
            nonlocal threat_score, verdict, tags

            if not isinstance(d, dict):
                return

            for key, val in d.items():
                key_lower = key.lower()

                # Look for score
                if threat_score is None:
                    for sf in score_fields:
                        if sf in key_lower and isinstance(val, (int, float)):
                            threat_score = int(val) if val <= 100 else int(val / 10)
                            break

                # Look for malicious indicators
                for mf in malicious_fields:
                    if mf in key_lower:
                        if val is True or (isinstance(val, (int, float)) and val > 0):
                            verdict = ReputationVerdict.MALICIOUS
                        elif val is False or val == 0:
                            verdict = ReputationVerdict.CLEAN

                # Look for verdict strings
                for vf in verdict_fields:
                    if vf in key_lower and isinstance(val, str):
                        val_lower = val.lower()
                        if any(m in val_lower for m in ['malicious', 'malware', 'bad', 'threat']):
                            verdict = ReputationVerdict.MALICIOUS
                        elif any(s in val_lower for s in ['suspicious', 'potential', 'medium']):
                            verdict = ReputationVerdict.SUSPICIOUS
                        elif any(c in val_lower for c in ['clean', 'safe', 'benign', 'good']):
                            verdict = ReputationVerdict.CLEAN

                # Extract tags
                if 'tag' in key_lower and isinstance(val, list):
                    tags.extend([str(t) for t in val[:10]])

                # Recurse into nested dicts
                if isinstance(val, dict):
                    search_dict(val, depth + 1)
                elif isinstance(val, list):
                    for item in val[:5]:
                        if isinstance(item, dict):
                            search_dict(item, depth + 1)

        search_dict(raw_data)

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider=provider,
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.5,  # Lower confidence for generic parsing
            raw_data=raw_data,
            tags=tags[:15]
        )

    def _parse_virustotal(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse VirusTotal response"""
        data = raw_data.get('data', {})
        attrs = data.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values()) if stats else 0

        # Calculate threat score (0-100)
        threat_score = 0
        if total > 0:
            threat_score = int(((malicious * 2 + suspicious) / (total * 2)) * 100)

        # Determine verdict
        if malicious > 3:
            verdict = ReputationVerdict.MALICIOUS
        elif malicious > 0 or suspicious > 2:
            verdict = ReputationVerdict.SUSPICIOUS
        else:
            verdict = ReputationVerdict.CLEAN

        # Extract tags
        tags = attrs.get('tags', [])
        categories = list(attrs.get('categories', {}).values()) if isinstance(attrs.get('categories'), dict) else []

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='virustotal',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.9 if total > 30 else 0.7 if total > 10 else 0.5,
            raw_data=raw_data,
            tags=tags,
            categories=categories
        )

    def _parse_abuseipdb(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse AbuseIPDB response"""
        data = raw_data.get('data', {})

        abuse_score = data.get('abuseConfidenceScore', 0)
        is_public = data.get('isPublic', True)
        total_reports = data.get('totalReports', 0)

        # Determine verdict
        if abuse_score >= 80:
            verdict = ReputationVerdict.MALICIOUS
        elif abuse_score >= 30:
            verdict = ReputationVerdict.SUSPICIOUS
        else:
            verdict = ReputationVerdict.CLEAN

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='abuseipdb',
            verdict=verdict,
            threat_score=abuse_score,
            confidence=0.85 if total_reports > 10 else 0.6,
            raw_data=raw_data,
            tags=[f"reports:{total_reports}"],
            categories=data.get('usageType', '').split(',') if data.get('usageType') else []
        )

    def _parse_shodan(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse Shodan response"""
        vulns = raw_data.get('vulns', [])
        ports = raw_data.get('ports', [])

        # Higher score for more vulns/exposed services
        threat_score = min(100, len(vulns) * 20 + len(ports) * 5)

        if len(vulns) >= 3:
            verdict = ReputationVerdict.SUSPICIOUS
        elif len(vulns) >= 1:
            verdict = ReputationVerdict.SUSPICIOUS
        else:
            verdict = ReputationVerdict.UNKNOWN

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='shodan',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.8,
            raw_data=raw_data,
            tags=[f"port:{p}" for p in ports[:10]],
            categories=vulns[:10] if vulns else []
        )

    def _parse_greynoise(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse GreyNoise response - identifies scanners vs targeted attacks"""
        noise = raw_data.get('noise', False)
        riot = raw_data.get('riot', False)  # Rule It Out Test - known benign
        classification = raw_data.get('classification', 'unknown')
        name = raw_data.get('name', '')

        # GreyNoise classifications: benign, malicious, unknown
        if riot:
            # RIOT = known good (CDNs, cloud providers, etc.)
            verdict = ReputationVerdict.CLEAN
            threat_score = 0
        elif classification == 'malicious':
            verdict = ReputationVerdict.MALICIOUS
            threat_score = 85
        elif classification == 'benign':
            verdict = ReputationVerdict.CLEAN
            threat_score = 10
        elif noise:
            # Internet background noise (scanners, but not necessarily malicious)
            verdict = ReputationVerdict.SUSPICIOUS
            threat_score = 40
        else:
            verdict = ReputationVerdict.UNKNOWN
            threat_score = None

        tags = []
        if noise:
            tags.append('internet_scanner')
        if riot:
            tags.append('known_benign')
        if name:
            tags.append(f"actor:{name}")

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='greynoise',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.85 if classification != 'unknown' else 0.5,
            raw_data=raw_data,
            tags=tags,
            categories=[classification] if classification != 'unknown' else []
        )

    def _parse_ipinfo(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse IPinfo response - geolocation and ASN context (not threat scoring)"""
        # IPinfo provides context, not threat scores
        # We use it to add geolocation and ASN info
        country = raw_data.get('country', '')
        city = raw_data.get('city', '')
        org = raw_data.get('org', '')  # Usually "ASXXXX OrgName"
        hostname = raw_data.get('hostname', '')
        is_anycast = raw_data.get('anycast', False)

        # Extract ASN from org field
        asn = ''
        if org and org.startswith('AS'):
            asn = org.split(' ')[0]

        tags = []
        if country:
            tags.append(f"country:{country}")
        if asn:
            tags.append(f"asn:{asn}")
        if is_anycast:
            tags.append('anycast')
        if hostname:
            tags.append(f"hostname:{hostname}")

        # IPinfo is enrichment, not threat intel - mark as unknown verdict
        # but still provide valuable context
        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='ipinfo',
            verdict=ReputationVerdict.UNKNOWN,  # IPinfo doesn't do threat scoring
            threat_score=None,
            confidence=0.95,  # High confidence in the data accuracy
            raw_data=raw_data,
            tags=tags,
            categories=[org] if org else []
        )

    def _parse_rdap(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse RDAP response - Registration Data Access Protocol (ARIN/Verisign)

        RDAP provides structured JSON registration data for IPs and domains.
        This is context/enrichment data, not threat scoring.
        """
        tags = []

        # Handle RDAP error responses
        if raw_data.get('errorCode'):
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='rdap',
                verdict=ReputationVerdict.UNKNOWN,
                threat_score=None,
                confidence=0.5,
                raw_data=raw_data,
                tags=['rdap_error']
            )

        # Extract common RDAP fields
        handle = raw_data.get('handle', '')
        name = raw_data.get('name', '')

        # For IP networks - extract network info
        if 'startAddress' in raw_data or 'cidr0_cidrs' in raw_data:
            start_addr = raw_data.get('startAddress', '')
            end_addr = raw_data.get('endAddress', '')

            # Get CIDR
            cidrs = raw_data.get('cidr0_cidrs', [])
            if cidrs:
                cidr_str = f"{cidrs[0].get('v4prefix', '')}/{cidrs[0].get('length', '')}"
                tags.append(f"cidr:{cidr_str}")
            elif start_addr and end_addr:
                tags.append(f"range:{start_addr}-{end_addr}")

            if handle:
                tags.append(f"handle:{handle}")
            if name:
                tags.append(f"netname:{name}")

            # Extract organization from entities
            entities = raw_data.get('entities', [])
            org_name = None
            abuse_email = None

            for entity in entities:
                roles = entity.get('roles', [])
                vcard = entity.get('vcardArray', [None, []])[1] if entity.get('vcardArray') else []

                # Extract organization name
                if 'registrant' in roles or not org_name:
                    for item in vcard:
                        if item[0] == 'fn':
                            org_name = item[3] if len(item) > 3 else None
                            break

                # Extract abuse email
                if 'abuse' in roles:
                    for item in vcard:
                        if item[0] == 'email':
                            abuse_email = item[3] if len(item) > 3 else None
                            break
                    # Also check nested entities
                    for sub_entity in entity.get('entities', []):
                        sub_vcard = sub_entity.get('vcardArray', [None, []])[1] if sub_entity.get('vcardArray') else []
                        for item in sub_vcard:
                            if item[0] == 'email':
                                abuse_email = item[3] if len(item) > 3 else None
                                break

            if org_name:
                tags.append(f"org:{org_name}")
            if abuse_email:
                tags.append(f"abuse:{abuse_email}")

            # Get network type
            net_type = raw_data.get('type', '')
            if net_type:
                tags.append(f"nettype:{net_type}")

            # Check for country
            country = raw_data.get('country', '')
            if country:
                tags.append(f"country:{country}")

        # For domains - extract registrar and dates
        elif 'ldhName' in raw_data:
            domain_name = raw_data.get('ldhName', '')
            status = raw_data.get('status', [])

            if domain_name:
                tags.append(f"domain:{domain_name}")

            # Domain status
            for s in status[:3]:  # Limit to first 3
                tags.append(f"status:{s}")

            # Events (creation, expiration, etc.)
            events = raw_data.get('events', [])
            for event in events:
                action = event.get('eventAction', '')
                date = event.get('eventDate', '')
                if action and date:
                    # Just get the date part
                    date_only = date.split('T')[0] if 'T' in date else date
                    tags.append(f"{action}:{date_only}")

            # Name servers
            nameservers = raw_data.get('nameservers', [])
            for ns in nameservers[:2]:  # First 2 nameservers
                ns_name = ns.get('ldhName', '')
                if ns_name:
                    tags.append(f"ns:{ns_name}")

            # Registrar from entities
            entities = raw_data.get('entities', [])
            for entity in entities:
                roles = entity.get('roles', [])
                if 'registrar' in roles:
                    vcard = entity.get('vcardArray', [None, []])[1] if entity.get('vcardArray') else []
                    for item in vcard:
                        if item[0] == 'fn':
                            registrar = item[3] if len(item) > 3 else None
                            if registrar:
                                tags.append(f"registrar:{registrar}")
                            break

        # RDAP is enrichment/context, not threat intel
        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='rdap',
            verdict=ReputationVerdict.UNKNOWN,  # RDAP doesn't score threats
            threat_score=None,
            confidence=0.95,  # High confidence in data accuracy (authoritative source)
            raw_data=raw_data,
            tags=tags[:20],  # Limit tags
            categories=[]
        )

    def _parse_urlhaus(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse URLhaus response - malware URL database"""
        query_status = raw_data.get('query_status', '')

        if query_status == 'no_results':
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='urlhaus',
                verdict=ReputationVerdict.CLEAN,
                threat_score=0,
                confidence=0.7,
                raw_data=raw_data,
                tags=['not_in_urlhaus']
            )

        # URL is in URLhaus database = malicious
        url_status = raw_data.get('url_status', '')
        threat = raw_data.get('threat', '')
        tags_list = raw_data.get('tags', [])

        if url_status == 'online':
            verdict = ReputationVerdict.MALICIOUS
            threat_score = 95
        elif url_status == 'offline':
            verdict = ReputationVerdict.MALICIOUS
            threat_score = 70  # Still malicious, but offline
        else:
            verdict = ReputationVerdict.SUSPICIOUS
            threat_score = 60

        tags = list(tags_list) if tags_list else []
        if threat:
            tags.append(f"threat:{threat}")
        tags.append(f"status:{url_status}")

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='urlhaus',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.9,
            raw_data=raw_data,
            tags=tags,
            categories=[threat] if threat else []
        )

    def _parse_malwarebazaar(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse MalwareBazaar response - malware sample database"""
        query_status = raw_data.get('query_status', '')

        if query_status == 'hash_not_found' or query_status == 'no_results':
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='malwarebazaar',
                verdict=ReputationVerdict.CLEAN,
                threat_score=5,  # Not 0, since absence of evidence isn't proof
                confidence=0.6,
                raw_data=raw_data,
                tags=['not_in_malwarebazaar']
            )

        # Hash found in MalwareBazaar = confirmed malware
        data = raw_data.get('data', [{}])
        sample = data[0] if data else {}

        signature = sample.get('signature', '')
        file_type = sample.get('file_type', '')
        tags_list = sample.get('tags', [])
        reporter = sample.get('reporter', '')

        tags = list(tags_list) if tags_list else []
        if signature:
            tags.append(f"signature:{signature}")
        if file_type:
            tags.append(f"filetype:{file_type}")

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='malwarebazaar',
            verdict=ReputationVerdict.MALICIOUS,
            threat_score=95,  # If it's in MalwareBazaar, it's malware
            confidence=0.95,
            raw_data=raw_data,
            tags=tags,
            categories=[signature] if signature else []
        )

    def _parse_otx(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse AlienVault OTX response"""
        pulse_count = raw_data.get('pulse_info', {}).get('count', 0)
        pulses = raw_data.get('pulse_info', {}).get('pulses', [])

        # OTX pulses are community-contributed intel -- high pulse counts
        # are common for popular infrastructure and don't mean malicious.
        # Only flag as suspicious at very high counts; never auto-malicious.
        if pulse_count >= 50:
            verdict = ReputationVerdict.SUSPICIOUS
            threat_score = 45
        elif pulse_count >= 20:
            verdict = ReputationVerdict.SUSPICIOUS
            threat_score = 35
        elif pulse_count >= 5:
            verdict = ReputationVerdict.UNKNOWN
            threat_score = 20
        elif pulse_count >= 1:
            verdict = ReputationVerdict.UNKNOWN
            threat_score = 10
        else:
            verdict = ReputationVerdict.CLEAN
            threat_score = 0

        # Extract tags from pulse names/tags
        tags = [f"pulses:{pulse_count}"]
        categories = []
        for pulse in pulses[:5]:
            if pulse.get('name'):
                categories.append(pulse['name'][:50])
            for tag in pulse.get('tags', [])[:3]:
                if tag not in tags:
                    tags.append(tag)

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='otx',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.75 if pulse_count > 0 else 0.5,
            raw_data=raw_data,
            tags=tags[:15],
            categories=categories[:5]
        )

    def _parse_urlscan(
        self,
        value: str,
        ioc_type: IOCType,
        raw_data: Dict[str, Any]
    ) -> EnrichmentResult:
        """Parse URLScan.io response - URL scanning and phishing detection"""
        results = raw_data.get('results', [])

        if not results:
            # No scans found for this URL
            return EnrichmentResult(
                ioc_value=value,
                ioc_type=ioc_type,
                provider='urlscan',
                verdict=ReputationVerdict.UNKNOWN,
                threat_score=10,  # Unknown - no prior data
                confidence=0.3,
                raw_data=raw_data,
                tags=['no_prior_scans']
            )

        # Analyze results for malicious indicators
        malicious_count = 0
        phishing_count = 0
        total_scans = len(results)
        tags = []
        categories = []

        for scan in results[:10]:  # Check up to 10 recent scans
            task = scan.get('task', {})
            verdicts = scan.get('verdicts', {}) or {}

            # Check verdicts from various engines
            overall_verdict = verdicts.get('overall', {})
            urlscan_verdict = verdicts.get('urlscan', {})

            if overall_verdict.get('malicious') or urlscan_verdict.get('malicious'):
                malicious_count += 1

            # Check for phishing tags
            scan_tags = task.get('tags', [])
            for tag in scan_tags:
                tag_lower = tag.lower()
                if 'phishing' in tag_lower:
                    phishing_count += 1
                if tag not in tags:
                    tags.append(tag)

            # Check for categories
            page = scan.get('page', {})
            scan_categories = verdicts.get('engines', {}).get('categories', [])
            for cat in scan_categories:
                if cat not in categories:
                    categories.append(cat)

        # Determine verdict based on scan results
        if malicious_count > 0 or phishing_count > 0:
            verdict = ReputationVerdict.MALICIOUS
            threat_score = min(95, 60 + malicious_count * 10 + phishing_count * 15)
        elif total_scans > 2:
            # Multiple scans exist but none flagged as malicious
            verdict = ReputationVerdict.CLEAN
            threat_score = 10
        else:
            verdict = ReputationVerdict.UNKNOWN
            threat_score = 30  # Single scan, uncertain

        # Add summary tags
        if phishing_count > 0:
            tags.insert(0, f"phishing:{phishing_count}")
        if malicious_count > 0:
            tags.insert(0, f"malicious_scans:{malicious_count}")
        tags.append(f"total_scans:{total_scans}")

        return EnrichmentResult(
            ioc_value=value,
            ioc_type=ioc_type,
            provider='urlscan',
            verdict=verdict,
            threat_score=threat_score,
            confidence=0.75 if total_scans > 1 else 0.5,
            raw_data=raw_data,
            tags=tags[:15],
            categories=categories[:5]
        )

    # Provider reliability weights (how much to trust each source)
    # Higher = more trusted for threat intelligence
    PROVIDER_WEIGHTS = {
        'virustotal': 1.0,       # Gold standard, aggregates 70+ engines
        'malwarebazaar': 0.95,   # Highly reliable for malware hashes
        'abuseipdb': 0.85,       # Community-driven, good for IPs
        'urlhaus': 0.90,         # Reliable malware URL database
        'urlscan': 0.85,         # Good for URL/phishing analysis
        'otx': 0.75,             # Good community intel
        'greynoise': 0.80,       # Great for scanner detection
        'shodan': 0.60,          # Context provider, not threat scorer
        'ipinfo': 0.0,           # Pure enrichment, no threat scoring
    }

    def _build_threat_report(
        self,
        ioc: IOC,
        enrichments: List[EnrichmentResult]
    ) -> ThreatIntelReport:
        """Build consolidated threat report from enrichments with weighted scoring"""
        if not enrichments:
            return ThreatIntelReport(ioc=ioc)

        # Filter enrichments that provide threat scores (not pure context)
        threat_enrichments = [
            e for e in enrichments
            if e.verdict != ReputationVerdict.UNKNOWN and self.PROVIDER_WEIGHTS.get(e.provider, 0.5) > 0
        ]

        # Calculate weighted consensus score
        consensus_score = self._calculate_weighted_score(enrichments)

        # Calculate weighted verdict
        consensus_verdict = self._calculate_weighted_verdict(threat_enrichments)

        # Count flagged sources
        malicious_count = sum(1 for e in threat_enrichments if e.verdict == ReputationVerdict.MALICIOUS)
        suspicious_count = sum(1 for e in threat_enrichments if e.verdict == ReputationVerdict.SUSPICIOUS)

        return ThreatIntelReport(
            ioc=ioc,
            enrichments=enrichments,
            consensus_verdict=consensus_verdict,
            consensus_score=consensus_score,
            sources_checked=len(enrichments),
            sources_flagged=malicious_count + suspicious_count
        )

    def _calculate_weighted_score(self, enrichments: List[EnrichmentResult]) -> Optional[int]:
        """Calculate weighted average score across providers"""
        weighted_sum = 0.0
        weight_total = 0.0

        for e in enrichments:
            if e.threat_score is not None:
                provider_weight = self.PROVIDER_WEIGHTS.get(e.provider, 0.5)
                confidence_weight = e.confidence if e.confidence else 0.5

                # Combined weight = provider reliability * result confidence
                combined_weight = provider_weight * confidence_weight

                if combined_weight > 0:
                    weighted_sum += e.threat_score * combined_weight
                    weight_total += combined_weight

        if weight_total > 0:
            return int(weighted_sum / weight_total)
        return None

    def _calculate_weighted_verdict(self, enrichments: List[EnrichmentResult]) -> ReputationVerdict:
        """Calculate consensus verdict using weighted voting"""
        if not enrichments:
            return ReputationVerdict.UNKNOWN

        # Verdict scores: malicious=2, suspicious=1, clean=0, unknown=ignored
        verdict_scores = {
            ReputationVerdict.MALICIOUS: 2.0,
            ReputationVerdict.SUSPICIOUS: 1.0,
            ReputationVerdict.CLEAN: 0.0,
        }

        weighted_score = 0.0
        weight_total = 0.0

        for e in enrichments:
            if e.verdict in verdict_scores:
                provider_weight = self.PROVIDER_WEIGHTS.get(e.provider, 0.5)
                confidence_weight = e.confidence if e.confidence else 0.5
                combined_weight = provider_weight * confidence_weight

                if combined_weight > 0:
                    weighted_score += verdict_scores[e.verdict] * combined_weight
                    weight_total += combined_weight

        if weight_total == 0:
            return ReputationVerdict.UNKNOWN

        # Normalize to 0-2 range
        normalized_score = weighted_score / weight_total

        # Determine verdict based on normalized score
        # 1.5+ = malicious, 0.7-1.5 = suspicious, <0.7 = clean
        if normalized_score >= 1.5:
            return ReputationVerdict.MALICIOUS
        elif normalized_score >= 0.7:
            return ReputationVerdict.SUSPICIOUS
        else:
            return ReputationVerdict.CLEAN

    async def _update_ioc_from_enrichments(
        self,
        ioc: IOC,
        enrichments: List[EnrichmentResult],
        trigger: Optional[EnrichmentTrigger] = None
    ) -> None:
        """Update IOC record with aggregated enrichment data and enrichment tracking"""
        if not enrichments:
            return

        db = self._get_db()
        if not db or not db.pool:
            return

        # Aggregate data
        all_tags = set(ioc.tags)
        for e in enrichments:
            all_tags.update(e.tags)

        # Calculate overall severity
        scores = [e.threat_score for e in enrichments if e.threat_score is not None]
        avg_score = sum(scores) / len(scores) if scores else None

        if avg_score:
            if avg_score >= 80:
                severity = ThreatSeverity.CRITICAL
            elif avg_score >= 60:
                severity = ThreatSeverity.HIGH
            elif avg_score >= 40:
                severity = ThreatSeverity.MEDIUM
            elif avg_score >= 20:
                severity = ThreatSeverity.LOW
            else:
                severity = ThreatSeverity.UNKNOWN
        else:
            severity = ioc.severity

        # Determine reputation
        verdicts = [e.verdict for e in enrichments if e.verdict != ReputationVerdict.UNKNOWN]
        if any(v == ReputationVerdict.MALICIOUS for v in verdicts):
            reputation = 'malicious'
        elif any(v == ReputationVerdict.SUSPICIOUS for v in verdicts):
            reputation = 'suspicious'
        elif verdicts:
            reputation = 'clean'
        else:
            reputation = None

        try:
            async with db.tenant_acquire() as conn:
                # Merge enrichment data
                enrichment_data = {}
                for e in enrichments:
                    enrichment_data[e.provider] = {
                        'verdict': e.verdict.value if isinstance(e.verdict, ReputationVerdict) else e.verdict,
                        'score': e.threat_score,
                        'enriched_at': e.enriched_at.isoformat()
                    }

                # Update IOC with enrichment data and tracking fields
                await conn.execute(
                    """
                    UPDATE iocs SET
                        severity = COALESCE($1, severity),
                        reputation = COALESCE($2, reputation),
                        confidence = $3,
                        tags = $4,
                        enrichment_data = enrichment_data || $5::jsonb,
                        last_enriched_at = $8,
                        enrichment_trigger = $9
                    WHERE ioc_value = $6 AND ioc_type = $7
                    """,
                    severity.value if isinstance(severity, ThreatSeverity) else severity,
                    reputation,
                    avg_score,
                    list(all_tags),
                    json.dumps(enrichment_data),
                    ioc.value,
                    ioc.type.value if isinstance(ioc.type, IOCType) else ioc.type,
                    datetime.utcnow(),
                    trigger.value if trigger else None
                )
        except Exception as e:
            logger.error(f"Failed to update IOC from enrichments: {e}")

    # ========================================================================
    # CORRELATION
    # ========================================================================

    async def correlate_iocs(
        self,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Find correlations between IOCs in an alert/investigation
        and other alerts/investigations.
        """
        db = self._get_db()
        if not db or not db.pool:
            return {"correlations": []}

        correlations = []

        try:
            async with db.tenant_acquire() as conn:
                # Get IOCs from the target alert/investigation
                if alert_id:
                    # Extract IOCs from alert raw_event
                    alert = await conn.fetchrow(
                        "SELECT raw_event FROM alerts WHERE alert_id = $1",
                        alert_id
                    )
                    if alert:
                        # Parse IOCs from raw event (simplified)
                        iocs = self._extract_iocs_from_event(alert['raw_event'])
                elif investigation_id:
                    # Get IOCs linked to investigation
                    # (Would need an investigation_iocs join table)
                    pass

                # For each IOC, find other alerts with same IOC
                # This is a simplified example

        except Exception as e:
            logger.error(f"Correlation failed: {e}")

        return {"correlations": correlations}

    def _extract_iocs_from_event(self, raw_event: Dict) -> List[Tuple[str, IOCType]]:
        """Extract IOCs from a raw event (simplified)"""
        import re

        iocs = []
        text = json.dumps(raw_event)

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, text):
            # Skip invalid IPs with leading zeros (e.g., 01.24.04.57)
            parts = ip.split('.')
            if any(len(p) > 1 and p.startswith('0') for p in parts):
                continue
            if not ip.startswith('10.') and not ip.startswith('192.168.'):
                iocs.append((ip, IOCType.IP))

        # Domains (simplified)
        domain_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'
        for domain in re.findall(domain_pattern, text):
            if '.' in domain and len(domain) > 4:
                iocs.append((domain, IOCType.DOMAIN))

        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for hash_val in re.findall(sha256_pattern, text):
            iocs.append((hash_val.lower(), IOCType.HASH_SHA256))

        return list(set(iocs))[:50]  # Limit to 50 IOCs

    # ========================================================================
    # STATISTICS
    # ========================================================================

    # ========================================================================
    # DELETE / UPDATE IOC
    # ========================================================================

    async def delete_ioc(
        self,
        value: str,
        ioc_type: Optional[IOCType] = None
    ) -> bool:
        """
        Delete an IOC by value (and optionally type).

        Args:
            value: The IOC value to delete
            ioc_type: Optional type for disambiguation if multiple IOCs have same value

        Returns:
            True if IOC was deleted, False if not found
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    if ioc_type:
                        result = await conn.execute(
                            "DELETE FROM iocs WHERE ioc_value = $1 AND ioc_type = $2",
                            value, ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type
                        )
                    else:
                        result = await conn.execute(
                            "DELETE FROM iocs WHERE ioc_value = $1",
                            value
                        )

                    # Also clean up related data
                    await conn.execute(
                        "DELETE FROM ioc_feed_appearances WHERE ioc_value = $1",
                        value
                    )
                    await conn.execute(
                        "DELETE FROM enrichment_cache WHERE ioc_value = $1",
                        value
                    )

                    # Check if any rows were deleted
                    deleted_count = int(result.split()[-1]) if result else 0
                    return deleted_count > 0

            except Exception as e:
                logger.error(f"Failed to delete IOC: {e}")
                raise

        return False

    async def update_ioc(
        self,
        value: str,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        tags_add: Optional[List[str]] = None,
        tags_remove: Optional[List[str]] = None,
        ioc_type: Optional[IOCType] = None
    ) -> Optional[IOC]:
        """
        Update an IOC's verdict, severity, and/or tags.

        Args:
            value: The IOC value to update
            verdict: New verdict (clean, suspicious, malicious, unknown)
            severity: New severity (low, medium, high, critical, unknown)
            tags_add: Tags to add
            tags_remove: Tags to remove
            ioc_type: Optional type for disambiguation

        Returns:
            Updated IOC or None if not found
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Build dynamic update query
                    set_clauses = []
                    params = []
                    param_idx = 1

                    if verdict:
                        set_clauses.append(f"reputation = ${param_idx}")
                        params.append(verdict)
                        param_idx += 1

                    if severity:
                        set_clauses.append(f"severity = ${param_idx}")
                        params.append(severity)
                        param_idx += 1

                    if tags_add:
                        set_clauses.append(f"tags = ARRAY(SELECT DISTINCT unnest(array_cat(tags, ${param_idx}::text[])))")
                        params.append(tags_add)
                        param_idx += 1

                    if tags_remove:
                        set_clauses.append(f"tags = array(SELECT unnest(tags) EXCEPT SELECT unnest(${param_idx}::text[]))")
                        params.append(tags_remove)
                        param_idx += 1

                    if not set_clauses:
                        # No updates to make, just return the existing IOC
                        return await self.get_ioc(value, ioc_type)

                    # Add WHERE clause params
                    params.append(value)
                    value_param = param_idx
                    param_idx += 1

                    where_clause = f"ioc_value = ${value_param}"

                    if ioc_type:
                        params.append(ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type)
                        where_clause += f" AND ioc_type = ${param_idx}"

                    query = f"""
                        UPDATE iocs SET {', '.join(set_clauses)}
                        WHERE {where_clause}
                        RETURNING *
                    """

                    row = await conn.fetchrow(query, *params)

                    if row:
                        return self._row_to_ioc(row)
                    return None

            except Exception as e:
                logger.error(f"Failed to update IOC: {e}")
                raise

        return None

    async def get_stats(self) -> Dict[str, Any]:
        """Get threat intel statistics including detailed cache metrics.

        Uses a single combined query to reduce round-trips to the database.
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Combined IOC stats query (type + severity in one pass)
                    ioc_combined = await conn.fetch(
                        """
                        SELECT ioc_type, severity, COUNT(*) as count
                        FROM iocs
                        GROUP BY ioc_type, severity
                        """
                    )

                    # Derive type and severity counts from combined result
                    type_counts_map: Dict[str, int] = {}
                    severity_counts_map: Dict[str, int] = {}
                    for r in ioc_combined:
                        t = r['ioc_type']
                        s = r['severity']
                        c = r['count']
                        type_counts_map[t] = type_counts_map.get(t, 0) + c
                        if s:
                            severity_counts_map[s] = severity_counts_map.get(s, 0) + c

                    # Combined cache stats (single query for all cache metrics)
                    cache_combined = await conn.fetch(
                        """
                        SELECT
                            provider, ioc_type,
                            COUNT(*) as count,
                            SUM(hit_count) as hits,
                            COUNT(CASE WHEN is_malicious THEN 1 END) as malicious,
                            COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired,
                            COUNT(CASE WHEN expires_at > NOW() AND expires_at <= NOW() + INTERVAL '7 days' THEN 1 END) as expiring_soon,
                            MAX(cached_at) as last_cache_time,
                            MIN(cached_at) as oldest_cache_time
                        FROM enrichment_cache
                        GROUP BY provider, ioc_type
                        """
                    )

                    # Derive all cache stats from combined result
                    total_cached = 0
                    total_hits = 0
                    total_malicious = 0
                    total_expired = 0
                    total_expiring_soon = 0
                    last_cache_time = None
                    oldest_cache_time = None
                    provider_stats_map: Dict[str, Dict] = {}
                    ioc_type_cache_map: Dict[str, Dict] = {}

                    for r in cache_combined:
                        c = r['count']
                        h = r['hits'] or 0
                        m = r['malicious'] or 0
                        total_cached += c
                        total_hits += h
                        total_malicious += m
                        total_expired += r['expired'] or 0
                        total_expiring_soon += r['expiring_soon'] or 0

                        if r['last_cache_time']:
                            if last_cache_time is None or r['last_cache_time'] > last_cache_time:
                                last_cache_time = r['last_cache_time']
                        if r['oldest_cache_time']:
                            if oldest_cache_time is None or r['oldest_cache_time'] < oldest_cache_time:
                                oldest_cache_time = r['oldest_cache_time']

                        # Active entries only for provider/type breakdowns
                        active_count = c - (r['expired'] or 0)
                        if active_count > 0:
                            p = r['provider']
                            if p not in provider_stats_map:
                                provider_stats_map[p] = {"count": 0, "hits": 0, "malicious": 0}
                            provider_stats_map[p]["count"] += active_count
                            provider_stats_map[p]["hits"] += h
                            provider_stats_map[p]["malicious"] += m

                            t = r['ioc_type']
                            if t not in ioc_type_cache_map:
                                ioc_type_cache_map[t] = {"count": 0, "hits": 0}
                            ioc_type_cache_map[t]["count"] += active_count
                            ioc_type_cache_map[t]["hits"] += h

                    hit_rate = round((total_hits / max(total_hits + total_cached, 1)) * 100, 1)
                    avg_hits = round(total_hits / max(total_cached, 1), 2)

                    return {
                        "iocs": {
                            "total": sum(type_counts_map.values()),
                            "by_type": type_counts_map,
                            "by_severity": severity_counts_map
                        },
                        "cache": {
                            "total_cached": total_cached,
                            "active_entries": total_cached - total_expired,
                            "expired_entries": total_expired,
                            "expiring_soon": total_expiring_soon,
                            "total_hits": total_hits,
                            "hit_rate_percent": hit_rate,
                            "avg_hits_per_entry": avg_hits,
                            "malicious_cached": total_malicious,
                            "last_cache_time": last_cache_time.isoformat() if last_cache_time else None,
                            "oldest_cache_time": oldest_cache_time.isoformat() if oldest_cache_time else None,
                            "by_provider": provider_stats_map,
                            "by_ioc_type": ioc_type_cache_map
                        }
                    }
            except Exception as e:
                logger.error(f"Failed to get stats: {e}")

        return {"iocs": {"total": 0}, "cache": {"total_cached": 0}}

    async def cleanup_expired_cache(self) -> Dict[str, Any]:
        """
        Remove expired cache entries.

        Returns count of deleted entries and reclaimed space estimate.
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Count before deletion
                    count_before = await conn.fetchval(
                        "SELECT COUNT(*) FROM enrichment_cache WHERE expires_at <= NOW()"
                    )

                    # Delete expired entries
                    result = await conn.execute(
                        "DELETE FROM enrichment_cache WHERE expires_at <= NOW()"
                    )

                    deleted_count = int(result.split()[-1]) if result else 0

                    logger.info(f"Cleaned up {deleted_count} expired cache entries")

                    return {
                        "success": True,
                        "deleted_count": deleted_count,
                        "message": f"Removed {deleted_count} expired cache entries"
                    }

            except Exception as e:
                logger.error(f"Failed to cleanup cache: {e}")
                return {"success": False, "error": str(e)}

        return {"success": False, "error": "Database not connected"}

    async def invalidate_cache(
        self,
        ioc_value: Optional[str] = None,
        ioc_type: Optional[str] = None,
        provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Invalidate (delete) cache entries matching criteria.

        Args:
            ioc_value: Specific IOC value to invalidate
            ioc_type: IOC type to invalidate (e.g., 'ip', 'domain')
            provider: Provider to invalidate (e.g., 'virustotal')

        If no arguments provided, returns error (use cleanup_expired_cache for bulk cleanup).
        """
        db = self._get_db()

        if not any([ioc_value, ioc_type, provider]):
            return {"success": False, "error": "Must specify at least one filter (ioc_value, ioc_type, or provider)"}

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Build dynamic query based on filters
                    conditions = []
                    params = []
                    param_idx = 1

                    if ioc_value:
                        conditions.append(f"ioc_value = ${param_idx}")
                        params.append(ioc_value)
                        param_idx += 1

                    if ioc_type:
                        conditions.append(f"ioc_type = ${param_idx}")
                        params.append(ioc_type)
                        param_idx += 1

                    if provider:
                        conditions.append(f"provider = ${param_idx}")
                        params.append(provider)
                        param_idx += 1

                    where_clause = " AND ".join(conditions)
                    query = f"DELETE FROM enrichment_cache WHERE {where_clause}"

                    result = await conn.execute(query, *params)
                    deleted_count = int(result.split()[-1]) if result else 0

                    logger.info(f"Invalidated {deleted_count} cache entries (filters: value={ioc_value}, type={ioc_type}, provider={provider})")

                    return {
                        "success": True,
                        "deleted_count": deleted_count,
                        "filters": {
                            "ioc_value": ioc_value,
                            "ioc_type": ioc_type,
                            "provider": provider
                        }
                    }

            except Exception as e:
                logger.error(f"Failed to invalidate cache: {e}")
                return {"success": False, "error": str(e)}

        return {"success": False, "error": "Database not connected"}

    async def get_cache_health(self) -> Dict[str, Any]:
        """
        Get detailed cache health metrics for monitoring.

        Returns expiration distribution, provider health, and recommendations.
        """
        db = self._get_db()

        if db and db.pool:
            try:
                async with db.tenant_acquire() as conn:
                    # Expiration distribution
                    expiration_dist = await conn.fetch(
                        """
                        SELECT
                            CASE
                                WHEN expires_at <= NOW() THEN 'expired'
                                WHEN expires_at <= NOW() + INTERVAL '1 day' THEN 'expiring_1d'
                                WHEN expires_at <= NOW() + INTERVAL '7 days' THEN 'expiring_7d'
                                WHEN expires_at <= NOW() + INTERVAL '30 days' THEN 'expiring_30d'
                                ELSE 'healthy'
                            END as status,
                            COUNT(*) as count
                        FROM enrichment_cache
                        GROUP BY status
                        ORDER BY count DESC
                        """
                    )

                    # Provider freshness (avg age of cache entries)
                    provider_freshness = await conn.fetch(
                        """
                        SELECT
                            provider,
                            COUNT(*) as entries,
                            AVG(EXTRACT(EPOCH FROM (NOW() - cached_at)) / 86400)::numeric(10,1) as avg_age_days,
                            MAX(cached_at) as newest,
                            MIN(cached_at) as oldest
                        FROM enrichment_cache
                        WHERE expires_at > NOW()
                        GROUP BY provider
                        """
                    )

                    # Hot IOCs (most frequently accessed)
                    hot_iocs = await conn.fetch(
                        """
                        SELECT ioc_value, ioc_type, provider, hit_count, is_malicious
                        FROM enrichment_cache
                        WHERE expires_at > NOW()
                        ORDER BY hit_count DESC
                        LIMIT 10
                        """
                    )

                    # Calculate overall health score
                    exp_dict = {r['status']: r['count'] for r in expiration_dist}
                    total = sum(exp_dict.values())
                    expired = exp_dict.get('expired', 0)
                    healthy = exp_dict.get('healthy', 0)

                    health_score = 100
                    recommendations = []

                    if total > 0:
                        expired_pct = (expired / total) * 100
                        if expired_pct > 20:
                            health_score -= 30
                            recommendations.append("High number of expired entries - run cache cleanup")
                        elif expired_pct > 10:
                            health_score -= 15
                            recommendations.append("Consider running cache cleanup")

                    if total == 0:
                        health_score = 0
                        recommendations.append("Cache is empty - enrichments will hit external APIs")

                    return {
                        "health_score": max(0, health_score),
                        "total_entries": total,
                        "expiration_distribution": {r['status']: r['count'] for r in expiration_dist},
                        "provider_freshness": {r['provider']: {
                            "entries": r['entries'],
                            "avg_age_days": float(r['avg_age_days']) if r['avg_age_days'] else 0,
                            "newest": r['newest'].isoformat() if r['newest'] else None,
                            "oldest": r['oldest'].isoformat() if r['oldest'] else None
                        } for r in provider_freshness},
                        "hot_iocs": [{
                            "value": r['ioc_value'],
                            "type": r['ioc_type'],
                            "provider": r['provider'],
                            "hits": r['hit_count'],
                            "malicious": r['is_malicious']
                        } for r in hot_iocs],
                        "recommendations": recommendations
                    }

            except Exception as e:
                logger.error(f"Failed to get cache health: {e}")
                return {"health_score": 0, "error": str(e)}

        return {"health_score": 0, "error": "Database not connected"}


    # ========================================================================
    # IOC DECONFLICTION
    # ========================================================================

    async def deconflict_ioc(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        new_verdict: ReputationVerdict,
        new_source: str,
        confidence: float = 0.5
    ) -> Dict[str, Any]:
        """
        Deconflict an IOC when multiple sources report different verdicts.

        This implements a weighted reconciliation algorithm that:
        1. Considers source reputation/authority
        2. Weighs recency of reports
        3. Applies confidence scores
        4. Resolves conflicts with documented reasoning

        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            new_verdict: Verdict from the new source
            new_source: Name of the new source
            confidence: Confidence score of the new report (0-1)

        Returns:
            Deconfliction result with final verdict and reasoning
        """
        db = self._get_db()
        if not db or not db.pool:
            return {"error": "Database not connected"}

        try:
            async with db.tenant_acquire() as conn:
                # Get existing IOC data
                existing = await conn.fetchrow('''
                    SELECT
                        ioc_value, ioc_type, reputation, severity, confidence,
                        enrichment_data, tags, first_seen, last_seen,
                        source_type, source_id, feed_name
                    FROM iocs
                    WHERE ioc_value = $1 AND ioc_type = $2
                ''', ioc_value, ioc_type.value)

                if not existing:
                    # No conflict - this is a new IOC
                    return {
                        "conflict": False,
                        "action": "create",
                        "final_verdict": new_verdict.value,
                        "reason": "New IOC, no existing data"
                    }

                existing_data = dict(existing)
                existing_verdict = existing_data.get('reputation')
                existing_confidence = existing_data.get('confidence') or 0.5
                enrichment_data = existing_data.get('enrichment_data') or {}

                # No conflict if verdicts match
                if existing_verdict == new_verdict.value:
                    return {
                        "conflict": False,
                        "action": "update",
                        "final_verdict": new_verdict.value,
                        "reason": "Verdicts match, updating timestamp"
                    }

                # CONFLICT DETECTED - apply deconfliction logic
                conflict_details = {
                    "existing_verdict": existing_verdict,
                    "existing_confidence": existing_confidence,
                    "existing_sources": list(enrichment_data.keys()),
                    "new_verdict": new_verdict.value,
                    "new_source": new_source,
                    "new_confidence": confidence
                }

                # Calculate weighted scores for each verdict
                verdict_weights = await self._calculate_verdict_weights(
                    existing_verdict,
                    existing_confidence,
                    enrichment_data,
                    new_verdict.value,
                    new_source,
                    confidence
                )

                # Determine final verdict based on weights
                final_verdict, final_confidence, reasoning = self._resolve_conflict(
                    verdict_weights,
                    existing_verdict,
                    new_verdict.value
                )

                # Log the deconfliction decision
                await self._log_deconfliction(
                    conn,
                    ioc_value,
                    ioc_type,
                    existing_verdict,
                    new_verdict.value,
                    new_source,
                    final_verdict,
                    reasoning
                )

                # Apply the deconflicted verdict if different
                if final_verdict != existing_verdict:
                    await conn.execute('''
                        UPDATE iocs
                        SET reputation = $1,
                            confidence = $2,
                            last_seen = CURRENT_TIMESTAMP,
                            tags = array_append(
                                array_remove(tags, 'deconflicted'),
                                'deconflicted'
                            )
                        WHERE ioc_value = $3 AND ioc_type = $4
                    ''', final_verdict, final_confidence, ioc_value, ioc_type.value)

                return {
                    "conflict": True,
                    "action": "deconflict",
                    "conflict_details": conflict_details,
                    "final_verdict": final_verdict,
                    "final_confidence": final_confidence,
                    "reason": reasoning,
                    "verdict_weights": verdict_weights
                }

        except Exception as e:
            logger.error(f"IOC deconfliction failed: {e}")
            return {"error": str(e)}

    async def _calculate_verdict_weights(
        self,
        existing_verdict: str,
        existing_confidence: float,
        enrichment_data: Dict[str, Any],
        new_verdict: str,
        new_source: str,
        new_confidence: float
    ) -> Dict[str, float]:
        """
        Calculate weighted scores for each possible verdict.

        Weights are based on:
        - Source reliability (PROVIDER_WEIGHTS)
        - Recency of reports
        - Confidence scores
        - Number of agreeing sources
        """
        verdict_weights = {
            'malicious': 0.0,
            'suspicious': 0.0,
            'clean': 0.0,
            'unknown': 0.0
        }

        # Map verdict strings to weight buckets
        verdict_values = {
            'malicious': 1.0,
            'suspicious': 0.5,
            'clean': 0.0,
            'unknown': 0.25
        }

        # Process existing enrichment data
        for source, data in enrichment_data.items():
            source_verdict = data.get('verdict', 'unknown')
            source_weight = self.PROVIDER_WEIGHTS.get(source, 0.5)

            # Apply time decay (older reports get less weight)
            enriched_at = data.get('enriched_at')
            recency_factor = 1.0
            if enriched_at:
                try:
                    enriched_time = datetime.fromisoformat(enriched_at.replace('Z', '+00:00'))
                    age_days = (datetime.utcnow().replace(tzinfo=enriched_time.tzinfo) - enriched_time).days
                    # Decay: 100% at 0 days, 50% at 30 days, 25% at 90 days
                    recency_factor = max(0.25, 1.0 - (age_days / 90))
                except:
                    pass

            # Add weight to the verdict bucket
            combined_weight = source_weight * recency_factor
            if source_verdict in verdict_weights:
                verdict_weights[source_verdict] += combined_weight

        # Add the new source's weight
        new_source_weight = self.PROVIDER_WEIGHTS.get(new_source, 0.5)
        combined_new_weight = new_source_weight * new_confidence
        if new_verdict in verdict_weights:
            verdict_weights[new_verdict] += combined_new_weight

        return verdict_weights

    def _resolve_conflict(
        self,
        weights: Dict[str, float],
        existing_verdict: str,
        new_verdict: str
    ) -> Tuple[str, float, str]:
        """
        Resolve the conflict based on calculated weights.

        Returns: (final_verdict, confidence, reasoning)
        """
        # Find the verdict with highest weight
        max_weight = max(weights.values())
        if max_weight == 0:
            return existing_verdict, 0.5, "No weighted data available, keeping existing verdict"

        # Get all verdicts with max weight
        top_verdicts = [v for v, w in weights.items() if w == max_weight]

        if len(top_verdicts) == 1:
            final_verdict = top_verdicts[0]
            total_weight = sum(weights.values())
            confidence = weights[final_verdict] / total_weight if total_weight > 0 else 0.5

            if final_verdict == existing_verdict:
                reasoning = f"Existing verdict '{existing_verdict}' confirmed with weight {weights[final_verdict]:.2f}"
            elif final_verdict == new_verdict:
                reasoning = f"New verdict '{new_verdict}' overrides with weight {weights[final_verdict]:.2f}"
            else:
                reasoning = f"Consensus verdict '{final_verdict}' with weight {weights[final_verdict]:.2f}"

            return final_verdict, confidence, reasoning

        else:
            # Tie-breaker: prefer malicious > suspicious > existing > clean
            priority = ['malicious', 'suspicious', 'unknown', 'clean']
            for v in priority:
                if v in top_verdicts:
                    confidence = 0.6  # Lower confidence due to tie
                    reasoning = f"Tie between {top_verdicts}, resolved to '{v}' by security priority"
                    return v, confidence, reasoning

            # Fallback
            return existing_verdict, 0.5, "Could not resolve conflict, keeping existing"

    async def _log_deconfliction(
        self,
        conn,
        ioc_value: str,
        ioc_type: IOCType,
        old_verdict: str,
        new_source_verdict: str,
        new_source: str,
        final_verdict: str,
        reasoning: str
    ):
        """Log deconfliction decisions to audit trail"""
        try:
            from middleware.tenant_middleware import get_optional_tenant_id
            _tenant_id = get_optional_tenant_id()

            await conn.execute('''
                INSERT INTO audit_log (username, action, resource_type, resource_id, details, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
            ''',
                'SYSTEM:Deconfliction',
                'ioc_deconflict',
                'ioc',
                f"{ioc_type.value}:{ioc_value[:50]}",
                json.dumps({
                    'ioc_value': ioc_value,
                    'ioc_type': ioc_type.value,
                    'old_verdict': old_verdict,
                    'new_source': new_source,
                    'new_source_verdict': new_source_verdict,
                    'final_verdict': final_verdict,
                    'reasoning': reasoning,
                    'timestamp': datetime.utcnow().isoformat()
                }),
                uuid.UUID(str(_tenant_id)) if _tenant_id else None
            )
        except Exception as e:
            logger.warning(f"Failed to log deconfliction: {e}")

    async def bulk_deconflict(
        self,
        iocs: List[Tuple[str, IOCType, ReputationVerdict, str, float]]
    ) -> Dict[str, Any]:
        """
        Deconflict multiple IOCs in bulk.

        Args:
            iocs: List of (ioc_value, ioc_type, verdict, source, confidence)

        Returns:
            Summary of deconfliction results
        """
        results = {
            'total': len(iocs),
            'conflicts': 0,
            'resolved': 0,
            'errors': 0,
            'details': []
        }

        for ioc_value, ioc_type, verdict, source, confidence in iocs:
            try:
                result = await self.deconflict_ioc(
                    ioc_value, ioc_type, verdict, source, confidence
                )

                if result.get('conflict'):
                    results['conflicts'] += 1
                    results['resolved'] += 1
                    results['details'].append({
                        'ioc': ioc_value,
                        'type': ioc_type.value,
                        'result': result.get('final_verdict'),
                        'reason': result.get('reason')
                    })
                elif result.get('error'):
                    results['errors'] += 1

            except Exception as e:
                results['errors'] += 1
                logger.error(f"Bulk deconflict error for {ioc_value}: {e}")

        return results

    async def get_deconfliction_history(
        self,
        ioc_value: Optional[str] = None,
        ioc_type: Optional[IOCType] = None,
        days: int = 30,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get history of deconfliction decisions.

        Useful for auditing and understanding verdict changes over time.
        """
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                query_parts = ['''
                    SELECT created_at, resource_id, details
                    FROM audit_log
                    WHERE action = 'ioc_deconflict'
                      AND created_at >= CURRENT_TIMESTAMP - INTERVAL '$1 days'
                ''']
                params = [days]
                param_idx = 2

                if ioc_value:
                    query_parts.append(f"AND details->>'ioc_value' = ${param_idx}")
                    params.append(ioc_value)
                    param_idx += 1

                if ioc_type:
                    query_parts.append(f"AND details->>'ioc_type' = ${param_idx}")
                    params.append(ioc_type.value)
                    param_idx += 1

                query_parts.append(f"ORDER BY created_at DESC LIMIT ${param_idx}")
                params.append(limit)

                # Build query with interval properly
                base_query = '''
                    SELECT created_at, resource_id, details
                    FROM audit_log
                    WHERE action = 'ioc_deconflict'
                      AND created_at >= CURRENT_TIMESTAMP - INTERVAL '%s days'
                ''' % days

                conditions = []
                actual_params = []
                param_idx = 1

                if ioc_value:
                    conditions.append(f"AND details->>'ioc_value' = ${param_idx}")
                    actual_params.append(ioc_value)
                    param_idx += 1

                if ioc_type:
                    conditions.append(f"AND details->>'ioc_type' = ${param_idx}")
                    actual_params.append(ioc_type.value)
                    param_idx += 1

                conditions.append(f"ORDER BY created_at DESC LIMIT ${param_idx}")
                actual_params.append(limit)

                full_query = base_query + ' '.join(conditions)
                rows = await conn.fetch(full_query, *actual_params)

                results = []
                for row in rows:
                    details = row['details']
                    if isinstance(details, str):
                        details = json.loads(details)

                    results.append({
                        'timestamp': row['created_at'].isoformat() if row['created_at'] else None,
                        'resource_id': row['resource_id'],
                        **details
                    })

                return results

        except Exception as e:
            logger.error(f"Failed to get deconfliction history: {e}")
            return []

    async def get_conflicting_iocs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Find IOCs that have conflicting verdicts across sources.

        Returns IOCs where enrichment providers disagree on the verdict.
        """
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                # Find IOCs where enrichment data contains different verdicts
                rows = await conn.fetch('''
                    SELECT
                        ioc_value, ioc_type, reputation as current_verdict,
                        confidence, enrichment_data, first_seen, last_seen, tags
                    FROM iocs
                    WHERE enrichment_data IS NOT NULL
                      AND jsonb_typeof(enrichment_data) = 'object'
                      AND (
                          SELECT COUNT(DISTINCT value->>'verdict')
                          FROM jsonb_each(enrichment_data) AS x(key, value)
                          WHERE value->>'verdict' IS NOT NULL
                      ) > 1
                    ORDER BY last_seen DESC
                    LIMIT $1
                ''', limit)

                results = []
                for row in rows:
                    enrichment = row['enrichment_data'] or {}

                    # Extract verdicts from each source
                    source_verdicts = {}
                    for source, data in enrichment.items():
                        if isinstance(data, dict) and data.get('verdict'):
                            source_verdicts[source] = data['verdict']

                    unique_verdicts = set(source_verdicts.values())

                    if len(unique_verdicts) > 1:
                        results.append({
                            'ioc_value': row['ioc_value'],
                            'ioc_type': row['ioc_type'],
                            'current_verdict': row['current_verdict'],
                            'confidence': row['confidence'],
                            'source_verdicts': source_verdicts,
                            'unique_verdicts': list(unique_verdicts),
                            'conflict_level': 'high' if 'malicious' in unique_verdicts and 'clean' in unique_verdicts else 'medium',
                            'first_seen': row['first_seen'].isoformat() if row['first_seen'] else None,
                            'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
                            'tags': row['tags'] or []
                        })

                return results

        except Exception as e:
            logger.error(f"Failed to get conflicting IOCs: {e}")
            return []


# ============================================================================
# SINGLETON
# ============================================================================

_threat_intel_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Get the global threat intel service instance"""
    global _threat_intel_service
    if _threat_intel_service is None:
        _threat_intel_service = ThreatIntelService()
    return _threat_intel_service
