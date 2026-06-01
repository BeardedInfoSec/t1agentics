# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent Scheduler Service
Background scheduler for automatically queuing events for AI agent triage.

This service periodically checks for new/untriaged alerts and queues them
for automatic analysis by tier 1 agents.

Environment Variables:
- AGENT_AUTO_TRIAGE_ENABLED: Set to 'false' to disable automatic T1/T2/T3 triage
- AGENT_SCHEDULER_ENABLED: Set to 'false' to disable the scheduler entirely
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


def _env_bool(key: str, default: bool = True) -> bool:
    """Get boolean from environment variable."""
    val = os.getenv(key, str(default)).lower()
    return val in ('true', '1', 'yes', 'on')


class AgentSchedulerConfig:
    """Configuration for the agent scheduler"""

    def __init__(
        self,
        enabled: bool = None,
        poll_interval_seconds: int = 1,  # Check every 10 seconds for fast MTTR
        max_events_per_cycle: int = 10,   # Process up to 10 events per cycle (was 25)
        max_queue_depth: int = 50,        # Max queue depth (was 100)
        event_age_threshold_minutes: int = 0,  # No delay - immediate pickup
        severity_filter: Optional[List[str]] = None,
        source_filter: Optional[List[str]] = None,
        auto_triage_enabled: bool = None
    ):
        # Check environment for overrides
        self.enabled = enabled if enabled is not None else _env_bool('AGENT_SCHEDULER_ENABLED', True)
        self.poll_interval_seconds = poll_interval_seconds
        self.max_events_per_cycle = max_events_per_cycle
        self.max_queue_depth = max_queue_depth
        self.event_age_threshold_minutes = event_age_threshold_minutes
        # Default: triage all severities except 'info'
        self.severity_filter = severity_filter or ['critical', 'high', 'medium', 'low']
        self.source_filter = source_filter  # None means all sources
        # Auto-triage can be disabled via environment
        self.auto_triage_enabled = auto_triage_enabled if auto_triage_enabled is not None else _env_bool('AGENT_AUTO_TRIAGE_ENABLED', True)


class AgentScheduler:
    """
    Background scheduler that automatically queues events for AI agent analysis.

    Responsibilities:
    - Periodically scan for new/untriaged alerts
    - Apply filtering criteria (severity, age, source)
    - Queue matching alerts for tier 1 agent triage
    - Track queue depth to prevent overload
    - Log scheduling activity for audit
    """

    def __init__(self, config: Optional[AgentSchedulerConfig] = None):
        self.config = config or AgentSchedulerConfig()
        self.running = False
        self._scheduler_task = None
        self._last_run: Optional[datetime] = None
        self._events_queued_total = 0
        self._cycles_completed = 0
        self._last_model_warm: Optional[datetime] = None
        self._model_warm_interval_minutes = 15  # Warm model every 15 minutes
        # Riggs queue tracking
        self._riggs_queue_count = 0
        self._riggs_queue_last_check: Optional[datetime] = None

    @asynccontextmanager
    async def _admin_conn(self):
        """Get a DB connection with platform admin privileges (bypasses RLS).

        The scheduler runs outside HTTP request context and needs to query
        across all tenants. This sets app.is_platform_admin so RLS policies
        allow cross-tenant visibility.
        """
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            # Verify admin flag is set (debug only)
            check = await conn.fetchval("SELECT current_setting('app.is_platform_admin', true)")
            logger.debug(f"admin_conn: is_platform_admin={check}")
            try:
                yield conn
            finally:
                try:
                    await conn.execute("RESET app.is_platform_admin")
                except Exception:
                    pass

    async def start(self):
        """Start the agent scheduler"""
        if self.running:
            logger.info("Agent scheduler already running")
            return

        if not self.config.enabled:
            logger.info("Agent scheduler disabled by configuration")
            return

        logger.info("Starting Agent Scheduler...")
        print("[AGENT] Starting Agent Scheduler...")

        self.running = True
        self._scheduler_task = asyncio.create_task(self._polling_loop())

        logger.info(f"Agent scheduler started (polling every {self.config.poll_interval_seconds}s)")
        print(f"[OK] Agent scheduler started (polling every {self.config.poll_interval_seconds}s)")

    async def _polling_loop(self):
        """Main polling loop that runs continuously"""
        logger.info("Polling loop started")

        # Initial delay to let the app fully start
        await asyncio.sleep(5)

        # Warm up the model on startup
        await self._maybe_warm_model(force=True)

        while self.running:
            try:
                await self._triage_cycle()
                self._cycles_completed += 1

                # Periodically warm the model to keep it loaded
                await self._maybe_warm_model()
            except Exception as e:
                logger.error(f"Triage cycle error: {e}", exc_info=True)
                print(f"[ERROR] Triage cycle error: {e}", flush=True)

            # Wait for next cycle
            await asyncio.sleep(self.config.poll_interval_seconds)

    async def _maybe_warm_model(self, force: bool = False):
        """
        Warm up the AI model if needed.

        For local LLMs (Ollama, LM Studio), this keeps the model loaded in memory.
        Called on startup (force=True) and periodically every 15 minutes.
        """
        try:
            now = datetime.utcnow()

            # Skip if we warmed recently (unless forced)
            if not force and self._last_model_warm:
                minutes_since_warm = (now - self._last_model_warm).total_seconds() / 60
                if minutes_since_warm < self._model_warm_interval_minutes:
                    return

            from services.agent_executor import AgentExecutor
            executor = AgentExecutor()
            result = await executor.warm_model(None)

            if result.get('success'):
                self._last_model_warm = now
                logger.info(f"🔥 Model warmed: {result.get('message', 'success')}")
                print(f"🔥 Model warmed: {result.get('message', 'success')}", flush=True)
            else:
                # Don't fail, just log
                logger.warning(f"Model warm-up skipped: {result.get('error', 'unknown')}")

        except Exception as e:
            # Don't fail the scheduler if model warming fails
            logger.warning(f"Model warm-up error (non-fatal): {e}")

    async def stop(self):
        """Stop the agent scheduler"""
        if not self.running:
            return

        logger.info("Stopping Agent Scheduler...")
        print("[STOP] Stopping Agent Scheduler...")

        self.running = False

        # Cancel the polling task if it exists
        if hasattr(self, '_scheduler_task') and self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        logger.info("Agent scheduler stopped")
        print("[OK] Agent scheduler stopped")

    async def _run_triage_with_error_handling(self):
        """Wrapper to catch and log errors from triage cycle"""
        print("[TRIAGE] Initial triage cycle...", flush=True)
        try:
            await self._triage_cycle()
        except Exception as e:
            logger.error(f"Triage cycle error: {e}", exc_info=True)
            print(f"[ERROR] Triage cycle error: {e}", flush=True)

    async def _triage_cycle(self):
        """
        Main triage cycle - find untriaged events and queue them.
        """
        logger.debug("Triage cycle running")

        try:
            from services.postgres_db import postgres_db, set_platform_admin_mode
            from services.job_queue import get_job_queue_service
            from services.agent_service import get_agent_service

            # Enable platform admin mode for all DB calls in this cycle
            set_platform_admin_mode(True)

            job_queue = await get_job_queue_service()
            agent_service = get_agent_service()

            # ALWAYS check for RIGGS_REVIEW investigations - this notifies/tracks Riggs queue
            # This runs regardless of auto-triage setting since Riggs is the human-AI interface
            try:
                await self._process_riggs_review_queue()
            except Exception as e:
                logger.error(f"Failed to process Riggs review queue: {e}")
                print(f"[ERROR] Failed to process Riggs review queue: {e}")

            # SLA breach sweep — fire one notification per investigation as it
            # crosses its severity-tier resolution target. Idempotent via a
            # dedup check against existing notifications.
            try:
                await self._check_sla_breaches()
            except Exception as e:
                logger.error(f"SLA breach sweep failed: {e}")

            # ALWAYS check for orphaned alerts - this creates investigations from new alerts
            # This should run even when auto-triage is disabled (Riggs mode)
            try:
                await self._process_orphaned_alerts()
            except Exception as e:
                logger.error(f"Failed to process orphaned alerts: {e}")
                print(f"[ERROR] Failed to process orphaned alerts: {e}")

            # Skip T1/T2/T3 agent processing if auto-triage is disabled (Riggs handles it)
            if not self.config.auto_triage_enabled:
                logger.debug("Auto-triage disabled, skipping T1/T2/T3 agent processing")
                print("[PAUSE] Auto-triage disabled - Riggs mode (investigations still created)")
                return

            # NOTE: T2 tier is disabled - Riggs is the deep analysis engine.
            # Workflow: T1 Triage -> RIGGS_REVIEW (direct, no T2 intermediate)
            # This improves latency and removes redundant "needs manual review" verdict.

            # Check for NEW investigations that need initial T1 processing
            try:
                await self._process_new_investigations(job_queue, agent_service)
            except Exception as e:
                logger.error(f"Failed to process new investigations: {e}")
                print(f"[ERROR] Failed to process new investigations: {e}")

            # Check if we have any enabled tier 1 agents for alert triage
            tier1_agents = await agent_service.list_agents(tier=1, enabled_only=True)
            if not tier1_agents:
                logger.debug("No enabled Tier 1 agents - skipping alert triage")
                return

            # Check current queue depth
            current_queue_depth = await self._get_pending_job_count()
            if current_queue_depth >= self.config.max_queue_depth:
                logger.debug(f"Queue depth ({current_queue_depth}) at max ({self.config.max_queue_depth}) - skipping cycle")
                return

            # Calculate how many events we can queue
            available_slots = min(
                self.config.max_events_per_cycle,
                self.config.max_queue_depth - current_queue_depth
            )

            if available_slots <= 0:
                return

            # Find untriaged events
            untriaged_events = await self._find_untriaged_events(limit=available_slots)

            if not untriaged_events:
                logger.debug("No untriaged events found")
                return

            logger.info(f"Found {len(untriaged_events)} untriaged events to queue")

            # Queue each event for triage
            from services.job_queue import QueueName
            queued_count = 0
            for event in untriaged_events:
                try:
                    await job_queue.enqueue(
                        queue_name=QueueName.AGENT,
                        job_type='agent_auto_triage',
                        payload={
                            'alert_id': str(event['id']),
                            'scheduled_by': 'agent_scheduler',
                            'scheduled_at': datetime.utcnow().isoformat()
                        },
                        priority=self._calculate_priority(event)
                    )
                    queued_count += 1

                    # Mark event as queued (to prevent re-queueing)
                    await self._mark_event_queued(event['id'])

                except Exception as e:
                    logger.error(f"Failed to queue event {event['id']}: {e}")

            self._events_queued_total += queued_count
            self._cycles_completed += 1
            self._last_run = datetime.utcnow()

            if queued_count > 0:
                logger.info(f"Queued {queued_count} events for AI triage")
                print(f"[AGENT] Queued {queued_count} events for AI triage")

        except Exception as e:
            logger.error(f"Agent triage cycle error: {e}")

    # ─── SLA breach detector ────────────────────────────────────────────
    # Targets mirror the frontend SLA calc in
    # `frontend/src/components/SecurityQueue/transforms.js` so the bell
    # agrees with the queue's "exceeded" badge. Keep in sync if you ever
    # introduce per-tenant overrides.
    _SLA_TARGET_MINUTES = {
        'critical': 60,
        'high':     240,
        'medium':   480,
        'low':      1440,
    }

    async def _check_sla_breaches(self):
        """Find investigations whose open age now exceeds their severity-tier
        SLA target and fire one notification per breach. Dedup keyed off the
        notifications table so repeated polls don't spam analysts."""
        try:
            from services.postgres_db import postgres_db
            from routes.notifications import create_notification
        except Exception:
            return

        if not postgres_db.connected:
            return

        async with self._admin_conn() as conn:
            # Investigations still in progress whose age has crossed the SLA
            # line. We do this in one pass with a CASE rather than four
            # queries — fewer round trips, cheaper.
            rows = await conn.fetch("""
                SELECT investigation_id, tenant_id, alert_title, severity, owner,
                       EXTRACT(EPOCH FROM (NOW() - created_at)) / 60.0 AS age_minutes
                  FROM investigations
                 WHERE state NOT IN ('CLOSED', 'RESOLVED')
                   AND created_at < NOW() - INTERVAL '1 hour'  -- cheap pre-filter
            """)

            for row in rows:
                sev = (row['severity'] or 'medium').lower()
                target = self._SLA_TARGET_MINUTES.get(sev, self._SLA_TARGET_MINUTES['medium'])
                age = float(row['age_minutes'] or 0)
                if age <= target:
                    continue

                inv_id = row['investigation_id']
                tenant_id = row['tenant_id']
                if not tenant_id:
                    continue

                # Idempotency: skip if a breach notification was already filed
                # for this investigation. We use the link + metadata pattern
                # since there's no dedicated event_type column.
                existing = await conn.fetchval("""
                    SELECT 1
                      FROM notifications
                     WHERE tenant_id = $1
                       AND link = $2
                       AND (metadata ->> 'event_type') = 'sla_breach'
                     LIMIT 1
                """, tenant_id, f"/investigation/{inv_id}")
                if existing:
                    continue

                over_by = int(age - target)
                inv_title = row['alert_title'] or 'Investigation'
                await create_notification(
                    tenant_id=str(tenant_id),
                    title=f"SLA breach: {inv_title[:80]}",
                    message=(
                        f"{sev.title()}-severity investigation has been open "
                        f"{int(age)}m (target {target}m, over by {over_by}m)."
                        + (f" Owner: {row['owner']}." if row['owner'] else " Unassigned.")
                    ),
                    category="alert",
                    severity="critical",
                    link=f"/investigation/{inv_id}",
                    metadata={
                        "event_type": "sla_breach",
                        "investigation_id": inv_id,
                        "severity": sev,
                        "target_minutes": target,
                        "age_minutes": int(age),
                    },
                )
                logger.info(f"[SLA] Fired breach notification for {inv_id} (age={int(age)}m target={target}m)")

    async def _process_riggs_review_queue(self):
        """
        Process investigations that need Riggs analysis and human review.

        Two-phase workflow:
        1. ANALYZING: Riggs runs deep analysis automatically
        2. NEEDS_REVIEW: Riggs done, awaiting human decision

        This method:
        - Queues Riggs analysis for ANALYZING investigations
        - Tracks NEEDS_REVIEW queue for dashboard visibility
        - Notifies via WebSocket when investigations need attention
        """
        try:
            async with self._admin_conn() as conn:
                # Phase 1: Get ANALYZING investigations that need Riggs analysis
                # Also check for legacy RIGGS_REVIEW state for backward compatibility
                analyzing_queue = await conn.fetch("""
                    SELECT
                        i.id,
                        i.investigation_id,
                        i.alert_title as title,
                        i.severity,
                        i.priority,
                        i.state,
                        i.created_at,
                        i.updated_at,
                        i.investigation_data,
                        EXTRACT(EPOCH FROM (NOW() - i.updated_at))/60 as minutes_in_state
                    FROM investigations i
                    WHERE i.state IN ('ANALYZING', 'RIGGS_REVIEW', 'AI_TRIAGE_L1', 'AI_TRIAGE_L2', 'ENRICHING', 'TRIAGE_PROVISIONAL')
                    ORDER BY
                        CASE i.priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,
                        i.created_at ASC
                """)

                logger.debug("Checking for ANALYZING investigations")

                # Auto-queue Riggs analysis for ANALYZING investigations
                if analyzing_queue:
                    logger.info(f"[ANALYZING] {len(analyzing_queue)} investigations in AI analysis phase")
                    await self._auto_start_riggs_analysis(conn, analyzing_queue)

                # Phase 2: Get NEEDS_REVIEW queue (Riggs done, awaiting human)
                riggs_queue = await conn.fetch("""
                    SELECT
                        i.id,
                        i.investigation_id,
                        i.alert_title as title,
                        i.severity,
                        i.priority,
                        i.state,
                        i.created_at,
                        i.updated_at,
                        i.investigation_data,
                        EXTRACT(EPOCH FROM (NOW() - i.updated_at))/60 as minutes_in_queue
                    FROM investigations i
                    WHERE i.state = 'NEEDS_REVIEW'
                    ORDER BY
                        CASE i.priority
                            WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2
                            WHEN 'P3' THEN 3
                            WHEN 'P4' THEN 4
                            ELSE 5
                        END,
                        i.updated_at ASC
                """)

                queue_count = len(riggs_queue) if riggs_queue else 0

                # Track queue stats — only log when count changes or every 60s
                prev_count = getattr(self, '_riggs_queue_count', -1)
                prev_log_time = getattr(self, '_riggs_queue_last_log', None)
                self._riggs_queue_count = queue_count
                self._riggs_queue_last_check = datetime.utcnow()

                should_log = (
                    queue_count != prev_count
                    or prev_log_time is None
                    or (datetime.utcnow() - prev_log_time).total_seconds() >= 60
                )

                if queue_count > 0:
                    oldest = riggs_queue[0] if riggs_queue else None
                    oldest_mins = oldest['minutes_in_queue'] if oldest else 0

                    if should_log:
                        self._riggs_queue_last_log = datetime.utcnow()
                        logger.info(f"[RIGGS] Queue: {queue_count} investigations awaiting review (oldest: {oldest_mins:.0f}m)")

                        stale_investigations = [inv for inv in riggs_queue if inv['minutes_in_queue'] > 30]
                        if stale_investigations:
                            logger.warning(f"[RIGGS] {len(stale_investigations)} investigations stale (>30m)")

                    # Broadcast queue update via WebSocket (if connected)
                    try:
                        from websocket import broadcast_to_all
                        await broadcast_to_all({
                            'type': 'needs_review_update',
                            'queue_count': queue_count,
                            'investigations': [
                                {
                                    'id': str(inv['id']),
                                    'investigation_id': inv['investigation_id'],
                                    'title': inv['title'],
                                    'severity': inv['severity'],
                                    'priority': inv['priority'],
                                    'minutes_in_queue': round(inv['minutes_in_queue'], 1)
                                }
                                for inv in riggs_queue[:10]  # Send top 10
                            ]
                        })
                    except Exception as ws_err:
                        # WebSocket broadcast is optional - don't fail the cycle
                        pass

                    # Note: Riggs analysis now happens during ANALYZING phase (see above)
                    # NEEDS_REVIEW = AI is done, awaiting human decision

        except Exception as e:
            logger.error(f"Riggs review queue processing error: {e}")
            print(f"[ERROR] Riggs review queue error: {e}", flush=True)

    async def _auto_start_riggs_analysis(self, conn, analyzing_queue: list):
        """
        Automatically start Riggs analysis for ANALYZING investigations.

        When Riggs completes analysis, the investigation transitions to NEEDS_REVIEW.
        This runs during the ANALYZING phase so human analysts see completed analysis.
        """
        from services.job_queue import get_job_queue_service

        import json as _json
        try:
            for inv in analyzing_queue:
                investigation_id = inv['investigation_id']
                inv_uuid = str(inv['id'])

                # Check investigation_data for existing Riggs analysis or running status
                inv_data_row = await conn.fetchval(
                    "SELECT investigation_data FROM investigations WHERE investigation_id = $1",
                    investigation_id,
                )
                if inv_data_row:
                    inv_data = inv_data_row if isinstance(inv_data_row, dict) else _json.loads(inv_data_row) if inv_data_row else {}
                    riggs_status = inv_data.get('riggs_status', '')

                    # Already has analysis — should transition to NEEDS_REVIEW
                    if inv_data.get('riggs_analysis'):
                        logger.info(f"[RIGGS] {investigation_id} already has analysis, transitioning to NEEDS_REVIEW")
                        await conn.execute(
                            "UPDATE investigations SET state = 'NEEDS_REVIEW' WHERE investigation_id = $1",
                            investigation_id,
                        )
                        continue

                    # Riggs currently running or completed
                    if riggs_status in ('RUNNING', 'COMPLETE', 'FAILED'):
                        continue

                # Check if Riggs has already started analysis (look for chat messages)
                existing_chat = await conn.fetchval("""
                    SELECT COUNT(*) FROM investigation_chat
                    WHERE investigation_id = $1 AND sender_type IN ('agent_t1', 'agent_t2', 'agent_t3')
                """, inv['id'])

                if existing_chat > 0:
                    # Riggs already engaged, skip
                    continue

                # Check if already queued for Riggs
                existing_job = await conn.fetchval("""
                    SELECT COUNT(*) FROM job_queue
                    WHERE payload->>'investigation_id' = $1
                    AND job_type = 'riggs_analysis'
                    AND status IN ('pending', 'processing')
                """, investigation_id)

                if existing_job > 0:
                    print(f"[RIGGS] {investigation_id} already has pending job, skipping", flush=True)
                    continue

                # Queue Riggs auto-analysis
                logger.info(f"[RIGGS] Auto-queuing analysis for investigation {investigation_id}")
                print(f"[RIGGS] >>> Auto-queuing analysis for investigation {investigation_id}", flush=True)

                job_queue = await get_job_queue_service()
                await job_queue.enqueue(
                    queue_name='agent',  # Use existing agent queue
                    job_type='riggs_analysis',
                    payload={
                        'investigation_id': investigation_id,
                        'investigation_uuid': inv_uuid,
                        'auto_initiated': True,
                        'trigger': 'scheduler_auto_riggs'
                    },
                    priority=1  # High priority
                )

        except Exception as e:
            logger.error(f"Auto-start Riggs analysis error: {e}")
            print(f"[ERROR] Auto-start Riggs analysis error: {e}", flush=True)

    async def schedule_riggs_review(
        self,
        investigation_id: str,
        mode: str = 'DEEP',
        reason: str = ''
    ):
        """
        Schedule Riggs (T2) deep analysis for an investigation.

        This queues a riggs_analysis job to perform deep analysis on the investigation,
        including full prompt generation and LLM-based verdict.

        Args:
            investigation_id: The investigation ID (e.g., "INV-12345678")
            mode: Analysis mode - 'DEEP' for full analysis
            reason: Reason for scheduling (for logging/tracking)
        """
        try:
            from services.job_queue import get_job_queue
            from services.postgres_db import postgres_db

            job_queue = get_job_queue()
            job_queue.set_db(postgres_db)

            # Check if investigation exists and is in a valid state for Riggs
            async with self._admin_conn() as conn:
                inv_row = await conn.fetchrow('''
                    SELECT id, investigation_id, state, investigation_data
                    FROM investigations
                    WHERE investigation_id = $1
                ''', investigation_id)

                if not inv_row:
                    logger.warning(f"[RIGGS_SCHEDULE] Investigation {investigation_id} not found")
                    return

                # Check if already has riggs_analysis
                inv_data = inv_row['investigation_data']
                if isinstance(inv_data, str):
                    import json
                    inv_data = json.loads(inv_data)
                if inv_data and inv_data.get('riggs_analysis'):
                    logger.debug(f"[RIGGS_SCHEDULE] Investigation {investigation_id} already has Riggs analysis - skipping")
                    return

            # Queue the riggs_analysis job
            job_id = await job_queue.enqueue(
                queue_name='agent',
                job_type='riggs_analysis',
                payload={
                    'investigation_id': investigation_id,
                    'mode': mode,
                    'reason': reason
                },
                priority=3  # High priority for deep analysis
            )

            if not job_id:
                logger.warning(f"[RIGGS_SCHEDULE] Queue full - dropped Riggs analysis for {investigation_id}")
                return

            logger.info(f"[RIGGS_SCHEDULE] Queued Riggs analysis for {investigation_id} (job_id={job_id}, mode={mode}, reason={reason[:100]})")
            print(f"[RIGGS_SCHEDULE] Queued Riggs analysis for {investigation_id} (job_id={job_id})", flush=True)

        except Exception as e:
            logger.error(f"[RIGGS_SCHEDULE] Failed to schedule Riggs for {investigation_id}: {e}")
            import traceback
            logger.error(f"[RIGGS_SCHEDULE] Traceback: {traceback.format_exc()}")

    async def _find_untriaged_events(self, limit: int) -> List[Dict[str, Any]]:
        """
        Find events that need triage.

        Criteria:
        - Status is 'new' (not yet processed)
        - Not already queued for triage (ai_triage_queued is false/null)
        - Matches severity filter
        - Older than age threshold (to avoid racing with manual triage)
        - Optional: matches source filter
        """
        from services.postgres_db import postgres_db

        age_threshold = datetime.utcnow() - timedelta(minutes=self.config.event_age_threshold_minutes)

        # Build severity filter
        severity_placeholders = ', '.join([f'${i+2}' for i in range(len(self.config.severity_filter))])

        # CRITICAL: Also exclude alerts that already have confident malicious verdicts
        # to prevent overwriting verdicts set by auto_enrichment -> ai_triage_service
        query = f"""
            SELECT id, alert_id, title, severity, source, source_type, created_at, status
            FROM alerts
            WHERE status IN ('new', 'open', 'investigating', 'enriched')
            AND (ai_triage_queued IS NULL OR ai_triage_queued = FALSE)
            AND created_at <= $1
            AND LOWER(severity) IN ({severity_placeholders})
            AND NOT (
                LOWER(COALESCE(ai_verdict, '')) IN ('malicious', 'true_positive')
                AND COALESCE(ai_confidence, 0) >= 0.80
            )
        """

        params = [age_threshold] + [s.lower() for s in self.config.severity_filter]

        # Add source filter if configured
        if self.config.source_filter:
            source_placeholders = ', '.join([f'${len(params)+i+1}' for i in range(len(self.config.source_filter))])
            query += f" AND (LOWER(COALESCE(source, '')) IN ({source_placeholders}) OR LOWER(COALESCE(source_type, '')) IN ({source_placeholders}))"
            params.extend([s.lower() for s in self.config.source_filter] * 2)

        query += f" ORDER BY CASE LOWER(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at ASC LIMIT ${len(params)+1}"
        params.append(limit)

        async with self._admin_conn() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]

    async def _mark_event_queued(self, event_id: str):
        """Mark an event as queued for triage to prevent re-queueing"""
        async with self._admin_conn() as conn:
            await conn.execute(
                "UPDATE alerts SET ai_triage_queued = TRUE, ai_triage_queued_at = $1 WHERE id = $2",
                datetime.utcnow(),
                event_id
            )

    async def _get_pending_job_count(self) -> int:
        """Get count of pending agent triage jobs"""
        async with self._admin_conn() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM job_queue WHERE job_type = 'agent_auto_triage' AND status IN ('pending', 'running')"
            )
            return count or 0

    def _calculate_priority(self, event: Dict[str, Any]) -> int:
        """
        Calculate job priority based on event severity.
        Lower number = higher priority.
        """
        severity_priority = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        }
        return severity_priority.get(event.get('severity', '').lower(), 5)

    async def _process_tier2_investigations(self, job_queue, agent_service):
        """
        [DEPRECATED] T2 tier is disabled - Riggs handles all deep analysis.

        This method is preserved for potential future use but is no longer called.
        The workflow now goes: T1 Triage -> RIGGS_REVIEW (skipping T2).

        Original purpose:
        Find investigations waiting for Tier 2 agent processing and queue them.

        Criteria:
        - State is 'AI_TRIAGE_L2' (waiting for Tier 2 agent)
        - Not already being processed (no active job)

        Deprecation date: 2026-01-21
        Reason: T2 produced redundant "needs manual review" verdicts. Riggs provides
                superior conversational analysis with specific threat context.
        """
        # DEPRECATED: This method is no longer called. See docstring for details.
        logger.warning("_process_tier2_investigations called but T2 is deprecated")
        return
        from services.postgres_db import postgres_db
        from services.job_queue import QueueName

        try:
            # Check if we have any enabled Tier 2 agents
            tier2_agents = await agent_service.list_agents(tier=2, enabled_only=True)
            if not tier2_agents:
                logger.debug("No enabled Tier 2 agents - skipping investigation processing")
                return

            async with postgres_db.tenant_acquire() as conn:
                # Find investigations in AI_TRIAGE_L2 state that aren't being processed
                # GUARD: Also skip investigations that already have tier2_analysis with a verdict
                investigations = await conn.fetch("""
                    SELECT i.id, i.investigation_id, i.alert_id, i.severity, i.priority,
                           i.escalated_to_tier, i.executive_summary
                    FROM investigations i
                    WHERE i.state = 'ANALYZING'
                    AND (
                        (i.investigation_data->>'tier2_analysis') IS NULL
                        OR (i.investigation_data->'tier2_analysis'->>'verdict') IS NULL
                        OR (i.investigation_data->'tier2_analysis'->>'verdict') = ''
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM job_queue jq
                        WHERE jq.job_type = 'agent_analyze_investigation'
                        AND jq.payload->>'investigation_id' = i.id::text
                        AND jq.status IN ('pending', 'running')
                    )
                    ORDER BY
                        CASE i.priority
                            WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2
                            WHEN 'P3' THEN 3
                            WHEN 'P4' THEN 4
                            ELSE 5
                        END,
                        i.created_at ASC
                    LIMIT 10
                """)

                if not investigations:
                    return

                logger.info(f"Found {len(investigations)} investigations waiting for Tier 2 processing")

                # Select a Tier 2 agent (round-robin or first available)
                tier2_agent = tier2_agents[0]

                queued_count = 0
                for inv in investigations:
                    try:
                        # Queue the investigation for Tier 2 analysis
                        await job_queue.enqueue(
                            queue_name=QueueName.AGENT,
                            job_type='agent_analyze_investigation',
                            payload={
                                'agent_id': str(tier2_agent['id']),
                                'investigation_id': str(inv['id']),
                                'alert_id': str(inv['alert_id']) if inv['alert_id'] else None,
                                'scheduled_by': 'agent_scheduler',
                                'scheduled_at': datetime.utcnow().isoformat()
                            },
                            priority=self._calculate_priority({'severity': inv['severity']})
                        )
                        queued_count += 1

                    except Exception as e:
                        logger.error(f"Failed to queue investigation {inv['investigation_id']}: {e}")

                if queued_count > 0:
                    logger.info(f"Queued {queued_count} investigations for Tier 2 analysis")
                    print(f"[T2] Queued {queued_count} investigations for Tier 2 analysis")

        except Exception as e:
            logger.error(f"Tier 2 investigation processing error: {e}")

    async def _process_new_investigations(self, job_queue, agent_service):
        """
        Find NEW investigations that need initial AI analysis.

        These are investigations that were manually created or came from sources
        that bypassed the normal alert -> T1 triage flow. They need to be
        processed by T1 agent first to establish initial analysis.
        """
        from services.postgres_db import postgres_db
        from services.job_queue import QueueName

        try:
            # Check if we have any enabled Tier 1 agents
            tier1_agents = await agent_service.list_agents(tier=1, enabled_only=True)
            if not tier1_agents:
                return

            async with self._admin_conn() as conn:
                # Find investigations that:
                # 1. Are in NEW or AI_TRIAGE_L1 state (stuck investigations)
                # 2. Don't have tier1_analysis
                # 3. Aren't already being processed
                # 4. Were created more than 30 seconds ago (avoid racing with UI)
                investigations = await conn.fetch("""
                    SELECT i.id, i.investigation_id, i.alert_id, i.severity, i.priority,
                           i.investigation_data, i.state
                    FROM investigations i
                    WHERE i.state IN ('NEW', 'AI_TRIAGE_L1')
                    AND (i.investigation_data->>'tier1_analysis') IS NULL
                    AND i.created_at < NOW() - INTERVAL '30 seconds'
                    AND NOT EXISTS (
                        SELECT 1 FROM job_queue jq
                        WHERE jq.job_type IN ('agent_analyze_investigation', 'agent_auto_triage')
                        AND (jq.payload->>'investigation_id' = i.id::text
                             OR jq.payload->>'investigation_id' = i.investigation_id)
                        AND jq.status IN ('pending', 'running')
                    )
                    ORDER BY i.created_at ASC
                    LIMIT 5
                """)

                if not investigations:
                    return

                logger.info(f"Found {len(investigations)} investigations (NEW/AI_TRIAGE_L1) needing initial AI analysis")
                print(f"[NEW] Found {len(investigations)} investigations needing AI analysis")

                tier1_agent = tier1_agents[0]
                queued_count = 0

                for inv in investigations:
                    try:
                        # Update state to AI_TRIAGE_L1 and queue for processing
                        await conn.execute("""
                            UPDATE investigations
                            SET state = 'ANALYZING', updated_at = NOW()
                            WHERE id = $1
                        """, inv['id'])

                        # Queue for T1 analysis
                        await job_queue.enqueue(
                            queue_name=QueueName.AGENT,
                            job_type='agent_analyze_investigation',
                            payload={
                                'agent_id': str(tier1_agent['id']),
                                'investigation_id': str(inv['id']),
                                'alert_id': str(inv['alert_id']) if inv['alert_id'] else None,
                                'scheduled_by': 'new_investigation_processor',
                                'scheduled_at': datetime.utcnow().isoformat(),
                                'tier': 1
                            },
                            priority=self._calculate_priority({'severity': inv['severity']})
                        )
                        queued_count += 1
                        logger.info(f"Queued NEW investigation {inv['investigation_id']} for T1 analysis")

                    except Exception as e:
                        logger.error(f"Failed to queue NEW investigation {inv['investigation_id']}: {e}")

                if queued_count > 0:
                    print(f"[T1] Queued {queued_count} NEW investigations for T1 analysis")

        except Exception as e:
            logger.error(f"New investigation processing error: {e}")

    async def _process_orphan_investigations(self, job_queue, agent_service):
        """
        [DEPRECATED] T2 tier is disabled - orphan investigations go directly to RIGGS_REVIEW.

        This method is preserved for potential future use but is no longer called.
        Orphan investigations are now handled by the RIGGS_REVIEW workflow.

        Original purpose:
        Find investigations created by orphan_watcher that don't have proper AI analysis.
        These are investigations created directly (bypassing T1) that need to be
        processed by T2 agents to populate tier2_analysis data.

        Deprecation date: 2026-01-21
        Reason: T2 tier removal - Riggs handles all deep analysis including orphans.
        """
        # DEPRECATED: This method is no longer called. See docstring for details.
        logger.warning("_process_orphan_investigations called but T2 is deprecated")
        return
        from services.postgres_db import postgres_db
        from services.job_queue import QueueName
        import json

        try:
            # Check if we have any enabled Tier 2 agents
            tier2_agents = await agent_service.list_agents(tier=2, enabled_only=True)
            if not tier2_agents:
                return

            async with postgres_db.tenant_acquire() as conn:
                # Find investigations that:
                # 1. Don't have tier2_analysis with a valid verdict (haven't been processed by T2 agent)
                # 2. Are in a state that allows processing (NEW, AWAITING_HUMAN, IN_PROGRESS - not AI_TRIAGE_L2)
                # 3. Aren't already being processed
                # GUARD: Check for both null tier2_analysis AND null/empty verdict
                investigations = await conn.fetch("""
                    SELECT i.id, i.investigation_id, i.alert_id, i.severity, i.priority,
                           i.investigation_data, i.state
                    FROM investigations i
                    WHERE i.state IN ('NEW', 'AWAITING_HUMAN', 'IN_PROGRESS')
                    AND (
                        (i.investigation_data->>'tier2_analysis') IS NULL
                        OR (i.investigation_data->'tier2_analysis'->>'verdict') IS NULL
                        OR (i.investigation_data->'tier2_analysis'->>'verdict') = ''
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM job_queue jq
                        WHERE jq.job_type = 'agent_analyze_investigation'
                        AND jq.payload->>'investigation_id' = i.id::text
                        AND jq.status IN ('pending', 'running')
                    )
                    ORDER BY i.created_at ASC
                    LIMIT 5
                """)

                if not investigations:
                    return

                logger.info(f"Found {len(investigations)} orphan-created investigations needing AI analysis")
                print(f"[ORPHAN] Found {len(investigations)} orphan investigations needing AI analysis")

                tier2_agent = tier2_agents[0]
                queued_count = 0

                for inv in investigations:
                    try:
                        # Update state to AI_TRIAGE_L2 and queue for processing
                        await conn.execute("""
                            UPDATE investigations
                            SET state = 'ANALYZING', updated_at = NOW()
                            WHERE id = $1
                        """, inv['id'])

                        # Queue for T2 analysis
                        await job_queue.enqueue(
                            queue_name=QueueName.AGENT,
                            job_type='agent_analyze_investigation',
                            payload={
                                'agent_id': str(tier2_agent['id']),
                                'investigation_id': str(inv['id']),
                                'alert_id': str(inv['alert_id']) if inv['alert_id'] else None,
                                'scheduled_by': 'orphan_investigation_processor',
                                'scheduled_at': datetime.utcnow().isoformat()
                            },
                            priority=self._calculate_priority({'severity': inv['severity']})
                        )
                        queued_count += 1
                        logger.info(f"Queued orphan investigation {inv['investigation_id']} for T2 analysis")

                    except Exception as e:
                        logger.error(f"Failed to queue orphan investigation {inv['investigation_id']}: {e}")

                if queued_count > 0:
                    print(f"[T2] Queued {queued_count} orphan investigations for T2 analysis")

        except Exception as e:
            logger.error(f"Orphan investigation processing error: {e}")

    async def _process_orphaned_alerts(self):
        """
        Find alerts that need AI agent processing but haven't been queued.

        This catches cases where:
        - Alerts were ingested but never picked up for triage
        - Investigation creation failed during agent execution
        - Alerts were marked but not processed through the full pipeline

        These alerts are queued for T1 agent triage so they go through the normal
        AI processing pipeline and get proper tier1_analysis data.
        """
        from services.postgres_db import postgres_db
        from services.job_queue import get_job_queue_service, QueueName

        logger.debug("Running orphaned alert check")

        try:
            if not postgres_db.pool:
                print("[ERROR] Database pool not available for orphan check")
                logger.warning("Database pool not available for orphan check")
                return

            job_queue = await get_job_queue_service()

            async with self._admin_conn() as conn:
                # Debug: check total visible alerts
                total = await conn.fetchval("SELECT COUNT(*) FROM alerts")
                open_count = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'open' AND ai_verdict IS NULL")
                logger.debug(f"Orphan check: total={total}, open+no_verdict={open_count}")

                # Find alerts that:
                # 1. Have a suspicious/malicious AI verdict OR are new/open without verdict
                # 2. Don't have an investigation linked
                # 3. Aren't in a terminal status
                # 4. Haven't been queued for triage yet
                # 5. Were created more than 2 minutes ago (to avoid racing with in-progress triage)
                # BUG FIX: The first condition was missing the ai_triage_queued check,
                # causing alerts with suspicious verdict to be re-queued infinitely.
                # Now we only pick up alerts that haven't been queued yet.
                orphaned_alerts = await conn.fetch("""
                    SELECT a.id, a.alert_id, a.title, a.severity, a.ai_verdict, a.ai_confidence, a.ai_summary,
                           a.ai_triage_queued
                    FROM alerts a
                    WHERE (
                        -- Has suspicious/malicious verdict without investigation AND not yet queued
                        (a.ai_verdict IN ('suspicious', 'SUSPICIOUS', 'malicious', 'MALICIOUS', 'true_positive', 'TRUE_POSITIVE')
                         AND a.investigation_id IS NULL
                         AND (a.ai_triage_queued IS NULL OR a.ai_triage_queued = FALSE))
                        OR
                        -- Or is a new alert that never got triaged
                        (a.ai_verdict IS NULL AND a.status IN ('new', 'open')
                         AND (a.ai_triage_queued IS NULL OR a.ai_triage_queued = FALSE))
                        OR
                        -- Or was queued but triage failed (no verdict after 10+ minutes)
                        (a.ai_verdict IS NULL AND a.status IN ('new', 'open')
                         AND a.ai_triage_queued = TRUE
                         AND a.ai_triage_queued_at < NOW() - INTERVAL '10 minutes')
                    )
                    AND a.status NOT IN ('resolved', 'closed', 'false_positive')
                    AND a.created_at < NOW() - INTERVAL '2 minutes'
                    AND NOT EXISTS (
                        SELECT 1 FROM job_queue jq
                        WHERE jq.job_type = 'agent_auto_triage'
                        AND jq.payload->>'alert_id' = a.id::text
                        AND jq.status IN ('pending', 'running')
                    )
                    ORDER BY
                        CASE LOWER(a.severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
                        a.created_at ASC
                    LIMIT 10
                """)

                orphan_count = len(orphaned_alerts) if orphaned_alerts else 0
                logger.debug(f"Orphan check: found {orphan_count} alerts needing processing")

                if not orphaned_alerts:
                    return

                logger.info(f"Found {len(orphaned_alerts)} orphaned alerts - queueing for AI agent triage")
                print(f"[WARN] Found {len(orphaned_alerts)} orphaned alerts - queueing for T1 triage")

                queued_count = 0
                for alert in orphaned_alerts:
                    try:
                        # Queue the alert for T1 agent triage (normal pipeline)
                        await job_queue.enqueue(
                            queue_name=QueueName.AGENT,
                            job_type='agent_auto_triage',
                            payload={
                                'alert_id': str(alert['id']),
                                'scheduled_by': 'orphan_watcher',
                                'scheduled_at': datetime.utcnow().isoformat(),
                                'reason': 'Orphaned alert detected - queueing for AI triage'
                            },
                            priority=self._calculate_priority(alert)
                        )

                        # Mark as queued to prevent re-queueing
                        await conn.execute("""
                            UPDATE alerts
                            SET ai_triage_queued = TRUE, ai_triage_queued_at = NOW(), updated_at = NOW()
                            WHERE id = $1
                        """, alert['id'])

                        queued_count += 1
                        logger.info(f"Queued orphaned alert {alert['alert_id']} for T1 triage (verdict: {alert['ai_verdict']})")

                    except Exception as e:
                        logger.error(f"Failed to queue orphaned alert {alert['id']}: {e}")

                if queued_count > 0:
                    print(f"[AGENT] Queued {queued_count} orphaned alerts for AI agent triage")

        except Exception as e:
            logger.error(f"Orphaned alert processing error: {e}")
            print(f"[ERROR] Orphaned alert processing error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        return {
            "running": self.running,
            "enabled": self.config.enabled,
            "auto_triage_enabled": self.config.auto_triage_enabled,
            "poll_interval_seconds": self.config.poll_interval_seconds,
            "max_events_per_cycle": self.config.max_events_per_cycle,
            "max_queue_depth": self.config.max_queue_depth,
            "severity_filter": self.config.severity_filter,
            "source_filter": self.config.source_filter,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "events_queued_total": self._events_queued_total,
            "cycles_completed": self._cycles_completed,
            # Riggs queue stats
            "riggs_queue_count": self._riggs_queue_count,
            "riggs_queue_last_check": self._riggs_queue_last_check.isoformat() if self._riggs_queue_last_check else None
        }

    def update_config(self, **kwargs):
        """Update scheduler configuration"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        logger.info(f"Agent scheduler config updated: {kwargs}")


# Singleton instance
_agent_scheduler: Optional[AgentScheduler] = None


def get_agent_scheduler() -> AgentScheduler:
    """Get the global agent scheduler instance"""
    global _agent_scheduler
    if _agent_scheduler is None:
        _agent_scheduler = AgentScheduler()
    return _agent_scheduler


async def start_agent_scheduler():
    """Start the global agent scheduler"""
    scheduler = get_agent_scheduler()
    await scheduler.start()
    return scheduler


async def stop_agent_scheduler():
    """Stop the global agent scheduler"""
    global _agent_scheduler
    if _agent_scheduler:
        await _agent_scheduler.stop()
