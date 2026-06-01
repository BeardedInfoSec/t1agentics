# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Scheduler Service
Runs scheduled playbooks using cron expressions in trigger_conditions.
Also handles resumption of delayed playbook executions.
"""

import asyncio
import json
import logging
from typing import Optional
from datetime import timezone as dt_timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

logger = logging.getLogger(__name__)


def _resolve_timezone(name: Optional[str]):
    if not name:
        return dt_timezone.utc
    if ZoneInfo:
        try:
            return ZoneInfo(name)
        except Exception:
            logger.warning(f"[PLAYBOOK_SCHED] Invalid timezone '{name}', falling back to UTC")
            return dt_timezone.utc
    return dt_timezone.utc


def _cron_trigger(cron_expr: str, tz_name: Optional[str]):
    if not cron_expr:
        return None
    fields = cron_expr.strip().split()
    tz = _resolve_timezone(tz_name)
    try:
        if len(fields) == 5:
            return CronTrigger.from_crontab(cron_expr, timezone=tz)
        if len(fields) == 6:
            return CronTrigger(
                second=fields[0],
                minute=fields[1],
                hour=fields[2],
                day=fields[3],
                month=fields[4],
                day_of_week=fields[5],
                timezone=tz
            )
    except Exception as e:
        logger.warning(f"[PLAYBOOK_SCHED] Invalid cron '{cron_expr}': {e}")
    return None


class PlaybookScheduler:
    """Cron-based scheduler for playbooks."""

    def __init__(self, db):
        self.scheduler = AsyncIOScheduler()
        self.db = db
        self.running = False

    async def start(self):
        """Start scheduler and load all jobs."""
        if self.running:
            return
        await self._load_jobs()
        self.scheduler.start()
        self.running = True
        logger.info("[PLAYBOOK_SCHED] Scheduler started")

    async def stop(self):
        """Stop scheduler."""
        if not self.running:
            return
        self.scheduler.shutdown(wait=True)
        self.running = False
        logger.info("[PLAYBOOK_SCHED] Scheduler stopped")

    async def refresh(self):
        """Reload jobs from database."""
        # Remove existing playbook jobs
        for job in list(self.scheduler.get_jobs()):
            if job.id.startswith("playbook_"):
                self.scheduler.remove_job(job.id)
        await self._load_jobs()

    async def _load_jobs(self):
        if not self.db.connected:
            logger.warning("[PLAYBOOK_SCHED] Database not connected, skipping job load")
            return

        from services.postgres_db import set_platform_admin_mode

        # Enable platform admin mode — runs at startup / refresh without
        # HTTP request context, needs to see all tenants' playbooks.
        set_platform_admin_mode(True)
        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch('''
                    SELECT id, name, trigger_conditions, riggs_allowed
                    FROM playbooks
                    WHERE is_enabled = true
                ''')
        finally:
            set_platform_admin_mode(False)

        for row in rows:
            self._add_job_from_row(row)

        logger.info(f"[PLAYBOOK_SCHED] Loaded {len(rows)} playbook schedules")

    def _add_job_from_row(self, row):
        trigger_conditions = row.get('trigger_conditions') or {}
        if isinstance(trigger_conditions, str):
            try:
                trigger_conditions = json.loads(trigger_conditions)
            except Exception:
                trigger_conditions = {}

        if not trigger_conditions.get('on_schedule'):
            return

        if not row.get('riggs_allowed', False):
            return

        schedule = trigger_conditions.get('schedule') or {}
        cron_expr = schedule.get('cron')
        tz_name = schedule.get('timezone') or 'UTC'
        trigger = _cron_trigger(cron_expr, tz_name)
        if not trigger:
            return

        job_id = f"playbook_{row['id']}"
        playbook_id = str(row['id'])
        playbook_name = row.get('name') or playbook_id

        self.scheduler.add_job(
            self._run_scheduled_playbook,
            trigger=trigger,
            args=[playbook_id, playbook_name, cron_expr, tz_name],
            id=job_id,
            name=f"Playbook Schedule: {playbook_name}",
            replace_existing=True,
            max_instances=1
        )

    async def _run_scheduled_playbook(self, playbook_id: str, playbook_name: str, cron_expr: str, tz_name: str):
        from services.postgres_db import set_platform_admin_mode

        # Cron-fired callback runs without HTTP context — enable admin mode.
        set_platform_admin_mode(True)
        try:
            from services.playbook_trigger_service import trigger_playbooks_for_event

            logger.info(f"[PLAYBOOK_SCHED] Triggering scheduled playbook {playbook_name} ({playbook_id})")
            await trigger_playbooks_for_event(
                event_type="schedule",
                playbook_id=playbook_id,
                schedule_meta={
                    "cron": cron_expr,
                    "timezone": tz_name
                }
            )
        except Exception as e:
            logger.error(f"[PLAYBOOK_SCHED] Failed to run scheduled playbook {playbook_name}: {e}")
        finally:
            set_platform_admin_mode(False)

    def list_jobs(self):
        return [
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            }
            for job in self.scheduler.get_jobs()
        ]


class DelayedExecutionScheduler:
    """
    Background scheduler for resuming delayed playbook executions.

    Polls the database for executions with:
    - status = 'waiting_delay'
    - resume_at <= NOW()

    And resumes them by calling the playbook engine.
    """

    def __init__(self, db, poll_interval_seconds: int = 30):
        self.db = db
        self.poll_interval = poll_interval_seconds
        self._running = False
        self._task = None

    async def start(self):
        """Start the background scheduler."""
        if self._running:
            logger.warning("[DELAY_SCHED] Scheduler is already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"[DELAY_SCHED] Delayed execution scheduler started (poll interval: {self.poll_interval}s)")

    async def stop(self):
        """Stop the background scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[DELAY_SCHED] Delayed execution scheduler stopped")

    async def _run_loop(self):
        """Main polling loop."""
        import asyncio
        from services.postgres_db import set_platform_admin_mode

        while self._running:
            try:
                # Enable platform admin mode — background loop has no HTTP
                # request context, needs admin RLS bypass for all tenants.
                set_platform_admin_mode(True)
                try:
                    await self._check_and_resume_delayed()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"[DELAY_SCHED] Scheduler error: {e}")

            await asyncio.sleep(self.poll_interval)

    async def _check_and_resume_delayed(self):
        """Check for delayed executions that are ready to resume."""
        if not self.db.connected:
            return

        try:
            async with self.db.tenant_acquire() as conn:
                # Find executions ready to resume
                rows = await conn.fetch('''
                    SELECT
                        id,
                        execution_id,
                        playbook_id,
                        current_node_id,
                        execution_context,
                        node_results,
                        resume_at
                    FROM playbook_executions
                    WHERE status = 'waiting_delay'
                      AND resume_at IS NOT NULL
                      AND resume_at <= NOW()
                    LIMIT 10
                ''')

                if not rows:
                    return

                logger.info(f"[DELAY_SCHED] Found {len(rows)} delayed executions ready to resume")

                for row in rows:
                    await self._resume_execution(dict(row))

        except Exception as e:
            logger.error(f"[DELAY_SCHED] Error checking delayed executions: {e}")

    async def _resume_execution(self, execution: dict):
        """Resume a single delayed execution."""
        execution_id = execution['execution_id']
        db_id = str(execution['id'])

        try:
            from services.playbook_engine import PlaybookEngine, NodeResult, ExecutionContext

            logger.info(f"[DELAY_SCHED] Resuming delayed execution: {execution_id}")

            # Mark as running
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE playbook_executions
                    SET status = 'running',
                        resume_at = NULL
                    WHERE id = $1
                ''', execution['id'])

                # Get the full playbook data
                playbook_row = await conn.fetchrow('''
                    SELECT canvas_data FROM playbooks WHERE id = $1
                ''', execution['playbook_id'])

            if not playbook_row:
                logger.error(f"[DELAY_SCHED] Playbook not found for execution {execution_id}")
                return

            canvas_data = playbook_row['canvas_data']
            if isinstance(canvas_data, str):
                canvas_data = json.loads(canvas_data)

            # Parse context
            context_data = execution['execution_context']
            if isinstance(context_data, str):
                context_data = json.loads(context_data)

            # Get the current node and find next node
            current_node_id = execution['current_node_id']

            # Create engine and resume
            engine = PlaybookEngine()

            # Create a result to get next nodes
            delay_result = NodeResult(
                node_id=current_node_id,
                kind="delay",
                status="success",
                outputs={"resumed_after_delay": True}
            )

            next_nodes = engine._get_next_nodes(canvas_data, current_node_id, delay_result)

            if not next_nodes:
                # No next nodes - mark as completed
                async with self.db.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE playbook_executions
                        SET status = 'completed',
                            completed_at = NOW()
                        WHERE id = $1
                    ''', execution['id'])
                logger.info(f"[DELAY_SCHED] Execution {execution_id} completed after delay (no next nodes)")
                return

            # Reconstruct context
            context = ExecutionContext(**context_data)
            context.completed_node_ids.append(current_node_id)

            # Update node results with delay completion
            node_results = execution.get('node_results') or {}
            if isinstance(node_results, str):
                node_results = json.loads(node_results)
            node_results[current_node_id] = {
                "node_id": current_node_id,
                "kind": "delay",
                "status": "success",
                "outputs": {"resumed_after_delay": True}
            }
            context.nodes[current_node_id] = {"resumed_after_delay": True}

            # Continue execution from the next node
            await engine._run_execution(
                execution_id=execution_id,
                db_id=db_id,
                canvas_data=canvas_data,
                context=context,
                start_node_id=next_nodes[0]
            )

            logger.info(f"[DELAY_SCHED] Execution {execution_id} resumed successfully")

        except Exception as e:
            logger.error(f"[DELAY_SCHED] Error resuming execution {execution_id}: {e}")

            # Mark as failed
            try:
                async with self.db.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE playbook_executions
                        SET status = 'failed',
                            error_message = $1,
                            completed_at = NOW()
                        WHERE id = $2
                    ''', f"Failed to resume after delay: {str(e)}", execution['id'])
            except:
                pass
