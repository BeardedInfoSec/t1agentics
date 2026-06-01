# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Update Scheduler

Background service that automatically updates integrations from their
OpenAPI specifications on a configurable schedule (daily, weekly, monthly).

Features:
- Runs as a background task in FastAPI
- Checks for spec changes using content hash
- Detects added/removed/modified actions
- Records all updates in history table
- Configurable per-integration schedule
"""

import asyncio
import hashlib
from datetime import datetime, time, timedelta
from typing import Optional, Dict, Any, List
import httpx

from services.postgres_db import get_pool
from integrations.engines.swagger_ingestion import get_ingestion_engine
from integrations.registry.integration_registry import get_registry


class IntegrationUpdateScheduler:
    """
    Background scheduler for integration auto-updates.

    Runs continuously and checks which integrations need updates
    based on their configured schedules.
    """

    def __init__(self):
        self.running = False
        self.check_interval_minutes = 15  # Check every 15 minutes
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the scheduler background task."""
        if self.running:
            return

        self.running = True
        self._task = asyncio.create_task(self._run_scheduler())
        print("Integration Update Scheduler started")

    async def stop(self):
        """Stop the scheduler."""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("Integration Update Scheduler stopped")

    async def _run_scheduler(self):
        """Main scheduler loop."""
        while self.running:
            try:
                await self._check_and_update()
            except Exception as e:
                print(f"Scheduler error: {e}")

            # Wait before next check
            await asyncio.sleep(self.check_interval_minutes * 60)

    async def _check_and_update(self):
        """Check all scheduled integrations and update if needed."""
        pool = await get_pool()
        if not pool:
            return

        now = datetime.utcnow()
        current_time = now.time()
        current_day = now.weekday()  # 0=Monday in Python, need to convert

        # Convert to Sunday=0 format (SQL standard)
        sql_day = (current_day + 1) % 7

        async with pool.acquire() as conn:
            # Get integrations due for update
            schedules = await conn.fetch("""
                SELECT
                    integration_id,
                    openapi_spec_url,
                    update_frequency,
                    day_of_week,
                    time_of_day,
                    last_check_at,
                    last_spec_hash
                FROM integration_update_schedules
                WHERE enabled = TRUE
            """)

            for schedule in schedules:
                if self._should_update(schedule, now, sql_day, current_time):
                    await self._update_integration(
                        schedule['integration_id'],
                        schedule['openapi_spec_url'],
                        schedule['last_spec_hash']
                    )

    def _should_update(
        self,
        schedule: Dict[str, Any],
        now: datetime,
        current_day: int,
        current_time: time
    ) -> bool:
        """Determine if an integration should be updated now."""
        frequency = schedule['update_frequency']
        scheduled_day = schedule['day_of_week']
        scheduled_time = schedule['time_of_day']
        last_check = schedule['last_check_at']

        # Manual only - skip
        if frequency == 'manual':
            return False

        # Check if we've already checked recently (within 1 hour)
        if last_check:
            time_since_check = now - last_check.replace(tzinfo=None)
            if time_since_check < timedelta(hours=1):
                return False

        # Check time window (within 30 minutes of scheduled time)
        if scheduled_time:
            scheduled_minutes = scheduled_time.hour * 60 + scheduled_time.minute
            current_minutes = current_time.hour * 60 + current_time.minute
            time_diff = abs(current_minutes - scheduled_minutes)
            if time_diff > 30 and time_diff < (24 * 60 - 30):
                return False

        # Frequency-specific checks
        if frequency == 'daily':
            return True

        elif frequency == 'weekly':
            # Check if it's the right day
            return current_day == scheduled_day

        elif frequency == 'monthly':
            # Run on the first occurrence of scheduled day each month
            if current_day != scheduled_day:
                return False
            # Check if this is the first occurrence this month
            if last_check:
                if last_check.month == now.month and last_check.year == now.year:
                    return False
            return now.day <= 7  # First week of month

        return False

    async def _update_integration(
        self,
        integration_id: str,
        spec_url: str,
        last_hash: Optional[str]
    ):
        """Perform the actual update for an integration."""
        pool = await get_pool()
        if not pool:
            return

        ingestion = get_ingestion_engine()
        registry = get_registry()
        started_at = datetime.utcnow()

        try:
            # Fetch the spec
            async with httpx.AsyncClient() as client:
                response = await client.get(spec_url, timeout=60.0)
                response.raise_for_status()
                spec_content = response.text

            # Calculate hash
            current_hash = hashlib.sha256(spec_content.encode()).hexdigest()

            # Check if changed
            if current_hash == last_hash:
                async with pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE integration_update_schedules
                        SET last_check_at = $2,
                            last_update_status = 'no_changes'
                        WHERE integration_id = $1
                    """, integration_id, started_at)

                    await conn.execute("""
                        INSERT INTO integration_update_history (
                            integration_id, update_type, status, spec_url,
                            triggered_by, started_at, completed_at,
                            duration_ms
                        )
                        VALUES ($1, 'scheduled', 'no_changes', $2, 'scheduler',
                                $3, NOW(), $4)
                    """,
                        integration_id,
                        spec_url,
                        started_at,
                        int((datetime.utcnow() - started_at).total_seconds() * 1000)
                    )

                print(f"[Scheduler] {integration_id}: No changes detected")
                return

            # Get current state
            current = registry.get(integration_id)
            actions_before = len(current.actions) if current else 0
            previous_version = current.version if current else None

            # Re-import the integration
            updated = await ingestion.update_integration(integration_id, spec_url)
            actions_after = len(updated.actions)

            # Calculate changes
            old_action_ids = set(a.id for a in current.actions) if current else set()
            new_action_ids = set(a.id for a in updated.actions)

            actions_added = list(new_action_ids - old_action_ids)
            actions_removed = list(old_action_ids - new_action_ids)
            # For modified, we'd need deeper comparison - simplified here
            actions_modified = []

            completed_at = datetime.utcnow()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Update database
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE integration_update_schedules
                    SET last_check_at = $2,
                        last_update_at = $2,
                        last_update_status = 'success',
                        last_spec_hash = $3,
                        actions_added = $4,
                        actions_removed = $5,
                        actions_modified = $6,
                        updated_at = NOW()
                    WHERE integration_id = $1
                """,
                    integration_id,
                    completed_at,
                    current_hash,
                    len(actions_added),
                    len(actions_removed),
                    len(actions_modified)
                )

                import json
                await conn.execute("""
                    INSERT INTO integration_update_history (
                        integration_id, update_type, status, spec_url,
                        previous_version, new_version,
                        actions_before, actions_after,
                        actions_added, actions_removed, actions_modified,
                        triggered_by, started_at, completed_at, duration_ms
                    )
                    VALUES ($1, 'scheduled', 'success', $2, $3, $4, $5, $6,
                            $7::jsonb, $8::jsonb, $9::jsonb,
                            'scheduler', $10, $11, $12)
                """,
                    integration_id,
                    spec_url,
                    previous_version,
                    updated.version,
                    actions_before,
                    actions_after,
                    json.dumps(actions_added),
                    json.dumps(actions_removed),
                    json.dumps(actions_modified),
                    started_at,
                    completed_at,
                    duration_ms
                )

            print(f"[Scheduler] {integration_id}: Updated successfully "
                  f"(+{len(actions_added)} -{len(actions_removed)} actions)")

        except Exception as e:
            completed_at = datetime.utcnow()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE integration_update_schedules
                    SET last_check_at = $2,
                        last_update_status = 'failed',
                        last_update_error = $3
                    WHERE integration_id = $1
                """, integration_id, completed_at, str(e))

                await conn.execute("""
                    INSERT INTO integration_update_history (
                        integration_id, update_type, status, spec_url,
                        error_message, triggered_by,
                        started_at, completed_at, duration_ms
                    )
                    VALUES ($1, 'scheduled', 'failed', $2, $3, 'scheduler',
                            $4, $5, $6)
                """,
                    integration_id,
                    spec_url,
                    str(e),
                    started_at,
                    completed_at,
                    duration_ms
                )

            print(f"[Scheduler] {integration_id}: Update failed - {e}")

    async def trigger_update(self, integration_id: str) -> Dict[str, Any]:
        """
        Manually trigger an update for a specific integration.

        Returns the update result.
        """
        pool = await get_pool()
        if not pool:
            return {"success": False, "error": "Database not available"}

        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT openapi_spec_url, last_spec_hash
                FROM integration_update_schedules
                WHERE integration_id = $1
            """, integration_id)

            if not row:
                return {"success": False, "error": "No schedule found"}

        await self._update_integration(
            integration_id,
            row['openapi_spec_url'],
            row['last_spec_hash']
        )

        return {"success": True, "integration_id": integration_id}

    async def update_all(self) -> Dict[str, Any]:
        """
        Trigger updates for all scheduled integrations.

        Useful for manual "update all" button.
        """
        pool = await get_pool()
        if not pool:
            return {"success": False, "error": "Database not available"}

        results = {"updated": [], "no_changes": [], "failed": []}

        async with pool.acquire() as conn:
            schedules = await conn.fetch("""
                SELECT integration_id, openapi_spec_url, last_spec_hash
                FROM integration_update_schedules
                WHERE enabled = TRUE
            """)

        for schedule in schedules:
            try:
                await self._update_integration(
                    schedule['integration_id'],
                    schedule['openapi_spec_url'],
                    schedule['last_spec_hash']
                )
                # Check the result
                async with pool.acquire() as conn:
                    status = await conn.fetchval("""
                        SELECT last_update_status
                        FROM integration_update_schedules
                        WHERE integration_id = $1
                    """, schedule['integration_id'])

                if status == 'success':
                    results['updated'].append(schedule['integration_id'])
                elif status == 'no_changes':
                    results['no_changes'].append(schedule['integration_id'])
                else:
                    results['failed'].append(schedule['integration_id'])

            except Exception as e:
                results['failed'].append(schedule['integration_id'])

        return {
            "success": True,
            "results": results,
            "total": len(schedules)
        }


# Global scheduler instance
_scheduler: Optional[IntegrationUpdateScheduler] = None


def get_scheduler() -> IntegrationUpdateScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = IntegrationUpdateScheduler()
    return _scheduler


async def start_scheduler():
    """Start the global scheduler."""
    scheduler = get_scheduler()
    await scheduler.start()


async def stop_scheduler():
    """Stop the global scheduler."""
    scheduler = get_scheduler()
    await scheduler.stop()
