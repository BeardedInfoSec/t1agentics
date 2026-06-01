# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Monitor Service

Monitors for new alerts and automatically triggers triage.

Features:
1. Database trigger on alert INSERT
2. Background polling (fallback)
3. Automatic fast triage dispatch
4. Alert queue management

Usage:
    # Start monitor
    monitor = AlertMonitor()
    await monitor.start()
"""

import asyncio
import asyncpg
from datetime import datetime, timedelta
from typing import Optional
import logging

from services.postgres_db import get_db
from services.fast_triage import get_triage_service
from services.job_queue import get_job_queue

logger = logging.getLogger(__name__)


class AlertMonitor:
    """
    Alert monitoring service

    Watches for new alerts and automatically triggers fast triage.

    Two modes:
    1. PostgreSQL LISTEN/NOTIFY (real-time, preferred)
    2. Polling (fallback, every 10 seconds)
    """

    def __init__(self, poll_interval: int = 10):
        self.poll_interval = poll_interval  # seconds
        self.running = False
        self.listener_conn: Optional[asyncpg.Connection] = None
        self.last_check = datetime.utcnow()

    async def start(self):
        """Start monitoring for new alerts"""
        self.running = True
        logger.info("🔍 Alert Monitor starting...")

        # Try to use PostgreSQL NOTIFY
        try:
            await self._start_notify_listener()
        except Exception as e:
            logger.warning(f"NOTIFY listener failed, falling back to polling: {e}")
            await self._start_polling()

    async def stop(self):
        """Stop monitoring"""
        self.running = False
        logger.info("🛑 Alert Monitor stopping...")

        if self.listener_conn:
            await self.listener_conn.close()
            self.listener_conn = None

    async def _start_notify_listener(self):
        """
        Use PostgreSQL LISTEN/NOTIFY for real-time alerts

        Requires database trigger:
            CREATE OR REPLACE FUNCTION notify_new_alert()
            RETURNS trigger AS $$
            BEGIN
                PERFORM pg_notify('new_alert', NEW.id::text);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER alert_insert_trigger
            AFTER INSERT ON alerts
            FOR EACH ROW
            EXECUTE FUNCTION notify_new_alert();
        """
        # Create dedicated connection for LISTEN
        self.listener_conn = await asyncpg.connect(
            host="postgres",
            port=5432,
            user="agentcore",
            password="agentcore_dev_password",
            database="agentcore"
        )

        # Set up trigger if not exists
        await self._ensure_trigger_exists()

        # Start listening
        await self.listener_conn.add_listener('new_alert', self._handle_notification)
        logger.info("✅ Real-time alert monitoring active (NOTIFY)")

        # Keep connection alive
        while self.running:
            await asyncio.sleep(1)

    async def _ensure_trigger_exists(self):
        """Create database trigger for new alerts"""
        async with get_db() as conn:
            # Create notify function
            await conn.execute("""
                CREATE OR REPLACE FUNCTION notify_new_alert()
                RETURNS trigger AS $$
                BEGIN
                    PERFORM pg_notify('new_alert', NEW.id::text);
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """)

            # Create trigger if not exists
            await conn.execute("""
                DROP TRIGGER IF EXISTS alert_insert_trigger ON alerts;
                CREATE TRIGGER alert_insert_trigger
                AFTER INSERT ON alerts
                FOR EACH ROW
                EXECUTE FUNCTION notify_new_alert();
            """)

            logger.info("✅ Database trigger configured")

    async def _handle_notification(self, connection, pid, channel, payload):
        """
        Handle new alert notification from PostgreSQL

        Args:
            payload: Alert ID as string
        """
        try:
            alert_id = int(payload)
            logger.info(f"📬 New alert detected: {alert_id}")
            await self._process_alert(alert_id)
        except Exception as e:
            logger.error(f"❌ Failed to handle notification: {e}")

    async def _start_polling(self):
        """
        Poll database for new alerts (fallback mode)

        Checks every N seconds for alerts created since last check.
        """
        logger.info(f"✅ Polling mode active (every {self.poll_interval}s)")

        while self.running:
            try:
                await self._check_for_new_alerts()
            except Exception as e:
                logger.error(f"❌ Polling error: {e}")

            await asyncio.sleep(self.poll_interval)

    async def _check_for_new_alerts(self):
        """Check for alerts created since last check"""
        async with get_db() as conn:
            # Find alerts created since last check that haven't been triaged
            rows = await conn.fetch("""
                SELECT id
                FROM alerts
                WHERE created_at > $1
                  AND status = 'open'
                  AND id NOT IN (
                      SELECT DISTINCT target_id::int
                      FROM job_queue
                      WHERE job_type = 'fast_triage'
                        AND status IN ('pending', 'running', 'completed')
                  )
                ORDER BY created_at ASC
                LIMIT 50
            """, self.last_check)

            if rows:
                logger.info(f"📬 Found {len(rows)} new alerts to triage")
                for row in rows:
                    await self._process_alert(row['id'])

            self.last_check = datetime.utcnow()

    async def _process_alert(self, alert_id: int):
        """
        Process new alert by queuing fast triage

        Args:
            alert_id: Alert database ID
        """
        try:
            # Check if already queued
            async with get_db() as conn:
                existing = await conn.fetchval("""
                    SELECT COUNT(*)
                    FROM job_queue
                    WHERE job_type = 'fast_triage'
                      AND target_id = $1
                      AND status IN ('pending', 'running', 'completed')
                """, str(alert_id))

                if existing > 0:
                    logger.debug(f"Alert {alert_id} already queued, skipping")
                    return

            # Queue auto triage job
            job_queue = get_job_queue()
            job_id = await job_queue.enqueue(
                job_type='agent_auto_triage',
                target_type='alert',
                target_id=str(alert_id),
                priority=self._calculate_priority(alert_id),
                payload={"alert_id": alert_id}
            )

            logger.info(f"✅ Queued fast triage for alert {alert_id} (job {job_id})")

        except Exception as e:
            logger.error(f"❌ Failed to process alert {alert_id}: {e}")

    def _calculate_priority(self, alert_id: int) -> int:
        """
        Calculate job priority based on alert severity

        Returns:
            1 = high priority (critical/high severity)
            5 = normal priority (medium severity)
            9 = low priority (low severity)
        """
        # TODO: Query alert severity from database
        # For now, default to normal priority
        return 5


# Global instance
_alert_monitor = None


def get_alert_monitor() -> AlertMonitor:
    """Get or create alert monitor singleton"""
    global _alert_monitor
    if _alert_monitor is None:
        _alert_monitor = AlertMonitor()
    return _alert_monitor


async def start_alert_monitoring():
    """Start alert monitoring (called from app startup)"""
    monitor = get_alert_monitor()
    await monitor.start()


async def stop_alert_monitoring():
    """Stop alert monitoring (called from app shutdown)"""
    monitor = get_alert_monitor()
    await monitor.stop()
