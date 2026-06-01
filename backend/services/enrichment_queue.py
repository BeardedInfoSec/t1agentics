# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enrichment Queue Service

Background service that periodically checks for alerts that were missed during
initial enrichment and queues them for processing.

Handles:
- Events that failed initial enrichment due to rate limits
- Events ingested during high load periods
- Events where enrichment timed out
- Bulk imports that exceeded processing limits
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class EnrichmentQueueService:
    """
    Manages a queue of alerts pending enrichment.
    Runs a background loop to catch up on missed enrichments.
    """

    def __init__(self):
        self.enabled = True
        self.batch_size = 20  # Process 20 alerts at a time
        self.check_interval = 60  # Check every 60 seconds
        self.max_alert_age_hours = 24  # Only process alerts from last 24 hours
        self.running = False
        self._task = None

    async def start(self):
        """Start the background enrichment loop."""
        if self.running:
            logger.warning("Enrichment queue already running")
            return

        self.running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Enrichment queue service started")

    async def stop(self):
        """Stop the background enrichment loop."""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Enrichment queue service stopped")

    async def _run_loop(self):
        """Main background loop that checks for pending enrichments."""
        from services.postgres_db import set_platform_admin_mode

        while self.running:
            try:
                # Enable platform admin mode — background loop has no HTTP
                # request context, needs admin RLS bypass for all tenants.
                set_platform_admin_mode(True)
                try:
                    await self._process_pending_alerts()
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.error(f"Enrichment queue error: {e}")

            # Wait before next check
            await asyncio.sleep(self.check_interval)

    async def _process_pending_alerts(self):
        """Find and process alerts that need enrichment."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return

            # Find alerts that:
            # 1. Have IOCs but no enrichment data
            # 2. Were created in the last 24 hours
            # 3. Have status 'open' or 'investigating'
            pending_alerts = await self._find_pending_alerts()

            if not pending_alerts:
                return

            logger.info(f"Found {len(pending_alerts)} alerts pending enrichment")

            # Process in batches
            from services.auto_enrichment import auto_enrichment_service

            from middleware.tenant_middleware import current_tenant_id

            for alert in pending_alerts[:self.batch_size]:
                try:
                    alert_id = alert['alert_id']
                    raw_event = alert.get('raw_event', {})
                    tenant_id = alert.get('_tenant_id')

                    # Skip if already has enrichment
                    if raw_event.get('_extracted', {}).get('enrichment', {}).get('status') == 'enriched':
                        continue

                    logger.info(f"Queue processing: Enriching alert {alert_id} (tenant: {tenant_id})")

                    # Set tenant context for RLS
                    if tenant_id:
                        token = current_tenant_id.set(tenant_id)
                        try:
                            await auto_enrichment_service.enrich_alert(alert_id, raw_event)
                        finally:
                            current_tenant_id.reset(token)
                    else:
                        await auto_enrichment_service.enrich_alert(alert_id, raw_event)

                    # Small delay between enrichments to avoid rate limits
                    await asyncio.sleep(2)

                except Exception as e:
                    logger.warning(f"Failed to enrich queued alert {alert.get('alert_id')}: {e}")

        except Exception as e:
            logger.error(f"Error processing pending alerts: {e}")

    async def _find_pending_alerts(self) -> List[Dict[str, Any]]:
        """
        Find alerts that have IOCs but haven't been enriched.

        Returns alerts where:
        - Created in last 24 hours
        - Has potential IOCs (hashes, IPs, domains in raw_event)
        - No enrichment data exists
        """
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return []

        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=self.max_alert_age_hours)

            async with postgres_db.tenant_acquire() as conn:
                # Scan all active tenants for unenriched alerts (RLS requires tenant context)
                tenants = await conn.fetch("SELECT id::text FROM tenants WHERE status = 'active'")
                results = []
                for tenant in tenants:
                    await conn.execute(f"SET app.current_tenant_id = '{tenant['id']}'")
                    rows = await conn.fetch('''
                        SELECT alert_id, raw_event, created_at
                        FROM alerts
                        WHERE created_at > $1
                          AND status IN ('open', 'investigating')
                          AND (
                              raw_event->>'_extracted' IS NULL
                              OR raw_event->'_extracted'->>'enrichment' IS NULL
                              OR raw_event->'_extracted'->'enrichment'->>'status' != 'enriched'
                          )
                        ORDER BY created_at DESC
                        LIMIT $2
                    ''', cutoff_time, self.batch_size)

                    for row in rows:
                        alert_data = dict(row)
                        alert_data['_tenant_id'] = tenant['id']
                        raw_event = alert_data.get('raw_event', {})

                        # Parse if string
                        if isinstance(raw_event, str):
                            import json
                            try:
                                raw_event = json.loads(raw_event)
                            except:
                                continue

                        # Check if alert has potential IOCs worth enriching
                        if self._has_enrichable_iocs(raw_event):
                            alert_data['raw_event'] = raw_event
                            results.append(alert_data)

                return results

        except Exception as e:
            logger.error(f"Error finding pending alerts: {e}")
            return []

    def _has_enrichable_iocs(self, raw_event: Dict[str, Any]) -> bool:
        """Check if raw_event contains IOCs that can be enriched."""
        import re

        # Convert to string for pattern matching
        event_str = str(raw_event)

        # Check for hashes (MD5, SHA1, SHA256)
        if re.search(r'\b[a-fA-F0-9]{32}\b', event_str):  # MD5
            return True
        if re.search(r'\b[a-fA-F0-9]{40}\b', event_str):  # SHA1
            return True
        if re.search(r'\b[a-fA-F0-9]{64}\b', event_str):  # SHA256
            return True

        # Check for public IPs (exclude private ranges)
        ip_pattern = r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'
        for match in re.finditer(ip_pattern, event_str):
            ip = match.group(0)
            # Skip IPs with leading zeros (e.g., 01.24.04.57)
            parts = ip.split('.')
            if any(len(p) > 1 and p.startswith('0') for p in parts):
                continue
            first = int(match.group(1))
            second = int(match.group(2))

            # Skip private/local IPs
            if first == 10:
                continue
            if first == 172 and 16 <= second <= 31:
                continue
            if first == 192 and second == 168:
                continue
            if first == 127 or first == 0:
                continue

            # Found a public IP
            return True

        # Check for domains (simple heuristic)
        # Look for known fields
        for field in ['domain', 'hostname', 'dns_query', 'url']:
            if field in event_str.lower():
                return True

        # Check structured fields
        if isinstance(raw_event, dict):
            if raw_event.get('file', {}).get('hashes'):
                return True
            if raw_event.get('network', {}).get('remote_ip'):
                return True
            if raw_event.get('dns', {}).get('query'):
                return True

        return False

    async def queue_alert(self, alert_id: str):
        """Manually add an alert to the enrichment queue."""
        # For now, the background loop handles this
        # Could be extended to maintain an in-memory queue for priority processing
        logger.info(f"Alert {alert_id} will be picked up by enrichment queue")

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get statistics about the enrichment queue."""
        from services.postgres_db import postgres_db

        stats = {
            'enabled': self.enabled,
            'running': self.running,
            'batch_size': self.batch_size,
            'check_interval': self.check_interval,
            'pending_count': 0
        }

        if postgres_db.connected:
            try:
                pending = await self._find_pending_alerts()
                stats['pending_count'] = len(pending)
            except:
                pass

        return stats


# Singleton instance
enrichment_queue = EnrichmentQueueService()


async def start_enrichment_queue():
    """Start the enrichment queue service."""
    await enrichment_queue.start()


async def stop_enrichment_queue():
    """Stop the enrichment queue service."""
    await enrichment_queue.stop()
