# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Trigger Service

Evaluates playbook trigger_conditions and starts executions on lifecycle events.
"""

import json
import logging
import uuid
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


async def trigger_playbooks_for_event(
    event_type: str,
    alert: Optional[Dict[str, Any]] = None,
    investigation: Optional[Dict[str, Any]] = None,
    alert_id: Optional[str] = None,
    investigation_id: Optional[str] = None,
    webhook_path: Optional[str] = None,
    schedule_meta: Optional[Dict[str, Any]] = None,
    playbook_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Trigger playbooks configured for a given event type.

    event_type: alert_created, alert_closed, investigation_created, investigation_closed, webhook, schedule
    """
    try:
        from services.postgres_db import postgres_db
        from services.playbook_engine import get_playbook_engine

        if not postgres_db.connected:
            return []

        async with postgres_db.tenant_acquire() as conn:
            if playbook_id:
                playbook_uuid = playbook_id if isinstance(playbook_id, uuid.UUID) else uuid.UUID(playbook_id)
                rows = await conn.fetch('''
                    SELECT id, name, trigger_conditions, riggs_allowed,
                           alert_types, severity_filter, data_sources
                    FROM playbooks
                    WHERE is_enabled = true
                    AND id = $1
                ''', playbook_uuid)
            else:
                rows = await conn.fetch('''
                    SELECT id, name, trigger_conditions, riggs_allowed,
                           alert_types, severity_filter, data_sources
                    FROM playbooks
                    WHERE is_enabled = true
                ''')

        engine = get_playbook_engine()
        results = []

        for row in rows:
            trigger_conditions = row.get('trigger_conditions') or {}
            if isinstance(trigger_conditions, str):
                try:
                    trigger_conditions = json.loads(trigger_conditions)
                except Exception:
                    trigger_conditions = {}

            flag = _event_flag(event_type)
            if flag and not trigger_conditions.get(flag, False):
                continue

            if event_type == "webhook":
                expected_path = (trigger_conditions.get('webhook') or {}).get('path')
                if expected_path and webhook_path:
                    if expected_path.rstrip('/') != webhook_path.rstrip('/'):
                        continue

            if not row.get('riggs_allowed', False):
                continue

            if alert and not _alert_matches_playbook(row, alert):
                continue

            trigger_context = {
                "event_type": event_type,
                "alert": alert,
                "investigation": investigation,
                "alert_id": alert_id,
                "investigation_id": investigation_id,
                "webhook_path": webhook_path,
                "schedule": schedule_meta
            }

            result = await engine.start_execution(
                playbook_id=str(row['id']),
                trigger_context=trigger_context,
                triggered_by=event_type
            )

            if "error" not in result:
                results.append({
                    "playbook_id": str(row['id']),
                    "playbook_name": row.get('name'),
                    "execution_id": result.get("execution_id"),
                    "status": result.get("status")
                })

        return results

    except Exception as e:
        logger.error(f"Failed to trigger playbooks for {event_type}: {e}")
        return []


def _event_flag(event_type: str) -> Optional[str]:
    return {
        "alert_created": "on_alert_created",
        "alert_closed": "on_alert_closed",
        "investigation_created": "on_investigation_created",
        "investigation_closed": "on_investigation_closed",
        "webhook": "on_webhook",
        "schedule": "on_schedule",
    }.get(event_type)


def _alert_matches_playbook(playbook_row, alert: Dict[str, Any]) -> bool:
    alert_type = alert.get('alert_type') or alert.get('type')
    severity = alert.get('severity')
    data_source = alert.get('data_source') or alert.get('source')

    alert_types = playbook_row.get('alert_types') or []
    severity_filter = playbook_row.get('severity_filter') or []
    data_sources = playbook_row.get('data_sources') or []

    if alert_types and alert_type and alert_type not in alert_types:
        return False
    if severity_filter and severity and severity not in severity_filter:
        return False
    if data_sources and data_source and data_source not in data_sources:
        return False

    return True
