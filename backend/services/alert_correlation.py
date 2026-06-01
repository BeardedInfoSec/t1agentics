# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Correlation Service

VERSION 3.0 - Hypothesis-Driven Correlation (single path)

Uses hypothesis matching, evidence-based scoring, and entity risk accumulation.
Entities validate but don't score; scoring is evidence-based.
"""

import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


async def correlate_and_link_alert(alert: Dict[str, Any]) -> Optional[str]:
    """
    Correlate an alert using hypothesis-driven correlation (v3).

    Args:
        alert: The alert dict (must have 'alert_id' or 'id' field)

    Returns:
        Investigation ID if linked/created, None otherwise
    """
    try:
        from services.hypothesis_correlation_service import (
            get_hypothesis_correlation_service, DecisionType
        )

        service = get_hypothesis_correlation_service()

        alert_id = alert.get('alert_id') or alert.get('id') or alert.get('external_id')
        if not alert_id:
            logger.warning("Alert missing ID field - cannot correlate")
            return None

        result = await service.correlate_alert(
            alert_id=str(alert_id),
            alert_data=alert,
            create_investigation=True
        )

        logger.info(
            f"Alert {alert_id}: Correlation decision={result.decision.value}, "
            f"investigation={result.investigation_id}, score={result.score}"
        )

        if result.investigation_id:
            return str(result.investigation_id)

        return None

    except Exception as e:
        logger.error(f"Correlation failed for alert: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


# ============================================================
# ALERT-INVESTIGATION LINK HELPERS
# ============================================================

async def get_linked_alerts(investigation_id: str) -> List[Dict[str, Any]]:
    """
    Get all alerts linked to an investigation.

    Args:
        investigation_id: Either the UUID or INV-xxx format

    Returns:
        List of linked alert dicts
    """
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            return []

        async with postgres_db.tenant_acquire() as conn:
            alerts = await conn.fetch("""
                SELECT a.id, a.alert_id, a.title, a.severity, a.status,
                       a.source, a.category, a.description, a.raw_event,
                       a.created_at, a.updated_at
                FROM alerts a
                JOIN investigations i ON a.investigation_id = i.id
                WHERE i.id::text = $1 OR i.investigation_id = $1
                ORDER BY a.created_at DESC
            """, investigation_id)

            return [dict(a) for a in alerts]

    except Exception as e:
        logger.error(f"Error getting linked alerts: {e}")
        return []


async def link_alert_to_investigation(
    alert_id: str,
    investigation_id: str,
    match_reasons: List[str] = None
) -> bool:
    """
    Link an alert to an investigation by updating the alert's investigation_id.

    Args:
        alert_id: The alert's ID (alert_id field, not UUID)
        investigation_id: The investigation's UUID (not INV-xxx)
        match_reasons: Optional reasons for the correlation

    Returns:
        True if successful
    """
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            return False

        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute("""
                UPDATE alerts
                SET investigation_id = $1::uuid,
                    status = 'investigating',
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = $2
                  AND investigation_id IS NULL
            """, investigation_id, alert_id)

            if 'UPDATE 1' in result:
                logger.info(f"Linked alert {alert_id} to investigation {investigation_id}")

                if match_reasons:
                    inv_number = await conn.fetchval(
                        "SELECT investigation_id FROM investigations WHERE id = $1::uuid",
                        investigation_id
                    )
                    if inv_number:
                        await conn.execute("""
                            INSERT INTO investigation_notes
                            (investigation_id, author, author_type, content, note_type)
                            VALUES ($1, 'System', 'SYSTEM', $2, 'correlation')
                        """, inv_number, f"Correlated alert {alert_id}: {', '.join(match_reasons)}")

                return True
            else:
                logger.debug(f"Alert {alert_id} already linked or not found")
                return False

    except Exception as e:
        logger.error(f"Error linking alert to investigation: {e}")
        return False


# ============================================================
# ENTITY CORRELATION HELPERS
# ============================================================

async def get_correlation_explanation(alert_id: str) -> Optional[Dict[str, Any]]:
    """
    Get the explainability data for a correlation decision.

    Args:
        alert_id: The alert ID

    Returns:
        Dict with decision details, reasons, and score breakdown
    """
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            return None

        async with postgres_db.pool.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                SELECT decision_type, investigation_id, score, threshold,
                       reasons, matched_entities, guardrails_applied,
                       processing_time_ms, created_at
                FROM correlation_decisions
                WHERE alert_id = $1
            ''', alert_id)

            if row:
                import json
                return {
                    'decision': row['decision_type'],
                    'investigation_id': row['investigation_id'],
                    'score': row['score'],
                    'threshold': row['threshold'],
                    'reasons': json.loads(row['reasons']) if row['reasons'] else [],
                    'matched_entities': json.loads(row['matched_entities']) if row['matched_entities'] else [],
                    'guardrails_applied': json.loads(row['guardrails_applied']) if row['guardrails_applied'] else [],
                    'processing_time_ms': row['processing_time_ms'],
                    'timestamp': row['created_at'].isoformat() if row['created_at'] else None,
                }
            return None

    except Exception as e:
        logger.error(f"Failed to get correlation explanation: {e}")
        return None


async def get_investigation_entities(investigation_id: int) -> List[Dict[str, Any]]:
    """
    Get all entities associated with an investigation.

    Args:
        investigation_id: The investigation ID

    Returns:
        List of entity dicts with type, value, confidence, alert_count
    """
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            return []

        async with postgres_db.pool.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT entity_type, entity_value, confidence,
                       alert_count, first_seen, last_seen
                FROM investigation_entities
                WHERE investigation_id = $1
                ORDER BY
                    CASE entity_type
                        WHEN 'user' THEN 1
                        WHEN 'host' THEN 2
                        WHEN 'mitre_technique' THEN 3
                        WHEN 'threat_object' THEN 4
                        WHEN 'internal_ip' THEN 5
                        WHEN 'external_ioc' THEN 6
                    END,
                    confidence DESC
            ''', investigation_id)

            return [dict(row) for row in rows]

    except Exception as e:
        logger.error(f"Failed to get investigation entities: {e}")
        return []


async def apply_entity_decay() -> Dict[str, Any]:
    """
    Apply confidence decay to investigation entities.

    This should be called periodically (e.g., hourly) to decay
    entity confidence based on time since last activity.

    Returns:
        Dict with update count and affected investigation IDs
    """
    try:
        from services.entity_correlation_service import get_entity_correlation_service

        service = get_entity_correlation_service()
        return await service.apply_decay()

    except Exception as e:
        logger.error(f"Failed to apply entity decay: {e}")
        return {'error': str(e)}
