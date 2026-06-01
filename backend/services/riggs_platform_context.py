"""
Riggs Platform Context Service

Centralizes the cheap reads that enrich RiggsInput with platform-aware
context the audit identified as missing: intake-form intent, entity-risk
state, SLA pressure, the tenant's actually-available connector actions,
and the tenant's custom suppression rules.

Each bundle is best-effort. If a fetch fails (table missing, no rows,
RLS hiccup) we return None for that bundle so Riggs's prompt simply
omits the section — never block the triage path on optional context.

Public entry point:
    await gather_platform_context(tenant_id, investigation, alert)
        -> dict with keys: intake_context, entity_risk_summary,
           sla_context, available_actions, tenant_custom_rules
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# SLA targets mirror frontend/src/components/SecurityQueue/transforms.js
# and backend/services/agent_scheduler._SLA_TARGET_MINUTES so all three
# surfaces agree on what counts as "approaching breach".
_SLA_TARGET_MINUTES = {
    'critical': 60,
    'high':     240,
    'medium':   480,
    'low':      1440,
}


async def gather_platform_context(
    tenant_id: Optional[str],
    investigation: Dict[str, Any],
    alert: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Fetch all five Round B context bundles for a given alert/investigation.
    Returns a dict of {field_name: bundle_or_None} ready to splat into
    build_riggs_input(**ctx).
    """
    result: Dict[str, Any] = {
        'intake_context': None,
        'entity_risk_summary': None,
        'sla_context': _build_sla_context(investigation, alert),
        'available_actions': None,
        'tenant_custom_rules': None,
    }

    if not tenant_id:
        return result

    # Each bundle is fetched independently with a per-bundle try/except so
    # a single failure (e.g., entity_risk table doesn't exist on a fresh
    # tenant) doesn't drop the others.
    result['intake_context'] = await _fetch_intake_context(tenant_id, alert)
    result['entity_risk_summary'] = await _fetch_entity_risk(tenant_id, alert)
    result['available_actions'] = await _fetch_available_actions(tenant_id, alert)
    result['tenant_custom_rules'] = await _fetch_tenant_custom_rules(tenant_id)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# SLA — derived in-process from investigation.created_at; no DB hit.
# ─────────────────────────────────────────────────────────────────────────────

def _build_sla_context(
    investigation: Dict[str, Any],
    alert: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    try:
        severity = (
            investigation.get('severity')
            or alert.get('severity')
            or 'medium'
        ).lower()
        target = _SLA_TARGET_MINUTES.get(severity, _SLA_TARGET_MINUTES['medium'])

        created_raw = investigation.get('created_at') or alert.get('created_at')
        if not created_raw:
            return {
                'target_minutes': target,
                'elapsed_minutes': None,
                'breached': False,
            }

        if isinstance(created_raw, str):
            # asyncpg gives back tz-aware datetimes, but the orchestrator
            # may serialize to ISO before getting here. Tolerate both.
            created = datetime.fromisoformat(created_raw.replace('Z', '+00:00'))
        else:
            created = created_raw

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        elapsed_min = (datetime.now(timezone.utc) - created).total_seconds() / 60.0
        return {
            'severity': severity,
            'target_minutes': target,
            'elapsed_minutes': elapsed_min,
            'breached': elapsed_min > target,
        }
    except Exception as e:
        logger.debug(f"riggs_platform_context: SLA derivation failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Intake form context — only present if the alert came in via /api/v1/intake.
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_intake_context(
    tenant_id: str,
    alert: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if (alert.get('source_type') or '').lower() != 'intake_form':
        return None
    alert_id = alert.get('alert_id')
    if not alert_id:
        return None
    try:
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT s.id           AS submission_id,
                       s.submitted_by,
                       s.payload,
                       f.name         AS form_name,
                       f.title        AS form_title,
                       f.alert_template
                  FROM intake_form_submissions s
                  JOIN intake_forms f ON f.id = s.form_id
                 WHERE s.alert_id = $1
                 LIMIT 1
                """,
                alert_id,
            )
        if not row:
            return None

        alert_tpl = row['alert_template'] or {}
        if isinstance(alert_tpl, str):
            import json
            try:
                alert_tpl = json.loads(alert_tpl)
            except Exception:
                alert_tpl = {}

        # Build a short, deterministic prose summary of the submission so
        # Riggs sees what the user actually wrote, not the rendered alert
        # title. Cap at 600 chars.
        summary_parts = []
        payload = row['payload'] or {}
        if isinstance(payload, str):
            import json
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        if isinstance(payload, dict):
            for k, v in list(payload.items())[:8]:
                if v is None or v == '':
                    continue
                v_str = str(v) if not isinstance(v, list) else ', '.join(str(x) for x in v)
                if len(v_str) > 120:
                    v_str = v_str[:117] + '...'
                summary_parts.append(f"{k}={v_str}")
        summary = '; '.join(summary_parts)
        if len(summary) > 600:
            summary = summary[:597] + '...'

        return {
            'submission_id': str(row['submission_id']),
            'form_name': row['form_name'],
            'form_title': row['form_title'],
            'category': alert_tpl.get('category'),
            'submitter': row['submitted_by'],
            'summary': summary or None,
        }
    except Exception as e:
        logger.debug(f"riggs_platform_context: intake fetch failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Entity risk — surface current score for entities mentioned in this alert.
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_entity_risk(
    tenant_id: str,
    alert: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    # Pull the entities directly off the alert's raw_event so we don't have
    # to wait for the full Riggs extraction (which runs after this).
    raw_event = alert.get('raw_event') or {}
    if isinstance(raw_event, str):
        import json
        try:
            raw_event = json.loads(raw_event)
        except Exception:
            raw_event = {}

    candidates: List[Dict[str, str]] = []
    # Users
    for key in ('username', 'user', 'user_name', 'src_user', 'dst_user', 'reporter_email'):
        v = raw_event.get(key) or alert.get(key)
        if v and isinstance(v, str):
            candidates.append({'type': 'user', 'value': v.lower()})
    # Hosts
    for key in ('hostname', 'host', 'src_host', 'dst_host', 'computer_name'):
        v = raw_event.get(key) or alert.get(key)
        if v and isinstance(v, str):
            candidates.append({'type': 'host', 'value': v.lower()})

    if not candidates:
        return None

    try:
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            # Build VALUES clause for a tuple lookup.
            values_sql = ", ".join(
                f"(${i*2+1}, ${i*2+2})" for i in range(len(candidates))
            )
            params: List[Any] = []
            for c in candidates:
                params.extend([c['type'], c['value']])

            rows = await conn.fetch(
                f"""
                WITH lookup(entity_type, entity_value) AS (
                    VALUES {values_sql}
                )
                SELECT er.entity_type,
                       er.entity_value,
                       er.score,
                       er.threshold,
                       er.threshold_breached,
                       er.related_alert_count,
                       er.last_updated
                  FROM entity_risk er
                  JOIN lookup l
                    ON LOWER(er.entity_type)  = LOWER(l.entity_type)
                   AND LOWER(er.entity_value) = LOWER(l.entity_value)
                """,
                *params,
            )
        if not rows:
            return None
        return {
            'entities': [
                {
                    'entity_type': r['entity_type'],
                    'entity_value': r['entity_value'],
                    'score': float(r['score'] or 0),
                    'threshold': float(r['threshold'] or 100),
                    'threshold_breached': bool(r['threshold_breached']),
                    'related_alert_count': int(r['related_alert_count'] or 0),
                }
                for r in rows
            ],
        }
    except Exception as e:
        # entity_risk table may not exist on every tenant — fine to skip silently.
        logger.debug(f"riggs_platform_context: entity_risk fetch failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Available connector actions — what the tenant can actually execute.
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_available_actions(
    tenant_id: str,
    alert: Dict[str, Any],
) -> Optional[List[Dict[str, Any]]]:
    try:
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT cd.name AS connector_name,
                       ca.action_id,
                       ca.display_name AS action_name,
                       ca.ioc_types
                  FROM connect_instances ci
                  JOIN connector_definitions cd ON cd.id = ci.connector_id
             LEFT JOIN connector_actions ca ON ca.connector_id = cd.id
                 WHERE ci.enabled = TRUE
                 LIMIT 40
                """
            )
        actions: List[Dict[str, Any]] = []
        for r in rows:
            if not r['action_id']:
                continue
            ioc_types = r['ioc_types']
            ioc_type_str = ''
            if isinstance(ioc_types, list) and ioc_types:
                ioc_type_str = ','.join(str(t) for t in ioc_types[:3])
            actions.append({
                'connector': r['connector_name'],
                'action': r['action_name'] or r['action_id'],
                'action_id': r['action_id'],
                'ioc_type': ioc_type_str,
            })
        return actions or None
    except Exception as e:
        logger.debug(f"riggs_platform_context: available_actions fetch failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Tenant custom rules — dedup / phishing-test / trusted-sender / PII patterns.
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_tenant_custom_rules(tenant_id: str) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    try:
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            # Phishing test list — tenant-self-reported test senders that
            # should never escalate.
            try:
                rows = await conn.fetch(
                    "SELECT sender FROM phishing_test_senders LIMIT 20"
                )
                if rows:
                    out['phishing_test_senders'] = [r['sender'] for r in rows if r['sender']]
            except Exception:
                pass
            # Trusted sender allowlist.
            try:
                rows = await conn.fetch(
                    "SELECT sender FROM trusted_senders LIMIT 20"
                )
                if rows:
                    out['trusted_senders'] = [r['sender'] for r in rows if r['sender']]
            except Exception:
                pass
            # Dedup rules — just a count, since Riggs only needs to know
            # they exist to recommend dismissal when matched.
            try:
                cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM dedup_rules WHERE enabled = TRUE"
                )
                if cnt:
                    out['dedup_rules'] = [{'enabled_count': int(cnt)}]
            except Exception:
                pass
            # PII patterns — same.
            try:
                cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM custom_pii_patterns WHERE enabled = TRUE"
                )
                if cnt:
                    out['pii_patterns'] = [{'enabled_count': int(cnt)}]
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"riggs_platform_context: tenant_custom_rules fetch failed: {e}")
        return None
    return out or None
