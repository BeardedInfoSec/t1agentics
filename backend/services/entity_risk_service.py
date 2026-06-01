# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Entity Risk Accumulation Service

Tracks risk scores per entity (user, host, IP, domain, hash) across alerts.
When an entity's accumulated risk crosses a configurable threshold,
it triggers elevated-priority correlation and surfaces in the UI.

Risk calculation per alert:
- Critical severity: +40 base
- High: +25, Medium: +15, Low: +5
- Malicious verdict multiplier: x2
- Suspicious verdict multiplier: x1.5
- Temporal decay: score * (0.5 ^ (hours_since / decay_hours))
"""

import json
import logging
import math
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Severity -> base risk contribution
SEVERITY_SCORES = {
    'critical': 40,
    'high': 25,
    'medium': 15,
    'low': 5,
}

# Verdict multipliers
VERDICT_MULTIPLIERS = {
    'MALICIOUS': 2.0,
    'malicious': 2.0,
    'SUSPICIOUS': 1.5,
    'suspicious': 1.5,
}


class EntityRiskService:
    """Accumulates and manages entity risk scores across alerts."""

    async def _get_pool(self):
        try:
            from services.postgres_db import postgres_db
            if postgres_db.pool:
                return postgres_db
        except Exception as e:
            logger.error(f"Failed to get database pool: {e}")
        return None

    async def get_tenant_settings(self, tenant_id: str) -> Dict[str, Any]:
        """Load correlation settings for a tenant, returning defaults if none exist."""
        pool = await self._get_pool()
        if not pool:
            return self._default_settings()

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM correlation_settings WHERE tenant_id = $1::uuid",
                    tenant_id
                )
                if row:
                    return dict(row)
        except Exception as e:
            logger.debug(f"Could not load correlation settings: {e}")

        return self._default_settings()

    def _default_settings(self) -> Dict[str, Any]:
        return {
            'correlation_enabled': True,
            'ai_hypothesis_enabled': True,
            'entity_risk_enabled': True,
            'allow_cross_domain': False,
            'time_window_hours': 24,
            'min_evidence_score': 40,
            'auto_confirm_threshold': 100,
            'max_alerts_per_investigation': 25,
            'entity_risk_threshold': 75,
            'entity_risk_decay_hours': 72,
            'user_weight': 30,
            'host_weight': 25,
            'ip_weight': 15,
            'ioc_weight': 20,
        }

    def _extract_entities(self, alert_data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract (entity_type, entity_value) pairs from alert data."""
        entities = []
        raw_event = alert_data.get('raw_event', {})
        if not isinstance(raw_event, dict):
            return entities

        # Check _extracted at multiple levels
        for extracted_src in [raw_event.get('_extracted', {}),
                              (raw_event.get('raw_event', {}) or {}).get('_extracted', {})]:
            if not isinstance(extracted_src, dict):
                continue
            ent = extracted_src.get('entities', {})
            if isinstance(ent, dict):
                for u in ent.get('users', []):
                    entities.append(('user', str(u).lower()))
                if ent.get('user'):
                    entities.append(('user', str(ent['user']).lower()))
                for h in ent.get('hosts', []):
                    entities.append(('host', str(h).lower()))
                if ent.get('host'):
                    entities.append(('host', str(ent['host']).lower()))
                for ip in ent.get('ips', []):
                    entities.append(('ip', str(ip)))

            iocs = extracted_src.get('iocs', {})
            if isinstance(iocs, dict):
                for ip in iocs.get('ips', []):
                    entities.append(('ip', str(ip)))
                for d in iocs.get('domains', []):
                    entities.append(('domain', str(d).lower()))
                for h in iocs.get('file_hashes', []) + iocs.get('hashes', []):
                    entities.append(('hash', str(h).lower()))

        # Direct raw_event fields
        if raw_event.get('user'):
            entities.append(('user', str(raw_event['user']).lower()))
        for f in ['hostname', 'host']:
            if raw_event.get(f):
                entities.append(('host', str(raw_event[f]).lower()))
        if raw_event.get('source_ip'):
            entities.append(('ip', str(raw_event['source_ip'])))

        # Deduplicate
        return list(set(entities))

    def _calculate_risk_contribution(self, alert_data: Dict[str, Any]) -> float:
        """Calculate the risk score an alert contributes to its entities."""
        severity = (alert_data.get('severity') or 'medium').lower()
        base = SEVERITY_SCORES.get(severity, 15)

        # Check verdict
        verdict = ''
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, dict):
            for extracted_src in [raw_event.get('_extracted', {}),
                                  (raw_event.get('raw_event', {}) or {}).get('_extracted', {})]:
                if isinstance(extracted_src, dict):
                    ai_triage = extracted_src.get('ai_triage', {})
                    if isinstance(ai_triage, dict):
                        verdict = ai_triage.get('verdict', '')
                        if verdict:
                            break

        multiplier = VERDICT_MULTIPLIERS.get(verdict, 1.0)
        return base * multiplier

    async def accumulate_risk(
        self,
        tenant_id: str,
        alert_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract entities from alert and accumulate risk scores.

        Returns list of entities that breached the threshold.
        """
        pool = await self._get_pool()
        if not pool:
            return []

        settings = await self.get_tenant_settings(tenant_id)
        if not settings.get('entity_risk_enabled', True):
            return []

        entities = self._extract_entities(alert_data)
        if not entities:
            return []

        risk_contribution = self._calculate_risk_contribution(alert_data)
        alert_id = alert_data.get('alert_id') or alert_data.get('id') or 'unknown'
        threshold = settings.get('entity_risk_threshold', 75)
        breached = []

        try:
            async with pool.tenant_acquire() as conn:
                for entity_type, entity_value in entities:
                    # Apply entity weight from settings
                    weight_key = f"{entity_type}_weight"
                    weight = settings.get(weight_key, 20) / 20.0  # Normalize around default=20
                    weighted_risk = risk_contribution * weight

                    row = await conn.fetchrow("""
                        INSERT INTO entity_risk (
                            tenant_id, entity_type, entity_value,
                            risk_score, alert_count, contributing_alerts,
                            first_seen, last_seen
                        ) VALUES (
                            $1::uuid, $2, $3,
                            $4, 1, $5::jsonb,
                            NOW(), NOW()
                        )
                        ON CONFLICT (tenant_id, entity_type, entity_value)
                        DO UPDATE SET
                            risk_score = entity_risk.risk_score + $4,
                            alert_count = entity_risk.alert_count + 1,
                            contributing_alerts = (
                                entity_risk.contributing_alerts || $5::jsonb
                            ),
                            last_seen = NOW()
                        RETURNING id, risk_score, threshold_breached
                    """,
                        tenant_id,
                        entity_type,
                        entity_value,
                        weighted_risk,
                        json.dumps([{
                            'alert_id': str(alert_id),
                            'contribution': weighted_risk,
                            'severity': alert_data.get('severity', 'medium'),
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                        }]),
                    )

                    if row and row['risk_score'] >= threshold and not row['threshold_breached']:
                        # Threshold just breached
                        await conn.execute("""
                            UPDATE entity_risk
                            SET threshold_breached = true,
                                threshold_breached_at = NOW()
                            WHERE id = $1
                        """, row['id'])
                        breached.append({
                            'entity_type': entity_type,
                            'entity_value': entity_value,
                            'risk_score': float(row['risk_score']),
                        })

        except Exception as e:
            logger.error(f"Failed to accumulate entity risk: {e}")

        if breached:
            breached_names = [b["entity_type"] + ":" + b["entity_value"] for b in breached]
            logger.info(
                f"Tenant {tenant_id}: {len(breached)} entities breached risk threshold: {breached_names}"
            )
            # Auto-create an investigation grouping the contributing alerts.
            # Best-effort; never blocks the alert pipeline if it fails.
            try:
                await self._auto_create_breach_investigation(tenant_id, breached)
            except Exception as inv_err:
                logger.warning(
                    f"Tenant {tenant_id}: failed to auto-create breach investigation: {inv_err}"
                )

        return breached

    async def check_for_breached_entities(
        self,
        tenant_id: str,
        alert_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Return any currently-flagged entities that this alert touches.

        Used by the alert pipeline to bump severity on future alerts
        involving entities that have already crossed the risk threshold.
        Read-only — does NOT mutate scores.
        """
        entities = self._extract_entities(alert_data)
        if not entities:
            return []

        pool = await self._get_pool()
        if not pool:
            return []

        # Build IN ((type, value), ...) tuple-match. Postgres supports
        # row-value comparison: WHERE (entity_type, entity_value) IN (($2,$3), ($4,$5), ...)
        placeholders: List[str] = []
        params: List[Any] = [tenant_id]
        for etype, evalue in entities:
            params.append(etype)
            params.append(evalue)
            placeholders.append(f"(${len(params) - 1}, ${len(params)})")

        sql = (
            "SELECT entity_type, entity_value, risk_score, alert_count "
            "FROM entity_risk "
            "WHERE tenant_id = $1::uuid "
            "  AND threshold_breached = TRUE "
            f"  AND (entity_type, entity_value) IN ({', '.join(placeholders)})"
        )

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch(sql, *params)
            return [
                {
                    "entity_type": r["entity_type"],
                    "entity_value": r["entity_value"],
                    "risk_score": float(r["risk_score"]),
                    "alert_count": int(r["alert_count"]),
                }
                for r in rows
            ]
        except Exception as e:
            logger.debug(f"check_for_breached_entities failed: {e}")
            return []

    async def _auto_create_breach_investigation(
        self,
        tenant_id: str,
        breached: List[Dict[str, Any]],
    ) -> None:
        """
        When entities breach the risk threshold, spawn an investigation
        that groups their contributing alerts as evidence.

        Idempotency: we don't create a second investigation for an entity
        that already has one. The breach flag flips once per entity (see
        accumulate_risk), so re-entry should be rare — but defending
        against repeat triggers anyway because race-condition reasons.

        Doesn't relink the contributing alerts to this investigation —
        each alert keeps whatever investigation_id it had. The new
        investigation references them in metadata only, so we don't
        orphan alerts that were already correlated elsewhere.
        """
        from services.postgres_db import postgres_db
        import secrets
        try:
            from datetime import datetime as _dt
        except Exception:
            return

        for ent in breached:
            entity_type = ent["entity_type"]
            entity_value = ent["entity_value"]
            risk_score = ent["risk_score"]

            # Fetch this entity's row to get contributing_alerts and stats
            try:
                async with postgres_db.pool.acquire() as conn:
                    await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
                    row = await conn.fetchrow(
                        "SELECT id, contributing_alerts, alert_count, first_seen, last_seen "
                        "FROM entity_risk "
                        "WHERE tenant_id = $1::uuid "
                        "  AND entity_type = $2 AND entity_value = $3",
                        tenant_id, entity_type, entity_value,
                    )
            except Exception as e:
                logger.debug(f"breach inv: fetch entity_risk row failed: {e}")
                continue
            if not row:
                continue

            contributing = row["contributing_alerts"]
            if isinstance(contributing, str):
                try:
                    contributing = json.loads(contributing)
                except Exception:
                    contributing = []
            if not isinstance(contributing, list):
                contributing = []

            # Find an anchor alert_id from the contributing list — the most recent
            anchor_alert_id = None
            if contributing:
                # Each entry has {alert_id, contribution, severity, timestamp}
                try:
                    sorted_contrib = sorted(
                        contributing,
                        key=lambda c: c.get("timestamp", ""),
                        reverse=True,
                    )
                    anchor_alert_id = (sorted_contrib[0] or {}).get("alert_id")
                except Exception:
                    anchor_alert_id = (contributing[-1] or {}).get("alert_id")

            inv_id = f"INV-{secrets.token_hex(4).upper()}"
            title = f"High-risk {entity_type}: {entity_value}"
            summary = (
                f"Entity {entity_type}={entity_value} crossed the risk threshold "
                f"(score {risk_score:.0f}) after {row['alert_count']} contributing alerts. "
                f"Auto-created investigation groups them for triage."
            )

            investigation_data = {
                "investigation_id": inv_id,
                "alert_id": anchor_alert_id,  # nullable
                "alert_title": title,
                "summary": summary,
                "state": "NEW",
                "disposition": "SUSPICIOUS",
                "priority": "P1" if risk_score >= 100 else "P2",
                "severity": "high",
                "confidence": 0.85,
                "investigation_data": {
                    "trigger": "entity_risk_threshold_breach",
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "risk_score": risk_score,
                    "alert_count": row["alert_count"],
                    "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                    "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                    "contributing_alerts": contributing,
                    "auto_created_at": _dt.utcnow().isoformat(),
                },
                "raw_alert": {
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                },
                "indicators": [
                    {"type": entity_type, "value": entity_value, "verdict": "suspicious"}
                ],
            }

            try:
                await postgres_db.create_investigation(investigation_data)
                logger.warning(
                    f"[ENTITY_RISK] Auto-created investigation {inv_id} for "
                    f"{entity_type}={entity_value} (score {risk_score:.0f})"
                )
                # Record the investigation_id on the entity_risk row so we
                # don't spawn dupes if accumulate_risk somehow re-triggers
                # (and so the UI can link).
                try:
                    async with postgres_db.pool.acquire() as conn:
                        await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
                        await conn.execute(
                            "UPDATE entity_risk "
                            "SET investigation_id = $1 "
                            "WHERE id = $2 AND investigation_id IS NULL",
                            inv_id, row["id"],
                        )
                except Exception:
                    # investigation_id column may not exist yet — see migration 075
                    pass
            except Exception as e:
                logger.error(
                    f"[ENTITY_RISK] Failed to create investigation for "
                    f"{entity_type}={entity_value}: {e}"
                )

    async def apply_decay(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Apply temporal decay to entity risk scores.

        decay formula: score * (0.5 ^ (hours_since_last_seen / decay_hours))
        """
        pool = await self._get_pool()
        if not pool:
            return {'error': 'No database pool'}

        try:
            from services.postgres_db import postgres_db

            # Use platform admin mode for background task
            async with postgres_db.pool.acquire() as conn:
                if tenant_id:
                    tenants = [{'id': tenant_id}]
                else:
                    tenants = await conn.fetch("SELECT id FROM tenants")

                total_updated = 0
                for t in tenants:
                    tid = str(t['id'])
                    settings = self._default_settings()
                    try:
                        row = await conn.fetchrow(
                            "SELECT entity_risk_decay_hours FROM correlation_settings WHERE tenant_id = $1::uuid",
                            tid
                        )
                        if row:
                            settings['entity_risk_decay_hours'] = row['entity_risk_decay_hours']
                    except:
                        pass

                    decay_hours = settings['entity_risk_decay_hours']

                    result = await conn.execute("""
                        UPDATE entity_risk
                        SET risk_score = risk_score * POWER(0.5, EXTRACT(EPOCH FROM (NOW() - last_seen)) / 3600.0 / $1),
                            threshold_breached = CASE
                                WHEN risk_score * POWER(0.5, EXTRACT(EPOCH FROM (NOW() - last_seen)) / 3600.0 / $1) < $2
                                THEN false
                                ELSE threshold_breached
                            END
                        WHERE tenant_id = $3::uuid
                          AND risk_score > 1
                    """, float(decay_hours), float(settings.get('entity_risk_threshold', 75)), tid)

                    count = int(result.split(' ')[-1]) if result else 0
                    total_updated += count

                # Clean up entities with negligible risk
                await conn.execute("""
                    DELETE FROM entity_risk WHERE risk_score < 0.5
                """)

                return {'updated': total_updated}

        except Exception as e:
            logger.error(f"Failed to apply entity risk decay: {e}")
            return {'error': str(e)}

    async def get_entity_risk(
        self,
        tenant_id: str,
        entity_type: str,
        entity_value: str
    ) -> Optional[Dict[str, Any]]:
        """Get current risk for a specific entity."""
        pool = await self._get_pool()
        if not pool:
            return None

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT * FROM entity_risk
                    WHERE tenant_id = $1::uuid
                      AND entity_type = $2
                      AND entity_value = $3
                """, tenant_id, entity_type, entity_value)
                if row:
                    result = dict(row)
                    # Ensure contributing_alerts is parsed
                    if isinstance(result.get('contributing_alerts'), str):
                        result['contributing_alerts'] = json.loads(result['contributing_alerts'])
                    return result
        except Exception as e:
            logger.error(f"Failed to get entity risk: {e}")
        return None

    async def get_high_risk_entities(
        self,
        tenant_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get entities with highest risk scores."""
        pool = await self._get_pool()
        if not pool:
            return []

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, entity_type, entity_value, risk_score,
                           alert_count, first_seen, last_seen,
                           threshold_breached, threshold_breached_at,
                           investigation_id
                    FROM entity_risk
                    WHERE tenant_id = $1::uuid
                      AND risk_score > 0
                    ORDER BY risk_score DESC
                    LIMIT $2
                """, tenant_id, limit)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to get high risk entities: {e}")
            return []

    async def reset_entity_risk(
        self,
        tenant_id: str,
        entity_type: str,
        entity_value: str
    ) -> bool:
        """Reset risk for a specific entity (manual override)."""
        pool = await self._get_pool()
        if not pool:
            return False

        try:
            async with pool.tenant_acquire() as conn:
                result = await conn.execute("""
                    UPDATE entity_risk
                    SET risk_score = 0,
                        alert_count = 0,
                        contributing_alerts = '[]'::jsonb,
                        threshold_breached = false,
                        threshold_breached_at = NULL
                    WHERE tenant_id = $1::uuid
                      AND entity_type = $2
                      AND entity_value = $3
                """, tenant_id, entity_type, entity_value)
                return 'UPDATE 1' in result
        except Exception as e:
            logger.error(f"Failed to reset entity risk: {e}")
            return False


# Singleton
_entity_risk_service: Optional[EntityRiskService] = None


def get_entity_risk_service() -> EntityRiskService:
    """Get or create the entity risk service singleton."""
    global _entity_risk_service
    if _entity_risk_service is None:
        _entity_risk_service = EntityRiskService()
    return _entity_risk_service
