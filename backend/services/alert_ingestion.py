# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Ingestion Service
Polls external integrations for new alerts

Phase 2.4 compliant:
- Integrates with AlertDeduplicationService for fingerprint-based deduplication
- Supports SUPPRESS (skip creation), GROUP (link to group), COUNT_ONLY actions
- Tracks deduplication statistics
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx
import secrets

from services.email_service import get_email_service
from services.alert_deduplication import check_alert_duplicate, DedupeAction
from services.alert_id_generator import generate_alert_id_sync

logger = logging.getLogger(__name__)


# Severity boost ladder used when an alert touches an entity that has
# already breached the risk threshold. Bumps exactly one tier; saturates
# at 'critical'. Unknown / non-standard severities pass through.
_SEVERITY_LADDER = ['info', 'low', 'medium', 'high', 'critical']


def _bump_severity(sev: str) -> str:
    s = (sev or 'medium').lower()
    if s in _SEVERITY_LADDER:
        i = _SEVERITY_LADDER.index(s)
        if i + 1 < len(_SEVERITY_LADDER):
            return _SEVERITY_LADDER[i + 1]
        return s
    return s


class AlertIngestionService:
    def __init__(self, db):
        self.db = db
        self.timeout = 30  # HTTP request timeout in seconds
    
    async def poll_integration(self, integration_id: str) -> Dict[str, Any]:
        """
        Poll a single integration for new alerts
        
        Args:
            integration_id: Integration identifier
            
        Returns:
            Dict with status and alert count
        """
        try:
            integration = await self.db.get_integration(integration_id)
            
            if not integration:
                return {"status": "error", "message": "Integration not found"}
            
            if not integration.get("enabled", False):
                return {"status": "skipped", "message": "Integration disabled"}
            
            if not integration.get("poll_enabled", False):
                return {"status": "skipped", "message": "Polling not enabled"}
            
            # Make HTTP request to integration endpoint
            response_data = await self.make_request(integration)
            
            # Parse response and extract alerts
            alert_mapping = integration.get("alert_mapping", {})
            alerts = self.parse_alerts(response_data, alert_mapping)
            
            # Store alerts in database with deduplication
            created_count = 0
            suppressed_count = 0
            grouped_count = 0

            for alert_data in alerts:
                # Check if alert already exists (by external_id)
                external_id = alert_data.get("external_id")
                if external_id:
                    existing = await self.db.get_alert_by_external_id(external_id)
                    if existing:
                        continue  # Skip duplicates by external_id

                # Build alert object for deduplication check
                alert = {
                    "alert_id": generate_alert_id_sync(
                        source=integration["name"],
                        source_type=integration.get("type"),
                        category=alert_data.get("category"),
                        title=alert_data.get("title")
                    ),
                    "external_id": external_id or f"poll_{secrets.token_hex(6)}",
                    "source": integration["name"],
                    "source_type": "integration",
                    "title": alert_data.get("title", "Untitled Alert"),
                    "description": alert_data.get("description", ""),
                    "severity": alert_data.get("severity", "medium").lower(),
                    "status": "open",
                    "raw_data": alert_data.get("raw_data", alert_data),
                    "created_at": alert_data.get("created_at", datetime.utcnow()),
                    "updated_at": datetime.utcnow(),
                    "processed": False
                }

                # Phase 2.4: Check for fingerprint-based deduplication
                try:
                    dedupe_result = await check_alert_duplicate(alert, self.db)

                    if dedupe_result.is_duplicate:
                        if dedupe_result.action == DedupeAction.SUPPRESS:
                            # Skip this alert entirely - it's a true duplicate
                            logger.debug(f"Suppressed duplicate alert: {alert['title'][:50]}")
                            suppressed_count += 1
                            continue

                        elif dedupe_result.action == DedupeAction.GROUP:
                            # Create alert but link it to existing group
                            alert["alert_group_id"] = dedupe_result.existing_group_id
                            alert["is_primary"] = False
                            alert["fingerprint"] = dedupe_result.fingerprint
                            grouped_count += 1
                            logger.debug(f"Grouped alert with existing: {dedupe_result.existing_group_id}")

                        elif dedupe_result.action == DedupeAction.COUNT_ONLY:
                            # Just increment count, don't create alert
                            suppressed_count += 1
                            continue
                    else:
                        # Not a duplicate - store fingerprint for future matching
                        alert["fingerprint"] = dedupe_result.fingerprint
                        alert["is_primary"] = True

                except Exception as dedupe_err:
                    # Don't fail alert creation if deduplication fails
                    logger.warning(f"Deduplication check failed: {dedupe_err}")

                await self.db.create_alert(alert)
                created_count += 1

                # Fire the same enrichment + triage pipeline the webhook path
                # uses. Without this, polled alerts land in the DB but never
                # get an AI verdict — they only move forward if auto-correlation
                # or agent_scheduler sweeps catch them. asyncio.create_task is
                # fire-and-forget; we're inside a scheduler tick, not a request
                # handler, so FastAPI's BackgroundTasks isn't available.
                try:
                    from services.auto_enrichment import enrich_alert_background
                    asyncio.create_task(
                        enrich_alert_background(
                            alert_id=alert['alert_id'],
                            raw_event=alert.get('raw_data') or alert,
                            tenant_id=alert.get('tenant_id'),
                        )
                    )
                except Exception as enq_err:
                    logger.warning(
                        f"Failed to queue enrichment for polled alert "
                        f"{alert.get('alert_id')}: {enq_err}"
                    )

                # Entity risk: first check if this alert touches any
                # already-breached entities and bump severity if so. Then
                # accumulate fresh contributions. The boost runs FIRST so
                # the alert's persisted severity (and downstream triage)
                # reflect the reputation we already have for these entities.
                try:
                    from services.entity_risk_service import get_entity_risk_service
                    entity_risk_svc = get_entity_risk_service()
                    tenant_id = alert.get('tenant_id')
                    if tenant_id:
                        touched_breached = await entity_risk_svc.check_for_breached_entities(
                            str(tenant_id), alert
                        )
                        if touched_breached:
                            old_sev = (alert.get('severity') or 'medium').lower()
                            new_sev = _bump_severity(old_sev)
                            if new_sev != old_sev:
                                alert['severity'] = new_sev
                                # Persist the bump so triage and the UI see it
                                try:
                                    from services.postgres_db import postgres_db
                                    async with postgres_db.tenant_acquire() as _conn:
                                        await _conn.execute(
                                            "UPDATE alerts SET severity = $1, updated_at = NOW() "
                                            "WHERE alert_id = $2",
                                            new_sev, alert['alert_id'],
                                        )
                                except Exception as upd_err:
                                    logger.debug(f"severity bump persist failed: {upd_err}")
                                ent_summary = ', '.join(
                                    f"{e['entity_type']}:{e['entity_value']}"
                                    for e in touched_breached[:3]
                                )
                                extra = '' if len(touched_breached) <= 3 else f' (+{len(touched_breached) - 3} more)'
                                logger.info(
                                    f"Alert {alert['alert_id']}: severity {old_sev} → {new_sev} "
                                    f"(touched breached entit{'y' if len(touched_breached) == 1 else 'ies'} "
                                    f"{ent_summary}{extra})"
                                )

                        breached = await entity_risk_svc.accumulate_risk(str(tenant_id), alert)
                        if breached:
                            logger.info(
                                f"Alert {alert['alert_id']}: {len(breached)} entities breached risk threshold"
                            )
                except Exception as risk_err:
                    logger.debug(f"Entity risk accumulation failed: {risk_err}")

                # Auto-correlate alert to open investigations (hypothesis-driven)
                try:
                    from services.alert_correlation import correlate_and_link_alert
                    linked_inv = await correlate_and_link_alert(alert)
                    if linked_inv:
                        logger.info(f"Alert {alert['alert_id']} auto-linked to investigation {linked_inv}")
                except Exception as corr_err:
                    logger.debug(f"Alert correlation check failed: {corr_err}")

                # IOC correlation: Link IOCs and check correlation rules for campaign detection
                try:
                    from services.ioc_correlation_engine import get_correlation_engine
                    ioc_engine = get_correlation_engine()

                    # Extract and link IOCs from this alert
                    ioc_count = await ioc_engine.link_alert_iocs(alert['alert_id'], alert)

                    # Check correlation rules (may trigger campaign creation)
                    if ioc_count > 0:
                        correlations = await ioc_engine.check_correlations(alert['alert_id'], alert)
                        if correlations:
                            for corr in correlations:
                                logger.info(
                                    f"[IOC_CORRELATION] Alert {alert['alert_id']} triggered rule '{corr.rule_name}' "
                                    f"(score={corr.correlation_score}, campaign={corr.campaign_id})"
                                )
                except Exception as ioc_corr_err:
                    logger.debug(f"IOC correlation check failed: {ioc_corr_err}")

                # Send notification for new alert
                try:
                    email_service = get_email_service()
                    email_service.set_db(self.db)

                    # Determine event type based on severity
                    event_type = 'alert_critical' if alert['severity'] == 'critical' else 'alert_created'

                    await email_service.notify_event(event_type, {
                        'alert_id': alert['alert_id'],
                        'title': alert['title'],
                        'severity': alert['severity'],
                        'source': alert['source'],
                        'description': alert.get('description', '')[:500]  # Truncate for email
                    })
                except Exception as notify_err:
                    # Don't fail alert creation if notification fails
                    pass

            # Update last poll time
            await self.db.update_integration(integration_id, {
                "last_poll_time": datetime.utcnow(),
                "last_poll_count": created_count
            })
            
            # Log poll result with deduplication stats
            await self.db.create_log({
                "level": "info",
                "message": f"Integration poll completed: {integration['name']}",
                "source": "alert_ingestion",
                "details": {
                    "integration_id": integration_id,
                    "alerts_created": created_count,
                    "alerts_suppressed": suppressed_count,
                    "alerts_grouped": grouped_count
                }
            })

            # Log deduplication activity if any duplicates were found
            if suppressed_count > 0 or grouped_count > 0:
                logger.info(
                    f"Deduplication: {suppressed_count} suppressed, {grouped_count} grouped "
                    f"from {len(alerts)} total alerts"
                )

            return {
                "status": "success",
                "integration": integration["name"],
                "alerts_created": created_count,
                "alerts_suppressed": suppressed_count,
                "alerts_grouped": grouped_count,
                "total_alerts": len(alerts)
            }
            
        except Exception as e:
            # Log error
            await self.db.create_log({
                "level": "error",
                "message": f"Integration poll failed: {str(e)}",
                "source": "alert_ingestion",
                "details": {"integration_id": integration_id, "error": str(e)}
            })
            
            return {
                "status": "error",
                "message": str(e)
            }
    
    async def make_request(self, integration: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make HTTP request to integration endpoint
        
        Args:
            integration: Integration configuration
            
        Returns:
            Response data as dict
        """
        # SECURITY: Enable TLS verification by default. Only disable for specific integrations
        # that explicitly set verify_ssl=False (e.g., internal services with self-signed certs)
        verify_ssl = integration.get("verify_ssl", True)
        async with httpx.AsyncClient(verify=verify_ssl, timeout=self.timeout) as client:
            # Build request
            url = integration["endpoint_url"]
            method = integration.get("method", "GET").upper()
            headers = self.build_headers(integration)
            
            # Add authentication
            if integration.get("auth_type") == "bearer":
                headers["Authorization"] = f"Bearer {integration.get('bearer_token', '')}"
            elif integration.get("auth_type") == "api_key_header":
                header_name = integration.get("header_name", "X-API-Key")
                headers[header_name] = integration.get("api_key", "")
            
            # Add custom headers if provided
            if integration.get("headers"):
                try:
                    custom_headers = json.loads(integration["headers"])
                    headers.update(custom_headers)
                except:
                    pass
            
            # Make request
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                body = self.build_body(integration)
                response = await client.post(url, headers=headers, json=body)
            else:
                response = await client.request(method, url, headers=headers)
            
            response.raise_for_status()
            return response.json()
    
    def build_headers(self, integration: Dict[str, Any]) -> Dict[str, str]:
        """Build request headers"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "T1 Agentics/1.0"
        }
        return headers
    
    def build_body(self, integration: Dict[str, Any]) -> Optional[Dict]:
        """Build request body for POST requests"""
        body_str = integration.get("body", "")
        if body_str:
            try:
                return json.loads(body_str)
            except:
                pass
        return None
    
    def parse_alerts(
        self,
        response_data: Dict[str, Any],
        alert_mapping: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Parse alerts from API response using field mapping
        
        Args:
            response_data: Raw API response
            alert_mapping: Field mapping configuration
            
        Returns:
            List of parsed alerts
        """
        alerts = []
        
        # If no mapping provided, use default structure
        if not alert_mapping:
            alert_mapping = {
                "alerts_key": "alerts",
                "id_field": "id",
                "title_field": "title",
                "description_field": "description",
                "severity_field": "severity",
                "timestamp_field": "created_at"
            }
        
        # Extract alerts array from response
        alerts_key = alert_mapping.get("alerts_key", "alerts")
        raw_alerts = response_data.get(alerts_key, [])
        
        # If response is already a list, use it directly
        if isinstance(response_data, list):
            raw_alerts = response_data
        
        # Parse each alert
        for raw_alert in raw_alerts:
            alert = {
                "external_id": self.get_field(raw_alert, alert_mapping.get("id_field", "id")),
                "title": self.get_field(raw_alert, alert_mapping.get("title_field", "title")),
                "description": self.get_field(raw_alert, alert_mapping.get("description_field", "description")),
                "severity": self.get_field(raw_alert, alert_mapping.get("severity_field", "severity")),
                "created_at": self.parse_timestamp(
                    self.get_field(raw_alert, alert_mapping.get("timestamp_field", "created_at"))
                ),
                "raw_data": raw_alert
            }
            alerts.append(alert)
        
        return alerts
    
    def get_field(self, obj: Dict, field_path: str) -> Any:
        """
        Get field value from object, supporting dot notation
        
        Args:
            obj: Object to extract from
            field_path: Field path (e.g., "data.alert.id")
            
        Returns:
            Field value or None
        """
        if not field_path:
            return None
        
        keys = field_path.split(".")
        value = obj
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def parse_timestamp(self, timestamp_str: Any) -> datetime:
        """
        Parse timestamp string to datetime
        
        Args:
            timestamp_str: Timestamp string or datetime
            
        Returns:
            datetime object
        """
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        
        if not timestamp_str:
            return datetime.utcnow()
        
        # Try common timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(str(timestamp_str), fmt)
            except:
                continue
        
        # If all parsing fails, return current time
        return datetime.utcnow()
