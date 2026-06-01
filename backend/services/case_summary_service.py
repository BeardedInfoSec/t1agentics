# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Case Summary Service
Generates investigation summary reports and handles post-resolution workflows
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class CaseSummaryService:
    """Service for generating case summaries and managing post-resolution tasks"""

    def __init__(self):
        self.db = None

    async def _get_db(self):
        """Lazy load database connection"""
        if not self.db:
            from services.postgres_db import postgres_db
            self.db = postgres_db
        return self.db

    async def generate_case_summary(
        self,
        investigation_id: str,
        format: str = "detailed"
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive case summary for a resolved investigation.

        Args:
            investigation_id: The investigation ID (e.g., INV-XXXXXXXX)
            format: 'detailed' or 'executive' summary style

        Returns:
            Structured case summary with timeline, findings, actions, etc.
        """
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            # Get investigation details
            inv = await conn.fetchrow("""
                SELECT i.*, a.alert_id as source_alert_id, a.title as alert_title,
                       a.severity as alert_severity, a.raw_event as alert_raw_event,
                       a.source as alert_source
                FROM investigations i
                LEFT JOIN alerts a ON i.alert_id = a.id
                WHERE i.investigation_id = $1
            """, investigation_id)

            if not inv:
                return {"error": f"Investigation {investigation_id} not found"}

            inv_dict = dict(inv)
            investigation_data = inv_dict.get('investigation_data', {})
            if isinstance(investigation_data, str):
                investigation_data = json.loads(investigation_data)

            # Get timeline from agent action log
            # Using correct column names: action, action_type, result, status, created_at
            timeline = await conn.fetch("""
                SELECT action_type, action AS action_data, result AS result_data, status,
                       created_at AS executed_at, 'agent' AS executed_by
                FROM agent_action_log
                WHERE execution_id IN (
                    SELECT id FROM agent_executions
                    WHERE trigger_source_id = $1
                )
                ORDER BY created_at ASC
            """, str(inv_dict['id']))

            # Get all related alerts
            related_alerts = await conn.fetch("""
                SELECT alert_id, title, severity, status, created_at
                FROM alerts
                WHERE id = $1 OR investigation_id = $2
                ORDER BY created_at
            """, inv_dict.get('alert_id'), str(inv_dict['id']))

            # Get IOCs from investigation
            iocs = investigation_data.get('indicators', [])
            enrichment_data = investigation_data.get('enrichment_data', {})

            # Build timeline entries
            timeline_entries = []

            # Add investigation creation
            timeline_entries.append({
                "timestamp": inv_dict['created_at'].isoformat() if inv_dict.get('created_at') else None,
                "event": "Investigation opened",
                "type": "lifecycle",
                "details": f"Priority: {inv_dict.get('priority', 'P3')}"
            })

            # Add agent actions
            for action in timeline:
                action_dict = dict(action)
                action_data = action_dict.get('action_data', {})
                if isinstance(action_data, str):
                    action_data = json.loads(action_data) if action_data else {}

                timeline_entries.append({
                    "timestamp": action_dict['executed_at'].isoformat() if action_dict.get('executed_at') else None,
                    "event": action_dict.get('action_type', 'Unknown action'),
                    "type": "action",
                    "status": action_dict.get('status'),
                    "executed_by": action_dict.get('executed_by'),
                    "details": action_data
                })

            # Add resolution if closed
            if inv_dict.get('completed_at'):
                timeline_entries.append({
                    "timestamp": inv_dict['completed_at'].isoformat(),
                    "event": "Investigation closed",
                    "type": "lifecycle",
                    "details": f"Disposition: {inv_dict.get('disposition', 'UNKNOWN')}"
                })

            # Get AI analysis from tier analysis
            tier_analysis = investigation_data.get('tier_analysis', {})
            ai_summary = investigation_data.get('executive_summary') or inv_dict.get('executive_summary')

            # Build recommendations from AI analysis
            recommendations = investigation_data.get('recommended_actions', [])

            # Check riggs_analysis first (most common location)
            if not recommendations:
                riggs_analysis = investigation_data.get('riggs_analysis', {})
                if isinstance(riggs_analysis, str):
                    try:
                        riggs_analysis = json.loads(riggs_analysis)
                    except:
                        riggs_analysis = {}
                if riggs_analysis.get('recommendations'):
                    recommendations = riggs_analysis['recommendations']

            # Fall back to tier_analysis if still no recommendations
            if not recommendations and tier_analysis:
                for tier in ['tier3_analysis', 'tier2_analysis', 'tier1_analysis']:
                    if tier in tier_analysis:
                        tier_data = tier_analysis[tier]
                        if isinstance(tier_data, str):
                            try:
                                tier_data = json.loads(tier_data)
                            except:
                                continue
                        if tier_data.get('recommendations'):
                            recommendations = tier_data['recommendations']
                            break

            # Generate default recommendations based on verdict if none available
            if not recommendations:
                verdict = (investigation_data.get('riggs_analysis', {}).get('verdict') or
                          inv_dict.get('disposition') or '').upper()
                if verdict == 'MALICIOUS' or verdict == 'TRUE_POSITIVE':
                    recommendations = [
                        {"action": "Isolate affected systems from network to prevent lateral movement", "priority": "high"},
                        {"action": "Collect forensic artifacts (memory dump, event logs, network traffic)", "priority": "high"},
                        {"action": "Block identified malicious IOCs at perimeter and endpoint", "priority": "high"},
                        {"action": "Notify incident response team and escalate per incident severity", "priority": "medium"},
                    ]
                elif verdict == 'SUSPICIOUS':
                    recommendations = [
                        {"action": "Enhance monitoring on affected entities for additional indicators", "priority": "medium"},
                        {"action": "Gather additional context from user or asset owner", "priority": "medium"},
                        {"action": "Review related alerts within correlation window", "priority": "medium"},
                    ]
                elif verdict in ('NEEDS_INVESTIGATION', 'NEEDS_REVIEW'):
                    recommendations = [
                        {"action": "Conduct deep-dive analysis with full forensic data collection", "priority": "medium"},
                        {"action": "Correlate with threat intelligence for IOC context", "priority": "medium"},
                    ]

            # Build the summary
            summary = {
                "investigation_id": investigation_id,
                "generated_at": datetime.utcnow().isoformat(),
                "format": format,

                # Overview
                "overview": {
                    "title": inv_dict.get('alert_title') or "Security Investigation",
                    "state": inv_dict.get('state'),
                    "disposition": inv_dict.get('disposition'),
                    "priority": inv_dict.get('priority'),
                    "severity": inv_dict.get('severity') or inv_dict.get('alert_severity'),
                    "owner": inv_dict.get('owner'),
                    "confidence": float(inv_dict['confidence']) if inv_dict.get('confidence') else None
                },

                # Timing
                "timing": {
                    "created_at": inv_dict['created_at'].isoformat() if inv_dict.get('created_at') else None,
                    "assigned_at": inv_dict['assigned_at'].isoformat() if inv_dict.get('assigned_at') else None,
                    "completed_at": inv_dict['completed_at'].isoformat() if inv_dict.get('completed_at') else None,
                    "total_duration_hours": self._calculate_duration_hours(
                        inv_dict.get('created_at'),
                        inv_dict.get('completed_at')
                    )
                },

                # Alert source
                "source_alert": {
                    "alert_id": inv_dict.get('source_alert_id'),
                    "title": inv_dict.get('alert_title'),
                    "severity": inv_dict.get('alert_severity'),
                    "source": inv_dict.get('alert_source')
                },

                # Executive summary
                "executive_summary": ai_summary,

                # Timeline
                "timeline": timeline_entries,

                # IOCs discovered
                "iocs": iocs,

                # Enrichment data
                "enrichment_summary": self._summarize_enrichment(enrichment_data, investigation_data),

                # Actions taken (from timeline)
                "actions_taken": [
                    e for e in timeline_entries
                    if e.get('type') == 'action' and e.get('status') == 'completed'
                ],

                # Recommendations
                "recommendations": recommendations,

                # Related alerts
                "related_alerts": [
                    {
                        "alert_id": a['alert_id'],
                        "title": a['title'],
                        "severity": a['severity'],
                        "status": a['status']
                    }
                    for a in related_alerts
                ],

                # AI Analysis summary
                "ai_analysis": {
                    "tier1": tier_analysis.get('tier1_analysis') is not None,
                    "tier2": tier_analysis.get('tier2_analysis') is not None,
                    "tier3": tier_analysis.get('tier3_analysis') is not None,
                    "final_verdict": investigation_data.get('final_verdict'),
                    "confidence_scores": investigation_data.get('confidence_scores', {})
                }
            }

            # Store the generated summary
            await self._store_case_summary(conn, investigation_id, summary)

            return summary

    def _calculate_duration_hours(self, start: datetime, end: datetime) -> Optional[float]:
        """Calculate duration in hours between two timestamps"""
        if not start or not end:
            return None
        duration = end - start
        return round(duration.total_seconds() / 3600, 2)

    def _summarize_enrichment(self, enrichment_data: Dict, investigation_data: Dict = None) -> Dict[str, Any]:
        """Summarize enrichment results and extract malicious IOC details"""
        summary = {
            "total_iocs_enriched": 0,
            "malicious_findings": 0,
            "sources_used": [],
            "key_findings": [],
            "malicious_iocs": []  # Explicit list of malicious IOCs for display
        }

        # Check standard enrichment_data structure
        for ioc_type, iocs in enrichment_data.items():
            if isinstance(iocs, dict):
                for ioc_value, results in iocs.items():
                    summary["total_iocs_enriched"] += 1
                    if isinstance(results, dict):
                        for source, data in results.items():
                            if source not in summary["sources_used"]:
                                summary["sources_used"].append(source)
                            # Check for malicious verdicts
                            if isinstance(data, dict):
                                if data.get('malicious') or data.get('is_malicious'):
                                    summary["malicious_findings"] += 1
                                    finding = {
                                        "ioc": ioc_value,
                                        "type": ioc_type,
                                        "source": source,
                                        "verdict": "malicious"
                                    }
                                    summary["key_findings"].append(finding)
                                    summary["malicious_iocs"].append(finding)

        # Also check indicators list if available
        if investigation_data:
            indicators = investigation_data.get('indicators', [])
            for indicator in indicators:
                if isinstance(indicator, dict):
                    verdict = (indicator.get('verdict') or '').lower()
                    if verdict == 'malicious':
                        finding = {
                            "ioc": indicator.get('value'),
                            "type": indicator.get('type'),
                            "source": indicator.get('source', 'enrichment'),
                            "verdict": "malicious"
                        }
                        if finding not in summary["malicious_iocs"]:
                            summary["malicious_iocs"].append(finding)
                            summary["malicious_findings"] += 1

            # Extract malicious IOCs mentioned in riggs key_findings
            riggs_analysis = investigation_data.get('riggs_analysis', {})
            if isinstance(riggs_analysis, str):
                try:
                    riggs_analysis = json.loads(riggs_analysis)
                except:
                    riggs_analysis = {}

            # If riggs verdict is MALICIOUS, extract IOCs from key_findings text
            if riggs_analysis.get('verdict', '').upper() == 'MALICIOUS':
                key_findings = riggs_analysis.get('key_findings', [])
                ioc_summary = investigation_data.get('ioc_summary', {})

                # Get all known IOC values
                all_iocs = set()
                for ioc_type, values in ioc_summary.items():
                    if isinstance(values, list):
                        all_iocs.update(values)
                for indicator in indicators:
                    if isinstance(indicator, dict) and indicator.get('value'):
                        all_iocs.add(indicator['value'])

                # Check which IOCs are mentioned as malicious in key_findings
                for finding in key_findings:
                    if 'malicious' in finding.lower():
                        for ioc in all_iocs:
                            if ioc in finding:
                                # This IOC is specifically mentioned as malicious
                                if not any(m.get('ioc') == ioc for m in summary["malicious_iocs"]):
                                    summary["malicious_iocs"].append({
                                        "ioc": ioc,
                                        "type": "unknown",
                                        "source": "riggs_analysis",
                                        "verdict": "malicious",
                                        "context": finding[:200]  # Include context from key_findings
                                    })

        return summary

    async def _store_case_summary(
        self,
        conn,
        investigation_id: str,
        summary: Dict[str, Any]
    ):
        """Store generated case summary in database"""
        from middleware.tenant_middleware import get_optional_tenant_id
        _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
        await conn.execute("""
            INSERT INTO case_summaries (investigation_id, summary_data, generated_at, tenant_id)
            VALUES ($1, $2, CURRENT_TIMESTAMP, $3)
            ON CONFLICT (investigation_id)
            DO UPDATE SET summary_data = $2, generated_at = CURRENT_TIMESTAMP
        """, investigation_id, json.dumps(summary), _tid)

    async def get_stored_summary(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get previously generated case summary"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT summary_data, generated_at
                FROM case_summaries
                WHERE investigation_id = $1
            """, investigation_id)

            if row:
                summary = json.loads(row['summary_data']) if isinstance(row['summary_data'], str) else row['summary_data']
                summary['retrieved_from_cache'] = True
                summary['cached_at'] = row['generated_at'].isoformat()
                return summary
            return None

    async def create_post_resolution_task(
        self,
        investigation_id: str,
        task_type: str,
        task_config: Dict[str, Any],
        created_by: str
    ) -> Dict[str, Any]:
        """Create a post-resolution task for an investigation"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            task_id = await conn.fetchval("""
                INSERT INTO post_resolution_tasks
                (investigation_id, task_type, task_config, status, created_by)
                VALUES ($1, $2, $3, 'pending', $4)
                RETURNING id
            """, investigation_id, task_type, json.dumps(task_config), created_by)

            return {
                "task_id": str(task_id),
                "investigation_id": investigation_id,
                "task_type": task_type,
                "status": "pending"
            }

    async def execute_post_resolution_task(
        self,
        task_id: str
    ) -> Dict[str, Any]:
        """Execute a post-resolution task"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            task = await conn.fetchrow("""
                SELECT * FROM post_resolution_tasks WHERE id = $1
            """, task_id)

            if not task:
                return {"error": "Task not found"}

            task_dict = dict(task)
            task_type = task_dict['task_type']
            config = json.loads(task_dict['task_config']) if isinstance(task_dict['task_config'], str) else task_dict['task_config']

            result = {"status": "completed", "task_type": task_type}

            try:
                if task_type == "email_summary":
                    result = await self._send_summary_email(
                        task_dict['investigation_id'],
                        config.get('recipients', []),
                        config.get('template', 'standard'),
                        config.get('attach_pdf', False)
                    )
                elif task_type == "itsm_export":
                    result = await self._export_to_itsm(
                        task_dict['investigation_id'],
                        config.get('system', 'servicenow'),
                        config.get('ticket_type', 'problem')
                    )
                elif task_type == "cmdb_update":
                    result = await self._update_cmdb(
                        task_dict['investigation_id'],
                        config.get('action', 'mark_remediated')
                    )
                elif task_type == "create_blocklist":
                    result = await self._create_blocklist_entries(
                        task_dict['investigation_id']
                    )

                # Update task status
                await conn.execute("""
                    UPDATE post_resolution_tasks
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                        result_data = $2
                    WHERE id = $1
                """, task_id, json.dumps(result))

            except Exception as e:
                logger.error(f"Post-resolution task {task_id} failed: {e}")
                await conn.execute("""
                    UPDATE post_resolution_tasks
                    SET status = 'failed', error_message = $2
                    WHERE id = $1
                """, task_id, str(e))
                result = {"status": "failed", "error": str(e)}

            return result

    async def _send_summary_email(
        self,
        investigation_id: str,
        recipients: List[str],
        template: str,
        attach_pdf: bool
    ) -> Dict[str, Any]:
        """Send case summary via email"""
        try:
            from services.email_service import get_email_service
            email_service = get_email_service()

            # Generate summary if needed
            summary = await self.generate_case_summary(investigation_id)

            # Format email body
            subject = f"Investigation Summary: {investigation_id}"
            body = self._format_email_body(summary, template)

            # Send email
            result = await email_service.send_email(
                to=recipients,
                subject=subject,
                body=body,
                html=True
            )

            return {
                "status": "sent",
                "recipients": recipients,
                "subject": subject
            }
        except Exception as e:
            logger.warning(f"Email service not available: {e}")
            return {
                "status": "skipped",
                "reason": "Email service not configured",
                "recipients": recipients
            }

    def _format_email_body(self, summary: Dict[str, Any], template: str) -> str:
        """Format case summary as HTML email"""
        overview = summary.get('overview', {})
        timing = summary.get('timing', {})

        html = f"""
        <html>
        <head><style>
            body {{ font-family: Arial, sans-serif; }}
            .header {{ background: #1a1a2e; color: white; padding: 20px; }}
            .section {{ margin: 20px 0; padding: 15px; background: #f5f5f5; }}
            .label {{ color: #666; font-size: 12px; }}
            .value {{ font-weight: bold; }}
            .timeline-item {{ padding: 8px; border-left: 3px solid #007bff; margin: 5px 0; }}
        </style></head>
        <body>
            <div class="header">
                <h1>Investigation Summary</h1>
                <h2>{summary.get('investigation_id')}</h2>
            </div>

            <div class="section">
                <h3>Overview</h3>
                <p><span class="label">Title:</span> <span class="value">{overview.get('title', 'N/A')}</span></p>
                <p><span class="label">Disposition:</span> <span class="value">{overview.get('disposition', 'N/A')}</span></p>
                <p><span class="label">Severity:</span> <span class="value">{overview.get('severity', 'N/A')}</span></p>
                <p><span class="label">Confidence:</span> <span class="value">{overview.get('confidence', 'N/A')}%</span></p>
            </div>

            <div class="section">
                <h3>Executive Summary</h3>
                <p>{summary.get('executive_summary', 'No summary available.')}</p>
            </div>

            <div class="section">
                <h3>Timing</h3>
                <p><span class="label">Created:</span> {timing.get('created_at', 'N/A')}</p>
                <p><span class="label">Completed:</span> {timing.get('completed_at', 'N/A')}</p>
                <p><span class="label">Duration:</span> {timing.get('total_duration_hours', 'N/A')} hours</p>
            </div>

            <div class="section">
                <h3>IOCs Discovered</h3>
                <ul>
        """

        for ioc in summary.get('iocs', [])[:10]:
            if isinstance(ioc, dict):
                html += f"<li>{ioc.get('type', 'unknown')}: {ioc.get('value', 'N/A')}</li>"
            else:
                html += f"<li>{ioc}</li>"

        html += """
                </ul>
            </div>

            <div class="section">
                <h3>Recommendations</h3>
                <ul>
        """

        for rec in summary.get('recommendations', []):
            if isinstance(rec, dict):
                html += f"<li>{rec.get('description', rec.get('action', str(rec)))}</li>"
            else:
                html += f"<li>{rec}</li>"

        html += """
                </ul>
            </div>

            <p style="color: #666; font-size: 11px; margin-top: 30px;">
                Generated by T1 Agentics SOC Platform
            </p>
        </body>
        </html>
        """

        return html

    async def _export_to_itsm(
        self,
        investigation_id: str,
        system: str,
        ticket_type: str
    ) -> Dict[str, Any]:
        """Export investigation to ITSM system"""
        # This would integrate with ServiceNow, Jira, etc.
        summary = await self.generate_case_summary(investigation_id)

        # For now, return a placeholder
        return {
            "status": "exported",
            "system": system,
            "ticket_type": ticket_type,
            "ticket_id": f"PRB-{investigation_id[-8:]}",
            "note": "ITSM integration placeholder - configure integration for real export"
        }

    async def _update_cmdb(
        self,
        investigation_id: str,
        action: str
    ) -> Dict[str, Any]:
        """Update CMDB assets related to investigation"""
        db = await self._get_db()

        # Get assets linked to this investigation
        async with db.tenant_acquire() as conn:
            # Look for assets mentioned in the investigation
            inv = await conn.fetchrow("""
                SELECT investigation_data FROM investigations
                WHERE investigation_id = $1
            """, investigation_id)

            if not inv:
                return {"status": "skipped", "reason": "Investigation not found"}

            inv_data = json.loads(inv['investigation_data']) if isinstance(inv['investigation_data'], str) else inv['investigation_data']

            # Extract hostnames/IPs from investigation
            affected_assets = []
            indicators = inv_data.get('indicators', [])
            for ind in indicators:
                if isinstance(ind, dict):
                    if ind.get('type') == 'hostname':
                        affected_assets.append(ind.get('value'))
                    elif ind.get('type') == 'ip':
                        affected_assets.append(ind.get('value'))

            # Update asset status
            updated = 0
            for asset in affected_assets:
                result = await conn.execute("""
                    UPDATE assets
                    SET status = $2,
                        last_incident_at = CURRENT_TIMESTAMP,
                        metadata = metadata || jsonb_build_object(
                            'last_investigation', $3,
                            'remediation_status', $1
                        )
                    WHERE hostname = $4 OR $4 = ANY(ip_addresses::text[])
                """, action, 'remediated' if action == 'mark_remediated' else 'incident',
                investigation_id, asset)
                if result:
                    updated += 1

            return {
                "status": "updated",
                "action": action,
                "assets_updated": updated,
                "affected_assets": affected_assets
            }

    async def _create_blocklist_entries(
        self,
        investigation_id: str
    ) -> Dict[str, Any]:
        """Create blocklist entries from investigation IOCs"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            inv = await conn.fetchrow("""
                SELECT investigation_data FROM investigations
                WHERE investigation_id = $1
            """, investigation_id)

            if not inv:
                return {"status": "skipped", "reason": "Investigation not found"}

            inv_data = json.loads(inv['investigation_data']) if isinstance(inv['investigation_data'], str) else inv['investigation_data']
            indicators = inv_data.get('indicators', [])

            from middleware.tenant_middleware import get_optional_tenant_id
            _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
            created = 0
            for ind in indicators:
                if isinstance(ind, dict) and ind.get('malicious'):
                    try:
                        await conn.execute("""
                            INSERT INTO ioc_blocklist (ioc_type, ioc_value, source, reason, added_at, tenant_id)
                            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
                            ON CONFLICT (ioc_type, ioc_value) DO NOTHING
                        """, ind.get('type'), ind.get('value'),
                        f"Investigation: {investigation_id}",
                        f"Auto-blocked from {investigation_id}",
                        _tid)
                        created += 1
                    except Exception as e:
                        logger.warning(f"Could not create blocklist entry: {e}")

            return {
                "status": "created",
                "entries_created": created,
                "total_indicators": len(indicators)
            }

    async def get_post_resolution_rules(self) -> List[Dict[str, Any]]:
        """Get all post-resolution rules"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM post_resolution_rules
                ORDER BY priority ASC
            """)

            return [dict(r) for r in rows]

    async def create_post_resolution_rule(
        self,
        rule_data: Dict[str, Any],
        created_by: str
    ) -> Dict[str, Any]:
        """Create a new post-resolution rule"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            rule_id = await conn.fetchval("""
                INSERT INTO post_resolution_rules
                (name, description, conditions, actions, enabled, priority, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
            """,
            rule_data.get('name'),
            rule_data.get('description'),
            json.dumps(rule_data.get('conditions', {})),
            json.dumps(rule_data.get('actions', [])),
            rule_data.get('enabled', True),
            rule_data.get('priority', 10),
            created_by)

            return {
                "rule_id": str(rule_id),
                "name": rule_data.get('name'),
                "status": "created"
            }

    async def apply_post_resolution_rules(
        self,
        investigation_id: str
    ) -> Dict[str, Any]:
        """Apply matching post-resolution rules to an investigation"""
        db = await self._get_db()

        async with db.tenant_acquire() as conn:
            # Get investigation details
            inv = await conn.fetchrow("""
                SELECT * FROM investigations WHERE investigation_id = $1
            """, investigation_id)

            if not inv:
                return {"error": "Investigation not found"}

            inv_dict = dict(inv)

            # Get enabled rules
            rules = await conn.fetch("""
                SELECT * FROM post_resolution_rules
                WHERE enabled = true
                ORDER BY priority ASC
            """)

            tasks_created = []

            for rule in rules:
                rule_dict = dict(rule)
                conditions = json.loads(rule_dict['conditions']) if isinstance(rule_dict['conditions'], str) else rule_dict['conditions']
                actions = json.loads(rule_dict['actions']) if isinstance(rule_dict['actions'], str) else rule_dict['actions']

                # Check if conditions match
                if self._evaluate_conditions(inv_dict, conditions):
                    # Create tasks for each action
                    for action in actions:
                        task = await self.create_post_resolution_task(
                            investigation_id=investigation_id,
                            task_type=action.get('type'),
                            task_config=action.get('config', {}),
                            created_by=f"rule:{rule_dict['name']}"
                        )
                        tasks_created.append(task)

            return {
                "investigation_id": investigation_id,
                "rules_evaluated": len(rules),
                "tasks_created": len(tasks_created),
                "tasks": tasks_created
            }

    def _evaluate_conditions(
        self,
        investigation: Dict[str, Any],
        conditions: Dict[str, Any]
    ) -> bool:
        """Evaluate if investigation matches rule conditions"""
        if not conditions:
            return True

        # Severity condition
        if 'severity' in conditions:
            required = conditions['severity']
            if isinstance(required, list):
                if investigation.get('severity') not in required:
                    return False
            elif investigation.get('severity') != required:
                return False

        # Disposition condition
        if 'disposition' in conditions:
            required = conditions['disposition']
            if isinstance(required, list):
                if investigation.get('disposition') not in required:
                    return False
            elif investigation.get('disposition') != required:
                return False

        # State condition (must be resolved/closed)
        if 'state' in conditions:
            required = conditions['state']
            if isinstance(required, list):
                if investigation.get('state') not in required:
                    return False
            elif investigation.get('state') != required:
                return False

        return True


# Singleton instance
_case_summary_service = None


def get_case_summary_service() -> CaseSummaryService:
    """Get or create the case summary service singleton"""
    global _case_summary_service
    if _case_summary_service is None:
        _case_summary_service = CaseSummaryService()
    return _case_summary_service
