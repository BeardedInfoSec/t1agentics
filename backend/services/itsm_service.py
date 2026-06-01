# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ITSM Integration Service
Handles exporting investigations to ServiceNow, Jira, and custom webhooks.
"""

import json
import logging
import httpx
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ITSMService:
    """Service for integrating with ITSM systems (ServiceNow, Jira, etc.)"""

    def __init__(self):
        self._db = None

    async def _get_db(self):
        if not self._db:
            from services.postgres_db import postgres_db
            self._db = postgres_db
        return self._db

    async def get_itsm_configurations(self) -> List[Dict[str, Any]]:
        """Get all ITSM integration configurations"""
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, name, system_type, base_url, instance_name,
                       credential_id, default_project, default_ticket_type,
                       field_mappings, enabled, created_at, updated_at
                FROM itsm_configurations
                ORDER BY name
            """)
            return [dict(row) for row in rows]

    async def get_itsm_configuration(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific ITSM configuration"""
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, name, system_type, base_url, instance_name,
                       credential_id, default_project, default_ticket_type,
                       field_mappings, enabled, created_at, updated_at
                FROM itsm_configurations
                WHERE id = $1
            """, config_id)
            return dict(row) if row else None

    async def create_itsm_configuration(
        self,
        name: str,
        system_type: str,
        base_url: str,
        credential_id: Optional[str] = None,
        instance_name: Optional[str] = None,
        default_project: Optional[str] = None,
        default_ticket_type: str = "incident",
        field_mappings: Optional[Dict[str, Any]] = None,
        created_by: str = "admin"
    ) -> Dict[str, Any]:
        """Create a new ITSM configuration"""
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO itsm_configurations
                (name, system_type, base_url, instance_name, credential_id,
                 default_project, default_ticket_type, field_mappings, enabled, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9)
                RETURNING id, name, system_type, base_url, enabled, created_at
            """, name, system_type, base_url, instance_name, credential_id,
                default_project, default_ticket_type,
                json.dumps(field_mappings or {}), created_by)
            return dict(row)

    async def update_itsm_configuration(
        self,
        config_id: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update an ITSM configuration"""
        db = await self._get_db()

        # Build dynamic update
        allowed_fields = [
            'name', 'base_url', 'instance_name', 'credential_id',
            'default_project', 'default_ticket_type', 'field_mappings', 'enabled'
        ]

        set_clauses = []
        values = []
        idx = 1

        for field in allowed_fields:
            if field in updates:
                set_clauses.append(f"{field} = ${idx}")
                if field == 'field_mappings':
                    values.append(json.dumps(updates[field]))
                else:
                    values.append(updates[field])
                idx += 1

        if not set_clauses:
            return None

        set_clauses.append(f"updated_at = CURRENT_TIMESTAMP")
        values.append(config_id)

        query = f"""
            UPDATE itsm_configurations
            SET {', '.join(set_clauses)}
            WHERE id = ${idx}
            RETURNING id, name, system_type, base_url, enabled, updated_at
        """

        async with db.tenant_acquire() as conn:
            row = await conn.fetchrow(query, *values)
            return dict(row) if row else None

    async def delete_itsm_configuration(self, config_id: str) -> bool:
        """Delete an ITSM configuration"""
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            result = await conn.execute("""
                DELETE FROM itsm_configurations WHERE id = $1
            """, config_id)
            return "DELETE 1" in result

    async def export_to_itsm(
        self,
        investigation_id: str,
        config_id: str,
        ticket_type: Optional[str] = None,
        additional_fields: Optional[Dict[str, Any]] = None,
        created_by: str = "admin"
    ) -> Dict[str, Any]:
        """
        Export an investigation to an ITSM system.

        Returns the created ticket details.
        """
        # Get ITSM configuration
        config = await self.get_itsm_configuration(config_id)
        if not config:
            return {"status": "error", "message": f"ITSM configuration {config_id} not found"}

        if not config.get('enabled'):
            return {"status": "error", "message": "ITSM configuration is disabled"}

        # Get investigation details
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            inv = await conn.fetchrow("""
                SELECT id, investigation_id, title, description, severity, priority,
                       state, disposition, investigation_data, created_at
                FROM investigations
                WHERE id::text = $1 OR investigation_id = $1
            """, investigation_id)

            if not inv:
                return {"status": "error", "message": "Investigation not found"}

            inv_dict = dict(inv)
            inv_data = inv_dict.get('investigation_data', {})
            if isinstance(inv_data, str):
                inv_data = json.loads(inv_data)

        # Build ticket payload based on system type
        system_type = config['system_type']
        ticket_payload = await self._build_ticket_payload(
            system_type=system_type,
            config=config,
            investigation=inv_dict,
            investigation_data=inv_data,
            ticket_type=ticket_type or config.get('default_ticket_type', 'incident'),
            additional_fields=additional_fields or {}
        )

        # Execute the API call
        result = await self._create_ticket(
            system_type=system_type,
            config=config,
            payload=ticket_payload
        )

        # Log the export
        if result.get('status') == 'success':
            async with db.tenant_acquire() as conn:
                await conn.execute("""
                    INSERT INTO itsm_exports
                    (investigation_id, itsm_config_id, ticket_id, ticket_url,
                     ticket_type, export_data, created_by)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """, str(inv_dict['id']), config_id, result.get('ticket_id'),
                    result.get('ticket_url'), ticket_type or config.get('default_ticket_type'),
                    json.dumps(ticket_payload), created_by)

        return result

    async def _build_ticket_payload(
        self,
        system_type: str,
        config: Dict[str, Any],
        investigation: Dict[str, Any],
        investigation_data: Dict[str, Any],
        ticket_type: str,
        additional_fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the ticket payload based on system type"""

        # Extract common fields
        title = investigation.get('title', 'Security Investigation')
        severity = investigation.get('severity', 'medium')
        disposition = investigation.get('disposition', 'UNKNOWN')

        # Build description
        description_parts = [
            f"## Security Investigation: {investigation.get('investigation_id', 'N/A')}",
            "",
            f"**Severity:** {severity.upper()}",
            f"**Disposition:** {disposition}",
            f"**State:** {investigation.get('state', 'N/A')}",
            "",
            "## Summary",
            investigation.get('description', 'No description available'),
            "",
        ]

        # Add IOCs if present
        indicators = investigation_data.get('indicators', [])
        if indicators:
            description_parts.append("## Indicators of Compromise")
            for ind in indicators[:10]:  # Limit to 10
                if isinstance(ind, dict):
                    ind_type = ind.get('type', 'unknown')
                    ind_value = ind.get('value', 'N/A')
                    description_parts.append(f"- **{ind_type}:** {ind_value}")
            description_parts.append("")

        # Add tier analyses if present
        for tier in ['tier1_analysis', 'tier2_analysis', 'tier3_analysis']:
            analysis = investigation_data.get(tier, {})
            if analysis:
                tier_name = tier.replace('_', ' ').title()
                description_parts.append(f"## {tier_name}")
                if 'verdict' in analysis:
                    description_parts.append(f"**Verdict:** {analysis['verdict']}")
                if 'confidence' in analysis:
                    description_parts.append(f"**Confidence:** {analysis['confidence']}")
                if 'summary' in analysis:
                    description_parts.append(f"\n{analysis['summary']}")
                description_parts.append("")

        description = "\n".join(description_parts)

        # Map to system-specific format
        if system_type == 'servicenow':
            return self._build_servicenow_payload(
                config, title, description, severity, ticket_type, additional_fields
            )
        elif system_type == 'jira':
            return self._build_jira_payload(
                config, title, description, severity, ticket_type, additional_fields
            )
        elif system_type == 'webhook':
            return self._build_webhook_payload(
                config, investigation, investigation_data, additional_fields
            )
        else:
            # Generic format
            return {
                "title": title,
                "description": description,
                "severity": severity,
                "type": ticket_type,
                **additional_fields
            }

    def _build_servicenow_payload(
        self,
        config: Dict[str, Any],
        title: str,
        description: str,
        severity: str,
        ticket_type: str,
        additional_fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build ServiceNow-specific payload"""
        # Map severity to ServiceNow impact/urgency
        severity_map = {
            'critical': {'impact': '1', 'urgency': '1'},
            'high': {'impact': '2', 'urgency': '1'},
            'medium': {'impact': '2', 'urgency': '2'},
            'low': {'impact': '3', 'urgency': '3'},
            'info': {'impact': '3', 'urgency': '3'}
        }
        sev = severity_map.get(severity.lower(), {'impact': '2', 'urgency': '2'})

        payload = {
            "short_description": title[:160],  # ServiceNow limit
            "description": description,
            "impact": sev['impact'],
            "urgency": sev['urgency'],
            "category": "Security",
            "subcategory": "Security Incident"
        }

        # Add assignment group if configured
        field_mappings = config.get('field_mappings', {})
        if field_mappings.get('assignment_group'):
            payload['assignment_group'] = field_mappings['assignment_group']

        # Apply any additional field mappings
        for field, value in additional_fields.items():
            payload[field] = value

        return payload

    def _build_jira_payload(
        self,
        config: Dict[str, Any],
        title: str,
        description: str,
        severity: str,
        ticket_type: str,
        additional_fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build Jira-specific payload"""
        # Map severity to Jira priority
        priority_map = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Lowest'
        }

        project_key = config.get('default_project', 'SEC')
        issue_type = ticket_type.title() if ticket_type else 'Task'

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": title[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": description}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_map.get(severity.lower(), 'Medium')}
            }
        }

        # Add labels if configured
        field_mappings = config.get('field_mappings', {})
        if field_mappings.get('labels'):
            payload['fields']['labels'] = field_mappings['labels']

        # Apply additional fields
        for field, value in additional_fields.items():
            payload['fields'][field] = value

        return payload

    def _build_webhook_payload(
        self,
        config: Dict[str, Any],
        investigation: Dict[str, Any],
        investigation_data: Dict[str, Any],
        additional_fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build generic webhook payload"""
        payload = {
            "event_type": "investigation_export",
            "timestamp": datetime.utcnow().isoformat(),
            "investigation": {
                "id": str(investigation.get('id')),
                "investigation_id": investigation.get('investigation_id'),
                "title": investigation.get('title'),
                "severity": investigation.get('severity'),
                "disposition": investigation.get('disposition'),
                "state": investigation.get('state'),
                "created_at": investigation.get('created_at').isoformat() if investigation.get('created_at') else None
            },
            "details": investigation_data,
            "additional": additional_fields
        }
        return payload

    async def _create_ticket(
        self,
        system_type: str,
        config: Dict[str, Any],
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the API call to create a ticket"""

        base_url = config.get('base_url', '').rstrip('/')

        # Get credentials if configured
        headers = {"Content-Type": "application/json"}
        auth = None

        if config.get('credential_id'):
            creds = await self._get_credentials(config['credential_id'])
            if creds:
                if creds.get('auth_type') == 'basic':
                    auth = (creds.get('username', ''), creds.get('password', ''))
                elif creds.get('auth_type') == 'bearer':
                    headers['Authorization'] = f"Bearer {creds.get('token', '')}"
                elif creds.get('auth_type') == 'api_key':
                    headers[creds.get('header_name', 'X-API-Key')] = creds.get('api_key', '')

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if system_type == 'servicenow':
                    # ServiceNow API
                    instance = config.get('instance_name', 'instance')
                    url = f"{base_url}/api/now/table/incident"
                    response = await client.post(url, json=payload, headers=headers, auth=auth)

                    if response.status_code in (200, 201):
                        data = response.json()
                        result = data.get('result', {})
                        return {
                            "status": "success",
                            "ticket_id": result.get('number', result.get('sys_id')),
                            "ticket_url": f"{base_url}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}",
                            "system": "servicenow"
                        }
                    else:
                        return {
                            "status": "error",
                            "message": f"ServiceNow API error: {response.status_code}",
                            "details": response.text
                        }

                elif system_type == 'jira':
                    # Jira API
                    url = f"{base_url}/rest/api/3/issue"
                    response = await client.post(url, json=payload, headers=headers, auth=auth)

                    if response.status_code in (200, 201):
                        data = response.json()
                        return {
                            "status": "success",
                            "ticket_id": data.get('key'),
                            "ticket_url": f"{base_url}/browse/{data.get('key')}",
                            "system": "jira"
                        }
                    else:
                        return {
                            "status": "error",
                            "message": f"Jira API error: {response.status_code}",
                            "details": response.text
                        }

                elif system_type == 'webhook':
                    # Generic webhook
                    url = base_url
                    response = await client.post(url, json=payload, headers=headers, auth=auth)

                    if response.status_code in (200, 201, 202, 204):
                        try:
                            data = response.json()
                            ticket_id = data.get('id') or data.get('ticket_id') or 'N/A'
                        except:
                            ticket_id = 'webhook_sent'

                        return {
                            "status": "success",
                            "ticket_id": ticket_id,
                            "ticket_url": base_url,
                            "system": "webhook"
                        }
                    else:
                        return {
                            "status": "error",
                            "message": f"Webhook error: {response.status_code}",
                            "details": response.text
                        }

                else:
                    return {
                        "status": "error",
                        "message": f"Unknown system type: {system_type}"
                    }

        except httpx.TimeoutException:
            return {"status": "error", "message": "Request timeout"}
        except Exception as e:
            logger.error(f"ITSM export error: {e}")
            return {"status": "error", "message": str(e)}

    async def _get_credentials(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get decrypted credentials"""
        try:
            from services.credentials_service import get_credentials_service
            creds_service = get_credentials_service()
            return await creds_service.get_credential(credential_id)
        except Exception as e:
            logger.error(f"Failed to get credentials: {e}")
            return None

    async def get_exports_for_investigation(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Get all ITSM exports for an investigation"""
        db = await self._get_db()
        async with db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT e.id, e.ticket_id, e.ticket_url, e.ticket_type,
                       e.created_at, e.created_by,
                       c.name as config_name, c.system_type
                FROM itsm_exports e
                JOIN itsm_configurations c ON e.itsm_config_id = c.id::text
                WHERE e.investigation_id = $1
                ORDER BY e.created_at DESC
            """, investigation_id)
            return [dict(row) for row in rows]

    async def test_configuration(self, config_id: str) -> Dict[str, Any]:
        """Test an ITSM configuration by making a health check call"""
        config = await self.get_itsm_configuration(config_id)
        if not config:
            return {"status": "error", "message": "Configuration not found"}

        base_url = config.get('base_url', '').rstrip('/')
        system_type = config.get('system_type')

        headers = {"Content-Type": "application/json"}
        auth = None

        if config.get('credential_id'):
            creds = await self._get_credentials(config['credential_id'])
            if creds:
                if creds.get('auth_type') == 'basic':
                    auth = (creds.get('username', ''), creds.get('password', ''))
                elif creds.get('auth_type') == 'bearer':
                    headers['Authorization'] = f"Bearer {creds.get('token', '')}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if system_type == 'servicenow':
                    url = f"{base_url}/api/now/table/sys_user?sysparm_limit=1"
                elif system_type == 'jira':
                    url = f"{base_url}/rest/api/3/myself"
                else:
                    url = base_url

                response = await client.get(url, headers=headers, auth=auth)

                if response.status_code in (200, 201):
                    return {"status": "success", "message": "Connection successful"}
                else:
                    return {
                        "status": "error",
                        "message": f"HTTP {response.status_code}",
                        "details": response.text[:200]
                    }
        except Exception as e:
            return {"status": "error", "message": str(e)}


# Singleton
_itsm_service = None


def get_itsm_service() -> ITSMService:
    """Get or create the ITSM service singleton"""
    global _itsm_service
    if _itsm_service is None:
        _itsm_service = ITSMService()
    return _itsm_service
