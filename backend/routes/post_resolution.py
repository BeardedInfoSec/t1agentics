# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Post-Resolution Workflow API Routes
Endpoints for case summaries, ITSM exports, and post-resolution tasks
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Header
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from dependencies.auth import get_current_user as auth_get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/post-resolution", tags=["Post-Resolution"], dependencies=[Depends(auth_get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class GenerateSummaryRequest(BaseModel):
    format: str = "detailed"  # detailed or executive


class SendSummaryEmailRequest(BaseModel):
    recipients: List[str]
    template: str = "standard"
    attach_pdf: bool = False


class ExportITSMRequest(BaseModel):
    system: str = "servicenow"  # servicenow, jira, webhook
    ticket_type: str = "problem"  # problem, incident, change


class CreateTaskRequest(BaseModel):
    task_type: str  # email_summary, itsm_export, cmdb_update, create_blocklist
    config: Dict[str, Any] = {}


class CreateRuleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    conditions: Dict[str, Any] = {}
    actions: List[Dict[str, Any]] = []
    enabled: bool = True
    priority: int = 10


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[List[Dict[str, Any]]] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None


# ============================================================================
# Case Summary Endpoints
# ============================================================================

@router.post("/investigations/{investigation_id}/summary")
async def generate_case_summary(
    investigation_id: str,
    request: GenerateSummaryRequest = None,
    authorization: str = Header(None)
):
    """
    Generate a comprehensive case summary for an investigation.

    Returns structured data including:
    - Overview (title, disposition, severity, etc.)
    - Timeline of all events and actions
    - IOCs discovered
    - Actions taken
    - AI analysis results
    - Recommendations
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        format_type = request.format if request else "detailed"
        summary = await service.generate_case_summary(
            investigation_id=investigation_id,
            format=format_type
        )

        if "error" in summary:
            raise HTTPException(status_code=404, detail=summary["error"])

        return summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate case summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigations/{investigation_id}/summary")
async def get_case_summary(
    investigation_id: str,
    regenerate: bool = Query(False, description="Force regeneration of summary"),
    authorization: str = Header(None)
):
    """
    Get the case summary for an investigation.

    By default, returns cached summary if available.
    Use regenerate=true to force a fresh summary.
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        if not regenerate:
            # Try to get cached summary
            cached = await service.get_stored_summary(investigation_id)
            if cached:
                return cached

        # Generate new summary
        summary = await service.generate_case_summary(investigation_id)

        if "error" in summary:
            raise HTTPException(status_code=404, detail=summary["error"])

        return summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get case summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Email Summary Endpoints
# ============================================================================

@router.post("/investigations/{investigation_id}/send-summary")
async def send_summary_email(
    investigation_id: str,
    request: SendSummaryEmailRequest,
    authorization: str = Header(None)
):
    """
    Send the case summary via email to specified recipients.
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service._send_summary_email(
            investigation_id=investigation_id,
            recipients=request.recipients,
            template=request.template,
            attach_pdf=request.attach_pdf
        )
        return result
    except Exception as e:
        logger.error(f"Failed to send summary email: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ITSM Export Endpoints
# ============================================================================

@router.post("/investigations/{investigation_id}/export-itsm")
async def export_to_itsm(
    investigation_id: str,
    request: ExportITSMRequest,
    authorization: str = Header(None)
):
    """
    Export the investigation to an ITSM system (ServiceNow, Jira, etc.)
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service._export_to_itsm(
            investigation_id=investigation_id,
            system=request.system,
            ticket_type=request.ticket_type
        )
        return result
    except Exception as e:
        logger.error(f"Failed to export to ITSM: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CMDB Update Endpoints
# ============================================================================

@router.post("/investigations/{investigation_id}/update-cmdb")
async def update_cmdb(
    investigation_id: str,
    action: str = Query("mark_remediated", description="CMDB action to take"),
    authorization: str = Header(None)
):
    """
    Update CMDB assets related to the investigation.

    Actions:
    - mark_remediated: Mark affected assets as remediated
    - mark_compromised: Mark affected assets as compromised
    - add_incident: Add incident reference to asset records
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service._update_cmdb(
            investigation_id=investigation_id,
            action=action
        )
        return result
    except Exception as e:
        logger.error(f"Failed to update CMDB: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Blocklist Creation
# ============================================================================

@router.post("/investigations/{investigation_id}/create-blocklist")
async def create_blocklist_entries(
    investigation_id: str,
    authorization: str = Header(None)
):
    """
    Create blocklist entries from malicious IOCs discovered in the investigation.
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service._create_blocklist_entries(investigation_id)
        return result
    except Exception as e:
        logger.error(f"Failed to create blocklist entries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Post-Resolution Tasks
# ============================================================================

@router.get("/investigations/{investigation_id}/tasks")
async def get_investigation_tasks(
    investigation_id: str,
    authorization: str = Header(None)
):
    """Get all post-resolution tasks for an investigation"""
    from services.postgres_db import postgres_db

    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, task_type, status, task_config, result_data,
                       created_at, completed_at, error_message
                FROM post_resolution_tasks
                WHERE investigation_id = $1
                ORDER BY created_at DESC
            """, investigation_id)

            tasks = []
            for row in rows:
                task = dict(row)
                task['id'] = str(task['id'])
                tasks.append(task)

            return {"investigation_id": investigation_id, "tasks": tasks}
    except Exception as e:
        logger.error(f"Failed to get tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/tasks")
async def create_task(
    investigation_id: str,
    request: CreateTaskRequest,
    current_user: dict = Depends(auth_get_current_user)
):
    """Create a post-resolution task for an investigation"""
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service.create_post_resolution_task(
            investigation_id=investigation_id,
            task_type=request.task_type,
            task_config=request.config,
            created_by=current_user.get('username', 'system')
        )
        return result
    except Exception as e:
        logger.error(f"Failed to create task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/execute")
async def execute_task(
    task_id: str,
    authorization: str = Header(None)
):
    """Execute a pending post-resolution task"""
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service.execute_post_resolution_task(task_id)
        return result
    except Exception as e:
        logger.error(f"Failed to execute task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Post-Resolution Rules
# ============================================================================

@router.get("/rules")
async def get_rules(
    authorization: str = Header(None)
):
    """Get all post-resolution rules"""
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        rules = await service.get_post_resolution_rules()
        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        logger.error(f"Failed to get rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules")
async def create_rule(
    request: CreateRuleRequest,
    current_user: dict = Depends(auth_get_current_user)
):
    """Create a new post-resolution rule"""
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service.create_post_resolution_rule(
            rule_data={
                "name": request.name,
                "description": request.description,
                "conditions": request.conditions,
                "actions": request.actions,
                "enabled": request.enabled,
                "priority": request.priority
            },
            created_by=current_user.get('username', 'system')
        )
        return result
    except Exception as e:
        logger.error(f"Failed to create rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: str,
    request: UpdateRuleRequest,
    authorization: str = Header(None)
):
    """Update a post-resolution rule"""
    from services.postgres_db import postgres_db
    import json

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build update query dynamically
            updates = []
            values = []
            param_count = 1

            if request.name is not None:
                updates.append(f"name = ${param_count}")
                values.append(request.name)
                param_count += 1

            if request.description is not None:
                updates.append(f"description = ${param_count}")
                values.append(request.description)
                param_count += 1

            if request.conditions is not None:
                updates.append(f"conditions = ${param_count}")
                values.append(json.dumps(request.conditions))
                param_count += 1

            if request.actions is not None:
                updates.append(f"actions = ${param_count}")
                values.append(json.dumps(request.actions))
                param_count += 1

            if request.enabled is not None:
                updates.append(f"enabled = ${param_count}")
                values.append(request.enabled)
                param_count += 1

            if request.priority is not None:
                updates.append(f"priority = ${param_count}")
                values.append(request.priority)
                param_count += 1

            if not updates:
                return {"status": "no_changes", "rule_id": rule_id}

            updates.append(f"updated_at = CURRENT_TIMESTAMP")
            values.append(rule_id)

            query = f"""
                UPDATE post_resolution_rules
                SET {', '.join(updates)}
                WHERE id = ${param_count}
                RETURNING id, name, enabled
            """

            row = await conn.fetchrow(query, *values)

            if not row:
                raise HTTPException(status_code=404, detail="Rule not found")

            return {
                "status": "updated",
                "rule_id": str(row['id']),
                "name": row['name'],
                "enabled": row['enabled']
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    authorization: str = Header(None)
):
    """Delete a post-resolution rule"""
    from services.postgres_db import postgres_db

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute("""
                DELETE FROM post_resolution_rules WHERE id = $1
            """, rule_id)

            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Rule not found")

            return {"status": "deleted", "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/apply-rules")
async def apply_rules(
    investigation_id: str,
    authorization: str = Header(None)
):
    """
    Apply all matching post-resolution rules to an investigation.

    This creates tasks based on rule conditions and actions.
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    try:
        result = await service.apply_post_resolution_rules(investigation_id)

        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to apply rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Bulk Operations
# ============================================================================

@router.post("/investigations/{investigation_id}/execute-all")
async def execute_all_post_resolution(
    investigation_id: str,
    authorization: str = Header(None)
):
    """
    Execute all post-resolution workflow for an investigation:
    1. Generate case summary
    2. Apply rules (creates tasks)
    3. Execute pending tasks
    """
    from services.case_summary_service import get_case_summary_service
    service = get_case_summary_service()

    results = {
        "investigation_id": investigation_id,
        "summary": None,
        "rules_applied": None,
        "tasks_executed": []
    }

    try:
        # Generate summary
        results["summary"] = await service.generate_case_summary(investigation_id)

        # Apply rules
        results["rules_applied"] = await service.apply_post_resolution_rules(investigation_id)

        # Execute pending tasks
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            pending_tasks = await conn.fetch("""
                SELECT id FROM post_resolution_tasks
                WHERE investigation_id = $1 AND status = 'pending'
            """, investigation_id)

            for task in pending_tasks:
                task_result = await service.execute_post_resolution_task(str(task['id']))
                results["tasks_executed"].append(task_result)

        return results
    except Exception as e:
        logger.error(f"Failed to execute post-resolution workflow: {e}")
        results["error"] = str(e)
        return results


# ============================================================================
# ITSM Configuration Endpoints
# ============================================================================

class ITSMConfigRequest(BaseModel):
    name: str
    system_type: str  # servicenow, jira, webhook
    base_url: str
    instance_name: Optional[str] = None
    credential_id: Optional[str] = None
    default_project: Optional[str] = None
    default_ticket_type: str = "incident"
    field_mappings: Optional[Dict[str, Any]] = None
    enabled: bool = True


class ITSMConfigUpdateRequest(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    instance_name: Optional[str] = None
    credential_id: Optional[str] = None
    default_project: Optional[str] = None
    default_ticket_type: Optional[str] = None
    field_mappings: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class ITSMExportRequest(BaseModel):
    config_id: str
    ticket_type: Optional[str] = None
    additional_fields: Optional[Dict[str, Any]] = None


@router.get("/itsm/configurations")
async def get_itsm_configurations(authorization: str = Header(None)):
    """Get all ITSM configurations"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        configs = await service.get_itsm_configurations()
        return {"configurations": configs, "count": len(configs)}
    except Exception as e:
        logger.error(f"Failed to get ITSM configurations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/itsm/configurations/{config_id}")
async def get_itsm_configuration(config_id: str, authorization: str = Header(None)):
    """Get a specific ITSM configuration"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        config = await service.get_itsm_configuration(config_id)
        if not config:
            raise HTTPException(status_code=404, detail="ITSM configuration not found")
        return config
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get ITSM configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/itsm/configurations")
async def create_itsm_configuration(
    request: ITSMConfigRequest,
    current_user: dict = Depends(auth_get_current_user)
):
    """Create a new ITSM configuration"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        config = await service.create_itsm_configuration(
            name=request.name,
            system_type=request.system_type,
            base_url=request.base_url,
            instance_name=request.instance_name,
            credential_id=request.credential_id,
            default_project=request.default_project,
            default_ticket_type=request.default_ticket_type,
            field_mappings=request.field_mappings,
            created_by=current_user.get('username', 'system')
        )
        return {"status": "created", "configuration": config}
    except Exception as e:
        logger.error(f"Failed to create ITSM configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/itsm/configurations/{config_id}")
async def update_itsm_configuration(
    config_id: str,
    request: ITSMConfigUpdateRequest,
    authorization: str = Header(None)
):
    """Update an ITSM configuration"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        updates = request.dict(exclude_unset=True)
        config = await service.update_itsm_configuration(config_id, updates)
        if not config:
            raise HTTPException(status_code=404, detail="ITSM configuration not found")
        return {"status": "updated", "configuration": config}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update ITSM configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/itsm/configurations/{config_id}")
async def delete_itsm_configuration(config_id: str, authorization: str = Header(None)):
    """Delete an ITSM configuration"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        deleted = await service.delete_itsm_configuration(config_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="ITSM configuration not found")
        return {"status": "deleted", "config_id": config_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete ITSM configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/itsm/configurations/{config_id}/test")
async def test_itsm_configuration(config_id: str, authorization: str = Header(None)):
    """Test an ITSM configuration by making a health check"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        result = await service.test_configuration(config_id)
        return result
    except Exception as e:
        logger.error(f"Failed to test ITSM configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/export-to-itsm")
async def export_investigation_to_itsm(
    investigation_id: str,
    request: ITSMExportRequest,
    current_user: dict = Depends(auth_get_current_user)
):
    """Export an investigation to an ITSM system using a configured integration"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        result = await service.export_to_itsm(
            investigation_id=investigation_id,
            config_id=request.config_id,
            ticket_type=request.ticket_type,
            additional_fields=request.additional_fields,
            created_by=current_user.get('username', 'system')
        )

        if result.get('status') == 'error':
            raise HTTPException(status_code=400, detail=result.get('message'))

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export to ITSM: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigations/{investigation_id}/itsm-exports")
async def get_investigation_itsm_exports(
    investigation_id: str,
    authorization: str = Header(None)
):
    """Get all ITSM exports for an investigation"""
    from services.itsm_service import get_itsm_service
    service = get_itsm_service()

    try:
        exports = await service.get_exports_for_investigation(investigation_id)
        return {"exports": exports, "count": len(exports)}
    except Exception as e:
        logger.error(f"Failed to get ITSM exports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


logger.info("Post-resolution routes loaded")
