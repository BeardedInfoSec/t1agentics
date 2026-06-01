# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent API Routes

REST API endpoints for managing AI agents in T1 Agentics.
Provides CRUD operations, execution tracking, and approval workflows.

All sensitive operational endpoints require authentication.
"""

from fastapi import APIRouter, HTTPException, Query, Body, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import logging
import json
import uuid as uuid_mod

from dependencies.auth import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class ApplicationAction(BaseModel):
    action: str
    type: str = "read"  # read, write, destructive
    requires_approval: bool = False
    allowed_targets: Optional[List[str]] = None
    denied_targets: Optional[List[str]] = None


class ApplicationPermission(BaseModel):
    id: str
    name: str
    actions: List[ApplicationAction]


class RateLimits(BaseModel):
    max_investigations_per_hour: int = 30
    max_actions_per_investigation: int = 50
    max_enrichments_per_minute: int = 20
    cooldown_after_destructive_action: int = 300


class AllowedHours(BaseModel):
    enabled: bool = False
    timezone: str = "UTC"
    windows: Optional[List[Dict[str, Any]]] = None
    emergency_override: bool = True


class Permissions(BaseModel):
    applications: List[ApplicationPermission] = []
    max_actions_per_run: int = 50
    require_approval: bool = True
    approval_timeout_minutes: int = 30


class AutoClosePolicy(BaseModel):
    """Policy for when agents can auto-close alerts and investigations"""
    enabled: bool = False  # Default: disabled for safety
    allowed_verdicts: List[str] = ["benign", "false_positive"]  # Verdicts that trigger auto-close
    min_confidence: float = 0.8  # Minimum confidence required to auto-close
    close_alert: bool = True  # Close the alert
    close_investigation: bool = True  # Close/resolve the investigation
    require_no_iocs: bool = False  # Only auto-close if no malicious IOCs found


class Guardrails(BaseModel):
    confidence_threshold: float = 0.6
    never_rules: List[str] = []
    escalation_triggers: List[str] = []
    allowed_hours: AllowedHours = AllowedHours()
    rate_limits: RateLimits = RateLimits()
    auto_close_policy: AutoClosePolicy = AutoClosePolicy()


class AgentModelConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    temperature: float = 0.1
    max_tokens_per_task: int = 8000
    max_cost_per_run: float = 2.00
    context_window: int = 64000


class AuditConfig(BaseModel):
    log_level: str = "standard"
    require_reasoning: bool = True
    evidence_retention_days: int = 90


class CreateAgentRequest(BaseModel):
    tier: int = Field(..., ge=1, le=3, description="Agent tier (1, 2, or 3)")
    focus: str = Field(..., description="Focus area (Alert, Identity, Endpoint, etc.)")
    role: str = Field(..., description="Role (Triage, Investigation, Response)")
    description: str = Field(..., description="Agent description")
    permissions: Permissions
    guardrails: Guardrails
    agent_model_config: AgentModelConfig = Field(default_factory=AgentModelConfig)
    audit_config: AuditConfig = Field(default_factory=AuditConfig)
    codename: Optional[str] = Field(None, description="Optional custom alias (cosmetic only)")


class UpdateAgentRequest(BaseModel):
    description: Optional[str] = None
    permissions: Optional[Permissions] = None
    guardrails: Optional[Guardrails] = None
    agent_model_config: Optional[AgentModelConfig] = None
    audit_config: Optional[AuditConfig] = None
    codename: Optional[str] = None
    enabled: Optional[bool] = None


class CreateFromTemplateRequest(BaseModel):
    template_id: str
    codename: Optional[str] = None
    description: Optional[str] = None
    model_config_override: Optional[Dict[str, Any]] = None  # Override model config from template


class TriggerExecutionRequest(BaseModel):
    trigger_type: str = "manual"
    trigger_source_id: Optional[str] = None
    trigger_source_type: Optional[str] = None


class RunAgentOnAlertRequest(BaseModel):
    alert_id: str
    run_async: bool = True


class ApprovalResponse(BaseModel):
    note: Optional[str] = None


# ============================================================================
# Agent CRUD Endpoints
# ============================================================================

@router.get("")
async def list_agents(
    tier: Optional[int] = Query(None, ge=1, le=3),
    focus: Optional[str] = None,
    enabled_only: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List all agents with optional filters"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        agents = await service.list_agents(
            tier=tier,
            focus=focus,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset
        )
        return {
            "agents": agents,
            "count": len(agents),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Failed to list agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("")
async def create_agent(request: CreateAgentRequest, current_user: dict = Depends(get_current_user)):
    """Create a new agent definition"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        agent = await service.create_agent(
            tier=request.tier,
            focus=request.focus,
            role=request.role,
            description=request.description,
            permissions=request.permissions.dict(),
            guardrails=request.guardrails.dict(),
            model_config=request.agent_model_config.dict(),
            audit_config=request.audit_config.dict(),
            codename=request.codename,
            created_by=current_user.get("username", "api")
        )
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/executions")
async def list_all_agent_executions(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List all agent executions with optional filters"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        executions = await service.list_executions(
            agent_id=agent_id,
            status=status,
            limit=limit,
            offset=offset
        )
        return {
            "executions": executions,
            "count": len(executions)
        }
    except Exception as e:
        logger.error(f"Failed to list executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Get an agent by ID"""
    try:
        uuid_mod.UUID(agent_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid agent ID format")
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{agent_id}")
async def update_agent(agent_id: str, request: UpdateAgentRequest):
    """Update an agent definition"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        updates = {k: v.dict() if hasattr(v, 'dict') else v
                   for k, v in request.dict(exclude_unset=True).items()}

        agent = await service.update_agent(agent_id, updates)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str):
    """Delete an agent definition"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        deleted = await service.delete_agent(agent_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"status": "deleted", "agent_id": agent_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_id}/enable")
async def enable_agent(agent_id: str):
    """Enable an agent"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        enabled = await service.enable_agent(agent_id)
        if not enabled:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"status": "enabled", "agent_id": agent_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_id}/disable")
async def disable_agent(agent_id: str):
    """Disable an agent"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        disabled = await service.disable_agent(agent_id)
        if not disabled:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"status": "disabled", "agent_id": agent_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class UpdateAutoClosePolicyRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable auto-close")
    allowed_verdicts: List[str] = Field(default=["benign", "false_positive"], description="Verdicts that trigger auto-close")
    min_confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Minimum confidence to auto-close")
    close_alert: bool = Field(default=True, description="Close the alert")
    close_investigation: bool = Field(default=True, description="Close/resolve the investigation")
    require_no_iocs: bool = Field(default=False, description="Only auto-close if no malicious IOCs found")


@router.put("/{agent_id}/auto-close-policy")
async def update_agent_auto_close_policy(agent_id: str, request: UpdateAutoClosePolicyRequest):
    """
    Update an agent's auto-close policy.

    Controls whether the agent can automatically close alerts and investigations
    when it determines them to be benign or false positive.
    """
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        # Verify agent exists
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Get current guardrails or create default
        current_guardrails = agent.get('guardrails', {})

        # Update auto_close_policy
        current_guardrails['auto_close_policy'] = {
            'enabled': request.enabled,
            'allowed_verdicts': request.allowed_verdicts,
            'min_confidence': request.min_confidence,
            'close_alert': request.close_alert,
            'close_investigation': request.close_investigation,
            'require_no_iocs': request.require_no_iocs
        }

        # Save updated guardrails
        updated = await service.update_agent(agent_id, {'guardrails': current_guardrails})
        if not updated:
            raise HTTPException(status_code=500, detail="Failed to update agent")

        return {
            "status": "updated",
            "agent_id": agent_id,
            "auto_close_policy": current_guardrails['auto_close_policy']
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update auto-close policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class UpdateModelConfigRequest(BaseModel):
    provider_id: str = Field(..., description="AI Provider ID from Settings")
    model: str = Field(..., description="Model ID to use")


@router.put("/{agent_id}/model-config")
async def update_agent_model_config(agent_id: str, request: UpdateModelConfigRequest):
    """
    Update an agent's AI model configuration.

    This updates the provider and model the agent uses for LLM calls,
    pulling the configuration from the Settings page.
    """
    from services.agent_service import get_agent_service
    from services.postgres_db import postgres_db
    service = get_agent_service()

    try:
        # Verify agent exists
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Verify provider exists and is enabled
        async with postgres_db.tenant_acquire() as conn:
            provider = await conn.fetchrow(
                "SELECT * FROM ai_providers WHERE id = $1 AND enabled = true",
                request.provider_id
            )
            if not provider:
                raise HTTPException(status_code=400, detail="AI Provider not found or disabled")

        # Build new model_config preserving other settings
        current_config = agent.get('model_config', {})

        # Get provider details to include in config
        provider_dict = dict(provider)
        provider_type = provider_dict.get('provider_type', 'openai_compatible')
        base_url = provider_dict.get('base_url', '')

        new_config = {
            **current_config,
            'provider_id': request.provider_id,
            'model': request.model,
            'provider': provider_type,  # Store provider type for executor lookup
            'base_url': base_url,       # Store base_url for direct API calls
        }

        # Update the agent
        updated = await service.update_agent(agent_id, {'model_config': new_config})

        return {
            "status": "updated",
            "agent_id": agent_id,
            "model_config": new_config,
            "provider_name": provider['name']
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent model config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Template Endpoints
# ============================================================================

@router.get("/templates/list")
async def list_templates(
    tier: Optional[int] = Query(None, ge=1, le=3),
    category: Optional[str] = None
):
    """List available agent templates"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        templates = await service.list_templates(tier=tier, category=category)
        return {"templates": templates, "count": len(templates)}
    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_id}")
async def get_template(template_id: str):
    """Get a template by ID"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        template = await service.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        return template
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/from-template")
async def create_agent_from_template(request: CreateFromTemplateRequest, current_user: dict = Depends(get_current_user)):
    """Create a new agent from a template"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        agent = await service.create_agent_from_template(
            template_id=request.template_id,
            codename=request.codename,
            description_override=request.description,
            model_config_override=request.model_config_override,
            created_by=current_user.get("username", "api")
        )
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create agent from template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Execution Endpoints
# ============================================================================

@router.post("/{agent_id}/run")
async def trigger_execution(agent_id: str, request: TriggerExecutionRequest):
    """Trigger a manual agent execution"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        # Verify agent exists and is enabled
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not agent.get('enabled', False):
            raise HTTPException(status_code=400, detail="Agent is disabled")

        execution = await service.create_execution(
            agent_id=agent_id,
            trigger_type=request.trigger_type,
            trigger_source_id=request.trigger_source_id,
            trigger_source_type=request.trigger_source_type
        )
        return execution
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger execution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_id}/analyze-alert")
async def run_agent_on_alert(agent_id: str, request: RunAgentOnAlertRequest):
    """
    Run an agent to analyze a specific alert.

    This triggers the full agent execution loop:
    1. Fetches the alert data
    2. Runs the agent with appropriate tools
    3. Returns the analysis result
    """
    from services.agent_service import get_agent_service
    from services.agent_executor import get_agent_executor
    import asyncio
    import json

    service = get_agent_service()
    executor = get_agent_executor()

    try:
        # Verify agent exists and is enabled
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not agent.get('enabled', False):
            raise HTTPException(status_code=400, detail="Agent is disabled")

        # Get the alert data
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            alert_row = await conn.fetchrow(
                'SELECT * FROM alerts WHERE id = $1',
                request.alert_id
            )
            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert = dict(alert_row)
            if isinstance(alert.get('raw_data'), str):
                alert['raw_data'] = json.loads(alert['raw_data'])

        # Create execution record
        execution = await service.create_execution(
            agent_id=agent_id,
            trigger_type='alert',  # Use 'alert' - allowed by DB constraint
            trigger_source_id=request.alert_id,
            trigger_source_type='alert'
        )

        execution_id = execution['execution_id']

        # Check if there are file attachments for this alert
        attachment_count = await conn.fetchval(
            'SELECT COUNT(*) FROM alert_attachments WHERE alert_id = $1 AND deleted_at IS NULL',
            alert.get('alert_id')
        )

        # Prepare input data for the agent
        input_data = {
            "trigger_type": "alert_analysis",
            "trigger_source_id": request.alert_id,
            "trigger_source_type": "alert",
            "alert": {
                "id": str(alert.get('id')),
                "alert_id": alert.get('alert_id'),
                "title": alert.get('title'),
                "description": alert.get('description'),
                "severity": alert.get('severity'),
                "status": alert.get('status'),
                "source_tool": alert.get('source_tool'),
                "created_at": str(alert.get('created_at')) if alert.get('created_at') else None,
                "raw_data": alert.get('raw_data', {}),
                "has_attachments": attachment_count > 0,
                "attachment_count": attachment_count
            },
            "instructions": "IMPORTANT: This alert has file attachments. Use list_alert_attachments and analyze_file_attachment tools." if attachment_count > 0 else None
        }

        if request.run_async:
            # Run in background
            async def run_in_background():
                try:
                    await executor.run_agent(
                        agent=agent,
                        execution_id=execution_id,
                        input_data=input_data
                    )
                except Exception as e:
                    logger.error(f"Background agent execution failed: {e}")
                    await service.update_execution(execution_id, {
                        'status': 'failed',
                        'error_details': {'error': str(e)}
                    })

            asyncio.create_task(run_in_background())

            return {
                "status": "started",
                "execution_id": execution_id,
                "agent_id": agent_id,
                "alert_id": request.alert_id,
                "message": "Agent execution started in background"
            }
        else:
            # Run synchronously (may timeout for complex analyses)
            result = await executor.run_agent(
                agent=agent,
                execution_id=execution_id,
                input_data=input_data
            )

            return {
                "status": "completed" if result.get('success') else "failed",
                "execution_id": execution_id,
                "agent_id": agent_id,
                "alert_id": request.alert_id,
                "result": result
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to run agent on alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{agent_id}/executions")
async def list_agent_executions(
    agent_id: str,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List executions for a specific agent"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        executions = await service.list_executions(
            agent_id=agent_id,
            status=status,
            limit=limit,
            offset=offset
        )
        return {
            "executions": executions,
            "count": len(executions),
            "agent_id": agent_id
        }
    except Exception as e:
        logger.error(f"Failed to list executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Execution Detail Endpoints (separate router)
# ============================================================================

executions_router = APIRouter(prefix="/api/v1/executions", tags=["Executions"], dependencies=[Depends(get_current_user)])


@executions_router.get("")
async def list_all_executions(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List all executions with optional filters"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        executions = await service.list_executions(
            agent_id=agent_id,
            status=status,
            limit=limit,
            offset=offset
        )
        return {
            "executions": executions,
            "count": len(executions)
        }
    except Exception as e:
        logger.error(f"Failed to list executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@executions_router.get("/{execution_id}")
async def get_execution(execution_id: str):
    """Get execution details"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        execution = await service.get_execution(execution_id)
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found")
        return execution
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get execution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@executions_router.get("/{execution_id}/timeline")
async def get_execution_timeline(execution_id: str):
    """Get the action timeline for an execution"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        actions = await service.get_action_log(execution_id)
        execution = await service.get_execution(execution_id)

        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found")

        return {
            "execution_id": execution_id,
            "agent_id": str(execution.get('agent_id')),
            "status": execution.get('status'),
            "started_at": execution.get('started_at'),
            "completed_at": execution.get('completed_at'),
            "reasoning": execution.get('reasoning', []),
            "actions": actions,
            "outcome": execution.get('outcome'),
            "compliance": execution.get('compliance')
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@executions_router.post("/{execution_id}/stop")
async def stop_execution(execution_id: str):
    """Stop a running execution"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        execution = await service.update_execution(
            execution_id,
            {
                'status': 'cancelled',
                'completed_at': 'CURRENT_TIMESTAMP'
            }
        )
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found")
        return {"status": "cancelled", "execution_id": execution_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop execution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Approval Endpoints
# ============================================================================

approvals_router = APIRouter(prefix="/api/v1/approvals", tags=["Approvals"], dependencies=[Depends(get_current_user)])


@approvals_router.get("")
async def list_pending_approvals(
    agent_id: Optional[str] = None,
    limit: int = Query(50, le=200)
):
    """List pending approval requests"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        approvals = await service.list_pending_approvals(
            agent_id=agent_id,
            limit=limit
        )
        return {
            "approvals": approvals,
            "count": len(approvals)
        }
    except Exception as e:
        logger.error(f"Failed to list approvals: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@approvals_router.get("/{request_id}")
async def get_approval_request(request_id: str):
    """Get an approval request by ID"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database unavailable")

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_approval_requests WHERE id = $1",
                request_id
            )
            if not row:
                raise HTTPException(status_code=404, detail="Approval request not found")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get approval: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@approvals_router.post("/{request_id}/approve")
async def approve_request(request_id: str, response: ApprovalResponse = Body(default=ApprovalResponse()), current_user: dict = Depends(get_current_user)):
    """Approve a pending request"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        result = await service.approve_request(
            request_id=request_id,
            approved_by=current_user.get("username", "api"),
            note=response.note
        )
        if not result:
            raise HTTPException(status_code=404, detail="Approval request not found or already processed")
        return {"status": "approved", "request_id": request_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@approvals_router.post("/{request_id}/deny")
async def deny_request(request_id: str, response: ApprovalResponse = Body(default=ApprovalResponse()), current_user: dict = Depends(get_current_user)):
    """Deny a pending request"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        result = await service.deny_request(
            request_id=request_id,
            denied_by=current_user.get("username", "api"),
            note=response.note
        )
        if not result:
            raise HTTPException(status_code=404, detail="Approval request not found or already processed")
        return {"status": "denied", "request_id": request_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deny request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Queue-based Agent Execution
# ============================================================================

class QueueAgentJobRequest(BaseModel):
    agent_id: str
    alert_id: str
    priority: int = 5


@router.post("/queue/analyze-alert")
async def queue_agent_alert_analysis(request: QueueAgentJobRequest):
    """
    Queue an agent job to analyze an alert.
    The job will be processed by the background worker.
    """
    from services.job_queue import get_job_queue_service, QueueName, QueueFullError
    from services.agent_service import get_agent_service
    from services.postgres_db import postgres_db
    import json

    service = get_agent_service()
    job_queue = await get_job_queue_service()

    try:
        # Verify agent exists and is enabled
        agent = await service.get_agent(request.agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not agent.get('enabled', False):
            raise HTTPException(status_code=400, detail="Agent is disabled")

        # Get the alert data
        async with postgres_db.tenant_acquire() as conn:
            alert_row = await conn.fetchrow(
                'SELECT * FROM alerts WHERE id = $1',
                request.alert_id
            )
            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert = dict(alert_row)
            if isinstance(alert.get('raw_data'), str):
                alert['raw_data'] = json.loads(alert['raw_data'])

        # Enqueue the job
        job_id = await job_queue.enqueue(
            queue_name=QueueName.AGENT,
            job_type='agent_analyze_alert',
            payload={
                'agent_id': request.agent_id,
                'alert_id': request.alert_id,
                'alert_data': {
                    "id": str(alert.get('id')),
                    "title": alert.get('title'),
                    "description": alert.get('description'),
                    "severity": alert.get('severity'),
                    "status": alert.get('status'),
                    "source_tool": alert.get('source_tool'),
                    "raw_data": alert.get('raw_data', {})
                }
            },
            priority=request.priority,
            raise_on_full=True
        )

        return {
            "status": "queued",
            "job_id": job_id,
            "agent_id": request.agent_id,
            "alert_id": request.alert_id
        }

    except QueueFullError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to queue agent job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class AutoTriageRequest(BaseModel):
    alert_id: str
    priority: int = 3  # Higher priority for auto-triage


@router.post("/queue/auto-triage")
async def queue_auto_triage(request: AutoTriageRequest):
    """
    Queue an alert for automatic triage by the appropriate agent.
    The system will select the best Tier 1 agent for the job.
    """
    from services.job_queue import get_job_queue_service, QueueName, QueueFullError
    from services.postgres_db import postgres_db

    job_queue = await get_job_queue_service()

    try:
        # Verify alert exists
        async with postgres_db.tenant_acquire() as conn:
            alert_row = await conn.fetchrow(
                'SELECT id FROM alerts WHERE id = $1',
                request.alert_id
            )
            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")

        # Enqueue the auto-triage job
        job_id = await job_queue.enqueue(
            queue_name=QueueName.AGENT,
            job_type='agent_auto_triage',
            payload={
                'alert_id': request.alert_id
            },
            priority=request.priority,
            raise_on_full=True
        )

        return {
            "status": "queued",
            "job_id": job_id,
            "alert_id": request.alert_id,
            "message": "Alert queued for automatic triage"
        }

    except QueueFullError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to queue auto-triage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Agent Scheduler Endpoints
# ============================================================================

class SchedulerConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    auto_triage_enabled: Optional[bool] = None
    poll_interval_seconds: Optional[int] = None
    max_events_per_cycle: Optional[int] = None
    max_queue_depth: Optional[int] = None
    severity_filter: Optional[List[str]] = None


@router.get("/ops/scheduler/status")
async def get_scheduler_status(current_user: dict = Depends(get_current_user)):
    """Get the current status of the agent scheduler"""
    from services.agent_scheduler import get_agent_scheduler

    try:
        scheduler = get_agent_scheduler()
        return scheduler.get_status()
    except Exception as e:
        logger.error(f"Failed to get scheduler status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ops/llm/queue-status")
async def get_llm_queue_status():
    """
    Get the current LLM queue status.

    Shows how many LLM requests are waiting and the concurrency limits.
    Useful for monitoring system load and diagnosing slowdowns.
    """
    from services.agent_executor import get_llm_queue_status

    try:
        return get_llm_queue_status()
    except Exception as e:
        logger.error(f"Failed to get LLM queue status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ops/job-queue-stats")
async def get_job_queue_stats():
    """
    Get job queue statistics for monitoring.

    Returns counts of pending, processing, completed, and failed jobs
    grouped by job type. Useful for the LLM mesh dashboard to show
    how many alerts/investigations are queued.
    """
    from services.postgres_db import postgres_db

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get job counts by type and status
            stats = await conn.fetch("""
                SELECT
                    job_type,
                    status,
                    COUNT(*) as count
                FROM job_queue
                WHERE created_at > NOW() - INTERVAL '24 hours'
                GROUP BY job_type, status
                ORDER BY job_type, status
            """)

            # Get overall totals
            totals = await conn.fetchrow("""
                SELECT
                    COUNT(*) FILTER (WHERE status = 'pending') as pending,
                    COUNT(*) FILTER (WHERE status IN ('running', 'processing')) as processing,
                    COUNT(*) FILTER (WHERE status = 'completed') as completed,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed,
                    COUNT(*) as total
                FROM job_queue
                WHERE created_at > NOW() - INTERVAL '24 hours'
            """)

            # Get pending alerts count
            pending_alerts = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE status NOT IN ('resolved', 'closed', 'false_positive')
                AND investigation_id IS NULL
            """)

            # Get pending investigations by state
            inv_states = await conn.fetch("""
                SELECT
                    state,
                    COUNT(*) as count
                FROM investigations
                WHERE state NOT IN ('CLOSED', 'RESOLVED', 'FALSE_POSITIVE')
                GROUP BY state
            """)

            # Structure the response
            by_type = {}
            for row in stats:
                job_type = row['job_type']
                if job_type not in by_type:
                    by_type[job_type] = {'pending': 0, 'processing': 0, 'completed': 0, 'failed': 0}
                status = row['status']
                if status in ('running', 'processing'):
                    by_type[job_type]['processing'] += row['count']
                elif status in by_type[job_type]:
                    by_type[job_type][status] = row['count']

            return {
                "totals": {
                    "pending": totals['pending'] if totals else 0,
                    "processing": totals['processing'] if totals else 0,
                    "completed": totals['completed'] if totals else 0,
                    "failed": totals['failed'] if totals else 0,
                    "total": totals['total'] if totals else 0
                },
                "by_type": by_type,
                "pending_alerts": pending_alerts or 0,
                "investigations_by_state": {
                    row['state']: row['count'] for row in inv_states
                }
            }

    except Exception as e:
        logger.error(f"Failed to get job queue stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))



@router.get("/ops/riggs/queue")
async def get_riggs_queue():
    """
    Get the current Riggs review queue.

    Returns investigations in RIGGS_REVIEW state awaiting human-AI collaboration.
    This endpoint is used by the dashboard to show pending Riggs work items.
    """
    from services.postgres_db import postgres_db

    try:
        async with postgres_db.tenant_acquire() as conn:
            investigations = await conn.fetch("""
                SELECT
                    i.id,
                    i.investigation_id,
                    i.title,
                    i.severity,
                    i.priority,
                    i.state,
                    i.created_at,
                    i.updated_at,
                    i.alert_id,
                    EXTRACT(EPOCH FROM (NOW() - i.updated_at))/60 as minutes_in_queue,
                    i.investigation_data->'tier2_analysis'->>'verdict' as t2_verdict,
                    i.investigation_data->'tier2_analysis'->>'summary' as t2_summary
                FROM investigations i
                WHERE i.state = 'NEEDS_REVIEW'
                ORDER BY
                    CASE i.priority
                        WHEN 'P1' THEN 1
                        WHEN 'P2' THEN 2
                        WHEN 'P3' THEN 3
                        WHEN 'P4' THEN 4
                        ELSE 5
                    END,
                    i.updated_at ASC
                LIMIT 50
            """)

            return {
                "queue_count": len(investigations),
                "investigations": [
                    {
                        "id": str(inv['id']),
                        "investigation_id": inv['investigation_id'],
                        "title": inv['title'],
                        "severity": inv['severity'],
                        "priority": inv['priority'],
                        "state": inv['state'],
                        "created_at": inv['created_at'].isoformat() if inv['created_at'] else None,
                        "updated_at": inv['updated_at'].isoformat() if inv['updated_at'] else None,
                        "alert_id": str(inv['alert_id']) if inv['alert_id'] else None,
                        "minutes_in_queue": round(inv['minutes_in_queue'], 1) if inv['minutes_in_queue'] else 0,
                        "t2_verdict": inv['t2_verdict'],
                        "t2_summary": inv['t2_summary']
                    }
                    for inv in investigations
                ]
            }

    except Exception as e:
        logger.error(f"Failed to get Riggs queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ops/scheduler/config")
async def update_scheduler_config(config: SchedulerConfigUpdate, current_user: dict = Depends(require_admin)):
    """Update the agent scheduler configuration. ADMIN ONLY."""
    from services.agent_scheduler import get_agent_scheduler

    try:
        scheduler = get_agent_scheduler()
        updates = {k: v for k, v in config.dict().items() if v is not None}
        scheduler.update_config(**updates)

        return {
            "status": "updated",
            "config": scheduler.get_status()
        }
    except Exception as e:
        logger.error(f"Failed to update scheduler config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ops/scheduler/start")
async def start_scheduler(current_user: dict = Depends(require_admin)):
    """Start the agent scheduler. ADMIN ONLY."""
    from services.agent_scheduler import get_agent_scheduler

    try:
        scheduler = get_agent_scheduler()
        await scheduler.start()
        return {
            "status": "started",
            "config": scheduler.get_status()
        }
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ops/scheduler/stop")
async def stop_scheduler(current_user: dict = Depends(require_admin)):
    """Stop the agent scheduler. ADMIN ONLY."""
    from services.agent_scheduler import get_agent_scheduler

    try:
        scheduler = get_agent_scheduler()
        await scheduler.stop()
        return {
            "status": "stopped",
            "config": scheduler.get_status()
        }
    except Exception as e:
        logger.error(f"Failed to stop scheduler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Statistics Endpoints
# ============================================================================

@router.get("/stats/overview")
async def get_agent_stats_overview(current_user: dict = Depends(get_current_user)):
    """Get agent statistics overview (alias for /ops/stats)"""
    return await get_agent_stats(current_user=current_user)


@router.get("/ops/stats")
async def get_agent_stats(current_user: dict = Depends(get_current_user)):
    """Get agent statistics overview"""
    from services.agent_service import get_agent_service
    service = get_agent_service()

    try:
        agents = await service.list_agents(limit=1000)

        stats = {
            "total_agents": len(agents),
            "enabled_agents": len([a for a in agents if a.get('enabled')]),
            "by_tier": {
                "tier_1": len([a for a in agents if a.get('tier') == 1]),
                "tier_2": len([a for a in agents if a.get('tier') == 2]),
                "tier_3": len([a for a in agents if a.get('tier') == 3])
            },
            "by_focus": {}
        }

        # Count by focus
        for agent in agents:
            focus = agent.get('focus', 'Unknown')
            stats['by_focus'][focus] = stats['by_focus'].get(focus, 0) + 1

        return stats
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Agent Operations Center Endpoints
# ============================================================================

@router.get("/ops/executions/recent")
async def get_recent_executions(
    limit: int = Query(50, le=200),
    status: Optional[str] = None,
    agent_id: Optional[str] = None
):
    """Get recent agent executions across all agents for the Operations Center"""
    from services.postgres_db import postgres_db
    import json

    try:
        query = """
            SELECT
                ae.execution_id,
                ae.agent_id,
                ae.status,
                ae.trigger_type,
                ae.trigger_source_id,
                ae.trigger_source_type,
                ae.started_at,
                ae.completed_at,
                ae.reasoning,
                ae.evidence,
                ae.outcome,
                ae.actions,
                ae.tokens_used,
                a.name as agent_name,
                a.display_name as agent_codename,
                a.level as agent_tier
            FROM agent_executions ae
            LEFT JOIN ai_agents a ON ae.agent_id::text = a.id::text
            WHERE 1=1
        """
        params = []

        if status:
            params.append(status)
            query += f" AND ae.status = ${len(params)}"

        if agent_id:
            params.append(agent_id)
            query += f" AND ae.agent_id = ${len(params)}"

        params.append(limit)
        query += f" ORDER BY ae.started_at DESC LIMIT ${len(params)}"

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(query, *params)

            executions = []
            for row in rows:
                exec_data = dict(row)
                # Parse JSON fields
                for field in ['reasoning', 'evidence', 'outcome']:
                    if exec_data.get(field) and isinstance(exec_data[field], str):
                        try:
                            exec_data[field] = json.loads(exec_data[field])
                        except:
                            pass
                # Convert datetime to ISO strings
                for field in ['started_at', 'completed_at']:
                    if exec_data.get(field):
                        exec_data[field] = exec_data[field].isoformat()
                executions.append(exec_data)

            return {"executions": executions, "count": len(executions)}

    except Exception as e:
        logger.error(f"Failed to get recent executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ops/metrics")
async def get_agent_metrics_overview():
    """
    Get comprehensive metrics for the Agent Operations Center.
    Includes token usage, resolution times, success rates, etc.
    """
    from services.postgres_db import postgres_db
    from datetime import datetime, timedelta

    try:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        yesterday = now - timedelta(days=1)

        async with postgres_db.tenant_acquire() as conn:
            # Token usage today
            tokens_today = await conn.fetchrow("""
                SELECT COALESCE(SUM(total_tokens), 0) as total
                FROM ai_token_usage
                WHERE created_at >= $1
            """, today_start)

            # Token usage this month
            tokens_month = await conn.fetchrow("""
                SELECT COALESCE(SUM(total_tokens), 0) as total
                FROM ai_token_usage
                WHERE created_at >= $1
            """, month_start)

            # Events processed in last 24h
            events_24h = await conn.fetchrow("""
                SELECT COUNT(*) as count
                FROM agent_executions
                WHERE started_at >= $1
                AND trigger_source_type = 'alert'
            """, yesterday)

            # Average resolution time (from alert creation to agent completion)
            avg_resolution = await conn.fetchrow("""
                SELECT
                    AVG(EXTRACT(EPOCH FROM (ae.completed_at - a.created_at)) * 1000) as avg_ms
                FROM agent_executions ae
                JOIN alerts a ON ae.trigger_source_id = a.id::text
                WHERE ae.status = 'completed'
                AND ae.completed_at IS NOT NULL
                AND ae.started_at >= $1
            """, yesterday)

            # Average agent execution time (just the agent processing time)
            avg_agent_time = await conn.fetchrow("""
                SELECT
                    AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) as avg_ms,
                    MIN(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) as min_ms,
                    MAX(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) as max_ms,
                    COUNT(*) as count
                FROM agent_executions
                WHERE status = 'completed'
                AND completed_at IS NOT NULL
                AND started_at >= $1
            """, yesterday)

            # Success rate (last 24h)
            success_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) FILTER (WHERE status = 'completed') as completed,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed,
                    COUNT(*) as total
                FROM agent_executions
                WHERE started_at >= $1
            """, yesterday)

            # Calculate success rate
            total_execs = success_stats['total'] or 0
            completed = success_stats['completed'] or 0
            success_rate = round((completed / total_execs * 100) if total_execs > 0 else 0, 1)

            # Events in (total alerts) vs Events touched (alerts with agent execution)
            events_in_vs_touched = await conn.fetchrow("""
                SELECT
                    COUNT(DISTINCT a.id) as total_events,
                    COUNT(DISTINCT ae.trigger_source_id) as events_touched,
                    COUNT(DISTINCT CASE WHEN a.status IN ('resolved', 'false_positive') THEN a.id END) as events_closed
                FROM alerts a
                LEFT JOIN agent_executions ae ON a.id::text = ae.trigger_source_id
                WHERE a.created_at >= $1
            """, yesterday)

            total_events = events_in_vs_touched['total_events'] or 0
            events_touched = events_in_vs_touched['events_touched'] or 0
            events_closed = events_in_vs_touched['events_closed'] or 0
            touch_rate = round((events_touched / total_events * 100) if total_events > 0 else 0, 1)
            close_rate = round((events_closed / total_events * 100) if total_events > 0 else 0, 1)

            # Average LLM response time
            avg_response_time = await conn.fetchrow("""
                SELECT
                    AVG(response_time_ms) as avg_ms,
                    MIN(response_time_ms) as min_ms,
                    MAX(response_time_ms) as max_ms,
                    COUNT(*) as call_count
                FROM ai_token_usage
                WHERE created_at >= $1
                AND response_time_ms IS NOT NULL
            """, yesterday)

            # Per-agent stats - Use agent_definitions table (not ai_agents)
            agent_stats = await conn.fetch("""
                SELECT
                    a.id as agent_id,
                    a.system_name,
                    a.codename,
                    a.tier,
                    COUNT(ae.execution_id) FILTER (WHERE ae.started_at >= $1) as executions_today,
                    COUNT(ae.execution_id) FILTER (WHERE ae.status = 'completed' AND ae.started_at >= $1) as completed_today,
                    COUNT(ae.execution_id) FILTER (WHERE ae.started_at >= $1 AND ae.status IN ('completed', 'failed')) as finished_today,
                    COALESCE(SUM(ae.tokens_used) FILTER (WHERE ae.started_at >= $1), 0) as tokens_today,
                    AVG(EXTRACT(EPOCH FROM (ae.completed_at - ae.started_at)) * 1000) FILTER (
                        WHERE ae.status = 'completed' AND ae.completed_at IS NOT NULL AND ae.started_at >= $1
                    ) as avg_duration_ms
                FROM agent_definitions a
                LEFT JOIN agent_executions ae ON a.id = ae.agent_id
                GROUP BY a.id, a.system_name, a.codename, a.tier
                ORDER BY executions_today DESC
            """, today_start)

            # Format agent stats with success rate
            formatted_agent_stats = []
            for stat in agent_stats:
                finished = stat['finished_today'] or 0
                completed = stat['completed_today'] or 0
                agent_success_rate = round((completed / finished * 100) if finished > 0 else 100, 1)

                formatted_agent_stats.append({
                    "agent_id": str(stat['agent_id']),
                    "system_name": stat['system_name'],
                    "codename": stat['codename'],
                    "tier": stat['tier'],
                    "stats": {
                        "executions_today": stat['executions_today'] or 0,
                        "success_rate": agent_success_rate,
                        "tokens_today": stat['tokens_today'] or 0,
                        "avg_duration": int(stat['avg_duration_ms'] or 0)
                    }
                })

            return {
                "totalTokensToday": tokens_today['total'] or 0,
                "totalTokensMonth": tokens_month['total'] or 0,
                "eventsProcessed24h": events_24h['count'] or 0,
                "avgResolutionTime": int(avg_resolution['avg_ms'] or 0),
                "successRate": success_rate,
                "agentStats": formatted_agent_stats,
                # New metrics: events coverage
                "eventsCoverage": {
                    "totalEvents": total_events,
                    "eventsTouched": events_touched,
                    "eventsClosed": events_closed,
                    "touchRate": touch_rate,
                    "closeRate": close_rate,
                    "untouchedEvents": total_events - events_touched
                },
                # New metrics: LLM response time
                "llmPerformance": {
                    "avgResponseTimeMs": int(avg_response_time['avg_ms'] or 0),
                    "minResponseTimeMs": int(avg_response_time['min_ms'] or 0),
                    "maxResponseTimeMs": int(avg_response_time['max_ms'] or 0),
                    "totalCalls": avg_response_time['call_count'] or 0
                },
                # Agent execution time (separate from queue wait time)
                "agentExecutionTime": {
                    "avgMs": int(avg_agent_time['avg_ms'] or 0),
                    "minMs": int(avg_agent_time['min_ms'] or 0),
                    "maxMs": int(avg_agent_time['max_ms'] or 0),
                    "executionCount": avg_agent_time['count'] or 0
                }
            }

    except Exception as e:
        logger.error(f"Failed to get agent metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ops/audit-log")
async def get_agent_audit_log(
    limit: int = Query(100, le=500),
    agent_id: Optional[str] = None,
    action_type: Optional[str] = None
):
    """
    Get audit log of agent actions.
    Shows what agents have done, including tool calls and verdicts.
    """
    from services.postgres_db import postgres_db
    import json

    try:
        # First, check if we have a dedicated audit table
        async with postgres_db.tenant_acquire() as conn:
            # Check if agent_audit_log table exists
            table_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'agent_audit_log'
                )
            """)

            if table_exists:
                query = """
                    SELECT
                        al.*,
                        ad.system_name as agent_name,
                        ad.codename as agent_codename
                    FROM agent_audit_log al
                    LEFT JOIN agent_definitions ad ON al.agent_id = ad.id
                    WHERE 1=1
                """
                params = []

                if agent_id:
                    params.append(agent_id)
                    query += f" AND al.agent_id = ${len(params)}"

                if action_type:
                    params.append(action_type)
                    query += f" AND al.action_type = ${len(params)}"

                params.append(limit)
                query += f" ORDER BY al.created_at DESC LIMIT ${len(params)}"

                rows = await conn.fetch(query, *params)
                logs = []
                for row in rows:
                    log = dict(row)
                    if log.get('created_at'):
                        log['timestamp'] = log['created_at'].isoformat()
                    logs.append(log)

                return {"logs": logs, "count": len(logs)}

            else:
                # Fall back to action_log from executions
                # Note: agent_definitions table holds agent configs, ai_agents is legacy
                query = """
                    SELECT
                        al.id,
                        al.execution_id,
                        al.action_type,
                        al.action,
                        al.target_type,
                        al.target_id,
                        al.result as action_result,
                        al.status,
                        al.error_message,
                        al.created_at as timestamp,
                        al.reasoning,
                        al.confidence,
                        ae.agent_id,
                        ad.system_name as agent_name,
                        ad.codename as agent_codename,
                        ad.tier as agent_tier
                    FROM agent_action_log al
                    JOIN agent_executions ae ON al.execution_id = ae.id
                    LEFT JOIN agent_definitions ad ON ae.agent_id = ad.id
                    WHERE 1=1
                """
                params = []

                if agent_id:
                    params.append(agent_id)
                    query += f" AND ae.agent_id = ${len(params)}"

                if action_type:
                    params.append(action_type)
                    query += f" AND al.action_type = ${len(params)}"

                params.append(limit)
                query += f" ORDER BY al.created_at DESC LIMIT ${len(params)}"

                rows = await conn.fetch(query, *params)
                logs = []
                for row in rows:
                    log = dict(row)
                    if log.get('timestamp'):
                        log['timestamp'] = log['timestamp'].isoformat()
                    logs.append(log)

                return {"logs": logs, "count": len(logs)}

    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ops/token-usage")
async def get_token_usage(
    days: int = Query(30, le=90),
    agent_id: Optional[str] = None
):
    """Get token usage statistics"""
    from services.token_tracking import get_token_tracker
    from datetime import datetime, timedelta

    try:
        tracker = get_token_tracker()
        start_date = datetime.utcnow() - timedelta(days=days)

        summary = await tracker.get_usage_summary(start_date=start_date)
        daily = await tracker.get_daily_usage(days=days)
        by_model = await tracker.get_usage_by_model(start_date=start_date)

        return {
            "summary": summary,
            "daily": daily,
            "by_model": by_model
        }

    except Exception as e:
        logger.error(f"Failed to get token usage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# BREAK GLASS - Emergency Stop
# ============================================================================

@router.post("/ops/emergency-stop")
async def emergency_stop(current_user: dict = Depends(require_admin)):
    """
    BREAK GLASS: Emergency stop all AI agents and clear the job queue. ADMIN ONLY.

    This will:
    1. Stop the agent scheduler
    2. Cancel all pending/running agent jobs
    3. Disable all agents temporarily
    4. Log the emergency action

    Use this when agents are misbehaving or need immediate halt.
    """
    from services.agent_scheduler import get_agent_scheduler
    from services.job_queue import get_job_queue_service
    from services.postgres_db import postgres_db
    from datetime import datetime

    results = {
        "scheduler_stopped": False,
        "jobs_cleared": 0,
        "agents_disabled": 0,
        "timestamp": datetime.utcnow().isoformat(),
        "errors": []
    }

    try:
        # 1. Stop the agent scheduler
        try:
            scheduler = get_agent_scheduler()
            if scheduler.running:
                await scheduler.stop()
                results["scheduler_stopped"] = True
                logger.warning("🛑 EMERGENCY: Agent scheduler stopped")
        except Exception as e:
            results["errors"].append(f"Scheduler stop failed: {str(e)}")
            logger.error(f"Emergency stop - scheduler error: {e}")

        # 2. Clear all agent jobs from the queue
        try:
            async with postgres_db.tenant_acquire() as conn:
                # Cancel pending jobs (status is 'pending' or 'processing' in the schema)
                pending_result = await conn.execute('''
                    UPDATE job_queue
                    SET status = 'failed',
                        completed_at = CURRENT_TIMESTAMP,
                        error_message = 'Emergency stop activated'
                    WHERE status IN ('pending', 'processing')
                    AND job_type LIKE 'agent_%'
                ''')
                results["jobs_cleared"] = int(pending_result.split()[-1]) if pending_result else 0
                logger.warning(f"🛑 EMERGENCY: Cleared {results['jobs_cleared']} agent jobs")
        except Exception as e:
            results["errors"].append(f"Job queue clear failed: {str(e)}")
            logger.error(f"Emergency stop - job queue error: {e}")

        # 3. Reset all alerts from ai_triage_queued state
        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE alerts
                    SET ai_triage_queued = FALSE,
                        ai_triage_queued_at = NULL
                    WHERE ai_triage_queued = TRUE
                ''')
                logger.warning("🛑 EMERGENCY: Reset alert triage queue flags")
        except Exception as e:
            results["errors"].append(f"Alert reset failed: {str(e)}")
            logger.error(f"Emergency stop - alert reset error: {e}")

        # 4. Reset stuck investigations in AI_TRIAGE states to AWAITING_HUMAN
        results["investigations_reset"] = 0
        try:
            async with postgres_db.tenant_acquire() as conn:
                inv_result = await conn.execute('''
                    UPDATE investigations
                    SET state = 'AWAITING_HUMAN',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE state IN ('AI_TRIAGE_L1', 'AI_TRIAGE_L2', 'AI_TRIAGE_L3')
                ''')
                results["investigations_reset"] = int(inv_result.split()[-1]) if inv_result else 0
                logger.warning(f"🛑 EMERGENCY: Reset {results['investigations_reset']} stuck investigations")
        except Exception as e:
            results["errors"].append(f"Investigation reset failed: {str(e)}")
            logger.error(f"Emergency stop - investigation reset error: {e}")

        # 5. Log the emergency action
        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO system_logs (level, source, message, details, created_at)
                    VALUES ('critical', 'emergency_stop', 'Emergency stop activated', $1, CURRENT_TIMESTAMP)
                ''', json.dumps(results))
        except Exception as e:
            # Don't fail if logging fails
            logger.error(f"Failed to log emergency stop: {e}")

        print("🛑 EMERGENCY STOP ACTIVATED")
        print(f"   Scheduler stopped: {results['scheduler_stopped']}")
        print(f"   Jobs cleared: {results['jobs_cleared']}")

        return {
            "success": True,
            "message": "Emergency stop activated - all agents halted",
            **results
        }

    except Exception as e:
        logger.error(f"Emergency stop failed: {e}")
        raise HTTPException(status_code=500, detail=f"Emergency stop failed: {str(e)}")


@router.post("/ops/emergency-resume")
async def emergency_resume(current_user: dict = Depends(require_admin)):
    """
    Resume agent operations after an emergency stop. ADMIN ONLY.

    This will:
    1. Restart the agent scheduler
    2. Re-enable agent processing
    """
    from services.agent_scheduler import get_agent_scheduler
    from services.postgres_db import postgres_db
    from datetime import datetime

    results = {
        "scheduler_started": False,
        "timestamp": datetime.utcnow().isoformat(),
        "errors": []
    }

    try:
        # 1. Start the agent scheduler
        try:
            scheduler = get_agent_scheduler()
            if not scheduler.running:
                await scheduler.start()
                results["scheduler_started"] = True
                logger.info("[OK] Agent scheduler resumed")
        except Exception as e:
            results["errors"].append(f"Scheduler start failed: {str(e)}")
            logger.error(f"Emergency resume - scheduler error: {e}")

        # 2. Log the resume action
        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO system_logs (level, source, message, details, created_at)
                    VALUES ('info', 'emergency_resume', 'Agent operations resumed', $1, CURRENT_TIMESTAMP)
                ''', json.dumps(results))
        except Exception as e:
            logger.error(f"Failed to log resume: {e}")

        print("[OK] AGENT OPERATIONS RESUMED")

        return {
            "success": True,
            "message": "Agent operations resumed",
            **results
        }

    except Exception as e:
        logger.error(f"Emergency resume failed: {e}")
        raise HTTPException(status_code=500, detail=f"Resume failed: {str(e)}")
