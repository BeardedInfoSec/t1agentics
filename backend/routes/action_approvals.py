# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs Action Approval Routes

API endpoints for managing Riggs response action approvals.
When Riggs wants to take a high-impact action (isolate host, suspend user, etc.),
it queues the request here for human approval.

This is separate from the general approval token system - these are specifically
for response actions that Riggs initiates during investigations.
"""

import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Body, Header, Request, Depends
from pydantic import BaseModel, Field

from routes.admin import get_current_username, require_admin
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/action-approvals", tags=["Action Approvals"], dependencies=[Depends(get_current_user)])


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class ActionApprovalRequest(BaseModel):
    """Request model for creating an action approval request."""
    action_name: str = Field(..., description="Name of the action (e.g., 'isolate_host')")
    integration_name: str = Field(..., description="Integration to execute via")
    target_type: str = Field(..., description="Type of target (host, user, ip, etc.)")
    target_identifier: str = Field(..., description="The actual target value")
    reason: str = Field(..., description="Why Riggs wants to take this action")
    alert_id: Optional[str] = Field(None, description="Associated alert ID")
    investigation_id: Optional[str] = Field(None, description="Associated investigation ID")
    riggs_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Riggs's confidence")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Supporting evidence")
    priority: str = Field(default='medium', description="low, medium, high, critical")
    expires_in_minutes: int = Field(default=30, ge=5, le=1440, description="Minutes until auto-reject")


class ActionApprovalReview(BaseModel):
    """Request model for approving/rejecting an action."""
    notes: Optional[str] = Field(None, description="Review notes")
    execute_immediately: bool = Field(default=True, description="Execute action after approval")


class ActionRejectRequest(BaseModel):
    """Request model for rejecting an action."""
    reason: Optional[str] = Field(None, description="Reason for rejection")


# ============================================================================
# ROUTES
# ============================================================================

@router.get("/")
async def list_pending_approvals(
    request: Request,
    priority: Optional[str] = Query(None, description="Filter by priority"),
    limit: int = Query(50, le=200),
    authorization: str = Header(None)
):
    """
    List pending action approval requests.

    Returns actions that Riggs has requested and are awaiting human review.
    Sorted by priority (critical first) then by request time.
    """
    await get_current_username(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()
    approvals = await service.get_pending_approvals(priority=priority, limit=limit)

    return {
        "approvals": approvals,
        "count": len(approvals),
        "status": "pending"
    }


@router.post("/")
async def create_approval_request(
    request: ActionApprovalRequest
):
    """
    Create a new action approval request.

    Typically called by Riggs when it wants to take a response action
    that requires human approval (based on integration permissions).
    """
    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()

    result = await service.create_approval_request(
        action_name=request.action_name,
        integration_name=request.integration_name,
        target_type=request.target_type,
        target_identifier=request.target_identifier,
        reason=request.reason,
        alert_id=request.alert_id,
        investigation_id=request.investigation_id,
        riggs_confidence=request.riggs_confidence,
        evidence=request.evidence,
        priority=request.priority,
        expires_in_minutes=request.expires_in_minutes
    )

    if result.get('error'):
        raise HTTPException(status_code=500, detail=result['error'])

    return result


@router.get("/stats")
async def get_approval_stats(request: Request, authorization: str = Header(None)):
    """
    Get statistics about action approvals.

    Returns counts by status, recent actions, and approval rate.
    """
    await get_current_username(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()
    stats = await service.get_approval_stats()

    if stats.get('error'):
        raise HTTPException(status_code=500, detail=stats['error'])

    return stats


@router.get("/{approval_id}")
async def get_approval(
    request: Request,
    approval_id: str,
    authorization: str = Header(None)
):
    """
    Get a specific action approval request by ID.

    Returns full details including evidence, execution result, etc.
    """
    await get_current_username(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()
    approval = await service.get_approval(approval_id)

    if not approval:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found")

    return approval


@router.post("/{approval_id}/approve")
async def approve_action(
    request: Request,
    approval_id: str,
    review: ActionApprovalReview = Body(default=ActionApprovalReview()),
    authorization: str = Header(None)
):
    """
    Approve a pending action request.

    If execute_immediately is True (default), the action will be executed
    via the integration immediately after approval.
    """
    username = await get_current_username(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()

    result = await service.approve_action(
        approval_id=approval_id,
        approved_by=username,
        notes=review.notes,
        execute_immediately=review.execute_immediately
    )

    if result.get('error'):
        # Check if it's a not found error
        if 'not found' in result['error'].lower():
            raise HTTPException(status_code=404, detail=result['error'])
        raise HTTPException(status_code=400, detail=result['error'])

    return result


@router.post("/{approval_id}/reject")
async def reject_action(
    request: Request,
    approval_id: str,
    body: ActionRejectRequest = Body(default=ActionRejectRequest()),
    authorization: str = Header(None)
):
    """
    Reject a pending action request.

    Rejected actions will not be executed. A reason should be provided
    to help Riggs learn from the feedback.
    """
    username = await get_current_username(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()

    result = await service.reject_action(
        approval_id=approval_id,
        rejected_by=username,
        reason=body.reason
    )

    if result.get('error'):
        if 'not found' in result['error'].lower():
            raise HTTPException(status_code=404, detail=result['error'])
        raise HTTPException(status_code=400, detail=result['error'])

    return result


@router.post("/expire-old")
async def expire_old_approvals(request: Request, authorization: str = Header(None)):
    """
    Mark expired approval requests as expired.

    Should be called periodically by a scheduler.
    Admin only.
    """
    await require_admin(request, authorization)

    from services.action_approval_service import get_action_approval_service

    service = get_action_approval_service()
    count = await service.expire_old_approvals()

    return {"expired_count": count}


# ============================================================================
# INTEGRATION CAPABILITIES (Permission Management)
# ============================================================================

class CapabilityUpdate(BaseModel):
    """Request model for updating capability permissions."""
    permission_level: str = Field(..., description="auto, approval_required, or disabled")


@router.get("/capabilities")
async def list_integration_capabilities(
    request: Request,
    integration_name: Optional[str] = Query(None, description="Filter by integration"),
    capability_type: Optional[str] = Query(None, description="Filter by type"),
    permission_level: Optional[str] = Query(None, description="Filter by permission"),
    authorization: str = Header(None)
):
    """
    List integration capabilities and their permission levels.

    Shows what actions Riggs can take and whether they require approval.
    """
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = '''
                SELECT ic.*, i.name as integration_name, i.display_name as integration_display_name
                FROM integration_capabilities ic
                LEFT JOIN integrations i ON ic.integration_id = i.id
                WHERE 1=1
            '''
            params = []
            param_count = 0

            if integration_name:
                param_count += 1
                query += f' AND i.name = ${param_count}'
                params.append(integration_name)

            if capability_type:
                param_count += 1
                query += f' AND ic.capability_type = ${param_count}'
                params.append(capability_type)

            if permission_level:
                param_count += 1
                query += f' AND ic.permission_level = ${param_count}'
                params.append(permission_level)

            query += ' ORDER BY i.name, ic.capability_name'

            rows = await conn.fetch(query, *params)

            capabilities = []
            for row in rows:
                cap = dict(row)
                # Convert UUID to string
                if cap.get('id'):
                    cap['id'] = str(cap['id'])
                if cap.get('integration_id'):
                    cap['integration_id'] = str(cap['integration_id'])
                capabilities.append(cap)

            return {
                "capabilities": capabilities,
                "count": len(capabilities)
            }

    except Exception as e:
        logger.error(f"Failed to list capabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/capabilities/{capability_id}")
async def update_capability_permission(
    request: Request,
    capability_id: str,
    update: CapabilityUpdate,
    authorization: str = Header(None)
):
    """
    Update the permission level for an integration capability.

    Permission levels:
    - auto: Riggs can use without asking
    - approval_required: Requires human approval
    - disabled: Riggs cannot use

    Admin only.
    """
    await require_admin(request, authorization)

    if update.permission_level not in ['auto', 'approval_required', 'disabled']:
        raise HTTPException(
            status_code=400,
            detail="Invalid permission level. Must be 'auto', 'approval_required', or 'disabled'"
        )

    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute('''
                UPDATE integration_capabilities
                SET permission_level = $1, updated_at = NOW()
                WHERE id = $2
            ''', update.permission_level, capability_id)

            if result == 'UPDATE 0':
                raise HTTPException(status_code=404, detail=f"Capability {capability_id} not found")

            return {
                "capability_id": capability_id,
                "permission_level": update.permission_level,
                "updated": True
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update capability: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# RIGGS DECISIONS (Audit Log)
# ============================================================================

@router.get("/decisions")
async def list_riggs_decisions(
    request: Request,
    decision_type: Optional[str] = Query(None, description="Filter by decision type"),
    alert_id: Optional[str] = Query(None, description="Filter by alert ID"),
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    has_feedback: Optional[bool] = Query(None, description="Filter by feedback status"),
    limit: int = Query(50, le=200),
    authorization: str = Header(None)
):
    """
    List Riggs's decisions for audit and review.

    Shows what decisions Riggs made, its reasoning, and any human feedback.
    """
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = 'SELECT * FROM riggs_decisions WHERE 1=1'
            params = []
            param_count = 0

            if decision_type:
                param_count += 1
                query += f' AND decision_type = ${param_count}'
                params.append(decision_type)

            if alert_id:
                param_count += 1
                query += f' AND alert_id = ${param_count}'
                params.append(alert_id)

            if investigation_id:
                param_count += 1
                query += f' AND investigation_id = ${param_count}'
                params.append(investigation_id)

            if has_feedback is not None:
                if has_feedback:
                    query += ' AND human_feedback IS NOT NULL'
                else:
                    query += ' AND human_feedback IS NULL'

            param_count += 1
            query += f' ORDER BY created_at DESC LIMIT ${param_count}'
            params.append(limit)

            rows = await conn.fetch(query, *params)

            decisions = []
            for row in rows:
                dec = dict(row)
                # Convert UUIDs to strings
                for field in ['id', 'alert_id', 'investigation_id', 'feedback_by']:
                    if dec.get(field):
                        dec[field] = str(dec[field])
                # Convert datetime to ISO string
                for field in ['created_at', 'feedback_at']:
                    if dec.get(field):
                        dec[field] = dec[field].isoformat()
                decisions.append(dec)

            return {
                "decisions": decisions,
                "count": len(decisions)
            }

    except Exception as e:
        logger.error(f"Failed to list decisions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class DecisionFeedback(BaseModel):
    """Request model for providing feedback on a Riggs decision."""
    feedback: str = Field(..., description="correct, incorrect, or partially_correct")
    notes: Optional[str] = Field(None, description="Feedback notes")


@router.post("/decisions/{decision_id}/feedback")
async def provide_decision_feedback(
    request: Request,
    decision_id: str,
    feedback: DecisionFeedback,
    authorization: str = Header(None)
):
    """
    Provide feedback on a Riggs decision.

    This feedback helps Riggs learn and improve over time.
    """
    username = await get_current_username(request, authorization)

    if feedback.feedback not in ['correct', 'incorrect', 'partially_correct']:
        raise HTTPException(
            status_code=400,
            detail="Invalid feedback. Must be 'correct', 'incorrect', or 'partially_correct'"
        )

    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute('''
                UPDATE riggs_decisions
                SET human_feedback = $1,
                    feedback_notes = $2,
                    feedback_by = $3,
                    feedback_at = NOW()
                WHERE decision_id = $4
            ''', feedback.feedback, feedback.notes, username, decision_id)

            if result == 'UPDATE 0':
                raise HTTPException(status_code=404, detail=f"Decision {decision_id} not found")

            return {
                "decision_id": decision_id,
                "feedback": feedback.feedback,
                "updated": True
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update decision feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))
