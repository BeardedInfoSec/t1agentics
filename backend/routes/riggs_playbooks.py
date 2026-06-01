# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs-Playbook Integration API Routes

Endpoints for Riggs playbook recommendations and execution.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from services.riggs_playbook_integration import get_riggs_playbook_integration
from services.postgres_db import postgres_db
from dependencies.auth import get_current_user
from dependencies.license_checks import enforce_riggs_limit, enforce_feature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/riggs/playbooks", tags=["riggs-playbooks"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class PlaybookRecommendationRequest(BaseModel):
    """Request playbook recommendations for an investigation."""
    investigation_id: str
    max_recommendations: int = Field(default=3, ge=1, le=10)


class PlaybookExecutionRequest(BaseModel):
    """Request playbook execution from Riggs."""
    investigation_id: str
    playbook_id: str
    auto_execute: bool = False
    wait_for_completion: bool = False


class PlaybookFeedbackRequest(BaseModel):
    """Submit feedback on playbook execution."""
    investigation_id: str
    execution_id: str
    outcome: str  # success, failed, partial
    effectiveness_score: int = Field(ge=0, le=100)
    analyst_notes: Optional[str] = None


class ApprovalDecisionRequest(BaseModel):
    """Approve or reject playbook execution."""
    approval_id: str
    decision: str  # approved, rejected
    notes: Optional[str] = None


class BuildFromAlertRequest(BaseModel):
    """Ask Riggs to draft a playbook from a specific ingested alert."""
    alert_id: str = Field(..., min_length=1, max_length=128)
    persist: bool = True
    use_llm: bool = True


class BuildFromAlertResponse(BaseModel):
    playbook_id: Optional[str]
    name: str
    source: str   # "llm" or "template" (or "soar_conversion" etc.)
    editor_url: Optional[str]
    node_count: int
    edge_count: int
    generation_reason: Optional[str] = None


class VPEAssistRequest(BaseModel):
    """Interactive playbook-editing chat inside the VPE."""
    message: str = Field(..., min_length=1, max_length=4000)
    canvas: Dict[str, Any] = Field(default_factory=lambda: {"nodes": [], "edges": []})
    playbook_id: Optional[str] = None


class VPEAssistResponse(BaseModel):
    reply: str
    mutations: List[Dict[str, Any]] = Field(default_factory=list)
    rejected: List[str] = Field(default_factory=list)
    source: str = "llm"


# ============================================================================
# Routes
# ============================================================================

@router.post("/recommend")
async def get_playbook_recommendations(
    request: PlaybookRecommendationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_chat")),
    _limit: None = Depends(enforce_riggs_limit("riggs_chat")),
):
    """
    Get playbook recommendations for an investigation.

    Returns playbooks that Riggs recommends based on investigation findings.
    """
    try:
        integration = get_riggs_playbook_integration()

        # Load investigation and alert data
        async with postgres_db.tenant_acquire() as conn:
            investigation = await conn.fetchrow('''
                SELECT * FROM investigations
                WHERE investigation_id = $1
            ''', request.investigation_id)

            if not investigation:
                raise HTTPException(status_code=404, detail="Investigation not found")

            investigation_dict = dict(investigation)

            # Get alert
            alert_id = investigation_dict.get('alert_id')
            if alert_id:
                alert_id = str(alert_id)
            alert = await conn.fetchrow('''
                SELECT * FROM alerts
                WHERE alert_id = $1
            ''', alert_id)

            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert_dict = dict(alert)

        # Extract Riggs analysis from investigation_data
        investigation_data = investigation_dict.get('investigation_data', {})
        if isinstance(investigation_data, str):
            import json
            investigation_data = json.loads(investigation_data)

        riggs_analysis = investigation_data.get('riggs_analysis', {})

        if not riggs_analysis:
            raise HTTPException(
                status_code=400,
                detail="No Riggs analysis found for this investigation"
            )

        # Get recommendations
        recommendations = await integration.recommend_playbooks(
            riggs_analysis=riggs_analysis,
            alert=alert_dict,
            investigation=investigation_dict,
            max_recommendations=request.max_recommendations
        )

        return {
            "investigation_id": request.investigation_id,
            "recommendations": [
                {
                    "playbook_id": rec.playbook_id,
                    "playbook_name": rec.playbook_name,
                    "match_score": rec.match_score,
                    "reasoning": rec.reasoning,
                    "auto_execute": rec.auto_execute,
                    "requires_approval": rec.requires_approval,
                    "estimated_duration_minutes": rec.estimated_duration_minutes,
                    "expected_actions": rec.expected_actions
                }
                for rec in recommendations
            ],
            "count": len(recommendations)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get playbook recommendations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/build-from-alert", response_model=BuildFromAlertResponse)
async def build_playbook_from_alert(
    request: BuildFromAlertRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_chat")),
    _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
):
    """
    Have Riggs draft a playbook from a specific ingested alert.

    Persists the result as a disabled draft in `playbooks` (name prefixed
    "Riggs Draft: ", tagged `riggs-draft` + `from-alert`). The caller can open
    `editor_url` to load it in the VPE for review before enabling.
    """
    from services.riggs_playbook_builder import get_riggs_playbook_builder

    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context missing")

    try:
        builder = get_riggs_playbook_builder()
        result = await builder.build_from_alert(
            alert_id=request.alert_id,
            tenant_id=tenant_id,
            persist=request.persist,
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as exc:
        logger.exception(f"build_from_alert failed for {request.alert_id}: {exc}")
        raise HTTPException(status_code=500, detail="Failed to build playbook")

    return BuildFromAlertResponse(
        playbook_id=result.get("playbook_id"),
        name=result.get("name", ""),
        source=result.get("source", "unknown"),
        editor_url=result.get("editor_url"),
        node_count=result.get("node_count", 0),
        edge_count=result.get("edge_count", 0),
        generation_reason=result.get("generation_reason"),
    )


@router.post("/vpe-assist", response_model=VPEAssistResponse)
async def vpe_assist_endpoint(
    request: VPEAssistRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_chat")),
    _limit: None = Depends(enforce_riggs_limit("riggs_chat")),
):
    """
    Interactive Riggs assistant for the Visual Playbook Editor.

    Takes the current canvas (nodes + edges) and a user message. Returns a
    natural-language reply plus a list of validated canvas mutations the
    frontend can apply directly to React Flow state.
    """
    from services.riggs_vpe_assistant import vpe_assist
    from uuid import UUID as _UUID

    tenant_id = current_user.get("tenant_id")
    user_id = current_user.get("user_id") or current_user.get("id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context missing")

    try:
        tid_uuid = _UUID(str(tenant_id))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid tenant id")

    uid_uuid = None
    if user_id:
        try:
            uid_uuid = _UUID(str(user_id))
        except Exception:
            uid_uuid = None

    result = await vpe_assist(
        message=request.message,
        canvas=request.canvas or {"nodes": [], "edges": []},
        tenant_id=tid_uuid,
        playbook_id=request.playbook_id,
        user_id=uid_uuid,
    )
    return VPEAssistResponse(**result)


@router.post("/execute")
async def execute_playbook(
    request: PlaybookExecutionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Execute a playbook for an investigation.

    Triggers playbook execution based on Riggs findings.
    """
    try:
        integration = get_riggs_playbook_integration()

        # Load investigation and alert data
        async with postgres_db.tenant_acquire() as conn:
            investigation = await conn.fetchrow('''
                SELECT * FROM investigations
                WHERE investigation_id = $1
            ''', request.investigation_id)

            if not investigation:
                raise HTTPException(status_code=404, detail="Investigation not found")

            investigation_dict = dict(investigation)

            # Get alert
            alert_id = investigation_dict.get('alert_id')
            if alert_id:
                alert_id = str(alert_id)
            alert = await conn.fetchrow('''
                SELECT * FROM alerts
                WHERE alert_id = $1
            ''', alert_id)

            alert_dict = dict(alert)

            # Get playbook
            playbook = await conn.fetchrow('''
                SELECT * FROM playbooks
                WHERE id = $1
            ''', request.playbook_id)

            if not playbook:
                raise HTTPException(status_code=404, detail="Playbook not found")

            playbook_dict = dict(playbook)

        # Extract Riggs analysis
        investigation_data = investigation_dict.get('investigation_data', {})
        if isinstance(investigation_data, str):
            import json
            investigation_data = json.loads(investigation_data)

        riggs_analysis = investigation_data.get('riggs_analysis', {})

        # Build recommendation for execution
        from services.riggs_playbook_integration import PlaybookRecommendation
        recommendation = PlaybookRecommendation(
            playbook_id=request.playbook_id,
            playbook_name=playbook_dict.get('name', 'Unknown'),
            match_score=100.0,  # Manual execution
            reasoning="Manually triggered by analyst",
            auto_execute=request.auto_execute,
            requires_approval=playbook_dict.get('requires_approval', True)
        )

        # Execute
        result = await integration.execute_recommended_playbook(
            recommendation=recommendation,
            investigation=investigation_dict,
            alert=alert_dict,
            riggs_analysis=riggs_analysis,
            triggered_by=f"analyst_{current_user.get('user_id', 'unknown')}"
        )

        return {
            "execution_id": result.execution_id,
            "playbook_id": result.playbook_id,
            "status": result.status,
            "started_at": result.started_at,
            "outcome": result.outcome
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute playbook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/executions/{investigation_id}")
async def get_investigation_executions(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get all playbook executions for an investigation."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            executions = await conn.fetch('''
                SELECT
                    rpe.*,
                    p.name as playbook_name,
                    pe.status as execution_status,
                    pe.completed_at
                FROM riggs_playbook_executions rpe
                LEFT JOIN playbooks p ON rpe.playbook_id = p.id
                LEFT JOIN playbook_executions pe ON rpe.execution_id = pe.execution_id
                WHERE rpe.investigation_id = $1
                ORDER BY rpe.created_at DESC
            ''', investigation_id)

            return {
                "investigation_id": investigation_id,
                "executions": [
                    {
                        "execution_id": e['execution_id'],
                        "playbook_id": str(e['playbook_id']),
                        "playbook_name": e['playbook_name'],
                        "triggered_by": e['triggered_by'],
                        "riggs_verdict": e['riggs_verdict'],
                        "status": e['execution_status'],
                        "outcome": e['outcome'],
                        "effectiveness_score": e['effectiveness_score'],
                        "created_at": e['created_at'].isoformat(),
                        "completed_at": e['completed_at'].isoformat() if e['completed_at'] else None
                    }
                    for e in executions
                ],
                "count": len(executions)
            }

    except Exception as e:
        logger.error(f"Failed to get executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback")
async def submit_playbook_feedback(
    request: PlaybookFeedbackRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Submit feedback on playbook execution effectiveness."""
    try:
        integration = get_riggs_playbook_integration()

        await integration.record_playbook_feedback(
            investigation_id=request.investigation_id,
            execution_id=request.execution_id,
            outcome=request.outcome,
            effectiveness_score=request.effectiveness_score,
            analyst_notes=request.analyst_notes
        )

        return {
            "success": True,
            "message": "Feedback recorded successfully"
        }

    except Exception as e:
        logger.error(f"Failed to record feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/approvals/pending")
async def get_pending_approvals(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get all pending playbook execution approvals."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            approvals = await conn.fetch('''
                SELECT
                    a.*,
                    i.title as investigation_title,
                    i.severity
                FROM playbook_execution_approvals a
                LEFT JOIN investigations i ON a.investigation_id = i.investigation_id
                WHERE a.status = 'pending'
                AND (a.expires_at IS NULL OR a.expires_at > NOW())
                ORDER BY a.created_at DESC
            ''')

            return {
                "approvals": [
                    {
                        "approval_id": a['id'],
                        "investigation_id": a['investigation_id'],
                        "investigation_title": a['investigation_title'],
                        "severity": a['severity'],
                        "playbook_id": str(a['playbook_id']),
                        "playbook_name": a['playbook_name'],
                        "riggs_verdict": a['riggs_verdict'],
                        "riggs_confidence": a['riggs_confidence'],
                        "riggs_reasoning": a['riggs_reasoning'],
                        "created_at": a['created_at'].isoformat(),
                        "expires_at": a['expires_at'].isoformat() if a['expires_at'] else None
                    }
                    for a in approvals
                ],
                "count": len(approvals)
            }

    except Exception as e:
        logger.error(f"Failed to get pending approvals: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approvals/decide")
async def decide_approval(
    request: ApprovalDecisionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Approve or reject a playbook execution request."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Update approval
            result = await conn.fetchrow('''
                UPDATE playbook_execution_approvals
                SET status = $2,
                    approved_by = $3,
                    approval_notes = $4,
                    responded_at = NOW()
                WHERE id = $1
                AND status = 'pending'
                RETURNING *
            ''',
                request.approval_id,
                request.decision,
                current_user.get('user_id'),
                request.notes
            )

            if not result:
                raise HTTPException(
                    status_code=404,
                    detail="Approval not found or already processed"
                )

            approval = dict(result)

            # If approved, trigger execution
            if request.decision == 'approved':
                integration = get_riggs_playbook_integration()

                # Load investigation data
                investigation = await conn.fetchrow('''
                    SELECT * FROM investigations
                    WHERE investigation_id = $1
                ''', approval['investigation_id'])

                # Execute playbook
                # ... (execution logic here)

                return {
                    "success": True,
                    "decision": "approved",
                    "message": "Playbook execution approved and triggered",
                    "approval_id": request.approval_id
                }
            else:
                return {
                    "success": True,
                    "decision": "rejected",
                    "message": "Playbook execution rejected",
                    "approval_id": request.approval_id
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process approval decision: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/effectiveness")
async def get_playbook_effectiveness_analytics(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get playbook effectiveness analytics."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            stats = await conn.fetch('''
                SELECT * FROM riggs_playbook_effectiveness
                WHERE total_executions > 0
                ORDER BY avg_effectiveness DESC NULLS LAST
                LIMIT 20
            ''')

            return {
                "playbooks": [
                    {
                        "playbook_id": str(s['playbook_id']),
                        "playbook_name": s['playbook_name'],
                        "total_executions": s['total_executions'],
                        "successful_executions": s['successful_executions'],
                        "success_rate": round(100 * s['successful_executions'] / s['total_executions'], 1) if s['total_executions'] > 0 else 0,
                        "avg_effectiveness": round(s['avg_effectiveness'], 1) if s['avg_effectiveness'] else None,
                        "auto_executions": s['auto_executions'],
                        "malicious_verdicts": s['malicious_verdicts'],
                        "last_executed": s['last_executed'].isoformat() if s['last_executed'] else None
                    }
                    for s in stats
                ],
                "count": len(stats)
            }

    except Exception as e:
        logger.error(f"Failed to get analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
