# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Unified Reasoning Engine API Routes

REST API endpoints for the unified reasoning engine.
This is the new architecture - ONE engine, ONE prompt, judgment-preserving.

Endpoints:
- POST /investigate - Run investigation cycle
- GET /investigate/{id}/status - Get investigation status
- POST /investigate/{id}/upgrade-authority - Upgrade authority level
- GET /heuristics - List heuristics
- GET /heuristics/stats - Heuristic performance stats
- POST /heuristics/{id}/feedback - Record heuristic feedback
"""

from fastapi import APIRouter, HTTPException, Query, Body, BackgroundTasks, Header, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
import logging
import uuid
import jwt
from datetime import datetime

# Try relative import first (when running as part of backend package)
# Fall back to absolute import (when backend is in PYTHONPATH)
try:
    from reasoning_engine import (
        get_investigation_runner,
        get_tool_broker,
        get_checkpoint_manager,
        get_confidence_gate,
        get_heuristic_loader,
        AuthorityLevel,
        Checkpoint,
        CycleResult
    )
except ImportError:
    from backend.reasoning_engine import (
        get_investigation_runner,
        get_tool_broker,
        get_checkpoint_manager,
        get_confidence_gate,
        get_heuristic_loader,
        AuthorityLevel,
        Checkpoint,
        CycleResult
    )

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reasoning", tags=["Unified Reasoning Engine"])


# =============================================================================
# Authentication
# =============================================================================

async def get_current_user(authorization: str = Header(None)) -> Dict[str, Any]:
    """
    Extract and validate user from JWT token in Authorization header.
    Returns user dict if valid, raises HTTPException if not.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.replace("Bearer ", "")

    try:
        # Get JWT secret from dependencies.auth (DB-backed, strict key)
        from dependencies.auth import JWT_SECRET_KEY, JWT_ALGORITHM

        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")

        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Get user from database
        from services.postgres_db import postgres_db
        user = await postgres_db.get_user_by_username(username)

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


async def require_analyst_or_admin(user: Dict = Depends(get_current_user)) -> Dict:
    """Require analyst or admin role for reasoning engine access."""
    role = user.get("role", "")
    if role not in ["admin", "analyst", "soc_analyst", "senior_analyst"]:
        raise HTTPException(
            status_code=403,
            detail="Analyst or admin role required for reasoning engine access"
        )
    return user


async def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    """Require admin role for sensitive operations."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# =============================================================================
# Request/Response Models
# =============================================================================

class AuthorityLevelEnum(str, Enum):
    OBSERVE = "OBSERVE"
    INVESTIGATE = "INVESTIGATE"
    RESPOND = "RESPOND"
    PRE_APPROVED = "PRE_APPROVED"


class RunInvestigationRequest(BaseModel):
    """Request to run an investigation cycle."""
    investigation_id: Optional[str] = Field(None, description="Investigation ID (generated if not provided)")
    alert_data: Dict[str, Any] = Field(..., description="Alert data to investigate")
    authority_level: AuthorityLevelEnum = Field(
        AuthorityLevelEnum.OBSERVE,
        description="Initial authority level"
    )
    max_cycles: int = Field(5, ge=1, le=20, description="Max reasoning cycles to run")
    auto_progress: bool = Field(True, description="Automatically progress through cycles")


class InvestigationStatusResponse(BaseModel):
    """Investigation status response."""
    investigation_id: str
    status: str
    current_checkpoint: str
    authority_level: str
    confidence: int
    iteration_count: int
    tool_calls: int
    established_facts: int
    confidence_history: List[int]
    last_assessment: Optional[str] = None
    last_gaps: Optional[List[str]] = None
    escalation_reason: Optional[str] = None
    started_at: str
    last_updated: str


class CycleResultResponse(BaseModel):
    """Result of a reasoning cycle."""
    result: str
    checkpoint: str
    confidence: int
    iteration: int
    assessment: Optional[str] = None
    gaps: Optional[List[str]] = None
    next_action: Optional[Dict[str, Any]] = None
    tool_result: Optional[Dict[str, Any]] = None
    escalation_reason: Optional[str] = None
    error: Optional[str] = None


class UpgradeAuthorityRequest(BaseModel):
    """Request to upgrade authority level."""
    new_level: AuthorityLevelEnum
    reason: str = Field(..., min_length=10, description="Reason for upgrade")


class HeuristicFeedbackRequest(BaseModel):
    """Feedback for a heuristic."""
    investigation_id: str
    was_helpful: bool
    confidence_delta: float = Field(0.0, ge=-100, le=100)
    feedback_text: Optional[str] = None


class HeuristicResponse(BaseModel):
    """Heuristic details."""
    id: str
    name: str
    category: str
    is_active: bool
    total_uses: int
    helpful_count: int
    accuracy: str
    weight: float


class ToolAccessCheckRequest(BaseModel):
    """Check tool access."""
    tool_id: str
    authority_level: AuthorityLevelEnum
    confidence: int = Field(..., ge=0, le=100)


# =============================================================================
# Investigation Endpoints
# =============================================================================

@router.post("/investigate", response_model=CycleResultResponse)
async def run_investigation(
    request: RunInvestigationRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """
    Run investigation cycle(s) on an alert.

    This is the main entry point for the unified reasoning engine.
    It runs reasoning cycles until completion, escalation, or max_cycles reached.

    Requires: Analyst or Admin role
    """
    try:
        runner = get_investigation_runner()

        # Generate investigation ID if not provided
        investigation_id = request.investigation_id or str(uuid.uuid4())

        # Set initial authority if this is a new investigation
        state = runner.get_state(investigation_id)
        if state is None:
            # New investigation - will be created with first cycle
            pass
        else:
            # Existing investigation
            if request.authority_level.value != state.authority_level:
                runner.upgrade_authority(investigation_id, AuthorityLevel(request.authority_level.value))

        # Run cycles
        last_result = None
        cycles_run = 0

        while cycles_run < request.max_cycles:
            result = await runner.run_cycle(
                investigation_id=investigation_id,
                alert_data=request.alert_data if cycles_run == 0 else None
            )

            last_result = result
            cycles_run += 1

            logger.info(f"[REASONING API] Cycle {cycles_run}: {result.result.value}, confidence: {result.confidence}%")

            # Stop conditions
            if result.result in [CycleResult.RESOLVED, CycleResult.ESCALATED, CycleResult.ERROR]:
                break

            if not request.auto_progress:
                break

        # Build response
        return CycleResultResponse(
            result=last_result.result.value,
            checkpoint=last_result.checkpoint,
            confidence=last_result.confidence,
            iteration=last_result.iteration,
            assessment=last_result.reasoning_output.assessment if last_result.reasoning_output else None,
            gaps=last_result.reasoning_output.gaps if last_result.reasoning_output else None,
            next_action=last_result.reasoning_output.next_action if last_result.reasoning_output else None,
            tool_result=last_result.tool_result,
            escalation_reason=last_result.escalation_reason,
            error=last_result.error
        )

    except Exception as e:
        logger.error(f"[REASONING API] Investigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigate/{investigation_id}/cycle", response_model=CycleResultResponse)
async def run_single_cycle(
    investigation_id: str,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """
    Run a single reasoning cycle for an existing investigation.

    Use this for step-by-step investigation control.

    Requires: Analyst or Admin role
    """
    try:
        runner = get_investigation_runner()

        state = runner.get_state(investigation_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

        result = await runner.run_cycle(investigation_id=investigation_id)

        return CycleResultResponse(
            result=result.result.value,
            checkpoint=result.checkpoint,
            confidence=result.confidence,
            iteration=result.iteration,
            assessment=result.reasoning_output.assessment if result.reasoning_output else None,
            gaps=result.reasoning_output.gaps if result.reasoning_output else None,
            next_action=result.reasoning_output.next_action if result.reasoning_output else None,
            tool_result=result.tool_result,
            escalation_reason=result.escalation_reason,
            error=result.error
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Cycle error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigate/{investigation_id}/status", response_model=InvestigationStatusResponse)
async def get_investigation_status(
    investigation_id: str,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Get the current status of an investigation.

    Requires: Analyst or Admin role
    """
    try:
        runner = get_investigation_runner()

        state = runner.get_state(investigation_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

        # Get last reasoning output
        last_assessment = None
        last_gaps = None
        if state.reasoning_history:
            last = state.reasoning_history[-1]
            last_assessment = last.assessment
            last_gaps = last.gaps

        return InvestigationStatusResponse(
            investigation_id=investigation_id,
            status="active" if state.current_checkpoint != "resolved" else "resolved",
            current_checkpoint=state.current_checkpoint,
            authority_level=state.authority_level,
            confidence=state.confidence,
            iteration_count=state.iteration_count,
            tool_calls=len(state.tool_results),
            established_facts=len(state.established_facts),
            confidence_history=state.confidence_history,
            last_assessment=last_assessment,
            last_gaps=last_gaps,
            started_at=state.started_at.isoformat(),
            last_updated=state.last_updated.isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigate/{investigation_id}/upgrade-authority")
async def upgrade_authority(
    investigation_id: str,
    request: UpgradeAuthorityRequest,
    current_user: Dict = Depends(require_admin)
):
    """
    Upgrade authority level for an investigation.

    Authority levels: OBSERVE -> INVESTIGATE -> RESPOND -> PRE_APPROVED

    Requires: Admin role (authority upgrades are sensitive operations)
    """
    try:
        runner = get_investigation_runner()

        state = runner.get_state(investigation_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

        old_level = state.authority_level
        success = runner.upgrade_authority(investigation_id, AuthorityLevel(request.new_level.value))

        if not success:
            raise HTTPException(status_code=400, detail="Failed to upgrade authority")

        logger.info(f"[REASONING API] Authority upgraded for {investigation_id}: {old_level} -> {request.new_level.value}")

        return {
            "success": True,
            "investigation_id": investigation_id,
            "old_level": old_level,
            "new_level": request.new_level.value,
            "reason": request.reason
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Authority upgrade error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Heuristics Endpoints
# =============================================================================

@router.get("/heuristics", response_model=List[HeuristicResponse])
async def list_heuristics(
    category: Optional[str] = Query(None, description="Filter by category"),
    active_only: bool = Query(True, description="Only show active heuristics"),
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """List all heuristics."""
    try:
        loader = get_heuristic_loader()
        stats = loader.get_heuristic_stats()

        if category:
            stats = [s for s in stats if s["category"] == category]

        if active_only:
            stats = [s for s in stats if s["is_active"]]

        return [HeuristicResponse(**s) for s in stats]

    except Exception as e:
        logger.error(f"[REASONING API] Heuristics list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/heuristics/stats")
async def get_heuristic_stats(current_user: Dict = Depends(require_analyst_or_admin)):
    """Get detailed heuristic performance statistics.

    Requires: Analyst or Admin role
    """
    try:
        loader = get_heuristic_loader()
        stats = loader.get_heuristic_stats()

        # Calculate aggregates
        total = len(stats)
        active = len([s for s in stats if s["is_active"]])
        total_uses = sum(s["total_uses"] for s in stats)

        return {
            "total_heuristics": total,
            "active_heuristics": active,
            "disabled_heuristics": total - active,
            "total_uses": total_uses,
            "by_category": _group_by_category(stats),
            "heuristics": stats
        }

    except Exception as e:
        logger.error(f"[REASONING API] Heuristics stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heuristics/{heuristic_id}/feedback")
async def record_heuristic_feedback(
    heuristic_id: str,
    request: HeuristicFeedbackRequest,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Record feedback for a heuristic use.

    Requires: Analyst or Admin role
    """
    try:
        loader = get_heuristic_loader()

        loader.record_outcome(
            heuristic_id=heuristic_id,
            investigation_id=request.investigation_id,
            was_helpful=request.was_helpful,
            confidence_delta=request.confidence_delta,
            analyst_feedback=request.feedback_text
        )

        return {
            "success": True,
            "heuristic_id": heuristic_id,
            "was_helpful": request.was_helpful
        }

    except Exception as e:
        logger.error(f"[REASONING API] Heuristic feedback error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heuristics/{heuristic_id}/disable")
async def disable_heuristic(heuristic_id: str, current_user: Dict = Depends(require_admin)):
    """Manually disable a heuristic.

    Requires: Admin role
    """
    try:
        loader = get_heuristic_loader()
        success = loader.disable_heuristic(heuristic_id)

        if not success:
            raise HTTPException(status_code=404, detail=f"Heuristic not found: {heuristic_id}")

        return {"success": True, "heuristic_id": heuristic_id, "is_active": False}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Disable heuristic error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heuristics/{heuristic_id}/enable")
async def enable_heuristic(heuristic_id: str, current_user: Dict = Depends(require_admin)):
    """Re-enable a disabled heuristic.

    Requires: Admin role
    """
    try:
        loader = get_heuristic_loader()
        success = loader.enable_heuristic(heuristic_id)

        if not success:
            raise HTTPException(status_code=404, detail=f"Heuristic not found: {heuristic_id}")

        return {"success": True, "heuristic_id": heuristic_id, "is_active": True}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Enable heuristic error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Tool Broker Endpoints
# =============================================================================

@router.post("/tools/check-access")
async def check_tool_access(
    request: ToolAccessCheckRequest,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Check if a tool can be accessed at given authority/confidence.

    Requires: Analyst or Admin role
    """
    try:
        broker = get_tool_broker()

        allowed, reason = broker.can_execute(
            tool_id=request.tool_id,
            current_authority=AuthorityLevel(request.authority_level.value),
            current_confidence=request.confidence
        )

        return {
            "tool_id": request.tool_id,
            "allowed": allowed,
            "reason": reason,
            "authority_level": request.authority_level.value,
            "confidence": request.confidence
        }

    except Exception as e:
        logger.error(f"[REASONING API] Tool access check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/available")
async def list_available_tools(
    authority_level: AuthorityLevelEnum = Query(AuthorityLevelEnum.OBSERVE),
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """List tools available at a given authority level.

    Requires: Analyst or Admin role
    """
    try:
        broker = get_tool_broker()
        tools = broker.get_available_tools(AuthorityLevel(authority_level.value))

        return {
            "authority_level": authority_level.value,
            "available_tools": tools,
            "count": len(tools)
        }

    except Exception as e:
        logger.error(f"[REASONING API] Available tools error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/execution-log")
async def get_tool_execution_log(
    investigation_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Get tool execution log.

    Requires: Analyst or Admin role
    """
    try:
        broker = get_tool_broker()
        log = broker.get_execution_log(investigation_id)

        return {
            "investigation_id": investigation_id,
            "entries": log[-limit:],
            "total": len(log)
        }

    except Exception as e:
        logger.error(f"[REASONING API] Execution log error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Checkpoint Endpoints
# =============================================================================

@router.get("/checkpoints/{investigation_id}")
async def get_checkpoint_progress(
    investigation_id: str,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Get checkpoint progress for an investigation.

    Requires: Analyst or Admin role
    """
    try:
        manager = get_checkpoint_manager()
        summary = manager.get_progress_summary(investigation_id)

        return summary

    except Exception as e:
        logger.error(f"[REASONING API] Checkpoint progress error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/checkpoints/{investigation_id}/force")
async def force_checkpoint(
    investigation_id: str,
    checkpoint: str = Query(..., description="Target checkpoint: triage, analysis, response, resolved"),
    current_user: Dict = Depends(require_admin)
):
    """Force an investigation to a specific checkpoint (admin override).

    Requires: Admin role (this is a dangerous operation)
    """
    try:
        manager = get_checkpoint_manager()

        try:
            target = Checkpoint(checkpoint)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid checkpoint: {checkpoint}")

        manager.force_checkpoint(investigation_id, target)

        return {
            "success": True,
            "investigation_id": investigation_id,
            "checkpoint": checkpoint,
            "warning": "This is an admin override - use with caution"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Force checkpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Confidence Gate Endpoints
# =============================================================================

@router.get("/confidence/{investigation_id}")
async def get_confidence_analysis(
    investigation_id: str,
    current_user: Dict = Depends(require_analyst_or_admin)
):
    """Get confidence analysis for an investigation.

    Requires: Analyst or Admin role
    """
    try:
        gate = get_confidence_gate()
        runner = get_investigation_runner()

        state = runner.get_state(investigation_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

        # Calculate gap to next threshold
        gap_analysis = gate.calculate_confidence_gap(
            state.confidence,
            state.current_checkpoint
        )

        # Check if stalled
        is_stalled, stall_reason = gate.is_stalled(investigation_id)

        # Get escalation decision
        severity = state.alert_data.get("severity", "medium")
        escalation = gate.should_escalate(
            state.confidence,
            severity,
            state.iteration_count
        )

        return {
            "investigation_id": investigation_id,
            "current_confidence": state.confidence,
            "confidence_history": state.confidence_history,
            "gap_analysis": gap_analysis,
            "is_stalled": is_stalled,
            "stall_reason": stall_reason,
            "escalation_needed": escalation.escalate,
            "escalation_reason": escalation.reason if escalation.escalate else None,
            "escalation_urgency": escalation.urgency if escalation.escalate else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[REASONING API] Confidence analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Health & Info Endpoints
# =============================================================================

@router.get("/health")
async def reasoning_engine_health():
    """Health check for the reasoning engine."""
    return {
        "status": "healthy",
        "engine": "unified_reasoning_engine",
        "version": "1.0.0",
        "doc_status": "FROZEN",
        "components": {
            "reasoning_engine": "ready",
            "tool_broker": "ready",
            "checkpoint_manager": "ready",
            "confidence_gate": "ready",
            "heuristic_loader": "ready",
            "sop_retriever": "ready"
        }
    }


@router.get("/info")
async def reasoning_engine_info():
    """Get information about the reasoning engine architecture."""
    return {
        "name": "Unified Reasoning Engine",
        "version": "1.0.0",
        "architecture": "judgment-preserving",
        "doctrine": "The reasoning engine is never responsible for enforcing policy, permissions, or safety. It only reasons. The system decides.",
        "invariants": [
            "ONE reasoning engine, ONE prompt",
            "Tiers = authority boundaries only, not agents",
            "Reasoning context persists across checkpoints",
            "SOPs never encoded as steps or rules",
            "Tool restrictions enforced by system, not prompt"
        ],
        "authority_levels": ["OBSERVE", "INVESTIGATE", "RESPOND", "PRE_APPROVED"],
        "checkpoints": ["triage", "analysis", "response", "resolved"],
        "heuristic_limits": {
            "target": 3,
            "max": 5,
            "auto_disable_threshold": "60% accuracy"
        }
    }


# =============================================================================
# Helper Functions
# =============================================================================

def _group_by_category(stats: List[Dict]) -> Dict[str, Any]:
    """Group heuristic stats by category."""
    by_category = {}
    for s in stats:
        cat = s["category"]
        if cat not in by_category:
            by_category[cat] = {"count": 0, "active": 0, "total_uses": 0}
        by_category[cat]["count"] += 1
        if s["is_active"]:
            by_category[cat]["active"] += 1
        by_category[cat]["total_uses"] += s["total_uses"]
    return by_category
