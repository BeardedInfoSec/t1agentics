# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent Capabilities API Routes (Phase 11)
========================================

Provides API endpoints for agent tool capabilities:
- Tool discovery for AI agents
- Tool execution with approval workflow
- Execution history and statistics
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

from dependencies.auth import get_current_user
from services.agent_capability_service import (
    get_agent_capability_service,
    AgentPermissionLevel,
    ToolExecutionStatus
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/agent-capabilities", tags=["Agent Capabilities"])

# Initialize the service
_capability_service = get_agent_capability_service()


# ============================================================================
# Pydantic Models
# ============================================================================

class ToolExecutionRequest(BaseModel):
    """Request to execute a tool"""
    tool_id: str = Field(..., description="Tool ID in format: integration_id.capability_id")
    parameters: Dict[str, Any] = Field(default={}, description="Tool parameters")
    investigation_id: Optional[str] = None


class ApprovalDecision(BaseModel):
    """Decision on a pending approval"""
    approved: bool
    reason: Optional[str] = None


class AgentContextRequest(BaseModel):
    """Request to create an agent context"""
    permission_level: str = "investigate"
    investigation_id: Optional[str] = None


# ============================================================================
# Tool Discovery Endpoints
# ============================================================================

@router.get("/tools")
async def get_available_tools(
    permission_level: str = Query("investigate", description="Permission level: observe, investigate, respond, admin"),
    category: Optional[str] = Query(None, description="Filter by category"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get all tools available for a permission level.

    Used by AI agents to discover what tools they can use.
    """
    try:
        perm = AgentPermissionLevel(permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {permission_level}")

    tools = _capability_service.get_available_tools(perm)

    if category:
        tools = [t for t in tools if t["category"] == category.lower()]

    return {
        "permission_level": permission_level,
        "total": len(tools),
        "tools": tools
    }


@router.get("/tools/documentation")
async def get_tool_documentation(
    permission_level: str = Query("investigate", description="Permission level"),
    max_tokens: int = Query(2000, description="Maximum tokens for documentation"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get formatted tool documentation for AI context injection.

    Returns a structured text block suitable for including in AI prompts.
    """
    try:
        perm = AgentPermissionLevel(permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {permission_level}")

    doc = _capability_service.get_tool_documentation(perm, max_tokens)
    return {
        "permission_level": permission_level,
        "documentation": doc,
        "char_count": len(doc)
    }


@router.get("/tools/search")
async def search_tools(
    task: str = Query(..., description="Task description to find tools for"),
    permission_level: str = Query("investigate", description="Permission level"),
    current_user: dict = Depends(get_current_user)
):
    """
    Find tools relevant to a specific task.

    AI agents can use this to find the right tool for a job.
    """
    try:
        perm = AgentPermissionLevel(permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {permission_level}")

    tools = _capability_service.find_tools_for_task(task, perm)
    return {
        "task": task,
        "total": len(tools),
        "recommended_tools": tools
    }


# ============================================================================
# Tool Execution Endpoints
# ============================================================================

@router.post("/execute")
async def execute_tool(
    request: ToolExecutionRequest,
    permission_level: str = Query("investigate", description="Permission level"),
    current_user: dict = Depends(get_current_user)
):
    """
    Execute a tool.

    If the tool requires approval, returns a pending status.
    Otherwise, executes immediately and returns the result.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    try:
        perm = AgentPermissionLevel(permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {permission_level}")

    try:
        agent_id = f"user:{current_user.get('username')}"
        execution = await _capability_service.request_tool_execution(
            agent_id=agent_id,
            tool_id=request.tool_id,
            parameters=request.parameters,
            investigation_id=request.investigation_id,
            permission_level=perm
        )

        return {
            "execution_id": execution.id,
            "tool_id": execution.tool_id,
            "status": execution.status.value,
            "requires_approval": execution.requires_approval,
            "result": execution.result,
            "error": execution.error,
            "execution_time_ms": execution.execution_time_ms
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute/batch")
async def execute_tools_batch(
    tools: List[ToolExecutionRequest],
    permission_level: str = Query("investigate", description="Permission level"),
    current_user: dict = Depends(get_current_user)
):
    """
    Execute multiple tools in sequence.

    Returns results for all tools, including any that require approval.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    try:
        perm = AgentPermissionLevel(permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {permission_level}")

    results = []
    agent_id = f"user:{current_user.get('username')}"

    for tool_request in tools:
        try:
            execution = await _capability_service.request_tool_execution(
                agent_id=agent_id,
                tool_id=tool_request.tool_id,
                parameters=tool_request.parameters,
                investigation_id=tool_request.investigation_id,
                permission_level=perm
            )
            results.append({
                "tool_id": tool_request.tool_id,
                "execution_id": execution.id,
                "status": execution.status.value,
                "result": execution.result,
                "error": execution.error
            })
        except Exception as e:
            results.append({
                "tool_id": tool_request.tool_id,
                "execution_id": None,
                "status": "failed",
                "result": None,
                "error": str(e)
            })

    return {
        "total": len(results),
        "succeeded": sum(1 for r in results if r["status"] == "completed"),
        "results": results
    }


# ============================================================================
# Approval Workflow Endpoints
# ============================================================================

@router.get("/approvals/pending")
async def get_pending_approvals(
    current_user: dict = Depends(get_current_user)
):
    """Get all tool executions pending approval"""
    pending = _capability_service.get_pending_approvals()
    return {
        "total": len(pending),
        "pending": pending
    }


@router.post("/approvals/{request_id}")
async def approve_or_reject(
    request_id: str,
    decision: ApprovalDecision,
    current_user: dict = Depends(get_current_user)
):
    """Approve or reject a pending tool execution"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required for approvals")

    try:
        if decision.approved:
            execution = await _capability_service.approve_execution(
                request_id=request_id,
                approved_by=current_user.get("username")
            )
        else:
            execution = await _capability_service.reject_execution(
                request_id=request_id,
                rejected_by=current_user.get("username"),
                reason=decision.reason
            )

        return {
            "execution_id": execution.id,
            "status": execution.status.value,
            "approved_by": execution.approved_by,
            "result": execution.result,
            "error": execution.error
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# Agent Context Endpoints
# ============================================================================

@router.post("/context")
async def create_agent_context(
    request: AgentContextRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a tool context for an agent session.

    Returns available tools for the permission level.
    """
    try:
        perm = AgentPermissionLevel(request.permission_level.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid permission level: {request.permission_level}")

    agent_id = f"user:{current_user.get('username')}"
    context = _capability_service.create_agent_context(
        agent_id=agent_id,
        permission_level=perm,
        investigation_id=request.investigation_id
    )

    tools = _capability_service.get_available_tools(perm)

    return {
        "agent_id": agent_id,
        "permission_level": perm.value,
        "investigation_id": request.investigation_id,
        "session_start": context.session_start.isoformat(),
        "available_tools_count": len(tools),
        "available_tools": [t["tool_id"] for t in tools]
    }


@router.delete("/context")
async def end_agent_context(
    current_user: dict = Depends(get_current_user)
):
    """
    End an agent's tool context session.

    Returns summary of tool usage during the session.
    """
    agent_id = f"user:{current_user.get('username')}"
    summary = _capability_service.end_agent_context(agent_id)

    if not summary:
        return {"message": "No active context found"}

    return summary


# ============================================================================
# History & Statistics Endpoints
# ============================================================================

@router.get("/history")
async def get_execution_history(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum results"),
    current_user: dict = Depends(get_current_user)
):
    """Get tool execution history"""
    status_filter = None
    if status:
        try:
            status_filter = ToolExecutionStatus(status.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    # Users can see all history, or filter to their own
    agent_id = None  # Admin sees all
    if current_user.get("role") != "admin":
        agent_id = f"user:{current_user.get('username')}"

    history = _capability_service.get_execution_history(
        agent_id=agent_id,
        investigation_id=investigation_id,
        status=status_filter,
        limit=limit
    )

    return {
        "total": len(history),
        "executions": history
    }


@router.get("/stats")
async def get_execution_stats(
    hours: int = Query(24, description="Time period in hours"),
    current_user: dict = Depends(get_current_user)
):
    """Get tool execution statistics"""
    agent_id = None  # Admin sees all stats
    if current_user.get("role") != "admin":
        agent_id = f"user:{current_user.get('username')}"

    stats = _capability_service.get_execution_stats(agent_id=agent_id, hours=hours)
    return stats


# ============================================================================
# Permission Reference
# ============================================================================

@router.get("/permissions")
async def get_permission_levels():
    """Get available permission levels and their allowed categories"""
    return {
        "levels": [
            {
                "level": "observe",
                "description": "Read-only access to query tools",
                "allowed_categories": ["query"]
            },
            {
                "level": "investigate",
                "description": "Query and enrich capabilities",
                "allowed_categories": ["query", "enrich"]
            },
            {
                "level": "respond",
                "description": "Full investigation and response capabilities",
                "allowed_categories": ["query", "enrich", "action", "notify", "ticket"]
            },
            {
                "level": "admin",
                "description": "All capabilities including admin functions",
                "allowed_categories": ["query", "enrich", "action", "notify", "ticket", "ingest", "export"]
            }
        ]
    }
