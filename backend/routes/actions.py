# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Execution API Routes

Endpoints for:
- Executing API actions (sync and async)
- Checking job status
- Managing rate limits
- Viewing execution stats and history
"""

from fastapi import APIRouter, HTTPException, Header, BackgroundTasks, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from services.action_engine import (
    get_execution_engine,
    init_execution_engine,
    ActionRequest,
    ActionResult,
    HttpMethod,
    JobStatus
)
from services.credentials_service import get_credentials_service
from dependencies.auth import get_current_user

router = APIRouter(prefix="/api/v1/actions", tags=["actions"], dependencies=[Depends(get_current_user)])


# Request/Response models for API

class ExecuteRequest(BaseModel):
    """Request to execute an API action"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    
    # Authentication
    credential_id: Optional[str] = None
    
    # Options
    timeout_seconds: int = 30
    retry_count: int = 3
    
    # For async execution
    callback_url: Optional[str] = None
    
    # Metadata for tracking
    integration_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExecuteResponse(BaseModel):
    """Response from action execution"""
    action_id: str
    status: str
    status_code: Optional[int] = None
    response_body: Optional[Any] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    token_refreshed: bool = False


class AsyncExecuteResponse(BaseModel):
    """Response when queueing async action"""
    action_id: str
    status: str = "pending"
    message: str = "Action queued for execution"


class JobStatusResponse(BaseModel):
    """Job status response"""
    action_id: str
    status: str
    status_code: Optional[int] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    attempt_number: int
    total_attempts: int
    error: Optional[str] = None
    token_refreshed: bool = False


class RateLimitConfig(BaseModel):
    """Rate limit configuration"""
    integration_id: str
    calls_per_minute: int


class EngineStats(BaseModel):
    """Engine statistics"""
    total_executed: int
    successful: int
    failed: int
    retries: int
    tokens_refreshed: int
    pending_jobs: int
    tracked_jobs: int


# Startup event to initialize engine
_engine_initialized = False

async def ensure_engine_initialized():
    """Ensure the execution engine is initialized"""
    global _engine_initialized
    if not _engine_initialized:
        credentials_service = get_credentials_service()
        await init_execution_engine(credentials_service, num_workers=5)
        _engine_initialized = True


# Routes

@router.post("/execute", response_model=ExecuteResponse)
async def execute_action(
    request: ExecuteRequest,
    authorization: str = Header(None)
):
    """
    Execute an API action synchronously.
    
    Waits for the action to complete and returns the result.
    Supports automatic token refresh for bearer credentials.
    """
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    # Convert to ActionRequest
    action_request = ActionRequest(
        url=request.url,
        method=HttpMethod(request.method.upper()),
        headers=request.headers,
        query_params=request.query_params,
        body=request.body,
        credential_id=request.credential_id,
        timeout_seconds=request.timeout_seconds,
        retry_count=request.retry_count,
        integration_id=request.integration_id,
        metadata=request.metadata
    )
    
    # Execute
    result = await engine.execute(action_request)
    
    return ExecuteResponse(
        action_id=result.action_id,
        status=result.status.value,
        status_code=result.status_code,
        response_body=result.response_body,
        duration_ms=result.duration_ms,
        error=result.error,
        token_refreshed=result.token_refreshed
    )


@router.post("/execute/async", response_model=AsyncExecuteResponse)
async def execute_action_async(
    request: ExecuteRequest,
    authorization: str = Header(None)
):
    """
    Queue an API action for asynchronous execution.
    
    Returns immediately with an action_id for tracking.
    Optionally calls a webhook when complete.
    """
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    # Convert to ActionRequest
    action_request = ActionRequest(
        url=request.url,
        method=HttpMethod(request.method.upper()),
        headers=request.headers,
        query_params=request.query_params,
        body=request.body,
        credential_id=request.credential_id,
        timeout_seconds=request.timeout_seconds,
        retry_count=request.retry_count,
        callback_url=request.callback_url,
        integration_id=request.integration_id,
        metadata=request.metadata
    )
    
    # Queue for execution
    action_id = await engine.execute_async(action_request)
    
    return AsyncExecuteResponse(
        action_id=action_id,
        status="pending",
        message="Action queued for execution"
    )


@router.get("/jobs/{action_id}", response_model=JobStatusResponse)
async def get_job_status(
    action_id: str,
    authorization: str = Header(None)
):
    """Get the status of an action/job"""
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    result = engine.get_job_status(action_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Job {action_id} not found")
    
    return JobStatusResponse(
        action_id=result.action_id,
        status=result.status.value,
        status_code=result.status_code,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_ms=result.duration_ms,
        attempt_number=result.attempt_number,
        total_attempts=result.total_attempts,
        error=result.error,
        token_refreshed=result.token_refreshed
    )


@router.get("/jobs", response_model=List[JobStatusResponse])
async def list_jobs(
    status: Optional[str] = None,
    integration_id: Optional[str] = None,
    limit: int = 50,
    authorization: str = Header(None)
):
    """List recent jobs with optional filters"""
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    jobs = list(engine._jobs.values())
    
    # Filter by status
    if status:
        jobs = [j for j in jobs if j.status.value == status]
    
    # Filter by integration
    if integration_id:
        jobs = [j for j in jobs if j.integration_id == integration_id]
    
    # Sort by started_at descending and limit
    jobs = sorted(jobs, key=lambda j: j.started_at, reverse=True)[:limit]
    
    return [
        JobStatusResponse(
            action_id=j.action_id,
            status=j.status.value,
            status_code=j.status_code,
            started_at=j.started_at,
            completed_at=j.completed_at,
            duration_ms=j.duration_ms,
            attempt_number=j.attempt_number,
            total_attempts=j.total_attempts,
            error=j.error,
            token_refreshed=j.token_refreshed
        )
        for j in jobs
    ]


@router.post("/rate-limits")
async def set_rate_limit(
    config: RateLimitConfig,
    authorization: str = Header(None)
):
    """Set rate limit for an integration"""
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    engine.set_rate_limit(config.integration_id, config.calls_per_minute)
    
    return {
        "success": True,
        "integration_id": config.integration_id,
        "calls_per_minute": config.calls_per_minute
    }


@router.get("/rate-limits/{integration_id}")
async def get_rate_limit(
    integration_id: str,
    authorization: str = Header(None)
):
    """Get rate limit for an integration"""
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    limit = engine.rate_limiter.get_limit(integration_id)
    wait_time = engine.rate_limiter.get_wait_time(integration_id)
    
    return {
        "integration_id": integration_id,
        "calls_per_minute": limit,
        "current_wait_seconds": wait_time
    }


@router.get("/stats", response_model=EngineStats)
async def get_engine_stats(authorization: str = Header(None)):
    """Get execution engine statistics"""
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    stats = engine.get_stats()
    return EngineStats(**stats)


# Convenience endpoints for common patterns

@router.post("/test-credential/{credential_id}")
async def test_credential_with_url(
    credential_id: str,
    test_url: str,
    authorization: str = Header(None)
):
    """
    Test a credential by making a GET request to the specified URL.
    
    Useful for verifying credentials work before using them.
    """
    await ensure_engine_initialized()
    engine = get_execution_engine()
    
    result = await engine.get(
        url=test_url,
        credential_id=credential_id,
        retry_count=1,
        timeout_seconds=15
    )
    
    return {
        "success": result.status == JobStatus.SUCCESS,
        "status_code": result.status_code,
        "duration_ms": result.duration_ms,
        "error": result.error,
        "token_refreshed": result.token_refreshed
    }


@router.post("/enrichment/{observable_type}")
async def enrich_observable(
    observable_type: str,
    observable_value: str,
    credential_id: str,
    provider_url: str,
    authorization: str = Header(None)
):
    """
    Enrich an observable (IP, hash, domain, etc.) using an external API.

    This is a convenience endpoint for threat intel lookups.
    """
    await ensure_engine_initialized()
    engine = get_execution_engine()

    # Build URL with observable value
    url = provider_url.replace("{value}", observable_value)
    url = url.replace("{type}", observable_type)

    result = await engine.get(
        url=url,
        credential_id=credential_id,
        integration_id=f"enrichment_{observable_type}",
        metadata={
            "observable_type": observable_type,
            "observable_value": observable_value
        }
    )

    return {
        "observable_type": observable_type,
        "observable_value": observable_value,
        "success": result.status == JobStatus.SUCCESS,
        "data": result.response_body if result.status == JobStatus.SUCCESS else None,
        "error": result.error,
        "duration_ms": result.duration_ms
    }


# ============================================================================
# ACTION REQUEST / APPROVAL QUEUE ENDPOINTS (Phase 5.1)
# ============================================================================
# These endpoints manage action requests from AI agents that require human approval

class ApprovalRequestBody(BaseModel):
    """Request to approve an action"""
    approved_by: str
    execute_immediately: bool = True


class DenialRequestBody(BaseModel):
    """Request to deny an action"""
    denied_by: str
    denial_reason: str


class RollbackRequestBody(BaseModel):
    """Request to rollback an action"""
    rolled_back_by: str


class ManualActionRequestBody(BaseModel):
    """Request to create a manual action"""
    action_type: str
    target_value: str
    reasoning: str
    priority: str = 'medium'
    target_metadata: Optional[Dict[str, Any]] = None
    investigation_id: Optional[str] = None
    alert_id: Optional[str] = None


@router.get("/requests/queue")
async def get_approval_queue(
    priority: Optional[str] = None,
    limit: int = 50
):
    """
    Get pending action requests for the approval queue.
    Returns requests sorted by priority and creation time.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        requests = await service.get_pending_requests(priority=priority, limit=limit)

        return {
            "success": True,
            "count": len(requests),
            "requests": requests
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/history")
async def get_action_history(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    action_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get all action requests with optional filters (for history view).
    Unlike /queue which only returns pending, this returns all statuses.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        requests = await service.get_all_requests(
            status=status,
            priority=priority,
            action_type=action_type,
            limit=limit,
            offset=offset
        )

        return {
            "success": True,
            "count": len(requests),
            "requests": requests
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/stats")
async def get_action_request_stats():
    """Get action request statistics for the dashboard."""
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        stats = await service.get_action_stats()

        return {
            "success": True,
            "stats": stats
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/types")
async def get_action_types(
    enabled_only: bool = True
):
    """Get available action types."""
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        action_types = await service.get_action_types(enabled_only=enabled_only)

        return {
            "success": True,
            "count": len(action_types),
            "action_types": action_types
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/{request_id}")
async def get_action_request(request_id: str):
    """Get a single action request by ID."""
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        request = await service.get_request_by_id(request_id)

        if not request:
            raise HTTPException(status_code=404, detail=f"Action request {request_id} not found")

        return {
            "success": True,
            "request": request
        }
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/investigation/{investigation_id}")
async def get_investigation_action_requests(investigation_id: str):
    """Get all action requests for an investigation."""
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        requests = await service.get_requests_for_investigation(investigation_id)

        return {
            "success": True,
            "count": len(requests),
            "requests": requests
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/approve")
async def approve_action_request(request_id: str, body: ApprovalRequestBody):
    """
    Approve an action request.
    If execute_immediately is True (default), the action will be executed right away.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        result = await service.approve_action(
            request_id=request_id,
            approved_by=body.approved_by,
            execute_immediately=body.execute_immediately
        )

        if not result['success']:
            raise HTTPException(status_code=400, detail=result.get('error', 'Approval failed'))

        return result
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/deny")
async def deny_action_request(request_id: str, body: DenialRequestBody):
    """Deny an action request with a reason."""
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        result = await service.deny_action(
            request_id=request_id,
            denied_by=body.denied_by,
            denial_reason=body.denial_reason
        )

        if not result['success']:
            raise HTTPException(status_code=400, detail=result.get('error', 'Denial failed'))

        return result
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/execute")
async def execute_action_request(request_id: str):
    """
    Execute an approved action request.
    Only works for requests in 'approved' status that haven't been executed yet.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        result = await service.execute_action(request_id)

        if not result['success']:
            raise HTTPException(status_code=400, detail=result.get('error', 'Execution failed'))

        return result
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/rollback")
async def rollback_action_request(request_id: str, body: RollbackRequestBody):
    """
    Rollback a completed action.
    Creates a new action request for the reverse action.
    Only works for reversible actions that have been completed.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        result = await service.rollback_action(
            request_id=request_id,
            rolled_back_by=body.rolled_back_by
        )

        if not result['success']:
            raise HTTPException(status_code=400, detail=result.get('error', 'Rollback failed'))

        return result
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/create")
async def create_manual_action_request(body: ManualActionRequestBody, current_user: dict = Depends(get_current_user)):
    """
    Create a manual action request (not from an agent).
    Useful for SOC analysts who want to queue an action for approval.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()

        # Determine target_type from action_type
        action_type_to_target = {
            'contain_host': 'host',
            'un-contain_host': 'host',
            'block_ip': 'ip',
            'unblock_ip': 'ip',
            'block_domain': 'domain',
            'unblock_domain': 'domain',
            'block_hash': 'hash',
            'unblock_hash': 'hash',
            'disable_user': 'user',
            'enable_user': 'user',
            'reset_password': 'user',
            'revoke_sessions': 'user',
            'collect_forensics': 'host',
            'run_scan': 'host'
        }
        target_type = action_type_to_target.get(body.action_type, 'unknown')

        result = await service.create_action_request(
            action_type=body.action_type,
            target_type=target_type,
            target_value=body.target_value,
            reasoning=body.reasoning,
            confidence=1.0,  # Manual requests are high confidence
            investigation_id=body.investigation_id,
            alert_id=body.alert_id,
            requested_by_human=current_user.get("username", "manual"),
            target_metadata=body.target_metadata,
            priority=body.priority
        )

        if not result['success']:
            raise HTTPException(status_code=400, detail=result.get('error', 'Creation failed'))

        return result
    except HTTPException:
        raise
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/expire-old")
async def expire_old_action_requests():
    """
    Expire old pending requests that have passed their expiration time.
    This is typically called by a scheduled job but can be triggered manually.
    """
    from services.action_request_service import get_action_request_service

    try:
        service = get_action_request_service()
        count = await service.expire_old_requests()

        return {
            "success": True,
            "expired_count": count,
            "message": f"Expired {count} pending action requests"
        }
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Action request service not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
