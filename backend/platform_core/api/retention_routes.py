# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Retention Settings API Routes

API endpoints for managing data retention policies.
"""

from typing import List, Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from ..rbac import (
    RequestContext, get_request_context,
    PermissionChecker
)
from ..database import DataClass, MINIMUM_RETENTION_DAYS, DEFAULT_RETENTION_DAYS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings/retention", tags=["Retention"])


# Request/Response Models
class RetentionPolicyResponse(BaseModel):
    data_class: str
    retention_days: int
    grace_days: int
    is_enabled: bool
    minimum_days: int
    last_run_at: Optional[str]
    last_run_deleted_count: Optional[int]


class RetentionPolicyUpdate(BaseModel):
    retention_days: int = Field(..., ge=1, description="Retention period in days")
    grace_days: int = Field(default=7, ge=0, description="Grace period before hard delete")
    is_enabled: bool = Field(default=True, description="Whether retention is enabled")


class RetentionJobResult(BaseModel):
    tenant_id: str
    results: dict
    total_deleted: int


# Routes
@router.get(
    "",
    response_model=List[RetentionPolicyResponse],
    summary="Get retention policies",
    description="Get all retention policies for the current tenant."
)
async def get_retention_policies(
    ctx: RequestContext = Depends(PermissionChecker(['retention:read'])),
):
    """Get all retention policies for the tenant."""
    from ..retention import RetentionService
    from ..database import get_async_session
    
    async with get_async_session() as db:
        service = RetentionService(db, ctx)
        policies = await service.get_policies(ctx.tenant.tenant_id)
        
        # Include all data classes, even if no policy exists
        result = []
        for data_class in DataClass.__dict__.values():
            if isinstance(data_class, str) and not data_class.startswith('_'):
                policy = policies.get(data_class)
                result.append(RetentionPolicyResponse(
                    data_class=data_class,
                    retention_days=policy.retention_days if policy else DEFAULT_RETENTION_DAYS.get(data_class, 90),
                    grace_days=policy.grace_days if policy else 7,
                    is_enabled=policy.is_enabled if policy else True,
                    minimum_days=MINIMUM_RETENTION_DAYS.get(data_class, 30),
                    last_run_at=policy.last_run_at.isoformat() if policy and policy.last_run_at else None,
                    last_run_deleted_count=policy.last_run_deleted_count if policy else None,
                ))
        
        return result


@router.get(
    "/{data_class}",
    response_model=RetentionPolicyResponse,
    summary="Get retention policy",
    description="Get retention policy for a specific data class."
)
async def get_retention_policy(
    data_class: str,
    ctx: RequestContext = Depends(PermissionChecker(['retention:read'])),
):
    """Get retention policy for a specific data class."""
    from ..retention import RetentionService
    from ..database import get_async_session
    
    # Validate data class
    valid_classes = [v for v in DataClass.__dict__.values() if isinstance(v, str) and not v.startswith('_')]
    if data_class not in valid_classes:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid data_class. Must be one of: {valid_classes}"
        )
    
    async with get_async_session() as db:
        service = RetentionService(db, ctx)
        policy = await service.get_policy(ctx.tenant.tenant_id, data_class)
        
        return RetentionPolicyResponse(
            data_class=data_class,
            retention_days=policy.retention_days if policy else DEFAULT_RETENTION_DAYS.get(data_class, 90),
            grace_days=policy.grace_days if policy else 7,
            is_enabled=policy.is_enabled if policy else True,
            minimum_days=MINIMUM_RETENTION_DAYS.get(data_class, 30),
            last_run_at=policy.last_run_at.isoformat() if policy and policy.last_run_at else None,
            last_run_deleted_count=policy.last_run_deleted_count if policy else None,
        )


@router.put(
    "/{data_class}",
    response_model=RetentionPolicyResponse,
    summary="Update retention policy",
    description="Update retention policy for a specific data class."
)
async def update_retention_policy(
    data_class: str,
    request: RetentionPolicyUpdate,
    ctx: RequestContext = Depends(PermissionChecker(['retention:update'])),
):
    """
    Update retention policy for a data class.
    
    Minimum retention days are enforced per data class.
    """
    from ..retention import RetentionService
    from ..database import get_async_session
    
    # Validate data class
    valid_classes = [v for v in DataClass.__dict__.values() if isinstance(v, str) and not v.startswith('_')]
    if data_class not in valid_classes:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid data_class. Must be one of: {valid_classes}"
        )
    
    # Check minimum
    minimum = MINIMUM_RETENTION_DAYS.get(data_class, 30)
    if request.retention_days < minimum:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum retention for {data_class} is {minimum} days"
        )
    
    async with get_async_session() as db:
        service = RetentionService(db, ctx)
        
        try:
            policy = await service.update_policy(
                tenant_id=ctx.tenant.tenant_id,
                data_class=data_class,
                retention_days=request.retention_days,
                grace_days=request.grace_days,
                is_enabled=request.is_enabled,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        return RetentionPolicyResponse(
            data_class=data_class,
            retention_days=policy.retention_days,
            grace_days=policy.grace_days,
            is_enabled=policy.is_enabled,
            minimum_days=minimum,
            last_run_at=policy.last_run_at.isoformat() if policy.last_run_at else None,
            last_run_deleted_count=policy.last_run_deleted_count,
        )


@router.post(
    "/run",
    response_model=RetentionJobResult,
    summary="Run retention job",
    description="Manually trigger retention cleanup job (admin only)."
)
async def run_retention_job(
    background: bool = False,
    ctx: RequestContext = Depends(PermissionChecker(['job:run'])),
    background_tasks: BackgroundTasks = None,
):
    """
    Manually trigger retention cleanup.
    
    If background=True, the job runs asynchronously.
    Requires admin/system permissions.
    """
    from ..retention import RetentionService
    from ..database import get_async_session
    
    if background and background_tasks:
        # Run in background
        async def run_job():
            async with get_async_session() as db:
                service = RetentionService(db, ctx)
                await service.run_retention_job(ctx.tenant.tenant_id)
        
        background_tasks.add_task(run_job)
        return RetentionJobResult(
            tenant_id=str(ctx.tenant.tenant_id),
            results={},
            total_deleted=0,
        )
    else:
        # Run synchronously
        async with get_async_session() as db:
            service = RetentionService(db, ctx)
            results = await service.run_retention_job(ctx.tenant.tenant_id)
            
            return RetentionJobResult(
                tenant_id=str(ctx.tenant.tenant_id),
                results=results,
                total_deleted=sum(results.values()),
            )
