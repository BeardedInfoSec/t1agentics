# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Audit Log API Routes

API endpoints for querying the immutable audit log.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..rbac import (
    RequestContext, get_request_context,
    PermissionChecker
)
from ..database import AuditCategory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit"])


# Response Models
class AuditEventResponse(BaseModel):
    id: UUID
    event_time: str
    actor_type: str
    actor_id: Optional[UUID]
    actor_display: Optional[str]
    actor_ip: Optional[str]
    action: str
    category: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[UUID]
    resource_display: Optional[str]
    summary: Optional[str]
    outcome: str
    correlation_id: Optional[UUID]


class AuditEventDetailResponse(AuditEventResponse):
    before_state: Optional[dict]
    after_state: Optional[dict]
    metadata: Optional[dict]
    actor_user_agent: Optional[str]


class AuditSearchResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[AuditEventResponse]


# Routes
@router.get(
    "",
    response_model=AuditSearchResponse,
    summary="Search audit logs",
    description="Search and filter audit events."
)
async def search_audit_logs(
    # Time filters
    start_time: Optional[datetime] = Query(None, description="Start of time range"),
    end_time: Optional[datetime] = Query(None, description="End of time range"),
    time_range: Optional[str] = Query(None, description="Preset time range: 1h, 24h, 7d, 30d"),
    # Filters
    action: Optional[str] = Query(None, description="Filter by action"),
    category: Optional[str] = Query(None, description="Filter by category"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[UUID] = Query(None, description="Filter by resource ID"),
    actor_id: Optional[UUID] = Query(None, description="Filter by actor ID"),
    correlation_id: Optional[UUID] = Query(None, description="Filter by correlation ID"),
    outcome: Optional[str] = Query(None, description="Filter by outcome"),
    # Search
    search: Optional[str] = Query(None, description="Search in summary"),
    # Pagination
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    ctx: RequestContext = Depends(PermissionChecker(['audit:read'])),
):
    """
    Search audit events with various filters.
    
    Results are ordered by event_time descending (newest first).
    """
    from sqlalchemy import select, and_, or_, func
    from sqlalchemy.ext.asyncio import AsyncSession
    from ..database import AuditEvent, get_async_session
    
    # Handle preset time ranges
    if time_range:
        end_time = datetime.utcnow()
        if time_range == '1h':
            start_time = end_time - timedelta(hours=1)
        elif time_range == '24h':
            start_time = end_time - timedelta(hours=24)
        elif time_range == '7d':
            start_time = end_time - timedelta(days=7)
        elif time_range == '30d':
            start_time = end_time - timedelta(days=30)
    
    async with get_async_session() as db:
        # Build query
        conditions = [AuditEvent.tenant_id == ctx.tenant.tenant_id]
        
        if start_time:
            conditions.append(AuditEvent.event_time >= start_time)
        if end_time:
            conditions.append(AuditEvent.event_time <= end_time)
        if action:
            conditions.append(AuditEvent.action == action)
        if category:
            conditions.append(AuditEvent.category == category)
        if resource_type:
            conditions.append(AuditEvent.resource_type == resource_type)
        if resource_id:
            conditions.append(AuditEvent.resource_id == resource_id)
        if actor_id:
            conditions.append(AuditEvent.actor_id == actor_id)
        if correlation_id:
            conditions.append(AuditEvent.correlation_id == correlation_id)
        if outcome:
            conditions.append(AuditEvent.outcome == outcome)
        if search:
            conditions.append(AuditEvent.summary.ilike(f'%{search}%'))
        
        # Count total
        count_query = select(func.count(AuditEvent.id)).where(and_(*conditions))
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0
        
        # Fetch page
        query = (
            select(AuditEvent)
            .where(and_(*conditions))
            .order_by(AuditEvent.event_time.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await db.execute(query)
        events = result.scalars().all()
        
        return AuditSearchResponse(
            total=total,
            page=page,
            page_size=page_size,
            results=[
                AuditEventResponse(
                    id=e.id,
                    event_time=e.event_time.isoformat(),
                    actor_type=e.actor_type,
                    actor_id=e.actor_id,
                    actor_display=e.actor_display,
                    actor_ip=str(e.actor_ip) if e.actor_ip else None,
                    action=e.action,
                    category=e.category,
                    resource_type=e.resource_type,
                    resource_id=e.resource_id,
                    resource_display=e.resource_display,
                    summary=e.summary,
                    outcome=e.outcome,
                    correlation_id=e.correlation_id,
                )
                for e in events
            ]
        )


@router.get(
    "/{event_id}",
    response_model=AuditEventDetailResponse,
    summary="Get audit event details",
    description="Get full details of a specific audit event."
)
async def get_audit_event(
    event_id: UUID,
    ctx: RequestContext = Depends(PermissionChecker(['audit:read'])),
):
    """Get detailed audit event by ID."""
    from sqlalchemy import select, and_
    from ..database import AuditEvent, get_async_session
    
    async with get_async_session() as db:
        result = await db.execute(
            select(AuditEvent).where(
                and_(
                    AuditEvent.tenant_id == ctx.tenant.tenant_id,
                    AuditEvent.id == event_id,
                )
            )
        )
        event = result.scalar_one_or_none()
        
        if not event:
            raise HTTPException(status_code=404, detail="Audit event not found")
        
        return AuditEventDetailResponse(
            id=event.id,
            event_time=event.event_time.isoformat(),
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            actor_display=event.actor_display,
            actor_ip=str(event.actor_ip) if event.actor_ip else None,
            actor_user_agent=event.actor_user_agent,
            action=event.action,
            category=event.category,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            resource_display=event.resource_display,
            summary=event.summary,
            before_state=event.before_state,
            after_state=event.after_state,
            metadata=event.metadata,
            outcome=event.outcome,
            correlation_id=event.correlation_id,
        )


@router.get(
    "/resource/{resource_type}/{resource_id}",
    response_model=List[AuditEventResponse],
    summary="Get audit trail for resource",
    description="Get all audit events for a specific resource."
)
async def get_resource_audit_trail(
    resource_type: str,
    resource_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    ctx: RequestContext = Depends(PermissionChecker(['audit:read'])),
):
    """Get complete audit trail for a resource."""
    from sqlalchemy import select, and_
    from ..database import AuditEvent, get_async_session
    
    async with get_async_session() as db:
        result = await db.execute(
            select(AuditEvent)
            .where(
                and_(
                    AuditEvent.tenant_id == ctx.tenant.tenant_id,
                    AuditEvent.resource_type == resource_type,
                    AuditEvent.resource_id == resource_id,
                )
            )
            .order_by(AuditEvent.event_time.desc())
            .limit(limit)
        )
        events = result.scalars().all()
        
        return [
            AuditEventResponse(
                id=e.id,
                event_time=e.event_time.isoformat(),
                actor_type=e.actor_type,
                actor_id=e.actor_id,
                actor_display=e.actor_display,
                actor_ip=str(e.actor_ip) if e.actor_ip else None,
                action=e.action,
                category=e.category,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                resource_display=e.resource_display,
                summary=e.summary,
                outcome=e.outcome,
                correlation_id=e.correlation_id,
            )
            for e in events
        ]


@router.get(
    "/categories",
    response_model=List[str],
    summary="Get audit categories",
    description="Get list of available audit event categories."
)
async def get_audit_categories(
    ctx: RequestContext = Depends(PermissionChecker(['audit:read'])),
):
    """Get list of audit event categories."""
    return [
        v for k, v in AuditCategory.__dict__.items()
        if isinstance(v, str) and not k.startswith('_')
    ]


@router.get(
    "/actions",
    response_model=List[str],
    summary="Get audit actions",
    description="Get list of unique actions in the audit log."
)
async def get_audit_actions(
    category: Optional[str] = Query(None, description="Filter by category"),
    ctx: RequestContext = Depends(PermissionChecker(['audit:read'])),
):
    """Get list of unique actions in the audit log."""
    from sqlalchemy import select, distinct, and_
    from ..database import AuditEvent, get_async_session
    
    async with get_async_session() as db:
        conditions = [AuditEvent.tenant_id == ctx.tenant.tenant_id]
        if category:
            conditions.append(AuditEvent.category == category)
        
        result = await db.execute(
            select(distinct(AuditEvent.action))
            .where(and_(*conditions))
            .order_by(AuditEvent.action)
        )
        return [row[0] for row in result.all()]
