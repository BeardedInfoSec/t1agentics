# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Work Queue API Routes
Endpoints for analyst work management, assignments, and workload balancing.

All endpoints require authentication.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List
from pydantic import BaseModel
import logging

from dependencies.auth import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/work-queue", tags=["Work Queue"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class AssignWorkItemRequest(BaseModel):
    item_id: str
    item_type: str  # alert, investigation, escalation
    analyst_id: str


class ClaimWorkRequest(BaseModel):
    analyst_id: str
    item_types: Optional[List[str]] = None  # Filter by type


class ReleaseWorkRequest(BaseModel):
    item_id: str
    item_type: str


class AutoAssignRequest(BaseModel):
    analyst_ids: List[str]
    max_items_per_analyst: int = 10


# ============================================================================
# Work Queue Endpoints
# ============================================================================

@router.get("")
async def get_work_queue(
    analyst_id: Optional[str] = None,
    item_types: Optional[str] = Query(None, description="Comma-separated: alert,investigation,escalation,approval"),
    status: Optional[str] = Query(None, description="Comma-separated status filter"),
    priority: Optional[str] = Query(None, description="Comma-separated priority filter"),
    unassigned_only: bool = False,
    include_linked: bool = Query(True, description="Include alerts linked to investigations"),
    limit: int = Query(100, le=5000),  # Increased from 500 to 5000
    current_user: dict = Depends(get_current_user)
):
    """
    Get the unified work queue.

    Returns alerts, investigations, escalations, and approvals
    that need analyst attention, sorted by priority and SLA.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        type_list = item_types.split(",") if item_types else None
        status_list = status.split(",") if status else None
        priority_list = priority.split(",") if priority else None

        items = await service.get_work_queue(
            analyst_id=analyst_id,
            item_types=type_list,
            status_filter=status_list,
            priority_filter=priority_list,
            unassigned_only=unassigned_only,
            include_linked=include_linked,
            limit=limit
        )

        return {
            "items": items,
            "count": len(items),
            "filters": {
                "analyst_id": analyst_id,
                "item_types": type_list,
                "unassigned_only": unassigned_only,
                "include_linked": include_linked
            }
        }
    except Exception as e:
        logger.error(f"Failed to get work queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_queue_stats(current_user: dict = Depends(get_current_user)):
    """
    Get overall queue statistics.

    Returns counts of open items, unassigned items, SLA breaches, etc.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        stats = await service.get_queue_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get queue stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/my-work/{analyst_id}")
async def get_my_work(
    analyst_id: str,
    item_types: Optional[str] = None,
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user)
):
    """
    Get work items assigned to a specific analyst.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        type_list = item_types.split(",") if item_types else None

        items = await service.get_work_queue(
            analyst_id=analyst_id,
            item_types=type_list,
            unassigned_only=False,
            limit=limit
        )

        # Filter to only items assigned to this analyst
        my_items = [i for i in items if i.get('assigned_to') == analyst_id]

        return {
            "analyst_id": analyst_id,
            "items": my_items,
            "count": len(my_items)
        }
    except Exception as e:
        logger.error(f"Failed to get analyst work: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/workload/{analyst_id}")
async def get_analyst_workload(analyst_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get workload summary for an analyst.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        workload = await service.get_analyst_workload(analyst_id)
        return workload
    except Exception as e:
        logger.error(f"Failed to get workload: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assign")
async def assign_work_item(request: AssignWorkItemRequest, current_user: dict = Depends(get_current_user)):
    """
    Assign a work item to an analyst.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        result = await service.assign_work_item(
            item_id=request.item_id,
            item_type=request.item_type,
            analyst_id=request.analyst_id
        )
        return result
    except Exception as e:
        logger.error(f"Failed to assign work item: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/claim")
async def claim_next_work(request: ClaimWorkRequest, current_user: dict = Depends(get_current_user)):
    """
    Claim the next available work item from the queue.

    Automatically selects the highest priority unassigned item
    and assigns it to the analyst.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        item = await service.claim_next_work_item(
            analyst_id=request.analyst_id,
            item_types=request.item_types
        )

        if item:
            return {
                "claimed": True,
                "item": item
            }
        return {
            "claimed": False,
            "message": "No available work items in queue"
        }
    except Exception as e:
        logger.error(f"Failed to claim work: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/release")
async def release_work_item(request: ReleaseWorkRequest, current_user: dict = Depends(get_current_user)):
    """
    Release a work item back to the queue.

    Use this when an analyst can't complete the work
    and it needs to be reassigned.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        result = await service.release_work_item(
            item_id=request.item_id,
            item_type=request.item_type
        )
        return result
    except Exception as e:
        logger.error(f"Failed to release work: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto-assign")
async def auto_assign_work(request: AutoAssignRequest, current_user: dict = Depends(require_admin)):
    """
    Automatically assign unassigned items to analysts. ADMIN ONLY.

    Uses round-robin assignment while respecting max capacity.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        result = await service.auto_assign_round_robin(
            analyst_ids=request.analyst_ids,
            max_items_per_analyst=request.max_items_per_analyst
        )
        return result
    except Exception as e:
        logger.error(f"Failed to auto-assign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysts")
async def get_available_analysts(current_user: dict = Depends(get_current_user)):
    """
    Get list of available analysts and their current workload.
    """
    from services.work_queue_service import get_work_queue_service
    from services.postgres_db import postgres_db
    service = get_work_queue_service()

    try:
        # Get analysts from users table
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, username, email, role
                FROM users
                WHERE role IN ('admin', 'analyst')
                ORDER BY username
            """)

        analysts = []
        for row in rows:
            workload = await service.get_analyst_workload(row['username'])
            analysts.append({
                "id": str(row['id']),
                "username": row['username'],
                "email": row['email'],
                "role": row['role'],
                **workload
            })

        return {"analysts": analysts, "count": len(analysts)}
    except Exception as e:
        logger.error(f"Failed to get analysts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SLA Endpoints
# ============================================================================

@router.get("/sla-breaches")
async def get_sla_breaches(
    analyst_id: Optional[str] = None,
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user)
):
    """
    Get work items that have breached their SLA.
    """
    from services.work_queue_service import get_work_queue_service
    service = get_work_queue_service()

    try:
        all_items = await service.get_work_queue(
            analyst_id=analyst_id,
            limit=500  # Get more to filter
        )

        # Filter to breached items
        breached = [i for i in all_items if i.get('sla_status') == 'breached']

        return {
            "breached_items": breached[:limit],
            "count": len(breached),
            "message": f"{len(breached)} items have breached their SLA"
        }
    except Exception as e:
        logger.error(f"Failed to get SLA breaches: {e}")
        raise HTTPException(status_code=500, detail=str(e))


logger.info("Work queue routes loaded")
