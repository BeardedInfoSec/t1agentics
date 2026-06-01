# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Breach Intelligence API Routes

Platform-level breach intelligence data shared across all tenants:
- List and search breach incidents
- Dashboard statistics and timeline
- Source management (enable/disable, manual poll)
- Background scheduler for automated polling
"""

import asyncio
import logging
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from dependencies.auth import get_current_user
from services.breach_intel_service import get_breach_intel_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/breach-intel",
    tags=["Breach Intelligence"],
    dependencies=[Depends(get_current_user)]
)


# =============================================================================
# MODELS
# =============================================================================

class BreachIncidentResponse(BaseModel):
    """Response model for a single breach incident"""
    id: str
    title: str
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    summary: Optional[str] = None
    ai_summary: Optional[str] = None
    affected_org: Optional[str] = None
    affected_records: Optional[int] = None
    source: Optional[str] = None
    source_url: Optional[str] = None
    published_at: Optional[datetime] = None
    discovered_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)


class BreachListResponse(BaseModel):
    """Paginated list of breach incidents"""
    items: List[BreachIncidentResponse]
    total: int
    limit: int
    offset: int


class BreachStatsResponse(BaseModel):
    """Dashboard statistics for breach intelligence"""
    total_incidents: int = 0
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    last_7_days: int = 0
    last_30_days: int = 0
    sources_active: int = 0


class TimelineEntry(BaseModel):
    """Single entry in the breach timeline"""
    date: str
    count: int = 0
    by_type: Dict[str, int] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    """Time series data for breach charts"""
    data: List[TimelineEntry]


class BreachSourceResponse(BaseModel):
    """Response model for a breach intel source"""
    source_id: str
    name: str
    description: Optional[str] = None
    enabled: bool = True
    source_type: Optional[str] = None
    last_poll_at: Optional[datetime] = None
    last_poll_status: Optional[str] = None
    last_poll_count: Optional[int] = None
    poll_interval_minutes: int = 60


class EnableSourceRequest(BaseModel):
    """Request to enable/disable a source"""
    enabled: bool


class SchedulerStatusResponse(BaseModel):
    """Scheduler status response"""
    running: bool
    last_run_at: Optional[datetime] = None
    sources_polled: int = 0
    sources_failed: int = 0
    interval_minutes: int = 60


class SchedulerConfigRequest(BaseModel):
    """Scheduler configuration request"""
    interval_minutes: int = 60


# =============================================================================
# MODULE-LEVEL SCHEDULER STATE
# =============================================================================

_scheduler_state = {
    "running": False,
    "task": None,
    "last_run_at": None,
    "sources_polled": 0,
    "sources_failed": 0,
    "interval_minutes": 60,
}


# =============================================================================
# ROUTES
# =============================================================================

@router.get("", response_model=BreachListResponse)
async def list_breach_incidents(
    incident_type: Optional[str] = Query(None, description="Filter by incident type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Text search on title"),
    date_from: Optional[str] = Query(None, description="Start date (ISO format)"),
    date_to: Optional[str] = Query(None, description="End date (ISO format)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List breach incidents with optional filtering and pagination"""
    service = get_breach_intel_service()

    try:
        result = await service.list_incidents(
            incident_type=incident_type,
            severity=severity,
            search=search,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        logger.error(f"Failed to list breach incidents: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve breach incidents")

    items = [BreachIncidentResponse(**item) for item in result.get("items", [])]

    return BreachListResponse(
        items=items,
        total=result.get("total", len(items)),
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=BreachStatsResponse)
async def get_breach_stats():
    """Get breach intelligence dashboard statistics"""
    service = get_breach_intel_service()

    try:
        stats = await service.get_stats()
    except Exception as e:
        logger.error(f"Failed to get breach stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve breach statistics")

    # Map service output to response model field names
    sources = stats.get("sources", [])
    return BreachStatsResponse(
        total_incidents=stats.get("total_incidents", 0),
        by_type=stats.get("by_type", {}),
        by_severity=stats.get("by_severity", {}),
        last_7_days=stats.get("last_7d", 0),
        last_30_days=stats.get("last_30d", 0),
        sources_active=len([s for s in sources if s.get("enabled")]),
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_breach_timeline(
    days: int = Query(30, ge=1, le=365, description="Number of days for timeline"),
):
    """Get time series data for breach incident charts"""
    service = get_breach_intel_service()

    try:
        data = await service.get_timeline(days=days)
    except Exception as e:
        logger.error(f"Failed to get breach timeline: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve breach timeline")

    entries = [TimelineEntry(**entry) for entry in data]

    return TimelineResponse(data=entries)


@router.get("/sources", response_model=List[BreachSourceResponse])
async def list_breach_sources():
    """List configured breach intelligence sources with status"""
    service = get_breach_intel_service()

    try:
        sources = await service.get_sources()
    except Exception as e:
        logger.error(f"Failed to list breach sources: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve breach sources")

    return [BreachSourceResponse(**src) for src in sources]


@router.post("/sources/{source_id}/poll")
async def poll_breach_source(
    source_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Manually trigger a poll for a specific breach source (admin only)"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    service = get_breach_intel_service()

    try:
        result = await service.poll_source(source_id)
    except Exception as e:
        logger.error(f"Failed to poll breach source {source_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to poll source: {source_id}")

    return result


@router.patch("/sources/{source_id}/enable")
async def enable_breach_source(
    source_id: str,
    request: EnableSourceRequest,
    current_user: dict = Depends(get_current_user),
):
    """Enable or disable a breach intelligence source (admin only)"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    service = get_breach_intel_service()

    try:
        await service.set_source_enabled(source_id, request.enabled)
    except Exception as e:
        logger.error(f"Failed to update breach source {source_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update source: {source_id}")

    return {"success": True, "source_id": source_id, "enabled": request.enabled}


@router.get("/search")
async def search_breach_incidents(
    q: str = Query(..., min_length=1, description="Search query string"),
    limit: int = Query(20, ge=1, le=100),
):
    """Full text search across breach incidents (title, summary, affected_org, ai_summary)"""
    service = get_breach_intel_service()

    try:
        results = await service.search_incidents(query=q, limit=limit)
    except Exception as e:
        logger.error(f"Failed to search breach incidents: {e}")
        raise HTTPException(status_code=500, detail="Failed to search breach incidents")

    items = [BreachIncidentResponse(**item) for item in results]

    return {"items": items, "total": len(items), "query": q}


@router.get("/{incident_id}", response_model=BreachIncidentResponse)
async def get_breach_incident(incident_id: str):
    """Get detailed information for a single breach incident"""
    service = get_breach_intel_service()

    try:
        incident = await service.get_incident(incident_id)
    except Exception as e:
        logger.error(f"Failed to get breach incident {incident_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve breach incident")

    if not incident:
        raise HTTPException(status_code=404, detail=f"Breach incident not found: {incident_id}")

    return BreachIncidentResponse(**incident)


# =============================================================================
# SCHEDULER ENDPOINTS
# =============================================================================

@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
async def get_scheduler_status():
    """Get the current breach intel scheduler status"""
    return SchedulerStatusResponse(
        running=_scheduler_state["running"],
        last_run_at=_scheduler_state["last_run_at"],
        sources_polled=_scheduler_state["sources_polled"],
        sources_failed=_scheduler_state["sources_failed"],
        interval_minutes=_scheduler_state["interval_minutes"],
    )


@router.post("/scheduler/start")
async def start_scheduler(config: Optional[SchedulerConfigRequest] = None):
    """Start the breach intelligence polling scheduler"""
    if _scheduler_state["running"]:
        return {"success": False, "message": "Scheduler is already running"}

    if config:
        _scheduler_state["interval_minutes"] = config.interval_minutes

    _scheduler_state["running"] = True
    _scheduler_state["sources_polled"] = 0
    _scheduler_state["sources_failed"] = 0

    _scheduler_state["task"] = asyncio.create_task(_scheduler_loop())

    return {
        "success": True,
        "message": "Breach intel scheduler started",
        "interval_minutes": _scheduler_state["interval_minutes"],
    }


@router.post("/scheduler/stop")
async def stop_scheduler():
    """Stop the breach intelligence polling scheduler"""
    if not _scheduler_state["running"]:
        return {"success": False, "message": "Scheduler is not running"}

    _scheduler_state["running"] = False

    if _scheduler_state["task"]:
        _scheduler_state["task"].cancel()
        try:
            await _scheduler_state["task"]
        except asyncio.CancelledError:
            pass
        _scheduler_state["task"] = None

    return {"success": True, "message": "Breach intel scheduler stopped"}


# =============================================================================
# SCHEDULER LOOP
# =============================================================================

async def _scheduler_loop():
    """Background scheduler loop that polls all breach intel sources"""
    while _scheduler_state["running"]:
        try:
            service = get_breach_intel_service()
            logger.info("[BREACH-INTEL] Scheduler: polling all sources")

            try:
                await service.poll_all_sources()
                _scheduler_state["sources_polled"] += 1
            except Exception as e:
                _scheduler_state["sources_failed"] += 1
                logger.error(f"[BREACH-INTEL] Poll cycle error: {e}")

            _scheduler_state["last_run_at"] = datetime.utcnow()

            logger.info(
                f"[BREACH-INTEL] Poll cycle complete. "
                f"Next cycle in {_scheduler_state['interval_minutes']} minutes."
            )

            if _scheduler_state["running"]:
                await asyncio.sleep(_scheduler_state["interval_minutes"] * 60)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[BREACH-INTEL] Scheduler loop error: {e}")
            if _scheduler_state["running"]:
                await asyncio.sleep(60)
