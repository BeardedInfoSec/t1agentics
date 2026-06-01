# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Frontend Telemetry Routes

Receives error reports, usage metrics, and UX telemetry events from the frontend.
UX events are stored in ClickHouse for analytics; error reports go to PostgreSQL.
"""

import logging
from datetime import datetime
from fastapi import APIRouter, Request, Depends, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"], dependencies=[Depends(get_current_user)])


class FrontendErrorReport(BaseModel):
    error: str
    componentStack: Optional[str] = None
    url: Optional[str] = None
    userAgent: Optional[str] = None
    timestamp: Optional[str] = None


@router.post("/frontend-error")
async def report_frontend_error(report: FrontendErrorReport, request: Request):
    """
    Receive frontend error reports from ErrorBoundary.
    Logs them for monitoring and debugging.
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.error(
        f"Frontend error from {client_ip}: {report.error}",
        extra={
            "error_type": "frontend",
            "url": report.url,
            "component_stack": report.componentStack[:500] if report.componentStack else None,
            "user_agent": report.userAgent,
        }
    )

    # Store in database for dashboard
    try:
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                INSERT INTO frontend_errors (error, component_stack, url, user_agent, client_ip, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING
            """,
                report.error[:1000],
                report.componentStack[:2000] if report.componentStack else None,
                report.url,
                report.userAgent,
                client_ip,
                datetime.utcnow()
            )
    except Exception as e:
        # Table might not exist yet - log and continue
        logger.debug(f"Could not store frontend error: {e}")

    return {"status": "received"}


# ═══════════════════════════════════════════════════════════════════════════
# UX Telemetry Events (ClickHouse-backed)
# ═══════════════════════════════════════════════════════════════════════════

class TelemetryEvent(BaseModel):
    event_type: str
    event_name: str
    properties: Optional[Dict[str, Any]] = None
    page: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: Optional[str] = None


@router.post("/events")
async def track_events(events: List[TelemetryEvent], request: Request):
    """
    Batch-insert UX telemetry events.
    Frontend sends batches every 30s or on page unload.
    """
    from services.telemetry_service import telemetry_service

    user = request.state.user if hasattr(request.state, "user") else None
    tenant_id = str(getattr(user, "tenant_id", "")) if user else ""
    user_id = str(getattr(user, "id", getattr(user, "user_id", ""))) if user else ""

    if not events:
        return {"status": "ok", "inserted": 0}

    # Cap batch size to prevent abuse
    capped = events[:100]
    count = telemetry_service.track_batch(
        tenant_id=tenant_id,
        user_id=user_id,
        events=[e.dict() for e in capped],
    )

    return {"status": "ok", "inserted": count}


@router.get("/usage")
async def get_usage_stats(request: Request, days: int = Query(default=30, ge=1, le=365)):
    """Feature usage aggregates for the current tenant."""
    from services.telemetry_service import telemetry_service

    user = request.state.user if hasattr(request.state, "user") else None
    tenant_id = str(getattr(user, "tenant_id", "")) if user else ""

    usage = telemetry_service.get_feature_usage(tenant_id, days=days)
    return {"usage": usage, "days": days}


@router.get("/investigation-metrics")
async def get_investigation_metrics(request: Request, days: int = Query(default=30, ge=1, le=365)):
    """Investigation decision-time metrics for the current tenant."""
    from services.telemetry_service import telemetry_service

    user = request.state.user if hasattr(request.state, "user") else None
    tenant_id = str(getattr(user, "tenant_id", "")) if user else ""

    metrics = telemetry_service.get_investigation_metrics(tenant_id, days=days)
    return {"metrics": metrics, "days": days}
