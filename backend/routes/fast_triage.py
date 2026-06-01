# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Fast Triage API Routes

Endpoints for triggering fast alert triage.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from pydantic import BaseModel

from services.fast_triage import get_triage_service
from dependencies.auth import require_role, get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/triage", tags=["Fast Triage"], dependencies=[Depends(get_current_user)])


class TriageRequest(BaseModel):
    alert_id: int


class AnalyzeRequest(BaseModel):
    """Request for Riggs AI analysis."""
    alert_id: str | int | None = None
    alert_data: Dict[str, Any] | None = None


class TriageResponse(BaseModel):
    alert_id: int
    severity: str
    iocs_extracted: list
    needs_riggs: bool
    confidence: float
    reasoning: str
    investigation_id: int | None
    triage_time_ms: int


@router.post("/execute", response_model=TriageResponse)
async def execute_triage(
    request: TriageRequest,
    _user=Depends(require_role(["admin", "analyst"]))
) -> TriageResponse:
    """
    Execute fast triage on an alert

    Flow:
    1. Extract IOCs from alert
    2. Quick LLM classification
    3. Decide if Riggs escalation needed
    4. Update alert and create investigation if needed

    Target: <5 seconds total
    """
    triage_service = get_triage_service()

    try:
        result = await triage_service.triage_alert(request.alert_id)
        return TriageResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")


@router.post("/bulk", response_model=Dict[str, Any])
async def bulk_triage(
    alert_ids: list[int],
    _user=Depends(require_role(["admin"]))
) -> Dict[str, Any]:
    """
    Execute fast triage on multiple alerts (batch processing)

    Useful for:
    - Initial ingestion of bulk alerts
    - Retroactive triage of old alerts
    - Testing triage logic

    Returns summary of triage results
    """
    triage_service = get_triage_service()

    results = []
    errors = []

    for alert_id in alert_ids:
        try:
            result = await triage_service.triage_alert(alert_id)
            results.append(result)
        except Exception as e:
            errors.append({"alert_id": alert_id, "error": str(e)})

    return {
        "total_alerts": len(alert_ids),
        "successful": len(results),
        "failed": len(errors),
        "results": results,
        "errors": errors,
        "summary": {
            "escalated_to_riggs": sum(1 for r in results if r["needs_riggs"]),
            "auto_closed": sum(1 for r in results if not r["needs_riggs"]),
            "avg_triage_time_ms": sum(r["triage_time_ms"] for r in results) // len(results) if results else 0
        }
    }


@router.get("/stats", response_model=Dict[str, Any])
async def triage_stats(
    _user=Depends(require_role(["admin", "analyst"]))
) -> Dict[str, Any]:
    """
    Get triage performance statistics

    Useful for monitoring triage effectiveness:
    - Average triage time
    - Escalation rate to Riggs
    - Auto-close rate
    """
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or postgres_db.pool is None:
            return {"avg_triage_time_ms": 0, "total_triaged": 0, "escalation_rate": 0.0, "auto_close_rate": 0.0}

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) * 1000), 0)::int AS avg_triage_time_ms,
                    COUNT(*) FILTER (WHERE status != 'new') AS total_triaged,
                    CASE WHEN COUNT(*) FILTER (WHERE status != 'new') > 0
                         THEN COUNT(*) FILTER (WHERE status = 'escalated')::float / COUNT(*) FILTER (WHERE status != 'new')
                         ELSE 0.0 END AS escalation_rate,
                    CASE WHEN COUNT(*) FILTER (WHERE status != 'new') > 0
                         THEN COUNT(*) FILTER (WHERE status = 'closed' AND disposition = 'benign')::float / COUNT(*) FILTER (WHERE status != 'new')
                         ELSE 0.0 END AS auto_close_rate
                FROM alerts
                WHERE created_at > NOW() - INTERVAL '30 days'
            """)
            return {
                "avg_triage_time_ms": row["avg_triage_time_ms"] if row else 0,
                "total_triaged": row["total_triaged"] if row else 0,
                "escalation_rate": round(row["escalation_rate"], 3) if row else 0.0,
                "auto_close_rate": round(row["auto_close_rate"], 3) if row else 0.0,
            }
    except Exception as e:
        logger.error(f"Error fetching triage stats: {e}")
        return {"avg_triage_time_ms": 0, "total_triaged": 0, "escalation_rate": 0.0, "auto_close_rate": 0.0}


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_alert(
    request: AnalyzeRequest,
    _user=Depends(require_role(["admin", "analyst"]))
) -> Dict[str, Any]:
    """
    Perform Riggs AI analysis on an alert.

    This endpoint is used by Riggs Studio for testing AI analysis on alerts.
    Accepts either alert_id (to load from DB) or alert_data (for ad-hoc analysis).

    Returns:
        Analysis results including verdict, confidence, summary, recommendations,
        and MITRE ATT&CK techniques.
    """
    import logging
    from services.postgres_db import postgres_db

    logger = logging.getLogger(__name__)

    try:
        # Get alert data
        alert_data = request.alert_data

        if request.alert_id and not alert_data:
            # Load alert from database using platform admin bypass
            # so admins can analyze alerts from any tenant
            if postgres_db.connected:
                async with postgres_db.pool._pool.acquire() as conn:
                    await conn.execute("SET app.is_platform_admin = 'true'")
                    # Try by alert_id string first, then by UUID if valid
                    alert_row = await conn.fetchrow(
                        'SELECT * FROM alerts WHERE alert_id = $1',
                        str(request.alert_id)
                    )
                    if not alert_row:
                        try:
                            import uuid
                            uid = uuid.UUID(str(request.alert_id))
                            alert_row = await conn.fetchrow(
                                'SELECT * FROM alerts WHERE id = $1', uid
                            )
                        except (ValueError, AttributeError):
                            pass

                    if alert_row:
                        alert_data = dict(alert_row)

        if not alert_data:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Set tenant context from the alert so downstream operations
        # (verdict storage, investigation creation) use the correct tenant
        alert_tenant_id = alert_data.get('tenant_id')
        if alert_tenant_id:
            from middleware.tenant_middleware import current_tenant_id
            current_tenant_id.set(str(alert_tenant_id))
            logger.info(f"Set tenant context to {alert_tenant_id} from alert")

        # Call AI Triage Service
        try:
            from services.ai_triage_service import AITriageService

            triage_service = AITriageService()
            result = await triage_service.triage_alert(
                alert_id=str(request.alert_id or alert_data.get('alert_id') or alert_data.get('id', 'unknown')),
                alert_data=alert_data,
                enrichment_data={}
            )

            return {
                "success": True,
                "alert_id": request.alert_id or alert_data.get('id'),
                "verdict": result.get('verdict', 'unknown'),
                "confidence": result.get('confidence', 0.5),
                "summary": result.get('summary', result.get('reasoning', '')),
                "reasoning": result.get('reasoning', ''),
                "recommendations": result.get('recommendations', []),
                "mitre_techniques": result.get('mitre_techniques', []),
                "iocs_extracted": result.get('iocs_extracted', []),
                "risk_score": result.get('risk_score', 50),
            }

        except ImportError:
            # AITriageService not available, use fast triage
            logger.warning("AITriageService not available, using fast triage")
            triage_service = get_triage_service()

            alert_id = int(request.alert_id) if str(request.alert_id).isdigit() else None
            if alert_id:
                result = await triage_service.triage_alert(alert_id)
                return {
                    "success": True,
                    "alert_id": alert_id,
                    "verdict": "suspicious" if result.get('needs_riggs') else "benign",
                    "confidence": result.get('confidence', 0.7),
                    "summary": result.get('reasoning', ''),
                    "reasoning": result.get('reasoning', ''),
                    "recommendations": [],
                    "mitre_techniques": [],
                    "iocs_extracted": result.get('iocs_extracted', []),
                    "risk_score": 70 if result.get('needs_riggs') else 30,
                }
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Alert ID required for fast triage fallback"
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
