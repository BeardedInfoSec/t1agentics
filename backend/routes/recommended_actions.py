# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Recommended Actions API Routes

Endpoints for managing Riggs-generated action recommendations within investigations.
Analysts can view, approve, execute, or dismiss recommended actions.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import logging

from dependencies.auth import get_current_user
from services import recommended_actions_service as ras

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/recommended-actions",
    tags=["Recommended Actions"],
    dependencies=[Depends(get_current_user)],
)


# ============================================================================
# Request/Response Models
# ============================================================================

class ActionResponse(BaseModel):
    id: str
    investigation_id: str
    action_type: str
    title: str
    description: Optional[str] = None
    priority: str
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    connector_name: Optional[str] = None
    connector_action_id: Optional[str] = None
    status: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    execution_result: Optional[dict] = None
    dismissed_by: Optional[str] = None
    dismiss_reason: Optional[str] = None
    created_at: Optional[str] = None

    class Config:
        from_attributes = True


class DismissRequest(BaseModel):
    reason: Optional[str] = None


class GenerateRequest(BaseModel):
    """Manually trigger recommendation generation for an investigation."""
    investigation_id: str


class ExecuteInstantRequest(BaseModel):
    """One-touch IOC action: create + approve + execute in a single step."""
    investigation_id: str
    ioc_type: str
    ioc_value: str
    action_type: str
    instance_id: str


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/investigation/{investigation_id}")
async def list_actions(
    investigation_id: str,
    status: Optional[str] = Query(None, description="Filter by status: pending, approved, completed, failed, dismissed"),
    user: dict = Depends(get_current_user),
):
    """Get all recommended actions for an investigation."""
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    try:
        actions = await ras.get_recommendations(tenant_id, investigation_id, status)
    except Exception as e:
        logger.error(f"[RecommendedActions] Failed to load recommendations for {investigation_id}: {e}")
        return {"actions": [], "total": 0}
    return {"actions": actions, "total": len(actions)}


@router.post("/{action_id}/approve")
async def approve_action(
    action_id: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    """Approve a recommended action. This marks it for execution."""
    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    result = await ras.approve_action(tenant_id, action_id, user_id)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found or already processed")

    # Auto-execute after approval
    background_tasks.add_task(ras.execute_action, tenant_id, action_id)

    return {"message": "Action approved and queued for execution", "action": result}


@router.post("/{action_id}/dismiss")
async def dismiss_action(
    action_id: str,
    body: DismissRequest = DismissRequest(),
    user: dict = Depends(get_current_user),
):
    """Dismiss a recommended action."""
    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    result = await ras.dismiss_action(tenant_id, action_id, user_id, body.reason)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found or already processed")

    return {"message": "Action dismissed", "action": result}


@router.post("/generate")
async def generate_actions(
    body: GenerateRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    """
    Manually generate recommended actions for an investigation.
    Pulls the latest Riggs analysis and matches IOCs to available connectors.
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    from services.postgres_db import postgres_db
    import json

    # Fetch the investigation data
    async with postgres_db.tenant_acquire() as conn:
        # Try as VARCHAR investigation_id first, then as UUID
        inv = await conn.fetchrow(
            "SELECT id, investigation_id, investigation_data FROM investigations WHERE investigation_id = $1",
            body.investigation_id,
        )
        if not inv:
            try:
                inv = await conn.fetchrow(
                    "SELECT id, investigation_id, investigation_data FROM investigations WHERE id = $1::uuid",
                    body.investigation_id,
                )
            except Exception:
                pass

    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    inv_uuid = str(inv["id"])  # UUID primary key for recommended_actions table
    inv_data = inv["investigation_data"]
    if isinstance(inv_data, str):
        inv_data = json.loads(inv_data)

    # Check all analysis tiers for data
    riggs_analysis = (
        inv_data.get("riggs_analysis")
        or inv_data.get("riggs_deep_analysis")
        or inv_data.get("tier3_analysis")
        or inv_data.get("tier2_analysis")
        or inv_data.get("tier1_analysis")
        or {}
    )
    if not riggs_analysis:
        raise HTTPException(status_code=400, detail="No Riggs analysis found for this investigation")

    # Extract IOCs from investigation data first
    indicators = inv_data.get("indicators", [])
    iocs = {}

    # Handle indicators as either list or dict
    if isinstance(indicators, list):
        for item in indicators:
            if isinstance(item, dict):
                ioc_type = item.get("type", "")
                ioc_value = item.get("value", "")
                if ioc_type and ioc_value:
                    if ioc_type not in iocs:
                        iocs[ioc_type] = []
                    iocs[ioc_type].append(ioc_value)
    elif isinstance(indicators, dict):
        iocs = indicators

    # Fallback: Try from riggs_extracted_iocs which has format like {'ips': [...], 'domains': [...]}
    if not iocs:
        riggs_iocs = riggs_analysis.get("riggs_extracted_iocs", {})
        if riggs_iocs:
            if isinstance(riggs_iocs, dict):
                iocs = riggs_iocs
                logger.info(f"[RecommendedActions] Loaded IOCs from riggs_extracted_iocs: {sum(len(v) for v in iocs.values())} total")
            elif isinstance(riggs_iocs, list):
                # Handle if riggs_extracted_iocs is accidentally a list instead of dict
                for item in riggs_iocs:
                    if isinstance(item, dict):
                        ioc_type = item.get("type", "").lower()
                        ioc_value = item.get("value", "")
                        if ioc_type and ioc_value:
                            if ioc_type not in iocs:
                                iocs[ioc_type] = []
                            if ioc_value not in iocs[ioc_type]:
                                iocs[ioc_type].append(ioc_value)
                if iocs:
                    logger.info(f"[RecommendedActions] Extracted IOCs from riggs_extracted_iocs (list format): {sum(len(v) for v in iocs.values())} total")

    # Fallback: Try to extract IOCs directly from riggs_analysis.iocs list
    if not iocs:
        riggs_ioc_list = riggs_analysis.get("iocs", [])
        if isinstance(riggs_ioc_list, list):
            for ioc in riggs_ioc_list:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get("type", "").lower()
                    ioc_value = ioc.get("value", "")
                    if ioc_type and ioc_value:
                        if ioc_type not in iocs:
                            iocs[ioc_type] = []
                        if ioc_value not in iocs[ioc_type]:
                            iocs[ioc_type].append(ioc_value)
            if iocs:
                logger.info(f"[RecommendedActions] Extracted IOCs from riggs_analysis.iocs: {sum(len(v) for v in iocs.values())} total")

    # Fallback: fetch IOCs from the investigation_iocs + ioc_enrichments tables
    if not iocs:
        async with postgres_db.tenant_acquire() as conn:
            ioc_rows = await conn.fetch(
                """
                SELECT ie.ioc_type, ie.ioc_value
                FROM investigation_iocs ii
                JOIN ioc_enrichments ie ON ii.ioc_enrichment_id = ie.id
                WHERE ii.investigation_id = $1::uuid
                """,
                inv["id"],
            )
        for row in ioc_rows:
            t = row["ioc_type"]
            v = row["ioc_value"]
            if t and v:
                if t not in iocs:
                    iocs[t] = []
                if v not in iocs[t]:
                    iocs[t].append(v)
        if iocs:
            logger.info(f"[RecommendedActions] Loaded {sum(len(v) for v in iocs.values())} IOCs from investigation_iocs table")

    # Log what we found for debugging
    if not iocs:
        logger.warning(f"[RecommendedActions] No IOCs found for investigation {body.investigation_id} from any source")
    else:
        logger.info(f"[RecommendedActions] Using {sum(len(v) for v in iocs.values())} IOCs for recommendations")

    # Generate recommendations
    recommendations = await ras.generate_recommendations(
        tenant_id=tenant_id,
        investigation_id=inv_uuid,
        riggs_analysis=riggs_analysis,
        iocs=iocs,
    )

    if not recommendations:
        # Even if no recommendations, return the IOCs found for analyst visibility
        ioc_display_list = []
        for ioc_type, values in iocs.items():
            for value in values:
                ioc_display_list.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "display_only": True,  # Mark as display-only, not actionable
                    "message": "IOC extracted by Riggs analysis - no matching connectors for recommendations"
                })

        return {
            "message": f"Found {sum(len(v) for v in iocs.values())} IOCs but no matching recommendations (no connectors or all benign)",
            "actions": ioc_display_list,
            "total": len(ioc_display_list),
            "ioc_count": sum(len(v) for v in iocs.values()),
        }

    # Save to DB (uses UUID investigation_id)
    saved = await ras.save_recommendations(
        tenant_id=tenant_id,
        investigation_id=inv_uuid,
        recommendations=recommendations,
    )

    # Check auto-response for each saved recommendation
    if saved:
        background_tasks.add_task(ras.check_auto_response_and_execute, tenant_id, saved)

    return {
        "message": f"Generated {len(saved)} recommended actions",
        "actions": await ras.get_recommendations(tenant_id, body.investigation_id),
        "total": len(saved),
    }


# ============================================================================
# One-Touch IOC Action Endpoints
# ============================================================================

@router.get("/available")
async def get_available_actions(
    ioc_type: str = Query(..., description="IOC type: ip, domain, hash, url, email, hostname, username"),
    ioc_value: str = Query(..., description="The IOC value"),
    investigation_id: Optional[str] = Query(None, description="Investigation context (optional)"),
    user: dict = Depends(get_current_user),
):
    """
    Return available connector actions for a given IOC without saving to the database.
    Used to populate the one-touch action menu in the investigation UI.
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    actions = await ras.get_available_actions_for_ioc(
        tenant_id=tenant_id,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        investigation_id=investigation_id,
    )

    return {"actions": actions, "total": len(actions)}


@router.post("/execute-instant")
async def execute_instant_action(
    body: ExecuteInstantRequest,
    user: dict = Depends(get_current_user),
):
    """
    One-touch action: create, approve, and execute a recommended action in one step.
    Used when an analyst clicks an IOC action button directly.
    """
    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    result = await ras.execute_instant_action(
        tenant_id=tenant_id,
        investigation_id=body.investigation_id,
        ioc_type=body.ioc_type,
        ioc_value=body.ioc_value,
        action_type=body.action_type,
        instance_id=body.instance_id,
        user_id=user_id,
    )

    if not result:
        raise HTTPException(status_code=400, detail="Failed to execute action. Check connector availability and action compatibility.")

    return {"message": "Action executed", "action": result}
