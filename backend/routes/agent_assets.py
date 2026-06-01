# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent-to-Asset Linking Routes (Phase 9)

Provides API endpoints for managing relationships between deployed agents
and CMDB assets, including auto-linking, coverage analysis, and manual overrides.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from dependencies.auth import get_current_user
from services.agent_asset_linker import (
    AgentAssetLinkerService,
    AgentAssetLink,
    CMDBAsset
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/agent-assets", tags=["Agent Assets"])

# Initialize the linker service
_linker_service = AgentAssetLinkerService()


# ============================================================================
# Pydantic Models
# ============================================================================

class ManualLinkRequest(BaseModel):
    """Request to manually link an agent to an asset"""
    agent_id: str
    asset_id: str
    agent_type: str = "collector"  # collector, edr, unified
    notes: Optional[str] = None


class AssetCreateRequest(BaseModel):
    """Request to create a new CMDB asset"""
    hostname: str
    ip_addresses: List[str] = []
    mac_addresses: List[str] = []
    asset_type: str = "server"
    environment: str = "production"
    criticality: str = "medium"
    owner: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    tags: List[str] = []
    custom_attributes: Dict[str, Any] = {}


class AssetUpdateRequest(BaseModel):
    """Request to update an existing asset"""
    hostname: Optional[str] = None
    ip_addresses: Optional[List[str]] = None
    mac_addresses: Optional[List[str]] = None
    asset_type: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    tags: Optional[List[str]] = None
    custom_attributes: Optional[Dict[str, Any]] = None


class BulkLinkRequest(BaseModel):
    """Request to link multiple agents"""
    links: List[ManualLinkRequest]


# ============================================================================
# Agent-Asset Link Endpoints
# ============================================================================

@router.get("/links")
async def list_agent_asset_links(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    agent_type: Optional[str] = Query(None, description="Filter by agent type"),
    linked: Optional[bool] = Query(None, description="Filter by linked status"),
    current_user: dict = Depends(get_current_user)
):
    """
    List all agent-to-asset links.

    Returns relationships between deployed agents and CMDB assets,
    including auto-discovered and manually configured links.
    """
    links = list(_linker_service._links.values())

    if agent_id:
        links = [l for l in links if l.agent_id == agent_id]
    if asset_id:
        links = [l for l in links if l.asset_id == asset_id]
    if agent_type:
        links = [l for l in links if l.agent_type == agent_type]
    if linked is not None:
        if linked:
            links = [l for l in links if l.asset_id is not None]
        else:
            links = [l for l in links if l.asset_id is None]

    return {
        "total": len(links),
        "links": [
            {
                "agent_id": l.agent_id,
                "asset_id": l.asset_id,
                "agent_type": l.agent_type,
                "match_method": l.match_method,
                "match_confidence": l.match_confidence,
                "linked_at": l.linked_at.isoformat() if l.linked_at else None,
                "linked_by": l.linked_by,
                "auto_discovered": l.auto_discovered,
                "last_verified": l.last_verified.isoformat() if l.last_verified else None,
                "notes": l.notes
            }
            for l in links
        ]
    }


@router.post("/links")
async def create_manual_link(
    request: ManualLinkRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Manually link an agent to a CMDB asset.

    Use this to override auto-linking or link agents that couldn't
    be automatically matched to assets.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    # Verify asset exists
    if request.asset_id not in _linker_service._assets:
        raise HTTPException(status_code=404, detail=f"Asset {request.asset_id} not found")

    link = await _linker_service.manual_link(
        agent_id=request.agent_id,
        asset_id=request.asset_id,
        agent_type=request.agent_type,
        linked_by=current_user.get("username"),
        notes=request.notes
    )

    logger.info(f"[AgentAssets] Manual link created: {request.agent_id} -> {request.asset_id} by {current_user.get('username')}")

    return {
        "success": True,
        "link": {
            "agent_id": link.agent_id,
            "asset_id": link.asset_id,
            "agent_type": link.agent_type,
            "match_method": link.match_method,
            "linked_at": link.linked_at.isoformat() if link.linked_at else None,
            "linked_by": link.linked_by
        }
    }


@router.post("/links/bulk")
async def bulk_create_links(
    request: BulkLinkRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create multiple agent-asset links at once"""
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    results = []
    for link_req in request.links:
        try:
            link = await _linker_service.manual_link(
                agent_id=link_req.agent_id,
                asset_id=link_req.asset_id,
                agent_type=link_req.agent_type,
                linked_by=current_user.get("username"),
                notes=link_req.notes
            )
            results.append({
                "agent_id": link_req.agent_id,
                "asset_id": link_req.asset_id,
                "success": True
            })
        except Exception as e:
            results.append({
                "agent_id": link_req.agent_id,
                "asset_id": link_req.asset_id,
                "success": False,
                "error": str(e)
            })

    success_count = sum(1 for r in results if r["success"])
    logger.info(f"[AgentAssets] Bulk link: {success_count}/{len(results)} successful")

    return {
        "total": len(results),
        "success": success_count,
        "failed": len(results) - success_count,
        "results": results
    }


@router.delete("/links/{agent_id}")
async def unlink_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Remove the link between an agent and its asset.

    The agent will remain registered but won't be associated
    with any CMDB asset until re-linked.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    success = await _linker_service.unlink_agent(agent_id)

    if success:
        logger.info(f"[AgentAssets] Agent {agent_id} unlinked by {current_user.get('username')}")
        return {"success": True, "message": f"Agent {agent_id} unlinked from asset"}
    else:
        raise HTTPException(status_code=404, detail=f"Link for agent {agent_id} not found")


@router.post("/links/{agent_id}/verify")
async def verify_link(
    agent_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Verify that an agent-asset link is still valid.

    Re-checks the matching criteria and updates verification timestamp.
    """
    if agent_id not in _linker_service._links:
        raise HTTPException(status_code=404, detail=f"Link for agent {agent_id} not found")

    link = _linker_service._links[agent_id]
    link.last_verified = datetime.utcnow()

    # Get agent data to re-verify
    agent_data = None
    try:
        from routes.logs import _registered_agents
        if agent_id in _registered_agents:
            agent_data = _registered_agents[agent_id]
    except ImportError:
        pass

    verification_result = {
        "agent_id": agent_id,
        "asset_id": link.asset_id,
        "verified_at": link.last_verified.isoformat(),
        "match_method": link.match_method,
        "match_confidence": link.match_confidence,
        "status": "verified"
    }

    # Check if agent still exists and matches
    if agent_data and link.asset_id:
        asset = _linker_service._assets.get(link.asset_id)
        if asset:
            # Verify hostname still matches
            if link.match_method == "hostname" and agent_data.get("hostname") != asset.hostname:
                verification_result["status"] = "mismatch"
                verification_result["warning"] = "Hostname no longer matches"

    return verification_result


# ============================================================================
# CMDB Asset Endpoints
# ============================================================================

@router.get("/assets")
async def list_assets(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    has_agent: Optional[bool] = Query(None, description="Filter by agent presence"),
    search: Optional[str] = Query(None, description="Search hostname or IP"),
    current_user: dict = Depends(get_current_user)
):
    """
    List all CMDB assets.

    Returns asset inventory with agent coverage status.
    """
    assets = list(_linker_service._assets.values())

    if environment:
        assets = [a for a in assets if a.environment == environment]
    if criticality:
        assets = [a for a in assets if a.criticality == criticality]
    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]
    if search:
        search_lower = search.lower()
        assets = [a for a in assets if
                  search_lower in a.hostname.lower() or
                  any(search_lower in ip for ip in a.ip_addresses)]

    # Build response with agent coverage info
    result = []
    for asset in assets:
        # Find linked agents
        linked_agents = [
            l for l in _linker_service._links.values()
            if l.asset_id == asset.id
        ]

        asset_data = {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip_addresses": asset.ip_addresses,
            "mac_addresses": asset.mac_addresses,
            "asset_type": asset.asset_type,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "owner": asset.owner,
            "department": asset.department,
            "location": asset.location,
            "tags": asset.tags,
            "custom_attributes": asset.custom_attributes,
            "created_at": asset.created_at.isoformat() if asset.created_at else None,
            "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
            "has_agent": len(linked_agents) > 0,
            "agent_count": len(linked_agents),
            "agents": [
                {"agent_id": l.agent_id, "agent_type": l.agent_type}
                for l in linked_agents
            ]
        }

        # Apply has_agent filter after computing
        if has_agent is not None:
            if has_agent and not asset_data["has_agent"]:
                continue
            if not has_agent and asset_data["has_agent"]:
                continue

        result.append(asset_data)

    return {
        "total": len(result),
        "assets": result
    }


@router.post("/assets")
async def create_asset(
    request: AssetCreateRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new CMDB asset.

    Assets can be manually created or auto-discovered when
    agents register from unknown hosts.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    # Check for duplicate hostname
    existing = [a for a in _linker_service._assets.values()
                if a.hostname.lower() == request.hostname.lower()]
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Asset with hostname {request.hostname} already exists"
        )

    asset = await _linker_service.create_asset(
        hostname=request.hostname,
        ip_addresses=request.ip_addresses,
        mac_addresses=request.mac_addresses,
        asset_type=request.asset_type,
        environment=request.environment,
        criticality=request.criticality,
        owner=request.owner,
        department=request.department,
        location=request.location,
        tags=request.tags,
        custom_attributes=request.custom_attributes
    )

    logger.info(f"[AgentAssets] Asset created: {asset.hostname} ({asset.id}) by {current_user.get('username')}")

    return {
        "success": True,
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "created_at": asset.created_at.isoformat() if asset.created_at else None
        }
    }


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed information about a specific asset"""
    if asset_id not in _linker_service._assets:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    asset = _linker_service._assets[asset_id]

    # Find linked agents
    linked_agents = [
        l for l in _linker_service._links.values()
        if l.asset_id == asset_id
    ]

    return {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_addresses": asset.ip_addresses,
        "mac_addresses": asset.mac_addresses,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "department": asset.department,
        "location": asset.location,
        "tags": asset.tags,
        "custom_attributes": asset.custom_attributes,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
        "agents": [
            {
                "agent_id": l.agent_id,
                "agent_type": l.agent_type,
                "match_method": l.match_method,
                "match_confidence": l.match_confidence,
                "linked_at": l.linked_at.isoformat() if l.linked_at else None,
                "last_verified": l.last_verified.isoformat() if l.last_verified else None
            }
            for l in linked_agents
        ]
    }


@router.patch("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    request: AssetUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Update an existing CMDB asset"""
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    if asset_id not in _linker_service._assets:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    asset = _linker_service._assets[asset_id]

    # Update fields if provided
    if request.hostname is not None:
        asset.hostname = request.hostname
    if request.ip_addresses is not None:
        asset.ip_addresses = request.ip_addresses
    if request.mac_addresses is not None:
        asset.mac_addresses = request.mac_addresses
    if request.asset_type is not None:
        asset.asset_type = request.asset_type
    if request.environment is not None:
        asset.environment = request.environment
    if request.criticality is not None:
        asset.criticality = request.criticality
    if request.owner is not None:
        asset.owner = request.owner
    if request.department is not None:
        asset.department = request.department
    if request.location is not None:
        asset.location = request.location
    if request.tags is not None:
        asset.tags = request.tags
    if request.custom_attributes is not None:
        asset.custom_attributes = request.custom_attributes

    asset.updated_at = datetime.utcnow()

    logger.info(f"[AgentAssets] Asset updated: {asset.hostname} ({asset_id}) by {current_user.get('username')}")

    return {
        "success": True,
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "updated_at": asset.updated_at.isoformat()
        }
    }


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a CMDB asset.

    Also removes any agent links associated with this asset.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    if asset_id not in _linker_service._assets:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    # Remove linked agents first
    agents_unlinked = 0
    for agent_id, link in list(_linker_service._links.items()):
        if link.asset_id == asset_id:
            link.asset_id = None
            agents_unlinked += 1

    # Remove asset
    asset = _linker_service._assets.pop(asset_id)

    logger.info(f"[AgentAssets] Asset deleted: {asset.hostname} ({asset_id}) by {current_user.get('username')}")

    return {
        "success": True,
        "message": f"Asset {asset.hostname} deleted",
        "agents_unlinked": agents_unlinked
    }


# ============================================================================
# Coverage Analysis Endpoints
# ============================================================================

@router.get("/coverage")
async def get_coverage_stats(
    current_user: dict = Depends(get_current_user)
):
    """
    Get agent coverage statistics.

    Shows how many assets have agents deployed and identifies
    coverage gaps in critical infrastructure.
    """
    stats = await _linker_service.get_coverage_stats()
    return stats


@router.get("/coverage/gaps")
async def get_coverage_gaps(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of assets without agent coverage.

    Prioritized by criticality - critical assets without agents
    are listed first.
    """
    gaps = await _linker_service.get_uncovered_assets()

    # Filter if specified
    if environment:
        gaps = [g for g in gaps if g.get("environment") == environment]
    if criticality:
        gaps = [g for g in gaps if g.get("criticality") == criticality]

    # Sort by criticality priority
    criticality_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda x: criticality_order.get(x.get("criticality", "low"), 4))

    return {
        "total_gaps": len(gaps),
        "assets": gaps
    }


@router.get("/coverage/report")
async def get_coverage_report(
    current_user: dict = Depends(get_current_user)
):
    """
    Generate comprehensive coverage report.

    Includes coverage by environment, criticality, department,
    and recommendations for improving coverage.
    """
    stats = await _linker_service.get_coverage_stats()
    gaps = await _linker_service.get_uncovered_assets()

    # Count gaps by criticality
    gaps_by_criticality = {}
    for gap in gaps:
        crit = gap.get("criticality", "unknown")
        gaps_by_criticality[crit] = gaps_by_criticality.get(crit, 0) + 1

    # Generate recommendations
    recommendations = []
    if gaps_by_criticality.get("critical", 0) > 0:
        recommendations.append({
            "priority": "high",
            "message": f"Deploy agents to {gaps_by_criticality['critical']} critical assets immediately",
            "action": "Review critical assets in coverage gaps"
        })
    if gaps_by_criticality.get("high", 0) > 0:
        recommendations.append({
            "priority": "medium",
            "message": f"Deploy agents to {gaps_by_criticality['high']} high-criticality assets",
            "action": "Schedule agent deployment for high-value targets"
        })
    if stats.get("total_assets", 0) > 0:
        coverage_pct = (stats.get("assets_with_agents", 0) / stats["total_assets"]) * 100
        if coverage_pct < 80:
            recommendations.append({
                "priority": "medium",
                "message": f"Overall coverage is {coverage_pct:.1f}% - target 80%+",
                "action": "Increase agent deployment across all environments"
            })

    return {
        "summary": stats,
        "gaps_by_criticality": gaps_by_criticality,
        "recommendations": recommendations,
        "generated_at": datetime.utcnow().isoformat()
    }


# ============================================================================
# Auto-Link Trigger Endpoints
# ============================================================================

@router.post("/auto-link")
async def trigger_auto_link(
    current_user: dict = Depends(get_current_user)
):
    """
    Trigger auto-linking for all registered agents.

    Re-runs the matching algorithm to link any unlinked agents
    to their corresponding assets.
    """
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    # Get all registered agents
    linked_count = 0
    errors = []

    try:
        from routes.logs import _registered_agents
        for agent_id, agent_data in _registered_agents.items():
            if agent_id not in _linker_service._links or _linker_service._links[agent_id].asset_id is None:
                try:
                    link = await _linker_service.link_agent_to_asset(
                        agent_id=agent_id,
                        agent_data=agent_data,
                        agent_type="collector"
                    )
                    if link and link.asset_id:
                        linked_count += 1
                except Exception as e:
                    errors.append({"agent_id": agent_id, "error": str(e)})
    except ImportError:
        pass

    # Also check EDR agents
    try:
        from routes.edr import _edr_agents
        for agent_id, agent_data in _edr_agents.items():
            if agent_id not in _linker_service._links or _linker_service._links[agent_id].asset_id is None:
                try:
                    link = await _linker_service.link_agent_to_asset(
                        agent_id=agent_id,
                        agent_data=agent_data,
                        agent_type="edr"
                    )
                    if link and link.asset_id:
                        linked_count += 1
                except Exception as e:
                    errors.append({"agent_id": agent_id, "error": str(e)})
    except ImportError:
        pass

    logger.info(f"[AgentAssets] Auto-link triggered by {current_user.get('username')}: {linked_count} agents linked")

    return {
        "success": True,
        "agents_linked": linked_count,
        "errors": errors if errors else None
    }


# ============================================================================
# Event Enrichment Endpoint
# ============================================================================

@router.post("/enrich-event")
async def enrich_event_with_asset(
    event: Dict[str, Any] = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Enrich an event with asset context.

    Adds asset criticality, owner, environment, and other
    metadata to events based on source host.
    """
    enriched = await _linker_service.enrich_event_with_asset_context(event)
    return enriched


# Export the linker service for use in other modules
def get_linker_service() -> AgentAssetLinkerService:
    """Get the shared linker service instance"""
    return _linker_service
