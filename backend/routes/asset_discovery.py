# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Asset Discovery API Routes
Phase 9.2: CMDB & Asset Discovery

Provides REST endpoints for discovery source management and execution.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

import logging
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/asset-discovery", tags=["asset-discovery"], dependencies=[Depends(get_current_user)])


def get_orchestrator_with_deps():
    """Get the discovery orchestrator with database and asset service"""
    from services.discovery_orchestrator import get_discovery_orchestrator
    from services.asset_service import get_asset_service
    from services.postgres_db import postgres_db

    orchestrator = get_discovery_orchestrator()
    orchestrator.set_db(postgres_db)

    asset_service = get_asset_service()
    asset_service.set_db(postgres_db)
    orchestrator.set_asset_service(asset_service)

    return orchestrator


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class DiscoverySourceCreate(BaseModel):
    """Request model for creating a discovery source"""
    source_type: str = Field(..., description="Type of discovery source")
    name: str = Field(..., description="Display name")
    config: Dict[str, Any] = Field(default={}, description="Source configuration")
    schedule_cron: Optional[str] = Field(None, description="Cron schedule for auto-discovery")
    priority: int = Field(default=50, ge=1, le=100, description="Source priority")
    enabled: bool = Field(default=True, description="Whether source is enabled")


class DiscoverySourceUpdate(BaseModel):
    """Request model for updating a discovery source"""
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    schedule_cron: Optional[str] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None


class ConflictResolution(BaseModel):
    """Request model for resolving a conflict"""
    resolution: Dict[str, Any] = Field(..., description="Resolved asset data")
    resolved_by: str = Field(default="api", description="Who resolved the conflict")


# =============================================================================
# DISCOVERY SOURCE MANAGEMENT
# =============================================================================

@router.get("/sources", response_model=Dict[str, Any])
async def list_discovery_sources(
    enabled_only: bool = Query(default=False, description="Only return enabled sources")
):
    """List all discovery sources"""
    try:
        orchestrator = get_orchestrator_with_deps()
        sources = await orchestrator.get_discovery_sources(enabled_only=enabled_only)

        return {"sources": sources, "total": len(sources)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in list_discovery_sources: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/sources", response_model=Dict[str, Any])
async def create_discovery_source(source: DiscoverySourceCreate):
    """Create a new discovery source"""
    try:
        orchestrator = get_orchestrator_with_deps()

        result = await orchestrator.create_discovery_source(
            source_type=source.source_type,
            name=source.name,
            config=source.config,
            schedule_cron=source.schedule_cron,
            priority=source.priority,
            enabled=source.enabled
        )

        if not result:
            raise HTTPException(status_code=500, detail="Failed to create discovery source")

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in create_discovery_source: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sources/{source_id}", response_model=Dict[str, Any])
async def get_discovery_source(source_id: str):
    """Get a single discovery source"""
    try:
        orchestrator = get_orchestrator_with_deps()
        sources = await orchestrator.get_discovery_sources()

        source = next((s for s in sources if s["id"] == source_id), None)

        if not source:
            raise HTTPException(status_code=404, detail="Discovery source not found")

        return source
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_discovery_source: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.patch("/sources/{source_id}", response_model=Dict[str, Any])
async def update_discovery_source(source_id: str, updates: DiscoverySourceUpdate):
    """Update a discovery source"""
    try:
        orchestrator = get_orchestrator_with_deps()

        update_dict = {k: v for k, v in updates.dict().items() if v is not None}

        if not update_dict:
            raise HTTPException(status_code=400, detail="No updates provided")

        result = await orchestrator.update_discovery_source(source_id, update_dict)

        if not result:
            raise HTTPException(status_code=404, detail="Discovery source not found or update failed")

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in update_discovery_source: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/sources/{source_id}")
async def delete_discovery_source(source_id: str):
    """Delete a discovery source"""
    try:
        orchestrator = get_orchestrator_with_deps()

        success = await orchestrator.delete_discovery_source(source_id)

        if not success:
            raise HTTPException(status_code=404, detail="Discovery source not found")

        return {"message": "Discovery source deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in delete_discovery_source: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# DISCOVERY EXECUTION
# =============================================================================

@router.post("/run/{source_id}", response_model=Dict[str, Any])
async def run_discovery(
    source_id: str,
    triggered_by: str = Query(default="api", description="Who triggered the discovery")
):
    """Run discovery for a specific source"""
    try:
        orchestrator = get_orchestrator_with_deps()

        result = await orchestrator.run_discovery(source_id, triggered_by=triggered_by)

        if not result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=result.get("error", "Discovery failed")
            )

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in run_discovery: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/run-all", response_model=Dict[str, Any])
async def run_all_discoveries(
    triggered_by: str = Query(default="api", description="Who triggered the discovery")
):
    """Run discovery for all enabled sources"""
    try:
        orchestrator = get_orchestrator_with_deps()

        sources = await orchestrator.get_discovery_sources(enabled_only=True)

        results = []
        for source in sources:
            result = await orchestrator.run_discovery(source["id"], triggered_by=triggered_by)
            results.append({
                "source_id": source["id"],
                "source_name": source["name"],
                **result
            })

        successful = len([r for r in results if r.get("success")])

        return {
            "total_sources": len(sources),
            "successful": successful,
            "failed": len(sources) - successful,
            "results": results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in run_all_discoveries: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# DISCOVERY HISTORY
# =============================================================================

@router.get("/history", response_model=Dict[str, Any])
async def get_discovery_history(
    source_id: Optional[str] = Query(None, description="Filter by source ID"),
    limit: int = Query(default=50, ge=1, le=200)
):
    """Get discovery run history"""
    try:
        orchestrator = get_orchestrator_with_deps()

        history = await orchestrator.get_discovery_history(source_id=source_id, limit=limit)

        return {"history": history, "total": len(history)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_discovery_history: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# CONFLICT MANAGEMENT
# =============================================================================

@router.get("/conflicts", response_model=Dict[str, Any])
async def get_pending_conflicts(
    limit: int = Query(default=50, ge=1, le=200)
):
    """Get pending asset conflicts"""
    try:
        orchestrator = get_orchestrator_with_deps()

        conflicts = await orchestrator.get_pending_conflicts(limit=limit)

        return {"conflicts": conflicts, "total": len(conflicts)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_pending_conflicts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/conflicts/{conflict_id}/resolve", response_model=Dict[str, Any])
async def resolve_conflict(conflict_id: str, resolution: ConflictResolution):
    """Resolve an asset conflict"""
    try:
        orchestrator = get_orchestrator_with_deps()

        success = await orchestrator.resolve_conflict(
            conflict_id=conflict_id,
            resolution=resolution.resolution,
            resolved_by=resolution.resolved_by
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to resolve conflict")

        return {"message": "Conflict resolved"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in resolve_conflict: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# STATISTICS
# =============================================================================

@router.get("/stats", response_model=Dict[str, Any])
async def get_discovery_stats():
    """Get discovery statistics"""
    try:
        orchestrator = get_orchestrator_with_deps()

        stats = await orchestrator.get_discovery_stats()

        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_discovery_stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# SOURCE TYPES
# =============================================================================

@router.get("/source-types", response_model=Dict[str, Any])
async def get_source_types():
    """Get available discovery source types"""
    try:
        return {
            "source_types": [
            {
                "type": "crowdstrike",
                "name": "CrowdStrike Falcon",
                "description": "Discover endpoints from CrowdStrike Falcon",
                "config_schema": {
                    "integration_id": {"type": "string", "description": "CrowdStrike integration ID"}
                }
            },
            {
                "type": "aws",
                "name": "AWS EC2",
                "description": "Discover EC2 instances from AWS",
                "config_schema": {
                    "integration_id": {"type": "string", "description": "AWS integration ID"},
                    "regions": {"type": "array", "description": "AWS regions to scan"}
                }
            },
            {
                "type": "azure",
                "name": "Azure VMs",
                "description": "Discover virtual machines from Azure",
                "config_schema": {
                    "integration_id": {"type": "string", "description": "Azure integration ID"},
                    "subscriptions": {"type": "array", "description": "Azure subscription IDs"}
                }
            },
            {
                "type": "active_directory",
                "name": "Active Directory",
                "description": "Discover computers from Active Directory",
                "config_schema": {
                    "ldap_server": {"type": "string", "description": "LDAP server address"},
                    "base_dn": {"type": "string", "description": "Base DN for search"}
                }
            },
            {
                "type": "vmware",
                "name": "VMware vSphere",
                "description": "Discover VMs from VMware vCenter",
                "config_schema": {
                    "vcenter_url": {"type": "string", "description": "vCenter URL"}
                }
            },
            {
                "type": "network_scan",
                "name": "Network Scan",
                "description": "Discover assets via network scanning",
                "config_schema": {
                    "subnets": {"type": "array", "description": "CIDR subnets to scan"},
                    "ports": {"type": "array", "description": "Ports to probe"}
                }
            },
            {
                "type": "custom",
                "name": "Custom Source",
                "description": "Custom discovery via API or webhook",
                "config_schema": {
                    "webhook_url": {"type": "string", "description": "Webhook URL for push discovery"}
                }
            }
        ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_source_types: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
