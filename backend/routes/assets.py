# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Asset Management API Routes
Phase 9: CMDB & Asset Discovery

Provides REST endpoints for asset CRUD, lookup, relationships, and history.
"""

from fastapi import APIRouter, HTTPException, Query, Body, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

import logging
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assets", tags=["assets"], dependencies=[Depends(get_current_user)])


def get_asset_service_with_db():
    """Get the asset service with database connection"""
    from services.asset_service import get_asset_service
    from services.postgres_db import postgres_db
    service = get_asset_service()
    service.set_db(postgres_db)
    return service


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class AssetCreate(BaseModel):
    """Request model for creating an asset"""
    asset_type: str = Field(default="unknown", description="Type of asset")
    hostname: Optional[str] = Field(None, description="Primary hostname")
    fqdn: Optional[str] = Field(None, description="Fully qualified domain name")
    display_name: Optional[str] = Field(None, description="Display name")
    ip_addresses: Optional[List[str]] = Field(default=[], description="IP addresses")
    mac_addresses: Optional[List[str]] = Field(default=[], description="MAC addresses")
    os_family: Optional[str] = Field(None, description="OS family (windows, linux, etc)")
    os_name: Optional[str] = Field(None, description="Full OS name")
    os_version: Optional[str] = Field(None, description="OS version")
    criticality: str = Field(default="tier4", description="Criticality tier")
    status: str = Field(default="active", description="Asset status")
    environment: str = Field(default="unknown", description="Environment")
    owner: Optional[str] = Field(None, description="Asset owner")
    owner_team: Optional[str] = Field(None, description="Owning team")
    department: Optional[str] = Field(None, description="Department")
    location: Optional[str] = Field(None, description="Physical/logical location")
    compliance_tags: Optional[List[str]] = Field(default=[], description="Compliance tags")
    custom_tags: Optional[List[str]] = Field(default=[], description="Custom tags")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Additional metadata")


class AssetUpdate(BaseModel):
    """Request model for updating an asset"""
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    display_name: Optional[str] = None
    asset_type: Optional[str] = None
    ip_addresses: Optional[List[str]] = None
    mac_addresses: Optional[List[str]] = None
    os_family: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    owner_team: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    compliance_tags: Optional[List[str]] = None
    custom_tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class IdentifierCreate(BaseModel):
    """Request model for adding an identifier"""
    identifier_type: str = Field(..., description="Type of identifier")
    identifier_value: str = Field(..., description="Identifier value")
    source: Optional[str] = Field(None, description="Source of this identifier")
    is_primary: bool = Field(default=False, description="Is primary identifier")
    confidence: int = Field(default=100, description="Confidence score 0-100")


class RelationshipCreate(BaseModel):
    """Request model for creating a relationship"""
    target_asset_id: str = Field(..., description="Target asset ID")
    relationship_type: str = Field(..., description="Type of relationship")
    discovered_by: Optional[str] = Field(None, description="Discovery source")
    confidence: int = Field(default=100, description="Confidence score")
    bidirectional: bool = Field(default=False, description="Is bidirectional")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Relationship metadata")


class AssetLookup(BaseModel):
    """Request model for asset lookup"""
    ip: Optional[str] = Field(None, description="IP address to lookup")
    hostname: Optional[str] = Field(None, description="Hostname to lookup")
    identifier_type: Optional[str] = Field(None, description="Identifier type")
    identifier_value: Optional[str] = Field(None, description="Identifier value")


# =============================================================================
# ASSET CRUD ENDPOINTS
# =============================================================================

@router.post("", response_model=Dict[str, Any])
async def create_asset(asset: AssetCreate):
    """Create a new asset"""
    service = get_asset_service_with_db()

    result = await service.create_asset(
        asset_type=asset.asset_type,
        hostname=asset.hostname,
        fqdn=asset.fqdn,
        display_name=asset.display_name,
        ip_addresses=asset.ip_addresses,
        mac_addresses=asset.mac_addresses,
        os_family=asset.os_family,
        os_name=asset.os_name,
        os_version=asset.os_version,
        criticality=asset.criticality,
        status=asset.status,
        environment=asset.environment,
        owner=asset.owner,
        owner_team=asset.owner_team,
        department=asset.department,
        location=asset.location,
        compliance_tags=asset.compliance_tags,
        custom_tags=asset.custom_tags,
        metadata=asset.metadata,
        created_by="api",
        source="manual"
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to create asset")

    return result


@router.get("", response_model=Dict[str, Any])
async def list_assets(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    asset_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    include_decommissioned: bool = Query(default=False)
):
    """List assets with filtering"""
    service = get_asset_service_with_db()

    assets, total = await service.list_assets(
        limit=limit,
        offset=offset,
        asset_type=asset_type,
        criticality=criticality,
        status=status,
        environment=environment,
        owner=owner,
        department=department,
        search=search,
        include_decommissioned=include_decommissioned
    )

    return {
        "assets": assets,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_asset_stats():
    """Get asset statistics"""
    service = get_asset_service_with_db()

    stats = await service.get_asset_stats()
    return stats


@router.get("/{asset_id}", response_model=Dict[str, Any])
async def get_asset(asset_id: str):
    """Get a single asset by ID"""
    service = get_asset_service_with_db()

    asset = await service.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return asset


@router.patch("/{asset_id}", response_model=Dict[str, Any])
async def update_asset(asset_id: str, updates: AssetUpdate):
    """Update an asset"""
    service = get_asset_service_with_db()

    # Filter out None values
    update_dict = {k: v for k, v in updates.dict().items() if v is not None}

    if not update_dict:
        raise HTTPException(status_code=400, detail="No updates provided")

    result = await service.update_asset(
        asset_id=asset_id,
        updates=update_dict,
        updated_by="api"
    )

    if not result:
        raise HTTPException(status_code=404, detail="Asset not found or update failed")

    return result


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str, hard_delete: bool = Query(default=False)):
    """Delete an asset (soft delete by default)"""
    service = get_asset_service_with_db()

    success = await service.delete_asset(asset_id, hard_delete=hard_delete)

    if not success:
        raise HTTPException(status_code=404, detail="Asset not found or delete failed")

    return {"message": "Asset deleted" if hard_delete else "Asset decommissioned"}


# =============================================================================
# ASSET LOOKUP ENDPOINTS
# =============================================================================

@router.post("/lookup", response_model=Dict[str, Any])
async def lookup_asset(lookup: AssetLookup):
    """
    Lookup an asset by IP, hostname, or identifier.
    Used for investigation enrichment.
    """
    service = get_asset_service_with_db()

    asset = await service.lookup_asset(
        ip=lookup.ip,
        hostname=lookup.hostname,
        identifier_type=lookup.identifier_type,
        identifier_value=lookup.identifier_value
    )

    if not asset:
        return {"found": False, "asset": None}

    return {"found": True, "asset": asset}


@router.get("/lookup/ip/{ip_address}", response_model=Dict[str, Any])
async def lookup_by_ip(ip_address: str):
    """Quick lookup by IP address"""
    service = get_asset_service_with_db()

    asset = await service.find_asset_by_ip(ip_address)

    if not asset:
        return {"found": False, "asset": None}

    return {"found": True, "asset": asset}


@router.get("/lookup/hostname/{hostname}", response_model=Dict[str, Any])
async def lookup_by_hostname(hostname: str):
    """Quick lookup by hostname"""
    service = get_asset_service_with_db()

    asset = await service.find_asset_by_hostname(hostname)

    if not asset:
        return {"found": False, "asset": None}

    return {"found": True, "asset": asset}


# =============================================================================
# IDENTIFIER ENDPOINTS
# =============================================================================

@router.get("/{asset_id}/identifiers", response_model=Dict[str, Any])
async def get_asset_identifiers(asset_id: str):
    """Get all identifiers for an asset"""
    service = get_asset_service_with_db()

    identifiers = await service.get_asset_identifiers(asset_id)

    return {"identifiers": identifiers}


@router.post("/{asset_id}/identifiers", response_model=Dict[str, Any])
async def add_asset_identifier(asset_id: str, identifier: IdentifierCreate):
    """Add an identifier to an asset"""
    service = get_asset_service_with_db()

    result = await service.add_identifier(
        asset_id=asset_id,
        identifier_type=identifier.identifier_type,
        identifier_value=identifier.identifier_value,
        source=identifier.source or "manual",
        is_primary=identifier.is_primary,
        confidence=identifier.confidence
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to add identifier")

    return result


# =============================================================================
# RELATIONSHIP ENDPOINTS
# =============================================================================

@router.get("/{asset_id}/relationships", response_model=Dict[str, Any])
async def get_asset_relationships(
    asset_id: str,
    direction: str = Query(default="both", enum=["outgoing", "incoming", "both"])
):
    """Get relationships for an asset"""
    service = get_asset_service_with_db()

    relationships = await service.get_asset_relationships(asset_id, direction=direction)

    return {"relationships": relationships}


@router.post("/{asset_id}/relationships", response_model=Dict[str, Any])
async def add_asset_relationship(asset_id: str, relationship: RelationshipCreate):
    """Add a relationship from this asset to another"""
    service = get_asset_service_with_db()

    result = await service.add_relationship(
        source_asset_id=asset_id,
        target_asset_id=relationship.target_asset_id,
        relationship_type=relationship.relationship_type,
        discovered_by=relationship.discovered_by or "manual",
        confidence=relationship.confidence,
        bidirectional=relationship.bidirectional,
        metadata=relationship.metadata
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to add relationship")

    return result


# =============================================================================
# HISTORY ENDPOINTS
# =============================================================================

@router.get("/{asset_id}/history", response_model=Dict[str, Any])
async def get_asset_history(
    asset_id: str,
    limit: int = Query(default=50, ge=1, le=200)
):
    """Get change history for an asset"""
    service = get_asset_service_with_db()

    history = await service.get_asset_history(asset_id, limit=limit)

    return {"history": history}


# =============================================================================
# BULK OPERATIONS
# =============================================================================

@router.post("/bulk/import", response_model=Dict[str, Any])
async def bulk_import_assets(assets: List[AssetCreate]):
    """Import multiple assets at once"""
    service = get_asset_service_with_db()

    created = 0
    failed = 0
    errors = []

    for asset_data in assets:
        try:
            result = await service.create_asset(
                asset_type=asset_data.asset_type,
                hostname=asset_data.hostname,
                fqdn=asset_data.fqdn,
                display_name=asset_data.display_name,
                ip_addresses=asset_data.ip_addresses,
                mac_addresses=asset_data.mac_addresses,
                os_family=asset_data.os_family,
                os_name=asset_data.os_name,
                os_version=asset_data.os_version,
                criticality=asset_data.criticality,
                status=asset_data.status,
                environment=asset_data.environment,
                owner=asset_data.owner,
                owner_team=asset_data.owner_team,
                department=asset_data.department,
                location=asset_data.location,
                compliance_tags=asset_data.compliance_tags,
                custom_tags=asset_data.custom_tags,
                metadata=asset_data.metadata,
                created_by="bulk_import",
                source="bulk_import"
            )
            if result:
                created += 1
            else:
                failed += 1
                errors.append(f"Failed to create: {asset_data.hostname or asset_data.fqdn}")
        except Exception as e:
            failed += 1
            errors.append(f"{asset_data.hostname or asset_data.fqdn}: {str(e)}")

    return {
        "total": len(assets),
        "created": created,
        "failed": failed,
        "errors": errors[:10]  # Limit error messages
    }


# =============================================================================
# INVESTIGATION ENRICHMENT ENDPOINTS (Phase 9.4)
# =============================================================================

class InvestigationEnrichRequest(BaseModel):
    """Request model for investigation enrichment"""
    investigation_id: str = Field(..., description="Investigation ID to enrich")
    alert_data: Optional[Dict[str, Any]] = Field(None, description="Alert data to extract indicators from")


@router.post("/enrich-investigation", response_model=Dict[str, Any])
async def enrich_investigation_with_assets(request: InvestigationEnrichRequest):
    """
    Enrich an investigation with asset data from CMDB.
    Looks up IPs/hostnames in the alert and matches to known assets.
    Also applies priority boost based on asset criticality.
    """
    from services.asset_investigation_enrichment import get_asset_enrichment_service
    from services.postgres_db import postgres_db

    service = get_asset_service_with_db()
    enrichment = get_asset_enrichment_service()
    enrichment.set_db(postgres_db)
    enrichment.set_asset_service(service)

    # If no alert_data provided, try to get it from the investigation
    alert_data = request.alert_data
    import uuid as uuid_module

    # Convert investigation_id to UUID if it's a valid UUID
    inv_uuid = None
    try:
        inv_uuid = uuid_module.UUID(request.investigation_id)
    except ValueError:
        pass  # Not a UUID, will try as investigation_id string

    if not alert_data:
        import json
        async with postgres_db.tenant_acquire() as conn:
            # Get investigation and its alert
            if inv_uuid:
                inv_row = await conn.fetchrow(
                    'SELECT * FROM investigations WHERE id = $1',
                    inv_uuid
                )
            else:
                inv_row = await conn.fetchrow(
                    'SELECT * FROM investigations WHERE investigation_id = $1',
                    request.investigation_id
                )
            if not inv_row:
                raise HTTPException(status_code=404, detail="Investigation not found")

            investigation = dict(inv_row)
            alert_id = investigation.get('alert_id')

            if alert_id:
                # alert_id can be UUID or string
                try:
                    alert_uuid = uuid_module.UUID(str(alert_id))
                    alert_row = await conn.fetchrow(
                        'SELECT * FROM alerts WHERE id = $1',
                        alert_uuid
                    )
                except ValueError:
                    alert_row = await conn.fetchrow(
                        'SELECT * FROM alerts WHERE alert_id = $1',
                        str(alert_id)
                    )
                if alert_row:
                    alert = dict(alert_row)
                    raw_event = alert.get('raw_event', {})
                    if isinstance(raw_event, str):
                        raw_event = json.loads(raw_event)
                    alert_data = {
                        **raw_event,
                        'title': alert.get('title'),
                        'description': alert.get('description')
                    }

    if not alert_data:
        alert_data = {}

    # Get current priority
    async with postgres_db.tenant_acquire() as conn:
        if inv_uuid:
            row = await conn.fetchrow(
                'SELECT priority FROM investigations WHERE id = $1',
                inv_uuid
            )
        else:
            row = await conn.fetchrow(
                'SELECT priority FROM investigations WHERE investigation_id = $1',
                request.investigation_id
            )
        current_priority = row['priority'] if row else 'P3'

    result = await enrichment.enrich_investigation(
        request.investigation_id,
        alert_data,
        current_priority
    )

    if not result.get('success'):
        raise HTTPException(status_code=500, detail=result.get('error', 'Enrichment failed'))

    return result


@router.post("/extract-indicators", response_model=Dict[str, Any])
async def extract_indicators_from_data(data: Dict[str, Any] = Body(...)):
    """
    Extract IP addresses and hostnames from any data payload.
    Useful for testing indicator extraction without creating assets.
    """
    from services.asset_investigation_enrichment import get_asset_enrichment_service

    enrichment = get_asset_enrichment_service()
    indicators = enrichment.extract_indicators(data)

    return {
        "ips": indicators['ips'],
        "hostnames": indicators['hostnames'],
        "total_indicators": len(indicators['ips']) + len(indicators['hostnames'])
    }


@router.post("/lookup-from-data", response_model=Dict[str, Any])
async def lookup_assets_from_data(data: Dict[str, Any] = Body(...)):
    """
    Extract indicators from data and lookup matching assets.
    Returns matched assets with enrichment context.
    """
    from services.asset_investigation_enrichment import get_asset_enrichment_service
    from services.postgres_db import postgres_db

    service = get_asset_service_with_db()
    enrichment = get_asset_enrichment_service()
    enrichment.set_db(postgres_db)
    enrichment.set_asset_service(service)

    result = await enrichment.enrich_alert(data)

    return {
        "extracted_indicators": result['extracted_indicators'],
        "matched_assets_count": result['asset_context']['asset_count'],
        "asset_context": result['asset_context'],
        "priority_boost": result['priority_boost'],
        "priority_boost_reason": result['priority_boost_reason']
    }
