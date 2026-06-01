# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Exclusion List API - Phase 2.1

Manage IOC exclusions for enrichment.
RFC1918 private IPs, internal domains, false positives, etc.
"""

from fastapi import APIRouter, HTTPException, Header, Query, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

from services.exclusion_service import get_exclusion_service, ExclusionCheckResult
from routes.admin import require_admin, get_current_username

router = APIRouter(prefix="/api/v1/exclusions", tags=["exclusions"])


# ==================== MODELS ====================

class MatchType(str, Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    CONTAINS = "contains"
    CIDR = "cidr"
    REGEX = "regex"


class ExclusionCategory(str, Enum):
    INTERNAL = "internal"
    VENDOR = "vendor"
    FALSE_POSITIVE = "false_positive"
    WHITELIST = "whitelist"
    CUSTOM = "custom"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    EMAIL = "email"
    HASH = "hash"
    CIDR = "cidr"
    REGEX = "regex"


class ExclusionCreate(BaseModel):
    """Create a new exclusion"""
    ioc_value: str = Field(..., description="The IOC value to exclude")
    ioc_type: IOCType = Field(IOCType.IP, description="Type of IOC")
    match_type: MatchType = Field(MatchType.EXACT, description="How to match")
    reason: Optional[str] = Field(None, description="Why this is excluded")
    category: ExclusionCategory = Field(ExclusionCategory.CUSTOM, description="Category")
    expires_at: Optional[datetime] = Field(None, description="When exclusion expires")

    class Config:
        json_schema_extra = {
            "example": {
                "ioc_value": "192.168.0.0/16",
                "ioc_type": "cidr",
                "match_type": "cidr",
                "reason": "Internal network",
                "category": "internal"
            }
        }


class BulkExclusionCreate(BaseModel):
    """Bulk create exclusions"""
    entries: List[Dict[str, Any]] = Field(
        ...,
        description="List of exclusions to add"
    )
    default_category: Optional[ExclusionCategory] = Field(
        ExclusionCategory.CUSTOM,
        description="Default category for entries without one"
    )
    default_match_type: Optional[MatchType] = Field(
        MatchType.EXACT,
        description="Default match type"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "entries": [
                    {"ioc_value": "10.0.0.0/8", "ioc_type": "cidr", "match_type": "cidr"},
                    {"ioc_value": "example.local", "ioc_type": "domain"},
                    {"ioc_value": "*.internal.corp", "ioc_type": "domain", "match_type": "regex"}
                ],
                "default_category": "internal"
            }
        }


class ExclusionResponse(BaseModel):
    """Exclusion entry response"""
    id: str
    ioc_value: str
    ioc_type: str
    match_type: str
    reason: Optional[str]
    category: str
    added_by: Optional[str]
    expires_at: Optional[str]
    is_active: bool
    hit_count: int
    last_hit_at: Optional[str]
    created_at: Optional[str]


class ExclusionCheckResponse(BaseModel):
    """Result of checking if an IOC is excluded"""
    is_excluded: bool
    reason: Optional[str] = None
    match_type: Optional[str] = None
    matched_rule_id: Optional[str] = None
    matched_value: Optional[str] = None


# ==================== ENDPOINTS ====================

@router.get("", response_model=List[ExclusionResponse])
async def list_exclusions(
    request: Request,
    ioc_type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    category: Optional[ExclusionCategory] = Query(None, description="Filter by category"),
    include_inactive: bool = Query(False, description="Include inactive exclusions"),
    authorization: str = Header(None)
):
    """List all exclusions with optional filters"""
    await require_admin(request, authorization)

    service = get_exclusion_service()
    exclusions = await service.list_exclusions(
        ioc_type=ioc_type.value if ioc_type else None,
        category=category.value if category else None,
        include_inactive=include_inactive
    )

    return exclusions


@router.post("", response_model=ExclusionResponse)
async def create_exclusion(
    request: Request,
    exclusion: ExclusionCreate,
    authorization: str = Header(None)
):
    """Add a new exclusion"""
    username = await get_current_username(request, authorization)

    service = get_exclusion_service()
    result = await service.add_exclusion(
        ioc_value=exclusion.ioc_value,
        ioc_type=exclusion.ioc_type.value,
        match_type=exclusion.match_type.value,
        reason=exclusion.reason,
        category=exclusion.category.value,
        added_by=username,
        expires_at=exclusion.expires_at
    )

    return result


@router.post("/bulk")
async def bulk_create_exclusions(
    request: Request,
    bulk: BulkExclusionCreate,
    authorization: str = Header(None)
):
    """
    Bulk import exclusions.

    Accepts a list of exclusion entries. Each entry should have at minimum:
    - ioc_value: The value to exclude

    Optional fields per entry:
    - ioc_type: ip, domain, email, hash, cidr, regex (default: auto-detect)
    - match_type: exact, prefix, suffix, contains, cidr, regex (default: exact)
    - reason: Why this is excluded
    - category: internal, vendor, false_positive, whitelist, custom
    """
    username = await get_current_username(request, authorization)

    # Apply defaults
    entries = []
    for entry in bulk.entries:
        e = dict(entry)
        if 'category' not in e and bulk.default_category:
            e['category'] = bulk.default_category.value
        if 'match_type' not in e and bulk.default_match_type:
            e['match_type'] = bulk.default_match_type.value
        if 'ioc_type' not in e:
            e['ioc_type'] = 'auto'
        entries.append(e)

    service = get_exclusion_service()
    result = await service.bulk_add_exclusions(entries, added_by=username)

    return {
        "success": True,
        "added": result["added"],
        "updated": result["updated"],
        "failed": result["failed"],
        "errors": result["errors"]
    }


@router.delete("/{exclusion_id}")
async def delete_exclusion(
    request: Request,
    exclusion_id: str,
    authorization: str = Header(None)
):
    """Remove an exclusion (soft delete)"""
    await require_admin(request, authorization)

    service = get_exclusion_service()
    success = await service.remove_exclusion(exclusion_id)

    if not success:
        raise HTTPException(status_code=404, detail="Exclusion not found")

    return {"success": True, "message": "Exclusion removed"}


@router.get("/check/{ioc_value}", response_model=ExclusionCheckResponse)
async def check_exclusion(
    request: Request,
    ioc_value: str,
    ioc_type: IOCType = Query(IOCType.IP, description="Type of IOC"),
    authorization: str = Header(None)
):
    """
    Check if an IOC is in the exclusion list.

    This is the primary endpoint used by the enrichment system
    to check if an IOC should be enriched.
    """
    await require_admin(request, authorization)

    service = get_exclusion_service()
    result = await service.check_excluded(ioc_value, ioc_type.value)

    return ExclusionCheckResponse(
        is_excluded=result.is_excluded,
        reason=result.reason,
        match_type=result.match_type,
        matched_rule_id=result.matched_rule.id if result.matched_rule else None,
        matched_value=result.matched_rule.ioc_value if result.matched_rule else None
    )


@router.get("/stats")
async def get_exclusion_stats(request: Request, authorization: str = Header(None)):
    """Get exclusion list statistics"""
    await require_admin(request, authorization)

    service = get_exclusion_service()
    return await service.get_stats()


@router.post("/reload")
async def reload_exclusions(request: Request, authorization: str = Header(None)):
    """Force reload exclusions from database (refresh cache)"""
    await require_admin(request, authorization)

    service = get_exclusion_service()
    await service.load_exclusions(force=True)

    return {
        "success": True,
        "message": "Exclusion list reloaded",
        "stats": await service.get_stats()
    }


# ==================== CONVENIENCE ENDPOINTS ====================

@router.post("/add-cidr")
async def add_cidr_exclusion(
    request: Request,
    cidr: str = Query(..., description="CIDR notation (e.g., 192.168.0.0/16)"),
    reason: Optional[str] = Query(None, description="Reason for exclusion"),
    category: ExclusionCategory = Query(ExclusionCategory.INTERNAL, description="Category"),
    authorization: str = Header(None)
):
    """Quick add a CIDR range to exclusions"""
    username = await get_current_username(request, authorization)

    # Validate CIDR format
    import ipaddress
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR notation: {cidr}")

    service = get_exclusion_service()
    result = await service.add_exclusion(
        ioc_value=cidr,
        ioc_type="cidr",
        match_type="cidr",
        reason=reason or f"CIDR range {cidr}",
        category=category.value,
        added_by=username
    )

    return result


@router.post("/add-domain-pattern")
async def add_domain_pattern(
    request: Request,
    pattern: str = Query(..., description="Domain pattern (e.g., *.internal.corp)"),
    reason: Optional[str] = Query(None, description="Reason for exclusion"),
    category: ExclusionCategory = Query(ExclusionCategory.INTERNAL, description="Category"),
    authorization: str = Header(None)
):
    """Quick add a domain wildcard pattern to exclusions"""
    username = await get_current_username(request, authorization)

    service = get_exclusion_service()
    result = await service.add_exclusion(
        ioc_value=pattern,
        ioc_type="domain",
        match_type="regex" if "*" in pattern else "exact",
        reason=reason or f"Domain pattern {pattern}",
        category=category.value,
        added_by=username
    )

    return result
