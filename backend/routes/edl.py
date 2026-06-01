# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
EDL (External Dynamic List) Management Routes

Handles:
- List CRUD (create, read, update, delete)
- Item management (add, remove, bulk operations)
- Credential management (create, list, delete, rotate)
- Access logs and change history
"""

import logging
import re
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field, validator

from services.postgres_db import postgres_db
from services.edl_service import get_edl_service
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/edl", tags=["EDL Management"])


# ============================================================================
# REQUEST MODELS
# ============================================================================

class CreateListRequest(BaseModel):
    """Create a new EDL list."""
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=200, pattern=r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$')
    description: Optional[str] = None
    ioc_type: str = Field(..., pattern=r'^(ip|domain|url)$')
    list_type: str = Field(default='static', pattern=r'^(static|dynamic|hybrid)$')
    max_items: int = Field(default=150000, gt=0, le=1000000)
    ttl_default_seconds: int = Field(default=0, ge=0)
    include_comments: bool = True
    tags: Optional[List[str]] = Field(default=None, description="Tags for categorizing this EDL list")


class UpdateListRequest(BaseModel):
    """Update an existing EDL list."""
    name: Optional[str] = None
    description: Optional[str] = None
    max_items: Optional[int] = Field(default=None, gt=0, le=1000000)
    ttl_default_seconds: Optional[int] = Field(default=None, ge=0)
    include_comments: Optional[bool] = None
    enabled: Optional[bool] = None


class AddItemRequest(BaseModel):
    """Add a single IOC to a list."""
    ioc_value: str = Field(..., min_length=1, max_length=2000)
    comment: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    severity: Optional[str] = None
    ttl_seconds: Optional[int] = Field(default=None, ge=0)
    source_type: str = Field(default='manual')
    source_id: Optional[str] = None


class AddItemsBulkRequest(BaseModel):
    """Add multiple IOCs to a list."""
    values: str = Field(..., min_length=1, description="Newline or comma separated IOC values")
    comment: Optional[str] = None
    ttl_seconds: Optional[int] = Field(default=None, ge=0)
    source_type: str = Field(default='manual')
    source_id: Optional[str] = None
    tags: Optional[List[str]] = Field(default=None, description="Tags to apply to added items")
    classification: Optional[str] = Field(default=None, description="Classification: blacklist, whitelist, suspicious")
    confidence: Optional[str] = Field(default=None, description="Confidence level: high, medium, low")
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Filter: only add IOCs with confidence >= this value")
    severity_filter: Optional[str] = Field(default=None, description="Filter: only add IOCs with this severity")


class RemoveItemRequest(BaseModel):
    """Remove a single IOC from a list."""
    ioc_value: str = Field(..., min_length=1, max_length=2000)
    reason: Optional[str] = None


class RemoveItemsBulkRequest(BaseModel):
    """Remove multiple IOCs from a list."""
    values: str = Field(..., min_length=1, description="Newline or comma separated IOC values")
    reason: Optional[str] = None


class CreateCredentialRequest(BaseModel):
    """Create an access credential for a list."""
    name: str = Field(..., min_length=1, max_length=200)
    auth_type: str = Field(..., pattern=r'^(none|token|basic|ip_allowlist)$')
    description: Optional[str] = None
    expires_at: Optional[str] = None
    ip_allowlist: Optional[List[str]] = None
    basic_username: Optional[str] = None
    basic_password: Optional[str] = None


# ============================================================================
# HELPERS
# ============================================================================

def _parse_values(raw: str) -> List[str]:
    """Parse newline/comma separated values into a clean list."""
    values = []
    for line in raw.strip().split('\n'):
        for part in line.split(','):
            cleaned = part.strip()
            if cleaned and not cleaned.startswith('#'):
                values.append(cleaned)
    return list(set(values))


# ============================================================================
# LIST ROUTES
# ============================================================================

@router.get("/lists")
async def list_edl_lists(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List all EDL lists with pagination and optional type filter."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        result = await svc.list_all(
            tenant_id=tenant_id,
            ioc_type=ioc_type,
            page=page,
            limit=limit,
        )
        return result
    except Exception as e:
        logger.error(f"Failed to list EDL lists: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists")
async def create_edl_list(
    req: CreateListRequest,
    current_user: dict = Depends(get_current_user),
):
    """Create a new EDL list. Type is locked at creation (ip, domain, or url)."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        result = await svc.create_list(
            name=req.name,
            slug=req.slug,
            ioc_type=req.ioc_type,
            description=req.description,
            list_type=req.list_type,
            max_items=req.max_items,
            ttl_default_seconds=req.ttl_default_seconds,
            include_comments=req.include_comments,
            tenant_id=tenant_id,
            created_by=current_user["username"],
            tags=req.tags,
        )
        return {"success": True, "list": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if 'unique' in str(e).lower() or 'duplicate' in str(e).lower():
            raise HTTPException(status_code=409, detail="List with this slug or name already exists")
        logger.error(f"Failed to create EDL list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lists/{list_id}")
async def get_edl_list(
    list_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get details for a specific EDL list."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        result = await svc.get_list(list_id, tenant_id=tenant_id)
        if not result:
            raise HTTPException(status_code=404, detail="List not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get EDL list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/lists/{list_id}")
async def update_edl_list(
    list_id: str,
    req: UpdateListRequest,
    current_user: dict = Depends(get_current_user),
):
    """Update an EDL list (cannot change ioc_type after creation)."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        updates = req.dict(exclude_none=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        result = await svc.update_list(list_id, updates, tenant_id=tenant_id)
        if not result:
            raise HTTPException(status_code=404, detail="List not found")

        return {"success": True, "list": result}
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update EDL list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/lists/{list_id}")
async def delete_edl_list(
    list_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete an EDL list and all associated items, credentials, and logs."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        deleted = await svc.delete_list(list_id, tenant_id=tenant_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="List not found")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete EDL list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ITEM ROUTES
# ============================================================================

@router.get("/lists/{list_id}/items")
async def get_edl_items(
    list_id: str,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
    search: Optional[str] = Query(default=None, max_length=500),
    include_expired: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """Get items in an EDL list with pagination and optional search."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        return await svc.get_items(
            list_id=list_id,
            tenant_id=tenant_id,
            page=page,
            limit=limit,
            include_expired=include_expired,
            search=search,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get EDL items: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/items")
async def add_edl_item(
    list_id: str,
    req: AddItemRequest,
    current_user: dict = Depends(get_current_user),
):
    """Add a single IOC to an EDL list. Value must match the list's IOC type."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        item = await svc.add_item(
            list_id=list_id,
            tenant_id=tenant_id,
            ioc_value=req.ioc_value,
            source_type=req.source_type,
            source_id=req.source_id,
            added_by=current_user["username"],
            comment=req.comment,
            confidence=req.confidence,
            severity=req.severity,
            ttl_seconds=req.ttl_seconds,
        )
        try:
            await svc.generate_content(list_id)
        except Exception:
            pass
        return {"success": True, "item": item}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to add EDL item: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/items/bulk")
async def add_edl_items_bulk(
    list_id: str,
    req: AddItemsBulkRequest,
    current_user: dict = Depends(get_current_user),
):
    """Add multiple IOCs to an EDL list. Invalid values are skipped."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        values = _parse_values(req.values)
        if not values:
            raise HTTPException(status_code=400, detail="No valid values provided")

        # Map string confidence to numeric for filtering
        confidence_float = None
        if req.confidence:
            confidence_map = {'high': 0.9, 'medium': 0.6, 'low': 0.3}
            confidence_float = confidence_map.get(req.confidence)

        result = await svc.add_items_bulk(
            list_id=list_id,
            tenant_id=tenant_id,
            ioc_values=values,
            source_type=req.source_type,
            source_id=req.source_id,
            added_by=current_user["username"],
            comment=req.comment,
            ttl_seconds=req.ttl_seconds,
            confidence=confidence_float,
            severity=req.classification,
        )
        try:
            await svc.generate_content(list_id)
        except Exception:
            pass
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to bulk add EDL items: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/lists/{list_id}/items")
async def remove_edl_item(
    list_id: str,
    req: RemoveItemRequest,
    current_user: dict = Depends(get_current_user),
):
    """Remove a single IOC from an EDL list."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        removed = await svc.remove_item(
            list_id=list_id,
            tenant_id=tenant_id,
            ioc_value=req.ioc_value,
            removed_by=current_user["username"],
            reason=req.reason,
        )
        if not removed:
            raise HTTPException(status_code=404, detail="Item not found in list")
        try:
            await svc.generate_content(list_id)
        except Exception:
            pass
        return {"success": True}
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to remove EDL item: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/items/bulk-remove")
async def remove_edl_items_bulk(
    list_id: str,
    req: RemoveItemsBulkRequest,
    current_user: dict = Depends(get_current_user),
):
    """Remove multiple IOCs from an EDL list."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        values = _parse_values(req.values)
        if not values:
            raise HTTPException(status_code=400, detail="No valid values provided")

        result = await svc.remove_items_bulk(
            list_id=list_id,
            tenant_id=tenant_id,
            ioc_values=values,
            removed_by=current_user["username"],
            reason=req.reason,
        )
        try:
            await svc.generate_content(list_id)
        except Exception:
            pass
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to bulk remove EDL items: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/regenerate")
async def regenerate_edl_content(
    list_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Force regeneration of cached EDL content."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant before regenerating
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        content = await svc.generate_content(list_id)
        line_count = len([l for l in content.split('\n') if l and not l.startswith('#')])
        return {
            "success": True,
            "items_generated": line_count,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to regenerate EDL content: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CREDENTIAL ROUTES
# ============================================================================

@router.get("/lists/{list_id}/credentials")
async def list_edl_credentials(
    list_id: str,
    current_user: dict = Depends(get_current_user),
):
    """List all credentials for an EDL list (secrets redacted)."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        creds = await svc.list_credentials(list_id)
        return {"credentials": creds}
    except Exception as e:
        logger.error(f"Failed to list EDL credentials: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/credentials")
async def create_edl_credential(
    list_id: str,
    req: CreateCredentialRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Create an access credential for an EDL list.
    For token auth, the raw token is returned ONCE in the response.
    """
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        from datetime import datetime
        expires = None
        if req.expires_at:
            expires = datetime.fromisoformat(req.expires_at.replace('Z', '+00:00'))

        svc = get_edl_service()
        # Verify list belongs to tenant
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        result = await svc.create_credential(
            list_id=list_id,
            name=req.name,
            auth_type=req.auth_type,
            created_by=current_user["username"],
            description=req.description,
            expires_at=expires,
            ip_allowlist=req.ip_allowlist,
            basic_username=req.basic_username,
            basic_password=req.basic_password,
        )
        return {"success": True, "credential": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create EDL credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/lists/{list_id}/credentials/{credential_id}")
async def delete_edl_credential(
    list_id: str,
    credential_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete an access credential."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant before deleting credential
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        deleted = await svc.delete_credential(credential_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Credential not found")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete EDL credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/lists/{list_id}/credentials/{credential_id}/rotate")
async def rotate_edl_credential(
    list_id: str,
    credential_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Rotate a token credential. Creates a new token while keeping the old one active.
    Both old and new tokens work during the transition period.
    """
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant before rotating credential
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        result = await svc.rotate_credential(
            credential_id=credential_id,
            created_by=current_user["username"],
        )
        return {"success": True, "credential": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to rotate EDL credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# LOGS & AUDIT ROUTES
# ============================================================================

@router.get("/lists/{list_id}/access-log")
async def get_edl_access_log(
    list_id: str,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    """Get access logs for an EDL list."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        return await svc.get_access_logs(list_id, page=page, limit=limit)
    except Exception as e:
        logger.error(f"Failed to get EDL access log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lists/{list_id}/change-log")
async def get_edl_change_log(
    list_id: str,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    """Get change history for an EDL list."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    tenant_id = str(current_user["tenant_id"])
    try:
        svc = get_edl_service()
        # Verify list belongs to tenant
        edl = await svc.get_list(list_id, tenant_id=tenant_id)
        if not edl:
            raise HTTPException(status_code=404, detail="List not found")
        return await svc.get_change_log(list_id, page=page, limit=limit)
    except Exception as e:
        logger.error(f"Failed to get EDL change log: {e}")
        raise HTTPException(status_code=500, detail=str(e))
