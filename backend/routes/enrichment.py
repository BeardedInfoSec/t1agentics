# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enrichment Cache API - Phase 2.2

Manage enrichment cache for IOC lookups.
View stats, invalidate entries, configure TTL.
"""

from fastapi import APIRouter, HTTPException, Header, Query, Request, Depends
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

from services.enrichment_cache import get_cache_service
from routes.admin import require_admin, get_current_username
from dependencies.auth import get_current_user

router = APIRouter(prefix="/api/v1/enrichment", tags=["enrichment"], dependencies=[Depends(get_current_user)])


# ==================== MODELS ====================

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class CacheEntryResponse(BaseModel):
    """A cached enrichment entry"""
    id: str
    ioc_type: str
    ioc_value: str
    provider: str
    is_malicious: Optional[bool]
    threat_score: Optional[int]
    confidence: Optional[float]
    cached_at: str
    expires_at: str
    hit_count: int
    is_expired: bool
    is_stale: bool
    ttl_remaining_seconds: int


class CacheLookupRequest(BaseModel):
    """Request to look up cached enrichment"""
    ioc_value: str = Field(..., description="The IOC value to look up")
    ioc_type: IOCType = Field(..., description="Type of IOC")
    provider: Optional[str] = Field(None, description="Specific provider to check")


class CacheStoreRequest(BaseModel):
    """Request to store enrichment in cache"""
    ioc_value: str = Field(..., description="The IOC value")
    ioc_type: IOCType = Field(..., description="Type of IOC")
    provider: str = Field(..., description="Provider name")
    data: Dict[str, Any] = Field(..., description="Enrichment data")
    is_malicious: Optional[bool] = Field(None, description="Whether IOC is malicious")
    threat_score: Optional[int] = Field(None, ge=0, le=100, description="Threat score 0-100")
    confidence: Optional[float] = Field(None, ge=0, le=1, description="Confidence 0-1")
    ttl_days: Optional[int] = Field(None, description="Override TTL in days")


class TTLConfigRequest(BaseModel):
    """Request to configure TTL"""
    ioc_type: IOCType
    ttl_days: int = Field(..., ge=1, le=365, description="TTL in days (1-365)")


# ==================== ENDPOINTS ====================

@router.get("/cache/stats")
async def get_cache_stats(request: Request, authorization: str = Header(None)):
    """Get enrichment cache statistics"""
    await require_admin(request, authorization)

    cache = get_cache_service()
    stats = await cache.get_stats()

    return {
        "success": True,
        "stats": stats
    }


@router.get("/cache/lookup")
async def lookup_cached_enrichment(
    request: Request,
    ioc_value: str = Query(..., description="IOC value to look up"),
    ioc_type: IOCType = Query(..., description="Type of IOC"),
    provider: Optional[str] = Query(None, description="Specific provider"),
    authorization: str = Header(None)
):
    """
    Look up cached enrichment for an IOC.

    Returns cached data if found and not expired.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    result = await cache.get(ioc_value, ioc_type.value, provider)

    if not result.found:
        return {
            "found": False,
            "ioc_value": ioc_value,
            "ioc_type": ioc_type.value
        }

    return {
        "found": True,
        "is_expired": result.is_expired,
        "is_stale": result.is_stale,
        "ttl_remaining_seconds": result.ttl_remaining_seconds,
        "data": {
            "id": result.data.id,
            "ioc_type": result.data.ioc_type,
            "ioc_value": result.data.ioc_value,
            "provider": result.data.provider,
            "enrichment_data": result.data.enrichment_data,
            "is_malicious": result.data.is_malicious,
            "threat_score": result.data.threat_score,
            "confidence": result.data.confidence,
            "cached_at": result.data.cached_at.isoformat() if result.data.cached_at else None,
            "expires_at": result.data.expires_at.isoformat() if result.data.expires_at else None,
            "hit_count": result.data.hit_count
        }
    }


@router.get("/cache/providers/{ioc_value}")
async def get_all_provider_results(
    request: Request,
    ioc_value: str,
    ioc_type: IOCType = Query(..., description="Type of IOC"),
    authorization: str = Header(None)
):
    """
    Get cached enrichment results from all providers for an IOC.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    results = await cache.get_all_providers(ioc_value, ioc_type.value)

    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type.value,
        "provider_count": len(results),
        "results": [
            {
                "provider": r.provider,
                "is_malicious": r.is_malicious,
                "threat_score": r.threat_score,
                "confidence": r.confidence,
                "cached_at": r.cached_at.isoformat() if r.cached_at else None,
                "hit_count": r.hit_count,
                "enrichment_data": r.enrichment_data
            }
            for r in results
        ]
    }


@router.post("/cache/store")
async def store_enrichment(
    request: Request,
    body: CacheStoreRequest,
    authorization: str = Header(None)
):
    """
    Manually store an enrichment result in cache.

    Useful for importing enrichment data or testing.
    """
    username = await get_current_username(request, authorization)

    cache = get_cache_service()
    entry_id = await cache.store(
        ioc_value=body.ioc_value,
        ioc_type=body.ioc_type.value,
        provider=body.provider,
        data=body.data,
        is_malicious=body.is_malicious,
        threat_score=body.threat_score,
        confidence=body.confidence,
        ttl_days=body.ttl_days
    )

    return {
        "success": True,
        "cache_entry_id": entry_id,
        "ioc_value": body.ioc_value,
        "provider": body.provider
    }


@router.delete("/cache/invalidate")
async def invalidate_cache(
    request: Request,
    ioc_value: str = Query(..., description="IOC value to invalidate"),
    ioc_type: IOCType = Query(..., description="Type of IOC"),
    provider: Optional[str] = Query(None, description="Specific provider to invalidate"),
    authorization: str = Header(None)
):
    """
    Invalidate (delete) cached enrichment for an IOC.

    Use when enrichment data is known to be stale or incorrect.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    deleted_count = await cache.invalidate(ioc_value, ioc_type.value, provider)

    return {
        "success": True,
        "deleted_count": deleted_count,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type.value,
        "provider": provider
    }


@router.post("/cache/cleanup")
async def cleanup_expired(request: Request, authorization: str = Header(None)):
    """
    Delete all expired cache entries.

    Should be run periodically to keep cache size manageable.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    deleted_count = await cache.cleanup_expired()

    return {
        "success": True,
        "deleted_count": deleted_count,
        "message": f"Cleaned up {deleted_count} expired cache entries"
    }


@router.get("/cache/ttl")
async def get_ttl_config(request: Request, authorization: str = Header(None)):
    """Get current TTL configuration for each IOC type"""
    await require_admin(request, authorization)

    cache = get_cache_service()

    return {
        "ttl_config": cache.ttl_config,
        "description": {
            "ip": "IP addresses - can change quickly (default: 7 days)",
            "domain": "Domains - relatively stable (default: 14 days)",
            "hash": "File hashes - rarely change (default: 30 days)",
            "url": "URLs - pages change frequently (default: 1 day)",
            "email": "Email addresses - stable (default: 30 days)"
        }
    }


@router.post("/cache/ttl")
async def set_ttl_config(
    request: Request,
    body: TTLConfigRequest,
    authorization: str = Header(None)
):
    """
    Set TTL for a specific IOC type.

    Changes apply to new cache entries only.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    old_ttl = cache.get_ttl_days(body.ioc_type.value)
    cache.set_ttl(body.ioc_type.value, body.ttl_days)

    return {
        "success": True,
        "ioc_type": body.ioc_type.value,
        "old_ttl_days": old_ttl,
        "new_ttl_days": body.ttl_days
    }


@router.get("/cache/by-provider/{provider}")
async def get_cache_by_provider(
    request: Request,
    provider: str,
    limit: int = Query(100, ge=1, le=1000),
    authorization: str = Header(None)
):
    """
    Get cached entries for a specific provider.

    Useful for debugging provider-specific caching issues.
    """
    await require_admin(request, authorization)

    cache = get_cache_service()
    entries = await cache.get_by_provider(provider, limit)

    return {
        "provider": provider,
        "entry_count": len(entries),
        "entries": [
            {
                "id": e.id,
                "ioc_type": e.ioc_type,
                "ioc_value": e.ioc_value,
                "is_malicious": e.is_malicious,
                "threat_score": e.threat_score,
                "cached_at": e.cached_at.isoformat() if e.cached_at else None,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "hit_count": e.hit_count
            }
            for e in entries
        ]
    }


# ==================== ALERT ENRICHMENT ====================

@router.get("/alerts/missing")
async def get_alerts_missing_enrichment(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    authorization: str = Header(None)
):
    """
    Get alerts that are missing enrichment data.

    These alerts were created before auto-enrichment was added or had enrichment failures.
    """
    await require_admin(request, authorization)

    try:
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Find alerts where raw_event doesn't have _extracted.enrichment
            rows = await conn.fetch("""
                SELECT alert_id, title, source, severity, created_at,
                       (raw_event::jsonb->'_extracted'->'enrichment') IS NOT NULL as has_enrichment
                FROM alerts
                WHERE (raw_event::jsonb->'_extracted'->'enrichment') IS NULL
                ORDER BY created_at DESC
                LIMIT $1
            """, limit)

            return {
                "count": len(rows),
                "alerts": [
                    {
                        "alert_id": row['alert_id'],
                        "title": row['title'],
                        "source": row['source'],
                        "severity": row['severity'],
                        "created_at": row['created_at'].isoformat() if row['created_at'] else None
                    }
                    for row in rows
                ]
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


@router.post("/alerts/{alert_id}/enrich")
async def enrich_single_alert(
    request: Request,
    alert_id: str,
    authorization: str = Header(None)
):
    """
    Manually trigger enrichment for a specific alert.

    Use this to enrich alerts that were created before auto-enrichment was enabled.
    """
    await require_admin(request, authorization)

    try:
        from services.postgres_db import postgres_db
        from services.auto_enrichment import auto_enrichment_service
        import json

        if not postgres_db.pool:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Get the alert
            row = await conn.fetchrow("""
                SELECT alert_id, raw_event FROM alerts WHERE alert_id = $1
            """, alert_id)

            if not row:
                raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

            raw_event = row['raw_event']
            if isinstance(raw_event, str):
                raw_event = json.loads(raw_event)

            # Check if already enriched
            if raw_event.get('_extracted', {}).get('enrichment'):
                return {
                    "success": True,
                    "alert_id": alert_id,
                    "message": "Alert already has enrichment data",
                    "already_enriched": True
                }

            # Run enrichment
            enrichment = await auto_enrichment_service.enrich_alert(alert_id, raw_event)

            return {
                "success": True,
                "alert_id": alert_id,
                "enrichment_status": enrichment.get('status', 'unknown'),
                "ioc_count": enrichment.get('ioc_count', 0),
                "summary": enrichment.get('summary', {})
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")


@router.post("/alerts/backfill")
async def backfill_alert_enrichment(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    authorization: str = Header(None)
):
    """
    Backfill enrichment for alerts that are missing it.

    Processes up to `limit` alerts in one batch. Run multiple times if needed.
    """
    await require_admin(request, authorization)

    try:
        from services.postgres_db import postgres_db
        from services.auto_enrichment import auto_enrichment_service
        import json
        import asyncio

        if not postgres_db.pool:
            raise HTTPException(status_code=503, detail="Database not connected")

        results = {
            "processed": 0,
            "success": 0,
            "skipped": 0,
            "failed": 0,
            "details": []
        }

        async with postgres_db.tenant_acquire() as conn:
            # Get alerts missing enrichment
            rows = await conn.fetch("""
                SELECT alert_id, raw_event FROM alerts
                WHERE (raw_event::jsonb->'_extracted'->'enrichment') IS NULL
                ORDER BY created_at DESC
                LIMIT $1
            """, limit)

            for row in rows:
                results["processed"] += 1
                alert_id = row['alert_id']

                try:
                    raw_event = row['raw_event']
                    if isinstance(raw_event, str):
                        raw_event = json.loads(raw_event)

                    # Run enrichment
                    enrichment = await auto_enrichment_service.enrich_alert(alert_id, raw_event)

                    status = enrichment.get('status', 'unknown')
                    if status == 'enriched':
                        results["success"] += 1
                    elif status == 'no_iocs':
                        results["skipped"] += 1
                    else:
                        results["failed"] += 1

                    results["details"].append({
                        "alert_id": alert_id,
                        "status": status,
                        "ioc_count": enrichment.get('ioc_count', 0)
                    })

                except Exception as e:
                    results["failed"] += 1
                    results["details"].append({
                        "alert_id": alert_id,
                        "status": "error",
                        "error": str(e)
                    })

                # Small delay between alerts to avoid rate limiting
                await asyncio.sleep(0.5)

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backfill failed: {str(e)}")
