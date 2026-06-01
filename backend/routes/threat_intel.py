# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Threat Intelligence API Routes

Endpoints for:
- IOC management (add, search, get)
- IOC enrichment from multiple sources
- Threat intel reports
- Correlation data
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Depends
from fastapi.responses import StreamingResponse
from typing import Optional, List, Any
from pydantic import BaseModel, Field
from datetime import datetime
import asyncio
import json
import logging

logger = logging.getLogger(__name__)


def json_serial(obj: Any) -> str:
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

from dependencies.auth import get_current_user, require_permission, User

from services.threat_intel_service import (
    get_threat_intel_service,
    IOCType,
    ThreatSeverity,
    ReputationVerdict,
    IOC,
    EnrichmentResult,
    ThreatIntelReport
)

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"], dependencies=[Depends(get_current_user)])


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class IOCCreateRequest(BaseModel):
    """Request to create/add an IOC"""
    value: str
    type: IOCType
    source: Optional[str] = None
    severity: Optional[ThreatSeverity] = None
    tags: Optional[List[str]] = None
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None


class IOCBulkCreateRequest(BaseModel):
    """Request to create multiple IOCs"""
    iocs: List[IOCCreateRequest]


class EnrichmentRequest(BaseModel):
    """Request to enrich an IOC"""
    value: str
    type: IOCType
    providers: Optional[List[str]] = None
    force_refresh: bool = False


class BulkEnrichmentRequest(BaseModel):
    """Request to enrich multiple IOCs"""
    iocs: List[dict]  # List of {value, type}
    providers: Optional[List[str]] = None
    max_concurrent: int = Field(default=5, ge=1, le=20)


class IOCSearchResponse(BaseModel):
    """Response for IOC search"""
    iocs: List[IOC]
    total: int
    offset: int
    limit: int


class StatsResponse(BaseModel):
    """Response for threat intel statistics"""
    iocs: dict
    cache: dict


# ============================================================================
# IOC MANAGEMENT ROUTES
# ============================================================================

@router.post("/iocs", response_model=IOC)
async def create_ioc(request: IOCCreateRequest):
    """
    Add or update an IOC.

    If the IOC already exists, updates last_seen and increments occurrence count.
    """
    service = get_threat_intel_service()

    try:
        ioc = await service.add_ioc(
            value=request.value,
            ioc_type=request.type,
            source=request.source,
            severity=request.severity,
            tags=request.tags,
            alert_id=request.alert_id,
            investigation_id=request.investigation_id
        )
        return ioc
    except Exception as e:
        logger.error(f"Failed to create IOC: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/iocs/bulk", response_model=dict)
async def create_iocs_bulk(request: IOCBulkCreateRequest):
    """
    Add multiple IOCs in bulk.
    """
    service = get_threat_intel_service()

    results = {"created": 0, "updated": 0, "errors": []}

    for ioc_req in request.iocs:
        try:
            await service.add_ioc(
                value=ioc_req.value,
                ioc_type=ioc_req.type,
                source=ioc_req.source,
                severity=ioc_req.severity,
                tags=ioc_req.tags,
                alert_id=ioc_req.alert_id,
                investigation_id=ioc_req.investigation_id
            )
            results["created"] += 1
        except Exception as e:
            results["errors"].append({"value": ioc_req.value, "error": str(e)})

    return results


@router.get("/iocs", response_model=IOCSearchResponse)
async def search_iocs(
    query: Optional[str] = Query(None, description="Search by IOC value"),
    type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by severity"),
    verdict: Optional[ReputationVerdict] = Query(None, description="Filter by verdict"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter by"),
    since: Optional[str] = Query(None, description="Only IOCs seen after this date (ISO format)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Search and filter IOCs.
    """
    service = get_threat_intel_service()

    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    # Parse since parameter into datetime
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            pass  # Silently ignore invalid date format

    try:
        iocs, total = await service.search_iocs(
            query=query,
            ioc_type=type,
            severity=severity,
            verdict=verdict,
            tags=tag_list,
            since=since_dt,
            limit=limit,
            offset=offset
        )

        return IOCSearchResponse(
            iocs=iocs,
            total=total,
            offset=offset,
            limit=limit
        )
    except Exception as e:
        logger.error(f"Failed to search IOCs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/ioc/lookup")
async def lookup_ioc(
    value: str = Query(..., description="IOC value to look up"),
    type: Optional[IOCType] = Query(None, description="IOC type for disambiguation"),
    with_enrichments: bool = Query(False, description="Include cached enrichment data")
):
    """
    Look up an IOC by value (query parameter version - better for URLs).

    Set with_enrichments=true to include cached enrichment data from all providers.
    If IOC doesn't exist in DB, returns a transient IOC object (not persisted until enriched).
    """
    return await get_ioc(value, type, with_enrichments)


@router.get("/iocs/{ioc_value:path}")
async def get_ioc(
    ioc_value: str,
    type: Optional[IOCType] = Query(None, description="IOC type for disambiguation"),
    with_enrichments: bool = Query(False, description="Include cached enrichment data")
):
    """
    Get a specific IOC by value (path parameter version).

    Set with_enrichments=true to include cached enrichment data from all providers.
    If IOC doesn't exist in DB, returns a transient IOC object (not persisted until enriched).
    """
    service = get_threat_intel_service()

    ioc = await service.get_ioc(ioc_value, type)

    # If IOC not in DB, create a transient object for display
    # This allows the frontend to show the IOC and trigger enrichment
    if not ioc:
        from datetime import datetime
        # Auto-detect type if not provided
        detected_type = type
        if not detected_type:
            import re
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ioc_value):
                detected_type = IOCType.IP
            elif re.match(r'^[a-fA-F0-9]{32}$', ioc_value):
                detected_type = IOCType.HASH_MD5
            elif re.match(r'^[a-fA-F0-9]{40}$', ioc_value):
                detected_type = IOCType.HASH_SHA1
            elif re.match(r'^[a-fA-F0-9]{64}$', ioc_value):
                detected_type = IOCType.HASH_SHA256
            elif ioc_value.startswith('http://') or ioc_value.startswith('https://'):
                detected_type = IOCType.URL
            elif '@' in ioc_value:
                detected_type = IOCType.EMAIL
            elif '.' in ioc_value:
                detected_type = IOCType.DOMAIN
            else:
                detected_type = IOCType.IP  # Default fallback

        # Return a transient IOC (not persisted)
        ioc = IOC(
            value=ioc_value,
            type=detected_type,
            severity=ThreatSeverity.UNKNOWN,
            source="on_demand",
            tags=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            occurrences=0
        )

    if not with_enrichments:
        return ioc

    # Fetch cached enrichments for this IOC
    from services.enrichment_cache import get_cache_service
    cache = get_cache_service()

    ioc_type = type.value if type else ioc.type
    cached_enrichments = await cache.get_all_providers(ioc_value, ioc_type)

    # Convert to enrichment format expected by frontend
    enrichments = []
    provider_status = []

    for cached in cached_enrichments:
        # Ensure enrichment_data is a dict (handle double-JSON-encoded strings)
        raw_data = cached.enrichment_data
        if isinstance(raw_data, str):
            try:
                import json
                raw_data = json.loads(raw_data)
            except:
                raw_data = {}

        enrichments.append({
            "provider": cached.provider,
            "raw_data": raw_data if isinstance(raw_data, dict) else {},
            "is_malicious": cached.is_malicious,
            "threat_score": cached.threat_score,
            "confidence": cached.confidence,
            "cached_at": cached.cached_at.isoformat() if cached.cached_at else None
        })
        provider_status.append({
            "provider_id": cached.provider,
            "provider_name": cached.provider.replace("_", " ").title(),
            "status": "cached",
            "has_data": True,
            "message": f"Cached data from {cached.cached_at.strftime('%Y-%m-%d %H:%M') if cached.cached_at else 'unknown'}"
        })

    # Return IOC with enrichments
    # Convert datetime objects to ISO strings to avoid serialization errors
    from datetime import datetime as dt  # Ensure datetime is available
    ioc_dict = ioc.dict()
    for key, value in ioc_dict.items():
        if isinstance(value, dt):
            ioc_dict[key] = value.isoformat()

    return {
        **ioc_dict,
        "enrichments": enrichments,
        "provider_status": provider_status
    }


@router.delete("/iocs/{ioc_value}")
async def delete_ioc(
    ioc_value: str,
    type: Optional[IOCType] = Query(None, description="IOC type for disambiguation"),
    current_user: User = Depends(require_permission("integration:manage"))
):
    """
    Delete an IOC by value.
    Requires MANAGE_INTEGRATIONS permission.
    """
    service = get_threat_intel_service()

    try:
        deleted = await service.delete_ioc(ioc_value, type)
        if not deleted:
            raise HTTPException(status_code=404, detail="IOC not found")
        return {"success": True, "message": f"IOC '{ioc_value}' deleted", "deleted_by": current_user.username}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete IOC: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


class BulkDeleteRequest(BaseModel):
    """Request to delete multiple IOCs"""
    iocs: List[str]  # List of IOC values


class BulkUpdateRequest(BaseModel):
    """Request to update multiple IOCs"""
    iocs: List[str]  # List of IOC values
    verdict: Optional[str] = None
    severity: Optional[str] = None
    tags_add: Optional[List[str]] = None
    tags_remove: Optional[List[str]] = None


@router.post("/iocs/bulk-delete")
async def delete_iocs_bulk(
    request: BulkDeleteRequest,
    current_user: User = Depends(require_permission("integration:manage"))
):
    """
    Delete multiple IOCs in bulk.
    Requires MANAGE_INTEGRATIONS permission.
    """
    service = get_threat_intel_service()

    results = {"deleted": 0, "not_found": 0, "errors": [], "deleted_by": current_user.username}

    for ioc_value in request.iocs:
        try:
            deleted = await service.delete_ioc(ioc_value)
            if deleted:
                results["deleted"] += 1
            else:
                results["not_found"] += 1
        except Exception as e:
            results["errors"].append({"value": ioc_value, "error": str(e)})

    return results


@router.post("/iocs/bulk-update")
async def update_iocs_bulk(
    request: BulkUpdateRequest,
    current_user: User = Depends(require_permission("integration:manage"))
):
    """
    Update multiple IOCs in bulk (verdict, severity, tags).
    Requires MANAGE_INTEGRATIONS permission.
    """
    service = get_threat_intel_service()

    results = {"updated": 0, "not_found": 0, "errors": [], "updated_by": current_user.username}

    for ioc_value in request.iocs:
        try:
            updated = await service.update_ioc(
                value=ioc_value,
                verdict=request.verdict,
                severity=request.severity,
                tags_add=request.tags_add,
                tags_remove=request.tags_remove
            )
            if updated:
                results["updated"] += 1
            else:
                results["not_found"] += 1
        except Exception as e:
            results["errors"].append({"value": ioc_value, "error": str(e)})

    return results


# ============================================================================
# ENRICHMENT ROUTES
# ============================================================================

@router.post("/enrich", response_model=ThreatIntelReport)
async def enrich_ioc(request: EnrichmentRequest):
    """
    Enrich an IOC using configured threat intel providers.

    Uses cached results unless force_refresh=True.
    Returns a consolidated report with consensus verdict.
    """
    print(f"[ENRICH ENDPOINT] Received request: value={request.value[:50]}, type={request.type}, force_refresh={request.force_refresh}")
    service = get_threat_intel_service()

    try:
        report = await service.enrich_ioc(
            value=request.value,
            ioc_type=request.type,
            providers=request.providers,
            force_refresh=request.force_refresh
        )
        logger.info(f"Enrich endpoint got report with {len(report.enrichments)} enrichments, sources_checked={report.sources_checked}")
        return report
    except Exception as e:
        logger.error(f"Failed to enrich IOC: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/enrich/stream")
async def enrich_ioc_stream(request: EnrichmentRequest):
    """
    Stream IOC enrichment results as they arrive from each provider.

    Uses Server-Sent Events (SSE) to push results incrementally.
    Each event contains data from a single provider as it completes.
    """
    print(f"[ENRICH STREAM] Starting stream for: {request.value[:50]}, type={request.type}")
    service = get_threat_intel_service()

    async def event_generator():
        """Generate SSE events as each provider returns results"""
        try:
            # Get available providers for this IOC type
            available_providers = await service._get_providers_for_type(request.type)
            if request.providers:
                available_providers = [p for p in available_providers if p in request.providers]

            print(f"[ENRICH STREAM] Providers: {available_providers}")

            # Send initial event with provider list
            yield f"data: {json.dumps({'event': 'start', 'providers': available_providers, 'total': len(available_providers)})}\n\n"

            # Get or create IOC
            ioc = await service.get_ioc(request.value, request.type)
            if not ioc:
                ioc = await service.add_ioc(request.value, request.type)

            # Get registry for provider names
            from integrations.registry.integration_registry import get_registry
            registry = get_registry()

            enrichments = []
            enrichment_results = []  # Raw EnrichmentResult objects for DB persistence
            provider_statuses = []
            completed = 0

            # Create tasks for all providers to run concurrently
            import time

            async def enrich_provider(provider: str):
                """Enrich from a single provider and return result"""
                nonlocal completed
                integration = registry.get(provider)
                provider_name = integration.name if integration else provider
                start_time = time.time()

                # Check cache first (unless force_refresh)
                if not request.force_refresh:
                    cached = await service.get_cached_enrichment(request.value, request.type, provider)
                    if cached:
                        elapsed_ms = int((time.time() - start_time) * 1000)
                        completed += 1
                        enrichment_results.append(cached)
                        return {
                            'event': 'result',
                            'provider_id': provider,
                            'provider_name': provider_name,
                            'status': 'cached',
                            'cached': True,
                            'has_data': True,
                            'enrichment': cached.model_dump() if hasattr(cached, 'model_dump') else cached.dict(),
                            'response_time_ms': elapsed_ms,
                            'completed': completed,
                            'total': len(available_providers)
                        }

                # Execute enrichment
                try:
                    result = await service._execute_enrichment(request.value, request.type, provider)
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    completed += 1

                    if result:
                        await service.cache_enrichment(result)
                        enrichment_results.append(result)
                        return {
                            'event': 'result',
                            'provider_id': provider,
                            'provider_name': provider_name,
                            'status': 'success',
                            'cached': False,
                            'has_data': True,
                            'enrichment': result.model_dump() if hasattr(result, 'model_dump') else result.dict(),
                            'response_time_ms': elapsed_ms,
                            'completed': completed,
                            'total': len(available_providers)
                        }
                    else:
                        return {
                            'event': 'result',
                            'provider_id': provider,
                            'provider_name': provider_name,
                            'status': 'no_data',
                            'cached': False,
                            'has_data': False,
                            'enrichment': None,
                            'response_time_ms': elapsed_ms,
                            'completed': completed,
                            'total': len(available_providers)
                        }
                except Exception as e:
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    completed += 1
                    print(f"[ENRICH STREAM] Error from {provider}: {str(e)}")
                    return {
                        'event': 'result',
                        'provider_id': provider,
                        'provider_name': provider_name,
                        'status': 'error',
                        'cached': False,
                        'has_data': False,
                        'enrichment': None,
                        'error': str(e),
                        'response_time_ms': elapsed_ms,
                        'completed': completed,
                        'total': len(available_providers)
                    }

            # Run all providers concurrently and yield results as they complete
            tasks = [asyncio.create_task(enrich_provider(p)) for p in available_providers]

            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    # Collect enrichment data for final summary
                    if result.get('enrichment'):
                        enrichments.append(result['enrichment'])
                    provider_statuses.append({
                        'provider_id': result['provider_id'],
                        'provider_name': result['provider_name'],
                        'status': result['status'],
                        'cached': result['cached'],
                        'has_data': result['has_data']
                    })
                    # Stream result to client (use custom serializer for datetime)
                    yield f"data: {json.dumps(result, default=json_serial)}\n\n"

            # Calculate consensus verdict
            verdict_counts = {'malicious': 0, 'suspicious': 0, 'clean': 0}
            total_score = 0
            score_count = 0

            for e in enrichments:
                v = e.get('verdict', '').lower()
                if 'malicious' in v:
                    verdict_counts['malicious'] += 1
                elif 'suspicious' in v:
                    verdict_counts['suspicious'] += 1
                elif 'clean' in v:
                    verdict_counts['clean'] += 1

                score = e.get('threat_score')
                if score is not None:
                    total_score += score
                    score_count += 1

            if verdict_counts['malicious'] > 0:
                consensus = 'malicious'
            elif verdict_counts['suspicious'] > 0:
                consensus = 'suspicious'
            else:
                consensus = 'clean'

            avg_score = total_score / score_count if score_count > 0 else 0

            # Persist enrichment results to the IOC record
            if ioc and enrichment_results:
                try:
                    from services.threat_intel_service import EnrichmentTrigger
                    await service._update_ioc_from_enrichments(
                        ioc, enrichment_results, EnrichmentTrigger.MANUAL
                    )
                    print(f"[ENRICH STREAM] Persisted {len(enrichment_results)} enrichment results to IOC record")
                except Exception as persist_err:
                    print(f"[ENRICH STREAM] Failed to persist enrichment to IOC: {persist_err}")

            # Send completion event with summary
            yield f"data: {json.dumps({'event': 'complete', 'sources_checked': len(available_providers), 'sources_flagged': verdict_counts['malicious'] + verdict_counts['suspicious'], 'consensus_verdict': consensus, 'consensus_score': avg_score, 'provider_status': provider_statuses}, default=json_serial)}\n\n"

        except Exception as e:
            print(f"[ENRICH STREAM] Error: {str(e)}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'event': 'error', 'error': str(e)}, default=json_serial)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
    )


@router.post("/enrich/bulk")
async def enrich_iocs_bulk(
    request: BulkEnrichmentRequest,
    background_tasks: BackgroundTasks
):
    """
    Enrich multiple IOCs in bulk (async).

    Returns a job ID for tracking progress.
    """
    service = get_threat_intel_service()

    # For small batches, process synchronously
    if len(request.iocs) <= 5:
        try:
            iocs = [(ioc['value'], IOCType(ioc['type'])) for ioc in request.iocs]
            reports = await service.bulk_enrich(
                iocs=iocs,
                providers=request.providers,
                max_concurrent=request.max_concurrent
            )

            # Filter out exceptions
            successful = [r for r in reports if isinstance(r, ThreatIntelReport)]
            errors = [str(r) for r in reports if isinstance(r, Exception)]

            return {
                "status": "completed",
                "total": len(request.iocs),
                "successful": len(successful),
                "errors": errors,
                "reports": [r.dict() for r in successful]
            }
        except Exception as e:
            logger.error(f"Failed to bulk enrich IOCs: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # For larger batches, run in background with DB-tracked job
    import uuid
    from services.postgres_db import postgres_db

    job_id = str(uuid.uuid4())

    # Ensure background_jobs table exists
    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS background_jobs (
                    job_id VARCHAR(100) PRIMARY KEY,
                    job_type VARCHAR(100) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                    total_items INTEGER NOT NULL DEFAULT 0,
                    processed_items INTEGER NOT NULL DEFAULT 0,
                    result_summary JSONB DEFAULT '{}',
                    error_message TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP WITH TIME ZONE
                )
            """)

            # Insert the job record
            await conn.execute("""
                INSERT INTO background_jobs (job_id, job_type, status, total_items, created_at)
                VALUES ($1, $2, 'queued', $3, CURRENT_TIMESTAMP)
            """, job_id, 'bulk_enrichment', len(request.iocs))
    except Exception as e:
        # If DB insert fails, still proceed with in-memory tracking
        import logging
        logging.getLogger(__name__).warning(f"Failed to persist job {job_id} to DB: {e}")

    # Define the background task that processes enrichments and updates job status
    async def _run_bulk_enrichment(
        j_id: str,
        iocs_list: list,
        providers: list,
        max_concurrent: int
    ):
        svc = get_threat_intel_service()
        processed = 0
        successful = 0
        errors_list = []

        try:
            # Update job status to running
            try:
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute("""
                        UPDATE background_jobs
                        SET status = 'running', updated_at = CURRENT_TIMESTAMP
                        WHERE job_id = $1
                    """, j_id)
            except Exception:
                pass

            # Process IOCs
            iocs_tuples = [(ioc['value'], IOCType(ioc['type'])) for ioc in iocs_list]
            reports = await svc.bulk_enrich(
                iocs=iocs_tuples,
                providers=providers,
                max_concurrent=max_concurrent
            )

            for r in reports:
                processed += 1
                if isinstance(r, ThreatIntelReport):
                    successful += 1
                elif isinstance(r, Exception):
                    errors_list.append(str(r))

                # Periodically update progress in DB
                if processed % 10 == 0 or processed == len(iocs_list):
                    try:
                        async with postgres_db.tenant_acquire() as conn:
                            await conn.execute("""
                                UPDATE background_jobs
                                SET processed_items = $2, updated_at = CURRENT_TIMESTAMP
                                WHERE job_id = $1
                            """, j_id, processed)
                    except Exception:
                        pass

            # Mark job as completed
            result_summary = {
                "successful": successful,
                "errors": len(errors_list),
                "error_details": errors_list[:20]  # Cap at 20 error messages
            }
            try:
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute("""
                        UPDATE background_jobs
                        SET status = 'completed', processed_items = $2,
                            result_summary = $3, completed_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE job_id = $1
                    """, j_id, processed, json.dumps(result_summary))
            except Exception:
                pass

        except Exception as e:
            # Mark job as failed
            try:
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute("""
                        UPDATE background_jobs
                        SET status = 'failed', error_message = $2,
                            processed_items = $3, completed_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE job_id = $1
                    """, j_id, str(e), processed)
            except Exception:
                pass

    # Schedule the background task
    background_tasks.add_task(
        _run_bulk_enrichment,
        job_id,
        request.iocs,
        request.providers,
        request.max_concurrent
    )

    return {
        "status": "queued",
        "job_id": job_id,
        "total": len(request.iocs),
        "message": "Large batch queued for background processing. Use GET /api/v1/threat-intel/jobs/{job_id} to check status."
    }


@router.get("/enrich/cache/{provider}/{ioc_value:path}")
async def get_cached_enrichment(
    provider: str,
    ioc_value: str,
    type: IOCType = Query(..., description="IOC type")
):
    """
    Get cached enrichment for a specific provider.
    """
    service = get_threat_intel_service()

    cached = await service.get_cached_enrichment(ioc_value, type, provider)

    if not cached:
        raise HTTPException(status_code=404, detail="No cached enrichment found")

    return cached


# ============================================================================
# BACKGROUND JOB TRACKING ROUTES
# ============================================================================

@router.get("/jobs")
async def list_jobs(
    status: Optional[str] = Query(None, description="Filter by status (queued/running/completed/failed)"),
    limit: int = Query(20, ge=1, le=100, description="Max jobs to return")
):
    """
    List recent background enrichment jobs.

    Returns most recent jobs with their status and progress.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        return {"jobs": [], "total": 0}

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Ensure table exists
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS background_jobs (
                    job_id VARCHAR(100) PRIMARY KEY,
                    job_type VARCHAR(100) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                    total_items INTEGER NOT NULL DEFAULT 0,
                    processed_items INTEGER NOT NULL DEFAULT 0,
                    result_summary JSONB DEFAULT '{}',
                    error_message TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP WITH TIME ZONE
                )
            """)

            if status:
                rows = await conn.fetch("""
                    SELECT job_id, job_type, status, total_items, processed_items,
                           result_summary, error_message, created_at, updated_at, completed_at
                    FROM background_jobs
                    WHERE status = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                """, status, limit)
            else:
                rows = await conn.fetch("""
                    SELECT job_id, job_type, status, total_items, processed_items,
                           result_summary, error_message, created_at, updated_at, completed_at
                    FROM background_jobs
                    ORDER BY created_at DESC
                    LIMIT $1
                """, limit)

            jobs = []
            for row in rows:
                job = {
                    "job_id": row['job_id'],
                    "job_type": row['job_type'],
                    "status": row['status'],
                    "total_items": row['total_items'],
                    "processed_items": row['processed_items'],
                    "progress_percentage": (
                        round((row['processed_items'] / row['total_items']) * 100, 1)
                        if row['total_items'] > 0 else 0
                    ),
                    "result_summary": row['result_summary'] if row['result_summary'] else {},
                    "error_message": row['error_message'],
                    "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                    "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None,
                    "completed_at": row['completed_at'].isoformat() if row['completed_at'] else None
                }
                jobs.append(job)

            return {"jobs": jobs, "total": len(jobs)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list jobs: {str(e)}")


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """
    Get status of a specific background enrichment job.

    Returns job details including progress and results.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT job_id, job_type, status, total_items, processed_items,
                       result_summary, error_message, created_at, updated_at, completed_at
                FROM background_jobs
                WHERE job_id = $1
            """, job_id)

            if not row:
                raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

            return {
                "job_id": row['job_id'],
                "job_type": row['job_type'],
                "status": row['status'],
                "total_items": row['total_items'],
                "processed_items": row['processed_items'],
                "progress_percentage": (
                    round((row['processed_items'] / row['total_items']) * 100, 1)
                    if row['total_items'] > 0 else 0
                ),
                "result_summary": row['result_summary'] if row['result_summary'] else {},
                "error_message": row['error_message'],
                "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None,
                "completed_at": row['completed_at'].isoformat() if row['completed_at'] else None
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")


# ============================================================================
# CORRELATION ROUTES
# ============================================================================

@router.get("/correlate")
async def get_correlations(
    alert_id: Optional[str] = Query(None),
    investigation_id: Optional[str] = Query(None)
):
    """
    Find IOC correlations for an alert or investigation.

    Returns related alerts/investigations sharing common IOCs.
    """
    if not alert_id and not investigation_id:
        raise HTTPException(
            status_code=400,
            detail="Must provide either alert_id or investigation_id"
        )

    service = get_threat_intel_service()

    try:
        result = await service.correlate_iocs(
            alert_id=alert_id,
            investigation_id=investigation_id
        )
        return result
    except Exception as e:
        logger.error(f"Failed to correlate IOCs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# QUICK LOOKUP ROUTES
# ============================================================================

@router.get("/lookup/ip/{ip}")
async def lookup_ip(
    ip: str,
    enrich: bool = Query(True, description="Enrich from providers if not cached")
):
    """
    Quick lookup for an IP address.
    """
    service = get_threat_intel_service()

    # Check if already exists
    ioc = await service.get_ioc(ip, IOCType.IP)

    if enrich:
        report = await service.enrich_ioc(ip, IOCType.IP)
        return {
            "ip": ip,
            "verdict": report.consensus_verdict,
            "score": report.consensus_score,
            "sources_checked": report.sources_checked,
            "sources_flagged": report.sources_flagged,
            "enrichments": [e.dict() for e in report.enrichments],
            "ioc": report.ioc.dict() if report.ioc else None
        }

    if not ioc:
        return {"ip": ip, "verdict": "unknown", "message": "Not found in database"}

    return {"ip": ip, "ioc": ioc.dict()}


@router.get("/lookup/domain/{domain}")
async def lookup_domain(
    domain: str,
    enrich: bool = Query(True, description="Enrich from providers if not cached")
):
    """
    Quick lookup for a domain.
    """
    service = get_threat_intel_service()

    if enrich:
        report = await service.enrich_ioc(domain, IOCType.DOMAIN)
        return {
            "domain": domain,
            "verdict": report.consensus_verdict,
            "score": report.consensus_score,
            "sources_checked": report.sources_checked,
            "sources_flagged": report.sources_flagged,
            "enrichments": [e.dict() for e in report.enrichments],
            "ioc": report.ioc.dict() if report.ioc else None
        }

    ioc = await service.get_ioc(domain, IOCType.DOMAIN)
    if not ioc:
        return {"domain": domain, "verdict": "unknown", "message": "Not found in database"}

    return {"domain": domain, "ioc": ioc.dict()}


@router.get("/lookup/hash/{hash_value}")
async def lookup_hash(
    hash_value: str,
    enrich: bool = Query(True, description="Enrich from providers if not cached")
):
    """
    Quick lookup for a file hash.

    Automatically detects hash type (MD5, SHA1, SHA256).
    """
    # Detect hash type
    hash_len = len(hash_value)
    if hash_len == 32:
        hash_type = IOCType.HASH_MD5
    elif hash_len == 40:
        hash_type = IOCType.HASH_SHA1
    elif hash_len == 64:
        hash_type = IOCType.HASH_SHA256
    else:
        raise HTTPException(status_code=400, detail="Invalid hash length. Must be MD5 (32), SHA1 (40), or SHA256 (64)")

    service = get_threat_intel_service()

    if enrich:
        report = await service.enrich_ioc(hash_value.lower(), hash_type)
        return {
            "hash": hash_value.lower(),
            "hash_type": hash_type.value,
            "verdict": report.consensus_verdict,
            "score": report.consensus_score,
            "sources_checked": report.sources_checked,
            "sources_flagged": report.sources_flagged,
            "enrichments": [e.dict() for e in report.enrichments],
            "ioc": report.ioc.dict() if report.ioc else None
        }

    ioc = await service.get_ioc(hash_value.lower(), hash_type)
    if not ioc:
        return {"hash": hash_value.lower(), "hash_type": hash_type.value, "verdict": "unknown", "message": "Not found in database"}

    return {"hash": hash_value.lower(), "hash_type": hash_type.value, "ioc": ioc.dict()}


@router.post("/lookup/url")
async def lookup_url(
    request: dict,
    enrich: bool = Query(True, description="Enrich from providers if not cached")
):
    """
    Quick lookup for a URL.

    URLs must be passed in the request body as {"url": "..."} since they contain
    special characters that don't work well in path parameters.
    """
    url = request.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required in request body")

    service = get_threat_intel_service()

    if enrich:
        report = await service.enrich_ioc(url, IOCType.URL)
        return {
            "url": url,
            "verdict": report.consensus_verdict,
            "score": report.consensus_score,
            "sources_checked": report.sources_checked,
            "sources_flagged": report.sources_flagged,
            "enrichments": [e.dict() for e in report.enrichments],
            "ioc": report.ioc.dict() if report.ioc else None
        }

    ioc = await service.get_ioc(url, IOCType.URL)
    if not ioc:
        return {"url": url, "verdict": "unknown", "message": "Not found in database"}

    return {"url": url, "ioc": ioc.dict()}


# ============================================================================
# STATISTICS ROUTES
# ============================================================================

@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """
    Get threat intel statistics.

    Returns:
    - IOC counts by type and severity
    - Cache statistics
    """
    service = get_threat_intel_service()

    try:
        stats = await service.get_stats()
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get threat intel stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# CACHE MANAGEMENT ROUTES
# ============================================================================

@router.get("/cache/health")
async def get_cache_health():
    """
    Get detailed cache health metrics.

    Returns:
    - Health score (0-100)
    - Expiration distribution
    - Provider freshness metrics
    - Hot IOCs (most frequently accessed)
    - Recommendations
    """
    service = get_threat_intel_service()

    try:
        health = await service.get_cache_health()
        return health
    except Exception as e:
        logger.error(f"Failed to get cache health: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/cache/cleanup")
async def cleanup_cache():
    """
    Remove expired cache entries.

    This is a maintenance operation that removes all cache entries
    that have passed their TTL expiration time.
    """
    service = get_threat_intel_service()

    try:
        result = await service.cleanup_expired_cache()
        if not result.get("success"):
            logger.error(f"Cache cleanup failed: {result.get('error', 'Unknown error')}")
            raise HTTPException(status_code=500, detail="Internal server error")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup cache: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/cache/invalidate")
async def invalidate_cache(
    ioc_value: Optional[str] = Query(None, description="Specific IOC value to invalidate"),
    ioc_type: Optional[str] = Query(None, description="IOC type to invalidate (ip, domain, etc)"),
    provider: Optional[str] = Query(None, description="Provider to invalidate (virustotal, etc)")
):
    """
    Invalidate (delete) cache entries matching the specified criteria.

    At least one filter must be specified:
    - ioc_value: Delete cache for a specific IOC
    - ioc_type: Delete all cache entries for a specific IOC type
    - provider: Delete all cache entries from a specific provider

    Use POST /cache/cleanup to remove expired entries instead.
    """
    service = get_threat_intel_service()

    try:
        result = await service.invalidate_cache(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=provider
        )
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Unknown error"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to invalidate cache: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# SUPPORTED TYPES ROUTES
# ============================================================================

@router.get("/types")
async def get_supported_types():
    """
    Get all supported IOC types and their available providers.
    """
    return {
        "types": [
            {
                "type": IOCType.IP.value,
                "name": "IP Address",
                "providers": ["virustotal", "abuseipdb", "shodan", "greynoise", "ipinfo"]
            },
            {
                "type": IOCType.DOMAIN.value,
                "name": "Domain",
                "providers": ["virustotal", "urlscan", "whois"]
            },
            {
                "type": IOCType.URL.value,
                "name": "URL",
                "providers": ["virustotal", "urlscan", "urlhaus"]
            },
            {
                "type": IOCType.HASH_MD5.value,
                "name": "MD5 Hash",
                "providers": ["virustotal", "malwarebazaar", "hybridanalysis"]
            },
            {
                "type": IOCType.HASH_SHA1.value,
                "name": "SHA1 Hash",
                "providers": ["virustotal", "malwarebazaar", "hybridanalysis"]
            },
            {
                "type": IOCType.HASH_SHA256.value,
                "name": "SHA256 Hash",
                "providers": ["virustotal", "malwarebazaar", "hybridanalysis"]
            },
            {
                "type": IOCType.EMAIL.value,
                "name": "Email Address",
                "providers": ["hibp", "emailrep"]
            },
            {
                "type": IOCType.CVE.value,
                "name": "CVE",
                "providers": ["nvd", "vulndb"]
            }
        ]
    }


# ============================================================================
# SMART ENRICHMENT SCHEDULER ROUTES
# ============================================================================

@router.get("/enrichment/queue/stats")
async def get_enrichment_queue_stats():
    """
    Get enrichment queue statistics.

    Returns:
    - Pending, processing, completed counts
    - Priority distribution
    - Trigger type distribution
    """
    from services.smart_enrichment_scheduler import get_smart_enrichment_scheduler

    scheduler = get_smart_enrichment_scheduler()
    return await scheduler.get_queue_stats()


@router.get("/enrichment/health")
async def get_enrichment_health():
    """
    Get overall enrichment system health.

    Returns:
    - Health score (0-100)
    - Provider-level metrics
    - Rate limit status
    - Issues and recommendations
    """
    from services.smart_enrichment_scheduler import get_smart_enrichment_scheduler

    scheduler = get_smart_enrichment_scheduler()
    return await scheduler.get_health_summary()


@router.post("/enrichment/queue")
async def queue_enrichment(
    ioc_value: str = Query(..., description="IOC value to enrich"),
    ioc_type: str = Query(..., description="IOC type (ip, domain, hash_sha256, etc)"),
    priority: Optional[int] = Query(None, ge=1, le=10, description="Priority override (1=highest)"),
    trigger: str = Query("manual", description="Trigger type")
):
    """
    Manually queue an IOC for enrichment.

    The system will calculate priority based on:
    - IOC severity
    - Cache state
    - Investigation context
    - Feed reappearance
    """
    from services.smart_enrichment_scheduler import (
        get_smart_enrichment_scheduler,
        EnrichmentTriggerType
    )

    scheduler = get_smart_enrichment_scheduler()

    # Map trigger string to enum
    trigger_map = {
        "manual": EnrichmentTriggerType.MANUAL,
        "investigation": EnrichmentTriggerType.INVESTIGATION,
        "severity_escalation": EnrichmentTriggerType.SEVERITY_ESCALATION
    }
    trigger_type = trigger_map.get(trigger, EnrichmentTriggerType.MANUAL)

    queue_id = await scheduler.queue_enrichment(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        trigger_type=trigger_type,
        priority_override=priority
    )

    if queue_id:
        return {
            "success": True,
            "queue_id": queue_id,
            "message": f"Queued {ioc_value} for enrichment"
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to queue enrichment")


@router.post("/enrichment/queue/bulk")
async def queue_bulk_enrichment(
    ioc_values: List[str] = Query(..., description="List of IOC values"),
    ioc_type: str = Query(..., description="IOC type for all values"),
    priority: Optional[int] = Query(None, ge=1, le=10, description="Priority override")
):
    """
    Queue multiple IOCs for enrichment at once.
    """
    from services.smart_enrichment_scheduler import (
        get_smart_enrichment_scheduler,
        EnrichmentTriggerType
    )

    scheduler = get_smart_enrichment_scheduler()

    queued = 0
    failed = 0

    for ioc_value in ioc_values[:100]:  # Limit to 100 at a time
        queue_id = await scheduler.queue_enrichment(
            ioc_value=ioc_value.strip(),
            ioc_type=ioc_type,
            trigger_type=EnrichmentTriggerType.MANUAL,
            priority_override=priority
        )
        if queue_id:
            queued += 1
        else:
            failed += 1

    return {
        "success": True,
        "queued": queued,
        "failed": failed,
        "total": len(ioc_values[:100])
    }


@router.get("/enrichment/rate-limits")
async def get_rate_limits():
    """
    Get current rate limit status for all providers.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            limits = await conn.fetch(
                """
                SELECT integration_id, minute_requests, minute_limit,
                       daily_requests, daily_limit, backoff_until,
                       last_429_error, consecutive_429_count,
                       avg_response_time_ms, success_count, error_count
                FROM integration_rate_limits
                ORDER BY integration_id
                """
            )

            return {
                "providers": [{
                    "id": r['integration_id'],
                    "minute": {
                        "used": r['minute_requests'],
                        "limit": r['minute_limit'],
                        "percent": round((r['minute_requests'] / max(r['minute_limit'], 1)) * 100, 1)
                    },
                    "daily": {
                        "used": r['daily_requests'],
                        "limit": r['daily_limit'],
                        "percent": round((r['daily_requests'] / max(r['daily_limit'], 1)) * 100, 1)
                    },
                    "backoff": {
                        "active": r['backoff_until'] is not None and r['backoff_until'].replace(tzinfo=None) > datetime.utcnow(),
                        "until": r['backoff_until'].isoformat() if r['backoff_until'] else None,
                        "consecutive_errors": r['consecutive_429_count']
                    },
                    "performance": {
                        "avg_response_ms": r['avg_response_time_ms'],
                        "success_count": r['success_count'],
                        "error_count": r['error_count'],
                        "success_rate": round((r['success_count'] / max(r['success_count'] + r['error_count'], 1)) * 100, 1)
                    }
                } for r in limits]
            }

    except Exception as e:
        logger.error(f"Failed to get provider rate limit status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# EXPORT ENDPOINTS
# ============================================================================

@router.get("/export/csv")
async def export_iocs_csv(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
    since: Optional[str] = Query(None, description="Only IOCs created after this date (ISO format)"),
    limit: int = Query(10000, ge=1, le=100000, description="Maximum IOCs to export"),
    current_user: User = Depends(get_current_user)
):
    """
    Export IOCs as CSV file.

    Returns a downloadable CSV file with columns:
    value, type, severity, verdict, confidence, first_seen, last_seen, source, tags
    """
    from fastapi.responses import StreamingResponse
    from services.postgres_db import postgres_db
    import csv
    import io

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        # Build query with filters
        conditions = []
        params = []
        param_idx = 1

        if ioc_type:
            conditions.append(f"ioc_type = ${param_idx}")
            params.append(ioc_type)
            param_idx += 1

        if severity:
            conditions.append(f"severity = ${param_idx}")
            params.append(severity)
            param_idx += 1

        if verdict:
            conditions.append(f"reputation = ${param_idx}")
            params.append(verdict)
            param_idx += 1

        if since:
            conditions.append(f"created_at >= ${param_idx}")
            params.append(since)
            param_idx += 1

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT ioc_value, ioc_type, severity, reputation, confidence,
                       first_seen, last_seen, source_type, tags
                FROM iocs
                WHERE {where_clause}
                ORDER BY last_seen DESC NULLS LAST
                LIMIT ${param_idx}
                """,
                *params, limit
            )

        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'value', 'type', 'severity', 'verdict', 'confidence',
            'first_seen', 'last_seen', 'source', 'tags'
        ])

        # Write data
        for row in rows:
            tags = row['tags'] if row['tags'] else []
            if isinstance(tags, str):
                import json
                try:
                    tags = json.loads(tags)
                except:
                    tags = []

            writer.writerow([
                row['ioc_value'],
                row['ioc_type'],
                row['severity'] or '',
                row['reputation'] or '',
                row['confidence'] or '',
                row['first_seen'].isoformat() if row['first_seen'] else '',
                row['last_seen'].isoformat() if row['last_seen'] else '',
                row['source_type'] or '',
                '|'.join(tags) if tags else ''
            ])

        output.seek(0)

        # Return as downloadable file
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=iocs_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )

    except Exception as e:
        logger.error(f"Failed to export IOCs as CSV: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/export/stix")
async def export_iocs_stix(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
    since: Optional[str] = Query(None, description="Only IOCs created after this date (ISO format)"),
    limit: int = Query(10000, ge=1, le=100000, description="Maximum IOCs to export"),
    current_user: User = Depends(get_current_user)
):
    """
    Export IOCs as STIX 2.1 bundle.

    Returns a JSON STIX bundle containing indicator objects for each IOC.
    """
    from fastapi.responses import JSONResponse
    from services.postgres_db import postgres_db
    import uuid

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        # Build query with filters
        conditions = []
        params = []
        param_idx = 1

        if ioc_type:
            conditions.append(f"ioc_type = ${param_idx}")
            params.append(ioc_type)
            param_idx += 1

        if severity:
            conditions.append(f"severity = ${param_idx}")
            params.append(severity)
            param_idx += 1

        if verdict:
            conditions.append(f"reputation = ${param_idx}")
            params.append(verdict)
            param_idx += 1

        if since:
            conditions.append(f"created_at >= ${param_idx}")
            params.append(since)
            param_idx += 1

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT ioc_value, ioc_type, severity, reputation, confidence,
                       first_seen, last_seen, source_type, feed_name
                FROM iocs
                WHERE {where_clause}
                ORDER BY last_seen DESC NULLS LAST
                LIMIT ${param_idx}
                """,
                *params, limit
            )

        # Build STIX bundle
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stix_objects = []

        # Add identity object for T1 Agentics
        identity_id = "identity--a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "T1 Agentics Threat Intelligence",
            "identity_class": "organization"
        })

        # Convert IOCs to STIX indicators
        for row in rows:
            ioc_value = row['ioc_value']
            ioc_type_val = row['ioc_type']

            # Build STIX pattern based on IOC type
            pattern = _build_stix_pattern(ioc_value, ioc_type_val)
            if not pattern:
                continue

            # Map reputation to labels
            labels = []
            if row['reputation']:
                labels.append(row['reputation'])
            if row['feed_name']:
                labels.append(f"feed:{row['feed_name']}")

            indicator_id = f"indicator--{uuid.uuid4()}"
            created = row['first_seen'].strftime("%Y-%m-%dT%H:%M:%S.000Z") if row['first_seen'] else now

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": created,
                "modified": now,
                "name": f"{ioc_type_val}: {ioc_value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created,
                "created_by_ref": identity_id,
            }

            if labels:
                indicator["labels"] = labels

            if row['confidence']:
                indicator["confidence"] = row['confidence']

            stix_objects.append(indicator)

        # Build bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }

        # Return as JSON with proper headers
        return JSONResponse(
            content=bundle,
            headers={
                "Content-Disposition": f"attachment; filename=iocs_stix_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            }
        )

    except Exception as e:
        logger.error(f"Failed to export IOCs as STIX: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


def _build_stix_pattern(value: str, ioc_type: str) -> Optional[str]:
    """Build STIX pattern string from IOC value and type"""
    ioc_type_lower = ioc_type.lower() if ioc_type else ''

    if ioc_type_lower == 'ip' or ioc_type_lower == 'ipv4':
        return f"[ipv4-addr:value = '{value}']"
    elif ioc_type_lower == 'ipv6':
        return f"[ipv6-addr:value = '{value}']"
    elif ioc_type_lower == 'domain':
        return f"[domain-name:value = '{value}']"
    elif ioc_type_lower == 'url':
        # Escape single quotes in URLs
        escaped_value = value.replace("'", "\\'")
        return f"[url:value = '{escaped_value}']"
    elif ioc_type_lower in ('hash_sha256', 'sha256'):
        return f"[file:hashes.'SHA-256' = '{value}']"
    elif ioc_type_lower in ('hash_sha1', 'sha1'):
        return f"[file:hashes.'SHA-1' = '{value}']"
    elif ioc_type_lower in ('hash_md5', 'md5'):
        return f"[file:hashes.'MD5' = '{value}']"
    elif ioc_type_lower == 'email':
        return f"[email-addr:value = '{value}']"
    else:
        return None
