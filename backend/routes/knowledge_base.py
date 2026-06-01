# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Knowledge Base API Routes

REST API for managing the Company Best Practices Database (SOP knowledge base).
Provides endpoints for:
- CRUD operations on knowledge base entries
- Search and filtering
- Version history
- AI-powered document processing
- Context queries for AI agents

All endpoints require authentication.
"""

import logging
import base64
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Body, Depends, UploadFile, File, Form
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/knowledge-base", tags=["Knowledge Base"], dependencies=[Depends(get_current_user)])


# Request/Response Models
class KBEntryCreate(BaseModel):
    """Request model for creating a knowledge base entry."""
    title: str = Field(..., description="Entry title", min_length=1, max_length=500)
    content: str = Field(..., description="Full content of the entry")
    content_type: str = Field(default='sop', description="Type: sop, playbook, escalation, etc.")
    category: Optional[str] = Field(None, description="Primary category")
    subcategory: Optional[str] = Field(None, description="Subcategory")
    tags: Optional[List[str]] = Field(default=[], description="Tags for searchability")
    severity_filter: Optional[List[str]] = Field(default=[], description="Applicable severities")
    incident_types: Optional[List[str]] = Field(default=[], description="Applicable incident types")
    ioc_types: Optional[List[str]] = Field(default=[], description="Relevant IOC types")
    mitre_techniques: Optional[List[str]] = Field(default=[], description="MITRE ATT&CK techniques")
    compliance_frameworks: Optional[List[str]] = Field(default=[], description="Compliance frameworks")
    priority: int = Field(default=100, description="Priority (lower = higher priority)")


class KBEntryUpdate(BaseModel):
    """Request model for updating a knowledge base entry."""
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    content: Optional[str] = None
    content_type: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    tags: Optional[List[str]] = None
    severity_filter: Optional[List[str]] = None
    incident_types: Optional[List[str]] = None
    ioc_types: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None
    change_reason: Optional[str] = Field(None, description="Reason for the change")


class KBContextQuery(BaseModel):
    """Request model for querying knowledge base for AI context."""
    severity: Optional[str] = None
    incident_type: Optional[str] = None
    ioc_types: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    keywords: Optional[List[str]] = None
    limit: int = Field(default=10, le=50)


# Routes
@router.get("/")
async def list_entries(
    content_type: Optional[str] = Query(None, description="Filter by content type"),
    category: Optional[str] = Query(None, description="Filter by category"),
    subcategory: Optional[str] = Query(None, description="Filter by subcategory"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter by"),
    severity: Optional[str] = Query(None, description="Filter by severity applicability"),
    incident_type: Optional[str] = Query(None, description="Filter by incident type"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    is_active: Optional[bool] = Query(True, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Full-text search query"),
    source: Optional[str] = Query(None, description="Filter by source (builtin, user)"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """
    List knowledge base entries with filtering and search.

    Supports filtering by content type, category, subcategory, tags, severity,
    incident type, IOC type, source, and full-text search across title and content.
    Search ranks title matches above tag matches above content matches.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    # Parse comma-separated tags
    tag_list = [t.strip() for t in tags.split(',')] if tags else None

    entries, total_count = await kb_service.list_entries(
        content_type=content_type,
        category=category,
        subcategory=subcategory,
        tags=tag_list,
        severity=severity,
        incident_type=incident_type,
        ioc_type=ioc_type,
        is_active=is_active,
        search_query=search,
        source=source,
        limit=limit,
        offset=offset
    )

    return {
        "entries": entries,
        "count": len(entries),
        "total_count": total_count,
        "limit": limit,
        "offset": offset
    }


@router.post("/")
async def create_entry(
    entry: KBEntryCreate,
    current_user: str = Depends(get_current_user)
):
    """
    Create a new knowledge base entry.

    Creates an SOP, playbook, escalation policy, or other knowledge base content.
    The entry is immediately active and available for AI queries.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    result = await kb_service.create_entry(
        title=entry.title,
        content=entry.content,
        content_type=entry.content_type,
        category=entry.category,
        subcategory=entry.subcategory,
        tags=entry.tags or [],
        severity_filter=entry.severity_filter or [],
        incident_types=entry.incident_types or [],
        ioc_types=entry.ioc_types or [],
        mitre_techniques=entry.mitre_techniques or [],
        compliance_frameworks=entry.compliance_frameworks or [],
        priority=entry.priority,
        created_by=current_user
    )

    if result.get('error'):
        logger.error(f"Failed to create KB entry: {result['error']}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return result


@router.get("/stats")
async def get_stats(
    source: Optional[str] = Query(None, description="Filter by source (builtin, user)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get knowledge base statistics.

    Returns counts by content type, category, approval status,
    and lists of available content types and categories.
    Optionally scoped to a specific source (builtin or user).
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()
    return await kb_service.get_stats(source=source)


@router.get("/content-types")
async def get_content_types(current_user: dict = Depends(get_current_user)):
    """Get list of available content types."""
    from services.knowledge_base_service import CONTENT_TYPES
    return {"content_types": CONTENT_TYPES}


@router.get("/categories")
async def get_categories(current_user: dict = Depends(get_current_user)):
    """Get list of available categories."""
    from services.knowledge_base_service import CATEGORIES
    return {"categories": CATEGORIES}


# ============================================================================
# COMMUNITY SUBMISSION ENDPOINTS
# ============================================================================

class CommunitySubmitRequest(BaseModel):
    """Request to submit an article for community review."""
    kb_id: str = Field(..., description="KB article ID to submit")


class CommunityReviewRequest(BaseModel):
    """Request to approve or reject a community submission."""
    reviewer_notes: Optional[str] = Field(None, description="Optional notes for the submitter")


@router.post("/community-submissions")
async def submit_to_community(
    request: CommunitySubmitRequest,
    current_user: dict = Depends(get_current_user)
):
    """Submit an organization article for community review."""
    from services.postgres_db import postgres_db
    from services.knowledge_base_service import get_knowledge_base_service

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    kb_service = get_knowledge_base_service()

    # Verify article exists and belongs to the submitting tenant
    entry = await kb_service.get_entry(request.kb_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Article not found")
    if entry.get('source') == 'builtin':
        raise HTTPException(status_code=400, detail="Builtin articles cannot be submitted")

    # Check for existing pending submission
    async with postgres_db.tenant_acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id, status FROM kb_community_submissions WHERE kb_id = $1 AND status = 'pending'",
            request.kb_id
        )
        if existing:
            raise HTTPException(status_code=409, detail="A pending submission already exists for this article")

        # Create submission
        row = await conn.fetchrow(
            """INSERT INTO kb_community_submissions (kb_id, tenant_id, submitted_by)
               VALUES ($1, $2::uuid, $3) RETURNING id, status, created_at""",
            request.kb_id,
            str(current_user['tenant_id']),
            current_user['username']
        )

    return {
        "submission_id": str(row['id']),
        "kb_id": request.kb_id,
        "status": row['status'],
        "created_at": row['created_at'].isoformat() if row['created_at'] else None
    }


@router.get("/community-submissions")
async def list_community_submissions(
    status: Optional[str] = Query('pending', description="Filter by status (pending, approved, rejected)"),
    current_user: dict = Depends(require_admin)
):
    """List community submissions. Platform admin only."""
    from services.postgres_db import postgres_db
    from config.constants import PLATFORM_OWNER_TENANT_ID

    if str(current_user.get('tenant_id')) != PLATFORM_OWNER_TENANT_ID:
        raise HTTPException(status_code=403, detail="Platform admin access required")

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.acquire() as conn:
        query = """
            SELECT s.*, kb.title as article_title, kb.content_type, kb.category
            FROM kb_community_submissions s
            LEFT JOIN knowledge_base kb ON kb.kb_id = s.kb_id
            WHERE 1=1
        """
        params = []
        param_count = 1
        if status:
            query += f" AND s.status = ${param_count}"
            params.append(status)
            param_count += 1
        query += " ORDER BY s.created_at DESC"

        rows = await conn.fetch(query, *params)

    submissions = []
    for row in rows:
        submissions.append({
            "id": str(row['id']),
            "kb_id": row['kb_id'],
            "tenant_id": str(row['tenant_id']),
            "submitted_by": row['submitted_by'],
            "status": row['status'],
            "reviewer_notes": row.get('reviewer_notes'),
            "reviewed_by": row.get('reviewed_by'),
            "reviewed_at": row['reviewed_at'].isoformat() if row.get('reviewed_at') else None,
            "created_at": row['created_at'].isoformat() if row.get('created_at') else None,
            "article_title": row.get('article_title'),
            "content_type": row.get('content_type'),
            "category": row.get('category'),
        })

    return {"submissions": submissions, "count": len(submissions)}


@router.get("/community-submissions/mine")
async def list_my_submissions(
    current_user: dict = Depends(get_current_user)
):
    """List the current user's community submissions."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.tenant_acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM kb_community_submissions
               WHERE tenant_id = $1::uuid
               ORDER BY created_at DESC""",
            str(current_user['tenant_id'])
        )

    submissions = []
    for row in rows:
        submissions.append({
            "id": str(row['id']),
            "kb_id": row['kb_id'],
            "status": row['status'],
            "reviewer_notes": row.get('reviewer_notes'),
            "reviewed_at": row['reviewed_at'].isoformat() if row.get('reviewed_at') else None,
            "created_at": row['created_at'].isoformat() if row.get('created_at') else None,
        })

    return {"submissions": submissions, "count": len(submissions)}


@router.post("/community-submissions/{submission_id}/approve")
async def approve_submission(
    submission_id: str,
    review: CommunityReviewRequest = Body(default=CommunityReviewRequest()),
    current_user: dict = Depends(require_admin)
):
    """Approve a community submission. Clones article as builtin. Platform admin only."""
    import uuid as uuid_mod
    from datetime import datetime, timezone
    from services.postgres_db import postgres_db
    from services.knowledge_base_service import get_knowledge_base_service
    from config.constants import PLATFORM_OWNER_TENANT_ID

    if str(current_user.get('tenant_id')) != PLATFORM_OWNER_TENANT_ID:
        raise HTTPException(status_code=403, detail="Platform admin access required")

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    # Get the submission
    async with postgres_db.acquire() as conn:
        submission = await conn.fetchrow(
            "SELECT * FROM kb_community_submissions WHERE id = $1",
            uuid_mod.UUID(submission_id)
        )
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        if submission['status'] != 'pending':
            raise HTTPException(status_code=400, detail=f"Submission is already {submission['status']}")

    # Get the original article
    kb_service = get_knowledge_base_service()
    original = await kb_service.get_entry(submission['kb_id'])
    if not original:
        raise HTTPException(status_code=404, detail="Original article no longer exists")

    # Clone article as builtin
    new_kb_id = f"KB-COMMUNITY-{uuid_mod.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc)

    async with postgres_db.acquire() as conn:
        # Set tenant context to platform owner for the insert (RLS)
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{PLATFORM_OWNER_TENANT_ID}'")

        await conn.execute("""
            INSERT INTO knowledge_base (
                kb_id, title, content, content_type, category, subcategory,
                tags, severity_filter, incident_types, ioc_types,
                mitre_techniques, compliance_frameworks, priority,
                source, ai_processed, ai_summary, ai_extracted_rules,
                tenant_id, created_by, created_at, approved_at, approved_by, is_active
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13,
                'builtin', $14, $15, $16,
                $17::uuid, $18, $19, $19, $20, TRUE
            )
        """,
            new_kb_id,
            original.get('title', ''),
            original.get('content', ''),
            original.get('content_type', 'sop'),
            original.get('category'),
            original.get('subcategory'),
            original.get('tags', []),
            original.get('severity_filter', []),
            original.get('incident_types', []),
            original.get('ioc_types', []),
            original.get('mitre_techniques', []),
            original.get('compliance_frameworks', []),
            original.get('priority', 100),
            original.get('ai_processed', False),
            original.get('ai_summary'),
            original.get('ai_extracted_rules', '[]'),
            PLATFORM_OWNER_TENANT_ID,
            original.get('created_by', 'community'),
            now,
            current_user['username'],
        )

        # Update submission status
        await conn.execute("""
            UPDATE kb_community_submissions
            SET status = 'approved', reviewed_by = $1, reviewed_at = $2, reviewer_notes = $3
            WHERE id = $4
        """, current_user['username'], now, review.reviewer_notes, uuid_mod.UUID(submission_id))

    return {
        "status": "approved",
        "new_kb_id": new_kb_id,
        "message": "Article published to Community Library"
    }


@router.post("/community-submissions/{submission_id}/reject")
async def reject_submission(
    submission_id: str,
    review: CommunityReviewRequest = Body(default=CommunityReviewRequest()),
    current_user: dict = Depends(require_admin)
):
    """Reject a community submission. Platform admin only."""
    import uuid as uuid_mod
    from datetime import datetime, timezone
    from services.postgres_db import postgres_db
    from config.constants import PLATFORM_OWNER_TENANT_ID

    if str(current_user.get('tenant_id')) != PLATFORM_OWNER_TENANT_ID:
        raise HTTPException(status_code=403, detail="Platform admin access required")

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.acquire() as conn:
        submission = await conn.fetchrow(
            "SELECT * FROM kb_community_submissions WHERE id = $1",
            uuid_mod.UUID(submission_id)
        )
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        if submission['status'] != 'pending':
            raise HTTPException(status_code=400, detail=f"Submission is already {submission['status']}")

        now = datetime.now(timezone.utc)
        await conn.execute("""
            UPDATE kb_community_submissions
            SET status = 'rejected', reviewed_by = $1, reviewed_at = $2, reviewer_notes = $3
            WHERE id = $4
        """, current_user['username'], now, review.reviewer_notes, uuid_mod.UUID(submission_id))

    return {
        "status": "rejected",
        "message": "Submission rejected"
    }


@router.post("/query")
async def query_for_context(query: KBContextQuery, current_user: dict = Depends(get_current_user)):
    """
    Query knowledge base for AI investigation context.

    This endpoint is used by AI agents during investigations to retrieve
    relevant SOPs, playbooks, and handling rules based on the alert/investigation
    context.

    Returns entries with full content suitable for AI consumption.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    results = await kb_service.query_for_context(
        severity=query.severity,
        incident_type=query.incident_type,
        ioc_types=query.ioc_types,
        mitre_techniques=query.mitre_techniques,
        keywords=query.keywords,
        limit=query.limit
    )

    return {
        "results": results,
        "count": len(results),
        "query": query.dict()
    }


@router.post("/semantic-search")
async def semantic_search(
    query: str = Body(..., description="Search query text"),
    limit: int = Body(10, le=50, description="Maximum results"),
    min_similarity: float = Body(0.7, ge=0, le=1, description="Minimum similarity score (0-1)"),
    content_types: Optional[List[str]] = Body(None, description="Filter by content types"),
    categories: Optional[List[str]] = Body(None, description="Filter by categories"),
    current_user: dict = Depends(get_current_user)
):
    """
    Perform semantic search using AI embeddings.

    Finds knowledge base entries that are semantically similar to the query,
    even if they don't contain the exact keywords. Uses vector similarity
    with cosine distance.

    Example: Query "email attack" will find entries about "phishing" even if
    they don't mention the word "email".

    Returns:
        List of KB entries with similarity scores
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    results = await kb_service.semantic_search(
        query=query,
        limit=limit,
        min_similarity=min_similarity,
        content_types=content_types,
        categories=categories
    )

    return {
        "results": results,
        "count": len(results),
        "query": query,
        "min_similarity": min_similarity
    }


# ============================================================================
# SOP RECOMMENDATION ENDPOINTS
# Automatic SOP suggestions based on alert/investigation context
# ============================================================================

class SOPRecommendationQuery(BaseModel):
    """Request model for text-based SOP recommendations."""
    query: str = Field(..., description="Search text for recommendations")
    limit: int = Field(default=5, le=20)
    content_types: Optional[List[str]] = Field(
        default=None,
        description="Filter by content types (sop, playbook, etc.)"
    )


class SOPEffectivenessFeedback(BaseModel):
    """Request model for SOP effectiveness feedback."""
    kb_id: str = Field(..., description="Knowledge base entry ID")
    investigation_id: str = Field(..., description="Investigation ID")
    was_helpful: bool = Field(..., description="Whether the SOP was helpful")
    resolution_time_minutes: Optional[int] = Field(
        None,
        description="Time to resolution in minutes"
    )


@router.get("/recommendations/for-alert/{alert_id}")
async def get_sop_recommendations_for_alert(
    alert_id: str,
    limit: int = Query(5, le=20),
    min_score: float = Query(0.2, ge=0, le=1)
):
    """
    Get SOP recommendations for a specific alert.

    Analyzes the alert's title, description, severity, IOCs, and MITRE techniques
    to recommend relevant SOPs, playbooks, and procedures.

    Returns:
    - recommendations: List of recommended SOPs with relevance scores
    - alert_context: Extracted context used for matching
    - query_time_ms: Query execution time
    """
    from services.postgres_db import postgres_db
    from services.sop_recommendation_service import get_sop_recommendation_service

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    # Get alert data
    async with postgres_db.tenant_acquire() as conn:
        alert = await conn.fetchrow(
            'SELECT * FROM alerts WHERE alert_id = $1',
            alert_id
        )

    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    sop_service = get_sop_recommendation_service()
    result = await sop_service.recommend_for_alert(
        alert_data=dict(alert),
        limit=limit,
        min_score=min_score
    )

    return {
        "recommendations": [
            {
                "kb_id": rec.kb_id,
                "title": rec.title,
                "content_type": rec.content_type,
                "category": rec.category,
                "relevance_score": round(rec.relevance_score, 3),
                "match_reasons": rec.match_reasons,
                "summary": rec.summary,
                "key_steps": rec.key_steps
            }
            for rec in result.recommendations
        ],
        "alert_context": result.alert_context,
        "query_time_ms": round(result.query_time_ms, 2),
        "source": result.source
    }


@router.get("/recommendations/for-investigation/{investigation_id}")
async def get_sop_recommendations_for_investigation(
    investigation_id: str,
    limit: int = Query(5, le=20),
    min_score: float = Query(0.2, ge=0, le=1)
):
    """
    Get SOP recommendations for an ongoing investigation.

    Aggregates context from all linked alerts to provide comprehensive
    SOP recommendations for the investigation.

    Returns:
    - recommendations: List of recommended SOPs with relevance scores
    - alert_context: Aggregated context from all linked alerts
    - query_time_ms: Query execution time
    """
    from services.sop_recommendation_service import get_sop_recommendation_service

    sop_service = get_sop_recommendation_service()
    result = await sop_service.recommend_for_investigation(
        investigation_id=investigation_id,
        limit=limit,
        min_score=min_score
    )

    if result.alert_context.get('error'):
        raise HTTPException(status_code=404, detail=result.alert_context['error'])

    return {
        "recommendations": [
            {
                "kb_id": rec.kb_id,
                "title": rec.title,
                "content_type": rec.content_type,
                "category": rec.category,
                "relevance_score": round(rec.relevance_score, 3),
                "match_reasons": rec.match_reasons,
                "summary": rec.summary,
                "key_steps": rec.key_steps
            }
            for rec in result.recommendations
        ],
        "alert_context": result.alert_context,
        "query_time_ms": round(result.query_time_ms, 2),
        "source": result.source
    }


@router.post("/recommendations/search")
async def search_sop_recommendations(query: SOPRecommendationQuery, current_user: dict = Depends(get_current_user)):
    """
    Search for SOP recommendations using free-text query.

    Uses semantic search to find relevant SOPs based on
    natural language queries like "how to investigate phishing emails"
    or "malware containment procedures".

    Returns:
    - recommendations: List of matching SOPs with similarity scores
    """
    from services.sop_recommendation_service import get_sop_recommendation_service

    sop_service = get_sop_recommendation_service()
    result = await sop_service.recommend_by_text(
        query_text=query.query,
        limit=query.limit,
        content_types=query.content_types
    )

    return {
        "recommendations": [
            {
                "kb_id": rec.kb_id,
                "title": rec.title,
                "content_type": rec.content_type,
                "category": rec.category,
                "relevance_score": round(rec.relevance_score, 3),
                "match_reasons": rec.match_reasons,
                "summary": rec.summary
            }
            for rec in result.recommendations
        ],
        "query": query.query,
        "query_time_ms": round(result.query_time_ms, 2)
    }


@router.post("/recommendations/feedback")
async def submit_sop_effectiveness_feedback(feedback: SOPEffectivenessFeedback, current_user: dict = Depends(get_current_user)):
    """
    Submit feedback on SOP effectiveness.

    Track whether recommended SOPs were helpful for investigations.
    This feedback is used to improve future recommendations.
    """
    from services.sop_recommendation_service import get_sop_recommendation_service

    sop_service = get_sop_recommendation_service()
    await sop_service.track_sop_effectiveness(
        kb_id=feedback.kb_id,
        investigation_id=feedback.investigation_id,
        was_helpful=feedback.was_helpful,
        resolution_time_minutes=feedback.resolution_time_minutes
    )

    return {
        "message": "Feedback recorded successfully",
        "kb_id": feedback.kb_id,
        "investigation_id": feedback.investigation_id
    }


@router.get("/{kb_id}")
async def get_entry(kb_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get a specific knowledge base entry by ID.

    Returns full entry details including content, metadata, and AI analysis.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()
    entry = await kb_service.get_entry(kb_id)

    if not entry:
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    return entry


@router.patch("/{kb_id}")
async def update_entry(
    kb_id: str,
    updates: KBEntryUpdate,
    current_user: str = Depends(get_current_user)
):
    """
    Update a knowledge base entry.

    Creates a version history record before applying updates.
    The change_reason field is recommended for audit purposes.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    # Convert to dict, excluding None values and change_reason
    update_dict = {k: v for k, v in updates.dict().items() if v is not None and k != 'change_reason'}

    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = await kb_service.update_entry(
        kb_id=kb_id,
        updates=update_dict,
        updated_by=current_user,
        change_reason=updates.change_reason
    )

    if not result:
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    return result


@router.delete("/{kb_id}")
async def delete_entry(
    kb_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Delete a knowledge base entry (soft delete).

    Sets is_active=False rather than removing the record.
    Builtin articles cannot be deleted.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()
    result = await kb_service.delete_entry(kb_id, deleted_by=current_user)

    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    if result.get("error") == "builtin_protected":
        raise HTTPException(status_code=403, detail="Builtin knowledge base articles cannot be deleted")

    if not result.get("deleted"):
        logger.error(f"Failed to delete KB entry {kb_id}: {result.get('error', 'Delete failed')}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": f"Deleted knowledge base entry {kb_id}", "kb_id": kb_id}


@router.get("/{kb_id}/versions")
async def get_entry_versions(kb_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get version history for a knowledge base entry.

    Returns all previous versions with timestamps and change reasons.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    # First check entry exists
    entry = await kb_service.get_entry(kb_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    versions = await kb_service.get_entry_versions(kb_id)

    return {
        "kb_id": kb_id,
        "current_version": entry.get('version', 1),
        "versions": versions
    }


@router.post("/{kb_id}/approve")
async def approve_entry(
    kb_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Approve a knowledge base entry.

    Sets approved_by and approved_at fields.
    Typically required before an entry becomes available for production use.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()
    result = await kb_service.approve_entry(kb_id, approved_by=current_user)

    if not result:
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    return result


@router.post("/{kb_id}/duplicate")
async def duplicate_entry(
    kb_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Create a copy of an existing knowledge base entry.

    Useful for creating variations of SOPs or playbooks.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    # Get original entry
    original = await kb_service.get_entry(kb_id)
    if not original:
        raise HTTPException(status_code=404, detail=f"Knowledge base entry {kb_id} not found")

    # Create duplicate with modified title
    result = await kb_service.create_entry(
        title=f"Copy of {original['title']}",
        content=original['content'],
        content_type=original['content_type'],
        category=original.get('category'),
        subcategory=original.get('subcategory'),
        tags=original.get('tags', []),
        severity_filter=original.get('severity_filter', []),
        incident_types=original.get('incident_types', []),
        ioc_types=original.get('ioc_types', []),
        mitre_techniques=original.get('mitre_techniques', []),
        compliance_frameworks=original.get('compliance_frameworks', []),
        priority=original.get('priority', 100),
        created_by=current_user
    )

    if result.get('error'):
        logger.error(f"Failed to duplicate KB entry {kb_id}: {result['error']}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return result


# Document Upload and Processing Routes

class SOARPlaybookImport(BaseModel):
    """Request model for importing a SOAR playbook."""
    playbook_content: str = Field(..., description="Playbook definition content")
    playbook_format: str = Field(..., description="Source format: splunk_soar, palo_xsoar, swimlane, etc.")


@router.post("/upload")
async def upload_documents(
    files: List[UploadFile] = File(...),
    current_user: str = Depends(get_current_user)
):
    """
    Upload one or more documents for AI processing.

    Supports PDF, DOCX, TXT, MD, JSON, YAML files.
    Documents will be analyzed by AI to extract SOPs, playbooks,
    and other knowledge base entries.

    Returns upload_ids that can be used to check processing status.
    """
    from services.kb_document_processor import get_kb_document_processor

    processor = get_kb_document_processor()
    results = []
    errors = []

    for file in files:
        # Validate file type
        filename = file.filename or "unknown"
        file_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

        if file_ext not in processor.supported_types:
            errors.append({
                "filename": filename,
                "error": f"Unsupported file type: {file_ext}. Supported: {', '.join(processor.supported_types)}"
            })
            continue

        # Read file content
        content = await file.read()

        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            errors.append({
                "filename": filename,
                "error": "File too large. Maximum size is 10MB."
            })
            continue

        if len(content) == 0:
            errors.append({
                "filename": filename,
                "error": "File is empty."
            })
            continue

        # Process document
        result = await processor.process_document(
            filename=filename,
            content=content,
            file_type=file_ext,
            uploaded_by=current_user
        )

        if result.get('error'):
            errors.append({
                "filename": filename,
                "error": result['error']
            })
        else:
            results.append(result)

    return {
        "uploads": results,
        "errors": errors,
        "total_files": len(files),
        "successful": len(results),
        "failed": len(errors)
    }


@router.get("/uploads")
async def list_uploads(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, le=200)
):
    """
    List document upload/processing jobs.

    Returns recent uploads with their processing status and results.
    """
    from services.kb_document_processor import get_kb_document_processor

    processor = get_kb_document_processor()
    uploads = await processor.list_uploads(status=status, limit=limit)

    return {
        "uploads": uploads,
        "count": len(uploads)
    }


@router.get("/uploads/{upload_id}")
async def get_upload_status(upload_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get status of a document upload/processing job.

    Returns processing status, any errors, and resulting KB entries.
    """
    from services.kb_document_processor import get_kb_document_processor

    processor = get_kb_document_processor()
    status = await processor.get_upload_status(upload_id)

    if not status:
        raise HTTPException(status_code=404, detail=f"Upload {upload_id} not found")

    return status


@router.post("/import/soar-playbook")
async def import_soar_playbook(
    data: SOARPlaybookImport,
    current_user: str = Depends(get_current_user)
):
    """
    Import and convert a SOAR playbook to knowledge base entries.

    Supports playbooks from various SOAR platforms:
    - splunk_soar (Splunk SOAR/Phantom)
    - palo_xsoar (Palo Alto XSOAR/Demisto)
    - swimlane
    - siemplify
    - custom

    The playbook will be analyzed by AI and converted into
    human-readable SOPs with extracted rules and procedures.
    """
    from services.kb_document_processor import get_kb_document_processor

    processor = get_kb_document_processor()

    result = await processor.process_soar_playbook(
        playbook_content=data.playbook_content,
        playbook_format=data.playbook_format,
        uploaded_by=current_user
    )

    if result.get('error'):
        logger.error(f"Failed to import SOAR playbook: {result['error']}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return result


@router.post("/import/text")
async def import_from_text(
    title: str = Form(..., description="Entry title"),
    content: str = Form(..., description="Text content to import"),
    process_with_ai: bool = Form(True, description="Process with AI to extract rules"),
    current_user: str = Depends(get_current_user)
):
    """
    Import text content directly into the knowledge base.

    Optionally processes with AI to:
    - Extract actionable rules
    - Generate summary
    - Auto-categorize and tag
    """
    from services.knowledge_base_service import get_knowledge_base_service
    from services.kb_document_processor import get_kb_document_processor

    kb_service = get_knowledge_base_service()

    if process_with_ai:
        # Use AI to analyze and structure the content
        processor = get_kb_document_processor()
        result = await processor.process_document(
            filename=f"{title}.txt",
            content=content.encode('utf-8'),
            file_type='txt',
            uploaded_by=current_user
        )

        if result.get('error'):
            logger.error(f"Failed to import text with AI: {result['error']}")
            raise HTTPException(status_code=500, detail="Internal server error")

        return result
    else:
        # Create entry directly without AI processing
        result = await kb_service.create_entry(
            title=title,
            content=content,
            content_type='sop',
            created_by=current_user
        )

        if result.get('error'):
            logger.error(f"Failed to import text: {result['error']}")
            raise HTTPException(status_code=500, detail="Internal server error")

        return result


# ============================================================================
# RIGGS-SPECIFIC ENDPOINTS
# These endpoints support the Riggs AI agent's knowledge base interactions
# ============================================================================

class RiggsDraftCreate(BaseModel):
    """Request model for Riggs to create a KB draft."""
    title: str = Field(..., description="Draft title")
    content: str = Field(..., description="Draft content")
    related_alerts: Optional[List[str]] = Field(default=[], description="Alert IDs that triggered this draft")
    suggested_tags: Optional[List[str]] = Field(default=[], description="AI-suggested tags")
    suggested_mitre: Optional[List[str]] = Field(default=[], description="AI-suggested MITRE techniques")
    category: Optional[str] = Field(None, description="Suggested category")
    content_type: str = Field(default='sop', description="Type of content")


class RiggsDraftReview(BaseModel):
    """Request model for reviewing a Riggs draft."""
    edits: Optional[Dict[str, Any]] = Field(None, description="Optional edits to apply")
    reason: Optional[str] = Field(None, description="Reason for approval/rejection")


@router.get("/riggs/drafts")
async def get_riggs_drafts(
    limit: int = Query(50, le=200),
    current_user: str = Depends(get_current_user)
):
    """
    Get pending Riggs-authored KB drafts awaiting review.

    Returns drafts created by Riggs that need human approval before publishing.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()
    drafts = await kb_service.get_riggs_drafts(limit=limit)

    return {
        "drafts": drafts,
        "count": len(drafts),
        "status": "draft"
    }


@router.post("/riggs/drafts")
async def create_riggs_draft(
    draft: RiggsDraftCreate
):
    """
    Create a new KB draft authored by Riggs.

    Riggs uses this endpoint to propose new knowledge base entries.
    All drafts require human approval before being published.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    result = await kb_service.create_riggs_draft(
        title=draft.title,
        content=draft.content,
        related_alerts=draft.related_alerts or [],
        suggested_tags=draft.suggested_tags or [],
        suggested_mitre=draft.suggested_mitre or [],
        category=draft.category,
        content_type=draft.content_type
    )

    if result.get('error'):
        logger.error(f"Failed to create Riggs draft: {result['error']}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return result


@router.post("/riggs/drafts/{kb_id}/approve")
async def approve_riggs_draft(
    kb_id: str,
    review: RiggsDraftReview = Body(default=RiggsDraftReview()),
    current_user: str = Depends(get_current_user)
):
    """
    Approve a Riggs-authored KB draft.

    Approving publishes the draft to the knowledge base.
    Optional edits can be applied during approval.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    result = await kb_service.approve_riggs_draft(
        kb_id=kb_id,
        approved_by=current_user,
        edits=review.edits
    )

    if not result:
        raise HTTPException(status_code=404, detail=f"Draft {kb_id} not found")

    if result.get('error'):
        raise HTTPException(status_code=400, detail=result['error'])

    return result


@router.post("/riggs/drafts/{kb_id}/reject")
async def reject_riggs_draft(
    kb_id: str,
    review: RiggsDraftReview = Body(default=RiggsDraftReview()),
    current_user: str = Depends(get_current_user)
):
    """
    Reject a Riggs-authored KB draft.

    Rejected drafts are archived and not published.
    A reason should be provided for Riggs to learn from.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    result = await kb_service.reject_riggs_draft(
        kb_id=kb_id,
        rejected_by=current_user,
        reason=review.reason
    )

    if not result:
        raise HTTPException(status_code=404, detail=f"Draft {kb_id} not found")

    if result.get('error'):
        raise HTTPException(status_code=400, detail=result['error'])

    return result


@router.post("/riggs/query")
async def riggs_kb_query(
    alert_data: Optional[Dict[str, Any]] = Body(None, description="Alert data for context"),
    keywords: Optional[List[str]] = Body(None, description="Keywords to search"),
    limit: int = Body(default=10, le=50)
):
    """
    Query knowledge base for Riggs investigation context.

    This endpoint is optimized for Riggs to retrieve relevant KB articles
    during alert analysis. It considers:
    - Alert severity and type
    - IOC types present
    - MITRE techniques
    - Keywords from alert content

    Returns articles sorted by relevance with full content.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    results = await kb_service.query_for_riggs(
        alert_data=alert_data,
        keywords=keywords,
        limit=limit
    )

    return {
        "articles": results,
        "count": len(results)
    }


@router.post("/{kb_id}/record-usage")
async def record_kb_usage(kb_id: str, current_user: dict = Depends(get_current_user)):
    """
    Record that a KB article was used by Riggs.

    Updates usage_count and last_used_at for analytics
    and to help surface frequently-used articles.
    """
    from services.knowledge_base_service import get_knowledge_base_service

    kb_service = get_knowledge_base_service()

    success = await kb_service.record_kb_usage(kb_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"KB entry {kb_id} not found")

    return {"success": True, "kb_id": kb_id}
