# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation API Routes
Endpoints for viewing investigation details, correlated alerts, and correlation explanations.

Provides analysts with:
1. Full investigation details including entity summaries
2. All correlated alerts with complete data (raw_event, enrichment, AI analysis)
3. Correlation explanations showing WHY each alert was linked

All endpoints require authentication.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime
import logging
import json

from dependencies.auth import get_current_user
from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/investigation-details", tags=["Investigation Details"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Response Models
# ============================================================================

class CorrelationMetadata(BaseModel):
    """Explains WHY an alert was correlated to an investigation."""
    decision_type: str  # auto_link, soft_link, create_new, legacy
    score: Optional[int] = None
    threshold: Optional[int] = None
    reasons: List[str] = []
    matched_entities: List[str] = []
    linked_at: Optional[datetime] = None


class CorrelatedAlert(BaseModel):
    """Full alert data with correlation explanation."""
    # Core fields
    id: str
    alert_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    source: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    # Full alert data
    raw_event: Dict[str, Any] = {}
    enrichment_data: Dict[str, Any] = {}
    ai_verdict: Optional[str] = None
    ai_reasoning: Optional[str] = None
    ai_summary: Optional[str] = None
    extracted_entities: Dict[str, List[str]] = {}
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

    # Correlation explanation
    correlation: CorrelationMetadata


class AlertListResponse(BaseModel):
    """Paginated list of correlated alerts."""
    items: List[CorrelatedAlert]
    total: int
    limit: int
    offset: int
    has_more: bool


class InvestigationDetailResponse(BaseModel):
    """Full investigation details with optional alerts."""
    # Core investigation fields
    id: str
    investigation_id: str
    state: str
    disposition: Optional[str] = None
    priority: str
    owner: Optional[str] = None

    # Analysis results
    alert_title: Optional[str] = None
    executive_summary: Optional[str] = None
    confidence: Optional[float] = None
    severity: Optional[str] = None

    # Timestamps
    created_at: datetime
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Entity summary
    alert_count: int = 0
    entity_summary: Dict[str, int] = {}
    primary_entity_type: Optional[str] = None
    primary_entity_value: Optional[str] = None
    user_count: int = 0
    host_count: int = 0

    # Full investigation data
    investigation_data: Dict[str, Any] = {}

    # Correlated alerts (optional, if include_alerts=true)
    alerts: Optional[AlertListResponse] = None


class InvestigationListItem(BaseModel):
    """Investigation summary for list view."""
    id: str
    investigation_id: str
    state: str
    disposition: Optional[str] = None
    priority: str
    owner: Optional[str] = None
    alert_title: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    alert_count: int = 0
    entity_summary: Dict[str, int] = {}
    user_count: int = 0
    host_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


class InvestigationListResponse(BaseModel):
    """Paginated list of investigations."""
    items: List[InvestigationListItem]
    total: int
    limit: int
    offset: int
    has_more: bool


# ============================================================================
# Helper Functions
# ============================================================================

def _parse_jsonb(value: Any, default: Any = None) -> Any:
    """Safely parse JSONB field from database."""
    if value is None:
        return default if default is not None else {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return default if default is not None else {}
    return value


def _extract_ai_fields(raw_event: Dict[str, Any], investigation_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract AI analysis fields from raw_event or investigation_data."""
    ai_fields = {
        "ai_verdict": None,
        "ai_reasoning": None,
        "ai_summary": None,
        "mitre_tactics": [],
        "mitre_techniques": []
    }

    # Check raw_event first
    if raw_event:
        ai_fields["ai_verdict"] = raw_event.get("ai_verdict") or raw_event.get("verdict")
        ai_fields["ai_reasoning"] = raw_event.get("ai_reasoning") or raw_event.get("reasoning")
        ai_fields["ai_summary"] = raw_event.get("ai_summary") or raw_event.get("summary")
        ai_fields["mitre_tactics"] = raw_event.get("mitre_tactics", []) or []
        ai_fields["mitre_techniques"] = raw_event.get("mitre_techniques", []) or []

    # Check investigation_data as fallback
    if investigation_data:
        if not ai_fields["ai_verdict"]:
            ai_fields["ai_verdict"] = investigation_data.get("ai_verdict") or investigation_data.get("verdict")
        if not ai_fields["ai_reasoning"]:
            ai_fields["ai_reasoning"] = investigation_data.get("ai_reasoning") or investigation_data.get("reasoning")
        if not ai_fields["ai_summary"]:
            ai_fields["ai_summary"] = investigation_data.get("ai_summary") or investigation_data.get("summary")
        if not ai_fields["mitre_tactics"]:
            ai_fields["mitre_tactics"] = investigation_data.get("mitre_tactics", []) or []
        if not ai_fields["mitre_techniques"]:
            ai_fields["mitre_techniques"] = investigation_data.get("mitre_techniques", []) or []

    return ai_fields


async def _get_correlated_alerts(
    investigation_uuid: str,
    limit: int = 50,
    offset: int = 0
) -> tuple[List[CorrelatedAlert], int]:
    """
    Fetch all alerts correlated to an investigation with full data and correlation explanations.

    Returns:
        Tuple of (list of CorrelatedAlert, total count)
    """
    async with postgres_db.tenant_acquire() as conn:
        # Get total count
        count_row = await conn.fetchrow("""
            SELECT COUNT(*) as total
            FROM alerts a
            WHERE a.investigation_id = $1
        """, investigation_uuid)
        total = count_row["total"] if count_row else 0

        # Try full query with correlation_decisions join; fall back to simple query
        # if tables/columns are missing (graceful degradation)
        rows = None
        use_full_query = True
        try:
            rows = await conn.fetch("""
                SELECT
                    a.id,
                    a.alert_id,
                    a.title,
                    a.description,
                    a.severity,
                    a.status,
                    a.source,
                    a.created_at,
                    a.updated_at,
                    a.raw_event,
                    a.extracted_entities,
                    a.correlation_score,
                    a.correlation_decision,
                    a.correlation_reasons,

                    -- Correlation decision details (from correlation_decisions table)
                    cd.decision_type,
                    cd.score as cd_score,
                    cd.threshold as cd_threshold,
                    cd.reasons as cd_reasons,
                    cd.matched_entities as cd_matched_entities,
                    cd.created_at as cd_linked_at

                FROM alerts a
                LEFT JOIN correlation_decisions cd ON cd.alert_id = a.id
                WHERE a.investigation_id = $1
                ORDER BY a.created_at DESC
                LIMIT $2 OFFSET $3
            """, investigation_uuid, limit, offset)
        except Exception as e:
            error_msg = str(e)
            if "does not exist" in error_msg:
                logger.warning(f"Correlation tables/columns missing, using fallback query: {error_msg}")
                use_full_query = False
            else:
                raise

        # Fallback: simple query without correlation_decisions join or new columns
        if not use_full_query:
            rows = await conn.fetch("""
                SELECT
                    a.id,
                    a.alert_id,
                    a.title,
                    a.description,
                    a.severity,
                    a.status,
                    a.source,
                    a.created_at,
                    a.updated_at,
                    a.raw_event
                FROM alerts a
                WHERE a.investigation_id = $1
                ORDER BY a.created_at DESC
                LIMIT $2 OFFSET $3
            """, investigation_uuid, limit, offset)

        alerts = []
        for row in rows:
            raw_event = _parse_jsonb(row["raw_event"], {})
            extracted_entities = _parse_jsonb(row.get("extracted_entities") if use_full_query else None, {})

            # Extract AI fields
            ai_fields = _extract_ai_fields(raw_event, {})

            # Extract enrichment data from raw_event if present
            enrichment_data = raw_event.get("enrichment", {}) or raw_event.get("enrichment_data", {}) or {}

            # Build correlation metadata
            if use_full_query:
                decision_type = row["decision_type"] or row["correlation_decision"] or "legacy"
                score = row["cd_score"] if row["cd_score"] is not None else row["correlation_score"]
                threshold = row["cd_threshold"]
                reasons = _parse_jsonb(row["cd_reasons"], []) or _parse_jsonb(row["correlation_reasons"], [])
                matched_entities = _parse_jsonb(row["cd_matched_entities"], [])
                linked_at = row["cd_linked_at"] or row["created_at"]
            else:
                decision_type = "legacy"
                score = None
                threshold = None
                reasons = []
                matched_entities = []
                linked_at = row["created_at"]

            correlation = CorrelationMetadata(
                decision_type=decision_type,
                score=score,
                threshold=threshold,
                reasons=reasons if isinstance(reasons, list) else [],
                matched_entities=matched_entities if isinstance(matched_entities, list) else [],
                linked_at=linked_at
            )

            alert = CorrelatedAlert(
                id=str(row["id"]),
                alert_id=row["alert_id"],
                title=row["title"],
                description=row["description"],
                severity=row["severity"],
                status=row["status"],
                source=row["source"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                raw_event=raw_event,
                enrichment_data=enrichment_data,
                ai_verdict=ai_fields["ai_verdict"],
                ai_reasoning=ai_fields["ai_reasoning"],
                ai_summary=ai_fields["ai_summary"],
                extracted_entities=extracted_entities,
                mitre_tactics=ai_fields["mitre_tactics"],
                mitre_techniques=ai_fields["mitre_techniques"],
                correlation=correlation
            )
            alerts.append(alert)

        return alerts, total


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    state: Optional[str] = Query(None, description="Filter by state (comma-separated)"),
    disposition: Optional[str] = Query(None, description="Filter by disposition"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    owner: Optional[str] = Query(None, description="Filter by owner"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, le=500, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: dict = Depends(get_current_user)
):
    """
    List investigations with optional filtering.

    Returns investigation summaries with alert counts and entity summaries.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build dynamic query
            conditions = []
            params = []
            param_idx = 1

            if state:
                states = [s.strip().upper() for s in state.split(",")]
                conditions.append(f"i.state = ANY(${param_idx})")
                params.append(states)
                param_idx += 1

            if disposition:
                conditions.append(f"i.disposition = ${param_idx}")
                params.append(disposition.upper())
                param_idx += 1

            if priority:
                conditions.append(f"i.priority = ${param_idx}")
                params.append(priority.upper())
                param_idx += 1

            if owner:
                conditions.append(f"i.owner = ${param_idx}")
                params.append(owner)
                param_idx += 1

            if severity:
                conditions.append(f"i.severity = ${param_idx}")
                params.append(severity.lower())
                param_idx += 1

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM investigations i {where_clause}"
            count_row = await conn.fetchrow(count_query, *params)
            total = count_row["total"] if count_row else 0

            # Get investigations with alert counts
            query = f"""
                SELECT
                    i.id,
                    i.investigation_id,
                    i.state,
                    i.disposition,
                    i.priority,
                    i.owner,
                    i.alert_title,
                    i.severity,
                    i.confidence,
                    i.created_at,
                    i.updated_at,
                    i.entity_summary,
                    i.user_count,
                    i.host_count,
                    COALESCE(
                        (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id),
                        0
                    ) as alert_count
                FROM investigations i
                {where_clause}
                ORDER BY i.created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            params.extend([limit, offset])

            rows = await conn.fetch(query, *params)

            items = []
            for row in rows:
                entity_summary = _parse_jsonb(row["entity_summary"], {})

                items.append(InvestigationListItem(
                    id=str(row["id"]),
                    investigation_id=row["investigation_id"],
                    state=row["state"],
                    disposition=row["disposition"],
                    priority=row["priority"],
                    owner=row["owner"],
                    alert_title=row["alert_title"],
                    severity=row["severity"],
                    confidence=float(row["confidence"]) if row["confidence"] else None,
                    alert_count=row["alert_count"],
                    entity_summary=entity_summary,
                    user_count=row["user_count"] or 0,
                    host_count=row["host_count"] or 0,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"]
                ))

            return InvestigationListResponse(
                items=items,
                total=total,
                limit=limit,
                offset=offset,
                has_more=(offset + len(items)) < total
            )

    except Exception as e:
        logger.error(f"Failed to list investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}", response_model=InvestigationDetailResponse)
async def get_investigation(
    investigation_id: str,
    include_alerts: bool = Query(True, description="Include correlated alerts in response"),
    alert_limit: int = Query(50, le=200, description="Max alerts to include"),
    alert_offset: int = Query(0, ge=0, description="Offset for alert pagination"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get full investigation details by ID.

    Returns:
    - Complete investigation metadata
    - Entity summary (users, hosts, MITRE techniques)
    - Optionally: All correlated alerts with full data and correlation explanations

    The investigation_id can be either the UUID or the human-readable ID (e.g., INV-12345678).
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Try to find by investigation_id (human-readable) or UUID
            row = await conn.fetchrow("""
                SELECT
                    i.id,
                    i.investigation_id,
                    i.state,
                    i.disposition,
                    i.priority,
                    i.owner,
                    i.alert_title,
                    i.executive_summary,
                    i.confidence,
                    i.severity,
                    i.created_at,
                    i.updated_at,
                    i.completed_at,
                    i.investigation_data,
                    i.entity_summary,
                    i.primary_entity_type,
                    i.primary_entity_value,
                    i.user_count,
                    i.host_count,
                    COALESCE(
                        (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id),
                        0
                    ) as alert_count
                FROM investigations i
                WHERE i.investigation_id = $1 OR i.id::text = $1
            """, investigation_id)

            if not row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = row["id"]
            entity_summary = _parse_jsonb(row["entity_summary"], {})
            investigation_data = _parse_jsonb(row["investigation_data"], {})

            # Build response
            response = InvestigationDetailResponse(
                id=str(row["id"]),
                investigation_id=row["investigation_id"],
                state=row["state"],
                disposition=row["disposition"],
                priority=row["priority"],
                owner=row["owner"],
                alert_title=row["alert_title"],
                executive_summary=row["executive_summary"],
                confidence=float(row["confidence"]) if row["confidence"] else None,
                severity=row["severity"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                completed_at=row["completed_at"],
                alert_count=row["alert_count"],
                entity_summary=entity_summary,
                primary_entity_type=row["primary_entity_type"],
                primary_entity_value=row["primary_entity_value"],
                user_count=row["user_count"] or 0,
                host_count=row["host_count"] or 0,
                investigation_data=investigation_data
            )

            # Include alerts if requested
            if include_alerts:
                alerts, total = await _get_correlated_alerts(
                    investigation_uuid,
                    limit=alert_limit,
                    offset=alert_offset
                )

                response.alerts = AlertListResponse(
                    items=alerts,
                    total=total,
                    limit=alert_limit,
                    offset=alert_offset,
                    has_more=(alert_offset + len(alerts)) < total
                )

            return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}/alerts", response_model=AlertListResponse)
async def get_investigation_alerts(
    investigation_id: str,
    limit: int = Query(50, le=200, description="Maximum alerts to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get paginated list of all alerts correlated to an investigation.

    Returns full alert data including:
    - raw_event (original alert payload)
    - enrichment data
    - AI analysis (verdict, reasoning, summary)
    - extracted entities
    - MITRE tactics and techniques
    - Correlation explanation (decision type, score, reasons)

    Use this endpoint when you need to paginate through many alerts.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Find investigation UUID
            inv_row = await conn.fetchrow("""
                SELECT id FROM investigations
                WHERE investigation_id = $1 OR id::text = $1
            """, investigation_id)

            if not inv_row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = inv_row["id"]

            # If severity filter is provided, we need a custom query
            if severity:
                async with postgres_db.tenant_acquire() as conn2:
                    # Get total count with filter
                    count_row = await conn2.fetchrow("""
                        SELECT COUNT(*) as total
                        FROM alerts a
                        WHERE a.investigation_id = $1 AND a.severity = $2
                    """, investigation_uuid, severity.lower())
                    total = count_row["total"] if count_row else 0

                    # Get alerts with filter
                    rows = await conn2.fetch("""
                        SELECT
                            a.id,
                            a.alert_id,
                            a.title,
                            a.description,
                            a.severity,
                            a.status,
                            a.source,
                            a.created_at,
                            a.updated_at,
                            a.raw_event,
                            a.extracted_entities,
                            a.correlation_score,
                            a.correlation_decision,
                            a.correlation_reasons,
                            cd.decision_type,
                            cd.score as cd_score,
                            cd.threshold as cd_threshold,
                            cd.reasons as cd_reasons,
                            cd.matched_entities as cd_matched_entities,
                            cd.created_at as cd_linked_at
                        FROM alerts a
                        LEFT JOIN correlation_decisions cd ON cd.alert_id = a.id
                        WHERE a.investigation_id = $1 AND a.severity = $2
                        ORDER BY a.created_at DESC
                        LIMIT $3 OFFSET $4
                    """, investigation_uuid, severity.lower(), limit, offset)

                    alerts = []
                    for row in rows:
                        raw_event = _parse_jsonb(row["raw_event"], {})
                        extracted_entities = _parse_jsonb(row["extracted_entities"], {})
                        ai_fields = _extract_ai_fields(raw_event, {})
                        enrichment_data = raw_event.get("enrichment", {}) or raw_event.get("enrichment_data", {}) or {}

                        decision_type = row["decision_type"] or row["correlation_decision"] or "legacy"
                        score = row["cd_score"] if row["cd_score"] is not None else row["correlation_score"]
                        threshold = row["cd_threshold"]
                        reasons = _parse_jsonb(row["cd_reasons"], []) or _parse_jsonb(row["correlation_reasons"], [])
                        matched_entities = _parse_jsonb(row["cd_matched_entities"], [])
                        linked_at = row["cd_linked_at"] or row["created_at"]

                        correlation = CorrelationMetadata(
                            decision_type=decision_type,
                            score=score,
                            threshold=threshold,
                            reasons=reasons if isinstance(reasons, list) else [],
                            matched_entities=matched_entities if isinstance(matched_entities, list) else [],
                            linked_at=linked_at
                        )

                        alert = CorrelatedAlert(
                            id=str(row["id"]),
                            alert_id=row["alert_id"],
                            title=row["title"],
                            description=row["description"],
                            severity=row["severity"],
                            status=row["status"],
                            source=row["source"],
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                            raw_event=raw_event,
                            enrichment_data=enrichment_data,
                            ai_verdict=ai_fields["ai_verdict"],
                            ai_reasoning=ai_fields["ai_reasoning"],
                            ai_summary=ai_fields["ai_summary"],
                            extracted_entities=extracted_entities,
                            mitre_tactics=ai_fields["mitre_tactics"],
                            mitre_techniques=ai_fields["mitre_techniques"],
                            correlation=correlation
                        )
                        alerts.append(alert)

                    return AlertListResponse(
                        items=alerts,
                        total=total,
                        limit=limit,
                        offset=offset,
                        has_more=(offset + len(alerts)) < total
                    )

            # No filter - use helper function
            alerts, total = await _get_correlated_alerts(
                investigation_uuid,
                limit=limit,
                offset=offset
            )

            return AlertListResponse(
                items=alerts,
                total=total,
                limit=limit,
                offset=offset,
                has_more=(offset + len(alerts)) < total
            )

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "does not exist" in error_msg:
            logger.warning(f"Correlation tables/columns missing for {investigation_id}, returning empty: {error_msg}")
            return AlertListResponse(items=[], total=0, limit=limit, offset=offset, has_more=False)
        logger.error(f"Failed to get alerts for investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}/entities")
async def get_investigation_entities(
    investigation_id: str,
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get all entities associated with an investigation.

    Returns entities grouped by type with their values, confidence scores,
    and alert counts.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Find investigation UUID
            inv_row = await conn.fetchrow("""
                SELECT id FROM investigations
                WHERE investigation_id = $1 OR id::text = $1
            """, investigation_id)

            if not inv_row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = inv_row["id"]

            # Build query
            if entity_type:
                rows = await conn.fetch("""
                    SELECT
                        ie.entity_type,
                        ie.entity_value,
                        ie.confidence,
                        ie.alert_count,
                        ie.first_seen,
                        ie.last_seen,
                        ie.metadata,
                        et.display_name as type_display_name,
                        et.priority as type_priority
                    FROM investigation_entities ie
                    JOIN entity_types et ON et.type_code = ie.entity_type
                    WHERE ie.investigation_id = $1 AND ie.entity_type = $2
                    ORDER BY ie.confidence DESC, ie.alert_count DESC
                """, investigation_uuid, entity_type)
            else:
                rows = await conn.fetch("""
                    SELECT
                        ie.entity_type,
                        ie.entity_value,
                        ie.confidence,
                        ie.alert_count,
                        ie.first_seen,
                        ie.last_seen,
                        ie.metadata,
                        et.display_name as type_display_name,
                        et.priority as type_priority
                    FROM investigation_entities ie
                    JOIN entity_types et ON et.type_code = ie.entity_type
                    WHERE ie.investigation_id = $1
                    ORDER BY et.priority, ie.confidence DESC, ie.alert_count DESC
                """, investigation_uuid)

            # Group by entity type
            entities_by_type = {}
            for row in rows:
                et = row["entity_type"]
                if et not in entities_by_type:
                    entities_by_type[et] = {
                        "type": et,
                        "display_name": row["type_display_name"],
                        "priority": row["type_priority"],
                        "values": []
                    }

                entities_by_type[et]["values"].append({
                    "value": row["entity_value"],
                    "confidence": row["confidence"],
                    "alert_count": row["alert_count"],
                    "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                    "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                    "metadata": _parse_jsonb(row["metadata"], {})
                })

            return {
                "investigation_id": investigation_id,
                "entity_types": list(entities_by_type.values()),
                "total_entities": sum(len(et["values"]) for et in entities_by_type.values())
            }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "does not exist" in error_msg:
            logger.warning(f"Entity tables missing for {investigation_id}, returning empty: {error_msg}")
            return {
                "investigation_id": investigation_id,
                "entity_types": [],
                "total_entities": 0
            }
        logger.error(f"Failed to get entities for investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}/correlation-history")
async def get_correlation_history(
    investigation_id: str,
    limit: int = Query(100, le=500),
    current_user: dict = Depends(get_current_user)
):
    """
    Get the correlation decision history for all alerts in an investigation.

    Shows the timeline of how alerts were correlated, including scores and reasons.
    Useful for understanding how an investigation grew over time.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Find investigation UUID
            inv_row = await conn.fetchrow("""
                SELECT id FROM investigations
                WHERE investigation_id = $1 OR id::text = $1
            """, investigation_id)

            if not inv_row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = inv_row["id"]

            # Get correlation decisions for this investigation
            rows = await conn.fetch("""
                SELECT
                    cd.id,
                    cd.alert_id,
                    a.alert_id as alert_external_id,
                    a.title as alert_title,
                    cd.decision_type,
                    cd.score,
                    cd.threshold,
                    cd.reasons,
                    cd.matched_entities,
                    cd.guardrails_applied,
                    cd.processing_time_ms,
                    cd.created_at
                FROM correlation_decisions cd
                JOIN alerts a ON a.id = cd.alert_id
                WHERE cd.investigation_id = $1
                ORDER BY cd.created_at ASC
                LIMIT $2
            """, investigation_uuid, limit)

            history = []
            for row in rows:
                history.append({
                    "decision_id": str(row["id"]),
                    "alert_id": str(row["alert_id"]),
                    "alert_external_id": row["alert_external_id"],
                    "alert_title": row["alert_title"],
                    "decision_type": row["decision_type"],
                    "score": row["score"],
                    "threshold": row["threshold"],
                    "reasons": _parse_jsonb(row["reasons"], []),
                    "matched_entities": _parse_jsonb(row["matched_entities"], []),
                    "guardrails_applied": _parse_jsonb(row["guardrails_applied"], []),
                    "processing_time_ms": row["processing_time_ms"],
                    "linked_at": row["created_at"].isoformat() if row["created_at"] else None
                })

            return {
                "investigation_id": investigation_id,
                "correlation_history": history,
                "total_decisions": len(history)
            }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "does not exist" in error_msg:
            logger.warning(f"Correlation tables missing for {investigation_id}, returning empty history: {error_msg}")
            return {"investigation_id": investigation_id, "decisions": [], "total": 0}
        logger.error(f"Failed to get correlation history for {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}/summary")
async def get_investigation_summary(
    investigation_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get a concise summary of an investigation for quick reference.

    This is designed for AI agents (like Riggs) to quickly answer questions like:
    - "How many alerts are in this investigation?"
    - "What are the key entities?"
    - "What's the current state?"

    Returns a text-friendly summary with key metrics.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get investigation with alert count
            row = await conn.fetchrow("""
                SELECT
                    i.id,
                    i.investigation_id,
                    i.state,
                    i.disposition,
                    i.priority,
                    i.severity,
                    i.owner,
                    i.alert_title,
                    i.executive_summary,
                    i.confidence,
                    i.user_count,
                    i.host_count,
                    i.entity_summary,
                    i.created_at,
                    i.updated_at,
                    COALESCE(
                        (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id),
                        0
                    ) as alert_count
                FROM investigations i
                WHERE i.investigation_id = $1 OR i.id::text = $1
            """, investigation_id)

            if not row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = row["id"]

            # Get severity breakdown
            severity_breakdown = await conn.fetch("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE investigation_id = $1
                GROUP BY severity
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END
            """, investigation_uuid)

            # Get top entities
            top_entities = await conn.fetch("""
                SELECT entity_type, entity_value, confidence, alert_count
                FROM investigation_entities
                WHERE investigation_id = $1
                ORDER BY
                    CASE entity_type
                        WHEN 'user' THEN 1
                        WHEN 'host' THEN 2
                        WHEN 'mitre_technique' THEN 3
                        ELSE 4
                    END,
                    confidence DESC
                LIMIT 10
            """, investigation_uuid)

            # Get time range
            time_range = await conn.fetchrow("""
                SELECT MIN(created_at) as first_alert, MAX(created_at) as last_alert
                FROM alerts
                WHERE investigation_id = $1
            """, investigation_uuid)

            # Build severity summary
            severities = {s["severity"]: s["count"] for s in severity_breakdown}

            # Build entity lists
            users = [e["entity_value"] for e in top_entities if e["entity_type"] == "user"]
            hosts = [e["entity_value"] for e in top_entities if e["entity_type"] == "host"]
            mitre = [e["entity_value"] for e in top_entities if e["entity_type"] == "mitre_technique"]

            # Format time range
            first_alert_time = time_range["first_alert"] if time_range else None
            last_alert_time = time_range["last_alert"] if time_range else None

            return {
                "investigation_id": row["investigation_id"],
                "state": row["state"],
                "disposition": row["disposition"],
                "priority": row["priority"],
                "severity": row["severity"],
                "owner": row["owner"],
                "title": row["alert_title"],
                "executive_summary": row["executive_summary"],
                "confidence": float(row["confidence"]) if row["confidence"] else None,

                # Key metrics
                "alert_count": row["alert_count"],
                "user_count": row["user_count"] or 0,
                "host_count": row["host_count"] or 0,

                # Severity breakdown
                "alerts_by_severity": {
                    "critical": severities.get("critical", 0),
                    "high": severities.get("high", 0),
                    "medium": severities.get("medium", 0),
                    "low": severities.get("low", 0),
                    "info": severities.get("info", 0)
                },

                # Key entities
                "key_users": users[:5],
                "key_hosts": hosts[:5],
                "mitre_techniques": mitre[:5],

                # Timeline
                "first_alert_at": first_alert_time.isoformat() if first_alert_time else None,
                "last_alert_at": last_alert_time.isoformat() if last_alert_time else None,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,

                # Human-readable summary for AI
                "text_summary": f"Investigation {row['investigation_id']} ({row['state']}) contains {row['alert_count']} alert(s). "
                    + (f"Severity: {row['severity'] or 'unknown'}. " if row['severity'] else "")
                    + (f"Priority: {row['priority']}. " if row['priority'] else "")
                    + (f"Involves {row['user_count'] or 0} user(s) and {row['host_count'] or 0} host(s). " if row['user_count'] or row['host_count'] else "")
                    + (f"Users: {', '.join(users[:3])}. " if users else "")
                    + (f"Hosts: {', '.join(hosts[:3])}. " if hosts else "")
                    + (f"MITRE: {', '.join(mitre[:3])}. " if mitre else "")
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get summary for investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{investigation_id}/alerts/search")
async def search_investigation_alerts(
    investigation_id: str,
    query: Optional[str] = Query(None, description="Search in title, description, or entities"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source: Optional[str] = Query(None, description="Filter by source"),
    user: Optional[str] = Query(None, description="Filter by user entity"),
    host: Optional[str] = Query(None, description="Filter by host entity"),
    mitre: Optional[str] = Query(None, description="Filter by MITRE technique"),
    from_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    to_time: Optional[str] = Query(None, description="End time (ISO format)"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """
    Search alerts within an investigation with various filters.

    This endpoint allows AI agents (like Riggs) to find specific alerts based on:
    - Text search in title/description
    - Severity level
    - Source system
    - User or host entities
    - MITRE techniques
    - Time range

    Returns matching alerts with correlation details.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Find investigation UUID
            inv_row = await conn.fetchrow("""
                SELECT id FROM investigations
                WHERE investigation_id = $1 OR id::text = $1
            """, investigation_id)

            if not inv_row:
                raise HTTPException(status_code=404, detail=f"Investigation not found: {investigation_id}")

            investigation_uuid = inv_row["id"]

            # Build dynamic query
            conditions = ["a.investigation_id = $1"]
            params = [investigation_uuid]
            param_idx = 2

            if query:
                conditions.append(f"""
                    (a.title ILIKE ${param_idx}
                     OR a.description ILIKE ${param_idx}
                     OR a.extracted_entities::text ILIKE ${param_idx})
                """)
                params.append(f"%{query}%")
                param_idx += 1

            if severity:
                conditions.append(f"a.severity = ${param_idx}")
                params.append(severity.lower())
                param_idx += 1

            if source:
                conditions.append(f"a.source ILIKE ${param_idx}")
                params.append(f"%{source}%")
                param_idx += 1

            if user:
                conditions.append(f"a.extracted_entities->'user' ? ${param_idx}")
                params.append(user)
                param_idx += 1

            if host:
                conditions.append(f"a.extracted_entities->'host' ? ${param_idx}")
                params.append(host)
                param_idx += 1

            if mitre:
                conditions.append(f"""
                    (a.raw_event->'mitre_techniques' ? ${param_idx}
                     OR a.raw_event::text ILIKE ${param_idx + 1})
                """)
                params.append(mitre)
                params.append(f"%{mitre}%")
                param_idx += 2

            if from_time:
                conditions.append(f"a.created_at >= ${param_idx}::timestamp")
                params.append(from_time)
                param_idx += 1

            if to_time:
                conditions.append(f"a.created_at <= ${param_idx}::timestamp")
                params.append(to_time)
                param_idx += 1

            where_clause = " AND ".join(conditions)

            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM alerts a WHERE {where_clause}"
            count_row = await conn.fetchrow(count_query, *params)
            total = count_row["total"] if count_row else 0

            # Get alerts
            query_sql = f"""
                SELECT
                    a.id,
                    a.alert_id,
                    a.title,
                    a.description,
                    a.severity,
                    a.status,
                    a.source,
                    a.created_at,
                    a.updated_at,
                    a.raw_event,
                    a.extracted_entities,
                    cd.decision_type,
                    cd.score as correlation_score,
                    cd.reasons as correlation_reasons,
                    cd.matched_entities
                FROM alerts a
                LEFT JOIN correlation_decisions cd ON cd.alert_id = a.id
                WHERE {where_clause}
                ORDER BY a.created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            params.extend([limit, offset])

            rows = await conn.fetch(query_sql, *params)

            alerts = []
            for row in rows:
                raw_event = _parse_jsonb(row["raw_event"], {})
                extracted_entities = _parse_jsonb(row["extracted_entities"], {})

                alerts.append({
                    "id": str(row["id"]),
                    "alert_id": row["alert_id"],
                    "title": row["title"],
                    "description": row["description"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "source": row["source"],
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                    "extracted_entities": extracted_entities,
                    "mitre_techniques": raw_event.get("mitre_techniques", []),
                    "ai_verdict": raw_event.get("ai_verdict") or raw_event.get("verdict"),
                    "correlation": {
                        "decision_type": row["decision_type"] or "legacy",
                        "score": row["correlation_score"],
                        "reasons": _parse_jsonb(row["correlation_reasons"], []),
                        "matched_entities": _parse_jsonb(row["matched_entities"], [])
                    }
                })

            return {
                "investigation_id": investigation_id,
                "query": query,
                "filters": {
                    "severity": severity,
                    "source": source,
                    "user": user,
                    "host": host,
                    "mitre": mitre,
                    "from_time": from_time,
                    "to_time": to_time
                },
                "results": alerts,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + len(alerts)) < total
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to search alerts for investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backfill/check-missing")
async def check_missing_analysis(
    user: dict = Depends(get_current_user),
):
    """
    Check which investigations in this tenant are missing Riggs analysis.

    Returns list of investigations without analysis and counts by severity.
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    id, investigation_id, state, severity, created_at,
                    COALESCE(investigation_data->>'status', 'unknown') as status
                FROM investigations
                WHERE (
                    investigation_data IS NULL
                    OR investigation_data::text NOT LIKE '%riggs_analysis%'
                    OR (investigation_data->>'riggs_analysis' = ''
                        OR investigation_data->>'riggs_analysis' IS NULL)
                )
                AND created_at > NOW() - INTERVAL '90 days'
                ORDER BY created_at DESC
                LIMIT 100
            """)

        # Count by severity
        severity_counts = {}
        for row in rows:
            sev = row["severity"] or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_missing": len(rows),
            "by_severity": severity_counts,
            "investigations": [
                {
                    "id": str(row["id"]),
                    "investigation_id": row["investigation_id"],
                    "state": row["state"],
                    "severity": row["severity"],
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None
                }
                for row in rows[:20]  # Return first 20
            ],
            "message": f"{len(rows)} investigations missing analysis (showing first 20)"
        }

    except Exception as e:
        logger.error(f"Failed to check missing analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to check missing analysis")


@router.post("/backfill/missing-analysis")
async def backfill_missing_analysis(
    user: dict = Depends(get_current_user),
):
    """
    Backfill Riggs analysis for all investigations that are missing it.

    Identifies investigations without riggs_analysis in their investigation_data
    and queues analysis for them. Respects license tier automatically.

    Returns count of investigations queued for analysis.
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    try:
        from services.job_queue import get_job_queue_service
        from services.postgres_db import postgres_db
        from dependencies.license_checks import _get_tenant_tier
        import json

        # Check license tier
        try:
            tier = await _get_tenant_tier(str(tenant_id))
            tier_str = (tier or "community").lower()
        except Exception as e:
            logger.warning(f"Failed to determine license tier for tenant {tenant_id}: {e}")
            tier_str = "community"

        # Find all investigations in this tenant that are missing riggs_analysis
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, investigation_id
                FROM investigations
                WHERE (
                    investigation_data IS NULL
                    OR investigation_data::text NOT LIKE '%riggs_analysis%'
                    OR (investigation_data->>'riggs_analysis' = ''
                        OR investigation_data->>'riggs_analysis' IS NULL)
                )
                AND created_at > NOW() - INTERVAL '90 days'
                ORDER BY created_at DESC
                LIMIT 500
            """)

        if not rows:
            return {
                "message": "No investigations missing analysis found",
                "queued_count": 0,
                "tier": tier_str
            }

        # Queue analysis for each investigation
        job_queue = await get_job_queue_service()
        queued_count = 0
        failed_count = 0

        for row in rows:
            try:
                inv_id = str(row["id"])
                inv_number = row["investigation_id"]

                job_id = await job_queue.enqueue(
                    job_type="agent_auto_triage",
                    target_type="investigation",
                    target_id=inv_id,
                    priority=5,  # Normal priority for backfill
                    payload={
                        "investigation_id": inv_id,
                        "auto_trigger": True,
                        "license_tier": tier_str,
                        "backfill": True,  # Mark as backfill operation
                    }
                )
                queued_count += 1
                logger.info(f"[BACKFILL] Queued analysis for investigation {inv_number} (job {job_id})")
            except Exception as e:
                failed_count += 1
                logger.error(f"[BACKFILL] Failed to queue analysis for investigation {row['investigation_id']}: {e}")

        return {
            "message": f"Queued analysis for {queued_count} investigations",
            "queued_count": queued_count,
            "failed_count": failed_count,
            "tier": tier_str,
            "total_found": len(rows)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to backfill missing analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to backfill analysis")


@router.post("/{investigation_id}/triage")
async def trigger_manual_triage(
    investigation_id: str,
    auto_trigger: bool = False,
    user: dict = Depends(get_current_user),
):
    """
    Trigger analysis for an investigation.

    Automatically determines analysis level based on license tier:
    - Free/Community: Basic agent_auto_triage
    - Pro/Enterprise: Deep analysis if available, otherwise basic

    Args:
        investigation_id: Investigation to analyze
        auto_trigger: If True, suppress some logging (internal auto-trigger)
        user: Current user context
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    try:
        from services.job_queue import get_job_queue_service
        from services.postgres_db import postgres_db
        from dependencies.license_checks import _get_tenant_tier
        import uuid

        # Verify investigation exists and user has access
        async with postgres_db.tenant_acquire() as conn:
            inv = await conn.fetchrow(
                "SELECT id FROM investigations WHERE investigation_id = $1",
                investigation_id,
            )
            if not inv:
                # Try as UUID if not found as INV- ID
                try:
                    inv = await conn.fetchrow(
                        "SELECT id FROM investigations WHERE id = $1::uuid",
                        investigation_id,
                    )
                except Exception:
                    inv = None
            if not inv:
                raise HTTPException(status_code=404, detail="Investigation not found")

            inv_id = str(inv["id"])

            # Find an alert linked to this investigation (required by agent_auto_triage)
            alert_row = await conn.fetchrow(
                "SELECT alert_id FROM alerts WHERE investigation_id = $1::uuid ORDER BY created_at DESC LIMIT 1",
                inv_id,
            )
            linked_alert_id = alert_row["alert_id"] if alert_row else None

        if not linked_alert_id:
            raise HTTPException(status_code=400, detail="No alert found for this investigation")

        # Check license tier to determine analysis level
        try:
            tier = await _get_tenant_tier(str(tenant_id))
            tier_str = (tier or "community").lower()
            supports_deep_dive = tier_str in ("pro", "enterprise", "platform")
        except Exception as e:
            logger.warning(f"Failed to determine license tier for tenant {tenant_id}: {e}")
            supports_deep_dive = False

        # Reset Riggs flight guard so re-analysis can run
        # Must clear riggs_analysis, riggs_status, riggs_started_at so mark_started() allows new run
        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE investigations
                    SET investigation_data = (COALESCE(investigation_data, '{}'::jsonb)
                        - 'riggs_analysis'
                        - 'riggs_status'
                        - 'riggs_started_at'
                        - 'riggs_completed_at'
                        - 'riggs_analyzed_at')
                    WHERE id = $1::uuid
                    """,
                    inv_id,
                )
                logger.info(f"[MANUAL_TRIAGE] Cleared riggs state for investigation {inv_id}")
        except Exception as e:
            logger.warning(f"Failed to reset riggs flight guard: {e}")

        # Queue Riggs analysis job (populates riggs_analysis + riggs_deep_analysis)
        job_queue = await get_job_queue_service()
        job_type = "riggs_analysis"
        logger.info(f"[TRIAGE] Queueing Riggs analysis for {tier_str} tier tenant")

        # Get the INV- ID for Riggs
        async with postgres_db.tenant_acquire() as conn:
            inv_row = await conn.fetchrow(
                "SELECT investigation_id FROM investigations WHERE id = $1::uuid",
                inv_id,
            )
        inv_display_id = inv_row["investigation_id"] if inv_row else investigation_id

        job_id = await job_queue.enqueue(
            queue_name="agent",
            job_type=job_type,
            priority=1,
            payload={
                "alert_id": linked_alert_id,
                "investigation_id": inv_display_id,
                "investigation_uuid": inv_id,
                "manual_trigger": True,
                "auto_trigger": auto_trigger,
                "license_tier": tier_str,
                "supports_deep_dive": supports_deep_dive
            }
        )

        if not auto_trigger:
            logger.info(f"[MANUAL_TRIAGE] Queued {tier_str} tier analysis for investigation {investigation_id} (job {job_id})")

        return {
            "message": "Analysis queued",
            "investigation_id": investigation_id,
            "job_id": job_id,
            "analysis_tier": "deep" if supports_deep_dive else "basic"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to queue triage for investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue analysis")


logger.info("Investigation routes loaded")
