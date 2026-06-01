# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Collector Management API Routes

REST API endpoints for managing log collectors, source types, and assignments.
Enables scalable configuration of what each collector monitors and where logs route.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
import logging
import uuid
import json

from services.postgres_db import postgres_db
from dependencies.auth import get_current_user


def _parse_jsonb(val, default=None):
    """Parse a JSONB value that may be returned as string by asyncpg."""
    if val is None:
        return default if default is not None else {}
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return default if default is not None else {}
    return val

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/collectors", tags=["Collectors"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class LogSourceTypeBase(BaseModel):
    """Base model for log source types"""
    source_type: str = Field(..., description="Unique source type identifier")
    display_name: str = Field(..., description="Human-readable name")
    description: Optional[str] = None
    category: str = Field(..., description="Category: endpoint, network, cloud, application, identity, email, database, custom")
    supported_platforms: List[str] = Field(default=["windows", "linux", "macos"])
    default_index_name: Optional[str] = Field(None, description="Default target index for routing")
    parser_type: str = Field(default="json", description="Parser type: json, syslog, cef, leef, csv, regex, xml, custom")
    parser_config: Dict[str, Any] = Field(default_factory=dict)
    default_config: Dict[str, Any] = Field(default_factory=dict)
    vendor: Optional[str] = None
    product: Optional[str] = None
    icon_name: Optional[str] = None


class CreateSourceTypeRequest(LogSourceTypeBase):
    """Request to create a new log source type"""
    pass


class UpdateSourceTypeRequest(BaseModel):
    """Request to update an existing log source type"""
    display_name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    supported_platforms: Optional[List[str]] = None
    default_index_name: Optional[str] = None
    parser_type: Optional[str] = None
    parser_config: Optional[Dict[str, Any]] = None
    default_config: Optional[Dict[str, Any]] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    icon_name: Optional[str] = None
    is_enabled: Optional[bool] = None


class LogSourceTypeResponse(LogSourceTypeBase):
    """Response model for log source types"""
    id: str
    default_index_id: Optional[str] = None
    is_builtin: bool
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None


class CollectorBase(BaseModel):
    """Base model for collectors (log agents)"""
    agent_id: str
    hostname: str
    os_type: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CollectorResponse(CollectorBase):
    """Response model for collectors"""
    id: str
    status: str
    last_heartbeat: Optional[datetime] = None
    last_event_received: Optional[datetime] = None
    events_received_total: int = 0
    registered_at: datetime
    registered_by: Optional[str] = None
    source_assignments: List[Dict[str, Any]] = Field(default_factory=list)


class SourceAssignmentBase(BaseModel):
    """Base model for source assignments"""
    source_type: str = Field(..., description="Source type to assign")
    target_index_name: Optional[str] = Field(None, description="Override target index (null = use default)")
    config_overrides: Dict[str, Any] = Field(default_factory=dict)
    include_filters: List[Dict[str, Any]] = Field(default_factory=list)
    exclude_filters: List[Dict[str, Any]] = Field(default_factory=list)
    is_enabled: bool = True


class CreateAssignmentRequest(SourceAssignmentBase):
    """Request to assign a source to a collector"""
    pass


class BulkAssignmentRequest(BaseModel):
    """Request to assign multiple sources to a collector"""
    assignments: List[SourceAssignmentBase]


class UpdateAssignmentRequest(BaseModel):
    """Request to update an existing assignment"""
    target_index_name: Optional[str] = None
    config_overrides: Optional[Dict[str, Any]] = None
    include_filters: Optional[List[Dict[str, Any]]] = None
    exclude_filters: Optional[List[Dict[str, Any]]] = None
    is_enabled: Optional[bool] = None


class SourceAssignmentResponse(SourceAssignmentBase):
    """Response model for source assignments"""
    id: str
    agent_id: str
    agent_hostname: str
    source_type_id: str
    target_index_id: Optional[str] = None
    status: str
    last_event_at: Optional[datetime] = None
    events_collected: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None


class CollectorGroupBase(BaseModel):
    """Base model for collector groups"""
    name: str = Field(..., description="Unique group name")
    display_name: str = Field(..., description="Human-readable name")
    description: Optional[str] = None
    auto_membership_rules: Optional[Dict[str, Any]] = Field(None, description="Rules for auto-membership")


class CreateGroupRequest(CollectorGroupBase):
    """Request to create a collector group"""
    pass


class UpdateGroupRequest(BaseModel):
    """Request to update a collector group"""
    display_name: Optional[str] = None
    description: Optional[str] = None
    auto_membership_rules: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class CollectorGroupResponse(CollectorGroupBase):
    """Response model for collector groups"""
    id: str
    is_enabled: bool
    member_count: int = 0
    source_assignment_count: int = 0
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None


class GroupSourceAssignmentRequest(BaseModel):
    """Request to assign a source to a group"""
    source_type: str
    target_index_name: Optional[str] = None
    config_overrides: Dict[str, Any] = Field(default_factory=dict)
    include_filters: List[Dict[str, Any]] = Field(default_factory=list)
    exclude_filters: List[Dict[str, Any]] = Field(default_factory=list)
    priority: int = 0
    is_enabled: bool = True


# ============================================================================
# Log Source Type Endpoints
# ============================================================================

@router.get("/source-types", response_model=List[LogSourceTypeResponse])
async def list_source_types(
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by supported platform"),
    enabled_only: bool = Query(True, description="Only return enabled source types"),
    include_builtin: bool = Query(True, description="Include built-in source types")
):
    """List all available log source types with optional filtering"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = "SELECT * FROM log_source_types WHERE 1=1"
            params = []

            if category:
                params.append(category)
                query += f" AND category = ${len(params)}"

            if platform:
                params.append(platform)
                query += f" AND ${len(params)} = ANY(supported_platforms)"

            if enabled_only:
                query += " AND is_enabled = true"

            if not include_builtin:
                query += " AND is_builtin = false"

            query += " ORDER BY category, display_name"

            rows = await conn.fetch(query, *params)

            return [
                LogSourceTypeResponse(
                    id=str(row["id"]),
                    source_type=row["source_type"],
                    display_name=row["display_name"],
                    description=row["description"],
                    category=row["category"],
                    supported_platforms=row["supported_platforms"] or [],
                    default_index_id=str(row["default_index_id"]) if row["default_index_id"] else None,
                    default_index_name=row["default_index_name"],
                    parser_type=row["parser_type"],
                    parser_config=row["parser_config"] or {},
                    default_config=row["default_config"] or {},
                    vendor=row["vendor"],
                    product=row["product"],
                    icon_name=row["icon_name"],
                    is_builtin=row["is_builtin"],
                    is_enabled=row["is_enabled"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    created_by=row["created_by"]
                )
                for row in rows
            ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing source types: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/source-types", response_model=LogSourceTypeResponse, status_code=201)
async def create_source_type(request: CreateSourceTypeRequest):
    """Create a new custom log source type"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        # Validate category
        valid_categories = ["endpoint", "network", "cloud", "application", "identity", "email", "database", "custom"]
        if request.category not in valid_categories:
            raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {valid_categories}")

        async with postgres_db.tenant_acquire() as conn:
            # Look up default index ID if name provided
            default_index_id = None
            if request.default_index_name:
                index_row = await conn.fetchrow(
                    "SELECT id FROM log_indexes WHERE name = $1",
                    request.default_index_name
                )
                if index_row:
                    default_index_id = index_row["id"]

            row = await conn.fetchrow("""
                INSERT INTO log_source_types (
                    source_type, display_name, description, category, supported_platforms,
                    default_index_id, default_index_name, parser_type, parser_config,
                    default_config, vendor, product, icon_name, is_builtin, is_enabled
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, false, true)
                RETURNING *
            """,
                request.source_type,
                request.display_name,
                request.description,
                request.category,
                request.supported_platforms,
                default_index_id,
                request.default_index_name,
                request.parser_type,
                request.parser_config,
                request.default_config,
                request.vendor,
                request.product,
                request.icon_name
            )

            return LogSourceTypeResponse(
                id=str(row["id"]),
                source_type=row["source_type"],
                display_name=row["display_name"],
                description=row["description"],
                category=row["category"],
                supported_platforms=row["supported_platforms"] or [],
                default_index_id=str(row["default_index_id"]) if row["default_index_id"] else None,
                default_index_name=row["default_index_name"],
                parser_type=row["parser_type"],
                parser_config=row["parser_config"] or {},
                default_config=row["default_config"] or {},
                vendor=row["vendor"],
                product=row["product"],
                icon_name=row["icon_name"],
                is_builtin=row["is_builtin"],
                is_enabled=row["is_enabled"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating source type: {e}")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Source type '{request.source_type}' already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/source-types/{source_type}", response_model=LogSourceTypeResponse)
async def get_source_type(source_type: str):
    """Get a specific log source type by name"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM log_source_types WHERE source_type = $1",
                source_type
            )

            if not row:
                raise HTTPException(status_code=404, detail=f"Source type '{source_type}' not found")

            return LogSourceTypeResponse(
                id=str(row["id"]),
                source_type=row["source_type"],
                display_name=row["display_name"],
                description=row["description"],
                category=row["category"],
                supported_platforms=row["supported_platforms"] or [],
                default_index_id=str(row["default_index_id"]) if row["default_index_id"] else None,
                default_index_name=row["default_index_name"],
                parser_type=row["parser_type"],
                parser_config=row["parser_config"] or {},
                default_config=row["default_config"] or {},
                vendor=row["vendor"],
                product=row["product"],
                icon_name=row["icon_name"],
                is_builtin=row["is_builtin"],
                is_enabled=row["is_enabled"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting source type: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/source-types/{source_type}", response_model=LogSourceTypeResponse)
async def update_source_type(source_type: str, request: UpdateSourceTypeRequest):
    """Update an existing log source type"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Check if exists and not builtin (or just updating enabled status)
            existing = await conn.fetchrow(
                "SELECT * FROM log_source_types WHERE source_type = $1",
                source_type
            )

            if not existing:
                raise HTTPException(status_code=404, detail=f"Source type '{source_type}' not found")

            # Build dynamic update
            updates = []
            params = []
            param_idx = 1

            update_fields = request.model_dump(exclude_unset=True)

            # Handle index name to ID conversion
            if "default_index_name" in update_fields:
                if update_fields["default_index_name"]:
                    index_row = await conn.fetchrow(
                        "SELECT id FROM log_indexes WHERE name = $1",
                        update_fields["default_index_name"]
                    )
                    if index_row:
                        updates.append(f"default_index_id = ${param_idx}")
                        params.append(index_row["id"])
                        param_idx += 1
                else:
                    updates.append(f"default_index_id = NULL")

            for field, value in update_fields.items():
                if field == "default_index_name":
                    updates.append(f"{field} = ${param_idx}")
                    params.append(value)
                    param_idx += 1
                elif value is not None:
                    updates.append(f"{field} = ${param_idx}")
                    params.append(value)
                    param_idx += 1

            if not updates:
                raise HTTPException(status_code=400, detail="No fields to update")

            updates.append("updated_at = CURRENT_TIMESTAMP")

            params.append(source_type)
            query = f"""
                UPDATE log_source_types
                SET {', '.join(updates)}
                WHERE source_type = ${param_idx}
                RETURNING *
            """

            row = await conn.fetchrow(query, *params)

            return LogSourceTypeResponse(
                id=str(row["id"]),
                source_type=row["source_type"],
                display_name=row["display_name"],
                description=row["description"],
                category=row["category"],
                supported_platforms=row["supported_platforms"] or [],
                default_index_id=str(row["default_index_id"]) if row["default_index_id"] else None,
                default_index_name=row["default_index_name"],
                parser_type=row["parser_type"],
                parser_config=row["parser_config"] or {},
                default_config=row["default_config"] or {},
                vendor=row["vendor"],
                product=row["product"],
                icon_name=row["icon_name"],
                is_builtin=row["is_builtin"],
                is_enabled=row["is_enabled"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating source type: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/source-types/{source_type}", status_code=204)
async def delete_source_type(source_type: str):
    """Delete a custom log source type (cannot delete built-in types)"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Check if exists and not builtin
            existing = await conn.fetchrow(
                "SELECT is_builtin FROM log_source_types WHERE source_type = $1",
                source_type
            )

            if not existing:
                raise HTTPException(status_code=404, detail=f"Source type '{source_type}' not found")

            if existing["is_builtin"]:
                raise HTTPException(status_code=403, detail="Cannot delete built-in source types")

            await conn.execute(
                "DELETE FROM log_source_types WHERE source_type = $1",
                source_type
            )

            return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting source type: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Collector (Agent) Endpoints
# ============================================================================

@router.get("", response_model=List[CollectorResponse])
async def list_collectors(
    status: Optional[str] = Query(None, description="Filter by status"),
    os_type: Optional[str] = Query(None, description="Filter by OS type"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    include_assignments: bool = Query(True, description="Include source assignments")
):
    """List all registered log collectors with their source assignments"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = "SELECT * FROM log_agents WHERE 1=1"
            params = []

            if status:
                params.append(status)
                query += f" AND status = ${len(params)}"

            if os_type:
                params.append(os_type)
                query += f" AND os_type = ${len(params)}"

            if tag:
                params.append(tag)
                query += f" AND ${len(params)} = ANY(tags)"

            query += " ORDER BY hostname"

            rows = await conn.fetch(query, *params)

            collectors = []
            for row in rows:
                assignments = []
                if include_assignments:
                    assignment_rows = await conn.fetch("""
                        SELECT csa.*, lst.display_name as source_display_name
                        FROM collector_source_assignments csa
                        JOIN log_source_types lst ON csa.source_type_id = lst.id
                        WHERE csa.agent_id = $1
                        ORDER BY lst.category, lst.display_name
                    """, row["id"])

                    assignments = [
                        {
                            "id": str(a["id"]),
                            "source_type": a["source_type"],
                            "source_display_name": a["source_display_name"],
                            "target_index_name": a["target_index_name"],
                            "is_enabled": a["is_enabled"],
                            "status": a["status"],
                            "events_collected": a["events_collected"],
                            "last_event_at": a["last_event_at"].isoformat() if a["last_event_at"] else None
                        }
                        for a in assignment_rows
                    ]

                collectors.append(CollectorResponse(
                    id=str(row["id"]),
                    agent_id=row["agent_id"],
                    hostname=row["hostname"],
                    os_type=row["os_type"],
                    os_version=row["os_version"],
                    ip_address=str(row["ip_address"]) if row["ip_address"] else None,
                    agent_version=row["agent_version"],
                    status=row["status"],
                    last_heartbeat=row["last_heartbeat"],
                    last_event_received=row["last_event_received"],
                    events_received_total=row["events_received_total"] or 0,
                    tags=row["tags"] or [],
                    metadata=_parse_jsonb(row["metadata"], {}),
                    registered_at=row["registered_at"],
                    registered_by=row["registered_by"],
                    source_assignments=assignments
                ))

            return collectors
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing collectors: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{collector_id}", response_model=CollectorResponse)
async def get_collector(collector_id: str):
    """Get a specific collector with its source assignments"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None,
            )

            # Try by agent_id if UUID lookup failed
            if not row:
                row = await conn.fetchrow(
                    "SELECT * FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not row:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            # Get assignments
            assignment_rows = await conn.fetch("""
                SELECT csa.*, lst.display_name as source_display_name
                FROM collector_source_assignments csa
                JOIN log_source_types lst ON csa.source_type_id = lst.id
                WHERE csa.agent_id = $1
                ORDER BY lst.category, lst.display_name
            """, row["id"])

            assignments = [
                {
                    "id": str(a["id"]),
                    "source_type": a["source_type"],
                    "source_display_name": a["source_display_name"],
                    "target_index_name": a["target_index_name"],
                    "is_enabled": a["is_enabled"],
                    "status": a["status"],
                    "events_collected": a["events_collected"],
                    "last_event_at": a["last_event_at"].isoformat() if a["last_event_at"] else None
                }
                for a in assignment_rows
            ]

            return CollectorResponse(
                id=str(row["id"]),
                agent_id=row["agent_id"],
                hostname=row["hostname"],
                os_type=row["os_type"],
                os_version=row["os_version"],
                ip_address=str(row["ip_address"]) if row["ip_address"] else None,
                agent_version=row["agent_version"],
                status=row["status"],
                last_heartbeat=row["last_heartbeat"],
                last_event_received=row["last_event_received"],
                events_received_total=row["events_received_total"] or 0,
                tags=row["tags"] or [],
                metadata=_parse_jsonb(row["metadata"], {}),
                registered_at=row["registered_at"],
                registered_by=row["registered_by"],
                source_assignments=assignments
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting collector: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Collector Registration Endpoint
# ============================================================================

class RegisterCollectorRequest(BaseModel):
    """Request to manually register a new collector"""
    agent_id: str = Field(..., description="Unique agent identifier")
    hostname: str = Field(..., description="Hostname of the collector")
    os_type: str = Field(..., description="OS type: windows, linux, macos, other")
    os_version: Optional[str] = Field(None, description="OS version string")
    ip_address: Optional[str] = Field(None, description="IP address")
    agent_version: Optional[str] = Field(None, description="Agent version")
    tags: List[str] = Field(default_factory=list, description="Tags for grouping")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


@router.post("/register", response_model=CollectorResponse, status_code=201)
async def register_collector(request: RegisterCollectorRequest):
    """
    Manually register a new log collector.

    This is typically called by agents on startup, but can also be used
    to manually register collectors for testing or manual deployments.
    """
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        # Validate OS type
        valid_os = ["windows", "linux", "macos", "other"]
        if request.os_type not in valid_os:
            raise HTTPException(status_code=400, detail=f"Invalid os_type. Must be one of: {valid_os}")

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO log_agents (
                    agent_id, hostname, os_type, os_version, ip_address,
                    agent_version, status, tags, metadata, last_heartbeat
                ) VALUES ($1, $2, $3, $4, $5::inet, $6, 'active', $7, $8, CURRENT_TIMESTAMP)
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    os_type = EXCLUDED.os_type,
                    os_version = EXCLUDED.os_version,
                    ip_address = EXCLUDED.ip_address,
                    agent_version = EXCLUDED.agent_version,
                    tags = EXCLUDED.tags,
                    metadata = EXCLUDED.metadata,
                    last_heartbeat = CURRENT_TIMESTAMP,
                    status = 'active',
                    updated_at = CURRENT_TIMESTAMP
                RETURNING *
            """,
                request.agent_id,
                request.hostname,
                request.os_type,
                request.os_version,
                request.ip_address,
                request.agent_version,
                request.tags,
                request.metadata
            )

            return CollectorResponse(
                id=str(row["id"]),
                agent_id=row["agent_id"],
                hostname=row["hostname"],
                os_type=row["os_type"],
                os_version=row["os_version"],
                ip_address=str(row["ip_address"]) if row["ip_address"] else None,
                agent_version=row["agent_version"],
                status=row["status"],
                last_heartbeat=row["last_heartbeat"],
                last_event_received=row["last_event_received"],
                events_received_total=row["events_received_total"] or 0,
                tags=row["tags"] or [],
                metadata=_parse_jsonb(row["metadata"], {}),
                registered_at=row["registered_at"],
                registered_by=row["registered_by"],
                source_assignments=[]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering collector: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{collector_id}")
async def update_collector(collector_id: str, tags: Optional[List[str]] = None, status: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
    """Update a collector's tags, status, or metadata"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            updates = []
            params = []
            param_idx = 1

            if tags is not None:
                updates.append(f"tags = ${param_idx}")
                params.append(tags)
                param_idx += 1

            if status is not None:
                valid_status = ["active", "inactive", "maintenance", "decommissioned"]
                if status not in valid_status:
                    raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_status}")
                updates.append(f"status = ${param_idx}")
                params.append(status)
                param_idx += 1

            if metadata is not None:
                updates.append(f"metadata = ${param_idx}")
                params.append(metadata)
                param_idx += 1

            if not updates:
                return {"status": "ok", "message": "No updates provided"}

            updates.append("updated_at = CURRENT_TIMESTAMP")

            params.append(collector["id"])
            query = f"""
                UPDATE log_agents
                SET {', '.join(updates)}
                WHERE id = ${param_idx}
                RETURNING agent_id, hostname, status
            """

            row = await conn.fetchrow(query, *params)

            return {
                "status": "ok",
                "collector": {
                    "agent_id": row["agent_id"],
                    "hostname": row["hostname"],
                    "status": row["status"]
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating collector: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Source Assignment Endpoints
# ============================================================================

@router.post("/{collector_id}/sources", response_model=SourceAssignmentResponse, status_code=201)
async def assign_source_to_collector(collector_id: str, request: CreateAssignmentRequest):
    """Assign a log source to a collector"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get collector
            collector = await conn.fetchrow(
                "SELECT id, hostname FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id, hostname FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            # Get source type
            source_type = await conn.fetchrow(
                "SELECT id, default_index_id, default_index_name FROM log_source_types WHERE source_type = $1 AND is_enabled = true",
                request.source_type
            )

            if not source_type:
                raise HTTPException(status_code=404, detail=f"Source type '{request.source_type}' not found or disabled")

            # Determine target index
            target_index_id = None
            target_index_name = request.target_index_name

            if target_index_name:
                index_row = await conn.fetchrow(
                    "SELECT id FROM log_indexes WHERE name = $1",
                    target_index_name
                )
                if index_row:
                    target_index_id = index_row["id"]
            else:
                target_index_id = source_type["default_index_id"]
                target_index_name = source_type["default_index_name"]

            # Create assignment
            row = await conn.fetchrow("""
                INSERT INTO collector_source_assignments (
                    agent_id, agent_hostname, source_type_id, source_type,
                    target_index_id, target_index_name, config_overrides,
                    include_filters, exclude_filters, is_enabled
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING *
            """,
                collector["id"],
                collector["hostname"],
                source_type["id"],
                request.source_type,
                target_index_id,
                target_index_name,
                request.config_overrides,
                request.include_filters,
                request.exclude_filters,
                request.is_enabled
            )

            return SourceAssignmentResponse(
                id=str(row["id"]),
                agent_id=str(row["agent_id"]),
                agent_hostname=row["agent_hostname"],
                source_type=row["source_type"],
                source_type_id=str(row["source_type_id"]),
                target_index_id=str(row["target_index_id"]) if row["target_index_id"] else None,
                target_index_name=row["target_index_name"],
                config_overrides=row["config_overrides"] or {},
                include_filters=row["include_filters"] or [],
                exclude_filters=row["exclude_filters"] or [],
                is_enabled=row["is_enabled"],
                status=row["status"],
                last_event_at=row["last_event_at"],
                events_collected=row["events_collected"] or 0,
                error_message=row["error_message"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning source to collector: {e}")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Source '{request.source_type}' is already assigned to this collector")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{collector_id}/sources/bulk", response_model=List[SourceAssignmentResponse], status_code=201)
async def bulk_assign_sources(collector_id: str, request: BulkAssignmentRequest):
    """Assign multiple log sources to a collector at once"""
    results = []
    errors = []

    for assignment in request.assignments:
        try:
            result = await assign_source_to_collector(
                collector_id,
                CreateAssignmentRequest(**assignment.model_dump())
            )
            results.append(result)
        except HTTPException as e:
            errors.append({"source_type": assignment.source_type, "error": e.detail})
        except Exception as e:
            errors.append({"source_type": assignment.source_type, "error": str(e)})

    if errors and not results:
        raise HTTPException(status_code=400, detail={"message": "All assignments failed", "errors": errors})

    return results


@router.get("/{collector_id}/sources", response_model=List[SourceAssignmentResponse])
async def list_collector_sources(collector_id: str):
    """List all source assignments for a collector"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get collector ID
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            rows = await conn.fetch("""
                SELECT * FROM collector_source_assignments
                WHERE agent_id = $1
                ORDER BY source_type
            """, collector["id"])

            return [
                SourceAssignmentResponse(
                    id=str(row["id"]),
                    agent_id=str(row["agent_id"]),
                    agent_hostname=row["agent_hostname"],
                    source_type=row["source_type"],
                    source_type_id=str(row["source_type_id"]),
                    target_index_id=str(row["target_index_id"]) if row["target_index_id"] else None,
                    target_index_name=row["target_index_name"],
                    config_overrides=row["config_overrides"] or {},
                    include_filters=row["include_filters"] or [],
                    exclude_filters=row["exclude_filters"] or [],
                    is_enabled=row["is_enabled"],
                    status=row["status"],
                    last_event_at=row["last_event_at"],
                    events_collected=row["events_collected"] or 0,
                    error_message=row["error_message"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    created_by=row["created_by"]
                )
                for row in rows
            ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing collector sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{collector_id}/sources/{source_type}", response_model=SourceAssignmentResponse)
async def update_source_assignment(collector_id: str, source_type: str, request: UpdateAssignmentRequest):
    """Update a source assignment for a collector"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            # Build update
            updates = []
            params = []
            param_idx = 1

            update_fields = request.model_dump(exclude_unset=True)

            # Handle index name to ID conversion
            if "target_index_name" in update_fields:
                if update_fields["target_index_name"]:
                    index_row = await conn.fetchrow(
                        "SELECT id FROM log_indexes WHERE name = $1",
                        update_fields["target_index_name"]
                    )
                    if index_row:
                        updates.append(f"target_index_id = ${param_idx}")
                        params.append(index_row["id"])
                        param_idx += 1
                else:
                    updates.append("target_index_id = NULL")

            for field, value in update_fields.items():
                updates.append(f"{field} = ${param_idx}")
                params.append(value)
                param_idx += 1

            if not updates:
                raise HTTPException(status_code=400, detail="No fields to update")

            updates.append("updated_at = CURRENT_TIMESTAMP")

            params.extend([collector["id"], source_type])
            query = f"""
                UPDATE collector_source_assignments
                SET {', '.join(updates)}
                WHERE agent_id = ${param_idx} AND source_type = ${param_idx + 1}
                RETURNING *
            """

            row = await conn.fetchrow(query, *params)

            if not row:
                raise HTTPException(status_code=404, detail=f"Source assignment for '{source_type}' not found")

            return SourceAssignmentResponse(
                id=str(row["id"]),
                agent_id=str(row["agent_id"]),
                agent_hostname=row["agent_hostname"],
                source_type=row["source_type"],
                source_type_id=str(row["source_type_id"]),
                target_index_id=str(row["target_index_id"]) if row["target_index_id"] else None,
                target_index_name=row["target_index_name"],
                config_overrides=row["config_overrides"] or {},
                include_filters=row["include_filters"] or [],
                exclude_filters=row["exclude_filters"] or [],
                is_enabled=row["is_enabled"],
                status=row["status"],
                last_event_at=row["last_event_at"],
                events_collected=row["events_collected"] or 0,
                error_message=row["error_message"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating source assignment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{collector_id}/sources/{source_type}", status_code=204)
async def remove_source_assignment(collector_id: str, source_type: str):
    """Remove a source assignment from a collector"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            result = await conn.execute("""
                DELETE FROM collector_source_assignments
                WHERE agent_id = $1 AND source_type = $2
            """, collector["id"], source_type)

            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail=f"Source assignment for '{source_type}' not found")

            return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing source assignment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Collector Group Endpoints
# ============================================================================

@router.get("/groups", response_model=List[CollectorGroupResponse])
async def list_collector_groups(enabled_only: bool = Query(True)):
    """List all collector groups"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = "SELECT * FROM collector_groups"
            if enabled_only:
                query += " WHERE is_enabled = true"
            query += " ORDER BY display_name"

            rows = await conn.fetch(query)

            groups = []
            for row in rows:
                # Get member count
                member_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM collector_group_membership WHERE group_id = $1",
                    row["id"]
                )

                # Get assignment count
                assignment_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM group_source_assignments WHERE group_id = $1",
                    row["id"]
                )

                groups.append(CollectorGroupResponse(
                    id=str(row["id"]),
                    name=row["name"],
                    display_name=row["display_name"],
                    description=row["description"],
                    auto_membership_rules=row["auto_membership_rules"],
                    is_enabled=row["is_enabled"],
                    member_count=member_count or 0,
                    source_assignment_count=assignment_count or 0,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    created_by=row["created_by"]
                ))

            return groups
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing collector groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/groups", response_model=CollectorGroupResponse, status_code=201)
async def create_collector_group(request: CreateGroupRequest):
    """Create a new collector group"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO collector_groups (name, display_name, description, auto_membership_rules)
                VALUES ($1, $2, $3, $4)
                RETURNING *
            """,
                request.name,
                request.display_name,
                request.description,
                request.auto_membership_rules
            )

            return CollectorGroupResponse(
                id=str(row["id"]),
                name=row["name"],
                display_name=row["display_name"],
                description=row["description"],
                auto_membership_rules=row["auto_membership_rules"],
                is_enabled=row["is_enabled"],
                member_count=0,
                source_assignment_count=0,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating collector group: {e}")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Group '{request.name}' already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/groups/{group_name}/members/{collector_id}", status_code=201)
async def add_collector_to_group(group_name: str, collector_id: str):
    """Add a collector to a group"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get group
            group = await conn.fetchrow(
                "SELECT id FROM collector_groups WHERE name = $1",
                group_name
            )
            if not group:
                raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            await conn.execute("""
                INSERT INTO collector_group_membership (group_id, agent_id, is_manual)
                VALUES ($1, $2, true)
                ON CONFLICT (group_id, agent_id) DO NOTHING
            """, group["id"], collector["id"])

            return {"message": "Collector added to group"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding collector to group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/groups/{group_name}/members/{collector_id}", status_code=204)
async def remove_collector_from_group(group_name: str, collector_id: str):
    """Remove a collector from a group"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get group
            group = await conn.fetchrow(
                "SELECT id FROM collector_groups WHERE name = $1",
                group_name
            )
            if not group:
                raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE id = $1 OR agent_id = $1",
                collector_id if len(collector_id) == 36 else None
            )
            if not collector:
                collector = await conn.fetchrow(
                    "SELECT id FROM log_agents WHERE agent_id = $1",
                    collector_id
                )

            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            await conn.execute("""
                DELETE FROM collector_group_membership
                WHERE group_id = $1 AND agent_id = $2
            """, group["id"], collector["id"])

            return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing collector from group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/groups/{group_name}/sources", response_model=Dict[str, Any], status_code=201)
async def assign_source_to_group(group_name: str, request: GroupSourceAssignmentRequest):
    """Assign a log source to a collector group (applies to all members)"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get group
            group = await conn.fetchrow(
                "SELECT id FROM collector_groups WHERE name = $1",
                group_name
            )
            if not group:
                raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

            # Get source type
            source_type = await conn.fetchrow(
                "SELECT id, default_index_id, default_index_name FROM log_source_types WHERE source_type = $1 AND is_enabled = true",
                request.source_type
            )
            if not source_type:
                raise HTTPException(status_code=404, detail=f"Source type '{request.source_type}' not found or disabled")

            # Determine target index
            target_index_id = None
            target_index_name = request.target_index_name

            if target_index_name:
                index_row = await conn.fetchrow(
                    "SELECT id FROM log_indexes WHERE name = $1",
                    target_index_name
                )
                if index_row:
                    target_index_id = index_row["id"]
            else:
                target_index_id = source_type["default_index_id"]
                target_index_name = source_type["default_index_name"]

            row = await conn.fetchrow("""
                INSERT INTO group_source_assignments (
                    group_id, group_name, source_type_id, source_type,
                    target_index_id, target_index_name, config_overrides,
                    include_filters, exclude_filters, priority, is_enabled
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING *
            """,
                group["id"],
                group_name,
                source_type["id"],
                request.source_type,
                target_index_id,
                target_index_name,
                request.config_overrides,
                request.include_filters,
                request.exclude_filters,
                request.priority,
                request.is_enabled
            )

            return {
                "id": str(row["id"]),
                "group_name": row["group_name"],
                "source_type": row["source_type"],
                "target_index_name": row["target_index_name"],
                "priority": row["priority"],
                "is_enabled": row["is_enabled"],
                "created_at": row["created_at"].isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning source to group: {e}")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Source '{request.source_type}' is already assigned to group '{group_name}'")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Summary/Dashboard Endpoints
# ============================================================================

@router.get("/summary")
async def get_collector_summary():
    """Get summary statistics for collectors and sources"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Collector stats
            collector_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'active') as active,
                    COUNT(*) FILTER (WHERE status = 'inactive') as inactive,
                    COUNT(*) FILTER (WHERE status = 'maintenance') as maintenance,
                    COUNT(*) FILTER (WHERE last_heartbeat > NOW() - INTERVAL '5 minutes') as online
                FROM log_agents
            """)

            # Source type stats
            source_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_enabled = true) as enabled,
                    COUNT(*) FILTER (WHERE is_builtin = true) as builtin,
                    COUNT(*) FILTER (WHERE is_builtin = false) as custom
                FROM log_source_types
            """)

            # Assignment stats
            assignment_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_enabled = true) as enabled,
                    COUNT(*) FILTER (WHERE status = 'active') as active,
                    COUNT(*) FILTER (WHERE status = 'error') as error,
                    COALESCE(SUM(events_collected), 0) as total_events
                FROM collector_source_assignments
            """)

            # Group stats
            group_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_enabled = true) as enabled
                FROM collector_groups
            """)

            # Top sources by event count
            top_sources = await conn.fetch("""
                SELECT source_type, SUM(events_collected) as events
                FROM collector_source_assignments
                GROUP BY source_type
                ORDER BY events DESC
                LIMIT 10
            """)

            return {
                "collectors": {
                    "total": collector_stats["total"] or 0,
                    "active": collector_stats["active"] or 0,
                    "inactive": collector_stats["inactive"] or 0,
                    "maintenance": collector_stats["maintenance"] or 0,
                    "online": collector_stats["online"] or 0
                },
                "source_types": {
                    "total": source_stats["total"] or 0,
                    "enabled": source_stats["enabled"] or 0,
                    "builtin": source_stats["builtin"] or 0,
                    "custom": source_stats["custom"] or 0
                },
                "assignments": {
                    "total": assignment_stats["total"] or 0,
                    "enabled": assignment_stats["enabled"] or 0,
                    "active": assignment_stats["active"] or 0,
                    "error": assignment_stats["error"] or 0,
                    "total_events": assignment_stats["total_events"] or 0
                },
                "groups": {
                    "total": group_stats["total"] or 0,
                    "enabled": group_stats["enabled"] or 0
                },
                "top_sources": [
                    {"source_type": row["source_type"], "events": row["events"] or 0}
                    for row in top_sources
                ]
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting collector summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/routing-preview")
async def preview_log_routing(
    source_type: str = Query(..., description="Source type to check routing for"),
    collector_id: Optional[str] = Query(None, description="Optional collector ID for specific routing")
):
    """Preview where logs from a source type will be routed"""
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get source type default
            source = await conn.fetchrow("""
                SELECT source_type, display_name, default_index_name, default_index_id
                FROM log_source_types
                WHERE source_type = $1
            """, source_type)

            if not source:
                raise HTTPException(status_code=404, detail=f"Source type '{source_type}' not found")

            result = {
                "source_type": source["source_type"],
                "display_name": source["display_name"],
                "default_index": source["default_index_name"],
                "collector_specific": None,
                "group_specific": []
            }

            # Check collector-specific routing
            if collector_id:
                collector = await conn.fetchrow(
                    "SELECT id, hostname FROM log_agents WHERE id = $1 OR agent_id = $1",
                    collector_id if len(collector_id) == 36 else None
                )
                if not collector:
                    collector = await conn.fetchrow(
                        "SELECT id, hostname FROM log_agents WHERE agent_id = $1",
                        collector_id
                    )

                if collector:
                    assignment = await conn.fetchrow("""
                        SELECT target_index_name, is_enabled
                        FROM collector_source_assignments
                        WHERE agent_id = $1 AND source_type = $2
                    """, collector["id"], source_type)

                    if assignment:
                        result["collector_specific"] = {
                            "collector": collector["hostname"],
                            "target_index": assignment["target_index_name"] or source["default_index_name"],
                            "is_enabled": assignment["is_enabled"]
                        }

            # Check group assignments
            group_assignments = await conn.fetch("""
                SELECT gsa.group_name, gsa.target_index_name, gsa.priority, gsa.is_enabled
                FROM group_source_assignments gsa
                WHERE gsa.source_type = $1 AND gsa.is_enabled = true
                ORDER BY gsa.priority DESC
            """, source_type)

            result["group_specific"] = [
                {
                    "group": row["group_name"],
                    "target_index": row["target_index_name"] or source["default_index_name"],
                    "priority": row["priority"]
                }
                for row in group_assignments
            ]

            return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error previewing log routing: {e}")
        raise HTTPException(status_code=500, detail=str(e))
