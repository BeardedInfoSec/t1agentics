# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Control Plane API Routes
========================

REST API for log collector configuration management.

SECURITY MODEL:
- Collectors ONLY pull configs (never accept inbound commands)
- All configs are Ed25519 signed
- Configs include version numbers for ordering
- Collectors must verify signatures before applying

Endpoints:
- GET /config/{collector_id} - Collector pulls its config (no auth required for collector)
- POST /config/{collector_id}/ack - Collector acknowledges config (collector auth)
- GET /collectors - List all collectors (UI/admin)
- GET /collectors/{id}/health - Get collector health (UI/admin)
- POST /collectors/{id}/config - Update collector config (admin only)
- GET /public-key - Get signing public key (for collector setup)
"""

from fastapi import APIRouter, HTTPException, Query, Depends, Header, Request
from dependencies.auth import get_current_user
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
import logging
import hashlib
import secrets

from services.control_plane import get_control_plane, init_control_plane
from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/control-plane", tags=["Control Plane"], dependencies=[Depends(get_current_user)])


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class ConfigAckRequest(BaseModel):
    """Collector acknowledgment of config delivery"""
    version: int = Field(..., description="Config version being acknowledged")
    success: bool = Field(..., description="Whether config was applied successfully")
    message: Optional[str] = Field(None, description="Optional status message or error")
    content_hash: Optional[str] = Field(None, description="Hash of received config for verification")


class ConfigUpdateRequest(BaseModel):
    """Request to update collector configuration"""
    settings: Optional[Dict[str, Any]] = Field(None, description="Settings to update")
    sources: Optional[List[Dict[str, Any]]] = Field(None, description="Source configs to update")


class CollectorHeartbeat(BaseModel):
    """Collector heartbeat data"""
    agent_id: str
    hostname: str
    agent_version: Optional[str] = None
    config_version: int = Field(0, description="Current config version collector has")
    events_sent: int = Field(0, description="Events sent since last heartbeat")
    uptime_seconds: int = Field(0)
    telemetry: Optional[Dict[str, Any]] = Field(None, description="Telemetry counters")


class CollectorRegistration(BaseModel):
    """New collector registration request"""
    agent_id: str
    hostname: str
    os_type: str = Field(..., description="OS type: windows, linux, macos, other")
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# COLLECTOR ENDPOINTS (Called by collectors - lightweight auth)
# ============================================================================

@router.get("/config/{collector_id}")
async def get_collector_config(
    collector_id: str,
    current_version: Optional[int] = Query(None, description="Collector's current config version"),
    x_collector_key: Optional[str] = Header(None, description="Collector authentication key")
):
    """
    Collector pulls its configuration.

    This is the primary endpoint collectors call to get their config.
    Collectors should poll this periodically (e.g., every 60 seconds).

    Security:
    - No sensitive auth required (config is signed, collector verifies)
    - Optionally validate collector key for additional security
    - Config includes Ed25519 signature for verification

    Returns:
    - Full config if no current_version or version changed
    - Empty response with "no_change": true if version unchanged
    """
    try:
        control_plane = get_control_plane()
        config = await control_plane.get_collector_config(collector_id)

        if not config:
            raise HTTPException(status_code=404, detail="Collector not found")

        # If collector already has this version, return minimal response
        if current_version is not None and config.get('version') == current_version:
            return {
                "collector_id": collector_id,
                "version": current_version,
                "no_change": True
            }

        return config

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting collector config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/{collector_id}/ack")
async def acknowledge_config(
    collector_id: str,
    request: ConfigAckRequest,
    x_collector_key: Optional[str] = Header(None, description="Collector authentication key")
):
    """
    Collector acknowledges config receipt and application status.

    Collectors should call this after successfully applying (or failing to apply)
    a configuration update.

    This helps the control plane track:
    - Which collectors have received the latest config
    - Which collectors are having issues
    - Overall deployment status of config changes
    """
    try:
        control_plane = get_control_plane()
        success = await control_plane.acknowledge_config(
            collector_id=collector_id,
            version=request.version,
            success=request.success,
            message=request.message
        )

        if success:
            return {
                "status": "ok",
                "collector_id": collector_id,
                "version": request.version,
                "acknowledged": True
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to record acknowledgment")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heartbeat")
async def collector_heartbeat(
    request: CollectorHeartbeat,
    x_collector_key: Optional[str] = Header(None, description="Collector authentication key")
):
    """
    Receive heartbeat from collector.

    Collectors send periodic heartbeats with:
    - Current config version
    - Event counts since last heartbeat
    - Telemetry data

    Returns:
    - Whether a config update is available
    - Current expected config version
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Update collector heartbeat in database
            await conn.execute("""
                UPDATE log_agents
                SET last_heartbeat = CURRENT_TIMESTAMP,
                    events_received_total = events_received_total + $1,
                    agent_version = COALESCE($2, agent_version),
                    config = config || $3::jsonb
                WHERE agent_id = $4
            """,
                request.events_sent,
                request.agent_version,
                '{"_last_heartbeat_version": ' + str(request.config_version) + '}',
                request.agent_id
            )

        # Check if config update is available
        control_plane = get_control_plane()
        latest_config = await control_plane.get_collector_config(request.agent_id)
        latest_version = latest_config.get('version', 0) if latest_config else 0

        return {
            "status": "ok",
            "collector_id": request.agent_id,
            "config_update_available": latest_version > request.config_version,
            "latest_config_version": latest_version,
            "server_time": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing heartbeat: {e}")
        # Don't fail on heartbeat errors - just log and return basic response
        return {
            "status": "ok",
            "collector_id": request.agent_id,
            "config_update_available": False,
            "server_time": datetime.utcnow().isoformat()
        }


@router.post("/register")
async def register_collector(
    request: CollectorRegistration,
    x_collector_key: Optional[str] = Header(None, description="Collector authentication key")
):
    """
    Register a new collector.

    Called by collectors on first startup to register themselves.
    Returns initial configuration and authentication credentials.
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        # Validate OS type
        valid_os = ["windows", "linux", "macos", "other"]
        if request.os_type not in valid_os:
            raise HTTPException(status_code=400, detail=f"Invalid os_type. Must be one of: {valid_os}")

        # Generate collector key for future auth
        collector_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(collector_key.encode()).hexdigest()

        async with postgres_db.tenant_acquire() as conn:
            # Register in database
            row = await conn.fetchrow("""
                INSERT INTO log_agents (
                    agent_id, hostname, os_type, os_version, ip_address,
                    agent_version, status, tags, metadata, last_heartbeat,
                    config
                ) VALUES ($1, $2, $3, $4, $5::inet, $6, 'active', $7, $8, CURRENT_TIMESTAMP, $9::jsonb)
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
                RETURNING id, agent_id, registered_at
            """,
                request.agent_id,
                request.hostname,
                request.os_type,
                request.os_version,
                request.ip_address,
                request.agent_version,
                request.tags,
                request.metadata,
                '{"_key_hash": "' + key_hash + '", "_version": 1}'
            )

        # Get initial config
        control_plane = get_control_plane()
        initial_config = await control_plane.get_collector_config(request.agent_id)

        logger.info(f"Registered collector: {request.agent_id} ({request.hostname})")

        return {
            "status": "registered",
            "collector_id": request.agent_id,
            "collector_key": collector_key,  # One-time display - collector must store this
            "registered_at": row["registered_at"].isoformat() if row["registered_at"] else None,
            "config": initial_config
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering collector: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ADMIN/UI ENDPOINTS (Require authentication)
# ============================================================================

@router.get("/collectors")
async def list_collectors(
    status: Optional[str] = Query(None, description="Filter by status"),
    online_only: bool = Query(False, description="Only show online collectors")
):
    """
    List all registered collectors.

    For admin dashboard and UI.
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        query = """
            SELECT id, agent_id, hostname, os_type, os_version, ip_address,
                   agent_version, status, last_heartbeat, events_received_total,
                   tags, config, registered_at
            FROM log_agents
            WHERE 1=1
        """
        params = []

        if status:
            params.append(status)
            query += f" AND status = ${len(params)}"

        if online_only:
            query += " AND last_heartbeat > NOW() - INTERVAL '5 minutes'"

        query += " ORDER BY hostname"

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(query, *params)

        collectors = []
        for row in rows:
            config = row['config'] or {}
            last_hb = row['last_heartbeat']

            # Calculate online status
            if last_hb:
                from datetime import timezone
                age = (datetime.now(timezone.utc) - last_hb.replace(tzinfo=timezone.utc)).total_seconds()
                is_online = age < 300
            else:
                age = None
                is_online = False

            collectors.append({
                "id": str(row['id']),
                "agent_id": row['agent_id'],
                "hostname": row['hostname'],
                "os_type": row['os_type'],
                "os_version": row['os_version'],
                "ip_address": str(row['ip_address']) if row['ip_address'] else None,
                "agent_version": row['agent_version'],
                "status": row['status'],
                "is_online": is_online,
                "last_heartbeat": last_hb.isoformat() if last_hb else None,
                "heartbeat_age_seconds": int(age) if age else None,
                "events_total": row['events_received_total'] or 0,
                "config_version": config.get('_version', 0),
                "tags": row['tags'] or [],
                "registered_at": row['registered_at'].isoformat() if row['registered_at'] else None
            })

        return {
            "collectors": collectors,
            "total": len(collectors),
            "online": sum(1 for c in collectors if c['is_online'])
        }

    except Exception as e:
        logger.error(f"Error listing collectors: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collectors/{collector_id}/health")
async def get_collector_health(collector_id: str):
    """
    Get detailed health status for a collector.

    For monitoring dashboard.
    """
    try:
        control_plane = get_control_plane()
        health = await control_plane.get_collector_health(collector_id)
        return health
    except Exception as e:
        logger.error(f"Error getting collector health: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collectors/{collector_id}/config")
async def update_collector_config(
    collector_id: str,
    request: ConfigUpdateRequest,
    x_user: str = Header("admin", description="User making the change")
):
    """
    Update a collector's configuration.

    Admin endpoint to push config changes.
    Changes are versioned and signed - collector will pull on next poll.
    """
    try:
        control_plane = get_control_plane()

        updates = {}
        if request.settings:
            updates['settings'] = request.settings
        if request.sources:
            updates['sources'] = request.sources

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        result = await control_plane.update_collector_config(
            collector_id=collector_id,
            config_updates=updates,
            changed_by=x_user
        )

        if result:
            return {
                "status": "ok",
                "collector_id": collector_id,
                "new_version": result.version,
                "signature": result.signature[:32] + "..." if result.signature else None,
                "content_hash": result.content_hash
            }
        else:
            raise HTTPException(status_code=404, detail="Collector not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating collector config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collectors/{collector_id}/config/history")
async def get_config_history(
    collector_id: str,
    limit: int = Query(10, le=100)
):
    """
    Get configuration change history for a collector.

    For audit trail and troubleshooting.
    """
    try:
        control_plane = get_control_plane()
        history = await control_plane.get_config_history(collector_id, limit)
        return {"collector_id": collector_id, "history": history}
    except Exception as e:
        logger.error(f"Error getting config history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pending-configs")
async def list_pending_configs():
    """
    List all configs that haven't been acknowledged by collectors.

    For monitoring config rollout status.
    """
    try:
        control_plane = get_control_plane()
        pending = await control_plane.list_pending_configs()
        return {"pending": pending, "count": len(pending)}
    except Exception as e:
        logger.error(f"Error listing pending configs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PUBLIC KEY DISTRIBUTION
# ============================================================================

@router.get("/public-key")
async def get_public_key():
    """
    Get the control plane's public signing key.

    Collectors use this to verify config signatures.
    This should be distributed to collectors during setup.
    """
    control_plane = get_control_plane()
    public_key = control_plane.get_public_key()

    if not public_key:
        return {
            "available": False,
            "message": "Config signing not available (cryptography not installed)"
        }

    return {
        "available": True,
        "algorithm": "Ed25519",
        "public_key": public_key,
        "format": "PEM"
    }


# ============================================================================
# LOG SOURCE MANAGEMENT (for control plane config distribution)
# ============================================================================

@router.get("/sources")
async def list_log_sources():
    """
    List all available log source types.

    Used by collectors to know what sources they can collect.
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT source_type, display_name, description, parser_type,
                       parser_config, is_active
                FROM log_source_configs
                WHERE is_active = true
                ORDER BY display_name
            """)

        sources = [
            {
                "source_type": row['source_type'],
                "display_name": row['display_name'],
                "description": row['description'],
                "parser_type": row['parser_type'],
                "parser_config": row['parser_config'] or {},
                "is_active": row['is_active']
            }
            for row in rows
        ]

        return {"sources": sources, "total": len(sources)}

    except Exception as e:
        logger.error(f"Error listing log sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sources/{source_type}/enable")
async def enable_source_for_collector(
    source_type: str,
    collector_id: str = Query(..., description="Collector to enable source for"),
    config_overrides: Dict[str, Any] = None
):
    """
    Enable a log source for a specific collector.

    This creates a source assignment that will be included in the
    collector's next config pull.
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Verify source type exists
            source = await conn.fetchrow(
                "SELECT id FROM log_source_types WHERE source_type = $1 AND is_enabled = true",
                source_type
            )
            if not source:
                raise HTTPException(status_code=404, detail=f"Source type '{source_type}' not found")

            # Verify collector exists
            collector = await conn.fetchrow(
                "SELECT id, hostname FROM log_agents WHERE agent_id = $1",
                collector_id
            )
            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            # Create assignment
            await conn.execute("""
                INSERT INTO collector_source_assignments (
                    agent_id, agent_hostname, source_type_id, source_type,
                    config_overrides, is_enabled
                ) VALUES ($1, $2, $3, $4, $5, true)
                ON CONFLICT (agent_id, source_type) DO UPDATE SET
                    is_enabled = true,
                    config_overrides = COALESCE($5, collector_source_assignments.config_overrides),
                    updated_at = CURRENT_TIMESTAMP
            """,
                collector['id'],
                collector['hostname'],
                source['id'],
                source_type,
                config_overrides or {}
            )

        # Increment config version to trigger collector update
        control_plane = get_control_plane()
        await control_plane.update_collector_config(
            collector_id=collector_id,
            config_updates={'_source_updated': source_type},
            changed_by='system'
        )

        return {
            "status": "ok",
            "collector_id": collector_id,
            "source_type": source_type,
            "enabled": True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error enabling source: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sources/{source_type}/disable")
async def disable_source_for_collector(
    source_type: str,
    collector_id: str = Query(..., description="Collector to disable source for")
):
    """
    Disable a log source for a specific collector.
    """
    try:
        if not postgres_db.connected or postgres_db.pool is None:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Get collector
            collector = await conn.fetchrow(
                "SELECT id FROM log_agents WHERE agent_id = $1",
                collector_id
            )
            if not collector:
                raise HTTPException(status_code=404, detail=f"Collector '{collector_id}' not found")

            # Disable assignment
            result = await conn.execute("""
                UPDATE collector_source_assignments
                SET is_enabled = false, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = $1 AND source_type = $2
            """, collector['id'], source_type)

        # Increment config version
        control_plane = get_control_plane()
        await control_plane.update_collector_config(
            collector_id=collector_id,
            config_updates={'_source_updated': source_type},
            changed_by='system'
        )

        return {
            "status": "ok",
            "collector_id": collector_id,
            "source_type": source_type,
            "enabled": False
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disabling source: {e}")
        raise HTTPException(status_code=500, detail=str(e))
