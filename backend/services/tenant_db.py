# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tenant-Scoped Database Access

Provides database connections with automatic tenant context for Row-Level Security.
All queries through tenant_connection() are automatically filtered by tenant_id.
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional, Any, List

from middleware.tenant_middleware import get_current_tenant_id, get_optional_tenant_id

logger = logging.getLogger(__name__)


@asynccontextmanager
async def tenant_connection():
    """
    Get a database connection with tenant context set for RLS.

    Usage:
        async with tenant_connection() as conn:
            # All queries automatically filtered by tenant_id
            rows = await conn.fetch("SELECT * FROM alerts")

    The connection sets `app.current_tenant_id` which is used by
    PostgreSQL Row-Level Security policies to filter all queries.

    Raises:
        RuntimeError: If no tenant context is available
    """
    from services.postgres_db import postgres_db

    tenant_id = get_current_tenant_id()  # Raises if not set

    if not postgres_db.connected or postgres_db.pool is None:
        raise RuntimeError("Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        # Set tenant context for RLS policies
        await conn.execute(
            "SELECT set_config('app.current_tenant_id', $1, false)",
            str(tenant_id)
        )

        logger.debug(f"Database connection opened for tenant: {tenant_id}")

        try:
            yield conn
        finally:
            # SET LOCAL automatically resets at transaction end
            # But we explicitly reset for safety
            try:
                await conn.execute("RESET app.current_tenant_id")
            except Exception:
                pass  # Connection may already be closed


@asynccontextmanager
async def platform_admin_connection():
    """
    Get a database connection with platform admin privileges.

    This bypasses RLS and should ONLY be used by platform admin operations.
    All access through this connection is logged for audit.

    Usage:
        async with platform_admin_connection() as conn:
            # Can see all tenants' data - use with caution!
            rows = await conn.fetch("SELECT * FROM tenants")
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise RuntimeError("Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        # Set admin bypass flag for RLS policies
        await conn.execute("SET app.is_platform_admin = 'true'")

        logger.info("Platform admin database connection opened")

        try:
            yield conn
        finally:
            try:
                await conn.execute("RESET app.is_platform_admin")
            except Exception:
                pass


@asynccontextmanager
async def tenant_context_connection(tenant_id: str):
    """
    Get a database connection for a specific tenant.

    Used when you need to operate on a specific tenant outside of a request context.
    Example: Background jobs, scheduled tasks, admin operations.

    Args:
        tenant_id: The tenant ID to set context for

    Usage:
        async with tenant_context_connection("tenant-uuid") as conn:
            rows = await conn.fetch("SELECT * FROM alerts")
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise RuntimeError("Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        await conn.execute(
            "SELECT set_config('app.current_tenant_id', $1, false)",
            str(tenant_id)
        )

        logger.debug(f"Explicit tenant connection opened for: {tenant_id}")

        try:
            yield conn
        finally:
            try:
                await conn.execute("RESET app.current_tenant_id")
            except Exception:
                pass


# =============================================================================
# Convenience Query Functions
# =============================================================================

async def tenant_fetch(query: str, *args) -> List[dict]:
    """
    Execute a query and return all rows for current tenant.

    Usage:
        alerts = await tenant_fetch("SELECT * FROM alerts WHERE severity = $1", "high")
    """
    async with tenant_connection() as conn:
        rows = await conn.fetch(query, *args)
        return [dict(row) for row in rows]


async def tenant_fetchrow(query: str, *args) -> Optional[dict]:
    """
    Execute a query and return first row for current tenant.

    Usage:
        alert = await tenant_fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    """
    async with tenant_connection() as conn:
        row = await conn.fetchrow(query, *args)
        return dict(row) if row else None


async def tenant_fetchval(query: str, *args) -> Any:
    """
    Execute a query and return a single value for current tenant.

    Usage:
        count = await tenant_fetchval("SELECT COUNT(*) FROM alerts")
    """
    async with tenant_connection() as conn:
        return await conn.fetchval(query, *args)


async def tenant_execute(query: str, *args) -> str:
    """
    Execute a query (INSERT, UPDATE, DELETE) for current tenant.

    Usage:
        await tenant_execute("UPDATE alerts SET status = $1 WHERE id = $2", "closed", alert_id)
    """
    async with tenant_connection() as conn:
        return await conn.execute(query, *args)


# =============================================================================
# Tenant-Aware Insert Helper
# =============================================================================

async def tenant_insert(
    table: str,
    data: dict,
    returning: str = "*"
) -> Optional[dict]:
    """
    Insert a row with automatic tenant_id injection.

    Usage:
        alert = await tenant_insert("alerts", {
            "title": "Suspicious Login",
            "severity": "high"
        })

    The tenant_id is automatically added from current context.
    """
    tenant_id = get_current_tenant_id()

    # Add tenant_id to data
    data_with_tenant = {"tenant_id": tenant_id, **data}

    # Build query
    columns = ", ".join(data_with_tenant.keys())
    placeholders = ", ".join(f"${i+1}" for i in range(len(data_with_tenant)))
    values = list(data_with_tenant.values())

    query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING {returning}"

    async with tenant_connection() as conn:
        row = await conn.fetchrow(query, *values)
        return dict(row) if row else None


# =============================================================================
# Cross-Tenant Safety Checks
# =============================================================================

def verify_tenant_ownership(resource_tenant_id: str) -> bool:
    """
    Verify that a resource belongs to the current tenant.

    Use this as an extra safety check when loading resources by ID
    that might have come from user input.

    Usage:
        if not verify_tenant_ownership(alert['tenant_id']):
            raise HTTPException(404, "Alert not found")
    """
    current = get_optional_tenant_id()
    if not current:
        return False
    return str(resource_tenant_id) == str(current)


def require_tenant_ownership(resource_tenant_id: str, resource_type: str = "resource") -> None:
    """
    Require that a resource belongs to the current tenant.
    Raises HTTPException if not.

    Usage:
        require_tenant_ownership(alert['tenant_id'], "alert")
    """
    from fastapi import HTTPException

    if not verify_tenant_ownership(resource_tenant_id):
        # Log potential attack attempt
        current = get_optional_tenant_id()
        logger.warning(
            f"SECURITY: Cross-tenant access attempt blocked. "
            f"Current tenant: {current}, Target resource tenant: {resource_tenant_id}, "
            f"Resource type: {resource_type}"
        )
        # Return 404 (not 403) to avoid leaking existence of resources
        raise HTTPException(status_code=404, detail=f"{resource_type.title()} not found")


async def get_resource_with_tenant_check(
    table: str,
    resource_id: str,
    id_column: str = "id"
) -> Optional[dict]:
    """
    Fetch a resource by ID with automatic tenant verification.

    This is the safest way to fetch a resource by ID from user input.
    Returns None if resource doesn't exist OR belongs to different tenant.

    Usage:
        alert = await get_resource_with_tenant_check("alerts", alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
    """
    async with tenant_connection() as conn:
        # RLS already filters, but we explicitly check tenant_id too
        row = await conn.fetchrow(
            f"SELECT * FROM {table} WHERE {id_column} = $1",
            resource_id
        )

        if not row:
            return None

        result = dict(row)

        # Double-check tenant ownership (defense in depth)
        if "tenant_id" in result:
            if not verify_tenant_ownership(result["tenant_id"]):
                logger.warning(
                    f"SECURITY: RLS bypass attempt? Resource {table}/{resource_id} "
                    f"returned but tenant_id mismatch"
                )
                return None

        return result


async def log_security_event(
    event_type: str,
    details: dict,
    severity: str = "warning"
) -> None:
    """
    Log a security-related event to the audit log.

    Usage:
        await log_security_event(
            "cross_tenant_attempt",
            {"target_tenant": "xxx", "resource": "alert/123"}
        )
    """
    from services.postgres_db import postgres_db

    tenant_id = get_optional_tenant_id()

    try:
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute("""
                    INSERT INTO tenant_audit_log
                    (tenant_id, actor_type, action, details, created_at)
                    VALUES ($1, 'system', $2, $3, NOW())
                """, tenant_id, f"security_{event_type}", details)
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

    # Always log to application logs
    log_func = getattr(logger, severity, logger.warning)
    log_func(f"SECURITY EVENT [{event_type}]: {details}")
