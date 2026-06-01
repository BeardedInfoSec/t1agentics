# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform Admin Routes

Provides administrative access for T1 Agentics platform management.
Allows viewing all tenants, managing licenses, and cross-tenant operations.
"""

import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/platform", tags=["Platform Admin"])

# JWT Configuration for Platform Admin
PLATFORM_JWT_SECRET = os.environ.get("PLATFORM_JWT_SECRET")
if not PLATFORM_JWT_SECRET:
    raise RuntimeError("CRITICAL: PLATFORM_JWT_SECRET environment variable is not set.")
PLATFORM_JWT_ALGORITHM = "HS256"
PLATFORM_JWT_EXPIRY_HOURS = 8


# =============================================================================
# Pydantic Models
# =============================================================================

class PlatformAdminLogin(BaseModel):
    email: str
    password: str


class PlatformAdminCreate(BaseModel):
    email: EmailStr
    name: str
    password: str = Field(min_length=12)
    permissions: List[str] = ["read", "write", "manage_tenants", "manage_licenses"]


class TenantCreate(BaseModel):
    slug: str = Field(min_length=3, max_length=50, pattern=r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$')
    name: str = Field(min_length=1, max_length=255)
    plan: str = "community"
    expires_in_days: Optional[int] = None
    admin_email: Optional[EmailStr] = None
    admin_name: Optional[str] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None
    alerts_per_day_limit: Optional[int] = None
    users_limit: Optional[int] = None
    playbooks_limit: Optional[int] = None
    integrations_limit: Optional[int] = None
    retention_days: Optional[int] = None


class LicenseCreate(BaseModel):
    tenant_id: str
    tier: str = "community"
    expires_in_days: Optional[int] = None
    custom_limits: Optional[dict] = None


class LicenseUpdate(BaseModel):
    tier: Optional[str] = None
    expires_at: Optional[datetime] = None
    custom_limits: Optional[dict] = None
    is_active: Optional[bool] = None


# =============================================================================
# Authentication Helpers
# =============================================================================

def create_platform_token(admin_id: str, email: str, permissions: list) -> str:
    """Create JWT token for platform admin."""
    payload = {
        "sub": admin_id,
        "email": email,
        "permissions": permissions,
        "is_platform_admin": True,
        "exp": datetime.utcnow() + timedelta(hours=PLATFORM_JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, PLATFORM_JWT_SECRET, algorithm=PLATFORM_JWT_ALGORITHM)


async def get_current_platform_admin(request: Request) -> dict:
    """Verify platform admin JWT and return admin info."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing platform admin token")

    token = auth_header[7:]
    try:
        payload = jwt.decode(token, PLATFORM_JWT_SECRET, algorithms=[PLATFORM_JWT_ALGORITHM])
        if not payload.get("is_platform_admin"):
            raise HTTPException(status_code=403, detail="Not a platform admin token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_permission(permission: str):
    """Decorator factory for permission checks."""
    async def check_permission(admin: dict = Depends(get_current_platform_admin)):
        if permission not in admin.get("permissions", []):
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required"
            )
        return admin
    return check_permission


def generate_license_key() -> str:
    """Generate a unique license key."""
    return f"T1-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"


def safe_admin_uuid(admin_sub: str) -> Optional[uuid.UUID]:
    """Parse admin sub to UUID, returning None for tenant-elevated admins."""
    try:
        return uuid.UUID(admin_sub)
    except (ValueError, AttributeError):
        return None


# Default license durations by plan tier (in days)
DEFAULT_LICENSE_DURATIONS = {
    "community": None,       # No expiry
    "professional": 365,     # 12 months
    "enterprise": 365,       # 12 months
    "platform": None,        # No expiry (internal)
    "trial": 30,             # 30 days
}


# =============================================================================
# Platform Admin Authentication
# =============================================================================

@router.post("/login")
async def platform_admin_login(credentials: PlatformAdminLogin):
    """
    Authenticate as a platform admin.
    Returns JWT token for subsequent API calls.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        admin = await conn.fetchrow(
            """
            SELECT id, email, name, password_hash, permissions, is_active
            FROM platform_admins
            WHERE email = $1
            """,
            credentials.email.lower()
        )

        if not admin:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not admin["is_active"]:
            raise HTTPException(status_code=403, detail="Account disabled")

        # Verify password
        if not bcrypt.checkpw(
            credentials.password.encode(),
            admin["password_hash"].encode()
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Update last login
        await conn.execute(
            "UPDATE platform_admins SET last_login_at = NOW() WHERE id = $1",
            admin["id"]
        )

        # Log login
        await conn.execute(
            """
            INSERT INTO platform_audit_log (admin_id, action, details)
            VALUES ($1, 'login', $2::jsonb)
            """,
            admin["id"],
            json.dumps({"email": admin["email"]})
        )

        token = create_platform_token(
            str(admin["id"]),
            admin["email"],
            admin["permissions"] or []
        )

        return {
            "token": token,
            "admin": {
                "id": str(admin["id"]),
                "email": admin["email"],
                "name": admin["name"],
                "permissions": admin["permissions"]
            }
        }


@router.get("/me")
async def get_current_admin(admin: dict = Depends(get_current_platform_admin)):
    """Get current platform admin info."""
    return {
        "id": admin["sub"],
        "email": admin["email"],
        "permissions": admin["permissions"]
    }


@router.post("/elevate")
async def elevate_to_platform_admin(request: Request):
    """
    Allows platform owner tenant admins to get a platform admin token.

    Uses the tenant session cookie to authenticate, then checks if the user
    is from the platform owner tenant with admin role. If so, issues a
    platform admin token.
    """
    from services.postgres_db import postgres_db
    from dependencies.auth import get_current_user

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    # Get current tenant user from session
    try:
        current_user = await get_current_user(request, request.headers.get("Authorization"))
    except HTTPException:
        raise HTTPException(status_code=401, detail="Not authenticated as tenant user")

    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="No tenant associated with user")

    # Check if user has admin role
    if current_user.get("role") not in ("admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Must be a tenant admin to elevate")

    async with postgres_db.pool.acquire() as conn:
        # Check if the tenant is the platform owner
        tenant = await conn.fetchrow(
            "SELECT slug, name, settings FROM tenants WHERE id = $1",
            tenant_id
        )

        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Parse settings
        raw_settings = tenant["settings"]
        if isinstance(raw_settings, str):
            settings = json.loads(raw_settings) if raw_settings else {}
        else:
            settings = raw_settings or {}

        if not settings.get("is_platform_owner"):
            raise HTTPException(
                status_code=403,
                detail="Only platform owner tenant admins can access platform admin"
            )

        # Create a platform admin token for this user
        # Use the tenant user's info to create a pseudo-admin identity
        token = create_platform_token(
            f"tenant:{current_user['username']}",
            current_user.get("email") or f"{current_user['username']}@{tenant['slug']}",
            ["read", "write", "manage_tenants", "manage_licenses"]  # Full permissions
        )

        # Log this elevation
        await conn.execute(
            """
            INSERT INTO platform_audit_log (admin_id, action, details)
            VALUES (NULL, 'tenant_admin_elevation', $1::jsonb)
            """,
            json.dumps({
                "username": current_user["username"],
                "tenant_slug": tenant["slug"],
                "tenant_name": tenant["name"]
            })
        )

        return {
            "token": token,
            "admin": {
                "id": f"tenant:{current_user['username']}",
                "email": current_user.get("email"),
                "name": current_user.get("full_name") or current_user["username"],
                "permissions": ["read", "write", "manage_tenants", "manage_licenses"],
                "is_tenant_elevated": True
            }
        }


# =============================================================================
# Tenant Management
# =============================================================================

@router.get("/tenants")
async def list_tenants(
    status: Optional[str] = None,
    plan: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    admin: dict = Depends(require_permission("read"))
):
    """
    List all tenants with their usage and license info.
    Platform admins can see everything.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        # Set platform admin bypass for RLS
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Build query with filters
        where_clauses = []
        params = []
        param_idx = 1

        if status:
            where_clauses.append(f"t.status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if plan:
            where_clauses.append(f"t.plan = ${param_idx}")
            params.append(plan)
            param_idx += 1

        if search:
            where_clauses.append(f"(t.name ILIKE ${param_idx} OR t.slug ILIKE ${param_idx})")
            params.append(f"%{search}%")
            param_idx += 1

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Get total count
        count_result = await conn.fetchval(
            f"SELECT COUNT(*) FROM tenants t {where_sql}",
            *params
        )

        # Get tenants with usage data
        params.extend([limit, offset])
        rows = await conn.fetch(f"""
            SELECT
                t.id,
                t.slug,
                t.name,
                t.plan,
                t.status,
                t.created_at,
                t.settings,
                t.alerts_per_day_limit,
                t.users_limit,
                t.playbooks_limit,
                tl.license_key,
                tl.tier AS license_tier,
                tl.expires_at AS license_expires,
                tl.is_active AS license_active,
                (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) AS user_count,
                (SELECT COUNT(*) FROM alerts a WHERE a.tenant_id = t.id) AS alert_count,
                (SELECT COUNT(*) FROM playbooks p WHERE p.tenant_id = t.id) AS playbook_count,
                COALESCE(tac.byo_allowed, FALSE) AS byo_allowed,
                COALESCE(tac.byo_enabled, FALSE) AS byo_enabled
            FROM tenants t
            LEFT JOIN tenant_licenses tl ON tl.id = t.active_license_id
            LEFT JOIN tenant_ai_config tac ON tac.tenant_id = t.id
            {where_sql}
            ORDER BY t.created_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """, *params)

        tenants = []
        for row in rows:
            tenant = dict(row)
            tenant["id"] = str(tenant["id"])
            tenant.pop("license_key", None)
            # Parse settings - may be JSON string or dict
            raw_settings = tenant.get("settings")
            if isinstance(raw_settings, str):
                settings = json.loads(raw_settings) if raw_settings else {}
            else:
                settings = raw_settings or {}
            tenant["is_platform_owner"] = settings.get("is_platform_owner", False)
            tenants.append(tenant)

        return {
            "tenants": tenants,
            "total": count_result,
            "limit": limit,
            "offset": offset
        }


@router.get("/tenants/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    admin: dict = Depends(require_permission("read"))
):
    """Get detailed tenant information including all usage metrics."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        tenant = await conn.fetchrow("""
            SELECT t.*, tl.license_key, tl.tier AS license_tier,
                   tl.expires_at AS license_expires, tl.custom_limits
            FROM tenants t
            LEFT JOIN tenant_licenses tl ON tl.id = t.active_license_id
            WHERE t.id = $1
        """, uuid.UUID(tenant_id))

        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Get usage metrics
        usage = await conn.fetchrow("""
            SELECT
                (SELECT COUNT(*) FROM users WHERE tenant_id = $1) AS users,
                (SELECT COUNT(*) FROM alerts WHERE tenant_id = $1) AS alerts,
                (SELECT COUNT(*) FROM playbooks WHERE tenant_id = $1) AS playbooks,
                (SELECT COUNT(*) FROM playbook_executions WHERE tenant_id = $1) AS executions,
                (SELECT COUNT(*) FROM investigations WHERE tenant_id = $1) AS investigations,
                (SELECT COUNT(*) FROM iocs WHERE tenant_id = $1) AS iocs
        """, uuid.UUID(tenant_id))

        # Get recent activity
        recent_alerts = await conn.fetch("""
            SELECT id, title, severity, status, created_at
            FROM alerts
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT 5
        """, uuid.UUID(tenant_id))

        # Get usage breakdowns for hover tooltips
        t_uuid = uuid.UUID(tenant_id)

        # Users: list usernames + email
        user_rows = await conn.fetch(
            "SELECT username, email, role FROM users WHERE tenant_id = $1 ORDER BY username LIMIT 20",
            t_uuid
        )

        # Locked accounts
        locked_rows = await conn.fetch("""
            SELECT username, email, failed_login_attempts, locked_until
            FROM users
            WHERE tenant_id = $1
              AND locked_until IS NOT NULL
              AND locked_until > NOW()
            ORDER BY locked_until DESC
        """, t_uuid)

        # Alerts: count by severity
        alert_breakdown = await conn.fetch(
            "SELECT severity, COUNT(*) AS count FROM alerts WHERE tenant_id = $1 GROUP BY severity ORDER BY count DESC",
            t_uuid
        )

        # Playbooks: list names
        playbook_rows = await conn.fetch(
            "SELECT name FROM playbooks WHERE tenant_id = $1 ORDER BY name LIMIT 20",
            t_uuid
        )

        # Executions: count by state
        exec_breakdown = await conn.fetch("""
            SELECT pe.status AS state, COUNT(*) AS count
            FROM playbook_executions pe
            WHERE pe.tenant_id = $1
            GROUP BY pe.status
            ORDER BY count DESC
        """, t_uuid)

        # Investigations: count by state
        inv_breakdown = await conn.fetch(
            "SELECT state, COUNT(*) AS count FROM investigations WHERE tenant_id = $1 GROUP BY state ORDER BY count DESC",
            t_uuid
        )

        # IOCs: count by type
        ioc_breakdown = await conn.fetch(
            "SELECT ioc_type, COUNT(*) AS count FROM iocs WHERE tenant_id = $1 GROUP BY ioc_type ORDER BY count DESC",
            t_uuid
        )

        result = dict(tenant)
        result["id"] = str(result["id"])
        result.pop("license_key", None)
        result["usage"] = dict(usage) if usage else {}
        result["usage_breakdowns"] = {
            "users": [{"username": r["username"], "email": r["email"], "role": r["role"]} for r in user_rows],
            "alerts": [{"severity": r["severity"], "count": r["count"]} for r in alert_breakdown],
            "playbooks": [{"name": r["name"]} for r in playbook_rows],
            "executions": [{"state": r["state"], "count": r["count"]} for r in exec_breakdown],
            "investigations": [{"state": r["state"], "count": r["count"]} for r in inv_breakdown],
            "iocs": [{"type": r["ioc_type"], "count": r["count"]} for r in ioc_breakdown],
        }
        result["recent_alerts"] = [dict(a) for a in recent_alerts]
        result["locked_accounts"] = [
            {
                "username": r["username"],
                "email": r["email"],
                "failed_attempts": r["failed_login_attempts"],
                "locked_until": r["locked_until"].isoformat() if r["locked_until"] else None,
            }
            for r in locked_rows
        ]

        return result


@router.post("/tenants")
async def create_tenant(
    data: TenantCreate,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Create a new tenant with optional initial admin user."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Check if slug exists
        existing = await conn.fetchval(
            "SELECT id FROM tenants WHERE slug = $1",
            data.slug.lower()
        )
        if existing:
            raise HTTPException(status_code=400, detail="Tenant slug already exists")

        # Create tenant
        tenant_id = uuid.uuid4()
        await conn.execute("""
            INSERT INTO tenants (id, slug, name, plan, status)
            VALUES ($1, $2, $3, $4, 'active')
        """, tenant_id, data.slug.lower(), data.name, data.plan)

        # Deactivate any pre-existing licenses for this tenant
        await conn.execute("""
            UPDATE tenant_licenses
            SET is_active = false, revoked_at = NOW(), revoke_reason = 'Superseded by new license'
            WHERE tenant_id = $1 AND is_active = true
        """, tenant_id)

        # Create license with optional expiration
        license_key = generate_license_key()
        license_id = uuid.uuid4()
        expires_at = None
        if data.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=data.expires_in_days)
        elif data.plan in DEFAULT_LICENSE_DURATIONS and DEFAULT_LICENSE_DURATIONS[data.plan]:
            expires_at = datetime.utcnow() + timedelta(days=DEFAULT_LICENSE_DURATIONS[data.plan])

        admin_uuid = safe_admin_uuid(admin.get("sub"))
        await conn.execute("""
            INSERT INTO tenant_licenses (id, tenant_id, license_key, tier, expires_at, issued_by)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, license_id, tenant_id, license_key, data.plan, expires_at, admin_uuid)

        # Link license to tenant
        await conn.execute(
            "UPDATE tenants SET active_license_id = $1 WHERE id = $2",
            license_id, tenant_id
        )

        # Always create default t1_admin account for the new tenant
        import secrets
        import string
        default_password = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(24))
        default_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()
        admin_email = data.admin_email or f"admin@{data.slug}.local"
        logger.info(f"Created tenant admin for {data.slug} -- initial password: {default_password} (force_password_reset=true)")

        await conn.execute("""
            INSERT INTO users (tenant_id, username, email, hashed_password, role, tenant_role, force_password_reset)
            VALUES ($1, 't1_admin', $2, $3, 'admin', 'admin', true)
        """, tenant_id, admin_email, default_hash)

        # Initialize Claude usage tracking for the new tenant
        await conn.execute("""
            INSERT INTO tenant_claude_usage (tenant_id, month_start)
            VALUES ($1, date_trunc('month', CURRENT_DATE)::date)
            ON CONFLICT DO NOTHING
        """, tenant_id)

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'create_tenant', 'tenant', $2, $3::jsonb)
        """, admin_uuid, tenant_id, json.dumps({
            "slug": data.slug,
            "name": data.name,
            "plan": data.plan,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_by": admin.get("sub", "unknown")
        }))

        logger.info(f"Platform admin {admin['email']} created tenant: {data.slug}")

        return {
            "id": str(tenant_id),
            "slug": data.slug,
            "name": data.name,
            "plan": data.plan,
            "license_expires": expires_at.isoformat() if expires_at else None,
            "status": "active",
            "admin_email": admin_email,
            "initial_password": default_password,
        }


@router.patch("/tenants/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    data: TenantUpdate,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Update tenant settings and limits."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Verify tenant exists
        existing = await conn.fetchrow(
            "SELECT id, slug FROM tenants WHERE id = $1",
            uuid.UUID(tenant_id)
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Build update query
        updates = []
        params = []
        param_idx = 1

        update_fields = data.model_dump(exclude_unset=True)
        for field, value in update_fields.items():
            updates.append(f"{field} = ${param_idx}")
            params.append(value)
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        updates.append(f"updated_at = NOW()")
        params.append(uuid.UUID(tenant_id))

        await conn.execute(
            f"UPDATE tenants SET {', '.join(updates)} WHERE id = ${param_idx}",
            *params
        )

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'update_tenant', 'tenant', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), uuid.UUID(tenant_id), json.dumps(update_fields))

        logger.info(f"Platform admin {admin['email']} updated tenant: {existing['slug']}")

        return {"status": "updated", "tenant_id": tenant_id}


@router.put("/tenants/{tenant_id}/byo-allowed")
async def set_tenant_byo_allowed(
    tenant_id: str,
    payload: Dict[str, Any] = Body(...),
    admin: dict = Depends(require_permission("manage_tenants")),
):
    """
    Platform-admin toggle: allow this tenant to bring their own LLM.

    When `allowed=true`, the tenant's admin can then turn `byo_enabled=true`
    via /api/v1/ai-config and provide a key. Until the tenant flips that
    second switch and saves a key, behavior is unchanged (still on platform).
    """
    from services import tenant_ai_config_service as cfg_svc

    allowed = bool(payload.get("allowed"))
    # Platform admin's `sub` claim is "tenant:admin" not a UUID; the
    # tenant_ai_config.updated_by column expects UUID. safe_admin_uuid
    # is the same helper the audit-log path uses to coerce or NULL it.
    admin_uuid = safe_admin_uuid(admin.get("sub"))
    try:
        result = await cfg_svc.set_byo_allowed(
            tenant_id, allowed,
            updated_by=str(admin_uuid) if admin_uuid else None,
        )
    except Exception as e:
        logger.error(f"Failed to set byo_allowed for tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail="update failed")

    # Audit
    try:
        from services.postgres_db import postgres_db
        async with postgres_db.pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            await conn.execute(
                """
                INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
                VALUES ($1, 'set_byo_allowed', 'tenant', $2, $3::jsonb)
                """,
                safe_admin_uuid(admin.get("sub")),
                uuid.UUID(tenant_id),
                json.dumps({"allowed": allowed}),
            )
    except Exception as e:
        logger.warning(f"audit log write failed for set_byo_allowed: {e}")

    return result


@router.post("/tenants/{tenant_id}/suspend")
async def suspend_tenant(
    tenant_id: str,
    reason: str = "Administrative action",
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Suspend a tenant, blocking all access."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Prevent suspending platform owner
        tenant = await conn.fetchrow(
            "SELECT slug, settings FROM tenants WHERE id = $1",
            uuid.UUID(tenant_id)
        )
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Parse settings - may be JSON string or dict
        raw_settings = tenant["settings"]
        if isinstance(raw_settings, str):
            settings = json.loads(raw_settings) if raw_settings else {}
        else:
            settings = raw_settings or {}

        if settings.get("is_platform_owner"):
            raise HTTPException(status_code=403, detail="Cannot suspend platform owner tenant")

        await conn.execute("""
            UPDATE tenants
            SET status = 'suspended', suspended_at = NOW(), suspended_reason = $1
            WHERE id = $2
        """, reason, uuid.UUID(tenant_id))

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'suspend_tenant', 'tenant', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), uuid.UUID(tenant_id), json.dumps({"reason": reason}))

        logger.warning(f"Platform admin {admin['email']} suspended tenant: {tenant['slug']}")

        return {"status": "suspended", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/reactivate")
async def reactivate_tenant(
    tenant_id: str,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Reactivate a suspended tenant."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        await conn.execute("""
            UPDATE tenants
            SET status = 'active', suspended_at = NULL, suspended_reason = NULL
            WHERE id = $1
        """, uuid.UUID(tenant_id))

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'reactivate_tenant', 'tenant', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), uuid.UUID(tenant_id), json.dumps({}))

        return {"status": "active", "tenant_id": tenant_id}


class TenantDeleteConfirm(BaseModel):
    confirm_slug: str = Field(..., description="Must match tenant slug to confirm deletion")


@router.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    confirmation: TenantDeleteConfirm,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """
    Permanently delete a tenant and all associated data.

    This action is irreversible. The confirm_slug must match the tenant's slug.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Get tenant info first
        tenant = await conn.fetchrow("""
            SELECT id, slug, name FROM tenants WHERE id = $1
        """, uuid.UUID(tenant_id))

        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Verify confirmation slug matches
        if confirmation.confirm_slug != tenant["slug"]:
            raise HTTPException(
                status_code=400,
                detail=f"Confirmation slug '{confirmation.confirm_slug}' does not match tenant slug '{tenant['slug']}'"
            )

        # Prevent deletion of protected tenants
        if tenant["slug"] in ("default", "platform"):
            raise HTTPException(status_code=403, detail="Cannot delete protected system tenants")

        tenant_uuid = uuid.UUID(tenant_id)
        deleted_data = {
            "tenant_slug": tenant["slug"],
            "tenant_name": tenant["name"],
        }

        # Delete all related data in order (respecting foreign keys)
        # Helper to safely delete and count
        async def delete_count(table: str) -> int:
            try:
                result = await conn.execute(f"DELETE FROM {table} WHERE tenant_id = $1", tenant_uuid)
                return int(result.split()[-1]) if result else 0
            except Exception as e:
                logger.warning(f"Failed to delete from {table}: {e}")
                return 0

        # 1. Delete alerts (and related data)
        deleted_data["alerts_deleted"] = await delete_count("alerts")

        # 2. Delete investigations
        deleted_data["investigations_deleted"] = await delete_count("investigations")

        # 3. Delete approval requests
        deleted_data["approval_requests_deleted"] = await delete_count("approval_requests")

        # 4. Delete IOCs
        deleted_data["iocs_deleted"] = await delete_count("iocs")

        # 5. Delete playbook executions
        deleted_data["playbook_executions_deleted"] = await delete_count("playbook_executions")

        # 6. Delete playbooks
        deleted_data["playbooks_deleted"] = await delete_count("playbooks")

        # 7. Delete webhooks
        deleted_data["webhooks_deleted"] = await delete_count("webhooks")

        # 8. Delete EDL lists
        deleted_data["edl_lists_deleted"] = await delete_count("edl_lists")

        # 9. Delete credentials
        deleted_data["credentials_deleted"] = await delete_count("credentials")

        # 10. Delete integration instances (if exists)
        try:
            result = await conn.execute("DELETE FROM integration_instances WHERE tenant_id = $1", tenant_uuid)
            deleted_data["integrations_deleted"] = int(result.split()[-1]) if result else 0
        except Exception:
            deleted_data["integrations_deleted"] = 0

        # 11. Delete threat feeds (if tenant-specific)
        deleted_data["threat_feeds_deleted"] = await delete_count("threat_feeds")

        # 12. Delete usage events
        deleted_data["usage_events_deleted"] = await delete_count("usage_events")

        # 13. Delete tenant usage snapshots
        deleted_data["usage_snapshots_deleted"] = await delete_count("tenant_usage_snapshots")

        # 14. Delete tenant audit log
        deleted_data["audit_log_deleted"] = await delete_count("tenant_audit_log")

        # 15. Delete platform tenant overview cache
        try:
            await conn.execute("DELETE FROM platform_tenant_overview WHERE tenant_id = $1", tenant_uuid)
        except Exception:
            pass

        # 16. Delete users
        deleted_data["users_deleted"] = await delete_count("users")

        # 17. Clear active_license_id FK on tenant before deleting licenses
        try:
            await conn.execute(
                "UPDATE tenants SET active_license_id = NULL WHERE id = $1", tenant_uuid
            )
        except Exception:
            pass

        # 18. Delete licenses
        deleted_data["licenses_deleted"] = await delete_count("tenant_licenses")

        # 19. Clear registration_requests FK reference
        try:
            await conn.execute(
                "UPDATE registration_requests SET provisioned_tenant_id = NULL WHERE provisioned_tenant_id = $1",
                tenant_uuid
            )
        except Exception:
            pass

        # 19b. Tables with FK -> tenants(id) set to NO ACTION (don't cascade);
        # must be deleted explicitly or the final DELETE FROM tenants fails
        # with "violates foreign key constraint". Discovered the hard way via
        # tenant_claude_usage_tenant_id_fkey on 2026-05-05.
        for tbl in (
            "tenant_claude_usage",
            "ai_token_usage",
            "recommended_actions",
            "entity_risk",
            "investigation_entities",
            "correlation_decisions",
            "correlation_settings",
            "phishing_tests",
            "playbook_templates",
            "stripe_checkout_sessions",
        ):
            deleted_data[f"{tbl}_deleted"] = await delete_count(tbl)

        # referrals has TWO FKs to tenants (referrer_tenant_id + referred_tenant_id).
        # Delete records this tenant initiated; null out where it was the referee
        # so the referrer's history is preserved.
        try:
            r = await conn.execute(
                "DELETE FROM referrals WHERE referrer_tenant_id = $1", tenant_uuid
            )
            deleted_data["referrals_as_referrer_deleted"] = int(r.split()[-1]) if r else 0
        except Exception as e:
            logger.warning(f"Failed to delete referrals (referrer): {e}")
            deleted_data["referrals_as_referrer_deleted"] = 0
        try:
            await conn.execute(
                "UPDATE referrals SET referred_tenant_id = NULL WHERE referred_tenant_id = $1",
                tenant_uuid,
            )
        except Exception as e:
            logger.warning(f"Failed to null referrals.referred_tenant_id: {e}")

        # 20. Finally delete the tenant
        await conn.execute("""
            DELETE FROM tenants WHERE id = $1
        """, tenant_uuid)

        # Audit log (non-blocking - don't fail the response if this fails)
        try:
            admin_uuid = safe_admin_uuid(admin.get("sub")) if isinstance(admin["sub"], str) else admin["sub"]
            await conn.execute("""
                INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
                VALUES ($1, 'delete_tenant', 'tenant', $2, $3::jsonb)
            """, admin_uuid, tenant_uuid, json.dumps(deleted_data))
        except Exception as e:
            logger.warning(f"Failed to write audit log for tenant deletion: {e}")

        logger.warning(f"Tenant {tenant['slug']} deleted by admin {admin['email']}: {deleted_data}")

        return {
            "status": "deleted",
            "tenant_id": tenant_id,
            "deleted_data": deleted_data
        }


# =============================================================================
# License Management
# =============================================================================

@router.get("/licenses")
async def list_licenses(
    tenant_id: Optional[str] = None,
    tier: Optional[str] = None,
    is_active: Optional[bool] = None,
    admin: dict = Depends(require_permission("read"))
):
    """List all licenses with optional filters."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        where_clauses = []
        params = []
        param_idx = 1

        if tenant_id:
            where_clauses.append(f"tl.tenant_id = ${param_idx}")
            params.append(uuid.UUID(tenant_id))
            param_idx += 1

        if tier:
            where_clauses.append(f"tl.tier = ${param_idx}")
            params.append(tier)
            param_idx += 1

        if is_active is not None:
            where_clauses.append(f"tl.is_active = ${param_idx}")
            params.append(is_active)
            param_idx += 1

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        rows = await conn.fetch(f"""
            SELECT tl.*, t.slug AS tenant_slug, t.name AS tenant_name
            FROM tenant_licenses tl
            JOIN tenants t ON t.id = tl.tenant_id
            {where_sql}
            ORDER BY tl.created_at DESC
        """, *params)

        licenses = []
        for row in rows:
            lic = dict(row)
            lic["id"] = str(lic["id"])
            lic["tenant_id"] = str(lic["tenant_id"])
            lic.pop("license_key", None)
            licenses.append(lic)

        return {"licenses": licenses}


@router.get("/licenses/expiring")
async def get_expiring_licenses(
    days: int = 30,
    admin: dict = Depends(require_permission("read"))
):
    """Get licenses expiring within the specified number of days."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        cutoff_date = datetime.utcnow() + timedelta(days=days)

        rows = await conn.fetch("""
            SELECT tl.*, t.slug AS tenant_slug, t.name AS tenant_name
            FROM tenant_licenses tl
            JOIN tenants t ON t.id = tl.tenant_id
            WHERE tl.is_active = true
              AND tl.expires_at IS NOT NULL
              AND tl.expires_at <= $1
              AND tl.expires_at > NOW()
            ORDER BY tl.expires_at ASC
        """, cutoff_date)

        licenses = []
        for row in rows:
            lic = dict(row)
            lic["id"] = str(lic["id"])
            lic["tenant_id"] = str(lic["tenant_id"])
            lic.pop("license_key", None)
            # Calculate days until expiration
            if lic["expires_at"]:
                delta = lic["expires_at"].replace(tzinfo=None) - datetime.utcnow()
                lic["days_remaining"] = max(0, delta.days)
            licenses.append(lic)

        return {"licenses": licenses, "count": len(licenses)}


@router.post("/licenses")
async def create_license(
    data: LicenseCreate,
    admin: dict = Depends(require_permission("manage_licenses"))
):
    """Create a new license for a tenant."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Verify tenant exists
        tenant = await conn.fetchrow(
            "SELECT id, slug, settings FROM tenants WHERE id = $1",
            uuid.UUID(data.tenant_id)
        )
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Prevent changing the platform owner's license
        raw_settings = tenant["settings"]
        if isinstance(raw_settings, str):
            t_settings = json.loads(raw_settings) if raw_settings else {}
        else:
            t_settings = raw_settings or {}
        if t_settings.get("is_platform_owner"):
            raise HTTPException(status_code=403, detail="Cannot modify the platform owner's license")

        # Deactivate all existing active licenses for this tenant
        await conn.execute("""
            UPDATE tenant_licenses
            SET is_active = false, revoked_at = NOW(), revoke_reason = 'Superseded by new license'
            WHERE tenant_id = $1 AND is_active = true
        """, uuid.UUID(data.tenant_id))

        # Generate license
        license_id = uuid.uuid4()
        license_key = generate_license_key()
        expires_at = None
        if data.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=data.expires_in_days)

        await conn.execute("""
            INSERT INTO tenant_licenses
            (id, tenant_id, license_key, tier, expires_at, custom_limits, issued_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, license_id, uuid.UUID(data.tenant_id), license_key, data.tier,
            expires_at, data.custom_limits, safe_admin_uuid(admin.get("sub")))

        # Set as active license
        await conn.execute(
            "UPDATE tenants SET active_license_id = $1, plan = $2 WHERE id = $3",
            license_id, data.tier, uuid.UUID(data.tenant_id)
        )

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'create_license', 'license', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), license_id, json.dumps({
            "tenant_slug": tenant["slug"],
            "tier": data.tier,
            "expires_at": expires_at.isoformat() if expires_at else None
        }))

        logger.info(f"Platform admin {admin['email']} created {data.tier} license for {tenant['slug']}")

        return {
            "id": str(license_id),
            "tenant_id": data.tenant_id,
            "tier": data.tier,
            "expires_at": expires_at
        }


@router.patch("/licenses/{license_id}")
async def update_license(
    license_id: str,
    data: LicenseUpdate,
    admin: dict = Depends(require_permission("manage_licenses"))
):
    """Update a license (tier, expiry, limits)."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Build update
        updates = []
        params = []
        param_idx = 1

        update_fields = data.model_dump(exclude_unset=True)
        for field, value in update_fields.items():
            updates.append(f"{field} = ${param_idx}")
            params.append(value)
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(license_id))

        await conn.execute(
            f"UPDATE tenant_licenses SET {', '.join(updates)} WHERE id = ${param_idx}",
            *params
        )

        # If tier changed, update tenant plan too
        if data.tier:
            await conn.execute("""
                UPDATE tenants SET plan = $1
                WHERE active_license_id = $2
            """, data.tier, uuid.UUID(license_id))

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'update_license', 'license', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), uuid.UUID(license_id), json.dumps(update_fields))

        return {"status": "updated", "license_id": license_id}


@router.post("/licenses/{license_id}/revoke")
async def revoke_license(
    license_id: str,
    reason: str = "Administrative action",
    admin: dict = Depends(require_permission("manage_licenses"))
):
    """Revoke a license, downgrading tenant to community."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Get license and tenant info
        license_info = await conn.fetchrow("""
            SELECT tl.*, t.slug AS tenant_slug, t.settings AS tenant_settings
            FROM tenant_licenses tl
            JOIN tenants t ON t.id = tl.tenant_id
            WHERE tl.id = $1
        """, uuid.UUID(license_id))

        if not license_info:
            raise HTTPException(status_code=404, detail="License not found")

        # Prevent revoking the platform owner's license
        raw_ts = license_info["tenant_settings"]
        if isinstance(raw_ts, str):
            ts = json.loads(raw_ts) if raw_ts else {}
        else:
            ts = raw_ts or {}
        if ts.get("is_platform_owner"):
            raise HTTPException(status_code=403, detail="Cannot revoke the platform owner's license")

        # Revoke license
        await conn.execute("""
            UPDATE tenant_licenses
            SET is_active = false, revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
            WHERE id = $3
        """, safe_admin_uuid(admin.get("sub")), reason, uuid.UUID(license_id))

        # Create new community license for tenant
        new_license_id = uuid.uuid4()
        new_license_key = generate_license_key()

        await conn.execute("""
            INSERT INTO tenant_licenses (id, tenant_id, license_key, tier, issued_by)
            VALUES ($1, $2, $3, 'community', $4)
        """, new_license_id, license_info["tenant_id"], new_license_key, safe_admin_uuid(admin.get("sub")))

        # Update tenant to use new community license
        await conn.execute("""
            UPDATE tenants SET active_license_id = $1, plan = 'community'
            WHERE id = $2
        """, new_license_id, license_info["tenant_id"])

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'revoke_license', 'license', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), uuid.UUID(license_id), json.dumps({
            "tenant_slug": license_info["tenant_slug"],
            "previous_tier": license_info["tier"],
            "reason": reason
        }))

        logger.warning(
            f"Platform admin {admin['email']} revoked license for {license_info['tenant_slug']}: {reason}"
        )

        return {
            "status": "revoked",
            "previous_tier": license_info["tier"],
            "new_tier": "community"
        }


# =============================================================================
# Cross-Tenant Data Access
# =============================================================================

@router.get("/tenants/{tenant_id}/alerts")
async def get_tenant_alerts(
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
    admin: dict = Depends(require_permission("read"))
):
    """View alerts for a specific tenant (platform admin access)."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        rows = await conn.fetch("""
            SELECT id, alert_id, title, severity, status, source, created_at
            FROM alerts
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        """, uuid.UUID(tenant_id), limit, offset)

        total = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE tenant_id = $1",
            uuid.UUID(tenant_id)
        )

        return {
            "alerts": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset
        }


@router.get("/tenants/{tenant_id}/users")
async def get_tenant_users(
    tenant_id: str,
    admin: dict = Depends(require_permission("read"))
):
    """View users for a specific tenant (platform admin access)."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        rows = await conn.fetch("""
            SELECT id, username, email, role, tenant_role, created_at, last_login_at
            FROM users
            WHERE tenant_id = $1
            ORDER BY created_at
        """, uuid.UUID(tenant_id))

        return {"users": [dict(r) for r in rows]}


@router.post("/tenants/{tenant_id}/users/{username}/unlock")
async def unlock_tenant_user(
    tenant_id: str,
    username: str,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Unlock a locked user account (platform admin cross-tenant action)."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.is_platform_admin', 'true', false)")

        result = await conn.execute("""
            UPDATE users
            SET failed_login_attempts = 0, locked_until = NULL
            WHERE tenant_id = $1 AND username = $2
        """, uuid.UUID(tenant_id), username)

    if "UPDATE 0" in result:
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Platform admin unlocked account: {username} (tenant={tenant_id})")
    return {"success": True, "message": f"Account '{username}' has been unlocked"}


# =============================================================================
# Platform Analytics
# =============================================================================

@router.get("/analytics/overview")
async def get_platform_overview(
    days: int = 1,
    search: str = "",
    admin: dict = Depends(require_permission("read")),
):
    """Get platform-wide analytics overview."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        stats = await conn.fetchrow("""
            SELECT
                (SELECT COUNT(*) FROM tenants WHERE status = 'active') AS active_tenants,
                (SELECT COUNT(*) FROM tenants WHERE status = 'suspended') AS suspended_tenants,
                (SELECT COUNT(*) FROM tenants WHERE created_at > NOW() - INTERVAL '30 days') AS new_tenants_30d,
                (SELECT COUNT(*) FROM users) AS total_users,
                (SELECT COUNT(*) FROM alerts) AS total_alerts,
                (SELECT COUNT(*) FROM playbooks) AS total_playbooks,
                (SELECT COUNT(*) FROM playbook_executions) AS total_executions
        """)

        # License distribution
        license_dist = await conn.fetch("""
            SELECT tier, COUNT(*) as count
            FROM tenant_licenses
            WHERE is_active = true
            GROUP BY tier
        """)

        # Tenant activity with configurable time range and search
        search_clause = ""
        params = [days]
        if search.strip():
            search_clause = "AND (t.name ILIKE $2 OR t.slug ILIKE $2)"
            params.append(f"%{search.strip()}%")

        recent_activity = await conn.fetch(f"""
            SELECT t.slug, t.name, t.plan, COUNT(a.id) AS alert_count
            FROM tenants t
            LEFT JOIN alerts a ON a.tenant_id = t.id
                AND a.created_at > NOW() - make_interval(days => $1)
            WHERE t.status = 'active' {search_clause}
            GROUP BY t.id
            ORDER BY alert_count DESC
        """, *params)

        return {
            "stats": dict(stats),
            "license_distribution": [dict(r) for r in license_dist],
            "most_active_tenants": [dict(r) for r in recent_activity]
        }


@router.get("/analytics/token-usage")
async def get_platform_token_usage(
    days: int = 30,
    admin: dict = Depends(require_permission("read"))
):
    """Platform-wide AI token usage summary with per-tenant breakdown and daily trend."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Platform-wide totals
        totals = await conn.fetchrow("""
            SELECT
                COUNT(*) AS total_requests,
                COALESCE(SUM(total_tokens), 0) AS total_tokens,
                COALESCE(SUM(prompt_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(completion_tokens), 0) AS total_output_tokens,
                COALESCE(SUM(estimated_cost_cents), 0) AS total_cost_cents,
                COUNT(DISTINCT tenant_id) AS active_tenants
            FROM ai_token_usage
            WHERE created_at >= NOW() - make_interval(days => $1)
        """, days)

        # Per-tenant breakdown
        by_tenant = await conn.fetch("""
            SELECT
                t.id AS tenant_id, t.name, t.slug, t.plan,
                COUNT(atu.id) AS request_count,
                COALESCE(SUM(atu.total_tokens), 0) AS total_tokens,
                COALESCE(SUM(atu.estimated_cost_cents), 0) AS cost_cents
            FROM tenants t
            LEFT JOIN ai_token_usage atu ON atu.tenant_id = t.id
                AND atu.created_at >= NOW() - make_interval(days => $1)
            WHERE t.status = 'active'
            GROUP BY t.id, t.name, t.slug, t.plan
            ORDER BY total_tokens DESC
        """, days)

        # Daily trend
        daily = await conn.fetch("""
            SELECT
                DATE(created_at) AS date,
                COUNT(*) AS requests,
                COALESCE(SUM(total_tokens), 0) AS tokens,
                COALESCE(SUM(estimated_cost_cents), 0) AS cost_cents
            FROM ai_token_usage
            WHERE created_at >= NOW() - make_interval(days => $1)
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """, days)

        return {
            "summary": {
                "total_tokens": totals["total_tokens"],
                "total_input_tokens": totals["total_input_tokens"],
                "total_output_tokens": totals["total_output_tokens"],
                "total_cost_usd": round(float(totals["total_cost_cents"]) / 100, 2),
                "total_requests": totals["total_requests"],
                "active_tenants": totals["active_tenants"],
            },
            "by_tenant": [
                {
                    "tenant_id": str(r["tenant_id"]),
                    "name": r["name"],
                    "slug": r["slug"],
                    "plan": r["plan"],
                    "request_count": r["request_count"],
                    "total_tokens": r["total_tokens"],
                    "cost_usd": round(float(r["cost_cents"]) / 100, 2),
                }
                for r in by_tenant
            ],
            "daily_trend": [
                {
                    "date": r["date"].isoformat(),
                    "requests": r["requests"],
                    "tokens": r["tokens"],
                    "cost_usd": round(float(r["cost_cents"]) / 100, 2),
                }
                for r in daily
            ],
        }


@router.get("/tenants/{tenant_id}/token-usage")
async def get_tenant_token_usage(
    tenant_id: str,
    days: int = 30,
    admin: dict = Depends(require_permission("read"))
):
    """Detailed token usage for a single tenant."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    tid = uuid.UUID(tenant_id)

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Tenant info
        tenant = await conn.fetchrow(
            "SELECT id, name, slug, plan FROM tenants WHERE id = $1", tid
        )
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Monthly summaries from cache
        monthly = await conn.fetch("""
            SELECT month_start, total_tokens, total_input_tokens,
                   total_output_tokens, total_cost_cents, overage_tokens
            FROM tenant_claude_usage
            WHERE tenant_id = $1
            ORDER BY month_start DESC LIMIT 6
        """, tid)

        # Daily breakdown
        daily = await conn.fetch("""
            SELECT DATE(created_at) AS date,
                   COUNT(*) AS requests,
                   COALESCE(SUM(total_tokens), 0) AS tokens,
                   COALESCE(SUM(estimated_cost_cents), 0) AS cost_cents
            FROM ai_token_usage
            WHERE tenant_id = $1 AND created_at >= NOW() - make_interval(days => $2)
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """, tid, days)

        # By model
        by_model = await conn.fetch("""
            SELECT provider, model, COUNT(*) AS requests,
                   COALESCE(SUM(total_tokens), 0) AS tokens,
                   COALESCE(SUM(estimated_cost_cents), 0) AS cost_cents
            FROM ai_token_usage
            WHERE tenant_id = $1 AND created_at >= NOW() - make_interval(days => $2)
            GROUP BY provider, model
            ORDER BY tokens DESC LIMIT 10
        """, tid, days)

        # By request type
        by_type = await conn.fetch("""
            SELECT request_type, COUNT(*) AS requests,
                   COALESCE(SUM(total_tokens), 0) AS tokens
            FROM ai_token_usage
            WHERE tenant_id = $1 AND created_at >= NOW() - make_interval(days => $2)
            GROUP BY request_type
            ORDER BY requests DESC
        """, tid, days)

        # Recent requests
        recent = await conn.fetch("""
            SELECT request_id, provider, model, prompt_tokens, completion_tokens,
                   total_tokens, estimated_cost_cents, request_type, status,
                   response_time_ms, created_at
            FROM ai_token_usage
            WHERE tenant_id = $1
            ORDER BY created_at DESC LIMIT 20
        """, tid)

        return {
            "tenant": {
                "id": str(tenant["id"]),
                "name": tenant["name"],
                "slug": tenant["slug"],
                "plan": tenant["plan"],
            },
            "monthly_summary": [
                {
                    "month_start": r["month_start"].isoformat(),
                    "total_tokens": r["total_tokens"],
                    "total_input_tokens": r["total_input_tokens"],
                    "total_output_tokens": r["total_output_tokens"],
                    "cost_usd": round(float(r["total_cost_cents"]) / 100, 2),
                    "overage_tokens": r["overage_tokens"],
                }
                for r in monthly
            ],
            "daily_breakdown": [
                {
                    "date": r["date"].isoformat(),
                    "requests": r["requests"],
                    "tokens": r["tokens"],
                    "cost_usd": round(float(r["cost_cents"]) / 100, 2),
                }
                for r in daily
            ],
            "by_model": [
                {
                    "provider": r["provider"],
                    "model": r["model"],
                    "requests": r["requests"],
                    "tokens": r["tokens"],
                    "cost_usd": round(float(r["cost_cents"]) / 100, 2),
                }
                for r in by_model
            ],
            "by_request_type": [
                {"request_type": r["request_type"], "requests": r["requests"], "tokens": r["tokens"]}
                for r in by_type
            ],
            "recent_requests": [
                {
                    "request_id": r["request_id"],
                    "provider": r["provider"],
                    "model": r["model"],
                    "prompt_tokens": r["prompt_tokens"],
                    "completion_tokens": r["completion_tokens"],
                    "total_tokens": r["total_tokens"],
                    "cost_usd": round(float(r["estimated_cost_cents"] or 0) / 100, 4),
                    "request_type": r["request_type"],
                    "status": r["status"],
                    "response_time_ms": r["response_time_ms"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in recent
            ],
        }


# NOTE: /analytics/billing and /tenants/{id}/billing endpoints removed
# in the OSS build. They depended on services.stripe_service and the
# `stripe` python package, which are not shipped here. Operators who want
# usage telemetry should query tenant_claude_usage directly.


# =============================================================================
# Platform Admin Management
# =============================================================================

@router.post("/admins")
async def create_platform_admin(
    data: PlatformAdminCreate,
    admin: dict = Depends(require_permission("manage_tenants"))
):
    """Create a new platform admin (requires existing admin)."""
    from services.postgres_db import postgres_db
    from services.auth import validate_password_complexity

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        # Check if email exists
        existing = await conn.fetchval(
            "SELECT id FROM platform_admins WHERE email = $1",
            data.email.lower()
        )
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create admin
        admin_id = uuid.uuid4()
        password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

        await conn.execute("""
            INSERT INTO platform_admins (id, user_id, email, name, password_hash, permissions, created_by)
            VALUES ($1, $1, $2, $3, $4, $5, $6)
        """, admin_id, data.email.lower(), data.name, password_hash,
            data.permissions, safe_admin_uuid(admin.get("sub")))

        # Audit log
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, target_type, target_id, details)
            VALUES ($1, 'create_admin', 'platform_admin', $2, $3::jsonb)
        """, safe_admin_uuid(admin.get("sub")), admin_id, json.dumps({"email": data.email, "name": data.name}))

        logger.info(f"Platform admin {admin['email']} created new admin: {data.email}")

        return {
            "id": str(admin_id),
            "email": data.email,
            "name": data.name,
            "permissions": data.permissions
        }


@router.get("/audit-log")
async def get_audit_log(
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    admin: dict = Depends(require_permission("read"))
):
    """View platform admin audit log."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.pool.acquire() as conn:
        where_sql = "WHERE action = $3" if action else ""
        params = [limit, offset]
        if action:
            params.append(action)

        rows = await conn.fetch(f"""
            SELECT pal.*, pa.email AS admin_email
            FROM platform_audit_log pal
            LEFT JOIN platform_admins pa ON pa.id = pal.admin_id
            {where_sql}
            ORDER BY pal.created_at DESC
            LIMIT $1 OFFSET $2
        """, *params)

        return {"audit_log": [dict(r) for r in rows]}
