# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Admin Panel Routes - DATABASE INTEGRATED VERSION
All operations now use PostgreSQL (no more MongoDB)
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Body, Header, Response, Request
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
import bcrypt
import secrets
import logging
import os
import jwt
import json
import uuid

from services.postgres_db import postgres_db
from services.database import db
from dependencies.auth import get_current_user as auth_get_current_user
from dependencies.license_checks import enforce_user_limit
from utils.auth_tokens import (
    ACCESS_TOKEN_COOKIE,
    CSRF_COOKIE,
    build_csrf_token,
    should_use_secure_cookies,
    get_auth_token,
    get_cookie_domain,
)
from services.auth import validate_password_complexity

logger = logging.getLogger(__name__)

# JWT Configuration - no fallback, must be set
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("CRITICAL: JWT_SECRET_KEY environment variable is not set")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 12

# Account lockout configuration
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 10

# Per-IP rate limiting for login
IP_MAX_FAILED_ATTEMPTS = 10  # Higher threshold than per-user (covers multiple users)
IP_LOCKOUT_DURATION_MINUTES = 15
IP_WINDOW_MINUTES = 30  # Rolling window for counting attempts

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# ==================== MODELS ====================

class LoginRequest(BaseModel):
    username: str
    password: str
    tenant: Optional[str] = None  # Tenant slug (e.g., "acme-corp") - optional for backwards compatibility


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    tenant_id: Optional[str] = None
    tenant_name: Optional[str] = None
    license_tier: Optional[str] = None
    force_password_reset: bool = False


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class PasswordVerify(BaseModel):
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: str = "user"  # platform_owner, admin, user, readonly


class UserResponse(BaseModel):
    username: str
    email: str
    full_name: Optional[str]
    role: str
    disabled: bool
    created_at: datetime
    last_login: Optional[datetime]


class APIKeyCreate(BaseModel):
    name: str
    role: str = "user"
    expires_days: Optional[int] = 365


class APIKeyResponse(BaseModel):
    key_id: str
    name: str
    role: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    enabled: bool


# ==================== HELPER FUNCTIONS ====================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_api_key_value() -> str:
    """Generate a random API key"""
    return f"T1 Agentics_{secrets.token_urlsafe(32)}"


def create_jwt_token(username: str, role: str, tenant_id: Optional[str] = None) -> str:
    """Create JWT token with configurable expiration and tenant context"""
    payload = {
        "sub": username,
        "role": role,
        "jti": secrets.token_hex(16),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    # Include tenant_id for multi-tenant isolation
    if tenant_id:
        payload["tenant_id"] = str(tenant_id)
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Optional[Dict]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None


async def get_current_user_from_token(token: str) -> Optional[Dict]:
    """Get user from JWT token using PostgreSQL"""
    payload = decode_jwt_token(token)
    if not payload:
        return None

    username = payload.get("sub")
    if not username:
        return None

    try:
        user = await postgres_db.get_user_by_username(username)
        if user:
            logger.debug(f"Token auth successful for user: {username}")
            return user
        else:
            logger.warning(f"Token valid but user not found in DB: {username}")
            return None
    except Exception as e:
        logger.error(f"Database error getting user: {e}")
        return None


async def get_current_username(request: Request, authorization: str = Header(None)) -> str:
    """
    Extract and validate username from JWT token in Authorization header.
    Returns username if valid, raises HTTPException if not.
    """
    token, _source = get_auth_token(request, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await get_current_user_from_token(token)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user["username"]


async def require_admin(request: Request, authorization: str = Header(None)) -> str:
    """
    Require admin role for endpoint access.
    Returns username if admin, raises HTTPException if not.
    """
    token, _source = get_auth_token(request, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await get_current_user_from_token(token)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    if user.get("role") not in ("admin", "platform_owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

    return user["username"]


# ==================== IP LOCKOUT HELPERS ====================

async def check_ip_lockout(client_ip: str):
    """Check if an IP is locked out from too many failed login attempts."""
    try:
        async with postgres_db.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT attempt_count, locked_until FROM login_attempts_by_ip WHERE ip_address = $1",
                client_ip
            )
            if row and row["locked_until"]:
                now = datetime.utcnow()
                lock_time = row["locked_until"].replace(tzinfo=None) if row["locked_until"].tzinfo else row["locked_until"]
                if lock_time > now:
                    remaining = int((lock_time - now).total_seconds() / 60) + 1
                    raise HTTPException(
                        status_code=429,
                        detail=f"Too many login attempts from this IP. Try again in {remaining} minute(s)"
                    )
                # Lock expired — clean up
                await conn.execute("DELETE FROM login_attempts_by_ip WHERE ip_address = $1", client_ip)
    except HTTPException:
        raise
    except Exception as e:
        # Table might not exist yet (pre-migration) — don't block login
        logger.debug(f"IP lockout check skipped: {e}")


async def record_ip_failed_attempt(client_ip: str):
    """Record a failed login attempt from an IP address."""
    try:
        async with postgres_db.pool.acquire() as conn:
            # Upsert: increment or insert
            row = await conn.fetchrow(
                "SELECT attempt_count, first_attempt_at FROM login_attempts_by_ip WHERE ip_address = $1",
                client_ip
            )
            now = datetime.utcnow()
            window_start = now - timedelta(minutes=IP_WINDOW_MINUTES)

            if row:
                first_at = row["first_attempt_at"].replace(tzinfo=None) if row["first_attempt_at"].tzinfo else row["first_attempt_at"]
                if first_at < window_start:
                    # Window expired, reset counter
                    await conn.execute(
                        "UPDATE login_attempts_by_ip SET attempt_count = 1, first_attempt_at = $1, locked_until = NULL WHERE ip_address = $2",
                        now, client_ip
                    )
                else:
                    new_count = row["attempt_count"] + 1
                    locked_until = None
                    if new_count >= IP_MAX_FAILED_ATTEMPTS:
                        locked_until = now + timedelta(minutes=IP_LOCKOUT_DURATION_MINUTES)
                        logger.warning(f"IP {client_ip} locked out after {new_count} failed attempts")
                    await conn.execute(
                        "UPDATE login_attempts_by_ip SET attempt_count = $1, locked_until = $2 WHERE ip_address = $3",
                        new_count, locked_until, client_ip
                    )
            else:
                await conn.execute(
                    "INSERT INTO login_attempts_by_ip (ip_address, attempt_count, first_attempt_at) VALUES ($1, 1, $2)",
                    client_ip, now
                )
    except Exception as e:
        logger.debug(f"IP attempt recording skipped: {e}")


async def clear_ip_attempts(client_ip: str):
    """Clear IP lockout on successful login."""
    try:
        async with postgres_db.pool.acquire() as conn:
            await conn.execute("DELETE FROM login_attempts_by_ip WHERE ip_address = $1", client_ip)
    except Exception:
        pass


# ==================== AUTH ENDPOINTS ====================

@router.post("/login")
async def login(login_data: LoginRequest, request: Request, response: Response):
    """
    Login with username and password using PostgreSQL.

    Security features:
    - Account lockout after 3 failed attempts (10 minute lockout)
    - Parameterized queries prevent SQL injection
    - Constant-time password comparison via bcrypt
    - Multi-tenant isolation via tenant slug

    The tenant can be provided:
    - In the request body as 'tenant' (slug like 'acme-corp')
    - Defaults to 'default' tenant if not specified (backwards compatible)
    """
    # SECURITY: No fallback credentials when PostgreSQL is unavailable
    # This prevents authentication bypass during database outages
    if not postgres_db.connected or postgres_db.pool is None:
        logger.error("Login failed: Database unavailable - no fallback auth permitted")
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable. Please try again later."
        )

    # Per-IP rate limiting (complement to per-user lockout)
    client_ip = request.client.host if request.client else "unknown"
    await check_ip_lockout(client_ip)

    # Resolve tenant
    tenant_id = None
    tenant_name = None
    tenant_slug = login_data.tenant or "default"

    try:
        async with postgres_db.pool.acquire() as conn:
            # Look up tenant by slug
            tenant_row = await conn.fetchrow(
                "SELECT id, name, status FROM tenants WHERE slug = $1",
                tenant_slug
            )

            if tenant_row:
                if tenant_row["status"] != "active":
                    raise HTTPException(
                        status_code=403,
                        detail=f"Tenant '{tenant_slug}' is {tenant_row['status']}. Contact support."
                    )
                tenant_id = str(tenant_row["id"])
                tenant_name = tenant_row["name"]
            elif tenant_slug != "default":
                # Tenant specified but not found
                raise HTTPException(
                    status_code=404,
                    detail=f"Tenant '{tenant_slug}' not found. Check your organization's login URL."
                )
            # If 'default' and not found, proceed without tenant (backwards compatible)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Tenant lookup failed (continuing without tenant): {e}")

    # Get user - uses parameterized query (SQL injection safe)
    # Supports login by username OR email
    if tenant_id:
        try:
            async with postgres_db.pool.acquire() as conn:
                # Bypass RLS for login — must find users across all tenants
                await conn.execute("SET app.is_platform_admin = 'true'")
                user = await conn.fetchrow(
                    """SELECT * FROM users
                       WHERE (username = $1 OR email = $1) AND tenant_id = $2""",
                    login_data.username, tenant_id
                )
                user = dict(user) if user else None
        except Exception as e:
            logger.error(f"Tenant-scoped user lookup failed: {e}")
            user = await postgres_db.get_user_by_username_or_email(login_data.username)
    else:
        user = await postgres_db.get_user_by_username_or_email(login_data.username)

    if not user:
        # Don't reveal if user exists - same error message for consistency
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # If no tenant was resolved from the slug, fall back to the user's tenant_id
    if not tenant_id and user.get("tenant_id"):
        user_tenant_id = str(user["tenant_id"])
        try:
            async with postgres_db.pool.acquire() as conn:
                t_row = await conn.fetchrow(
                    "SELECT id, name FROM tenants WHERE id = $1 AND status = 'active'",
                    user["tenant_id"]
                )
                if t_row:
                    tenant_id = str(t_row["id"])
                    tenant_name = t_row["name"]
        except Exception as e:
            logger.warning(f"User tenant lookup failed: {e}")

    if user.get("disabled", False):
        raise HTTPException(status_code=401, detail="User account is disabled")

    # Check if account is locked
    locked_until = user.get("locked_until")
    if locked_until:
        # Handle timezone-aware comparison
        now = datetime.utcnow()
        lock_time = locked_until.replace(tzinfo=None) if locked_until.tzinfo else locked_until
        if lock_time > now:
            remaining_minutes = int((lock_time - now).total_seconds() / 60) + 1
            logger.warning(f"Login attempt for locked account: {login_data.username}")
            raise HTTPException(
                status_code=401,
                detail=f"Account is locked. Try again in {remaining_minutes} minute(s)"
            )

    # Verify password
    if not verify_password(login_data.password, user["hashed_password"]):
        # Record failed attempt
        try:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                failed_attempts = (user.get("failed_login_attempts") or 0) + 1

                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    # Lock the account
                    lockout_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                    await conn.execute(
                        """UPDATE users
                           SET failed_login_attempts = $1,
                               locked_until = $2,
                               last_failed_login = $3
                           WHERE id = $4""",
                        failed_attempts, lockout_until, datetime.utcnow(), user["id"]
                    )
                    logger.warning(f"Account locked due to {failed_attempts} failed attempts: {login_data.username}")
                    raise HTTPException(
                        status_code=401,
                        detail=f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts"
                    )
                else:
                    # Just increment failed attempts
                    await conn.execute(
                        """UPDATE users
                           SET failed_login_attempts = $1,
                               last_failed_login = $2
                           WHERE id = $3""",
                        failed_attempts, datetime.utcnow(), user["id"]
                    )
                    remaining = MAX_FAILED_ATTEMPTS - failed_attempts
                    logger.info(f"Failed login attempt {failed_attempts}/{MAX_FAILED_ATTEMPTS} for: {login_data.username}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")

        # Record IP-level failed attempt
        await record_ip_failed_attempt(client_ip)

        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Successful login - reset failed attempts, clear IP lockout, update last_login
    await clear_ip_attempts(client_ip)
    try:
        async with postgres_db.pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            await conn.execute(
                """UPDATE users
                   SET last_login = $1,
                       failed_login_attempts = 0,
                       locked_until = NULL
                   WHERE id = $2""",
                datetime.utcnow(), user["id"]
            )
    except Exception as e:
        logger.warning(f"Failed to update last_login: {e}")

    # Check if MFA is enabled for this user
    if user.get("mfa_enabled"):
        # Create a short-lived MFA token (5 min) that only allows /verify-mfa
        mfa_payload = {
            "sub": user["username"],
            "user_id": str(user["id"]),
            "role": user["role"],
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "purpose": "mfa_verification",
            "jti": secrets.token_hex(16),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=5)
        }
        mfa_token = jwt.encode(mfa_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        logger.info(f"MFA required for user: {login_data.username}")
        return JSONResponse(content={
            "mfa_required": True,
            "mfa_token": mfa_token,
            "username": user["username"],
            "message": "MFA verification required. Submit your TOTP code to /api/v1/admin/verify-mfa"
        })

    # Create JWT token with tenant context
    token = create_jwt_token(user["username"], user["role"], tenant_id)
    logger.info(f"Successful login for user: {login_data.username} (tenant: {tenant_slug})")

    # Fetch license tier for the tenant
    license_tier = None
    if tenant_id:
        try:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                tier_row = await conn.fetchrow(
                    "SELECT tier FROM tenant_licenses WHERE tenant_id = $1 AND is_active = true ORDER BY created_at DESC LIMIT 1",
                    uuid.UUID(tenant_id)
                )
                if tier_row:
                    license_tier = tier_row["tier"]
        except Exception as e:
            logger.warning(f"Failed to fetch license tier: {e}")

    secure_cookie = should_use_secure_cookies()
    csrf_token = build_csrf_token()
    cookie_domain = get_cookie_domain()
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600,
        path="/",
        domain=cookie_domain,
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=False,
        secure=secure_cookie,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600,
        path="/",
        domain=cookie_domain,
    )

    return Token(
        access_token=token,
        username=user["username"],
        role=user["role"],
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        license_tier=license_tier,
        force_password_reset=user.get("force_password_reset", False)
    )


# ==================== MFA VERIFICATION ENDPOINT ====================

class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str  # 6-digit TOTP code or 8-char recovery code


@router.post("/verify-mfa")
async def verify_mfa(mfa_data: MFAVerifyRequest, response: Response):
    """
    Verify MFA TOTP code after initial password authentication.

    This endpoint is called after login returns mfa_required=true.
    It validates the temporary MFA token and the TOTP code,
    then issues the full auth cookie (same as normal login).

    This endpoint is public (no auth middleware) because the user
    only has a temporary mfa_token at this point, not a full JWT.
    """
    # Decode the MFA token
    payload = decode_jwt_token(mfa_data.mfa_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    # Verify this is an MFA-purpose token, not a regular JWT
    if payload.get("purpose") != "mfa_verification":
        raise HTTPException(status_code=401, detail="Invalid token type")

    username = payload.get("sub")
    user_id = payload.get("user_id")
    if not username or not user_id:
        raise HTTPException(status_code=401, detail="Invalid MFA token payload")

    # Verify the TOTP code
    from services.totp_service import get_totp_manager
    manager = get_totp_manager()

    is_valid = await manager.verify_code(user_id, mfa_data.code)
    if not is_valid:
        logger.warning(f"MFA verification failed for user: {username}")
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # MFA verified - issue full auth token and cookies (same as normal login)
    tenant_id = payload.get("tenant_id")
    tenant_name = payload.get("tenant_name")

    token = create_jwt_token(username, payload.get("role", "user"), tenant_id)
    logger.info(f"MFA verification successful for user: {username}")

    # Fetch license tier for the tenant
    license_tier = None
    if tenant_id:
        try:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                tier_row = await conn.fetchrow(
                    "SELECT tier FROM tenant_licenses WHERE tenant_id = $1 AND is_active = true ORDER BY created_at DESC LIMIT 1",
                    uuid.UUID(tenant_id)
                )
                if tier_row:
                    license_tier = tier_row["tier"]
        except Exception as e:
            logger.warning(f"Failed to fetch license tier: {e}")

    # Get user for force_password_reset check (uses admin bypass internally)
    user = await postgres_db.get_user_by_username(username)

    secure_cookie = should_use_secure_cookies()
    csrf_token = build_csrf_token()
    cookie_domain = get_cookie_domain()
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600,
        path="/",
        domain=cookie_domain,
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=False,
        secure=secure_cookie,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600,
        path="/",
        domain=cookie_domain,
    )

    return Token(
        access_token=token,
        username=username,
        role=payload.get("role", "user"),
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        license_tier=license_tier,
        force_password_reset=user.get("force_password_reset", False) if user else False
    )


@router.get("/me/tenant")
async def get_current_tenant_info(current_user: dict = Depends(auth_get_current_user)):
    """
    Get current tenant info for authenticated user.

    Returns tenant info including is_platform_owner flag for UI visibility control.
    Requires authentication.
    """
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Service unavailable")

    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant associated with user")

    try:
        async with postgres_db.pool.acquire() as conn:
            tenant = await conn.fetchrow(
                """SELECT slug, name, status, settings
                   FROM tenants
                   WHERE id = $1""",
                tenant_id
            )

            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")

            # Parse settings - may be JSON string or dict
            raw_settings = tenant["settings"]
            if isinstance(raw_settings, str):
                settings = json.loads(raw_settings) if raw_settings else {}
            else:
                settings = raw_settings or {}

            return {
                "slug": tenant["slug"],
                "name": tenant["name"],
                "status": tenant["status"],
                "is_platform_owner": settings.get("is_platform_owner", False)
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching current tenant: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch tenant info")


@router.get("/tenant/{slug}")
async def get_tenant_info(slug: str):
    """
    Get tenant info by slug for login page customization.

    This is a public endpoint - only returns non-sensitive info.
    Used by frontend to show tenant name/branding on login page.

    Supports flexible matching:
    - Exact slug match
    - Slug without hyphens (t1agentics -> t1-agentics)
    - Case-insensitive name match
    """
    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Service unavailable")

    try:
        async with postgres_db.pool.acquire() as conn:
            # Normalize the search term
            normalized_slug = slug.lower().strip()

            # Try multiple matching strategies
            tenant = await conn.fetchrow(
                """SELECT slug, name, status, settings
                   FROM tenants
                   WHERE slug = $1
                      OR REPLACE(slug, '-', '') = REPLACE($1, '-', '')
                      OR LOWER(name) = $1
                   LIMIT 1""",
                normalized_slug
            )

            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")

            if tenant["status"] != "active":
                raise HTTPException(
                    status_code=403,
                    detail=f"This organization is currently {tenant['status']}"
                )

            # Parse settings - may be JSON string or dict
            raw_settings = tenant["settings"]
            if isinstance(raw_settings, str):
                settings = json.loads(raw_settings) if raw_settings else {}
            else:
                settings = raw_settings or {}

            return {
                "slug": tenant["slug"],
                "name": tenant["name"],
                "branding": {
                    "logo_url": settings.get("logo_url"),
                    "primary_color": settings.get("primary_color"),
                    "welcome_message": settings.get("welcome_message")
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching tenant: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch tenant info")


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Clear auth cookies and revoke the current JWT token."""
    from services.token_blacklist import get_token_blacklist
    import time

    # Try to get the current token and blacklist it
    token, _source = get_auth_token(request, request.headers.get("Authorization"))
    if token:
        try:
            payload = decode_jwt_token(token)
            if payload:
                blacklist = get_token_blacklist()
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp:
                    # Convert exp to timestamp if it's a datetime
                    if isinstance(exp, datetime):
                        exp_ts = exp.timestamp()
                    else:
                        exp_ts = float(exp)
                    await blacklist.revoke_async(jti, exp_ts, reason="logout")
        except Exception as e:
            logger.warning(f"Failed to blacklist token during logout: {e}")

    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/", domain=get_cookie_domain())
    response.delete_cookie(CSRF_COOKIE, path="/", domain=get_cookie_domain())
    return {"status": "ok"}


@router.post("/logout-all")
async def logout_all(request: Request, response: Response):
    """
    Revoke all sessions for the current user (logout all devices).
    Clears auth cookies for the current session.
    """
    from services.token_blacklist import get_token_blacklist
    import time

    token, _source = get_auth_token(request, request.headers.get("Authorization"))
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    blacklist = get_token_blacklist()
    # Revoke all tokens issued before now (persisted to database)
    await blacklist.revoke_all_for_user_async(username, time.time(), reason="logout_all")

    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/", domain=get_cookie_domain())
    response.delete_cookie(CSRF_COOKIE, path="/", domain=get_cookie_domain())

    logger.info(f"All sessions revoked for user: {username}")
    return {"status": "ok", "message": "All sessions have been revoked"}


# ==================== USER MANAGEMENT ====================

@router.get("/users", response_model=List[UserResponse])
async def list_users(username: str = Depends(require_admin)):
    """List all users. ADMIN ONLY."""
    try:
        users = await db.get_all_users()
        
        # Ensure all required fields exist with defaults
        user_responses = []
        for user in users:
            # Add missing fields with defaults
            if "created_at" not in user:
                user["created_at"] = datetime.utcnow()
            if "last_login" not in user:
                user["last_login"] = None
            if "full_name" not in user:
                user["full_name"] = None
            if "disabled" not in user:
                user["disabled"] = False
            
            # Remove internal fields before validation
            user.pop("_id", None)  # Legacy field from MongoDB migration
            user.pop("permissions", None)  # Not in response model
            
            try:
                user_responses.append(UserResponse(**user))
            except Exception as e:
                logger.error(f"Error serializing user {user.get('username')}: {e}")
                continue
        
        return user_responses
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load users: {str(e)}")


async def _send_account_created_email(
    email: str,
    username: str,
    tenant_name: str,
    login_url: str,
    created_by: str,
):
    """Send account-created welcome email. Runs as a BackgroundTask."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_account_created_email

        html = render_account_created_email(username, email, tenant_name, login_url, created_by)
        svc = get_email_service()
        await svc.send_email([email], f"Your T1 Agentics Account - {tenant_name}", html)
        logger.info("Account-created email sent to %s (workspace: %s)", email, tenant_name)
    except Exception as exc:
        logger.error("Failed to send account-created email to %s: %s", email, exc)


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    admin_user: str = Depends(require_admin),
    _limit: None = Depends(enforce_user_limit),
):
    """Create a new user. ADMIN ONLY. Enforces per-tier user limit."""
    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(user_data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Check if user exists
    existing = await db.get_user(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = await db.get_user_by_email(user_data.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    # Create user
    new_user = {
        "username": user_data.username,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "role": user_data.role,
        "hashed_password": hash_password(user_data.password),
        "disabled": False,
        "permissions": []  # Set based on role
    }

    try:
        created_user = await db.create_user(new_user)

        # Send welcome email in background (non-blocking)
        try:
            from middleware.tenant_middleware import get_current_tenant
            tenant = get_current_tenant()
            tenant_name = tenant.get("name", "T1 Agentics")
            tenant_slug = tenant.get("slug", "")
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            login_url = f"{frontend_url}/login?tenant={tenant_slug}" if tenant_slug else f"{frontend_url}/login"

            background_tasks.add_task(
                _send_account_created_email,
                user_data.email,
                user_data.username,
                tenant_name,
                login_url,
                admin_user,
            )
        except Exception as email_err:
            logger.warning("Could not queue welcome email: %s", email_err)

        return UserResponse(**created_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")


@router.put("/users/{username}")
async def update_user(username: str, update_data: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """Update user. ADMIN ONLY."""
    existing = await db.get_user(username)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow updating password this way without complexity check
    if "password" in update_data:
        is_valid, error_msg = validate_password_complexity(update_data["password"])
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        update_data["hashed_password"] = hash_password(update_data.pop("password"))
    
    success = await db.update_user(username, update_data)
    if success:
        return {"message": "User updated successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to update user")


@router.delete("/users/{username}")
async def delete_user(username: str, admin_user: str = Depends(require_admin)):
    """Delete user. ADMIN ONLY."""
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin user")

    success = await db.delete_user(username)
    if success:
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")


@router.get("/limits")
async def get_tenant_limits_endpoint(
    request: Request,
    _user: str = Depends(require_admin),
):
    """Get the current tenant's license limits and usage. ADMIN ONLY."""
    from dependencies.license_checks import get_tenant_limits
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    limits = await get_tenant_limits(str(tenant_id))

    # Add current usage counts
    try:
        user_count = await postgres_db.pool.fetchval(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1::uuid AND disabled = false", str(tenant_id)
        )
        integration_count = await postgres_db.pool.fetchval(
            "SELECT COUNT(*) FROM connect_instances WHERE tenant_id = $1 AND enabled = true", str(tenant_id)
        )
        limits["usage"] = {
            "users": user_count or 0,
            "integrations": integration_count or 0,
        }
    except Exception as e:
        logger.warning(f"Failed to fetch usage counts: {e}")
        limits["usage"] = {}

    return limits


@router.post("/users/{username}/reset-password")
async def reset_user_password(username: str, password_data: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """Reset a user's password. ADMIN ONLY."""
    existing = await db.get_user(username)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_password = password_data.get("new_password")
    if not new_password:
        raise HTTPException(status_code=400, detail="New password is required")

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    hashed = hash_password(new_password)
    success = await db.update_user(username, {"hashed_password": hashed})
    
    if success:
        # Log the action
        await db.log_audit(
            action=f"Password reset for user: {username}",
            user="admin",
            details={"target_user": username}
        )
        return {"message": "Password reset successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to reset password")


@router.post("/users/{username}/unlock")
async def unlock_user_account(username: str, authorization: str = Header(None)):
    """
    Unlock a locked user account (admin action).
    Resets failed login attempts and clears the lockout.
    """
    await require_admin(authorization)

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                """UPDATE users
                   SET failed_login_attempts = 0,
                       locked_until = NULL
                   WHERE username = $1""",
                username
            )

        if "UPDATE 0" in result:
            raise HTTPException(status_code=404, detail="User not found")

        logger.info(f"Account unlocked by admin: {username}")
        return {"success": True, "message": f"Account '{username}' has been unlocked"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unlock account: {e}")
        raise HTTPException(status_code=500, detail="Failed to unlock account")


@router.get("/users/{username}/lockout-status")
async def get_user_lockout_status(username: str, authorization: str = Header(None)):
    """Get the lockout status of a user account"""
    await require_admin(authorization)

    user = await postgres_db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    locked_until = user.get("locked_until")
    is_locked = False
    remaining_minutes = 0

    if locked_until:
        now = datetime.utcnow()
        lock_time = locked_until.replace(tzinfo=None) if locked_until.tzinfo else locked_until
        if lock_time > now:
            is_locked = True
            remaining_minutes = int((lock_time - now).total_seconds() / 60) + 1

    return {
        "username": username,
        "is_locked": is_locked,
        "failed_attempts": user.get("failed_login_attempts", 0),
        "max_attempts": MAX_FAILED_ATTEMPTS,
        "locked_until": locked_until.isoformat() if locked_until and is_locked else None,
        "remaining_minutes": remaining_minutes if is_locked else 0,
        "last_failed_login": user.get("last_failed_login").isoformat() if user.get("last_failed_login") else None
    }


# ==================== API KEY MANAGEMENT ====================

@router.post("/api-keys")
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: dict = Depends(auth_get_current_user)
):
    """Create a new API key"""
    key_id = f"key_{secrets.token_hex(8)}"
    api_key = create_api_key_value()

    new_key = {
        "key_id": key_id,
        "api_key": api_key,
        "name": key_data.name,
        "role": key_data.role,
        "created_by": current_user.get('username', 'system'),
        "expires_at": datetime.utcnow() + timedelta(days=key_data.expires_days) if key_data.expires_days else None,
        "last_used": None,
        "enabled": True
    }
    
    try:
        created_key = await db.create_api_key(new_key)
        # Return the actual API key only once
        return {
            "key_id": key_id,
            "api_key": api_key,  # Only returned on creation!
            "name": key_data.name,
            "role": key_data.role,
            "created_at": created_key["created_at"],
            "expires_at": new_key["expires_at"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating API key: {str(e)}")


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(admin_user: str = Depends(require_admin)):
    """List all API keys (without showing the actual keys). ADMIN ONLY."""
    keys = await db.get_all_api_keys()
    return [APIKeyResponse(**{**key, "api_key": None}) for key in keys]


@router.delete("/api-keys/{key_id}")
async def delete_api_key(key_id: str, admin_user: str = Depends(require_admin)):
    """Delete an API key. ADMIN ONLY."""
    success = await db.delete_api_key(key_id)
    if success:
        return {"message": "API key deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="API key not found")


@router.put("/api-keys/{key_id}/toggle")
async def toggle_api_key(key_id: str, admin_user: str = Depends(require_admin)):
    """Enable/disable an API key. ADMIN ONLY."""
    key = await db.get_api_key_by_id(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    new_state = not key.get("enabled", True)
    success = await db.update_api_key(key_id, {"enabled": new_state})
    
    if success:
        return {"message": f"API key {'enabled' if new_state else 'disabled'}", "enabled": new_state}
    else:
        raise HTTPException(status_code=500, detail="Failed to update API key")


# ==================== IOC TRACKING ====================

@router.post("/ioc/track")
async def track_ioc(ioc_data: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """Track an IOC. ADMIN ONLY."""
    required_fields = ["ioc_value", "ioc_type"]
    for field in required_fields:
        if field not in ioc_data:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
    
    success = await db.track_ioc(ioc_data)
    if success:
        return {"message": "IOC tracked successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to track IOC")


@router.get("/ioc/track/{ioc_value}")
async def get_tracked_ioc(ioc_value: str, ioc_type: Optional[str] = None, admin_user: str = Depends(require_admin)):
    """Get tracked IOC details. ADMIN ONLY."""
    ioc = await db.get_tracked_ioc(ioc_value, ioc_type)
    if ioc:
        return ioc
    else:
        raise HTTPException(status_code=404, detail="IOC not found")


@router.get("/ioc/track")
async def list_tracked_iocs(ioc_type: Optional[str] = None, limit: int = 100, admin_user: str = Depends(require_admin)):
    """List all tracked IOCs. ADMIN ONLY."""
    iocs = await db.get_all_tracked_iocs(ioc_type, limit)
    return iocs


# ==================== INTEGRATIONS ====================

@router.post("/integrations/custom")
async def create_integration(integration_data: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """Create a custom integration. ADMIN ONLY."""
    if "name" not in integration_data:
        raise HTTPException(status_code=400, detail="Integration name is required")
    
    success = await db.create_integration(integration_data)
    if success:
        return {"message": "Integration created successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to create integration")


@router.get("/integrations/custom")
async def list_integrations(admin_user: str = Depends(require_admin)):
    """List all custom integrations. ADMIN ONLY."""
    integrations = await db.get_all_integrations()
    return integrations


@router.put("/integrations/custom/{name}")
async def update_integration(name: str, update_data: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """Update an integration. ADMIN ONLY."""
    success = await db.update_integration(name, update_data)
    if success:
        return {"message": "Integration updated successfully"}
    else:
        raise HTTPException(status_code=404, detail="Integration not found")


@router.delete("/integrations/custom/{name}")
async def delete_integration(name: str, admin_user: str = Depends(require_admin)):
    """Delete an integration. ADMIN ONLY."""
    success = await db.delete_integration(name)
    if success:
        return {"message": "Integration deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Integration not found")


# ==================== STATISTICS ====================

@router.get("/stats")
async def get_admin_stats(admin_user: str = Depends(require_admin)):
    """Get comprehensive admin statistics. ADMIN ONLY."""
    stats = await db.get_database_stats()
    ioc_stats = await db.get_ioc_statistics()
    
    return {
        "database": stats,
        "iocs": ioc_stats,
        "timestamp": datetime.utcnow().isoformat()
    }


# ==================== PYTHON SCRIPTS ====================

class ScriptCreate(BaseModel):
    name: str
    description: Optional[str] = None
    code: str
    language: str = "python"
    created_by: str


class ScriptResponse(BaseModel):
    script_id: str
    name: str
    description: Optional[str]
    code: str
    language: str
    created_by: str
    created_at: datetime
    updated_at: datetime  # Changed from last_modified to match database


@router.get("/scripts", response_model=List[ScriptResponse])
async def get_all_scripts(admin_user: str = Depends(require_admin)):
    """Get all saved Python scripts. ADMIN ONLY."""
    scripts = await db.get_all_scripts()
    return scripts


@router.get("/scripts/{script_id}", response_model=ScriptResponse)
async def get_script(script_id: str, admin_user: str = Depends(require_admin)):
    """Get a specific script by ID. ADMIN ONLY."""
    script = await db.get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    return script


@router.post("/scripts", response_model=ScriptResponse)
async def create_script(script_data: ScriptCreate, admin_user: str = Depends(require_admin)):
    """Create a new Python script. ADMIN ONLY."""
    try:
        script = await db.save_script(script_data.dict())
        return script
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save script: {str(e)}")


@router.delete("/scripts/{script_id}")
async def delete_script(script_id: str, admin_user: str = Depends(require_admin)):
    """Delete a Python script. ADMIN ONLY."""
    success = await db.delete_script(script_id)
    if success:
        return {"message": "Script deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Script not found")


# ==================== PASSWORD RESET ====================

@router.post("/password-reset/request")
async def request_password_reset(request: PasswordResetRequest):
    """Request a password reset - generates token and stores in DB"""
    user = await db.get_user_by_email(request.email)
    if not user:
        # Don't reveal if email exists or not for security
        return {"message": "If the email exists, a reset link has been sent"}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
    
    # Store reset token in database
    reset_data = {
        "token": reset_token,
        "username": user["username"],
        "email": user["email"],
        "expiry": expiry,
        "used": False,
        "created_at": datetime.utcnow()
    }
    
    await db.create_password_reset_token(reset_data)

    # Send email with reset link via email service
    try:
        from services.email_service import get_email_service
        email_service = get_email_service()
        base_url = os.environ.get("PUBLIC_URL", "https://t1agentics.ai")
        reset_link = f"{base_url}/reset-password?token={reset_token}"
        body_text = f"Click the link to reset your password: {reset_link}\n\nThis link expires in 1 hour."
        body_html = (
            f"<p>You requested a password reset for your T1 Agentics account.</p>"
            f"<p><a href=\"{reset_link}\">Click here to reset your password</a></p>"
            f"<p>Or copy this link: {reset_link}</p>"
            f"<p>This link expires in 1 hour.</p>"
        )
        await email_service.send_email(
            to=[user["email"]],
            subject="Password Reset Request - T1 Agentics",
            body_html=body_html,
            body_text=body_text
        )
    except Exception as e:
        logger.warning(f"Failed to send password reset email: {e}")

    # Security: Never reveal if user exists or return tokens in response
    return {
        "message": "If the email exists, a reset link has been sent"
    }


@router.get("/password-reset/verify")
async def verify_password_reset_token(token: str):
    """Check whether a reset token is currently valid (exists, unused, unexpired).

    Called by the frontend on mount so the reset page can show a clear
    "expired" / "already used" / "invalid" message instead of rendering the
    form when the link is no longer good.

    Intentionally does NOT reveal which user the token belongs to.
    """
    if not token:
        return {"valid": False, "reason": "invalid"}

    token_data = await db.get_password_reset_token(token)
    if not token_data:
        return {"valid": False, "reason": "invalid"}
    if token_data.get("used"):
        return {"valid": False, "reason": "used"}
    if datetime.utcnow() > token_data["expiry"]:
        return {"valid": False, "reason": "expired"}
    return {"valid": True}


@router.post("/password-reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset with token and set new password.

    The users table has RLS enabled (migration 045); this endpoint runs
    unauthenticated, so the UPDATE must be performed with platform-admin
    mode set on the connection or it silently affects 0 rows.
    """
    # Validate token
    token_data = await db.get_password_reset_token(request.token)

    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    if token_data["used"]:
        raise HTTPException(status_code=400, detail="Reset token has already been used")

    if datetime.utcnow() > token_data["expiry"]:
        raise HTTPException(status_code=400, detail="Reset token has expired")

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Hash new password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(request.new_password.encode('utf-8'), salt).decode('utf-8')

    # Update user password under platform-admin mode. The users table has
    # tenant RLS (migration 045); this endpoint runs unauthenticated so a
    # plain UPDATE silently affects 0 rows. set_platform_admin_mode(True)
    # tells TenantAwarePool to set app.is_platform_admin on the connection,
    # which the RLS policy honors.
    from services.postgres_db import postgres_db, set_platform_admin_mode

    if not postgres_db.connected:
        logger.error("Password reset: postgres_db not connected")
        raise HTTPException(status_code=503, detail="Database not connected")

    set_platform_admin_mode(True)
    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "UPDATE users SET hashed_password = $1, "
                "failed_login_attempts = 0, locked_until = NULL "
                "WHERE username = $2",
                hashed,
                token_data["username"],
            )
        # asyncpg returns "UPDATE N"
        try:
            rows_updated = int(result.split()[-1])
        except Exception:
            rows_updated = 0
    finally:
        set_platform_admin_mode(False)

    if rows_updated < 1:
        logger.error(
            "Password reset for username=%s affected 0 rows — user may have been "
            "deleted or RLS bypass failed",
            token_data["username"],
        )
        raise HTTPException(status_code=500, detail="Failed to update password")

    # Mark token as used (only after the password actually changed)
    await db.mark_password_reset_token_used(request.token)

    # Send confirmation email so the user knows the change took effect.
    # Deliberately silent on failure — the password was reset; email is a
    # best-effort notice, not a gate.
    try:
        from services.email_service import get_email_service
        email_service = get_email_service()
        base_url = os.environ.get("PUBLIC_URL", "https://t1agentics.ai")
        login_link = f"{base_url}/login"
        body_text = (
            f"Your T1 Agentics password was just changed.\n\n"
            f"If this was you, you can sign in here: {login_link}\n\n"
            f"If this was NOT you, please contact support immediately at "
            f"support@t1agentics.ai — your account may be compromised."
        )
        body_html = (
            f"<p>Your T1 Agentics password was just changed.</p>"
            f"<p>If this was you, you can <a href=\"{login_link}\">sign in here</a>.</p>"
            f"<p>If this was <strong>NOT</strong> you, please contact "
            f"<a href=\"mailto:support@t1agentics.ai\">support@t1agentics.ai</a> "
            f"immediately — your account may be compromised.</p>"
        )
        await email_service.send_email(
            to=[token_data["email"]],
            subject="Your T1 Agentics password was changed",
            body_html=body_html,
            body_text=body_text,
        )
    except Exception as e:
        logger.warning(f"Password reset confirmation email failed: {e}")

    return {"message": "Password has been reset successfully"}


@router.post("/verify-password")
async def verify_password_endpoint(
    request: PasswordVerify,
    http_request: Request,
    authorization: str = Header(None)
):
    """Verify current user's password for sensitive actions (e.g. delete confirmation)"""
    token, _source = get_auth_token(http_request, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    current_user = await get_current_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if not bcrypt.checkpw(request.password.encode('utf-8'), current_user["hashed_password"].encode('utf-8')):
        raise HTTPException(status_code=403, detail="Incorrect password")

    return {"verified": True}


@router.post("/password-change")
async def change_password(
    request: PasswordChange,
    http_request: Request,
    authorization: str = Header(None)
):
    """Change password for logged-in user (requires current password)"""
    token, _source = get_auth_token(http_request, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    current_user = await get_current_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username = current_user["username"]

    # Verify current password
    if not bcrypt.checkpw(request.current_password.encode('utf-8'), current_user["hashed_password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    if request.new_password == request.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    # Hash new password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(request.new_password.encode('utf-8'), salt)

    # Update password and clear force_password_reset flag
    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE users SET hashed_password = $1, force_password_reset = false WHERE username = $2",
                hashed.decode('utf-8'), username
            )
    except Exception as e:
        logger.error(f"Failed to update password: {e}")
        raise HTTPException(status_code=500, detail="Failed to update password")

    # Log the password change
    await postgres_db.log_audit(
        username=username,
        action="password_change",
        resource_type="user",
        resource_id=username,
        details={"forced": current_user.get("force_password_reset", False)}
    )

    return {"message": "Password changed successfully"}


# ==================== CREDENTIALS ====================

class CredentialCreate(BaseModel):
    name: str
    description: Optional[str] = None
    auth_type: str  # basic, api_key, bearer
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    key_name: Optional[str] = "X-API-Key"
    key_location: Optional[str] = "header"  # header or query
    token: Optional[str] = None


class CredentialResponse(BaseModel):
    credential_id: str
    name: str
    description: Optional[str]
    auth_type: str
    username: Optional[str]
    key_name: Optional[str]
    key_location: Optional[str]
    created_by: str
    created_at: datetime
    # Note: sensitive values (password, api_key, token) not returned in response


class CredentialUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    key_name: Optional[str] = None
    key_location: Optional[str] = None
    token: Optional[str] = None


@router.get("/credentials")
async def list_credentials(admin_user: str = Depends(require_admin)):
    """List all credentials (without sensitive values). ADMIN ONLY."""
    try:
        credentials = await db.get_all_credentials()
        return credentials
    except Exception as e:
        logger.error(f"Error listing credentials: {e}")
        return []


@router.post("/credentials")
async def create_credential(
    credential: CredentialCreate,
    admin_user: str = Depends(require_admin)
):
    """Create a new credential with encrypted sensitive values. ADMIN ONLY."""
    from services.auth_helpers import encrypt_value

    credential_data = credential.dict()
    credential_data["created_by"] = admin_user or 'system'
    
    # Encrypt sensitive fields
    if credential_data.get("password"):
        credential_data["password"] = encrypt_value(credential_data["password"])
    
    if credential_data.get("api_key"):
        credential_data["api_key"] = encrypt_value(credential_data["api_key"])
    
    if credential_data.get("token"):
        credential_data["token"] = encrypt_value(credential_data["token"])
    
    result = await db.create_credential(credential_data)
    
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create credential")
    
    # Remove sensitive values from response
    result.pop("password", None)
    result.pop("api_key", None)
    result.pop("token", None)
    
    return result


@router.get("/credentials/{credential_id}", response_model=CredentialResponse)
async def get_credential(credential_id: str, admin_user: str = Depends(require_admin)):
    """Get a specific credential (without sensitive values). ADMIN ONLY."""
    credential = await db.get_credential(credential_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    # Remove sensitive values
    credential.pop("password", None)
    credential.pop("api_key", None)
    credential.pop("token", None)
    
    return credential


@router.put("/credentials/{credential_id}")
async def update_credential(credential_id: str, updates: CredentialUpdate, admin_user: str = Depends(require_admin)):
    """Update a credential. ADMIN ONLY."""
    from services.auth_helpers import encrypt_value
    
    update_data = {k: v for k, v in updates.dict().items() if v is not None}
    
    # Encrypt sensitive fields if provided
    if "password" in update_data and update_data["password"]:
        update_data["password"] = encrypt_value(update_data["password"])
    
    if "api_key" in update_data and update_data["api_key"]:
        update_data["api_key"] = encrypt_value(update_data["api_key"])
    
    if "token" in update_data and update_data["token"]:
        update_data["token"] = encrypt_value(update_data["token"])
    
    success = await db.update_credential(credential_id, update_data)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return {"message": "Credential updated successfully"}


@router.delete("/credentials/{credential_id}")
async def delete_credential(credential_id: str, admin_user: str = Depends(require_admin)):
    """Delete a credential. ADMIN ONLY."""
    success = await db.delete_credential(credential_id)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return {"message": "Credential deleted successfully"}


# ==================== WEBHOOKS ====================

class WebhookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True


class WebhookResponse(BaseModel):
    name: str
    description: Optional[str]
    endpoint_path: str
    enabled: bool
    created_by: Optional[str]
    created_at: datetime
    last_triggered: Optional[datetime]
    trigger_count: int


@router.get("/webhooks")
async def list_webhooks(admin_user: str = Depends(require_admin)):
    """List all webhooks. ADMIN ONLY."""
    try:
        webhooks = await db.get_all_webhooks()
        return webhooks
    except Exception as e:
        logger.error(f"Error listing webhooks: {e}")
        return []


@router.post("/webhooks")
async def create_webhook(
    webhook: WebhookCreate,
    admin_user: str = Depends(require_admin)
):
    """Create a new webhook endpoint with HEC token. ADMIN ONLY."""
    import secrets as sec
    
    # Generate HEC token
    hec_token = f"hec_{sec.token_urlsafe(32)}"
    
    # Generate endpoint path from name
    endpoint_path = f"/api/v1/webhooks/ingest/{webhook.name}"
    
    webhook_data = {
        "name": webhook.name,
        "description": webhook.description,
        "endpoint_path": endpoint_path,
        "enabled": webhook.enabled,
        "created_by": admin_user or "admin",
        "trigger_count": 0,
        # Persist under the column name database.create_webhook actually reads;
        # previously stored as "hec_token" and silently dropped on INSERT, which
        # left the token column NULL and bypassed inbound auth entirely.
        "token": hec_token
    }
    
    try:
        result = await db.create_webhook(webhook_data)
        
        # Also create a credential entry for the HEC token
        credential_data = {
            "name": f"webhook-{webhook.name}-token",
            "description": f"HEC token for webhook: {webhook.name}",
            "auth_type": "hec_token",
            "api_key": hec_token,
            "integration_id": webhook.name,
            "created_by": "system"
        }
        await db.create_credential(credential_data)
        
        # Return the token to the user (shown once)
        return {
            **result,
            "hec_token": hec_token,
            "message": "Webhook created. Save this HEC token - it won't be shown again!"
        }
    except Exception as e:
        logger.error(f"Error creating webhook: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/webhooks/{name}")
async def get_webhook(name: str, admin_user: str = Depends(require_admin)):
    """Get a specific webhook. ADMIN ONLY."""
    webhook = await db.get_webhook(name)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return webhook


@router.delete("/webhooks/{name}")
async def delete_webhook(name: str, admin_user: str = Depends(require_admin)):
    """Delete a webhook. ADMIN ONLY."""
    success = await db.delete_webhook(name)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"message": "Webhook deleted successfully"}


# ==================== ENHANCED INTEGRATIONS ====================

class IntegrationCreate(BaseModel):
    name: str
    description: Optional[str] = None
    endpoint_url: str
    method: str = "GET"
    enabled: bool = True
    poll_enabled: bool = False
    poll_interval_minutes: int = 60
    ioc_tracking: bool = False
    
    # Authentication
    credential_id: Optional[str] = None  # Reference to saved credential
    auth_overrides: Optional[Dict[str, Any]] = None  # Or use inline auth
    
    # POST body support
    post_body: Optional[Dict[str, Any]] = None


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    endpoint_url: Optional[str] = None
    method: Optional[str] = None
    enabled: Optional[bool] = None
    poll_enabled: Optional[bool] = None
    poll_interval_minutes: Optional[int] = None
    ioc_tracking: Optional[bool] = None
    credential_id: Optional[str] = None
    auth_overrides: Optional[Dict[str, Any]] = None
    post_body: Optional[Dict[str, Any]] = None


@router.post("/integrations/custom")
async def create_integration_enhanced(integration: IntegrationCreate, admin_user: str = Depends(require_admin)):
    """Create a custom integration with enhanced auth support. ADMIN ONLY."""
    integration_data = integration.dict()
    integration_data["created_at"] = datetime.utcnow()
    
    success = await db.create_integration(integration_data)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to create integration")
    
    return {"message": "Integration created successfully", "name": integration.name}


@router.put("/integrations/custom/{name}")
async def update_integration_enhanced(name: str, updates: IntegrationUpdate, admin_user: str = Depends(require_admin)):
    """Update an existing integration. ADMIN ONLY."""
    update_data = {k: v for k, v in updates.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    success = await db.update_integration(name, update_data)
    if not success:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    return {"message": "Integration updated successfully"}


@router.post("/integrations/test")
async def test_integration(test_request: Dict[str, Any], admin_user: str = Depends(require_admin)):
    """
    Test an integration by making a request. ADMIN ONLY.

    Request body should include:
    - endpoint_url
    - method
    - credential_id (optional)
    - auth_overrides (optional)
    - post_body (optional)
    """
    from services.auth_helpers import make_integration_request, build_auth_data
    from urllib.parse import urlparse
    import ipaddress
    import socket

    endpoint_url = test_request.get("endpoint_url")
    method = test_request.get("method", "GET")

    if not endpoint_url:
        raise HTTPException(status_code=400, detail="endpoint_url is required")

    # SSRF protection: validate URL scheme and block private/internal IPs
    try:
        parsed = urlparse(endpoint_url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed")
        if not parsed.hostname:
            raise HTTPException(status_code=400, detail="Invalid URL: no hostname")
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_multicast or resolved_ip.is_reserved:
            raise HTTPException(status_code=403, detail="Target URL resolves to a private/internal address")
    except (ValueError, socket.gaierror) as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL or DNS resolution failed: {str(e)}")
    
    # Get credential if credential_id provided
    credential = None
    if test_request.get("credential_id"):
        credential = await db.get_credential(test_request["credential_id"])
    
    # Build auth data
    auth_info = build_auth_data(test_request, credential)
    
    # Make request
    result = await make_integration_request(
        endpoint_url=endpoint_url,
        method=method,
        auth_type=auth_info["auth_type"],
        auth_data=auth_info["auth_data"],
        body=test_request.get("post_body"),
        timeout=15
    )
    
    return {
        "success": result["success"],
        "status_code": result["status_code"],
        "response_body": result["body"][:1000],  # Truncate for display
        "error": result.get("error")
    }


# ==================== IOC CORRELATIONS ====================

@router.get("/ioc/correlations")
async def get_ioc_correlations(ioc_values: str, admin_user: str = Depends(require_admin)):
    """
    Get correlation data for IOC values. ADMIN ONLY.

    Query param: ioc_values (comma-separated list)
    Example: /api/v1/admin/ioc/correlations?ioc_values=192.168.1.100,evil.com
    """
    ioc_list = [ioc.strip() for ioc in ioc_values.split(",")]
    correlations = await db.get_ioc_correlations(ioc_list)
    
    return correlations


# ==================== PYTHON PACKAGE MANAGEMENT ====================

class PackageInstall(BaseModel):
    package_name: str
    version: Optional[str] = None


_PIP_ALLOWED_PACKAGES = frozenset({
    "requests", "aiohttp", "httpx", "pyyaml", "jinja2", "python-dateutil",
    "xmltodict", "defusedxml", "paramiko", "netaddr", "dnspython", "pytz",
    "pandas", "numpy", "cryptography", "bcrypt", "pyjwt",
})

def _redact_sensitive(text: str) -> str:
    """Strip potential credentials from pip output."""
    import re
    return re.sub(r'(password|token|secret|key|auth)[=:]\S+', r'\1=***', text, flags=re.IGNORECASE)

@router.post("/python/install_package")
async def install_python_package(package: PackageInstall, admin_user: str = Depends(require_admin)):
    """
    Install an allowed Python package persistently in the backend environment. ADMIN ONLY.

    Only packages in the allowlist can be installed.
    Disabled in production environments.
    """
    import subprocess
    import sys

    if os.getenv("ENVIRONMENT", "").lower() in ("production", "prod"):
        raise HTTPException(status_code=403, detail="Runtime package management is disabled in production")

    if package.package_name.lower() not in _PIP_ALLOWED_PACKAGES:
        raise HTTPException(
            status_code=403,
            detail=f"Package '{package.package_name}' is not in the allowed list. Contact platform admin to whitelist it."
        )
    
    try:
        package_spec = package.package_name
        if package.version:
            package_spec = f"{package.package_name}=={package.version}"
        
        # Install into the current Python environment
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_spec],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"Successfully installed {package_spec}",
                "output": _redact_sensitive(result.stdout)
            }
        else:
            return {
                "success": False,
                "message": f"Failed to install {package_spec}",
                "error": _redact_sensitive(result.stderr)
            }
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Package installation timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Installation error: {str(e)}")


@router.get("/python/installed_packages")
async def list_installed_packages(admin_user: str = Depends(require_admin)):
    """List all installed Python packages. ADMIN ONLY."""
    import subprocess
    import sys
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            import json
            packages = json.loads(result.stdout)
            return {"packages": packages}
        else:
            raise HTTPException(status_code=500, detail="Failed to list packages")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing packages: {str(e)}")


@router.post("/python/uninstall_package")
async def uninstall_python_package(package: PackageInstall, admin_user: str = Depends(require_admin)):
    """Uninstall a Python package. ADMIN ONLY. Disabled in production."""
    import subprocess
    import sys

    if os.getenv("ENVIRONMENT", "").lower() in ("production", "prod"):
        raise HTTPException(status_code=403, detail="Runtime package management is disabled in production")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y", package.package_name],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"Successfully uninstalled {package.package_name}",
                "output": result.stdout
            }
        else:
            return {
                "success": False,
                "message": f"Failed to uninstall {package.package_name}",
                "error": result.stderr
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Uninstall error: {str(e)}")


# ==================== SYSTEM LOGS ====================

@router.get("/logs")
async def get_system_logs(
    limit: int = 100,
    admin_user: str = Depends(require_admin)
):
    """Get system logs. ADMIN ONLY."""
    
    try:
        logs = await postgres_db.get_system_logs(limit)
        return logs
    except Exception as e:
        logger.error(f"Error getting system logs: {e}")
        return []


# ==================== USER PREFERENCES ====================

@router.get("/preferences")
async def get_user_preferences(username: str = Depends(get_current_username)):
    """Get current user's preferences"""
    try:
        prefs = await postgres_db.get_user_preferences(username)
        return {"preferences": prefs}
    except Exception as e:
        logger.error(f"Error getting user preferences: {e}")
        return {"preferences": {}}


@router.put("/preferences")
async def save_user_preferences(
    preferences: Dict[str, Any] = Body(...),
    username: str = Depends(get_current_username)
):
    """Save user preferences"""
    try:
        success = await postgres_db.save_user_preferences(username, preferences)
        if success:
            return {"status": "saved", "preferences": preferences}
        else:
            raise HTTPException(status_code=500, detail="Failed to save preferences")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving user preferences: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/preferences")
async def update_user_preference(
    key: str = Body(...),
    value: Any = Body(...),
    username: str = Depends(get_current_username)
):
    """Update a single preference"""
    try:
        success = await postgres_db.update_user_preference(username, key, value)
        if success:
            return {"status": "updated", "key": key, "value": value}
        else:
            raise HTTPException(status_code=500, detail="Failed to update preference")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user preference: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== INTEGRATION POLLING ====================

@router.post("/integrations/{integration_id}/poll")
async def manual_poll_integration(
    integration_id: str,
    request: Request,
    username: str = Depends(get_current_username),
):
    """Manually trigger a poll for an integration"""
    try:
        scheduler = getattr(request.app.state, "scheduler", None)
        if scheduler is None:
            return {"status": "error", "message": "Scheduler not available"}
        return await scheduler.trigger_manual_poll(integration_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/integrations/{integration_id}/poll-status")
async def get_poll_status(
    integration_id: str,
    request: Request,
    username: str = Depends(get_current_username),
):
    """Get polling status for an integration"""
    try:
        scheduler = getattr(request.app.state, "scheduler", None)
        if scheduler is None:
            return {"exists": False, "message": "Scheduler not available"}
        return scheduler.get_job_status(integration_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== RBAC MANAGEMENT ====================

class IndexPermissionConfig(BaseModel):
    """Index permission configuration for a role"""
    index_name: str
    can_read: bool = True
    can_write: bool = False
    can_delete: bool = False
    can_admin: bool = False
    allowed_fields: Optional[List[str]] = None  # NULL = all fields
    denied_fields: Optional[List[str]] = None   # Fields to hide


class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: List[str] = []
    # Index permissions - if not provided, uses template or defaults
    index_permissions: Optional[List[IndexPermissionConfig]] = None
    # Use a predefined template: 'full_access', 'analyst_access', 'read_only_access', 'minimal_access'
    index_permission_template: Optional[str] = None


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    index_permissions: Optional[List[IndexPermissionConfig]] = None


class RoleResponse(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str]
    permissions: List[str]
    is_system: bool = False
    created_at: Optional[datetime] = None
    index_permissions: Optional[List[Dict[str, Any]]] = None


class UserRoleUpdate(BaseModel):
    role: str


# Default permissions
DEFAULT_PERMISSIONS = [
    {"key": "tenant:read", "description": "View tenant information", "category": "Tenant"},
    {"key": "user:read", "description": "View users", "category": "Users"},
    {"key": "user:create", "description": "Create users", "category": "Users"},
    {"key": "user:update", "description": "Update users", "category": "Users"},
    {"key": "user:disable", "description": "Disable users", "category": "Users"},
    {"key": "role:read", "description": "View roles", "category": "Roles"},
    {"key": "role:create", "description": "Create roles", "category": "Roles"},
    {"key": "role:update", "description": "Update roles", "category": "Roles"},
    {"key": "role:delete", "description": "Delete roles", "category": "Roles"},
    {"key": "permission:read", "description": "View permissions", "category": "Permissions"},
    {"key": "settings:read", "description": "View settings", "category": "Settings"},
    {"key": "settings:update", "description": "Update settings", "category": "Settings"},
    {"key": "retention:read", "description": "View retention policies", "category": "Retention"},
    {"key": "retention:update", "description": "Update retention policies", "category": "Retention"},
    {"key": "audit:read", "description": "View audit logs", "category": "Audit"},
    {"key": "investigation:read", "description": "View investigations", "category": "Investigations"},
    {"key": "investigation:create", "description": "Create investigations", "category": "Investigations"},
    {"key": "investigation:update", "description": "Update investigations", "category": "Investigations"},
    {"key": "investigation:assign", "description": "Assign investigations", "category": "Investigations"},
    {"key": "investigation:close", "description": "Close investigations", "category": "Investigations"},
    {"key": "alert:read", "description": "View alerts", "category": "Alerts"},
    {"key": "alert:update", "description": "Update alerts", "category": "Alerts"},
    {"key": "alert:link", "description": "Link alerts to investigations", "category": "Alerts"},
    {"key": "note:read", "description": "View notes", "category": "Notes"},
    {"key": "note:create", "description": "Create notes", "category": "Notes"},
    {"key": "note:update", "description": "Update notes", "category": "Notes"},
    {"key": "note:delete", "description": "Delete notes", "category": "Notes"},
    {"key": "file:upload", "description": "Upload files", "category": "Files"},
    {"key": "file:read", "description": "View file metadata", "category": "Files"},
    {"key": "file:download", "description": "Download files", "category": "Files"},
    {"key": "file:delete", "description": "Delete files (admin)", "category": "Files"},
    {"key": "action:read", "description": "View action history", "category": "Actions"},
    {"key": "action:execute", "description": "Execute actions", "category": "Actions"},
    {"key": "integration:manage", "description": "Manage integrations", "category": "Integrations"},
    {"key": "job:run", "description": "Run system jobs", "category": "System"},
]

# Default roles
DEFAULT_ROLES = [
    {
        "name": "Platform Owner",
        "description": "Highest level of access - full platform control, billing, and tenant management",
        "is_system": True,
        "permissions": ["*"]
    },
    {
        "name": "Admin",
        "description": "Full administrative access to all features",
        "is_system": True,
        "permissions": ["*"]
    },
    {
        "name": "Analyst",
        "description": "Security analyst with investigation capabilities",
        "is_system": True,
        "permissions": [
            "tenant:read", "investigation:read", "investigation:create", "investigation:update",
            "alert:read", "alert:update", "alert:link", "note:read", "note:create", "note:update",
            "file:upload", "file:read", "file:download", "action:read", "action:execute"
        ]
    },
    {
        "name": "ReadOnly",
        "description": "Read-only access to investigations and alerts",
        "is_system": True,
        "permissions": [
            "tenant:read", "investigation:read", "alert:read", "note:read", "file:read", "action:read"
        ]
    },
    {
        "name": "Automation",
        "description": "Service account for automation and integrations",
        "is_system": True,
        "permissions": ["action:execute"]
    }
]

# In-memory role storage (in production, use database)
_custom_roles = []


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(username: str = Depends(require_admin)):
    """List all roles including system and custom roles"""
    try:
        # Try to get from database
        roles_data = await db.fetch_all(
            "SELECT * FROM roles ORDER BY is_system DESC, name"
        )
        if roles_data:
            return [
                RoleResponse(
                    id=str(r['id']),
                    name=r['name'],
                    description=r.get('description'),
                    permissions=r.get('permissions', []),
                    is_system=r.get('is_system', False),
                    created_at=r.get('created_at')
                )
                for r in roles_data
            ]
    except Exception as e:
        logger.warning(f"Could not fetch roles from DB: {e}")
    
    # Return defaults + custom roles
    all_roles = DEFAULT_ROLES + _custom_roles
    return [
        RoleResponse(
            name=r['name'],
            description=r.get('description'),
            permissions=r.get('permissions', []),
            is_system=r.get('is_system', False)
        )
        for r in all_roles
    ]


@router.post("/roles", response_model=RoleResponse)
async def create_role(role: RoleCreate, username: str = Depends(require_admin)):
    """Create a new custom role"""
    # Check if role name already exists
    existing_names = [r['name'].lower() for r in DEFAULT_ROLES + _custom_roles]
    if role.name.lower() in existing_names:
        raise HTTPException(status_code=400, detail="Role with this name already exists")
    
    new_role = {
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions,
        "is_system": False,
        "created_at": datetime.utcnow()
    }
    
    try:
        # Try to save to database
        result = await db.execute(
            """
            INSERT INTO roles (name, description, permissions, is_system, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            """,
            role.name, role.description, role.permissions, False, datetime.utcnow()
        )
        new_role['id'] = str(result)
    except Exception as e:
        logger.warning(f"Could not save role to DB: {e}")
        _custom_roles.append(new_role)
    
    logger.info(f"Role created: {role.name} by {username}")
    
    return RoleResponse(**new_role)


@router.put("/roles/{role_name}", response_model=RoleResponse)
async def update_role(role_name: str, role_update: RoleUpdate, username: str = Depends(require_admin)):
    """Update an existing role (system roles cannot be updated)"""
    # Check if it's a system role
    for sr in DEFAULT_ROLES:
        if sr['name'].lower() == role_name.lower():
            raise HTTPException(status_code=403, detail="System roles cannot be modified")
    
    # Find and update custom role
    for i, r in enumerate(_custom_roles):
        if r['name'].lower() == role_name.lower():
            if role_update.name:
                r['name'] = role_update.name
            if role_update.description is not None:
                r['description'] = role_update.description
            if role_update.permissions is not None:
                r['permissions'] = role_update.permissions
            
            logger.info(f"Role updated: {role_name} by {username}")
            return RoleResponse(**r)
    
    raise HTTPException(status_code=404, detail="Role not found")


@router.delete("/roles/{role_name}")
async def delete_role(role_name: str, username: str = Depends(require_admin)):
    """Delete a custom role (system roles cannot be deleted)"""
    # Check if it's a system role
    for sr in DEFAULT_ROLES:
        if sr['name'].lower() == role_name.lower():
            raise HTTPException(status_code=403, detail="System roles cannot be deleted")
    
    # Find and delete custom role
    for i, r in enumerate(_custom_roles):
        if r['name'].lower() == role_name.lower():
            _custom_roles.pop(i)
            logger.info(f"Role deleted: {role_name} by {username}")
            return {"status": "deleted", "role": role_name}
    
    raise HTTPException(status_code=404, detail="Role not found")


@router.get("/permissions")
async def list_permissions(username: str = Depends(get_current_username)):
    """List all available permissions"""
    return DEFAULT_PERMISSIONS


@router.put("/users/{target_username}/role")
async def update_user_role(
    target_username: str,
    role_update: UserRoleUpdate,
    username: str = Depends(require_admin)
):
    """Update a user's role assignment"""
    # Normalize role name: accept both display names ("Platform Owner") and DB names ("platform_owner")
    role_value = role_update.role.lower().replace(' ', '_')

    # Validate role exists (check against both display-name and normalized forms)
    valid_roles = set()
    for r in DEFAULT_ROLES + _custom_roles:
        valid_roles.add(r['name'].lower())
        valid_roles.add(r['name'].lower().replace(' ', '_'))
    if role_value not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role: {role_update.role}")

    try:
        # Update in database (store normalized underscore form)
        result = await db.execute(
            "UPDATE users SET role = $1 WHERE username = $2",
            role_value, target_username
        )
        
        logger.info(f"User {target_username} role updated to {role_value} by {username}")

        return {
            "status": "updated",
            "username": target_username,
            "role": role_value
        }
    except Exception as e:
        logger.error(f"Failed to update user role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user role")


# ==================== RATE LIMITING MANAGEMENT ====================

class WebhookRateLimitConfig(BaseModel):
    """Configuration for webhook rate limits"""
    requests_per_minute: int = 200
    requests_per_hour: int = 5000
    burst_limit: int = 50
    tier_override: Optional[str] = None  # "free", "pro", "enterprise", "unlimited"
    trusted_ips: Optional[List[str]] = None


class TrustedSourceAdd(BaseModel):
    """Add a trusted source"""
    ip: Optional[str] = None
    token: Optional[str] = None


class TokenTierSet(BaseModel):
    """Set tier for a token"""
    token: str
    tier: str  # "free", "pro", "enterprise", "unlimited"


@router.get("/rate-limits/metrics")
async def get_rate_limit_metrics(
    webhook_name: Optional[str] = None,
    username: str = Depends(require_admin)
):
    """
    Get rate limiting metrics for webhooks.

    - Without webhook_name: Returns metrics for all webhooks
    - With webhook_name: Returns metrics for specific webhook
    """
    try:
        from middleware.rate_limiter import get_webhook_metrics
        metrics = get_webhook_metrics(webhook_name)
        return {
            "status": "success",
            "metrics": metrics
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except Exception as e:
        logger.error(f"Failed to get rate limit metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rate-limits/config")
async def get_rate_limit_config(
    username: str = Depends(require_admin)
):
    """Get current rate limiting configuration"""
    try:
        from middleware.rate_limiter import get_rate_limiter_state, TIER_LIMITS
        state = get_rate_limiter_state()

        return {
            "status": "success",
            "tiers": {
                name: {
                    "requests_per_minute": limits.requests_per_minute,
                    "requests_per_hour": limits.requests_per_hour,
                    "burst_limit": limits.burst_limit
                }
                for name, limits in TIER_LIMITS.items()
            },
            "webhooks": {
                name: {
                    "requests_per_minute": config.requests_per_minute,
                    "requests_per_hour": config.requests_per_hour,
                    "burst_limit": config.burst_limit,
                    "tier_override": config.tier_override,
                    "trusted_ips": list(config.trusted_ips),
                    "enabled": config.enabled
                }
                for name, config in state.webhook_configs.items()
            },
            "trusted_ips": list(state.trusted_ips),
            "trusted_tokens_count": len(state.trusted_tokens)
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except Exception as e:
        logger.error(f"Failed to get rate limit config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/rate-limits/webhooks/{webhook_name}")
async def configure_webhook_rate_limit(
    webhook_name: str,
    config: WebhookRateLimitConfig,
    username: str = Depends(require_admin)
):
    """
    Configure rate limits for a specific webhook.

    Example:
    ```json
    {
        "requests_per_minute": 500,
        "requests_per_hour": 10000,
        "burst_limit": 100,
        "tier_override": "enterprise",
        "trusted_ips": ["10.0.0.1", "192.168.1.100"]
    }
    ```
    """
    try:
        from middleware.rate_limiter import configure_webhook_limits

        result = configure_webhook_limits(
            webhook_name=webhook_name,
            requests_per_minute=config.requests_per_minute,
            requests_per_hour=config.requests_per_hour,
            burst_limit=config.burst_limit,
            tier_override=config.tier_override,
            trusted_ips=set(config.trusted_ips) if config.trusted_ips else None
        )

        logger.info(f"Webhook '{webhook_name}' rate limits configured by {username}: {config.requests_per_minute}/min")

        return {
            "status": "configured",
            "webhook": webhook_name,
            "config": {
                "requests_per_minute": result.requests_per_minute,
                "requests_per_hour": result.requests_per_hour,
                "burst_limit": result.burst_limit,
                "tier_override": result.tier_override
            }
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to configure webhook rate limits: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rate-limits/trusted-sources")
async def add_trusted_source(
    source: TrustedSourceAdd,
    username: str = Depends(require_admin)
):
    """
    Add a trusted source that bypasses rate limiting.

    Trusted sources are useful for:
    - Internal relays/proxies
    - Known good automation systems
    - Development/testing IPs
    """
    if not source.ip and not source.token:
        raise HTTPException(status_code=400, detail="Must provide either ip or token")

    try:
        from middleware.rate_limiter import add_trusted_source as add_source
        add_source(ip=source.ip, token=source.token)

        logger.info(f"Trusted source added by {username}: ip={source.ip}, token={'***' if source.token else None}")

        return {
            "status": "added",
            "ip": source.ip,
            "token_added": bool(source.token)
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except Exception as e:
        logger.error(f"Failed to add trusted source: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rate-limits/trusted-sources")
async def remove_trusted_source(
    ip: Optional[str] = None,
    username: str = Depends(require_admin)
):
    """Remove a trusted source IP"""
    if not ip:
        raise HTTPException(status_code=400, detail="Must provide ip parameter")

    try:
        from middleware.rate_limiter import get_rate_limiter_state
        state = get_rate_limiter_state()

        if ip in state.trusted_ips:
            state.trusted_ips.discard(ip)
            logger.info(f"Trusted IP {ip} removed by {username}")
            return {"status": "removed", "ip": ip}
        else:
            raise HTTPException(status_code=404, detail=f"IP {ip} not in trusted list")
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove trusted source: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rate-limits/token-tiers")
async def set_token_tier(
    tier_config: TokenTierSet,
    username: str = Depends(require_admin)
):
    """
    Set the subscription tier for an API token.

    Tiers and their limits:
    - free: 60/min, 1000/hour, 20 burst
    - pro: 300/min, 10000/hour, 100 burst
    - enterprise: 1000/min, 50000/hour, 500 burst
    - unlimited: No rate limiting
    """
    valid_tiers = ["free", "pro", "enterprise", "unlimited"]
    if tier_config.tier not in valid_tiers:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier: {tier_config.tier}. Valid tiers: {valid_tiers}"
        )

    try:
        from middleware.rate_limiter import set_token_tier as set_tier
        set_tier(tier_config.token, tier_config.tier)

        logger.info(f"Token tier set to '{tier_config.tier}' by {username}")

        return {
            "status": "configured",
            "tier": tier_config.tier,
            "token_prefix": tier_config.token[:10] + "..."
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Rate limiting not available")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to set token tier: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CIRCUIT BREAKER ENDPOINTS ====================

@router.get("/circuit-breakers")
async def get_circuit_breaker_status(username: str = Depends(require_admin)):
    """Get status of all circuit breakers."""
    try:
        from integrations.policies.circuit_breaker import get_circuit_breaker_registry
        registry = get_circuit_breaker_registry()
        return registry.get_health_summary()
    except Exception as e:
        logger.error(f"Failed to get circuit breaker status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/circuit-breakers/{integration_id}")
async def get_circuit_breaker_by_id(
    integration_id: str,
    username: str = Depends(require_admin)
):
    """Get status of a specific circuit breaker."""
    try:
        from integrations.policies.circuit_breaker import get_circuit_breaker_registry
        registry = get_circuit_breaker_registry()
        status = registry.get_status(integration_id)
        if not status:
            raise HTTPException(status_code=404, detail=f"No circuit breaker for {integration_id}")
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get circuit breaker status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/circuit-breakers/{integration_id}/reset")
async def reset_circuit_breaker(
    integration_id: str,
    username: str = Depends(require_admin)
):
    """Manually reset a circuit breaker to closed state."""
    try:
        from integrations.policies.circuit_breaker import get_circuit_breaker_registry
        registry = get_circuit_breaker_registry()
        success = registry.reset_breaker(integration_id)

        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"No circuit breaker found for {integration_id}"
            )

        logger.info(f"Circuit breaker for {integration_id} reset by {username}")

        return {
            "status": "reset",
            "integration_id": integration_id,
            "reset_by": username
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset circuit breaker: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# TENANT AUDIT LOG
# =============================================================================

@router.get("/audit-log")
async def get_tenant_audit_log(
    action: Optional[str] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(auth_get_current_user),
):
    """
    Return audit log entries for the current tenant.
    RLS on audit_log enforces tenant scoping automatically.
    Requires audit:read permission.
    """
    from dependencies.auth import _has_permission
    role = current_user.get("role", "")
    if not _has_permission(role, "audit:read"):
        raise HTTPException(status_code=403, detail="audit:read permission required")

    try:
        conditions = []
        params: list = []
        p = 1  # param counter

        if username:
            conditions.append(f"username ILIKE ${p}")
            params.append(f"%{username}%")
            p += 1

        if action:
            conditions.append(f"action ILIKE ${p}")
            params.append(f"%{action}%")
            p += 1

        if resource_type:
            conditions.append(f"resource_type ILIKE ${p}")
            params.append(f"%{resource_type}%")
            p += 1

        if date_from:
            conditions.append(f"created_at >= ${p}::timestamptz")
            params.append(date_from)
            p += 1

        if date_to:
            conditions.append(f"created_at <= ${p}::timestamptz")
            params.append(date_to)
            p += 1

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        async with postgres_db.tenant_acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM audit_log {where_clause}", *params
            )
            rows = await conn.fetch(
                f"""
                SELECT
                    id::text,
                    username,
                    action,
                    resource_type,
                    resource_id,
                    details,
                    ip_address::text,
                    created_at
                FROM audit_log
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ${p} OFFSET ${p + 1}
                """,
                *params, limit, offset
            )

        entries = []
        for row in rows:
            entry = dict(row)
            entry["created_at"] = entry["created_at"].isoformat() if entry.get("created_at") else None
            if isinstance(entry.get("details"), str):
                try:
                    entry["details"] = json.loads(entry["details"])
                except Exception:
                    pass
            entries.append(entry)

        return {"total": total, "offset": offset, "limit": limit, "entries": entries}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch tenant audit log: {e}")
        raise HTTPException(status_code=500, detail=str(e))
