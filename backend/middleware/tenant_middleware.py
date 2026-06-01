# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tenant Context Middleware

Resolves tenant from request and sets context for the entire request lifecycle.
Uses ContextVar for thread-safe tenant isolation.
Enforces billing status — tenants with cancelled/expired subscriptions are blocked
from paid features and downgraded to community.
"""

import hashlib
import logging
import os

from config.constants import PLATFORM_OWNER_TENANT_ID
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Derive base domain from PUBLIC_URL for subdomain resolution
# e.g. PUBLIC_URL=https://t1agentics.ai → _BASE_DOMAIN="t1agentics.ai"
_public_url = os.getenv("PUBLIC_URL", "")
_BASE_DOMAIN = urlparse(_public_url).hostname if _public_url else None

# Thread-safe context variables for current tenant
current_tenant_id: ContextVar[Optional[str]] = ContextVar('current_tenant_id', default=None)
current_tenant: ContextVar[Optional[dict]] = ContextVar('current_tenant', default=None)

# Routes that don't require tenant context
# Routes exempt from tenant context (prefix-matched)
TENANT_EXEMPT_PREFIXES: Set[str] = {
    "/health",
    "/api/v1/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/admin/login",
    "/api/v1/admin/password-reset",  # Forgot/reset password (pre-auth flow)
    "/api/v1/admin/tenant",  # Tenant lookup for login page (public)
    "/api/v1/license",
    "/api/v1/platform",  # Platform admin routes (use different auth)
    "/api/v1/onboarding",
    "/api/v1/register",   # Self-service registration
    "/api/v1/contact",    # Enterprise contact form
    "/api/v1/public",     # Public website endpoints
    "/api/v1/billing",    # Stripe billing (uses own auth/signature verification)
    "/api/v1/affiliate/validate",  # Public: validate referral code (no auth, no tenant)
    # NOTE: /api/v1/riggs removed from exempt list — needs tenant context for
    # tenant_acquire() and RLS. Auth is handled by Depends(get_current_user).
    "/api/v1/notifications",  # Notification inbox (uses own auth via _get_inbox_user)
    "/api/v1/breach-intel",    # Platform-level breach intel shared across all tenants
    "/api/v1/webhooks/ingest",  # Webhook ingestion (resolves tenant from webhook token)
    "/api/v1/lead-drafts",      # Inbox-link approve/reject (HMAC-signed, no tenant)
    "/static",
}

# Routes that must match exactly (not prefix-matched)
TENANT_EXEMPT_EXACT: Set[str] = {
    "/",
}


def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage/lookup."""
    return hashlib.sha256(api_key.encode()).hexdigest()


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Resolves tenant context from request and sets it for the request lifecycle.

    Resolution order:
    1. JWT token (tenant_id claim)
    2. API key (lookup from api_keys table)
    3. Subdomain (acme.t1agentics.ai → acme)
    4. X-Tenant-ID header (internal services)
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt routes
        if self._is_exempt(path):
            return await call_next(request)

        # Resolve tenant from request
        tenant_id, tenant = await self._resolve_tenant(request)

        if not tenant_id:
            host = request.headers.get("Host", "")
            has_cookie = bool(request.cookies.get("t1_access_token"))
            logger.warning(
                f"Request without tenant context: {path} "
                f"(host={host}, has_cookie={has_cookie}, "
                f"base_domain={_BASE_DOMAIN})"
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "tenant_required",
                    "message": "Tenant context is required for this request"
                }
            )

        # Tenant conflict detection: if both JWT and explicit header provide
        # tenant_id, they must agree. Prevents cross-tenant request forgery.
        jwt_tenant = await self._get_jwt_tenant_id(request)
        header_tenant = request.headers.get("X-Tenant-ID")
        if jwt_tenant and header_tenant and jwt_tenant != header_tenant:
            logger.warning(
                f"Tenant conflict detected: JWT tenant={jwt_tenant}, "
                f"header tenant={header_tenant}, path={path}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "tenant_conflict",
                    "message": "Tenant ID in token does not match request header"
                }
            )

        if not tenant:
            logger.warning(f"Tenant not found: {tenant_id}")
            return JSONResponse(
                status_code=404,
                content={
                    "error": "tenant_not_found",
                    "message": "The specified tenant does not exist"
                }
            )

        # Check tenant status
        if tenant.get("status") != "active":
            logger.warning(f"Request to non-active tenant: {tenant_id} ({tenant.get('status')})")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "tenant_not_active",
                    "message": f"Tenant is {tenant.get('status')}",
                    "reason": tenant.get("suspended_reason"),
                    "support_url": "https://t1agentics.ai/support"
                }
            )

        # Enforce billing status for paid tenants
        billing_block = await self._check_billing_enforcement(tenant, tenant_id)
        if billing_block:
            return billing_block

        # Set context for this request
        token_tenant_id = current_tenant_id.set(tenant_id)
        token_tenant = current_tenant.set(tenant)

        # Also store in request.state for easy access
        request.state.tenant_id = tenant_id
        request.state.tenant = tenant

        try:
            response = await call_next(request)
            return response
        finally:
            # Reset context after request completes
            current_tenant_id.reset(token_tenant_id)
            current_tenant.reset(token_tenant)

    # T1 Agentics platform owner tenant — exempt from ALL restrictions
    OWNER_TENANT_ID = PLATFORM_OWNER_TENANT_ID

    async def _check_billing_enforcement(self, tenant: dict, tenant_id: str):
        """
        Enforce billing status for paid tenants.

        - billing_status='cancelled': Subscription ended → force downgrade to community
        - billing_status='past_due' + grace expired: Payment failed, grace period over → downgrade
        - billing_status='past_due' + grace active: Allow access with warning header

        Community and 'none' billing_status tenants are always allowed through.
        The platform owner tenant (T1 Agentics) is always exempt.
        """
        # Platform owner tenant is exempt from all billing enforcement
        if tenant_id == self.OWNER_TENANT_ID:
            return None

        plan = tenant.get("plan", "community")
        billing_status = tenant.get("billing_status", "none")

        # Community/platform tenants and normal billing → no enforcement needed
        if plan in ("community", "platform") or billing_status in ("none", "active"):
            return None

        if billing_status == "cancelled":
            # Subscription was cancelled but plan wasn't downgraded yet (missed webhook safety net)
            # Force synchronous downgrade
            await self._force_downgrade_to_community(tenant_id)
            logger.warning(
                f"Billing enforcement: tenant {tenant_id} has cancelled billing "
                f"but plan={plan}. Forced downgrade to community."
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "subscription_cancelled",
                    "message": "Your subscription has been cancelled. "
                               "Your workspace has been downgraded to the Community plan. "
                               "Please renew your subscription to restore access.",
                    "billing_status": "cancelled",
                    "upgrade_url": "/pricing",
                }
            )

        if billing_status == "past_due":
            grace_deadline = tenant.get("billing_grace_deadline")
            now = datetime.now(timezone.utc)

            if grace_deadline and now > grace_deadline:
                # Grace period expired → force downgrade
                await self._force_downgrade_to_community(tenant_id)
                logger.warning(
                    f"Billing enforcement: tenant {tenant_id} past_due "
                    f"and grace period expired. Forced downgrade."
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "payment_overdue",
                        "message": "Your payment is overdue and your grace period has expired. "
                                   "Your workspace has been downgraded to the Community plan. "
                                   "Please update your payment method to restore access.",
                        "billing_status": "past_due",
                        "upgrade_url": "/pricing",
                    }
                )
            # Grace period still active — allow through but log it
            # (Stripe will retry the payment automatically)
            return None

        return None

    async def _force_downgrade_to_community(self, tenant_id: str):
        """Force downgrade a tenant to community plan (safety net for missed webhooks)."""
        try:
            from services.postgres_db import postgres_db
            import uuid
            import secrets

            if not postgres_db.connected or postgres_db.pool is None:
                logger.error("Cannot force downgrade: database not connected")
                return

            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")

                # Deactivate all active licenses
                await conn.execute(
                    """
                    UPDATE tenant_licenses
                    SET is_active = false, revoked_at = NOW(),
                        revoke_reason = 'Billing enforcement: subscription cancelled/expired'
                    WHERE tenant_id = $1 AND is_active = true
                    """,
                    uuid.UUID(tenant_id),
                )

                # Create community license
                license_id = uuid.uuid4()
                license_key = f"T1-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
                await conn.execute(
                    """
                    INSERT INTO tenant_licenses (id, tenant_id, license_key, tier)
                    VALUES ($1, $2, $3, 'community')
                    """,
                    license_id,
                    uuid.UUID(tenant_id),
                    license_key,
                )

                # Update tenant
                await conn.execute(
                    """
                    UPDATE tenants
                    SET active_license_id = $1, plan = 'community',
                        billing_status = 'cancelled', stripe_subscription_id = NULL,
                        billing_grace_deadline = NULL
                    WHERE id = $2
                    """,
                    license_id,
                    uuid.UUID(tenant_id),
                )

                logger.info(f"Force downgraded tenant {tenant_id} to community")
        except Exception as e:
            logger.error(f"Error force-downgrading tenant {tenant_id}: {e}")

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from tenant requirement."""
        # Exact match routes
        if path in TENANT_EXEMPT_EXACT:
            return True

        # Prefix match routes
        for exempt in TENANT_EXEMPT_PREFIXES:
            if path.startswith(exempt):
                return True

        # Static files and assets
        if any(path.endswith(ext) for ext in ['.css', '.js', '.ico', '.png', '.jpg', '.svg']):
            return True

        return False

    async def _resolve_tenant(self, request: Request) -> Tuple[Optional[str], Optional[dict]]:
        """
        Resolve tenant from multiple sources in priority order.

        Returns:
            Tuple of (tenant_id, tenant_dict) or (None, None)
        """
        tenant_id = None

        # 1. From JWT claims (Authorization header or HttpOnly cookie)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            tenant_id = await self._tenant_from_jwt(auth_header[7:])

        if not tenant_id:
            cookie_token = request.cookies.get("t1_access_token")
            if cookie_token:
                tenant_id = await self._tenant_from_jwt(cookie_token)

        # 2. From API key header
        if not tenant_id:
            api_key = request.headers.get("X-API-Key")
            if api_key:
                tenant_id = await self._tenant_from_api_key(api_key)

        # 3. From subdomain
        if not tenant_id:
            host = request.headers.get("Host", "")
            tenant_id = await self._tenant_from_subdomain(host)

        # 4. From explicit header (internal services only)
        if not tenant_id:
            header_tenant = request.headers.get("X-Tenant-ID")
            if header_tenant:
                # Verify this is from a trusted internal service
                internal_key = request.headers.get("X-Internal-Key")
                if await self._verify_internal_key(internal_key):
                    tenant_id = header_tenant

        # 5. Single-node native fallback: when running without subdomains
        #    (the no-Docker localhost mode), resolve every request to the
        #    configured default tenant. Gated by NATIVE_SINGLE_TENANT so it is
        #    a no-op in the multi-tenant Docker deployment.
        if not tenant_id and os.getenv("NATIVE_SINGLE_TENANT") == "1":
            tenant_id = os.getenv("DEFAULT_TENANT_ID", "00000000-0000-0000-0000-000000000001")

        if not tenant_id:
            return None, None

        # Load full tenant details
        tenant = await self._load_tenant(tenant_id)
        return tenant_id, tenant

    async def _get_jwt_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant_id from JWT in request (without full resolution)."""
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if not token:
            token = request.cookies.get("t1_access_token")
        if token:
            return await self._tenant_from_jwt(token)
        return None

    async def _tenant_from_jwt(self, token: str) -> Optional[str]:
        """Extract tenant_id from JWT token."""
        try:
            import jwt
            from services.auth import SECRET_KEY, ALGORITHM

            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload.get("tenant_id")
        except Exception:
            return None

    async def _tenant_from_api_key(self, api_key: str) -> Optional[str]:
        """Lookup tenant from API key."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected or postgres_db.pool is None:
                return None

            key_hash = hash_api_key(api_key)

            async with postgres_db.pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT tenant_id FROM api_keys
                    WHERE key_hash = $1 AND revoked = false AND expires_at > NOW()
                """, key_hash)

                return str(row["tenant_id"]) if row else None
        except Exception as e:
            logger.error(f"Error looking up API key: {e}")
            return None

    async def _tenant_from_subdomain(self, host: str) -> Optional[str]:
        """
        Resolve tenant from subdomain.

        acme.t1agentics.ai → lookup tenant with slug 'acme'
        """
        try:
            # Skip if no base domain configured or host doesn't match
            if not host or not _BASE_DOMAIN or _BASE_DOMAIN not in host:
                return None

            subdomain = host.split(".")[0].lower()

            if subdomain in ("www", "app", "api", "admin", "dashboard"):
                return None

            from services.postgres_db import postgres_db

            if not postgres_db.connected or postgres_db.pool is None:
                return None

            async with postgres_db.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id FROM tenants WHERE slug = $1 AND status = 'active'",
                    subdomain
                )
                return str(row["id"]) if row else None
        except Exception as e:
            logger.error(f"Error resolving subdomain: {e}")
            return None

    async def _verify_internal_key(self, key: Optional[str]) -> bool:
        """Verify internal service key for X-Tenant-ID header."""
        import os
        if not key:
            return False
        expected = os.environ.get("INTERNAL_SERVICE_KEY")
        if not expected:
            return False
        return key == expected

    async def _load_tenant(self, tenant_id: str) -> Optional[dict]:
        """Load full tenant record from database."""
        try:
            import uuid as _uuid
            from services.postgres_db import postgres_db

            if not postgres_db.connected or postgres_db.pool is None:
                return None

            # Ensure we pass a proper UUID to asyncpg
            try:
                tid = _uuid.UUID(tenant_id)
            except (ValueError, AttributeError):
                return None

            async with postgres_db.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM tenants WHERE id = $1",
                    tid
                )
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error loading tenant: {e}")
            return None


# =============================================================================
# Helper Functions for Accessing Tenant Context
# =============================================================================

def get_current_tenant_id() -> str:
    """
    Get the current tenant ID.

    Raises:
        RuntimeError: If called outside of a tenant context
    """
    tenant_id = current_tenant_id.get()
    if not tenant_id:
        raise RuntimeError(
            "No tenant context available. "
            "Ensure TenantMiddleware is active and request has valid tenant credentials."
        )
    return tenant_id


def get_current_tenant() -> dict:
    """
    Get the current tenant details.

    Raises:
        RuntimeError: If called outside of a tenant context
    """
    tenant = current_tenant.get()
    if not tenant:
        raise RuntimeError(
            "No tenant context available. "
            "Ensure TenantMiddleware is active and request has valid tenant credentials."
        )
    return tenant


def get_optional_tenant_id() -> Optional[str]:
    """Get the current tenant ID, or None if not in tenant context."""
    return current_tenant_id.get()


def get_optional_tenant() -> Optional[dict]:
    """Get the current tenant, or None if not in tenant context."""
    return current_tenant.get()
