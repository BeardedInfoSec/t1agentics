# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Authentication Middleware for T1 Agentics
Enforces JWT authentication on all routes except explicit whitelist.
"""

import os
import jwt
import logging
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Set, Optional
import re
from utils.auth_tokens import get_auth_token

logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("CRITICAL: JWT_SECRET_KEY environment variable is not set. Cannot start without a secret key.")
JWT_ALGORITHM = "HS256"

# Environment detection
ENVIRONMENT = os.getenv("ENVIRONMENT", "production").lower()
IS_DEVELOPMENT = ENVIRONMENT in ("development", "dev", "test", "testing")

# Routes that don't require authentication (public endpoints)
PUBLIC_ROUTES: Set[str] = {
    # Health checks (required for load balancers/k8s)
    "/health",
    "/ready",
    "/live",
    "/health/live",
    "/health/ready",
    "/health/detailed",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/live",
    "/api/v1/health/live",
    "/api/v1/health/ready",
    "/api/v1/health/detailed",
    "/metrics",
    "/",

    # Authentication endpoints
    "/api/v1/admin/login",
    "/api/v1/auth/login",
    "/api/v1/admin/password-reset/request",
    "/api/v1/admin/password-reset/confirm",

    # MFA verification during login (uses temporary mfa_token, not full JWT)
    "/api/v1/admin/verify-mfa",

    # Platform admin routes (uses separate auth)
    "/api/v1/platform/login",

    # Test endpoints (dev only)
    "/api/v1/test/alert",

    # Reasoning Engine public endpoints
    "/api/v1/reasoning/health",
    "/api/v1/reasoning/info",

    # Self-service registration and public website endpoints
    "/api/v1/register",
    "/api/v1/contact",
    "/api/v1/public/tiers",

    # Billing public endpoints
    "/api/v1/billing/config",

    # Frontend telemetry (error reporting from ErrorBoundary, no auth needed)
    "/api/v1/telemetry/frontend-error",
}

# SECURITY: API documentation only available in development mode
# This prevents endpoint enumeration and attack surface exposure in production
if IS_DEVELOPMENT:
    PUBLIC_ROUTES.add("/docs")
    PUBLIC_ROUTES.add("/redoc")
    PUBLIC_ROUTES.add("/openapi.json")
    logger.info("Development mode: API documentation endpoints exposed")
else:
    logger.info("Production mode: API documentation endpoints hidden (require auth)")

# Route patterns that don't require authentication (regex patterns)
PUBLIC_ROUTE_PATTERNS = [
    # Tenant lookup for login page (public)
    r"^/api/v1/admin/tenant/.*$",

    # Platform admin routes (uses separate authentication via platform admin tokens)
    r"^/api/v1/platform/.*$",

    # EDR agent self-registration (agents register themselves, approval handled separately)
    r"^/api/v1/edr/agents/register$",
    r"^/api/v1/edr/agents/check/.*$",
    # EDR agent operational endpoints (use X-Agent-Token header for auth)
    r"^/api/v1/edr/agents/edr-.*/inventory$",
    r"^/api/v1/edr/agents/edr-.*/heartbeat$",
    r"^/api/v1/edr/agents/edr-.*/actions$",
    r"^/api/v1/edr/events$",
    r"^/api/v1/edr/iocs$",

    # Log collector agent endpoints (use agent tokens for auth)
    r"^/api/v1/logs/agents/self-register$",
    r"^/api/v1/logs/agents/check/.*$",
    r"^/api/v1/logs/agents/agent-.*/heartbeat$",
    r"^/api/v1/logs/ingest$",
    r"^/api/v1/logs/ingest/bulk$",

    # Webhook ingestion (uses HEC tokens for auth)
    r"^/api/v1/webhooks/ingest/.*$",

    # One-time approval links (token-based auth)
    r"^/api/v1/approvals/page/.*$",
    r"^/api/v1/approvals/use/.*$",
    r"^/api/v1/approvals/info/.*$",

    # Inbound lead-draft approve/reject from daily summary email
    # (HMAC signature in URL is the auth — verified by route handler)
    r"^/api/v1/lead-drafts/.*$",

    # Integration catalog - browsing is public (import requires auth via route dependency)
    r"^/api/v1/catalog/connectors.*$",
    r"^/api/v1/catalog/categories.*$",
    r"^/api/v1/catalog/stats.*$",
    r"^/api/v1/catalog/vendors.*$",

    # Discovery endpoints - browsing APIs is public
    r"^/api/v1/discovery/.*$",

    # Log search syntax help - documentation is public
    r"^/api/v1/logs/search/syntax-help$",

    # EDL delivery endpoints (firewalls + browser page; route handles its own auth)
    r"^/v1/lists/.*$",

    # Self-service registration endpoints
    r"^/api/v1/register/.*$",
    r"^/api/v1/public/.*$",

    # Billing public endpoints (webhook + checkout status polling)
    r"^/api/v1/billing/webhooks/.*$",
    r"^/api/v1/billing/checkout-status/.*$",

    # Affiliate referral code validation (public — called from registration page)
    r"^/api/v1/affiliate/validate/.*$",
]

# Compiled regex patterns for performance
_compiled_patterns = [re.compile(p) for p in PUBLIC_ROUTE_PATTERNS]


def is_public_route(path: str) -> bool:
    """Check if a route is public (doesn't require authentication)."""
    # Check exact matches
    if path in PUBLIC_ROUTES:
        return True

    # Check pattern matches
    for pattern in _compiled_patterns:
        if pattern.match(path):
            return True

    return False


def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        return None


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces authentication on all routes except public ones.

    Supports:
    - JWT Bearer tokens in Authorization header
    - API keys in X-API-Key header
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # Allow OPTIONS requests (CORS preflight)
        if method == "OPTIONS":
            return await call_next(request)

        # Check if route is public
        if is_public_route(path):
            return await call_next(request)

        # Get authentication credentials
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        user_info = None

        # Try JWT token (Authorization header or HttpOnly cookie)
        token, token_source = get_auth_token(request, auth_header)
        if token:
            payload = decode_jwt_token(token)
            if payload:
                # Check token blacklist for revoked tokens/sessions
                try:
                    from services.token_blacklist import get_token_blacklist
                    blacklist = get_token_blacklist()

                    jti = payload.get("jti", "")
                    if jti and blacklist.is_revoked(jti):
                        payload = None  # Treat as invalid

                    if payload:
                        username = payload.get("sub", "")
                        iat = payload.get("iat")
                        if username and iat is not None:
                            if isinstance(iat, (int, float)):
                                iat_ts = float(iat)
                            else:
                                import calendar
                                iat_ts = calendar.timegm(iat.timetuple())
                            if blacklist.is_user_revoked(username, iat_ts):
                                payload = None  # Treat as invalid
                except Exception as e:
                    logger.warning(f"Token blacklist check failed in middleware: {e}")

            if payload:
                user_info = {
                    "username": payload.get("sub"),
                    "role": payload.get("role"),
                    "auth_type": "jwt",
                    "token_source": token_source
                }

        # Try API key if JWT not provided or invalid
        if not user_info and api_key_header:
            # Validate API key against database
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    async with postgres_db.pool.acquire() as conn:
                        key_record = await conn.fetchrow(
                            """SELECT ak.*, u.username, u.role
                               FROM api_keys ak
                               JOIN users u ON ak.created_by = u.username
                               WHERE ak.key_hash = crypt($1, ak.key_hash)
                               AND ak.enabled = true
                               AND (ak.expires_at IS NULL OR ak.expires_at > NOW())""",
                            api_key_header
                        )
                        if key_record:
                            # Update last used timestamp
                            await conn.execute(
                                "UPDATE api_keys SET last_used = NOW() WHERE key_id = $1",
                                key_record['key_id']
                            )
                            user_info = {
                                "username": key_record['username'],
                                "role": key_record['role'],
                                "auth_type": "api_key",
                                "key_name": key_record.get('name')
                            }
            except Exception as e:
                logger.error(f"API key validation error: {e}")

        # If no valid authentication, return 401
        if not user_info:
            # Build CORS headers to ensure browser can read the error
            cors_headers = {}
            origin = request.headers.get("origin", "")
            if origin:
                cors_headers["Access-Control-Allow-Origin"] = origin
                cors_headers["Access-Control-Allow-Credentials"] = "true"

            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Not authenticated",
                    "message": "Please provide a valid Bearer token, API key, or session cookie"
                },
                headers=cors_headers
            )

        # Attach user info to request state for use in route handlers
        request.state.user = user_info

        # Continue processing request
        response = await call_next(request)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware for sensitive endpoints.
    Uses in-memory storage (use Redis in production for distributed systems).
    """

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}  # IP -> (count, window_start)

    # Rate-limited routes and their limits
    RATE_LIMITED_ROUTES = {
        "/api/v1/admin/login": 5,  # 5 attempts per minute
        "/api/v1/auth/login": 5,
        "/api/v1/admin/password-reset/request": 3,
        "/api/v1/alerts/ingest": 100,
        "/api/v1/webhooks/ingest": 200,
        "/api/v1/admin/credentials": 10,  # credential operations
        "/api/v1/admin/users": 10,  # user management
        "/api/v1/admin/rbac": 10,  # RBAC changes
        "/api/v1/playbooks/execute": 20,  # playbook execution
        "/api/v1/admin/pip-install": 3,  # pip install
        "/api/v1/admin/tenant": 10,  # tenant lookup - prevent enumeration
    }

    async def dispatch(self, request: Request, call_next):
        import time

        path = request.url.path
        client_ip = request.client.host if request.client else "unknown"

        # Check if this route has specific rate limits
        limit = None
        for route_prefix, route_limit in self.RATE_LIMITED_ROUTES.items():
            if path.startswith(route_prefix):
                limit = route_limit
                break

        if limit:
            current_time = time.time()
            key = f"{client_ip}:{path}"

            if key in self.request_counts:
                count, window_start = self.request_counts[key]

                # Reset window if minute has passed
                if current_time - window_start > 60:
                    self.request_counts[key] = (1, current_time)
                elif count >= limit:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": "Rate limit exceeded",
                            "message": f"Too many requests. Limit: {limit}/minute",
                            "retry_after": int(60 - (current_time - window_start))
                        }
                    )
                else:
                    self.request_counts[key] = (count + 1, window_start)
            else:
                self.request_counts[key] = (1, current_time)

            # Cleanup old entries periodically (every 100 requests)
            if len(self.request_counts) > 1000:
                self._cleanup_old_entries(current_time)

        return await call_next(request)

    def _cleanup_old_entries(self, current_time: float):
        """Remove entries older than 2 minutes."""
        keys_to_remove = [
            key for key, (_, window_start) in self.request_counts.items()
            if current_time - window_start > 120
        ]
        for key in keys_to_remove:
            del self.request_counts[key]
