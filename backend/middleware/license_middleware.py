# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Enforcement Middleware

Validates license on every request and enforces usage limits.
Blocks requests when license is invalid or limits are exceeded.
"""

import logging
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Set

logger = logging.getLogger(__name__)

# Routes that don't require license validation
LICENSE_EXEMPT_ROUTES: Set[str] = {
    "/health",
    "/",
    "/api/v1/license",
    "/api/v1/license/activate",
    "/api/v1/license/status",
    "/api/v1/admin/login",
    "/docs",
    "/redoc",
    "/openapi.json",
}

# Routes that consume specific resources
ALERT_ROUTES = {"/api/v1/alerts", "/api/v1/webhook"}
PLAYBOOK_ROUTES = {"/api/v1/playbooks"}
INTEGRATION_ROUTES = {"/api/v1/integrations"}
AI_ROUTES = {"/api/v1/reasoning", "/api/v1/riggs"}


class LicenseMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces license requirements on all requests.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # Skip exempt routes
        if self._is_exempt(path):
            return await call_next(request)

        # Import here to avoid circular imports
        from services.license_manager import get_license_manager

        license_manager = get_license_manager()
        license_obj = license_manager.get_license()

        # Check license validity
        if not license_obj.is_valid:
            logger.warning(f"Request blocked - invalid license: {path}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "license_required",
                    "message": "Valid license required. Please activate a license to continue.",
                    "license_status": license_obj.validation_message,
                    "activate_url": "/api/v1/license/activate"
                }
            )

        # Check resource-specific limits for write operations
        if method in ("POST", "PUT", "PATCH"):
            limit_check = self._check_resource_limits(path, license_manager)
            if limit_check:
                return limit_check

        # Check feature access
        feature_check = self._check_feature_access(path, license_obj)
        if feature_check:
            return feature_check

        # Process request
        response = await call_next(request)

        # Record usage for successful write operations
        if method == "POST" and response.status_code in (200, 201):
            self._record_usage(path, license_manager)

        return response

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from license validation."""
        # Exact match
        if path in LICENSE_EXEMPT_ROUTES:
            return True

        # Prefix match for exempt routes
        for exempt in LICENSE_EXEMPT_ROUTES:
            if path.startswith(exempt):
                return True

        # Static files
        if path.startswith("/static") or path.endswith((".css", ".js", ".ico", ".png")):
            return True

        return False

    def _check_resource_limits(self, path: str, license_manager):
        """Check if resource limits allow the operation."""
        resource = None

        if any(path.startswith(r) for r in ALERT_ROUTES):
            resource = "alerts"
        elif any(path.startswith(r) for r in PLAYBOOK_ROUTES):
            resource = "playbooks"
        elif any(path.startswith(r) for r in INTEGRATION_ROUTES):
            resource = "integrations"
        elif any(path.startswith(r) for r in AI_ROUTES):
            resource = "ai_queries"

        if resource:
            allowed, message = license_manager.check_limit(resource, increment=1)
            if not allowed:
                logger.warning(f"Request blocked - limit exceeded: {resource}")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "limit_exceeded",
                        "resource": resource,
                        "message": message,
                        "upgrade_url": "/api/v1/license"
                    }
                )

        return None

    def _check_feature_access(self, path: str, license_obj):
        """Check if license includes required features."""
        required_feature = None

        # Map routes to required features
        if "/playbooks" in path and "/execute" in path:
            required_feature = "basic_playbooks"
        elif "/approval" in path:
            required_feature = "approval_workflows"
        elif "/schedule" in path:
            required_feature = "scheduled_playbooks"
        elif "/sso" in path:
            required_feature = "sso"
        elif "/audit" in path:
            required_feature = "audit_logs"
        elif "/tenant" in path:
            required_feature = "multi_tenant"

        if required_feature and required_feature not in license_obj.limits.features:
            logger.warning(f"Request blocked - feature not licensed: {required_feature}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "feature_not_licensed",
                    "feature": required_feature,
                    "message": f"Feature '{required_feature}' requires a higher license tier.",
                    "current_tier": license_obj.tier.value,
                    "upgrade_url": "/api/v1/license"
                }
            )

        return None

    def _record_usage(self, path: str, license_manager):
        """Record resource usage for successful operations."""
        if any(path.startswith(r) for r in ALERT_ROUTES):
            license_manager.record_usage("alerts")
        elif any(path.startswith(r) for r in AI_ROUTES):
            license_manager.record_usage("ai_queries")
