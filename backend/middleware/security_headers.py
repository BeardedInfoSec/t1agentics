# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Security Headers Middleware for T1 Agentics

Implements security headers following OWASP recommendations:
- X-Content-Type-Options: Prevents MIME sniffing
- X-Frame-Options: Prevents clickjacking
- X-XSS-Protection: Legacy XSS protection (for older browsers)
- Strict-Transport-Security: Enforces HTTPS
- Content-Security-Policy: Controls resource loading
- Referrer-Policy: Controls referrer information
- Permissions-Policy: Controls browser features

References:
- OWASP Secure Headers Project
- SOC 2 Type 2 CC6.1, CC6.6
- NIST 800-53 SC-8, SC-23
"""

import os
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Configuration via environment variables:
    - ENABLE_HSTS: Enable HSTS header (default: true in production)
    - HSTS_MAX_AGE: HSTS max-age in seconds (default: 31536000 = 1 year)
    - CSP_REPORT_ONLY: Use Content-Security-Policy-Report-Only (default: false)
    """

    def __init__(self, app):
        super().__init__(app)

        # Configuration
        self.environment = os.environ.get("ENVIRONMENT", "development")
        self.is_production = self.environment.lower() == "production"

        # HSTS settings
        self.enable_hsts = os.environ.get("ENABLE_HSTS", "true").lower() == "true"
        self.hsts_max_age = int(os.environ.get("HSTS_MAX_AGE", "31536000"))

        # CSP settings
        self.csp_report_only = os.environ.get("CSP_REPORT_ONLY", "false").lower() == "true"

        logger.info(f"Security headers middleware initialized (production={self.is_production})")

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Skip restrictive headers for CORS preflight requests
        is_cors_preflight = request.method == "OPTIONS" and "access-control-request-method" in request.headers

        # Add security headers (with CORS-aware adjustments)
        self._add_security_headers(response, is_cors_preflight)

        return response

    def _add_security_headers(self, response: Response, is_cors_preflight: bool = False):
        """Add security headers to the response"""

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Legacy XSS protection (for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Prevent caching of sensitive data
        if self._is_sensitive_endpoint(response):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # HSTS (only in production and over HTTPS)
        if self.enable_hsts and self.is_production:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self.hsts_max_age}; includeSubDomains; preload"
            )

        # Content Security Policy
        csp = self._build_csp()
        if self.csp_report_only:
            response.headers["Content-Security-Policy-Report-Only"] = csp
        else:
            response.headers["Content-Security-Policy"] = csp

        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = self._build_permissions_policy()

        # Cross-Origin policies - skip for CORS preflight to avoid conflicts
        # These policies can interfere with cross-origin requests
        if not is_cors_preflight:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"  # Allow cross-origin for API

    def _is_sensitive_endpoint(self, response: Response) -> bool:
        """Check if response is from a sensitive endpoint"""
        # In practice, we'd check the request path
        # For now, mark all API responses as non-cacheable
        content_type = response.headers.get("content-type", "")
        return "application/json" in content_type

    def _build_csp(self) -> str:
        """
        Build Content-Security-Policy header value.

        NOTE: style-src uses 'unsafe-inline' because React 18 injects inline styles
        for styled-components, CSS modules, and dynamic styling. Migrating to nonce-based
        styles would require ejecting from CRA and custom webpack config. This is an
        accepted tradeoff — script-src is the higher-risk directive and is locked to 'self'.
        """
        # CSP directives
        directives = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",  # Required by React 18 (see note above)
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' wss:",  # Allow WebSocket connections
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "worker-src 'self' blob:",
            "manifest-src 'self'",
        ]

        # Add upgrade-insecure-requests in production
        if self.is_production:
            directives.append("upgrade-insecure-requests")

        return "; ".join(directives)

    def _build_permissions_policy(self) -> str:
        """Build Permissions-Policy header value"""
        # Disable features we don't need
        policies = [
            "accelerometer=()",
            "ambient-light-sensor=()",
            "autoplay=()",
            "battery=()",
            "camera=()",
            "cross-origin-isolated=()",
            "display-capture=()",
            "document-domain=()",
            "encrypted-media=()",
            "execution-while-not-rendered=()",
            "execution-while-out-of-viewport=()",
            "fullscreen=()",
            "geolocation=()",
            "gyroscope=()",
            "keyboard-map=()",
            "magnetometer=()",
            "microphone=()",
            "midi=()",
            "navigation-override=()",
            "payment=()",
            "picture-in-picture=()",
            "publickey-credentials-get=()",
            "screen-wake-lock=()",
            "sync-xhr=()",
            "usb=()",
            "web-share=()",
            "xr-spatial-tracking=()",
        ]
        return ", ".join(policies)
