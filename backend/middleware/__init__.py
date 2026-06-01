# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Middleware package for T1 Agentics

Includes:
- Authentication middleware (JWT + API Key)
- Advanced rate limiting with per-webhook limits, tiers, and metrics
- Security headers (OWASP best practices)
"""

from .auth_middleware import (
    AuthenticationMiddleware,
    RateLimitMiddleware,
    is_public_route,
    decode_jwt_token,
    PUBLIC_ROUTES,
    PUBLIC_ROUTE_PATTERNS
)

from .rate_limiter import (
    AdvancedRateLimitMiddleware,
    AdvancedRateLimiter,
    RateLimiterState,
    get_rate_limiter_state,
    get_webhook_metrics,
    configure_webhook_limits,
    add_trusted_source,
    set_token_tier,
    TIER_LIMITS,
    TierLimits,
    WebhookConfig,
    WebhookMetrics
)

from .security_headers import SecurityHeadersMiddleware

__all__ = [
    # Auth middleware
    "AuthenticationMiddleware",
    "RateLimitMiddleware",
    "is_public_route",
    "decode_jwt_token",
    "PUBLIC_ROUTES",
    "PUBLIC_ROUTE_PATTERNS",
    # Advanced rate limiting
    "AdvancedRateLimitMiddleware",
    "AdvancedRateLimiter",
    "RateLimiterState",
    "get_rate_limiter_state",
    "get_webhook_metrics",
    "configure_webhook_limits",
    "add_trusted_source",
    "set_token_tier",
    "TIER_LIMITS",
    "TierLimits",
    "WebhookConfig",
    "WebhookMetrics",
    # Security headers
    "SecurityHeadersMiddleware"
]
