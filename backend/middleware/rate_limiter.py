# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Advanced Rate Limiting System for T1 Agentics

Features:
- Per webhook configurable limits
- Tier-based limits (Free / Pro / Enterprise)
- Per-IP + per-token hybrid limiting
- Trusted source bypass for internal relays
- Metrics per webhook (requests/min, drops, retries)
- SECURITY: Trusted proxy validation for X-Forwarded-For
"""

import os
import time
import logging
import ipaddress
from typing import Dict, Optional, Set, Tuple, List
from dataclasses import dataclass, field
from collections import defaultdict
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# ============================================================================
# SECURITY: Trusted Proxy Configuration
# ============================================================================
# Only accept X-Forwarded-For headers from these IP ranges
# Configure via TRUSTED_PROXY_IPS environment variable (comma-separated)
# Example: TRUSTED_PROXY_IPS=127.0.0.1,10.0.0.0/8,172.16.0.0/12

_trusted_proxy_env = os.environ.get("TRUSTED_PROXY_IPS", "127.0.0.1,::1")
TRUSTED_PROXY_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

for proxy in _trusted_proxy_env.split(","):
    proxy = proxy.strip()
    if not proxy:
        continue
    try:
        # Try as network (with CIDR)
        TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(proxy, strict=False))
    except ValueError:
        try:
            # Try as single IP
            ip = ipaddress.ip_address(proxy)
            if isinstance(ip, ipaddress.IPv4Address):
                TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(f"{proxy}/32"))
            else:
                TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(f"{proxy}/128"))
        except ValueError:
            logger.warning(f"Invalid trusted proxy IP/network: {proxy}")


def is_trusted_proxy(ip_str: str) -> bool:
    """Check if an IP address is from a trusted proxy."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in TRUSTED_PROXY_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class TierLimits:
    """Rate limits per subscription tier"""
    requests_per_minute: int
    requests_per_hour: int
    burst_limit: int  # Max requests in 10 seconds


# Default tier configurations
TIER_LIMITS = {
    "free": TierLimits(
        requests_per_minute=60,
        requests_per_hour=1000,
        burst_limit=20
    ),
    "pro": TierLimits(
        requests_per_minute=300,
        requests_per_hour=10000,
        burst_limit=100
    ),
    "enterprise": TierLimits(
        requests_per_minute=1000,
        requests_per_hour=50000,
        burst_limit=500
    ),
    "unlimited": TierLimits(
        requests_per_minute=999999,
        requests_per_hour=999999,
        burst_limit=999999
    )
}


@dataclass
class WebhookConfig:
    """Per-webhook rate limit configuration"""
    name: str
    requests_per_minute: int = 200
    requests_per_hour: int = 5000
    burst_limit: int = 50
    tier_override: Optional[str] = None  # Override with tier limits
    trusted_ips: Set[str] = field(default_factory=set)
    enabled: bool = True


@dataclass
class WebhookMetrics:
    """Metrics tracking for a webhook"""
    total_requests: int = 0
    requests_last_minute: int = 0
    requests_last_hour: int = 0
    dropped_requests: int = 0
    rate_limited_requests: int = 0
    last_request_time: float = 0
    unique_ips: Set[str] = field(default_factory=set)


# =============================================================================
# RATE LIMITER STATE
# =============================================================================

class RateLimiterState:
    """Global state for rate limiting"""

    def __init__(self):
        # Request counts: {key: (count, window_start)}
        self.minute_counts: Dict[str, Tuple[int, float]] = {}
        self.hour_counts: Dict[str, Tuple[int, float]] = {}
        self.burst_counts: Dict[str, Tuple[int, float]] = {}

        # Webhook configurations: {webhook_name: WebhookConfig}
        self.webhook_configs: Dict[str, WebhookConfig] = {}

        # Webhook metrics: {webhook_name: WebhookMetrics}
        self.webhook_metrics: Dict[str, WebhookMetrics] = defaultdict(WebhookMetrics)

        # Token to tier mapping: {token: tier_name}
        self.token_tiers: Dict[str, str] = {}

        # Trusted sources (bypass rate limiting)
        self.trusted_ips: Set[str] = set()
        self.trusted_tokens: Set[str] = set()

        # Load configuration
        self._load_config()

    def _load_config(self):
        """Load rate limit configuration from environment/database"""
        # Trusted IPs from environment (comma-separated)
        trusted_ips_env = os.getenv("RATE_LIMIT_TRUSTED_IPS", "")
        if trusted_ips_env:
            self.trusted_ips = set(ip.strip() for ip in trusted_ips_env.split(","))

        # Add localhost/internal IPs as trusted by default
        self.trusted_ips.update({
            "127.0.0.1",
            "::1",
            "localhost",
        })

        # Add Docker internal network ranges
        docker_trusted = os.getenv("RATE_LIMIT_TRUST_DOCKER", "true").lower() == "true"
        if docker_trusted:
            self.trusted_ips.update({
                "172.17.0.1",  # Docker bridge
                "172.18.0.1",  # Docker compose network
                "host.docker.internal",
            })

    def configure_webhook(self, config: WebhookConfig):
        """Add or update webhook configuration"""
        self.webhook_configs[config.name] = config
        logger.info(f"Configured webhook '{config.name}': {config.requests_per_minute}/min")

    def get_webhook_config(self, webhook_name: str) -> WebhookConfig:
        """Get webhook config, creating default if not exists"""
        if webhook_name not in self.webhook_configs:
            self.webhook_configs[webhook_name] = WebhookConfig(
                name=webhook_name,
                requests_per_minute=200,  # Default: 200/min per webhook
                requests_per_hour=5000,
                burst_limit=50
            )
        return self.webhook_configs[webhook_name]

    def set_token_tier(self, token: str, tier: str):
        """Set the tier for a token/API key"""
        if tier not in TIER_LIMITS:
            raise ValueError(f"Unknown tier: {tier}. Valid: {list(TIER_LIMITS.keys())}")
        self.token_tiers[token] = tier

    def add_trusted_source(self, ip: Optional[str] = None, token: Optional[str] = None):
        """Add a trusted source that bypasses rate limiting"""
        if ip:
            self.trusted_ips.add(ip)
        if token:
            self.trusted_tokens.add(token)

    def is_trusted(self, ip: str, token: Optional[str] = None) -> bool:
        """Check if source is trusted (bypasses rate limiting)"""
        if ip in self.trusted_ips:
            return True
        if token and token in self.trusted_tokens:
            return True
        return False

    def get_tier_limits(self, token: Optional[str] = None) -> TierLimits:
        """Get rate limits based on token tier"""
        if token and token in self.token_tiers:
            tier = self.token_tiers[token]
        else:
            tier = os.getenv("DEFAULT_RATE_LIMIT_TIER", "pro")
        return TIER_LIMITS.get(tier, TIER_LIMITS["pro"])


# Global state instance
_rate_limiter_state: Optional[RateLimiterState] = None

def get_rate_limiter_state() -> RateLimiterState:
    """Get or create the global rate limiter state"""
    global _rate_limiter_state
    if _rate_limiter_state is None:
        _rate_limiter_state = RateLimiterState()
    return _rate_limiter_state


# =============================================================================
# RATE LIMITING LOGIC
# =============================================================================

class AdvancedRateLimiter:
    """Advanced rate limiter with multiple strategies"""

    def __init__(self, state: RateLimiterState):
        self.state = state

    async def check_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        counts_dict: Dict[str, Tuple[int, float]]
    ) -> Tuple[bool, int, int]:
        """
        Check if request is within rate limit.

        Uses Redis fixed-window counter when available (shared across workers),
        falls back to the in-process counts_dict when Redis is unreachable.

        Returns: (allowed, current_count, retry_after_seconds)
        """
        # Try Redis first - critical for multi-worker correctness
        try:
            from services.redis_client import get_redis
            client = await get_redis()
        except Exception:
            client = None

        if client is not None:
            try:
                redis_key = f"ratelimit:{key}:{window_seconds}"
                pipe = client.pipeline()
                pipe.incr(redis_key)
                pipe.expire(redis_key, window_seconds, nx=True)
                pipe.ttl(redis_key)
                results = await pipe.execute()
                count = int(results[0])
                ttl = int(results[2]) if results[2] is not None else window_seconds
                if ttl < 0:
                    ttl = window_seconds
                if count > limit:
                    return (False, count, max(1, ttl))
                return (True, count, 0)
            except Exception as e:
                logger.warning(f"Redis rate-limit failed, using in-memory fallback: {e}")

        # Fallback: in-process counter (single-worker only)
        current_time = time.time()

        if key in counts_dict:
            count, window_start = counts_dict[key]

            # Check if window expired
            if current_time - window_start > window_seconds:
                # Reset window
                counts_dict[key] = (1, current_time)
                return (True, 1, 0)
            elif count >= limit:
                # Rate limited
                retry_after = int(window_seconds - (current_time - window_start)) + 1
                return (False, count, retry_after)
            else:
                # Increment count
                counts_dict[key] = (count + 1, window_start)
                return (True, count + 1, 0)
        else:
            # First request in window
            counts_dict[key] = (1, current_time)
            return (True, 1, 0)

    async def check_webhook_limits(
        self,
        webhook_name: str,
        client_ip: str,
        token: Optional[str] = None
    ) -> Tuple[bool, str, int]:
        """
        Check all rate limits for a webhook request.

        Returns: (allowed, reason, retry_after)
        """
        # Check if trusted source
        if self.state.is_trusted(client_ip, token):
            return (True, "trusted", 0)

        # Get webhook config
        config = self.state.get_webhook_config(webhook_name)

        if not config.enabled:
            return (False, "webhook_disabled", 0)

        # Check if IP is trusted for this specific webhook
        if client_ip in config.trusted_ips:
            return (True, "webhook_trusted", 0)

        # Determine limits (webhook-specific or tier-based)
        if config.tier_override:
            tier_limits = TIER_LIMITS.get(config.tier_override, TIER_LIMITS["pro"])
            minute_limit = tier_limits.requests_per_minute
            hour_limit = tier_limits.requests_per_hour
            burst_limit = tier_limits.burst_limit
        else:
            minute_limit = config.requests_per_minute
            hour_limit = config.requests_per_hour
            burst_limit = config.burst_limit

        # Build rate limit key: IP + webhook
        base_key = f"{client_ip}:{webhook_name}"

        # If token provided, also check token-based limits (hybrid)
        if token:
            token_key = f"token:{token}:{webhook_name}"
            token_limits = self.state.get_tier_limits(token)

            # Check token burst limit
            allowed, count, retry = await self.check_limit(
                f"{token_key}:burst",
                token_limits.burst_limit,
                10,  # 10 second burst window
                self.state.burst_counts
            )
            if not allowed:
                return (False, "token_burst_exceeded", retry)

        # Check burst limit (10 second window)
        allowed, count, retry = await self.check_limit(
            f"{base_key}:burst",
            burst_limit,
            10,
            self.state.burst_counts
        )
        if not allowed:
            self._record_rate_limited(webhook_name)
            return (False, "burst_exceeded", retry)

        # Check minute limit
        allowed, count, retry = await self.check_limit(
            f"{base_key}:minute",
            minute_limit,
            60,
            self.state.minute_counts
        )
        if not allowed:
            self._record_rate_limited(webhook_name)
            return (False, "minute_limit_exceeded", retry)

        # Check hour limit
        allowed, count, retry = await self.check_limit(
            f"{base_key}:hour",
            hour_limit,
            3600,
            self.state.hour_counts
        )
        if not allowed:
            self._record_rate_limited(webhook_name)
            return (False, "hour_limit_exceeded", retry)

        # Update metrics
        self._record_request(webhook_name, client_ip)

        return (True, "allowed", 0)

    async def check_general_limits(
        self,
        path: str,
        client_ip: str,
        token: Optional[str] = None
    ) -> Tuple[bool, str, int]:
        """
        Check rate limits for non-webhook endpoints.

        Returns: (allowed, reason, retry_after)
        """
        # Check if trusted
        if self.state.is_trusted(client_ip, token):
            return (True, "trusted", 0)

        # Get tier limits
        limits = self.state.get_tier_limits(token)

        # Build key
        key = f"{client_ip}:{path}"

        # Check minute limit
        allowed, count, retry = await self.check_limit(
            f"{key}:minute",
            limits.requests_per_minute,
            60,
            self.state.minute_counts
        )
        if not allowed:
            return (False, "minute_limit_exceeded", retry)

        return (True, "allowed", 0)

    def _record_request(self, webhook_name: str, client_ip: str):
        """Record successful request in metrics"""
        metrics = self.state.webhook_metrics[webhook_name]
        metrics.total_requests += 1
        metrics.requests_last_minute += 1
        metrics.last_request_time = time.time()
        metrics.unique_ips.add(client_ip)

    def _record_rate_limited(self, webhook_name: str):
        """Record rate-limited request in metrics"""
        metrics = self.state.webhook_metrics[webhook_name]
        metrics.rate_limited_requests += 1
        metrics.dropped_requests += 1


# =============================================================================
# MIDDLEWARE
# =============================================================================

class AdvancedRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Advanced rate limiting middleware with:
    - Per webhook limits (200/min/IP/webhook by default)
    - Tier-based limits
    - Trusted source bypass
    - Metrics tracking
    """

    # Special rate limits for sensitive endpoints
    SENSITIVE_ROUTES = {
        "/api/v1/admin/login": (5, 60),           # 5 per minute
        "/api/v1/auth/login": (5, 60),            # 5 per minute
        "/api/v1/admin/password-reset/request": (3, 60),  # 3 per minute
        "/api/v1/admin/users": (10, 60),          # 10 per minute
        "/api/v1/admin/python/install_package": (3, 300),  # 3 per 5 minutes
        "/api/v1/admin/python/uninstall_package": (3, 300),  # 3 per 5 minutes
        "/api/v1/credentials": (10, 60),          # 10 per minute
        "/api/v1/playbooks/approvals": (20, 60),  # 20 per minute
    }

    def __init__(self, app):
        super().__init__(app)
        self.state = get_rate_limiter_state()
        self.limiter = AdvancedRateLimiter(self.state)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # Skip rate limiting for OPTIONS (CORS preflight)
        if method == "OPTIONS":
            return await call_next(request)

        # Get client info
        client_ip = self._get_client_ip(request)
        token = self._get_token(request)

        # Check if this is a webhook endpoint
        if path.startswith("/api/v1/webhooks/ingest/"):
            webhook_name = path.replace("/api/v1/webhooks/ingest/", "").split("/")[0]
            allowed, reason, retry_after = await self.limiter.check_webhook_limits(
                webhook_name, client_ip, token
            )
        # Check if this is a sensitive endpoint
        elif path in self.SENSITIVE_ROUTES:
            limit, window = self.SENSITIVE_ROUTES[path]
            allowed, count, retry_after = await self.limiter.check_limit(
                f"{client_ip}:{path}",
                limit,
                window,
                self.state.minute_counts
            )
            reason = "allowed" if allowed else "sensitive_limit_exceeded"
        # General endpoint
        else:
            allowed, reason, retry_after = await self.limiter.check_general_limits(
                path, client_ip, token
            )

        if not allowed:
            logger.warning(
                f"Rate limited: {client_ip} on {path} - {reason} "
                f"(retry after {retry_after}s)"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "reason": reason,
                    "retry_after": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Reason": reason
                }
            )

        response = await call_next(request)
        return response

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP, considering proxies.

        SECURITY: Only trust X-Forwarded-For from configured trusted proxies.
        This prevents IP spoofing attacks that bypass rate limiting.
        """
        direct_ip = request.client.host if request.client else "unknown"

        # SECURITY: Only trust forwarded headers from trusted proxies
        if direct_ip != "unknown" and is_trusted_proxy(direct_ip):
            # Check X-Forwarded-For header (from reverse proxy)
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                # Take the first IP (original client)
                client_ip = forwarded.split(",")[0].strip()
                logger.debug(f"Trusted proxy {direct_ip} forwarded client IP: {client_ip}")
                return client_ip

            # Check X-Real-IP header
            real_ip = request.headers.get("X-Real-IP")
            if real_ip:
                logger.debug(f"Trusted proxy {direct_ip} provided X-Real-IP: {real_ip}")
                return real_ip

        # Use direct connection IP (don't trust forwarded headers from untrusted sources)
        return direct_ip

    def _get_token(self, request: Request) -> Optional[str]:
        """Extract authentication token from request"""
        # Check Authorization header (Bearer token)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]

        # Check X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return api_key

        # Check HEC token for webhooks
        if auth.startswith("HEC "):
            return auth[4:]

        return None


# =============================================================================
# METRICS API
# =============================================================================

def get_webhook_metrics(webhook_name: Optional[str] = None) -> Dict:
    """Get metrics for webhooks"""
    state = get_rate_limiter_state()

    if webhook_name:
        metrics = state.webhook_metrics.get(webhook_name)
        if not metrics:
            return {"error": "Webhook not found"}
        return {
            "webhook": webhook_name,
            "total_requests": metrics.total_requests,
            "requests_last_minute": metrics.requests_last_minute,
            "dropped_requests": metrics.dropped_requests,
            "rate_limited_requests": metrics.rate_limited_requests,
            "unique_ips": len(metrics.unique_ips),
            "last_request_time": metrics.last_request_time
        }
    else:
        # Return all webhooks
        result = {}
        for name, metrics in state.webhook_metrics.items():
            result[name] = {
                "total_requests": metrics.total_requests,
                "dropped_requests": metrics.dropped_requests,
                "rate_limited_requests": metrics.rate_limited_requests,
                "unique_ips": len(metrics.unique_ips)
            }
        return result


def configure_webhook_limits(
    webhook_name: str,
    requests_per_minute: int = 200,
    requests_per_hour: int = 5000,
    burst_limit: int = 50,
    tier_override: Optional[str] = None,
    trusted_ips: Optional[Set[str]] = None
):
    """Configure rate limits for a specific webhook"""
    state = get_rate_limiter_state()
    config = WebhookConfig(
        name=webhook_name,
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
        burst_limit=burst_limit,
        tier_override=tier_override,
        trusted_ips=trusted_ips or set()
    )
    state.configure_webhook(config)
    return config


def add_trusted_source(ip: Optional[str] = None, token: Optional[str] = None):
    """Add a trusted source that bypasses rate limiting"""
    state = get_rate_limiter_state()
    state.add_trusted_source(ip=ip, token=token)


def set_token_tier(token: str, tier: str):
    """Set the subscription tier for an API token"""
    state = get_rate_limiter_state()
    state.set_token_tier(token, tier)
