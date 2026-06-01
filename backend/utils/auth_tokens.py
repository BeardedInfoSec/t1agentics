# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Shared helpers for extracting auth tokens and cookie configuration.
"""

import os
import secrets
from typing import Optional, Tuple
from fastapi import Request

ACCESS_TOKEN_COOKIE = "t1_access_token"
CSRF_COOKIE = "t1_csrf"


def get_auth_token(request: Optional[Request], authorization: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract a JWT token from Authorization header (Bearer) or HttpOnly cookie.
    Returns (token, source) where source is "bearer" or "cookie".
    """
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:], "bearer"

    if request is not None:
        cookie_token = request.cookies.get(ACCESS_TOKEN_COOKIE)
        if cookie_token:
            return cookie_token, "cookie"

    return None, None


def should_use_secure_cookies() -> bool:
    """Return True if cookies should be marked Secure."""
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env in ("production", "prod"):
        return True
    return os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")


def get_cookie_domain() -> Optional[str]:
    """
    Derive the cookie Domain attribute from PUBLIC_URL.

    On production (e.g. PUBLIC_URL=https://t1agentics.ai), returns
    ".t1agentics.ai" so cookies are sent to all subdomains.
    On localhost / dev, returns None (cookie scoped to exact hostname).
    """
    from urllib.parse import urlparse
    public_url = os.getenv("PUBLIC_URL", "")
    if not public_url:
        return None
    hostname = urlparse(public_url).hostname or ""
    if not hostname or hostname == "localhost" or hostname.replace(".", "").isdigit():
        return None
    # Return with leading dot for subdomain coverage
    return f".{hostname}"


def build_csrf_token() -> str:
    """Generate a new CSRF token."""
    return secrets.token_urlsafe(32)
