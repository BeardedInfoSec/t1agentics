# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
CSRF protection middleware.
Enforces double-submit CSRF for cookie-based auth on unsafe HTTP methods.
"""

import logging
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from middleware.auth_middleware import is_public_route
from utils.auth_tokens import ACCESS_TOKEN_COOKIE, CSRF_COOKIE

logger = logging.getLogger(__name__)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Require X-CSRF-Token header for cookie-authenticated unsafe requests."""

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path

        if method not in UNSAFE_METHODS:
            return await call_next(request)

        if is_public_route(path):
            return await call_next(request)

        # If Authorization header is present, assume non-browser client and skip CSRF
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")
        if auth_header.startswith("Bearer ") or api_key_header:
            return await call_next(request)

        # Only enforce CSRF when cookie auth is used
        cookie_token = request.cookies.get(ACCESS_TOKEN_COOKIE)
        if not cookie_token:
            return await call_next(request)

        csrf_cookie = request.cookies.get(CSRF_COOKIE)
        csrf_header = request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRF")

        logger.warning(f"[CSRF] Method={method}, Path={path}, Cookie={'present' if csrf_cookie else 'missing'}, Header={'present' if csrf_header else 'missing'}, Match={csrf_cookie == csrf_header if (csrf_cookie and csrf_header) else 'N/A'}")

        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            logger.error(f"[CSRF-FAIL] Method={method}, Path={path}, Cookie={csrf_cookie[:10] if csrf_cookie else None}..., Header={csrf_header[:10] if csrf_header else None}...")
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF validation failed",
                    "message": "Missing or invalid CSRF token",
                },
            )

        return await call_next(request)
