# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
EDL Delivery Routes (Public-Facing)

These endpoints are consumed by firewalls (Palo Alto, Fortinet, Cisco, etc.).
They return plain-text IOC lists over HTTP(S) with:
- Multi-method authentication (token, basic, IP allowlist)
- ETag / If-None-Match / If-Modified-Since support
- Access logging
- Rate limiting (per-IP)

URL structure:
  GET /v1/lists/{slug}          -> plain text
  GET /v1/lists/{slug}.txt      -> plain text (explicit)
  GET /v1/lists/{slug}.json     -> JSON with metadata
  HEAD /v1/lists/{slug}         -> check for changes without downloading
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse

from services.postgres_db import postgres_db
from services.edl_service import get_edl_service
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["EDL Delivery"], dependencies=[Depends(get_current_user)])


def _is_browser(request: Request) -> bool:
    """Check if the request is from a browser based on Accept header."""
    accept = request.headers.get("Accept", "")
    return "text/html" in accept

# Simple in-memory rate limiter (per-IP, per-minute)
# In production, use the PostgreSQL-based approach or Redis
_rate_limit_store: dict = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_UNAUTHED = 10
RATE_LIMIT_MAX_AUTHED = 120


def _check_rate_limit(client_ip: str, authenticated: bool) -> bool:
    """Returns True if request is allowed, False if rate-limited."""
    now = time.time()
    key = f"edl:{client_ip}"

    if key not in _rate_limit_store:
        _rate_limit_store[key] = {"count": 0, "window_start": now}

    entry = _rate_limit_store[key]

    # Reset window if expired
    if now - entry["window_start"] > RATE_LIMIT_WINDOW:
        entry["count"] = 0
        entry["window_start"] = now

    entry["count"] += 1

    limit = RATE_LIMIT_MAX_AUTHED if authenticated else RATE_LIMIT_MAX_UNAUTHED

    # Cleanup old entries periodically (every 100 requests)
    if len(_rate_limit_store) > 10000:
        cutoff = now - RATE_LIMIT_WINDOW * 2
        expired = [k for k, v in _rate_limit_store.items() if v["window_start"] < cutoff]
        for k in expired:
            del _rate_limit_store[k]

    return entry["count"] <= limit


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For behind load balancers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ============================================================================
# DELIVERY ENDPOINTS
# ============================================================================

@router.get("/v1/lists/{slug}")
@router.get("/v1/lists/{slug}.txt")
async def deliver_edl_text(
    slug: str,
    request: Request,
):
    """
    Deliver EDL list as plain text (one IOC per line).
    This is the primary endpoint consumed by firewalls.

    Supports:
    - Bearer token auth (Authorization: Bearer <token>)
    - Basic auth (Authorization: Basic <base64>)
    - Custom header auth (X-EDL-Token: <token>)
    - IP allowlist auth
    - ETag / If-None-Match for cache validation
    - If-Modified-Since header
    """
    # Strip .txt extension if present
    if slug.endswith('.txt'):
        slug = slug[:-4]

    return await _deliver_list(slug, request, format="text")


@router.get("/v1/lists/{slug}.json")
async def deliver_edl_json(
    slug: str,
    request: Request,
):
    """
    Deliver EDL list as JSON with metadata.
    For API consumers, SIEMs, and non-firewall integrations.
    """
    return await _deliver_list(slug, request, format="json")


@router.head("/v1/lists/{slug}")
async def head_edl_list(
    slug: str,
    request: Request,
):
    """
    HEAD request for EDL list. Returns headers only (no body).
    Firewalls use this to check if content has changed before downloading.
    """
    return await _deliver_list(slug, request, format="text", head_only=True)


# ============================================================================
# METADATA ENDPOINT
# ============================================================================

@router.get("/v1/lists/{slug}/metadata")
async def get_edl_metadata(
    slug: str,
    request: Request,
):
    """
    Get list metadata without downloading content.
    Useful for monitoring dashboards and consumer health checks.
    """
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Service unavailable")

    svc = get_edl_service()
    edl = await svc.get_list_by_slug(slug)
    if not edl:
        raise HTTPException(status_code=404, detail="List not found")

    return {
        "list_id": str(edl['list_id']),
        "name": edl['name'],
        "slug": edl['slug'],
        "ioc_type": edl['ioc_type'],
        "item_count": edl['item_count'],
        "last_generated_at": edl['last_generated_at'].isoformat() if edl.get('last_generated_at') else None,
        "content_hash": edl.get('content_hash'),
        "enabled": edl['enabled'],
    }


# ============================================================================
# CORE DELIVERY LOGIC
# ============================================================================

async def _deliver_list(
    slug: str,
    request: Request,
    format: str = "text",
    head_only: bool = False,
) -> Response:
    """Core delivery logic shared by all endpoints."""
    start_time = time.time()
    client_ip = _get_client_ip(request)

    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Service unavailable")

    svc = get_edl_service()

    # 1. Resolve list
    edl = await svc.get_list_by_slug(slug)
    if not edl:
        raise HTTPException(status_code=404, detail="List not found")

    list_id = str(edl['list_id'])

    # 2. Authenticate
    auth_header = request.headers.get("Authorization")
    edl_token = request.headers.get("X-EDL-Token")

    # If browser sends Basic auth, also try the password as a Bearer token
    # so token-type credentials work with the browser's native login prompt.
    extra_token = None
    if auth_header and auth_header.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            _, password = decoded.split(":", 1)
            extra_token = password
        except Exception:
            pass

    authenticated, credential_id = await svc.authenticate_request(
        list_id=list_id,
        client_ip=client_ip,
        auth_header=auth_header,
        edl_token_header=edl_token,
    )

    # Retry with the Basic password as a Bearer token
    if not authenticated and extra_token:
        authenticated, credential_id = await svc.authenticate_request(
            list_id=list_id,
            client_ip=client_ip,
            auth_header=f"Bearer {extra_token}",
            edl_token_header=None,
        )

    if not authenticated:
        # Log failed auth
        await svc.log_access(
            list_id=list_id,
            client_ip=client_ip,
            status_code=401,
            auth_method=_detect_auth_method(auth_header, edl_token),
            auth_success=False,
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
        )
        return Response(
            status_code=401,
            content="Unauthorized",
            media_type="text/plain",
            headers={"WWW-Authenticate": 'Basic realm="EDL"'},
        )

    # 3. Rate limit
    if not _check_rate_limit(client_ip, authenticated):
        await svc.log_access(
            list_id=list_id,
            client_ip=client_ip,
            status_code=429,
            auth_method=_detect_auth_method(auth_header, edl_token),
            auth_success=True,
            credential_id=credential_id,
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    # 4. Get cached content
    cached = await svc.get_cached_content(list_id)
    content = cached["content"]
    content_hash = cached.get("content_hash") or ""
    item_count = cached.get("item_count", 0)
    generated_at = cached.get("generated_at")
    cache_hit = cached.get("cache_hit", False)

    # 5. ETag / conditional request handling
    etag = f'"{content_hash}"'
    if_none_match = request.headers.get("If-None-Match")
    if if_none_match and if_none_match == etag:
        elapsed_ms = int((time.time() - start_time) * 1000)
        await svc.log_access(
            list_id=list_id,
            client_ip=client_ip,
            status_code=304,
            auth_method=_detect_auth_method(auth_header, edl_token),
            auth_success=True,
            credential_id=credential_id,
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
            items_returned=0,
            response_time_ms=elapsed_ms,
            cache_hit=True,
        )
        return Response(
            status_code=304,
            headers={
                "ETag": etag,
                "Cache-Control": f"public, max-age={edl['refresh_interval_seconds']}",
            },
        )

    # 6. If-Modified-Since
    if_modified = request.headers.get("If-Modified-Since")
    if if_modified and generated_at:
        try:
            from email.utils import parsedate_to_datetime
            client_date = parsedate_to_datetime(if_modified)
            if generated_at.replace(tzinfo=timezone.utc) <= client_date.replace(tzinfo=timezone.utc):
                elapsed_ms = int((time.time() - start_time) * 1000)
                await svc.log_access(
                    list_id=list_id,
                    client_ip=client_ip,
                    status_code=304,
                    auth_method=_detect_auth_method(auth_header, edl_token),
                    auth_success=True,
                    credential_id=credential_id,
                    user_agent=request.headers.get("User-Agent"),
                    request_path=str(request.url.path),
                    items_returned=0,
                    response_time_ms=elapsed_ms,
                    cache_hit=True,
                )
                return Response(status_code=304, headers={"ETag": etag})
        except Exception:
            pass  # If parsing fails, serve full response

    # 7. Build response headers
    last_modified = None
    if generated_at:
        from email.utils import format_datetime
        last_modified = format_datetime(
            generated_at.replace(tzinfo=timezone.utc) if generated_at.tzinfo is None else generated_at
        )

    common_headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={edl['refresh_interval_seconds']}",
        "X-EDL-List-ID": list_id,
        "X-EDL-Item-Count": str(item_count),
        "X-EDL-IOC-Type": edl['ioc_type'],
    }
    if last_modified:
        common_headers["Last-Modified"] = last_modified
    if generated_at:
        common_headers["X-EDL-Generated-At"] = generated_at.isoformat()

    # 8. HEAD request - headers only
    if head_only:
        elapsed_ms = int((time.time() - start_time) * 1000)
        await svc.log_access(
            list_id=list_id,
            client_ip=client_ip,
            status_code=200,
            auth_method=_detect_auth_method(auth_header, edl_token),
            auth_success=True,
            credential_id=credential_id,
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
            items_returned=0,
            response_time_ms=elapsed_ms,
            cache_hit=cache_hit,
        )
        return Response(
            status_code=200,
            headers={**common_headers, "Content-Type": "text/plain; charset=utf-8"},
        )

    # 9. Build response body
    elapsed_ms = int((time.time() - start_time) * 1000)

    if format == "json":
        # Parse content lines into structured JSON
        items = []
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                items.append({"value": line, "type": edl['ioc_type']})

        body = {
            "list_id": list_id,
            "name": edl['name'],
            "ioc_type": edl['ioc_type'],
            "generated_at": generated_at.isoformat() if generated_at else None,
            "item_count": item_count,
            "items": items,
        }

        await svc.log_access(
            list_id=list_id,
            client_ip=client_ip,
            status_code=200,
            auth_method=_detect_auth_method(auth_header, edl_token),
            auth_success=True,
            credential_id=credential_id,
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
            items_returned=item_count,
            response_time_ms=elapsed_ms,
            cache_hit=cache_hit,
        )

        return JSONResponse(
            content=body,
            headers=common_headers,
        )

    # Default: plain text
    await svc.log_access(
        list_id=list_id,
        client_ip=client_ip,
        status_code=200,
        auth_method=_detect_auth_method(auth_header, edl_token),
        auth_success=True,
        credential_id=credential_id,
        user_agent=request.headers.get("User-Agent"),
        request_path=str(request.url.path),
        items_returned=item_count,
        response_time_ms=elapsed_ms,
        cache_hit=cache_hit,
    )

    return PlainTextResponse(
        content=content,
        headers=common_headers,
    )


# ============================================================================
# BROWSER PAGE
# ============================================================================

_BROWSER_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EDL - {name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;width:100%;max-width:640px;overflow:hidden}}
.header{{padding:1.25rem 1.5rem;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}}
.header h1{{font-size:1rem;font-weight:600}}
.badge{{padding:0.2rem 0.6rem;border-radius:4px;font-size:0.7rem;font-weight:600;text-transform:uppercase;background:{type_bg};color:{type_color};border:1px solid {type_border}}}
.meta{{padding:0.75rem 1.5rem;background:#0f172a;font-size:0.75rem;color:#64748b;display:flex;gap:1.5rem}}
.body{{padding:1.5rem}}
label{{display:block;font-size:0.75rem;font-weight:600;color:#94a3b8;margin-bottom:0.4rem}}
input{{width:100%;padding:0.6rem 0.75rem;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0;font-size:0.85rem;font-family:monospace}}
input:focus{{outline:none;border-color:#3CB371}}
button{{width:100%;margin-top:1rem;padding:0.65rem;background:linear-gradient(135deg,#3CB371,#2e8b57);border:none;border-radius:6px;color:#fff;font-weight:600;cursor:pointer;font-size:0.85rem}}
button:hover{{opacity:0.9}}
.error{{margin-top:0.75rem;padding:0.6rem;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#ef4444;font-size:0.8rem;display:none}}
.content{{margin-top:0;max-height:60vh;overflow:auto;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:0.75rem;font-family:monospace;font-size:0.75rem;line-height:1.6;white-space:pre-wrap;display:none}}
.info{{font-size:0.75rem;color:#64748b;margin-top:0.75rem;text-align:center}}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>{name}</h1>
    <span class="badge">{ioc_type}</span>
  </div>
  <div class="meta">
    <span>Slug: {slug}</span>
    <span>Items: {item_count}</span>
    <span>Type: {ioc_type}</span>
  </div>
  <div class="body">
    <div id="auth-section" style="display:{show_auth}">
      <label>Bearer Token</label>
      <input type="password" id="token" placeholder="edl_..." autocomplete="off">
      <button onclick="authenticate()">Authenticate & View</button>
      <div id="error" class="error"></div>
    </div>
    <div id="content-box" class="content"></div>
    <div id="no-auth-msg" style="display:{show_public}">
      <button onclick="loadPublic()">Load List Content</button>
    </div>
    <p class="info">Delivery URL: /v1/lists/{slug}</p>
  </div>
</div>
<script>
const slug = "{slug}";
function showError(msg) {{
  const el = document.getElementById('error');
  el.textContent = msg; el.style.display = 'block';
}}
function authenticate() {{
  const token = document.getElementById('token').value.trim();
  if (!token) {{ showError('Enter a token'); return; }}
  fetch('/v1/lists/' + slug, {{
    headers: {{ 'Authorization': 'Bearer ' + token, 'Accept': 'text/plain' }}
  }}).then(r => {{
    if (r.status === 401) {{ showError('Invalid token'); throw new Error('401'); }}
    if (!r.ok) {{ showError('Error: ' + r.status); throw new Error(r.status); }}
    return r.text();
  }}).then(text => {{
    document.getElementById('auth-section').style.display = 'none';
    const box = document.getElementById('content-box');
    box.textContent = text; box.style.display = 'block';
  }}).catch(() => {{}});
}}
function loadPublic() {{
  fetch('/v1/lists/' + slug, {{
    headers: {{ 'Accept': 'text/plain' }}
  }}).then(r => {{
    if (!r.ok) throw new Error(r.status);
    return r.text();
  }}).then(text => {{
    document.getElementById('no-auth-msg').style.display = 'none';
    const box = document.getElementById('content-box');
    box.textContent = text; box.style.display = 'block';
  }}).catch(e => alert('Failed: ' + e.message));
}}
document.getElementById('token')?.addEventListener('keydown', function(e) {{
  if (e.key === 'Enter') authenticate();
}});
</script>
</body></html>"""


async def _serve_browser_page(slug: str, request: Request) -> HTMLResponse:
    """Serve a simple HTML page for browser-based EDL access."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Service unavailable")

    svc = get_edl_service()
    edl = await svc.get_list_by_slug(slug)
    if not edl:
        raise HTTPException(status_code=404, detail="List not found")

    list_id = str(edl['list_id'])

    # Check if list has credentials
    creds = await svc.list_credentials(list_id)
    has_auth = len(creds) > 0

    type_colors = {
        'ip': ('#3b82f620', '#3b82f6', '#3b82f640'),
        'domain': ('#8b5cf620', '#8b5cf6', '#8b5cf640'),
        'url': ('#f9731620', '#f97316', '#f9731640'),
    }
    bg, fg, border = type_colors.get(edl['ioc_type'], ('#64748b20', '#64748b', '#64748b40'))

    html = _BROWSER_PAGE.format(
        name=edl['name'],
        slug=edl['slug'],
        ioc_type=edl['ioc_type'].upper(),
        item_count=edl.get('item_count', 0),
        type_bg=bg,
        type_color=fg,
        type_border=border,
        show_auth='block' if has_auth else 'none',
        show_public='block' if not has_auth else 'none',
    )

    return HTMLResponse(content=html)


# ============================================================================
# HELPERS
# ============================================================================

def _detect_auth_method(auth_header: str = None, edl_token: str = None) -> str:
    """Detect which auth method was attempted."""
    if edl_token:
        return "header"
    if auth_header:
        if auth_header.startswith("Bearer "):
            return "token"
        if auth_header.startswith("Basic "):
            return "basic"
    return "none"
