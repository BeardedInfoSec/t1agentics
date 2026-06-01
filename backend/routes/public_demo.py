# Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0

"""
Public Demo Routes

Unauthenticated lead-magnet endpoints. Currently:
  - POST /api/v1/public/triage  — alert triage demo

Security model:
  - No auth, no CSRF (public endpoints).
  - Cloudflare Turnstile required on each request (proves the caller is
    a real browser, not a bot — see PUBLIC_TRIAGE_TURNSTILE_SECRET).
  - Per-IP rate limit + daily platform spend cap enforced inside
    services.public_triage_service.
  - Input payload is never persisted; only request counters survive.
"""

import logging
import os
from typing import Any, Optional

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services import public_triage_service
from services.public_triage_service import (
    PublicTriageError,
    InputTooLarge,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/public", tags=["public-demo"])

TURNSTILE_SECRET = os.environ.get("PUBLIC_TRIAGE_TURNSTILE_SECRET", "")
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ENABLED = bool(TURNSTILE_SECRET)


# ─── Models ───────────────────────────────────────────────────────────────

class TriageRequest(BaseModel):
    alert: Any = Field(..., description="The raw alert payload to triage (any JSON-serializable object).")
    turnstile_token: Optional[str] = Field(
        None, description="Cloudflare Turnstile token from the widget."
    )


# ─── Helpers ──────────────────────────────────────────────────────────────

def _get_client_ip(request: Request) -> str:
    """
    Resolve the real client IP. Cloudflare sets CF-Connecting-IP; nginx
    forwards via X-Forwarded-For. Falls back to the socket peer.
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # First entry is the original client (rest are proxies)
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def _verify_turnstile(token: Optional[str], client_ip: str) -> None:
    """
    Verify the Turnstile token with Cloudflare. Raises HTTPException(403)
    if the token is missing or invalid.

    Skipped entirely when TURNSTILE_SECRET is unset (local dev convenience).
    """
    if not TURNSTILE_ENABLED:
        logger.warning(
            "Public triage: Turnstile disabled (PUBLIC_TRIAGE_TURNSTILE_SECRET unset). "
            "DO NOT run this in production without a Turnstile secret."
        )
        return

    if not token:
        raise HTTPException(status_code=403, detail="Turnstile token required.")

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.post(
                TURNSTILE_VERIFY_URL,
                data={
                    "secret": TURNSTILE_SECRET,
                    "response": token,
                    "remoteip": client_ip,
                },
            ) as resp:
                data = await resp.json()
    except aiohttp.ClientError as e:
        logger.warning(f"Public triage: Turnstile verification call failed: {e}")
        # Fail open on Cloudflare-side outages — but log it so we notice.
        return

    if not data.get("success"):
        codes = data.get("error-codes", [])
        logger.info(f"Public triage: Turnstile rejected token: {codes}")
        raise HTTPException(status_code=403, detail="Turnstile verification failed.")


# ─── Routes ───────────────────────────────────────────────────────────────

@router.post("/triage")
async def public_triage(req: TriageRequest, request: Request) -> dict:
    """
    Public alert-triage demo.

    No authentication. Rate-limited per IP. Daily platform spend cap applies.
    Alert payload is not stored anywhere — only request counters survive.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Demo service temporarily unavailable.")

    client_ip = _get_client_ip(request)

    await _verify_turnstile(req.turnstile_token, client_ip)

    if req.alert is None or (isinstance(req.alert, str) and not req.alert.strip()):
        raise HTTPException(status_code=400, detail="Alert payload is required.")

    try:
        result = await public_triage_service.triage_demo_alert(
            alert_payload=req.alert,
            client_ip=client_ip,
            db_pool=postgres_db.pool,
        )
    except InputTooLarge as e:
        raise HTTPException(status_code=e.status_code, detail=str(e) or e.message)
    except PublicTriageError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e) or e.message)
    except Exception as e:
        logger.exception(f"Public triage: unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal error processing triage request.")

    # Tell the user how many requests they have left today (transparency,
    # and lets the frontend disable the button after the last one).
    return {
        "ok": True,
        **result,
    }


# ─── Breach / security-news RSS proxy ────────────────────────────────────

import asyncio
import re
import time
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

_FEED_SOURCES = [
    {"name": "BleepingComputer",  "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "CISA Advisories",   "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "DarkReading",       "url": "https://www.darkreading.com/rss.xml"},
]

_FEED_CACHE: dict = {"items": [], "fetched_at": 0.0}
_FEED_TTL_SECONDS = 600  # 10 minutes
_FEED_TIMEOUT_SECONDS = 8

# Crude HTML-tag stripper for description snippets so we don't render
# raw markup. Real feeds tend to embed HTML in <description>.
_HTML_TAG = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def _clean(text: str, max_len: int = 320) -> str:
    text = _HTML_TAG.sub("", text or "")
    text = _WHITESPACE.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def _parse_pubdate(s: str) -> Optional[str]:
    """Normalize RFC 822 dates to ISO 8601 so the frontend can sort easily."""
    if not s:
        return None
    try:
        return parsedate_to_datetime(s).isoformat()
    except Exception:
        return None


async def _fetch_feed(session: aiohttp.ClientSession, src: dict) -> list:
    items = []
    try:
        timeout = aiohttp.ClientTimeout(total=_FEED_TIMEOUT_SECONDS)
        async with session.get(
            src["url"],
            headers={"User-Agent": "T1 Agentics Demo Feed Reader (security news aggregator)"},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                logger.info(f"Breach feed: {src['name']} returned {resp.status}")
                return items
            text = await resp.text()
        root = ET.fromstring(text)
        # Support both RSS 2.0 (<item>) and Atom (<entry>) feeds
        for item in root.iter():
            tag = item.tag.split("}")[-1] if "}" in item.tag else item.tag
            if tag not in ("item", "entry"):
                continue
            title_el = next((c for c in item if (c.tag.split("}")[-1] if "}" in c.tag else c.tag) == "title"), None)
            link_el = next((c for c in item if (c.tag.split("}")[-1] if "}" in c.tag else c.tag) == "link"), None)
            date_el = next((c for c in item if (c.tag.split("}")[-1] if "}" in c.tag else c.tag) in ("pubDate", "published", "updated")), None)
            desc_el = next((c for c in item if (c.tag.split("}")[-1] if "}" in c.tag else c.tag) in ("description", "summary", "content")), None)
            title = (title_el.text or "").strip() if title_el is not None else ""
            # Atom <link> uses href attribute; RSS uses inner text
            link = ""
            if link_el is not None:
                link = (link_el.text or link_el.attrib.get("href", "")).strip()
            pub_iso = _parse_pubdate(date_el.text) if (date_el is not None and date_el.text) else None
            description = _clean(desc_el.text if desc_el is not None else "")
            if not title or not link:
                continue
            items.append({
                "source": src["name"],
                "title": title,
                "link": link,
                "publishedAt": pub_iso,
                "summary": description,
            })
            if len(items) >= 12:
                break
    except asyncio.TimeoutError:
        logger.info(f"Breach feed: timeout fetching {src['name']}")
    except ET.ParseError as e:
        logger.info(f"Breach feed: XML parse error from {src['name']}: {e}")
    except Exception as e:
        logger.info(f"Breach feed: unexpected error fetching {src['name']}: {e}")
    return items


@router.get("/breach-feeds")
async def breach_feeds() -> dict:
    """
    Aggregates recent security/breach news from a curated list of public
    RSS feeds. Cached server-side for 10 minutes to avoid hammering the
    sources and to keep response latency low. No persistence — feeds are
    fetched on demand and held only in-process memory.
    """
    now = time.time()
    if _FEED_CACHE["items"] and (now - _FEED_CACHE["fetched_at"] < _FEED_TTL_SECONDS):
        return {
            "items": _FEED_CACHE["items"],
            "sources": [s["name"] for s in _FEED_SOURCES],
            "fetched_at": int(_FEED_CACHE["fetched_at"]),
            "cached": True,
            "ttl_seconds": _FEED_TTL_SECONDS,
        }

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[_fetch_feed(session, s) for s in _FEED_SOURCES])

    items: list = []
    for r in results:
        items.extend(r)
    # Most recent first (items without a published date sink to the bottom)
    items.sort(key=lambda x: x.get("publishedAt") or "", reverse=True)
    items = items[:40]

    _FEED_CACHE["items"] = items
    _FEED_CACHE["fetched_at"] = now

    return {
        "items": items,
        "sources": [s["name"] for s in _FEED_SOURCES],
        "fetched_at": int(now),
        "cached": False,
        "ttl_seconds": _FEED_TTL_SECONDS,
    }


@router.get("/triage/info")
async def triage_info() -> dict:
    """
    Public metadata about the triage demo: limits, model in use, privacy
    promise. Used by the frontend to render the privacy banner and to
    confirm the service is reachable before the user pastes a payload.
    """
    return {
        "hourly_limit_per_ip": public_triage_service.HOURLY_REQUESTS_PER_IP,
        "daily_limit_per_ip": public_triage_service.DAILY_REQUESTS_PER_IP,
        "max_input_bytes": public_triage_service.MAX_INPUT_BYTES,
        "model": public_triage_service.DEMO_MODEL,
        "turnstile_required": TURNSTILE_ENABLED,
        "privacy": (
            "Your alert payload is sent to T1's AI for analysis and is never "
            "stored on disk, written to a database, or included in logs. Only "
            "anonymized request counters are kept for rate limiting."
        ),
    }
