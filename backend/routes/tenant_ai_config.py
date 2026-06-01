# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant AI Config API (BYO LLM)

GET   /api/v1/ai-config         current tenant's BYO config (encrypted columns redacted)
PUT   /api/v1/ai-config         tenant-admin upsert (validates key via probe before persisting)
POST  /api/v1/ai-config/test    explicit probe without persisting
GET   /api/v1/ai-config/usage   current period's tenant_byo_usage breakdown

The byo_allowed gate is platform-admin-only and is NOT writable here —
that endpoint lives in routes/platform_admin.py.
"""

import logging
import os
from typing import Any, Dict, Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user
from services import tenant_ai_config_service as svc

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-config",
    tags=["ai-config"],
    dependencies=[Depends(get_current_user)],
)


# ── Request models ───────────────────────────────────────────────────────────


class AIConfigUpdate(BaseModel):
    # All optional — PATCH semantics. Passing "" for a key clears it; None
    # leaves it untouched (so a user can save model changes without
    # re-entering the key).
    byo_enabled: Optional[bool] = None

    chat_provider: Optional[str] = Field(default=None, description="anthropic | openai | self_hosted")
    chat_api_key: Optional[str] = None
    chat_model: Optional[str] = None
    chat_base_url: Optional[str] = None
    chat_api_style: Optional[str] = Field(default=None, description="anthropic | openai (self_hosted only)")

    embed_provider: Optional[str] = Field(default=None, description="openai | self_hosted | disabled")
    embed_api_key: Optional[str] = None
    embed_model: Optional[str] = None
    embed_base_url: Optional[str] = None
    embed_dimensions: Optional[int] = Field(default=None, ge=1, le=8192)


class AIConfigTestRequest(BaseModel):
    target: str = Field(..., description="'chat' | 'embed'")
    provider: str
    api_key: str
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_style: Optional[str] = None  # for self_hosted chat


# ── Helpers ──────────────────────────────────────────────────────────────────


def _is_admin(user: Dict[str, Any]) -> bool:
    role = (user.get("role") or "").lower()
    return role in ("admin", "owner", "platform_admin")


def _require_https_in_prod(url: Optional[str]) -> None:
    if not url:
        return
    if os.getenv("ENVIRONMENT", "").lower() == "production" and not url.lower().startswith("https://"):
        raise HTTPException(
            status_code=400,
            detail="base_url must use https:// in production",
        )


async def _probe_chat(
    provider: str,
    api_key: str,
    model: Optional[str],
    base_url: Optional[str],
    api_style: Optional[str],
) -> None:
    """Send a 1-token round-trip to confirm the key works. Raises HTTPException on failure."""
    style = api_style or ("anthropic" if provider == "anthropic" else "openai")
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        if style == "anthropic":
            url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": model or os.getenv("CLAUDE_DEFAULT_MODEL", "claude-haiku-4-5-20251001"),
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            }
        else:
            url = (base_url or "https://api.openai.com").rstrip("/") + "/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": model or "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            }
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, headers=headers, json=payload) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    raise HTTPException(
                        status_code=400,
                        detail=f"Provider rejected probe ({resp.status}): {body}",
                    )
    except HTTPException:
        raise
    except Exception as e:
        # Never leak the key in error strings.
        raise HTTPException(status_code=400, detail=f"Probe failed: {type(e).__name__}")


async def _probe_embed(
    provider: str,
    api_key: str,
    model: Optional[str],
    base_url: Optional[str],
) -> int:
    """Returns the embedding dimension produced by the provider."""
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        url = (base_url or "https://api.openai.com").rstrip("/") + "/v1/embeddings"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {"input": "ping", "model": model or "text-embedding-3-small"}
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, headers=headers, json=payload) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    raise HTTPException(
                        status_code=400,
                        detail=f"Provider rejected probe ({resp.status}): {body}",
                    )
                data = await resp.json()
        vec = data["data"][0]["embedding"]
        return len(vec)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Embed probe failed: {type(e).__name__}")


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("")
async def get_ai_config(user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return await svc.get_safe_for_tenant(str(tenant_id))


@router.put("")
async def update_ai_config(
    body: AIConfigUpdate,
    user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")

    # byo_allowed is platform-admin gated; refuse to enable if not allowed.
    current = await svc.get_raw(str(tenant_id))
    if body.byo_enabled and not current.get("byo_allowed"):
        raise HTTPException(
            status_code=403,
            detail="BYO LLM is not allowed for this tenant — contact your administrator",
        )

    _require_https_in_prod(body.chat_base_url)
    _require_https_in_prod(body.embed_base_url)

    last_error: Optional[str] = None
    from datetime import datetime
    last_validated_at = None

    # Probe chat if a key was supplied (saving without a key is fine — the
    # user can persist provider/model now and add the key later).
    if body.chat_api_key:
        await _probe_chat(
            provider=body.chat_provider or current.get("chat_provider") or "anthropic",
            api_key=body.chat_api_key,
            model=body.chat_model or current.get("chat_model"),
            base_url=body.chat_base_url or current.get("chat_base_url"),
            api_style=body.chat_api_style or current.get("chat_api_style"),
        )
        last_validated_at = datetime.utcnow()

    embed_dim: Optional[int] = body.embed_dimensions
    if body.embed_api_key and body.embed_provider not in (None, "disabled"):
        embed_dim = await _probe_embed(
            provider=body.embed_provider or current.get("embed_provider") or "openai",
            api_key=body.embed_api_key,
            model=body.embed_model or current.get("embed_model"),
            base_url=body.embed_base_url or current.get("embed_base_url"),
        )
        last_validated_at = datetime.utcnow()

    try:
        return await svc.upsert_tenant_config(
            str(tenant_id),
            byo_enabled=body.byo_enabled,
            chat_provider=body.chat_provider,
            chat_api_key=body.chat_api_key,
            chat_model=body.chat_model,
            chat_base_url=body.chat_base_url,
            chat_api_style=body.chat_api_style,
            embed_provider=body.embed_provider,
            embed_api_key=body.embed_api_key,
            embed_model=body.embed_model,
            embed_base_url=body.embed_base_url,
            embed_dimensions=embed_dim,
            last_validated_at=last_validated_at,
            last_validation_error=last_error,
            updated_by=user.get("user_id") or user.get("id"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/test")
async def test_ai_config(
    body: AIConfigTestRequest,
    user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Run a probe without persisting. Useful for the UI's Test button."""
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    _require_https_in_prod(body.base_url)
    if body.target == "chat":
        await _probe_chat(body.provider, body.api_key, body.model, body.base_url, body.api_style)
        return {"ok": True, "target": "chat"}
    if body.target == "embed":
        dims = await _probe_embed(body.provider, body.api_key, body.model, body.base_url)
        return {"ok": True, "target": "embed", "dimensions": dims}
    raise HTTPException(status_code=400, detail="target must be 'chat' or 'embed'")


@router.get("/usage")
async def get_ai_config_usage(
    period: Optional[str] = None,
    user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Per-period BYO usage breakdown (the tenant's view of their own spend)."""
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return await svc.get_usage_for_tenant(str(tenant_id), period=period)
