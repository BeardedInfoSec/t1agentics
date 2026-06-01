# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
AI Provider Resolver

Single source of truth for "which key + endpoint + model does this tenant
use for a given AI call?". Returns a ChatContext or EmbeddingContext that
both claude_service and the legacy ai_triage_service can consume.

Effective BYO requires all three:
  byo_allowed     (platform admin gated this tenant in)
  byo_enabled     (tenant admin turned it on)
  *_api_key_encrypted IS NOT NULL  (tenant actually supplied a key)

When any of those is false the resolver returns mode='platform' and the
caller uses the existing env-key path with the platform daily cap and
per-tenant quota in effect.

Per-process cache (60s TTL) avoids hammering the DB on every triage call.
The cache invalidates on PUT via tenant_ai_config_service.on_invalidate().
"""

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from services import tenant_ai_config_service as cfg_svc
from services.credentials_service import CredentialsVault

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60


@dataclass
class ChatContext:
    mode: str                       # 'platform' | 'byo'
    provider: str                   # 'anthropic' | 'openai' | 'self_hosted'
    api_style: str                  # 'anthropic' | 'openai' — request shape selector
    api_key: str                    # decrypted (or env-loaded for platform)
    model: Optional[str]            # None = caller's default
    base_url: Optional[str]         # None = provider default
    count_quota: bool               # True = platform-billed; False = tenant-billed
    max_tokens: Optional[int] = None  # BYO override; None = caller's default


@dataclass
class EmbeddingContext:
    mode: str                       # 'platform' | 'byo' | 'disabled'
    provider: str                   # 'openai' | 'self_hosted' | 'disabled'
    api_key: Optional[str]          # decrypted; None for platform/disabled
    model: Optional[str]
    base_url: Optional[str]
    dimensions: Optional[int]


_vault: Optional[CredentialsVault] = None
_cache: dict = {}                   # tenant_id -> (expires_at, raw_row)


def _get_vault() -> CredentialsVault:
    global _vault
    if _vault is None:
        _vault = CredentialsVault()
    return _vault


def _invalidate(tenant_id: str) -> None:
    _cache.pop(str(tenant_id), None)


cfg_svc.on_invalidate(_invalidate)


async def _load_row(tenant_id: Optional[str]) -> dict:
    if not tenant_id:
        return cfg_svc._empty()
    key = str(tenant_id)
    now = time.time()
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]
    row = await cfg_svc.get_raw(tenant_id)
    _cache[key] = (now + CACHE_TTL_SECONDS, row)
    return row


def _platform_chat() -> ChatContext:
    return ChatContext(
        mode="platform",
        provider="anthropic",
        api_style="anthropic",
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        model=os.environ.get("CLAUDE_DEFAULT_MODEL"),
        base_url=None,
        count_quota=True,
    )


def _byo_effective(row: dict) -> bool:
    return bool(
        row.get("byo_allowed")
        and row.get("byo_enabled")
        and row.get("chat_api_key_encrypted")
        and row.get("chat_provider")
    )


def _embed_byo_effective(row: dict) -> bool:
    return bool(
        row.get("byo_allowed")
        and row.get("byo_enabled")
        and row.get("embed_provider")
        and row.get("embed_provider") != "disabled"
        and (row.get("embed_api_key_encrypted") or row.get("embed_provider") == "self_hosted")
    )


def _resolve_api_style(provider: str, configured_style: Optional[str]) -> str:
    """anthropic → anthropic, openai → openai, self_hosted → configured or default openai."""
    if provider == "anthropic":
        return "anthropic"
    if provider == "openai":
        return "openai"
    if provider == "self_hosted":
        return configured_style or "openai"
    return "anthropic"


async def resolve_chat(tenant_id: Optional[str]) -> ChatContext:
    """Resolve chat/triage provider for a tenant. Falls back to platform on any failure."""
    try:
        row = await _load_row(tenant_id)
    except Exception as e:
        logger.warning(f"ai_provider_resolver: row load failed for {tenant_id}: {e}")
        return _platform_chat()

    if not _byo_effective(row):
        return _platform_chat()

    try:
        plain_key = _get_vault().decrypt(row["chat_api_key_encrypted"]) if row.get("chat_api_key_encrypted") else ""
    except Exception as e:
        logger.warning(f"ai_provider_resolver: key decrypt failed for {tenant_id}: {e}")
        return _platform_chat()

    if not plain_key:
        # Decryption returned empty (corrupt ciphertext) — safer to fall back
        # to platform than to send blank Authorization headers.
        return _platform_chat()

    provider = row["chat_provider"]
    return ChatContext(
        mode="byo",
        provider=provider,
        api_style=_resolve_api_style(provider, row.get("chat_api_style")),
        api_key=plain_key,
        model=row.get("chat_model"),
        base_url=row.get("chat_base_url"),
        count_quota=False,
        max_tokens=row.get("chat_max_tokens"),
    )


async def resolve_embeddings(tenant_id: Optional[str]) -> Optional[EmbeddingContext]:
    """
    Resolve embeddings provider for a tenant.

    Returns None when there's no per-tenant embedding config — the caller
    keeps doing whatever it does today (OpenAI-via-env or MiniLM fallback).
    """
    try:
        row = await _load_row(tenant_id)
    except Exception:
        return None

    if not _embed_byo_effective(row):
        if row.get("embed_provider") == "disabled":
            return EmbeddingContext(
                mode="disabled", provider="disabled",
                api_key=None, model=None, base_url=None, dimensions=None,
            )
        return None

    enc = row.get("embed_api_key_encrypted")
    plain_key: Optional[str] = None
    if enc:
        try:
            plain_key = _get_vault().decrypt(enc)
        except Exception as e:
            logger.warning(f"ai_provider_resolver: embed key decrypt failed for {tenant_id}: {e}")
            return None
        if not plain_key:
            return None

    return EmbeddingContext(
        mode="byo",
        provider=row["embed_provider"],
        api_key=plain_key,
        model=row.get("embed_model"),
        base_url=row.get("embed_base_url"),
        dimensions=row.get("embed_dimensions"),
    )
