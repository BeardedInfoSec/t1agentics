# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant AI Config Service

Read/write helpers for `tenant_ai_config` (migration 067). Holds per-tenant
BYO LLM configuration: chat provider + key (Anthropic/OpenAI/self-hosted)
and optionally embeddings provider + key. Keys are encrypted with the
shared CredentialsVault Fernet helper before they touch the database;
decryption is only ever performed by the resolver in the hot path.

Two flags both must be true for BYO to take effect:
- byo_allowed: written by platform admin (T1) only
- byo_enabled: written by tenant admin
"""

import logging
from typing import Any, Dict, Optional

from services.credentials_service import CredentialsVault

logger = logging.getLogger(__name__)

VALID_CHAT_PROVIDERS = {"anthropic", "openai", "self_hosted"}
VALID_CHAT_API_STYLES = {"anthropic", "openai"}
VALID_EMBED_PROVIDERS = {"openai", "self_hosted", "disabled"}

# Singleton vault — initializing Fernet does a PBKDF2 round-trip when the
# explicit key isn't set, so we don't want to do it per-call.
_vault: Optional[CredentialsVault] = None


def _get_vault() -> CredentialsVault:
    global _vault
    if _vault is None:
        _vault = CredentialsVault()
    return _vault


def _empty() -> Dict[str, Any]:
    return {
        "byo_allowed": False,
        "byo_enabled": False,
        "chat_provider": None,
        "chat_api_key_encrypted": None,
        "chat_model": None,
        "chat_base_url": None,
        "chat_api_style": None,
        "chat_max_tokens": None,
        "embed_provider": None,
        "embed_api_key_encrypted": None,
        "embed_model": None,
        "embed_base_url": None,
        "embed_dimensions": None,
        "last_validated_at": None,
        "last_validation_error": None,
    }


# BYO max-tokens override bounds — too low truncates Riggs JSON, too
# high lets a runaway loop eat the tenant's bill.
MAX_TOKENS_FLOOR = 100
MAX_TOKENS_CEILING = 16000


async def get_raw(tenant_id: Optional[str]) -> Dict[str, Any]:
    """Fetch the full encrypted row. Used by the resolver, never by routes."""
    if not tenant_id:
        return _empty()
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected:
            return _empty()
        async with postgres_db.tenant_acquire() as conn:
            try:
                await conn.execute("SET app.is_platform_admin = 'true'")
            except Exception:
                pass
            row = await conn.fetchrow(
                "SELECT byo_allowed, byo_enabled, "
                "chat_provider, chat_api_key_encrypted, chat_model, chat_base_url, chat_api_style, chat_max_tokens, "
                "embed_provider, embed_api_key_encrypted, embed_model, embed_base_url, embed_dimensions, "
                "last_validated_at, last_validation_error "
                "FROM tenant_ai_config WHERE tenant_id = $1::uuid",
                str(tenant_id),
            )
    except Exception as e:
        logger.debug(f"tenant_ai_config fetch failed for {tenant_id}: {e}")
        return _empty()
    if not row:
        return _empty()
    return dict(row)


def to_safe_view(raw: Dict[str, Any]) -> Dict[str, Any]:
    """API-safe view: encrypted columns redacted to 'set' | 'unset' booleans."""
    chat_set = bool(raw.get("chat_api_key_encrypted"))
    embed_set = bool(raw.get("embed_api_key_encrypted"))
    last_val = raw.get("last_validated_at")
    return {
        "byo_allowed": bool(raw.get("byo_allowed")),
        "byo_enabled": bool(raw.get("byo_enabled")),
        "chat_provider": raw.get("chat_provider"),
        "chat_key_status": "set" if chat_set else "unset",
        "chat_model": raw.get("chat_model"),
        "chat_base_url": raw.get("chat_base_url"),
        "chat_api_style": raw.get("chat_api_style"),
        "chat_max_tokens": raw.get("chat_max_tokens"),
        "embed_provider": raw.get("embed_provider"),
        "embed_key_status": "set" if embed_set else "unset",
        "embed_model": raw.get("embed_model"),
        "embed_base_url": raw.get("embed_base_url"),
        "embed_dimensions": raw.get("embed_dimensions"),
        "last_validated_at": last_val.isoformat() if last_val and hasattr(last_val, "isoformat") else last_val,
        "last_validation_error": raw.get("last_validation_error"),
    }


async def get_safe_for_tenant(tenant_id: str) -> Dict[str, Any]:
    raw = await get_raw(tenant_id)
    return to_safe_view(raw)


async def set_byo_allowed(
    tenant_id: str,
    allowed: bool,
    *,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Platform-admin-only: flip the gate. Auth enforced at the route layer."""
    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        await conn.execute(
            """
            INSERT INTO tenant_ai_config (tenant_id, byo_allowed, updated_at, updated_by)
            VALUES ($1::uuid, $2, NOW(), $3)
            ON CONFLICT (tenant_id) DO UPDATE
                SET byo_allowed = EXCLUDED.byo_allowed,
                    updated_at  = NOW(),
                    updated_by  = EXCLUDED.updated_by
            """,
            tenant_id, bool(allowed), updated_by,
        )
    invalidate_cache(tenant_id)
    return await get_safe_for_tenant(tenant_id)


async def upsert_tenant_config(
    tenant_id: str,
    *,
    byo_enabled: Optional[bool] = None,
    chat_provider: Optional[str] = None,
    chat_api_key: Optional[str] = None,         # plaintext; encrypted before write
    chat_model: Optional[str] = None,
    chat_base_url: Optional[str] = None,
    chat_api_style: Optional[str] = None,
    chat_max_tokens: Optional[int] = None,
    embed_provider: Optional[str] = None,
    embed_api_key: Optional[str] = None,        # plaintext; encrypted before write
    embed_model: Optional[str] = None,
    embed_base_url: Optional[str] = None,
    embed_dimensions: Optional[int] = None,
    last_validated_at=None,
    last_validation_error: Optional[str] = None,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tenant-admin upsert. Cannot change byo_allowed — that's platform-admin only.
    Passing an api_key of "" (empty string) clears the stored key; None leaves
    it unchanged. This lets the UI distinguish "user typed nothing" from
    "user explicitly wants to remove the key".
    """
    if chat_provider is not None and chat_provider not in VALID_CHAT_PROVIDERS:
        raise ValueError(f"invalid chat_provider: {chat_provider}")
    if chat_api_style is not None and chat_api_style not in VALID_CHAT_API_STYLES:
        raise ValueError(f"invalid chat_api_style: {chat_api_style}")
    if embed_provider is not None and embed_provider not in VALID_EMBED_PROVIDERS:
        raise ValueError(f"invalid embed_provider: {embed_provider}")

    vault = _get_vault()

    # COALESCE semantics: anything passed as None leaves the column untouched.
    # Encrypted keys: None = leave alone, "" = clear, anything else = encrypt
    # and store.
    def _key_arg(plaintext: Optional[str]) -> Optional[str]:
        if plaintext is None:
            return None
        if plaintext == "":
            return ""   # sentinel for "clear" — caller handles via COALESCE-aware SQL
        return vault.encrypt(plaintext)

    chat_enc = _key_arg(chat_api_key)
    embed_enc = _key_arg(embed_api_key)

    # Clamp max_tokens to safe bounds. None leaves the column untouched.
    if chat_max_tokens is not None:
        chat_max_tokens = max(MAX_TOKENS_FLOOR, min(MAX_TOKENS_CEILING, int(chat_max_tokens)))

    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        # Build dynamic UPDATE so unset args stay untouched (vs forcing NULL).
        await conn.execute(
            """
            INSERT INTO tenant_ai_config (
                tenant_id, byo_enabled,
                chat_provider, chat_api_key_encrypted, chat_model, chat_base_url, chat_api_style, chat_max_tokens,
                embed_provider, embed_api_key_encrypted, embed_model, embed_base_url, embed_dimensions,
                last_validated_at, last_validation_error, updated_at, updated_by
            )
            VALUES (
                $1::uuid,
                COALESCE($2, FALSE),
                $3, NULLIF($4, ''), $5, $6, $7, $8,
                $9, NULLIF($10, ''), $11, $12, $13,
                $14, $15, NOW(), $16
            )
            ON CONFLICT (tenant_id) DO UPDATE SET
                byo_enabled             = COALESCE($2, tenant_ai_config.byo_enabled),
                chat_provider           = COALESCE($3, tenant_ai_config.chat_provider),
                chat_api_key_encrypted  = CASE
                                            WHEN $4 IS NULL          THEN tenant_ai_config.chat_api_key_encrypted
                                            WHEN $4 = ''             THEN NULL
                                            ELSE $4
                                          END,
                chat_model              = COALESCE($5, tenant_ai_config.chat_model),
                chat_base_url           = COALESCE($6, tenant_ai_config.chat_base_url),
                chat_api_style          = COALESCE($7, tenant_ai_config.chat_api_style),
                chat_max_tokens         = COALESCE($8, tenant_ai_config.chat_max_tokens),
                embed_provider          = COALESCE($9, tenant_ai_config.embed_provider),
                embed_api_key_encrypted = CASE
                                            WHEN $10 IS NULL         THEN tenant_ai_config.embed_api_key_encrypted
                                            WHEN $10 = ''            THEN NULL
                                            ELSE $10
                                          END,
                embed_model             = COALESCE($11, tenant_ai_config.embed_model),
                embed_base_url          = COALESCE($12, tenant_ai_config.embed_base_url),
                embed_dimensions        = COALESCE($13, tenant_ai_config.embed_dimensions),
                last_validated_at       = COALESCE($14, tenant_ai_config.last_validated_at),
                last_validation_error   = $15,
                updated_at              = NOW(),
                updated_by              = COALESCE($16, tenant_ai_config.updated_by)
            """,
            tenant_id,
            byo_enabled,
            chat_provider, chat_enc, chat_model, chat_base_url, chat_api_style, chat_max_tokens,
            embed_provider, embed_enc, embed_model, embed_base_url, embed_dimensions,
            last_validated_at, last_validation_error,
            updated_by,
        )
    invalidate_cache(tenant_id)
    return await get_safe_for_tenant(tenant_id)


# ── BYO usage tracking (writes to tenant_byo_usage) ─────────────────────────

async def record_byo_usage(
    tenant_id: str,
    *,
    provider: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
) -> None:
    """Upsert a row in tenant_byo_usage keyed on (tenant, current period, provider)."""
    from datetime import datetime
    from services.postgres_db import postgres_db

    if not tenant_id:
        return
    period = datetime.utcnow().strftime("%Y-%m")
    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            await conn.execute(
                """
                INSERT INTO tenant_byo_usage
                    (tenant_id, period, provider, request_count,
                     prompt_tokens, completion_tokens, total_tokens, last_request_at)
                VALUES ($1::uuid, $2, $3, 1, $4, $5, $6, NOW())
                ON CONFLICT (tenant_id, period, provider) DO UPDATE SET
                    request_count     = tenant_byo_usage.request_count + 1,
                    prompt_tokens     = tenant_byo_usage.prompt_tokens + EXCLUDED.prompt_tokens,
                    completion_tokens = tenant_byo_usage.completion_tokens + EXCLUDED.completion_tokens,
                    total_tokens      = tenant_byo_usage.total_tokens + EXCLUDED.total_tokens,
                    last_request_at   = NOW(),
                    updated_at        = NOW()
                """,
                tenant_id, period, provider,
                int(prompt_tokens or 0), int(completion_tokens or 0), int(total_tokens or 0),
            )
    except Exception as e:
        # Usage tracking must never break a successful inference call.
        logger.warning(f"tenant_byo_usage record failed: {e}")


async def get_usage_for_tenant(tenant_id: str, period: Optional[str] = None) -> Dict[str, Any]:
    """Return BYO usage for the period (default: current month)."""
    from datetime import datetime
    from services.postgres_db import postgres_db

    if not period:
        period = datetime.utcnow().strftime("%Y-%m")
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                "SELECT provider, request_count, prompt_tokens, completion_tokens, "
                "total_tokens, last_request_at "
                "FROM tenant_byo_usage WHERE tenant_id = $1::uuid AND period = $2",
                str(tenant_id), period,
            )
    except Exception:
        rows = []
    return {
        "period": period,
        "providers": [
            {
                "provider": r["provider"],
                "request_count": r["request_count"],
                "prompt_tokens": r["prompt_tokens"],
                "completion_tokens": r["completion_tokens"],
                "total_tokens": r["total_tokens"],
                "last_request_at": r["last_request_at"].isoformat()
                    if r["last_request_at"] else None,
            } for r in rows
        ],
    }


# ── Cache invalidation hook used by the resolver ───────────────────────────

_invalidate_listeners = []


def on_invalidate(callback) -> None:
    """Resolver registers here so it can drop its per-process cache."""
    _invalidate_listeners.append(callback)


def invalidate_cache(tenant_id: str) -> None:
    for cb in _invalidate_listeners:
        try:
            cb(tenant_id)
        except Exception:
            pass
