# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Claude API Service

Central wrapper for all Claude API calls. All AI requests from tenants
are routed through this service, which handles:
- Platform API key management (operator-provided; no default)
- Pre-call quota enforcement against tenant's managed_tokens_per_month
- Token tracking with tenant_id for per-tenant usage accounting
- Monthly usage cache updates
"""

import os
import time
import uuid
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any
from uuid import UUID
from decimal import Decimal

import aiohttp

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_DEFAULT_MODEL = os.environ.get("CLAUDE_DEFAULT_MODEL", "claude-sonnet-4-5-20250929")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"


# ── Response Model ────────────────────────────────────────────────────────────

@dataclass
class ClaudeResponse:
    """Response from a Claude API call.

    ``input_tokens`` is the full context size (non-cached + cache write +
    cache read) so quota accounting stays in "context tokens consumed".
    ``cost_cents`` reflects the actual Anthropic bill, which is cheaper
    when prompt caching hits (cache reads at 10% of input rate, cache
    writes at 125%). The cache_* fields are exposed for observability
    so we can verify the cache hit rate after deploys.
    """
    text: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_cents: float
    model: str
    response_time_ms: int
    quota_warning: Optional[str] = None       # Set when approaching limit
    cache_creation_tokens: int = 0            # Tokens written to ephemeral cache (1.25x cost)
    cache_read_tokens: int = 0                # Tokens served from cache (0.1x cost)


class QuotaExceededError(Exception):
    """Raised when a tenant has exhausted their token allowance,
    or when the global platform daily ceiling is hit (tenant_id=None)."""
    def __init__(self, tenant_id: Optional[UUID], used: int, limit: int):
        self.tenant_id = tenant_id
        self.used = used
        self.limit = limit
        if tenant_id is None:
            super().__init__(
                f"Platform daily Claude spend ceiling reached: "
                f"${used/100:.2f}/${limit/100:.2f} today"
            )
        else:
            super().__init__(
                f"Token quota exceeded for tenant {tenant_id}: "
                f"{used:,}/{limit:,} tokens used this month"
            )


# ── Claude Service ────────────────────────────────────────────────────────────

class ClaudeService:
    """
    Central Claude API wrapper for all tenant AI calls.

    Usage:
        service = await get_claude_service()
        response = await service.complete(
            tenant_id=uuid, prompt="Analyze this alert...",
            request_type="triage"
        )
    """

    def __init__(self):
        self._api_key = ANTHROPIC_API_KEY
        self._default_model = CLAUDE_DEFAULT_MODEL

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def complete(
        self,
        tenant_id: UUID,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 2000,
        temperature: float = 0.1,
        request_type: str = "triage",
        user_id: Optional[UUID] = None,
        alert_id: Optional[UUID] = None,
        investigation_id: Optional[UUID] = None,
    ) -> ClaudeResponse:
        """
        Send a completion request to Claude via the platform API key.

        Args:
            tenant_id: The tenant making the request (for quota/billing).
            prompt: The user prompt.
            system: Optional system prompt.
            model: Override model (defaults to CLAUDE_DEFAULT_MODEL).
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.
            request_type: Purpose label (triage, investigation, playbook, etc.).
            user_id: The user making the request.
            alert_id: Associated alert.
            investigation_id: Associated investigation.

        Returns:
            ClaudeResponse with text, token counts, and cost.

        Raises:
            QuotaExceededError: If tenant has no remaining allowance.
            RuntimeError: If the API key is not configured.
        """
        # ── 0. Resolve provider for this tenant (BYO or platform) ────────
        # When BYO is effective we use the tenant's own key / endpoint /
        # model and skip platform quota checks; BYO calls are billed by
        # the tenant's provider, not T1.
        from services import ai_provider_resolver
        ctx = await ai_provider_resolver.resolve_chat(tenant_id)

        if ctx.mode == "platform" and not ctx.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not configured. "
                "Set the environment variable to enable Claude API calls."
            )

        # BYO tenants pick their own model; the platform allowlist only
        # protects T1's pooled key spend. For BYO, ctx.model from the
        # tenant config takes precedence over the caller's `model` arg
        # since the tenant explicitly chose it.
        if ctx.mode == "byo":
            use_model = model or ctx.model or self._default_model
            # BYO max_tokens override: only apply when the tenant set one
            # explicitly. Keeps callers in control by default; lets the
            # tenant raise the ceiling on their own bill when they need it.
            if ctx.max_tokens:
                max_tokens = ctx.max_tokens
        else:
            use_model = model or self._default_model
            ALLOWED_MODELS = frozenset({
                "claude-sonnet-4-5-20250929", "claude-opus-4-6",
                "claude-3-haiku", "claude-haiku-4-5-20251001",
                "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
            })
            if use_model not in ALLOWED_MODELS:
                raise ValueError(f"Model '{use_model}' is not in the allowed model list.")

        # ── 1. Platform-only quota gates ──────────────────────────────────
        # BYO calls bypass these — the tenant is on their own bill, so the
        # platform daily ceiling and monthly per-tenant quota don't apply.
        quota_info: Optional[Dict[str, Any]] = None
        if ctx.count_quota:
            try:
                await self._check_global_daily_ceiling()
            except QuotaExceededError:
                raise
            except Exception as e:
                logger.warning(f"Global daily ceiling check failed (allowing call): {e}")

            quota_info = await self._check_quota(tenant_id)
            if quota_info["status"] in ("blocked", "exceeded"):
                raise QuotaExceededError(
                    tenant_id, quota_info["used"], quota_info["limit"]
                )

        # ── 2. Dispatch by API style ─────────────────────────────────────
        start_time = time.time()
        try:
            if ctx.api_style == "anthropic":
                result = await self._call_anthropic_api(
                    ctx, use_model, prompt, system, max_tokens, temperature,
                )
            else:
                result = await self._call_openai_api(
                    ctx, use_model, prompt, system, max_tokens, temperature,
                )
        except aiohttp.ClientError as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"[claude/{request_type}] Connection error: {e}")
            if ctx.count_quota:
                # Only platform calls write to ai_token_usage (the table
                # the daily-ceiling query reads). BYO failures are the
                # tenant's problem and not platform-relevant.
                await self._track_usage(
                    tenant_id=tenant_id, model=use_model,
                    input_tokens=0, output_tokens=0, cost_cents=0,
                    request_type=request_type, user_id=user_id,
                    alert_id=alert_id, investigation_id=investigation_id,
                    status="failed", response_time_ms=response_time_ms,
                    error_message=str(e),
                )
            raise RuntimeError(f"AI provider connection error ({ctx.provider}): {e}")
        except RuntimeError as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            if ctx.count_quota:
                await self._track_usage(
                    tenant_id=tenant_id, model=use_model,
                    input_tokens=0, output_tokens=0, cost_cents=0,
                    request_type=request_type, user_id=user_id,
                    alert_id=alert_id, investigation_id=investigation_id,
                    status="failed", response_time_ms=response_time_ms,
                    error_message=str(e)[:200],
                )
            raise

        response_time_ms = int((time.time() - start_time) * 1000)

        # ── 3. Cost estimation (platform only — we pay that bill) ────────
        cost_cents = 0.0
        if ctx.count_quota:
            cost_cents = self._estimate_cost(
                use_model,
                input_tokens=result["base_input_tokens"],
                output_tokens=result["output_tokens"],
                cache_creation_tokens=result["cache_creation_tokens"],
                cache_read_tokens=result["cache_read_tokens"],
            )

        cache_note = ""
        if result["cache_read_tokens"] or result["cache_creation_tokens"]:
            total_in = (
                result["base_input_tokens"]
                + result["cache_creation_tokens"]
                + result["cache_read_tokens"]
            )
            hit_rate = (result["cache_read_tokens"] / total_in * 100) if total_in else 0
            cache_note = (
                f" [cache: read={result['cache_read_tokens']}, "
                f"create={result['cache_creation_tokens']}, hit={hit_rate:.0f}%]"
            )
        mode_tag = "byo" if ctx.mode == "byo" else "platform"
        logger.info(
            f"[claude/{request_type}/{mode_tag}/{ctx.provider}] OK: "
            f"{result['input_tokens']}+{result['output_tokens']}={result['total_tokens']} "
            f"tokens, ${cost_cents/100:.4f}, {response_time_ms}ms{cache_note}"
        )

        # ── 4-6. Tracking diverges between platform and BYO ──────────────
        if ctx.count_quota:
            await self._track_usage(
                tenant_id=tenant_id, model=use_model,
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
                cost_cents=cost_cents,
                request_type=request_type, user_id=user_id,
                alert_id=alert_id, investigation_id=investigation_id,
                status="success", response_time_ms=response_time_ms,
            )
            await self._update_monthly_cache(
                tenant_id, result["input_tokens"], result["output_tokens"], cost_cents,
                message_id=result.get("message_id"),
            )
            # OSS build: no commercial overage reporting. Quota status
            # is surfaced to the caller but not billed.
        else:
            try:
                from services import tenant_ai_config_service as _cfg_svc
                await _cfg_svc.record_byo_usage(
                    tenant_id=str(tenant_id),
                    provider=ctx.provider,
                    prompt_tokens=result["input_tokens"],
                    completion_tokens=result["output_tokens"],
                    total_tokens=result["total_tokens"],
                )
            except Exception as e:
                logger.warning(f"BYO usage tracking failed (call succeeded): {e}")

        quota_warning = None
        if quota_info and quota_info["status"] == "warning":
            quota_warning = (
                f"Approaching token limit: {quota_info['used']:,}/"
                f"{quota_info['limit']:,} ({quota_info['percent']:.0f}%)"
            )

        return ClaudeResponse(
            text=result["text"],
            input_tokens=result["input_tokens"],
            output_tokens=result["output_tokens"],
            total_tokens=result["total_tokens"],
            cost_cents=cost_cents,
            model=use_model,
            response_time_ms=response_time_ms,
            quota_warning=quota_warning,
            cache_creation_tokens=result["cache_creation_tokens"],
            cache_read_tokens=result["cache_read_tokens"],
        )

    # ── HTTP dispatch helpers (per api_style) ─────────────────────────────

    async def _call_anthropic_api(
        self,
        ctx,
        use_model: str,
        prompt: str,
        system: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        """POST /v1/messages against Anthropic-shape endpoints (Anthropic, Anthropic-compat proxies)."""
        base = (ctx.base_url or "https://api.anthropic.com").rstrip("/")
        url = f"{base}/v1/messages"
        headers = {
            "x-api-key": ctx.api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "content-type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": use_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = [{
                "type": "text", "text": system,
                "cache_control": {"type": "ephemeral"},
            }]
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=max(120, max_tokens // 5)),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"Anthropic API {resp.status}: {error_text[:200]}")
                data = await resp.json()

        text = ""
        for block in data.get("content", []) or []:
            if block.get("type") == "text":
                text += block.get("text", "")
        usage = data.get("usage", {})
        base_in = int(usage.get("input_tokens", 0) or 0)
        cache_create = int(usage.get("cache_creation_input_tokens", 0) or 0)
        cache_read = int(usage.get("cache_read_input_tokens", 0) or 0)
        out = int(usage.get("output_tokens", 0) or 0)
        input_total = base_in + cache_create + cache_read
        return {
            "text": text,
            "base_input_tokens": base_in,
            "cache_creation_tokens": cache_create,
            "cache_read_tokens": cache_read,
            "input_tokens": input_total,
            "output_tokens": out,
            "total_tokens": input_total + out,
            "message_id": data.get("id"),
        }

    async def _call_openai_api(
        self,
        ctx,
        use_model: str,
        prompt: str,
        system: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        """POST /v1/chat/completions against OpenAI-shape endpoints (OpenAI, LM Studio, vLLM, Ollama)."""
        base = (ctx.base_url or "https://api.openai.com").rstrip("/")
        url = f"{base}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {ctx.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: Dict[str, Any] = {
            "model": use_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=max(120, max_tokens // 5)),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"OpenAI API {resp.status}: {error_text[:200]}")
                data = await resp.json()

        text = ""
        choices = data.get("choices") or []
        if choices:
            text = (choices[0].get("message") or {}).get("content", "") or ""
        usage = data.get("usage", {}) or {}
        pt = int(usage.get("prompt_tokens", 0) or 0)
        ct = int(usage.get("completion_tokens", 0) or 0)
        tt = int(usage.get("total_tokens", pt + ct) or (pt + ct))
        return {
            "text": text,
            "base_input_tokens": pt,
            "cache_creation_tokens": 0,
            "cache_read_tokens": 0,
            "input_tokens": pt,
            "output_tokens": ct,
            "total_tokens": tt,
            "message_id": data.get("id"),
        }

    # ── Internal Methods ──────────────────────────────────────────────────

    def _estimate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_creation_tokens: int = 0,
        cache_read_tokens: int = 0,
    ) -> float:
        """Estimate cost in USD cents based on model pricing.

        ``input_tokens`` here is non-cached input only. Cache reads and
        cache writes are billed separately by Anthropic:
            cache write  = 1.25x input rate (one-time per cache entry)
            cache read   = 0.10x input rate (every cached call within TTL)
        """
        # Per-1K-token pricing (cents)
        pricing = {
            "claude-sonnet-4-5-20250929": {"input": 0.3, "output": 1.5},
            "claude-sonnet-4-5": {"input": 0.3, "output": 1.5},
            "claude-opus-4-6": {"input": 1.5, "output": 7.5},
            "claude-3-5-sonnet": {"input": 0.3, "output": 1.5},
            "claude-3-opus": {"input": 1.5, "output": 7.5},
            "claude-3-haiku": {"input": 0.025, "output": 0.125},
        }

        model_lower = model.lower()
        costs = None
        for key, val in pricing.items():
            if key in model_lower or model_lower.startswith(key):
                costs = val
                break

        if not costs:
            costs = {"input": 0.3, "output": 1.5}  # Default to Sonnet pricing

        input_rate = Decimal(str(costs["input"])) / Decimal(1000)
        output_rate = Decimal(str(costs["output"])) / Decimal(1000)
        cache_write_rate = input_rate * Decimal("1.25")
        cache_read_rate = input_rate * Decimal("0.1")

        total = (
            input_rate * Decimal(input_tokens)
            + output_rate * Decimal(output_tokens)
            + cache_write_rate * Decimal(cache_creation_tokens)
            + cache_read_rate * Decimal(cache_read_tokens)
        )
        return float(total)

    async def _check_global_daily_ceiling(self) -> None:
        """Reject the call if total platform-wide Claude spend for the
        current UTC day already exceeds CLAUDE_MAX_DAILY_USD.

        This is a safety backstop, NOT a per-tenant quota. It exists so
        a sudden flood of free-tier signups (or a single tenant abusing
        BYO model entitlements) cannot bankrupt the platform overnight.

        Defaults to $25/day. Set via CLAUDE_MAX_DAILY_USD env var.
        Set to 0 to disable.
        """
        max_daily = float(os.getenv("CLAUDE_MAX_DAILY_USD", "25") or "25")
        if max_daily <= 0:
            return

        try:
            from services.postgres_db import postgres_db
            if not postgres_db.connected or postgres_db.pool is None:
                return

            async with postgres_db.pool.acquire() as conn:
                cents = await conn.fetchval(
                    """
                    SELECT COALESCE(SUM(estimated_cost_cents), 0)
                    FROM ai_token_usage
                    WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC')
                    """
                )
            today_usd = float(cents or 0) / 100.0
            if today_usd >= max_daily:
                logger.error(
                    f"[CLAUDE_KILL_SWITCH] Daily platform Claude spend "
                    f"${today_usd:.2f} >= ceiling ${max_daily:.2f}. Rejecting all calls until UTC midnight."
                )
                # Use QuotaExceededError so callers handle it the same as
                # tenant-level quota exhaustion.
                raise QuotaExceededError(
                    tenant_id=None,
                    used=int(today_usd * 100),
                    limit=int(max_daily * 100),
                )
        except QuotaExceededError:
            raise
        except Exception as e:
            # Fail open so a DB hiccup doesn't take Riggs down entirely.
            logger.warning(f"[CLAUDE_KILL_SWITCH] Check errored, allowing call: {e}")

    async def _check_quota(self, tenant_id: UUID) -> Dict[str, Any]:
        """
        Check tenant's token quota against their license tier.

        Returns:
            {"status": "ok"|"warning"|"overage"|"blocked",
             "used": int, "limit": int, "percent": float}
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected or postgres_db.pool is None:
                return {"status": "ok", "used": 0, "limit": 999999999, "percent": 0}

            async with postgres_db.pool.acquire() as conn:
                # Get current month usage from cache
                row = await conn.fetchrow(
                    """
                    SELECT total_tokens FROM tenant_claude_usage
                    WHERE tenant_id = $1
                      AND month_start = date_trunc('month', CURRENT_DATE)::date
                    """,
                    tenant_id,
                )
                used = row["total_tokens"] if row else 0

                # Get tier limit from license
                limit = await self._get_tenant_token_limit(conn, tenant_id)

                if limit <= 0:
                    # Unlimited or uncapped
                    return {"status": "ok", "used": used, "limit": limit, "percent": 0}

                percent = (used / limit) * 100 if limit > 0 else 0

                # OSS build: no commercial overage billing path. Hard-block
                # at the quota ceiling. Operators can lift the quota in the
                # license/entitlements record.
                if percent >= 100:
                    return {"status": "blocked", "used": used, "limit": limit, "percent": percent}
                elif percent >= 80:
                    return {"status": "warning", "used": used, "limit": limit, "percent": percent}
                else:
                    return {"status": "ok", "used": used, "limit": limit, "percent": percent}

        except Exception as e:
            logger.error(f"Quota check failed (denying request): {e}")
            return {"status": "exceeded", "used": 0, "limit": 0, "percent": 100, "error": "Quota check unavailable"}

    async def _get_tenant_token_limit(self, conn, tenant_id: UUID) -> int:
        """Get managed_tokens_per_month for tenant's license tier."""
        from services.licensing.default_plans import get_default_entitlements
        from services.licensing.models import LicenseTier

        row = await conn.fetchrow(
            """
            SELECT tl.tier
            FROM tenants t
            JOIN tenant_licenses tl ON t.active_license_id = tl.id
            WHERE t.id = $1
            """,
            tenant_id,
        )

        if not row:
            return 0  # No license → no managed tokens

        tier_str = row["tier"]
        try:
            tier = LicenseTier(tier_str)
        except ValueError:
            tier = LicenseTier.FREE

        entitlements = get_default_entitlements(tier)
        return entitlements.llm.managed_tokens_per_month

    async def _track_usage(
        self,
        tenant_id: UUID,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_cents: float,
        request_type: str,
        user_id: Optional[UUID] = None,
        alert_id: Optional[UUID] = None,
        investigation_id: Optional[UUID] = None,
        status: str = "success",
        response_time_ms: int = 0,
        error_message: Optional[str] = None,
    ):
        """Track usage in ai_token_usage table via TokenTrackingService."""
        try:
            from services.token_tracking import get_token_tracker

            tracker = get_token_tracker()
            await tracker.track(
                provider="anthropic",
                model=model,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                request_type=request_type,
                user_id=str(user_id) if user_id else None,
                alert_id=str(alert_id) if alert_id else None,
                investigation_id=str(investigation_id) if investigation_id else None,
                status=status,
                response_time_ms=response_time_ms,
                error_message=error_message,
                tenant_id=str(tenant_id),
            )
        except Exception as e:
            logger.error(f"Failed to track Claude usage: {e}")

    async def _update_monthly_cache(
        self,
        tenant_id: UUID,
        input_tokens: int,
        output_tokens: int,
        cost_cents: float,
        message_id: Optional[str] = None,
    ):
        """Upsert into tenant_claude_usage for fast quota lookups.

        When `message_id` is supplied (an Anthropic response id), the
        aggregate update is gated on first-time claim of that id in
        tenant_claude_usage_applied_events. Re-processing the same
        response (retry, redelivery, deploy-during-inflight) becomes a
        no-op so the tenant's monthly aggregate doesn't drift upward.

        Calls without a message_id (legacy paths, dev fallback) still
        run unconditionally — the idempotency layer is opt-in and
        backward-compatible.
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected or postgres_db.pool is None:
                return

            async with postgres_db.pool.acquire() as conn:
                if message_id:
                    # Atomically claim the message_id. INSERT ON CONFLICT
                    # DO NOTHING returns NULL if the row already existed.
                    claimed = await conn.fetchval(
                        """
                        INSERT INTO tenant_claude_usage_applied_events
                            (message_id, tenant_id, applied_at)
                        VALUES ($1, $2, NOW())
                        ON CONFLICT (message_id) DO NOTHING
                        RETURNING 1
                        """,
                        message_id,
                        tenant_id,
                    )
                    if not claimed:
                        logger.info(
                            f"Skipping duplicate usage aggregate update "
                            f"for message_id={message_id} (already counted)"
                        )
                        return

                await conn.execute(
                    """
                    INSERT INTO tenant_claude_usage
                        (tenant_id, month_start, total_input_tokens, total_output_tokens,
                         total_tokens, total_cost_cents, updated_at)
                    VALUES ($1, date_trunc('month', CURRENT_DATE)::date, $2, $3, $4, $5, NOW())
                    ON CONFLICT (tenant_id, month_start)
                    DO UPDATE SET
                        total_input_tokens = tenant_claude_usage.total_input_tokens + $2,
                        total_output_tokens = tenant_claude_usage.total_output_tokens + $3,
                        total_tokens = tenant_claude_usage.total_tokens + $4,
                        total_cost_cents = tenant_claude_usage.total_cost_cents + $5,
                        updated_at = NOW()
                    """,
                    tenant_id,
                    input_tokens,
                    output_tokens,
                    input_tokens + output_tokens,
                    cost_cents,
                )
        except Exception as e:
            logger.error(f"Failed to update monthly cache: {e}")

# ── Singleton ─────────────────────────────────────────────────────────────────

import asyncio as _asyncio

_claude_service: Optional[ClaudeService] = None
_claude_service_lock = _asyncio.Lock()


async def get_claude_service() -> ClaudeService:
    """Get the global ClaudeService singleton (async-safe)."""
    global _claude_service
    if _claude_service is None:
        async with _claude_service_lock:
            if _claude_service is None:
                _claude_service = ClaudeService()
    return _claude_service
