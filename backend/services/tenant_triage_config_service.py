# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant Triage Config Service

Read/write helpers for `tenant_triage_config` (migration 066). Holds the
per-tenant auto-close thresholds used by ai_triage_service._should_auto_close.
Falls back to the historical hardcoded defaults if the table is unreachable
or the tenant has never set values.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_MIN_CONFIDENCE = 0.90
DEFAULT_MIN_FP_LIKELIHOOD = 0.0  # 0 = off the gate (matches pre-066 behavior)


def _defaults() -> Dict[str, Any]:
    return {
        "auto_close_min_confidence": DEFAULT_MIN_CONFIDENCE,
        "auto_close_min_fp_likelihood": DEFAULT_MIN_FP_LIKELIHOOD,
        "force_all_to_investigation": False,
    }


def _clamp(v: Any, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return lo
    if f < lo:
        return lo
    if f > hi:
        return hi
    return f


async def get_for_tenant(tenant_id: Optional[str]) -> Dict[str, Any]:
    """Return the per-tenant thresholds, or defaults on any failure."""
    if not tenant_id:
        return _defaults()
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected:
            return _defaults()
        # Background callers don't always have RLS context; use platform-admin
        # bypass to read this lightweight config table safely.
        async with postgres_db.tenant_acquire() as conn:
            try:
                await conn.execute("SET app.is_platform_admin = 'true'")
            except Exception:
                pass
            row = await conn.fetchrow(
                "SELECT auto_close_min_confidence, auto_close_min_fp_likelihood, "
                "force_all_to_investigation "
                "FROM tenant_triage_config WHERE tenant_id = $1::uuid",
                str(tenant_id),
            )
    except Exception as e:
        logger.debug(f"tenant_triage_config fetch failed for {tenant_id}: {e}")
        return _defaults()

    if not row:
        return _defaults()
    return {
        "auto_close_min_confidence": float(row["auto_close_min_confidence"]),
        "auto_close_min_fp_likelihood": float(row["auto_close_min_fp_likelihood"]),
        "force_all_to_investigation": bool(row["force_all_to_investigation"]),
    }


async def upsert_for_tenant(
    tenant_id: str,
    *,
    auto_close_min_confidence: Optional[float] = None,
    auto_close_min_fp_likelihood: Optional[float] = None,
    force_all_to_investigation: Optional[bool] = None,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Upsert the per-tenant thresholds; missing values keep current/default."""
    from services.postgres_db import postgres_db

    current = await get_for_tenant(tenant_id)
    conf = _clamp(
        auto_close_min_confidence
        if auto_close_min_confidence is not None
        else current["auto_close_min_confidence"]
    )
    fp = _clamp(
        auto_close_min_fp_likelihood
        if auto_close_min_fp_likelihood is not None
        else current["auto_close_min_fp_likelihood"]
    )
    force_all = bool(
        force_all_to_investigation
        if force_all_to_investigation is not None
        else current["force_all_to_investigation"]
    )

    async with postgres_db.tenant_acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tenant_triage_config
                (tenant_id, auto_close_min_confidence, auto_close_min_fp_likelihood,
                 force_all_to_investigation, updated_at, updated_by)
            VALUES ($1::uuid, $2, $3, $4, NOW(), $5)
            ON CONFLICT (tenant_id) DO UPDATE
                SET auto_close_min_confidence    = EXCLUDED.auto_close_min_confidence,
                    auto_close_min_fp_likelihood = EXCLUDED.auto_close_min_fp_likelihood,
                    force_all_to_investigation   = EXCLUDED.force_all_to_investigation,
                    updated_at                   = NOW(),
                    updated_by                   = EXCLUDED.updated_by
            """,
            tenant_id, conf, fp, force_all, updated_by,
        )

    return {
        "auto_close_min_confidence": conf,
        "auto_close_min_fp_likelihood": fp,
        "force_all_to_investigation": force_all,
    }
