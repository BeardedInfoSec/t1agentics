# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant LLM Context Service

Read/write helpers for `tenant_llm_context` (migration 065). The table is
the symmetric counterpart to the hardcoded RIGGS_EXCLUDED_FIELDS list /
sensitive-key redactor in agents/riggs.py:

  * extra_context      free-form prose appended to every Riggs prompt
                       for this tenant
  * include_field_keys raw_event keys the tenant wants preserved even
                       if they'd otherwise be excluded or redacted
  * exclude_field_keys raw_event keys to drop in addition to the
                       hardcoded defaults

All callers use `tenant_acquire()` so RLS scopes the rows to the
current tenant automatically; background callers should set the
platform-admin bypass before touching this table.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Free-form prose ceiling. 4 KB is plenty for a paragraph or two of
# org-specific guidance without bloating every prompt.
MAX_EXTRA_CONTEXT_CHARS = 4096

# Per-side cap so misconfiguration (e.g. paste of 10k field names) can't
# OOM downstream prompt builders.
MAX_FIELD_KEYS = 64


_EMPTY: Dict[str, Any] = {
    "extra_context": None,
    "include_field_keys": [],
    "exclude_field_keys": [],
}


def _normalize_keys(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value[:MAX_FIELD_KEYS]:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    # Stable-dedupe while preserving order so the API response is
    # deterministic.
    seen = set()
    deduped = []
    for k in out:
        if k not in seen:
            seen.add(k)
            deduped.append(k)
    return deduped


async def get_for_tenant(tenant_id: str) -> Dict[str, Any]:
    """Fetch context row for `tenant_id`. Returns _EMPTY when no row exists."""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected:
            return dict(_EMPTY)
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT extra_context, include_field_keys, exclude_field_keys "
                "FROM tenant_llm_context WHERE tenant_id = $1::uuid",
                tenant_id,
            )
    except Exception as e:
        logger.warning(f"tenant_llm_context fetch failed for {tenant_id}: {e}")
        return dict(_EMPTY)

    if not row:
        return dict(_EMPTY)

    extra = row["extra_context"]
    inc = row["include_field_keys"]
    exc = row["exclude_field_keys"]
    if isinstance(inc, str):
        try:
            inc = json.loads(inc)
        except Exception:
            inc = []
    if isinstance(exc, str):
        try:
            exc = json.loads(exc)
        except Exception:
            exc = []
    return {
        "extra_context": extra,
        "include_field_keys": _normalize_keys(inc),
        "exclude_field_keys": _normalize_keys(exc),
    }


async def upsert_for_tenant(
    tenant_id: str,
    *,
    extra_context: Optional[str],
    include_field_keys: List[str],
    exclude_field_keys: List[str],
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert-or-update the per-tenant context. Returns the stored row."""
    from services.postgres_db import postgres_db

    text = (extra_context or "").strip() or None
    if text and len(text) > MAX_EXTRA_CONTEXT_CHARS:
        text = text[:MAX_EXTRA_CONTEXT_CHARS]

    inc = _normalize_keys(include_field_keys)
    exc = _normalize_keys(exclude_field_keys)

    async with postgres_db.tenant_acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tenant_llm_context
                (tenant_id, extra_context, include_field_keys,
                 exclude_field_keys, updated_at, updated_by)
            VALUES ($1::uuid, $2, $3::jsonb, $4::jsonb, NOW(), $5)
            ON CONFLICT (tenant_id) DO UPDATE
                SET extra_context      = EXCLUDED.extra_context,
                    include_field_keys = EXCLUDED.include_field_keys,
                    exclude_field_keys = EXCLUDED.exclude_field_keys,
                    updated_at         = NOW(),
                    updated_by         = EXCLUDED.updated_by
            """,
            tenant_id,
            text,
            json.dumps(inc),
            json.dumps(exc),
            updated_by,
        )

    return {
        "extra_context": text,
        "include_field_keys": inc,
        "exclude_field_keys": exc,
    }
