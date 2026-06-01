# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant PII Patterns Service

CRUD + cache for `tenant_pii_patterns` (migration 071). Each row is a
regex + label + redaction mode that the PII obfuscator applies on top
of its built-in patterns when processing this tenant's data.

The cache is per-process and short-lived (60s) so changes propagate
without restart but the obfuscator hot path doesn't hammer the DB.
Each tenant gets a list of compiled regex objects ready for use.
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

VALID_MODES = {"mask", "redact", "hash"}
CACHE_TTL_SECONDS = 60

# tenant_id -> (expires_at, list[{id, label, pattern, mode, enabled, compiled}])
_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}


def _compile_or_raise(pattern: str) -> re.Pattern:
    """Compile a tenant-supplied regex. Raises ValueError on bad regex."""
    if not pattern or not isinstance(pattern, str):
        raise ValueError("pattern must be a non-empty string")
    if len(pattern) > 1024:
        raise ValueError("pattern is too long (max 1024 chars)")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"invalid regex: {e}")


def _validate_mode(mode: Optional[str]) -> str:
    m = (mode or "mask").lower()
    if m not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)}")
    return m


def invalidate(tenant_id: Optional[str]) -> None:
    if tenant_id:
        _cache.pop(str(tenant_id), None)


async def list_for_tenant(tenant_id: str, include_disabled: bool = True) -> List[Dict[str, Any]]:
    """API-safe list (no compiled regex). Used by the route."""
    from services.postgres_db import postgres_db
    rows: List[Dict[str, Any]] = []
    if not postgres_db.connected:
        return rows
    async with postgres_db.tenant_acquire() as conn:
        sql = (
            "SELECT id, label, pattern, mode, enabled, created_at, updated_at "
            "FROM tenant_pii_patterns WHERE tenant_id = $1::uuid "
        )
        if not include_disabled:
            sql += "AND enabled = TRUE "
        sql += "ORDER BY label ASC"
        records = await conn.fetch(sql, str(tenant_id))
        for r in records:
            rows.append({
                "id": str(r["id"]),
                "label": r["label"],
                "pattern": r["pattern"],
                "mode": r["mode"],
                "enabled": bool(r["enabled"]),
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            })
    return rows


async def get_compiled_for_tenant(tenant_id: Optional[str]) -> List[Dict[str, Any]]:
    """
    Hot path for the obfuscator. Returns only enabled patterns with their
    compiled regex objects. Cached per-process.
    """
    if not tenant_id:
        return []
    key = str(tenant_id)
    now = time.time()
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected:
            _cache[key] = (now + CACHE_TTL_SECONDS, [])
            return []
        async with postgres_db.tenant_acquire() as conn:
            try:
                await conn.execute("SET app.is_platform_admin = 'true'")
            except Exception:
                pass
            records = await conn.fetch(
                "SELECT id, label, pattern, mode FROM tenant_pii_patterns "
                "WHERE tenant_id = $1::uuid AND enabled = TRUE",
                str(tenant_id),
            )
    except Exception as e:
        logger.debug(f"tenant_pii_patterns fetch failed for {tenant_id}: {e}")
        records = []

    compiled: List[Dict[str, Any]] = []
    for r in records:
        try:
            compiled.append({
                "id": str(r["id"]),
                "label": r["label"],
                "mode": r["mode"],
                "compiled": re.compile(r["pattern"], re.IGNORECASE),
            })
        except re.error as e:
            # Should not happen — patterns are compile-tested on save —
            # but defend against a regex that became invalid because of
            # a Python upgrade.
            logger.warning(
                f"skipping uncompilable tenant PII pattern '{r['label']}' "
                f"for {tenant_id}: {e}"
            )
    _cache[key] = (now + CACHE_TTL_SECONDS, compiled)
    return compiled


async def create_pattern(
    tenant_id: str,
    *,
    label: str,
    pattern: str,
    mode: str = "mask",
    enabled: bool = True,
    created_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Compile-test, then persist. Raises ValueError on bad input."""
    if not label or not label.strip():
        raise ValueError("label is required")
    _compile_or_raise(pattern)
    mode = _validate_mode(mode)

    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO tenant_pii_patterns
                (tenant_id, label, pattern, mode, enabled, created_by)
            VALUES ($1::uuid, $2, $3, $4, $5, $6)
            RETURNING id, label, pattern, mode, enabled, created_at, updated_at
            """,
            tenant_id, label.strip(), pattern, mode, bool(enabled), created_by,
        )
    invalidate(tenant_id)
    return {
        "id": str(row["id"]),
        "label": row["label"],
        "pattern": row["pattern"],
        "mode": row["mode"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


async def update_pattern(
    tenant_id: str,
    pattern_id: str,
    *,
    label: Optional[str] = None,
    pattern: Optional[str] = None,
    mode: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    """Partial update. Compile-tests pattern when provided."""
    sets = []
    args: List[Any] = []
    if label is not None:
        if not label.strip():
            raise ValueError("label cannot be empty")
        args.append(label.strip())
        sets.append(f"label = ${len(args)}")
    if pattern is not None:
        _compile_or_raise(pattern)
        args.append(pattern)
        sets.append(f"pattern = ${len(args)}")
    if mode is not None:
        args.append(_validate_mode(mode))
        sets.append(f"mode = ${len(args)}")
    if enabled is not None:
        args.append(bool(enabled))
        sets.append(f"enabled = ${len(args)}")
    if not sets:
        return None
    sets.append("updated_at = NOW()")

    args.append(tenant_id)
    args.append(pattern_id)
    sql = (
        f"UPDATE tenant_pii_patterns SET {', '.join(sets)} "
        f"WHERE tenant_id = ${len(args) - 1}::uuid AND id = ${len(args)}::uuid "
        "RETURNING id, label, pattern, mode, enabled, created_at, updated_at"
    )

    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(sql, *args)
    if not row:
        return None
    invalidate(tenant_id)
    return {
        "id": str(row["id"]),
        "label": row["label"],
        "pattern": row["pattern"],
        "mode": row["mode"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


async def delete_pattern(tenant_id: str, pattern_id: str) -> bool:
    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        result = await conn.execute(
            "DELETE FROM tenant_pii_patterns WHERE tenant_id = $1::uuid AND id = $2::uuid",
            tenant_id, pattern_id,
        )
    invalidate(tenant_id)
    return "DELETE 1" in result
