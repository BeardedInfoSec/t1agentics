# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant PII Patterns API

Tenant-admin CRUD for custom PII regex patterns. Each pattern is
compile-tested on save so a broken regex never lands in the DB and
the obfuscator hot path can trust the stored value.

GET    /api/v1/pii-patterns         list (any role)
POST   /api/v1/pii-patterns         create (admin)
PATCH  /api/v1/pii-patterns/{id}    update (admin)
DELETE /api/v1/pii-patterns/{id}    delete (admin)
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user
from services import tenant_pii_patterns_service as svc

router = APIRouter(
    prefix="/api/v1/pii-patterns",
    tags=["pii-patterns"],
    dependencies=[Depends(get_current_user)],
)


class PIIPatternCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=120)
    pattern: str = Field(..., min_length=1, max_length=1024)
    mode: str = Field(default="mask")
    enabled: bool = True


class PIIPatternUpdate(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=120)
    pattern: Optional[str] = Field(default=None, min_length=1, max_length=1024)
    mode: Optional[str] = None
    enabled: Optional[bool] = None


class PIIPatternTest(BaseModel):
    pattern: str = Field(..., min_length=1, max_length=1024)
    mode: str = Field(default="mask")
    sample_text: str = Field(..., max_length=10_000)


def _is_admin(user: Dict[str, Any]) -> bool:
    role = (user.get("role") or "").lower()
    return role in ("admin", "owner", "platform_admin")


def _require_tenant(user: Dict[str, Any]) -> str:
    tid = user.get("tenant_id")
    if not tid:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return str(tid)


@router.get("")
async def list_pii_patterns(user: Dict = Depends(get_current_user)):
    return {"patterns": await svc.list_for_tenant(_require_tenant(user))}


@router.post("")
async def create_pii_pattern(
    body: PIIPatternCreate,
    user: Dict = Depends(get_current_user),
):
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    try:
        return await svc.create_pattern(
            _require_tenant(user),
            label=body.label,
            pattern=body.pattern,
            mode=body.mode,
            enabled=body.enabled,
            created_by=user.get("user_id") or user.get("id"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/{pattern_id}")
async def update_pii_pattern(
    pattern_id: str,
    body: PIIPatternUpdate,
    user: Dict = Depends(get_current_user),
):
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    try:
        updated = await svc.update_pattern(
            _require_tenant(user),
            pattern_id,
            label=body.label,
            pattern=body.pattern,
            mode=body.mode,
            enabled=body.enabled,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not updated:
        raise HTTPException(status_code=404, detail="pattern not found")
    return updated


@router.post("/test")
async def test_pii_pattern(
    body: PIIPatternTest,
    user: Dict = Depends(get_current_user),
):
    """
    Compile + run a candidate regex against caller-supplied sample text
    without persisting anything. Returns each match with the obfuscated
    preview so the user can iterate on the regex before saving.

    Uses the exact same Python `re` engine and obfuscation logic the
    real pipeline runs — JS regex differences would mislead the user.
    """
    import re as _re
    from services.pii_obfuscation import (
        get_pii_service, PIIType, ObfuscationMode,
    )

    # Compile-test the pattern
    try:
        compiled = _re.compile(body.pattern, _re.IGNORECASE)
    except _re.error as e:
        return {
            "ok": False,
            "error": f"invalid regex: {e}",
            "match_count": 0,
            "matches": [],
            "obfuscated_text": body.sample_text,
        }

    # Validate mode
    mode_lower = (body.mode or "mask").lower()
    if mode_lower not in {"mask", "redact", "hash"}:
        return {
            "ok": False,
            "error": "mode must be one of: mask, redact, hash",
            "match_count": 0,
            "matches": [],
            "obfuscated_text": body.sample_text,
        }
    obf_mode = ObfuscationMode(mode_lower)
    obfuscator = get_pii_service().obfuscator

    # Find matches (limit to first 200 so a runaway regex doesn't blow up
    # the response payload — generous bound but caps the worst case).
    raw_matches = []
    for m in compiled.finditer(body.sample_text):
        raw_matches.append(m)
        if len(raw_matches) >= 200:
            break

    # Build the obfuscated preview by walking matches in reverse order
    obfuscated_text = body.sample_text
    matches_info = []
    for m in reversed(raw_matches):
        original = m.group()
        try:
            obfuscated = obfuscator._obfuscate_value(original, PIIType.CUSTOM, obf_mode)
        except Exception:
            obfuscated = "***"
        matches_info.append({
            "start": m.start(),
            "end": m.end(),
            "value": original,
            "obfuscated": obfuscated,
        })
        obfuscated_text = (
            obfuscated_text[:m.start()] + obfuscated + obfuscated_text[m.end():]
        )

    matches_info.reverse()  # forward order for display

    return {
        "ok": True,
        "match_count": len(matches_info),
        "matches": matches_info,
        "obfuscated_text": obfuscated_text,
        "truncated": len(raw_matches) >= 200,
    }


@router.delete("/{pattern_id}")
async def delete_pii_pattern(
    pattern_id: str,
    user: Dict = Depends(get_current_user),
):
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    ok = await svc.delete_pattern(_require_tenant(user), pattern_id)
    if not ok:
        raise HTTPException(status_code=404, detail="pattern not found")
    return {"status": "deleted", "id": pattern_id}
