# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant Triage Config API

GET  /api/v1/triage-config  → current tenant's auto-close thresholds
PUT  /api/v1/triage-config  → admin upsert

Lets a tenant tune how aggressive auto-close is (verdict + confidence gate
already gates BENIGN/FALSE_POSITIVE; this surfaces the confidence floor
and an optional fp_likelihood floor as user-controlled settings instead
of compile-time constants).
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user
from services import tenant_triage_config_service as svc

router = APIRouter(
    prefix="/api/v1/triage-config",
    tags=["triage-config"],
    dependencies=[Depends(get_current_user)],
)


class TriageConfigUpdate(BaseModel):
    auto_close_min_confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="Min Riggs confidence (0-1) before BENIGN/FALSE_POSITIVE auto-closes.",
    )
    auto_close_min_fp_likelihood: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="Min false-positive-likelihood (0-1) required for auto-close. 0 = off the gate.",
    )
    force_all_to_investigation: Optional[bool] = Field(
        default=None,
        description=(
            "When true, every triage result opens an investigation (no auto-close). "
            "BYO-gated at the route layer because it can raise cost noticeably."
        ),
    )


class TriageConfigResponse(BaseModel):
    auto_close_min_confidence: float
    auto_close_min_fp_likelihood: float
    force_all_to_investigation: bool


def _is_admin(user: Dict[str, Any]) -> bool:
    role = (user.get("role") or "").lower()
    return role in ("admin", "owner", "platform_admin")


@router.get("", response_model=TriageConfigResponse)
async def get_triage_config(user: Dict = Depends(get_current_user)) -> Dict[str, float]:
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return await svc.get_for_tenant(str(tenant_id))


@router.put("", response_model=TriageConfigResponse)
async def update_triage_config(
    body: TriageConfigUpdate,
    user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")

    # force_all_to_investigation is BYO-gated. Refuse to set it on if the
    # tenant isn't actually on their own LLM bill — otherwise it'd amplify
    # platform Claude spend without consent. Saving force_all=false stays
    # allowed (so a tenant can turn it off after losing BYO access).
    if body.force_all_to_investigation:
        try:
            from services import tenant_ai_config_service as cfg_svc
            ai_cfg = await cfg_svc.get_raw(str(tenant_id))
            byo_effective = bool(
                ai_cfg.get("byo_allowed")
                and ai_cfg.get("byo_enabled")
                and ai_cfg.get("chat_api_key_encrypted")
            )
        except Exception:
            byo_effective = False
        if not byo_effective:
            raise HTTPException(
                status_code=403,
                detail="force_all_to_investigation is only available to BYO LLM tenants",
            )

    return await svc.upsert_for_tenant(
        str(tenant_id),
        auto_close_min_confidence=body.auto_close_min_confidence,
        auto_close_min_fp_likelihood=body.auto_close_min_fp_likelihood,
        force_all_to_investigation=body.force_all_to_investigation,
        updated_by=user.get("user_id") or user.get("id"),
    )
