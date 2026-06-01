# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Tenant LLM Context API

GET  /api/v1/llm-context  → current tenant's extra context + key overrides
PUT  /api/v1/llm-context  → upsert the tenant's row (admin only)

Symmetric to the hardcoded RIGGS_EXCLUDED_FIELDS / sensitive-key redactor:
this is how a tenant declares the inverse — context they want preserved
*or* added — without us shipping a code change.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user
from services import tenant_llm_context_service as svc

router = APIRouter(
    prefix="/api/v1/llm-context",
    tags=["llm-context"],
    dependencies=[Depends(get_current_user)],
)


class LLMContextUpdate(BaseModel):
    extra_context: Optional[str] = Field(
        default=None,
        max_length=svc.MAX_EXTRA_CONTEXT_CHARS,
        description="Free-form prose appended to every Riggs prompt for this tenant.",
    )
    include_field_keys: List[str] = Field(
        default_factory=list,
        description=(
            "raw_event keys that should be kept even if they'd otherwise be "
            "dropped or redacted (e.g. 'cookie' for a tenant that needs to "
            "see session info during triage)."
        ),
    )
    exclude_field_keys: List[str] = Field(
        default_factory=list,
        description="raw_event keys to drop in addition to the platform defaults.",
    )


class LLMContextResponse(BaseModel):
    extra_context: Optional[str]
    include_field_keys: List[str]
    exclude_field_keys: List[str]


def _is_admin(user: Dict[str, Any]) -> bool:
    role = (user.get("role") or "").lower()
    return role in ("admin", "owner", "platform_admin")


@router.get("", response_model=LLMContextResponse)
async def get_llm_context(user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return await svc.get_for_tenant(str(tenant_id))


@router.put("", response_model=LLMContextResponse)
async def update_llm_context(
    body: LLMContextUpdate,
    user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant context unavailable")
    return await svc.upsert_for_tenant(
        str(tenant_id),
        extra_context=body.extra_context,
        include_field_keys=body.include_field_keys,
        exclude_field_keys=body.exclude_field_keys,
        updated_by=user.get("user_id") or user.get("id"),
    )
