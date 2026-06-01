# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs Assist Routes — Global AI assistant (Clippy) endpoint.
REST-based quick Q&A, not WebSocket. Lightweight and context-aware.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
import logging
import re

from dependencies.auth import get_current_user
from services.claude_service import get_claude_service, QuotaExceededError
from config.riggs_assist_prompts import build_system_prompt

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/riggs",
    tags=["riggs-assist"],
    dependencies=[Depends(get_current_user)]
)


class AssistRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    context: Optional[dict] = None


class SuggestedAction(BaseModel):
    label: str
    navigate: Optional[str] = None
    tour_id: Optional[str] = None


class AssistResponse(BaseModel):
    response: str
    suggested_actions: List[SuggestedAction] = []


_BUILD_PLAYBOOK_INTENT = re.compile(
    r"\b(build|make|create|draft|generate)\b.{0,30}\bplaybook\b",
    re.IGNORECASE,
)


def _looks_like_build_playbook(message: str) -> bool:
    return bool(_BUILD_PLAYBOOK_INTENT.search(message))


async def _try_build_playbook_intent(
    message: str,
    context: dict,
    tenant_id: Optional[str],
) -> Optional[AssistResponse]:
    """If the user is asking Riggs to build a playbook *and* an alert is in
    page context, kick off the builder and return a navigable response.
    Returns None when the intent doesn't apply (caller should fall back to
    normal chat)."""
    if not _looks_like_build_playbook(message):
        return None
    alert_id = (context or {}).get("alert_id") or (context or {}).get("alertId")
    investigation_id = (context or {}).get("investigation_id") or (context or {}).get("investigationId")
    if not alert_id and investigation_id:
        # Resolve alert_id from investigation_id so users can ask Riggs from
        # the investigation page without us having to plumb alert_id into the
        # frontend everywhere.
        try:
            from services.postgres_db import postgres_db
            if postgres_db.connected:
                async with postgres_db.tenant_acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT alert_id FROM investigations WHERE investigation_id = $1",
                        str(investigation_id),
                    )
                    if row and row["alert_id"]:
                        alert_id = str(row["alert_id"])
        except Exception as exc:
            logger.debug(f"investigation→alert lookup failed: {exc}")
    if not alert_id:
        return AssistResponse(
            response=(
                "I can draft a playbook from an alert — open an alert or "
                "investigation first and ask me again, or use the "
                "\"Build Playbook from Alert\" button on the investigation view."
            ),
            suggested_actions=[],
        )
    if not tenant_id:
        return None  # let normal path handle it; tenant context is required
    try:
        from services.riggs_playbook_builder import get_riggs_playbook_builder
        builder = get_riggs_playbook_builder()
        result = await builder.build_from_alert(
            alert_id=str(alert_id),
            tenant_id=tenant_id,
            persist=True,
        )
    except ValueError:
        return AssistResponse(
            response="I couldn't find that alert. Try opening the investigation first.",
            suggested_actions=[],
        )
    except Exception as exc:
        logger.exception(f"Riggs chat build_from_alert failed: {exc}")
        return AssistResponse(
            response=(
                "I hit an error while drafting the playbook. You can retry from "
                "the \"Build Playbook from Alert\" button on the investigation view."
            ),
            suggested_actions=[],
        )

    nodes = result.get("node_count", 0)
    edges = result.get("edge_count", 0)
    source = result.get("source", "")
    method_note = "" if source == "llm" else " (template-based fallback)"
    return AssistResponse(
        response=(
            f"Drafted \"{result.get('name', 'Untitled')}\" — {nodes} nodes, "
            f"{edges} edges{method_note}. Saved as a disabled draft. "
            "Open it in the editor to review and enable."
        ),
        suggested_actions=[
            SuggestedAction(label="Open in editor", navigate=result.get("editor_url") or "/playbooks"),
        ],
    )


@router.post("/assist", response_model=AssistResponse)
async def riggs_assist(req: AssistRequest, user=Depends(get_current_user)):
    """
    Context-aware Riggs assistant. Quick Q&A about the platform.
    Uses claude_service with token tracking per tenant.
    """
    tenant_id = user.get("tenant_id")
    user_id = user.get("id")
    page = (req.context or {}).get("page", "/")

    # Sanitize message
    message = req.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Intercept "build me a playbook" intent when an alert is in context.
    intent_response = await _try_build_playbook_intent(message, req.context or {}, tenant_id)
    if intent_response is not None:
        return intent_response

    # Build system prompt with page context
    system_prompt = build_system_prompt(page)

    try:
        claude = await get_claude_service()
        result = await claude.complete(
            tenant_id=UUID(tenant_id) if tenant_id else None,
            prompt=message,
            system=system_prompt,
            max_tokens=500,
            temperature=0.3,
            request_type="riggs_assist",
            user_id=UUID(user_id) if user_id else None,
        )

        return AssistResponse(
            response=result.text,
            suggested_actions=[]
        )

    except QuotaExceededError:
        return AssistResponse(
            response="Your AI token quota has been reached for this month. Contact your administrator to increase your plan limits.",
            suggested_actions=[
                SuggestedAction(label="View Usage", navigate="/admin/billing")
            ]
        )
    except RuntimeError as e:
        logger.error(f"Riggs assist error: {e}")
        return AssistResponse(
            response="I'm having trouble connecting to my AI backend right now. Please try again in a moment.",
            suggested_actions=[]
        )
    except Exception as e:
        logger.exception(f"Riggs assist unexpected error: {e}")
        return AssistResponse(
            response="Something went wrong. Please try again.",
            suggested_actions=[]
        )
