# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Inbound Lead Agent — signup-to-conversation marketing.

When a new signup (registration_requests), contact-form submission, or
public-triage-demo user comes in, this agent:

  1. Classifies the lead (real_prospect / partner / competitor / noise / unknown)
     based on the email domain, company name, role, and message context.
  2. Drafts a personalized follow-up email tailored to the classification
     and what we know about the lead.
  3. Persists the draft to `lead_drafts` (status='pending_review').

The drafts surface in the daily summary email with HMAC-signed
approve/reject links so the founder can triage from inbox. No email is
ever sent to the lead until the founder explicitly approves it.

Design rules:
  - NEVER send outbound directly. Always queue for review.
  - NEVER reference Claude, Anthropic, OpenAI, or any vendor LLM in
    the drafted email body or anywhere user-visible.
  - Conservative confidence: when in doubt, classify as `unknown` and
    leave a short note explaining what the founder should double-check.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

logger = logging.getLogger(__name__)


# Public free-mail providers: not disqualifying, but a strong signal the
# lead is not buying for a corporate SOC. The classifier downweights these.
_FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "pm.me", "tutanota.com", "mail.com", "gmx.com", "yandex.com",
})

# Known competitor / adjacent vendor domains. We do NOT email these.
# Edit this list as new competitors emerge.
_COMPETITOR_DOMAINS = frozenset({
    "splunk.com", "crowdstrike.com", "sentinelone.com", "paloaltonetworks.com",
    "fortinet.com", "checkpoint.com", "trendmicro.com", "tines.com",
    "torq.io", "xsoar.com", "swimlane.com", "demisto.com", "rapid7.com",
    "qradar.com", "securonix.com", "exabeam.com", "elastic.co",
})

# Disposable / throwaway email domains. Treated as noise.
_DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "sharklasers.com", "yopmail.com", "trashmail.com",
    "getnada.com", "maildrop.cc", "mintemail.com", "fakeinbox.com",
})


SYSTEM_PROMPT = """You are the inbound lead classifier and follow-up drafter for T1 Agentics, an AI-assisted SOC platform sold to security teams.

Your job: given a single inbound signup or contact submission, return JSON with:
  - classification: one of `real_prospect`, `partner`, `competitor`, `noise`, `unknown`
  - confidence: 0.0 to 1.0
  - reason: one sentence explaining the classification
  - draft_subject: the proposed email subject line (under 80 chars)
  - draft_body: the proposed plain-text email body, signed off as "Aaron" (the founder)

Classification rules:
  - real_prospect: corporate email domain, role or company suggests a security team
    or buyer (SOC, security engineer, IR, CISO, etc.), or message describes an
    actual evaluation context
  - partner: works at an MSSP / MSP / consultancy / channel partner, or message
    explicitly references partnership/reselling
  - competitor: domain or company is a known SOAR / SIEM / XDR vendor
  - noise: disposable email, .test address, single-character name, no useful signal,
    obviously fake submission
  - unknown: signal is mixed; flag for human review

Email draft rules:
  - Warm but not gushing. The founder ships products; he doesn't send templated cold spam.
  - Reference what we actually know about them (their company, role, what they said).
  - End with a low-friction CTA: "want a 15-min walkthrough?" or "happy to send a Loom".
  - NEVER mention "AI" generically — mention "Riggs" (the platform's AI analyst) where relevant.
  - NEVER name any LLM vendor (Claude, Anthropic, OpenAI, etc.).
  - For `competitor` and `noise`, leave draft_subject and draft_body empty strings.
  - For `partner`, draft a brief partnership-curious reply, not a sales pitch.
  - Sign as "Aaron" — short signature, no title.

Output ONLY the JSON object, no markdown."""


def _domain_of(email: str) -> str:
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].lower().strip()


def _seed_signals(email: str) -> Dict[str, Any]:
    """Cheap deterministic signals we can feed into the prompt — saves the
    LLM from having to memorize our competitor list."""
    domain = _domain_of(email)
    return {
        "email_domain": domain,
        "is_freemail": domain in _FREEMAIL_DOMAINS,
        "is_disposable": domain in _DISPOSABLE_DOMAINS,
        "is_known_competitor": domain in _COMPETITOR_DOMAINS,
    }


def _strip_code_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```\s*$", "", text)
    return text.strip()


def _generate_approval_token() -> str:
    """Random per-draft token. The full HMAC for approval links is derived
    from this + a server-side secret in routes/lead_drafts.py."""
    return secrets.token_urlsafe(32)


def hmac_for_action(approval_token: str, action: str) -> str:
    """Sign an action ('approve' or 'reject') for a given draft. The daily
    summary email embeds the result of this in its approve/reject links.
    Routes in lead_drafts.py verify the same signature before mutating state.
    """
    secret = os.environ.get("LEAD_DRAFT_SIGNING_SECRET") or os.environ.get("JWT_SECRET_KEY") or ""
    if not secret:
        raise RuntimeError("LEAD_DRAFT_SIGNING_SECRET (or JWT_SECRET_KEY) must be set")
    msg = f"{approval_token}:{action}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


async def _classify_and_draft(
    *,
    email: str,
    full_name: str,
    company: str,
    role: str,
    source_type: str,
    extra_context: str,
    tenant_id: Optional[UUID],
) -> Optional[Dict[str, Any]]:
    """Single LLM call. Returns None on failure (caller falls back to
    deterministic classification + no draft, still queued for review)."""
    try:
        from services.claude_service import get_claude_service, QuotaExceededError
        claude = await get_claude_service()
        if not getattr(claude, "is_configured", False):
            return None

        signals = _seed_signals(email)
        user_prompt = (
            "Classify and draft a follow-up for this inbound lead.\n\n"
            "Lead:\n"
            + json.dumps({
                "email": email,
                "full_name": full_name or None,
                "company": company or None,
                "role": role or None,
                "source": source_type,
                "extra_context": extra_context[:1500] if extra_context else None,
                "signals": signals,
            }, indent=2)
        )

        try:
            result = await claude.complete(
                tenant_id=tenant_id,
                prompt=user_prompt,
                system=SYSTEM_PROMPT,
                max_tokens=1200,
                temperature=0.3,
                request_type="inbound_lead_agent",
            )
        except QuotaExceededError:
            logger.warning("[INBOUND_LEAD] quota exceeded, falling back to deterministic classification")
            return None

        try:
            payload = json.loads(_strip_code_fences(result.text or ""))
        except Exception as exc:
            logger.warning(f"[INBOUND_LEAD] LLM returned non-JSON: {exc}")
            return None

        classification = (payload.get("classification") or "unknown").strip().lower()
        if classification not in ("real_prospect", "partner", "competitor", "noise", "unknown"):
            classification = "unknown"

        try:
            confidence = float(payload.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        return {
            "classification": classification,
            "confidence": confidence,
            "reason": (payload.get("reason") or "").strip()[:500],
            "draft_subject": (payload.get("draft_subject") or "").strip()[:300],
            "draft_body": (payload.get("draft_body") or "").strip()[:6000],
        }
    except Exception as exc:
        logger.exception(f"[INBOUND_LEAD] classify_and_draft failed: {exc}")
        return None


def _deterministic_classification(email: str) -> Dict[str, Any]:
    """Fallback when the LLM is unavailable. Based purely on signals — no
    drafted body, because we don't want to send a template that ignores
    the actual lead context."""
    signals = _seed_signals(email)
    if signals["is_disposable"]:
        return {
            "classification": "noise",
            "confidence": 0.9,
            "reason": "Disposable email provider.",
            "draft_subject": "",
            "draft_body": "",
        }
    if signals["is_known_competitor"]:
        return {
            "classification": "competitor",
            "confidence": 0.85,
            "reason": f"Domain {signals['email_domain']} is on the competitor list.",
            "draft_subject": "",
            "draft_body": "",
        }
    if signals["is_freemail"]:
        return {
            "classification": "unknown",
            "confidence": 0.4,
            "reason": "Free-mail domain; could be solo practitioner or noise.",
            "draft_subject": "",
            "draft_body": "",
        }
    return {
        "classification": "unknown",
        "confidence": 0.3,
        "reason": "LLM unavailable; needs manual review.",
        "draft_subject": "",
        "draft_body": "",
    }


async def process_lead(
    *,
    source_type: str,            # 'signup' | 'contact' | 'triage_demo'
    source_id: str,
    email: str,
    full_name: str = "",
    company: str = "",
    role: str = "",
    extra_context: str = "",
    tenant_id: Optional[UUID] = None,
) -> Optional[str]:
    """Run the agent on one inbound lead and persist the result.

    Returns the lead_drafts.id (as a string) on success, or None if the lead
    was deduped or the DB is offline.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        logger.warning("[INBOUND_LEAD] DB not connected; skipping")
        return None

    # Don't double-process the same (source_type, source_id).
    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        existing = await conn.fetchrow(
            "SELECT id FROM lead_drafts WHERE source_type = $1 AND source_id = $2",
            source_type, source_id,
        )
        if existing:
            logger.info(f"[INBOUND_LEAD] already processed {source_type}:{source_id}, skipping")
            return str(existing["id"])

    result = await _classify_and_draft(
        email=email,
        full_name=full_name,
        company=company,
        role=role,
        source_type=source_type,
        extra_context=extra_context,
        tenant_id=tenant_id,
    )
    if result is None:
        result = _deterministic_classification(email)

    approval_token = _generate_approval_token()

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        row = await conn.fetchrow(
            """
            INSERT INTO lead_drafts (
                source_type, source_id, lead_email, lead_name, lead_company,
                classification, classification_confidence, classification_reason,
                draft_subject, draft_body, status, approval_token,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, NOW(), NOW()
            )
            RETURNING id
            """,
            source_type, source_id, email, full_name or None, company or None,
            result["classification"], result["confidence"], result["reason"],
            result["draft_subject"] or None, result["draft_body"] or None,
            # Auto-finalize obvious non-actionable outcomes so they don't
            # clutter the founder's daily review.
            "rejected" if result["classification"] in ("competitor", "noise") else "pending_review",
            approval_token,
        )

    draft_id = str(row["id"])
    logger.info(
        "[INBOUND_LEAD] queued %s lead %s (classification=%s, confidence=%.2f, draft_id=%s)",
        source_type, email, result["classification"], result["confidence"], draft_id,
    )
    return draft_id
