# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Lead-draft review endpoints.

The daily summary email surfaces pending lead drafts inline with HMAC-signed
approve/reject links. Clicking a link goes to one of these endpoints, which
verifies the signature, marks the draft, and (on approve) actually sends
the drafted email to the lead.

These endpoints are intentionally GET-able (so they work from any mail
client) and do not require login — the HMAC signature is the auth. The
signing secret is the same one used by inbound_lead_agent.hmac_for_action.
"""

import hashlib
import hmac
import html
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/lead-drafts", tags=["lead-drafts"])


def _verify_signature(approval_token: str, action: str, provided_sig: str) -> bool:
    """Constant-time compare of the provided signature against the expected
    HMAC. Returns False on any error rather than throwing — we never want
    a bad inbox click to leak why it failed."""
    try:
        from services.inbound_lead_agent import hmac_for_action
        expected = hmac_for_action(approval_token, action)
        return hmac.compare_digest(expected, provided_sig)
    except Exception as exc:
        logger.warning(f"[LEAD_DRAFT] signature verify failed: {exc}")
        return False


def _page(title: str, body: str, color: str = "#3CB371") -> HTMLResponse:
    """Tiny standalone confirmation page returned after clicking an inbox link."""
    safe_title = html.escape(title)
    return HTMLResponse(
        f"""<!doctype html>
<html><head>
<meta charset="utf-8" />
<title>{safe_title} - T1 Agentics</title>
<style>
  body {{ background: #080a0f; color: #f0f6fc; font-family: -apple-system, sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
  .card {{ background: #151b23; border: 1px solid rgba(48,54,61,0.8); border-radius: 12px;
          padding: 32px 40px; max-width: 480px; }}
  h1 {{ color: {color}; margin: 0 0 16px 0; font-size: 20px; }}
  p {{ margin: 8px 0; font-size: 14px; line-height: 1.5; color: #c9d1d9; }}
  code {{ background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }}
</style>
</head><body>
  <div class="card">
    <h1>{safe_title}</h1>
    {body}
  </div>
</body></html>"""
    )


@router.get("/approve")
async def approve_lead_draft(
    id: str = Query(..., min_length=8, max_length=64),
    token: str = Query(..., min_length=8, max_length=128),
    sig: str = Query(..., min_length=32, max_length=128),
):
    """
    Approve a drafted follow-up email. Loads the draft, verifies the HMAC
    signature, sends the email to the lead, and marks the draft as sent.
    """
    from services.postgres_db import postgres_db
    from services.email_service import get_email_service

    try:
        draft_uuid = UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid draft id")

    if not _verify_signature(token, "approve", sig):
        return _page("Link expired", "<p>This approval link has expired or is invalid. Open the draft from the latest daily summary email.</p>", color="#d29922")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        row = await conn.fetchrow(
            "SELECT * FROM lead_drafts WHERE id = $1 AND approval_token = $2",
            draft_uuid, token,
        )
        if not row:
            return _page("Not found", "<p>That draft no longer exists.</p>", color="#d29922")

        if row["status"] == "sent":
            return _page("Already sent", f"<p>This draft was already sent to <code>{html.escape(row['lead_email'])}</code>.</p>", color="#d29922")
        if row["status"] in ("rejected",):
            return _page("Already rejected", "<p>This draft was rejected. To send it, edit and approve from the admin UI.</p>", color="#d29922")

        subject = row["draft_subject"] or ""
        body = row["draft_body"] or ""
        if not subject.strip() or not body.strip():
            return _page("Nothing to send", "<p>This draft is empty. Edit it in the admin UI before approving.</p>", color="#d29922")

        try:
            svc = get_email_service()
            # Email service uses HTML; convert plain-text body to <p> blocks
            # so paragraph breaks survive. Drafts are intentionally plain so
            # they read like a personal email, not a templated blast.
            html_body = "<div style='font-family:-apple-system,sans-serif;font-size:14px;line-height:1.6;color:#1f2328;'>"
            for para in body.split("\n\n"):
                escaped = html.escape(para).replace("\n", "<br/>")
                html_body += f"<p style='margin:0 0 12px 0;'>{escaped}</p>"
            html_body += "</div>"

            await svc.send_email([row["lead_email"]], subject, html_body)
        except Exception as exc:
            logger.error(f"[LEAD_DRAFT] send failed for {row['lead_email']}: {exc}")
            await conn.execute(
                "UPDATE lead_drafts SET status='failed', send_error=$2, updated_at=NOW() WHERE id=$1",
                draft_uuid, str(exc)[:500],
            )
            return _page("Send failed", f"<p>The email could not be sent. Reason: <code>{html.escape(str(exc)[:200])}</code></p>", color="#ef4444")

        await conn.execute(
            """
            UPDATE lead_drafts
               SET status='sent', sent_at=NOW(), reviewed_at=NOW(),
                   updated_at=NOW()
             WHERE id=$1
            """,
            draft_uuid,
        )

    return _page(
        "Approved and sent",
        f"<p>Reply sent to <code>{html.escape(row['lead_email'])}</code>.</p>"
        f"<p style='color:#8b949e;'>Subject: {html.escape(subject[:200])}</p>",
    )


@router.get("/reject")
async def reject_lead_draft(
    id: str = Query(..., min_length=8, max_length=64),
    token: str = Query(..., min_length=8, max_length=128),
    sig: str = Query(..., min_length=32, max_length=128),
):
    """
    Reject a drafted follow-up. Marks the draft as rejected; no email is sent.
    """
    from services.postgres_db import postgres_db

    try:
        draft_uuid = UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid draft id")

    if not _verify_signature(token, "reject", sig):
        return _page("Link expired", "<p>This rejection link has expired or is invalid.</p>", color="#d29922")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        row = await conn.fetchrow(
            "SELECT id, status, lead_email FROM lead_drafts WHERE id = $1 AND approval_token = $2",
            draft_uuid, token,
        )
        if not row:
            return _page("Not found", "<p>That draft no longer exists.</p>", color="#d29922")
        if row["status"] == "sent":
            return _page("Already sent", "<p>This draft was already sent and cannot be rejected.</p>", color="#d29922")
        if row["status"] == "rejected":
            return _page("Already rejected", "<p>Already marked rejected.</p>", color="#8b949e")
        await conn.execute(
            "UPDATE lead_drafts SET status='rejected', reviewed_at=NOW(), updated_at=NOW() WHERE id=$1",
            draft_uuid,
        )

    return _page(
        "Rejected",
        f"<p>Draft for <code>{html.escape(row['lead_email'])}</code> rejected. No email was sent.</p>",
        color="#8b949e",
    )
