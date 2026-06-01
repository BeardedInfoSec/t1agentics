# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Daily Cost Summary Scheduler

Sends a daily activity + Claude spend digest to platform admins so the founder
has a daily heartbeat on platform usage and burn without having to open the
admin console. Runs once per day at 09:00 UTC by default.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


def _summary_hour_utc() -> int:
    try:
        return max(0, min(23, int(os.environ.get("DAILY_SUMMARY_HOUR_UTC", "9"))))
    except ValueError:
        return 9


async def _admin_recipients() -> list:
    """Resolve admin recipient emails. Mirrors the helper in routes/registration.py."""
    from services.postgres_db import postgres_db
    recipients = []
    try:
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                rows = await conn.fetch(
                    "SELECT email FROM platform_admins WHERE is_active = true"
                )
                recipients = [r["email"] for r in rows]
    except Exception as exc:
        logger.warning("[COST_SUMMARY] Failed to resolve platform_admins: %s", exc)

    if not recipients:
        admin_email = os.environ.get("ADMIN_EMAIL")
        if admin_email:
            recipients = [admin_email]
    return recipients


async def send_daily_summary():
    """Build and send yesterday's Claude spend + signup summary to platform admins.

    Aggregates ``ai_token_usage`` by tenant for the previous UTC day, joins to
    ``tenants`` for slugs, and counts new signups + waitlist entries from the
    same window before emailing the digest.
    """
    try:
        from services.postgres_db import postgres_db
        from services.email_service import get_email_service
        from services.email_templates import render_admin_daily_summary

        if not postgres_db.connected or postgres_db.pool is None:
            logger.warning("[COST_SUMMARY] Database not connected, skipping summary")
            return

        recipients = await _admin_recipients()
        if not recipients:
            logger.info("[COST_SUMMARY] No admin recipients configured, skipping")
            return

        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=1)
        summary_date = start.strftime("%Y-%m-%d")

        async with postgres_db.pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")

            totals = await conn.fetchrow(
                """
                SELECT
                    COALESCE(SUM(estimated_cost_cents), 0)::bigint AS total_cents,
                    COUNT(*)::bigint                                AS total_calls,
                    COALESCE(SUM(total_tokens), 0)::bigint          AS total_tokens
                FROM ai_token_usage
                WHERE created_at >= $1 AND created_at < $2
                """,
                start, end,
            )

            tenant_rows = await conn.fetch(
                """
                SELECT
                    atu.tenant_id                                    AS tenant_id,
                    t.slug                                           AS tenant_slug,
                    COUNT(*)::bigint                                 AS calls,
                    COALESCE(SUM(atu.total_tokens), 0)::bigint       AS tokens,
                    COALESCE(SUM(atu.estimated_cost_cents), 0)::bigint AS cost_cents
                FROM ai_token_usage atu
                LEFT JOIN tenants t ON t.id = atu.tenant_id
                WHERE atu.created_at >= $1 AND atu.created_at < $2
                GROUP BY atu.tenant_id, t.slug
                ORDER BY cost_cents DESC, calls DESC
                """,
                start, end,
            )

            signup_rows = await conn.fetch(
                """
                SELECT email, full_name, tenant_name, tenant_slug,
                       requested_plan, status, created_at
                FROM registration_requests
                WHERE created_at >= $1 AND created_at < $2
                ORDER BY created_at ASC
                """,
                start, end,
            )

            public_triage_row = await conn.fetchrow(
                """
                SELECT
                    COALESCE(SUM(request_count), 0)::bigint            AS calls,
                    COALESCE(SUM(input_tokens + output_tokens), 0)::bigint AS tokens,
                    COALESCE(SUM(estimated_cost_usd), 0)::numeric      AS cost_usd
                FROM public_demo_usage
                WHERE bucket_day >= $1::date AND bucket_day < $2::date
                """,
                start, end,
            )

            # Pending lead drafts (any age) — these are queued for review until
            # the founder approves/rejects from the inbox link.
            lead_draft_rows = await conn.fetch(
                """
                SELECT id, source_type, lead_email, lead_name, lead_company,
                       classification, classification_confidence, classification_reason,
                       draft_subject, draft_body, approval_token, created_at
                FROM lead_drafts
                WHERE status = 'pending_review'
                ORDER BY created_at ASC
                LIMIT 20
                """
            )

        total_cost_usd = float(totals["total_cents"] or 0) / 100.0
        total_calls = int(totals["total_calls"] or 0)
        total_tokens = int(totals["total_tokens"] or 0)

        def _label_tenant(tenant_id, slug):
            if slug:
                return slug
            if tenant_id is None:
                return "untracked (no tenant_id)"
            return f"deleted:{str(tenant_id)[:8]}"

        per_tenant = [
            {
                "tenant_slug": _label_tenant(row["tenant_id"], row["tenant_slug"]),
                "calls": int(row["calls"]),
                "tokens": int(row["tokens"]),
                "cost_usd": float(row["cost_cents"] or 0) / 100.0,
            }
            for row in tenant_rows
        ]

        signups = [
            {
                "email": r["email"],
                "full_name": r["full_name"] or "",
                "tenant_name": r["tenant_name"] or "",
                "tenant_slug": r["tenant_slug"] or "",
                "plan": r["requested_plan"] or "",
                "status": r["status"] or "",
            }
            for r in signup_rows
        ]
        new_signups_24h = sum(1 for s in signups if s["status"] != "waitlisted")
        waitlisted_24h = sum(1 for s in signups if s["status"] == "waitlisted")

        public_triage = {
            "calls": int(public_triage_row["calls"] or 0),
            "tokens": int(public_triage_row["tokens"] or 0),
            "cost_usd": float(public_triage_row["cost_usd"] or 0),
        }

        # Build per-draft approve/reject links with HMAC signatures so the
        # founder can act on inbound leads from the inbox without logging in.
        site_url = os.environ.get("PUBLIC_SITE_URL", "https://t1agentics.ai").rstrip("/")
        lead_drafts = []
        try:
            from services.inbound_lead_agent import hmac_for_action
            for r in lead_draft_rows:
                token = r["approval_token"]
                draft_id = str(r["id"])
                lead_drafts.append({
                    "id": draft_id,
                    "source_type": r["source_type"],
                    "email": r["lead_email"],
                    "name": r["lead_name"] or "",
                    "company": r["lead_company"] or "",
                    "classification": r["classification"],
                    "confidence": float(r["classification_confidence"] or 0),
                    "reason": r["classification_reason"] or "",
                    "subject": r["draft_subject"] or "",
                    "body": r["draft_body"] or "",
                    "approve_url": (
                        f"{site_url}/api/v1/lead-drafts/approve?id={draft_id}"
                        f"&token={token}&sig={hmac_for_action(token, 'approve')}"
                    ),
                    "reject_url": (
                        f"{site_url}/api/v1/lead-drafts/reject?id={draft_id}"
                        f"&token={token}&sig={hmac_for_action(token, 'reject')}"
                    ),
                })
        except Exception as exc:
            logger.warning("[COST_SUMMARY] failed to sign lead-draft links: %s", exc)
            lead_drafts = []

        html = render_admin_daily_summary(
            summary_date=summary_date,
            total_cost_usd=total_cost_usd,
            total_calls=total_calls,
            total_tokens=total_tokens,
            per_tenant_rows=per_tenant,
            new_signups_24h=new_signups_24h,
            waitlisted_24h=waitlisted_24h,
            signups=signups,
            public_triage=public_triage,
            lead_drafts=lead_drafts,
        )

        grand_total = total_cost_usd + public_triage["cost_usd"]
        svc = get_email_service()
        await svc.send_email(
            recipients,
            f"T1 Agentics daily summary {summary_date} — ${grand_total:.2f} total spend, {new_signups_24h} signup(s)",
            html,
        )
        logger.info(
            "[COST_SUMMARY] Sent daily summary for %s: $%.2f Claude + $%.2f public-triage, "
            "%d calls, %d signups, %d waitlisted",
            summary_date, total_cost_usd, public_triage["cost_usd"],
            total_calls, new_signups_24h, waitlisted_24h,
        )
    except Exception as exc:
        logger.error("[COST_SUMMARY] Failed to send daily summary: %s", exc, exc_info=True)


class CostSummaryScheduler:
    """Wraps APScheduler to fire ``send_daily_summary`` once per day."""

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.running = False

    async def start(self):
        if self.running:
            return
        hour = _summary_hour_utc()
        self.scheduler.add_job(
            send_daily_summary,
            CronTrigger(hour=hour, minute=0, timezone=timezone.utc),
            id="daily_cost_summary",
            replace_existing=True,
            misfire_grace_time=60 * 60,
        )
        self.scheduler.start()
        self.running = True
        logger.info("[COST_SUMMARY] Scheduler started; will fire daily at %02d:00 UTC", hour)

    async def stop(self):
        if not self.running:
            return
        self.scheduler.shutdown(wait=False)
        self.running = False
        logger.info("[COST_SUMMARY] Scheduler stopped")
