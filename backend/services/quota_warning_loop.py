# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Proactive tenant quota warning sweep.

Issue #16 said: "80% quota warning fires post-hoc, not proactively."
The old behavior was to attach a warning string to the response of the
call that crossed 80% — meaning the tenant had already paid for that
call AND only saw the warning if they happened to look at that response.

New behavior: a periodic background task scans every tenant's MTD
Claude usage and emails the tenant admin when they first cross 80%
(warning) and again at 100% (block notice) for the current billing
period. tenant_quota_warnings has a UNIQUE constraint on
(tenant_id, period, threshold) so each threshold fires once per
period — no alert spam if the tenant hovers around 80% for the rest
of the month.

Wired into app.py:lifespan as an asyncio task, runs every 30 minutes.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Thresholds we proactively notify on. Order matters — we send each
# the first time it crosses, but skip lower thresholds if the tenant
# already crossed a higher one this period (no point telling someone
# "you hit 80%" when they hit 100% an hour ago).
THRESHOLDS = [
    ("warning", 0.80),
    ("block",   1.00),
]


async def _fetch_tenants_to_check() -> List[Dict[str, Any]]:
    """
    Return active tenants with their managed Claude token quota for
    the current period and their MTD consumption.

    Joins tenants -> plan -> tenant_claude_usage. Uses platform-admin
    mode so the sweep sees every tenant. Excludes tenants with a 0 or
    unlimited (huge) quota — nothing to warn about for either.
    """
    from services.postgres_db import postgres_db, set_platform_admin_mode

    if not postgres_db.connected or not postgres_db.pool:
        return []

    rows = []
    set_platform_admin_mode(True)
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                WITH usage_this_month AS (
                    SELECT tenant_id, COALESCE(total_tokens, 0) AS used
                    FROM tenant_claude_usage
                    WHERE month_start = date_trunc('month', CURRENT_DATE)::date
                )
                SELECT
                    t.id          AS tenant_id,
                    t.name        AS tenant_name,
                    t.plan        AS plan_string,
                    COALESCE(u.used, 0) AS used_tokens
                FROM tenants t
                LEFT JOIN usage_this_month u ON u.tenant_id = t.id
                WHERE t.is_active = true
                """
            )
    except Exception as e:
        logger.error(f"Quota warning sweep: tenant fetch failed: {e}")
        return []
    finally:
        set_platform_admin_mode(False)

    return [dict(r) for r in rows]


def _quota_for_plan(plan_string: str) -> int:
    """
    Look up the managed token quota for this plan string. Maps from the
    DB plan column to the LicenseTier enum, then to entitlements.
    """
    try:
        from dependencies.license_checks import _TIER_MAP
        from services.licensing.default_plans import get_default_entitlements
        from services.licensing.models import LicenseTier

        tier = _TIER_MAP.get((plan_string or "").lower(), LicenseTier.FREE)
        ent = get_default_entitlements(tier)
        return int(ent.llm.managed_tokens_per_month or 0)
    except Exception as e:
        logger.warning(f"Could not resolve quota for plan '{plan_string}': {e}")
        return 0


async def _already_sent(conn, tenant_id: str, period: str, threshold: str) -> bool:
    """True if we've already sent this threshold to this tenant this period."""
    row = await conn.fetchrow(
        """
        SELECT 1 FROM tenant_quota_warnings
        WHERE tenant_id = $1::uuid AND period = $2 AND threshold = $3
        """,
        str(tenant_id),
        period,
        threshold,
    )
    return row is not None


async def _record_sent(conn, tenant_id: str, period: str, threshold: str) -> bool:
    """Insert the notification record. ON CONFLICT DO NOTHING — returns
    True if this was the first time and we should actually send."""
    row = await conn.fetchval(
        """
        INSERT INTO tenant_quota_warnings (tenant_id, period, threshold)
        VALUES ($1::uuid, $2, $3)
        ON CONFLICT (tenant_id, period, threshold) DO NOTHING
        RETURNING 1
        """,
        str(tenant_id),
        period,
        threshold,
    )
    return row is not None


async def _send_email(tenant: Dict[str, Any], threshold: str, used: int, limit: int) -> None:
    """
    Fire off the notification email to the tenant admin.

    Reuses the existing email_service. Best-effort — a failed send
    leaves the row in tenant_quota_warnings (so we don't infinite-retry)
    but logs loudly so ops can re-trigger if needed.
    """
    try:
        from services.email_service import get_email_service

        pct = int(round((used / limit) * 100)) if limit else 0
        tier_msg = (
            "You've used about 80% of this month's Claude token allowance."
            if threshold == "warning"
            else "You've reached this month's Claude token cap."
        )
        verb_msg = (
            "You can keep using AI features through the rest of the month, but consider upgrading if you expect heavier usage."
            if threshold == "warning"
            else "AI features are blocked for the rest of the billing period unless you upgrade. Investigations still work — Riggs deep-dive will pause."
        )

        body_text = (
            f"Hi from T1 Agentics,\n\n"
            f"{tier_msg}\n\n"
            f"Tenant: {tenant.get('tenant_name', 'your team')}\n"
            f"Usage: {used:,} of {limit:,} tokens ({pct}%)\n"
            f"Period: this month\n\n"
            f"{verb_msg}\n\n"
            f"Manage your plan: https://t1agentics.ai/dashboard\n"
        )
        body_html = (
            f"<p>Hi from T1 Agentics,</p>"
            f"<p>{tier_msg}</p>"
            f"<ul>"
            f"<li><strong>Tenant:</strong> {tenant.get('tenant_name', 'your team')}</li>"
            f"<li><strong>Usage:</strong> {used:,} of {limit:,} tokens ({pct}%)</li>"
            f"<li><strong>Period:</strong> this month</li>"
            f"</ul>"
            f"<p>{verb_msg}</p>"
            f"<p><a href=\"https://t1agentics.ai/dashboard\">Manage your plan</a></p>"
        )

        subject = (
            f"T1 Agentics: 80% Claude token usage warning"
            if threshold == "warning"
            else f"T1 Agentics: Claude token cap reached"
        )

        # Resolve the tenant admin email. For now, we send to all admins
        # of the tenant; future enhancement could let tenants pick a
        # billing contact specifically.
        from services.postgres_db import postgres_db
        async with postgres_db.tenant_acquire() as conn:
            admin_rows = await conn.fetch(
                """
                SELECT email FROM users
                WHERE tenant_id = $1::uuid
                  AND role IN ('admin', 'platform_owner', 'platform_admin')
                  AND email IS NOT NULL
                """,
                str(tenant["tenant_id"]),
            )

        recipients = [r["email"] for r in admin_rows if r["email"]]
        if not recipients:
            logger.warning(
                f"No admin email for tenant {tenant['tenant_id']} — quota {threshold} not sent"
            )
            return

        email_service = get_email_service()
        await email_service.send_email(
            to=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        logger.info(
            f"Sent quota {threshold} notification to {len(recipients)} admin(s) "
            f"for tenant {tenant['tenant_id']} ({pct}% used)"
        )
    except Exception as e:
        logger.error(
            f"Failed to send quota {threshold} email for tenant "
            f"{tenant.get('tenant_id')}: {e}"
        )


async def _evaluate_tenant(tenant: Dict[str, Any]) -> None:
    """Check one tenant against each threshold; send if first-time crossing."""
    from services.postgres_db import postgres_db, set_platform_admin_mode

    limit = _quota_for_plan(tenant.get("plan_string", ""))
    used = int(tenant.get("used_tokens") or 0)

    # Unlimited plans (~1B+ tokens) and zero-quota dev plans don't get
    # warnings. The remaining tiers have meaningful caps.
    if limit <= 0 or limit > 100_000_000_000:
        return

    pct = used / limit
    if pct < THRESHOLDS[0][1]:
        return  # nothing to send

    period = datetime.now(timezone.utc).strftime("%Y-%m")

    # Determine the highest threshold the tenant has crossed this period
    # but not yet been notified about. We send only ONE email per check
    # cycle — the highest unsent threshold.
    set_platform_admin_mode(True)
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Walk thresholds high-to-low so we send the most relevant one
            for name, level in reversed(THRESHOLDS):
                if pct < level:
                    continue
                if await _already_sent(conn, tenant["tenant_id"], period, name):
                    return  # higher threshold already sent; no further work
                # Claim the slot (UNIQUE constraint dedups against races)
                if await _record_sent(conn, tenant["tenant_id"], period, name):
                    await _send_email(tenant, name, used, limit)
                    return
    finally:
        set_platform_admin_mode(False)


async def cleanup_loop(interval_seconds: int = 1800) -> None:
    """
    Main loop. Sweeps every 30 minutes by default. The first tick is
    delayed 90 seconds so app startup isn't blocked on email fanout.
    """
    await asyncio.sleep(90)
    while True:
        try:
            tenants = await _fetch_tenants_to_check()
            for tenant in tenants:
                try:
                    await _evaluate_tenant(tenant)
                except Exception as e:
                    logger.error(
                        f"Quota warning sweep: tenant "
                        f"{tenant.get('tenant_id')} eval failed: {e}"
                    )
        except Exception as e:
            logger.error(f"Quota warning sweep tick failed: {e}")
        await asyncio.sleep(interval_seconds)
