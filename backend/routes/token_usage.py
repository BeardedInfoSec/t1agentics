# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Token Usage API Routes

Provides endpoints for:
- Viewing token usage statistics
- Getting usage by provider/model
- Daily/monthly breakdowns
- Recent requests

All endpoints require authentication.
"""

from fastapi import APIRouter, Query, HTTPException, Depends
from typing import Optional
from datetime import datetime, timedelta

from dependencies.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/v1/ai/tokens", tags=["AI Token Usage"], dependencies=[Depends(get_current_user)])


def get_tracker():
    """Get token tracking service"""
    from services.token_tracking import get_token_tracker
    return get_token_tracker()


@router.get("/summary")
async def get_usage_summary(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    provider: Optional[str] = Query(None, description="Filter by provider"),
    model: Optional[str] = Query(None, description="Filter by model"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get token usage summary for a period

    Returns aggregated statistics including:
    - Total tokens used
    - Cost estimation
    - Request counts
    - Success/failure rates
    """
    tracker = get_tracker()

    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    summary = await tracker.get_usage_summary(
        start_date=start,
        end_date=end,
        provider=provider,
        model=model
    )

    return summary


@router.get("/daily")
async def get_daily_usage(
    days: int = Query(30, ge=1, le=365, description="Number of days"),
    provider: Optional[str] = Query(None, description="Filter by provider"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get daily token usage breakdown

    Returns daily aggregated statistics for charting
    """
    tracker = get_tracker()
    return await tracker.get_daily_usage(days=days, provider=provider)


@router.get("/by-provider")
async def get_usage_by_provider(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get token usage grouped by provider

    Useful for comparing costs across different AI providers
    """
    tracker = get_tracker()

    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await tracker.get_usage_by_provider(start_date=start, end_date=end)


@router.get("/by-model")
async def get_usage_by_model(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    limit: int = Query(20, ge=1, le=100, description="Max models to return"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get token usage grouped by model

    Returns top models by token usage
    """
    tracker = get_tracker()

    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await tracker.get_usage_by_model(start_date=start, end_date=end, limit=limit)


@router.get("/recent")
async def get_recent_requests(
    limit: int = Query(50, ge=1, le=200, description="Number of requests"),
    provider: Optional[str] = Query(None, description="Filter by provider"),
    status: Optional[str] = Query(None, description="Filter by status (success, failed)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get recent token usage requests

    Returns detailed information about recent AI calls
    """
    tracker = get_tracker()
    return await tracker.get_recent_requests(limit=limit, provider=provider, status=status)


@router.get("/quota")
async def get_quota_status(current_user: dict = Depends(get_current_user)):
    """
    Get current Claude token quota status for the authenticated tenant.

    Uses the tenant_claude_usage cache for fast lookups. Falls back to
    aggregating ai_token_usage if tenant context is unavailable.

    Returns:
    - Monthly token allowance from license tier
    - Tokens used this month
    - Remaining tokens and usage percentage
    - Overage info for Stripe-billed tenants
    - Days until monthly reset
    """
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # Calculate days until reset
    if now.month == 12:
        next_month = now.replace(year=now.year + 1, month=1, day=1)
    else:
        next_month = now.replace(month=now.month + 1, day=1)
    days_until_reset = (next_month - now).days

    # Try to get tenant-specific quota from tenant_claude_usage cache
    try:
        from services.postgres_db import postgres_db

        # Resolve tenant_id from current user
        tenant_id = None
        if hasattr(current_user, 'tenant_id'):
            tenant_id = current_user.tenant_id
        elif isinstance(current_user, dict):
            tenant_id = current_user.get('tenant_id')

        if tenant_id and postgres_db.connected and postgres_db.pool:
            import uuid as _uuid
            if isinstance(tenant_id, str):
                tenant_id = _uuid.UUID(tenant_id)

            async with postgres_db.tenant_acquire() as conn:
                # Get usage from monthly cache
                usage_row = await conn.fetchrow(
                    """
                    SELECT total_tokens, total_input_tokens, total_output_tokens,
                           total_cost_cents, overage_tokens
                    FROM tenant_claude_usage
                    WHERE tenant_id = $1
                      AND month_start = date_trunc('month', CURRENT_DATE)::date
                    """,
                    tenant_id,
                )

                tokens_used = usage_row["total_tokens"] if usage_row else 0
                cost_cents = float(usage_row["total_cost_cents"]) if usage_row else 0
                overage_tokens = usage_row["overage_tokens"] if usage_row else 0

                # Get tier limit
                tier_row = await conn.fetchrow(
                    """
                    SELECT tl.tier FROM tenants t
                    JOIN tenant_licenses tl ON t.active_license_id = tl.id
                    WHERE t.id = $1
                    """,
                    tenant_id,
                )

                monthly_quota = 0
                tier_name = "unknown"
                if tier_row:
                    tier_name = tier_row["tier"]
                    from services.licensing.default_plans import get_default_entitlements
                    from services.licensing.models import LicenseTier
                    try:
                        tier = LicenseTier(tier_name)
                        entitlements = get_default_entitlements(tier)
                        monthly_quota = entitlements.llm.managed_tokens_per_month
                    except (ValueError, KeyError):
                        monthly_quota = 0

                # Get request count this month
                req_count = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM ai_token_usage
                    WHERE tenant_id = $1 AND created_at >= $2
                    """,
                    tenant_id, month_start,
                )

                is_unlimited = monthly_quota >= 999_999_999
                tokens_remaining = -1 if is_unlimited else max(0, monthly_quota - tokens_used)

                return {
                    "monthly_quota": monthly_quota,
                    "unlimited": is_unlimited,
                    "tokens_used": tokens_used,
                    "tokens_remaining": tokens_remaining,
                    "usage_percentage": 0 if is_unlimited else (
                        round((tokens_used / monthly_quota) * 100, 2) if monthly_quota > 0 else 0
                    ),
                    "estimated_cost_usd": cost_cents / 100,
                    "overage_tokens": overage_tokens,
                    "tier": tier_name,
                    "days_until_reset": days_until_reset,
                    "period": {
                        "start": month_start.isoformat(),
                        "end": next_month.isoformat()
                    },
                    "request_count": req_count or 0,
                }
    except Exception:
        pass  # Fall through to legacy path

    # Fallback: aggregate from ai_token_usage (legacy path)
    tracker = get_tracker()
    summary = await tracker.get_usage_summary(start_date=month_start, end_date=now)
    tokens_used = summary.get("total_tokens", 0)

    return {
        "monthly_quota": 1_000_000,
        "unlimited": False,
        "tokens_used": tokens_used,
        "tokens_remaining": max(0, 1_000_000 - tokens_used),
        "usage_percentage": round((tokens_used / 1_000_000) * 100, 2) if tokens_used else 0,
        "estimated_cost_usd": summary.get("total_cost_usd", 0),
        "overage_tokens": 0,
        "tier": "unknown",
        "days_until_reset": days_until_reset,
        "period": {
            "start": month_start.isoformat(),
            "end": next_month.isoformat()
        },
        "request_count": summary.get("request_count", 0),
    }


@router.delete("/reset")
async def reset_token_usage(current_user: dict = Depends(require_admin)):
    """
    Reset all token usage data. ADMIN ONLY.

    This permanently deletes all token usage records.
    Use with caution - this action cannot be undone.
    """
    tracker = get_tracker()
    result = await tracker.reset_all()

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to reset token usage"))

    return result


@router.get("/stats/realtime")
async def get_realtime_stats(current_user: dict = Depends(get_current_user)):
    """
    Get real-time token usage stats for dashboard

    Returns quick stats for the dashboard widget
    """
    tracker = get_tracker()
    now = datetime.utcnow()

    # Today's usage
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_summary = await tracker.get_usage_summary(start_date=today_start, end_date=now)

    # This week's usage
    week_start = now - timedelta(days=now.weekday())
    week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
    week_summary = await tracker.get_usage_summary(start_date=week_start, end_date=now)

    # This month's usage
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_summary = await tracker.get_usage_summary(start_date=month_start, end_date=now)

    # By provider breakdown for this month
    by_provider = await tracker.get_usage_by_provider(start_date=month_start, end_date=now)

    return {
        "today": {
            "tokens": today_summary.get("total_tokens", 0),
            "requests": today_summary.get("request_count", 0),
            "cost_usd": today_summary.get("total_cost_usd", 0)
        },
        "this_week": {
            "tokens": week_summary.get("total_tokens", 0),
            "requests": week_summary.get("request_count", 0),
            "cost_usd": week_summary.get("total_cost_usd", 0)
        },
        "this_month": {
            "tokens": month_summary.get("total_tokens", 0),
            "requests": month_summary.get("request_count", 0),
            "cost_usd": month_summary.get("total_cost_usd", 0)
        },
        "by_provider": by_provider
    }
