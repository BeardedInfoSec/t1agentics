# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Enforcement Dependencies for FastAPI Routes

Lightweight enforcement checks that query the database for:
  - Tenant license tier (from tenant_licenses table)
  - Current resource counts
  - Tier limits (from default_plans.py)

Usage:
    @router.post("/users")
    async def create_user(
        ...,
        _limit: None = Depends(enforce_user_limit),
    ):
        ...
"""

import logging
from datetime import datetime, timezone
from fastapi import Request, HTTPException, Depends
from typing import Optional, Dict, Tuple

from services.licensing.models import LicenseTier
from services.licensing.default_plans import get_default_entitlements

logger = logging.getLogger(__name__)

# Map DB tier strings to LicenseTier enum.
# Source of truth for valid DB values is the CHECK constraint in
# migrations/022_stripe_enforcement.sql. Every value allowed there must
# appear here, or _TIER_MAP.get(..., FREE) will silently downgrade real
# paying tenants. There is no ENTERPRISE_PLUS enum value, so we collapse
# it to ENTERPRISE (same feature set, custom pricing).
_TIER_MAP = {
    "community": LicenseTier.FREE,
    "free": LicenseTier.FREE,
    "dev": LicenseTier.DEV,
    "core": LicenseTier.CORE,
    "starter": LicenseTier.STARTER,
    "professional": LicenseTier.PRO,
    "pro": LicenseTier.PRO,
    "poc": LicenseTier.PRO,             # POC has Pro-equivalent limits
    "trial": LicenseTier.PRO,           # Trial has Pro-equivalent limits
    "enterprise": LicenseTier.ENTERPRISE,
    "enterprise_plus": LicenseTier.ENTERPRISE,
    "platform": LicenseTier.UNLIMITED,  # T1 platform tenant itself
    "unlimited": LicenseTier.UNLIMITED,
}


async def _get_tenant_tier(tenant_id: str) -> LicenseTier:
    """Resolve the tenant's license tier from the database."""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return LicenseTier.UNLIMITED  # self-hosted fallback

        # Must use platform admin bypass because tenant_licenses has RLS.
        # Without it, get_tenant_license_tier() can't see any rows and
        # always falls back to 'community'.
        async with postgres_db.pool.acquire() as conn:
            await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
            tier_str = await conn.fetchval(
                "SELECT get_tenant_license_tier($1::uuid)", tenant_id
            )
        return _TIER_MAP.get((tier_str or "").lower(), LicenseTier.FREE)
    except Exception as e:
        logger.warning(f"Failed to resolve tenant tier for {tenant_id}: {e}")
        return LicenseTier.UNLIMITED  # fail-open for safety


async def _get_tenant_id_from_request(request: Request) -> Optional[str]:
    """Extract tenant_id from request state (set by tenant middleware)."""
    return getattr(request.state, "tenant_id", None)


# =========================================================================
# USER LIMIT
# =========================================================================

async def enforce_user_limit(request: Request) -> None:
    """
    FastAPI dependency that blocks user creation if tenant is at the user limit.
    Attach with: Depends(enforce_user_limit)
    """
    tenant_id = await _get_tenant_id_from_request(request)
    if not tenant_id:
        return  # no tenant context — skip enforcement

    tier = await _get_tenant_tier(str(tenant_id))
    entitlements = get_default_entitlements(tier)
    max_users = entitlements.max_users

    try:
        from services.postgres_db import postgres_db
        current_users = await postgres_db.pool.fetchval(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND disabled = false",
            tenant_id,
        )
    except Exception as e:
        logger.warning(f"Failed to count users for tenant {tenant_id}: {e}")
        return  # fail-open

    if current_users >= max_users:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "limit_exceeded",
                "resource": "users",
                "current": current_users,
                "limit": max_users,
                "tier": tier.value,
                "message": f"User limit reached ({current_users}/{max_users}). Please upgrade your plan.",
            },
        )


# =========================================================================
# INTEGRATION LIMIT
# =========================================================================

async def enforce_integration_limit(request: Request) -> None:
    """
    FastAPI dependency that blocks connector installation if at the integration limit.
    Attach with: Depends(enforce_integration_limit)
    """
    tenant_id = await _get_tenant_id_from_request(request)
    if not tenant_id:
        return

    tier = await _get_tenant_tier(str(tenant_id))
    entitlements = get_default_entitlements(tier)
    max_integrations = entitlements.integrations.max_integrations

    try:
        from services.postgres_db import postgres_db
        current_integrations = await postgres_db.pool.fetchval(
            "SELECT COUNT(*) FROM connect_instances WHERE tenant_id = $1::uuid AND enabled = true",
            str(tenant_id),
        )
    except Exception as e:
        logger.warning(f"Failed to count integrations for tenant {tenant_id}: {e}")
        return

    if current_integrations >= max_integrations:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "limit_exceeded",
                "resource": "integrations",
                "current": current_integrations,
                "limit": max_integrations,
                "tier": tier.value,
                "message": f"Integration limit reached ({current_integrations}/{max_integrations}). Please upgrade your plan.",
            },
        )


# =========================================================================
# FEATURE GATE
# =========================================================================

def enforce_feature(feature: str):
    """
    Factory: creates a FastAPI dependency that blocks if a feature is not enabled.

    Usage:
        @router.post("/playbooks/{id}/execute")
        async def execute(... , _gate: None = Depends(enforce_feature("custom_playbooks"))):
            ...
    """
    async def _check(request: Request) -> None:
        tenant_id = await _get_tenant_id_from_request(request)
        if not tenant_id:
            return

        tier = await _get_tenant_tier(str(tenant_id))
        entitlements = get_default_entitlements(tier)

        if not entitlements.features.get(feature, False):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "feature_not_licensed",
                    "feature": feature,
                    "tier": tier.value,
                    "message": f"Feature '{feature}' is not available on your {tier.value} plan. Please upgrade.",
                },
            )
    return _check


# =========================================================================
# RIGGS AI USAGE LIMIT
# =========================================================================

def enforce_riggs_limit(feature_type: str):
    """
    Factory: creates a FastAPI dependency that enforces per-feature monthly
    usage limits for Riggs AI features.

    feature_type: "riggs_chat" or "riggs_playbook_create"

    Free tier has hard monthly caps (e.g. 100 chats, 5 playbook creations).
    Pro+ tiers have limit=0 which means unlimited — always passes.

    Usage:
        @router.post("/generate")
        async def generate(
            ...,
            _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
        ):
            ...
    """
    async def _check(request: Request) -> None:
        tenant_id = await _get_tenant_id_from_request(request)
        if not tenant_id:
            return  # no tenant context — skip

        tier = await _get_tenant_tier(str(tenant_id))
        entitlements = get_default_entitlements(tier)

        # Determine the limit for this feature
        if feature_type == "riggs_chat":
            limit = entitlements.riggs.chat_messages_per_month
        elif feature_type == "riggs_playbook_create":
            limit = entitlements.riggs.playbook_creations_per_month
        else:
            return  # unknown feature type — fail-open

        # 0 = unlimited (Pro+ tiers)
        if limit == 0:
            return

        # Count this month's usage from ai_token_usage
        try:
            from services.postgres_db import postgres_db
            if not postgres_db.connected or not postgres_db.pool:
                return  # fail-open

            now = datetime.now(timezone.utc)
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

            current_usage = await postgres_db.pool.fetchval(
                """
                SELECT COUNT(*) FROM ai_token_usage
                WHERE tenant_id = $1::uuid
                  AND request_type = $2
                  AND created_at >= $3
                """,
                str(tenant_id),
                feature_type,
                month_start,
            )
        except Exception as e:
            logger.warning(f"Failed to count Riggs usage for tenant {tenant_id}: {e}")
            return  # fail-open

        if current_usage >= limit:
            remaining = max(0, limit - current_usage)
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "riggs_limit_exceeded",
                    "feature": feature_type,
                    "current": current_usage,
                    "limit": limit,
                    "remaining": remaining,
                    "tier": tier.value,
                    "message": (
                        f"Monthly {feature_type.replace('_', ' ')} limit reached "
                        f"({current_usage}/{limit}). Upgrade to Pro for unlimited access."
                    ),
                    "upgrade_url": "/pricing",
                },
            )
    return _check


async def get_deep_dive_usage(tenant_id: str) -> Dict:
    """Get current month's deep dive usage for a tenant."""
    tier = await _get_tenant_tier(tenant_id)
    entitlements = get_default_entitlements(tier)
    limit = entitlements.features.get("deep_dive_monthly_limit", 0)

    # 0 = unlimited (Pro+ tiers)
    if limit == 0:
        return {"used": 0, "limit": 0, "remaining": 0, "unlimited": True}

    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return {"used": 0, "limit": limit, "remaining": limit, "unlimited": False}

        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        current_usage = await postgres_db.pool.fetchval(
            """
            SELECT COUNT(*) FROM ai_token_usage
            WHERE tenant_id = $1::uuid
              AND request_type = 'deep_dive'
              AND created_at >= $2
            """,
            str(tenant_id),
            month_start,
        )
        used = current_usage or 0
        return {
            "used": used,
            "limit": limit,
            "remaining": max(0, limit - used),
            "unlimited": False,
        }
    except Exception as e:
        logger.warning(f"Failed to get deep dive usage for {tenant_id}: {e}")
        return {"used": 0, "limit": limit, "remaining": limit, "unlimited": False}


async def get_riggs_usage(tenant_id: str, feature_type: str) -> Dict:
    """Get current month's Riggs usage for a specific feature."""
    tier = await _get_tenant_tier(tenant_id)
    entitlements = get_default_entitlements(tier)

    if feature_type == "riggs_chat":
        limit = entitlements.riggs.chat_messages_per_month
    elif feature_type == "riggs_playbook_create":
        limit = entitlements.riggs.playbook_creations_per_month
    else:
        return {"used": 0, "limit": 0, "unlimited": True}

    if limit == 0:
        return {"used": 0, "limit": 0, "unlimited": True}

    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return {"used": 0, "limit": limit, "unlimited": False}

        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        current_usage = await postgres_db.pool.fetchval(
            """
            SELECT COUNT(*) FROM ai_token_usage
            WHERE tenant_id = $1::uuid
              AND request_type = $2
              AND created_at >= $3
            """,
            str(tenant_id),
            feature_type,
            month_start,
        )
        return {
            "used": current_usage or 0,
            "limit": limit,
            "remaining": max(0, limit - (current_usage or 0)),
            "unlimited": False,
        }
    except Exception as e:
        logger.warning(f"Failed to get Riggs usage for {tenant_id}: {e}")
        return {"used": 0, "limit": limit, "unlimited": False}


# =========================================================================
# HELPER: get limits for API response (for UI display)
# =========================================================================

async def get_tenant_limits(tenant_id: str) -> Dict:
    """
    Return the resolved limits for a tenant (for dashboards / profile pages).
    Includes features and riggs limits for frontend license cache.
    """
    tier = await _get_tenant_tier(tenant_id)
    ent = get_default_entitlements(tier)

    # Get current Riggs usage counts for this month
    riggs_chat_usage = await get_riggs_usage(tenant_id, "riggs_chat")
    riggs_playbook_usage = await get_riggs_usage(tenant_id, "riggs_playbook_create")
    deep_dive_usage = await get_deep_dive_usage(tenant_id)

    return {
        "tier": tier.value,
        "max_users": ent.max_users,
        "max_integrations": ent.integrations.max_integrations,
        "investigations_per_month": ent.investigations_per_month,
        "automation_runs_per_month": ent.automation_runs_per_month,
        "managed_tokens_per_month": ent.llm.managed_tokens_per_month,
        "data_retention_days": ent.data_retention_days,
        "features": ent.features,
        "riggs_limits": {
            "chat_messages_per_month": ent.riggs.chat_messages_per_month,
            "playbook_creations_per_month": ent.riggs.playbook_creations_per_month,
        },
        "riggs_usage": {
            "chat": riggs_chat_usage,
            "playbook_create": riggs_playbook_usage,
        },
        "deep_dive_usage": deep_dive_usage,
        "default_model": ent.llm.default_model,
    }
