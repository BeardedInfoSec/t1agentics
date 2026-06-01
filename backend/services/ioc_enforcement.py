# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IOC Limit Enforcement

Enforces per-tenant IOC storage caps based on license tier.
When the cap is reached, the oldest IOCs (by first_seen) are evicted
to keep the total count at or below the limit.

Tier limits (iocs_max):
    Community:       50,000
    POC:             250,000
    Professional:    500,000  (add-on available via LicenseManager.set_ioc_addon())
    Enterprise:      Unlimited (-1)
    Enterprise Plus: Unlimited (-1)
"""

import logging
from typing import Optional

from services.license_manager import TIER_LIMITS, LicenseTier, get_license_manager

logger = logging.getLogger(__name__)


async def get_tenant_ioc_limit(conn, tenant_id=None) -> int:
    """
    Look up the IOC limit for a tenant based on their active license tier.

    Falls back to tenants.plan when no tenant_licenses row exists.

    Returns:
        int: Max IOC count (-1 = unlimited, 0 = no IOCs allowed)
    """
    try:
        tier_str = None

        if tenant_id:
            row = await conn.fetchrow(
                """
                SELECT tl.tier, t.plan
                FROM tenants t
                LEFT JOIN tenant_licenses tl
                    ON t.active_license_id = tl.id AND tl.is_active = true
                WHERE t.id = $1
                """,
                tenant_id
            )
            if row:
                tier_str = row["tier"] or row["plan"]
        else:
            # Platform-wide fallback: use the highest plan across active tenants
            row = await conn.fetchrow(
                """
                SELECT tl.tier, t.plan
                FROM tenants t
                LEFT JOIN tenant_licenses tl
                    ON t.active_license_id = tl.id AND tl.is_active = true
                WHERE t.status = 'active'
                ORDER BY tl.created_at DESC NULLS LAST
                LIMIT 1
                """
            )
            if row:
                tier_str = row["tier"] or row["plan"]

        if not tier_str:
            logger.warning("No plan/license found; defaulting to community IOC limit")
            return TIER_LIMITS[LicenseTier.COMMUNITY].iocs_max

        try:
            tier = LicenseTier(tier_str.lower())
        except ValueError:
            logger.warning(f"Unknown license tier '{tier_str}'; defaulting to community")
            return TIER_LIMITS[LicenseTier.COMMUNITY].iocs_max

        base_limit = TIER_LIMITS[tier].iocs_max
        if base_limit == -1:
            return -1  # Unlimited

        # Add any IOC addon capacity from the license manager
        try:
            manager = get_license_manager()
            addon = manager.get_license().ioc_addon_capacity
            return base_limit + addon
        except Exception:
            return base_limit

    except Exception as e:
        logger.error(f"Failed to look up tenant IOC limit: {e}")
        return TIER_LIMITS[LicenseTier.COMMUNITY].iocs_max


async def get_ioc_count(conn) -> int:
    """Return the total number of IOCs in the database."""
    count = await conn.fetchval("SELECT COUNT(*) FROM iocs")
    return count or 0


async def enforce_ioc_limit(conn, tenant_id=None) -> dict:
    """
    Enforce the IOC storage cap for a tenant.

    If the IOC count exceeds the tier limit, the oldest IOCs (by first_seen)
    are deleted until the count is at or below the limit.

    Returns:
        dict with keys: enforced (bool), deleted (int), current_count (int), limit (int)
    """
    limit = await get_tenant_ioc_limit(conn, tenant_id)

    # Unlimited tier — nothing to enforce
    if limit < 0:
        return {"enforced": False, "deleted": 0, "current_count": -1, "limit": limit}

    current_count = await get_ioc_count(conn)

    if current_count <= limit:
        return {"enforced": False, "deleted": 0, "current_count": current_count, "limit": limit}

    excess = current_count - limit
    logger.info(
        f"IOC limit enforcement: {current_count} IOCs exceeds limit of {limit}. "
        f"Evicting {excess} oldest IOCs."
    )

    # Delete the oldest IOCs by first_seen.
    # execute() returns "DELETE N" — parse N for the count.
    result = await conn.execute(
        """
        WITH to_delete AS (
            SELECT id FROM iocs
            ORDER BY first_seen ASC
            LIMIT $1
        )
        DELETE FROM iocs
        WHERE id IN (SELECT id FROM to_delete)
        """,
        excess
    )
    try:
        deleted = int(result.split()[-1])
    except Exception:
        deleted = excess

    # Also clean up orphaned references in related tables
    await _cleanup_orphaned_references(conn)

    final_count = await get_ioc_count(conn)
    logger.info(f"IOC eviction complete: deleted {deleted}, remaining {final_count}")

    return {
        "enforced": True,
        "deleted": deleted or excess,
        "current_count": final_count,
        "limit": limit,
    }


async def _cleanup_orphaned_references(conn):
    """Remove references to IOCs that no longer exist."""
    try:
        # Clean up alert_ioc_links pointing to deleted IOCs
        await conn.execute(
            """
            DELETE FROM alert_ioc_links
            WHERE NOT EXISTS (
                SELECT 1 FROM iocs
                WHERE iocs.ioc_value = alert_ioc_links.ioc_value
                  AND iocs.ioc_type = alert_ioc_links.ioc_type
            )
            """
        )
        # Clean up campaign_iocs pointing to deleted IOCs
        await conn.execute(
            """
            DELETE FROM campaign_iocs
            WHERE NOT EXISTS (
                SELECT 1 FROM iocs
                WHERE iocs.ioc_value = campaign_iocs.ioc_value
                  AND iocs.ioc_type = campaign_iocs.ioc_type
            )
            """
        )
    except Exception as e:
        # Non-fatal: orphan cleanup is best-effort
        logger.warning(f"Orphan cleanup error (non-fatal): {e}")


async def check_ioc_quota(conn, tenant_id=None) -> dict:
    """
    Check IOC quota status without enforcing.

    Returns:
        dict with: count, limit, remaining, percentage, at_limit (bool)
    """
    limit = await get_tenant_ioc_limit(conn, tenant_id)
    count = await get_ioc_count(conn)

    if limit < 0:
        return {
            "count": count,
            "limit": "unlimited",
            "remaining": "unlimited",
            "percentage": 0,
            "at_limit": False,
        }

    remaining = max(0, limit - count)
    percentage = round((count / limit) * 100, 1) if limit > 0 else 100

    return {
        "count": count,
        "limit": limit,
        "remaining": remaining,
        "percentage": percentage,
        "at_limit": count >= limit,
    }
