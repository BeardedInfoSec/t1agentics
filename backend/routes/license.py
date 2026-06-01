# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Management API Routes

Endpoints for license activation, validation, and status checking.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any

from services.license_manager import get_license_manager, LicenseTier
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/license", tags=["license"])


class LicenseActivationRequest(BaseModel):
    """Request to activate a license key."""
    license_key: str


class LicenseStatusResponse(BaseModel):
    """License status response."""
    tier: str
    organization: str
    is_valid: bool
    message: str
    expires_at: Optional[str]
    limits: Dict[str, Any]
    usage: Dict[str, Any]
    features: list


@router.get("/status")
async def get_license_status() -> Dict[str, Any]:
    """
    Get current license status and usage.

    Returns license tier, limits, current usage, and available features.
    This endpoint is always accessible (no auth required for bootstrapping).
    """
    try:
        license_manager = get_license_manager()
        return license_manager.get_status()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_license_status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/activate")
async def activate_license(
    request: LicenseActivationRequest,
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Activate a new license key.

    Requires admin role. Validates the license key and activates it if valid.
    """
    try:
        # Only admins can activate licenses
        if current_user.get("role") not in ("admin", "super_admin"):
            raise HTTPException(
                status_code=403,
                detail="Only administrators can activate licenses"
            )

        license_manager = get_license_manager()
        success, message = license_manager.activate_license(request.license_key)

        if not success:
            raise HTTPException(status_code=400, detail=message)

        logger.info(f"License activated by {current_user.get('username')}: {message}")

        return {
            "success": True,
            "message": message,
            "status": license_manager.get_status()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in activate_license: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/limits")
async def get_license_limits() -> Dict[str, Any]:
    """
    Get current license limits and usage.

    Returns detailed breakdown of limits vs current usage.
    """
    try:
        license_manager = get_license_manager()
        license_obj = license_manager.get_license()
        usage = license_manager.get_usage()

        limits = license_obj.limits

        def calc_remaining(limit: int, used: int) -> int:
            if limit == -1:
                return -1  # Unlimited
            return max(0, limit - used)

        return {
            "tier": license_obj.tier.value,
            "resources": {
                "alerts_per_day": {
                    "limit": limits.alerts_per_day,
                    "used": usage.alerts_today,
                    "remaining": calc_remaining(limits.alerts_per_day, usage.alerts_today)
                },
                "playbooks": {
                    "limit": limits.playbooks_max,
                    "used": usage.playbooks_count,
                    "remaining": calc_remaining(limits.playbooks_max, usage.playbooks_count)
                },
                "integrations": {
                    "limit": limits.integrations_max,
                    "used": usage.integrations_count,
                    "remaining": calc_remaining(limits.integrations_max, usage.integrations_count)
                },
                "users": {
                    "limit": limits.users_max,
                    "used": usage.users_count,
                    "remaining": calc_remaining(limits.users_max, usage.users_count)
                },
                "ai_queries_per_day": {
                    "limit": limits.ai_queries_per_day,
                    "used": usage.ai_queries_today,
                    "remaining": calc_remaining(limits.ai_queries_per_day, usage.ai_queries_today)
                }
            },
            "features": limits.features,
            "support_level": limits.support_level,
            "retention_days": limits.retention_days
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_license_limits: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/check/{resource}")
async def check_resource_limit(
    resource: str,
    increment: int = 1
) -> Dict[str, Any]:
    """
    Check if a specific resource limit allows an operation.

    Args:
        resource: One of 'alerts', 'playbooks', 'integrations', 'users', 'ai_queries'
        increment: Amount to add (default 1)

    Returns:
        Whether the operation is allowed and current limit info.
    """
    try:
        valid_resources = {"alerts", "playbooks", "integrations", "users", "ai_queries"}
        if resource not in valid_resources:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid resource. Must be one of: {', '.join(valid_resources)}"
            )

        license_manager = get_license_manager()
        allowed, message = license_manager.check_limit(resource, increment)

        return {
            "resource": resource,
            "allowed": allowed,
            "message": message
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in check_resource_limit: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/features")
async def get_licensed_features() -> Dict[str, Any]:
    """
    Get list of features available in current license.
    """
    try:
        license_manager = get_license_manager()
        license_obj = license_manager.get_license()

        # All possible features with their tier requirements
        all_features = {
            "basic_alerts": {"name": "Basic Alerts", "min_tier": "community"},
            "basic_playbooks": {"name": "Basic Playbooks", "min_tier": "community"},
            "basic_enrichment": {"name": "Basic Enrichment", "min_tier": "community"},
            "advanced_playbooks": {"name": "Advanced Playbooks", "min_tier": "professional"},
            "custom_integrations": {"name": "Custom Integrations", "min_tier": "professional"},
            "api_access": {"name": "API Access", "min_tier": "professional"},
            "scheduled_playbooks": {"name": "Scheduled Playbooks", "min_tier": "professional"},
            "approval_workflows": {"name": "Approval Workflows", "min_tier": "professional"},
            "multi_tenant": {"name": "Multi-Tenancy", "min_tier": "enterprise"},
            "sso": {"name": "Single Sign-On (SSO)", "min_tier": "enterprise"},
            "audit_logs": {"name": "Audit Logs", "min_tier": "enterprise"},
            "custom_branding": {"name": "Custom Branding", "min_tier": "enterprise"},
            "dedicated_support": {"name": "Dedicated Support", "min_tier": "enterprise"},
            "sla_guarantee": {"name": "SLA Guarantee", "min_tier": "enterprise"},
        }

        licensed_features = license_obj.limits.features

        return {
            "tier": license_obj.tier.value,
            "features": {
                key: {
                    **info,
                    "enabled": key in licensed_features
                }
                for key, info in all_features.items()
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_licensed_features: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/tiers")
async def get_license_tiers() -> Dict[str, Any]:
    """
    Get information about available license tiers.

    Useful for upgrade prompts and pricing pages.
    """
    try:
        from services.license_manager import TIER_LIMITS

        tiers = {}
        for tier in [LicenseTier.COMMUNITY, LicenseTier.PROFESSIONAL, LicenseTier.ENTERPRISE]:
            limits = TIER_LIMITS[tier]
            tiers[tier.value] = {
                "name": tier.value.title(),
                "alerts_per_day": limits.alerts_per_day if limits.alerts_per_day != -1 else "Unlimited",
                "playbooks": limits.playbooks_max if limits.playbooks_max != -1 else "Unlimited",
                "integrations": limits.integrations_max if limits.integrations_max != -1 else "Unlimited",
                "users": limits.users_max if limits.users_max != -1 else "Unlimited",
                "ai_queries_per_day": limits.ai_queries_per_day if limits.ai_queries_per_day != -1 else "Unlimited",
                "retention_days": limits.retention_days,
                "support": limits.support_level,
                "features": limits.features
            }

        return {"tiers": tiers}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_license_tiers: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
