# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Licensing API Routes

Admin endpoints for managing licenses, viewing usage, and configuring plans.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import logging

from dependencies.auth import require_admin, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/licensing", tags=["licensing"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class CreateLicenseRequest(BaseModel):
    """Request to create a new license"""
    tenant_id: str = Field(default="default", description="Tenant ID")
    tier: str = Field(..., description="License tier: free, core, pro, enterprise, custom")
    valid_days: int = Field(default=365, description="License validity in days (0 = no expiration)")
    is_trial: bool = Field(default=False, description="Is this a trial license")
    trial_days: int = Field(default=14, description="Trial duration in days")
    overrides: Optional[Dict[str, Any]] = Field(default=None, description="Custom entitlement overrides")
    notes: str = Field(default="", description="Admin notes")


class UpdateLicenseRequest(BaseModel):
    """Request to update license overrides"""
    overrides: Dict[str, Any] = Field(..., description="Entitlement overrides to apply")
    notes: Optional[str] = Field(default=None, description="Update notes")


class UpgradeLicenseRequest(BaseModel):
    """Request to upgrade a license"""
    new_tier: str = Field(..., description="New tier to upgrade to")
    additional_overrides: Optional[Dict[str, Any]] = Field(default=None, description="Additional overrides")


class SetOverrideRequest(BaseModel):
    """Request to set a single override"""
    key: str = Field(..., description="Override key (e.g., 'investigations_per_month' or 'agents.seats_tier3')")
    value: Any = Field(..., description="Override value")


class LicenseResponse(BaseModel):
    """License response"""
    license_id: str
    tenant_id: str
    tier: str
    is_active: bool
    is_trial: bool
    valid_until: Optional[str]
    trial_ends_at: Optional[str]
    days_remaining: Optional[int]
    has_overrides: bool
    entitlements_summary: Dict[str, Any]


class UsageResponse(BaseModel):
    """Usage response"""
    metric: str
    current: int
    limit: int
    soft_limit: int
    hard_limit: int
    percent_used: float
    status: str
    overage_amount: int
    period: str


class PlanComparisonResponse(BaseModel):
    """Plan comparison response"""
    tiers: Dict[str, Dict[str, Any]]


# =============================================================================
# LICENSE MANAGEMENT ENDPOINTS
# =============================================================================

@router.post("/licenses", response_model=Dict[str, Any])
async def create_license(
    request: CreateLicenseRequest,
    admin: dict = Depends(require_admin),
):
    """
    Create a new license for a tenant.

    Returns the license details and the raw license key (shown only once).
    """
    try:
        from services.licensing.license_generator import get_license_generator
        from services.licensing.models import LicenseTier

        generator = get_license_generator()

        # Validate tier
        try:
            tier = LicenseTier(request.tier)
        except ValueError:
            raise HTTPException(400, f"Invalid tier: {request.tier}. Valid: free, core, pro, enterprise, custom")

        # Create license
        license, license_key = generator.create_license(
            tenant_id=request.tenant_id,
            tier=tier,
            valid_days=request.valid_days,
            is_trial=request.is_trial,
            trial_days=request.trial_days,
            overrides=request.overrides,
            created_by=admin["username"],
            notes=request.notes,
        )

        # Store in entitlement service (and optionally database)
        from services.licensing.entitlement_service import get_entitlement_service
        service = get_entitlement_service()
        service.set_license(request.tenant_id, license)

        # Persist to database
        await _persist_license(license, license_key)

        logger.info(f"License {license.license_id} created for tenant {request.tenant_id} by {admin['username']}")

        return {
            "status": "created",
            "license_id": license.license_id,
            "license_key": license_key,  # Only shown once!
            "tenant_id": license.tenant_id,
            "tier": license.tier.value,
            "valid_until": license.valid_until.isoformat() if license.valid_until else None,
            "message": "Save the license key - it will not be shown again!",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating license: {e}")
        raise HTTPException(500, f"Failed to create license: {str(e)}")


@router.get("/licenses/{tenant_id}")
async def get_license(
    tenant_id: str,
    admin: dict = Depends(require_admin),
):
    """Get license details for a tenant"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service
        from services.licensing.license_generator import get_license_generator

        service = get_entitlement_service()
        generator = get_license_generator()

        license = service.get_license(tenant_id)
        if not license:
            raise HTTPException(404, f"No license found for tenant {tenant_id}")

        return generator.get_license_summary(license)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting license: {e}")
        raise HTTPException(500, str(e))


@router.get("/licenses/{tenant_id}/entitlements")
async def get_entitlements(
    tenant_id: str,
    user: dict = Depends(get_current_user),
):
    """Get full entitlements for a tenant (can be called by tenant users)"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service

        service = get_entitlement_service()
        entitlements = service.get_entitlements(tenant_id)

        return entitlements.to_dict()

    except Exception as e:
        logger.error(f"Error getting entitlements: {e}")
        raise HTTPException(500, str(e))


@router.put("/licenses/{tenant_id}/upgrade")
async def upgrade_license(
    tenant_id: str,
    request: UpgradeLicenseRequest,
    admin: dict = Depends(require_admin),
):
    """Upgrade a license to a new tier"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service
        from services.licensing.license_generator import get_license_generator
        from services.licensing.models import LicenseTier

        service = get_entitlement_service()
        generator = get_license_generator()

        # Get current license
        current_license = service.get_license(tenant_id)
        if not current_license:
            raise HTTPException(404, f"No license found for tenant {tenant_id}")

        # Validate new tier
        try:
            new_tier = LicenseTier(request.new_tier)
        except ValueError:
            raise HTTPException(400, f"Invalid tier: {request.new_tier}")

        # Upgrade
        upgraded = generator.upgrade_license(
            current_license,
            new_tier,
            request.additional_overrides,
        )

        # Update in service
        service.set_license(tenant_id, upgraded)

        logger.info(f"License {upgraded.license_id} upgraded to {new_tier.value} by {admin['username']}")

        return {
            "status": "upgraded",
            "license_id": upgraded.license_id,
            "old_tier": current_license.tier.value,
            "new_tier": upgraded.tier.value,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upgrading license: {e}")
        raise HTTPException(500, str(e))


@router.patch("/licenses/{tenant_id}/overrides")
async def set_override(
    tenant_id: str,
    request: SetOverrideRequest,
    admin: dict = Depends(require_admin),
):
    """Set a single entitlement override"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service
        from services.licensing.license_generator import get_license_generator

        service = get_entitlement_service()
        generator = get_license_generator()

        license = service.get_license(tenant_id)
        if not license:
            raise HTTPException(404, f"No license found for tenant {tenant_id}")

        # Add override
        updated = generator.add_override(license, request.key, request.value)
        service.set_license(tenant_id, updated)

        logger.info(f"Override {request.key}={request.value} set for tenant {tenant_id} by {admin['username']}")

        return {
            "status": "updated",
            "override": {request.key: request.value},
            "total_overrides": len(updated.overrides),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting override: {e}")
        raise HTTPException(500, str(e))


@router.delete("/licenses/{tenant_id}")
async def deactivate_license(
    tenant_id: str,
    admin: dict = Depends(require_admin),
):
    """Deactivate a license (soft delete)"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service

        service = get_entitlement_service()
        license = service.get_license(tenant_id)

        if not license:
            raise HTTPException(404, f"No license found for tenant {tenant_id}")

        license.is_active = False
        service.set_license(tenant_id, license)

        logger.info(f"License {license.license_id} deactivated by {admin['username']}")

        return {"status": "deactivated", "license_id": license.license_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating license: {e}")
        raise HTTPException(500, str(e))


# =============================================================================
# USAGE & QUOTA ENDPOINTS
# =============================================================================

@router.get("/usage/{tenant_id}")
async def get_usage(
    tenant_id: str,
    user: dict = Depends(get_current_user),
):
    """Get current usage for a tenant"""
    try:
        from services.licensing.quota_service import get_quota_service

        service = get_quota_service()
        snapshots = service.get_all_usage_snapshots(tenant_id)

        return {
            "tenant_id": tenant_id,
            "period": service._get_current_period(),
            "usage": {
                key: {
                    "current": snapshot.current,
                    "limit": snapshot.limit,
                    "soft_limit": snapshot.soft_limit,
                    "hard_limit": snapshot.hard_limit,
                    "percent_used": snapshot.percent_used,
                    "status": snapshot.status.value,
                    "overage_amount": snapshot.overage_amount,
                }
                for key, snapshot in snapshots.items()
            }
        }

    except Exception as e:
        logger.error(f"Error getting usage: {e}")
        raise HTTPException(500, str(e))


@router.get("/usage/{tenant_id}/projections")
async def get_usage_projections(
    tenant_id: str,
    user: dict = Depends(get_current_user),
):
    """Get projected end-of-month usage"""
    try:
        from services.licensing.quota_service import get_quota_service
        from services.licensing.models import UsageMetric

        service = get_quota_service()

        projections = {}
        for metric in [UsageMetric.INVESTIGATIONS_CREATED, UsageMetric.AUTOMATION_RUNS]:
            projections[metric.value] = service.get_projected_usage(tenant_id, metric)

        return {
            "tenant_id": tenant_id,
            "projections": projections,
        }

    except Exception as e:
        logger.error(f"Error getting projections: {e}")
        raise HTTPException(500, str(e))


@router.get("/billing-events/{tenant_id}")
async def get_billing_events(
    tenant_id: str,
    period: Optional[str] = Query(None, description="Billing period (YYYY-MM)"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged status"),
    admin: dict = Depends(require_admin),
):
    """Get billing events for a tenant"""
    try:
        from services.licensing.quota_service import get_quota_service

        service = get_quota_service()
        events = service.get_billing_events(tenant_id, period, acknowledged)

        return {
            "tenant_id": tenant_id,
            "count": len(events),
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "metric": e.metric.value,
                    "threshold_type": e.threshold_type.value,
                    "threshold_value": e.threshold_value,
                    "current_value": e.current_value,
                    "overage_amount": e.overage_amount,
                    "period": e.period,
                    "timestamp": e.timestamp.isoformat(),
                    "acknowledged": e.acknowledged,
                }
                for e in events
            ],
        }

    except Exception as e:
        logger.error(f"Error getting billing events: {e}")
        raise HTTPException(500, str(e))


# =============================================================================
# PLAN MANAGEMENT ENDPOINTS
# =============================================================================

@router.get("/plans")
async def get_plans(
    user: dict = Depends(get_current_user),
):
    """Get all available plans"""
    try:
        from services.licensing.default_plans import get_tier_comparison

        return {
            "plans": get_tier_comparison(),
        }

    except Exception as e:
        logger.error(f"Error getting plans: {e}")
        raise HTTPException(500, str(e))


@router.get("/plans/{tier}")
async def get_plan_details(
    tier: str,
    user: dict = Depends(get_current_user),
):
    """Get details for a specific plan tier"""
    try:
        from services.licensing.default_plans import get_default_entitlements
        from services.licensing.models import LicenseTier

        try:
            license_tier = LicenseTier(tier)
        except ValueError:
            raise HTTPException(400, f"Invalid tier: {tier}")

        entitlements = get_default_entitlements(license_tier)

        return {
            "tier": tier,
            "entitlements": entitlements.to_dict(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting plan details: {e}")
        raise HTTPException(500, str(e))


# =============================================================================
# SIGNED LICENSE (BYOC) ENDPOINTS
# =============================================================================

@router.post("/licenses/generate-signed")
async def generate_signed_license(
    request: CreateLicenseRequest,
    admin: dict = Depends(require_admin),
):
    """
    Generate a signed JWT license for BYOC deployments.

    The returned token can be used for offline license validation.
    """
    try:
        from services.licensing.license_generator import get_license_generator
        from services.licensing.models import LicenseTier

        generator = get_license_generator()

        try:
            tier = LicenseTier(request.tier)
        except ValueError:
            raise HTTPException(400, f"Invalid tier: {request.tier}")

        token = generator.generate_signed_license(
            tenant_id=request.tenant_id,
            tier=tier,
            valid_days=request.valid_days,
            overrides=request.overrides,
        )

        logger.info(f"Signed license generated for tenant {request.tenant_id} by {admin['username']}")

        return {
            "status": "generated",
            "tenant_id": request.tenant_id,
            "tier": tier.value,
            "license_token": token,
            "message": "Use this token for BYOC deployments",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating signed license: {e}")
        raise HTTPException(500, str(e))


@router.post("/licenses/validate-signed")
async def validate_signed_license(
    token: str = Body(..., embed=True),
    admin: dict = Depends(require_admin),
):
    """Validate a signed JWT license token"""
    try:
        from services.licensing.license_generator import get_license_generator

        generator = get_license_generator()
        license = generator.decode_signed_license(token)

        if not license:
            return {"valid": False, "message": "Invalid or expired license token"}

        return {
            "valid": True,
            "license": generator.get_license_summary(license),
        }

    except Exception as e:
        logger.error(f"Error validating signed license: {e}")
        raise HTTPException(500, str(e))


# =============================================================================
# LICENSE ACTIVATION ENDPOINTS (For Settings UI)
# =============================================================================

class ActivateLicenseRequest(BaseModel):
    """Request to activate a license via key or JWT token"""
    license_key: Optional[str] = Field(default=None, description="License key (XXXX-XXXX-XXXX-XXXX-XXXX format)")
    license_token: Optional[str] = Field(default=None, description="Signed JWT license token")


@router.post("/activate")
async def activate_license(
    request: ActivateLicenseRequest,
    user: dict = Depends(get_current_user),
):
    """
    Activate a license using either a license key or signed JWT token.

    This endpoint is used by the Settings UI to activate licenses.
    """
    try:
        from services.licensing.license_generator import get_license_generator
        from services.licensing.entitlement_service import get_entitlement_service

        generator = get_license_generator()
        service = get_entitlement_service()

        if not request.license_key and not request.license_token:
            raise HTTPException(400, "Either license_key or license_token is required")

        license = None

        # Try JWT token first
        if request.license_token:
            license = generator.decode_signed_license(request.license_token)
            if not license:
                raise HTTPException(400, "Invalid or expired license token")

        # Try license key
        if request.license_key and not license:
            # Validate key format
            if not generator.validate_license_key_format(request.license_key):
                raise HTTPException(400, "Invalid license key format")

            # Load license from database by key hash
            license = await _load_license_by_key(request.license_key)
            if not license:
                raise HTTPException(400, "License key not found or invalid")

        if license:
            # Activate the license
            service.set_default_license(license)
            service.set_license(license.tenant_id, license)

            logger.info(f"License {license.license_id} activated by {user['username']}")

            return {
                "status": "activated",
                "license_id": license.license_id,
                "tier": license.tier.value,
                "valid_until": license.valid_until.isoformat() if license.valid_until else "never",
                "features": license.entitlements.features,
            }

        raise HTTPException(400, "Failed to activate license")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating license: {e}")
        raise HTTPException(500, str(e))


@router.get("/current")
async def get_current_license(
    user: dict = Depends(get_current_user),
):
    """Get the currently active license information for the current tenant"""
    try:
        from services.postgres_db import postgres_db

        # Get tenant_id from request state (set by TenantMiddleware)
        tenant_id = getattr(user, 'tenant_id', None) or user.get('tenant_id')

        if not tenant_id:
            # Fallback: try to get from database using username
            if postgres_db.connected and postgres_db.pool:
                async with postgres_db.tenant_acquire() as conn:
                    user_row = await conn.fetchrow(
                        "SELECT tenant_id FROM users WHERE username = $1",
                        user.get('username') or user.get('sub')
                    )
                    if user_row:
                        tenant_id = user_row['tenant_id']

        if not tenant_id:
            return {
                "status": "no_tenant",
                "tier": "community",
                "message": "No tenant associated with user.",
            }

        # Get license from tenant_licenses table
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                license_row = await conn.fetchrow("""
                    SELECT tl.*, t.name as tenant_name, t.plan
                    FROM tenants t
                    LEFT JOIN tenant_licenses tl ON tl.id = t.active_license_id
                    WHERE t.id = $1
                """, tenant_id)

                if license_row:
                    tier = license_row.get('tier') or license_row.get('plan') or 'community'
                    is_active = license_row.get('is_active', True)
                    expires_at = license_row.get('expires_at')

                    # Check if expired
                    if expires_at and expires_at < datetime.now(timezone.utc):
                        is_active = False

                    return {
                        "status": "active" if is_active else "expired",
                        "tier": tier,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                        "tenant_name": license_row.get('tenant_name'),
                        "is_active": is_active,
                    }

        # Fallback to in-memory service
        from services.licensing.entitlement_service import get_entitlement_service
        from services.licensing.license_generator import get_license_generator

        service = get_entitlement_service()
        generator = get_license_generator()

        license = service.get_license()

        if not license:
            return {
                "status": "no_license",
                "tier": "community",
                "message": "No license activated. Using community tier.",
            }

        summary = generator.get_license_summary(license)
        summary["status"] = "active" if service.is_valid() else "expired"

        return summary

    except Exception as e:
        logger.error(f"Error getting current license: {e}")
        raise HTTPException(500, str(e))


@router.delete("/current")
async def deactivate_current_license(
    admin: dict = Depends(require_admin),
):
    """Deactivate the current license and revert to unlimited mode"""
    try:
        from services.licensing.entitlement_service import get_entitlement_service, create_unlimited_license

        service = get_entitlement_service()

        # Reset to unlimited license
        unlimited = create_unlimited_license()
        service.set_default_license(unlimited)

        logger.info(f"License deactivated by {admin['username']}, reverted to unlimited mode")

        return {
            "status": "deactivated",
            "message": "License deactivated. Reverted to unlimited mode.",
        }

    except Exception as e:
        logger.error(f"Error deactivating license: {e}")
        raise HTTPException(500, str(e))


async def _load_license_by_key(license_key: str):
    """Load license from database by license key"""
    try:
        from services.postgres_db import postgres_db
        from services.licensing.license_generator import get_license_generator
        from services.licensing.entitlement_service import get_entitlement_service

        if not postgres_db.connected:
            return None

        generator = get_license_generator()
        key_hash = generator.hash_license_key(license_key)

        row = await postgres_db.pool.fetchrow(
            """
            SELECT * FROM licenses
            WHERE license_key_hash = $1 AND is_active = true
            """,
            key_hash
        )

        if row:
            service = get_entitlement_service()
            return service._row_to_license(row)

    except Exception as e:
        logger.error(f"Error loading license by key: {e}")
    return None


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def _persist_license(license, license_key: str):
    """Persist license to database"""
    try:
        from services.postgres_db import postgres_db
        from services.licensing.license_generator import get_license_generator
        import json

        if not postgres_db.connected:
            return

        generator = get_license_generator()
        key_hash = generator.hash_license_key(license_key)

        await postgres_db.pool.execute(
            """
            INSERT INTO licenses (
                license_id, tenant_id, license_key_hash, tier,
                entitlements, overrides, issued_at, valid_from, valid_until,
                is_active, is_trial, trial_ends_at, created_by, notes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (license_id) DO UPDATE SET
                tier = $4, entitlements = $5, overrides = $6,
                valid_until = $9, is_active = $10, updated_at = NOW()
            """,
            license.license_id,
            license.tenant_id,
            key_hash,
            license.tier.value,
            json.dumps(license.entitlements.to_dict()),
            json.dumps(license.overrides),
            license.issued_at,
            license.valid_from,
            license.valid_until,
            license.is_active,
            license.is_trial,
            license.trial_ends_at,
            license.created_by,
            license.notes,
        )
    except Exception as e:
        logger.error(f"Error persisting license: {e}")
