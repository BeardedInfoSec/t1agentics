# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Entitlement Service

Central service for checking what a tenant is allowed to do.
This is the single point of truth for license/entitlement checks.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Optional, Any, List

from .models import (
    License,
    LicenseTier,
    Entitlements,
    AgentTier,
    LLMMode,
)
from .default_plans import get_default_entitlements

logger = logging.getLogger(__name__)


def create_unlimited_license(tenant_id: str = "default") -> License:
    """
    Create an unlimited license for self-hosted instances.

    This license has no restrictions and never expires.
    """
    return License(
        license_id="unlimited-self-hosted",
        tenant_id=tenant_id,
        tier=LicenseTier.UNLIMITED,
        entitlements=get_default_entitlements(LicenseTier.UNLIMITED),
        issued_at=datetime.utcnow(),
        valid_from=datetime.utcnow(),
        valid_until=None,  # Never expires
        is_active=True,
        is_trial=False,
        trial_ends_at=None,
        overrides={},
        notes="Self-hosted unlimited license - no restrictions",
        created_by="system",
    )


def create_dev_license(tenant_id: str = "default") -> License:
    """
    Create a development license.

    All features enabled but with volume limits to prevent abuse.
    Perfect for development, testing, and POC environments.
    """
    return License(
        license_id="dev-license",
        tenant_id=tenant_id,
        tier=LicenseTier.DEV,
        entitlements=get_default_entitlements(LicenseTier.DEV),
        issued_at=datetime.utcnow(),
        valid_from=datetime.utcnow(),
        valid_until=None,  # Never expires
        is_active=True,
        is_trial=False,
        trial_ends_at=None,
        overrides={},
        notes="Development license - all features, limited volume",
        created_by="system",
    )


class EntitlementService:
    """
    Central service for checking tenant entitlements.

    Usage:
        service = EntitlementService()
        entitlements = await service.get_entitlements("tenant-123")
        if service.has_feature("tenant-123", "ai_triage"):
            # do AI triage
    """

    def __init__(self, auto_unlimited: bool = True):
        # Cache for licenses (in production, use Redis)
        self._license_cache: Dict[str, License] = {}
        # Default license for single-tenant mode
        self._default_license: Optional[License] = None

        # Auto-initialize unlimited license for self-hosted mode
        # Can be disabled via REQUIRE_LICENSE=true environment variable
        require_license = os.environ.get("REQUIRE_LICENSE", "false").lower() == "true"
        if auto_unlimited and not require_license:
            self._default_license = create_unlimited_license()
            logger.info("Initialized with unlimited self-hosted license (no restrictions)")
        else:
            logger.info("License required mode enabled - waiting for license activation")

    # =========================================================================
    # LICENSE MANAGEMENT
    # =========================================================================

    def set_license(self, tenant_id: str, license: License):
        """Set/update a tenant's license"""
        self._license_cache[tenant_id] = license
        logger.info(f"Set license for tenant {tenant_id}: tier={license.tier.value}")

    def set_default_license(self, license: License):
        """Set default license for single-tenant mode"""
        self._default_license = license
        logger.info(f"Set default license: tier={license.tier.value}")

    def get_license(self, tenant_id: str = None) -> Optional[License]:
        """Get a tenant's license"""
        if tenant_id and tenant_id in self._license_cache:
            return self._license_cache[tenant_id]
        return self._default_license

    async def load_license_from_db(self, tenant_id: str) -> Optional[License]:
        """Load license from database"""
        try:
            from services.postgres_db import postgres_db
            if not postgres_db.connected:
                return None

            row = await postgres_db.pool.fetchrow(
                """
                SELECT * FROM licenses
                WHERE tenant_id = $1 AND is_active = true
                ORDER BY created_at DESC LIMIT 1
                """,
                tenant_id
            )

            if row:
                license = self._row_to_license(row)
                self._license_cache[tenant_id] = license
                return license
        except Exception as e:
            logger.error(f"Error loading license for tenant {tenant_id}: {e}")
        return None

    def _row_to_license(self, row) -> License:
        """Convert database row to License object"""
        import json
        entitlements_data = row.get("entitlements", {})
        if isinstance(entitlements_data, str):
            entitlements_data = json.loads(entitlements_data)

        overrides_data = row.get("overrides", {})
        if isinstance(overrides_data, str):
            overrides_data = json.loads(overrides_data)

        return License(
            license_id=row["license_id"],
            tenant_id=row["tenant_id"],
            tier=LicenseTier(row["tier"]),
            entitlements=Entitlements.from_dict(entitlements_data),
            issued_at=row.get("issued_at", datetime.utcnow()),
            valid_from=row.get("valid_from", datetime.utcnow()),
            valid_until=row.get("valid_until"),
            is_active=row.get("is_active", True),
            is_trial=row.get("is_trial", False),
            trial_ends_at=row.get("trial_ends_at"),
            overrides=overrides_data,
            notes=row.get("notes", ""),
            created_by=row.get("created_by", "system"),
        )

    # =========================================================================
    # ENTITLEMENT CHECKS
    # =========================================================================

    def get_entitlements(self, tenant_id: str = None) -> Entitlements:
        """Get entitlements for a tenant"""
        license = self.get_license(tenant_id)
        if license:
            return license.entitlements
        # Return free tier as default
        return get_default_entitlements(LicenseTier.FREE)

    def get_tier(self, tenant_id: str = None) -> LicenseTier:
        """Get the license tier for a tenant"""
        license = self.get_license(tenant_id)
        if license:
            return license.tier
        return LicenseTier.FREE

    def is_valid(self, tenant_id: str = None) -> bool:
        """Check if tenant has a valid, active license"""
        license = self.get_license(tenant_id)
        if not license:
            return False

        if not license.is_active:
            return False

        now = datetime.utcnow()

        # Check expiration
        if license.valid_until and license.valid_until < now:
            return False

        # Check trial expiration
        if license.is_trial and license.trial_ends_at and license.trial_ends_at < now:
            return False

        return True

    def is_trial(self, tenant_id: str = None) -> bool:
        """Check if tenant is on a trial"""
        license = self.get_license(tenant_id)
        return license.is_trial if license else False

    def has_feature(self, tenant_id: str, feature: str) -> bool:
        """Check if tenant has a specific feature enabled"""
        entitlements = self.get_entitlements(tenant_id)
        return entitlements.features.get(feature, False)

    # =========================================================================
    # QUOTA LIMITS
    # =========================================================================

    def get_investigation_limit(self, tenant_id: str = None) -> int:
        """Get monthly investigation limit"""
        return self.get_entitlements(tenant_id).investigations_per_month

    def get_automation_limit(self, tenant_id: str = None) -> int:
        """Get monthly automation runs limit"""
        return self.get_entitlements(tenant_id).automation_runs_per_month

    def get_overage_config(self, tenant_id: str = None) -> tuple[bool, int]:
        """Get overage configuration (allowed, max_percent)"""
        ent = self.get_entitlements(tenant_id)
        return ent.overage_allowed, ent.overage_max_percent

    def get_hard_limit(self, tenant_id: str, base_limit: int) -> int:
        """Calculate hard limit including overage allowance"""
        allowed, max_percent = self.get_overage_config(tenant_id)
        if not allowed:
            return base_limit
        return int(base_limit * (1 + max_percent / 100))

    # =========================================================================
    # AGENT ENTITLEMENTS
    # =========================================================================

    def get_agent_seats(self, tenant_id: str, tier: AgentTier) -> int:
        """Get allowed agent seats for a tier"""
        return self.get_entitlements(tenant_id).agents.get_seats(tier)

    def get_agent_runs_limit(self, tenant_id: str, tier: AgentTier) -> int:
        """Get monthly agent runs limit for a tier"""
        return self.get_entitlements(tenant_id).agents.get_runs_per_month(tier)

    def get_agent_concurrent_limit(self, tenant_id: str, tier: AgentTier) -> int:
        """Get concurrent agent runs limit for a tier"""
        return self.get_entitlements(tenant_id).agents.get_concurrent_runs(tier)

    def can_use_agent_tier(self, tenant_id: str, tier: AgentTier) -> bool:
        """Check if tenant can use agents of a specific tier"""
        seats = self.get_agent_seats(tenant_id, tier)
        return seats > 0

    # =========================================================================
    # LLM ENTITLEMENTS
    # =========================================================================

    def can_use_llm(self, tenant_id: str, mode: LLMMode) -> bool:
        """Check if tenant can use LLM in specified mode"""
        llm = self.get_entitlements(tenant_id).llm
        if mode == LLMMode.BYO:
            return llm.byo_allowed
        return llm.managed_allowed

    def get_managed_llm_limit(self, tenant_id: str = None) -> int:
        """Get monthly managed LLM token limit"""
        return self.get_entitlements(tenant_id).llm.managed_tokens_per_month

    def is_model_allowed(self, tenant_id: str, model: str) -> bool:
        """Check if a specific model is allowed"""
        llm = self.get_entitlements(tenant_id).llm
        # Empty list means all models allowed
        if not llm.managed_models_allowed:
            return True
        return model in llm.managed_models_allowed

    # =========================================================================
    # INTEGRATION ENTITLEMENTS
    # =========================================================================

    def get_max_integrations(self, tenant_id: str = None) -> int:
        """Get maximum allowed integrations"""
        return self.get_entitlements(tenant_id).integrations.max_integrations

    def is_integration_allowed(self, tenant_id: str, integration_id: str, category: str = None) -> bool:
        """Check if an integration is allowed"""
        integrations = self.get_entitlements(tenant_id).integrations

        # Check blocked list
        if integration_id in integrations.blocked_integrations:
            return False

        # Check category allowlist (empty = all allowed)
        if integrations.allowed_categories and category:
            if category not in integrations.allowed_categories:
                return False

        return True

    def requires_approval(self, tenant_id: str, action_type: str) -> bool:
        """Check if an action type requires approval"""
        integrations = self.get_entitlements(tenant_id).integrations
        return action_type in integrations.require_approval_actions

    # =========================================================================
    # RATE LIMIT ENTITLEMENTS
    # =========================================================================

    def get_webhook_rate_limit(self, tenant_id: str = None) -> int:
        """Get webhook rate limit (requests per minute)"""
        return self.get_entitlements(tenant_id).rate_limits.webhook_requests_per_minute

    def get_api_rate_limit(self, tenant_id: str = None) -> int:
        """Get API rate limit (requests per minute)"""
        return self.get_entitlements(tenant_id).rate_limits.api_requests_per_minute

    def get_burst_limit(self, tenant_id: str = None) -> int:
        """Get burst limit"""
        return self.get_entitlements(tenant_id).rate_limits.burst_limit

    # =========================================================================
    # OTHER ENTITLEMENTS
    # =========================================================================

    def get_max_users(self, tenant_id: str = None) -> int:
        """Get maximum allowed users"""
        return self.get_entitlements(tenant_id).max_users

    def get_data_retention_days(self, tenant_id: str = None) -> int:
        """Get data retention period in days"""
        return self.get_entitlements(tenant_id).data_retention_days

    def get_audit_retention_days(self, tenant_id: str = None) -> int:
        """Get audit log retention period in days"""
        return self.get_entitlements(tenant_id).audit_retention_days


# Global instance
_entitlement_service: Optional[EntitlementService] = None


def get_entitlement_service() -> EntitlementService:
    """Get or create the global entitlement service instance"""
    global _entitlement_service
    if _entitlement_service is None:
        _entitlement_service = EntitlementService()
    return _entitlement_service
