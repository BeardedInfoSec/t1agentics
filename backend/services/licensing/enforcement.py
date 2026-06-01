# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Enforcement

Enforcement logic for each boundary point:
- Investigation creation
- Automation runs
- Integration action execution
- LLM calls

Implements soft limit → overage → hard stop behavior.
"""

import logging
from datetime import datetime
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from .models import (
    UsageMetric,
    QuotaStatus,
    AgentTier,
    LLMMode,
    ThresholdType,
)
from .entitlement_service import get_entitlement_service
from .quota_service import get_quota_service

logger = logging.getLogger(__name__)


class EnforcementAction(str, Enum):
    """Actions to take based on enforcement check"""
    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    ALLOW_OVERAGE = "allow_overage"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class EnforcementResult:
    """Result of an enforcement check"""
    action: EnforcementAction
    allowed: bool
    message: str
    warning: Optional[str] = None
    usage_percent: float = 0
    overage_amount: int = 0
    requires_approval: bool = False
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class LicenseEnforcement:
    """
    Central enforcement service for license boundaries.

    Usage:
        enforcement = LicenseEnforcement()

        # Before creating investigation
        result = enforcement.check_investigation_creation("tenant-123")
        if not result.allowed:
            raise HTTPException(429, result.message)

        # Show warning in UI
        if result.warning:
            send_notification(result.warning)
    """

    def __init__(self):
        self.entitlements = get_entitlement_service()
        self.quotas = get_quota_service()

    # =========================================================================
    # INVESTIGATION BOUNDARY
    # =========================================================================

    def check_investigation_creation(
        self,
        tenant_id: str,
        idempotency_key: str = None,
    ) -> EnforcementResult:
        """
        Check if a new investigation can be created.

        Called at: POST /api/v1/investigations
        """
        # Check license validity
        if not self.entitlements.is_valid(tenant_id):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message="License expired or invalid. Please renew your license.",
            )

        # Check quota
        quota_result = self.quotas.can_create_investigation(tenant_id)

        if quota_result.should_block:
            # Hard stop
            self.quotas.record_billing_event(
                tenant_id=tenant_id,
                event_type="hard_stop_hit",
                metric=UsageMetric.INVESTIGATIONS_CREATED,
                threshold_type=ThresholdType.HARD_STOP,
                threshold_value=quota_result.limit,
                current_value=quota_result.current_usage,
            )
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=quota_result.message,
                usage_percent=(quota_result.current_usage / quota_result.limit * 100) if quota_result.limit > 0 else 0,
            )

        # Increment usage
        if idempotency_key:
            new_count, was_incremented = self.quotas.increment_usage(
                tenant_id,
                UsageMetric.INVESTIGATIONS_CREATED,
                1,
                idempotency_key,
            )
        else:
            new_count, was_incremented = self.quotas.increment_usage(
                tenant_id,
                UsageMetric.INVESTIGATIONS_CREATED,
            )

        # Determine action
        if quota_result.status == QuotaStatus.OVERAGE:
            # Allow but track overage
            self.quotas.record_billing_event(
                tenant_id=tenant_id,
                event_type="overage_recorded",
                metric=UsageMetric.INVESTIGATIONS_CREATED,
                threshold_type=ThresholdType.OVERAGE_MAX,
                threshold_value=quota_result.limit,
                current_value=new_count,
            )
            return EnforcementResult(
                action=EnforcementAction.ALLOW_OVERAGE,
                allowed=True,
                message="Investigation created (overage tracking)",
                warning=f"You have exceeded your monthly investigation limit. Overage charges may apply.",
                usage_percent=(new_count / quota_result.limit * 100) if quota_result.limit > 0 else 0,
                overage_amount=new_count - quota_result.limit,
            )

        if quota_result.should_warn:
            # Soft limit warning
            return EnforcementResult(
                action=EnforcementAction.ALLOW_WITH_WARNING,
                allowed=True,
                message="Investigation created",
                warning=f"Approaching monthly limit: {new_count}/{quota_result.limit} investigations used.",
                usage_percent=(new_count / quota_result.limit * 100) if quota_result.limit > 0 else 0,
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message="Investigation created",
            usage_percent=(new_count / quota_result.limit * 100) if quota_result.limit > 0 else 0,
        )

    # =========================================================================
    # AUTOMATION BOUNDARY
    # =========================================================================

    def check_automation_run(
        self,
        tenant_id: str,
        agent_tier: AgentTier,
        agent_id: str = None,
        idempotency_key: str = None,
    ) -> EnforcementResult:
        """
        Check if an automation/agent run is allowed.

        Called at: Agent execution start
        """
        # Check license validity
        if not self.entitlements.is_valid(tenant_id):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message="License expired or invalid.",
            )

        # Check if tier is allowed
        if not self.entitlements.can_use_agent_tier(tenant_id, agent_tier):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"Tier {agent_tier.value} agents not available on your plan. Please upgrade.",
            )

        # Check general automation quota
        quota_result = self.quotas.can_run_automation(tenant_id, agent_tier)

        if quota_result.should_block:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=quota_result.message,
            )

        # Increment usage
        tier_metric = getattr(UsageMetric, f"AGENT_RUNS_TIER{agent_tier.value}")
        self.quotas.increment_usage(tenant_id, UsageMetric.AUTOMATION_RUNS, 1, idempotency_key)
        self.quotas.increment_usage(tenant_id, tier_metric, 1, f"{idempotency_key}:tier" if idempotency_key else None)

        # Determine action
        if quota_result.status == QuotaStatus.OVERAGE:
            return EnforcementResult(
                action=EnforcementAction.ALLOW_OVERAGE,
                allowed=True,
                message="Automation allowed (overage)",
                warning="Automation run limit exceeded. Overage charges may apply.",
                overage_amount=quota_result.overage_amount,
            )

        if quota_result.should_warn:
            return EnforcementResult(
                action=EnforcementAction.ALLOW_WITH_WARNING,
                allowed=True,
                message="Automation allowed",
                warning=quota_result.message,
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message="Automation allowed",
        )

    # =========================================================================
    # INTEGRATION ACTION BOUNDARY
    # =========================================================================

    def check_action_execution(
        self,
        tenant_id: str,
        integration_id: str,
        action_id: str,
        action_type: str,
        category: str = None,
    ) -> EnforcementResult:
        """
        Check if an integration action can be executed.

        Called at: Action execution
        """
        # Check license validity
        if not self.entitlements.is_valid(tenant_id):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message="License expired or invalid.",
            )

        # Check if action is allowed
        allowed, message, requires_approval = self.quotas.can_execute_action(
            tenant_id, integration_id, action_type, category
        )

        if not allowed:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=message,
            )

        # Track integration action (metered, not limited)
        self.quotas.increment_usage(tenant_id, UsageMetric.INTEGRATION_ACTIONS)

        if requires_approval:
            return EnforcementResult(
                action=EnforcementAction.REQUIRE_APPROVAL,
                allowed=True,  # Allowed but needs approval
                message="Action requires approval before execution",
                requires_approval=True,
                metadata={"action_type": action_type, "integration_id": integration_id},
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message="Action allowed",
        )

    # =========================================================================
    # LLM GATEWAY BOUNDARY
    # =========================================================================

    def check_llm_call(
        self,
        tenant_id: str,
        mode: LLMMode,
        model: str,
        tokens_estimate: int,
        idempotency_key: str = None,
    ) -> EnforcementResult:
        """
        Check if an LLM call is allowed.

        Called at: LLM gateway/proxy
        """
        # Check license validity
        if not self.entitlements.is_valid(tenant_id):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message="License expired or invalid.",
            )

        # Check if mode is allowed
        if not self.entitlements.can_use_llm(tenant_id, mode):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"LLM mode '{mode.value}' not available on your plan.",
            )

        # BYO mode: always allowed, just meter
        if mode == LLMMode.BYO:
            self.quotas.increment_usage(
                tenant_id,
                UsageMetric.LLM_TOKENS_BYO,
                tokens_estimate,
                idempotency_key,
            )
            return EnforcementResult(
                action=EnforcementAction.ALLOW,
                allowed=True,
                message="BYO LLM call allowed",
                metadata={"mode": "byo", "metered": True, "billed": False},
            )

        # Managed mode: check model and quota
        if not self.entitlements.is_model_allowed(tenant_id, model):
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"Model '{model}' not available on your plan.",
            )

        # Check token quota
        quota_result = self.quotas.can_call_llm(tenant_id, mode, tokens_estimate)

        if quota_result.should_block:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=quota_result.message,
            )

        # Increment usage
        self.quotas.increment_usage(
            tenant_id,
            UsageMetric.LLM_TOKENS_MANAGED,
            tokens_estimate,
            idempotency_key,
        )

        if quota_result.status == QuotaStatus.OVERAGE:
            return EnforcementResult(
                action=EnforcementAction.ALLOW_OVERAGE,
                allowed=True,
                message="LLM call allowed (overage)",
                warning="Managed LLM token limit exceeded. Overage charges apply.",
                overage_amount=quota_result.overage_amount,
                metadata={"mode": "managed", "metered": True, "billed": True},
            )

        if quota_result.should_warn:
            return EnforcementResult(
                action=EnforcementAction.ALLOW_WITH_WARNING,
                allowed=True,
                message="LLM call allowed",
                warning=quota_result.message,
                metadata={"mode": "managed", "metered": True, "billed": True},
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message="LLM call allowed",
            metadata={"mode": "managed", "metered": True, "billed": True},
        )

    # =========================================================================
    # FEATURE GATE
    # =========================================================================

    def check_feature(self, tenant_id: str, feature: str) -> EnforcementResult:
        """Check if a feature is enabled for tenant"""
        if not self.entitlements.has_feature(tenant_id, feature):
            tier = self.entitlements.get_tier(tenant_id)
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"Feature '{feature}' not available on {tier.value} plan. Please upgrade.",
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message=f"Feature '{feature}' enabled",
        )

    # =========================================================================
    # USER LIMIT
    # =========================================================================

    def check_user_creation(self, tenant_id: str, current_users: int) -> EnforcementResult:
        """Check if tenant can create another user"""
        max_users = self.entitlements.get_max_users(tenant_id)

        if current_users >= max_users:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"User limit reached ({current_users}/{max_users}). Please upgrade for more users.",
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message=f"User creation allowed ({current_users + 1}/{max_users})",
        )

    # =========================================================================
    # INTEGRATION LIMIT
    # =========================================================================

    def check_integration_creation(self, tenant_id: str, current_integrations: int) -> EnforcementResult:
        """Check if tenant can add another integration"""
        max_integrations = self.entitlements.get_max_integrations(tenant_id)

        if current_integrations >= max_integrations:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                allowed=False,
                message=f"Integration limit reached ({current_integrations}/{max_integrations}). Please upgrade.",
            )

        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            allowed=True,
            message=f"Integration creation allowed ({current_integrations + 1}/{max_integrations})",
        )


# Global instance
_enforcement: Optional[LicenseEnforcement] = None


def get_enforcement() -> LicenseEnforcement:
    """Get or create the global enforcement instance"""
    global _enforcement
    if _enforcement is None:
        _enforcement = LicenseEnforcement()
    return _enforcement
