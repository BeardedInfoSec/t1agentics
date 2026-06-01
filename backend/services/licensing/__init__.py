# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Licensing & Metering System

A production-ready licensing system supporting:
- Investigation-based pricing (primary metric)
- Automation runs metering (secondary metric)
- Tiered agent limits (Tier 1/2/3)
- LLM token tracking (BYO vs Managed)
- Soft limits, overage tracking, and hard stops

Business Model:
- Ingest is unlimited (alerts flow freely)
- Pay for: investigations + automation runs + agent capacity
- LLM tokens billed only for managed keys (BYO allowed, metered for visibility)

Quick Start:
    from services.licensing import get_enforcement, get_entitlement_service

    # Check if investigation creation is allowed
    enforcement = get_enforcement()
    result = enforcement.check_investigation_creation("tenant-123")
    if not result.allowed:
        raise HTTPException(429, result.message)

    # Get tenant entitlements
    service = get_entitlement_service()
    entitlements = service.get_entitlements("tenant-123")
"""

from .models import (
    LicenseTier,
    UsageMetric,
    ThresholdType,
    LLMMode,
    AgentTier,
    QuotaStatus,
    Entitlements,
    RiggsLimits,
    License,
    BillingEvent,
    QuotaCheckResult,
    UsageSnapshot,
)

from .entitlement_service import EntitlementService, get_entitlement_service, create_unlimited_license, create_dev_license
from .quota_service import QuotaService, get_quota_service
from .license_generator import LicenseGenerator, get_license_generator
from .enforcement import LicenseEnforcement, get_enforcement, EnforcementAction, EnforcementResult
from .default_plans import DEFAULT_PLANS, get_default_entitlements, get_tier_comparison

__all__ = [
    # Enums
    "LicenseTier",
    "UsageMetric",
    "ThresholdType",
    "LLMMode",
    "AgentTier",
    "QuotaStatus",
    "EnforcementAction",
    # Data classes
    "Entitlements",
    "RiggsLimits",
    "License",
    "BillingEvent",
    "QuotaCheckResult",
    "UsageSnapshot",
    "EnforcementResult",
    # Services
    "EntitlementService",
    "QuotaService",
    "LicenseGenerator",
    "LicenseEnforcement",
    # Service getters
    "get_entitlement_service",
    "get_quota_service",
    "get_license_generator",
    "get_enforcement",
    # License helpers
    "create_unlimited_license",
    "create_dev_license",
    # Plan helpers
    "DEFAULT_PLANS",
    "get_default_entitlements",
    "get_tier_comparison",
]
