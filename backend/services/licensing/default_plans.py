# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Default Quota Profiles

Defines the default entitlements (quotas + feature flags) for each
license tier. Self-hosted OSS build — these are quota profiles, not
commercial tiers. Operators assign them per-tenant; they can also be
overridden in the database. No prices are recorded here.

Tiers: FREE -> STARTER -> PRO -> ENTERPRISE
  - DEV / UNLIMITED for internal use
  - CORE removed (legacy, maps to FREE)
"""

from .models import (
    LicenseTier,
    Entitlements,
    AgentEntitlements,
    LLMEntitlements,
    RiggsLimits,
    IntegrationEntitlements,
    RateLimitEntitlements,
)


# =============================================================================
# DEFAULT PLAN CONFIGURATIONS
# =============================================================================

DEFAULT_PLANS = {
    # -------------------------------------------------------------------------
    # DEV TIER - Development/Testing (all features, limited volume)
    # -------------------------------------------------------------------------
    LicenseTier.DEV: Entitlements(
        # Core quotas - reasonable limits to prevent abuse
        investigations_per_month=200,
        automation_runs_per_month=1000,

        # Overage - allowed but capped
        overage_allowed=True,
        overage_max_percent=25,

        # Agents - all tiers enabled with moderate limits
        agents=AgentEntitlements(
            seats_tier1=10,
            seats_tier2=5,
            seats_tier3=3,
            runs_per_month_tier1=500,
            runs_per_month_tier2=250,
            runs_per_month_tier3=100,
            concurrent_runs_tier1=5,
            concurrent_runs_tier2=3,
            concurrent_runs_tier3=2,
        ),

        # LLM - both modes available
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=5_000_000,
            managed_models_allowed=[],  # All models for testing
            default_model="claude-sonnet-4-5-20250929",
        ),

        # Riggs AI - unlimited for testing
        riggs=RiggsLimits(
            chat_messages_per_month=0,       # 0 = unlimited
            playbook_creations_per_month=0,
        ),

        # Integrations - unlimited
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],  # All categories
            blocked_integrations=[],
            require_approval_actions=["destructive"],
        ),

        # Rate limits - moderate
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=100,
            api_requests_per_minute=100,
            burst_limit=50,
        ),

        # Features - ALL features enabled for testing
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 0,  # 0 = unlimited
            "ioc_correlation": True,
            "custom_playbooks": True,
            "api_access": True,
            "sso": True,
            "audit_logs": True,
            "multi_tenant": True,
            "priority_support": False,
            "custom_models": True,
            "dedicated_support": False,
            "dev_mode": True,
            "soar_converter": True,
            "riggs_suggestions": True,
        },

        # Retention - shorter for dev
        data_retention_days=14,
        audit_retention_days=30,

        # Users
        max_users=10,
    ),

    # -------------------------------------------------------------------------
    # FREE TIER - Community/Trial
    # -------------------------------------------------------------------------
    LicenseTier.FREE: Entitlements(
        # Core quotas
        investigations_per_month=50,
        automation_runs_per_month=100,

        # Overage
        overage_allowed=False,
        overage_max_percent=0,

        # Agents
        agents=AgentEntitlements(
            seats_tier1=2,
            seats_tier2=1,
            seats_tier3=0,
            runs_per_month_tier1=100,
            runs_per_month_tier2=25,
            runs_per_month_tier3=0,
            concurrent_runs_tier1=1,
            concurrent_runs_tier2=1,
            concurrent_runs_tier3=0,
        ),

        # LLM - Haiku for free tier (cheapest model). 200K tokens/month
        # is approximately 100 AI operations for the free quota profile.
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=200_000,
            managed_models_allowed=["claude-haiku-4-5-20251001"],
            default_model="claude-haiku-4-5-20251001",
        ),

        # Riggs AI - limited monthly usage
        riggs=RiggsLimits(
            chat_messages_per_month=100,
            playbook_creations_per_month=5,
        ),

        # Integrations - unlimited, all categories
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],  # All categories
            blocked_integrations=[],
            require_approval_actions=["containment", "remediation", "destructive"],
        ),

        # Rate limits
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=50,
            api_requests_per_minute=30,
            burst_limit=20,
        ),

        # Features
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 3,  # 3 free deep dives/month (0 = unlimited)
            "ioc_correlation": False,
            "custom_playbooks": False,
            "api_access": False,
            "sso": False,
            "audit_logs": True,
            "multi_tenant": False,
            "priority_support": False,
            "soar_converter": False,        # Premium — requires PRO+
            "riggs_suggestions": False,     # Premium — requires PRO+
        },

        # Retention
        data_retention_days=7,
        audit_retention_days=7,

        # Users
        max_users=2,
    ),

    # -------------------------------------------------------------------------
    # STARTER TIER - Mid-volume quota profile.
    # 500 alerts/day, 10 users, ~1,500 AI ops/mo, 60-day retention,
    # API access. Sits between FREE and PRO.
    # -------------------------------------------------------------------------
    LicenseTier.STARTER: Entitlements(
        # Core quotas
        investigations_per_month=500,
        automation_runs_per_month=2500,

        # Overage
        overage_allowed=True,
        overage_max_percent=15,

        # Agents
        agents=AgentEntitlements(
            seats_tier1=5,
            seats_tier2=3,
            seats_tier3=1,
            runs_per_month_tier1=1500,
            runs_per_month_tier2=750,
            runs_per_month_tier3=100,
            concurrent_runs_tier1=3,
            concurrent_runs_tier2=2,
            concurrent_runs_tier3=1,
        ),

        # LLM — Sonnet allowed for daily work, Haiku for high-volume cheap path.
        # 3M tokens/month is approximately 1,500 AI operations.
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=3_000_000,
            managed_models_allowed=["claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"],
            default_model="claude-sonnet-4-5-20250929",
        ),

        # Riggs AI — unlimited at Starter (the AI op cap is the real meter)
        riggs=RiggsLimits(
            chat_messages_per_month=0,       # 0 = unlimited
            playbook_creations_per_month=0,
        ),

        # Integrations
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],
            blocked_integrations=[],
            require_approval_actions=["containment", "destructive"],
        ),

        # Rate limits
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=200,
            api_requests_per_minute=100,
            burst_limit=50,
        ),

        # Features — IOC correlation + API access on; SSO + custom_playbooks
        # gated to Pro+.
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 0,   # unlimited per marketing
            "ioc_correlation": True,
            "custom_playbooks": False,      # Pro+
            "api_access": True,
            "sso": False,                   # Pro+
            "audit_logs": True,
            "multi_tenant": False,
            "priority_support": False,      # email support, not priority
            "soar_converter": False,        # Pro+
            "riggs_suggestions": False,     # Pro+
        },

        # Retention
        data_retention_days=60,
        audit_retention_days=180,

        # Users
        max_users=10,
    ),

    # -------------------------------------------------------------------------
    # PRO TIER - Higher-volume quota profile.
    # -------------------------------------------------------------------------
    LicenseTier.PRO: Entitlements(
        # Core quotas
        investigations_per_month=2500,
        automation_runs_per_month=15000,

        # Overage
        overage_allowed=True,
        overage_max_percent=20,

        # Agents
        agents=AgentEntitlements(
            seats_tier1=15,
            seats_tier2=10,
            seats_tier3=5,
            runs_per_month_tier1=5000,
            runs_per_month_tier2=3000,
            runs_per_month_tier3=500,
            concurrent_runs_tier1=10,
            concurrent_runs_tier2=5,
            concurrent_runs_tier3=2,
        ),

        # LLM - Sonnet for paid tiers, 15M tokens
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=15_000_000,
            managed_models_allowed=["claude-sonnet-4-5-20250929", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
            default_model="claude-sonnet-4-5-20250929",
        ),

        # Riggs AI - unlimited
        riggs=RiggsLimits(
            chat_messages_per_month=0,       # 0 = unlimited
            playbook_creations_per_month=0,
        ),

        # Integrations - unlimited
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],
            blocked_integrations=[],
            require_approval_actions=["destructive"],
        ),

        # Rate limits
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=500,
            api_requests_per_minute=300,
            burst_limit=100,
        ),

        # Features
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 0,  # 0 = unlimited
            "ioc_correlation": True,
            "custom_playbooks": True,
            "api_access": True,
            "sso": True,
            "audit_logs": True,
            "multi_tenant": False,
            "priority_support": True,
            "soar_converter": True,
            "riggs_suggestions": True,
        },

        # Retention
        data_retention_days=90,
        audit_retention_days=365,

        # Users
        max_users=50,
    ),

    # -------------------------------------------------------------------------
    # ENTERPRISE TIER - Full Features
    # -------------------------------------------------------------------------
    LicenseTier.ENTERPRISE: Entitlements(
        # Core quotas
        investigations_per_month=25000,
        automation_runs_per_month=150000,

        # Overage
        overage_allowed=True,
        overage_max_percent=50,

        # Agents
        agents=AgentEntitlements(
            seats_tier1=999,
            seats_tier2=999,
            seats_tier3=50,
            runs_per_month_tier1=999999,
            runs_per_month_tier2=999999,
            runs_per_month_tier3=10000,
            concurrent_runs_tier1=50,
            concurrent_runs_tier2=25,
            concurrent_runs_tier3=10,
        ),

        # LLM - Sonnet, 50M tokens, all models
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=50_000_000,
            managed_models_allowed=[],  # All models
            default_model="claude-sonnet-4-5-20250929",
        ),

        # Riggs AI - unlimited
        riggs=RiggsLimits(
            chat_messages_per_month=0,
            playbook_creations_per_month=0,
        ),

        # Integrations - unlimited
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],
            blocked_integrations=[],
            require_approval_actions=["destructive"],
        ),

        # Rate limits
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=2000,
            api_requests_per_minute=1000,
            burst_limit=500,
        ),

        # Features
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 0,  # 0 = unlimited
            "ioc_correlation": True,
            "custom_playbooks": True,
            "api_access": True,
            "sso": True,
            "audit_logs": True,
            "multi_tenant": True,
            "priority_support": True,
            "custom_models": True,
            "dedicated_support": True,
            "soar_converter": True,
            "riggs_suggestions": True,
        },

        # Retention
        data_retention_days=365,
        audit_retention_days=730,

        # Users
        max_users=999,
    ),

    # -------------------------------------------------------------------------
    # UNLIMITED TIER - Self-hosted / No restrictions
    # -------------------------------------------------------------------------
    LicenseTier.UNLIMITED: Entitlements(
        # Core quotas - effectively unlimited
        investigations_per_month=999999999,
        automation_runs_per_month=999999999,

        # Overage - not applicable
        overage_allowed=False,
        overage_max_percent=0,

        # Agents - unlimited
        agents=AgentEntitlements(
            seats_tier1=999999,
            seats_tier2=999999,
            seats_tier3=999999,
            runs_per_month_tier1=999999999,
            runs_per_month_tier2=999999999,
            runs_per_month_tier3=999999999,
            concurrent_runs_tier1=999,
            concurrent_runs_tier2=999,
            concurrent_runs_tier3=999,
        ),

        # LLM - all modes available
        llm=LLMEntitlements(
            byo_allowed=True,
            managed_allowed=True,
            managed_tokens_per_month=999999999,
            managed_models_allowed=[],
            default_model="claude-sonnet-4-5-20250929",
        ),

        # Riggs AI - unlimited
        riggs=RiggsLimits(
            chat_messages_per_month=0,
            playbook_creations_per_month=0,
        ),

        # Integrations - unlimited
        integrations=IntegrationEntitlements(
            max_integrations=999999,
            allowed_categories=[],
            blocked_integrations=[],
            require_approval_actions=[],
        ),

        # Rate limits - very high
        rate_limits=RateLimitEntitlements(
            webhook_requests_per_minute=999999,
            api_requests_per_minute=999999,
            burst_limit=999999,
        ),

        # Features - all enabled
        features={
            "ai_triage": True,
            "riggs_chat": True,
            "riggs_playbook_create": True,
            "deep_dive": True,
            "deep_dive_monthly_limit": 0,  # 0 = unlimited
            "ioc_correlation": True,
            "custom_playbooks": True,
            "api_access": True,
            "sso": True,
            "audit_logs": True,
            "multi_tenant": True,
            "priority_support": True,
            "custom_models": True,
            "dedicated_support": True,
            "unlimited_mode": True,
            "soar_converter": True,
            "riggs_suggestions": True,
        },

        # Retention - unlimited
        data_retention_days=99999,
        audit_retention_days=99999,

        # Users - unlimited
        max_users=999999,
    ),
}

# CORE tier removed — legacy references map to FREE
DEFAULT_PLANS[LicenseTier.CORE] = DEFAULT_PLANS[LicenseTier.FREE]


def get_default_entitlements(tier: LicenseTier) -> Entitlements:
    """Get default entitlements for a tier"""
    if tier == LicenseTier.CUSTOM:
        # Custom starts from Enterprise and should be overridden
        return DEFAULT_PLANS[LicenseTier.ENTERPRISE]
    if tier == LicenseTier.UNLIMITED:
        return DEFAULT_PLANS[LicenseTier.UNLIMITED]
    return DEFAULT_PLANS.get(tier, DEFAULT_PLANS[LicenseTier.FREE])


def get_tier_comparison() -> dict:
    """Get a comparison table of all tiers for display"""
    comparison = {}

    for tier in [LicenseTier.DEV, LicenseTier.FREE, LicenseTier.PRO, LicenseTier.ENTERPRISE]:
        ent = DEFAULT_PLANS[tier]
        comparison[tier.value] = {
            "investigations_per_month": ent.investigations_per_month,
            "automation_runs_per_month": ent.automation_runs_per_month,
            "agent_seats": {
                "tier1": ent.agents.seats_tier1,
                "tier2": ent.agents.seats_tier2,
                "tier3": ent.agents.seats_tier3,
            },
            "agent_runs_per_month": {
                "tier1": ent.agents.runs_per_month_tier1,
                "tier2": ent.agents.runs_per_month_tier2,
                "tier3": ent.agents.runs_per_month_tier3,
            },
            "llm": {
                "byo_allowed": ent.llm.byo_allowed,
                "managed_allowed": ent.llm.managed_allowed,
                "managed_tokens": ent.llm.managed_tokens_per_month,
                "default_model": ent.llm.default_model,
            },
            "riggs": {
                "chat_messages_per_month": ent.riggs.chat_messages_per_month,
                "playbook_creations_per_month": ent.riggs.playbook_creations_per_month,
            },
            "integrations": ent.integrations.max_integrations,
            "rate_limit_webhook": ent.rate_limits.webhook_requests_per_minute,
            "rate_limit_api": ent.rate_limits.api_requests_per_minute,
            "data_retention_days": ent.data_retention_days,
            "max_users": ent.max_users,
            "overage_allowed": ent.overage_allowed,
            "overage_max_percent": ent.overage_max_percent,
            "features": ent.features,
        }

    return comparison
