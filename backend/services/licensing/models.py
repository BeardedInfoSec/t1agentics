# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Licensing Data Models & Enums

Defines the core data structures for the licensing system.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, date


# =============================================================================
# ENUMS
# =============================================================================

class LicenseTier(str, Enum):
    """License plan tiers"""
    FREE = "free"           # Limited trial/community
    DEV = "dev"             # Development - open features, limited volume
    CORE = "core"           # Entry-level paid (legacy alias for FREE in DEFAULT_PLANS)
    STARTER = "starter"     # Small-team paid (Pro outcomes minus SSO/custom playbooks/365d)
    PRO = "pro"             # Mid-market
    ENTERPRISE = "enterprise"  # Full features
    CUSTOM = "custom"       # Custom negotiated
    UNLIMITED = "unlimited" # Self-hosted unlimited (no restrictions)


class UsageMetric(str, Enum):
    """Tracked usage metrics"""
    # Primary billing metrics
    INVESTIGATIONS_CREATED = "investigations_created"
    AUTOMATION_RUNS = "automation_runs"

    # Tiered agent metrics
    AGENT_RUNS_TIER1 = "agent_runs_tier1"
    AGENT_RUNS_TIER2 = "agent_runs_tier2"
    AGENT_RUNS_TIER3 = "agent_runs_tier3"

    # LLM metrics
    LLM_TOKENS_MANAGED = "llm_tokens_managed"  # Billed
    LLM_TOKENS_BYO = "llm_tokens_byo"          # Metered, not billed

    # Secondary metrics (visibility, not billing)
    ALERTS_INGESTED = "alerts_ingested"
    INTEGRATION_ACTIONS = "integration_actions"
    ACTIVE_USERS = "active_users"
    API_CALLS = "api_calls"


class ThresholdType(str, Enum):
    """Usage threshold types"""
    SOFT_LIMIT = "soft_limit"      # 100% - warnings begin
    OVERAGE_MAX = "overage_max"    # 120% - new work blocked
    HARD_STOP = "hard_stop"        # Absolute stop


class LLMMode(str, Enum):
    """LLM usage modes"""
    BYO = "byo"          # Bring Your Own keys (not billed)
    MANAGED = "managed"  # Our managed keys (billed)


class AgentTier(int, Enum):
    """Agent capability tiers"""
    TIER1 = 1  # Basic agents: enrichment, lookup
    TIER2 = 2  # Standard agents: investigation, correlation
    TIER3 = 3  # Premium agents: response, containment (destructive)


class QuotaStatus(str, Enum):
    """Current quota status"""
    OK = "ok"                    # Under soft limit
    WARNING = "warning"          # At/over soft limit, under overage max
    OVERAGE = "overage"          # Over soft limit, tracking overage
    BLOCKED = "blocked"          # At hard stop, new work blocked


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AgentEntitlements:
    """Agent-specific entitlements by tier"""
    seats_tier1: int = 0
    seats_tier2: int = 0
    seats_tier3: int = 0

    runs_per_month_tier1: int = 0
    runs_per_month_tier2: int = 0
    runs_per_month_tier3: int = 0

    concurrent_runs_tier1: int = 1
    concurrent_runs_tier2: int = 1
    concurrent_runs_tier3: int = 1

    def get_seats(self, tier: AgentTier) -> int:
        return getattr(self, f"seats_tier{tier.value}", 0)

    def get_runs_per_month(self, tier: AgentTier) -> int:
        return getattr(self, f"runs_per_month_tier{tier.value}", 0)

    def get_concurrent_runs(self, tier: AgentTier) -> int:
        return getattr(self, f"concurrent_runs_tier{tier.value}", 0)


@dataclass
class LLMEntitlements:
    """LLM-specific entitlements"""
    byo_allowed: bool = True
    managed_allowed: bool = False
    managed_tokens_per_month: int = 0
    managed_models_allowed: List[str] = field(default_factory=list)
    default_model: str = "claude-haiku-4-5-20251001"


@dataclass
class RiggsLimits:
    """Per-feature monthly usage limits for Riggs AI features"""
    chat_messages_per_month: int = 100     # 0 = unlimited
    playbook_creations_per_month: int = 5  # 0 = unlimited


@dataclass
class IntegrationEntitlements:
    """Integration-specific entitlements"""
    max_integrations: int = 5
    allowed_categories: List[str] = field(default_factory=list)  # Empty = all
    blocked_integrations: List[str] = field(default_factory=list)
    require_approval_actions: List[str] = field(default_factory=lambda: ["containment", "remediation", "destructive"])


@dataclass
class RateLimitEntitlements:
    """Rate limit entitlements"""
    webhook_requests_per_minute: int = 200
    api_requests_per_minute: int = 60
    burst_limit: int = 50


@dataclass
class Entitlements:
    """
    Complete entitlements for a tenant.
    This is the single source of truth for what a tenant can do.
    """
    # Core quotas
    investigations_per_month: int = 100
    automation_runs_per_month: int = 500

    # Overage configuration
    overage_allowed: bool = True
    overage_max_percent: int = 20  # Allow up to 20% over

    # Agent entitlements
    agents: AgentEntitlements = field(default_factory=AgentEntitlements)

    # LLM entitlements
    llm: LLMEntitlements = field(default_factory=LLMEntitlements)

    # Integration entitlements
    integrations: IntegrationEntitlements = field(default_factory=IntegrationEntitlements)

    # Rate limits
    rate_limits: RateLimitEntitlements = field(default_factory=RateLimitEntitlements)

    # Riggs AI limits
    riggs: RiggsLimits = field(default_factory=RiggsLimits)

    # Feature flags
    features: Dict[str, bool] = field(default_factory=dict)

    # Retention
    data_retention_days: int = 30
    audit_retention_days: int = 90

    # Users
    max_users: int = 3

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage"""
        return {
            "investigations_per_month": self.investigations_per_month,
            "automation_runs_per_month": self.automation_runs_per_month,
            "overage_allowed": self.overage_allowed,
            "overage_max_percent": self.overage_max_percent,
            "agents": {
                "seats_tier1": self.agents.seats_tier1,
                "seats_tier2": self.agents.seats_tier2,
                "seats_tier3": self.agents.seats_tier3,
                "runs_per_month_tier1": self.agents.runs_per_month_tier1,
                "runs_per_month_tier2": self.agents.runs_per_month_tier2,
                "runs_per_month_tier3": self.agents.runs_per_month_tier3,
                "concurrent_runs_tier1": self.agents.concurrent_runs_tier1,
                "concurrent_runs_tier2": self.agents.concurrent_runs_tier2,
                "concurrent_runs_tier3": self.agents.concurrent_runs_tier3,
            },
            "llm": {
                "byo_allowed": self.llm.byo_allowed,
                "managed_allowed": self.llm.managed_allowed,
                "managed_tokens_per_month": self.llm.managed_tokens_per_month,
                "managed_models_allowed": self.llm.managed_models_allowed,
                "default_model": self.llm.default_model,
            },
            "riggs": {
                "chat_messages_per_month": self.riggs.chat_messages_per_month,
                "playbook_creations_per_month": self.riggs.playbook_creations_per_month,
            },
            "integrations": {
                "max_integrations": self.integrations.max_integrations,
                "allowed_categories": self.integrations.allowed_categories,
                "blocked_integrations": self.integrations.blocked_integrations,
                "require_approval_actions": self.integrations.require_approval_actions,
            },
            "rate_limits": {
                "webhook_requests_per_minute": self.rate_limits.webhook_requests_per_minute,
                "api_requests_per_minute": self.rate_limits.api_requests_per_minute,
                "burst_limit": self.rate_limits.burst_limit,
            },
            "features": self.features,
            "data_retention_days": self.data_retention_days,
            "audit_retention_days": self.audit_retention_days,
            "max_users": self.max_users,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entitlements":
        """Deserialize from dictionary"""
        agents_data = data.get("agents", {})
        llm_data = data.get("llm", {})
        integrations_data = data.get("integrations", {})
        rate_limits_data = data.get("rate_limits", {})
        riggs_data = data.get("riggs", {})

        return cls(
            investigations_per_month=data.get("investigations_per_month", 100),
            automation_runs_per_month=data.get("automation_runs_per_month", 500),
            overage_allowed=data.get("overage_allowed", True),
            overage_max_percent=data.get("overage_max_percent", 20),
            agents=AgentEntitlements(
                seats_tier1=agents_data.get("seats_tier1", 0),
                seats_tier2=agents_data.get("seats_tier2", 0),
                seats_tier3=agents_data.get("seats_tier3", 0),
                runs_per_month_tier1=agents_data.get("runs_per_month_tier1", 0),
                runs_per_month_tier2=agents_data.get("runs_per_month_tier2", 0),
                runs_per_month_tier3=agents_data.get("runs_per_month_tier3", 0),
                concurrent_runs_tier1=agents_data.get("concurrent_runs_tier1", 1),
                concurrent_runs_tier2=agents_data.get("concurrent_runs_tier2", 1),
                concurrent_runs_tier3=agents_data.get("concurrent_runs_tier3", 1),
            ),
            llm=LLMEntitlements(
                byo_allowed=llm_data.get("byo_allowed", True),
                managed_allowed=llm_data.get("managed_allowed", False),
                managed_tokens_per_month=llm_data.get("managed_tokens_per_month", 0),
                managed_models_allowed=llm_data.get("managed_models_allowed", []),
                default_model=llm_data.get("default_model", "claude-haiku-4-5-20251001"),
            ),
            riggs=RiggsLimits(
                chat_messages_per_month=riggs_data.get("chat_messages_per_month", 100),
                playbook_creations_per_month=riggs_data.get("playbook_creations_per_month", 5),
            ),
            integrations=IntegrationEntitlements(
                max_integrations=integrations_data.get("max_integrations", 5),
                allowed_categories=integrations_data.get("allowed_categories", []),
                blocked_integrations=integrations_data.get("blocked_integrations", []),
                require_approval_actions=integrations_data.get("require_approval_actions", ["containment", "remediation", "destructive"]),
            ),
            rate_limits=RateLimitEntitlements(
                webhook_requests_per_minute=rate_limits_data.get("webhook_requests_per_minute", 200),
                api_requests_per_minute=rate_limits_data.get("api_requests_per_minute", 60),
                burst_limit=rate_limits_data.get("burst_limit", 50),
            ),
            features=data.get("features", {}),
            data_retention_days=data.get("data_retention_days", 30),
            audit_retention_days=data.get("audit_retention_days", 90),
            max_users=data.get("max_users", 3),
        )


@dataclass
class UsageSnapshot:
    """Current usage for a metric"""
    metric: UsageMetric
    current: int
    limit: int
    soft_limit: int
    hard_limit: int
    status: QuotaStatus
    percent_used: float
    overage_amount: int = 0
    period: str = ""  # YYYY-MM


@dataclass
class QuotaCheckResult:
    """Result of a quota check"""
    allowed: bool
    status: QuotaStatus
    metric: UsageMetric
    current_usage: int
    limit: int
    message: str
    overage_amount: int = 0
    should_warn: bool = False
    should_block: bool = False


@dataclass
class License:
    """
    A complete license record for a tenant.
    """
    license_id: str
    tenant_id: str
    tier: LicenseTier
    entitlements: Entitlements

    # Validity
    issued_at: datetime
    valid_from: datetime
    valid_until: Optional[datetime]

    # Status
    is_active: bool = True
    is_trial: bool = False
    trial_ends_at: Optional[datetime] = None

    # Overrides (tenant-specific adjustments)
    overrides: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    notes: str = ""
    created_by: str = ""


@dataclass
class BillingEvent:
    """
    A billing event for threshold crossings or overages.
    """
    event_id: str
    tenant_id: str
    event_type: str  # "threshold_crossed", "overage_recorded", "hard_stop_hit"
    metric: UsageMetric
    threshold_type: ThresholdType
    threshold_value: int
    current_value: int
    overage_amount: int
    period: str  # YYYY-MM
    timestamp: datetime
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
