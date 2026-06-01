# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Quota Service

Tracks and enforces usage quotas with:
- Redis for real-time counters (fast path)
- PostgreSQL for persistent storage and aggregation
- Idempotent increments to prevent double-counting
- Soft/overage/hard stop logic
"""

import os
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass

from .models import (
    UsageMetric,
    QuotaStatus,
    QuotaCheckResult,
    UsageSnapshot,
    BillingEvent,
    ThresholdType,
    AgentTier,
    LLMMode,
)
from .entitlement_service import get_entitlement_service

logger = logging.getLogger(__name__)


@dataclass
class UsageIncrement:
    """Record of a usage increment for idempotency"""
    idempotency_key: str
    tenant_id: str
    metric: UsageMetric
    amount: int
    timestamp: datetime
    processed: bool = False


class QuotaService:
    """
    Manages usage quotas and tracks consumption.

    Features:
    - Real-time quota checks
    - Idempotent usage increments
    - Soft limit warnings
    - Overage tracking
    - Hard stop enforcement
    - Billing event generation
    """

    def __init__(self):
        self.entitlements = get_entitlement_service()

        # In-memory counters (use Redis in production)
        # Format: {tenant_id: {metric: {period: count}}}
        self._counters: Dict[str, Dict[str, Dict[str, int]]] = {}

        # Processed idempotency keys (use Redis SET in production)
        self._processed_keys: set = set()

        # Billing events queue
        self._billing_events: List[BillingEvent] = []

    # =========================================================================
    # CURRENT PERIOD HELPER
    # =========================================================================

    def _get_current_period(self) -> str:
        """Get current billing period as YYYY-MM"""
        return datetime.utcnow().strftime("%Y-%m")

    def _get_counter_key(self, tenant_id: str, metric: UsageMetric, period: str = None) -> str:
        """Generate counter key"""
        period = period or self._get_current_period()
        return f"{tenant_id}:{metric.value}:{period}"

    # =========================================================================
    # USAGE TRACKING
    # =========================================================================

    def get_usage(self, tenant_id: str, metric: UsageMetric, period: str = None) -> int:
        """Get current usage for a metric"""
        period = period or self._get_current_period()

        if tenant_id not in self._counters:
            return 0
        if metric.value not in self._counters[tenant_id]:
            return 0
        return self._counters[tenant_id][metric.value].get(period, 0)

    def increment_usage(
        self,
        tenant_id: str,
        metric: UsageMetric,
        amount: int = 1,
        idempotency_key: str = None,
    ) -> Tuple[int, bool]:
        """
        Increment usage counter.

        Args:
            tenant_id: Tenant ID
            metric: Usage metric to increment
            amount: Amount to increment by
            idempotency_key: Key to prevent double-counting

        Returns:
            Tuple of (new_count, was_incremented)
        """
        # Check idempotency
        if idempotency_key:
            if idempotency_key in self._processed_keys:
                current = self.get_usage(tenant_id, metric)
                return current, False
            self._processed_keys.add(idempotency_key)

        # Initialize nested dicts
        period = self._get_current_period()
        if tenant_id not in self._counters:
            self._counters[tenant_id] = {}
        if metric.value not in self._counters[tenant_id]:
            self._counters[tenant_id][metric.value] = {}

        # Increment
        current = self._counters[tenant_id][metric.value].get(period, 0)
        new_count = current + amount
        self._counters[tenant_id][metric.value][period] = new_count

        logger.debug(f"Incremented {metric.value} for {tenant_id}: {current} -> {new_count}")
        return new_count, True

    async def persist_usage(self, tenant_id: str, metric: UsageMetric):
        """Persist current usage to database"""
        try:
            from services.postgres_db import postgres_db
            if not postgres_db.connected:
                return

            period = self._get_current_period()
            current = self.get_usage(tenant_id, metric, period)

            await postgres_db.pool.execute(
                """
                INSERT INTO usage_counters (tenant_id, metric, period, value, updated_at)
                VALUES ($1, $2, $3, $4, NOW())
                ON CONFLICT (tenant_id, metric, period)
                DO UPDATE SET value = $4, updated_at = NOW()
                """,
                tenant_id, metric.value, period, current
            )
        except Exception as e:
            logger.error(f"Error persisting usage: {e}")

    # =========================================================================
    # QUOTA CHECKS
    # =========================================================================

    def _calculate_status(
        self,
        current: int,
        limit: int,
        overage_allowed: bool,
        overage_max_percent: int,
    ) -> Tuple[QuotaStatus, int]:
        """
        Calculate quota status and overage amount.

        Returns:
            Tuple of (status, overage_amount)
        """
        if limit <= 0:  # Unlimited
            return QuotaStatus.OK, 0

        percent_used = (current / limit) * 100
        hard_limit = limit * (1 + overage_max_percent / 100) if overage_allowed else limit

        if current >= hard_limit:
            return QuotaStatus.BLOCKED, current - limit
        elif current > limit:
            return QuotaStatus.OVERAGE, current - limit
        elif percent_used >= 80:  # Warning at 80%
            return QuotaStatus.WARNING, 0
        else:
            return QuotaStatus.OK, 0

    def check_quota(
        self,
        tenant_id: str,
        metric: UsageMetric,
        increment: int = 1,
    ) -> QuotaCheckResult:
        """
        Check if a quota increment is allowed.

        Args:
            tenant_id: Tenant ID
            metric: Metric to check
            increment: Amount to increment by

        Returns:
            QuotaCheckResult with allowed status and details
        """
        current = self.get_usage(tenant_id, metric)
        projected = current + increment

        # Get limit based on metric
        limit = self._get_limit_for_metric(tenant_id, metric)
        overage_allowed, overage_max_percent = self.entitlements.get_overage_config(tenant_id)

        status, overage = self._calculate_status(
            projected, limit, overage_allowed, overage_max_percent
        )

        hard_limit = limit * (1 + overage_max_percent / 100) if overage_allowed else limit

        allowed = status != QuotaStatus.BLOCKED
        should_warn = status in [QuotaStatus.WARNING, QuotaStatus.OVERAGE]
        should_block = status == QuotaStatus.BLOCKED

        message = self._get_status_message(status, current, limit, hard_limit)

        return QuotaCheckResult(
            allowed=allowed,
            status=status,
            metric=metric,
            current_usage=current,
            limit=limit,
            message=message,
            overage_amount=overage,
            should_warn=should_warn,
            should_block=should_block,
        )

    def _get_limit_for_metric(self, tenant_id: str, metric: UsageMetric) -> int:
        """Get the limit for a specific metric"""
        if metric == UsageMetric.INVESTIGATIONS_CREATED:
            return self.entitlements.get_investigation_limit(tenant_id)
        elif metric == UsageMetric.AUTOMATION_RUNS:
            return self.entitlements.get_automation_limit(tenant_id)
        elif metric == UsageMetric.AGENT_RUNS_TIER1:
            return self.entitlements.get_agent_runs_limit(tenant_id, AgentTier.TIER1)
        elif metric == UsageMetric.AGENT_RUNS_TIER2:
            return self.entitlements.get_agent_runs_limit(tenant_id, AgentTier.TIER2)
        elif metric == UsageMetric.AGENT_RUNS_TIER3:
            return self.entitlements.get_agent_runs_limit(tenant_id, AgentTier.TIER3)
        elif metric == UsageMetric.LLM_TOKENS_MANAGED:
            return self.entitlements.get_managed_llm_limit(tenant_id)
        else:
            return 0  # No limit (metered only)

    def _get_status_message(
        self,
        status: QuotaStatus,
        current: int,
        limit: int,
        hard_limit: int,
    ) -> str:
        """Generate human-readable status message"""
        if status == QuotaStatus.OK:
            return f"Usage: {current}/{limit}"
        elif status == QuotaStatus.WARNING:
            return f"Approaching limit: {current}/{limit} (80%+)"
        elif status == QuotaStatus.OVERAGE:
            overage = current - limit
            return f"Overage: {current}/{limit} ({overage} over, hard limit at {hard_limit})"
        else:  # BLOCKED
            return f"Quota exceeded: {current}/{limit}. New requests blocked until next billing period."

    # =========================================================================
    # SPECIFIC QUOTA CHECKS
    # =========================================================================

    def can_create_investigation(self, tenant_id: str) -> QuotaCheckResult:
        """Check if tenant can create a new investigation"""
        return self.check_quota(tenant_id, UsageMetric.INVESTIGATIONS_CREATED)

    def can_run_automation(self, tenant_id: str, agent_tier: AgentTier = None) -> QuotaCheckResult:
        """Check if tenant can run an automation"""
        # Check general automation limit
        result = self.check_quota(tenant_id, UsageMetric.AUTOMATION_RUNS)
        if not result.allowed:
            return result

        # If tier specified, also check tier-specific limit
        if agent_tier:
            tier_metric = getattr(UsageMetric, f"AGENT_RUNS_TIER{agent_tier.value}")
            tier_result = self.check_quota(tenant_id, tier_metric)
            if not tier_result.allowed:
                return tier_result

        return result

    def can_call_llm(
        self,
        tenant_id: str,
        mode: LLMMode,
        tokens_estimate: int,
    ) -> QuotaCheckResult:
        """Check if tenant can make an LLM call"""
        # BYO mode is always allowed (metered but not limited)
        if mode == LLMMode.BYO:
            return QuotaCheckResult(
                allowed=True,
                status=QuotaStatus.OK,
                metric=UsageMetric.LLM_TOKENS_BYO,
                current_usage=self.get_usage(tenant_id, UsageMetric.LLM_TOKENS_BYO),
                limit=0,  # No limit
                message="BYO LLM - metered but not limited",
            )

        # Managed mode has token limits
        return self.check_quota(tenant_id, UsageMetric.LLM_TOKENS_MANAGED, tokens_estimate)

    def can_execute_action(
        self,
        tenant_id: str,
        integration_id: str,
        action_type: str,
        category: str = None,
    ) -> Tuple[bool, str, bool]:
        """
        Check if tenant can execute an integration action.

        Returns:
            Tuple of (allowed, message, requires_approval)
        """
        # Check if integration is allowed
        if not self.entitlements.is_integration_allowed(tenant_id, integration_id, category):
            return False, f"Integration '{integration_id}' not allowed on your plan", False

        # Check if action requires approval
        requires_approval = self.entitlements.requires_approval(tenant_id, action_type)

        # Tier 3 actions (destructive) ALWAYS require approval
        if action_type in ["containment", "remediation", "destructive"]:
            requires_approval = True

        return True, "Action allowed", requires_approval

    # =========================================================================
    # USAGE SNAPSHOTS
    # =========================================================================

    def get_usage_snapshot(self, tenant_id: str, metric: UsageMetric) -> UsageSnapshot:
        """Get a complete usage snapshot for a metric"""
        current = self.get_usage(tenant_id, metric)
        limit = self._get_limit_for_metric(tenant_id, metric)
        overage_allowed, overage_max_percent = self.entitlements.get_overage_config(tenant_id)

        soft_limit = limit
        hard_limit = int(limit * (1 + overage_max_percent / 100)) if overage_allowed else limit

        status, overage = self._calculate_status(current, limit, overage_allowed, overage_max_percent)
        percent_used = (current / limit * 100) if limit > 0 else 0

        return UsageSnapshot(
            metric=metric,
            current=current,
            limit=limit,
            soft_limit=soft_limit,
            hard_limit=hard_limit,
            status=status,
            percent_used=round(percent_used, 1),
            overage_amount=overage,
            period=self._get_current_period(),
        )

    def get_all_usage_snapshots(self, tenant_id: str) -> Dict[str, UsageSnapshot]:
        """Get usage snapshots for all tracked metrics"""
        metrics = [
            UsageMetric.INVESTIGATIONS_CREATED,
            UsageMetric.AUTOMATION_RUNS,
            UsageMetric.AGENT_RUNS_TIER1,
            UsageMetric.AGENT_RUNS_TIER2,
            UsageMetric.AGENT_RUNS_TIER3,
            UsageMetric.LLM_TOKENS_MANAGED,
            UsageMetric.LLM_TOKENS_BYO,
        ]

        return {
            metric.value: self.get_usage_snapshot(tenant_id, metric)
            for metric in metrics
        }

    # =========================================================================
    # BILLING EVENTS
    # =========================================================================

    def record_billing_event(
        self,
        tenant_id: str,
        event_type: str,
        metric: UsageMetric,
        threshold_type: ThresholdType,
        threshold_value: int,
        current_value: int,
    ):
        """Record a billing event for threshold crossing"""
        import uuid
        event = BillingEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            event_type=event_type,
            metric=metric,
            threshold_type=threshold_type,
            threshold_value=threshold_value,
            current_value=current_value,
            overage_amount=max(0, current_value - threshold_value),
            period=self._get_current_period(),
            timestamp=datetime.utcnow(),
        )
        self._billing_events.append(event)
        logger.info(f"Billing event: {event_type} for {tenant_id} on {metric.value}")

    def get_billing_events(
        self,
        tenant_id: str,
        period: str = None,
        acknowledged: bool = None,
    ) -> List[BillingEvent]:
        """Get billing events for a tenant"""
        events = [e for e in self._billing_events if e.tenant_id == tenant_id]

        if period:
            events = [e for e in events if e.period == period]
        if acknowledged is not None:
            events = [e for e in events if e.acknowledged == acknowledged]

        return events

    # =========================================================================
    # PROJECTIONS
    # =========================================================================

    def get_projected_usage(self, tenant_id: str, metric: UsageMetric) -> Dict[str, any]:
        """
        Project end-of-month usage based on current rate.
        """
        current = self.get_usage(tenant_id, metric)
        limit = self._get_limit_for_metric(tenant_id, metric)

        now = datetime.utcnow()
        days_elapsed = now.day
        days_in_month = 30  # Simplified

        if days_elapsed == 0:
            daily_rate = 0
        else:
            daily_rate = current / days_elapsed

        projected_eom = int(daily_rate * days_in_month)
        projected_overage = max(0, projected_eom - limit)

        return {
            "current": current,
            "limit": limit,
            "days_elapsed": days_elapsed,
            "daily_rate": round(daily_rate, 1),
            "projected_eom": projected_eom,
            "projected_overage": projected_overage,
            "projected_percent": round((projected_eom / limit * 100) if limit > 0 else 0, 1),
            "on_track": projected_eom <= limit,
        }


# Global instance
_quota_service: Optional[QuotaService] = None


def get_quota_service() -> QuotaService:
    """Get or create the global quota service instance"""
    global _quota_service
    if _quota_service is None:
        _quota_service = QuotaService()
    return _quota_service
