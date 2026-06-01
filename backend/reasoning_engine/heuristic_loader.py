# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Heuristic Loader - Dynamic Guidance Loading

Heuristics are guidance patterns, NOT procedures.
They inform judgment, they don't dictate actions.

Heuristics must earn their place:
- Auto-disable if accuracy < 60% over 50 samples
- Track outcomes for continuous improvement
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class HeuristicCategory(str, Enum):
    """Categories for heuristics."""
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    RESPONSE = "response"
    GENERAL = "general"


@dataclass
class Heuristic:
    """A heuristic guidance pattern."""
    id: str
    name: str
    category: HeuristicCategory
    trigger_conditions: Dict[str, Any]
    guidance_text: str
    weight: float = 1.0
    version: int = 1
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Performance tracking
    total_uses: int = 0
    helpful_count: int = 0

    @property
    def accuracy(self) -> float:
        """Calculate heuristic accuracy."""
        if self.total_uses == 0:
            return 0.0
        return self.helpful_count / self.total_uses


@dataclass
class HeuristicOutcome:
    """Outcome tracking for a heuristic use."""
    heuristic_id: str
    investigation_id: str
    was_helpful: bool
    confidence_delta: float  # How much it affected confidence
    analyst_feedback: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Lifecycle rules - LOCKED
HEURISTIC_LIFECYCLE = {
    "min_samples_for_evaluation": 50,    # Need data before judging
    "accuracy_threshold": 0.6,           # Below this = auto-disable
    "staleness_days": 90,                # Review if no recent use
    "max_active_per_category": 10,       # Prevent bloat
}


# =============================================================================
# SEED HEURISTICS
# =============================================================================
# These are starting points. They should evolve based on outcomes.

SEED_HEURISTICS = [
    Heuristic(
        id="internal_ip_context",
        name="Internal IP Context",
        category=HeuristicCategory.TRIAGE,
        trigger_conditions={"has_internal_ip": True},
        guidance_text=(
            "Internal IPs communicating with external threats warrant immediate attention. "
            "Consider: Is this a server or workstation? What's the normal traffic pattern? "
            "High confidence indicators: Known C2 domains, beaconing patterns, data exfil volumes."
        ),
        weight=1.0
    ),
    Heuristic(
        id="phishing_domain_age",
        name="Phishing Domain Age",
        category=HeuristicCategory.ANALYSIS,
        trigger_conditions={"alert_type": "phishing", "has_domain": True},
        guidance_text=(
            "Recently registered domains (< 30 days) in phishing contexts are highly suspicious. "
            "However, legitimate services do use new domains. Cross-reference with: "
            "domain registrar reputation, SSL certificate details, similar domain patterns (typosquatting)."
        ),
        weight=1.2
    ),
    Heuristic(
        id="credential_exposure_urgency",
        name="Credential Exposure Urgency",
        category=HeuristicCategory.RESPONSE,
        trigger_conditions={"involves_credentials": True},
        guidance_text=(
            "Credential exposure requires rapid assessment of blast radius. "
            "Priority factors: privilege level, service accounts vs user accounts, "
            "evidence of actual use vs potential exposure. "
            "Time-sensitivity: Credentials may already be in use elsewhere."
        ),
        weight=1.5
    ),
    Heuristic(
        id="edr_high_confidence",
        name="EDR High Confidence Alert",
        category=HeuristicCategory.TRIAGE,
        trigger_conditions={"source_type": "edr", "source_confidence": "high"},
        guidance_text=(
            "EDR alerts with high source confidence have already passed vendor detection logic. "
            "Focus on scope and impact rather than re-validating the detection. "
            "Key questions: What else did this host do? Are there related alerts?"
        ),
        weight=1.3
    ),
    Heuristic(
        id="lateral_movement_indicators",
        name="Lateral Movement Indicators",
        category=HeuristicCategory.ANALYSIS,
        trigger_conditions={"has_multiple_hosts": True},
        guidance_text=(
            "Multiple hosts in an alert chain suggest lateral movement. "
            "Map the progression: initial access -> privilege escalation -> lateral spread. "
            "Check for: shared credentials, admin tool abuse, unusual service account activity."
        ),
        weight=1.4
    ),
    Heuristic(
        id="known_malware_family",
        name="Known Malware Family",
        category=HeuristicCategory.TRIAGE,
        trigger_conditions={"has_malware_family": True},
        guidance_text=(
            "Identified malware families have known TTPs - leverage threat intel. "
            "Check: associated C2 infrastructure, typical persistence mechanisms, "
            "expected lateral movement patterns. Don't re-investigate known behavior."
        ),
        weight=1.5
    ),
    Heuristic(
        id="user_behavior_anomaly",
        name="User Behavior Anomaly",
        category=HeuristicCategory.ANALYSIS,
        trigger_conditions={"alert_type": "ueba", "has_user": True},
        guidance_text=(
            "User behavior anomalies need context before escalation. "
            "Check: recent role changes, travel, new projects, time zone differences. "
            "False positives common for: new employees, visiting executives, IT admins."
        ),
        weight=0.9
    ),
    Heuristic(
        id="data_exfiltration_signs",
        name="Data Exfiltration Signs",
        category=HeuristicCategory.RESPONSE,
        trigger_conditions={"has_large_transfer": True},
        guidance_text=(
            "Large data transfers out of network need immediate scoping. "
            "Priority checks: destination reputation, data classification, user authorization. "
            "Consider: legitimate cloud backup, approved file sharing, versus true exfil."
        ),
        weight=1.6
    ),
]


class HeuristicLoader:
    """
    Loads relevant heuristics for investigation context.

    Heuristics are dynamically selected based on alert characteristics.
    Limited to 3-5 per investigation to maintain prompt efficiency.
    """

    # Limits - LOCKED
    HEURISTIC_TARGET = 3
    HEURISTIC_MAX = 5
    MAX_TOKENS_PER_HEURISTIC = 100

    def __init__(self, db_service=None):
        """
        Initialize heuristic loader.

        Args:
            db_service: Database service for persistent storage.
                       If None, uses in-memory storage.
        """
        self.db_service = db_service
        self._heuristics: Dict[str, Heuristic] = {}
        self._outcomes: List[HeuristicOutcome] = []

        # Load seed heuristics
        self._load_seed_heuristics()

    def _load_seed_heuristics(self) -> None:
        """Load seed heuristics into memory."""
        for h in SEED_HEURISTICS:
            self._heuristics[h.id] = h
        logger.info(f"[HEURISTIC] Loaded {len(SEED_HEURISTICS)} seed heuristics")

    def get_matching_heuristics(
        self,
        alert_context: Dict[str, Any],
        checkpoint: str
    ) -> List[str]:
        """
        Get heuristics matching the alert context.

        Args:
            alert_context: Alert data and extracted features
            checkpoint: Current checkpoint (triage, analysis, response)

        Returns:
            List of heuristic guidance strings (max 5)
        """
        candidates = []

        for heuristic in self._heuristics.values():
            if not heuristic.is_active:
                continue

            # Check trigger conditions
            if self._matches_conditions(heuristic.trigger_conditions, alert_context):
                score = self._score_heuristic(heuristic, checkpoint)
                candidates.append((heuristic, score))

        # Sort by score (weight * relevance)
        candidates.sort(key=lambda x: x[1], reverse=True)

        # Take top heuristics
        selected = []
        for heuristic, score in candidates[:self.HEURISTIC_MAX]:
            if len(selected) >= self.HEURISTIC_TARGET and score < 0.5:
                break  # Stop at target if relevance drops
            guidance = self._truncate_guidance(heuristic.guidance_text)
            selected.append(guidance)
            heuristic.total_uses += 1

        logger.info(f"[HEURISTIC] Selected {len(selected)} heuristics for checkpoint: {checkpoint}")
        return selected

    def _matches_conditions(
        self,
        conditions: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """Check if context matches heuristic trigger conditions."""
        for key, expected in conditions.items():
            actual = context.get(key)

            if isinstance(expected, bool):
                # Boolean check - key presence or truthiness
                if expected and not actual:
                    return False
                if not expected and actual:
                    return False
            elif actual != expected:
                return False

        return True

    def _score_heuristic(self, heuristic: Heuristic, checkpoint: str) -> float:
        """Score a heuristic based on relevance and weight."""
        score = heuristic.weight

        # Boost if category matches checkpoint
        category_checkpoint_map = {
            HeuristicCategory.TRIAGE: "triage",
            HeuristicCategory.ANALYSIS: "analysis",
            HeuristicCategory.RESPONSE: "response",
        }
        if category_checkpoint_map.get(heuristic.category) == checkpoint:
            score *= 1.5

        # Boost based on historical accuracy (if we have data)
        if heuristic.total_uses >= HEURISTIC_LIFECYCLE["min_samples_for_evaluation"]:
            score *= (0.5 + heuristic.accuracy)  # Range: 0.5 to 1.5

        return score

    def _truncate_guidance(self, text: str) -> str:
        """Truncate guidance to token limit."""
        max_chars = self.MAX_TOKENS_PER_HEURISTIC * 4  # Rough estimate
        if len(text) > max_chars:
            return text[:max_chars] + "..."
        return text

    def record_outcome(
        self,
        heuristic_id: str,
        investigation_id: str,
        was_helpful: bool,
        confidence_delta: float = 0.0,
        analyst_feedback: Optional[str] = None
    ) -> None:
        """
        Record outcome for a heuristic use.

        This data is used to auto-disable underperforming heuristics.
        """
        if heuristic_id not in self._heuristics:
            logger.warning(f"[HEURISTIC] Unknown heuristic: {heuristic_id}")
            return

        outcome = HeuristicOutcome(
            heuristic_id=heuristic_id,
            investigation_id=investigation_id,
            was_helpful=was_helpful,
            confidence_delta=confidence_delta,
            analyst_feedback=analyst_feedback
        )
        self._outcomes.append(outcome)

        # Update heuristic stats
        heuristic = self._heuristics[heuristic_id]
        if was_helpful:
            heuristic.helpful_count += 1

        # Check if we should evaluate
        self._evaluate_heuristic_health(heuristic_id)

    def _evaluate_heuristic_health(self, heuristic_id: str) -> None:
        """Evaluate and potentially disable underperforming heuristics."""
        heuristic = self._heuristics.get(heuristic_id)
        if not heuristic:
            return

        if heuristic.total_uses < HEURISTIC_LIFECYCLE["min_samples_for_evaluation"]:
            return  # Not enough data

        if heuristic.accuracy < HEURISTIC_LIFECYCLE["accuracy_threshold"]:
            logger.warning(
                f"[HEURISTIC] Auto-disabling {heuristic_id}: "
                f"accuracy {heuristic.accuracy:.1%} < threshold {HEURISTIC_LIFECYCLE['accuracy_threshold']:.0%}"
            )
            heuristic.is_active = False

    def get_heuristic_stats(self) -> List[Dict[str, Any]]:
        """Get stats for all heuristics."""
        return [
            {
                "id": h.id,
                "name": h.name,
                "category": h.category.value,
                "is_active": h.is_active,
                "total_uses": h.total_uses,
                "helpful_count": h.helpful_count,
                "accuracy": f"{h.accuracy:.1%}" if h.total_uses > 0 else "N/A",
                "weight": h.weight
            }
            for h in self._heuristics.values()
        ]

    def add_heuristic(self, heuristic: Heuristic) -> None:
        """Add a new heuristic."""
        self._heuristics[heuristic.id] = heuristic
        logger.info(f"[HEURISTIC] Added heuristic: {heuristic.id}")

    def disable_heuristic(self, heuristic_id: str) -> bool:
        """Manually disable a heuristic."""
        if heuristic_id in self._heuristics:
            self._heuristics[heuristic_id].is_active = False
            logger.info(f"[HEURISTIC] Disabled: {heuristic_id}")
            return True
        return False

    def enable_heuristic(self, heuristic_id: str) -> bool:
        """Re-enable a heuristic."""
        if heuristic_id in self._heuristics:
            self._heuristics[heuristic_id].is_active = True
            logger.info(f"[HEURISTIC] Enabled: {heuristic_id}")
            return True
        return False


# =============================================================================
# SINGLETON
# =============================================================================

_heuristic_loader: Optional[HeuristicLoader] = None


def get_heuristic_loader(db_service=None) -> HeuristicLoader:
    """Get the global heuristic loader instance."""
    global _heuristic_loader
    if _heuristic_loader is None:
        _heuristic_loader = HeuristicLoader(db_service)
    return _heuristic_loader
