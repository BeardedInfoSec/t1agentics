# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Confidence Gate - Threshold-Based Decision System

Confidence drives everything: tool access, escalation, and resolution.
Thresholds are starting points - tune based on outcomes.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class EscalationDecision:
    """Decision about whether to escalate."""
    escalate: bool
    reason: str
    urgency: str = "normal"  # "normal", "high", "critical"


@dataclass
class ToolAccessDecision:
    """Decision about tool access based on confidence."""
    allowed: bool
    reason: str
    required_confidence: int
    current_confidence: int


class ConfidenceGate:
    """
    Confidence thresholds that govern investigation behavior.

    These are starting points - they should be tuned based on real outcomes.
    Track: confidence vs analyst agreement to calibrate.
    """

    # Checkpoint progression thresholds
    CHECKPOINT_THRESHOLDS = {
        "triage_to_analysis": 60,
        "analysis_to_response": 80,
        "response_to_resolved": 95,
    }

    # Tool access thresholds (minimum confidence to use)
    TOOL_THRESHOLDS = {
        "passive_enrichment": 0,       # Always allowed
        "active_enrichment": 40,       # Need some basis
        "containment_recommend": 70,   # High confidence to suggest
        "containment_execute": 90,     # Very high to auto-execute
    }

    # Escalation triggers
    ESCALATION_THRESHOLDS = {
        "request_human_review": 50,    # Stuck or uncertain
        "urgent_escalation": 30,       # High severity + low confidence
    }

    # Confidence stall detection
    STALL_DETECTION = {
        "min_iterations": 2,           # Need at least 2 data points
        "min_improvement": 5,          # Less than 5% improvement = stalled
    }

    def __init__(self):
        self._confidence_history: Dict[str, List[int]] = {}

    def record_confidence(self, investigation_id: str, confidence: int) -> None:
        """Record confidence for stall detection."""
        if investigation_id not in self._confidence_history:
            self._confidence_history[investigation_id] = []
        self._confidence_history[investigation_id].append(confidence)

        # Keep only last 10 readings
        if len(self._confidence_history[investigation_id]) > 10:
            self._confidence_history[investigation_id] = self._confidence_history[investigation_id][-10:]

    def get_confidence_history(self, investigation_id: str) -> List[int]:
        """Get confidence history for an investigation."""
        return self._confidence_history.get(investigation_id, [])

    def can_access_tool_category(
        self,
        tool_category: str,
        current_confidence: int
    ) -> ToolAccessDecision:
        """
        Check if a tool category is accessible at current confidence.

        Categories:
        - passive_enrichment: Internal lookups, read-only
        - active_enrichment: External API calls, threat intel
        - containment_recommend: Suggest containment actions
        - containment_execute: Actually execute containment
        """
        threshold = self.TOOL_THRESHOLDS.get(tool_category, 100)
        allowed = current_confidence >= threshold

        if allowed:
            reason = f"Confidence {current_confidence}% meets threshold {threshold}%"
        else:
            reason = f"Confidence {current_confidence}% below threshold {threshold}%"

        return ToolAccessDecision(
            allowed=allowed,
            reason=reason,
            required_confidence=threshold,
            current_confidence=current_confidence
        )

    def should_escalate(
        self,
        confidence: int,
        severity: str,
        iterations: int
    ) -> EscalationDecision:
        """
        Determine if investigation should be escalated to human.

        Escalation triggers:
        1. High severity + low confidence
        2. Stuck - multiple iterations without progress
        """
        # High severity + low confidence = urgent escalation
        if severity in ["critical", "high"]:
            if confidence < self.ESCALATION_THRESHOLDS["urgent_escalation"]:
                return EscalationDecision(
                    escalate=True,
                    reason=f"High severity ({severity}) with low confidence ({confidence}%)",
                    urgency="critical" if severity == "critical" else "high"
                )

        # Stuck detection
        if iterations > 3 and confidence < self.ESCALATION_THRESHOLDS["request_human_review"]:
            return EscalationDecision(
                escalate=True,
                reason=f"Stuck - {iterations} iterations with only {confidence}% confidence",
                urgency="normal"
            )

        return EscalationDecision(
            escalate=False,
            reason="No escalation needed"
        )

    def is_stalled(self, investigation_id: str) -> tuple[bool, str]:
        """
        Check if confidence is stalled (not improving).

        Used to trigger SOP reference retrieval.
        """
        history = self.get_confidence_history(investigation_id)

        if len(history) < self.STALL_DETECTION["min_iterations"]:
            return False, "Insufficient data for stall detection"

        recent = history[-self.STALL_DETECTION["min_iterations"]:]
        improvement = recent[-1] - recent[0]

        if improvement < self.STALL_DETECTION["min_improvement"]:
            return True, f"Confidence stalled - only {improvement}% improvement over {len(recent)} iterations"

        return False, f"Confidence improving - {improvement}% over {len(recent)} iterations"

    def get_next_threshold(self, current_checkpoint: str) -> int:
        """Get the confidence threshold for progressing from current checkpoint."""
        thresholds = {
            "triage": self.CHECKPOINT_THRESHOLDS["triage_to_analysis"],
            "analysis": self.CHECKPOINT_THRESHOLDS["analysis_to_response"],
            "response": self.CHECKPOINT_THRESHOLDS["response_to_resolved"],
        }
        return thresholds.get(current_checkpoint, 80)

    def calculate_confidence_gap(
        self,
        current_confidence: int,
        current_checkpoint: str
    ) -> Dict[str, Any]:
        """Calculate how far from next checkpoint threshold."""
        threshold = self.get_next_threshold(current_checkpoint)
        gap = threshold - current_confidence

        return {
            "current_confidence": current_confidence,
            "target_threshold": threshold,
            "gap": gap,
            "progress_percentage": min(100, int((current_confidence / threshold) * 100)),
            "needs_improvement": gap > 0
        }

    def suggest_actions_for_confidence(
        self,
        current_confidence: int,
        available_evidence: List[str],
        gaps: List[str]
    ) -> List[str]:
        """Suggest actions to improve confidence."""
        suggestions = []

        if current_confidence < 40:
            suggestions.append("Gather more initial evidence - IOC enrichment, asset context")

        if current_confidence < 60 and gaps:
            suggestions.append(f"Address known gaps: {', '.join(gaps[:3])}")

        if current_confidence < 80:
            suggestions.append("Cross-reference with threat intelligence")
            suggestions.append("Verify scope and affected assets")

        if current_confidence >= 80:
            suggestions.append("Document findings and prepare recommendations")

        return suggestions

    def clear_history(self, investigation_id: str) -> None:
        """Clear confidence history for an investigation."""
        if investigation_id in self._confidence_history:
            del self._confidence_history[investigation_id]


# =============================================================================
# SINGLETON
# =============================================================================

_confidence_gate: Optional[ConfidenceGate] = None


def get_confidence_gate() -> ConfidenceGate:
    """Get the global confidence gate instance."""
    global _confidence_gate
    if _confidence_gate is None:
        _confidence_gate = ConfidenceGate()
    return _confidence_gate
