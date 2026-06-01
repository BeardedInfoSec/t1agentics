# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Checkpoint Manager - Investigation Progression

Checkpoints represent investigation milestones, NOT agent handoffs.
The reasoning context PERSISTS across checkpoints.

Checkpoints: TRIAGE -> ANALYSIS -> RESPONSE -> RESOLVED
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class Checkpoint(str, Enum):
    """
    Investigation checkpoints.

    These are milestones, not tiers. The same reasoning engine
    handles all checkpoints with continuous context.
    """
    TRIAGE = "triage"       # Initial assessment
    ANALYSIS = "analysis"   # Deep investigation
    RESPONSE = "response"   # Action determination
    RESOLVED = "resolved"   # Complete


@dataclass
class CheckpointConfig:
    """Configuration for a checkpoint transition."""
    next_checkpoint: Checkpoint
    confidence_threshold: int
    required_evidence: List[str]
    max_iterations: int


# Checkpoint transition rules
CHECKPOINT_TRANSITIONS: Dict[str, CheckpointConfig] = {
    "triage": CheckpointConfig(
        next_checkpoint=Checkpoint.ANALYSIS,
        confidence_threshold=60,
        required_evidence=["initial_severity", "affected_assets", "ioc_identification"],
        max_iterations=5
    ),
    "analysis": CheckpointConfig(
        next_checkpoint=Checkpoint.RESPONSE,
        confidence_threshold=80,
        required_evidence=["threat_classification", "scope_determination", "root_cause"],
        max_iterations=10
    ),
    "response": CheckpointConfig(
        next_checkpoint=Checkpoint.RESOLVED,
        confidence_threshold=95,
        required_evidence=["recommended_actions", "risk_assessment", "containment_status"],
        max_iterations=5
    )
}


@dataclass
class CheckpointState:
    """Current state of an investigation's checkpoint."""
    investigation_id: str
    current_checkpoint: Checkpoint
    iterations_at_checkpoint: int = 0
    evidence_collected: List[str] = field(default_factory=list)
    checkpoint_history: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProgressionResult:
    """Result of checkpoint progression evaluation."""
    action: str  # "continue", "progress", "escalate"
    current_checkpoint: str
    next_checkpoint: Optional[str] = None
    reason: str = ""
    gaps: List[str] = field(default_factory=list)
    confidence: int = 0


class CheckpointManager:
    """
    Manages checkpoint progression for investigations.

    The checkpoint manager evaluates whether an investigation
    should progress to the next checkpoint based on:
    - Confidence threshold
    - Required evidence
    - Iteration limits
    """

    def __init__(self):
        self._states: Dict[str, CheckpointState] = {}

    def get_or_create_state(self, investigation_id: str) -> CheckpointState:
        """Get or create checkpoint state for an investigation."""
        if investigation_id not in self._states:
            self._states[investigation_id] = CheckpointState(
                investigation_id=investigation_id,
                current_checkpoint=Checkpoint.TRIAGE
            )
        return self._states[investigation_id]

    def get_threshold(self, checkpoint: str) -> int:
        """Get confidence threshold for a checkpoint."""
        config = CHECKPOINT_TRANSITIONS.get(checkpoint)
        return config.confidence_threshold if config else 80

    def get_required_evidence(self, checkpoint: str) -> List[str]:
        """Get required evidence for checkpoint progression."""
        config = CHECKPOINT_TRANSITIONS.get(checkpoint)
        return config.required_evidence if config else []

    async def evaluate_progression(
        self,
        investigation_id: str,
        reasoning_output: Dict[str, Any],
        evidence_collected: Optional[List[str]] = None
    ) -> ProgressionResult:
        """
        Evaluate whether an investigation should progress to next checkpoint.

        Args:
            investigation_id: Investigation ID
            reasoning_output: Output from reasoning engine
            evidence_collected: List of evidence types collected

        Returns:
            ProgressionResult with action to take
        """
        state = self.get_or_create_state(investigation_id)
        current = state.current_checkpoint.value
        config = CHECKPOINT_TRANSITIONS.get(current)

        if not config:
            # Already resolved or invalid state
            return ProgressionResult(
                action="complete",
                current_checkpoint=current,
                reason="Investigation already at final checkpoint"
            )

        confidence = reasoning_output.get("confidence", 0)
        gaps = reasoning_output.get("gaps", [])

        # Update state
        state.iterations_at_checkpoint += 1
        state.last_updated = datetime.now(timezone.utc)
        if evidence_collected:
            state.evidence_collected = list(set(state.evidence_collected + evidence_collected))

        # Check iteration limit
        if state.iterations_at_checkpoint >= config.max_iterations:
            logger.warning(f"[CHECKPOINT] Max iterations reached for {investigation_id} at {current}")
            return ProgressionResult(
                action="escalate",
                current_checkpoint=current,
                reason=f"Max iterations ({config.max_iterations}) reached without resolution",
                gaps=gaps,
                confidence=confidence
            )

        # Check confidence threshold
        if confidence < config.confidence_threshold:
            return ProgressionResult(
                action="continue",
                current_checkpoint=current,
                reason=f"Confidence {confidence}% below threshold {config.confidence_threshold}%",
                gaps=gaps,
                confidence=confidence
            )

        # Check required evidence
        missing_evidence = [
            e for e in config.required_evidence
            if e not in state.evidence_collected
        ]

        if missing_evidence:
            return ProgressionResult(
                action="continue",
                current_checkpoint=current,
                reason=f"Missing required evidence: {missing_evidence}",
                gaps=missing_evidence,
                confidence=confidence
            )

        # All conditions met - progress to next checkpoint
        next_checkpoint = config.next_checkpoint
        logger.info(f"[CHECKPOINT] Progressing {investigation_id}: {current} -> {next_checkpoint.value}")

        # Record history
        state.checkpoint_history.append({
            "from": current,
            "to": next_checkpoint.value,
            "confidence": confidence,
            "iterations": state.iterations_at_checkpoint,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        # Update state
        state.current_checkpoint = next_checkpoint
        state.iterations_at_checkpoint = 0

        return ProgressionResult(
            action="progress",
            current_checkpoint=current,
            next_checkpoint=next_checkpoint.value,
            reason=f"Confidence {confidence}% meets threshold, evidence complete",
            confidence=confidence
        )

    def add_evidence(self, investigation_id: str, evidence_type: str) -> None:
        """Record that a type of evidence has been collected."""
        state = self.get_or_create_state(investigation_id)
        if evidence_type not in state.evidence_collected:
            state.evidence_collected.append(evidence_type)
            logger.debug(f"[CHECKPOINT] Added evidence '{evidence_type}' to {investigation_id}")

    def get_progress_summary(self, investigation_id: str) -> Dict[str, Any]:
        """Get a summary of investigation progress."""
        state = self.get_or_create_state(investigation_id)
        config = CHECKPOINT_TRANSITIONS.get(state.current_checkpoint.value)

        return {
            "investigation_id": investigation_id,
            "current_checkpoint": state.current_checkpoint.value,
            "iterations_at_checkpoint": state.iterations_at_checkpoint,
            "max_iterations": config.max_iterations if config else 0,
            "confidence_threshold": config.confidence_threshold if config else 0,
            "required_evidence": config.required_evidence if config else [],
            "evidence_collected": state.evidence_collected,
            "missing_evidence": [
                e for e in (config.required_evidence if config else [])
                if e not in state.evidence_collected
            ],
            "checkpoint_history": state.checkpoint_history,
            "started_at": state.started_at.isoformat(),
            "last_updated": state.last_updated.isoformat()
        }

    def reset_investigation(self, investigation_id: str) -> None:
        """Reset investigation to initial state."""
        if investigation_id in self._states:
            del self._states[investigation_id]
        logger.info(f"[CHECKPOINT] Reset investigation: {investigation_id}")

    def force_checkpoint(self, investigation_id: str, checkpoint: Checkpoint) -> None:
        """Force an investigation to a specific checkpoint (admin override)."""
        state = self.get_or_create_state(investigation_id)
        old_checkpoint = state.current_checkpoint

        state.checkpoint_history.append({
            "from": old_checkpoint.value,
            "to": checkpoint.value,
            "forced": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        state.current_checkpoint = checkpoint
        state.iterations_at_checkpoint = 0
        logger.warning(f"[CHECKPOINT] Forced {investigation_id}: {old_checkpoint.value} -> {checkpoint.value}")


# =============================================================================
# SINGLETON
# =============================================================================

import threading as _threading

_checkpoint_manager: Optional[CheckpointManager] = None
_checkpoint_manager_lock = _threading.Lock()


def get_checkpoint_manager() -> CheckpointManager:
    """Get the global checkpoint manager instance (thread-safe)."""
    global _checkpoint_manager
    if _checkpoint_manager is None:
        with _checkpoint_manager_lock:
            if _checkpoint_manager is None:
                _checkpoint_manager = CheckpointManager()
    return _checkpoint_manager
