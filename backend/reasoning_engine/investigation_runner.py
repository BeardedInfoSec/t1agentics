# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Unified Investigation Cycle Runner

This is the main orchestrator that runs the unified reasoning loop.
It coordinates:
- ReasoningEngine (the brain)
- ToolBroker (authority enforcement)
- CheckpointManager (progression)
- ConfidenceGate (thresholds)
- HeuristicLoader (guidance)
- SOPRetriever (reference context when stalled)

ONE loop. ONE engine. Continuous context.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .core import ReasoningEngine, ReasoningOutput, InvestigationContext, get_reasoning_engine
from .tool_broker import ToolBroker, AuthorityLevel, get_tool_broker
from .checkpoint_manager import CheckpointManager, Checkpoint, get_checkpoint_manager
from .confidence_gate import ConfidenceGate, get_confidence_gate
from .heuristic_loader import HeuristicLoader, get_heuristic_loader
from .sop_retriever import SOPRetriever, get_sop_retriever

logger = logging.getLogger(__name__)


class CycleResult(str, Enum):
    """Result of a reasoning cycle."""
    CONTINUE = "continue"      # Keep reasoning
    PROGRESSED = "progressed"  # Moved to next checkpoint
    RESOLVED = "resolved"      # Investigation complete
    ESCALATED = "escalated"    # Needs human review
    ERROR = "error"            # System error


@dataclass
class InvestigationCycleResult:
    """Result of running one investigation cycle."""
    result: CycleResult
    checkpoint: str
    confidence: int
    reasoning_output: Optional[ReasoningOutput] = None
    tool_result: Optional[Dict[str, Any]] = None
    escalation_reason: Optional[str] = None
    error: Optional[str] = None
    iteration: int = 0


@dataclass
class InvestigationState:
    """Full state of an investigation."""
    investigation_id: str
    alert_data: Dict[str, Any]
    current_checkpoint: str = "triage"
    authority_level: str = "OBSERVE"
    confidence: int = 0
    iteration_count: int = 0

    # Evidence and results
    evidence_collected: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    established_facts: List[str] = field(default_factory=list)
    reasoning_history: List[ReasoningOutput] = field(default_factory=list)

    # Tracking
    confidence_history: List[int] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context(self) -> InvestigationContext:
        """Convert to InvestigationContext for reasoning engine."""
        return InvestigationContext(
            investigation_id=self.investigation_id,
            alert_data=self.alert_data,
            evidence_collected=self.evidence_collected,
            tool_results=self.tool_results,
            established_facts=self.established_facts,
            current_checkpoint=self.current_checkpoint,
            authority_level=self.authority_level,
            confidence_history=self.confidence_history,
            iteration_count=self.iteration_count
        )


class InvestigationRunner:
    """
    Orchestrates the unified investigation loop.

    This is the main entry point for running investigations.
    It coordinates all components while maintaining the invariants:
    - ONE reasoning engine
    - ONE prompt
    - Continuous context
    - System-enforced authority
    """

    # Maximum iterations before forced escalation
    MAX_TOTAL_ITERATIONS = 25

    def __init__(
        self,
        llm_client=None,
        db_service=None
    ):
        """
        Initialize the investigation runner.

        Args:
            llm_client: Client for LLM API calls. If None, uses ReasoningLLMClient.
            db_service: Database service for persistence
        """
        # Auto-create LLM client if not provided
        if llm_client is None:
            from .llm_client import get_reasoning_llm_client
            llm_client = get_reasoning_llm_client()

        self.reasoning_engine = get_reasoning_engine(llm_client)
        self.tool_broker = get_tool_broker()
        self.checkpoint_manager = get_checkpoint_manager()
        self.confidence_gate = get_confidence_gate()
        self.heuristic_loader = get_heuristic_loader(db_service)
        self.sop_retriever = get_sop_retriever()

        self._states: Dict[str, InvestigationState] = {}
        self.db_service = db_service

    def get_or_create_state(
        self,
        investigation_id: str,
        alert_data: Optional[Dict[str, Any]] = None
    ) -> InvestigationState:
        """Get or create investigation state."""
        if investigation_id not in self._states:
            if alert_data is None:
                raise ValueError(f"No state found for {investigation_id} and no alert_data provided")
            self._states[investigation_id] = InvestigationState(
                investigation_id=investigation_id,
                alert_data=alert_data
            )
        return self._states[investigation_id]

    def extract_alert_features(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from alert for heuristic matching."""
        features = {
            "alert_type": alert_data.get("type", alert_data.get("category", "unknown")),
            "severity": alert_data.get("severity", "medium"),
            "source": alert_data.get("source", "unknown"),
        }

        # Check for specific content
        raw_event = alert_data.get("raw_event", {})
        title = alert_data.get("title", "").lower()

        # IOC presence
        features["has_ip"] = bool(alert_data.get("ip") or "ip" in str(raw_event).lower())
        features["has_domain"] = bool(alert_data.get("domain") or "domain" in str(raw_event).lower())
        features["has_hash"] = bool(alert_data.get("hash") or alert_data.get("file_hash"))
        features["has_user"] = bool(alert_data.get("user") or alert_data.get("username"))

        # Alert type detection
        features["has_internal_ip"] = any(
            ip.startswith(("10.", "192.168.", "172."))
            for ip in [alert_data.get("src_ip", ""), alert_data.get("dest_ip", "")]
            if ip
        )

        # Type-specific features
        if "phish" in title or features["alert_type"] == "phishing":
            features["alert_type"] = "phishing"
        if "malware" in title or "ransomware" in title:
            features["alert_type"] = "malware"
        if "credential" in title or "password" in title:
            features["involves_credentials"] = True
        if "lateral" in title:
            features["alert_type"] = "lateral_movement"

        # Source confidence
        if alert_data.get("source_confidence"):
            features["source_confidence"] = alert_data["source_confidence"]

        return features

    async def run_cycle(
        self,
        investigation_id: str,
        alert_data: Optional[Dict[str, Any]] = None
    ) -> InvestigationCycleResult:
        """
        Run one iteration of the investigation reasoning cycle.

        This is the main entry point. Call this repeatedly until
        result is RESOLVED or ESCALATED.

        Args:
            investigation_id: Investigation ID
            alert_data: Alert data (required for first call)

        Returns:
            InvestigationCycleResult with action to take
        """
        try:
            # Get or create state
            state = self.get_or_create_state(investigation_id, alert_data)
            state.iteration_count += 1
            state.last_updated = datetime.now(timezone.utc)

            logger.info(
                f"[RUNNER] Cycle {state.iteration_count} for {investigation_id}, "
                f"checkpoint: {state.current_checkpoint}, confidence: {state.confidence}%"
            )

            # Check total iteration limit
            if state.iteration_count > self.MAX_TOTAL_ITERATIONS:
                logger.warning(f"[RUNNER] Max iterations reached for {investigation_id}")
                return InvestigationCycleResult(
                    result=CycleResult.ESCALATED,
                    checkpoint=state.current_checkpoint,
                    confidence=state.confidence,
                    escalation_reason=f"Max iterations ({self.MAX_TOTAL_ITERATIONS}) reached",
                    iteration=state.iteration_count
                )

            # Extract alert features for heuristic matching
            features = self.extract_alert_features(state.alert_data)

            # Load relevant heuristics
            heuristics = self.heuristic_loader.get_matching_heuristics(
                features,
                state.current_checkpoint
            )

            # Check if stalled - maybe retrieve SOP context
            supplemental_context = None
            if self.sop_retriever.should_retrieve_sop(state.confidence_history):
                logger.info(f"[RUNNER] Reasoning stalled, retrieving SOP reference")
                sop_context = self.sop_retriever.get_sop_context(
                    features.get("alert_type", "unknown"),
                    state.reasoning_history[-1].gaps if state.reasoning_history else []
                )
                if sop_context:
                    supplemental_context = self.sop_retriever.format_for_prompt(sop_context)

            # Build context and run reasoning
            context = state.to_context()
            reasoning_output = await self.reasoning_engine.reason(
                context=context,
                heuristics=heuristics,
                supplemental_context=supplemental_context
            )

            # Store reasoning output
            state.reasoning_history.append(reasoning_output)
            state.confidence = reasoning_output.confidence
            state.confidence_history.append(reasoning_output.confidence)

            # Record confidence for stall detection
            self.confidence_gate.record_confidence(investigation_id, reasoning_output.confidence)

            # Handle the next action
            return await self._handle_action(state, reasoning_output, features)

        except Exception as e:
            logger.error(f"[RUNNER] Cycle error for {investigation_id}: {e}")
            return InvestigationCycleResult(
                result=CycleResult.ERROR,
                checkpoint=state.current_checkpoint if 'state' in locals() else "unknown",
                confidence=0,
                error=str(e),
                iteration=state.iteration_count if 'state' in locals() else 0
            )

    async def _handle_action(
        self,
        state: InvestigationState,
        reasoning_output: ReasoningOutput,
        features: Dict[str, Any]
    ) -> InvestigationCycleResult:
        """Handle the action from reasoning output."""

        action_type = reasoning_output.action_type

        # Tool call requested
        if action_type == "tool_call":
            return await self._handle_tool_call(state, reasoning_output)

        # Checkpoint progression requested
        if action_type == "checkpoint_progress":
            return await self._handle_checkpoint_progress(state, reasoning_output)

        # Escalation requested
        if action_type == "escalate":
            return self._handle_escalation(state, reasoning_output)

        # Investigation complete
        if action_type == "complete":
            return self._handle_completion(state, reasoning_output)

        # Default: continue reasoning
        return InvestigationCycleResult(
            result=CycleResult.CONTINUE,
            checkpoint=state.current_checkpoint,
            confidence=reasoning_output.confidence,
            reasoning_output=reasoning_output,
            iteration=state.iteration_count
        )

    async def _handle_tool_call(
        self,
        state: InvestigationState,
        reasoning_output: ReasoningOutput
    ) -> InvestigationCycleResult:
        """Handle tool call request."""
        tool_name = reasoning_output.requested_tool
        parameters = reasoning_output.tool_parameters

        # Execute through broker (enforces authority)
        investigation_context = {
            "investigation_id": state.investigation_id,
            "authority_level": state.authority_level,
            "confidence": state.confidence
        }

        result = await self.tool_broker.execute_tool(
            tool_id=tool_name,
            parameters=parameters,
            investigation_context=investigation_context
        )

        if result.success:
            # Store tool result
            state.tool_results.append({
                "tool": tool_name,
                "parameters": parameters,
                "data": result.data,
                "summary": str(result.data)[:200] if result.data else "",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            return InvestigationCycleResult(
                result=CycleResult.CONTINUE,
                checkpoint=state.current_checkpoint,
                confidence=state.confidence,
                reasoning_output=reasoning_output,
                tool_result=result.data,
                iteration=state.iteration_count
            )
        else:
            # Tool blocked or failed
            logger.warning(f"[RUNNER] Tool {tool_name} blocked: {result.blocked_reason or result.error}")

            # If blocked due to authority, might need upgrade
            if result.blocked_reason:
                # Add to context so reasoning knows
                state.established_facts.append(
                    f"Tool {tool_name} blocked: {result.blocked_reason}"
                )

            return InvestigationCycleResult(
                result=CycleResult.CONTINUE,
                checkpoint=state.current_checkpoint,
                confidence=state.confidence,
                reasoning_output=reasoning_output,
                error=result.blocked_reason or result.error,
                iteration=state.iteration_count
            )

    async def _handle_checkpoint_progress(
        self,
        state: InvestigationState,
        reasoning_output: ReasoningOutput
    ) -> InvestigationCycleResult:
        """Handle checkpoint progression request."""

        # Evaluate progression through checkpoint manager
        progression = await self.checkpoint_manager.evaluate_progression(
            investigation_id=state.investigation_id,
            reasoning_output={
                "confidence": reasoning_output.confidence,
                "gaps": reasoning_output.gaps
            },
            evidence_collected=[f.get("type", "unknown") for f in state.evidence_collected]
        )

        if progression.action == "progress":
            # Update state
            state.current_checkpoint = progression.next_checkpoint
            logger.info(f"[RUNNER] Progressed to checkpoint: {progression.next_checkpoint}")

            # Check if resolved
            if progression.next_checkpoint == "resolved":
                return InvestigationCycleResult(
                    result=CycleResult.RESOLVED,
                    checkpoint="resolved",
                    confidence=reasoning_output.confidence,
                    reasoning_output=reasoning_output,
                    iteration=state.iteration_count
                )

            return InvestigationCycleResult(
                result=CycleResult.PROGRESSED,
                checkpoint=progression.next_checkpoint,
                confidence=reasoning_output.confidence,
                reasoning_output=reasoning_output,
                iteration=state.iteration_count
            )

        elif progression.action == "escalate":
            return InvestigationCycleResult(
                result=CycleResult.ESCALATED,
                checkpoint=state.current_checkpoint,
                confidence=reasoning_output.confidence,
                reasoning_output=reasoning_output,
                escalation_reason=progression.reason,
                iteration=state.iteration_count
            )

        # Continue (didn't meet threshold)
        return InvestigationCycleResult(
            result=CycleResult.CONTINUE,
            checkpoint=state.current_checkpoint,
            confidence=reasoning_output.confidence,
            reasoning_output=reasoning_output,
            iteration=state.iteration_count
        )

    def _handle_escalation(
        self,
        state: InvestigationState,
        reasoning_output: ReasoningOutput
    ) -> InvestigationCycleResult:
        """Handle escalation request."""
        reason = reasoning_output.next_action.get("reason", "Reasoning requested escalation")

        logger.info(f"[RUNNER] Escalating {state.investigation_id}: {reason}")

        return InvestigationCycleResult(
            result=CycleResult.ESCALATED,
            checkpoint=state.current_checkpoint,
            confidence=reasoning_output.confidence,
            reasoning_output=reasoning_output,
            escalation_reason=reason,
            iteration=state.iteration_count
        )

    def _handle_completion(
        self,
        state: InvestigationState,
        reasoning_output: ReasoningOutput
    ) -> InvestigationCycleResult:
        """Handle investigation completion."""
        logger.info(f"[RUNNER] Investigation {state.investigation_id} resolved")

        return InvestigationCycleResult(
            result=CycleResult.RESOLVED,
            checkpoint="resolved",
            confidence=reasoning_output.confidence,
            reasoning_output=reasoning_output,
            iteration=state.iteration_count
        )

    def upgrade_authority(
        self,
        investigation_id: str,
        new_level: AuthorityLevel
    ) -> bool:
        """Upgrade authority level for an investigation."""
        if investigation_id not in self._states:
            return False

        state = self._states[investigation_id]
        old_level = state.authority_level
        state.authority_level = new_level.value

        logger.info(f"[RUNNER] Authority upgraded for {investigation_id}: {old_level} -> {new_level.value}")
        return True

    def get_state(self, investigation_id: str) -> Optional[InvestigationState]:
        """Get investigation state."""
        return self._states.get(investigation_id)

    def get_summary(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get investigation summary."""
        state = self._states.get(investigation_id)
        if not state:
            return None

        return {
            "investigation_id": investigation_id,
            "current_checkpoint": state.current_checkpoint,
            "authority_level": state.authority_level,
            "confidence": state.confidence,
            "iteration_count": state.iteration_count,
            "tool_calls": len(state.tool_results),
            "established_facts": len(state.established_facts),
            "confidence_history": state.confidence_history,
            "started_at": state.started_at.isoformat(),
            "last_updated": state.last_updated.isoformat()
        }


# =============================================================================
# SINGLETON
# =============================================================================

import threading as _threading

_investigation_runner: Optional[InvestigationRunner] = None
_investigation_runner_lock = _threading.Lock()


def get_investigation_runner(llm_client=None, db_service=None) -> InvestigationRunner:
    """Get the global investigation runner instance (thread-safe)."""
    global _investigation_runner
    if _investigation_runner is None:
        with _investigation_runner_lock:
            if _investigation_runner is None:
                _investigation_runner = InvestigationRunner(llm_client, db_service)
    return _investigation_runner
