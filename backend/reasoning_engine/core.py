# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Unified Reasoning Engine Core

ONE reasoning engine. ONE prompt. No tiers. No personas.

The reasoning engine only reasons. The system enforces everything else.
"""

import json
import logging
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# UNIFIED REASONING PROMPT - FROZEN
# =============================================================================
# This prompt is version-controlled. Changes require justification + outcome data.
# Target: ~400 tokens base. Total with heuristics: ~1,200 tokens.

UNIFIED_REASONING_PROMPT = """You are a security analyst reasoning engine. Your goal is to reach accurate conclusions through evidence-based analysis, not to follow procedures.

CURRENT AUTHORITY LEVEL: {authority_level}
- OBSERVE: Read data, no external calls
- INVESTIGATE: Query threat intel, enrich IOCs
- RESPOND: Recommend containment actions
- PRE_APPROVED: Execute approved response actions

ACTIVE HEURISTICS:
{loaded_heuristics}

CURRENT CHECKPOINT: {checkpoint}
CONFIDENCE THRESHOLD FOR NEXT CHECKPOINT: {threshold}%

INVESTIGATION CONTEXT:
{context}

INSTRUCTIONS:
1. Assess the evidence presented
2. Apply relevant heuristics as GUIDANCE (not rules)
3. Determine what additional information would increase confidence
4. If confidence >= threshold, progress to next checkpoint
5. If blocked or uncertain, explain what's needed

CURIOSITY CONSTRAINT:
You may explore ONE unexpected angle if evidence suggests it.
Do not pursue multiple tangents. If the unexpected angle does not yield confidence-increasing evidence within one tool call, abandon it.

OUTPUT your reasoning as JSON:
{{
    "assessment": "What the evidence suggests",
    "confidence": <0-100>,
    "confidence_justification": "Why this confidence level",
    "gaps": ["What information is missing"],
    "next_action": {{
        "type": "tool_call|checkpoint_progress|escalate|complete",
        "tool": "tool_name if tool_call",
        "parameters": {{}},
        "reason": "Why this action"
    }},
    "rationale": "Why this action moves toward resolution"
}}"""


@dataclass
class ReasoningOutput:
    """Parsed output from the reasoning engine."""
    assessment: str
    confidence: int
    confidence_justification: str
    gaps: List[str]
    next_action: Dict[str, Any]
    rationale: str
    raw_response: str = ""
    parse_error: Optional[str] = None

    @property
    def action_type(self) -> str:
        return self.next_action.get("type", "unknown")

    @property
    def requested_tool(self) -> Optional[str]:
        if self.action_type == "tool_call":
            return self.next_action.get("tool")
        return None

    @property
    def tool_parameters(self) -> Dict[str, Any]:
        return self.next_action.get("parameters", {})


@dataclass
class InvestigationContext:
    """Context passed to the reasoning engine."""
    investigation_id: str
    alert_data: Dict[str, Any]
    evidence_collected: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    established_facts: List[str] = field(default_factory=list)
    current_checkpoint: str = "triage"
    authority_level: str = "OBSERVE"
    confidence_history: List[int] = field(default_factory=list)
    iteration_count: int = 0

    def to_context_string(self, max_tokens: int = 800) -> str:
        """Convert context to string for prompt injection."""
        parts = []

        # Alert summary (always include)
        parts.append(f"ALERT: {self.alert_data.get('title', 'Unknown Alert')}")
        parts.append(f"SEVERITY: {self.alert_data.get('severity', 'unknown')}")
        parts.append(f"SOURCE: {self.alert_data.get('source', 'unknown')}")

        # Established facts (compressed)
        if self.established_facts:
            facts_str = "; ".join(self.established_facts[-5:])  # Last 5 facts
            parts.append(f"ESTABLISHED FACTS: {facts_str}")

        # Recent tool results (compressed)
        if self.tool_results:
            recent = self.tool_results[-3:]  # Last 3 results
            for result in recent:
                tool_name = result.get("tool", "unknown")
                summary = result.get("summary", str(result.get("data", ""))[:200])
                parts.append(f"TOOL [{tool_name}]: {summary}")

        # Current gaps
        if self.evidence_collected:
            last_gaps = self.evidence_collected[-1].get("gaps", [])
            if last_gaps:
                parts.append(f"KNOWN GAPS: {', '.join(last_gaps[:3])}")

        context_str = "\n".join(parts)

        # Truncate if too long (rough token estimate: 4 chars per token)
        max_chars = max_tokens * 4
        if len(context_str) > max_chars:
            context_str = context_str[:max_chars] + "... [truncated]"

        return context_str


class ReasoningEngine:
    """
    Unified Reasoning Engine

    ONE engine. ONE prompt. Judgment-preserving.

    The engine ONLY reasons. It does not:
    - Enforce tool permissions (ToolBroker does this)
    - Manage checkpoints (CheckpointManager does this)
    - Apply confidence gates (ConfidenceGate does this)
    - Execute tools (system does this)
    """

    # Heuristic limits - LOCKED
    HEURISTIC_TARGET = 3
    HEURISTIC_MAX = 5
    HEURISTIC_TOKEN_LIMIT = 100  # Per heuristic

    # Confidence thresholds for checkpoints
    CHECKPOINT_THRESHOLDS = {
        "triage": 60,      # To progress to analysis
        "analysis": 80,    # To progress to response
        "response": 95,    # To mark resolved
    }

    def __init__(self, llm_client=None):
        """
        Initialize the reasoning engine.

        Args:
            llm_client: Client for LLM API calls. If None, must be set before use.
        """
        self.llm_client = llm_client
        self._prompt_version = "1.0"

    def build_prompt(
        self,
        context: InvestigationContext,
        heuristics: List[str],
        supplemental_context: Optional[str] = None
    ) -> str:
        """
        Build the reasoning prompt.

        Args:
            context: Investigation context
            heuristics: List of heuristic guidance strings (max 5)
            supplemental_context: Optional SOP reference (only if stalled)

        Returns:
            Complete prompt string
        """
        # Enforce heuristic limits
        heuristics = heuristics[:self.HEURISTIC_MAX]

        # Format heuristics
        if heuristics:
            heuristics_str = "\n".join(f"- {h[:self.HEURISTIC_TOKEN_LIMIT * 4]}" for h in heuristics)
        else:
            heuristics_str = "- No specific heuristics loaded for this alert type"

        # Get threshold for current checkpoint
        threshold = self.CHECKPOINT_THRESHOLDS.get(context.current_checkpoint, 80)

        # Build context string
        context_str = context.to_context_string()

        # Add supplemental context if provided (SOP reference on stall)
        if supplemental_context:
            context_str += f"\n\nSUPPLEMENTAL CONTEXT (reference only, not authoritative):\n{supplemental_context}"

        # Build prompt
        prompt = UNIFIED_REASONING_PROMPT.format(
            authority_level=context.authority_level,
            loaded_heuristics=heuristics_str,
            checkpoint=context.current_checkpoint,
            threshold=threshold,
            context=context_str
        )

        return prompt

    async def reason(
        self,
        context: InvestigationContext,
        heuristics: List[str],
        supplemental_context: Optional[str] = None
    ) -> ReasoningOutput:
        """
        Execute one reasoning cycle.

        Args:
            context: Investigation context
            heuristics: Relevant heuristics for this alert type
            supplemental_context: Optional SOP reference

        Returns:
            ReasoningOutput with assessment, confidence, and next action
        """
        if not self.llm_client:
            raise ValueError("LLM client not configured")

        # Build prompt
        prompt = self.build_prompt(context, heuristics, supplemental_context)

        # Log token estimate
        estimated_tokens = len(prompt) // 4
        logger.info(f"[REASONING] Prompt tokens (est): {estimated_tokens}, checkpoint: {context.current_checkpoint}")

        # Call LLM
        try:
            # Support both our ReasoningLLMClient and generic clients
            if hasattr(self.llm_client, 'complete'):
                # Our ReasoningLLMClient
                llm_response = await self.llm_client.complete(
                    prompt=prompt,
                    temperature=0.3  # Low temperature for consistent reasoning
                )
                if not llm_response.success:
                    raise ValueError(llm_response.error or "LLM call failed")
                raw_response = llm_response.content
            else:
                # Generic client with generate() method
                response = await self.llm_client.generate(
                    prompt=prompt,
                    max_tokens=800,
                    temperature=0.3
                )
                raw_response = response.get("content", response.get("text", str(response)))

            # Parse response
            output = self._parse_response(raw_response)
            output.raw_response = raw_response

            logger.info(f"[REASONING] Confidence: {output.confidence}%, Action: {output.action_type}")

            return output

        except Exception as e:
            logger.error(f"[REASONING] LLM call failed: {e}")
            return ReasoningOutput(
                assessment="Reasoning failed due to LLM error",
                confidence=0,
                confidence_justification="LLM call failed",
                gaps=["Unable to reason - system error"],
                next_action={"type": "escalate", "reason": str(e)},
                rationale="System error requires human review",
                parse_error=str(e)
            )

    def _parse_response(self, response_text: str) -> ReasoningOutput:
        """Parse LLM response into ReasoningOutput."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                data = json.loads(json_match.group())

                return ReasoningOutput(
                    assessment=data.get("assessment", ""),
                    confidence=int(data.get("confidence", 0)),
                    confidence_justification=data.get("confidence_justification", ""),
                    gaps=data.get("gaps", []),
                    next_action=data.get("next_action", {"type": "unknown"}),
                    rationale=data.get("rationale", "")
                )
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"[REASONING] Failed to parse JSON response: {e}")

        # Fallback: try to extract key fields from text
        return self._parse_text_response(response_text)

    def _parse_text_response(self, response_text: str) -> ReasoningOutput:
        """Fallback parser for non-JSON responses."""
        # Extract confidence if mentioned
        confidence = 50  # Default
        conf_match = re.search(r'confidence[:\s]*(\d+)', response_text, re.IGNORECASE)
        if conf_match:
            confidence = int(conf_match.group(1))

        return ReasoningOutput(
            assessment=response_text[:500],
            confidence=confidence,
            confidence_justification="Parsed from unstructured response",
            gaps=["Unable to parse structured output"],
            next_action={"type": "escalate", "reason": "Unstructured response"},
            rationale="Response was not in expected format",
            parse_error="Response was not valid JSON"
        )

    def estimate_prompt_tokens(
        self,
        context: InvestigationContext,
        heuristics: List[str]
    ) -> int:
        """Estimate token count for the prompt."""
        prompt = self.build_prompt(context, heuristics)
        # Rough estimate: 4 characters per token
        return len(prompt) // 4


# =============================================================================
# SINGLETON
# =============================================================================

_reasoning_engine: Optional[ReasoningEngine] = None


def get_reasoning_engine(llm_client=None) -> ReasoningEngine:
    """Get the global reasoning engine instance."""
    global _reasoning_engine
    if _reasoning_engine is None:
        _reasoning_engine = ReasoningEngine(llm_client)
    elif llm_client is not None:
        _reasoning_engine.llm_client = llm_client
    return _reasoning_engine
