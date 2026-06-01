# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Frozen Tool Registry - Token Optimization ENFORCED

HARD ENFORCEMENT MODE:
- Tier 1: ONLY 3 tools: extract_indicators, enrich_indicator, complete_analysis
- NO JSON schemas sent to LLM - tools are in prompt text only
- Max 2 tool calls per alert
- Target: 700-900 tokens per alert

This module:
1. Defines the EXACT 3 tools allowed for Tier 1
2. Provides tool name list for prompt injection (NOT JSON schemas)
3. Enforces tool call limits at code level
4. Validates tool calls against whitelist
"""

import hashlib
import json
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class FrozenRegistryError(Exception):
    """Raised when attempting to modify a frozen tool registry"""
    pass


class ToolCallLimitExceeded(Exception):
    """Raised when tool call limit is exceeded"""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 1 STRICT TOOL LIST - EXACTLY 3 TOOLS, NO EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

TIER1_ALLOWED_TOOLS = frozenset([
    "extract_indicators",
    "enrich_indicator",
    "complete_analysis"
])

# Tool descriptions for prompt injection (NOT JSON schemas)
# IMPORTANT: complete_analysis MUST be emphasized and should be called directly for clear-cut alerts
TIER1_TOOL_DESCRIPTIONS = """TOOLS (max 3 calls - be decisive):
1. complete_analysis(verdict, confidence, summary) - REQUIRED: Submit final verdict
   verdict: true_positive|false_positive|suspicious|benign|needs_escalation
2. extract_indicators(text) - Optional: Extract IOCs if needed for enrichment
3. enrich_indicator(type, value) - Optional: Only if IOC verdict is unclear

WORKFLOW: For clear-cut alerts, call complete_analysis IMMEDIATELY.
Only use extract/enrich if the alert context is insufficient to decide."""

# TIER 1 DECISION-ONLY MODE - No tools except complete_analysis
# Used when pre-digested context is provided (enrichment already done)
TIER1_DECISION_ONLY_TOOLS = frozenset(["complete_analysis"])

TIER1_DECISION_ONLY_DESCRIPTIONS = """DECISION-ONLY MODE - All enrichment is pre-computed above.
Call complete_analysis with your verdict based on the pre-digested context.

IMPORTANT: If you see base64/encoded content (like "powershell -enc"), DECODE IT and include hidden IOCs in decoded_iocs.

FORMAT:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"brief finding","decoded_iocs":{"ips":[],"urls":[],"domains":[]}}}

VERDICTS:
- benign: Legitimate activity, no threat
- false_positive: Alert fired incorrectly
- true_positive: Confirmed malicious
- suspicious: Genuinely unclear (use sparingly)
- needs_escalation: Critical incident requiring T3"""

# Tier 2 tool descriptions - more tools but still compact
TIER2_TOOL_DESCRIPTIONS = """TOOLS (max 4 calls - validate T1 findings):
1. complete_analysis(verdict, confidence, summary) - REQUIRED: Submit final verdict
   verdict: true_positive|false_positive|suspicious|benign|needs_escalation
2. inspect_raw_event_data(alert_id) - View full raw event (only if context unclear)
3. enrich_indicator(type, value) - Only if T1 enrichment was insufficient
4. search_ioc_database(query) - Search for known malicious indicators
5. query_knowledge_base(query) - Check for similar past incidents

WORKFLOW: Review T1 verdict and raw event. Confirm or override with complete_analysis.
If T1 is correct, confirm immediately. Only use other tools if evidence is conflicting."""

# Tier 3 tool descriptions - response actions
TIER3_TOOL_DESCRIPTIONS = """TOOLS (call by name):
- extract_indicators(text): Extract IOCs
- enrich_indicator(type, value): Enrich IOC
- complete_analysis(verdict, confidence, summary): Submit verdict
- search_ioc_database(query): Search IOCs
- search_investigations(query): Search investigations
- request_action(action_type, target, reason): Request response action"""


# ═══════════════════════════════════════════════════════════════════════════════
# HARD LIMITS - NON-NEGOTIABLE (ALL TIERS)
# ═══════════════════════════════════════════════════════════════════════════════

TIER1_MAX_TOOL_CALLS = 3  # Maximum 3 tool calls per alert (extract+enrich+complete)
TIER1_MAX_STEPS = 2  # Maximum 2 LLM calls per alert

TIER2_MAX_TOOL_CALLS = 4  # Maximum 4 tool calls for investigation
TIER2_MAX_STEPS = 3  # Maximum 3 LLM calls (more complex validation)

TIER3_MAX_TOOL_CALLS = 5  # Maximum 5 tool calls for response
TIER3_MAX_STEPS = 3  # Maximum 3 LLM calls


@dataclass
class ToolGatingFlags:
    """
    Flags indicating what data is available for an alert.
    Used to gate tools that would return empty results.
    """
    has_attachments: bool = False
    attachment_count: int = 0
    has_related_alerts: bool = False
    related_alert_count: int = 0
    has_raw_event: bool = False
    has_enrichment_data: bool = False
    has_iocs_extracted: bool = False

    @classmethod
    def from_alert(cls, alert: Dict[str, Any]) -> 'ToolGatingFlags':
        """Extract gating flags from alert data"""
        return cls(
            has_attachments=alert.get('has_attachments', False),
            attachment_count=alert.get('attachment_count', 0),
            has_related_alerts=alert.get('related_alert_count', 0) > 0,
            related_alert_count=alert.get('related_alert_count', 0),
            has_raw_event=bool(alert.get('raw_event')),
            has_enrichment_data=bool(alert.get('enrichment_data')),
            has_iocs_extracted=bool(alert.get('iocs_extracted'))
        )


@dataclass
class FrozenToolRegistry:
    """
    Immutable tool registry for Tier 1 agent execution.

    ENFORCED CONSTRAINTS:
    - ONLY 3 tools allowed: extract_indicators, enrich_indicator, complete_analysis
    - Max 2 tool calls total per execution
    - No JSON schemas - tools described in prompt text

    DECISION-ONLY MODE:
    - Only complete_analysis tool
    - Max 1 tool call
    - Used when pre-digested context is provided
    """
    tier: int = 1
    tool_names: Set[str] = field(default_factory=set)
    gating_flags: Optional[ToolGatingFlags] = None
    prefix_hash: str = ""
    _frozen: bool = False
    _tool_call_count: int = 0
    _max_tool_calls: int = TIER1_MAX_TOOL_CALLS
    _decision_only: bool = False

    def freeze(self) -> str:
        """
        Freeze the registry and compute prefix hash.
        Returns the prefix hash for logging/debugging.
        """
        if self._frozen:
            raise FrozenRegistryError("Registry already frozen")

        # Compute deterministic hash based on tool names (stable prefix)
        tool_str = ",".join(sorted(self.tool_names))
        self.prefix_hash = hashlib.sha256(tool_str.encode()).hexdigest()[:16]
        self._frozen = True

        logger.info(f"[FROZEN_REGISTRY] Tier {self.tier} frozen: tools={self.tool_names}, max_calls={self._max_tool_calls}, prefix_hash={self.prefix_hash}")
        return self.prefix_hash

    def get_tool_names(self) -> List[str]:
        """Get list of allowed tool names (NOT schemas)"""
        return list(self.tool_names)

    def get_tool_descriptions(self) -> str:
        """Get tool descriptions for prompt injection based on tier"""
        if self.tier == 1:
            if self._decision_only:
                return TIER1_DECISION_ONLY_DESCRIPTIONS
            return TIER1_TOOL_DESCRIPTIONS
        elif self.tier == 2:
            return TIER2_TOOL_DESCRIPTIONS
        else:
            return TIER3_TOOL_DESCRIPTIONS

    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool is in the registry"""
        return tool_name in self.tool_names

    def validate_tool_call(self, tool_name: str) -> bool:
        """
        Validate that a tool call is allowed.

        Returns False if:
        - Tool not in whitelist
        - Tool call limit exceeded
        """
        if not self._frozen:
            raise FrozenRegistryError("Registry not frozen - call freeze() first")

        # Check whitelist
        if tool_name not in self.tool_names:
            logger.warning(f"[FROZEN_REGISTRY] BLOCKED: '{tool_name}' not in whitelist {self.tool_names}")
            return False

        # Check call limit
        if self._tool_call_count >= self._max_tool_calls:
            logger.warning(f"[FROZEN_REGISTRY] BLOCKED: Tool call limit exceeded ({self._tool_call_count}/{self._max_tool_calls})")
            return False

        return True

    def record_tool_call(self, tool_name: str) -> bool:
        """
        Record a tool call and check if limit exceeded.

        Returns True if call allowed, False if blocked.
        """
        if not self.validate_tool_call(tool_name):
            return False

        self._tool_call_count += 1
        remaining = self._max_tool_calls - self._tool_call_count
        logger.info(f"[FROZEN_REGISTRY] Tool call recorded: {tool_name} ({self._tool_call_count}/{self._max_tool_calls}, {remaining} remaining)")
        return True

    def get_remaining_calls(self) -> int:
        """Get number of remaining tool calls allowed"""
        return max(0, self._max_tool_calls - self._tool_call_count)

    def is_limit_reached(self) -> bool:
        """Check if tool call limit has been reached"""
        return self._tool_call_count >= self._max_tool_calls


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 1 TOOL SCHEMAS (for tool execution, NOT sent to LLM)
# These are used internally to validate and execute tool calls
# ═══════════════════════════════════════════════════════════════════════════════

TIER1_TOOL_SCHEMAS = {
    "extract_indicators": {
        "parameters": ["text"],
        "required": ["text"]
    },
    "enrich_indicator": {
        "parameters": ["indicator_type", "indicator_value"],
        "required": ["indicator_type", "indicator_value"],
        "enum_values": {
            "indicator_type": ["ip", "domain", "hash", "url", "email"]
        }
    },
    "complete_analysis": {
        "parameters": ["verdict", "confidence", "summary", "recommended_actions", "decoded_iocs", "key_findings"],
        "required": ["verdict", "confidence", "summary"],
        "enum_values": {
            "verdict": ["true_positive", "false_positive", "suspicious", "benign", "needs_escalation"]
        }
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2+ TOOL LIST (expanded set for escalated analysis)
# ═══════════════════════════════════════════════════════════════════════════════

TIER2_ALLOWED_TOOLS = frozenset([
    "extract_indicators",
    "enrich_indicator",
    "complete_analysis",
    "decode_data",
    "inspect_raw_event_data",
    "search_ioc_database",
    "search_investigations",
    "lookup_phishing_email",
    "list_alert_attachments",
    "query_knowledge_base"
])


def create_frozen_registry(
    tier: int,
    alert_data: Optional[Dict[str, Any]] = None,
    include_kb_tool: bool = False,
    decision_only: bool = False
) -> FrozenToolRegistry:
    """
    Create a frozen tool registry for an agent execution.

    TIER 1 ENFORCEMENT:
    - ONLY 3 tools: extract_indicators, enrich_indicator, complete_analysis
    - Max 2 tool calls
    - No JSON schemas

    DECISION-ONLY MODE (Tier 1 only):
    - Only complete_analysis tool
    - Max 1 tool call
    - Used when pre-digested context is provided

    Args:
        tier: Agent tier (1, 2, or 3)
        alert_data: Alert data for gating flags
        include_kb_tool: Ignored for Tier 1
        decision_only: If True, only allow complete_analysis (T1 only)

    Returns:
        Frozen and immutable tool registry
    """
    gating_flags = ToolGatingFlags.from_alert(alert_data or {})

    if tier == 1:
        if decision_only:
            # TIER 1 DECISION-ONLY: Only complete_analysis
            tool_names = set(TIER1_DECISION_ONLY_TOOLS)
            max_tool_calls = 1  # Single decision call
            logger.info(f"[FROZEN_REGISTRY] Creating Tier 1 DECISION-ONLY registry")
        else:
            # TIER 1: STRICT - Only 3 tools
            tool_names = set(TIER1_ALLOWED_TOOLS)
            max_tool_calls = TIER1_MAX_TOOL_CALLS
    elif tier == 2:
        # TIER 2: Investigation tools - still optimized
        tool_names = set(TIER2_ALLOWED_TOOLS)
        max_tool_calls = TIER2_MAX_TOOL_CALLS
    else:
        # TIER 3: Response tools
        tool_names = set(TIER2_ALLOWED_TOOLS)  # Same tools as T2 for now
        max_tool_calls = TIER3_MAX_TOOL_CALLS

    logger.info(f"[FROZEN_REGISTRY] Creating Tier {tier} registry: {len(tool_names)} tools, max {max_tool_calls} calls")

    registry = FrozenToolRegistry(
        tier=tier,
        tool_names=tool_names,
        gating_flags=gating_flags,
        _max_tool_calls=max_tool_calls,
        _decision_only=(tier == 1 and decision_only)
    )

    # Freeze and compute hash
    registry.freeze()

    return registry


def get_tier1_token_estimate() -> int:
    """Estimate token count for Tier 1 (no JSON schemas)"""
    # Tool descriptions in prompt: ~50 tokens
    return 50


def get_tier2_token_estimate() -> int:
    """Estimate token count for Tier 2"""
    return 150
