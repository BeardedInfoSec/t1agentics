# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tool Broker - Authority Enforcement at System Level

The Tool Broker is the gatekeeper. It enforces authority levels.
The LLM can REQUEST any tool, but the broker decides what's allowed.

DOCTRINE: Tool restrictions are enforced ONLY by the system, never by prompts.
"""

import logging
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AuthorityLevel(str, Enum):
    """
    Authority levels for tool access.

    These are NOT tiers. Authority can be elevated at any checkpoint.
    """
    OBSERVE = "OBSERVE"           # Read-only, internal data
    INVESTIGATE = "INVESTIGATE"   # External queries, enrichment
    RESPOND = "RESPOND"           # Recommendations, safe actions
    PRE_APPROVED = "PRE_APPROVED" # Execute approved containment


# Authority hierarchy (lower index = less authority)
AUTHORITY_HIERARCHY = [
    AuthorityLevel.OBSERVE,
    AuthorityLevel.INVESTIGATE,
    AuthorityLevel.RESPOND,
    AuthorityLevel.PRE_APPROVED,
]


@dataclass
class ToolDefinition:
    """Definition of a tool available to the reasoning engine."""
    id: str
    name: str
    description: str
    required_authority: AuthorityLevel
    min_confidence: int = 0  # Minimum confidence to use
    parameters: Dict[str, Any] = None
    handler: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class ToolExecutionResult:
    """Result of a tool execution attempt."""
    success: bool
    tool_id: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    blocked_reason: Optional[str] = None
    authority_required: Optional[str] = None
    confidence_required: Optional[int] = None


class ToolBroker:
    """
    Central authority for tool access.

    The LLM can REQUEST any tool, but the broker enforces what's allowed
    based on authority level and confidence.

    NEVER put tool restrictions in prompts. The broker enforces everything.
    """

    # Default tool authority mappings
    DEFAULT_TOOL_AUTHORITY = {
        # OBSERVE level - read-only, internal data
        "get_alert_details": AuthorityLevel.OBSERVE,
        "get_asset_info": AuthorityLevel.OBSERVE,
        "get_user_history": AuthorityLevel.OBSERVE,
        "search_logs": AuthorityLevel.OBSERVE,
        "get_log_stats": AuthorityLevel.OBSERVE,
        "generate_log_report": AuthorityLevel.OBSERVE,
        "get_investigation_history": AuthorityLevel.OBSERVE,
        "list_related_alerts": AuthorityLevel.OBSERVE,

        # INVESTIGATE level - external queries, enrichment
        "lookup_ip_reputation": AuthorityLevel.INVESTIGATE,
        "lookup_domain_whois": AuthorityLevel.INVESTIGATE,
        "lookup_file_hash": AuthorityLevel.INVESTIGATE,
        "query_threat_intel": AuthorityLevel.INVESTIGATE,
        "enrich_ioc": AuthorityLevel.INVESTIGATE,
        "search_virustotal": AuthorityLevel.INVESTIGATE,
        "search_abuseipdb": AuthorityLevel.INVESTIGATE,
        "search_shodan": AuthorityLevel.INVESTIGATE,
        "resolve_dns": AuthorityLevel.INVESTIGATE,
        "get_whois": AuthorityLevel.INVESTIGATE,

        # RESPOND level - recommendations and safe actions
        "recommend_containment": AuthorityLevel.RESPOND,
        "create_ticket": AuthorityLevel.RESPOND,
        "notify_stakeholder": AuthorityLevel.RESPOND,
        "request_approval": AuthorityLevel.RESPOND,
        "add_to_watchlist": AuthorityLevel.RESPOND,
        "update_case_notes": AuthorityLevel.RESPOND,

        # PRE_APPROVED level - actual containment
        "isolate_endpoint": AuthorityLevel.PRE_APPROVED,
        "disable_user": AuthorityLevel.PRE_APPROVED,
        "block_ip": AuthorityLevel.PRE_APPROVED,
        "quarantine_file": AuthorityLevel.PRE_APPROVED,
        "revoke_session": AuthorityLevel.PRE_APPROVED,
        "reset_password": AuthorityLevel.PRE_APPROVED,
    }

    # Minimum confidence for high-impact tools
    TOOL_CONFIDENCE_REQUIREMENTS = {
        "recommend_containment": 70,
        "isolate_endpoint": 90,
        "disable_user": 90,
        "block_ip": 85,
        "quarantine_file": 85,
        "revoke_session": 80,
        "reset_password": 85,
    }

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._execution_log: List[Dict[str, Any]] = []

    def register_tool(self, tool: ToolDefinition) -> None:
        """Register a tool with the broker."""
        self._tools[tool.id] = tool
        logger.info(f"[TOOL_BROKER] Registered tool: {tool.id} (authority: {tool.required_authority})")

    def register_default_tools(self) -> None:
        """Register default tool definitions."""
        for tool_id, authority in self.DEFAULT_TOOL_AUTHORITY.items():
            min_conf = self.TOOL_CONFIDENCE_REQUIREMENTS.get(tool_id, 0)
            self.register_tool(ToolDefinition(
                id=tool_id,
                name=tool_id.replace("_", " ").title(),
                description=f"Default tool: {tool_id}",
                required_authority=authority,
                min_confidence=min_conf
            ))

    def can_execute(
        self,
        tool_id: str,
        current_authority: AuthorityLevel,
        current_confidence: int
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a tool can be executed.

        Args:
            tool_id: Tool to check
            current_authority: Current authority level
            current_confidence: Current confidence percentage

        Returns:
            (allowed, reason) - True if allowed, else False with reason
        """
        # Get tool definition
        tool = self._tools.get(tool_id)
        if not tool:
            # Check default mappings
            default_authority = self.DEFAULT_TOOL_AUTHORITY.get(tool_id)
            if default_authority:
                tool = ToolDefinition(
                    id=tool_id,
                    name=tool_id,
                    description="Default tool",
                    required_authority=default_authority,
                    min_confidence=self.TOOL_CONFIDENCE_REQUIREMENTS.get(tool_id, 0)
                )
            else:
                return False, f"Unknown tool: {tool_id}"

        # Check authority level
        if not self._has_authority(current_authority, tool.required_authority):
            return False, f"Insufficient authority. Required: {tool.required_authority}, Current: {current_authority}"

        # Check confidence for high-impact tools
        if tool.min_confidence > 0 and current_confidence < tool.min_confidence:
            return False, f"Confidence too low. Required: {tool.min_confidence}%, Current: {current_confidence}%"

        return True, None

    def _has_authority(
        self,
        current: AuthorityLevel,
        required: AuthorityLevel
    ) -> bool:
        """Check if current authority is sufficient."""
        try:
            current_idx = AUTHORITY_HIERARCHY.index(current)
            required_idx = AUTHORITY_HIERARCHY.index(required)
            return current_idx >= required_idx
        except ValueError:
            return False

    async def execute_tool(
        self,
        tool_id: str,
        parameters: Dict[str, Any],
        investigation_context: Dict[str, Any]
    ) -> ToolExecutionResult:
        """
        Execute a tool if authority permits.

        Args:
            tool_id: Tool to execute
            parameters: Tool parameters
            investigation_context: Context including authority_level and confidence

        Returns:
            ToolExecutionResult
        """
        current_authority = AuthorityLevel(investigation_context.get("authority_level", "OBSERVE"))
        current_confidence = investigation_context.get("confidence", 0)
        investigation_id = investigation_context.get("investigation_id", "unknown")

        # Check if allowed
        allowed, reason = self.can_execute(tool_id, current_authority, current_confidence)

        if not allowed:
            logger.warning(f"[TOOL_BROKER] Blocked {tool_id}: {reason}")
            self._log_execution(
                tool_id=tool_id,
                investigation_id=investigation_id,
                success=False,
                blocked_reason=reason
            )
            return ToolExecutionResult(
                success=False,
                tool_id=tool_id,
                blocked_reason=reason,
                authority_required=str(self._tools.get(tool_id, ToolDefinition(
                    id=tool_id, name=tool_id, description="",
                    required_authority=self.DEFAULT_TOOL_AUTHORITY.get(tool_id, AuthorityLevel.OBSERVE)
                )).required_authority),
                confidence_required=self.TOOL_CONFIDENCE_REQUIREMENTS.get(tool_id, 0)
            )

        # Get tool definition
        tool = self._tools.get(tool_id)
        if not tool or not tool.handler:
            logger.warning(f"[TOOL_BROKER] No handler for tool: {tool_id}")
            return ToolExecutionResult(
                success=False,
                tool_id=tool_id,
                error=f"No handler registered for tool: {tool_id}"
            )

        # Execute the tool
        try:
            logger.info(f"[TOOL_BROKER] Executing {tool_id} (authority: {current_authority}, confidence: {current_confidence}%)")
            result = await tool.handler(parameters, investigation_context)

            self._log_execution(
                tool_id=tool_id,
                investigation_id=investigation_id,
                success=True
            )

            return ToolExecutionResult(
                success=True,
                tool_id=tool_id,
                data=result
            )

        except Exception as e:
            logger.error(f"[TOOL_BROKER] Tool {tool_id} failed: {e}")
            self._log_execution(
                tool_id=tool_id,
                investigation_id=investigation_id,
                success=False,
                error=str(e)
            )
            return ToolExecutionResult(
                success=False,
                tool_id=tool_id,
                error=str(e)
            )

    def _log_execution(
        self,
        tool_id: str,
        investigation_id: str,
        success: bool,
        blocked_reason: Optional[str] = None,
        error: Optional[str] = None
    ) -> None:
        """Log tool execution for audit trail."""
        self._execution_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_id": tool_id,
            "investigation_id": investigation_id,
            "success": success,
            "blocked_reason": blocked_reason,
            "error": error
        })

        # Keep only last 1000 entries
        if len(self._execution_log) > 1000:
            self._execution_log = self._execution_log[-1000:]

    def get_available_tools(self, authority_level: AuthorityLevel) -> List[str]:
        """Get list of tools available at a given authority level."""
        available = []
        for tool_id in self.DEFAULT_TOOL_AUTHORITY:
            if self._has_authority(authority_level, self.DEFAULT_TOOL_AUTHORITY[tool_id]):
                available.append(tool_id)
        return available

    def get_execution_log(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get execution log, optionally filtered by investigation."""
        if investigation_id:
            return [e for e in self._execution_log if e["investigation_id"] == investigation_id]
        return self._execution_log


# =============================================================================
# SINGLETON
# =============================================================================

_tool_broker: Optional[ToolBroker] = None


def get_tool_broker() -> ToolBroker:
    """Get the global tool broker instance."""
    global _tool_broker
    if _tool_broker is None:
        _tool_broker = ToolBroker()
        _tool_broker.register_default_tools()
    return _tool_broker
