# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent Capability Service (Phase 11)
====================================

Bridges AI agents with the integration store to enable tool use.

This service:
1. Provides a unified interface for agents to discover and use tools
2. Handles capability execution with approval checks
3. Tracks tool usage per agent/investigation
4. Enforces rate limits and permissions
5. Generates tool documentation for AI context
6. Persists approval requests to database via action_approval_service
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

from services.integration_store import (
    get_integration_store,
    IntegrationType,
    CapabilityCategory
)

# Try to import action approval service for persistence
try:
    from services.action_approval_service import get_action_approval_service
    HAS_ACTION_APPROVAL_SERVICE = True
except ImportError:
    HAS_ACTION_APPROVAL_SERVICE = False

logger = logging.getLogger(__name__)


class AgentPermissionLevel(str, Enum):
    """Permission levels for agent tool use"""
    OBSERVE = "observe"          # Can only query/read
    INVESTIGATE = "investigate"   # Can query and enrich
    RESPOND = "respond"           # Can take actions
    ADMIN = "admin"               # Full access


class ToolExecutionStatus(str, Enum):
    """Status of a tool execution"""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolExecutionRequest:
    """Request to execute a tool"""
    id: str
    agent_id: str
    investigation_id: Optional[str]
    tool_id: str  # format: integration_id.capability_id
    parameters: Dict[str, Any]
    status: ToolExecutionStatus
    requires_approval: bool
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    db_approval_id: Optional[str] = None  # Link to action_approvals table


@dataclass
class AgentToolContext:
    """Context about an agent's tool usage session"""
    agent_id: str
    permission_level: AgentPermissionLevel
    investigation_id: Optional[str]
    session_start: datetime
    tools_used: List[str] = field(default_factory=list)
    execution_count: int = 0
    error_count: int = 0
    rate_limit_remaining: Dict[str, int] = field(default_factory=dict)


class AgentCapabilityService:
    """
    Service for managing agent tool capabilities.

    Provides:
    - Tool discovery for agents
    - Permission-based tool access
    - Execution with approval workflow
    - Usage tracking and rate limiting
    """

    def __init__(self):
        self._integration_store = get_integration_store()
        self._execution_requests: Dict[str, ToolExecutionRequest] = {}
        self._pending_approvals: List[str] = []  # request_ids
        self._agent_contexts: Dict[str, AgentToolContext] = {}
        self._rate_limits: Dict[str, Dict[str, int]] = {}  # agent_id -> {tool_id -> calls_remaining}

        # Map permission levels to allowed categories
        self._permission_categories = {
            AgentPermissionLevel.OBSERVE: [CapabilityCategory.QUERY],
            AgentPermissionLevel.INVESTIGATE: [CapabilityCategory.QUERY, CapabilityCategory.ENRICH],
            AgentPermissionLevel.RESPOND: [
                CapabilityCategory.QUERY, CapabilityCategory.ENRICH,
                CapabilityCategory.ACTION, CapabilityCategory.NOTIFY, CapabilityCategory.TICKET
            ],
            AgentPermissionLevel.ADMIN: list(CapabilityCategory)
        }

    # =========================================================================
    # TOOL DISCOVERY
    # =========================================================================

    def get_available_tools(
        self,
        permission_level: AgentPermissionLevel,
        investigation_context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all tools available to an agent based on permission level.

        Returns tool definitions formatted for AI consumption.
        """
        allowed_categories = self._permission_categories.get(permission_level, [])

        tools = []
        integrations = self._integration_store.list_integrations(enabled_only=True)

        for integration in integrations:
            full_integration = self._integration_store.get_integration(integration["id"])
            if not full_integration or "capabilities" not in full_integration:
                continue

            for cap in full_integration["capabilities"]:
                # Check if category is allowed
                try:
                    cat = CapabilityCategory(cap["category"])
                    if cat not in allowed_categories:
                        continue
                except ValueError:
                    continue

                tool = {
                    "tool_id": f"{integration['id']}.{cap['id']}",
                    "name": cap["name"],
                    "description": cap["description"],
                    "integration": integration["display_name"],
                    "category": cap["category"],
                    "parameters": cap["parameters"],
                    "requires_approval": cap["requires_approval"],
                    "example": cap.get("example")
                }
                tools.append(tool)

        return tools

    def get_tool_documentation(
        self,
        permission_level: AgentPermissionLevel,
        max_tokens: int = 2000
    ) -> str:
        """
        Generate tool documentation for AI context injection.

        Formats tools as a structured prompt section.
        """
        tools = self.get_available_tools(permission_level)

        doc_lines = [
            "## Available Tools",
            f"Permission level: {permission_level.value}",
            f"Total tools available: {len(tools)}",
            ""
        ]

        # Group by category
        by_category: Dict[str, List[Dict]] = {}
        for tool in tools:
            cat = tool["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tool)

        for category, cat_tools in by_category.items():
            doc_lines.append(f"### {category.upper()} Tools")

            for tool in cat_tools:
                doc_lines.append(f"- **{tool['tool_id']}**: {tool['description']}")
                if tool.get("example"):
                    doc_lines.append(f"  Example: `{tool['example']}`")
                if tool["requires_approval"]:
                    doc_lines.append(f"  *Requires human approval*")

            doc_lines.append("")

        doc = "\n".join(doc_lines)

        # Truncate if too long
        if len(doc) > max_tokens * 4:  # rough char estimate
            doc = doc[:max_tokens * 4] + "\n... (truncated)"

        return doc

    def find_tools_for_task(
        self,
        task_description: str,
        permission_level: AgentPermissionLevel
    ) -> List[Dict[str, Any]]:
        """
        Find tools relevant to a specific task.

        Uses keyword matching to suggest appropriate tools.
        """
        tools = self.get_available_tools(permission_level)

        # Keywords to match
        keywords = task_description.lower().split()

        scored_tools = []
        for tool in tools:
            score = 0
            text = (tool["name"] + " " + tool["description"]).lower()

            for keyword in keywords:
                if keyword in text:
                    score += 1

            if score > 0:
                scored_tools.append((score, tool))

        # Sort by score descending
        scored_tools.sort(key=lambda x: x[0], reverse=True)

        return [tool for _, tool in scored_tools[:10]]

    # =========================================================================
    # TOOL EXECUTION
    # =========================================================================

    async def request_tool_execution(
        self,
        agent_id: str,
        tool_id: str,
        parameters: Dict[str, Any],
        investigation_id: Optional[str] = None,
        permission_level: AgentPermissionLevel = AgentPermissionLevel.INVESTIGATE
    ) -> ToolExecutionRequest:
        """
        Request execution of a tool.

        If the tool requires approval, it will be queued for human review.
        Otherwise, it will be executed immediately.
        """
        # Parse tool_id
        parts = tool_id.split(".", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid tool_id format: {tool_id}")

        integration_id, capability_id = parts

        # Check if tool exists and is accessible
        integration = self._integration_store.get_integration(integration_id)
        if not integration:
            raise ValueError(f"Integration not found: {integration_id}")

        capability = None
        for cap in integration.get("capabilities", []):
            if cap["id"] == capability_id:
                capability = cap
                break

        if not capability:
            raise ValueError(f"Capability not found: {capability_id}")

        # Check permission
        try:
            cat = CapabilityCategory(capability["category"])
            allowed_categories = self._permission_categories.get(permission_level, [])
            if cat not in allowed_categories:
                raise PermissionError(
                    f"Permission level {permission_level.value} cannot use {capability['category']} tools"
                )
        except ValueError:
            pass

        # Check rate limit
        if not self._check_rate_limit(agent_id, tool_id):
            raise Exception(f"Rate limit exceeded for tool: {tool_id}")

        # Create execution request
        request = ToolExecutionRequest(
            id=f"exec-{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            investigation_id=investigation_id,
            tool_id=tool_id,
            parameters=parameters,
            status=ToolExecutionStatus.PENDING_APPROVAL if capability["requires_approval"] else ToolExecutionStatus.APPROVED,
            requires_approval=capability["requires_approval"]
        )

        self._execution_requests[request.id] = request

        if capability["requires_approval"]:
            self._pending_approvals.append(request.id)
            logger.info(f"[AgentCapability] Tool {tool_id} queued for approval: {request.id}")

            # Persist to database via action approval service
            if HAS_ACTION_APPROVAL_SERVICE:
                try:
                    approval_service = get_action_approval_service()
                    db_approval = await approval_service.create_approval_request(
                        action_name=capability_id,
                        integration_name=integration_id,
                        target_type=parameters.get("target_type", "unknown"),
                        target_identifier=str(parameters.get("target", parameters.get("ip", parameters.get("host", "")))),
                        reason=f"Agent {agent_id} requested {capability['name']}",
                        alert_id=parameters.get("alert_id"),
                        investigation_id=investigation_id,
                        riggs_confidence=parameters.get("confidence"),
                        evidence={"parameters": parameters, "tool_id": tool_id},
                        priority="medium" if capability.get("risk_level") != "high" else "high",
                        expires_in_minutes=30
                    )
                    if db_approval and not db_approval.get("error"):
                        request.db_approval_id = db_approval.get("approval_id")
                        logger.info(f"[AgentCapability] Created DB approval: {db_approval.get('approval_id')}")
                except Exception as e:
                    logger.warning(f"[AgentCapability] Failed to persist approval to DB: {e}")

            return request

        # Execute immediately
        return await self._execute_tool(request)

    async def _execute_tool(self, request: ToolExecutionRequest) -> ToolExecutionRequest:
        """Execute an approved tool request"""
        request.status = ToolExecutionStatus.EXECUTING
        request.executed_at = datetime.utcnow()

        parts = request.tool_id.split(".", 1)
        integration_id, capability_id = parts

        try:
            start_time = datetime.utcnow()

            # Execute via integration store
            result = await self._integration_store.execute_capability(
                integration_id=integration_id,
                capability_id=capability_id,
                parameters=request.parameters,
                agent_id=request.agent_id
            )

            request.execution_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            if result.get("success"):
                request.status = ToolExecutionStatus.COMPLETED
                request.result = result
            else:
                request.status = ToolExecutionStatus.FAILED
                request.error = result.get("error", "Unknown error")

        except Exception as e:
            request.status = ToolExecutionStatus.FAILED
            request.error = str(e)
            logger.error(f"[AgentCapability] Tool execution failed: {e}")

        request.completed_at = datetime.utcnow()

        # Update rate limit
        self._decrement_rate_limit(request.agent_id, request.tool_id)

        # Update agent context
        if request.agent_id in self._agent_contexts:
            ctx = self._agent_contexts[request.agent_id]
            ctx.execution_count += 1
            ctx.tools_used.append(request.tool_id)
            if request.status == ToolExecutionStatus.FAILED:
                ctx.error_count += 1

        logger.info(f"[AgentCapability] Tool {request.tool_id} executed: {request.status.value}")
        return request

    def _check_rate_limit(self, agent_id: str, tool_id: str) -> bool:
        """Check if rate limit allows execution"""
        if agent_id not in self._rate_limits:
            self._rate_limits[agent_id] = {}

        if tool_id not in self._rate_limits[agent_id]:
            # Default: 60 calls per minute
            self._rate_limits[agent_id][tool_id] = 60

        return self._rate_limits[agent_id][tool_id] > 0

    def _decrement_rate_limit(self, agent_id: str, tool_id: str):
        """Decrement rate limit counter"""
        if agent_id in self._rate_limits and tool_id in self._rate_limits[agent_id]:
            self._rate_limits[agent_id][tool_id] -= 1

    # =========================================================================
    # APPROVAL WORKFLOW
    # =========================================================================

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests"""
        pending = []
        for request_id in self._pending_approvals:
            request = self._execution_requests.get(request_id)
            if request and request.status == ToolExecutionStatus.PENDING_APPROVAL:
                pending.append({
                    "id": request.id,
                    "agent_id": request.agent_id,
                    "investigation_id": request.investigation_id,
                    "tool_id": request.tool_id,
                    "parameters": request.parameters,
                    "created_at": request.created_at.isoformat(),
                    "status": request.status.value
                })
        return pending

    async def approve_execution(
        self,
        request_id: str,
        approved_by: str
    ) -> ToolExecutionRequest:
        """Approve a pending tool execution"""
        request = self._execution_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ToolExecutionStatus.PENDING_APPROVAL:
            raise ValueError(f"Request not pending approval: {request.status.value}")

        request.status = ToolExecutionStatus.APPROVED
        request.approved_by = approved_by
        request.approval_timestamp = datetime.utcnow()

        if request_id in self._pending_approvals:
            self._pending_approvals.remove(request_id)

        # Update database approval if exists
        if HAS_ACTION_APPROVAL_SERVICE and request.db_approval_id:
            try:
                approval_service = get_action_approval_service()
                await approval_service.approve_action(
                    approval_id=request.db_approval_id,
                    approved_by=approved_by,
                    notes=f"Approved via agent capability service",
                    execute_immediately=False  # We'll execute ourselves
                )
            except Exception as e:
                logger.warning(f"[AgentCapability] Failed to update DB approval: {e}")

        logger.info(f"[AgentCapability] Request {request_id} approved by {approved_by}")

        # Execute the tool
        return await self._execute_tool(request)

    async def reject_execution(
        self,
        request_id: str,
        rejected_by: str,
        reason: Optional[str] = None
    ) -> ToolExecutionRequest:
        """Reject a pending tool execution"""
        request = self._execution_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ToolExecutionStatus.PENDING_APPROVAL:
            raise ValueError(f"Request not pending approval: {request.status.value}")

        request.status = ToolExecutionStatus.REJECTED
        request.approved_by = rejected_by
        request.approval_timestamp = datetime.utcnow()
        request.error = reason or "Rejected by user"
        request.completed_at = datetime.utcnow()

        if request_id in self._pending_approvals:
            self._pending_approvals.remove(request_id)

        # Update database approval if exists
        if HAS_ACTION_APPROVAL_SERVICE and request.db_approval_id:
            try:
                approval_service = get_action_approval_service()
                await approval_service.reject_action(
                    approval_id=request.db_approval_id,
                    rejected_by=rejected_by,
                    reason=reason
                )
            except Exception as e:
                logger.warning(f"[AgentCapability] Failed to update DB rejection: {e}")

        logger.info(f"[AgentCapability] Request {request_id} rejected by {rejected_by}")
        return request

    # =========================================================================
    # AGENT CONTEXT MANAGEMENT
    # =========================================================================

    def create_agent_context(
        self,
        agent_id: str,
        permission_level: AgentPermissionLevel,
        investigation_id: Optional[str] = None
    ) -> AgentToolContext:
        """Create a new tool context for an agent"""
        context = AgentToolContext(
            agent_id=agent_id,
            permission_level=permission_level,
            investigation_id=investigation_id,
            session_start=datetime.utcnow()
        )
        self._agent_contexts[agent_id] = context

        # Initialize rate limits
        if agent_id not in self._rate_limits:
            self._rate_limits[agent_id] = {}

        return context

    def get_agent_context(self, agent_id: str) -> Optional[AgentToolContext]:
        """Get an agent's current context"""
        return self._agent_contexts.get(agent_id)

    def end_agent_context(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """End an agent's context and return summary"""
        context = self._agent_contexts.pop(agent_id, None)
        if not context:
            return None

        duration = (datetime.utcnow() - context.session_start).total_seconds()

        return {
            "agent_id": agent_id,
            "permission_level": context.permission_level.value,
            "investigation_id": context.investigation_id,
            "duration_seconds": duration,
            "tools_used": context.tools_used,
            "execution_count": context.execution_count,
            "error_count": context.error_count
        }

    # =========================================================================
    # EXECUTION HISTORY
    # =========================================================================

    def get_execution_history(
        self,
        agent_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        status: Optional[ToolExecutionStatus] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get tool execution history"""
        results = []

        for request in self._execution_requests.values():
            if agent_id and request.agent_id != agent_id:
                continue
            if investigation_id and request.investigation_id != investigation_id:
                continue
            if status and request.status != status:
                continue

            results.append({
                "id": request.id,
                "agent_id": request.agent_id,
                "investigation_id": request.investigation_id,
                "tool_id": request.tool_id,
                "parameters": request.parameters,
                "status": request.status.value,
                "requires_approval": request.requires_approval,
                "approved_by": request.approved_by,
                "created_at": request.created_at.isoformat(),
                "executed_at": request.executed_at.isoformat() if request.executed_at else None,
                "completed_at": request.completed_at.isoformat() if request.completed_at else None,
                "execution_time_ms": request.execution_time_ms,
                "error": request.error
            })

        # Sort by created_at descending
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results[:limit]

    def get_execution_stats(
        self,
        agent_id: Optional[str] = None,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get execution statistics"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        total = 0
        completed = 0
        failed = 0
        pending = 0
        by_tool: Dict[str, int] = {}
        total_time_ms = 0

        for request in self._execution_requests.values():
            if request.created_at < cutoff:
                continue
            if agent_id and request.agent_id != agent_id:
                continue

            total += 1

            if request.status == ToolExecutionStatus.COMPLETED:
                completed += 1
                total_time_ms += request.execution_time_ms
            elif request.status == ToolExecutionStatus.FAILED:
                failed += 1
            elif request.status == ToolExecutionStatus.PENDING_APPROVAL:
                pending += 1

            if request.tool_id not in by_tool:
                by_tool[request.tool_id] = 0
            by_tool[request.tool_id] += 1

        return {
            "total_executions": total,
            "completed": completed,
            "failed": failed,
            "pending_approval": pending,
            "success_rate": round(completed / total * 100, 1) if total > 0 else 0,
            "avg_execution_time_ms": round(total_time_ms / completed) if completed > 0 else 0,
            "by_tool": by_tool,
            "time_period_hours": hours
        }


# Singleton instance
_capability_service: Optional[AgentCapabilityService] = None


def get_agent_capability_service() -> AgentCapabilityService:
    """Get the agent capability service singleton"""
    global _capability_service
    if _capability_service is None:
        _capability_service = AgentCapabilityService()
    return _capability_service
