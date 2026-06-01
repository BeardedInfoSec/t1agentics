# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation Audit Service

Provides immutable audit logging for all investigation actions.
This creates an activity trail that cannot be modified or deleted.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


class AuditAction(str, Enum):
    """Standard audit action types."""
    # Status changes
    CREATED = "created"
    CLOSED = "closed"
    REOPENED = "reopened"
    STATE_CHANGED = "state_changed"

    # Field changes
    DISPOSITION_CHANGED = "disposition_changed"
    PRIORITY_CHANGED = "priority_changed"
    OWNER_CHANGED = "owner_changed"

    # Notes and findings
    NOTE_ADDED = "note_added"
    FINDING_ADDED = "finding_added"

    # AI actions
    AI_ANALYSIS = "ai_analysis"
    AI_RECOMMENDATION = "ai_recommendation"
    AI_TOOL_EXECUTED = "ai_tool_executed"

    # System actions
    AUTO_ENRICHMENT = "auto_enrichment"
    AUTO_ESCALATION = "auto_escalation"
    ALERT_LINKED = "alert_linked"


class AuditCategory(str, Enum):
    """Categories for grouping audit events."""
    STATUS = "status"
    DISPOSITION = "disposition"
    PRIORITY = "priority"
    ASSIGNMENT = "assignment"
    NOTE = "note"
    AI = "ai"
    SYSTEM = "system"
    GENERAL = "general"


class ActorType(str, Enum):
    """Who performed the action."""
    HUMAN = "human"
    AI_AGENT = "ai_agent"
    SYSTEM = "system"


class InvestigationAuditService:
    """
    Service for logging immutable audit entries for investigations.

    All entries are append-only - the database enforces this with rules
    that prevent UPDATE and DELETE operations.
    """

    def __init__(self):
        self._initialized = False

    async def log_action(
        self,
        investigation_id: str,
        action: str,
        actor_type: str,
        actor_name: str,
        summary: str,
        actor_id: Optional[str] = None,
        action_category: str = "general",
        field_changed: Optional[str] = None,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Log an action to the investigation audit trail.

        Args:
            investigation_id: The investigation this action relates to
            action: The action type (e.g., 'disposition_changed', 'closed')
            actor_type: Who did it ('human', 'ai_agent', 'system')
            actor_name: Display name (username or "Riggs")
            summary: Human-readable summary of what happened
            actor_id: Optional ID (user_id or agent name)
            action_category: Category for filtering ('status', 'disposition', etc.)
            field_changed: Which field changed (if applicable)
            old_value: Previous value
            new_value: New value
            reason: Why the change was made
            metadata: Additional context as JSON

        Returns:
            The audit log entry ID, or None on failure
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            logger.warning("[AUDIT] Database not connected, cannot log audit entry")
            return None

        try:
            async with postgres_db.tenant_acquire() as conn:
                result = await conn.fetchval("""
                    INSERT INTO investigation_audit_log (
                        investigation_id, action, action_category,
                        actor_type, actor_id, actor_name,
                        field_changed, old_value, new_value,
                        reason, summary, metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    RETURNING id::text
                """,
                    investigation_id,
                    action,
                    action_category,
                    actor_type,
                    actor_id,
                    actor_name,
                    field_changed,
                    old_value,
                    new_value,
                    reason,
                    summary,
                    metadata or {}
                )

                logger.info(f"[AUDIT] Logged: {action} on {investigation_id} by {actor_name}")
                return result

        except Exception as e:
            logger.error(f"[AUDIT] Failed to log audit entry: {e}")
            return None

    async def log_disposition_change(
        self,
        investigation_id: str,
        old_disposition: Optional[str],
        new_disposition: str,
        actor_type: str,
        actor_name: str,
        actor_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Optional[str]:
        """Log a disposition change."""
        summary = f"Changed disposition from **{old_disposition or 'none'}** to **{new_disposition}**"
        if reason:
            summary += f" - {reason}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.DISPOSITION_CHANGED,
            action_category=AuditCategory.DISPOSITION,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            field_changed="disposition",
            old_value=old_disposition,
            new_value=new_disposition,
            reason=reason,
            summary=summary
        )

    async def log_priority_change(
        self,
        investigation_id: str,
        old_priority: Optional[str],
        new_priority: str,
        actor_type: str,
        actor_name: str,
        actor_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Optional[str]:
        """Log a priority change."""
        summary = f"Changed priority from **{old_priority or 'none'}** to **{new_priority}**"
        if reason:
            summary += f" - {reason}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.PRIORITY_CHANGED,
            action_category=AuditCategory.PRIORITY,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            field_changed="priority",
            old_value=old_priority,
            new_value=new_priority,
            reason=reason,
            summary=summary
        )

    async def log_close(
        self,
        investigation_id: str,
        disposition: str,
        actor_type: str,
        actor_name: str,
        actor_id: Optional[str] = None,
        resolution_notes: Optional[str] = None
    ) -> Optional[str]:
        """Log investigation closure."""
        summary = f"Closed investigation as **{disposition}**"
        if resolution_notes:
            summary += f" - {resolution_notes[:100]}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.CLOSED,
            action_category=AuditCategory.STATUS,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            field_changed="state",
            old_value="in_progress",
            new_value="closed",
            reason=resolution_notes,
            summary=summary,
            metadata={"disposition": disposition}
        )

    async def log_reopen(
        self,
        investigation_id: str,
        previous_state: str,
        actor_type: str,
        actor_name: str,
        actor_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Optional[str]:
        """Log investigation reopening."""
        summary = f"Reopened investigation (was: {previous_state})"
        if reason:
            summary += f" - {reason}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.REOPENED,
            action_category=AuditCategory.STATUS,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            field_changed="state",
            old_value=previous_state,
            new_value="in_progress",
            reason=reason,
            summary=summary
        )

    async def log_note_added(
        self,
        investigation_id: str,
        note_type: str,
        note_preview: str,
        actor_type: str,
        actor_name: str,
        actor_id: Optional[str] = None
    ) -> Optional[str]:
        """Log a note being added."""
        summary = f"Added {note_type}: {note_preview[:80]}{'...' if len(note_preview) > 80 else ''}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.NOTE_ADDED,
            action_category=AuditCategory.NOTE,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            summary=summary,
            metadata={"note_type": note_type}
        )

    async def log_ai_tool_use(
        self,
        investigation_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        result_summary: str,
        agent_name: str = "Riggs"
    ) -> Optional[str]:
        """Log AI agent tool execution."""
        summary = f"AI executed **{tool_name}**: {result_summary}"

        return await self.log_action(
            investigation_id=investigation_id,
            action=AuditAction.AI_TOOL_EXECUTED,
            action_category=AuditCategory.AI,
            actor_type=ActorType.AI_AGENT,
            actor_id=agent_name,
            actor_name=agent_name,
            summary=summary,
            metadata={"tool": tool_name, "args": tool_args}
        )

    async def get_audit_trail(
        self,
        investigation_id: str,
        limit: int = 100,
        offset: int = 0,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get the audit trail for an investigation.

        Returns entries in reverse chronological order (newest first).
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return []

        try:
            async with postgres_db.tenant_acquire() as conn:
                if category:
                    rows = await conn.fetch("""
                        SELECT
                            id::text, investigation_id, action, action_category,
                            actor_type, actor_id, actor_name,
                            field_changed, old_value, new_value,
                            reason, summary, metadata, created_at
                        FROM investigation_audit_log
                        WHERE investigation_id = $1 AND action_category = $2
                        ORDER BY created_at DESC
                        LIMIT $3 OFFSET $4
                    """, investigation_id, category, limit, offset)
                else:
                    rows = await conn.fetch("""
                        SELECT
                            id::text, investigation_id, action, action_category,
                            actor_type, actor_id, actor_name,
                            field_changed, old_value, new_value,
                            reason, summary, metadata, created_at
                        FROM investigation_audit_log
                        WHERE investigation_id = $1
                        ORDER BY created_at DESC
                        LIMIT $2 OFFSET $3
                    """, investigation_id, limit, offset)

                return [
                    {
                        "id": r["id"],
                        "investigation_id": r["investigation_id"],
                        "action": r["action"],
                        "category": r["action_category"],
                        "actor_type": r["actor_type"],
                        "actor_id": r["actor_id"],
                        "actor_name": r["actor_name"],
                        "field_changed": r["field_changed"],
                        "old_value": r["old_value"],
                        "new_value": r["new_value"],
                        "reason": r["reason"],
                        "summary": r["summary"],
                        "metadata": r["metadata"],
                        "created_at": r["created_at"].isoformat() if r["created_at"] else None
                    }
                    for r in rows
                ]

        except Exception as e:
            logger.error(f"[AUDIT] Failed to get audit trail: {e}")
            return []


# Singleton instance
_audit_service: Optional[InvestigationAuditService] = None


def get_audit_service() -> InvestigationAuditService:
    """Get or create the audit service singleton."""
    global _audit_service
    if _audit_service is None:
        _audit_service = InvestigationAuditService()
    return _audit_service
