# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation Assignment Service

Phase 3.4 compliant:
- Auto-assignment based on rules (severity, category, source)
- Round-robin assignment within teams
- Claim/release/reassign operations
- Ownership change logging
- SLA tracking
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class OwnerType(str, Enum):
    """Investigation owner types"""
    UNASSIGNED = "unassigned"
    HUMAN = "human"
    AGENT = "agent"
    TEAM = "team"


class ChangeType(str, Enum):
    """Types of ownership changes"""
    ASSIGNED = "assigned"
    REASSIGNED = "reassigned"
    CLAIMED = "claimed"
    RELEASED = "released"
    ESCALATED = "escalated"
    AUTO_ASSIGNED = "auto_assigned"
    SYSTEM = "system"


@dataclass
class AssignmentResult:
    """Result of an assignment operation"""
    success: bool
    investigation_id: str
    owner: Optional[str] = None
    owner_type: Optional[str] = None
    message: str = ""
    rule_name: Optional[str] = None


class AssignmentService:
    """
    Manages investigation assignments, claims, and ownership tracking.

    Features:
    - Rule-based auto-assignment
    - Round-robin within teams
    - Ownership history logging
    - SLA tracking
    """

    def __init__(self):
        self._rules_cache: List[Dict] = []
        self._rules_cache_time: Optional[datetime] = None
        self._teams_cache: Dict[str, Dict] = {}
        self._teams_cache_time: Optional[datetime] = None

    def _get_db(self):
        """Get database connection"""
        try:
            from services.postgres_db import postgres_db
            return postgres_db
        except Exception:
            return None

    # ========================================================================
    # AUTO-ASSIGNMENT
    # ========================================================================

    async def auto_assign_investigation(
        self,
        investigation_id: str,
        investigation_data: Dict
    ) -> AssignmentResult:
        """
        Automatically assign investigation based on rules.

        Args:
            investigation_id: Investigation ID
            investigation_data: Investigation details (severity, category, source, etc.)

        Returns:
            AssignmentResult with assignment details
        """
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            # Get matching rules (sorted by priority)
            rules = await self._get_active_rules()

            for rule in rules:
                if self._rule_matches(rule, investigation_data):
                    # Found matching rule - process assignment
                    result = await self._process_rule_assignment(
                        investigation_id,
                        rule,
                        investigation_data
                    )

                    if result.success:
                        # Update rule stats
                        await self._update_rule_stats(rule['id'])
                        return result

            # No rules matched - leave unassigned
            return AssignmentResult(
                success=True,
                investigation_id=investigation_id,
                owner=None,
                owner_type=OwnerType.UNASSIGNED.value,
                message="No matching assignment rules"
            )

        except Exception as e:
            logger.error(f"Auto-assignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    def _rule_matches(self, rule: Dict, investigation: Dict) -> bool:
        """Check if investigation matches rule conditions"""
        conditions = rule.get('conditions', {})

        if not conditions:
            # Empty conditions = catch-all rule (used for default round-robin)
            return True

        for field, expected_value in conditions.items():
            actual_value = investigation.get(field)

            # Handle list conditions (any match)
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            else:
                # Handle case-insensitive string comparison
                if isinstance(actual_value, str) and isinstance(expected_value, str):
                    if actual_value.lower() != expected_value.lower():
                        return False
                elif actual_value != expected_value:
                    return False

        return True

    async def _process_rule_assignment(
        self,
        investigation_id: str,
        rule: Dict,
        investigation_data: Dict
    ) -> AssignmentResult:
        """Process assignment based on rule type"""
        assign_to_type = rule.get('assign_to_type')
        assign_to = rule.get('assign_to')

        if assign_to_type == 'user':
            # Direct user assignment
            return await self._assign_to_user(
                investigation_id,
                assign_to,
                ChangeType.AUTO_ASSIGNED,
                f"Auto-assigned by rule: {rule.get('name')}"
            )

        elif assign_to_type == 'team':
            # Assign to team (first available member)
            return await self._assign_to_team(
                investigation_id,
                assign_to,
                rule.get('name')
            )

        elif assign_to_type == 'round_robin':
            # Round-robin assignment within team
            return await self._assign_round_robin(
                investigation_id,
                assign_to,
                rule
            )

        elif assign_to_type == 'agent':
            # Assign to AI agent
            return await self._assign_to_agent(
                investigation_id,
                assign_to,
                rule.get('name')
            )

        return AssignmentResult(
            success=False,
            investigation_id=investigation_id,
            message=f"Unknown assignment type: {assign_to_type}"
        )

    async def _assign_to_user(
        self,
        investigation_id: str,
        user_id: str,
        change_type: ChangeType,
        reason: str
    ) -> AssignmentResult:
        """Assign investigation to a specific user"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get current owner for logging
                current = await conn.fetchrow(
                    "SELECT owner, owner_type FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="Investigation not found"
                    )

                # Update investigation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET owner = $1,
                        owner_type = $2,
                        assigned_at = NOW(),
                        last_activity_at = NOW(),
                        state = CASE
                            WHEN state = 'NEW' THEN 'IN_PROGRESS'
                            ELSE state
                        END,
                        updated_at = NOW()
                    WHERE investigation_id = $3
                    """,
                    user_id,
                    OwnerType.HUMAN.value,
                    investigation_id
                )

                # Log ownership change
                await self._log_ownership_change(
                    conn,
                    investigation_id,
                    current['owner'],
                    user_id,
                    current['owner_type'],
                    OwnerType.HUMAN.value,
                    change_type,
                    reason
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    owner=user_id,
                    owner_type=OwnerType.HUMAN.value,
                    message=f"Assigned to {user_id}"
                )

        except Exception as e:
            logger.error(f"User assignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def _assign_to_team(
        self,
        investigation_id: str,
        team_id: str,
        rule_name: str
    ) -> AssignmentResult:
        """Assign to first available team member"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get team members
                team = await conn.fetchrow(
                    "SELECT * FROM teams WHERE team_id = $1 AND enabled = true",
                    team_id
                )

                if not team:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message=f"Team not found: {team_id}"
                    )

                members = team['members'] or []

                if not members:
                    # No members - assign to team as a whole
                    return await self._assign_to_user(
                        investigation_id,
                        f"team:{team_id}",
                        ChangeType.AUTO_ASSIGNED,
                        f"Auto-assigned to team by rule: {rule_name}"
                    )

                # Find member with lowest load
                member_loads = {}
                for member in members:
                    count = await conn.fetchval(
                        """
                        SELECT COUNT(*) FROM investigations
                        WHERE owner = $1
                          AND state NOT IN ('RESOLVED', 'CLOSED')
                        """,
                        member
                    )
                    member_loads[member] = count or 0

                # Get member with lowest load
                best_member = min(member_loads, key=member_loads.get)

                return await self._assign_to_user(
                    investigation_id,
                    best_member,
                    ChangeType.AUTO_ASSIGNED,
                    f"Auto-assigned from team {team_id} by rule: {rule_name}"
                )

        except Exception as e:
            logger.error(f"Team assignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def _assign_round_robin(
        self,
        investigation_id: str,
        team_id: str,
        rule: Dict
    ) -> AssignmentResult:
        """Round-robin assignment within team"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get team members
                team = await conn.fetchrow(
                    "SELECT * FROM teams WHERE team_id = $1 AND enabled = true",
                    team_id
                )

                if not team:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message=f"Team not found: {team_id}"
                    )

                members = team['members'] or []

                if not members:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message=f"Team {team_id} has no members"
                    )

                # Get round-robin state from rule
                rr_state = rule.get('round_robin_state', {})
                last_index = rr_state.get('last_assigned_index', -1)

                # Get next member
                next_index = (last_index + 1) % len(members)
                next_member = members[next_index]

                # Update round-robin state
                rr_state['last_assigned_index'] = next_index
                await conn.execute(
                    "UPDATE assignment_rules SET round_robin_state = $1 WHERE id = $2",
                    json.dumps(rr_state),
                    rule['id']
                )

                return await self._assign_to_user(
                    investigation_id,
                    next_member,
                    ChangeType.AUTO_ASSIGNED,
                    f"Round-robin assigned from team {team_id}"
                )

        except Exception as e:
            logger.error(f"Round-robin assignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def _assign_to_agent(
        self,
        investigation_id: str,
        agent_id: str,
        rule_name: str
    ) -> AssignmentResult:
        """Assign to AI agent"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get current owner
                current = await conn.fetchrow(
                    "SELECT owner, owner_type FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="Investigation not found"
                    )

                # Update investigation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET owner = $1,
                        owner_type = $2,
                        assigned_at = NOW(),
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $3
                    """,
                    f"agent:{agent_id}",
                    OwnerType.AGENT.value,
                    investigation_id
                )

                # Log ownership change
                await self._log_ownership_change(
                    conn,
                    investigation_id,
                    current['owner'],
                    f"agent:{agent_id}",
                    current['owner_type'],
                    OwnerType.AGENT.value,
                    ChangeType.AUTO_ASSIGNED,
                    f"Auto-assigned to agent by rule: {rule_name}"
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    owner=f"agent:{agent_id}",
                    owner_type=OwnerType.AGENT.value,
                    message=f"Assigned to agent {agent_id}",
                    rule_name=rule_name
                )

        except Exception as e:
            logger.error(f"Agent assignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    # ========================================================================
    # MANUAL OPERATIONS (Claim/Release/Reassign)
    # ========================================================================

    async def claim_investigation(
        self,
        investigation_id: str,
        user_id: str
    ) -> AssignmentResult:
        """User claims an investigation for themselves"""
        return await self._assign_to_user(
            investigation_id,
            user_id,
            ChangeType.CLAIMED,
            f"Claimed by {user_id}"
        )

    async def release_investigation(
        self,
        investigation_id: str,
        user_id: str,
        reason: Optional[str] = None
    ) -> AssignmentResult:
        """User releases ownership of an investigation"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Verify user is current owner
                current = await conn.fetchrow(
                    "SELECT owner, owner_type FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="Investigation not found"
                    )

                if current['owner'] != user_id:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="You are not the current owner"
                    )

                # Release ownership
                await conn.execute(
                    """
                    UPDATE investigations
                    SET owner = NULL,
                        owner_type = $1,
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $2
                    """,
                    OwnerType.UNASSIGNED.value,
                    investigation_id
                )

                # Log ownership change
                await self._log_ownership_change(
                    conn,
                    investigation_id,
                    user_id,
                    None,
                    current['owner_type'],
                    OwnerType.UNASSIGNED.value,
                    ChangeType.RELEASED,
                    reason or f"Released by {user_id}"
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    owner=None,
                    owner_type=OwnerType.UNASSIGNED.value,
                    message="Investigation released"
                )

        except Exception as e:
            logger.error(f"Release failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def reassign_investigation(
        self,
        investigation_id: str,
        new_owner: str,
        reassigned_by: str,
        reason: Optional[str] = None
    ) -> AssignmentResult:
        """Reassign investigation to another user"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get current owner
                current = await conn.fetchrow(
                    "SELECT owner, owner_type FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="Investigation not found"
                    )

                # Update investigation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET owner = $1,
                        owner_type = $2,
                        assigned_at = NOW(),
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $3
                    """,
                    new_owner,
                    OwnerType.HUMAN.value,
                    investigation_id
                )

                # Log ownership change
                await self._log_ownership_change(
                    conn,
                    investigation_id,
                    current['owner'],
                    new_owner,
                    current['owner_type'],
                    OwnerType.HUMAN.value,
                    ChangeType.REASSIGNED,
                    reason or f"Reassigned by {reassigned_by}",
                    changed_by=reassigned_by
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    owner=new_owner,
                    owner_type=OwnerType.HUMAN.value,
                    message=f"Reassigned to {new_owner}"
                )

        except Exception as e:
            logger.error(f"Reassignment failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def escalate_investigation(
        self,
        investigation_id: str,
        escalated_by: str,
        escalation_level: int,
        reason: str
    ) -> AssignmentResult:
        """Escalate investigation to higher tier"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # Get current state
                current = await conn.fetchrow(
                    "SELECT owner, owner_type, escalated_to_tier FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return AssignmentResult(
                        success=False,
                        investigation_id=investigation_id,
                        message="Investigation not found"
                    )

                # Update escalation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET escalated_to_tier = $1,
                        escalated_at = NOW(),
                        escalated_by = $2,
                        escalation_reason = $3,
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $4
                    """,
                    escalation_level,
                    escalated_by,
                    reason,
                    investigation_id
                )

                # Log escalation
                await self._log_ownership_change(
                    conn,
                    investigation_id,
                    current['owner'],
                    current['owner'],  # Owner may not change
                    current['owner_type'],
                    current['owner_type'],
                    ChangeType.ESCALATED,
                    reason,
                    changed_by=escalated_by,
                    metadata={'escalation_level': escalation_level}
                )

                # Record in escalation_history
                from middleware.tenant_middleware import get_optional_tenant_id
                await conn.execute(
                    """
                    INSERT INTO escalation_history (investigation_id, escalation_level, reason, escalated_by, tenant_id)
                    SELECT id, $1, $2, $3, $4 FROM investigations WHERE investigation_id = $5
                    """,
                    escalation_level,
                    reason,
                    escalated_by,
                    get_optional_tenant_id(),
                    investigation_id
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    owner=current['owner'],
                    owner_type=current['owner_type'],
                    message=f"Escalated to level {escalation_level}"
                )

        except Exception as e:
            logger.error(f"Escalation failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    # ========================================================================
    # WORKFLOW STATE CHANGES
    # ========================================================================

    async def block_investigation(
        self,
        investigation_id: str,
        blocked_by: str,
        reason: str
    ) -> AssignmentResult:
        """Mark investigation as blocked"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE investigations
                    SET blocked_reason = $1,
                        blocked_at = NOW(),
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $2
                    """,
                    reason,
                    investigation_id
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    message=f"Investigation blocked: {reason}"
                )

        except Exception as e:
            logger.error(f"Block failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def unblock_investigation(
        self,
        investigation_id: str,
        unblocked_by: str
    ) -> AssignmentResult:
        """Remove block from investigation"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE investigations
                    SET blocked_reason = NULL,
                        blocked_at = NULL,
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $1
                    """,
                    investigation_id
                )

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    message="Investigation unblocked"
                )

        except Exception as e:
            logger.error(f"Unblock failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def resolve_investigation(
        self,
        investigation_id: str,
        resolved_by: str,
        resolution_type: str,
        resolution_notes: Optional[str] = None
    ) -> AssignmentResult:
        """Mark investigation as resolved and update linked alerts"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # First get the investigation to find linked alert_id and UUID
                inv_row = await conn.fetchrow(
                    "SELECT id, alert_id, owner_type FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                # Update the investigation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET state = 'CLOSED',
                        resolution_type = $1,
                        resolution_notes = $2,
                        completed_at = NOW(),
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $3
                    """,
                    resolution_type,
                    resolution_notes,
                    investigation_id
                )

                # Map resolution type to alert status
                # verified_malicious, false_positive, benign_activity -> closed
                # inconclusive -> might stay open for further review
                alert_status = 'closed'
                if resolution_type == 'inconclusive':
                    alert_status = 'resolved_inconclusive'

                # Update linked alerts - by investigation_id reference
                alerts_updated = await conn.execute(
                    """
                    UPDATE alerts
                    SET status = $1,
                        closed_by = $2,
                        closed_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = (
                        SELECT id FROM investigations WHERE investigation_id = $3
                    )
                    """,
                    alert_status,
                    resolved_by,
                    investigation_id
                )

                # Also update by direct alert_id link if exists
                if inv_row and inv_row['alert_id']:
                    await conn.execute(
                        """
                        UPDATE alerts
                        SET status = $1,
                            closed_by = $2,
                            closed_at = NOW(),
                            updated_at = NOW()
                        WHERE id = $3
                        """,
                        alert_status,
                        resolved_by,
                        inv_row['alert_id']
                    )

                logger.info(f"Investigation {investigation_id} resolved as {resolution_type}, linked alerts updated to {alert_status}")

                # =====================================================
                # AUTO-LEARN: Add sender to trusted list on benign resolution
                # =====================================================
                if resolution_type in ['false_positive', 'benign_activity']:
                    await self._auto_learn_trusted_sender(conn, investigation_id, resolution_type, resolved_by)

                # =====================================================
                # ML FEEDBACK: Record analyst verdict for ML learning
                # =====================================================
                try:
                    from services.ml_training_trigger import record_analyst_feedback
                    if inv_row and inv_row.get('alert_id'):
                        await record_analyst_feedback(
                            alert_id=str(inv_row['alert_id']),
                            analyst_disposition=resolution_type,
                            resolved_by=resolved_by,
                            investigation_id=investigation_id
                        )
                        logger.info(f"[ML_FEEDBACK] Recorded feedback for investigation {investigation_id}")
                except Exception as ml_err:
                    logger.warning(f"Failed to record ML feedback: {ml_err}")

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    message=f"Investigation resolved: {resolution_type}"
                )

        except Exception as e:
            logger.error(f"Resolve failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    async def close_investigation(
        self,
        investigation_id: str,
        closed_by: str
    ) -> AssignmentResult:
        """Mark investigation as closed and ensure linked alerts are closed"""
        db = self._get_db()
        if not db or not db.pool:
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message="Database not available"
            )

        try:
            async with db.tenant_acquire() as conn:
                # First get the investigation to find linked alert_id
                inv_row = await conn.fetchrow(
                    "SELECT alert_id FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                # Update the investigation
                await conn.execute(
                    """
                    UPDATE investigations
                    SET state = 'CLOSED',
                        closed_by = $1,
                        last_activity_at = NOW(),
                        updated_at = NOW()
                    WHERE investigation_id = $2
                    """,
                    closed_by,
                    investigation_id
                )

                # Also close any linked alerts that aren't already closed
                await conn.execute(
                    """
                    UPDATE alerts
                    SET status = 'closed',
                        closed_by = COALESCE(closed_by, $1),
                        closed_at = COALESCE(closed_at, NOW()),
                        updated_at = NOW()
                    WHERE investigation_id = (
                        SELECT id FROM investigations WHERE investigation_id = $2
                    )
                    AND status != 'closed'
                    """,
                    closed_by,
                    investigation_id
                )

                # Also update by direct alert_id link if exists
                if inv_row and inv_row['alert_id']:
                    await conn.execute(
                        """
                        UPDATE alerts
                        SET status = 'closed',
                            closed_by = COALESCE(closed_by, $1),
                            closed_at = COALESCE(closed_at, NOW()),
                            updated_at = NOW()
                        WHERE id = $2
                        AND status != 'closed'
                        """,
                        closed_by,
                        inv_row['alert_id']
                    )

                logger.info(f"Investigation {investigation_id} closed by {closed_by}, linked alerts also closed")

                return AssignmentResult(
                    success=True,
                    investigation_id=investigation_id,
                    message="Investigation closed"
                )

        except Exception as e:
            logger.error(f"Close failed: {e}")
            return AssignmentResult(
                success=False,
                investigation_id=investigation_id,
                message=str(e)
            )

    # ========================================================================
    # QUEUE QUERIES
    # ========================================================================

    async def get_my_queue(self, user_id: str) -> List[Dict]:
        """Get investigations assigned to a specific user"""
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT * FROM investigations
                    WHERE owner = $1
                      AND state NOT IN ('RESOLVED', 'CLOSED')
                    ORDER BY
                        CASE priority
                            WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2
                            WHEN 'P3' THEN 3
                            WHEN 'P4' THEN 4
                        END,
                        created_at ASC
                    """,
                    user_id
                )
                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Queue query failed: {e}")
            return []

    async def get_team_queue(self, team_id: str) -> List[Dict]:
        """Get investigations for a team"""
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                # Get team members
                team = await conn.fetchrow(
                    "SELECT members FROM teams WHERE team_id = $1",
                    team_id
                )

                if not team or not team['members']:
                    return []

                members = team['members']

                rows = await conn.fetch(
                    """
                    SELECT * FROM investigations
                    WHERE (owner = ANY($1) OR owner LIKE 'team:' || $2)
                      AND state NOT IN ('RESOLVED', 'CLOSED')
                    ORDER BY
                        CASE priority
                            WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2
                            WHEN 'P3' THEN 3
                            WHEN 'P4' THEN 4
                        END,
                        created_at ASC
                    """,
                    members,
                    team_id
                )
                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Team queue query failed: {e}")
            return []

    async def get_orphaned_investigations(self, stale_minutes: int = 60) -> List[Dict]:
        """Get investigations that are unassigned and stale"""
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT * FROM investigations
                    WHERE (owner IS NULL OR owner_type = 'unassigned')
                      AND state NOT IN ('RESOLVED', 'CLOSED')
                      AND last_activity_at < NOW() - $1 * INTERVAL '1 minute'
                    ORDER BY priority, created_at ASC
                    """,
                    stale_minutes
                )
                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Orphaned query failed: {e}")
            return []

    # ========================================================================
    # HELPERS
    # ========================================================================

    async def _get_active_rules(self) -> List[Dict]:
        """Get active assignment rules (with caching)"""
        # Check cache (5 minute TTL)
        if self._rules_cache_time and (datetime.utcnow() - self._rules_cache_time).seconds < 300:
            return self._rules_cache

        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT * FROM assignment_rules
                    WHERE enabled = true
                    ORDER BY priority ASC
                    """
                )
                self._rules_cache = [dict(row) for row in rows]
                self._rules_cache_time = datetime.utcnow()
                return self._rules_cache

        except Exception as e:
            logger.error(f"Failed to get rules: {e}")
            return []

    async def _update_rule_stats(self, rule_id: str):
        """Update rule trigger stats"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE assignment_rules
                    SET trigger_count = trigger_count + 1,
                        last_triggered_at = NOW()
                    WHERE id = $1
                    """,
                    rule_id
                )
        except Exception as e:
            logger.debug(f"Failed to update rule stats: {e}")

    async def _auto_learn_trusted_sender(
        self,
        conn,
        investigation_id: str,
        resolution_type: str,
        resolved_by: str
    ):
        """
        Auto-learn: Add sender domain to trusted senders when investigation is resolved as benign.

        This enables the AI to automatically recognize similar emails from this sender in the future
        and auto-close them as benign.

        Args:
            conn: Database connection
            investigation_id: The investigation ID
            resolution_type: 'false_positive' or 'benign_activity'
            resolved_by: Username of analyst who resolved
        """
        try:
            # Get linked alert data to find original sender
            alert_row = await conn.fetchrow("""
                SELECT a.raw_event, a.alert_id, a.title, i.investigation_data
                FROM investigations i
                LEFT JOIN alerts a ON a.investigation_id = i.id OR a.id = i.alert_id
                WHERE i.investigation_id = $1
                LIMIT 1
            """, investigation_id)

            if not alert_row:
                logger.debug(f"No linked alert found for investigation {investigation_id}")
                return

            # Parse raw_event to find sender
            raw_event = alert_row['raw_event']
            if isinstance(raw_event, str):
                try:
                    raw_event = json.loads(raw_event)
                except:
                    raw_event = {}

            # Also check investigation_data
            inv_data = alert_row['investigation_data']
            if isinstance(inv_data, str):
                try:
                    inv_data = json.loads(inv_data)
                except:
                    inv_data = {}

            # Extract sender from various possible fields
            sender = None
            sender_sources = [
                raw_event.get('original_sender'),
                raw_event.get('sender'),
                raw_event.get('from'),
                raw_event.get('reporter'),
                inv_data.get('original_sender'),
                inv_data.get('sender'),
            ]

            for s in sender_sources:
                if s and '@' in str(s):
                    sender = str(s).lower().strip()
                    break

            if not sender:
                logger.debug(f"No sender found in investigation {investigation_id}")
                return

            # Extract domain from sender email
            sender_domain = sender.split('@')[-1] if '@' in sender else None
            if not sender_domain or '.' not in sender_domain:
                logger.debug(f"Invalid sender domain: {sender}")
                return

            # Determine trust level based on resolution type
            # false_positive = analyst confirmed it's not a threat -> "trusted"
            # benign_activity = confirmed legitimate activity -> "known"
            trust_level = 'trusted' if resolution_type == 'false_positive' else 'known'

            # Add to trusted senders
            try:
                from services.sender_trust_service import get_sender_trust_service
                sender_trust = get_sender_trust_service()

                result = await sender_trust.add_trusted_sender(
                    domain=sender_domain,
                    sender_pattern=sender if sender != sender_domain else None,
                    trust_level=trust_level,
                    category='auto_learned',
                    organization=None,
                    reason=f"Auto-learned: {resolution_type} by {resolved_by} on investigation {investigation_id}",
                    added_by=f"auto_learn:{resolved_by}"
                )

                if result.get('success'):
                    logger.info(
                        f"AUTO-LEARN: Added {sender_domain} to trusted senders "
                        f"(level={trust_level}, investigation={investigation_id}, analyst={resolved_by})"
                    )
                else:
                    logger.debug(f"Sender trust add returned: {result}")

            except ImportError:
                logger.warning("Sender trust service not available for auto-learn")
            except Exception as trust_err:
                logger.warning(f"Failed to auto-learn sender trust: {trust_err}")

        except Exception as e:
            # Don't fail the resolution if auto-learn fails
            logger.error(f"Auto-learn trusted sender failed for {investigation_id}: {e}")

    async def _log_ownership_change(
        self,
        conn,
        investigation_id: str,
        previous_owner: Optional[str],
        new_owner: Optional[str],
        previous_owner_type: Optional[str],
        new_owner_type: str,
        change_type: ChangeType,
        reason: str,
        changed_by: Optional[str] = None,
        metadata: Optional[Dict] = None
    ):
        """Log ownership change to audit table"""
        try:
            from middleware.tenant_middleware import get_optional_tenant_id
            await conn.execute(
                """
                INSERT INTO investigation_ownership_log (
                    investigation_id, previous_owner, new_owner,
                    previous_owner_type, new_owner_type,
                    change_type, reason, changed_by, metadata, tenant_id
                )
                SELECT id, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10
                FROM investigations WHERE investigation_id = $1
                """,
                investigation_id,
                previous_owner,
                new_owner,
                previous_owner_type,
                new_owner_type,
                change_type.value,
                reason,
                changed_by or new_owner or 'system',
                json.dumps(metadata or {}),
                get_optional_tenant_id()
            )
        except Exception as e:
            logger.debug(f"Failed to log ownership change: {e}")


# ============================================================================
# SINGLETON
# ============================================================================

_assignment_service: Optional[AssignmentService] = None


def get_assignment_service() -> AssignmentService:
    """Get the global assignment service instance"""
    global _assignment_service
    if _assignment_service is None:
        _assignment_service = AssignmentService()
    return _assignment_service
