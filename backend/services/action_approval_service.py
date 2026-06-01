# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Approval Service

Manages the approval queue for response actions requested by Riggs.
When Riggs wants to take a high-impact action (isolate host, suspend user, etc.),
it queues the request here for human approval.

Features:
- Queue actions for approval with expiration
- Approve/reject actions
- Execute approved actions via integrations
- Track action history
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ActionApprovalService:
    """
    Service for managing Riggs action approvals.
    """

    def __init__(self):
        self.enabled = True

    async def create_approval_request(
        self,
        action_name: str,
        integration_name: str,
        target_type: str,
        target_identifier: str,
        reason: str,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        riggs_confidence: Optional[float] = None,
        evidence: Optional[Dict[str, Any]] = None,
        priority: str = 'medium',
        expires_in_minutes: int = 30
    ) -> Dict[str, Any]:
        """
        Create a new action approval request.

        Args:
            action_name: Name of the action (e.g., 'isolate_host')
            integration_name: Integration to execute via
            target_type: Type of target (host, user, ip, etc.)
            target_identifier: The actual target value
            reason: Why Riggs wants to take this action
            alert_id: Associated alert ID
            investigation_id: Associated investigation ID
            riggs_confidence: Riggs's confidence (0.0-1.0)
            evidence: Supporting evidence
            priority: low, medium, high, critical
            expires_in_minutes: Minutes until auto-reject

        Returns:
            Created approval request
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            approval_id = f"APR-{uuid.uuid4().hex[:6].upper()}"

            async with postgres_db.tenant_acquire() as conn:
                # Get capability ID if exists
                capability_id = await conn.fetchval('''
                    SELECT ic.id FROM integration_capabilities ic
                    JOIN integrations i ON ic.integration_id = i.id
                    WHERE i.name = $1 AND ic.capability_name = $2
                ''', integration_name, action_name)

                row = await conn.fetchrow('''
                    INSERT INTO action_approvals (
                        approval_id, action_name, capability_id, integration_name,
                        target_type, target_identifier, target_context,
                        reason, evidence, riggs_confidence,
                        alert_id, investigation_id,
                        status, priority,
                        requested_at, expires_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', $13, NOW(), NOW() + $14 * INTERVAL '1 minute')
                    RETURNING *
                ''',
                    approval_id,
                    action_name,
                    capability_id,
                    integration_name,
                    target_type,
                    target_identifier,
                    json.dumps({}),
                    reason,
                    json.dumps(evidence or {}),
                    riggs_confidence,
                    alert_id,
                    investigation_id,
                    priority,
                    expires_in_minutes
                )

                logger.info(f"Created approval request: {approval_id} for {action_name}")
                return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to create approval request: {e}")
            return {"error": str(e)}

    async def get_pending_approvals(
        self,
        priority: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get pending approval requests.

        Args:
            priority: Filter by priority
            limit: Max results

        Returns:
            List of pending approvals
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return []

            async with postgres_db.tenant_acquire() as conn:
                if priority:
                    rows = await conn.fetch('''
                        SELECT * FROM action_approvals
                        WHERE status = 'pending'
                          AND (expires_at IS NULL OR expires_at > NOW())
                          AND priority = $1
                        ORDER BY
                            CASE priority
                                WHEN 'critical' THEN 1
                                WHEN 'high' THEN 2
                                WHEN 'medium' THEN 3
                                WHEN 'low' THEN 4
                            END,
                            requested_at ASC
                        LIMIT $2
                    ''', priority, limit)
                else:
                    rows = await conn.fetch('''
                        SELECT * FROM action_approvals
                        WHERE status = 'pending'
                          AND (expires_at IS NULL OR expires_at > NOW())
                        ORDER BY
                            CASE priority
                                WHEN 'critical' THEN 1
                                WHEN 'high' THEN 2
                                WHEN 'medium' THEN 3
                                WHEN 'low' THEN 4
                            END,
                            requested_at ASC
                        LIMIT $1
                    ''', limit)

                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get pending approvals: {e}")
            return []

    async def get_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Get a single approval request by ID."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return None

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    'SELECT * FROM action_approvals WHERE approval_id = $1',
                    approval_id
                )
                return self._row_to_dict(row) if row else None

        except Exception as e:
            logger.error(f"Failed to get approval {approval_id}: {e}")
            return None

    async def approve_action(
        self,
        approval_id: str,
        approved_by: str,
        notes: Optional[str] = None,
        execute_immediately: bool = True
    ) -> Dict[str, Any]:
        """
        Approve an action request.

        Args:
            approval_id: Approval request ID
            approved_by: User ID of approver
            notes: Optional review notes
            execute_immediately: Whether to execute the action now

        Returns:
            Updated approval with execution result
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with postgres_db.tenant_acquire() as conn:
                # Get the approval
                approval = await conn.fetchrow(
                    'SELECT * FROM action_approvals WHERE approval_id = $1',
                    approval_id
                )

                if not approval:
                    return {"error": "Approval not found"}

                if approval['status'] != 'pending':
                    return {"error": f"Approval is already {approval['status']}"}

                # Check if expired
                if approval['expires_at'] and approval['expires_at'] < datetime.now(approval['expires_at'].tzinfo):
                    await conn.execute('''
                        UPDATE action_approvals
                        SET status = 'expired'
                        WHERE approval_id = $1
                    ''', approval_id)
                    return {"error": "Approval has expired"}

                # Update to approved
                await conn.execute('''
                    UPDATE action_approvals
                    SET status = 'approved',
                        reviewed_by = $1,
                        reviewed_at = NOW(),
                        review_notes = $2
                    WHERE approval_id = $3
                ''', approved_by, notes, approval_id)

                result = {"approval_id": approval_id, "status": "approved"}

                # Execute if requested
                if execute_immediately:
                    execution_result = await self._execute_action(approval)
                    result["execution"] = execution_result

                    # Update with execution result
                    final_status = 'executed' if execution_result.get('success') else 'failed'
                    await conn.execute('''
                        UPDATE action_approvals
                        SET status = $1,
                            executed_at = NOW(),
                            execution_result = $2
                        WHERE approval_id = $3
                    ''', final_status, json.dumps(execution_result), approval_id)

                    result["status"] = final_status

                logger.info(f"Approved action: {approval_id} by {approved_by}")
                return result

        except Exception as e:
            logger.error(f"Failed to approve action {approval_id}: {e}")
            return {"error": str(e)}

    async def reject_action(
        self,
        approval_id: str,
        rejected_by: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reject an action request.

        Args:
            approval_id: Approval request ID
            rejected_by: User ID of rejector
            reason: Optional rejection reason

        Returns:
            Updated approval
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE action_approvals
                    SET status = 'rejected',
                        reviewed_by = $1,
                        reviewed_at = NOW(),
                        review_notes = $2
                    WHERE approval_id = $3 AND status = 'pending'
                ''', rejected_by, reason, approval_id)

                logger.info(f"Rejected action: {approval_id} by {rejected_by}. Reason: {reason}")
                return {"approval_id": approval_id, "status": "rejected"}

        except Exception as e:
            logger.error(f"Failed to reject action {approval_id}: {e}")
            return {"error": str(e)}

    async def expire_old_approvals(self) -> int:
        """
        Mark expired approvals as expired.
        Should be called periodically by a scheduler.

        Returns:
            Number of approvals expired
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return 0

            async with postgres_db.tenant_acquire() as conn:
                result = await conn.execute('''
                    UPDATE action_approvals
                    SET status = 'expired'
                    WHERE status = 'pending'
                      AND expires_at IS NOT NULL
                      AND expires_at < NOW()
                ''')

                # Parse result to get count
                count = int(result.split()[-1]) if result else 0
                if count > 0:
                    logger.info(f"Expired {count} pending approvals")
                return count

        except Exception as e:
            logger.error(f"Failed to expire old approvals: {e}")
            return 0

    async def get_approval_stats(self) -> Dict[str, Any]:
        """Get statistics about action approvals."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with postgres_db.tenant_acquire() as conn:
                # Pending count
                pending = await conn.fetchval('''
                    SELECT COUNT(*) FROM action_approvals
                    WHERE status = 'pending'
                      AND (expires_at IS NULL OR expires_at > NOW())
                ''')

                # By status
                by_status = await conn.fetch('''
                    SELECT status, COUNT(*) as count
                    FROM action_approvals
                    GROUP BY status
                ''')

                # Recent actions
                recent = await conn.fetch('''
                    SELECT action_name, integration_name, status, requested_at
                    FROM action_approvals
                    ORDER BY requested_at DESC
                    LIMIT 10
                ''')

                # Approval rate (last 7 days)
                approved = await conn.fetchval('''
                    SELECT COUNT(*) FROM action_approvals
                    WHERE status IN ('approved', 'executed')
                      AND requested_at > NOW() - INTERVAL '7 days'
                ''')

                total_reviewed = await conn.fetchval('''
                    SELECT COUNT(*) FROM action_approvals
                    WHERE status IN ('approved', 'executed', 'rejected')
                      AND requested_at > NOW() - INTERVAL '7 days'
                ''')

                return {
                    'pending_count': pending,
                    'by_status': {row['status']: row['count'] for row in by_status},
                    'recent_actions': [dict(row) for row in recent],
                    'approval_rate_7d': approved / total_reviewed if total_reviewed > 0 else 0
                }

        except Exception as e:
            logger.error(f"Failed to get approval stats: {e}")
            return {"error": str(e)}

    async def _execute_action(self, approval: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an approved action via the appropriate integration.

        Args:
            approval: The approval record

        Returns:
            Execution result
        """
        action_name = approval['action_name']
        integration_name = approval['integration_name']
        target = approval['target_identifier']

        logger.info(f"Executing action: {action_name} via {integration_name} on {target}")

        try:
            # Get integration handler
            from services.integrations import get_integration_handler

            handler = await get_integration_handler(integration_name)
            if not handler:
                return {
                    "success": False,
                    "error": f"Integration {integration_name} not found or not configured"
                }

            # Execute the action
            result = await handler.execute_action(
                action=action_name,
                target=target,
                context={
                    'approval_id': approval['approval_id'],
                    'alert_id': approval.get('alert_id'),
                    'reason': approval['reason']
                }
            )

            return {
                "success": True,
                "action": action_name,
                "target": target,
                "result": result
            }

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        if not row:
            return None

        result = dict(row)

        # Convert UUID to string
        for field in ['id', 'capability_id', 'alert_id', 'investigation_id', 'reviewed_by']:
            if result.get(field):
                result[field] = str(result[field])

        # Convert datetime to ISO string
        for field in ['requested_at', 'expires_at', 'reviewed_at', 'executed_at']:
            if result.get(field):
                result[field] = result[field].isoformat()

        # Parse JSONB fields
        for field in ['target_context', 'evidence', 'execution_result']:
            if result.get(field) and isinstance(result[field], str):
                try:
                    result[field] = json.loads(result[field])
                except:
                    pass

        return result


# Singleton instance
action_approval_service = ActionApprovalService()


def get_action_approval_service() -> ActionApprovalService:
    """Get the action approval service singleton."""
    return action_approval_service
