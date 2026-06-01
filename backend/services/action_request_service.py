# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Request Service - Phase 5.1

Manages action requests from AI agents that require human approval before execution.
Supports containment, blocking, user management, and investigation actions.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ActionStatus(Enum):
    PENDING = 'pending'
    APPROVED = 'approved'
    DENIED = 'denied'
    EXECUTING = 'executing'
    COMPLETED = 'completed'
    FAILED = 'failed'
    EXPIRED = 'expired'
    CANCELLED = 'cancelled'


class ActionPriority(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'


class ActionRequestService:
    """
    Service for managing action requests from AI agents.

    Flow:
    1. Agent calls request_action tool with action details
    2. Service creates pending request and returns request_id
    3. Human reviews in approval queue UI
    4. On approval, service executes via integration
    5. Results logged and investigation updated
    """

    def __init__(self, postgres_service):
        self._postgres = postgres_service
        self._execution_handlers = {}  # integration_name -> handler function

    async def initialize(self):
        """Initialize the service and load action type configurations."""
        logger.info("Initializing ActionRequestService")

    # =========================================================================
    # ACTION REQUEST CREATION
    # =========================================================================

    async def create_action_request(
        self,
        action_type: str,
        target_type: str,
        target_value: str,
        reasoning: str,
        confidence: float,
        investigation_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        requested_by_agent: Optional[str] = None,
        requested_by_human: Optional[str] = None,
        evidence: Optional[List[Dict]] = None,
        target_metadata: Optional[Dict] = None,
        parameters: Optional[Dict] = None,
        priority: str = 'medium',
        integration_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new action request.

        Returns:
            Dict with request_id, status, and action details
        """
        try:
            # Validate action type exists and is enabled
            action_type_info = await self._get_action_type(action_type)
            if not action_type_info:
                return {
                    'success': False,
                    'error': f"Unknown action type: {action_type}"
                }

            if not action_type_info['enabled']:
                return {
                    'success': False,
                    'error': f"Action type '{action_type}' is currently disabled"
                }

            # Check agent tier permission
            if requested_by_agent:
                agent_tier = await self._get_agent_tier(requested_by_agent)
                if agent_tier and agent_tier < action_type_info['min_agent_tier']:
                    return {
                        'success': False,
                        'error': f"Agent tier {agent_tier} cannot request '{action_type}' (requires tier {action_type_info['min_agent_tier']}+)"
                    }

            # Calculate expiration time
            timeout_minutes = action_type_info['approval_timeout_minutes'] or 240
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=timeout_minutes)

            # Select integration if not specified
            if not integration_name:
                integration_name = await self._select_integration_for_action(
                    action_type,
                    action_type_info['integration_mappings']
                )

            integration_action_id = None
            if integration_name and action_type_info['integration_mappings']:
                integration_action_id = action_type_info['integration_mappings'].get(integration_name)

            # Create the request
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO action_requests (
                        action_type, target_type, target_value, target_metadata,
                        integration_name, integration_action_id, parameters,
                        investigation_id, alert_id, requested_by_agent, requested_by_human,
                        status, priority, expires_at, reasoning, confidence, evidence,
                        is_reversible, rollback_action_type
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                        'pending', $12, $13, $14, $15, $16, $17, $18
                    )
                    RETURNING id, request_id, created_at
                ''',
                    action_type,
                    target_type,
                    target_value,
                    json.dumps(target_metadata or {}),
                    integration_name,
                    integration_action_id,
                    json.dumps(parameters or {}),
                    uuid.UUID(investigation_id) if investigation_id else None,
                    uuid.UUID(alert_id) if alert_id else None,
                    uuid.UUID(requested_by_agent) if requested_by_agent else None,
                    requested_by_human,
                    priority,
                    expires_at,
                    reasoning,
                    confidence,
                    json.dumps(evidence or []),
                    action_type_info['is_reversible'],
                    action_type_info['reverse_action_type']
                )

            request_id = row['request_id']

            logger.info(f"Created action request {request_id}: {action_type} on {target_type}:{target_value}")

            # Log to audit
            await self._log_audit(
                'action_request_created',
                request_id,
                {
                    'action_type': action_type,
                    'target': f"{target_type}:{target_value}",
                    'requested_by': requested_by_agent or requested_by_human,
                    'priority': priority
                }
            )

            return {
                'success': True,
                'request_id': request_id,
                'status': 'pending',
                'action_type': action_type,
                'target': f"{target_type}:{target_value}",
                'requires_approval': action_type_info['requires_approval'],
                'expires_at': expires_at.isoformat(),
                'message': f"Action request {request_id} created. {'Awaiting human approval.' if action_type_info['requires_approval'] else 'Will execute automatically.'}"
            }

        except Exception as e:
            logger.error(f"Error creating action request: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }

    # =========================================================================
    # APPROVAL / DENIAL
    # =========================================================================

    async def approve_action(
        self,
        request_id: str,
        approved_by: str,
        execute_immediately: bool = True
    ) -> Dict[str, Any]:
        """
        Approve an action request.

        Args:
            request_id: The action request ID (ACT-XXXXXXXX)
            approved_by: Username of approver
            execute_immediately: Whether to execute right away or just mark approved
        """
        try:
            async with self._postgres.tenant_acquire() as conn:
                # Get current request
                row = await conn.fetchrow('''
                    SELECT * FROM action_requests WHERE request_id = $1
                ''', request_id)

                if not row:
                    return {'success': False, 'error': f"Action request {request_id} not found"}

                if row['status'] != 'pending':
                    return {'success': False, 'error': f"Action request is not pending (status: {row['status']})"}

                # Check if expired
                if row['expires_at'] and row['expires_at'] < datetime.now(timezone.utc):
                    await conn.execute('''
                        UPDATE action_requests
                        SET status = 'expired', updated_at = CURRENT_TIMESTAMP
                        WHERE request_id = $1
                    ''', request_id)
                    return {'success': False, 'error': f"Action request has expired"}

                # Update to approved
                await conn.execute('''
                    UPDATE action_requests
                    SET status = 'approved', approved_by = $2, approved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE request_id = $1
                ''', request_id, approved_by)

                logger.info(f"Action request {request_id} approved by {approved_by}")

                await self._log_audit(
                    'action_request_approved',
                    request_id,
                    {'approved_by': approved_by, 'action_type': row['action_type']}
                )

            # Execute if requested
            if execute_immediately:
                return await self.execute_action(request_id)

            return {
                'success': True,
                'request_id': request_id,
                'status': 'approved',
                'message': f"Action request {request_id} approved by {approved_by}"
            }

        except Exception as e:
            logger.error(f"Error approving action request: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    async def deny_action(
        self,
        request_id: str,
        denied_by: str,
        denial_reason: str
    ) -> Dict[str, Any]:
        """Deny an action request."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT * FROM action_requests WHERE request_id = $1
                ''', request_id)

                if not row:
                    return {'success': False, 'error': f"Action request {request_id} not found"}

                if row['status'] != 'pending':
                    return {'success': False, 'error': f"Action request is not pending (status: {row['status']})"}

                await conn.execute('''
                    UPDATE action_requests
                    SET status = 'denied', denied_by = $2, denied_at = CURRENT_TIMESTAMP,
                        denial_reason = $3, updated_at = CURRENT_TIMESTAMP
                    WHERE request_id = $1
                ''', request_id, denied_by, denial_reason)

                logger.info(f"Action request {request_id} denied by {denied_by}: {denial_reason}")

                await self._log_audit(
                    'action_request_denied',
                    request_id,
                    {'denied_by': denied_by, 'reason': denial_reason, 'action_type': row['action_type']}
                )

            return {
                'success': True,
                'request_id': request_id,
                'status': 'denied',
                'message': f"Action request {request_id} denied by {denied_by}"
            }

        except Exception as e:
            logger.error(f"Error denying action request: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # EXECUTION
    # =========================================================================

    async def execute_action(self, request_id: str) -> Dict[str, Any]:
        """
        Execute an approved action request via the configured integration.
        """
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT * FROM action_requests WHERE request_id = $1
                ''', request_id)

                if not row:
                    return {'success': False, 'error': f"Action request {request_id} not found"}

                if row['status'] not in ('approved', 'pending'):
                    return {'success': False, 'error': f"Action request cannot be executed (status: {row['status']})"}

                # Check if action type requires approval
                action_type_info = await self._get_action_type(row['action_type'])
                if action_type_info['requires_approval'] and row['status'] == 'pending':
                    return {'success': False, 'error': "This action requires approval before execution"}

                # Update to executing
                await conn.execute('''
                    UPDATE action_requests
                    SET status = 'executing', updated_at = CURRENT_TIMESTAMP
                    WHERE request_id = $1
                ''', request_id)

            # Execute via integration
            execution_result = await self._execute_via_integration(row)

            # Update final status
            async with self._postgres.tenant_acquire() as conn:
                if execution_result['success']:
                    await conn.execute('''
                        UPDATE action_requests
                        SET status = 'completed', executed_at = CURRENT_TIMESTAMP,
                            execution_result = $2, updated_at = CURRENT_TIMESTAMP
                        WHERE request_id = $1
                    ''', request_id, json.dumps(execution_result.get('result', {})))

                    logger.info(f"Action request {request_id} executed successfully")

                    # Update investigation if linked
                    if row['investigation_id']:
                        await self._update_investigation_with_action(
                            str(row['investigation_id']),
                            row['action_type'],
                            row['target_value'],
                            'completed',
                            execution_result
                        )
                else:
                    await conn.execute('''
                        UPDATE action_requests
                        SET status = 'failed', error_message = $2, updated_at = CURRENT_TIMESTAMP
                        WHERE request_id = $1
                    ''', request_id, execution_result.get('error', 'Unknown error'))

                    logger.error(f"Action request {request_id} failed: {execution_result.get('error')}")

            await self._log_audit(
                'action_request_executed' if execution_result['success'] else 'action_request_failed',
                request_id,
                {
                    'action_type': row['action_type'],
                    'target': f"{row['target_type']}:{row['target_value']}",
                    'result': execution_result
                }
            )

            return {
                'success': execution_result['success'],
                'request_id': request_id,
                'status': 'completed' if execution_result['success'] else 'failed',
                'result': execution_result.get('result'),
                'error': execution_result.get('error'),
                'message': f"Action {row['action_type']} on {row['target_value']} {'completed' if execution_result['success'] else 'failed'}"
            }

        except Exception as e:
            logger.error(f"Error executing action request: {e}", exc_info=True)

            # Mark as failed
            try:
                async with self._postgres.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE action_requests
                        SET status = 'failed', error_message = $2, updated_at = CURRENT_TIMESTAMP
                        WHERE request_id = $1
                    ''', request_id, str(e))
            except:
                pass

            return {'success': False, 'error': str(e)}

    async def _execute_via_integration(self, request: Dict) -> Dict[str, Any]:
        """
        Execute the action via the configured integration.

        This is a stub - actual integration execution will be implemented
        when integrations are connected.
        """
        integration_name = request['integration_name']
        action_type = request['action_type']
        target_value = request['target_value']
        parameters = json.loads(request['parameters']) if isinstance(request['parameters'], str) else request['parameters']

        # Check if we have a handler for this integration
        if integration_name in self._execution_handlers:
            handler = self._execution_handlers[integration_name]
            return await handler(
                action=request['integration_action_id'] or action_type,
                target=target_value,
                parameters=parameters
            )

        # Simulated execution for testing
        logger.warning(f"No integration handler for '{integration_name}', simulating execution")

        # Simulate execution delay
        await asyncio.sleep(1)

        return {
            'success': True,
            'result': {
                'simulated': True,
                'integration': integration_name,
                'action': action_type,
                'target': target_value,
                'message': f"Simulated {action_type} on {target_value} (no integration configured)"
            }
        }

    def register_execution_handler(self, integration_name: str, handler):
        """Register an execution handler for an integration."""
        self._execution_handlers[integration_name] = handler
        logger.info(f"Registered execution handler for integration: {integration_name}")

    # =========================================================================
    # QUERIES
    # =========================================================================

    async def get_pending_requests(
        self,
        priority: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Get pending action requests for the approval queue."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                query = '''
                    SELECT ar.*,
                           at.display_name as action_display_name,
                           at.category as action_category,
                           at.risk_level,
                           i.investigation_id as inv_number,
                           ad.system_name as agent_name
                    FROM action_requests ar
                    LEFT JOIN action_types at ON ar.action_type = at.action_type
                    LEFT JOIN investigations i ON ar.investigation_id = i.id
                    LEFT JOIN agent_definitions ad ON ar.requested_by_agent = ad.id
                    WHERE ar.status = 'pending'
                '''
                params = []

                if priority:
                    query += f' AND ar.priority = ${len(params) + 1}'
                    params.append(priority)

                query += f' ORDER BY CASE ar.priority WHEN \'critical\' THEN 1 WHEN \'high\' THEN 2 WHEN \'medium\' THEN 3 ELSE 4 END, ar.created_at ASC LIMIT ${len(params) + 1}'
                params.append(limit)

                rows = await conn.fetch(query, *params)

                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting pending requests: {e}", exc_info=True)
            return []

    async def get_request_by_id(self, request_id: str) -> Optional[Dict]:
        """Get a single action request by ID."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT ar.*,
                           at.display_name as action_display_name,
                           at.category as action_category,
                           at.risk_level,
                           at.description as action_description,
                           i.investigation_id as inv_number,
                           ad.system_name as agent_name
                    FROM action_requests ar
                    LEFT JOIN action_types at ON ar.action_type = at.action_type
                    LEFT JOIN investigations i ON ar.investigation_id = i.id
                    LEFT JOIN agent_definitions ad ON ar.requested_by_agent = ad.id
                    WHERE ar.request_id = $1
                ''', request_id)

                return self._row_to_dict(row) if row else None

        except Exception as e:
            logger.error(f"Error getting request by ID: {e}", exc_info=True)
            return None

    async def get_requests_for_investigation(self, investigation_id: str) -> List[Dict]:
        """Get all action requests for an investigation."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                # investigation_id can be either a UUID or an investigation number like "INV-..."
                # Join with investigations table to handle both cases
                rows = await conn.fetch('''
                    SELECT ar.*, at.display_name as action_display_name
                    FROM action_requests ar
                    LEFT JOIN action_types at ON ar.action_type = at.action_type
                    LEFT JOIN investigations i ON ar.investigation_id = i.id
                    WHERE i.investigation_id = $1 OR ar.investigation_id::text = $1
                    ORDER BY ar.created_at DESC
                ''', investigation_id)

                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting requests for investigation: {e}", exc_info=True)
            return []

    async def get_all_requests(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        action_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """Get all action requests with optional filters (for history view)."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                query = '''
                    SELECT ar.*,
                           at.display_name as action_display_name,
                           at.category as action_category,
                           at.risk_level,
                           i.investigation_id as inv_number,
                           ad.system_name as agent_name
                    FROM action_requests ar
                    LEFT JOIN action_types at ON ar.action_type = at.action_type
                    LEFT JOIN investigations i ON ar.investigation_id = i.id
                    LEFT JOIN agent_definitions ad ON ar.requested_by_agent = ad.id
                    WHERE 1=1
                '''
                params = []

                if status:
                    params.append(status)
                    query += f' AND ar.status = ${len(params)}'

                if priority:
                    params.append(priority)
                    query += f' AND ar.priority = ${len(params)}'

                if action_type:
                    params.append(action_type)
                    query += f' AND ar.action_type = ${len(params)}'

                query += ' ORDER BY ar.created_at DESC'
                params.append(limit)
                query += f' LIMIT ${len(params)}'
                params.append(offset)
                query += f' OFFSET ${len(params)}'

                rows = await conn.fetch(query, *params)
                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting all requests: {e}", exc_info=True)
            return []

    async def get_action_types(self, enabled_only: bool = True) -> List[Dict]:
        """Get available action types."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                query = 'SELECT * FROM action_types'
                if enabled_only:
                    query += ' WHERE enabled = true'
                query += ' ORDER BY category, action_type'

                rows = await conn.fetch(query)
                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting action types: {e}", exc_info=True)
            return []

    async def get_action_stats(self) -> Dict[str, Any]:
        """Get action request statistics."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                stats = {}

                # Status counts
                rows = await conn.fetch('''
                    SELECT status, COUNT(*) as count FROM action_requests GROUP BY status
                ''')
                stats['by_status'] = {row['status']: row['count'] for row in rows}

                # Priority counts for pending
                rows = await conn.fetch('''
                    SELECT priority, COUNT(*) as count FROM action_requests
                    WHERE status = 'pending' GROUP BY priority
                ''')
                stats['pending_by_priority'] = {row['priority']: row['count'] for row in rows}

                # Recent activity (last 24h)
                stats['last_24h'] = await conn.fetchval('''
                    SELECT COUNT(*) FROM action_requests
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                ''')

                # Expiring soon (next 30 min)
                stats['expiring_soon'] = await conn.fetchval('''
                    SELECT COUNT(*) FROM action_requests
                    WHERE status = 'pending'
                    AND expires_at < NOW() + INTERVAL '30 minutes'
                    AND expires_at > NOW()
                ''')

                return stats

        except Exception as e:
            logger.error(f"Error getting action stats: {e}", exc_info=True)
            return {}

    # =========================================================================
    # EXPIRATION HANDLING
    # =========================================================================

    async def expire_old_requests(self) -> int:
        """Mark expired pending requests as expired. Returns count of expired requests."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                result = await conn.execute('''
                    UPDATE action_requests
                    SET status = 'expired', updated_at = CURRENT_TIMESTAMP
                    WHERE status = 'pending'
                    AND expires_at < CURRENT_TIMESTAMP
                ''')

                count = int(result.split()[-1]) if result else 0
                if count > 0:
                    logger.info(f"Expired {count} action requests")

                return count

        except Exception as e:
            logger.error(f"Error expiring requests: {e}", exc_info=True)
            return 0

    # =========================================================================
    # ROLLBACK
    # =========================================================================

    async def rollback_action(
        self,
        request_id: str,
        rolled_back_by: str
    ) -> Dict[str, Any]:
        """
        Rollback a completed action by creating and executing the reverse action.
        """
        try:
            request = await self.get_request_by_id(request_id)
            if not request:
                return {'success': False, 'error': f"Action request {request_id} not found"}

            if request['status'] != 'completed':
                return {'success': False, 'error': f"Only completed actions can be rolled back (status: {request['status']})"}

            if not request['is_reversible']:
                return {'success': False, 'error': f"Action type '{request['action_type']}' is not reversible"}

            if request['rolled_back_at']:
                return {'success': False, 'error': "Action has already been rolled back"}

            # Create reverse action request
            reverse_result = await self.create_action_request(
                action_type=request['rollback_action_type'],
                target_type=request['target_type'],
                target_value=request['target_value'],
                reasoning=f"Rollback of action {request_id}",
                confidence=1.0,
                investigation_id=str(request['investigation_id']) if request['investigation_id'] else None,
                requested_by_human=rolled_back_by,
                priority='high'
            )

            if not reverse_result['success']:
                return reverse_result

            # Mark original as rolled back
            async with self._postgres.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE action_requests
                    SET rolled_back_at = CURRENT_TIMESTAMP, rolled_back_by = $2, updated_at = CURRENT_TIMESTAMP
                    WHERE request_id = $1
                ''', request_id, rolled_back_by)

            logger.info(f"Rollback initiated for {request_id} by {rolled_back_by}")

            return {
                'success': True,
                'original_request_id': request_id,
                'rollback_request_id': reverse_result['request_id'],
                'message': f"Rollback action created: {reverse_result['request_id']}"
            }

        except Exception as e:
            logger.error(f"Error rolling back action: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    async def _get_action_type(self, action_type: str) -> Optional[Dict]:
        """Get action type configuration."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT * FROM action_types WHERE action_type = $1
                ''', action_type)
                return self._row_to_dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting action type: {e}")
            return None

    async def _get_agent_tier(self, agent_id: str) -> Optional[int]:
        """Get the tier level of an agent."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT tier FROM agent_definitions WHERE id = $1
                ''', uuid.UUID(agent_id))
                return row['tier'] if row else None
        except Exception as e:
            logger.error(f"Error getting agent tier: {e}")
            return None

    async def _select_integration_for_action(
        self,
        action_type: str,
        integration_mappings: Dict
    ) -> Optional[str]:
        """Select the best available integration for an action type."""
        if not integration_mappings:
            return None

        # For now, just return the first integration that has a mapping
        # In the future, check which integrations are actually configured and healthy
        for integration_name in integration_mappings.keys():
            # TODO: Check if integration is configured and healthy
            return integration_name

        return None

    async def _update_investigation_with_action(
        self,
        investigation_id: str,
        action_type: str,
        target: str,
        status: str,
        result: Dict
    ):
        """Update investigation with action execution result."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                # Add action to investigation_data
                await conn.execute('''
                    UPDATE investigations
                    SET investigation_data = COALESCE(investigation_data, '{}'::jsonb) ||
                        jsonb_build_object('actions_taken',
                            COALESCE(investigation_data->'actions_taken', '[]'::jsonb) || $2::jsonb
                        ),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                ''',
                    uuid.UUID(investigation_id),
                    json.dumps([{
                        'action_type': action_type,
                        'target': target,
                        'status': status,
                        'executed_at': datetime.now(timezone.utc).isoformat(),
                        'result': result
                    }])
                )
        except Exception as e:
            logger.error(f"Error updating investigation with action: {e}")

    async def _log_audit(self, action: str, request_id: str, details: Dict):
        """Log action to audit trail."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO audit_log (action, target_type, target_id, details, tenant_id)
                    VALUES ($1, 'action_request', $2, $3, $4)
                ''', action, request_id, json.dumps(details),
                    uuid.UUID(str(_tenant_id)) if _tenant_id else None)
        except Exception as e:
            logger.error(f"Error logging audit: {e}")

    def _row_to_dict(self, row) -> Dict:
        """Convert asyncpg Record to dict with JSON parsing."""
        if not row:
            return {}

        result = dict(row)

        # Convert UUIDs to strings
        for key in ['id', 'investigation_id', 'alert_id', 'requested_by_agent', 'integration_id']:
            if key in result and result[key]:
                result[key] = str(result[key])

        # Parse JSON fields
        for key in ['target_metadata', 'parameters', 'execution_result', 'evidence', 'integration_mappings']:
            if key in result and result[key]:
                if isinstance(result[key], str):
                    try:
                        result[key] = json.loads(result[key])
                    except:
                        pass

        # Convert datetimes to ISO strings
        for key in ['created_at', 'updated_at', 'expires_at', 'approved_at', 'denied_at', 'executed_at', 'rolled_back_at']:
            if key in result and result[key]:
                result[key] = result[key].isoformat()

        return result


# Singleton instance
_action_request_service: Optional[ActionRequestService] = None


def get_action_request_service() -> ActionRequestService:
    """Get the action request service singleton."""
    global _action_request_service
    if _action_request_service is None:
        raise RuntimeError("ActionRequestService not initialized. Call init_action_request_service first.")
    return _action_request_service


async def init_action_request_service(postgres_service) -> ActionRequestService:
    """Initialize the action request service singleton."""
    global _action_request_service
    _action_request_service = ActionRequestService(postgres_service)
    await _action_request_service.initialize()
    return _action_request_service
