# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Chat Analytics Service
Tracks user chat activity for auditing and compliance.

Features:
- Session tracking (start, end, duration)
- Message analytics (count, types, lengths)
- Quick action usage tracking
- Action request auditing
- User activity reports
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ChatAnalyticsService:
    """
    Service for tracking and analyzing chat usage.
    """

    def __init__(self, postgres_service):
        self._postgres = postgres_service

    async def initialize(self):
        """Initialize the analytics service."""
        logger.info("ChatAnalyticsService initialized")

    async def _resolve_investigation_uuid(self, investigation_id: str) -> Optional[uuid.UUID]:
        """
        Resolve an investigation identifier to its UUID.

        The investigation_id can be either:
        - A UUID string (the internal id)
        - A human-readable ID like 'INV-20251222-F461587D' (the investigation_id column)

        Returns the UUID or None if not found.
        """
        if not investigation_id:
            return None

        try:
            # First try parsing as UUID directly
            return uuid.UUID(investigation_id)
        except (ValueError, AttributeError):
            # Not a UUID, look up by investigation_id string
            pass

        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                if row:
                    return row['id']
        except Exception as e:
            logger.error(f"Error resolving investigation UUID: {e}")

        return None

    # =========================================================================
    # EVENT TRACKING
    # =========================================================================

    async def track_event(
        self,
        user_id: str,
        event_type: str,
        investigation_id: Optional[str] = None,
        session_id: Optional[str] = None,
        username: Optional[str] = None,
        message_type: Optional[str] = None,
        message_length: Optional[int] = None,
        quick_action_category: Optional[str] = None,
        quick_action_label: Optional[str] = None,
        action_type: Optional[str] = None,
        action_target: Optional[str] = None,
        response_time_ms: Optional[int] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Track a chat usage event.
        """
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id) if investigation_id else None

            async with self._postgres.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                await conn.execute('''
                    INSERT INTO chat_usage_analytics (
                        user_id, username, session_id, investigation_id, event_type,
                        message_type, message_length, quick_action_category, quick_action_label,
                        action_type, action_target, response_time_ms,
                        user_agent, ip_address, metadata, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                ''',
                    user_id,
                    username or user_id,
                    session_id,
                    inv_uuid,
                    event_type,
                    message_type,
                    message_length,
                    quick_action_category,
                    quick_action_label,
                    action_type,
                    action_target,
                    response_time_ms,
                    user_agent,
                    ip_address,
                    json.dumps(metadata or {}),
                    _tid
                )
                return True
        except Exception as e:
            logger.error(f"Error tracking chat event: {e}")
            return False

    async def track_session_start(
        self,
        user_id: str,
        investigation_id: str,
        session_id: str,
        username: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> bool:
        """Track when a user opens the chat."""
        return await self.track_event(
            user_id=user_id,
            event_type='session_start',
            investigation_id=investigation_id,
            session_id=session_id,
            username=username,
            user_agent=user_agent,
            ip_address=ip_address
        )

    async def track_session_end(
        self,
        user_id: str,
        investigation_id: str,
        session_id: str
    ) -> bool:
        """Track when a user closes the chat."""
        return await self.track_event(
            user_id=user_id,
            event_type='session_end',
            investigation_id=investigation_id,
            session_id=session_id
        )

    async def track_message_sent(
        self,
        user_id: str,
        investigation_id: str,
        message_type: str,
        message_length: int,
        session_id: Optional[str] = None,
        username: Optional[str] = None
    ) -> bool:
        """Track when a user sends a message."""
        return await self.track_event(
            user_id=user_id,
            event_type='message_sent',
            investigation_id=investigation_id,
            session_id=session_id,
            username=username,
            message_type=message_type,
            message_length=message_length
        )

    async def track_quick_action(
        self,
        user_id: str,
        investigation_id: str,
        category: str,
        label: str,
        session_id: Optional[str] = None,
        username: Optional[str] = None
    ) -> bool:
        """Track when a user uses a quick action shortcut."""
        return await self.track_event(
            user_id=user_id,
            event_type='quick_action_used',
            investigation_id=investigation_id,
            session_id=session_id,
            username=username,
            quick_action_category=category,
            quick_action_label=label
        )

    async def track_action_requested(
        self,
        user_id: str,
        investigation_id: str,
        action_type: str,
        action_target: str,
        session_id: Optional[str] = None,
        username: Optional[str] = None
    ) -> bool:
        """Track when a user requests an agent action."""
        return await self.track_event(
            user_id=user_id,
            event_type='action_requested',
            investigation_id=investigation_id,
            session_id=session_id,
            username=username,
            action_type=action_type,
            action_target=action_target
        )

    # =========================================================================
    # ACTION AUDIT
    # =========================================================================

    async def create_action_audit(
        self,
        user_id: str,
        investigation_id: str,
        action_type: str,
        user_prompt: str,
        chat_message_id: Optional[str] = None,
        username: Optional[str] = None,
        action_target_type: Optional[str] = None,
        action_target_value: Optional[str] = None,
        action_parameters: Optional[Dict] = None,
        agent_tier: Optional[int] = None,
        agent_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Create an action audit record when user requests an action through chat.
        Returns the audit ID.
        """
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id) if investigation_id else None

            async with self._postgres.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                row = await conn.fetchrow('''
                    INSERT INTO chat_action_audit (
                        chat_message_id, investigation_id, user_id, username,
                        action_type, action_target_type, action_target_value,
                        action_parameters, agent_tier, agent_id, user_prompt, status, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'requested', $12)
                    RETURNING id
                ''',
                    uuid.UUID(chat_message_id) if chat_message_id else None,
                    inv_uuid,
                    user_id,
                    username,
                    action_type,
                    action_target_type,
                    action_target_value,
                    json.dumps(action_parameters or {}),
                    agent_tier,
                    agent_id,
                    user_prompt,
                    _tid
                )
                return str(row['id']) if row else None
        except Exception as e:
            logger.error(f"Error creating action audit: {e}")
            return None

    async def update_action_audit_status(
        self,
        audit_id: str,
        status: str,
        action_request_id: Optional[str] = None,
        approved_by: Optional[str] = None,
        denial_reason: Optional[str] = None,
        execution_result: Optional[Dict] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """Update the status of an action audit record."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                updates = ["status = $2", "updated_at = CURRENT_TIMESTAMP"]
                params = [uuid.UUID(audit_id), status]
                idx = 3

                if action_request_id:
                    updates.append(f"action_request_id = ${idx}")
                    params.append(action_request_id)
                    idx += 1

                if approved_by:
                    updates.append(f"approved_by = ${idx}")
                    params.append(approved_by)
                    idx += 1
                    updates.append(f"approved_at = CURRENT_TIMESTAMP")

                if denial_reason:
                    updates.append(f"denial_reason = ${idx}")
                    params.append(denial_reason)
                    idx += 1

                if execution_result:
                    updates.append(f"execution_result = ${idx}")
                    params.append(json.dumps(execution_result))
                    idx += 1
                    updates.append(f"executed_at = CURRENT_TIMESTAMP")

                if error_message:
                    updates.append(f"error_message = ${idx}")
                    params.append(error_message)
                    idx += 1

                query = f"UPDATE chat_action_audit SET {', '.join(updates)} WHERE id = $1"
                await conn.execute(query, *params)
                return True
        except Exception as e:
            logger.error(f"Error updating action audit: {e}")
            return False

    # =========================================================================
    # ANALYTICS QUERIES
    # =========================================================================

    async def get_user_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get chat usage statistics for a specific user."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT * FROM user_chat_statistics WHERE user_id = $1
                ''', user_id)

                if not row:
                    return {
                        'user_id': user_id,
                        'total_messages': 0,
                        'quick_actions_used': 0,
                        'actions_requested': 0,
                        'investigations_participated': 0,
                        'total_sessions': 0
                    }

                return dict(row)
        except Exception as e:
            logger.error(f"Error getting user statistics: {e}")
            return {}

    async def get_all_user_statistics(
        self,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = 'total_messages',
        order: str = 'DESC'
    ) -> List[Dict]:
        """Get chat statistics for all users."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                # Validate sort column
                valid_sorts = ['total_messages', 'quick_actions_used', 'actions_requested',
                              'investigations_participated', 'total_sessions', 'last_activity']
                if sort_by not in valid_sorts:
                    sort_by = 'total_messages'

                order = 'DESC' if order.upper() == 'DESC' else 'ASC'

                rows = await conn.fetch(f'''
                    SELECT * FROM user_chat_statistics
                    ORDER BY {sort_by} {order} NULLS LAST
                    LIMIT $1 OFFSET $2
                ''', limit, offset)

                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting all user statistics: {e}")
            return []

    async def get_user_conversation_history(
        self,
        user_id: str,
        investigation_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """Get a user's conversation history (their sent messages)."""
        try:
            # Resolve investigation_id to UUID if provided
            inv_uuid = await self._resolve_investigation_uuid(investigation_id) if investigation_id else None

            async with self._postgres.tenant_acquire() as conn:
                query = '''
                    SELECT
                        ic.id, ic.investigation_id, ic.message, ic.message_type,
                        ic.metadata, ic.created_at,
                        i.title as investigation_title
                    FROM investigation_chat ic
                    LEFT JOIN investigations i ON ic.investigation_id = i.id
                    WHERE ic.sender_id = $1 AND ic.sender_type = 'human'
                '''
                params = [user_id]

                if inv_uuid:
                    params.append(inv_uuid)
                    query += f' AND ic.investigation_id = ${len(params)}'

                query += f' ORDER BY ic.created_at DESC LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}'
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)

                return [
                    {
                        'id': str(row['id']),
                        'investigation_id': str(row['investigation_id']) if row['investigation_id'] else None,
                        'investigation_title': row['investigation_title'],
                        'message': row['message'],
                        'message_type': row['message_type'],
                        'metadata': json.loads(row['metadata']) if isinstance(row['metadata'], str) else row['metadata'],
                        'created_at': row['created_at'].isoformat() if row['created_at'] else None
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Error getting user conversation history: {e}")
            return []

    async def get_user_action_history(
        self,
        user_id: str,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """Get a user's action request history from chat."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                query = '''
                    SELECT
                        caa.*,
                        i.title as investigation_title
                    FROM chat_action_audit caa
                    LEFT JOIN investigations i ON caa.investigation_id = i.id
                    WHERE caa.user_id = $1
                '''
                params = [user_id]

                if status:
                    params.append(status)
                    query += f' AND caa.status = ${len(params)}'

                query += f' ORDER BY caa.created_at DESC LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}'
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)

                return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting user action history: {e}")
            return []

    async def get_chat_activity_summary(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get overall chat activity summary for the past N days."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)

                # Total events by type
                event_counts = await conn.fetch('''
                    SELECT event_type, COUNT(*) as count
                    FROM chat_usage_analytics
                    WHERE created_at > $1
                    GROUP BY event_type
                ''', cutoff)

                # Active users
                active_users = await conn.fetchval('''
                    SELECT COUNT(DISTINCT user_id)
                    FROM chat_usage_analytics
                    WHERE created_at > $1
                ''', cutoff)

                # Active investigations
                active_investigations = await conn.fetchval('''
                    SELECT COUNT(DISTINCT investigation_id)
                    FROM chat_usage_analytics
                    WHERE created_at > $1 AND investigation_id IS NOT NULL
                ''', cutoff)

                # Action requests
                action_stats = await conn.fetch('''
                    SELECT status, COUNT(*) as count
                    FROM chat_action_audit
                    WHERE created_at > $1
                    GROUP BY status
                ''', cutoff)

                # Top quick actions
                top_quick_actions = await conn.fetch('''
                    SELECT quick_action_category, quick_action_label, COUNT(*) as count
                    FROM chat_usage_analytics
                    WHERE event_type = 'quick_action_used' AND created_at > $1
                    GROUP BY quick_action_category, quick_action_label
                    ORDER BY count DESC
                    LIMIT 10
                ''', cutoff)

                # Daily activity trend
                daily_activity = await conn.fetch('''
                    SELECT DATE(created_at) as date, COUNT(*) as messages
                    FROM chat_usage_analytics
                    WHERE event_type = 'message_sent' AND created_at > $1
                    GROUP BY DATE(created_at)
                    ORDER BY date
                ''', cutoff)

                return {
                    'period_days': days,
                    'active_users': active_users or 0,
                    'active_investigations': active_investigations or 0,
                    'events_by_type': {row['event_type']: row['count'] for row in event_counts},
                    'action_requests_by_status': {row['status']: row['count'] for row in action_stats},
                    'top_quick_actions': [
                        {
                            'category': row['quick_action_category'],
                            'label': row['quick_action_label'],
                            'count': row['count']
                        }
                        for row in top_quick_actions
                    ],
                    'daily_activity': [
                        {'date': row['date'].isoformat(), 'messages': row['messages']}
                        for row in daily_activity
                    ]
                }
        except Exception as e:
            logger.error(f"Error getting chat activity summary: {e}")
            return {}

    def _row_to_dict(self, row) -> Dict:
        """Convert a database row to a dictionary."""
        if not row:
            return {}

        result = dict(row)

        # Convert UUIDs
        for key in ['id', 'chat_message_id', 'investigation_id']:
            if key in result and result[key]:
                result[key] = str(result[key])

        # Parse JSON fields
        for key in ['action_parameters', 'execution_result', 'metadata']:
            if key in result and result[key]:
                if isinstance(result[key], str):
                    try:
                        result[key] = json.loads(result[key])
                    except:
                        pass

        # Convert timestamps
        for key in ['created_at', 'updated_at', 'approved_at', 'executed_at']:
            if key in result and result[key]:
                result[key] = result[key].isoformat()

        return result


# Singleton instance
_chat_analytics_service: Optional[ChatAnalyticsService] = None


def get_chat_analytics_service() -> ChatAnalyticsService:
    """Get the chat analytics service singleton."""
    global _chat_analytics_service
    if _chat_analytics_service is None:
        raise RuntimeError("ChatAnalyticsService not initialized")
    return _chat_analytics_service


async def init_chat_analytics_service(postgres_service) -> ChatAnalyticsService:
    """Initialize the chat analytics service singleton."""
    global _chat_analytics_service
    _chat_analytics_service = ChatAnalyticsService(postgres_service)
    await _chat_analytics_service.initialize()
    return _chat_analytics_service
