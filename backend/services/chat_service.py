# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Chat Service - Phase 6
Real-time chat for investigations between analysts and AI agents.

Supports:
- Message CRUD operations
- Message types (text, actions, enrichments, findings)
- Read tracking
- Typing indicators
- Agent message streaming
"""

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class SenderType(Enum):
    HUMAN = 'human'
    AGENT_T1 = 'agent_t1'
    AGENT_T2 = 'agent_t2'
    AGENT_T3 = 'agent_t3'
    SYSTEM = 'system'
    INTEGRATION = 'integration'


class MessageType(Enum):
    TEXT = 'text'
    ACTION_REQUEST = 'action_request'
    ACTION_RESULT = 'action_result'
    FIELD_UPDATE = 'field_update'
    STATUS_CHANGE = 'status_change'
    ENRICHMENT = 'enrichment'
    FINDING = 'finding'
    RECOMMENDATION = 'recommendation'
    QUESTION = 'question'
    SYSTEM = 'system'
    ERROR = 'error'


class ChatService:
    """
    Service for managing investigation chat messages.
    """

    def __init__(self, postgres_service):
        self._postgres = postgres_service
        self._message_handlers = []  # Callbacks for new messages (WebSocket broadcast)

    @asynccontextmanager
    async def _tenant_conn(self):
        """
        Acquire a DB connection with tenant context for RLS.

        WebSocket connections bypass TenantMiddleware, so the ContextVar may be
        set manually by the chat handler. This helper reads it and applies
        SET app.current_tenant_id on the connection so RLS policies work.
        """
        from middleware.tenant_middleware import get_optional_tenant_id
        tenant_id = get_optional_tenant_id()
        async with self._postgres.tenant_acquire() as conn:
            if tenant_id:
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, false)",
                    str(tenant_id)
                )
            try:
                yield conn
            finally:
                if tenant_id:
                    try:
                        await conn.execute("RESET app.current_tenant_id")
                    except Exception:
                        pass

    async def initialize(self):
        """Initialize the chat service."""
        logger.info("ChatService initialized")

    def register_message_handler(self, handler):
        """Register a callback for new messages (used by WebSocket handler)."""
        self._message_handlers.append(handler)

    def unregister_message_handler(self, handler):
        """Unregister a message handler."""
        if handler in self._message_handlers:
            self._message_handlers.remove(handler)

    async def _notify_handlers(self, investigation_id: str, message: Dict):
        """Notify all registered handlers of a new message."""
        for handler in self._message_handlers:
            try:
                await handler(investigation_id, message)
            except Exception as e:
                logger.error(f"Error notifying message handler: {e}")

    async def _resolve_investigation_uuid(self, investigation_id: str) -> Optional[uuid.UUID]:
        """
        Resolve an investigation identifier to its UUID.

        The investigation_id can be either:
        - A UUID string (the internal id)
        - A human-readable ID like 'INV-20251222-F461587D' (the investigation_id column)

        Returns the UUID or None if not found.
        """
        try:
            # First try parsing as UUID directly
            return uuid.UUID(investigation_id)
        except (ValueError, AttributeError):
            # Not a UUID, look up by investigation_id string
            pass

        try:
            async with self._tenant_conn() as conn:
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
    # MESSAGE CRUD
    # =========================================================================

    async def send_message(
        self,
        investigation_id: str,
        sender_type: str,
        sender_id: str,
        sender_name: str,
        message: str,
        message_type: str = 'text',
        metadata: Optional[Dict] = None,
        parent_message_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send a new chat message.

        Returns the created message with ID.
        """
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return {'success': False, 'error': 'Investigation not found'}

            async with self._tenant_conn() as conn:
                # Insert message
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                row = await conn.fetchrow('''
                    INSERT INTO investigation_chat (
                        investigation_id, sender_type, sender_id, sender_name,
                        message, message_type, metadata, parent_message_id, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING *
                ''',
                    inv_uuid,
                    sender_type,
                    sender_id,
                    sender_name,
                    message,
                    message_type,
                    json.dumps(metadata or {}),
                    uuid.UUID(parent_message_id) if parent_message_id else None,
                    _tid
                )

                msg = self._row_to_dict(row)

                # Notify WebSocket handlers
                await self._notify_handlers(investigation_id, msg)

                logger.debug(f"Chat message sent: {msg['id']} in {investigation_id}")

                return {'success': True, 'message': msg}

        except Exception as e:
            logger.error(f"Error sending chat message: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    async def get_messages(
        self,
        investigation_id: str,
        limit: int = 100,
        before_id: Optional[str] = None,
        after_id: Optional[str] = None,
        message_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Get chat messages for an investigation.

        Supports pagination via before_id/after_id and filtering by message_type.
        """
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return []

            async with self._tenant_conn() as conn:
                query = '''
                    SELECT * FROM investigation_chat
                    WHERE investigation_id = $1
                '''
                params = [inv_uuid]

                if before_id:
                    # Get messages before a specific message (older)
                    params.append(uuid.UUID(before_id))
                    query += f' AND created_at < (SELECT created_at FROM investigation_chat WHERE id = ${len(params)})'

                if after_id:
                    # Get messages after a specific message (newer)
                    params.append(uuid.UUID(after_id))
                    query += f' AND created_at > (SELECT created_at FROM investigation_chat WHERE id = ${len(params)})'

                if message_type:
                    params.append(message_type)
                    query += f' AND message_type = ${len(params)}'

                query += ' ORDER BY created_at DESC'
                params.append(limit)
                query += f' LIMIT ${len(params)}'

                rows = await conn.fetch(query, *params)

                # Return in chronological order (reverse the DESC)
                messages = [self._row_to_dict(row) for row in reversed(rows)]

                return messages

        except Exception as e:
            logger.error(f"Error getting chat messages: {e}", exc_info=True)
            return []

    async def get_message_by_id(self, message_id: str) -> Optional[Dict]:
        """Get a single message by ID."""
        try:
            async with self._tenant_conn() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM investigation_chat WHERE id = $1",
                    uuid.UUID(message_id)
                )
                return self._row_to_dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting message: {e}")
            return None

    async def update_message(
        self,
        message_id: str,
        message: Optional[str] = None,
        metadata: Optional[Dict] = None,
        is_streaming: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Update a message (for streaming updates or edits).
        """
        try:
            async with self._tenant_conn() as conn:
                updates = []
                params = [uuid.UUID(message_id)]
                idx = 2

                if message is not None:
                    updates.append(f"message = ${idx}")
                    params.append(message)
                    idx += 1

                if metadata is not None:
                    updates.append(f"metadata = ${idx}")
                    params.append(json.dumps(metadata))
                    idx += 1

                if is_streaming is not None:
                    updates.append(f"is_streaming = ${idx}")
                    params.append(is_streaming)
                    idx += 1

                if not updates:
                    return {'success': False, 'error': 'No updates provided'}

                query = f'''
                    UPDATE investigation_chat
                    SET {', '.join(updates)}
                    WHERE id = $1
                    RETURNING *
                '''

                row = await conn.fetchrow(query, *params)

                if not row:
                    return {'success': False, 'error': 'Message not found'}

                msg = self._row_to_dict(row)

                # Notify handlers of update
                await self._notify_handlers(str(row['investigation_id']), {
                    **msg,
                    '_event': 'message_updated'
                })

                return {'success': True, 'message': msg}

        except Exception as e:
            logger.error(f"Error updating message: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    async def _delete_message_internal(self, message_id: str) -> Dict[str, Any]:
        """
        Internal method to delete a message (for system use only).
        Note: Public message deletion is disabled for audit compliance.
        All chat messages are retained as part of the investigation audit trail.
        """
        try:
            async with self._tenant_conn() as conn:
                row = await conn.fetchrow(
                    "DELETE FROM investigation_chat WHERE id = $1 RETURNING investigation_id",
                    uuid.UUID(message_id)
                )

                if not row:
                    return {'success': False, 'error': 'Message not found'}

                # Notify handlers
                await self._notify_handlers(str(row['investigation_id']), {
                    'id': message_id,
                    '_event': 'message_deleted'
                })

                return {'success': True}

        except Exception as e:
            logger.error(f"Error deleting message: {e}")
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # READ TRACKING
    # =========================================================================

    async def mark_messages_read(
        self,
        investigation_id: str,
        user_id: str,
        up_to_message_id: Optional[str] = None
    ) -> int:
        """
        Mark messages as read by a user.

        If up_to_message_id is provided, marks all messages up to and including that ID.
        Otherwise marks all messages in the investigation.

        Returns count of messages marked.
        """
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return 0

            async with self._tenant_conn() as conn:
                if up_to_message_id:
                    result = await conn.execute('''
                        UPDATE investigation_chat
                        SET read_by = array_append(read_by, $1)
                        WHERE investigation_id = $2
                          AND created_at <= (SELECT created_at FROM investigation_chat WHERE id = $3)
                          AND NOT ($1 = ANY(read_by))
                    ''',
                        user_id,
                        inv_uuid,
                        uuid.UUID(up_to_message_id)
                    )
                else:
                    result = await conn.execute('''
                        UPDATE investigation_chat
                        SET read_by = array_append(read_by, $1)
                        WHERE investigation_id = $2
                          AND NOT ($1 = ANY(read_by))
                    ''',
                        user_id,
                        inv_uuid
                    )

                count = int(result.split()[-1]) if result else 0
                return count

        except Exception as e:
            logger.error(f"Error marking messages read: {e}")
            return 0

    async def get_unread_count(self, investigation_id: str, user_id: str) -> int:
        """Get count of unread messages for a user."""
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return 0

            async with self._tenant_conn() as conn:
                count = await conn.fetchval('''
                    SELECT COUNT(*) FROM investigation_chat
                    WHERE investigation_id = $1
                      AND NOT ($2 = ANY(read_by))
                ''',
                    inv_uuid,
                    user_id
                )
                return count or 0

        except Exception as e:
            logger.error(f"Error getting unread count: {e}")
            return 0

    # =========================================================================
    # TYPING INDICATORS
    # =========================================================================

    async def set_typing(
        self,
        investigation_id: str,
        user_id: str,
        user_name: str,
        is_agent: bool = False
    ) -> bool:
        """Set typing indicator for a user."""
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return False

            async with self._tenant_conn() as conn:
                await conn.execute('''
                    INSERT INTO chat_typing_status (investigation_id, user_id, user_name, is_agent, started_at, expires_at)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '10 seconds')
                    ON CONFLICT (investigation_id, user_id)
                    DO UPDATE SET started_at = CURRENT_TIMESTAMP, expires_at = CURRENT_TIMESTAMP + INTERVAL '10 seconds'
                ''',
                    inv_uuid,
                    user_id,
                    user_name,
                    is_agent
                )

                # Notify handlers
                await self._notify_handlers(investigation_id, {
                    '_event': 'typing_start',
                    'user_id': user_id,
                    'user_name': user_name,
                    'is_agent': is_agent
                })

                return True

        except Exception as e:
            logger.error(f"Error setting typing status: {e}")
            return False

    async def clear_typing(self, investigation_id: str, user_id: str) -> bool:
        """Clear typing indicator for a user."""
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return False

            async with self._tenant_conn() as conn:
                await conn.execute('''
                    DELETE FROM chat_typing_status
                    WHERE investigation_id = $1 AND user_id = $2
                ''',
                    inv_uuid,
                    user_id
                )

                # Notify handlers
                await self._notify_handlers(investigation_id, {
                    '_event': 'typing_stop',
                    'user_id': user_id
                })

                return True

        except Exception as e:
            logger.error(f"Error clearing typing status: {e}")
            return False

    async def get_typing_users(self, investigation_id: str) -> List[Dict]:
        """Get users currently typing in a chat."""
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return []

            async with self._tenant_conn() as conn:
                rows = await conn.fetch('''
                    SELECT user_id, user_name, is_agent, started_at
                    FROM chat_typing_status
                    WHERE investigation_id = $1 AND expires_at > CURRENT_TIMESTAMP
                ''',
                    inv_uuid
                )

                return [
                    {
                        'user_id': row['user_id'],
                        'user_name': row['user_name'],
                        'is_agent': row['is_agent'],
                        'started_at': row['started_at'].isoformat() if row['started_at'] else None
                    }
                    for row in rows
                ]

        except Exception as e:
            logger.error(f"Error getting typing users: {e}")
            return []

    async def cleanup_expired_typing(self) -> int:
        """Cleanup expired typing indicators."""
        try:
            async with self._tenant_conn() as conn:
                result = await conn.execute('''
                    DELETE FROM chat_typing_status WHERE expires_at < CURRENT_TIMESTAMP
                ''')
                count = int(result.split()[-1]) if result else 0
                return count
        except Exception as e:
            logger.error(f"Error cleaning up typing status: {e}")
            return 0

    # =========================================================================
    # AGENT HELPER METHODS
    # =========================================================================

    async def send_agent_message(
        self,
        investigation_id: str,
        agent_id: str,
        agent_name: str,
        agent_tier: int,
        message: str,
        message_type: str = 'text',
        metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Convenience method for agents to send messages.
        """
        sender_type = f'agent_t{agent_tier}' if agent_tier in [1, 2, 3] else 'agent_t1'

        return await self.send_message(
            investigation_id=investigation_id,
            sender_type=sender_type,
            sender_id=agent_id,
            sender_name=agent_name,
            message=message,
            message_type=message_type,
            metadata=metadata
        )

    async def send_system_message(
        self,
        investigation_id: str,
        message: str,
        message_type: str = 'system',
        metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Send a system-generated message.
        """
        return await self.send_message(
            investigation_id=investigation_id,
            sender_type='system',
            sender_id='system',
            sender_name='System',
            message=message,
            message_type=message_type,
            metadata=metadata
        )

    async def send_finding(
        self,
        investigation_id: str,
        agent_id: str,
        agent_name: str,
        agent_tier: int,
        finding: str,
        confidence: float = 0.0,
        evidence: Optional[List] = None
    ) -> Dict[str, Any]:
        """
        Send a finding message from an agent.
        """
        return await self.send_agent_message(
            investigation_id=investigation_id,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_tier=agent_tier,
            message=finding,
            message_type='finding',
            metadata={
                'confidence': confidence,
                'evidence': evidence or []
            }
        )

    async def send_recommendation(
        self,
        investigation_id: str,
        agent_id: str,
        agent_name: str,
        agent_tier: int,
        recommendation: str,
        action_type: Optional[str] = None,
        target: Optional[str] = None,
        confidence: float = 0.0
    ) -> Dict[str, Any]:
        """
        Send a recommendation message from an agent.
        """
        return await self.send_agent_message(
            investigation_id=investigation_id,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_tier=agent_tier,
            message=recommendation,
            message_type='recommendation',
            metadata={
                'action_type': action_type,
                'target': target,
                'confidence': confidence
            }
        )

    async def send_action_request_notification(
        self,
        investigation_id: str,
        agent_id: str,
        agent_name: str,
        agent_tier: int,
        action_type: str,
        target: str,
        request_id: str,
        reasoning: str
    ) -> Dict[str, Any]:
        """
        Send a notification that an action has been requested.
        """
        return await self.send_agent_message(
            investigation_id=investigation_id,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_tier=agent_tier,
            message=f"I've requested a **{action_type.replace('_', ' ')}** action on `{target}`. {reasoning}",
            message_type='action_request',
            metadata={
                'action_type': action_type,
                'target': target,
                'request_id': request_id
            }
        )

    # =========================================================================
    # CHAT HISTORY & STATS
    # =========================================================================

    async def get_chat_stats(self, investigation_id: str) -> Dict[str, Any]:
        """Get chat statistics for an investigation."""
        try:
            # Resolve investigation_id to UUID
            inv_uuid = await self._resolve_investigation_uuid(investigation_id)
            if not inv_uuid:
                return {}

            async with self._tenant_conn() as conn:
                stats = {}

                # Total messages
                stats['total_messages'] = await conn.fetchval('''
                    SELECT COUNT(*) FROM investigation_chat WHERE investigation_id = $1
                ''', inv_uuid)

                # By sender type
                rows = await conn.fetch('''
                    SELECT sender_type, COUNT(*) as count
                    FROM investigation_chat
                    WHERE investigation_id = $1
                    GROUP BY sender_type
                ''', inv_uuid)
                stats['by_sender_type'] = {row['sender_type']: row['count'] for row in rows}

                # By message type
                rows = await conn.fetch('''
                    SELECT message_type, COUNT(*) as count
                    FROM investigation_chat
                    WHERE investigation_id = $1
                    GROUP BY message_type
                ''', inv_uuid)
                stats['by_message_type'] = {row['message_type']: row['count'] for row in rows}

                # First and last message
                first = await conn.fetchval('''
                    SELECT created_at FROM investigation_chat
                    WHERE investigation_id = $1
                    ORDER BY created_at ASC LIMIT 1
                ''', inv_uuid)
                last = await conn.fetchval('''
                    SELECT created_at FROM investigation_chat
                    WHERE investigation_id = $1
                    ORDER BY created_at DESC LIMIT 1
                ''', inv_uuid)

                stats['first_message'] = first.isoformat() if first else None
                stats['last_message'] = last.isoformat() if last else None

                return stats

        except Exception as e:
            logger.error(f"Error getting chat stats: {e}")
            return {}

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _row_to_dict(self, row) -> Dict:
        """Convert database row to dict with proper types."""
        if not row:
            return {}

        result = dict(row)

        # Convert UUIDs
        for key in ['id', 'investigation_id', 'parent_message_id']:
            if key in result and result[key]:
                result[key] = str(result[key])

        # Parse JSON
        if 'metadata' in result and result['metadata']:
            if isinstance(result['metadata'], str):
                try:
                    result['metadata'] = json.loads(result['metadata'])
                except:
                    pass

        # Convert datetimes
        if 'created_at' in result and result['created_at']:
            result['created_at'] = result['created_at'].isoformat()

        return result


# Singleton instance
_chat_service: Optional[ChatService] = None


def get_chat_service() -> ChatService:
    """Get the chat service singleton."""
    global _chat_service
    if _chat_service is None:
        raise RuntimeError("ChatService not initialized. Call init_chat_service first.")
    return _chat_service


async def init_chat_service(postgres_service) -> ChatService:
    """Initialize the chat service singleton."""
    global _chat_service
    _chat_service = ChatService(postgres_service)
    await _chat_service.initialize()
    return _chat_service
