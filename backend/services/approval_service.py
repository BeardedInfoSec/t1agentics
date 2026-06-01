# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Approval Service
Handles approval workflow tokens with TTL, one-time use, and optional authentication
"""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ApprovalAction(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    USED = "used"


@dataclass
class ApprovalToken:
    """Approval token configuration"""
    token_id: str
    token_secret: str  # The actual token value used in URLs
    action_type: str   # escalation, investigation_close, etc.
    entity_type: str   # alert, investigation, case
    entity_id: str     # The alert/investigation/case ID
    action: ApprovalAction  # approve or reject
    ttl_minutes: int = 60
    require_auth: bool = False  # If true, user must be logged in
    used: bool = False
    used_at: Optional[datetime] = None
    used_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    created_by: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Convert datetime objects to ISO strings
        for key in ['used_at', 'expires_at', 'created_at']:
            if data[key] and isinstance(data[key], datetime):
                data[key] = data[key].isoformat()
        return data

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        # Handle both timezone-aware and naive datetimes
        now = datetime.utcnow()
        expires = self.expires_at
        # If expires_at is timezone-aware, make it naive for comparison
        if hasattr(expires, 'tzinfo') and expires.tzinfo is not None:
            expires = expires.replace(tzinfo=None)
        return now > expires

    def is_valid(self) -> bool:
        return not self.used and not self.is_expired()


class ApprovalService:
    """Service for managing approval tokens and workflows"""

    def __init__(self):
        self.db = None

    def set_db(self, db):
        """Set database connection"""
        self.db = db

    async def create_approval_pair(
        self,
        action_type: str,
        entity_type: str,
        entity_id: str,
        ttl_minutes: int = 60,
        require_auth: bool = False,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, ApprovalToken]:
        """
        Create a pair of approval tokens (approve + reject) for an action.

        Args:
            action_type: Type of action (escalation, investigation_close, etc.)
            entity_type: Entity type (alert, investigation, case)
            entity_id: Entity ID
            ttl_minutes: Token expiration in minutes (default 60)
            require_auth: Whether authentication is required to use the token
            created_by: Username who created the tokens
            metadata: Additional metadata to store with tokens

        Returns:
            Dict with 'approve' and 'reject' tokens
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=ttl_minutes)

        tokens = {}
        for action in [ApprovalAction.APPROVE, ApprovalAction.REJECT]:
            token = ApprovalToken(
                token_id=f"approval_{secrets.token_hex(8)}",
                token_secret=secrets.token_urlsafe(32),
                action_type=action_type,
                entity_type=entity_type,
                entity_id=entity_id,
                action=action,
                ttl_minutes=ttl_minutes,
                require_auth=require_auth,
                used=False,
                expires_at=expires_at,
                created_at=now,
                created_by=created_by,
                metadata=metadata or {}
            )
            tokens[action.value] = token

            # Save to database
            await self._save_token(token)

        logger.info(f"Created approval pair for {entity_type}/{entity_id}: {action_type}")
        return tokens

    async def _save_token(self, token: ApprovalToken) -> bool:
        """Save token to database"""
        if not self.db:
            logger.error("Database not set")
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                await conn.execute('''
                    INSERT INTO approval_tokens (
                        token_id, token_secret, action_type, entity_type, entity_id,
                        action, ttl_minutes, require_auth, used, used_at, used_by,
                        expires_at, created_at, created_by, metadata, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                    ON CONFLICT (token_id) DO UPDATE SET
                        used = $9,
                        used_at = $10,
                        used_by = $11
                ''',
                    token.token_id,
                    token.token_secret,
                    token.action_type,
                    token.entity_type,
                    token.entity_id,
                    token.action.value if isinstance(token.action, ApprovalAction) else token.action,
                    token.ttl_minutes,
                    token.require_auth,
                    token.used,
                    token.used_at,
                    token.used_by,
                    token.expires_at,
                    token.created_at,
                    token.created_by,
                    token.metadata if isinstance(token.metadata, str) else (
                        __import__('json').dumps(token.metadata) if token.metadata else '{}'
                    ),
                    _tid
                )
            return True
        except Exception as e:
            logger.error(f"Failed to save approval token: {e}")
            return False

    async def get_token_by_secret(self, token_secret: str) -> Optional[ApprovalToken]:
        """Get token by its secret value"""
        if not self.db:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM approval_tokens WHERE token_secret = $1",
                    token_secret
                )
                if row:
                    return self._row_to_token(row)
        except Exception as e:
            logger.error(f"Failed to get approval token: {e}")
        return None

    async def get_token_by_id(self, token_id: str) -> Optional[ApprovalToken]:
        """Get token by its ID"""
        if not self.db:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM approval_tokens WHERE token_id = $1",
                    token_id
                )
                if row:
                    return self._row_to_token(row)
        except Exception as e:
            logger.error(f"Failed to get approval token: {e}")
        return None

    async def get_pending_tokens_for_entity(
        self,
        entity_type: str,
        entity_id: str
    ) -> List[ApprovalToken]:
        """Get all pending (unused, non-expired) tokens for an entity"""
        if not self.db:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch('''
                    SELECT * FROM approval_tokens
                    WHERE entity_type = $1
                    AND entity_id = $2
                    AND used = FALSE
                    AND expires_at > NOW()
                    ORDER BY created_at DESC
                ''', entity_type, entity_id)
                return [self._row_to_token(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get pending tokens: {e}")
        return []

    async def use_token(
        self,
        token_secret: str,
        used_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Use (consume) an approval token.

        Args:
            token_secret: The token secret from the URL
            used_by: Username of who used the token (for authenticated tokens)

        Returns:
            Dict with result info:
            - success: bool
            - action: approve/reject
            - entity_type: alert/investigation/case
            - entity_id: the entity ID
            - error: error message if failed
        """
        token = await self.get_token_by_secret(token_secret)

        if not token:
            return {
                "success": False,
                "error": "Token not found",
                "code": "NOT_FOUND"
            }

        if token.used:
            return {
                "success": False,
                "error": "This link has already been used",
                "code": "ALREADY_USED",
                "used_at": token.used_at.isoformat() if token.used_at else None,
                "used_by": token.used_by
            }

        if token.is_expired():
            return {
                "success": False,
                "error": "This link has expired",
                "code": "EXPIRED",
                "expired_at": token.expires_at.isoformat() if token.expires_at else None
            }

        if token.require_auth and not used_by:
            return {
                "success": False,
                "error": "Authentication required to use this link",
                "code": "AUTH_REQUIRED"
            }

        # Mark token as used
        token.used = True
        token.used_at = datetime.utcnow()
        token.used_by = used_by

        await self._save_token(token)

        # Also invalidate the paired token (approve invalidates reject and vice versa)
        await self._invalidate_paired_token(token)

        logger.info(
            f"Approval token used: {token.action.value} for {token.entity_type}/{token.entity_id} by {used_by or 'anonymous'}"
        )

        return {
            "success": True,
            "action": token.action.value if isinstance(token.action, ApprovalAction) else token.action,
            "action_type": token.action_type,
            "entity_type": token.entity_type,
            "entity_id": token.entity_id,
            "metadata": token.metadata
        }

    async def _invalidate_paired_token(self, used_token: ApprovalToken):
        """Invalidate the paired token when one is used"""
        if not self.db:
            return

        # Determine the opposite action
        opposite_action = ApprovalAction.REJECT.value if used_token.action == ApprovalAction.APPROVE else ApprovalAction.APPROVE.value

        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE approval_tokens
                    SET used = TRUE,
                        used_at = NOW(),
                        used_by = $1
                    WHERE entity_type = $2
                    AND entity_id = $3
                    AND action_type = $4
                    AND action = $5
                    AND used = FALSE
                    AND token_id != $6
                ''',
                    f"invalidated_by_{used_token.token_id}",
                    used_token.entity_type,
                    used_token.entity_id,
                    used_token.action_type,
                    opposite_action,
                    used_token.token_id
                )
        except Exception as e:
            logger.error(f"Failed to invalidate paired token: {e}")

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens from database"""
        if not self.db:
            return 0

        try:
            async with self.db.tenant_acquire() as conn:
                result = await conn.execute('''
                    DELETE FROM approval_tokens
                    WHERE expires_at < NOW() - INTERVAL '7 days'
                ''')
                # Parse the result to get the count
                count = int(result.split()[-1]) if result else 0
                logger.info(f"Cleaned up {count} expired approval tokens")
                return count
        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens: {e}")
            return 0

    async def get_approval_history(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get approval token history"""
        if not self.db:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                if entity_type and entity_id:
                    rows = await conn.fetch('''
                        SELECT * FROM approval_tokens
                        WHERE entity_type = $1 AND entity_id = $2
                        ORDER BY created_at DESC
                        LIMIT $3
                    ''', entity_type, entity_id, limit)
                else:
                    rows = await conn.fetch('''
                        SELECT * FROM approval_tokens
                        ORDER BY created_at DESC
                        LIMIT $1
                    ''', limit)

                return [self._row_to_token(row).to_dict() for row in rows]
        except Exception as e:
            logger.error(f"Failed to get approval history: {e}")
            return []

    def _row_to_token(self, row) -> ApprovalToken:
        """Convert database row to ApprovalToken"""
        import json
        metadata = row.get('metadata', '{}')
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}

        action_value = row['action']
        action = ApprovalAction(action_value) if action_value in ['approve', 'reject'] else action_value

        return ApprovalToken(
            token_id=row['token_id'],
            token_secret=row['token_secret'],
            action_type=row['action_type'],
            entity_type=row['entity_type'],
            entity_id=row['entity_id'],
            action=action,
            ttl_minutes=row['ttl_minutes'],
            require_auth=row['require_auth'],
            used=row['used'],
            used_at=row['used_at'],
            used_by=row['used_by'],
            expires_at=row['expires_at'],
            created_at=row['created_at'],
            created_by=row['created_by'],
            metadata=metadata
        )

    def build_approval_url(
        self,
        token: ApprovalToken,
        base_url: str = "http://localhost:3000"
    ) -> str:
        """Build the approval URL for a token"""
        return f"{base_url}/approve/{token.token_secret}"


# Global instance
_approval_service: Optional[ApprovalService] = None


def get_approval_service() -> ApprovalService:
    """Get or create the global approval service instance"""
    global _approval_service
    if _approval_service is None:
        _approval_service = ApprovalService()
    return _approval_service
