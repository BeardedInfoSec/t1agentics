# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Audit Logging Utility

Immutable audit log for all system actions.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
import logging
import json

from sqlalchemy.ext.asyncio import AsyncSession

from ..database import AuditEvent, AuditAction, AuditCategory, ActorType
from ..rbac import RequestContext

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Audit logger that writes to the immutable audit_events table.
    
    Usage:
        audit = AuditLogger(db, ctx)
        await audit.log(
            action=AuditAction.FILE_UPLOADED,
            resource_type='file',
            resource_id=file_id,
            summary=f"Uploaded file: {filename}",
            after={'filename': filename, 'size': size}
        )
    """
    
    def __init__(self, db: AsyncSession, ctx: Optional[RequestContext] = None):
        self.db = db
        self.ctx = ctx
    
    async def log(
        self,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        resource_display: Optional[str] = None,
        summary: Optional[str] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        outcome: str = 'success',
        error_message: Optional[str] = None,
        # Override actor if needed (e.g., for system events)
        actor_type: Optional[str] = None,
        actor_id: Optional[UUID] = None,
        actor_display: Optional[str] = None,
        # Override tenant if needed
        tenant_id: Optional[UUID] = None,
    ) -> UUID:
        """
        Write an audit event to the log.
        
        Args:
            action: The action being audited (use AuditAction constants)
            resource_type: Type of resource being acted upon
            resource_id: ID of the resource
            resource_display: Human-readable identifier for the resource
            summary: Brief description of the event
            before: State before the change (for updates)
            after: State after the change
            metadata: Additional context
            outcome: success, failure, or denied
            error_message: Error message if failed
            actor_type: Override actor type (user, system, service)
            actor_id: Override actor ID
            actor_display: Override actor display name
            tenant_id: Override tenant ID
            
        Returns:
            The ID of the created audit event
        """
        event_id = uuid4()
        
        # Determine actor
        if actor_type is None and self.ctx and self.ctx.user:
            actor_type = ActorType.USER
            actor_id = self.ctx.user.user_id
            actor_display = self.ctx.user.email
        elif actor_type is None:
            actor_type = ActorType.SYSTEM
            actor_display = 'system'
        
        # Determine tenant
        if tenant_id is None and self.ctx:
            tenant_id = self.ctx.tenant.tenant_id
        
        if tenant_id is None:
            raise ValueError("tenant_id is required for audit logging")
        
        # Determine category from action
        category = self._get_category(action)
        
        # Create the audit event
        event = AuditEvent(
            id=event_id,
            tenant_id=tenant_id,
            event_time=datetime.utcnow(),
            actor_type=actor_type,
            actor_id=actor_id,
            actor_display=actor_display,
            actor_ip=self.ctx.ip_address if self.ctx else None,
            actor_user_agent=self.ctx.user_agent if self.ctx else None,
            action=action,
            category=category,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_display=resource_display,
            summary=summary,
            before_state=before,
            after_state=after,
            metadata=metadata,
            correlation_id=self.ctx.correlation_id if self.ctx else None,
            request_id=self.ctx.request_id if self.ctx else None,
            outcome=outcome,
            error_message=error_message,
        )
        
        self.db.add(event)
        
        # Log to application logger as well
        log_level = logging.INFO if outcome == 'success' else logging.WARNING
        logger.log(
            log_level,
            f"AUDIT: {action} | {resource_type}:{resource_id} | "
            f"actor={actor_display} | outcome={outcome} | {summary}"
        )
        
        return event_id
    
    async def log_auth(
        self,
        action: str,
        user_email: str,
        success: bool,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[UUID] = None,
    ) -> UUID:
        """Log authentication events."""
        return await self.log(
            action=action,
            resource_type='user',
            resource_display=user_email,
            summary=f"Authentication {'successful' if success else 'failed'} for {user_email}",
            outcome='success' if success else 'failure',
            error_message=error_message,
            metadata=metadata,
            actor_type=ActorType.USER,
            actor_display=user_email,
            tenant_id=tenant_id,
        )
    
    async def log_change(
        self,
        action: str,
        resource_type: str,
        resource_id: UUID,
        before: Dict[str, Any],
        after: Dict[str, Any],
        resource_display: Optional[str] = None,
    ) -> UUID:
        """Log a change event with before/after states."""
        # Compute changes
        changes = {}
        for key in set(list(before.keys()) + list(after.keys())):
            old_val = before.get(key)
            new_val = after.get(key)
            if old_val != new_val:
                changes[key] = {'from': old_val, 'to': new_val}
        
        return await self.log(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_display=resource_display,
            summary=f"Updated {resource_type}: {list(changes.keys())}",
            before=before,
            after=after,
            metadata={'changes': changes},
        )
    
    async def log_denied(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[UUID] = None,
        reason: str = "Permission denied",
    ) -> UUID:
        """Log a denied access attempt."""
        return await self.log(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            summary=f"Access denied: {reason}",
            outcome='denied',
            error_message=reason,
        )
    
    def _get_category(self, action: str) -> str:
        """Determine category from action name."""
        if action.startswith('login') or action.startswith('logout') or action.startswith('password') or action.startswith('mfa'):
            return AuditCategory.AUTH
        elif action.startswith('role') or action.startswith('permission'):
            return AuditCategory.RBAC
        elif action.startswith('user'):
            return AuditCategory.USER
        elif action.startswith('retention') or action.startswith('setting'):
            return AuditCategory.SETTINGS
        elif action.startswith('investigation'):
            return AuditCategory.INVESTIGATION
        elif action.startswith('alert'):
            return AuditCategory.ALERT
        elif action.startswith('note'):
            return AuditCategory.NOTE
        elif action.startswith('file'):
            return AuditCategory.FILE
        elif action.startswith('action'):
            return AuditCategory.ACTION
        elif action.startswith('integration'):
            return AuditCategory.INTEGRATION
        else:
            return AuditCategory.SYSTEM


# Convenience function for one-off audit logs
async def audit(
    db: AsyncSession,
    ctx: Optional[RequestContext],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[UUID] = None,
    summary: Optional[str] = None,
    before: Optional[Dict[str, Any]] = None,
    after: Optional[Dict[str, Any]] = None,
    **kwargs
) -> UUID:
    """
    Convenience function to log an audit event.
    
    Usage:
        await audit(
            db, ctx,
            action=AuditAction.FILE_UPLOADED,
            resource_type='file',
            resource_id=file_id,
            summary=f"Uploaded {filename}"
        )
    """
    logger_instance = AuditLogger(db, ctx)
    return await logger_instance.log(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        summary=summary,
        before=before,
        after=after,
        **kwargs
    )
