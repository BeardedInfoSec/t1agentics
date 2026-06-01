# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IAM Service - Central Service for Identity Management Operations

This service provides:
1. Adapter management (connect, disconnect, health checks)
2. Approval gate integration
3. JWT invalidation triggers
4. Audit log persistence
5. Metrics and monitoring

SOC Integration Points:
- Approval workflow for high-risk actions
- Session invalidation after credential changes
- Alert correlation for IAM actions
- Playbook integration via structured responses

Author: T1 Agentics Security Team
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass, field
import uuid
import json

from .base import (
    IAMAdapter,
    IAMActionRequest,
    IAMActionResult,
    IAMActionType,
    IAMAuditEntry,
    IAMRollbackContext,
    IAMErrorCode,
)
from .openldap_adapter import OpenLDAPAdapter, OpenLDAPConfig

logger = logging.getLogger(__name__)


# =============================================================================
# Approval Integration
# =============================================================================

@dataclass
class ApprovalRequirement:
    """
    Defines when approval is required for an IAM action.

    SOC Reasoning:
    - High-risk actions (disable accounts, password reset) may need approval
    - Automated responses from playbooks might bypass approval
    - VIP/privileged accounts may always require approval
    """
    # Actions that always require approval
    require_approval_actions: set = field(default_factory=lambda: {
        IAMActionType.DISABLE_ACCOUNT,
        IAMActionType.RESET_PASSWORD,
        IAMActionType.QUARANTINE_USER,
    })

    # Actions that can be auto-approved
    auto_approve_actions: set = field(default_factory=lambda: {
        IAMActionType.VALIDATE_STATE,
        IAMActionType.FETCH_USER,
    })

    # Users/roles that can bypass approval
    approval_bypass_roles: set = field(default_factory=lambda: {
        "admin",
        "soc_lead",
        "incident_commander",
    })

    # UIDs that always require approval (VIPs)
    vip_users: set = field(default_factory=set)

    # Auto-approve if initiated by playbook with this tag
    playbook_auto_approve_tags: set = field(default_factory=lambda: {
        "automated_response",
        "high_confidence",
    })

    def requires_approval(
        self,
        action_type: IAMActionType,
        target_uid: str,
        initiated_by: str,
        initiator_role: Optional[str] = None,
        playbook_tags: Optional[List[str]] = None,
    ) -> bool:
        """
        Determine if an action requires approval.

        Decision logic:
        1. Read-only actions never need approval
        2. Admin/SOC lead roles can bypass
        3. VIP users always need approval (even for admins)
        4. High-confidence playbooks can auto-approve
        5. Otherwise, check action type
        """
        # Read-only actions don't need approval
        if action_type in self.auto_approve_actions:
            return False

        # VIP users always require approval
        if target_uid in self.vip_users:
            return True

        # Check role bypass
        if initiator_role and initiator_role.lower() in self.approval_bypass_roles:
            return False

        # Check playbook auto-approve
        if playbook_tags:
            if any(tag in self.playbook_auto_approve_tags for tag in playbook_tags):
                return False

        # Default to requiring approval for high-risk actions
        return action_type in self.require_approval_actions


@dataclass
class PendingApproval:
    """Tracks a pending approval request."""
    approval_id: str
    request: IAMActionRequest
    created_at: datetime
    expires_at: datetime
    status: str = "pending"  # pending, approved, rejected, expired
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None


# =============================================================================
# JWT Invalidation
# =============================================================================

class JWTInvalidationManager:
    """
    Manages JWT invalidation after IAM actions.

    When a user's password is reset or account is disabled, their existing
    JWTs should be invalidated to force re-authentication.

    Integration approaches:
    1. Blacklist tokens by user (recommended)
    2. Short-lived tokens + refresh token revocation
    3. Token version/generation in user record
    """

    def __init__(self):
        # In production, use Redis or database for distributed invalidation
        self._invalidated_users: Dict[str, datetime] = {}
        self._callbacks: List[Callable[[str, IAMActionType, str], Awaitable[None]]] = []

    def register_callback(self, callback: Callable[[str, IAMActionType, str], Awaitable[None]]):
        """
        Register a callback to be invoked when tokens should be invalidated.

        Callback signature: async def callback(uid: str, action_type: IAMActionType, reason: str)
        """
        self._callbacks.append(callback)

    async def invalidate_user_tokens(self, uid: str, action_type: IAMActionType, reason: str):
        """
        Invalidate all tokens for a user.

        This should be called after:
        - Password reset
        - Account disable
        - Quarantine
        - Security incidents
        """
        logger.info(f"Invalidating tokens for user {uid} - Action: {action_type.value}, Reason: {reason}")

        self._invalidated_users[uid] = datetime.now(timezone.utc)

        # Invoke registered callbacks
        for callback in self._callbacks:
            try:
                await callback(uid, action_type, reason)
            except Exception as e:
                logger.error(f"JWT invalidation callback failed: {e}")

    def is_user_invalidated_after(self, uid: str, token_issued_at: datetime) -> bool:
        """
        Check if a user's tokens issued before a certain time should be invalid.

        Use this in JWT validation middleware.
        """
        invalidation_time = self._invalidated_users.get(uid)
        if invalidation_time:
            return token_issued_at < invalidation_time
        return False

    def get_invalidation_time(self, uid: str) -> Optional[datetime]:
        """Get the invalidation timestamp for a user."""
        return self._invalidated_users.get(uid)


# =============================================================================
# Audit Log Persistence
# =============================================================================

class IAMAuditLogger:
    """
    Persists IAM audit entries for compliance and forensics.

    In production, this should:
    1. Write to tamper-evident storage
    2. Support SIEM integration
    3. Enable regulatory compliance (SOX, HIPAA, etc.)
    """

    def __init__(self, db_connection=None):
        self._db = db_connection
        self._pending_entries: List[IAMAuditEntry] = []

    async def log_action(self, audit_entry: IAMAuditEntry):
        """
        Persist an audit entry.

        In production:
        - Write to database
        - Send to SIEM
        - Trigger alerts for suspicious patterns
        """
        logger.info(
            f"IAM_AUDIT: action={audit_entry.action_type.value} "
            f"target={audit_entry.target_uid} "
            f"by={audit_entry.initiated_by} "
            f"success={audit_entry.success} "
            f"reason={audit_entry.reason}"
        )

        # Store for later persistence
        self._pending_entries.append(audit_entry)

        # In production, persist to database
        if self._db:
            await self._persist_to_db(audit_entry)

    async def _persist_to_db(self, audit_entry: IAMAuditEntry):
        """Persist audit entry to database."""
        try:
            # This would be actual database insert
            # await self._db.execute(...)
            pass
        except Exception as e:
            logger.error(f"Failed to persist audit entry: {e}")

    def get_recent_entries(self, limit: int = 100) -> List[IAMAuditEntry]:
        """Get recent audit entries (for debugging/testing)."""
        return self._pending_entries[-limit:]


# =============================================================================
# Main IAM Service
# =============================================================================

class IAMService:
    """
    Central service for IAM operations in T1 Agentics.

    Provides:
    - Adapter lifecycle management
    - Approval workflow integration
    - JWT invalidation triggers
    - Audit logging
    - Health monitoring

    Usage:
        service = get_iam_service()
        result = await service.execute_action(request)
    """

    def __init__(
        self,
        adapter: Optional[IAMAdapter] = None,
        config: Optional[OpenLDAPConfig] = None,
    ):
        """
        Initialize IAM service.

        Args:
            adapter: Pre-configured adapter (for testing/custom setups)
            config: OpenLDAP configuration (creates adapter if adapter not provided)
        """
        # Initialize adapter
        if adapter:
            self._adapter = adapter
        elif config:
            self._adapter = OpenLDAPAdapter(config)
        else:
            # Default configuration from environment
            self._adapter = self._create_default_adapter()

        # Initialize components
        self.approval_requirements = ApprovalRequirement()
        self.jwt_invalidation = JWTInvalidationManager()
        self.audit_logger = IAMAuditLogger()

        # Pending approvals (in production, use database)
        self._pending_approvals: Dict[str, PendingApproval] = {}

        # Rollback registry (stores rollback contexts for executed actions)
        self._rollback_registry: Dict[str, IAMRollbackContext] = {}

        # Metrics
        self._action_counts: Dict[str, int] = {}
        self._error_counts: Dict[str, int] = {}

    def _create_default_adapter(self) -> IAMAdapter:
        """Create adapter from environment configuration."""
        config = OpenLDAPConfig(
            host=os.getenv("LDAP_HOST", "192.168.128.106"),
            port=int(os.getenv("LDAP_PORT", "636")),
            use_ssl=os.getenv("LDAP_USE_SSL", "true").lower() == "true",
            base_dn=os.getenv("LDAP_BASE_DN", "dc=T1 Agentics,dc=local"),
            user_ou=os.getenv("LDAP_USER_OU", "ou=people,dc=T1 Agentics,dc=local"),
            group_ou=os.getenv("LDAP_GROUP_OU", "ou=groups,dc=T1 Agentics,dc=local"),
            service_account_dn=os.getenv(
                "LDAP_SERVICE_ACCOUNT_DN",
                "uid=svc_T1 Agentics,ou=service_accounts,dc=T1 Agentics,dc=local"
            ),
            service_account_password=os.getenv("LDAP_SERVICE_ACCOUNT_PASSWORD", ""),
            validate_certs=os.getenv("LDAP_VALIDATE_CERTS", "true").lower() == "true",
        )
        return OpenLDAPAdapter(config)

    @property
    def adapter(self) -> IAMAdapter:
        """Get the IAM adapter."""
        return self._adapter

    # =========================================================================
    # Connection Management
    # =========================================================================

    async def connect(self) -> bool:
        """Connect to the IAM backend."""
        return await self._adapter.connect()

    async def disconnect(self) -> None:
        """Disconnect from the IAM backend."""
        await self._adapter.disconnect()

    async def health_check(self) -> Dict[str, Any]:
        """
        Check health of IAM service.

        Returns status suitable for /health endpoints.
        """
        try:
            result = await self._adapter.test_connection()
            return {
                "status": "healthy" if result.success else "unhealthy",
                "adapter_type": self._adapter.adapter_type,
                "connected": self._adapter.is_connected,
                "message": result.message,
                "last_check": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "adapter_type": self._adapter.adapter_type,
                "connected": False,
                "error": str(e),
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

    # =========================================================================
    # Action Execution
    # =========================================================================

    async def execute_action(
        self,
        request: IAMActionRequest,
        initiator_role: Optional[str] = None,
        playbook_tags: Optional[List[str]] = None,
        force_approval: bool = False,
    ) -> IAMActionResult:
        """
        Execute an IAM action with full workflow integration.

        This is the main entry point for IAM operations. It:
        1. Checks if approval is required
        2. Creates approval request if needed
        3. Executes the action (if approved or no approval needed)
        4. Triggers JWT invalidation for credential changes
        5. Logs audit entry

        Args:
            request: The IAM action request
            initiator_role: Role of the person initiating (for approval bypass)
            playbook_tags: Tags from playbook (for auto-approve)
            force_approval: Always require approval regardless of rules

        Returns:
            IAMActionResult with full details
        """
        # Track metrics
        action_key = request.action_type.value
        self._action_counts[action_key] = self._action_counts.get(action_key, 0) + 1

        # Check if approval is required
        needs_approval = force_approval or (
            request.require_approval or
            self.approval_requirements.requires_approval(
                action_type=request.action_type,
                target_uid=request.target_uid,
                initiated_by=request.initiated_by,
                initiator_role=initiator_role,
                playbook_tags=playbook_tags,
            )
        )

        # If approval required and not pre-approved, create pending approval
        if needs_approval and not request.approval_id:
            return await self._create_pending_approval(request)

        # If has approval_id, verify it's valid
        if request.approval_id:
            approval_valid = await self._verify_approval(request.approval_id, request)
            if not approval_valid:
                return IAMActionResult.failure(
                    error_code=IAMErrorCode.INSUFFICIENT_PERMISSIONS,
                    message=f"Invalid or expired approval: {request.approval_id}",
                )

        # Execute the action
        result = await self._execute_adapter_action(request)

        # Post-action processing
        if result.success:
            # Trigger JWT invalidation for credential-affecting actions
            if request.action_type in {
                IAMActionType.DISABLE_ACCOUNT,
                IAMActionType.RESET_PASSWORD,
                IAMActionType.QUARANTINE_USER,
            }:
                await self.jwt_invalidation.invalidate_user_tokens(
                    uid=request.target_uid,
                    action_type=request.action_type,
                    reason=request.reason,
                )

            # Store rollback context
            if result.rollback_context:
                rollback_id = result.audit.audit_id if result.audit else str(uuid.uuid4())
                self._rollback_registry[rollback_id] = result.rollback_context

        # Log audit entry
        if result.audit:
            await self.audit_logger.log_action(result.audit)

        # Track errors
        if not result.success:
            error_key = result.error_code.value
            self._error_counts[error_key] = self._error_counts.get(error_key, 0) + 1

        return result

    async def _execute_adapter_action(self, request: IAMActionRequest) -> IAMActionResult:
        """Execute action on the adapter."""
        try:
            if request.action_type == IAMActionType.DISABLE_ACCOUNT:
                return await self._adapter.disable_account(request)

            elif request.action_type == IAMActionType.ENABLE_ACCOUNT:
                return await self._adapter.enable_account(request)

            elif request.action_type == IAMActionType.RESET_PASSWORD:
                return await self._adapter.reset_password(request)

            elif request.action_type == IAMActionType.VALIDATE_STATE:
                return await self._adapter.validate_state(request)

            elif request.action_type == IAMActionType.FETCH_USER:
                return await self._adapter.fetch_user(request)

            elif request.action_type == IAMActionType.ADD_TO_GROUP:
                return await self._adapter.add_to_group(request)

            elif request.action_type == IAMActionType.REMOVE_FROM_GROUP:
                return await self._adapter.remove_from_group(request)

            elif request.action_type == IAMActionType.QUARANTINE_USER:
                return await self._adapter.quarantine_user(request)

            else:
                return IAMActionResult.failure(
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    message=f"Unknown action type: {request.action_type}",
                )

        except Exception as e:
            logger.exception(f"Error executing IAM action: {e}")
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message=f"Internal error: {str(e)}",
            )

    # =========================================================================
    # Approval Workflow
    # =========================================================================

    async def _create_pending_approval(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Create a pending approval request.

        Returns a result indicating approval is needed, with the approval_id
        that can be used to approve/reject.
        """
        from datetime import timedelta

        approval_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        pending = PendingApproval(
            approval_id=approval_id,
            request=request,
            created_at=now,
            expires_at=now + timedelta(hours=24),  # 24 hour expiry
        )

        self._pending_approvals[approval_id] = pending

        logger.info(
            f"Created approval request {approval_id} for {request.action_type.value} "
            f"on {request.target_uid} by {request.initiated_by}"
        )

        # Create audit entry for approval request
        audit = IAMAuditEntry(
            correlation_id=request.correlation_id,
            action_type=request.action_type,
            target_uid=request.target_uid,
            initiated_by=request.initiated_by,
            source_ip=request.source_ip,
            reason=request.reason,
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            playbook_id=request.playbook_id,
            success=False,
            error_code=IAMErrorCode.INSUFFICIENT_PERMISSIONS,
            error_message=f"Approval required. Approval ID: {approval_id}",
        )

        await self.audit_logger.log_action(audit)

        return IAMActionResult(
            success=False,
            error_code=IAMErrorCode.INSUFFICIENT_PERMISSIONS,
            message=f"Approval required for this action. Approval ID: {approval_id}",
            audit=audit,
        )

    async def approve_action(
        self,
        approval_id: str,
        approved_by: str,
        comments: Optional[str] = None,
    ) -> IAMActionResult:
        """
        Approve a pending action and execute it.

        Args:
            approval_id: ID of the pending approval
            approved_by: Username of the approver
            comments: Optional approval comments

        Returns:
            Result of the executed action
        """
        pending = self._pending_approvals.get(approval_id)

        if not pending:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message=f"Approval not found: {approval_id}",
            )

        if pending.status != "pending":
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message=f"Approval already {pending.status}",
            )

        if datetime.now(timezone.utc) > pending.expires_at:
            pending.status = "expired"
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message="Approval has expired",
            )

        # Mark as approved
        pending.status = "approved"
        pending.approved_by = approved_by
        pending.approved_at = datetime.now(timezone.utc)

        # Update request with approval info
        pending.request.approval_id = approval_id

        logger.info(f"Approval {approval_id} granted by {approved_by}")

        # Execute the action
        result = await self.execute_action(pending.request)

        # Add approval info to audit
        if result.audit:
            result.audit.changes["approved_by"] = approved_by
            result.audit.changes["approval_id"] = approval_id
            if comments:
                result.audit.changes["approval_comments"] = comments

        return result

    async def reject_action(
        self,
        approval_id: str,
        rejected_by: str,
        reason: str,
    ) -> IAMActionResult:
        """
        Reject a pending action.

        Args:
            approval_id: ID of the pending approval
            rejected_by: Username of the rejector
            reason: Reason for rejection

        Returns:
            Result indicating rejection
        """
        pending = self._pending_approvals.get(approval_id)

        if not pending:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message=f"Approval not found: {approval_id}",
            )

        if pending.status != "pending":
            return IAMActionResult.failure(
                error_code=IAMErrorCode.UNKNOWN_ERROR,
                message=f"Approval already {pending.status}",
            )

        # Mark as rejected
        pending.status = "rejected"
        pending.approved_by = rejected_by
        pending.approved_at = datetime.now(timezone.utc)
        pending.rejection_reason = reason

        logger.info(f"Approval {approval_id} rejected by {rejected_by}: {reason}")

        # Create audit entry
        audit = IAMAuditEntry(
            correlation_id=pending.request.correlation_id,
            action_type=pending.request.action_type,
            target_uid=pending.request.target_uid,
            initiated_by=pending.request.initiated_by,
            reason=f"Rejected by {rejected_by}: {reason}",
            alert_id=pending.request.alert_id,
            investigation_id=pending.request.investigation_id,
            success=False,
            error_code=IAMErrorCode.INSUFFICIENT_PERMISSIONS,
            error_message=f"Action rejected: {reason}",
        )

        await self.audit_logger.log_action(audit)

        return IAMActionResult(
            success=False,
            error_code=IAMErrorCode.INSUFFICIENT_PERMISSIONS,
            message=f"Action rejected: {reason}",
            audit=audit,
        )

    async def _verify_approval(self, approval_id: str, request: IAMActionRequest) -> bool:
        """Verify an approval is valid for the request."""
        pending = self._pending_approvals.get(approval_id)

        if not pending:
            return False

        if pending.status != "approved":
            return False

        if datetime.now(timezone.utc) > pending.expires_at:
            return False

        # Verify request matches
        if pending.request.target_uid != request.target_uid:
            return False

        if pending.request.action_type != request.action_type:
            return False

        return True

    def get_pending_approvals(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        pending = [
            {
                "approval_id": p.approval_id,
                "action_type": p.request.action_type.value,
                "target_uid": p.request.target_uid,
                "initiated_by": p.request.initiated_by,
                "reason": p.request.reason,
                "created_at": p.created_at.isoformat(),
                "expires_at": p.expires_at.isoformat(),
                "status": p.status,
                "alert_id": p.request.alert_id,
                "investigation_id": p.request.investigation_id,
            }
            for p in self._pending_approvals.values()
            if p.status == "pending"
        ]
        return pending[:limit]

    # =========================================================================
    # Rollback Operations
    # =========================================================================

    async def rollback_action(
        self,
        rollback_id: str,
        initiated_by: str,
        reason: str,
    ) -> IAMActionResult:
        """
        Rollback a previously executed action.

        Args:
            rollback_id: ID of the action to rollback (from audit entry)
            initiated_by: Who is initiating the rollback
            reason: Why the rollback is being performed

        Returns:
            Result of the rollback operation
        """
        rollback_context = self._rollback_registry.get(rollback_id)

        if not rollback_context:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.ROLLBACK_FAILED,
                message=f"No rollback context found for ID: {rollback_id}",
            )

        if rollback_context.rollback_executed:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.ROLLBACK_FAILED,
                message="Rollback has already been executed",
            )

        result = await self._adapter.rollback(rollback_context, reason, initiated_by)

        if result.success:
            rollback_context.rollback_executed = True
            rollback_context.rollback_timestamp = datetime.now(timezone.utc)
            rollback_context.rollback_success = True

            # JWT invalidation may be needed after rollback too
            if rollback_context.action_type in {
                IAMActionType.DISABLE_ACCOUNT,
                IAMActionType.QUARANTINE_USER,
            }:
                # Re-enabled user should re-authenticate with fresh token
                await self.jwt_invalidation.invalidate_user_tokens(
                    uid=rollback_context.target_uid,
                    action_type=rollback_context.action_type,
                    reason=f"Rollback: {reason}",
                )

        return result

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    async def disable_user(
        self,
        uid: str,
        initiated_by: str,
        reason: str,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> IAMActionResult:
        """Convenience method to disable a user account."""
        request = IAMActionRequest(
            target_uid=uid,
            action_type=IAMActionType.DISABLE_ACCOUNT,
            initiated_by=initiated_by,
            reason=reason,
            alert_id=alert_id,
            investigation_id=investigation_id,
            source_ip=source_ip,
        )
        return await self.execute_action(request)

    async def enable_user(
        self,
        uid: str,
        initiated_by: str,
        reason: str,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> IAMActionResult:
        """Convenience method to enable a user account."""
        request = IAMActionRequest(
            target_uid=uid,
            action_type=IAMActionType.ENABLE_ACCOUNT,
            initiated_by=initiated_by,
            reason=reason,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )
        return await self.execute_action(request)

    async def reset_user_password(
        self,
        uid: str,
        new_password: str,
        initiated_by: str,
        reason: str,
        alert_id: Optional[str] = None,
    ) -> IAMActionResult:
        """Convenience method to reset a user's password."""
        request = IAMActionRequest(
            target_uid=uid,
            action_type=IAMActionType.RESET_PASSWORD,
            initiated_by=initiated_by,
            reason=reason,
            new_password=new_password,
            alert_id=alert_id,
        )
        return await self.execute_action(request)

    async def get_user_state(
        self,
        uid: str,
        initiated_by: str = "system",
    ) -> IAMActionResult:
        """Convenience method to check user state."""
        request = IAMActionRequest(
            target_uid=uid,
            action_type=IAMActionType.VALIDATE_STATE,
            initiated_by=initiated_by,
            reason="State validation check",
        )
        return await self.execute_action(request)

    async def quarantine_user(
        self,
        uid: str,
        initiated_by: str,
        reason: str,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> IAMActionResult:
        """Convenience method to quarantine a user (disable + remove from groups)."""
        request = IAMActionRequest(
            target_uid=uid,
            action_type=IAMActionType.QUARANTINE_USER,
            initiated_by=initiated_by,
            reason=reason,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )
        return await self.execute_action(request)

    # =========================================================================
    # Metrics
    # =========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Get service metrics."""
        return {
            "adapter_type": self._adapter.adapter_type,
            "connected": self._adapter.is_connected,
            "action_counts": self._action_counts.copy(),
            "error_counts": self._error_counts.copy(),
            "pending_approvals": len([p for p in self._pending_approvals.values() if p.status == "pending"]),
            "rollback_contexts": len(self._rollback_registry),
        }


# =============================================================================
# Singleton Service Instance
# =============================================================================

_iam_service: Optional[IAMService] = None


def get_iam_service() -> IAMService:
    """Get the singleton IAM service instance."""
    global _iam_service
    if _iam_service is None:
        _iam_service = IAMService()
    return _iam_service


def configure_iam_service(config: OpenLDAPConfig) -> IAMService:
    """Configure the IAM service with specific settings."""
    global _iam_service
    _iam_service = IAMService(config=config)
    return _iam_service
