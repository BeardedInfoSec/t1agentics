# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IAM (Identity and Access Management) Response Action Routes

REST API endpoints for automated identity management actions:
- Disable/enable user accounts
- Reset user passwords
- Validate user state
- Fetch user information
- Quarantine users (disable + remove from all groups)

All actions support:
- Approval workflow integration
- Full audit logging
- Rollback capability
- SOAR playbook integration via structured responses

Author: T1 Agentics Security Team
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging
from dependencies.auth import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/iam", tags=["iam"], dependencies=[Depends(require_admin)])


# =============================================================================
# Request/Response Models
# =============================================================================

class IAMUserActionRequest(BaseModel):
    """Base request for user-targeted IAM actions"""
    username: str = Field(..., description="Target username (uid in LDAP)")
    reason: str = Field(..., description="Reason for the action (audit trail)")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracking")
    alert_id: Optional[str] = Field(None, description="Related alert ID")
    investigation_id: Optional[str] = Field(None, description="Related investigation ID")
    skip_approval: bool = Field(False, description="Skip approval workflow (requires elevated permissions)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class DisableUserRequest(IAMUserActionRequest):
    """Request to disable a user account"""
    pass


class EnableUserRequest(IAMUserActionRequest):
    """Request to enable a previously disabled user account"""
    pass


class ResetPasswordRequest(IAMUserActionRequest):
    """Request to reset a user's password"""
    new_password: Optional[str] = Field(None, description="New password (auto-generated if not provided)")
    force_change: bool = Field(True, description="Force password change on next login")
    notify_user: bool = Field(False, description="Send password to user via email")


class QuarantineUserRequest(IAMUserActionRequest):
    """Request to quarantine a user (disable + remove from all groups)"""
    preserve_group_membership: bool = Field(True, description="Store group membership for restoration")


class FetchUserRequest(BaseModel):
    """Request to fetch user information"""
    username: str = Field(..., description="Target username")
    include_groups: bool = Field(True, description="Include group memberships")
    include_attributes: bool = Field(True, description="Include all LDAP attributes")


class ValidateStateRequest(BaseModel):
    """Request to validate user state"""
    username: str = Field(..., description="Target username")


class RollbackActionRequest(BaseModel):
    """Request to rollback a previous IAM action"""
    audit_id: str = Field(..., description="Audit ID of the action to rollback")
    reason: str = Field(..., description="Reason for rollback")


class ApproveActionRequest(BaseModel):
    """Request to approve a pending IAM action"""
    approval_id: str = Field(..., description="Approval ID")
    approved_by: str = Field(..., description="Username of approver")
    comments: Optional[str] = Field(None, description="Approval comments")


class RejectActionRequest(BaseModel):
    """Request to reject a pending IAM action"""
    approval_id: str = Field(..., description="Approval ID")
    rejected_by: str = Field(..., description="Username of rejector")
    reason: str = Field(..., description="Rejection reason")


class IAMActionResponse(BaseModel):
    """Standard response for IAM actions"""
    success: bool
    action_type: str
    target_user: str
    message: str
    audit_id: Optional[str] = None
    approval_required: bool = False
    approval_id: Optional[str] = None
    rollback_available: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None


class IAMUserResponse(BaseModel):
    """Response containing user information"""
    success: bool
    user: Optional[Dict[str, Any]] = None
    message: str
    error_code: Optional[str] = None


class IAMStateResponse(BaseModel):
    """Response for user state validation"""
    success: bool
    username: str
    state: str
    is_active: bool
    exists: bool
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class IAMAuditListResponse(BaseModel):
    """Response containing audit entries"""
    success: bool
    count: int
    entries: List[Dict[str, Any]]


class IAMPendingApprovalsResponse(BaseModel):
    """Response containing pending approvals"""
    success: bool
    count: int
    approvals: List[Dict[str, Any]]


# =============================================================================
# Helper Functions
# =============================================================================

def get_current_user(request: Request) -> str:
    """Extract current user from request state (set by auth middleware)"""
    if hasattr(request.state, 'user') and request.state.user:
        return request.state.user.get('username', 'system')
    return 'system'


async def get_iam_service():
    """Get or initialize the IAM service"""
    from services.iam import get_iam_service as _get_iam_service, IAMActionRequest, IAMActionType
    return _get_iam_service()


# =============================================================================
# User Account Actions
# =============================================================================

@router.post("/users/disable", response_model=IAMActionResponse)
async def disable_user(
    body: DisableUserRequest,
    request: Request
):
    """
    Disable a user account.

    This action:
    - Sets the account to disabled state in LDAP
    - Triggers JWT invalidation for the user
    - Creates an audit trail entry
    - Supports rollback (re-enable)

    May require approval based on configured policies.
    """
    from services.iam import IAMActionRequest, IAMActionType

    try:
        service = await get_iam_service()
        initiator = get_current_user(request)

        result = await service.disable_user(
            uid=body.username,
            initiated_by=initiator,
            reason=body.reason,
            alert_id=body.alert_id,
            investigation_id=body.investigation_id,
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type="DISABLE_ACCOUNT",
                target_user=body.username,
                message=f"User '{body.username}' has been disabled",
                audit_id=result.audit.audit_id if result.audit else None,
                rollback_available=result.rollback_context is not None,
                details=result.to_dict()
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type="DISABLE_ACCOUNT",
                target_user=body.username,
                message=result.message or "Failed to disable user",
                error_code=result.error_code.value if result.error_code else None,
                details=result.to_dict()
            )

    except Exception as e:
        logger.error(f"Error disabling user {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/enable", response_model=IAMActionResponse)
async def enable_user(
    body: EnableUserRequest,
    request: Request
):
    """
    Enable a previously disabled user account.

    This action:
    - Removes the disabled state from the account
    - Creates an audit trail entry
    - Supports rollback (disable again)
    """
    try:
        service = await get_iam_service()
        initiator = get_current_user(request)

        result = await service.enable_user(
            uid=body.username,
            initiated_by=initiator,
            reason=body.reason,
            alert_id=body.alert_id,
            investigation_id=body.investigation_id,
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type="ENABLE_ACCOUNT",
                target_user=body.username,
                message=f"User '{body.username}' has been enabled",
                audit_id=result.audit.audit_id if result.audit else None,
                rollback_available=result.rollback_context is not None,
                details=result.to_dict()
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type="ENABLE_ACCOUNT",
                target_user=body.username,
                message=result.message or "Failed to enable user",
                error_code=result.error_code.value if result.error_code else None,
                details=result.to_dict()
            )

    except Exception as e:
        logger.error(f"Error enabling user {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/reset-password", response_model=IAMActionResponse)
async def reset_user_password(
    body: ResetPasswordRequest,
    request: Request
):
    """
    Reset a user's password.

    This action:
    - Sets a new password for the user
    - Optionally forces password change on next login
    - Triggers JWT invalidation for the user
    - Creates an audit trail entry
    - Does NOT support rollback (passwords are one-way)

    If no new_password is provided, a secure random password is generated.
    """
    import secrets
    import string

    try:
        service = await get_iam_service()
        initiator = get_current_user(request)

        # Generate password if not provided
        new_password = body.new_password
        password_generated = False
        if not new_password:
            # Generate a secure 16-char password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            new_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            password_generated = True

        result = await service.reset_user_password(
            uid=body.username,
            new_password=new_password,
            initiated_by=initiator,
            reason=body.reason,
            alert_id=body.alert_id,
        )

        response_details = result.to_dict()

        # Include generated password in response if one was created
        if result.success and password_generated:
            response_details['password_generated'] = True
            if not body.notify_user:
                response_details['generated_password'] = new_password

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type="RESET_PASSWORD",
                target_user=body.username,
                message=f"Password reset for user '{body.username}'",
                audit_id=result.audit.audit_id if result.audit else None,
                rollback_available=False,  # Passwords cannot be rolled back
                details=response_details
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type="RESET_PASSWORD",
                target_user=body.username,
                message=result.message or "Failed to reset password",
                error_code=result.error_code.value if result.error_code else None,
                details=response_details
            )

    except Exception as e:
        logger.error(f"Error resetting password for {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/quarantine", response_model=IAMActionResponse)
async def quarantine_user(
    body: QuarantineUserRequest,
    request: Request
):
    """
    Quarantine a user account.

    This is a compound action that:
    1. Disables the user account
    2. Removes the user from all groups
    3. Optionally preserves group membership for restoration
    4. Triggers JWT invalidation

    Use this for compromised accounts that need immediate isolation.
    """
    try:
        service = await get_iam_service()
        initiator = get_current_user(request)

        result = await service.quarantine_user(
            uid=body.username,
            initiated_by=initiator,
            reason=body.reason,
            alert_id=body.alert_id,
            investigation_id=body.investigation_id,
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type="QUARANTINE_USER",
                target_user=body.username,
                message=f"User '{body.username}' has been quarantined",
                audit_id=result.audit.audit_id if result.audit else None,
                rollback_available=result.rollback_context is not None,
                details=result.to_dict()
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type="QUARANTINE_USER",
                target_user=body.username,
                message=result.message or "Failed to quarantine user",
                error_code=result.error_code.value if result.error_code else None,
                details=result.to_dict()
            )

    except Exception as e:
        logger.error(f"Error quarantining user {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# User Information Endpoints
# =============================================================================

@router.post("/users/fetch", response_model=IAMUserResponse)
async def fetch_user(body: FetchUserRequest):
    """
    Fetch user information from the directory.

    Returns:
    - Basic user attributes (uid, displayName, email, etc.)
    - Account state (active, disabled, locked, expired)
    - Group memberships (if requested)
    - All LDAP attributes (if requested)

    This is a read-only operation that does not require approval.
    """
    from services.iam import IAMActionRequest, IAMActionType

    try:
        service = await get_iam_service()

        request = IAMActionRequest(
            target_uid=body.username,
            action_type=IAMActionType.FETCH_USER,
            initiated_by="system",
            reason="User information fetch",
        )

        result = await service.adapter.fetch_user(request)

        if result.success and result.user:
            user_data = result.user.to_dict()
            if not body.include_attributes:
                user_data['attributes'] = {}

            return IAMUserResponse(
                success=True,
                user=user_data,
                message=f"User '{body.username}' found"
            )
        else:
            return IAMUserResponse(
                success=False,
                user=None,
                message=result.message or f"User '{body.username}' not found",
                error_code=result.error_code.value if result.error_code else None
            )

    except Exception as e:
        logger.error(f"Error fetching user {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/{username}", response_model=IAMUserResponse)
async def get_user(
    username: str,
    include_groups: bool = True,
    include_attributes: bool = False
):
    """
    Get user information (convenience GET endpoint).

    Same as POST /users/fetch but as a GET request.
    """
    from services.iam import IAMActionRequest, IAMActionType

    try:
        service = await get_iam_service()

        request = IAMActionRequest(
            target_uid=username,
            action_type=IAMActionType.FETCH_USER,
            initiated_by="system",
            reason="User information fetch",
        )

        result = await service.adapter.fetch_user(request)

        if result.success and result.user:
            user_data = result.user.to_dict()
            if not include_attributes:
                user_data['attributes'] = {}

            return IAMUserResponse(
                success=True,
                user=user_data,
                message=f"User '{username}' found"
            )
        else:
            return IAMUserResponse(
                success=False,
                user=None,
                message=result.message or f"User '{username}' not found",
                error_code=result.error_code.value if result.error_code else None
            )

    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/validate-state", response_model=IAMStateResponse)
async def validate_user_state(body: ValidateStateRequest):
    """
    Validate the current state of a user account.

    Returns:
    - Whether the user exists
    - Current account state (active, disabled, locked, expired)
    - Whether the user can authenticate
    - Any issues detected

    This is a read-only operation useful for pre-flight checks.
    """
    from services.iam import IAMActionRequest, IAMActionType

    try:
        service = await get_iam_service()

        request = IAMActionRequest(
            target_uid=body.username,
            action_type=IAMActionType.VALIDATE_STATE,
            initiated_by="system",
            reason="State validation check",
        )

        result = await service.adapter.validate_state(request)

        if result.success and result.user:
            state = result.user.state.value
            is_active = state == 'active'

            return IAMStateResponse(
                success=True,
                username=body.username,
                state=state,
                is_active=is_active,
                exists=True,
                message=f"User state: {state}",
                details=result.to_dict()
            )
        else:
            # Check if user doesn't exist vs other error
            is_not_found = result.error_code and result.error_code.value == 'USER_NOT_FOUND'

            return IAMStateResponse(
                success=False,
                username=body.username,
                state='unknown',
                is_active=False,
                exists=not is_not_found,
                message=result.message or "Failed to validate state",
                details=result.to_dict()
            )

    except Exception as e:
        logger.error(f"Error validating state for {body.username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/{username}/state", response_model=IAMStateResponse)
async def get_user_state(username: str):
    """
    Get user state (convenience GET endpoint).
    """
    from services.iam import IAMActionRequest, IAMActionType

    try:
        service = await get_iam_service()

        request = IAMActionRequest(
            target_uid=username,
            action_type=IAMActionType.VALIDATE_STATE,
            initiated_by="system",
            reason="State validation check",
        )

        result = await service.adapter.validate_state(request)

        if result.success and result.user:
            state = result.user.state.value
            is_active = state == 'active'

            return IAMStateResponse(
                success=True,
                username=username,
                state=state,
                is_active=is_active,
                exists=True,
                message=f"User state: {state}",
                details=result.to_dict()
            )
        else:
            is_not_found = result.error_code and result.error_code.value == 'USER_NOT_FOUND'

            return IAMStateResponse(
                success=False,
                username=username,
                state='unknown',
                is_active=False,
                exists=not is_not_found,
                message=result.message or "Failed to validate state",
                details=result.to_dict()
            )

    except Exception as e:
        logger.error(f"Error getting state for {username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Approval Workflow Endpoints
# =============================================================================

@router.get("/approvals/pending", response_model=IAMPendingApprovalsResponse)
async def get_pending_approvals(request: Request):
    """
    Get all pending IAM action approvals.

    Returns actions waiting for approval, sorted by priority and timestamp.
    """
    try:
        service = await get_iam_service()

        pending = service.get_pending_approvals()

        return IAMPendingApprovalsResponse(
            success=True,
            count=len(pending),
            approvals=pending
        )

    except Exception as e:
        logger.error(f"Error getting pending approvals: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approvals/approve", response_model=IAMActionResponse)
async def approve_action(body: ApproveActionRequest):
    """
    Approve a pending IAM action.

    Once approved, the action is executed immediately.
    """
    try:
        service = await get_iam_service()

        result = await service.approve_action(
            approval_id=body.approval_id,
            approved_by=body.approved_by,
            comments=body.comments
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type=result.details.get('action_type', 'UNKNOWN'),
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message="Action approved and executed",
                audit_id=result.audit_entry.audit_id if result.audit_entry else None,
                rollback_available=result.rollback_context is not None,
                details=result.details
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type=result.details.get('action_type', 'UNKNOWN'),
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message=result.error or "Failed to approve action",
                error_code=result.error_code.value if result.error_code else None,
                details=result.details
            )

    except Exception as e:
        logger.error(f"Error approving action {body.approval_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approvals/reject", response_model=IAMActionResponse)
async def reject_action(body: RejectActionRequest):
    """
    Reject a pending IAM action.

    The action will not be executed and will be logged as rejected.
    """
    try:
        service = await get_iam_service()

        result = await service.reject_action(
            approval_id=body.approval_id,
            rejected_by=body.rejected_by,
            reason=body.reason
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type=result.details.get('action_type', 'UNKNOWN'),
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message="Action rejected",
                details=result.details
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type=result.details.get('action_type', 'UNKNOWN'),
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message=result.error or "Failed to reject action",
                error_code=result.error_code.value if result.error_code else None,
                details=result.details
            )

    except Exception as e:
        logger.error(f"Error rejecting action {body.approval_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Audit & Rollback Endpoints
# =============================================================================

@router.get("/audit", response_model=IAMAuditListResponse)
async def get_audit_log(
    username: Optional[str] = None,
    action_type: Optional[str] = None,
    correlation_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get IAM action audit log entries.

    Supports filtering by:
    - Target username
    - Action type
    - Correlation ID

    Results are sorted by timestamp descending (most recent first).
    """
    try:
        service = await get_iam_service()

        entries = await service.audit_logger.get_audit_entries(
            target_user=username,
            action_type=action_type,
            correlation_id=correlation_id,
            limit=limit,
            offset=offset
        )

        return IAMAuditListResponse(
            success=True,
            count=len(entries),
            entries=entries
        )

    except Exception as e:
        logger.error(f"Error getting audit log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit/{audit_id}")
async def get_audit_entry(audit_id: str):
    """
    Get a specific audit entry by ID.
    """
    try:
        service = await get_iam_service()

        entry = await service.audit_logger.get_audit_entry(audit_id)

        if entry:
            return {
                "success": True,
                "entry": entry
            }
        else:
            raise HTTPException(status_code=404, detail=f"Audit entry {audit_id} not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audit entry {audit_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rollback", response_model=IAMActionResponse)
async def rollback_action(
    body: RollbackActionRequest,
    request: Request
):
    """
    Rollback a previous IAM action.

    Not all actions can be rolled back:
    - [Y] Disable account → Enable account
    - [Y] Enable account → Disable account
    - [Y] Remove from group → Add to group
    - [Y] Add to group → Remove from group
    - [N] Password reset (irreversible)

    Rollback creates a new audit entry linked to the original.
    """
    try:
        service = await get_iam_service()
        initiator = get_current_user(request)

        result = await service.rollback_action(
            audit_id=body.audit_id,
            reason=body.reason,
            initiator=initiator
        )

        if result.success:
            return IAMActionResponse(
                success=True,
                action_type="ROLLBACK",
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message="Action rolled back successfully",
                audit_id=result.audit_entry.audit_id if result.audit_entry else None,
                details=result.details
            )
        else:
            return IAMActionResponse(
                success=False,
                action_type="ROLLBACK",
                target_user=result.details.get('target_user', 'UNKNOWN'),
                message=result.error or "Failed to rollback action",
                error_code=result.error_code.value if result.error_code else None,
                details=result.details
            )

    except Exception as e:
        logger.error(f"Error rolling back action {body.audit_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Service Status & Configuration
# =============================================================================

@router.get("/status")
async def get_iam_status():
    """
    Get IAM service status and connectivity.

    Returns:
    - Whether the service is initialized
    - Connection status to directory server
    - Configured adapter type
    - Metrics
    """
    try:
        service = await get_iam_service()

        # Test connection
        connected = await service.adapter.test_connection()

        return {
            "success": True,
            "status": "operational" if connected else "degraded",
            "connected": connected,
            "adapter_type": service.adapter.__class__.__name__,
            "metrics": service.get_metrics(),
            "pending_approvals": len(service.get_pending_approvals())
        }

    except Exception as e:
        logger.error(f"Error getting IAM status: {e}")
        return {
            "success": False,
            "status": "unavailable",
            "connected": False,
            "error": str(e)
        }


@router.get("/config")
async def get_iam_config():
    """
    Get IAM service configuration (non-sensitive).

    Returns connection details without credentials.
    """
    try:
        service = await get_iam_service()

        config = service.adapter.get_config_info()

        return {
            "success": True,
            "config": config
        }

    except Exception as e:
        logger.error(f"Error getting IAM config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-connection")
async def test_iam_connection():
    """
    Test connection to the directory server.

    Performs a bind operation to verify credentials and connectivity.
    """
    try:
        service = await get_iam_service()

        connected = await service.adapter.test_connection()

        if connected:
            return {
                "success": True,
                "message": "Successfully connected to directory server",
                "adapter": service.adapter.__class__.__name__
            }
        else:
            return {
                "success": False,
                "message": "Failed to connect to directory server"
            }

    except Exception as e:
        logger.error(f"Error testing IAM connection: {e}")
        return {
            "success": False,
            "message": str(e)
        }
