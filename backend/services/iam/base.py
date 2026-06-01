# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IAM Base Classes and Interfaces

Defines the abstract interface for IAM adapters, ensuring consistent behavior
across different directory services (OpenLDAP, Active Directory, etc.)

Design Principles:
1. Adapter Pattern - Each directory type implements the same interface
2. Immutable Results - Action results are frozen after creation
3. Audit-First - Every action generates audit entries
4. Rollback-Ready - All mutating operations support undo

SOC Reasoning:
- Standardized interface allows playbooks to work across environments
- Structured results enable automated decision making in SOAR
- Audit entries provide forensic trail for incident response

=============================================================================
ACTIVE DIRECTORY MAPPING GUIDE (Future Implementation)
=============================================================================

When implementing an Active Directory adapter, use the following attribute mappings:

ACCOUNT DISABLE/ENABLE:
-----------------------
OpenLDAP (ppolicy overlay):
  - Attribute: pwdAccountLockedTime
  - Disable: Set to "000001010000Z" (epoch)
  - Enable: Remove attribute

Active Directory:
  - Attribute: userAccountControl (UAC flags)
  - Disable: Set bit 0x2 (ACCOUNTDISABLE)
    userAccountControl |= 0x2   # Disable
    userAccountControl &= ~0x2  # Enable
  - Alternative: Use msDS-UserAccountDisabled for simpler boolean

USER STATE DETECTION:
---------------------
OpenLDAP:
  - Disabled: pwdAccountLockedTime present
  - Locked: pwdAccountLockedTime set by ppolicy (failed attempts)
  - Expired: Check shadowExpire or similar

Active Directory:
  - Disabled: userAccountControl & 0x2
  - Locked: lockoutTime > 0 && now < lockoutTime + lockoutDuration
  - Expired: accountExpires < now (0 or max = never expires)
  - Password Expired: userAccountControl & 0x800000 (PASSWORD_EXPIRED)
  - Must Change: pwdLastSet == 0

GROUP MEMBERSHIP:
-----------------
OpenLDAP (posixGroup):
  - Attribute: memberUid (list of UIDs)
  - Add: Modify ADD memberUid: username
  - Remove: Modify DELETE memberUid: username

Active Directory:
  - Attribute: member (list of DNs on group object)
  - User's groups: memberOf attribute (list of group DNs)
  - Add: Modify ADD member: userDN (on group object)
  - Remove: Modify DELETE member: userDN (on group object)

PASSWORD RESET:
---------------
OpenLDAP:
  - Use Extended Operation (RFC 3062): LDAP_EXOP_PASSWD_MODIFY
  - OID: 1.3.6.1.4.1.4203.1.11.1

Active Directory:
  - Attribute: unicodePwd (must be over SSL/TLS)
  - Format: UTF-16LE encoded, surrounded by quotes
    password_value = f'"{new_password}"'.encode('utf-16-le')
  - Requires secure connection (LDAPS or StartTLS)

TIMESTAMP ATTRIBUTES:
---------------------
OpenLDAP:
  - Created: createTimestamp (generalizedTime)
  - Modified: modifyTimestamp
  - Last Login: Often custom (authTimestamp)
  - Password Set: pwdChangedTime

Active Directory:
  - Created: whenCreated (generalizedTime)
  - Modified: whenChanged
  - Last Logon: lastLogonTimestamp (Windows FILETIME, replicated)
             or lastLogon (not replicated, per-DC)
  - Password Set: pwdLastSet (Windows FILETIME)

WINDOWS FILETIME CONVERSION:
  - 100-nanosecond intervals since Jan 1, 1601
  - Python: datetime.fromtimestamp((filetime - 116444736000000000) / 10000000)

LDAP SEARCH FILTERS:
--------------------
OpenLDAP:
  - User: (&(objectClass=inetOrgPerson)(uid={username}))
  - Group: (&(objectClass=posixGroup)(cn={groupname}))

Active Directory:
  - User: (&(objectClass=user)(sAMAccountName={username}))
  - Group: (&(objectClass=group)(cn={groupname}))
  - Either: (&(objectCategory=person)(sAMAccountName={username}))

COMMON AD UAC FLAGS:
--------------------
  0x0001 - SCRIPT (logon script executed)
  0x0002 - ACCOUNTDISABLE
  0x0008 - HOMEDIR_REQUIRED
  0x0010 - LOCKOUT
  0x0020 - PASSWD_NOTREQD
  0x0040 - PASSWD_CANT_CHANGE
  0x0080 - ENCRYPTED_TEXT_PWD_ALLOWED
  0x0100 - TEMP_DUPLICATE_ACCOUNT
  0x0200 - NORMAL_ACCOUNT
  0x0800 - INTERDOMAIN_TRUST_ACCOUNT
  0x1000 - WORKSTATION_TRUST_ACCOUNT
  0x2000 - SERVER_TRUST_ACCOUNT
  0x10000 - DONT_EXPIRE_PASSWORD
  0x20000 - MNS_LOGON_ACCOUNT
  0x40000 - SMARTCARD_REQUIRED
  0x80000 - TRUSTED_FOR_DELEGATION
  0x100000 - NOT_DELEGATED
  0x200000 - USE_DES_KEY_ONLY
  0x400000 - DONT_REQ_PREAUTH
  0x800000 - PASSWORD_EXPIRED
  0x1000000 - TRUSTED_TO_AUTH_FOR_DELEGATION
  0x04000000 - PARTIAL_SECRETS_ACCOUNT

IMPLEMENTATION NOTES:
---------------------
1. AD requires SSL/TLS for password operations
2. AD uses different default ports: 389 (LDAP), 636 (LDAPS), 3268 (GC), 3269 (GC-SSL)
3. AD supports paged searches (important for large directories)
4. AD referrals should be handled for multi-domain forests
5. AD uses Kerberos by default; NTLM is fallback
6. Service accounts should use gMSA (Group Managed Service Accounts) in production
7. Consider using the ldap3 library's AD-specific helpers

=============================================================================
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
import uuid
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Enumerations
# =============================================================================

class IAMActionType(str, Enum):
    """Types of IAM actions that can be performed."""
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_ACCOUNT = "enable_account"
    RESET_PASSWORD = "reset_password"
    VALIDATE_STATE = "validate_state"
    FETCH_USER = "fetch_user"
    ADD_TO_GROUP = "add_to_group"
    REMOVE_FROM_GROUP = "remove_from_group"

    # Composite actions
    QUARANTINE_USER = "quarantine_user"  # Disable + remove from groups
    RESTORE_USER = "restore_user"  # Enable + restore groups


class IAMUserState(str, Enum):
    """Possible states of a user account."""
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"  # Too many failed attempts
    EXPIRED = "expired"  # Password or account expired
    PENDING = "pending"  # Awaiting activation
    UNKNOWN = "unknown"


class IAMErrorCode(str, Enum):
    """Standardized error codes for IAM operations."""
    SUCCESS = "SUCCESS"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    ACCOUNT_ALREADY_DISABLED = "ACCOUNT_ALREADY_DISABLED"
    ACCOUNT_ALREADY_ENABLED = "ACCOUNT_ALREADY_ENABLED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    TIMEOUT = "TIMEOUT"
    INVALID_PASSWORD_POLICY = "INVALID_PASSWORD_POLICY"
    GROUP_NOT_FOUND = "GROUP_NOT_FOUND"
    ALREADY_MEMBER = "ALREADY_MEMBER"
    NOT_A_MEMBER = "NOT_A_MEMBER"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass(frozen=True)
class IAMUser:
    """
    Represents a user account from an IAM system.

    Frozen to prevent accidental modification after retrieval.
    All times are UTC.
    """
    uid: str
    dn: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    state: IAMUserState = IAMUserState.UNKNOWN
    groups: tuple = field(default_factory=tuple)  # Immutable list of group names

    # Timestamps
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    password_last_set: Optional[datetime] = None
    disabled_at: Optional[datetime] = None

    # Additional attributes (directory-specific)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "uid": self.uid,
            "dn": self.dn,
            "display_name": self.display_name,
            "email": self.email,
            "state": self.state.value,
            "groups": list(self.groups),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "password_last_set": self.password_last_set.isoformat() if self.password_last_set else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class IAMGroup:
    """Represents a group from an IAM system."""
    name: str
    dn: str
    description: Optional[str] = None
    members: tuple = field(default_factory=tuple)  # UIDs of members

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "dn": self.dn,
            "description": self.description,
            "members": list(self.members),
        }


@dataclass
class IAMAuditEntry:
    """
    Audit entry for IAM operations.

    Every IAM action generates an audit entry for compliance and forensics.
    These entries should be persisted to a tamper-evident audit log.
    """
    # Identifiers
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None  # Links to alert/investigation

    # What happened
    action_type: IAMActionType = IAMActionType.VALIDATE_STATE
    target_uid: str = ""
    target_dn: Optional[str] = None

    # Who did it
    initiated_by: str = ""  # Username or system component
    service_account: str = ""  # Service account used for execution
    source_ip: Optional[str] = None

    # When
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: Optional[int] = None

    # Why
    reason: str = ""  # Human-readable justification
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    playbook_id: Optional[str] = None

    # Result
    success: bool = False
    error_code: Optional[IAMErrorCode] = None
    error_message: Optional[str] = None

    # Changes made (for rollback)
    changes: Dict[str, Any] = field(default_factory=dict)
    rollback_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization and logging."""
        return {
            "audit_id": self.audit_id,
            "correlation_id": self.correlation_id,
            "action_type": self.action_type.value,
            "target_uid": self.target_uid,
            "target_dn": self.target_dn,
            "initiated_by": self.initiated_by,
            "service_account": self.service_account,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "alert_id": self.alert_id,
            "investigation_id": self.investigation_id,
            "playbook_id": self.playbook_id,
            "success": self.success,
            "error_code": self.error_code.value if self.error_code else None,
            "error_message": self.error_message,
            "changes": self.changes,
            "rollback_data": self.rollback_data,
        }


@dataclass
class IAMRollbackContext:
    """
    Context for rolling back an IAM operation.

    Captures the state before an operation so it can be restored if needed.
    Used for:
    - Automatic rollback on partial failures
    - Manual undo of actions
    - Approval workflow rejections
    """
    action_type: IAMActionType
    target_uid: str
    target_dn: str

    # State before the operation
    previous_state: IAMUserState = IAMUserState.UNKNOWN
    previous_groups: List[str] = field(default_factory=list)
    previous_attributes: Dict[str, Any] = field(default_factory=dict)

    # For password reset rollback (we can't restore old password, but can flag)
    password_was_reset: bool = False

    # Rollback execution
    rollback_executed: bool = False
    rollback_timestamp: Optional[datetime] = None
    rollback_success: bool = False
    rollback_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "target_uid": self.target_uid,
            "target_dn": self.target_dn,
            "previous_state": self.previous_state.value,
            "previous_groups": self.previous_groups,
            "previous_attributes": self.previous_attributes,
            "password_was_reset": self.password_was_reset,
            "rollback_executed": self.rollback_executed,
            "rollback_timestamp": self.rollback_timestamp.isoformat() if self.rollback_timestamp else None,
            "rollback_success": self.rollback_success,
            "rollback_error": self.rollback_error,
        }


@dataclass
class IAMActionResult:
    """
    Result of an IAM action.

    Structured for SOAR integration:
    - success: Boolean for simple branching
    - error_code: Enum for programmatic error handling
    - user: Full user state after action
    - audit: Complete audit entry
    - rollback_context: Data needed to undo the action

    SOC Reasoning:
    - Playbooks need both simple (success/fail) and detailed (error_code) results
    - User state after action is needed for validation steps
    - Rollback context enables "undo" in approval workflows
    """
    # Core result
    success: bool
    error_code: IAMErrorCode = IAMErrorCode.SUCCESS
    message: str = ""

    # Detailed results
    user: Optional[IAMUser] = None
    groups: List[IAMGroup] = field(default_factory=list)

    # Audit and rollback
    audit: Optional[IAMAuditEntry] = None
    rollback_context: Optional[IAMRollbackContext] = None

    # For composite actions (multiple steps)
    sub_results: List['IAMActionResult'] = field(default_factory=list)

    # Timing
    execution_time_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary suitable for API responses."""
        return {
            "success": self.success,
            "error_code": self.error_code.value,
            "message": self.message,
            "user": self.user.to_dict() if self.user else None,
            "groups": [g.to_dict() for g in self.groups],
            "audit": self.audit.to_dict() if self.audit else None,
            "rollback_context": self.rollback_context.to_dict() if self.rollback_context else None,
            "sub_results": [r.to_dict() for r in self.sub_results],
            "execution_time_ms": self.execution_time_ms,
        }

    @classmethod
    def failure(
        cls,
        error_code: IAMErrorCode,
        message: str,
        audit: Optional[IAMAuditEntry] = None
    ) -> 'IAMActionResult':
        """Factory method for creating failure results."""
        return cls(
            success=False,
            error_code=error_code,
            message=message,
            audit=audit,
        )

    @classmethod
    def success_result(
        cls,
        message: str,
        user: Optional[IAMUser] = None,
        audit: Optional[IAMAuditEntry] = None,
        rollback_context: Optional[IAMRollbackContext] = None
    ) -> 'IAMActionResult':
        """Factory method for creating success results."""
        return cls(
            success=True,
            error_code=IAMErrorCode.SUCCESS,
            message=message,
            user=user,
            audit=audit,
            rollback_context=rollback_context,
        )


# =============================================================================
# Action Request Context
# =============================================================================

@dataclass
class IAMActionRequest:
    """
    Request context for an IAM action.

    Captures all context needed for:
    - Executing the action
    - Generating audit entries
    - Approval workflow integration
    """
    # Target
    target_uid: str
    action_type: IAMActionType

    # Initiator context
    initiated_by: str  # Username of human or system initiating
    source_ip: Optional[str] = None

    # Correlation
    reason: str = ""  # Human-readable justification
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    playbook_id: Optional[str] = None
    correlation_id: Optional[str] = None

    # Action-specific parameters
    new_password: Optional[str] = None  # For password reset
    target_group: Optional[str] = None  # For group operations

    # Control flags
    require_approval: bool = False
    approval_id: Optional[str] = None  # If pre-approved
    skip_rollback_capture: bool = False  # For read-only operations

    def __post_init__(self):
        # Generate correlation ID if not provided
        if not self.correlation_id:
            self.correlation_id = str(uuid.uuid4())


# =============================================================================
# Abstract Adapter Interface
# =============================================================================

class IAMAdapter(ABC):
    """
    Abstract base class for IAM adapters.

    Implementations must provide all IAM operations for their specific
    directory service (OpenLDAP, Active Directory, etc.)

    Design Contract:
    1. All methods must be thread-safe
    2. All methods must generate audit entries
    3. All mutating methods must support rollback
    4. Connection management is handled internally
    5. Credentials are never logged or returned
    """

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Return the adapter type identifier (e.g., 'openldap', 'active_directory')."""
        pass

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        pass

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the directory service.

        Returns:
            True if connection successful, False otherwise.
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the directory service."""
        pass

    @abstractmethod
    async def test_connection(self) -> IAMActionResult:
        """
        Test connectivity and service account authentication.

        Used for health checks and configuration validation.
        """
        pass

    # =========================================================================
    # Core IAM Operations
    # =========================================================================

    @abstractmethod
    async def disable_account(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Disable a user account.

        SOC Use Cases:
        - Automated response to compromised account
        - Off-boarding workflow
        - Suspicious activity containment

        Must capture rollback context to re-enable if needed.
        """
        pass

    @abstractmethod
    async def enable_account(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Re-enable a disabled user account.

        SOC Use Cases:
        - Rollback of false positive containment
        - Account restoration after investigation
        - Approval workflow completion

        Should validate account exists and is actually disabled.
        """
        pass

    @abstractmethod
    async def reset_password(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Reset user's password.

        SOC Use Cases:
        - Compromised credential response
        - Forced rotation after breach
        - User-requested reset (via helpdesk)

        Note: Password reset cannot be rolled back (old password unknown).
        Rollback context should flag that password was changed.
        """
        pass

    @abstractmethod
    async def validate_state(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Check the current state of a user account.

        SOC Use Cases:
        - Verify containment action succeeded
        - Pre-flight check before other actions
        - Periodic account status audits

        Read-only operation, no rollback needed.
        """
        pass

    @abstractmethod
    async def fetch_user(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Fetch complete user information including group memberships.

        SOC Use Cases:
        - Investigation enrichment
        - Access review
        - Compliance reporting

        Read-only operation, no rollback needed.
        """
        pass

    # =========================================================================
    # Group Operations
    # =========================================================================

    @abstractmethod
    async def add_to_group(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Add user to a group.

        SOC Use Cases:
        - Granting temporary access during incident
        - Restoring access after investigation
        """
        pass

    @abstractmethod
    async def remove_from_group(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Remove user from a group.

        SOC Use Cases:
        - Revoking compromised access
        - Quarantine workflow (remove from privileged groups)
        """
        pass

    # =========================================================================
    # Composite Operations
    # =========================================================================

    async def quarantine_user(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Quarantine a user: disable account AND remove from all groups.

        This is a composite action that:
        1. Captures current state (groups, enabled status)
        2. Removes user from all groups
        3. Disables the account

        If any step fails, previous steps are rolled back.

        SOC Use Cases:
        - Severe compromise response
        - Insider threat containment
        - Immediate access revocation
        """
        # Default implementation using primitive operations
        # Adapters can override for atomic operations if supported

        start_time = datetime.now(timezone.utc)
        sub_results = []

        # Step 1: Fetch current state
        fetch_request = IAMActionRequest(
            target_uid=request.target_uid,
            action_type=IAMActionType.FETCH_USER,
            initiated_by=request.initiated_by,
            source_ip=request.source_ip,
            reason=f"Pre-quarantine state capture: {request.reason}",
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            correlation_id=request.correlation_id,
        )
        fetch_result = await self.fetch_user(fetch_request)

        if not fetch_result.success:
            return IAMActionResult.failure(
                error_code=fetch_result.error_code,
                message=f"Failed to fetch user state before quarantine: {fetch_result.message}",
            )

        original_user = fetch_result.user
        original_groups = list(original_user.groups) if original_user else []

        # Step 2: Remove from all groups
        for group_name in original_groups:
            remove_request = IAMActionRequest(
                target_uid=request.target_uid,
                action_type=IAMActionType.REMOVE_FROM_GROUP,
                initiated_by=request.initiated_by,
                source_ip=request.source_ip,
                reason=f"Quarantine group removal: {request.reason}",
                target_group=group_name,
                alert_id=request.alert_id,
                investigation_id=request.investigation_id,
                correlation_id=request.correlation_id,
            )
            remove_result = await self.remove_from_group(remove_request)
            sub_results.append(remove_result)

            if not remove_result.success and remove_result.error_code != IAMErrorCode.NOT_A_MEMBER:
                # Rollback previous group removals
                for prev_result in sub_results[:-1]:
                    if prev_result.success and prev_result.rollback_context:
                        await self._execute_rollback(prev_result.rollback_context)

                return IAMActionResult.failure(
                    error_code=IAMErrorCode.PARTIAL_FAILURE,
                    message=f"Quarantine failed during group removal: {remove_result.message}",
                )

        # Step 3: Disable account
        disable_request = IAMActionRequest(
            target_uid=request.target_uid,
            action_type=IAMActionType.DISABLE_ACCOUNT,
            initiated_by=request.initiated_by,
            source_ip=request.source_ip,
            reason=f"Quarantine account disable: {request.reason}",
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            correlation_id=request.correlation_id,
        )
        disable_result = await self.disable_account(disable_request)
        sub_results.append(disable_result)

        if not disable_result.success and disable_result.error_code != IAMErrorCode.ACCOUNT_ALREADY_DISABLED:
            # Rollback group removals
            for prev_result in sub_results[:-1]:
                if prev_result.success and prev_result.rollback_context:
                    await self._execute_rollback(prev_result.rollback_context)

            return IAMActionResult.failure(
                error_code=IAMErrorCode.PARTIAL_FAILURE,
                message=f"Quarantine failed during account disable: {disable_result.message}",
            )

        # Success - create composite rollback context
        end_time = datetime.now(timezone.utc)
        execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.QUARANTINE_USER,
            target_uid=request.target_uid,
            target_dn=original_user.dn if original_user else "",
            previous_state=original_user.state if original_user else IAMUserState.UNKNOWN,
            previous_groups=original_groups,
        )

        audit = IAMAuditEntry(
            correlation_id=request.correlation_id,
            action_type=IAMActionType.QUARANTINE_USER,
            target_uid=request.target_uid,
            target_dn=original_user.dn if original_user else None,
            initiated_by=request.initiated_by,
            service_account=self._get_service_account_identifier(),
            source_ip=request.source_ip,
            duration_ms=execution_time_ms,
            reason=request.reason,
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            playbook_id=request.playbook_id,
            success=True,
            changes={
                "groups_removed": original_groups,
                "account_disabled": True,
            },
            rollback_data=rollback_context.to_dict(),
        )

        # Fetch final state
        final_fetch = await self.fetch_user(fetch_request)

        return IAMActionResult(
            success=True,
            error_code=IAMErrorCode.SUCCESS,
            message=f"User {request.target_uid} quarantined: disabled and removed from {len(original_groups)} groups",
            user=final_fetch.user if final_fetch.success else None,
            audit=audit,
            rollback_context=rollback_context,
            sub_results=sub_results,
            execution_time_ms=execution_time_ms,
        )

    async def restore_user(self, request: IAMActionRequest, rollback_context: IAMRollbackContext) -> IAMActionResult:
        """
        Restore a quarantined user using saved rollback context.

        This reverses a quarantine by:
        1. Re-enabling the account
        2. Adding user back to original groups

        SOC Use Cases:
        - False positive reversal
        - Post-investigation restoration
        - Approval workflow rejection handling
        """
        start_time = datetime.now(timezone.utc)
        sub_results = []

        # Step 1: Enable account (if was disabled by quarantine)
        if rollback_context.previous_state == IAMUserState.ACTIVE:
            enable_request = IAMActionRequest(
                target_uid=request.target_uid,
                action_type=IAMActionType.ENABLE_ACCOUNT,
                initiated_by=request.initiated_by,
                source_ip=request.source_ip,
                reason=f"Restore from quarantine: {request.reason}",
                alert_id=request.alert_id,
                investigation_id=request.investigation_id,
                correlation_id=request.correlation_id,
            )
            enable_result = await self.enable_account(enable_request)
            sub_results.append(enable_result)

            if not enable_result.success and enable_result.error_code != IAMErrorCode.ACCOUNT_ALREADY_ENABLED:
                return IAMActionResult.failure(
                    error_code=enable_result.error_code,
                    message=f"Restore failed during account enable: {enable_result.message}",
                )

        # Step 2: Add back to original groups
        for group_name in rollback_context.previous_groups:
            add_request = IAMActionRequest(
                target_uid=request.target_uid,
                action_type=IAMActionType.ADD_TO_GROUP,
                initiated_by=request.initiated_by,
                source_ip=request.source_ip,
                reason=f"Restore group membership: {request.reason}",
                target_group=group_name,
                alert_id=request.alert_id,
                investigation_id=request.investigation_id,
                correlation_id=request.correlation_id,
            )
            add_result = await self.add_to_group(add_request)
            sub_results.append(add_result)

            if not add_result.success and add_result.error_code != IAMErrorCode.ALREADY_MEMBER:
                logger.warning(f"Failed to restore group {group_name} for {request.target_uid}: {add_result.message}")
                # Continue with other groups, log partial failure

        end_time = datetime.now(timezone.utc)
        execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

        # Update rollback context
        rollback_context.rollback_executed = True
        rollback_context.rollback_timestamp = end_time
        rollback_context.rollback_success = True

        # Fetch final state
        fetch_request = IAMActionRequest(
            target_uid=request.target_uid,
            action_type=IAMActionType.FETCH_USER,
            initiated_by=request.initiated_by,
            correlation_id=request.correlation_id,
        )
        final_fetch = await self.fetch_user(fetch_request)

        audit = IAMAuditEntry(
            correlation_id=request.correlation_id,
            action_type=IAMActionType.RESTORE_USER,
            target_uid=request.target_uid,
            target_dn=rollback_context.target_dn,
            initiated_by=request.initiated_by,
            service_account=self._get_service_account_identifier(),
            source_ip=request.source_ip,
            duration_ms=execution_time_ms,
            reason=request.reason,
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            playbook_id=request.playbook_id,
            success=True,
            changes={
                "account_enabled": rollback_context.previous_state == IAMUserState.ACTIVE,
                "groups_restored": rollback_context.previous_groups,
            },
        )

        return IAMActionResult(
            success=True,
            error_code=IAMErrorCode.SUCCESS,
            message=f"User {request.target_uid} restored: enabled and added to {len(rollback_context.previous_groups)} groups",
            user=final_fetch.user if final_fetch.success else None,
            audit=audit,
            sub_results=sub_results,
            execution_time_ms=execution_time_ms,
        )

    # =========================================================================
    # Rollback Support
    # =========================================================================

    async def rollback(self, rollback_context: IAMRollbackContext, reason: str, initiated_by: str) -> IAMActionResult:
        """
        Execute a rollback using saved context.

        This is the generic rollback dispatcher that routes to appropriate
        undo operations based on the original action type.
        """
        request = IAMActionRequest(
            target_uid=rollback_context.target_uid,
            action_type=rollback_context.action_type,
            initiated_by=initiated_by,
            reason=f"Rollback: {reason}",
        )

        if rollback_context.action_type == IAMActionType.DISABLE_ACCOUNT:
            return await self.enable_account(request)

        elif rollback_context.action_type == IAMActionType.ENABLE_ACCOUNT:
            return await self.disable_account(request)

        elif rollback_context.action_type == IAMActionType.QUARANTINE_USER:
            return await self.restore_user(request, rollback_context)

        elif rollback_context.action_type == IAMActionType.RESET_PASSWORD:
            # Password reset cannot be truly rolled back
            rollback_context.rollback_executed = True
            rollback_context.rollback_success = False
            rollback_context.rollback_error = "Password reset cannot be rolled back - old password unknown"
            return IAMActionResult.failure(
                error_code=IAMErrorCode.ROLLBACK_FAILED,
                message="Password reset cannot be rolled back. User must set a new password.",
            )

        elif rollback_context.action_type == IAMActionType.ADD_TO_GROUP:
            request.target_group = rollback_context.previous_attributes.get('group_name')
            return await self.remove_from_group(request)

        elif rollback_context.action_type == IAMActionType.REMOVE_FROM_GROUP:
            request.target_group = rollback_context.previous_attributes.get('group_name')
            return await self.add_to_group(request)

        else:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.ROLLBACK_FAILED,
                message=f"Rollback not supported for action type: {rollback_context.action_type}",
            )

    @abstractmethod
    async def _execute_rollback(self, rollback_context: IAMRollbackContext) -> bool:
        """
        Internal method to execute a single rollback operation.
        Used during composite action failures.
        """
        pass

    @abstractmethod
    def _get_service_account_identifier(self) -> str:
        """Return identifier of the service account used for operations."""
        pass
