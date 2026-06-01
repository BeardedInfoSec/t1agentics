# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
OpenLDAP Adapter for IAM Operations

Implements IAM operations for OpenLDAP directory services.
Uses LDAP3 library for connection management.

Security Controls:
- TLS/LDAPS required for production (configurable for testing)
- Service account authentication only
- No anonymous binds
- Connection pooling for performance
- Automatic reconnection on failure

OpenLDAP-Specific Implementation:
- Account disable: Uses pwdAccountLockedTime attribute (ppolicy overlay)
- Group membership: Uses posixGroup with memberUid attribute
- Password operations: Uses LDAP password modify extended operation

Active Directory Differences (for future implementation):
- Account disable: Uses userAccountControl bit flags
- Group membership: Uses member attribute with full DN
- Password operations: Uses unicodePwd attribute with specific encoding

Author: T1 Agentics Security Team
"""

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass

# LDAP3 is the recommended LDAP library for Python
# pip install ldap3
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
    from ldap3.extend.standard.modifyPassword import ModifyPassword
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
    ldap3 = None

from .base import (
    IAMAdapter,
    IAMActionRequest,
    IAMActionResult,
    IAMActionType,
    IAMUserState,
    IAMUser,
    IAMGroup,
    IAMAuditEntry,
    IAMRollbackContext,
    IAMErrorCode,
)

logger = logging.getLogger(__name__)


@dataclass
class OpenLDAPConfig:
    """
    Configuration for OpenLDAP connection.

    All sensitive values should come from environment variables or secrets manager.
    """
    # Connection settings
    host: str = "192.168.128.106"
    port: int = 636  # LDAPS default
    use_ssl: bool = True  # LDAPS
    use_tls: bool = False  # StartTLS (alternative to LDAPS)

    # Base DNs
    base_dn: str = "dc=T1 Agentics,dc=local"
    user_ou: str = "ou=people,dc=T1 Agentics,dc=local"
    group_ou: str = "ou=groups,dc=T1 Agentics,dc=local"
    service_accounts_ou: str = "ou=service_accounts,dc=T1 Agentics,dc=local"

    # Service account credentials
    service_account_dn: str = "uid=svc_T1 Agentics,ou=service_accounts,dc=T1 Agentics,dc=local"
    service_account_password: str = ""  # Must be set from secure source

    # Connection pool settings
    pool_size: int = 5
    pool_lifetime: int = 3600  # seconds

    # Timeout settings
    connect_timeout: int = 10  # seconds
    operation_timeout: int = 30  # seconds

    # TLS settings
    validate_certs: bool = True  # Set False only for testing
    ca_certs_file: Optional[str] = None

    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0  # seconds

    def get_server_uri(self) -> str:
        """Get the LDAP server URI."""
        protocol = "ldaps" if self.use_ssl else "ldap"
        return f"{protocol}://{self.host}:{self.port}"


class OpenLDAPAdapter(IAMAdapter):
    """
    OpenLDAP implementation of the IAM adapter.

    Thread-safe, supports connection pooling, and implements all required
    IAM operations with full audit logging and rollback support.
    """

    # OpenLDAP-specific attribute mappings
    ATTR_UID = "uid"
    ATTR_CN = "cn"
    ATTR_SN = "sn"
    ATTR_GIVEN_NAME = "givenName"
    ATTR_DISPLAY_NAME = "displayName"
    ATTR_MAIL = "mail"
    ATTR_MEMBER_UID = "memberUid"

    # Password policy attributes (requires ppolicy overlay)
    ATTR_PWD_ACCOUNT_LOCKED_TIME = "pwdAccountLockedTime"
    ATTR_PWD_CHANGED_TIME = "pwdChangedTime"
    ATTR_PWD_FAILURE_TIME = "pwdFailureTime"
    ATTR_PWD_HISTORY = "pwdHistory"

    # Operational attributes
    ATTR_CREATE_TIMESTAMP = "createTimestamp"
    ATTR_MODIFY_TIMESTAMP = "modifyTimestamp"

    # Lock time value to disable account (max value = permanent lock)
    LOCK_TIME_PERMANENT = "000001010000Z"  # Epoch time in generalized time format

    def __init__(self, config: Optional[OpenLDAPConfig] = None):
        """
        Initialize the OpenLDAP adapter.

        Args:
            config: OpenLDAP configuration. If None, uses defaults.
        """
        if not LDAP3_AVAILABLE:
            raise ImportError(
                "ldap3 library is required for OpenLDAP adapter. "
                "Install with: pip install ldap3"
            )

        self.config = config or OpenLDAPConfig()
        self._server: Optional[ldap3.Server] = None
        self._connection: Optional[ldap3.Connection] = None
        self._connected = False
        self._lock = asyncio.Lock()

    @property
    def adapter_type(self) -> str:
        return "openldap"

    @property
    def is_connected(self) -> bool:
        return self._connected and self._connection is not None and self._connection.bound

    async def connect(self) -> bool:
        """
        Establish connection to OpenLDAP server.

        Uses service account credentials for authentication.
        Supports both LDAPS and StartTLS.
        """
        async with self._lock:
            if self.is_connected:
                return True

            try:
                # Configure TLS if needed
                tls_config = None
                if self.config.use_ssl or self.config.use_tls:
                    tls_config = ldap3.Tls(
                        validate=ssl.CERT_REQUIRED if self.config.validate_certs else ssl.CERT_NONE,
                        ca_certs_file=self.config.ca_certs_file,
                    )

                # Create server object
                self._server = Server(
                    host=self.config.host,
                    port=self.config.port,
                    use_ssl=self.config.use_ssl,
                    tls=tls_config,
                    get_info=ALL,
                    connect_timeout=self.config.connect_timeout,
                )

                # Create connection with service account
                self._connection = Connection(
                    self._server,
                    user=self.config.service_account_dn,
                    password=self.config.service_account_password,
                    auto_bind=False,
                    raise_exceptions=True,
                    receive_timeout=self.config.operation_timeout,
                )

                # Bind to server
                if self.config.use_tls and not self.config.use_ssl:
                    # StartTLS
                    self._connection.open()
                    self._connection.start_tls()

                bound = self._connection.bind()

                if not bound:
                    logger.error(f"LDAP bind failed: {self._connection.result}")
                    return False

                self._connected = True
                logger.info(f"Connected to OpenLDAP server at {self.config.get_server_uri()}")
                return True

            except LDAPBindError as e:
                logger.error(f"LDAP bind error (invalid credentials?): {e}")
                return False
            except LDAPSocketOpenError as e:
                logger.error(f"LDAP connection failed: {e}")
                return False
            except LDAPException as e:
                logger.error(f"LDAP error: {e}")
                return False
            except Exception as e:
                logger.error(f"Unexpected error connecting to LDAP: {e}")
                return False

    async def disconnect(self) -> None:
        """Close connection to OpenLDAP server."""
        async with self._lock:
            if self._connection:
                try:
                    self._connection.unbind()
                except Exception as e:
                    logger.warning(f"Error unbinding LDAP connection: {e}")
                finally:
                    self._connection = None
                    self._connected = False
                    logger.info("Disconnected from OpenLDAP server")

    async def test_connection(self) -> IAMActionResult:
        """Test connectivity and service account authentication."""
        start_time = datetime.now(timezone.utc)

        try:
            connected = await self.connect()
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            if connected:
                # Verify we can search
                search_result = self._connection.search(
                    search_base=self.config.base_dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["namingContexts"],
                )

                if search_result:
                    return IAMActionResult.success_result(
                        message=f"Successfully connected to {self.config.get_server_uri()}",
                        audit=IAMAuditEntry(
                            action_type=IAMActionType.VALIDATE_STATE,
                            target_uid="__connection_test__",
                            initiated_by="system",
                            service_account=self.config.service_account_dn,
                            success=True,
                            duration_ms=execution_time_ms,
                        ),
                    )
                else:
                    return IAMActionResult.failure(
                        error_code=IAMErrorCode.CONNECTION_FAILED,
                        message=f"Connected but search failed: {self._connection.result}",
                    )
            else:
                return IAMActionResult.failure(
                    error_code=IAMErrorCode.CONNECTION_FAILED,
                    message="Failed to connect to LDAP server",
                )

        except Exception as e:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message=f"Connection test failed: {str(e)}",
            )

    async def _ensure_connected(self) -> bool:
        """Ensure we have an active connection, reconnecting if needed."""
        if self.is_connected:
            return True

        for attempt in range(self.config.max_retries):
            if await self.connect():
                return True
            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(self.config.retry_delay)

        return False

    def _get_service_account_identifier(self) -> str:
        """Return the service account DN."""
        return self.config.service_account_dn

    # =========================================================================
    # User Lookup Helpers
    # =========================================================================

    def _get_user_dn(self, uid: str) -> str:
        """Construct user DN from uid."""
        return f"uid={uid},{self.config.user_ou}"

    def _get_group_dn(self, group_name: str) -> str:
        """Construct group DN from group name."""
        return f"cn={group_name},{self.config.group_ou}"

    async def _find_user(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Find a user by uid and return their attributes.

        Returns None if user not found.
        """
        if not await self._ensure_connected():
            return None

        search_filter = f"(uid={ldap3.utils.conv.escape_filter_chars(uid)})"

        try:
            found = self._connection.search(
                search_base=self.config.user_ou,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=[
                    self.ATTR_UID,
                    self.ATTR_CN,
                    self.ATTR_DISPLAY_NAME,
                    self.ATTR_MAIL,
                    self.ATTR_PWD_ACCOUNT_LOCKED_TIME,
                    self.ATTR_PWD_CHANGED_TIME,
                    self.ATTR_CREATE_TIMESTAMP,
                    "*",  # All user attributes
                ],
            )

            if found and len(self._connection.entries) > 0:
                entry = self._connection.entries[0]
                return {
                    "dn": str(entry.entry_dn),
                    "attributes": dict(entry.entry_attributes_as_dict),
                }

            return None

        except LDAPException as e:
            logger.error(f"Error searching for user {uid}: {e}")
            return None

    async def _get_user_groups(self, uid: str) -> List[str]:
        """Get list of groups a user belongs to."""
        if not await self._ensure_connected():
            return []

        # For posixGroup, search for groups containing the uid in memberUid
        search_filter = f"(&(objectClass=posixGroup)(memberUid={ldap3.utils.conv.escape_filter_chars(uid)}))"

        try:
            found = self._connection.search(
                search_base=self.config.group_ou,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["cn"],
            )

            if found:
                return [str(entry.cn) for entry in self._connection.entries]

            return []

        except LDAPException as e:
            logger.error(f"Error getting groups for user {uid}: {e}")
            return []

    def _parse_user_state(self, attributes: Dict[str, Any]) -> IAMUserState:
        """
        Determine user state from LDAP attributes.

        OpenLDAP uses pwdAccountLockedTime from the ppolicy overlay
        to indicate a locked/disabled account.
        """
        locked_time = attributes.get(self.ATTR_PWD_ACCOUNT_LOCKED_TIME)

        if locked_time:
            # Account is locked/disabled
            return IAMUserState.DISABLED

        return IAMUserState.ACTIVE

    def _build_iam_user(
        self,
        uid: str,
        dn: str,
        attributes: Dict[str, Any],
        groups: List[str]
    ) -> IAMUser:
        """Build an IAMUser object from LDAP attributes."""

        def get_first(attr_list):
            """Get first value from attribute list or None."""
            if attr_list and len(attr_list) > 0:
                return attr_list[0]
            return None

        def parse_timestamp(val):
            """Parse LDAP timestamp to datetime."""
            if not val:
                return None
            try:
                # LDAP generalized time format: 20231215120000Z
                if isinstance(val, list):
                    val = val[0]
                if isinstance(val, datetime):
                    return val
                return datetime.strptime(str(val), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
            except Exception:
                return None

        state = self._parse_user_state(attributes)

        return IAMUser(
            uid=uid,
            dn=dn,
            display_name=get_first(attributes.get(self.ATTR_DISPLAY_NAME)) or get_first(attributes.get(self.ATTR_CN)),
            email=get_first(attributes.get(self.ATTR_MAIL)),
            state=state,
            groups=tuple(groups),
            created_at=parse_timestamp(get_first(attributes.get(self.ATTR_CREATE_TIMESTAMP))),
            password_last_set=parse_timestamp(get_first(attributes.get(self.ATTR_PWD_CHANGED_TIME))),
            disabled_at=parse_timestamp(get_first(attributes.get(self.ATTR_PWD_ACCOUNT_LOCKED_TIME))) if state == IAMUserState.DISABLED else None,
            attributes={k: v for k, v in attributes.items() if not k.startswith("pwd")},  # Exclude password-related
        )

    # =========================================================================
    # Core IAM Operations
    # =========================================================================

    async def disable_account(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Disable a user account by setting pwdAccountLockedTime.

        OpenLDAP Implementation:
        - Sets pwdAccountLockedTime to a past date (epoch)
        - This is interpreted by ppolicy as a permanent lock
        - User cannot authenticate until the attribute is removed

        Rollback:
        - Removes pwdAccountLockedTime attribute
        """
        start_time = datetime.now(timezone.utc)

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Find the user
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
            )

        user_dn = user_data["dn"]
        attributes = user_data["attributes"]

        # Check current state
        current_state = self._parse_user_state(attributes)
        if current_state == IAMUserState.DISABLED:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            # Return success but note it was already disabled
            audit = self._create_audit_entry(
                request=request,
                target_dn=user_dn,
                success=True,
                duration_ms=execution_time_ms,
                error_code=IAMErrorCode.ACCOUNT_ALREADY_DISABLED,
                changes={"already_disabled": True},
            )

            groups = await self._get_user_groups(request.target_uid)
            user = self._build_iam_user(request.target_uid, user_dn, attributes, groups)

            return IAMActionResult(
                success=True,
                error_code=IAMErrorCode.ACCOUNT_ALREADY_DISABLED,
                message=f"Account {request.target_uid} was already disabled",
                user=user,
                audit=audit,
                execution_time_ms=execution_time_ms,
            )

        # Capture rollback context
        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.DISABLE_ACCOUNT,
            target_uid=request.target_uid,
            target_dn=user_dn,
            previous_state=current_state,
        )

        # Disable by setting pwdAccountLockedTime
        try:
            success = self._connection.modify(
                user_dn,
                {self.ATTR_PWD_ACCOUNT_LOCKED_TIME: [(MODIFY_REPLACE, [self.LOCK_TIME_PERMANENT])]}
            )

            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            if success:
                # Fetch updated user state
                updated_data = await self._find_user(request.target_uid)
                groups = await self._get_user_groups(request.target_uid)
                user = self._build_iam_user(
                    request.target_uid,
                    user_dn,
                    updated_data["attributes"] if updated_data else attributes,
                    groups
                )

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    changes={"account_disabled": True, "previous_state": current_state.value},
                    rollback_data=rollback_context.to_dict(),
                )

                logger.info(f"Disabled account {request.target_uid} - Reason: {request.reason}")

                return IAMActionResult.success_result(
                    message=f"Account {request.target_uid} has been disabled",
                    user=user,
                    audit=audit,
                    rollback_context=rollback_context,
                )

            else:
                error_msg = self._connection.result.get('description', 'Unknown error')
                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    error_message=error_msg,
                )

                return IAMActionResult.failure(
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    message=f"Failed to disable account: {error_msg}",
                    audit=audit,
                )

        except LDAPException as e:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            error_code = self._map_ldap_exception(e)
            audit = self._create_audit_entry(
                request=request,
                target_dn=user_dn,
                success=False,
                duration_ms=execution_time_ms,
                error_code=error_code,
                error_message=str(e),
            )

            return IAMActionResult.failure(
                error_code=error_code,
                message=f"LDAP error disabling account: {str(e)}",
                audit=audit,
            )

    async def enable_account(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Re-enable a disabled user account by removing pwdAccountLockedTime.

        OpenLDAP Implementation:
        - Removes the pwdAccountLockedTime attribute
        - User can authenticate again after this
        """
        start_time = datetime.now(timezone.utc)

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Find the user
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
            )

        user_dn = user_data["dn"]
        attributes = user_data["attributes"]

        # Check current state
        current_state = self._parse_user_state(attributes)
        if current_state == IAMUserState.ACTIVE:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            audit = self._create_audit_entry(
                request=request,
                target_dn=user_dn,
                success=True,
                duration_ms=execution_time_ms,
                error_code=IAMErrorCode.ACCOUNT_ALREADY_ENABLED,
                changes={"already_enabled": True},
            )

            groups = await self._get_user_groups(request.target_uid)
            user = self._build_iam_user(request.target_uid, user_dn, attributes, groups)

            return IAMActionResult(
                success=True,
                error_code=IAMErrorCode.ACCOUNT_ALREADY_ENABLED,
                message=f"Account {request.target_uid} was already enabled",
                user=user,
                audit=audit,
                execution_time_ms=execution_time_ms,
            )

        # Capture rollback context
        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.ENABLE_ACCOUNT,
            target_uid=request.target_uid,
            target_dn=user_dn,
            previous_state=current_state,
        )

        # Enable by removing pwdAccountLockedTime
        try:
            success = self._connection.modify(
                user_dn,
                {self.ATTR_PWD_ACCOUNT_LOCKED_TIME: [(MODIFY_DELETE, [])]}
            )

            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            if success or 'noSuchAttribute' in str(self._connection.result):
                # Success or attribute didn't exist (already enabled)
                updated_data = await self._find_user(request.target_uid)
                groups = await self._get_user_groups(request.target_uid)
                user = self._build_iam_user(
                    request.target_uid,
                    user_dn,
                    updated_data["attributes"] if updated_data else attributes,
                    groups
                )

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    changes={"account_enabled": True, "previous_state": current_state.value},
                    rollback_data=rollback_context.to_dict(),
                )

                logger.info(f"Enabled account {request.target_uid} - Reason: {request.reason}")

                return IAMActionResult.success_result(
                    message=f"Account {request.target_uid} has been enabled",
                    user=user,
                    audit=audit,
                    rollback_context=rollback_context,
                )

            else:
                error_msg = self._connection.result.get('description', 'Unknown error')
                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    error_message=error_msg,
                )

                return IAMActionResult.failure(
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    message=f"Failed to enable account: {error_msg}",
                    audit=audit,
                )

        except LDAPException as e:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            error_code = self._map_ldap_exception(e)
            audit = self._create_audit_entry(
                request=request,
                target_dn=user_dn,
                success=False,
                duration_ms=execution_time_ms,
                error_code=error_code,
                error_message=str(e),
            )

            return IAMActionResult.failure(
                error_code=error_code,
                message=f"LDAP error enabling account: {str(e)}",
                audit=audit,
            )

    async def reset_password(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Reset user's password using LDAP password modify extended operation.

        OpenLDAP Implementation:
        - Uses RFC 3062 password modify extended operation
        - Supports both admin reset (no old password) and user change
        - Password policy enforcement (if ppolicy overlay enabled)

        Important: Password reset cannot be rolled back - the old password
        is not known and cannot be restored.
        """
        start_time = datetime.now(timezone.utc)

        if not request.new_password:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.INVALID_PASSWORD_POLICY,
                message="New password is required",
            )

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Find the user
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
            )

        user_dn = user_data["dn"]

        # Capture rollback context (note: password reset is NOT reversible)
        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.RESET_PASSWORD,
            target_uid=request.target_uid,
            target_dn=user_dn,
            password_was_reset=True,
        )

        try:
            # Use LDAP password modify extended operation
            # This is the RFC 3062 compliant way to change passwords
            modify_password = ModifyPassword(
                self._connection,
                user=user_dn,
                new_password=request.new_password,
            )

            if modify_password.result is None:
                modify_password.send()

            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            # Check result
            if self._connection.result['result'] == 0:
                # Success
                updated_data = await self._find_user(request.target_uid)
                groups = await self._get_user_groups(request.target_uid)
                user = self._build_iam_user(
                    request.target_uid,
                    user_dn,
                    updated_data["attributes"] if updated_data else user_data["attributes"],
                    groups
                )

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    changes={"password_reset": True},
                    rollback_data=rollback_context.to_dict(),
                )

                logger.info(f"Reset password for {request.target_uid} - Reason: {request.reason}")

                return IAMActionResult.success_result(
                    message=f"Password reset for {request.target_uid}",
                    user=user,
                    audit=audit,
                    rollback_context=rollback_context,
                )

            else:
                # Password policy violation or other error
                error_msg = self._connection.result.get('message', self._connection.result.get('description', 'Unknown error'))

                # Check for common password policy violations
                if 'constraint' in error_msg.lower() or 'policy' in error_msg.lower():
                    error_code = IAMErrorCode.INVALID_PASSWORD_POLICY
                else:
                    error_code = IAMErrorCode.UNKNOWN_ERROR

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=error_code,
                    error_message=error_msg,
                )

                return IAMActionResult.failure(
                    error_code=error_code,
                    message=f"Password reset failed: {error_msg}",
                    audit=audit,
                )

        except LDAPException as e:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            error_code = self._map_ldap_exception(e)
            audit = self._create_audit_entry(
                request=request,
                target_dn=user_dn,
                success=False,
                duration_ms=execution_time_ms,
                error_code=error_code,
                error_message=str(e),
            )

            return IAMActionResult.failure(
                error_code=error_code,
                message=f"LDAP error resetting password: {str(e)}",
                audit=audit,
            )

    async def validate_state(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Check the current state of a user account.

        Read-only operation - validates whether account is active, disabled, etc.
        """
        start_time = datetime.now(timezone.utc)

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Find the user
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
                audit=self._create_audit_entry(
                    request=request,
                    target_dn=None,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=IAMErrorCode.USER_NOT_FOUND,
                ),
            )

        user_dn = user_data["dn"]
        attributes = user_data["attributes"]
        groups = await self._get_user_groups(request.target_uid)

        user = self._build_iam_user(request.target_uid, user_dn, attributes, groups)

        end_time = datetime.now(timezone.utc)
        execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

        audit = self._create_audit_entry(
            request=request,
            target_dn=user_dn,
            success=True,
            duration_ms=execution_time_ms,
            changes={"state_validated": user.state.value},
        )

        return IAMActionResult.success_result(
            message=f"User {request.target_uid} state: {user.state.value}",
            user=user,
            audit=audit,
        )

    async def fetch_user(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Fetch complete user information including group memberships.

        Same as validate_state but semantically indicates intent to retrieve
        full user data rather than just checking status.
        """
        # Implementation is the same as validate_state
        return await self.validate_state(request)

    # =========================================================================
    # Group Operations
    # =========================================================================

    async def add_to_group(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Add user to a group (posixGroup with memberUid).
        """
        start_time = datetime.now(timezone.utc)

        if not request.target_group:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.GROUP_NOT_FOUND,
                message="Target group is required",
            )

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Verify user exists
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
            )

        user_dn = user_data["dn"]
        group_dn = self._get_group_dn(request.target_group)

        # Check if already a member
        current_groups = await self._get_user_groups(request.target_uid)
        if request.target_group in current_groups:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            return IAMActionResult(
                success=True,
                error_code=IAMErrorCode.ALREADY_MEMBER,
                message=f"User {request.target_uid} is already a member of {request.target_group}",
                audit=self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    error_code=IAMErrorCode.ALREADY_MEMBER,
                ),
                execution_time_ms=execution_time_ms,
            )

        # Capture rollback context
        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.ADD_TO_GROUP,
            target_uid=request.target_uid,
            target_dn=user_dn,
            previous_attributes={"group_name": request.target_group},
        )

        try:
            # Add memberUid to the group (posixGroup style)
            success = self._connection.modify(
                group_dn,
                {self.ATTR_MEMBER_UID: [(MODIFY_ADD, [request.target_uid])]}
            )

            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            if success:
                groups = await self._get_user_groups(request.target_uid)
                user = self._build_iam_user(
                    request.target_uid,
                    user_dn,
                    user_data["attributes"],
                    groups
                )

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    changes={"added_to_group": request.target_group},
                    rollback_data=rollback_context.to_dict(),
                )

                logger.info(f"Added {request.target_uid} to group {request.target_group}")

                return IAMActionResult.success_result(
                    message=f"Added {request.target_uid} to group {request.target_group}",
                    user=user,
                    audit=audit,
                    rollback_context=rollback_context,
                )

            else:
                error_msg = self._connection.result.get('description', 'Unknown error')

                # Check if group doesn't exist
                if 'noSuchObject' in str(self._connection.result):
                    error_code = IAMErrorCode.GROUP_NOT_FOUND
                else:
                    error_code = IAMErrorCode.UNKNOWN_ERROR

                return IAMActionResult.failure(
                    error_code=error_code,
                    message=f"Failed to add to group: {error_msg}",
                    audit=self._create_audit_entry(
                        request=request,
                        target_dn=user_dn,
                        success=False,
                        duration_ms=execution_time_ms,
                        error_code=error_code,
                        error_message=error_msg,
                    ),
                )

        except LDAPException as e:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            error_code = self._map_ldap_exception(e)

            return IAMActionResult.failure(
                error_code=error_code,
                message=f"LDAP error adding to group: {str(e)}",
                audit=self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=error_code,
                    error_message=str(e),
                ),
            )

    async def remove_from_group(self, request: IAMActionRequest) -> IAMActionResult:
        """
        Remove user from a group (posixGroup with memberUid).
        """
        start_time = datetime.now(timezone.utc)

        if not request.target_group:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.GROUP_NOT_FOUND,
                message="Target group is required",
            )

        if not await self._ensure_connected():
            return IAMActionResult.failure(
                error_code=IAMErrorCode.CONNECTION_FAILED,
                message="Failed to connect to LDAP server",
            )

        # Verify user exists
        user_data = await self._find_user(request.target_uid)
        if not user_data:
            return IAMActionResult.failure(
                error_code=IAMErrorCode.USER_NOT_FOUND,
                message=f"User not found: {request.target_uid}",
            )

        user_dn = user_data["dn"]
        group_dn = self._get_group_dn(request.target_group)

        # Check if actually a member
        current_groups = await self._get_user_groups(request.target_uid)
        if request.target_group not in current_groups:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            return IAMActionResult(
                success=True,
                error_code=IAMErrorCode.NOT_A_MEMBER,
                message=f"User {request.target_uid} is not a member of {request.target_group}",
                audit=self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    error_code=IAMErrorCode.NOT_A_MEMBER,
                ),
                execution_time_ms=execution_time_ms,
            )

        # Capture rollback context
        rollback_context = IAMRollbackContext(
            action_type=IAMActionType.REMOVE_FROM_GROUP,
            target_uid=request.target_uid,
            target_dn=user_dn,
            previous_attributes={"group_name": request.target_group},
        )

        try:
            # Remove memberUid from the group
            success = self._connection.modify(
                group_dn,
                {self.ATTR_MEMBER_UID: [(MODIFY_DELETE, [request.target_uid])]}
            )

            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            if success:
                groups = await self._get_user_groups(request.target_uid)
                user = self._build_iam_user(
                    request.target_uid,
                    user_dn,
                    user_data["attributes"],
                    groups
                )

                audit = self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=True,
                    duration_ms=execution_time_ms,
                    changes={"removed_from_group": request.target_group},
                    rollback_data=rollback_context.to_dict(),
                )

                logger.info(f"Removed {request.target_uid} from group {request.target_group}")

                return IAMActionResult.success_result(
                    message=f"Removed {request.target_uid} from group {request.target_group}",
                    user=user,
                    audit=audit,
                    rollback_context=rollback_context,
                )

            else:
                error_msg = self._connection.result.get('description', 'Unknown error')
                return IAMActionResult.failure(
                    error_code=IAMErrorCode.UNKNOWN_ERROR,
                    message=f"Failed to remove from group: {error_msg}",
                )

        except LDAPException as e:
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            error_code = self._map_ldap_exception(e)

            return IAMActionResult.failure(
                error_code=error_code,
                message=f"LDAP error removing from group: {str(e)}",
                audit=self._create_audit_entry(
                    request=request,
                    target_dn=user_dn,
                    success=False,
                    duration_ms=execution_time_ms,
                    error_code=error_code,
                    error_message=str(e),
                ),
            )

    # =========================================================================
    # Rollback Support
    # =========================================================================

    async def _execute_rollback(self, rollback_context: IAMRollbackContext) -> bool:
        """Execute a single rollback operation."""
        try:
            request = IAMActionRequest(
                target_uid=rollback_context.target_uid,
                action_type=rollback_context.action_type,
                initiated_by="system_rollback",
                reason="Automatic rollback due to composite action failure",
            )

            result = await self.rollback(rollback_context, "Composite action failure", "system")
            return result.success

        except Exception as e:
            logger.error(f"Rollback failed for {rollback_context.target_uid}: {e}")
            return False

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _create_audit_entry(
        self,
        request: IAMActionRequest,
        target_dn: Optional[str],
        success: bool,
        duration_ms: int,
        error_code: Optional[IAMErrorCode] = None,
        error_message: Optional[str] = None,
        changes: Optional[Dict[str, Any]] = None,
        rollback_data: Optional[Dict[str, Any]] = None,
    ) -> IAMAuditEntry:
        """Create an audit entry for an IAM operation."""
        return IAMAuditEntry(
            correlation_id=request.correlation_id,
            action_type=request.action_type,
            target_uid=request.target_uid,
            target_dn=target_dn,
            initiated_by=request.initiated_by,
            service_account=self.config.service_account_dn,
            source_ip=request.source_ip,
            duration_ms=duration_ms,
            reason=request.reason,
            alert_id=request.alert_id,
            investigation_id=request.investigation_id,
            playbook_id=request.playbook_id,
            success=success,
            error_code=error_code or (IAMErrorCode.SUCCESS if success else IAMErrorCode.UNKNOWN_ERROR),
            error_message=error_message,
            changes=changes or {},
            rollback_data=rollback_data,
        )

    def _map_ldap_exception(self, e: Exception) -> IAMErrorCode:
        """Map LDAP exceptions to IAMErrorCode."""
        error_str = str(e).lower()

        if 'invalid credentials' in error_str or 'bind' in error_str:
            return IAMErrorCode.INVALID_CREDENTIALS
        elif 'no such object' in error_str:
            return IAMErrorCode.USER_NOT_FOUND
        elif 'insufficient access' in error_str or 'permission' in error_str:
            return IAMErrorCode.INSUFFICIENT_PERMISSIONS
        elif 'timeout' in error_str:
            return IAMErrorCode.TIMEOUT
        elif 'connect' in error_str or 'socket' in error_str:
            return IAMErrorCode.CONNECTION_FAILED
        else:
            return IAMErrorCode.UNKNOWN_ERROR
