# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enhanced RBAC for SOC Operations
Defines permissions for alerts and investigations workflow
"""

from enum import Enum
from typing import List, Dict


class UserRole(str, Enum):
    """User roles for SOC operations"""
    PLATFORM_OWNER = "platform_owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    READ_ONLY = "read_only"


class SOCPermission(str, Enum):
    """SOC-specific permissions"""
    # Alert permissions
    VIEW_ALERTS = "view_alerts"
    FILTER_ALERTS = "filter_alerts"
    CREATE_INVESTIGATION = "create_investigation"
    UPDATE_ALERT_STATUS = "update_alert_status"
    
    # Investigation permissions
    VIEW_INVESTIGATIONS = "view_investigations"
    UPDATE_INVESTIGATION_STATE = "update_investigation_state"
    UPDATE_DISPOSITION = "update_disposition"
    ASSIGN_OWNER = "assign_owner"
    ADD_NOTES = "add_notes"
    CLOSE_INVESTIGATION = "close_investigation"
    
    # Sensitivity
    UPDATE_SENSITIVITY = "update_sensitivity"

    # User management
    MANAGE_USERS = "manage_users"
    VIEW_USERS = "view_users"


# RBAC Permissions Matrix (from requirements)
ROLE_PERMISSIONS: Dict[UserRole, List[SOCPermission]] = {
    UserRole.PLATFORM_OWNER: [
        # All permissions - highest level of access
        SOCPermission.VIEW_ALERTS,
        SOCPermission.FILTER_ALERTS,
        SOCPermission.CREATE_INVESTIGATION,
        SOCPermission.UPDATE_ALERT_STATUS,
        SOCPermission.VIEW_INVESTIGATIONS,
        SOCPermission.UPDATE_INVESTIGATION_STATE,
        SOCPermission.UPDATE_DISPOSITION,
        SOCPermission.ASSIGN_OWNER,
        SOCPermission.ADD_NOTES,
        SOCPermission.CLOSE_INVESTIGATION,
        SOCPermission.UPDATE_SENSITIVITY,
        SOCPermission.MANAGE_USERS,
        SOCPermission.VIEW_USERS,
    ],
    UserRole.ADMIN: [
        # All permissions
        SOCPermission.VIEW_ALERTS,
        SOCPermission.FILTER_ALERTS,
        SOCPermission.CREATE_INVESTIGATION,
        SOCPermission.UPDATE_ALERT_STATUS,
        SOCPermission.VIEW_INVESTIGATIONS,
        SOCPermission.UPDATE_INVESTIGATION_STATE,
        SOCPermission.UPDATE_DISPOSITION,
        SOCPermission.ASSIGN_OWNER,
        SOCPermission.ADD_NOTES,
        SOCPermission.CLOSE_INVESTIGATION,
        SOCPermission.UPDATE_SENSITIVITY,
        SOCPermission.MANAGE_USERS,
        SOCPermission.VIEW_USERS,
    ],
    UserRole.ANALYST: [
        # Standard SOC analyst permissions
        SOCPermission.VIEW_ALERTS,
        SOCPermission.FILTER_ALERTS,
        SOCPermission.CREATE_INVESTIGATION,
        SOCPermission.UPDATE_ALERT_STATUS,
        SOCPermission.VIEW_INVESTIGATIONS,
        SOCPermission.UPDATE_INVESTIGATION_STATE,
        SOCPermission.UPDATE_DISPOSITION,
        SOCPermission.ASSIGN_OWNER,
        SOCPermission.ADD_NOTES,
        SOCPermission.CLOSE_INVESTIGATION,
        SOCPermission.UPDATE_SENSITIVITY,
        SOCPermission.VIEW_USERS,  # Can see users for assignment
    ],
    UserRole.READ_ONLY: [
        # View-only access
        SOCPermission.VIEW_ALERTS,
        SOCPermission.FILTER_ALERTS,
        SOCPermission.VIEW_INVESTIGATIONS,
        SOCPermission.VIEW_USERS,  # Can see who's assigned
    ]
}


def has_permission(user_role: str, permission: SOCPermission) -> bool:
    """Check if a role has a specific permission"""
    try:
        role = UserRole(user_role)
        return permission in ROLE_PERMISSIONS.get(role, [])
    except (ValueError, KeyError):
        return False


def get_user_permissions(user_role: str) -> List[str]:
    """Get all permissions for a role"""
    try:
        role = UserRole(user_role)
        return [p.value for p in ROLE_PERMISSIONS.get(role, [])]
    except (ValueError, KeyError):
        return []
