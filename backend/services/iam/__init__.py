# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IAM (Identity and Access Management) Response Actions for T1 Agentics

This module provides automated response actions for identity management systems.
Supports OpenLDAP initially, designed for future Active Directory support.

Security Controls:
- Service account authentication only (no anonymous/admin binds)
- Full audit trail for all operations
- Rollback support for failed operations
- Structured responses for SOAR integration

Author: T1 Agentics Security Team
"""

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
)
from .openldap_adapter import OpenLDAPAdapter
from .iam_service import IAMService, get_iam_service

__all__ = [
    # Base classes
    'IAMAdapter',
    'IAMActionRequest',
    'IAMActionResult',
    'IAMActionType',
    'IAMUserState',
    'IAMUser',
    'IAMGroup',
    'IAMAuditEntry',
    'IAMRollbackContext',
    # Adapters
    'OpenLDAPAdapter',
    # Service
    'IAMService',
    'get_iam_service',
]
