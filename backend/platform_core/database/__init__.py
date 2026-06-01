# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform Database Models

All SQLAlchemy models for the enterprise SOC platform.
"""

from .base import (
    Base,
    TenantMixin,
    TimestampMixin,
    MutableTimestampMixin,
    SoftDeleteMixin,
    generate_uuid,
    # Constants
    UserStatus,
    TenantStatus,
    InvestigationStatus,
    Severity,
    Priority,
    FileStatus,
    SandboxStatus,
    ActionStatus,
    RiskLevel,
    DataClass,
    EntityType,
    ActorType,
)

from .identity import (
    Tenant,
    User,
    Role,
    Permission,
    role_permissions,
    user_roles,
    DEFAULT_PERMISSIONS,
    DEFAULT_ROLES,
)

from .investigations import (
    Investigation,
    Alert,
    investigation_alerts,
    generate_investigation_number,
    generate_alert_id,
)

from .evidence import (
    Note,
    File,
    Attachment,
)

from .integrations import (
    Integration,
    IntegrationAction,
    ActionResult,
)

from .audit import (
    AuditEvent,
    RetentionPolicy,
    AuditAction,
    AuditCategory,
    MINIMUM_RETENTION_DAYS,
    DEFAULT_RETENTION_DAYS,
)

__all__ = [
    # Base
    'Base',
    'TenantMixin',
    'TimestampMixin',
    'MutableTimestampMixin',
    'SoftDeleteMixin',
    'generate_uuid',
    # Constants
    'UserStatus',
    'TenantStatus',
    'InvestigationStatus',
    'Severity',
    'Priority',
    'FileStatus',
    'SandboxStatus',
    'ActionStatus',
    'RiskLevel',
    'DataClass',
    'EntityType',
    'ActorType',
    # Identity
    'Tenant',
    'User',
    'Role',
    'Permission',
    'role_permissions',
    'user_roles',
    'DEFAULT_PERMISSIONS',
    'DEFAULT_ROLES',
    # Investigations
    'Investigation',
    'Alert',
    'investigation_alerts',
    'generate_investigation_number',
    'generate_alert_id',
    # Evidence
    'Note',
    'File',
    'Attachment',
    # Integrations
    'Integration',
    'IntegrationAction',
    'ActionResult',
    # Audit
    'AuditEvent',
    'RetentionPolicy',
    'AuditAction',
    'AuditCategory',
    'MINIMUM_RETENTION_DAYS',
    'DEFAULT_RETENTION_DAYS',
]
