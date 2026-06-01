# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tenancy and Identity Models

Core models for multi-tenant architecture and user management.
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text,
    ForeignKey, Index, UniqueConstraint, Table
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, CITEXT
from sqlalchemy.orm import relationship

from .base import (
    Base, TenantMixin, TimestampMixin, MutableTimestampMixin,
    generate_uuid, UserStatus, TenantStatus
)


class Tenant(Base, TimestampMixin):
    """
    Tenant (Organization) - Top-level isolation boundary.
    All data is scoped to a tenant.
    """
    __tablename__ = 'tenants'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name = Column(Text, nullable=False)
    slug = Column(String(100), unique=True, nullable=False)  # URL-safe identifier
    status = Column(String(20), nullable=False, default=TenantStatus.ACTIVE)
    
    # Settings
    settings = Column(Text, nullable=True)  # JSON string for tenant settings
    
    # Relationships
    users = relationship('User', back_populates='tenant', lazy='dynamic')
    roles = relationship('Role', back_populates='tenant', lazy='dynamic')
    
    __table_args__ = (
        Index('ix_tenants_status', 'status'),
        Index('ix_tenants_slug', 'slug'),
    )


class User(Base, TenantMixin, MutableTimestampMixin):
    """
    User account within a tenant.
    """
    __tablename__ = 'users'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    email = Column(CITEXT, nullable=False)
    display_name = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default=UserStatus.ACTIVE)
    
    # Authentication
    auth_type = Column(String(20), nullable=False, default='local')  # local, oidc, saml
    password_hash = Column(Text, nullable=True)  # Only for local auth
    
    # Tracking
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(Text, nullable=True)
    failed_login_count = Column(Text, default='0')  # String for simplicity
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(Text, nullable=True)  # Encrypted
    
    # Relationships
    tenant = relationship('Tenant', back_populates='users')
    roles = relationship('Role', secondary='user_roles', back_populates='users')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='uq_users_tenant_email'),
        Index('ix_users_tenant_status', 'tenant_id', 'status'),
        Index('ix_users_tenant_email', 'tenant_id', 'email'),
    )


class Role(Base, TenantMixin, TimestampMixin):
    """
    Role definition within a tenant.
    System roles (is_system=True) cannot be modified.
    """
    __tablename__ = 'roles'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_system = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    tenant = relationship('Tenant', back_populates='roles')
    permissions = relationship('Permission', secondary='role_permissions', back_populates='roles')
    users = relationship('User', secondary='user_roles', back_populates='roles')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'name', name='uq_roles_tenant_name'),
        Index('ix_roles_tenant_name', 'tenant_id', 'name'),
    )


class Permission(Base):
    """
    Permission definition (global, not tenant-specific).
    Permissions follow pattern: <resource>:<verb>[:<scope>]
    """
    __tablename__ = 'permissions'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    key = Column(String(200), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=True)  # For grouping in UI
    is_system = Column(Boolean, default=False)  # System permissions cannot be modified
    
    # Relationships
    roles = relationship('Role', secondary='role_permissions', back_populates='permissions')
    
    __table_args__ = (
        Index('ix_permissions_key', 'key'),
        Index('ix_permissions_category', 'category'),
    )


# Association tables
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('tenant_id', PGUUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
    Column('role_id', PGUUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
    Column('permission_id', PGUUID(as_uuid=True), ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False),
    Column('granted_at', DateTime(timezone=True), default=datetime.utcnow),
    Column('granted_by', PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    UniqueConstraint('tenant_id', 'role_id', 'permission_id', name='uq_role_permissions'),
    Index('ix_role_permissions_tenant_role', 'tenant_id', 'role_id'),
    Index('ix_role_permissions_tenant_permission', 'tenant_id', 'permission_id'),
)


user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('tenant_id', PGUUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
    Column('user_id', PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
    Column('role_id', PGUUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
    Column('assigned_at', DateTime(timezone=True), default=datetime.utcnow),
    Column('assigned_by', PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    UniqueConstraint('tenant_id', 'user_id', 'role_id', name='uq_user_roles'),
    Index('ix_user_roles_tenant_user', 'tenant_id', 'user_id'),
    Index('ix_user_roles_tenant_role', 'tenant_id', 'role_id'),
)


# Default permissions to seed
DEFAULT_PERMISSIONS = [
    # Tenant
    ('tenant:read', 'View tenant information', 'tenant'),
    
    # Users
    ('user:read', 'View users', 'users'),
    ('user:create', 'Create users', 'users'),
    ('user:update', 'Update users', 'users'),
    ('user:disable', 'Disable users', 'users'),
    
    # Roles
    ('role:read', 'View roles', 'roles'),
    ('role:create', 'Create roles', 'roles'),
    ('role:update', 'Update roles', 'roles'),
    ('role:delete', 'Delete roles', 'roles'),
    
    # Permissions
    ('permission:read', 'View permissions', 'permissions'),
    
    # Settings
    ('settings:read', 'View settings', 'settings'),
    ('settings:update', 'Update settings', 'settings'),
    
    # Retention
    ('retention:read', 'View retention policies', 'retention'),
    ('retention:update', 'Update retention policies', 'retention'),
    
    # Audit
    ('audit:read', 'View audit logs', 'audit'),
    
    # Investigations
    ('investigation:read', 'View investigations', 'investigations'),
    ('investigation:create', 'Create investigations', 'investigations'),
    ('investigation:update', 'Update investigations', 'investigations'),
    ('investigation:assign', 'Assign investigations', 'investigations'),
    ('investigation:close', 'Close investigations', 'investigations'),
    
    # Alerts
    ('alert:read', 'View alerts', 'alerts'),
    ('alert:update', 'Update alerts', 'alerts'),
    ('alert:link', 'Link alerts to investigations', 'alerts'),
    
    # Notes
    ('note:read', 'View notes', 'notes'),
    ('note:create', 'Create notes', 'notes'),
    ('note:update', 'Update notes', 'notes'),
    ('note:delete', 'Delete notes', 'notes'),
    
    # Files/Evidence
    ('file:upload', 'Upload files', 'files'),
    ('file:read', 'View file metadata', 'files'),
    ('file:download', 'Download files', 'files'),
    ('file:delete', 'Delete files (admin)', 'files'),
    
    # Actions
    ('action:read', 'View action history', 'actions'),
    ('action:execute', 'Execute actions', 'actions'),

    # Integrations (Connect)
    ('integration:view', 'View integrations and marketplace', 'integrations'),
    ('integration:install', 'Install or uninstall integrations', 'integrations'),
    ('integration:configure', 'Configure integrations, credentials, and test connections', 'integrations'),
    ('integration:manage', 'Full integration management including custom connectors', 'integrations'),

    # Playbooks
    ('playbook:view', 'View playbooks and templates', 'playbooks'),
    ('playbook:create', 'Create new playbooks', 'playbooks'),
    ('playbook:edit', 'Edit and update playbooks', 'playbooks'),
    ('playbook:execute', 'Execute playbooks manually', 'playbooks'),
    ('playbook:delete', 'Delete playbooks', 'playbooks'),

    # System/Jobs
    ('job:run', 'Run system jobs', 'system'),
]


# Default roles with their permissions
DEFAULT_ROLES = {
    'Admin': {
        'description': 'Full administrative access',
        'permissions': ['*'],  # All permissions
    },
    'Analyst': {
        'description': 'Security analyst with investigation capabilities',
        'permissions': [
            'tenant:read',
            'investigation:read', 'investigation:create', 'investigation:update',
            'investigation:assign', 'investigation:close',
            'alert:read', 'alert:update', 'alert:link',
            'note:read', 'note:create', 'note:update',
            'file:upload', 'file:read', 'file:download',
            'action:read', 'action:execute',
            'integration:view',
            'playbook:view', 'playbook:execute',
        ],
    },
    'ReadOnly': {
        'description': 'Read-only access to investigations and alerts',
        'permissions': [
            'tenant:read',
            'investigation:read',
            'alert:read',
            'note:read',
            'file:read',
            'action:read',
            'integration:view',
            'playbook:view',
        ],
    },
    'Automation': {
        'description': 'Service account for automation',
        'permissions': [
            'action:execute',
            'playbook:execute',
            'integration:view',
        ],
    },
}
