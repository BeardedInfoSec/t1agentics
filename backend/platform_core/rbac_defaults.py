# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Default Permission and Role Definitions (no SQLAlchemy dependency).

This module is intentionally kept free of heavy imports so it can be
safely imported from lightweight code paths like dependencies/auth.py
without triggering the SQLAlchemy import chain in platform_core.database.
"""

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
