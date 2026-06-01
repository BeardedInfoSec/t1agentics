# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform Layer Initial Schema

Revision ID: 001_platform_layer
Revises: 
Create Date: 2025-12-16

This migration creates the foundational platform layer tables.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001_platform_layer'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Enable required extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "citext"')
    
    # =========================================
    # TENANTS
    # =========================================
    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column('settings', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
    )
    
    # =========================================
    # USERS
    # =========================================
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', postgresql.CITEXT(), nullable=False),
        sa.Column('display_name', sa.Text(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column('auth_type', sa.String(20), nullable=False, server_default='local'),
        sa.Column('password_hash', sa.Text(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('mfa_enabled', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_users_tenant_email', 'users', ['tenant_id', 'email'], unique=True)
    
    # =========================================
    # ROLES AND PERMISSIONS
    # =========================================
    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_roles_tenant_name', 'roles', ['tenant_id', 'name'], unique=True)
    
    op.create_table(
        'permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('key', sa.String(200), unique=True, nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(50), nullable=True),
    )
    
    op.create_table(
        'role_permissions',
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_unique_constraint('uq_role_permissions', 'role_permissions', ['tenant_id', 'role_id', 'permission_id'])
    
    op.create_table(
        'user_roles',
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_unique_constraint('uq_user_roles', 'user_roles', ['tenant_id', 'user_id', 'role_id'])
    
    # =========================================
    # INVESTIGATIONS V2
    # =========================================
    op.create_table(
        'investigations_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('investigation_number', sa.String(20), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='new'),
        sa.Column('severity', sa.String(20), nullable=False, server_default='medium'),
        sa.Column('priority', sa.String(10), nullable=False, server_default='p3'),
        sa.Column('disposition', sa.String(30), nullable=True),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('tags', postgresql.JSONB(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_investigations_v2_tenant_number', 'investigations_v2', ['tenant_id', 'investigation_number'], unique=True)
    op.create_index('ix_investigations_v2_tenant_status', 'investigations_v2', ['tenant_id', 'status'])
    
    # =========================================
    # ALERTS V2
    # =========================================
    op.create_table(
        'alerts_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('alert_id', sa.String(50), nullable=False),
        sa.Column('alert_source', sa.String(100), nullable=False),
        sa.Column('alert_key', sa.String(500), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False, server_default='medium'),
        sa.Column('status', sa.String(30), nullable=False, server_default='open'),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('raw_event', postgresql.JSONB(), nullable=True),
        sa.Column('enrichment_data', postgresql.JSONB(), nullable=True),
        sa.Column('entities', postgresql.JSONB(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_alerts_v2_tenant_alert_id', 'alerts_v2', ['tenant_id', 'alert_id'], unique=True)
    op.create_index('ix_alerts_v2_tenant_detected', 'alerts_v2', ['tenant_id', 'detected_at'])
    
    op.create_table(
        'investigation_alerts_v2',
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('investigation_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('investigations_v2.id', ondelete='CASCADE'), nullable=False),
        sa.Column('alert_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('alerts_v2.id', ondelete='CASCADE'), nullable=False),
        sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint('uq_investigation_alerts_v2', 'investigation_alerts_v2', ['tenant_id', 'investigation_id', 'alert_id'])
    
    # =========================================
    # NOTES V2
    # =========================================
    op.create_table(
        'notes_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('parent_type', sa.String(50), nullable=False),
        sa.Column('parent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('note_type', sa.String(50), server_default='comment'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_notes_v2_tenant_parent', 'notes_v2', ['tenant_id', 'parent_type', 'parent_id'])
    
    # =========================================
    # FILES V2
    # =========================================
    op.create_table(
        'files_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('filename', sa.Text(), nullable=False),
        sa.Column('original_filename', sa.Text(), nullable=True),
        sa.Column('content_type', sa.String(255), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('md5', sa.String(32), nullable=True),
        sa.Column('storage_provider', sa.String(50), nullable=False, server_default='s3'),
        sa.Column('storage_bucket', sa.String(255), nullable=False),
        sa.Column('storage_key', sa.Text(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('uploaded_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('classification', sa.String(50), nullable=True),
        sa.Column('tags', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_files_v2_tenant_sha256', 'files_v2', ['tenant_id', 'sha256'])
    op.create_index('ix_files_v2_tenant_status', 'files_v2', ['tenant_id', 'status'])
    
    op.create_table(
        'attachments_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('files_v2.id', ondelete='CASCADE'), nullable=False),
        sa.Column('entity_type', sa.String(50), nullable=False),
        sa.Column('entity_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_unique_constraint('uq_attachments_v2', 'attachments_v2', ['tenant_id', 'file_id', 'entity_type', 'entity_id'])
    
    # =========================================
    # INTEGRATIONS V2
    # =========================================
    op.create_table(
        'integrations_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_key', sa.String(100), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), server_default='true'),
        sa.Column('config', postgresql.JSONB(), nullable=True),
        sa.Column('health_status', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_integrations_v2_tenant_key', 'integrations_v2', ['tenant_id', 'integration_key'], unique=True)
    
    op.create_table(
        'integration_actions_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations_v2.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action_key', sa.String(100), nullable=False),
        sa.Column('display_name', sa.Text(), nullable=False),
        sa.Column('risk_level', sa.String(20), nullable=False, server_default='low'),
        sa.Column('is_allowed', sa.Boolean(), server_default='false'),
        sa.Column('requires_justification', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint('uq_integration_actions_v2', 'integration_actions_v2', ['tenant_id', 'integration_id', 'action_key'])
    
    op.create_table(
        'action_results_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_key', sa.String(100), nullable=False),
        sa.Column('action_key', sa.String(100), nullable=False),
        sa.Column('requested_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('target_type', sa.String(50), nullable=True),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('input_data', postgresql.JSONB(), nullable=True),
        sa.Column('justification', sa.Text(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='queued'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', postgresql.JSONB(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_action_results_v2_tenant_requested', 'action_results_v2', ['tenant_id', 'requested_at'])
    
    # =========================================
    # AUDIT EVENTS V2 (IMMUTABLE)
    # =========================================
    op.create_table(
        'audit_events_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('actor_type', sa.String(20), nullable=False, server_default='user'),
        sa.Column('actor_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('actor_display', sa.Text(), nullable=True),
        sa.Column('actor_ip', postgresql.INET(), nullable=True),
        sa.Column('actor_user_agent', sa.Text(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('category', sa.String(50), nullable=True),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resource_display', sa.Text(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('before_state', postgresql.JSONB(), nullable=True),
        sa.Column('after_state', postgresql.JSONB(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), nullable=True),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('outcome', sa.String(20), server_default='success'),
        sa.Column('error_message', sa.Text(), nullable=True),
    )
    op.create_index('ix_audit_events_v2_tenant_time', 'audit_events_v2', ['tenant_id', 'event_time'])
    op.create_index('ix_audit_events_v2_tenant_action', 'audit_events_v2', ['tenant_id', 'action'])
    op.create_index('ix_audit_events_v2_tenant_resource', 'audit_events_v2', ['tenant_id', 'resource_type', 'resource_id'])
    
    # =========================================
    # RETENTION POLICIES V2
    # =========================================
    op.create_table(
        'retention_policies_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('data_class', sa.String(50), nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=False),
        sa.Column('grace_days', sa.Integer(), server_default='7'),
        sa.Column('is_enabled', sa.Boolean(), server_default='true'),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_deleted_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_retention_policies_v2_tenant_class', 'retention_policies_v2', ['tenant_id', 'data_class'], unique=True)


def downgrade():
    op.drop_table('retention_policies_v2')
    op.drop_table('audit_events_v2')
    op.drop_table('action_results_v2')
    op.drop_table('integration_actions_v2')
    op.drop_table('integrations_v2')
    op.drop_table('attachments_v2')
    op.drop_table('files_v2')
    op.drop_table('notes_v2')
    op.drop_table('investigation_alerts_v2')
    op.drop_table('alerts_v2')
    op.drop_table('investigations_v2')
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_table('permissions')
    op.drop_table('roles')
    op.drop_table('users')
    op.drop_table('tenants')
