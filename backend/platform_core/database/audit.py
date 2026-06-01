# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Audit and Retention Models

Immutable audit log and data retention policy models.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    ForeignKey, Index, UniqueConstraint, event
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB, INET
from sqlalchemy.orm import relationship

from .base import (
    Base, TenantMixin, TimestampMixin, MutableTimestampMixin,
    generate_uuid, DataClass, ActorType
)


class AuditEvent(Base, TenantMixin):
    """
    Immutable audit log entry.
    
    CRITICAL: This table is append-only. No updates or deletes allowed.
    This is enforced at the application layer and can be enforced at the DB level
    with triggers.
    """
    __tablename__ = 'audit_events_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # When
    event_time = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    # Who
    actor_type = Column(String(20), nullable=False, default=ActorType.USER)
    actor_id = Column(PGUUID(as_uuid=True), nullable=True)  # Null for system events
    actor_display = Column(Text, nullable=True)  # Email or "system" for display
    actor_ip = Column(INET, nullable=True)
    actor_user_agent = Column(Text, nullable=True)
    
    # What
    action = Column(String(100), nullable=False)  # e.g., file_uploaded, investigation_created
    category = Column(String(50), nullable=True)  # auth, rbac, investigation, etc.
    
    # Target
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(PGUUID(as_uuid=True), nullable=True)
    resource_display = Column(Text, nullable=True)  # Human-readable identifier
    
    # Details
    summary = Column(Text, nullable=True)
    before_state = Column(JSONB, nullable=True)  # State before change
    after_state = Column(JSONB, nullable=True)  # State after change
    metadata = Column(JSONB, nullable=True)  # Additional context
    
    # Request context
    correlation_id = Column(PGUUID(as_uuid=True), nullable=True)  # Link related events
    session_id = Column(PGUUID(as_uuid=True), nullable=True)
    request_id = Column(PGUUID(as_uuid=True), nullable=True)
    
    # Outcome
    outcome = Column(String(20), default='success')  # success, failure, denied
    error_message = Column(Text, nullable=True)
    
    __table_args__ = (
        Index('ix_audit_events_v2_tenant_time', 'tenant_id', 'event_time'),
        Index('ix_audit_events_v2_tenant_action', 'tenant_id', 'action'),
        Index('ix_audit_events_v2_tenant_category', 'tenant_id', 'category'),
        Index('ix_audit_events_v2_tenant_resource', 'tenant_id', 'resource_type', 'resource_id'),
        Index('ix_audit_events_v2_tenant_actor', 'tenant_id', 'actor_id'),
        Index('ix_audit_events_v2_tenant_correlation', 'tenant_id', 'correlation_id'),
    )


class RetentionPolicy(Base, TenantMixin, MutableTimestampMixin):
    """
    Data retention policies per data class.
    """
    __tablename__ = 'retention_policies_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # What data class
    data_class = Column(String(50), nullable=False)  # alerts, investigations, notes, files, etc.
    
    # Retention settings
    retention_days = Column(Integer, nullable=False)
    grace_days = Column(Integer, default=7)  # Days after expiry before hard delete
    
    # Status
    is_enabled = Column(Boolean, default=True, nullable=False)
    
    # Last run
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_deleted_count = Column(Integer, nullable=True)
    
    # Update tracking
    updated_by = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'data_class', name='uq_retention_policies_v2'),
        Index('ix_retention_policies_v2_tenant_class', 'tenant_id', 'data_class'),
    )


# Minimum retention days per data class (cannot go below these)
MINIMUM_RETENTION_DAYS = {
    DataClass.AUDIT_LOGS: 730,  # 2 years minimum for audit logs
    DataClass.INVESTIGATIONS: 90,
    DataClass.ALERTS: 30,
    DataClass.NOTES: 90,
    DataClass.FILES: 30,
    DataClass.ACTION_RESULTS: 90,
}

# Default retention days per data class
DEFAULT_RETENTION_DAYS = {
    DataClass.AUDIT_LOGS: 2555,  # 7 years
    DataClass.INVESTIGATIONS: 365,  # 1 year
    DataClass.ALERTS: 90,  # 90 days
    DataClass.NOTES: 365,  # 1 year
    DataClass.FILES: 180,  # 6 months
    DataClass.ACTION_RESULTS: 365,  # 1 year
}


# Audit event types
class AuditAction:
    """Standard audit action names."""
    
    # Authentication
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILED = 'login_failed'
    LOGOUT = 'logout'
    PASSWORD_CHANGED = 'password_changed'
    MFA_ENABLED = 'mfa_enabled'
    MFA_DISABLED = 'mfa_disabled'
    
    # RBAC
    ROLE_CREATED = 'role_created'
    ROLE_UPDATED = 'role_updated'
    ROLE_DELETED = 'role_deleted'
    ROLE_ASSIGNED = 'role_assigned'
    ROLE_REVOKED = 'role_revoked'
    PERMISSION_GRANTED = 'permission_granted'
    PERMISSION_REVOKED = 'permission_revoked'
    
    # Users
    USER_CREATED = 'user_created'
    USER_UPDATED = 'user_updated'
    USER_DISABLED = 'user_disabled'
    USER_ENABLED = 'user_enabled'
    
    # Settings
    RETENTION_POLICY_UPDATED = 'retention_policy_updated'
    SETTING_UPDATED = 'setting_updated'
    
    # Investigations
    INVESTIGATION_CREATED = 'investigation_created'
    INVESTIGATION_UPDATED = 'investigation_updated'
    INVESTIGATION_ASSIGNED = 'investigation_assigned'
    INVESTIGATION_CLOSED = 'investigation_closed'
    INVESTIGATION_REOPENED = 'investigation_reopened'
    
    # Alerts
    ALERT_INGESTED = 'alert_ingested'
    ALERT_UPDATED = 'alert_updated'
    ALERT_LINKED = 'alert_linked'
    ALERT_UNLINKED = 'alert_unlinked'
    
    # Notes
    NOTE_CREATED = 'note_created'
    NOTE_UPDATED = 'note_updated'
    NOTE_DELETED = 'note_deleted'
    
    # Files
    FILE_UPLOADED = 'file_uploaded'
    FILE_DOWNLOADED = 'file_downloaded'
    FILE_DELETED = 'file_deleted'
    FILE_DELETED_RETENTION = 'file_deleted_retention'
    FILE_ATTACHED = 'file_attached'
    FILE_DETACHED = 'file_detached'
    
    # Actions
    ACTION_EXECUTED = 'action_executed'
    ACTION_DENIED = 'action_denied'
    ACTION_COMPLETED = 'action_completed'
    ACTION_FAILED = 'action_failed'
    
    # Integrations
    INTEGRATION_CREATED = 'integration_created'
    INTEGRATION_UPDATED = 'integration_updated'
    INTEGRATION_ENABLED = 'integration_enabled'
    INTEGRATION_DISABLED = 'integration_disabled'

    # Credentials (security-sensitive operations)
    CREDENTIAL_CREATED = 'credential_created'
    CREDENTIAL_UPDATED = 'credential_updated'
    CREDENTIAL_DELETED = 'credential_deleted'
    CREDENTIAL_ACCESSED = 'credential_accessed'
    CREDENTIAL_LINKED = 'credential_linked'
    CREDENTIAL_UNLINKED = 'credential_unlinked'
    CREDENTIAL_TEST_SUCCESS = 'credential_test_success'
    CREDENTIAL_TEST_FAILED = 'credential_test_failed'

    # System
    RETENTION_JOB_RUN = 'retention_job_run'
    RETENTION_DELETED = 'retention_deleted'


# Audit categories
class AuditCategory:
    """Audit event categories for filtering."""
    AUTH = 'auth'
    RBAC = 'rbac'
    USER = 'user'
    SETTINGS = 'settings'
    INVESTIGATION = 'investigation'
    ALERT = 'alert'
    NOTE = 'note'
    FILE = 'file'
    ACTION = 'action'
    INTEGRATION = 'integration'
    SYSTEM = 'system'
