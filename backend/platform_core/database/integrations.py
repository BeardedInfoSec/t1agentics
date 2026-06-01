# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integrations and Actions Models

Models for external integrations and action execution.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import (
    Base, TenantMixin, TimestampMixin, MutableTimestampMixin,
    generate_uuid, ActionStatus, RiskLevel
)


class Integration(Base, TenantMixin, MutableTimestampMixin):
    """
    External integration configuration (CrowdStrike, VirusTotal, etc.)
    """
    __tablename__ = 'integrations_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # Identification
    integration_key = Column(String(100), nullable=False)  # crowdstrike, virustotal, etc.
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Status
    is_enabled = Column(Boolean, default=True, nullable=False)
    
    # Configuration (encrypted at rest)
    config = Column(JSONB, nullable=True)  # API keys, endpoints, etc.
    
    # Health tracking
    last_health_check = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String(20), nullable=True)  # healthy, degraded, offline
    health_message = Column(Text, nullable=True)
    
    # Rate limiting
    rate_limit_remaining = Column(String(20), nullable=True)
    rate_limit_reset_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    actions = relationship('IntegrationAction', back_populates='integration', lazy='dynamic')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'integration_key', name='uq_integrations_v2_key'),
        Index('ix_integrations_v2_tenant_key', 'tenant_id', 'integration_key'),
        Index('ix_integrations_v2_tenant_enabled', 'tenant_id', 'is_enabled'),
    )


class IntegrationAction(Base, TenantMixin, TimestampMixin):
    """
    Allowlisted actions for an integration.
    Controls what actions are available and who can execute them.
    """
    __tablename__ = 'integration_actions_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # Integration reference
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey('integrations_v2.id', ondelete='CASCADE'), nullable=False)
    
    # Action definition
    action_key = Column(String(100), nullable=False)  # contain_host, lookup_ip, etc.
    display_name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Risk and control
    risk_level = Column(String(20), nullable=False, default=RiskLevel.LOW)
    is_allowed = Column(Boolean, default=False, nullable=False)
    requires_justification = Column(Boolean, default=False, nullable=False)  # For high-risk actions
    requires_approval = Column(Boolean, default=False, nullable=False)  # Future: approval workflow
    
    # Execution settings
    timeout_seconds = Column(String(10), default='60')
    retry_count = Column(String(5), default='3')
    
    # Input/output schema (for validation and UI generation)
    input_schema = Column(JSONB, nullable=True)
    output_schema = Column(JSONB, nullable=True)
    
    # Relationships
    integration = relationship('Integration', back_populates='actions')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'integration_id', 'action_key', name='uq_integration_actions_v2'),
        Index('ix_integration_actions_v2_tenant_int', 'tenant_id', 'integration_id'),
        Index('ix_integration_actions_v2_tenant_allowed', 'tenant_id', 'is_allowed'),
    )


class ActionResult(Base, TenantMixin, TimestampMixin):
    """
    Record of action execution with full audit trail.
    """
    __tablename__ = 'action_results_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # What was executed
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey('integrations_v2.id', ondelete='SET NULL'), nullable=True)
    integration_key = Column(String(100), nullable=False)  # Denormalized for history
    action_key = Column(String(100), nullable=False)
    
    # Who requested it
    requested_by = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    # Target context
    target_type = Column(String(50), nullable=True)  # alert, investigation, entity
    target_id = Column(PGUUID(as_uuid=True), nullable=True)
    target_context = Column(JSONB, nullable=True)  # Additional context (IP, hostname, etc.)
    
    # Input
    input_data = Column(JSONB, nullable=True)
    
    # Authorization
    justification = Column(Text, nullable=True)  # Required for high-risk actions
    approved_by = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Execution status
    status = Column(String(20), nullable=False, default=ActionStatus.QUEUED)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(String(20), nullable=True)
    
    # Result
    result = Column(JSONB, nullable=True)
    error_message = Column(Text, nullable=True)
    error_code = Column(String(50), nullable=True)
    
    # Retry tracking
    attempt_number = Column(String(5), default='1')
    parent_action_id = Column(PGUUID(as_uuid=True), ForeignKey('action_results_v2.id', ondelete='SET NULL'), nullable=True)
    
    __table_args__ = (
        Index('ix_action_results_v2_tenant_requested', 'tenant_id', 'requested_at'),
        Index('ix_action_results_v2_tenant_target', 'tenant_id', 'target_type', 'target_id'),
        Index('ix_action_results_v2_tenant_status', 'tenant_id', 'status'),
        Index('ix_action_results_v2_tenant_integration', 'tenant_id', 'integration_key', 'action_key'),
    )
