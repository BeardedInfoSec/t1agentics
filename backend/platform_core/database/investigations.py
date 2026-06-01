# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation and Alert Models

Core SOC workflow models for investigations and alerts.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID
import secrets

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    ForeignKey, Index, UniqueConstraint, Table, func
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import (
    Base, TenantMixin, TimestampMixin, MutableTimestampMixin,
    generate_uuid, InvestigationStatus, Severity, Priority
)


def generate_investigation_number() -> str:
    """Generate a unique investigation number like INV-82021485."""
    return f"INV-{secrets.token_hex(4).upper()}"


def generate_alert_id(
    source: str = None,
    source_type: str = None,
    category: str = None,
    title: str = None
) -> str:
    """
    Generate a systematic alert ID.

    Format: PREFIX-YYMMDD-NNNN
    Examples: PHI-241225-0001, MAL-241225-0042, ALT-241225-0099
    """
    try:
        from services.alert_id_generator import generate_alert_id_sync
        return generate_alert_id_sync(source, source_type, category, title)
    except ImportError:
        # Fallback if service not available
        return f"ALT-{secrets.token_hex(4).upper()}"


class Investigation(Base, TenantMixin, MutableTimestampMixin):
    """
    Investigation case that groups related alerts and analysis.
    """
    __tablename__ = 'investigations_v2'  # v2 to distinguish from existing
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    investigation_number = Column(String(20), nullable=False)
    
    # Core fields
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default=InvestigationStatus.NEW)
    severity = Column(String(20), nullable=False, default=Severity.MEDIUM)
    priority = Column(String(10), nullable=False, default=Priority.P3)
    confidence = Column(String(20), nullable=True)
    disposition = Column(String(30), nullable=True)  # true_positive, false_positive, etc.
    
    # Assignment
    assigned_to = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    assigned_at = Column(DateTime(timezone=True), nullable=True)
    
    # Closure
    closed_at = Column(DateTime(timezone=True), nullable=True)
    closed_by = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    close_reason = Column(Text, nullable=True)
    
    # Extended data
    tags = Column(JSONB, nullable=True, default=list)
    metadata = Column(JSONB, nullable=True, default=dict)
    
    # SLA tracking
    sla_due_at = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(Boolean, default=False)
    
    # Relationships
    alerts = relationship('Alert', secondary='investigation_alerts_v2', back_populates='investigations')
    notes = relationship('Note', back_populates='investigation', lazy='dynamic')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'investigation_number', name='uq_investigations_v2_number'),
        Index('ix_investigations_v2_tenant_number', 'tenant_id', 'investigation_number'),
        Index('ix_investigations_v2_tenant_status', 'tenant_id', 'status'),
        Index('ix_investigations_v2_tenant_updated', 'tenant_id', 'updated_at'),
        Index('ix_investigations_v2_tenant_assigned', 'tenant_id', 'assigned_to'),
        Index('ix_investigations_v2_tenant_severity', 'tenant_id', 'severity'),
        Index('ix_investigations_v2_tenant_priority', 'tenant_id', 'priority'),
        Index('ix_investigations_v2_tenant_sla', 'tenant_id', 'sla_due_at', 'sla_breached'),
    )


class Alert(Base, TenantMixin, TimestampMixin):
    """
    Security alert from various sources.
    Alerts are immutable after creation (updates create new records or link to investigations).
    """
    __tablename__ = 'alerts_v2'  # v2 to distinguish from existing
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    alert_id = Column(String(50), nullable=False)  # Our ID (ALT-xxx)
    
    # Source identification
    alert_source = Column(String(100), nullable=False)  # crowdstrike, sentinel, etc.
    alert_key = Column(String(500), nullable=True)  # Vendor ID for deduplication
    external_id = Column(String(500), nullable=True)  # Vendor's alert ID
    
    # Core fields
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default=Severity.MEDIUM)
    confidence = Column(String(20), nullable=True)
    
    # Timing
    detected_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    
    # Status (for workflow, not source status)
    status = Column(String(30), nullable=False, default='open')  # open, investigating, closed
    
    # Raw data
    raw_event = Column(JSONB, nullable=True)
    normalized_event = Column(JSONB, nullable=True)  # After normalization pipeline
    
    # Enrichment
    enrichment_data = Column(JSONB, nullable=True)
    iocs_extracted = Column(JSONB, nullable=True)
    
    # MITRE ATT&CK
    mitre_tactics = Column(JSONB, nullable=True)  # Array of tactic IDs
    mitre_techniques = Column(JSONB, nullable=True)  # Array of technique IDs
    
    # Entity extraction
    entities = Column(JSONB, nullable=True)  # {hosts: [], users: [], ips: [], etc.}
    
    # Risk scoring
    risk_score = Column(Integer, nullable=True)
    
    # Relationships
    investigations = relationship('Investigation', secondary='investigation_alerts_v2', back_populates='alerts')
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'alert_id', name='uq_alerts_v2_alert_id'),
        UniqueConstraint('tenant_id', 'alert_source', 'alert_key', name='uq_alerts_v2_source_key'),
        Index('ix_alerts_v2_tenant_detected', 'tenant_id', 'detected_at'),
        Index('ix_alerts_v2_tenant_source', 'tenant_id', 'alert_source'),
        Index('ix_alerts_v2_tenant_status', 'tenant_id', 'status'),
        Index('ix_alerts_v2_tenant_severity', 'tenant_id', 'severity'),
        Index('ix_alerts_v2_tenant_alert_id', 'tenant_id', 'alert_id'),
    )


# Association table for investigations <-> alerts (many-to-many)
investigation_alerts = Table(
    'investigation_alerts_v2',
    Base.metadata,
    Column('tenant_id', PGUUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
    Column('investigation_id', PGUUID(as_uuid=True), ForeignKey('investigations_v2.id', ondelete='CASCADE'), nullable=False),
    Column('alert_id', PGUUID(as_uuid=True), ForeignKey('alerts_v2.id', ondelete='CASCADE'), nullable=False),
    Column('linked_at', DateTime(timezone=True), default=datetime.utcnow, nullable=False),
    Column('linked_by', PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    Column('link_reason', Text, nullable=True),
    UniqueConstraint('tenant_id', 'investigation_id', 'alert_id', name='uq_investigation_alerts_v2'),
    Index('ix_investigation_alerts_v2_tenant_inv', 'tenant_id', 'investigation_id'),
    Index('ix_investigation_alerts_v2_tenant_alert', 'tenant_id', 'alert_id'),
)
