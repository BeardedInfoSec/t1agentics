# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform Database Configuration and Base Classes

All models inherit TenantMixin for mandatory tenant isolation.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, BigInteger,
    ForeignKey, Index, UniqueConstraint, CheckConstraint,
    event, DDL
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB, INET, CITEXT
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class TenantMixin:
    """
    Mixin that adds tenant_id to all models.
    CRITICAL: All queries MUST filter by tenant_id.
    """
    
    @declared_attr
    def tenant_id(cls):
        return Column(
            PGUUID(as_uuid=True),
            ForeignKey('tenants.id', ondelete='CASCADE'),
            nullable=False,
            index=True
        )


class TimestampMixin:
    """Standard timestamp fields for all models."""
    
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow
    )
    
    @declared_attr
    def created_by(cls):
        return Column(
            PGUUID(as_uuid=True),
            ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True
        )


class MutableTimestampMixin(TimestampMixin):
    """For mutable records that track updates."""
    
    updated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.utcnow
    )


class SoftDeleteMixin:
    """Mixin for soft-deletable records."""
    
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    @declared_attr
    def deleted_by(cls):
        return Column(
            PGUUID(as_uuid=True),
            ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True
        )


def generate_uuid():
    """Generate a new UUID4."""
    return uuid4()


# Enum-like constants (not actual enums for flexibility)
class UserStatus:
    ACTIVE = 'active'
    DISABLED = 'disabled'
    PENDING = 'pending'


class TenantStatus:
    ACTIVE = 'active'
    SUSPENDED = 'suspended'
    TRIAL = 'trial'


class InvestigationStatus:
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    AWAITING_HUMAN = 'awaiting_human'
    CLOSED = 'closed'


class Severity:
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class Priority:
    P1 = 'p1'
    P2 = 'p2'
    P3 = 'p3'
    P4 = 'p4'


class FileStatus:
    ACTIVE = 'active'
    EXPIRED = 'expired'
    DELETED = 'deleted'


class SandboxStatus:
    NONE = 'none'
    PENDING = 'pending'
    SUBMITTED = 'submitted'
    COMPLETE = 'complete'
    FAILED = 'failed'


class ActionStatus:
    QUEUED = 'queued'
    RUNNING = 'running'
    SUCCESS = 'success'
    FAILURE = 'failure'
    DENIED = 'denied'


class RiskLevel:
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'


class DataClass:
    """Data classes for retention policies."""
    ALERTS = 'alerts'
    INVESTIGATIONS = 'investigations'
    NOTES = 'notes'
    FILES = 'files'
    ACTION_RESULTS = 'action_results'
    AUDIT_LOGS = 'audit_logs'


class EntityType:
    """Entity types for attachments and notes."""
    INVESTIGATION = 'investigation'
    ALERT = 'alert'
    NOTE = 'note'
    ACTION_RESULT = 'action_result'


class ActorType:
    """Actor types for audit events."""
    USER = 'user'
    SYSTEM = 'system'
    SERVICE = 'service'
    AUTOMATION = 'automation'
