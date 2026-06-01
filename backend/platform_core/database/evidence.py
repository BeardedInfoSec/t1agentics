# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Notes, Files, and Attachments Models

Evidence and documentation models for investigations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, BigInteger,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import (
    Base, TenantMixin, TimestampMixin, MutableTimestampMixin, SoftDeleteMixin,
    generate_uuid, FileStatus, SandboxStatus, EntityType
)


class Note(Base, TenantMixin, MutableTimestampMixin, SoftDeleteMixin):
    """
    Notes attached to investigations, alerts, or other entities.
    Supports rich text and attachments.
    """
    __tablename__ = 'notes_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # Parent reference (polymorphic)
    parent_type = Column(String(50), nullable=False)  # investigation, alert, action_result
    parent_id = Column(PGUUID(as_uuid=True), nullable=False)
    
    # Content
    body = Column(Text, nullable=False)
    content_type = Column(String(50), default='text/plain')  # text/plain, text/markdown, text/html
    
    # Note type
    note_type = Column(String(50), default='comment')  # comment, finding, recommendation, system
    
    # Visibility
    is_internal = Column(Boolean, default=False)  # Internal notes not shown in reports
    
    # For threaded notes
    reply_to_id = Column(PGUUID(as_uuid=True), ForeignKey('notes_v2.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    investigation = relationship(
        'Investigation',
        foreign_keys=[parent_id],
        primaryjoin="and_(Note.parent_type=='investigation', Note.parent_id==Investigation.id)",
        back_populates='notes',
        uselist=False,
        viewonly=True
    )
    attachments = relationship('Attachment', back_populates='note', lazy='dynamic')
    replies = relationship('Note', backref='parent_note', remote_side=[id])
    
    __table_args__ = (
        Index('ix_notes_v2_tenant_parent', 'tenant_id', 'parent_type', 'parent_id'),
        Index('ix_notes_v2_tenant_created', 'tenant_id', 'created_at'),
        Index('ix_notes_v2_tenant_deleted', 'tenant_id', 'is_deleted'),
    )


class File(Base, TenantMixin, TimestampMixin):
    """
    File/Evidence metadata. Actual files stored in S3-compatible storage.
    Files are immutable - new upload = new record.
    """
    __tablename__ = 'files_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # File metadata
    filename = Column(Text, nullable=False)
    original_filename = Column(Text, nullable=True)  # Original name before sanitization
    content_type = Column(String(255), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    
    # Integrity
    sha256 = Column(String(64), nullable=False)
    md5 = Column(String(32), nullable=True)  # Optional, for compatibility
    
    # Storage location
    storage_provider = Column(String(50), nullable=False, default='s3')  # s3, minio, azure
    storage_bucket = Column(String(255), nullable=False)
    storage_key = Column(Text, nullable=False)  # Full path in bucket
    storage_region = Column(String(50), nullable=True)
    
    # Status
    status = Column(String(20), nullable=False, default=FileStatus.ACTIVE)
    
    # Retention
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Upload context
    uploaded_by = Column(PGUUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    uploaded_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    upload_source = Column(String(100), nullable=True)  # web, api, automation
    
    # Malware analysis (future)
    sandbox_status = Column(String(20), nullable=False, default=SandboxStatus.NONE)
    sandbox_result = Column(JSONB, nullable=True)
    sandbox_submitted_at = Column(DateTime(timezone=True), nullable=True)
    sandbox_completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Classification
    classification = Column(String(50), nullable=True)  # public, internal, confidential, restricted
    tags = Column(JSONB, nullable=True, default=list)
    
    # Extracted metadata
    file_metadata = Column(JSONB, nullable=True)  # EXIF, document properties, etc.
    
    # Relationships
    attachments = relationship('Attachment', back_populates='file', lazy='dynamic')
    
    __table_args__ = (
        Index('ix_files_v2_tenant_sha256', 'tenant_id', 'sha256'),
        Index('ix_files_v2_tenant_uploaded', 'tenant_id', 'uploaded_at'),
        Index('ix_files_v2_tenant_status', 'tenant_id', 'status'),
        Index('ix_files_v2_tenant_expires', 'tenant_id', 'expires_at'),
        Index('ix_files_v2_tenant_sandbox', 'tenant_id', 'sandbox_status'),
    )


class Attachment(Base, TenantMixin, TimestampMixin):
    """
    Links files to entities (investigations, alerts, notes, action results).
    A file can be attached to multiple entities.
    """
    __tablename__ = 'attachments_v2'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)
    
    # File reference
    file_id = Column(PGUUID(as_uuid=True), ForeignKey('files_v2.id', ondelete='CASCADE'), nullable=False)
    
    # Entity reference (polymorphic)
    entity_type = Column(String(50), nullable=False)  # investigation, alert, note, action_result
    entity_id = Column(PGUUID(as_uuid=True), nullable=False)
    
    # Context
    description = Column(Text, nullable=True)
    attachment_type = Column(String(50), nullable=True)  # evidence, screenshot, log, report
    
    # Relationships
    file = relationship('File', back_populates='attachments')
    note = relationship(
        'Note',
        foreign_keys=[entity_id],
        primaryjoin="and_(Attachment.entity_type=='note', Attachment.entity_id==Note.id)",
        back_populates='attachments',
        uselist=False,
        viewonly=True
    )
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'file_id', 'entity_type', 'entity_id', name='uq_attachments_v2'),
        Index('ix_attachments_v2_tenant_entity', 'tenant_id', 'entity_type', 'entity_id'),
        Index('ix_attachments_v2_tenant_file', 'tenant_id', 'file_id'),
    )
