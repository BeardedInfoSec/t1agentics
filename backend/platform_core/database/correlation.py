# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Correlation Models

Models for hypothesis-driven alert correlation system.
Supports soft-join/hard-join workflow where correlations start as SUGGESTED
and require evidence or analyst confirmation to become CONFIRMED.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    ForeignKey, Index, UniqueConstraint, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import Base, generate_uuid


# ============================================================================
# Enum-like Constants for Correlation
# ============================================================================

class LinkState:
    """Correlation link states for soft-join/hard-join workflow."""
    SUGGESTED = 'SUGGESTED'  # Default - awaiting confirmation
    CONFIRMED = 'CONFIRMED'  # Analyst or auto-confirmed
    REJECTED = 'REJECTED'    # Analyst rejected


class RelationshipType:
    """Types of relationships between alerts and investigations."""
    ROOT_CAUSE = 'ROOT_CAUSE'      # Alert is the root cause/origin
    SUPPORTING = 'SUPPORTING'      # Alert supports the hypothesis
    CONSEQUENCE = 'CONSEQUENCE'    # Alert is a result of the attack
    CONTEXT_ONLY = 'CONTEXT_ONLY'  # Alert provides context but weak signal


class HypothesisSupport:
    """How well an alert supports an investigation's hypothesis."""
    SUPPORTS = 'SUPPORTS'        # Directly supports hypothesis
    COMPATIBLE = 'COMPATIBLE'    # Doesn't contradict, could fit
    CONTRADICTS = 'CONTRADICTS'  # Contradicts hypothesis
    UNRELATED = 'UNRELATED'      # No relationship to hypothesis


class HypothesisCategory:
    """Standard categories for investigation hypotheses."""
    MALWARE_INFECTION = 'MALWARE_INFECTION'
    CREDENTIAL_THEFT = 'CREDENTIAL_THEFT'
    DATA_EXFIL = 'DATA_EXFIL'
    LATERAL_MOVEMENT = 'LATERAL_MOVEMENT'
    PERSISTENCE = 'PERSISTENCE'
    PHISHING_CAMPAIGN = 'PHISHING_CAMPAIGN'
    INSIDER_THREAT = 'INSIDER_THREAT'
    POLICY_VIOLATION = 'POLICY_VIOLATION'
    C2_COMMUNICATION = 'C2_COMMUNICATION'
    RECONNAISSANCE = 'RECONNAISSANCE'


class ThreatDomain:
    """Threat domains for cross-domain isolation."""
    EMAIL = 'EMAIL'
    ENDPOINT = 'ENDPOINT'
    IDENTITY = 'IDENTITY'
    NETWORK = 'NETWORK'
    CLOUD = 'CLOUD'

    @classmethod
    def get_allowed_correlations(cls) -> dict:
        """
        Get allowed cross-domain correlations.

        By default, domains only correlate with themselves.
        NETWORK is the exception - it can cross to ENDPOINT.
        """
        return {
            cls.EMAIL: [cls.EMAIL],
            cls.ENDPOINT: [cls.ENDPOINT],
            cls.IDENTITY: [cls.IDENTITY],
            cls.NETWORK: [cls.NETWORK, cls.ENDPOINT],
            cls.CLOUD: [cls.CLOUD],
        }


class CorrelationDecision:
    """Possible correlation decisions."""
    SUGGESTED = 'SUGGESTED'    # Soft-link created
    CONFIRMED = 'CONFIRMED'    # Hard-link created
    REJECTED = 'REJECTED'      # Link rejected
    BLOCKED = 'BLOCKED'        # Blocked by gate
    CREATE_NEW = 'CREATE_NEW'  # New investigation created
    STANDALONE = 'STANDALONE'  # Alert remains standalone


# ============================================================================
# CorrelationLink Model
# ============================================================================

class CorrelationLink(Base):
    """
    Tracks soft-join and hard-join relationships between alerts and investigations.

    Workflow:
    1. Correlation engine creates link with state=SUGGESTED
    2. Analyst reviews and CONFIRMS or REJECTS
    3. Auto-confirm is possible for high-confidence matches
    """
    __tablename__ = 'correlation_links'

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)

    # Links
    alert_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey('alerts.id', ondelete='CASCADE'),
        nullable=False
    )
    investigation_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey('investigations.id', ondelete='CASCADE'),
        nullable=False
    )

    # Link state (soft-join vs hard-join)
    link_state = Column(
        String(20),
        nullable=False,
        default=LinkState.SUGGESTED
    )

    # Relationship classification
    relationship_type = Column(
        String(20),
        nullable=False,
        default=RelationshipType.SUPPORTING
    )

    # Correlation evidence
    correlation_score = Column(Integer, nullable=False, default=0)
    why_correlated = Column(Text, nullable=False, default='')
    evidence_json = Column(JSONB, nullable=False, default=list)

    # Gate results (for audit)
    gates_passed = Column(JSONB, default=list)
    gates_failed = Column(JSONB, default=list)
    hypothesis_support = Column(String(20), default=HypothesisSupport.COMPATIBLE)

    # Timestamps
    suggested_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)

    # Who confirmed/rejected
    confirmed_by = Column(String(100), nullable=True)  # 'SYSTEM' or username
    reject_reason = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint('alert_id', 'investigation_id', name='uq_correlation_links_alert_inv'),
        CheckConstraint(
            "link_state IN ('SUGGESTED', 'CONFIRMED', 'REJECTED')",
            name='ck_correlation_links_state'
        ),
        CheckConstraint(
            "relationship_type IN ('ROOT_CAUSE', 'SUPPORTING', 'CONSEQUENCE', 'CONTEXT_ONLY')",
            name='ck_correlation_links_relationship'
        ),
        CheckConstraint(
            "hypothesis_support IS NULL OR hypothesis_support IN ('SUPPORTS', 'COMPATIBLE', 'CONTRADICTS', 'UNRELATED')",
            name='ck_correlation_links_hypothesis_support'
        ),
        Index('ix_correlation_links_alert_id', 'alert_id'),
        Index('ix_correlation_links_investigation_id', 'investigation_id'),
        Index('ix_correlation_links_state', 'link_state'),
        Index('ix_correlation_links_pending', 'investigation_id', 'suggested_at',
              postgresql_where="link_state = 'SUGGESTED'"),
    )

    def confirm(self, confirmed_by: str = 'SYSTEM') -> None:
        """Confirm this correlation link."""
        self.link_state = LinkState.CONFIRMED
        self.confirmed_at = datetime.utcnow()
        self.confirmed_by = confirmed_by

    def reject(self, reason: str, rejected_by: str = None) -> None:
        """Reject this correlation link."""
        self.link_state = LinkState.REJECTED
        self.rejected_at = datetime.utcnow()
        self.reject_reason = reason
        if rejected_by:
            self.confirmed_by = rejected_by  # Reuse field for tracking

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            'id': str(self.id),
            'alert_id': str(self.alert_id),
            'investigation_id': str(self.investigation_id),
            'link_state': self.link_state,
            'relationship_type': self.relationship_type,
            'correlation_score': self.correlation_score,
            'why_correlated': self.why_correlated,
            'evidence': self.evidence_json or [],
            'hypothesis_support': self.hypothesis_support,
            'suggested_at': self.suggested_at.isoformat() if self.suggested_at else None,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'confirmed_by': self.confirmed_by,
        }


# ============================================================================
# CorrelationAudit Model
# ============================================================================

class CorrelationAudit(Base):
    """
    Audit trail for all correlation decisions.

    Records every correlation decision including:
    - SUGGESTED: Soft-link created
    - CONFIRMED: Hard-link created (auto or manual)
    - REJECTED: Link rejected by analyst
    - BLOCKED: Blocked by eligibility gate
    - CREATE_NEW: New investigation created
    - STANDALONE: Alert remains standalone
    """
    __tablename__ = 'correlation_audit'

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=generate_uuid)

    # Alert being correlated
    alert_id = Column(PGUUID(as_uuid=True), nullable=False)

    # Decision made
    decision = Column(String(20), nullable=False)

    # Investigation (if applicable)
    investigation_id = Column(PGUUID(as_uuid=True), nullable=True)
    investigation_number = Column(String(50), nullable=True)

    # Scoring
    score = Column(Integer, default=0)
    threshold_used = Column(Integer, default=40)

    # Gate results
    gates_passed = Column(JSONB, default=list)
    gates_failed = Column(JSONB, default=list)

    # Evidence
    evidence = Column(JSONB, default=list)

    # Hypothesis evaluation
    hypothesis_support = Column(String(20), nullable=True)
    hypothesis_category = Column(String(50), nullable=True)

    # Human-readable reason
    reason = Column(Text, nullable=True)

    # Performance metrics
    processing_time_ms = Column(Integer, nullable=True)

    # Timestamp
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint(
            "decision IN ('SUGGESTED', 'CONFIRMED', 'REJECTED', 'BLOCKED', 'CREATE_NEW', 'STANDALONE')",
            name='ck_correlation_audit_decision'
        ),
        Index('ix_correlation_audit_alert_id', 'alert_id'),
        Index('ix_correlation_audit_investigation_id', 'investigation_id',
              postgresql_where="investigation_id IS NOT NULL"),
        Index('ix_correlation_audit_created_at', 'created_at'),
        Index('ix_correlation_audit_decision', 'decision'),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            'id': str(self.id),
            'alert_id': str(self.alert_id),
            'decision': self.decision,
            'investigation_id': str(self.investigation_id) if self.investigation_id else None,
            'investigation_number': self.investigation_number,
            'score': self.score,
            'threshold_used': self.threshold_used,
            'gates_passed': self.gates_passed or [],
            'gates_failed': self.gates_failed or [],
            'evidence': self.evidence or [],
            'hypothesis_support': self.hypothesis_support,
            'reason': self.reason,
            'processing_time_ms': self.processing_time_ms,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ============================================================================
# Evidence Types for Scoring
# ============================================================================

class EvidenceType:
    """Types of evidence used in correlation scoring."""
    MALICIOUS_IOC = 'MALICIOUS_IOC'        # Shared malicious IOC (+50)
    SUSPICIOUS_IOC = 'SUSPICIOUS_IOC'      # Shared suspicious IOC (+20)
    MITRE_CHAIN = 'MITRE_CHAIN'            # MITRE technique chain (+40)
    CAUSAL_SEQUENCE = 'CAUSAL_SEQUENCE'    # Causal relationship (+60)
    THREAT_FINGERPRINT = 'THREAT_FINGERPRINT'  # Same threat actor (+70)
    MALWARE_FAMILY = 'MALWARE_FAMILY'      # Same malware family (+80)
