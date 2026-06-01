# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Data models for T1 Agentics.
Defines the structure for alerts, indicators, investigation results, and reports.
"""

from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum


class SeverityLevel(str, Enum):
    """Alert severity levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ConfidenceLevel(str, Enum):
    """Confidence in findings"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class DispositionType(str, Enum):
    """
    Investigation disposition/verdict - final classification
    Replaces both verdict and disposition for consistency
    Values must match PostgreSQL CHECK constraint exactly

    NOTE: For new code, prefer using models.verdict.Verdict which is the canonical
    single source of truth. This enum is kept for backwards compatibility with Pydantic models.
    """
    # Security verdicts
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    # Disposition values (analyst classification)
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_POSITIVE = "BENIGN_POSITIVE"
    # Process verdicts
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "UNKNOWN"


class PriorityLevel(str, Enum):
    """Investigation priority levels"""
    P1 = "P1"  # Critical - immediate action required
    P2 = "P2"  # High - action required soon
    P3 = "P3"  # Medium - normal priority
    P4 = "P4"  # Low - can be deferred


class InvestigationState(str, Enum):
    """
    Simplified 5-state investigation workflow.
    Must match PostgreSQL CHECK constraint in init-db.sql.

    Workflow: NEW -> ANALYZING -> NEEDS_REVIEW -> IN_PROGRESS -> CLOSED

    States:
    - NEW: Alert just arrived, not yet processed
    - ANALYZING: AI working (enriching, triaging, Riggs analysis combined)
    - NEEDS_REVIEW: AI complete, needs human decision/action
    - IN_PROGRESS: Analyst actively investigating
    - CLOSED: Terminal state (disposition field contains verdict)
    """
    NEW = "NEW"
    ANALYZING = "ANALYZING"      # AI processing (replaces ENRICHING, AI_TRIAGE_*, RIGGS_REVIEW while AI working)
    NEEDS_REVIEW = "NEEDS_REVIEW"  # AI done, human action needed (replaces AWAITING_HUMAN, RIGGS_ANALYZED)
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"            # Terminal (replaces both RESOLVED and CLOSED)

    # Legacy aliases for backward compatibility during transition
    # These map to new states but are kept for code that references them
    @classmethod
    def from_legacy(cls, state: str) -> 'InvestigationState':
        """Convert legacy state names to new simplified states."""
        legacy_map = {
            'ENRICHING': cls.ANALYZING,
            'AI_TRIAGE_L1': cls.ANALYZING,
            'AI_TRIAGE_L2': cls.ANALYZING,
            'RIGGS_REVIEW': cls.NEEDS_REVIEW,
            'RIGGS_ANALYZED': cls.NEEDS_REVIEW,
            'AWAITING_HUMAN': cls.NEEDS_REVIEW,
            'RESOLVED': cls.CLOSED,
        }
        if state in legacy_map:
            return legacy_map[state]
        return cls(state)


class IndicatorType(str, Enum):
    """Types of indicators"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    USERNAME = "username"
    HOSTNAME = "hostname"


class Indicator(BaseModel):
    """Extracted indicator from alert"""
    type: IndicatorType
    value: str
    context: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)


class Alert(BaseModel):
    """Incoming alert structure"""
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Optional[str] = Field(default="medium", description="Alert severity: low, medium, high, critical")
    raw_log: Optional[str] = None
    raw_event: Optional[Any] = Field(default=None, description="Raw event data (JSON string or dict)")
    source: Optional[str] = None
    category: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator('severity', pre=True, always=True)
    def validate_severity(cls, v):
        """Ensure severity is lowercase and valid"""
        if v is None:
            return "medium"
        valid = ['low', 'medium', 'high', 'critical']
        v_lower = str(v).lower()
        return v_lower if v_lower in valid else "medium"

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Suspicious Login Attempt",
                "description": "Multiple failed login attempts from 192.168.1.100",
                "severity": "high",
                "source": "auth_logs",
                "metadata": {
                    "user": "admin",
                    "ip": "192.168.1.100",
                    "attempts": 15
                }
            }
        }


class EnrichmentResult(BaseModel):
    """Result from an enrichment tool"""
    tool_name: str
    success: bool
    result: Dict[str, Any] = Field(default_factory=dict)
    raw: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None


class TimelineEvent(BaseModel):
    """Event in investigation timeline"""
    timestamp: datetime
    event_type: str
    description: str
    indicators: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TechnicalFinding(BaseModel):
    """Individual technical finding"""
    title: str
    description: str
    severity: SeverityLevel
    indicators: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    """Recommended response action"""
    action: str
    priority: Literal["Low", "Medium", "High", "Critical"]
    rationale: str
    automation_possible: bool = False


class IOCSummary(BaseModel):
    """Summary of indicators of compromise"""
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)


class IOCCorrelation(BaseModel):
    """IOC correlation data for cross-referencing"""
    ioc_value: str
    ioc_type: str
    severity: Optional[str] = "medium"
    occurrences: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_investigations: List[Dict[str, Any]] = Field(default_factory=list)


class InvestigationPlan(BaseModel):
    """Agent's investigation plan"""
    steps: List[str]
    reasoning: str
    estimated_duration: Optional[int] = None  # seconds


class InvestigationNote(BaseModel):
    """Note added to investigation"""
    note_id: str
    author: str  # username
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    note_type: Literal["analyst", "system", "ai"] = "analyst"


class InvestigationResult(BaseModel):
    """Complete investigation output"""
    investigation_id: str
    alert_id: Optional[str] = None
    executive_summary: str
    technical_findings: List[TechnicalFinding]
    timeline: List[TimelineEvent]
    severity: SeverityLevel
    confidence: ConfidenceLevel
    verdict: DispositionType = Field(
        default=DispositionType.INCONCLUSIVE,
        description="AI/system classification (legacy field, use disposition)"
    )
    recommended_actions: List[RecommendedAction]
    ioc_summary: IOCSummary
    enrichment_results: List[EnrichmentResult] = Field(default_factory=list)
    reasoning_trace: List[str] = Field(default_factory=list)
    ioc_correlations: Optional[Dict[str, Any]] = None  # IOC correlation data
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # NEW: Disposition and Workflow Fields
    # NOTE: disposition and verdict are now merged - use disposition as primary
    disposition: DispositionType = Field(
        default=DispositionType.UNKNOWN,
        description="Final classification (replaces verdict)"
    )
    priority: PriorityLevel = Field(
        default=PriorityLevel.P3,
        description="Investigation priority level"
    )
    owner: Optional[str] = Field(
        default=None,
        description="Username of assigned analyst"
    )
    assigned_at: Optional[datetime] = Field(
        default=None,
        description="When investigation was assigned"
    )
    state: InvestigationState = Field(
        default=InvestigationState.NEW,
        description="Current workflow state"
    )
    notes: List[InvestigationNote] = Field(
        default_factory=list,
        description="Investigation notes and comments"
    )
    
    # AI ANALYSIS FIELDS
    ai_analysis: Optional[Dict[str, Any]] = Field(
        default=None,
        description="AI agent analysis results"
    )
    escalation_history: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="History of escalations between agent levels"
    )
    
    # NEW ADVANCED FEATURES
    framework_matches: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="Matched cybersecurity framework controls"
    )
    timeline_events: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Chronological timeline of investigation events"
    )
    correlations: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Related alerts, investigations, and IOCs"
    )
    indicators: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Extracted indicators of compromise"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "investigation_id": "inv-123456",
                "alert_id": "alert-789",
                "executive_summary": "Investigation revealed suspicious login activity from a known malicious IP.",
                "severity": "High",
                "confidence": "High",
                "verdict": "Malicious"
            }
        }


class AgentState(BaseModel):
    """Current state of agent during investigation"""
    phase: Literal["intake", "extraction", "planning", "enrichment", "analysis", "reporting"]
    current_step: str
    completed_steps: List[str] = Field(default_factory=list)
    pending_steps: List[str] = Field(default_factory=list)
    findings: Dict[str, Any] = Field(default_factory=dict)


class ToolInput(BaseModel):
    """Standard input for tools"""
    indicator_type: IndicatorType
    value: str
    context: Optional[Dict[str, Any]] = None


class ToolOutput(BaseModel):
    """Standard output from tools"""
    success: bool
    result: Dict[str, Any]
    raw: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
