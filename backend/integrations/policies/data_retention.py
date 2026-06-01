# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Data Retention Policy Engine

Manages data retention policies across the platform:
- Enrichment cache TTL
- Alert retention
- Investigation retention
- IOC retention
- Audit log retention
- Integration result retention

Different companies have different compliance requirements.
This engine enforces organization-specific retention policies.
"""

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timedelta


class DataType(str, Enum):
    """Types of data subject to retention policies"""
    ENRICHMENT_CACHE = "enrichment_cache"
    ALERT = "alert"
    INVESTIGATION = "investigation"
    IOC = "ioc"
    AUDIT_LOG = "audit_log"
    INTEGRATION_RESULT = "integration_result"
    SANDBOX_RESULT = "sandbox_result"
    FILE_METADATA = "file_metadata"
    NOTES = "notes"
    TIMELINE_EVENT = "timeline_event"


class RetentionAction(str, Enum):
    """Actions to take when retention period expires"""
    DELETE = "delete"  # Hard delete
    ARCHIVE = "archive"  # Move to cold storage
    ANONYMIZE = "anonymize"  # Remove PII, keep metadata
    MARK_STALE = "mark_stale"  # Flag as stale but keep


class RetentionPolicy(BaseModel):
    """Retention policy for a data type"""
    data_type: DataType
    retention_days: int
    action: RetentionAction = Field(default=RetentionAction.DELETE)
    enabled: bool = Field(default=True)
    description: Optional[str] = None
    
    # Exceptions
    never_delete_if_referenced: bool = Field(default=True)  # Keep if linked to active investigation
    keep_if_high_severity: bool = Field(default=False)  # Keep critical/high severity items longer
    extended_retention_days: Optional[int] = None  # Extended retention for special cases
    
    # Audit
    last_cleanup_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "data_type": "enrichment_cache",
                "retention_days": 30,
                "action": "delete",
                "enabled": True,
                "description": "Delete enrichment cache after 30 days to comply with GDPR",
                "never_delete_if_referenced": True
            }
        }


class DataRetentionConfig(BaseModel):
    """Global data retention configuration"""
    
    # Enrichment & Integration Results
    enrichment_cache_days: int = Field(default=30, description="How long to cache enrichment results")
    integration_result_days: int = Field(default=90, description="How long to keep integration API responses")
    sandbox_result_days: int = Field(default=180, description="How long to keep sandbox analysis results")
    
    # Core Security Data
    alert_retention_days: int = Field(default=365, description="How long to keep alerts")
    investigation_retention_days: int = Field(default=730, description="How long to keep investigations (2 years)")
    ioc_retention_days: int = Field(default=365, description="How long to keep IOC data")
    
    # Supporting Data
    audit_log_retention_days: int = Field(default=2555, description="How long to keep audit logs (7 years for compliance)")
    file_metadata_retention_days: int = Field(default=365, description="How long to keep file metadata")
    notes_retention_days: int = Field(default=730, description="How long to keep investigation notes")
    timeline_event_retention_days: int = Field(default=365, description="How long to keep timeline events")
    
    # Cleanup settings
    auto_cleanup_enabled: bool = Field(default=True, description="Enable automatic cleanup jobs")
    cleanup_batch_size: int = Field(default=1000, description="How many records to process per cleanup batch")
    
    # Special retention rules
    never_delete_active_investigations: bool = Field(default=True)
    never_delete_malicious_verdicts: bool = Field(default=True)
    extended_retention_for_incidents: bool = Field(default=True)
    extended_retention_days: int = Field(default=2555, description="Extended retention period (7 years)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "enrichment_cache_days": 30,
                "alert_retention_days": 365,
                "investigation_retention_days": 730,
                "audit_log_retention_days": 2555,
                "auto_cleanup_enabled": True,
                "never_delete_active_investigations": True
            }
        }


class DataRetentionEngine:
    """
    Data Retention Policy Engine
    
    Enforces retention policies across all data types.
    Supports configurable TTLs, cleanup actions, and compliance rules.
    """
    
    def __init__(self, config: Optional[DataRetentionConfig] = None):
        self.config = config or DataRetentionConfig()
        self.policies: Dict[DataType, RetentionPolicy] = {}
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default retention policies from config"""
        
        # Enrichment cache
        self.policies[DataType.ENRICHMENT_CACHE] = RetentionPolicy(
            data_type=DataType.ENRICHMENT_CACHE,
            retention_days=self.config.enrichment_cache_days,
            action=RetentionAction.DELETE,
            description="Enrichment cache TTL",
            never_delete_if_referenced=False  # Cache can always be deleted
        )
        
        # Alerts
        self.policies[DataType.ALERT] = RetentionPolicy(
            data_type=DataType.ALERT,
            retention_days=self.config.alert_retention_days,
            action=RetentionAction.ARCHIVE,
            description="Alert retention policy",
            never_delete_if_referenced=True,
            keep_if_high_severity=True
        )
        
        # Investigations
        self.policies[DataType.INVESTIGATION] = RetentionPolicy(
            data_type=DataType.INVESTIGATION,
            retention_days=self.config.investigation_retention_days,
            action=RetentionAction.ARCHIVE,
            description="Investigation retention policy",
            never_delete_if_referenced=True,
            keep_if_high_severity=True,
            extended_retention_days=self.config.extended_retention_days
        )
        
        # IOCs
        self.policies[DataType.IOC] = RetentionPolicy(
            data_type=DataType.IOC,
            retention_days=self.config.ioc_retention_days,
            action=RetentionAction.MARK_STALE,
            description="IOC retention policy",
            never_delete_if_referenced=True
        )
        
        # Audit logs (compliance requirement)
        self.policies[DataType.AUDIT_LOG] = RetentionPolicy(
            data_type=DataType.AUDIT_LOG,
            retention_days=self.config.audit_log_retention_days,
            action=RetentionAction.ARCHIVE,
            description="Audit log retention (7 years for compliance)",
            never_delete_if_referenced=False
        )
        
        # Integration results
        self.policies[DataType.INTEGRATION_RESULT] = RetentionPolicy(
            data_type=DataType.INTEGRATION_RESULT,
            retention_days=self.config.integration_result_days,
            action=RetentionAction.DELETE,
            description="Integration API response retention",
            never_delete_if_referenced=True
        )
        
        # Sandbox results
        self.policies[DataType.SANDBOX_RESULT] = RetentionPolicy(
            data_type=DataType.SANDBOX_RESULT,
            retention_days=self.config.sandbox_result_days,
            action=RetentionAction.ARCHIVE,
            description="Sandbox analysis retention",
            never_delete_if_referenced=True,
            keep_if_high_severity=True
        )
        
        # File metadata
        self.policies[DataType.FILE_METADATA] = RetentionPolicy(
            data_type=DataType.FILE_METADATA,
            retention_days=self.config.file_metadata_retention_days,
            action=RetentionAction.ANONYMIZE,
            description="File metadata retention",
            never_delete_if_referenced=True
        )
        
        # Notes
        self.policies[DataType.NOTES] = RetentionPolicy(
            data_type=DataType.NOTES,
            retention_days=self.config.notes_retention_days,
            action=RetentionAction.ARCHIVE,
            description="Investigation notes retention",
            never_delete_if_referenced=True
        )
        
        # Timeline events
        self.policies[DataType.TIMELINE_EVENT] = RetentionPolicy(
            data_type=DataType.TIMELINE_EVENT,
            retention_days=self.config.timeline_event_retention_days,
            action=RetentionAction.ARCHIVE,
            description="Timeline event retention",
            never_delete_if_referenced=True
        )
    
    def get_policy(self, data_type: DataType) -> RetentionPolicy:
        """Get retention policy for a data type"""
        return self.policies.get(data_type)
    
    def update_policy(
        self,
        data_type: DataType,
        retention_days: Optional[int] = None,
        action: Optional[RetentionAction] = None,
        enabled: Optional[bool] = None
    ) -> RetentionPolicy:
        """Update a retention policy"""
        policy = self.policies.get(data_type)
        if not policy:
            raise ValueError(f"No policy found for {data_type}")
        
        if retention_days is not None:
            policy.retention_days = retention_days
        if action is not None:
            policy.action = action
        if enabled is not None:
            policy.enabled = enabled
        
        policy.updated_at = datetime.utcnow()
        return policy
    
    def is_expired(
        self,
        data_type: DataType,
        created_at: datetime,
        severity: Optional[str] = None,
        is_referenced: bool = False
    ) -> bool:
        """
        Check if data has exceeded retention period
        
        Args:
            data_type: Type of data
            created_at: When data was created
            severity: Optional severity level (critical, high, medium, low)
            is_referenced: Whether data is referenced by other records
            
        Returns:
            True if data should be cleaned up
        """
        policy = self.get_policy(data_type)
        if not policy or not policy.enabled:
            return False
        
        # Check if referenced and should be kept
        if is_referenced and policy.never_delete_if_referenced:
            return False
        
        # Check if high severity and should be kept longer
        if severity and severity.lower() in ['critical', 'high'] and policy.keep_if_high_severity:
            if policy.extended_retention_days:
                retention_days = policy.extended_retention_days
            else:
                return False  # Keep indefinitely
        else:
            retention_days = policy.retention_days
        
        # Calculate expiration
        expiration_date = created_at + timedelta(days=retention_days)
        return datetime.utcnow() > expiration_date
    
    def get_ttl_days(
        self,
        data_type: DataType,
        severity: Optional[str] = None
    ) -> int:
        """Get TTL in days for a data type"""
        policy = self.get_policy(data_type)
        if not policy:
            return 365  # Default 1 year
        
        # Use extended retention for high severity
        if (severity and 
            severity.lower() in ['critical', 'high'] and 
            policy.keep_if_high_severity and 
            policy.extended_retention_days):
            return policy.extended_retention_days
        
        return policy.retention_days
    
    def get_expiration_date(
        self,
        data_type: DataType,
        created_at: datetime,
        severity: Optional[str] = None
    ) -> datetime:
        """Calculate expiration date for data"""
        ttl_days = self.get_ttl_days(data_type, severity)
        return created_at + timedelta(days=ttl_days)
    
    def should_cleanup(
        self,
        data_type: DataType,
        created_at: datetime,
        **kwargs
    ) -> tuple[bool, Optional[RetentionAction]]:
        """
        Determine if data should be cleaned up and what action to take
        
        Returns:
            (should_cleanup: bool, action: Optional[RetentionAction])
        """
        policy = self.get_policy(data_type)
        if not policy or not policy.enabled:
            return (False, None)
        
        if self.is_expired(data_type, created_at, **kwargs):
            return (True, policy.action)
        
        return (False, None)
    
    def list_policies(self) -> Dict[DataType, RetentionPolicy]:
        """List all retention policies"""
        return self.policies.copy()
    
    def get_cache_ttl(self, integration_id: str, action_id: str) -> int:
        """Get cache TTL for a specific integration action (in days)"""
        # This can be overridden per integration/action
        # For now, return the global enrichment cache TTL
        return self.config.enrichment_cache_days
    
    def update_config(self, **kwargs) -> DataRetentionConfig:
        """Update global retention configuration"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        # Reinitialize policies with new config
        self._initialize_default_policies()
        
        return self.config


# Singleton instance
_retention_engine: Optional[DataRetentionEngine] = None


def get_retention_engine() -> DataRetentionEngine:
    """Get the global data retention engine instance"""
    global _retention_engine
    if _retention_engine is None:
        _retention_engine = DataRetentionEngine()
    return _retention_engine


def get_cache_ttl_days(integration_id: str, action_id: str) -> int:
    """Convenience function to get cache TTL in days"""
    engine = get_retention_engine()
    return engine.get_cache_ttl(integration_id, action_id)


def is_data_expired(
    data_type: DataType,
    created_at: datetime,
    **kwargs
) -> bool:
    """Convenience function to check if data is expired"""
    engine = get_retention_engine()
    return engine.is_expired(data_type, created_at, **kwargs)
