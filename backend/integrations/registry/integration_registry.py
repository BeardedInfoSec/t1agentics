# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Registry - Single Source of Truth

The registry is the central authority for:
- Available integrations
- Integration types
- Authentication methods
- Supported actions
- Input/output schemas
- Cache behavior
- Observable compatibility
- Policy enforcement requirements
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from integrations.observables import ObservableType


class IntegrationType(str, Enum):
    """Types of integrations"""
    THREAT_INTEL = "threat_intel"
    ENRICHMENT = "enrichment"
    SANDBOX = "sandbox"
    TICKETING = "ticketing"
    SIEM = "siem"
    SOAR = "soar"
    COMMUNICATION = "communication"
    CASE_MANAGEMENT = "case_management"
    EDR = "edr"
    FIREWALL = "firewall"
    NETWORK = "network"
    VULNERABILITY = "vulnerability"
    IDENTITY = "identity"
    CUSTOM = "custom"


class AuthType(str, Enum):
    """Authentication methods"""
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    CUSTOM_HEADER = "custom_header"
    NONE = "none"


class ActionSchema(BaseModel):
    """Schema definition for an integration action"""
    id: str
    name: str
    description: Optional[str] = None
    observable_type: Optional[str] = None  # What type of observable this acts on (ip, domain, file_hash, etc.)
    http_method: str = Field(default="POST")
    endpoint: str
    requires_auth: bool = Field(default=True)

    # Action metadata
    action_type: Optional[str] = None  # investigate, contain, remediate, etc.
    read_only: bool = Field(default=True)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)  # Action parameters

    # Policy enforcement
    policy_enforced: bool = Field(default=False)  # Does this action require enrichment policy check?
    requires_permission: bool = Field(default=True)  # Does this require actor permission?

    # Caching
    cacheable: bool = Field(default=False)
    cache_ttl_days: int = Field(default=30)

    # Schemas
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)

    # Headers and parameters
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)

    # Content type for POST/PUT requests
    content_type: str = Field(default="application/json")  # application/json, application/x-www-form-urlencoded, multipart/form-data

    # Rate limiting
    rate_limit_per_minute: Optional[int] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "enrich_hash",
                "name": "Enrich File Hash",
                "description": "Get threat intelligence for a file hash",
                "observable_type": "file_hash",
                "http_method": "GET",
                "endpoint": "/file/{hash}/report",
                "requires_auth": True,
                "policy_enforced": True,
                "cacheable": True,
                "cache_ttl_days": 30,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string"}
                    },
                    "required": ["hash"]
                }
            }
        }


class Integration(BaseModel):
    """Integration definition"""
    id: str
    name: str
    type: IntegrationType
    description: Optional[str] = None
    version: str = Field(default="1.0.0")

    # Authentication
    auth_type: AuthType
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    credential_id: Optional[str] = None  # Reference to stored credential

    # Base configuration
    base_url: str
    enabled: bool = Field(default=False)
    
    # Actions
    actions: List[ActionSchema] = Field(default_factory=list)
    
    # Metadata
    vendor: Optional[str] = None
    documentation_url: Optional[str] = None
    icon_url: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    # Status
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    # OpenAPI source
    openapi_spec_url: Optional[str] = None
    openapi_imported_at: Optional[datetime] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "virustotal",
                "name": "VirusTotal",
                "type": "threat_intel",
                "description": "VirusTotal threat intelligence platform",
                "version": "1.0.0",
                "auth_type": "api_key",
                "auth_config": {
                    "key_name": "x-apikey",
                    "key_location": "header"
                },
                "base_url": "https://www.virustotal.com/api/v3",
                "enabled": True,
                "vendor": "VirusTotal",
                "tags": ["threat_intel", "file_analysis", "malware"]
            }
        }


class IntegrationRegistry:
    """
    Integration Registry
    
    Central repository for all integration definitions.
    """
    
    def __init__(self):
        self.integrations: Dict[str, Integration] = {}
        self._initialize_core_integrations()
    
    def _initialize_core_integrations(self):
        """Initialize core integrations - now handled by catalog import"""
        # Pre-built integrations are NO LONGER used
        # Users import integrations from the catalog via the UI/API
        # This gives a clean slate on fresh installations
        pass
    
    def register(self, integration: Integration) -> None:
        """Register a new integration"""
        self.integrations[integration.id] = integration
        integration.updated_at = datetime.utcnow()
    
    def get(self, integration_id: str) -> Optional[Integration]:
        """Get an integration by ID"""
        return self.integrations.get(integration_id)
    
    def list(
        self,
        integration_type: Optional[IntegrationType] = None,
        enabled_only: bool = False
    ) -> List[Integration]:
        """List integrations with optional filters"""
        integrations = list(self.integrations.values())
        
        if integration_type:
            integrations = [i for i in integrations if i.type == integration_type]
        
        if enabled_only:
            integrations = [i for i in integrations if i.enabled]
        
        return integrations
    
    def enable(self, integration_id: str) -> bool:
        """Enable an integration"""
        integration = self.get(integration_id)
        if integration:
            integration.enabled = True
            integration.updated_at = datetime.utcnow()
            return True
        return False
    
    def disable(self, integration_id: str) -> bool:
        """Disable an integration"""
        integration = self.get(integration_id)
        if integration:
            integration.enabled = False
            integration.updated_at = datetime.utcnow()
            return True
        return False
    
    def get_action(
        self,
        integration_id: str,
        action_id: str
    ) -> Optional[ActionSchema]:
        """Get a specific action from an integration"""
        integration = self.get(integration_id)
        if not integration:
            return None
        
        for action in integration.actions:
            if action.id == action_id:
                return action
        return None
    
    def list_actions_for_observable(
        self,
        observable_type: ObservableType,
        enabled_integrations_only: bool = True
    ) -> List[tuple[Integration, ActionSchema]]:
        """
        List all actions that can operate on a specific observable type
        
        Returns:
            List of (integration, action) tuples
        """
        results = []
        
        integrations = self.list(enabled_only=enabled_integrations_only)
        for integration in integrations:
            for action in integration.actions:
                if action.observable_type == observable_type:
                    results.append((integration, action))
        
        return results
    
    def delete(self, integration_id: str) -> bool:
        """Delete an integration"""
        if integration_id in self.integrations:
            del self.integrations[integration_id]
            return True
        return False


# Singleton instance
_registry: Optional[IntegrationRegistry] = None


def get_registry() -> IntegrationRegistry:
    """Get the global integration registry instance"""
    global _registry
    if _registry is None:
        _registry = IntegrationRegistry()
    return _registry
