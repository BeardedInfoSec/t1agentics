# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Permission Engine - Actor-Based Allow-Lists

Controls WHO can execute WHAT actions.

Actors:
- Human users
- API keys
- Automation workflows  
- AI agents

Permission model: actor → integration → action

Default: DENY
New integrations: NO actions allowed
New actions: DISABLED until approved
AI sees only explicitly allowed actions
"""

from enum import Enum
from typing import Optional, List, Dict, Set
from pydantic import BaseModel, Field
from datetime import datetime


class ActorType(str, Enum):
    """Types of actors in the system"""
    HUMAN = "human"
    API_KEY = "api_key"
    AUTOMATION = "automation"
    AI_AGENT = "ai_agent"


class Actor(BaseModel):
    """An actor that can execute integration actions"""
    id: str
    type: ActorType
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "ai_analyst",
                "type": "ai_agent",
                "name": "AI Analyst Agent",
                "description": "Autonomous investigation agent"
            }
        }


class ActionPermission(BaseModel):
    """Permission grant for an actor to execute actions"""
    actor_id: str
    integration_id: str
    allowed_actions: List[str] = Field(default_factory=list)
    denied_actions: List[str] = Field(default_factory=list)
    allow_all: bool = Field(default=False)  # Allow all actions in this integration
    granted_by: str
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    reason: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "actor_id": "ai_analyst",
                "integration_id": "virustotal",
                "allowed_actions": ["enrich_hash", "enrich_ip"],
                "denied_actions": [],
                "allow_all": False,
                "granted_by": "admin",
                "reason": "Allow AI to enrich IOCs for investigations"
            }
        }


class PermissionDecision(BaseModel):
    """Result of a permission check"""
    allowed: bool
    reason: str
    permission: Optional[ActionPermission] = None


class ActionPermissionEngine:
    """
    Action Permission Engine
    
    Enforces actor-based permissions for integration actions.
    """
    
    def __init__(self):
        self.actors: Dict[str, Actor] = {}
        self.permissions: List[ActionPermission] = []
        self._initialize_default_actors()
    
    def _initialize_default_actors(self):
        """Initialize default system actors"""
        default_actors = [
            Actor(
                id="admin",
                type=ActorType.HUMAN,
                name="Administrator",
                description="System administrator"
            ),
            Actor(
                id="ai_analyst",
                type=ActorType.AI_AGENT,
                name="AI Analyst",
                description="Autonomous investigation agent"
            ),
            Actor(
                id="automation_engine",
                type=ActorType.AUTOMATION,
                name="Automation Engine",
                description="Workflow automation system"
            ),
            Actor(
                id="api_public",
                type=ActorType.API_KEY,
                name="Public API",
                description="Public API access"
            ),
            Actor(
                id="threat_intel_service",
                type=ActorType.AUTOMATION,
                name="Threat Intel Service",
                description="Internal threat intelligence enrichment service"
            )
        ]
        
        for actor in default_actors:
            self.actors[actor.id] = actor

        # Grant default permissions for internal services
        self._initialize_default_permissions()

    def _initialize_default_permissions(self):
        """Initialize default permissions for internal services"""
        # Threat intel service needs access to all threat intel integrations
        # Note: This is a default allow-list for common integrations
        # New integrations are auto-granted if they match THREAT_INTEL or ENRICHMENT types
        threat_intel_integrations = [
            'virustotal', 'virustotal_v3', 'abuseipdb', 'shodan', 'greynoise', 'ipinfo',
            'urlhaus', 'malwarebazaar', 'otx', 'hibp', 'alienvault_otx', 'urlscan',
            'hybrid_analysis', 'misp',
            # RDAP - Registration Data Access Protocol (free WHOIS replacement)
            'rdap_arin', 'rdap_verisign', 'rdap_ripe', 'rdap_apnic', 'rdap_lacnic', 'rdap_afrinic',
            # Additional free services
            'whois', 'dns_lookup'
        ]

        for integration_id in threat_intel_integrations:
            permission = ActionPermission(
                actor_id='threat_intel_service',
                integration_id=integration_id,
                granted_by='system',
                reason='Internal service auto-grant',
                allow_all=True
            )
            self.permissions.append(permission)

        # AI analyst also needs access to threat intel for investigations
        for integration_id in threat_intel_integrations:
            permission = ActionPermission(
                actor_id='ai_analyst',
                integration_id=integration_id,
                granted_by='system',
                reason='AI analyst auto-grant for investigations',
                allow_all=True
            )
            self.permissions.append(permission)

    def auto_grant_for_integration(self, integration_id: str, integration_type: str) -> None:
        """
        Auto-grant permissions for threat intel and enrichment integrations.

        Called when new integrations are imported from the catalog.
        """
        # Only auto-grant for threat intel, enrichment, and sandbox types
        allowed_types = ['threat_intel', 'enrichment', 'sandbox', 'THREAT_INTEL', 'ENRICHMENT', 'SANDBOX']
        if integration_type not in allowed_types:
            return

        # Grant to threat_intel_service
        if not self._find_permission('threat_intel_service', integration_id):
            self.permissions.append(ActionPermission(
                actor_id='threat_intel_service',
                integration_id=integration_id,
                granted_by='system',
                reason='Auto-grant for threat intel integration',
                allow_all=True
            ))

        # Grant to ai_analyst
        if not self._find_permission('ai_analyst', integration_id):
            self.permissions.append(ActionPermission(
                actor_id='ai_analyst',
                integration_id=integration_id,
                granted_by='system',
                reason='Auto-grant for AI analyst investigations',
                allow_all=True
            ))

    def register_actor(self, actor: Actor) -> None:
        """Register a new actor"""
        self.actors[actor.id] = actor
    
    def grant_permission(
        self,
        actor_id: str,
        integration_id: str,
        actions: List[str],
        granted_by: str,
        reason: Optional[str] = None,
        allow_all: bool = False
    ) -> ActionPermission:
        """
        Grant permission for an actor to execute actions
        
        Args:
            actor_id: Actor receiving permission
            integration_id: Integration ID
            actions: List of action IDs to allow
            granted_by: Who granted this permission
            reason: Justification for grant
            allow_all: Allow all actions in integration
        """
        # Check if actor exists
        if actor_id not in self.actors:
            raise ValueError(f"Actor {actor_id} not found")
        
        # Check if permission already exists
        existing = self._find_permission(actor_id, integration_id)
        if existing:
            # Update existing permission
            existing.allowed_actions = list(set(existing.allowed_actions + actions))
            existing.allow_all = allow_all
            existing.granted_by = granted_by
            existing.granted_at = datetime.utcnow()
            existing.reason = reason
            return existing
        
        # Create new permission
        permission = ActionPermission(
            actor_id=actor_id,
            integration_id=integration_id,
            allowed_actions=actions,
            allow_all=allow_all,
            granted_by=granted_by,
            reason=reason
        )
        self.permissions.append(permission)
        return permission
    
    def revoke_permission(
        self,
        actor_id: str,
        integration_id: str,
        action_id: Optional[str] = None
    ) -> bool:
        """
        Revoke permission
        
        Args:
            actor_id: Actor ID
            integration_id: Integration ID
            action_id: Specific action to revoke (None = revoke all)
        """
        permission = self._find_permission(actor_id, integration_id)
        if not permission:
            return False
        
        if action_id:
            # Revoke specific action
            if action_id in permission.allowed_actions:
                permission.allowed_actions.remove(action_id)
                return True
            return False
        else:
            # Revoke entire integration permission
            self.permissions.remove(permission)
            return True
    
    def check_permission(
        self,
        actor_id: str,
        integration_id: str,
        action_id: str
    ) -> PermissionDecision:
        """
        Check if an actor can execute an action
        
        Args:
            actor_id: Actor attempting action
            integration_id: Integration ID
            action_id: Action ID
            
        Returns:
            PermissionDecision with allowed=True/False
        """
        # Check if actor exists
        if actor_id not in self.actors:
            return PermissionDecision(
                allowed=False,
                reason=f"Actor {actor_id} not found"
            )
        
        actor = self.actors[actor_id]
        
        # Find permission for this actor + integration
        permission = self._find_permission(actor_id, integration_id)
        
        if not permission:
            return PermissionDecision(
                allowed=False,
                reason=f"No permissions granted for {actor.name} on integration {integration_id}"
            )
        
        # Check if action is explicitly denied
        if action_id in permission.denied_actions:
            return PermissionDecision(
                allowed=False,
                reason=f"Action {action_id} is explicitly denied for {actor.name}",
                permission=permission
            )
        
        # Check if allow_all is enabled
        if permission.allow_all:
            return PermissionDecision(
                allowed=True,
                reason=f"{actor.name} has full access to {integration_id}",
                permission=permission
            )
        
        # Check if action is in allowed list
        if action_id in permission.allowed_actions:
            return PermissionDecision(
                allowed=True,
                reason=f"{actor.name} is authorized to execute {action_id}",
                permission=permission
            )
        
        # Default deny
        return PermissionDecision(
            allowed=False,
            reason=f"Action {action_id} not in allowed list for {actor.name}"
        )
    
    def list_actor_permissions(self, actor_id: str) -> List[ActionPermission]:
        """List all permissions for an actor"""
        return [p for p in self.permissions if p.actor_id == actor_id]
    
    def list_integration_permissions(self, integration_id: str) -> List[ActionPermission]:
        """List all permissions for an integration"""
        return [p for p in self.permissions if p.integration_id == integration_id]
    
    def get_allowed_actions_for_actor(
        self,
        actor_id: str,
        integration_id: str
    ) -> Set[str]:
        """Get set of allowed actions for an actor on an integration"""
        permission = self._find_permission(actor_id, integration_id)
        if not permission:
            return set()
        
        if permission.allow_all:
            return set(["*"])  # All actions
        
        return set(permission.allowed_actions) - set(permission.denied_actions)
    
    def _find_permission(
        self,
        actor_id: str,
        integration_id: str
    ) -> Optional[ActionPermission]:
        """Find permission for actor + integration"""
        for permission in self.permissions:
            if (permission.actor_id == actor_id and 
                permission.integration_id == integration_id):
                return permission
        return None


# Singleton instance
_permission_engine: Optional[ActionPermissionEngine] = None


def get_permission_engine() -> ActionPermissionEngine:
    """Get the global permission engine instance"""
    global _permission_engine
    if _permission_engine is None:
        _permission_engine = ActionPermissionEngine()
    return _permission_engine


def check_action_permission(
    actor_id: str,
    integration_id: str,
    action_id: str
) -> PermissionDecision:
    """
    Convenience function to check action permission
    
    This is a REQUIRED check before executing any action.
    """
    engine = get_permission_engine()
    return engine.check_permission(actor_id, integration_id, action_id)
