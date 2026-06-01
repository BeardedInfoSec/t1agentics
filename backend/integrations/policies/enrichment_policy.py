# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enrichment Policy Engine - Hard Gate

Determines whether an observable may be enriched.
This is a REQUIRED check before any enrichment action.

Default behavior: DENY
- Private IPs (RFC 1918)
- Loopback addresses
- Link-local addresses
- Internal domains
- Localhost

Configurable:
- Organization deny lists
- Explicit allow overrides (auditable)
- TTL on overrides
"""

import ipaddress
import re
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

from integrations.observables import (
    Observable, IPObservable, DomainObservable, URLObservable,
    FileObservable, ObservableType
)


class EnrichmentPolicyConfig(BaseModel):
    """Enrichment policy configuration"""
    deny_ip_ranges: List[str] = Field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fe80::/10",
        "fc00::/7"
    ])
    deny_domains: List[str] = Field(default_factory=lambda: [
        "*.local",
        "*.internal",
        "*.lan",
        "*.corp",
        "localhost"
    ])
    deny_file_types: List[str] = Field(default_factory=lambda: [
        "txt",
        "log",
        "csv"
    ])
    allow_overrides: Dict[str, Any] = Field(default_factory=dict)  # {value: {expires_at, reason}}
    
    class Config:
        json_schema_extra = {
            "example": {
                "deny_ip_ranges": ["10.0.0.0/8", "192.168.0.0/16"],
                "deny_domains": ["*.internal.local"],
                "deny_file_types": ["txt", "log"],
                "allow_overrides": {
                    "10.1.2.3": {
                        "expires_at": "2025-12-31T23:59:59Z",
                        "reason": "Test environment monitoring",
                        "approved_by": "admin"
                    }
                }
            }
        }


class PolicyDecision(BaseModel):
    """Result of a policy evaluation"""
    allowed: bool
    reason: Optional[str] = None
    policy_matched: Optional[str] = None
    override_active: bool = Field(default=False)
    override_expires_at: Optional[datetime] = None


class EnrichmentPolicyEngine:
    """
    Enrichment Policy Engine
    
    Enforces enrichment policies on observables.
    Must be called before any enrichment action.
    """
    
    def __init__(self, config: Optional[EnrichmentPolicyConfig] = None):
        self.config = config or EnrichmentPolicyConfig()
        self._ip_networks = [ipaddress.ip_network(cidr) for cidr in self.config.deny_ip_ranges]
    
    def evaluate(self, observable: Observable) -> PolicyDecision:
        """
        Evaluate whether an observable may be enriched
        
        Returns:
            PolicyDecision with allowed=True/False and reason
        """
        # Check for explicit allow override first
        override_check = self._check_override(observable)
        if override_check:
            return override_check
        
        # Type-specific policy checks
        if isinstance(observable, IPObservable):
            return self._evaluate_ip(observable)
        elif isinstance(observable, DomainObservable):
            return self._evaluate_domain(observable)
        elif isinstance(observable, URLObservable):
            return self._evaluate_url(observable)
        elif isinstance(observable, FileObservable):
            return self._evaluate_file(observable)
        else:
            # Default allow for other types
            return PolicyDecision(allowed=True)
    
    def _check_override(self, observable: Observable) -> Optional[PolicyDecision]:
        """Check if there's an active allow override"""
        value = observable.value if hasattr(observable, 'value') else None
        if not value:
            return None
        
        override = self.config.allow_overrides.get(value)
        if not override:
            return None
        
        # Check if override is expired
        expires_at = override.get('expires_at')
        if expires_at:
            expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if datetime.utcnow() > expires_dt:
                return None
        
        return PolicyDecision(
            allowed=True,
            reason=f"Override active: {override.get('reason', 'No reason provided')}",
            override_active=True,
            override_expires_at=expires_at
        )
    
    def _evaluate_ip(self, observable: IPObservable) -> PolicyDecision:
        """Evaluate IP address enrichment policy"""
        try:
            ip = ipaddress.ip_address(observable.value)
            
            # Check against denied networks
            for network in self._ip_networks:
                if ip in network:
                    return PolicyDecision(
                        allowed=False,
                        reason=f"IP {observable.value} is in denied range {network}",
                        policy_matched=str(network)
                    )
            
            # Allow if not in denied ranges
            return PolicyDecision(allowed=True)
            
        except ValueError:
            return PolicyDecision(
                allowed=False,
                reason=f"Invalid IP address: {observable.value}"
            )
    
    def _evaluate_domain(self, observable: DomainObservable) -> PolicyDecision:
        """Evaluate domain enrichment policy"""
        domain = observable.value.lower()
        
        # Check against denied domain patterns
        for pattern in self.config.deny_domains:
            if self._domain_matches_pattern(domain, pattern):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Domain {domain} matches denied pattern {pattern}",
                    policy_matched=pattern
                )
        
        return PolicyDecision(allowed=True)
    
    def _evaluate_url(self, observable: URLObservable) -> PolicyDecision:
        """Evaluate URL enrichment policy"""
        # Extract domain from URL and evaluate
        if observable.domain:
            domain_obs = DomainObservable(value=observable.domain)
            return self._evaluate_domain(domain_obs)
        
        return PolicyDecision(allowed=True)
    
    def _evaluate_file(self, observable: FileObservable) -> PolicyDecision:
        """Evaluate file enrichment policy"""
        # Check file type against denied types
        if observable.file_type:
            file_ext = observable.name.split('.')[-1].lower() if '.' in observable.name else None
            if file_ext in self.config.deny_file_types:
                return PolicyDecision(
                    allowed=False,
                    reason=f"File type {file_ext} is in denied list",
                    policy_matched=file_ext
                )
        
        return PolicyDecision(allowed=True)
    
    def _domain_matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check if domain matches a wildcard pattern"""
        # Convert wildcard pattern to regex
        # *.internal.local -> .*\.internal\.local$
        regex_pattern = pattern.replace('.', r'\.').replace('*', r'[^.]*') + '$'
        return bool(re.match(regex_pattern, domain, re.IGNORECASE))
    
    def add_override(
        self, 
        value: str, 
        reason: str, 
        approved_by: str,
        ttl_days: Optional[int] = None
    ) -> None:
        """
        Add an enrichment override (explicit allow)
        
        Args:
            value: Observable value to allow
            reason: Justification for override
            approved_by: Who approved this override
            ttl_days: Optional TTL in days (None = permanent)
        """
        override = {
            "reason": reason,
            "approved_by": approved_by,
            "created_at": datetime.utcnow().isoformat()
        }
        
        if ttl_days:
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)
            override["expires_at"] = expires_at.isoformat()
        
        self.config.allow_overrides[value] = override
    
    def remove_override(self, value: str) -> bool:
        """Remove an enrichment override"""
        if value in self.config.allow_overrides:
            del self.config.allow_overrides[value]
            return True
        return False
    
    def list_overrides(self) -> Dict[str, Any]:
        """List all active overrides"""
        active_overrides = {}
        now = datetime.utcnow()
        
        for value, override in self.config.allow_overrides.items():
            # Skip expired overrides
            expires_at = override.get('expires_at')
            if expires_at:
                expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if now > expires_dt:
                    continue
            
            active_overrides[value] = override
        
        return active_overrides


# Singleton instance
_policy_engine: Optional[EnrichmentPolicyEngine] = None


def get_policy_engine() -> EnrichmentPolicyEngine:
    """Get the global enrichment policy engine instance"""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = EnrichmentPolicyEngine()
    return _policy_engine


def evaluate_enrichment_policy(observable: Observable) -> PolicyDecision:
    """
    Convenience function to evaluate enrichment policy
    
    This is the REQUIRED gate before enrichment.
    """
    engine = get_policy_engine()
    return engine.evaluate(observable)
