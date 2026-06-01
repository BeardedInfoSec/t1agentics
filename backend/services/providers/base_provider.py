# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Base Provider Interface
All threat intelligence providers must implement this interface
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseThreatIntelProvider(ABC):
    """Base class for all threat intelligence providers"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        self.api_key = api_key
        self.config = kwargs
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'virustotal', 'otx')"""
        pass
    
    @property
    @abstractmethod
    def supported_ioc_types(self) -> list:
        """Return list of supported IOC types: ['ip', 'domain', 'hash', 'url', 'email']"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """
        Test the connection to the provider
        
        Returns:
            Dict with success status and details
        """
        pass
    
    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich an IP address"""
        raise NotImplementedError(f"{self.provider_name} does not support IP enrichment")
    
    async def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich a domain"""
        raise NotImplementedError(f"{self.provider_name} does not support domain enrichment")
    
    async def enrich_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Enrich a file hash"""
        raise NotImplementedError(f"{self.provider_name} does not support hash enrichment")
    
    async def enrich_url(self, url: str) -> Dict[str, Any]:
        """Enrich a URL"""
        raise NotImplementedError(f"{self.provider_name} does not support URL enrichment")
    
    async def enrich_email(self, email: str) -> Dict[str, Any]:
        """Enrich an email address"""
        raise NotImplementedError(f"{self.provider_name} does not support email enrichment")
    
    def _standardize_response(
        self,
        ioc_value: str,
        ioc_type: str,
        raw_data: Dict[str, Any],
        is_malicious: bool,
        threat_score: int,
        confidence: float,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Standardize provider responses into common format
        
        This ensures all providers return consistent data structure
        """
        return {
            "provider": self.provider_name,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "is_malicious": is_malicious,
            "threat_score": threat_score,  # 0-100
            "confidence": confidence,  # 0.0-1.0
            "details": details or {},
            "raw_data": raw_data,
            "timestamp": None  # Will be added by caller
        }
