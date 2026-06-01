# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Base tool interface and implementations.
All enrichment tools follow the same async interface pattern.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import aiohttp
import asyncio
from models import ToolOutput, IndicatorType


class BaseTool(ABC):
    """Base class for all enrichment tools"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
    
    @abstractmethod
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Execute the tool with given input"""
        pass
    
    async def _make_request(self, url: str, method: str = 'GET', 
                           headers: Optional[Dict] = None,
                           params: Optional[Dict] = None,
                           json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request with timeout"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    method, url, 
                    headers=headers, 
                    params=params, 
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    return {
                        'status': response.status,
                        'data': await response.json() if response.content_type == 'application/json' else await response.text()
                    }
            except asyncio.TimeoutError:
                return {'status': 408, 'error': 'Request timeout'}
            except Exception as e:
                return {'status': 500, 'error': str(e)}


class IPReputationTool(BaseTool):
    """Check IP address reputation (mock implementation)"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("ip_reputation", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """
        Check IP reputation against threat intelligence sources.
        In production, this would call real APIs (AbuseIPDB, VirusTotal, etc.)
        """
        ip = input_data.get('value')
        
        # Mock implementation - check against known bad patterns
        suspicious_ips = ['192.168.1.100', '10.0.0.1']  # Mock malicious IPs
        
        is_suspicious = ip in suspicious_ips
        
        result = {
            'ip': ip,
            'reputation_score': 20 if is_suspicious else 90,  # 0-100, higher is better
            'is_malicious': is_suspicious,
            'is_tor': False,
            'is_vpn': False,
            'threat_categories': ['brute_force'] if is_suspicious else [],
            'country': 'US',
            'asn': 'AS15169',
            'isp': 'Mock ISP',
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_threat_intel'},
            metadata={'tool': self.name}
        )


class DomainReputationTool(BaseTool):
    """Check domain reputation"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("domain_reputation", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Check domain reputation"""
        domain = input_data.get('value')
        
        # Mock suspicious domains
        suspicious_domains = ['malicious-site.com', 'phishing-test.net']
        
        is_suspicious = domain in suspicious_domains
        
        result = {
            'domain': domain,
            'reputation_score': 25 if is_suspicious else 85,
            'is_malicious': is_suspicious,
            'threat_categories': ['phishing', 'malware'] if is_suspicious else [],
            'age_days': 30 if is_suspicious else 3650,
            'registrar': 'Mock Registrar',
            'nameservers': ['ns1.example.com', 'ns2.example.com']
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_domain_intel'},
            metadata={'tool': self.name}
        )


class HashAnalysisTool(BaseTool):
    """Analyze file hash"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("hash_analysis", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Analyze file hash against malware databases"""
        file_hash = input_data.get('value')
        
        # Mock malicious hashes
        malicious_hashes = [
            '44d88612fea8a8f36de82e1278abb02f',  # Mock MD5
            'da39a3ee5e6b4b0d3255bfef95601890afd80709'  # Mock SHA1
        ]
        
        is_malicious = file_hash in malicious_hashes
        
        result = {
            'hash': file_hash,
            'hash_type': 'md5' if len(file_hash) == 32 else 'sha1' if len(file_hash) == 40 else 'sha256',
            'is_malicious': is_malicious,
            'detection_count': 45 if is_malicious else 0,
            'total_scans': 70,
            'malware_family': 'Trojan.Generic' if is_malicious else None,
            'file_type': 'PE32',
            'first_seen': '2024-01-15T10:30:00Z' if is_malicious else None
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_sandbox'},
            metadata={'tool': self.name}
        )


class WhoisLookupTool(BaseTool):
    """Perform WHOIS lookup"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("whois_lookup", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Perform WHOIS lookup for domain"""
        domain = input_data.get('value')
        
        result = {
            'domain': domain,
            'registrar': 'Mock Registrar Inc.',
            'creation_date': '2020-01-15',
            'expiration_date': '2025-01-15',
            'registrant_country': 'US',
            'nameservers': ['ns1.mockdns.com', 'ns2.mockdns.com'],
            'dnssec': False,
            'status': ['clientTransferProhibited']
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_whois'},
            metadata={'tool': self.name}
        )


class GeoIPLookupTool(BaseTool):
    """Perform GeoIP lookup"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("geoip_lookup", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Get geographic information for IP"""
        ip = input_data.get('value')
        
        result = {
            'ip': ip,
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'Mountain View',
            'latitude': 37.386,
            'longitude': -122.084,
            'timezone': 'America/Los_Angeles',
            'isp': 'Mock Internet Service Provider',
            'organization': 'Mock Organization'
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_geoip'},
            metadata={'tool': self.name}
        )


class URLAnalysisTool(BaseTool):
    """Analyze URL"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("url_analysis", config)
    
    async def execute(self, input_data: Dict[str, Any]) -> ToolOutput:
        """Analyze URL for malicious content"""
        url = input_data.get('value')
        
        suspicious_urls = ['http://malicious-site.com', 'https://phishing-test.net']
        is_suspicious = any(sus in url for sus in suspicious_urls)
        
        result = {
            'url': url,
            'is_malicious': is_suspicious,
            'threat_score': 85 if is_suspicious else 10,
            'categories': ['phishing'] if is_suspicious else ['legitimate'],
            'redirects': [],
            'final_url': url,
            'ssl_valid': url.startswith('https://'),
            'page_title': 'Mock Page Title',
            'suspicious_patterns': ['suspicious_keyword'] if is_suspicious else []
        }
        
        return ToolOutput(
            success=True,
            result=result,
            raw={'source': 'mock_url_scanner'},
            metadata={'tool': self.name}
        )


# Tool registry
AVAILABLE_TOOLS = {
    'ip_reputation': IPReputationTool,
    'domain_reputation': DomainReputationTool,
    'hash_analysis': HashAnalysisTool,
    'whois_lookup': WhoisLookupTool,
    'geoip_lookup': GeoIPLookupTool,
    'url_analysis': URLAnalysisTool
}


def get_tool(tool_name: str, config: Optional[Dict[str, Any]] = None) -> BaseTool:
    """Get tool instance by name"""
    tool_class = AVAILABLE_TOOLS.get(tool_name)
    if not tool_class:
        raise ValueError(f"Unknown tool: {tool_name}")
    return tool_class(config)
