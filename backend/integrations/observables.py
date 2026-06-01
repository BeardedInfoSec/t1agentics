# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Observable Model - First-Class Objects

All integration actions operate on typed observables, not raw strings.
This ensures type safety, validation, and enrichment policy enforcement.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime


class ObservableType(str, Enum):
    """Supported observable types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    FILE = "file"
    ALERT = "alert"
    INVESTIGATION = "investigation"
    USER = "user"
    HOSTNAME = "hostname"


class IPObservable(BaseModel):
    """IP Address Observable"""
    type: ObservableType = Field(default=ObservableType.IP)
    value: str
    version: str = Field(default="ipv4")  # ipv4 or ipv6
    is_private: bool = Field(default=False)
    asn: Optional[str] = None
    country: Optional[str] = None
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "ip",
                "value": "8.8.8.8",
                "version": "ipv4",
                "is_private": False,
                "enrichment_allowed": True
            }
        }


class DomainObservable(BaseModel):
    """Domain Observable"""
    type: ObservableType = Field(default=ObservableType.DOMAIN)
    value: str
    is_internal: bool = Field(default=False)
    tld: Optional[str] = None
    subdomain: Optional[str] = None
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None


class URLObservable(BaseModel):
    """URL Observable"""
    type: ObservableType = Field(default=ObservableType.URL)
    value: str
    scheme: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None


class EmailObservable(BaseModel):
    """Email Address Observable"""
    type: ObservableType = Field(default=ObservableType.EMAIL)
    value: str
    username: Optional[str] = None
    domain: Optional[str] = None
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None


class FileHashObservable(BaseModel):
    """File Hash Observable"""
    type: ObservableType = Field(default=ObservableType.FILE_HASH)
    value: str
    hash_type: str  # md5, sha1, sha256, sha512
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "file_hash",
                "value": "44d88612fea8a8f36de82e1278abb02f",
                "hash_type": "md5",
                "enrichment_allowed": True
            }
        }


class FileObservable(BaseModel):
    """File Observable (Full File Context)"""
    type: ObservableType = Field(default=ObservableType.FILE)
    name: str
    size: Optional[int] = None
    mime_type: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)  # {md5: ..., sha256: ...}
    file_type: Optional[str] = None
    source: Optional[str] = None  # endpoint, email, download, etc.
    sandboxed: bool = Field(default=False)
    sandbox_verdict: Optional[str] = None
    enrichment_allowed: bool = Field(default=True)
    enrichment_denied_reason: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "file",
                "name": "invoice.pdf.exe",
                "size": 483921,
                "mime_type": "application/x-msdownload",
                "hashes": {
                    "md5": "44d88612fea8a8f36de82e1278abb02f",
                    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                },
                "file_type": "PE32 executable",
                "source": "email_attachment",
                "sandboxed": False,
                "enrichment_allowed": True
            }
        }


class AlertObservable(BaseModel):
    """Alert Observable"""
    type: ObservableType = Field(default=ObservableType.ALERT)
    alert_id: str
    title: str
    severity: str
    source: Optional[str] = None
    timestamp: datetime


class InvestigationObservable(BaseModel):
    """Investigation Observable"""
    type: ObservableType = Field(default=ObservableType.INVESTIGATION)
    investigation_id: str
    alert_id: Optional[str] = None
    state: str
    disposition: Optional[str] = None
    priority: str


# Union type for all observables
Observable = (
    IPObservable | 
    DomainObservable | 
    URLObservable | 
    EmailObservable | 
    FileHashObservable | 
    FileObservable | 
    AlertObservable | 
    InvestigationObservable
)


class EnrichmentResult(BaseModel):
    """Result of an enrichment action"""
    observable_type: ObservableType
    observable_value: str
    integration_id: str
    action_id: str
    success: bool
    cached: bool = Field(default=False)
    cache_age_days: Optional[int] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ttl_days: int = Field(default=30)
    
    class Config:
        json_schema_extra = {
            "example": {
                "observable_type": "file_hash",
                "observable_value": "44d88612fea8a8f36de82e1278abb02f",
                "integration_id": "virustotal",
                "action_id": "enrich_hash",
                "success": True,
                "cached": False,
                "data": {
                    "malicious": 42,
                    "suspicious": 5,
                    "clean": 12,
                    "verdict": "malicious"
                },
                "timestamp": "2025-12-15T02:00:00Z",
                "ttl_days": 30
            }
        }


def create_observable(observable_type: str, value: str, **kwargs) -> Observable:
    """Factory function to create observables"""
    observable_map = {
        "ip": IPObservable,
        "domain": DomainObservable,
        "url": URLObservable,
        "email": EmailObservable,
        "file_hash": FileHashObservable,
        "file": FileObservable,
        "alert": AlertObservable,
        "investigation": InvestigationObservable
    }
    
    obs_class = observable_map.get(observable_type)
    if not obs_class:
        raise ValueError(f"Unknown observable type: {observable_type}")
    
    return obs_class(value=value, **kwargs)
