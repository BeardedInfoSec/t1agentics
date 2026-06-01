# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Utility functions for extracting indicators from alerts and logs.
Supports IPs, domains, URLs, hashes, emails, usernames, and hostnames.
"""

import re
from typing import List, Dict, Any
from models import Indicator, IndicatorType


class IndicatorExtractor:
    """Extract indicators of compromise from text"""
    
    # Regex patterns for various indicator types
    IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    
    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IP addresses from text"""
        ips = re.findall(IndicatorExtractor.IP_PATTERN, text)
        # Filter out invalid IPs (e.g., version numbers)
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        return list(set(valid_ips))
    
    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """Extract domain names from text"""
        domains = re.findall(IndicatorExtractor.DOMAIN_PATTERN, text)
        # Filter out common false positives
        filtered = [d for d in domains if not any(d.endswith(suffix) for suffix in ['.local', '.internal', '.test'])]
        return list(set(filtered))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        urls = re.findall(IndicatorExtractor.URL_PATTERN, text)
        return list(set(urls))
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        emails = re.findall(IndicatorExtractor.EMAIL_PATTERN, text)
        return list(set(emails))
    
    @staticmethod
    def extract_hashes(text: str) -> Dict[str, List[str]]:
        """Extract file hashes from text"""
        return {
            'md5': list(set(re.findall(IndicatorExtractor.MD5_PATTERN, text))),
            'sha1': list(set(re.findall(IndicatorExtractor.SHA1_PATTERN, text))),
            'sha256': list(set(re.findall(IndicatorExtractor.SHA256_PATTERN, text)))
        }
    
    @staticmethod
    def extract_all(text: str, metadata: Dict[str, Any] = None) -> List[Indicator]:
        """Extract all indicators from text and metadata"""
        indicators = []
        
        # Combine text sources
        full_text = text
        if metadata:
            full_text += " " + str(metadata)
        
        # Extract IPs
        for ip in IndicatorExtractor.extract_ips(full_text):
            indicators.append(Indicator(
                type=IndicatorType.IP,
                value=ip,
                context="extracted_from_alert"
            ))
        
        # Extract domains
        for domain in IndicatorExtractor.extract_domains(full_text):
            indicators.append(Indicator(
                type=IndicatorType.DOMAIN,
                value=domain,
                context="extracted_from_alert"
            ))
        
        # Extract URLs
        for url in IndicatorExtractor.extract_urls(full_text):
            indicators.append(Indicator(
                type=IndicatorType.URL,
                value=url,
                context="extracted_from_alert"
            ))
        
        # Extract emails
        for email in IndicatorExtractor.extract_emails(full_text):
            indicators.append(Indicator(
                type=IndicatorType.EMAIL,
                value=email,
                context="extracted_from_alert"
            ))
        
        # Extract hashes
        hashes = IndicatorExtractor.extract_hashes(full_text)
        for hash_value in hashes['md5'] + hashes['sha1'] + hashes['sha256']:
            indicators.append(Indicator(
                type=IndicatorType.HASH,
                value=hash_value,
                context="extracted_from_alert"
            ))
        
        # Extract from metadata if available
        if metadata:
            if 'user' in metadata or 'username' in metadata:
                user = metadata.get('user') or metadata.get('username')
                if user:
                    indicators.append(Indicator(
                        type=IndicatorType.USERNAME,
                        value=str(user),
                        context="metadata"
                    ))
            
            if 'host' in metadata or 'hostname' in metadata:
                host = metadata.get('host') or metadata.get('hostname')
                if host:
                    indicators.append(Indicator(
                        type=IndicatorType.HOSTNAME,
                        value=str(host),
                        context="metadata"
                    ))
        
        return indicators


def normalize_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize alert format from various sources"""
    normalized = {
        'title': '',
        'description': '',
        'source': 'unknown',
        'metadata': {}
    }
    
    # Common field mappings
    title_fields = ['title', 'name', 'alert_name', 'event_name', 'rule_name']
    description_fields = ['description', 'message', 'details', 'summary']
    source_fields = ['source', 'log_source', 'event_source', 'sensor']
    
    # Extract title
    for field in title_fields:
        if field in raw_alert:
            normalized['title'] = str(raw_alert[field])
            break
    
    # Extract description
    for field in description_fields:
        if field in raw_alert:
            normalized['description'] = str(raw_alert[field])
            break
    
    # Extract source
    for field in source_fields:
        if field in raw_alert:
            normalized['source'] = str(raw_alert[field])
            break
    
    # Store everything else in metadata
    skip_fields = set(title_fields + description_fields + source_fields)
    normalized['metadata'] = {k: v for k, v in raw_alert.items() if k not in skip_fields}
    
    return normalized
