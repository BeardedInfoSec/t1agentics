# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Field Extraction Engine
Automatically extracts and normalizes fields from security events
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import ipaddress

logger = logging.getLogger(__name__)


class FieldType(Enum):
    """Canonical field types for security data"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    IP_ADDRESS = "ip"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    DOMAIN = "domain"
    LIST = "list"


class ExtractionMethod(Enum):
    """Methods for extracting fields"""
    REGEX = "regex"
    JSON_PATH = "json_path"
    HEURISTIC = "heuristic"
    MAPPING = "mapping"


@dataclass
class ExtractionRule:
    """Definition of a field extraction rule"""
    id: str
    name: str
    description: str
    source_field: str  # Field to extract from (e.g., "raw_message", "$.user.email")
    method: ExtractionMethod
    pattern: Optional[str] = None  # Regex pattern or JSON path
    target_field: str = ""  # Canonical field name (e.g., "user.username")
    field_type: FieldType = FieldType.STRING
    multi_value: bool = False
    enabled: bool = True
    priority: int = 100
    vendor_scope: Optional[List[str]] = None  # Apply only to specific vendors
    source_type_scope: Optional[List[str]] = None
    transform: Optional[str] = None  # Post-extraction transform (e.g., "lowercase")
    default_value: Optional[Any] = None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source_field': self.source_field,
            'method': self.method.value,
            'pattern': self.pattern,
            'target_field': self.target_field,
            'field_type': self.field_type.value,
            'multi_value': self.multi_value,
            'enabled': self.enabled,
            'priority': self.priority,
            'vendor_scope': self.vendor_scope,
            'source_type_scope': self.source_type_scope,
            'transform': self.transform,
            'default_value': self.default_value
        }


class FieldExtractor:
    """
    Core field extraction engine
    Extracts and normalizes fields from raw security events
    """
    
    # Built-in regex patterns for common security fields
    BUILTIN_PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        'windows_path': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        'unix_path': r'/(?:[^/\0]+/)*[^/\0]*',
        'cve': r'CVE-\d{4}-\d{4,}',
        'mitre_technique': r'T\d{4}(?:\.\d{3})?',
    }
    
    # Canonical field mappings - maps various vendor field names to canonical names
    CANONICAL_MAPPINGS = {
        # User fields
        'user.username': ['username', 'user', 'user_name', 'userName', 'account_name', 'accountName', 'login', 'uid'],
        'user.email': ['email', 'user_email', 'userEmail', 'mail', 'emailAddress'],
        'user.display_name': ['display_name', 'displayName', 'full_name', 'fullName', 'name'],
        'user.domain': ['user_domain', 'userDomain', 'domain', 'ad_domain'],
        'user.role': ['role', 'user_role', 'userRole', 'group', 'groups'],
        'user.privileged': ['privileged', 'is_admin', 'isAdmin', 'elevated', 'admin'],
        
        # Host fields
        'host.hostname': ['hostname', 'host', 'computer_name', 'computerName', 'machine', 'device_name'],
        'host.ip': ['host_ip', 'hostIp', 'device_ip', 'local_ip', 'internal_ip'],
        'host.os.name': ['os', 'os_name', 'osName', 'operating_system', 'platform'],
        'host.os.version': ['os_version', 'osVersion', 'os_ver'],
        'host.mac': ['mac', 'mac_address', 'macAddress', 'physical_address'],
        
        # Network fields
        'source.ip': ['source_ip', 'sourceIp', 'src_ip', 'srcIp', 'src', 'source_address', 'client_ip'],
        'source.port': ['source_port', 'sourcePort', 'src_port', 'srcPort', 'client_port'],
        'destination.ip': ['destination_ip', 'destinationIp', 'dest_ip', 'destIp', 'dst', 'dst_ip', 'target_ip', 'server_ip'],
        'destination.port': ['destination_port', 'destinationPort', 'dest_port', 'destPort', 'dst_port', 'server_port'],
        'network.protocol': ['protocol', 'proto', 'network_protocol'],
        'network.direction': ['direction', 'traffic_direction', 'flow_direction'],
        
        # Process fields
        'process.name': ['process_name', 'processName', 'proc_name', 'image', 'exe'],
        'process.pid': ['pid', 'process_id', 'processId', 'proc_id'],
        'process.command_line': ['command_line', 'commandLine', 'cmdline', 'cmd', 'process_command_line'],
        'process.parent.name': ['parent_process', 'parentProcess', 'parent_name', 'parent_image'],
        'process.parent.pid': ['parent_pid', 'parentPid', 'ppid', 'parent_process_id'],
        'process.hash.sha256': ['process_sha256', 'sha256', 'file_sha256'],
        'process.hash.md5': ['process_md5', 'md5', 'file_md5'],
        
        # File fields
        'file.path': ['file_path', 'filePath', 'path', 'full_path', 'target_filename'],
        'file.name': ['file_name', 'fileName', 'filename'],
        'file.extension': ['file_extension', 'extension', 'ext'],
        'file.size': ['file_size', 'fileSize', 'size', 'bytes'],
        'file.hash.sha256': ['sha256', 'file_sha256', 'hash_sha256'],
        'file.hash.md5': ['md5', 'file_md5', 'hash_md5'],
        'file.hash.sha1': ['sha1', 'file_sha1', 'hash_sha1'],
        
        # Event fields
        'event.id': ['event_id', 'eventId', 'id', 'alert_id', 'alertId', 'uuid'],
        'event.action': ['action', 'event_action', 'eventAction', 'activity', 'operation'],
        'event.category': ['category', 'event_category', 'eventCategory', 'type'],
        'event.severity': ['severity', 'event_severity', 'priority', 'risk_level', 'threat_level'],
        'event.outcome': ['outcome', 'result', 'status', 'disposition'],
        
        # Cloud fields
        'cloud.provider': ['cloud_provider', 'cloudProvider', 'provider'],
        'cloud.account.id': ['account_id', 'accountId', 'aws_account', 'subscription_id'],
        'cloud.region': ['region', 'cloud_region', 'location', 'zone'],
        
        # Email fields
        'email.from': ['from', 'sender', 'from_address', 'email_from'],
        'email.to': ['to', 'recipient', 'to_address', 'email_to', 'recipients'],
        'email.subject': ['subject', 'email_subject', 'mail_subject'],
        'email.attachments': ['attachments', 'attachment_names', 'attached_files'],
        
        # Threat fields
        'threat.technique.id': ['technique_id', 'mitre_technique', 'attack_technique', 'mitre_id'],
        'threat.technique.name': ['technique', 'technique_name', 'attack_name'],
        'threat.tactic': ['tactic', 'mitre_tactic', 'attack_tactic'],
        'threat.indicator.ip': ['malicious_ip', 'threat_ip', 'ioc_ip'],
        'threat.indicator.domain': ['malicious_domain', 'threat_domain', 'ioc_domain'],
    }
    
    def __init__(self):
        self.custom_rules: List[ExtractionRule] = []
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_builtin_patterns()
    
    def _compile_builtin_patterns(self):
        """Pre-compile regex patterns for performance"""
        for name, pattern in self.BUILTIN_PATTERNS.items():
            try:
                self._compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Failed to compile pattern {name}: {e}")
    
    def add_rule(self, rule: ExtractionRule) -> None:
        """Add a custom extraction rule"""
        self.custom_rules.append(rule)
        # Compile the pattern if it's a regex
        if rule.method == ExtractionMethod.REGEX and rule.pattern:
            try:
                self._compiled_patterns[rule.id] = re.compile(rule.pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Failed to compile rule pattern {rule.id}: {e}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a custom extraction rule"""
        for i, rule in enumerate(self.custom_rules):
            if rule.id == rule_id:
                self.custom_rules.pop(i)
                self._compiled_patterns.pop(rule_id, None)
                return True
        return False
    
    def extract_all(self, event: Dict[str, Any], vendor: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract all fields from an event using built-in patterns, 
        canonical mappings, and custom rules
        """
        extracted = {}
        
        # Step 1: Apply canonical field mappings
        extracted.update(self._apply_canonical_mappings(event))
        
        # Step 2: Extract from raw message if present
        raw_message = event.get('raw_message', '') or event.get('raw_log', '') or event.get('message', '')
        if raw_message:
            extracted.update(self._extract_from_raw(raw_message))
        
        # Step 3: Apply heuristic extraction (nested object traversal)
        extracted.update(self._heuristic_extraction(event))
        
        # Step 4: Apply custom rules
        for rule in sorted(self.custom_rules, key=lambda r: r.priority):
            if not rule.enabled:
                continue
            if rule.vendor_scope and vendor and vendor not in rule.vendor_scope:
                continue
            
            value = self._apply_rule(event, rule, raw_message)
            if value is not None:
                extracted[rule.target_field] = value
        
        # Step 5: Validate and normalize extracted values
        extracted = self._normalize_values(extracted)
        
        return extracted
    
    def _apply_canonical_mappings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Map vendor-specific field names to canonical names"""
        extracted = {}
        
        def search_nested(obj: Any, key: str) -> Any:
            """Recursively search for a key in nested dicts"""
            if isinstance(obj, dict):
                if key in obj:
                    return obj[key]
                for v in obj.values():
                    result = search_nested(v, key)
                    if result is not None:
                        return result
            elif isinstance(obj, list):
                for item in obj:
                    result = search_nested(item, key)
                    if result is not None:
                        return result
            return None
        
        for canonical_name, vendor_names in self.CANONICAL_MAPPINGS.items():
            for vendor_name in vendor_names:
                value = search_nested(event, vendor_name)
                if value is not None:
                    extracted[canonical_name] = value
                    break
        
        return extracted
    
    def _extract_from_raw(self, raw_message: str) -> Dict[str, Any]:
        """Extract fields from raw message using regex patterns"""
        extracted = {}
        
        # Extract IPs
        ipv4_matches = self._compiled_patterns['ipv4'].findall(raw_message)
        if ipv4_matches:
            # First IP is often source, last is often destination
            if len(ipv4_matches) >= 2:
                extracted['source.ip'] = ipv4_matches[0]
                extracted['destination.ip'] = ipv4_matches[-1]
            else:
                extracted['network.ip'] = ipv4_matches[0]
        
        # Extract hashes
        sha256_matches = self._compiled_patterns['sha256'].findall(raw_message)
        if sha256_matches:
            extracted['file.hash.sha256'] = sha256_matches[0]
        
        md5_matches = self._compiled_patterns['md5'].findall(raw_message)
        if md5_matches:
            extracted['file.hash.md5'] = md5_matches[0]
        
        # Extract emails
        email_matches = self._compiled_patterns['email'].findall(raw_message)
        if email_matches:
            extracted['user.email'] = email_matches[0]
        
        # Extract URLs
        url_matches = self._compiled_patterns['url'].findall(raw_message)
        if url_matches:
            extracted['url.full'] = url_matches[0]
        
        # Extract domains
        domain_matches = self._compiled_patterns['domain'].findall(raw_message)
        if domain_matches:
            # Filter out common TLDs that might be false positives
            valid_domains = [d for d in domain_matches if not d.endswith(('.exe', '.dll', '.sys'))]
            if valid_domains:
                extracted['url.domain'] = valid_domains[0]
        
        # Extract CVEs
        cve_matches = self._compiled_patterns['cve'].findall(raw_message)
        if cve_matches:
            extracted['vulnerability.id'] = cve_matches
        
        # Extract MITRE technique IDs
        mitre_matches = self._compiled_patterns['mitre_technique'].findall(raw_message)
        if mitre_matches:
            extracted['threat.technique.id'] = mitre_matches[0]
        
        return extracted
    
    def _heuristic_extraction(self, event: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """
        Heuristically extract fields by traversing nested objects
        and applying smart field detection
        """
        extracted = {}
        
        def process_value(key: str, value: Any, path: str):
            """Process a single value and determine its type"""
            full_path = f"{path}.{key}" if path else key
            
            if isinstance(value, dict):
                # Recurse into nested objects
                nested = self._heuristic_extraction(value, full_path)
                extracted.update(nested)
            elif isinstance(value, list):
                # Handle lists
                if value and all(isinstance(v, str) for v in value):
                    extracted[full_path] = value
            elif isinstance(value, str):
                # Detect value type heuristically
                detected_type = self._detect_value_type(value)
                if detected_type:
                    canonical = self._map_to_canonical(full_path, detected_type)
                    if canonical:
                        extracted[canonical] = value
                    else:
                        extracted[full_path] = value
            elif isinstance(value, (int, float, bool)):
                extracted[full_path] = value
        
        for key, value in event.items():
            if key in ('raw_message', 'raw_log', 'message', '_raw'):
                continue  # Skip raw fields - handled separately
            process_value(key, value, prefix)
        
        return extracted
    
    def _detect_value_type(self, value: str) -> Optional[str]:
        """Detect the type of a string value"""
        if not value or len(value) < 3:
            return None
        
        # Check for IP address
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            pass
        
        # Check for email
        if self._compiled_patterns['email'].match(value):
            return 'email'
        
        # Check for URL
        if value.startswith(('http://', 'https://')):
            return 'url'
        
        # Check for hash
        if len(value) == 64 and self._compiled_patterns['sha256'].match(value):
            return 'sha256'
        if len(value) == 32 and self._compiled_patterns['md5'].match(value):
            return 'md5'
        if len(value) == 40 and self._compiled_patterns['sha1'].match(value):
            return 'sha1'
        
        # Check for UUID
        if self._compiled_patterns['uuid'].match(value):
            return 'uuid'
        
        # Check for file path
        if self._compiled_patterns['windows_path'].match(value) or self._compiled_patterns['unix_path'].match(value):
            return 'path'
        
        return None
    
    def _map_to_canonical(self, path: str, value_type: str) -> Optional[str]:
        """Map a detected value type to its canonical field name"""
        type_mappings = {
            'ip': 'network.ip',
            'email': 'user.email',
            'url': 'url.full',
            'sha256': 'file.hash.sha256',
            'md5': 'file.hash.md5',
            'sha1': 'file.hash.sha1',
            'uuid': 'event.id',
            'path': 'file.path',
        }
        return type_mappings.get(value_type)
    
    def _apply_rule(self, event: Dict[str, Any], rule: ExtractionRule, raw_message: str) -> Optional[Any]:
        """Apply a single extraction rule"""
        try:
            if rule.method == ExtractionMethod.REGEX:
                # Get source text
                if rule.source_field == 'raw_message':
                    source_text = raw_message
                else:
                    source_text = str(self._get_nested_value(event, rule.source_field) or '')
                
                if not source_text:
                    return rule.default_value
                
                pattern = self._compiled_patterns.get(rule.id)
                if not pattern:
                    return rule.default_value
                
                if rule.multi_value:
                    matches = pattern.findall(source_text)
                    return matches if matches else rule.default_value
                else:
                    match = pattern.search(source_text)
                    if match:
                        # Return first group if exists, else full match
                        return match.group(1) if match.groups() else match.group(0)
                    return rule.default_value
            
            elif rule.method == ExtractionMethod.JSON_PATH:
                value = self._get_nested_value(event, rule.pattern)
                if value is not None:
                    # Apply transform if specified
                    if rule.transform:
                        value = self._apply_transform(value, rule.transform)
                return value if value is not None else rule.default_value
            
            elif rule.method == ExtractionMethod.MAPPING:
                # Direct field mapping with optional transform
                value = self._get_nested_value(event, rule.source_field)
                if value is not None and rule.transform:
                    value = self._apply_transform(value, rule.transform)
                return value if value is not None else rule.default_value
        
        except Exception as e:
            logger.error(f"Error applying rule {rule.id}: {e}")
            return rule.default_value
    
    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get a value from a nested dict using dot notation or JSON path"""
        if path.startswith('$.'):
            path = path[2:]  # Remove $. prefix
        
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def _apply_transform(self, value: Any, transform: str) -> Any:
        """Apply a transformation to a value"""
        if isinstance(value, str):
            if transform == 'lowercase':
                return value.lower()
            elif transform == 'uppercase':
                return value.upper()
            elif transform == 'trim':
                return value.strip()
            elif transform.startswith('regex:'):
                # Extract using regex: regex:pattern:group
                parts = transform.split(':')
                if len(parts) >= 2:
                    pattern = parts[1]
                    group = int(parts[2]) if len(parts) > 2 else 0
                    match = re.search(pattern, value)
                    if match:
                        return match.group(group)
        return value
    
    def _normalize_values(self, extracted: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and validate extracted values"""
        normalized = {}
        
        for key, value in extracted.items():
            if value is None or value == '':
                continue
            
            # Normalize boolean strings
            if isinstance(value, str) and value.lower() in ('true', 'false', 'yes', 'no', '1', '0'):
                value = value.lower() in ('true', 'yes', '1')
            
            # Normalize severity
            if 'severity' in key and isinstance(value, str):
                severity_map = {
                    'info': 'low', 'informational': 'low', '1': 'low',
                    'low': 'low', '2': 'low',
                    'medium': 'medium', 'med': 'medium', '3': 'medium',
                    'high': 'high', '4': 'high',
                    'critical': 'critical', 'crit': 'critical', '5': 'critical'
                }
                value = severity_map.get(value.lower(), value)
            
            normalized[key] = value
        
        return normalized
    
    def test_pattern(self, pattern: str, sample_text: str) -> Dict[str, Any]:
        """Test a regex pattern against sample text"""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            matches = compiled.findall(sample_text)
            groups = []
            for match in compiled.finditer(sample_text):
                groups.append({
                    'full_match': match.group(0),
                    'groups': match.groups(),
                    'start': match.start(),
                    'end': match.end()
                })
            return {
                'valid': True,
                'matches': matches,
                'match_details': groups,
                'match_count': len(matches)
            }
        except re.error as e:
            return {
                'valid': False,
                'error': str(e),
                'matches': [],
                'match_count': 0
            }
    
    def get_builtin_patterns(self) -> Dict[str, str]:
        """Return all built-in patterns for UI display"""
        return dict(self.BUILTIN_PATTERNS)
    
    def get_rules(self) -> List[Dict]:
        """Return all custom rules"""
        return [rule.to_dict() for rule in self.custom_rules]


# Global extractor instance
field_extractor = FieldExtractor()
