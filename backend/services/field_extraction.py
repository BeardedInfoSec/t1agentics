# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Automatic Field Extraction and Mapping System
Uses AI to learn alert schemas and extract structured data
"""

import re
import json
import base64
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class FieldExtractor:
    """
    Automatically extracts and maps fields from raw alerts
    Uses pattern matching and AI learning
    """
    
    # Standard field mappings (OCSF-inspired)
    STANDARD_FIELDS = {
        'timestamp': ['time', 'timestamp', 'event_time', 'created_at', 'detected_at'],
        'severity': ['severity', 'priority', 'level', 'criticality', 'risk'],
        'source_ip': ['src_ip', 'source_ip', 'srcip', 'src_address', 'source_address'],
        'dest_ip': ['dst_ip', 'dest_ip', 'dstip', 'dst_address', 'dest_address'],
        'source_host': ['src_host', 'source_host', 'srchost', 'src_hostname'],
        'dest_host': ['dst_host', 'dest_host', 'dsthost', 'dst_hostname'],
        'username': ['user', 'username', 'account', 'user_name', 'account_name'],
        'domain': ['domain', 'domain_name', 'dns_domain'],
        'file_hash': ['hash', 'md5', 'sha1', 'sha256', 'file_hash'],
        'file_name': ['filename', 'file_name', 'file'],
        'file_path': ['filepath', 'file_path', 'path'],
        'process_name': ['process', 'process_name', 'proc_name'],
        'command_line': ['command', 'cmdline', 'command_line', 'cmd'],
        'url': ['url', 'uri', 'link'],
        'email': ['email', 'email_address', 'sender', 'recipient'],
        'port': ['port', 'dst_port', 'dest_port', 'dstport'],
        'protocol': ['protocol', 'proto'],
        'action': ['action', 'event_type', 'activity'],
        'result': ['result', 'status', 'outcome'],
    }
    
    # IOC patterns
    IOC_PATTERNS = {
        'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
    }
    
    # Entity patterns
    ENTITY_PATTERNS = {
        # Hostnames (Windows/Linux style)
        'hostname': re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\b'),
        # Usernames (various formats)
        'username': re.compile(r'\b(?:user|account|username)[:=\s]+([a-zA-Z0-9._-]+)\b', re.IGNORECASE),
        # Windows usernames (DOMAIN\user)
        'domain_user': re.compile(r'\b([A-Z0-9]+)\\([a-zA-Z0-9._-]+)\b'),
        # Email addresses (also captures username)
        'user_email': re.compile(r'\b([A-Za-z0-9._%+-]+)@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        # Process names
        'process': re.compile(r'\b([a-zA-Z0-9_-]+\.exe|[a-zA-Z0-9_-]+\.dll)\b', re.IGNORECASE),
        # File paths (Windows)
        'file_path_win': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', re.IGNORECASE),
        # File paths (Linux)
        'file_path_linux': re.compile(r'/(?:[^/\0\s]+/)*[^/\0\s]*'),
    }

    # PII patterns - for sensitive data detection
    PII_PATTERNS = {
        # Credit card numbers (various formats with spaces, dashes, or continuous)
        # Supports major card types: Visa, Mastercard, Amex, Discover, etc.
        'credit_card': re.compile(
            r'\b(?:'
            r'4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|'    # Visa (16 digits)
            r'5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|'  # Mastercard
            r'3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|'              # Amex (15 digits)
            r'6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|'  # Discover
            r'3(?:0[0-5]|[68][0-9])[0-9][\s-]?[0-9]{6}[\s-]?[0-9]{4}|'  # Diners Club
            r'(?:2131|1800|35[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}'  # JCB
            r')\b'
        ),
        # SSN (US Social Security Numbers)
        'ssn': re.compile(r'\b(?!000|666|9\d{2})\d{3}[\s-]?(?!00)\d{2}[\s-]?(?!0000)\d{4}\b'),
        # US Phone numbers
        'phone_us': re.compile(r'\b(?:\+1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b'),
        # AWS Access Key IDs
        'aws_key': re.compile(r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'),
        # Generic API keys (long alphanumeric strings)
        'api_key_generic': re.compile(r'\b(?:api[_-]?key|apikey|api_secret|secret_key)[\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?\b', re.IGNORECASE),
    }

    # Credit card type prefixes (IIN/BIN ranges)
    CARD_TYPE_PREFIXES = {
        'visa': [(4,)],
        'mastercard': [(51, 52, 53, 54, 55), range(2221, 2721)],
        'amex': [(34, 37)],
        'discover': [(6011,), range(644, 650), (65,)],
        'diners': [(300, 301, 302, 303, 304, 305), (36,), (38,)],
        'jcb': [(2131, 1800), range(3528, 3590)],
    }

    # Base64 pattern - matches strings that look like base64 (min 16 chars to catch shorter encoded commands)
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

    # PowerShell encoded command pattern - specifically looks for -enc/-encodedcommand followed by base64
    # This catches even short base64 strings when in PowerShell context
    POWERSHELL_ENC_PATTERN = re.compile(
        r'(?:powershell|pwsh)(?:\.exe)?.*?(?:-enc(?:odedcommand)?|-e|-ec)\s+([A-Za-z0-9+/]{4,}={0,2})',
        re.IGNORECASE
    )

    # Defanged URL/domain patterns for reversal
    DEFANG_PATTERNS = {
        # Protocol defanging: hxxp, hXXp, etc.
        'protocol': [
            (re.compile(r'hxxps?://', re.IGNORECASE), lambda m: m.group().replace('xx', 'tt').replace('XX', 'tt')),
            (re.compile(r'h\[tt\]ps?://', re.IGNORECASE), lambda m: m.group().replace('[tt]', 'tt')),
            (re.compile(r'h__ps?://', re.IGNORECASE), lambda m: m.group().replace('__', 'tt')),
        ],
        # Domain defanging: [.] or (.) or {.}
        'dots': [
            (re.compile(r'\[\.\]'), '.'),
            (re.compile(r'\(\.\)'), '.'),
            (re.compile(r'\{\.\}'), '.'),
            (re.compile(r'\[dot\]', re.IGNORECASE), '.'),
            (re.compile(r'\(dot\)', re.IGNORECASE), '.'),
        ],
        # @ symbol defanging
        'at': [
            (re.compile(r'\[@\]'), '@'),
            (re.compile(r'\[at\]', re.IGNORECASE), '@'),
            (re.compile(r'\(at\)', re.IGNORECASE), '@'),
        ],
    }
    
    def __init__(self):
        self.learned_mappings = {}  # Source → Standard field mappings
    
    def extract_fields(self, raw_alert: Dict[str, Any], source: str = "unknown") -> Dict[str, Any]:
        """
        Extract and normalize fields from raw alert
        
        Args:
            raw_alert: Raw alert dictionary
            source: Alert source (splunk, crowdstrike, etc.)
            
        Returns:
            Normalized field dictionary
        """
        normalized = {}
        
        # Flatten nested structures
        flat_alert = self._flatten_dict(raw_alert)
        
        # Apply learned mappings first
        if source in self.learned_mappings:
            for src_field, std_field in self.learned_mappings[source].items():
                if src_field in flat_alert:
                    normalized[std_field] = flat_alert[src_field]
        
        # Apply standard field mappings
        for std_field, variants in self.STANDARD_FIELDS.items():
            if std_field not in normalized:  # Don't override learned mappings
                for variant in variants:
                    for key, value in flat_alert.items():
                        if variant in key.lower():
                            normalized[std_field] = value
                            break
                    if std_field in normalized:
                        break
        
        # Store original raw data
        normalized['_raw'] = raw_alert
        normalized['_source'] = source
        
        return normalized
    
    def extract_iocs(self, alert: Dict[str, Any], include_private_ips: bool = True) -> Dict[str, List[str]]:
        """
        Extract IOCs from alert using pattern matching

        Args:
            alert: Raw alert dictionary
            include_private_ips: If True, include private IPs in 'private_ips' key for visibility

        Returns:
            Dict mapping IOC type to list of values
            - 'ips': Public/external IPs (enrichable)
            - 'private_ips': Internal IPs like 192.168.x.x (visible but not enrichable)
        """
        iocs = {
            'ips': set(),
            'private_ips': set(),  # Internal IPs - visible but not enrichable
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'hashes': set(),
            'cves': set()
        }

        # Convert alert to searchable text
        alert_text = json.dumps(alert, default=str)

        # Extract IPs - separate public from private
        ipv4_matches = self.IOC_PATTERNS['ipv4'].findall(alert_text)
        ipv6_matches = self.IOC_PATTERNS['ipv6'].findall(alert_text)
        for ip in ipv4_matches + ipv6_matches:
            # Filter invalid IPs (leading zeros like 01.24.04.57)
            if '.' in ip and not self._is_valid_ipv4(ip):
                continue
            if self._is_private_ip(ip):
                # Keep private IPs for investigation visibility (C2 to internal hosts)
                if include_private_ips:
                    iocs['private_ips'].add(ip)
            else:
                iocs['ips'].add(ip)
        
        # Extract domains (excluding IPs and false positives)
        domain_matches = self.IOC_PATTERNS['domain'].findall(alert_text)
        for domain in domain_matches:
            # Filter out common false positives
            if self._is_valid_domain(domain):
                iocs['domains'].add(domain.lower())
        
        # Extract URLs and clean them
        url_matches = self.IOC_PATTERNS['url'].findall(alert_text)
        for url in url_matches:
            # Clean trailing characters that shouldn't be part of URLs
            cleaned_url = self._clean_url(url)
            if cleaned_url:
                iocs['urls'].add(cleaned_url)
        
        # Extract emails
        email_matches = self.IOC_PATTERNS['email'].findall(alert_text)
        iocs['emails'].update(email_matches)
        
        # Extract hashes
        md5_matches = self.IOC_PATTERNS['md5'].findall(alert_text)
        sha1_matches = self.IOC_PATTERNS['sha1'].findall(alert_text)
        sha256_matches = self.IOC_PATTERNS['sha256'].findall(alert_text)
        iocs['hashes'].update(md5_matches + sha1_matches + sha256_matches)
        
        # Extract CVEs
        cve_matches = self.IOC_PATTERNS['cve'].findall(alert_text)
        iocs['cves'].update(cve_matches)
        
        # Convert sets to lists
        return {k: list(v) for k, v in iocs.items()}
    
    def extract_entities(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract assets, users, and entities from alert
        
        Returns:
            Dict mapping entity type to list of values
        """
        entities = {
            'hostnames': set(),
            'users': set(),
            'processes': set(),
            'file_paths': set(),
            'assets': set()  # Combined view of hostnames + IPs
        }
        
        # Convert alert to searchable text
        alert_text = json.dumps(alert, default=str)
        
        # Extract hostnames
        # First try standard fields
        for field in ['hostname', 'host', 'computer_name', 'device_name', 
                      'src_host', 'dst_host', 'source_host', 'dest_host']:
            if field in alert:
                value = alert[field]
                if isinstance(value, str) and value:
                    entities['hostnames'].add(value.lower())
        
        # Extract usernames
        # From standard fields
        for field in ['user', 'username', 'account', 'user_name', 
                      'src_user', 'dst_user', 'source_user', 'dest_user']:
            if field in alert:
                value = alert[field]
                if isinstance(value, str) and value:
                    entities['users'].add(value.lower())
        
        # Extract from DOMAIN\user format
        domain_user_matches = self.ENTITY_PATTERNS['domain_user'].findall(alert_text)
        for domain, user in domain_user_matches:
            entities['users'].add(f"{domain}\\{user}".lower())
        
        # Extract from email addresses
        email_matches = self.ENTITY_PATTERNS['user_email'].findall(alert_text)
        for username in email_matches:
            entities['users'].add(username.lower())
        
        # Extract process names
        process_matches = self.ENTITY_PATTERNS['process'].findall(alert_text)
        for process in process_matches:
            # Filter out common false positives
            if len(process) > 3 and not process.lower() in ['com', 'exe', 'dll', 'sys']:
                entities['processes'].add(process.lower())
        
        # Extract file paths
        file_path_win = self.ENTITY_PATTERNS['file_path_win'].findall(alert_text)
        file_path_linux = self.ENTITY_PATTERNS['file_path_linux'].findall(alert_text)
        for path in file_path_win + file_path_linux:
            # Filter out very short paths
            if len(path) > 5:
                entities['file_paths'].add(path)
        
        # Build combined assets list (hostnames + IPs from alert)
        # This gives a unified view of all affected systems
        entities['assets'] = entities['hostnames'].copy()
        
        # Add IPs as assets too
        for field in ['ip', 'ip_address', 'src_ip', 'dst_ip', 'source_ip', 'dest_ip']:
            if field in alert:
                value = alert[field]
                if isinstance(value, str) and value:
                    entities['assets'].add(value)
        
        # Convert sets to lists
        return {k: list(v) for k, v in entities.items()}

    def luhn_checksum(self, card_number: str) -> bool:
        """
        Validate a credit card number using the Luhn algorithm (Mod 10).

        The Luhn algorithm works as follows:
        1. Starting from the rightmost digit (check digit), double every second digit
        2. If doubling results in a number > 9, subtract 9
        3. Sum all digits
        4. If the total modulo 10 equals 0, the number is valid

        Args:
            card_number: Credit card number (may contain spaces or dashes)

        Returns:
            True if the card number passes Luhn validation
        """
        # Remove spaces and dashes
        digits = card_number.replace(' ', '').replace('-', '')

        # Must be all digits
        if not digits.isdigit():
            return False

        # Convert to list of integers
        digits = [int(d) for d in digits]

        # Reverse for easier processing
        digits = digits[::-1]

        # Double every second digit (index 1, 3, 5, etc. in reversed list)
        total = 0
        for i, digit in enumerate(digits):
            if i % 2 == 1:
                doubled = digit * 2
                # If > 9, subtract 9 (equivalent to summing the digits)
                if doubled > 9:
                    doubled -= 9
                total += doubled
            else:
                total += digit

        # Valid if total is divisible by 10
        return total % 10 == 0

    def identify_card_type(self, card_number: str) -> Optional[str]:
        """
        Identify the card type based on the IIN/BIN prefix.

        Args:
            card_number: Credit card number

        Returns:
            Card type name or None if unknown
        """
        digits = card_number.replace(' ', '').replace('-', '')

        if not digits.isdigit():
            return None

        # Check each card type
        for card_type, prefix_groups in self.CARD_TYPE_PREFIXES.items():
            for prefix_group in prefix_groups:
                if isinstance(prefix_group, range):
                    # Check range of prefixes
                    for prefix_len in [4, 3, 2, 1]:
                        if len(digits) >= prefix_len:
                            prefix_val = int(digits[:prefix_len])
                            if prefix_val in prefix_group:
                                return card_type
                elif isinstance(prefix_group, tuple):
                    # Check tuple of specific prefixes
                    for prefix in prefix_group:
                        prefix_str = str(prefix)
                        if digits.startswith(prefix_str):
                            return card_type

        return 'unknown'

    def extract_pii(self, alert: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract PII (Personally Identifiable Information) from alert.
        Uses Luhn algorithm to validate credit card numbers.

        Returns:
            Dict mapping PII type to list of findings with details
        """
        pii = {
            'credit_cards': [],
            'ssns': [],
            'phone_numbers': [],
            'aws_keys': [],
            'api_keys': [],
        }

        # Convert alert to searchable text
        alert_text = json.dumps(alert, default=str)

        # Extract credit card numbers with Luhn validation
        cc_matches = self.PII_PATTERNS['credit_card'].findall(alert_text)
        seen_cards = set()
        for match in cc_matches:
            # Normalize the card number
            normalized = match.replace(' ', '').replace('-', '')

            # Skip duplicates
            if normalized in seen_cards:
                continue

            # Validate with Luhn algorithm
            if self.luhn_checksum(normalized):
                card_type = self.identify_card_type(normalized)
                # Mask the card number (show first 4 and last 4 digits)
                masked = normalized[:4] + '*' * (len(normalized) - 8) + normalized[-4:]

                pii['credit_cards'].append({
                    'masked': masked,
                    'card_type': card_type,
                    'original_format': match,
                    'luhn_valid': True,
                    'length': len(normalized)
                })
                seen_cards.add(normalized)

        # Extract SSNs
        ssn_matches = self.PII_PATTERNS['ssn'].findall(alert_text)
        seen_ssns = set()
        for match in ssn_matches:
            normalized = match.replace(' ', '').replace('-', '')
            if normalized not in seen_ssns:
                # Mask SSN (show last 4 digits)
                masked = '***-**-' + normalized[-4:]
                pii['ssns'].append({
                    'masked': masked,
                    'original_format': match
                })
                seen_ssns.add(normalized)

        # Extract AWS keys
        aws_matches = self.PII_PATTERNS['aws_key'].findall(alert_text)
        for match in aws_matches:
            # Mask key (show first 4 chars)
            masked = match[:4] + '*' * (len(match) - 4)
            pii['aws_keys'].append({
                'masked': masked,
                'key_type': 'AWS Access Key ID'
            })

        # Extract generic API keys
        api_matches = self.PII_PATTERNS['api_key_generic'].findall(alert_text)
        for match in api_matches:
            # Match is the captured group (the key value)
            if len(match) >= 20:
                masked = match[:4] + '*' * (len(match) - 8) + match[-4:]
                pii['api_keys'].append({
                    'masked': masked,
                    'length': len(match)
                })

        # Filter out empty categories
        return {k: v for k, v in pii.items() if v}

    def extract_all(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract everything: fields, IOCs, entities, and decoded content.

        Returns:
            Complete extraction with all data including:
            - normalized_fields: Standard field mappings
            - iocs: Extracted IOCs (IPs, domains, hashes, etc.)
            - entities: Users, hosts, processes
            - decoded_content: Base64 decoded strings and their IOCs
            - defanged_iocs: IOCs extracted from defanged URLs/domains
        """
        # Convert alert to text for decoding operations
        alert_text = json.dumps(alert, default=str)

        # Extract standard IOCs first
        iocs = self.extract_iocs(alert)

        # Decode base64 strings and extract IOCs from them
        decoded_content = []
        decoded_iocs = {
            'ips': set(),
            'private_ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'hashes': set(),
        }

        base64_results = self.decode_base64_strings(alert_text)
        for original, decoded, context in base64_results:
            decoded_content.append({
                'encoded': original[:50] + '...' if len(original) > 50 else original,
                'decoded': decoded[:500] + '...' if len(decoded) > 500 else decoded,
                'full_decoded': decoded,
                'context': context,  # 'powershell' or 'generic'
                'human_readable': f"Decoded {context} command: {decoded}" if context == 'powershell' else f"Decoded content: {decoded}"
            })

            # Extract IOCs from decoded content
            decoded_iocs_from_text = self.extract_iocs({'decoded': decoded})
            for ioc_type, values in decoded_iocs_from_text.items():
                if ioc_type in decoded_iocs:
                    decoded_iocs[ioc_type].update(values)

        # Extract defanged IOCs
        defanged_results = self.extract_defanged_iocs(alert_text)

        # Merge defanged IOCs into main IOCs
        for url in defanged_results.get('urls', []):
            if url not in iocs['urls']:
                iocs['urls'].append(url)
        for domain in defanged_results.get('domains', []):
            if domain not in iocs['domains']:
                iocs['domains'].append(domain)
        for email in defanged_results.get('emails', []):
            if email not in iocs['emails']:
                iocs['emails'].append(email)

        # Extract PII (credit cards with Luhn validation, SSNs, etc.)
        pii = self.extract_pii(alert)

        return {
            'normalized_fields': self.extract_fields(alert),
            'iocs': iocs,
            'entities': self.extract_entities(alert),
            'pii': pii,  # Credit cards (Luhn-validated), SSNs, API keys
            'decoded_content': decoded_content,
            'decoded_iocs': {k: list(v) for k, v in decoded_iocs.items()},
            'defanged_iocs': defanged_results,
            'extraction_timestamp': datetime.utcnow().isoformat()
        }
    
    def learn_mapping(self, source: str, sample_alerts: List[Dict[str, Any]]):
        """
        Learn field mappings from sample alerts using AI
        
        Args:
            source: Alert source identifier
            sample_alerts: List of sample alerts to learn from
        """
        # TODO: Use Claude API to learn mappings
        # For now, use heuristic approach
        
        field_frequencies = {}
        
        for alert in sample_alerts:
            flat = self._flatten_dict(alert)
            for key in flat.keys():
                if key not in field_frequencies:
                    field_frequencies[key] = 0
                field_frequencies[key] += 1
        
        # Map to standard fields based on name similarity
        mappings = {}
        for src_field in field_frequencies.keys():
            best_match = None
            best_score = 0
            
            for std_field, variants in self.STANDARD_FIELDS.items():
                for variant in variants:
                    # Simple similarity: check if variant is in source field
                    if variant in src_field.lower():
                        score = len(variant) / len(src_field)
                        if score > best_score:
                            best_score = score
                            best_match = std_field
            
            if best_match and best_score > 0.5:
                mappings[src_field] = best_match
        
        self.learned_mappings[source] = mappings
        logger.info(f"Learned {len(mappings)} field mappings for source: {source}")
        
        return mappings
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            octets = [int(x) for x in ip.split('.')]
            # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:  # Localhost
                return True
            return False
        except:
            return False

    def _is_valid_ipv4(self, ip: str) -> bool:
        """
        Validate IPv4 address format.
        Rejects IPs with leading zeros in octets (e.g., 01.24.04.57)
        and ensures each octet is in valid range (0-255).
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                # Reject leading zeros (except '0' itself)
                if len(part) > 1 and part.startswith('0'):
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate that a string looks like a valid domain.
        Filters out filenames, Windows paths, hostnames, and other false positives.
        """
        if not domain or not isinstance(domain, str):
            return False

        # Must contain at least one dot
        if '.' not in domain:
            return False

        domain_lower = domain.lower()

        # Reject if it's just numbers (IPs handled separately)
        if domain.replace('.', '').isdigit():
            return False

        # Reject file extensions - these are NOT domains
        file_extensions = [
            '.exe', '.dll', '.sys', '.msi', '.bat', '.ps1', '.vbs', '.cmd',
            '.tmp', '.log', '.txt', '.json', '.xml', '.cfg', '.ini', '.dat',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.js', '.css', '.html', '.htm', '.php', '.py', '.rb', '.java',
        ]
        for ext in file_extensions:
            if domain_lower.endswith(ext):
                return False

        # Reject Windows-style paths and UNC paths
        if '\\' in domain or domain.startswith('//'):
            return False

        # Reject if starts with invalid chars
        if domain.startswith('-') or domain.startswith('.') or domain.startswith('_'):
            return False

        # Reject single-letter TLDs (not valid)
        parts = domain.split('.')
        if len(parts[-1]) < 2:
            return False

        # Reject if TLD looks like a file extension without being one
        last_part = parts[-1].lower()
        suspicious_tlds = ['exe', 'dll', 'tmp', 'log', 'bak', 'old', 'new', 'dat']
        if last_part in suspicious_tlds:
            return False

        # Reject short hostnames that look like machine names (e.g., "user.pc", "app.server")
        # Valid domains have TLDs >= 2 chars and typically have recognizable patterns
        common_tlds = [
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'io', 'co', 'me', 'us', 'uk', 'de', 'fr', 'jp', 'cn', 'ru', 'br',
            'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum',
            'app', 'dev', 'cloud', 'online', 'site', 'store', 'tech', 'xyz'
        ]
        # If TLD is not recognized and domain has only 2 parts, be suspicious
        if len(parts) == 2 and last_part not in common_tlds and len(last_part) <= 4:
            return False

        # Reject obvious non-domain patterns
        non_domain_patterns = [
            'localhost', 'undefined', 'null', 'none', 'unknown',
            'administrator', 'system', 'user', 'admin', 'guest',
        ]
        if domain_lower in non_domain_patterns:
            return False

        return True

    def _clean_url(self, url: str) -> Optional[str]:
        """
        Clean a URL by removing trailing characters that shouldn't be part of it.

        Args:
            url: Raw URL string

        Returns:
            Cleaned URL or None if invalid
        """
        if not url:
            return None

        # Remove trailing punctuation and quotes that often get captured
        trailing_chars = "')\">,;]}"
        cleaned = url.rstrip(trailing_chars)

        # Remove trailing single quote followed by paren (common in code)
        while cleaned.endswith("')") or cleaned.endswith('")'):
            cleaned = cleaned[:-2]

        # Validate it still looks like a URL
        if cleaned.startswith('http://') or cleaned.startswith('https://'):
            return cleaned

        return None

    def decode_base64_strings(self, text: str) -> List[Tuple[str, str, str]]:
        """
        Find and decode base64 encoded strings in text.

        Args:
            text: Text to search for base64 strings

        Returns:
            List of tuples: (original_base64, decoded_content, context)
            context is 'powershell' if found in PowerShell -enc, otherwise 'generic'
        """
        decoded_results = []
        seen_b64 = set()  # Track what we've already decoded

        # First, specifically look for PowerShell encoded commands (even short ones)
        ps_matches = self.POWERSHELL_ENC_PATTERN.findall(text)
        for match in ps_matches:
            if match in seen_b64:
                continue
            decoded = self._try_decode_base64(match)
            if decoded:
                decoded_results.append((match, decoded, 'powershell'))
                seen_b64.add(match)

        # Then find other potential base64 strings
        matches = self.BASE64_PATTERN.findall(text)

        for match in matches:
            if match in seen_b64:
                continue
            # Skip if too short or looks like a hash
            if len(match) < 20:
                continue
            # Skip if it's exactly 32, 40, or 64 chars AND looks like a hex hash
            # Base64 uses +/= which hex hashes don't have
            if len(match) in (32, 40, 64):
                # Check if it's all hex characters (hashes are hex-only)
                is_hex = all(c in '0123456789abcdefABCDEF' for c in match)
                if is_hex:
                    continue

            decoded = self._try_decode_base64(match)
            if decoded:
                decoded_results.append((match, decoded, 'generic'))
                seen_b64.add(match)

        return decoded_results

    def _try_decode_base64(self, encoded: str) -> Optional[str]:
        """
        Try to decode a base64 string with various encodings.

        Args:
            encoded: Potential base64 string

        Returns:
            Decoded string or None if decoding fails
        """
        # Add padding if needed
        padding_needed = len(encoded) % 4
        if padding_needed:
            encoded += '=' * (4 - padding_needed)

        try:
            decoded_bytes = base64.b64decode(encoded)
        except Exception:
            return None

        # Track best result
        best_decoded = None
        best_score = 0

        # Try UTF-8 first (most common for regular base64)
        try:
            decoded = decoded_bytes.decode('utf-8')
            score = self._text_quality_score(decoded)
            if score > best_score:
                best_score = score
                best_decoded = decoded
        except:
            pass

        # Try UTF-16LE (PowerShell -enc uses this)
        # Only try if length is even (UTF-16 requires pairs)
        if len(decoded_bytes) % 2 == 0:
            try:
                decoded = decoded_bytes.decode('utf-16-le').strip('\x00')
                score = self._text_quality_score(decoded)
                if score > best_score:
                    best_score = score
                    best_decoded = decoded
            except:
                pass

        # Try ASCII
        try:
            decoded = decoded_bytes.decode('ascii')
            score = self._text_quality_score(decoded)
            if score > best_score:
                best_score = score
                best_decoded = decoded
        except:
            pass

        # Only return if we found something readable (score > 0.5)
        if best_decoded and best_score > 0.5:
            return best_decoded

        return None

    def _text_quality_score(self, text: str) -> float:
        """
        Score text quality - higher is better (more readable).

        Args:
            text: Decoded text to score

        Returns:
            Score from 0.0 to 1.0
        """
        if not text or len(text) < 3:
            return 0.0

        # Count ASCII printable characters (most readable)
        ascii_printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')

        # Penalize control characters and high unicode
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\n\r\t')
        high_unicode = sum(1 for c in text if ord(c) > 255)

        # Calculate base ratio
        ratio = ascii_printable / len(text)

        # Penalize control chars heavily
        ratio -= (control_chars / len(text)) * 2

        # Penalize high unicode (often sign of wrong encoding)
        ratio -= (high_unicode / len(text)) * 1.5

        return max(0.0, min(1.0, ratio))

    def _is_readable_text(self, text: str) -> bool:
        """
        Check if decoded text looks like readable content.

        Args:
            text: Decoded text to check

        Returns:
            True if it appears to be readable text
        """
        if not text or len(text) < 3:
            return False

        # Count printable characters
        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        ratio = printable_count / len(text)

        # At least 70% should be printable
        return ratio > 0.7

    def refang_text(self, text: str) -> str:
        """
        Convert defanged URLs/domains back to their original form.

        Args:
            text: Text containing defanged IOCs

        Returns:
            Text with defanged IOCs restored
        """
        result = text

        # Apply protocol defanging reversals
        for pattern, replacement in self.DEFANG_PATTERNS['protocol']:
            if callable(replacement):
                result = pattern.sub(replacement, result)
            else:
                result = pattern.sub(replacement, result)

        # Apply dot defanging reversals
        for pattern, replacement in self.DEFANG_PATTERNS['dots']:
            result = pattern.sub(replacement, result)

        # Apply @ symbol reversals
        for pattern, replacement in self.DEFANG_PATTERNS['at']:
            result = pattern.sub(replacement, result)

        return result

    def extract_defanged_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from text that contains defanged URLs/domains.

        Args:
            text: Text potentially containing defanged IOCs

        Returns:
            Dict of IOC types to lists of refanged values
        """
        # First, refang the text
        refanged_text = self.refang_text(text)

        # Then extract IOCs from the refanged text
        iocs = {
            'urls': [],
            'domains': [],
            'emails': [],
        }

        # Extract URLs
        url_matches = self.IOC_PATTERNS['url'].findall(refanged_text)
        iocs['urls'] = list(set(url_matches))

        # Extract domains
        domain_matches = self.IOC_PATTERNS['domain'].findall(refanged_text)
        for domain in domain_matches:
            if self._is_valid_domain(domain):
                iocs['domains'].append(domain.lower())
        iocs['domains'] = list(set(iocs['domains']))

        # Extract emails
        email_matches = self.IOC_PATTERNS['email'].findall(refanged_text)
        iocs['emails'] = list(set(email_matches))

        return iocs


class PrivacyFilter:
    """
    Protects sensitive data from being enriched or sent externally
    """
    
    # Default sensitive field patterns
    SENSITIVE_PATTERNS = [
        # Credentials
        r'password', r'passwd', r'pwd', r'secret', r'token', r'api_key',
        # PII
        r'ssn', r'social_security', r'credit_card', r'cc_number',
        r'drivers_license', r'passport', r'dob', r'date_of_birth',
        # Healthcare
        r'medical', r'health', r'diagnosis', r'medication',
        # Financial
        r'bank_account', r'routing_number', r'account_number',
    ]
    
    def __init__(self):
        self.exception_lists = {
            'internal_ips': set(),      # IPs that should not be enriched
            'internal_domains': set(),  # Domains that should not be enriched
            'internal_users': set(),    # Usernames to protect
            'sensitive_fields': set(self.SENSITIVE_PATTERNS)
        }
    
    def add_exception(self, category: str, value: str):
        """Add item to exception list"""
        if category in self.exception_lists:
            self.exception_lists[category].add(value)
    
    def is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data"""
        field_lower = field_name.lower()
        for pattern in self.exception_lists['sensitive_fields']:
            if re.search(pattern, field_lower):
                return True
        return False
    
    def should_enrich(self, ioc_type: str, ioc_value: str) -> bool:
        """
        Determine if IOC should be sent for external enrichment
        
        Args:
            ioc_type: Type of IOC (ip, domain, hash, etc.)
            ioc_value: The IOC value
            
        Returns:
            True if safe to enrich, False if should be protected
        """
        # Check IP exceptions
        if ioc_type == 'ip':
            # Always block private IPs
            if self._is_private_ip(ioc_value):
                return False
            # Check exception list
            if ioc_value in self.exception_lists['internal_ips']:
                return False
        
        # Check domain exceptions
        if ioc_type == 'domain':
            if ioc_value in self.exception_lists['internal_domains']:
                return False
            # Check if it's an internal domain
            for internal_domain in self.exception_lists['internal_domains']:
                if ioc_value.endswith(internal_domain):
                    return False
        
        # File hashes are generally safe to enrich
        if ioc_type == 'hash':
            return True
        
        return True
    
    def filter_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove or mask sensitive fields from data
        
        Returns:
            Filtered data safe for external processing
        """
        filtered = {}
        
        for key, value in data.items():
            if self.is_sensitive_field(key):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = self.filter_sensitive_data(value)
            elif isinstance(value, list):
                filtered[key] = [
                    self.filter_sensitive_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                filtered[key] = value
        
        return filtered
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:
                return True
            return False
        except:
            return False


# Singleton instances
field_extractor = FieldExtractor()
privacy_filter = PrivacyFilter()
