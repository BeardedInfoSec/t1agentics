# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
PII Obfuscation Service for PCI Compliance

Handles detection and obfuscation of Personally Identifiable Information (PII)
to ensure compliance with PCI-DSS, GDPR, and other data protection regulations.

Obfuscated PII Types:
- Credit/Debit Card Numbers (PAN)
- Social Security Numbers (SSN)
- Email addresses
- Phone numbers
- IP addresses (optional, configurable)
- Names (when detected with confidence)
- Addresses
- Dates of Birth

Obfuscation Modes:
- MASK: Replace with asterisks (****1234)
- HASH: Replace with SHA-256 hash (for correlation)
- REDACT: Replace with [REDACTED]
- TOKENIZE: Replace with reversible token (for authorized access)
"""

import re
import hashlib
import secrets
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


class ObfuscationMode(str, Enum):
    """How to obfuscate detected PII"""
    MASK = "mask"           # Partial masking: ****1234
    HASH = "hash"           # SHA-256 hash (one-way, for correlation)
    REDACT = "redact"       # Full redaction: [REDACTED]
    TOKENIZE = "tokenize"   # Reversible token (requires key)


# Lookup used when the caller passes a stringified mode (e.g. from a
# tenant pattern row) rather than the enum.
_STR_TO_OBFUSCATION_MODE = {
    "mask": ObfuscationMode.MASK,
    "hash": ObfuscationMode.HASH,
    "redact": ObfuscationMode.REDACT,
    "tokenize": ObfuscationMode.TOKENIZE,
}


class PIIType(str, Enum):
    """Types of PII we detect and obfuscate"""
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    ADDRESS = "address"
    DOB = "dob"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    BANK_ACCOUNT = "bank_account"
    # Tenant-defined pattern matches (services/tenant_pii_patterns).
    # Carry the configured mode + label on the PIIMatch directly so the
    # obfuscator doesn't need to round-trip back to the DB.
    CUSTOM = "custom"


@dataclass
class PIIMatch:
    """A detected PII match"""
    pii_type: PIIType
    original_value: str
    obfuscated_value: str
    start_pos: int
    end_pos: int
    confidence: float = 1.0
    # Per-match mode override used by tenant-defined custom patterns;
    # built-in matches leave this None and pick up the type_modes entry.
    mode_override: Optional["ObfuscationMode"] = None
    custom_label: Optional[str] = None


@dataclass
class PIIConfig:
    """Configuration for PII obfuscation"""
    enabled: bool = True
    default_mode: ObfuscationMode = ObfuscationMode.MASK

    # Which PII types to obfuscate (PCI compliance focus)
    # NOTE: Emails and phones are NOT obfuscated - they're useful for SOC analysis
    obfuscate_types: Set[PIIType] = field(default_factory=lambda: {
        PIIType.CREDIT_CARD,      # PCI-DSS requirement
        PIIType.SSN,              # PII protection
        PIIType.BANK_ACCOUNT,     # Financial data
        PIIType.PASSPORT,         # Government ID
        PIIType.DRIVER_LICENSE,   # Government ID
    })

    # Type-specific modes (overrides default)
    type_modes: Dict[PIIType, ObfuscationMode] = field(default_factory=lambda: {
        PIIType.CREDIT_CARD: ObfuscationMode.MASK,  # Show last 4 digits: ****-****-****-1234
        PIIType.SSN: ObfuscationMode.MASK,          # Show last 4: ***-**-1234
        PIIType.BANK_ACCOUNT: ObfuscationMode.MASK, # Show last 4: ****1234
    })

    # Fields to always scan for PII (financial/identity focused)
    sensitive_fields: Set[str] = field(default_factory=lambda: {
        'ssn', 'credit_card', 'card_number', 'pan',
        'account_number', 'bank_account', 'passport', 'driver_license',
        'social_security', 'cc_number', 'cvv', 'expiry', 'pin',
        'password', 'secret', 'token', 'api_key', 'private_key'
    })

    # Fields to never scan (performance optimization)
    skip_fields: Set[str] = field(default_factory=lambda: {
        'id', 'uuid', 'timestamp', 'created_at', 'updated_at',
        'hash', 'sha256', 'md5', 'checksum', 'signature',
        # Alert/Investigation identifiers - these are UUIDs, not PII
        'alert_id', 'investigation_id', 'execution_id', 'job_id',
        'correlation_id', 'request_id', 'session_id', 'trace_id',
        'event_id', 'group_id', 'alert_group_id', 'fingerprint',
        # QA test identifiers
        'test_id', 'qa_id', 'test_case_id'
    })


class PIIDetector:
    """Detects PII in text and structured data"""

    # Regex patterns for PII detection
    PATTERNS = {
        PIIType.CREDIT_CARD: [
            # Visa: 4xxx (13 or 16 digits)
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',
            # Mastercard: 51-55 or 2221-2720 (16 digits)
            r'\b(?:5[1-5][0-9]{14}|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12})\b',
            # Amex: 34 or 37 (15 digits)
            r'\b3[47][0-9]{13}\b',
            # Discover: 6011, 65, 644-649 (16 digits)
            r'\b6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12}\b',
            # With spaces or dashes (Visa/MC format)
            r'\b4[0-9]{3}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}\b',
            r'\b5[1-5][0-9]{2}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}\b',
        ],
        PIIType.SSN: [
            # US SSN: 123-45-6789 or 123456789
            r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
        ],
        PIIType.EMAIL: [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        PIIType.PHONE: [
            # US phone numbers: (123) 456-7890, 123-456-7890, 1234567890
            r'\b(?:\+1[\s.-]?)?(?:\([0-9]{3}\)|[0-9]{3})[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b',
            # International format
            r'\b\+[1-9][0-9]{7,14}\b',
        ],
        PIIType.IP_ADDRESS: [
            # IPv4
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        ],
        PIIType.DOB: [
            # Date of birth patterns: MM/DD/YYYY, DD-MM-YYYY, etc.
            r'\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}\b',
        ],
        PIIType.PASSPORT: [
            # US passport: 9 alphanumeric characters
            r'\b[A-Z][0-9]{8}\b',
        ],
        PIIType.DRIVER_LICENSE: [
            # Generic format (varies by state/country)
            r'\b[A-Z]{1,2}[0-9]{6,8}\b',
            # Format with DL prefix: DL-XXXXXXXX
            r'\bDL-[A-Z0-9]{6,12}\b',
            # Mixed alphanumeric: A1B2C3D4E5
            r'\b[A-Z][0-9][A-Z0-9]{6,10}\b',
        ],
        PIIType.BANK_ACCOUNT: [
            # Bank account numbers (generic pattern)
            r'\b[0-9]{8,17}\b',  # Very broad - use with context
        ],
    }

    def __init__(self, config: Optional[PIIConfig] = None):
        self.config = config or PIIConfig()
        self._compiled_patterns: Dict[PIIType, List[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for performance"""
        for pii_type, patterns in self.PATTERNS.items():
            self._compiled_patterns[pii_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    # Priority order for PII types (higher priority types are checked first)
    # This ensures credit cards aren't misclassified as bank accounts
    TYPE_PRIORITY = [
        PIIType.CREDIT_CARD,  # Check first - has Luhn validation
        PIIType.SSN,
        PIIType.PASSPORT,
        PIIType.DRIVER_LICENSE,
        PIIType.PHONE,
        PIIType.EMAIL,
        PIIType.IP_ADDRESS,
        PIIType.DOB,
        PIIType.BANK_ACCOUNT,  # Check last - very broad pattern
    ]

    # UUID pattern - skip these as they're identifiers, not PII
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )

    def detect_in_text(self, text: str, types: Optional[Set[PIIType]] = None) -> List[PIIMatch]:
        """
        Detect PII in a text string.

        Args:
            text: The text to scan
            types: Optional set of PII types to look for (defaults to config)

        Returns:
            List of PIIMatch objects
        """
        if not text or not isinstance(text, str):
            return []

        # Skip UUID-formatted strings entirely - they're identifiers, not PII
        if self.UUID_PATTERN.match(text.strip()):
            return []

        types_to_check = types or self.config.obfuscate_types
        matches = []
        matched_ranges = set()  # Track (start, end) to avoid duplicates

        # Check types in priority order
        for pii_type in self.TYPE_PRIORITY:
            if pii_type not in types_to_check:
                continue
            if pii_type not in self._compiled_patterns:
                continue

            for pattern in self._compiled_patterns[pii_type]:
                for match in pattern.finditer(text):
                    # Skip if this range already matched a higher-priority type
                    match_range = (match.start(), match.end())
                    if any(self._ranges_overlap(match_range, existing) for existing in matched_ranges):
                        continue

                    # Validate the match (e.g., Luhn check for credit cards)
                    if self._validate_match(pii_type, match.group()):
                        matches.append(PIIMatch(
                            pii_type=pii_type,
                            original_value=match.group(),
                            obfuscated_value="",  # Will be filled by obfuscator
                            start_pos=match.start(),
                            end_pos=match.end(),
                            confidence=self._calculate_confidence(pii_type, match.group())
                        ))
                        matched_ranges.add(match_range)

        return matches

    def _ranges_overlap(self, range1: tuple, range2: tuple) -> bool:
        """Check if two (start, end) ranges overlap"""
        return not (range1[1] <= range2[0] or range2[1] <= range1[0])

    def _validate_match(self, pii_type: PIIType, value: str) -> bool:
        """Validate a potential PII match"""
        if pii_type == PIIType.CREDIT_CARD:
            return self._luhn_check(value)
        elif pii_type == PIIType.SSN:
            # Already validated in regex pattern
            return True
        elif pii_type == PIIType.BANK_ACCOUNT:
            # Only flag in context of known sensitive fields
            return len(value) >= 10
        return True

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        # Remove spaces and dashes
        digits = re.sub(r'[\s-]', '', card_number)
        if not digits.isdigit():
            return False

        # Luhn algorithm
        total = 0
        for i, digit in enumerate(reversed(digits)):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n

        return total % 10 == 0

    def _calculate_confidence(self, pii_type: PIIType, value: str) -> float:
        """Calculate confidence score for a PII match"""
        if pii_type == PIIType.CREDIT_CARD and self._luhn_check(value):
            return 0.99
        elif pii_type == PIIType.SSN:
            return 0.95
        elif pii_type == PIIType.EMAIL:
            return 0.99
        elif pii_type == PIIType.PHONE:
            return 0.85
        return 0.7


class PIIObfuscator:
    """Obfuscates detected PII according to configuration"""

    def __init__(self, config: Optional[PIIConfig] = None):
        self.config = config or PIIConfig()
        self.detector = PIIDetector(config)
        self._token_map: Dict[str, str] = {}  # For tokenization

    def obfuscate_text(
        self,
        text: str,
        mode: Optional[ObfuscationMode] = None,
        extra_patterns: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[str, List[PIIMatch]]:
        """
        Obfuscate PII in text.

        Args:
            extra_patterns: tenant-defined custom patterns as
                            [{'compiled': re.Pattern, 'mode': str, 'label': str}, ...]

        Returns:
            Tuple of (obfuscated_text, list of matches)
        """
        if not self.config.enabled or not text:
            return text, []

        matches = self.detector.detect_in_text(text)

        # Scan for tenant-defined custom patterns alongside the built-ins
        if extra_patterns:
            existing_ranges = {(m.start_pos, m.end_pos) for m in matches}
            for ep in extra_patterns:
                compiled = ep.get("compiled")
                if not compiled:
                    continue
                ep_mode = _STR_TO_OBFUSCATION_MODE.get(
                    (ep.get("mode") or "mask").lower(),
                    ObfuscationMode.MASK,
                )
                for m in compiled.finditer(text):
                    rng = (m.start(), m.end())
                    # Built-in matches win on overlap (Luhn-validated CC vs
                    # a permissive tenant regex shouldn't be displaced).
                    if any(self.detector._ranges_overlap(rng, ex) for ex in existing_ranges):
                        continue
                    matches.append(PIIMatch(
                        pii_type=PIIType.CUSTOM,
                        original_value=m.group(),
                        obfuscated_value="",
                        start_pos=m.start(),
                        end_pos=m.end(),
                        confidence=0.9,
                        mode_override=ep_mode,
                        custom_label=ep.get("label"),
                    ))
                    existing_ranges.add(rng)

        if not matches:
            return text, []

        # Sort matches by position (reverse order for replacement)
        matches.sort(key=lambda m: m.start_pos, reverse=True)

        result = text
        for match in matches:
            obfuscation_mode = (
                mode
                or match.mode_override
                or self.config.type_modes.get(match.pii_type, self.config.default_mode)
            )
            match.obfuscated_value = self._obfuscate_value(
                match.original_value, match.pii_type, obfuscation_mode
            )
            result = result[:match.start_pos] + match.obfuscated_value + result[match.end_pos:]

        return result, matches

    def obfuscate_dict(
        self,
        data: Dict[str, Any],
        mode: Optional[ObfuscationMode] = None,
        _path: str = "",
        extra_patterns: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[Dict[str, Any], List[PIIMatch]]:
        """
        Recursively obfuscate PII in a dictionary.

        Returns:
            Tuple of (obfuscated_dict, list of all matches)
        """
        if not self.config.enabled or not data:
            return data, []

        all_matches = []
        result = {}

        for key, value in data.items():
            current_path = f"{_path}.{key}" if _path else key

            # Skip certain fields
            if key.lower() in self.config.skip_fields:
                result[key] = value
                continue

            # Check if this is a sensitive field (always scan)
            is_sensitive = key.lower() in self.config.sensitive_fields

            if isinstance(value, str):
                if is_sensitive or len(value) > 5:  # Skip very short strings
                    obfuscated, matches = self.obfuscate_text(value, mode, extra_patterns=extra_patterns)
                    result[key] = obfuscated
                    for m in matches:
                        m.start_pos = 0  # Reset for dict context
                        m.end_pos = 0
                    all_matches.extend(matches)
                else:
                    result[key] = value

            elif isinstance(value, dict):
                obfuscated, matches = self.obfuscate_dict(value, mode, current_path, extra_patterns=extra_patterns)
                result[key] = obfuscated
                all_matches.extend(matches)

            elif isinstance(value, list):
                obfuscated_list = []
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        obfuscated, matches = self.obfuscate_dict(item, mode, f"{current_path}[{i}]", extra_patterns=extra_patterns)
                        obfuscated_list.append(obfuscated)
                        all_matches.extend(matches)
                    elif isinstance(item, str):
                        obfuscated, matches = self.obfuscate_text(item, mode, extra_patterns=extra_patterns)
                        obfuscated_list.append(obfuscated)
                        all_matches.extend(matches)
                    else:
                        obfuscated_list.append(item)
                result[key] = obfuscated_list

            else:
                result[key] = value

        return result, all_matches

    def _obfuscate_value(
        self,
        value: str,
        pii_type: PIIType,
        mode: ObfuscationMode
    ) -> str:
        """Apply obfuscation to a single value"""
        if mode == ObfuscationMode.REDACT:
            return f"[{pii_type.value.upper()}_REDACTED]"

        elif mode == ObfuscationMode.HASH:
            # SHA-256 hash for correlation without revealing PII
            hash_val = hashlib.sha256(value.encode()).hexdigest()[:16]
            return f"[HASH:{hash_val}]"

        elif mode == ObfuscationMode.TOKENIZE:
            # Reversible tokenization
            if value not in self._token_map:
                token = f"TOK_{secrets.token_hex(8)}"
                self._token_map[value] = token
            return f"[{self._token_map[value]}]"

        else:  # MASK (default)
            return self._mask_value(value, pii_type)

    def _mask_value(self, value: str, pii_type: PIIType) -> str:
        """Apply masking based on PII type"""
        # Remove formatting
        clean_value = re.sub(r'[\s-]', '', value)

        if pii_type == PIIType.CREDIT_CARD:
            # Show last 4 digits: ****-****-****-1234
            if len(clean_value) >= 4:
                return f"****-****-****-{clean_value[-4:]}"
            return "****-****-****-****"

        elif pii_type == PIIType.SSN:
            # Show last 4 digits: ***-**-1234
            if len(clean_value) >= 4:
                return f"***-**-{clean_value[-4:]}"
            return "***-**-****"

        elif pii_type == PIIType.EMAIL:
            # Mask username: u***@domain.com
            parts = value.split('@')
            if len(parts) == 2:
                username = parts[0]
                domain = parts[1]
                if len(username) > 2:
                    masked_user = username[0] + '*' * (len(username) - 2) + username[-1]
                else:
                    masked_user = '*' * len(username)
                return f"{masked_user}@{domain}"
            return "***@***.***"

        elif pii_type == PIIType.PHONE:
            # Show last 4 digits: ***-***-1234
            digits = re.sub(r'\D', '', value)
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"
            return "***-***-****"

        elif pii_type == PIIType.IP_ADDRESS:
            # Mask last octet: 192.168.1.***
            parts = value.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
            return "***.***.***.***"

        else:
            # Generic masking: show first and last char
            if len(value) > 4:
                return value[0] + '*' * (len(value) - 2) + value[-1]
            return '*' * len(value)


class PIIObfuscationService:
    """
    Main service for PII obfuscation in T1 Agentics.

    Usage:
        service = get_pii_service()
        obfuscated_data, matches = service.obfuscate_event(raw_event)
    """

    def __init__(self, config: Optional[PIIConfig] = None):
        self.config = config or PIIConfig()
        self.obfuscator = PIIObfuscator(config)
        self._stats = {
            'events_processed': 0,
            'pii_detected': 0,
            'pii_obfuscated': 0,
            'by_type': {}
        }

    def obfuscate_event(
        self,
        event_data: Dict[str, Any],
        mode: Optional[ObfuscationMode] = None,
        extra_patterns: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Obfuscate PII in an event/alert.

        Args:
            event_data: The raw event data
            mode: Optional override for obfuscation mode
            extra_patterns: tenant-defined custom patterns; pass the list
                            returned from tenant_pii_patterns_service.get_compiled_for_tenant

        Returns:
            Tuple of (obfuscated_event, obfuscation_report)
        """
        if not self.config.enabled:
            return event_data, {'enabled': False, 'matches': []}

        self._stats['events_processed'] += 1

        obfuscated, matches = self.obfuscator.obfuscate_dict(event_data, mode, extra_patterns=extra_patterns)

        # Update stats
        self._stats['pii_detected'] += len(matches)
        self._stats['pii_obfuscated'] += len(matches)
        for match in matches:
            pii_type = match.pii_type.value
            self._stats['by_type'][pii_type] = self._stats['by_type'].get(pii_type, 0) + 1

        report = {
            'enabled': True,
            'matches_count': len(matches),
            'matches': [
                {
                    'type': m.pii_type.value,
                    'confidence': m.confidence,
                    'obfuscated': True
                }
                for m in matches
            ],
            'timestamp': datetime.utcnow().isoformat()
        }

        return obfuscated, report

    def obfuscate_text(
        self,
        text: str,
        mode: Optional[ObfuscationMode] = None
    ) -> Tuple[str, List[Dict]]:
        """Obfuscate PII in a text string"""
        if not self.config.enabled:
            return text, []

        obfuscated, matches = self.obfuscator.obfuscate_text(text, mode)
        return obfuscated, [
            {'type': m.pii_type.value, 'confidence': m.confidence}
            for m in matches
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get obfuscation statistics"""
        return {
            **self._stats,
            'config': {
                'enabled': self.config.enabled,
                'default_mode': self.config.default_mode.value,
                'types_enabled': [t.value for t in self.config.obfuscate_types]
            }
        }

    def reset_stats(self):
        """Reset statistics"""
        self._stats = {
            'events_processed': 0,
            'pii_detected': 0,
            'pii_obfuscated': 0,
            'by_type': {}
        }


# Global instance
_pii_service: Optional[PIIObfuscationService] = None


def get_pii_service() -> PIIObfuscationService:
    """Get or create the global PII obfuscation service"""
    global _pii_service
    if _pii_service is None:
        _pii_service = PIIObfuscationService()
    return _pii_service


def obfuscate_event(event_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Convenience function to obfuscate an event"""
    return get_pii_service().obfuscate_event(event_data)


def obfuscate_text(text: str) -> Tuple[str, List[Dict]]:
    """Convenience function to obfuscate text"""
    return get_pii_service().obfuscate_text(text)
