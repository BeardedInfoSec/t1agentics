# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IOC Deduplication Service

Provides functions to extract, deduplicate, and prioritize IOCs.
Prevents redundant enrichment calls and enforces per-tier IOC limits.

Security Note: Ensures critical IOCs are always enriched while
staying within budget constraints.
"""

import re
import hashlib
from typing import Dict, Any, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from config.agent_limits import (
    should_skip_ioc_pattern,
    is_safe_domain,
    get_tier_limits
)


@dataclass
class IOCTracker:
    """
    Tracks IOC enrichment state across an agent execution.

    Prevents duplicate enrichments and enforces limits.
    """
    enriched_iocs: Set[str] = field(default_factory=set)
    pending_iocs: List[Tuple[str, str, int]] = field(default_factory=list)  # (value, type, priority)
    skipped_iocs: Set[str] = field(default_factory=set)
    max_enrichments: int = 5

    def mark_enriched(self, ioc_value: str) -> None:
        """Mark an IOC as enriched."""
        self.enriched_iocs.add(self._normalize(ioc_value))

    def is_enriched(self, ioc_value: str) -> bool:
        """Check if IOC has already been enriched."""
        return self._normalize(ioc_value) in self.enriched_iocs

    def can_enrich_more(self) -> bool:
        """Check if we're under the enrichment limit."""
        return len(self.enriched_iocs) < self.max_enrichments

    def remaining_budget(self) -> int:
        """Get remaining enrichment budget."""
        return max(0, self.max_enrichments - len(self.enriched_iocs))

    def add_pending(self, ioc_value: str, ioc_type: str, priority: int = 5) -> bool:
        """
        Add IOC to pending queue if not already processed.

        Args:
            ioc_value: The IOC value
            ioc_type: Type (ip, domain, hash, etc.)
            priority: 1-10, higher = more important

        Returns:
            True if added, False if skipped/duplicate
        """
        normalized = self._normalize(ioc_value)

        # Skip if already enriched or skipped
        if normalized in self.enriched_iocs or normalized in self.skipped_iocs:
            return False

        # Check skip patterns
        if should_skip_ioc(ioc_value, ioc_type):
            self.skipped_iocs.add(normalized)
            return False

        # Add to pending with priority
        self.pending_iocs.append((ioc_value, ioc_type, priority))
        return True

    def get_next_batch(self, count: int = 3) -> List[Tuple[str, str]]:
        """
        Get next batch of IOCs to enrich, sorted by priority.

        Args:
            count: Maximum IOCs to return

        Returns:
            List of (value, type) tuples
        """
        # Sort by priority descending
        self.pending_iocs.sort(key=lambda x: -x[2])

        batch = []
        remaining = []

        for ioc_value, ioc_type, priority in self.pending_iocs:
            if len(batch) < count and self.can_enrich_more():
                normalized = self._normalize(ioc_value)
                if normalized not in self.enriched_iocs:
                    batch.append((ioc_value, ioc_type))
                    self.enriched_iocs.add(normalized)
            else:
                remaining.append((ioc_value, ioc_type, priority))

        self.pending_iocs = remaining
        return batch

    def _normalize(self, value: str) -> str:
        """Normalize IOC value for comparison."""
        return value.lower().strip()


# IOC type priorities (higher = enrich first)
IOC_PRIORITIES: Dict[str, int] = {
    'hash': 10,        # File hashes are critical
    'sha256': 10,
    'sha1': 9,
    'md5': 9,
    'c2_ip': 9,        # C2 indicators
    'c2_domain': 9,
    'ip': 7,           # External IPs
    'domain': 6,       # Domains
    'url': 5,          # URLs
    'email': 4,        # Email addresses
    'hostname': 3,     # Internal hostnames
    'username': 2,     # Usernames
    'file_path': 1,    # File paths
}


def should_skip_ioc(value: str, ioc_type: str) -> bool:
    """
    Determine if IOC should be skipped for enrichment.

    Args:
        value: IOC value
        ioc_type: Type of IOC

    Returns:
        True if should skip
    """
    if not value or not value.strip():
        return True

    value_lower = value.lower().strip()

    # Skip patterns from config
    if should_skip_ioc_pattern(value_lower):
        return True

    # Skip safe domains
    if ioc_type in ('domain', 'c2_domain') and is_safe_domain(value_lower):
        return True

    # Skip localhost and common local references
    if value_lower in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        return True

    # Skip obviously internal hostnames
    if ioc_type == 'hostname':
        # Skip if contains common internal patterns
        internal_patterns = [
            r'workstation', r'desktop', r'laptop', r'server',
            r'dc\d', r'ad\d', r'domain', r'internal'
        ]
        for pattern in internal_patterns:
            if re.search(pattern, value_lower):
                return True

    # Skip usernames that are system accounts
    if ioc_type in ('username', 'user'):
        system_users = [
            'system', 'local service', 'network service', 'administrator',
            'admin', 'guest', 'root', 'nobody', 'daemon'
        ]
        if value_lower in system_users:
            return True

    # Skip file paths that are standard system paths
    if ioc_type in ('file_path', 'file', 'path'):
        safe_prefixes = [
            'c:\\windows\\', 'c:\\program files\\', 'c:\\program files (x86)\\',
            '/usr/', '/bin/', '/sbin/', '/lib/', '/etc/',
        ]
        for prefix in safe_prefixes:
            if value_lower.startswith(prefix):
                # Unless it's in temp or suspicious location
                if 'temp' in value_lower or 'downloads' in value_lower:
                    return False
                return True

    return False


def extract_iocs_from_alert(alert: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract all IOCs from an alert with deduplication.

    Args:
        alert: Alert data dict

    Returns:
        Dict mapping IOC type to list of values
    """
    iocs: Dict[str, List[str]] = {}

    # Get raw event
    raw = alert.get('raw_event', {})
    if isinstance(raw, str):
        try:
            import json
            raw = json.loads(raw)
        except:
            raw = {}

    # Also check _extracted if present
    extracted = raw.get('_extracted', {}).get('iocs', {})

    # Field mappings: (field_name, ioc_type)
    field_mappings = [
        ('file_hash', 'hash'),
        ('md5', 'hash'),
        ('sha1', 'hash'),
        ('sha256', 'hash'),
        ('c2_ip', 'ip'),
        ('src_ip', 'ip'),
        ('dst_ip', 'ip'),
        ('source_ip', 'ip'),
        ('dest_ip', 'ip'),
        ('ip_address', 'ip'),
        ('c2_domain', 'domain'),
        ('domain', 'domain'),
        ('url', 'url'),
        ('hostname', 'hostname'),
        ('computer_name', 'hostname'),
        ('machine_name', 'hostname'),
        ('username', 'username'),
        ('user', 'username'),
        ('user_name', 'username'),
        ('email', 'email'),
        ('sender', 'email'),
        ('recipient', 'email'),
        ('file_path', 'file_path'),
        ('path', 'file_path'),
        ('process_name', 'process'),
        ('parent_process', 'process'),
    ]

    # Extract from raw event
    for field, ioc_type in field_mappings:
        value = raw.get(field)
        if value and isinstance(value, str) and value.strip():
            if ioc_type not in iocs:
                iocs[ioc_type] = []
            if value not in iocs[ioc_type]:
                iocs[ioc_type].append(value)

    # Merge with already extracted IOCs
    for ioc_type, values in extracted.items():
        if isinstance(values, list):
            if ioc_type not in iocs:
                iocs[ioc_type] = []
            for v in values:
                if v and v not in iocs[ioc_type]:
                    iocs[ioc_type].append(v)

    # Extract from description/title using regex
    text_to_scan = f"{alert.get('title', '')} {alert.get('description', '')}"

    # IP regex
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for ip in re.findall(ip_pattern, text_to_scan):
        if 'ip' not in iocs:
            iocs['ip'] = []
        if ip not in iocs['ip']:
            iocs['ip'].append(ip)

    # Hash regex (SHA256, MD5)
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    for h in re.findall(hash_pattern, text_to_scan):
        if len(h) in (32, 40, 64):  # MD5, SHA1, SHA256
            if 'hash' not in iocs:
                iocs['hash'] = []
            if h.lower() not in [x.lower() for x in iocs['hash']]:
                iocs['hash'].append(h)

    return iocs


def prioritize_iocs(iocs: Dict[str, List[str]], tier: int = 1) -> List[Tuple[str, str, int]]:
    """
    Prioritize IOCs for enrichment based on type and tier limits.

    Args:
        iocs: Dict of IOC type -> values
        tier: Current tier (affects limits)

    Returns:
        List of (value, type, priority) sorted by priority
    """
    limits = get_tier_limits(tier)
    max_enrichments = limits.get('max_ioc_enrichments', 5)

    prioritized = []

    for ioc_type, values in iocs.items():
        base_priority = IOC_PRIORITIES.get(ioc_type, 5)

        for value in values:
            if should_skip_ioc(value, ioc_type):
                continue

            # Adjust priority based on value characteristics
            priority = base_priority

            # Boost priority for C2 indicators
            if 'c2' in ioc_type.lower():
                priority += 2

            # Boost priority for external IPs (not private)
            if ioc_type == 'ip' and not should_skip_ioc_pattern(value):
                priority += 1

            prioritized.append((value, ioc_type, priority))

    # Sort by priority descending
    prioritized.sort(key=lambda x: -x[2])

    # Return top N based on tier limit
    return prioritized[:max_enrichments * 2]  # Return 2x limit for flexibility


def create_ioc_tracker(tier: int = 1) -> IOCTracker:
    """
    Create an IOC tracker configured for the specified tier.

    Args:
        tier: Agent tier (1, 2, or 3)

    Returns:
        Configured IOCTracker instance
    """
    limits = get_tier_limits(tier)
    return IOCTracker(max_enrichments=limits.get('max_ioc_enrichments', 5))


def deduplicate_enrichment_requests(
    requests: List[Dict[str, Any]],
    tracker: IOCTracker
) -> List[Dict[str, Any]]:
    """
    Filter enrichment requests to remove duplicates and over-budget items.

    Args:
        requests: List of enrichment request dicts
        tracker: IOCTracker instance

    Returns:
        Filtered list of requests
    """
    filtered = []

    for req in requests:
        ioc_value = req.get('value', req.get('indicator', req.get('ioc', '')))
        ioc_type = req.get('type', req.get('ioc_type', 'unknown'))

        if not ioc_value:
            continue

        # Skip if already enriched
        if tracker.is_enriched(ioc_value):
            continue

        # Skip if over budget
        if not tracker.can_enrich_more():
            break

        # Skip if matches skip patterns
        if should_skip_ioc(ioc_value, ioc_type):
            tracker.skipped_iocs.add(ioc_value.lower())
            continue

        # Add to filtered and mark as enriched
        filtered.append(req)
        tracker.mark_enriched(ioc_value)

    return filtered
