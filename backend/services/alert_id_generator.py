# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert ID Generator Service

Generates systematic, human-readable alert IDs with meaningful prefixes.

Format: {PREFIX}-{YYMMDD}-{SEQ}
Examples:
  - PHI-241225-0001  (Phishing report)
  - MAL-241225-0042  (Malware detection)
  - NET-241225-0003  (Network anomaly)
  - EDR-241225-0015  (EDR/Endpoint alert)
  - IAM-241225-0007  (Identity/Access alert)
  - TI-241225-0002   (Threat Intel match)
  - ALT-241225-0099  (Generic/Unknown)

The format provides:
  - Instant recognition of alert type from prefix
  - Chronological ordering from date component
  - Daily sequence for volume tracking
  - Compact, memorable IDs for verbal communication
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

# Alert type prefixes based on source/category
ALERT_PREFIXES: Dict[str, str] = {
    # Email/Phishing
    'phishing': 'PHI',
    'email': 'PHI',
    'email_inbox': 'EML',
    'phishing_report': 'PHI',
    'inbound_email': 'PHI',
    'suspicious_email': 'PHI',

    # Malware/AV
    'malware': 'MAL',
    'antivirus': 'MAL',
    'virus': 'MAL',
    'trojan': 'MAL',
    'ransomware': 'MAL',
    'defender': 'MAL',
    'crowdstrike': 'MAL',

    # Network
    'network': 'NET',
    'firewall': 'NET',
    'ids': 'NET',
    'ips': 'NET',
    'proxy': 'NET',
    'dns': 'NET',
    'traffic': 'NET',

    # Endpoint/EDR
    'edr': 'EDR',
    'endpoint': 'EDR',
    'process': 'EDR',
    'file': 'EDR',
    'registry': 'EDR',
    'carbon_black': 'EDR',
    'sentinel_one': 'EDR',

    # Identity/Access
    'iam': 'IAM',
    'identity': 'IAM',
    'authentication': 'IAM',
    'login': 'IAM',
    'access': 'IAM',
    'okta': 'IAM',
    'azure_ad': 'IAM',
    'entra': 'IAM',
    'ldap': 'IAM',

    # Threat Intel
    'threat_intel': 'TI',
    'ioc': 'TI',
    'indicator': 'TI',
    'feed': 'TI',
    'misp': 'TI',
    'otx': 'TI',

    # Cloud
    'cloud': 'CLD',
    'aws': 'CLD',
    'azure': 'CLD',
    'gcp': 'CLD',
    'o365': 'CLD',
    'saas': 'CLD',

    # Vulnerability
    'vulnerability': 'VUL',
    'cve': 'VUL',
    'patch': 'VUL',
    'scan': 'VUL',

    # Data Loss/DLP
    'dlp': 'DLP',
    'data_loss': 'DLP',
    'exfiltration': 'DLP',
    'sensitive': 'DLP',

    # SIEM/Generic
    'siem': 'SIM',
    'splunk': 'SIM',
    'sentinel': 'SIM',
    'qradar': 'SIM',

    # Webhook/Integration
    'webhook': 'WHK',
    'integration': 'INT',
    'api': 'API',

    # User Behavior
    'ueba': 'UBA',
    'behavior': 'UBA',
    'anomaly': 'UBA',

    # Form submission
    'form': 'FRM',
    'submission': 'FRM',
    'report': 'FRM',

    # Test/Simulation
    'test': 'TST',
    'simulation': 'TST',
    'phishing_test': 'TST',
}

# Default prefix for unknown sources
DEFAULT_PREFIX = 'ALT'

# In-memory sequence counter (per date per prefix)
# Format: {date_str: {prefix: last_seq}}
_sequence_cache: Dict[str, Dict[str, int]] = {}
_sequence_lock = asyncio.Lock()


def get_prefix_for_source(source: Optional[str] = None,
                          source_type: Optional[str] = None,
                          category: Optional[str] = None,
                          title: Optional[str] = None) -> str:
    """
    Determine the appropriate prefix based on alert metadata.

    Checks source, source_type, category, and title for matching keywords.
    """
    # Combine all hints for matching
    hints = []
    if source:
        hints.append(source.lower())
    if source_type:
        hints.append(source_type.lower())
    if category:
        hints.append(category.lower())
    if title:
        hints.append(title.lower())

    combined = ' '.join(hints)

    # Check each prefix keyword against combined hints
    for keyword, prefix in ALERT_PREFIXES.items():
        if keyword in combined or keyword.replace('_', ' ') in combined:
            return prefix

    return DEFAULT_PREFIX


async def get_next_sequence(prefix: str, date_str: str, db_pool=None) -> int:
    """
    Get the next sequence number for a given prefix and date.

    Uses database sequence if available, falls back to in-memory counter.
    """
    global _sequence_cache

    async with _sequence_lock:
        # Try database sequence first
        if db_pool:
            try:
                async with db_pool.acquire() as conn:
                    # Get current max for this prefix and date pattern
                    result = await conn.fetchval("""
                        SELECT COALESCE(MAX(
                            CASE
                                WHEN alert_id ~ $1
                                THEN CAST(SPLIT_PART(alert_id, '-', 3) AS INTEGER)
                                ELSE 0
                            END
                        ), 0) + 1
                        FROM alerts
                        WHERE alert_id LIKE $2
                    """, f'^{prefix}-{date_str}-\\d+$', f'{prefix}-{date_str}-%')

                    return result or 1
            except Exception as e:
                logger.warning(f"Database sequence lookup failed: {e}, using in-memory counter")

        # Fallback to in-memory counter
        if date_str not in _sequence_cache:
            _sequence_cache[date_str] = {}
            # Clean old dates to prevent memory leak
            old_dates = [d for d in _sequence_cache.keys() if d != date_str]
            for old_date in old_dates[:-2]:  # Keep last 2 days
                del _sequence_cache[old_date]

        if prefix not in _sequence_cache[date_str]:
            _sequence_cache[date_str][prefix] = 0

        _sequence_cache[date_str][prefix] += 1
        return _sequence_cache[date_str][prefix]


async def generate_alert_id(
    source: Optional[str] = None,
    source_type: Optional[str] = None,
    category: Optional[str] = None,
    title: Optional[str] = None,
    db_pool=None
) -> str:
    """
    Generate a systematic alert ID.

    Args:
        source: Alert source (e.g., 'phishing_report', 'crowdstrike')
        source_type: Type of source (e.g., 'email', 'edr')
        category: Alert category (e.g., 'malware', 'phishing')
        title: Alert title for keyword matching
        db_pool: Optional database pool for sequence lookup (deprecated, not used)

    Returns:
        Formatted alert ID like 'PHI-241225-ABCD1234'
    """
    import secrets

    # Get appropriate prefix
    prefix = get_prefix_for_source(source, source_type, category, title)

    # Get date component (YYMMDD)
    now = datetime.utcnow()
    date_str = now.strftime('%y%m%d')

    # Use 4-byte random hex (16M+ unique values per day) for collision resistance
    random_suffix = secrets.token_hex(4).upper()

    # Format: PREFIX-YYMMDD-XXXXXXXX
    alert_id = f"{prefix}-{date_str}-{random_suffix}"

    logger.debug(f"Generated alert ID: {alert_id} (source={source}, type={source_type})")
    return alert_id


def generate_alert_id_sync(
    source: Optional[str] = None,
    source_type: Optional[str] = None,
    category: Optional[str] = None,
    title: Optional[str] = None
) -> str:
    """
    Synchronous version for non-async contexts.
    Uses high-entropy random suffix to avoid collisions under high load.
    """
    import secrets

    prefix = get_prefix_for_source(source, source_type, category, title)
    now = datetime.utcnow()
    date_str = now.strftime('%y%m%d')

    # Use 4-byte random hex (16M+ unique values per day) for collision resistance
    random_suffix = secrets.token_hex(4).upper()

    return f"{prefix}-{date_str}-{random_suffix}"


# Convenience function for legacy compatibility
def legacy_alert_id() -> str:
    """Generate old-style ALT-XXXXXXXX ID for backwards compatibility."""
    import secrets
    return f"ALT-{secrets.token_hex(4).upper()}"
