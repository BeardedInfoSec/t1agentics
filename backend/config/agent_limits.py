# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent Token Control Configuration

Defines hard limits for token usage, iterations, and tool calls per tier.
Also contains known malware families and trusted EDR sources for verdict convergence.

Security Note: These limits prevent token explosion attacks and ensure
bounded resource consumption per agent execution.
"""

import re
from typing import Dict, Any, List

# =============================================================================
# TIER LIMITS CONFIGURATION
# =============================================================================

TIER_LIMITS: Dict[int, Dict[str, Any]] = {
    1: {
        # T1: Triage - quick decisions with full context
        "max_iterations": 6,            # Increased from 4 to allow more tool calls
        "force_complete_at": 5,         # Increased from 3
        "max_tokens_total": 80000,      # Increased from 50000 for GPT-5.2 comparison
        "max_tokens_per_call": 20000,   # Increased from 15000
        "max_ioc_enrichments": 8,       # Increased from 5
        "max_tool_calls": 10,           # Increased from 6
        "context_budget": {
            "system_prompt": 5000,      # Full dynamic prompt with KB
            "alert_context": 4000,      # Email body, description, etc.
            "tool_results": 3000,       # Enrichment results
            "response_buffer": 1500
        }
    },
    2: {
        # T2: Investigation - deeper analysis
        "max_iterations": 6,
        "force_complete_at": 5,
        "max_tokens_total": 80000,
        "max_tokens_per_call": 20000,
        "max_ioc_enrichments": 10,
        "max_tool_calls": 10,
        "context_budget": {
            "system_prompt": 5000,
            "alert_context": 4000,
            "tool_results": 4000,
            "response_buffer": 2000
        }
    },
    3: {
        # T3: Response - full investigation with response actions
        "max_iterations": 8,
        "force_complete_at": 7,
        "max_tokens_total": 120000,
        "max_tokens_per_call": 30000,
        "max_ioc_enrichments": 15,
        "max_tool_calls": 15,
        "context_budget": {
            "system_prompt": 6000,
            "alert_context": 5000,
            "tool_results": 6000,
            "response_buffer": 3000
        }
    }
}

# =============================================================================
# IOC SKIP PATTERNS
# =============================================================================

# IOCs matching these patterns should never be enriched (internal, private, safe)
SKIP_ENRICHMENT_PATTERNS: List[str] = [
    r'^10\.',                          # Private IP (Class A)
    r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # Private IP (Class B)
    r'^192\.168\.',                     # Private IP (Class C)
    r'^127\.',                          # Loopback
    r'^0\.',                            # Invalid
    r'^169\.254\.',                     # Link-local
    r'^224\.',                          # Multicast
    r'^255\.',                          # Broadcast
    r'localhost',
    r'\.internal$',
    r'\.local$',
    r'\.corp$',
    r'\.lan$',
    r'\.home$',
    r'\.localdomain$',
]

# Compiled patterns for performance
SKIP_ENRICHMENT_COMPILED = [re.compile(p, re.IGNORECASE) for p in SKIP_ENRICHMENT_PATTERNS]

# Known safe domains that should not be enriched
SAFE_DOMAINS: List[str] = [
    'google.com',
    'googleapis.com',
    'gstatic.com',
    'microsoft.com',
    'microsoftonline.com',
    'windows.net',
    'azure.com',
    'office.com',
    'office365.com',
    'amazonaws.com',
    'aws.amazon.com',
    'cloudflare.com',
    'cloudflare-dns.com',
    'akamai.com',
    'akamaiedge.net',
    'cloudfront.net',
    'fastly.net',
    'github.com',
    'githubusercontent.com',
    'apple.com',
    'icloud.com',
]

# =============================================================================
# KNOWN MALWARE FAMILIES
# =============================================================================

# Detection names containing these strings indicate confirmed malware
# Auto-confirm as true_positive when detected
KNOWN_MALWARE_FAMILIES: List[str] = [
    'emotet',
    'trickbot',
    'cobalt',
    'cobaltstrike',
    'mimikatz',
    'ryuk',
    'conti',
    'lockbit',
    'revil',
    'blackcat',
    'alphv',
    'qakbot',
    'qbot',
    'icedid',
    'bazarloader',
    'bazarbackdoor',
    'dridex',
    'zloader',
    'formbook',
    'xloader',
    'redline',
    'raccoon',
    'vidar',
    'asyncrat',
    'remcos',
    'njrat',
    'darkcomet',
    'nanocore',
    'agenttesla',
    'lokibot',
    'azorult',
    'hancitor',
    'ursnif',
    'gozi',
    'isfb',
    'nymaim',
    'smokeloader',
    'amadey',
    'systembc',
    'bumblebee',
    'pikabot',
]

# Malware type keywords in detection names
MALWARE_KEYWORDS: List[str] = [
    'trojan',
    'virus',
    'malware',
    'ransomware',
    'worm',
    'backdoor',
    'rootkit',
    'keylogger',
    'spyware',
    'adware',
    'cryptominer',
    'coinminer',
    'exploit',
    'dropper',
    'downloader',
    'infostealer',
    'stealer',
    'banker',
    'rat',  # Remote Access Trojan
    'botnet',
]

# =============================================================================
# TRUSTED EDR SOURCES
# =============================================================================

# Alerts from these sources with high confidence should be auto-confirmed
TRUSTED_EDR_SOURCES: List[str] = [
    'microsoft defender',
    'defender for endpoint',
    'mde',
    'windows defender',
    'crowdstrike',
    'falcon',
    'sentinelone',
    'carbon black',
    'vmware carbon black',
    'cb defense',
    'cylance',
    'blackberry cylance',
    'cortex xdr',
    'palo alto cortex',
    'elastic endpoint',
    'elastic security',
    'trend micro',
    'apex one',
    'symantec',
    'sep',
    'broadcom endpoint',
    'mcafee',
    'trellix',
    'fireeye',
    'mandiant',
    'kaspersky',
    'eset',
    'bitdefender',
    'sophos',
    'malwarebytes',
    'webroot',
    'f-secure',
    'avira',
    'avg',
    'avast',
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_tier_limits(tier: int) -> Dict[str, Any]:
    """
    Get limits for a specific tier with fallback to tier 1.

    Args:
        tier: Agent tier (1, 2, or 3)

    Returns:
        Dict containing all limits for the tier
    """
    return TIER_LIMITS.get(tier, TIER_LIMITS[1])


def should_skip_ioc_pattern(value: str) -> bool:
    """
    Check if IOC value matches skip patterns.

    Args:
        value: IOC value to check

    Returns:
        True if IOC should be skipped
    """
    for pattern in SKIP_ENRICHMENT_COMPILED:
        if pattern.search(value):
            return True
    return False


def is_safe_domain(domain: str) -> bool:
    """
    Check if domain is in the known safe list.

    Args:
        domain: Domain to check

    Returns:
        True if domain is known safe
    """
    domain_lower = domain.lower()
    for safe in SAFE_DOMAINS:
        if domain_lower == safe or domain_lower.endswith('.' + safe):
            return True
    return False


def is_known_malware(detection_name: str, threat_family: str = '') -> bool:
    """
    Check if detection indicates known malware.

    Args:
        detection_name: Detection name from alert
        threat_family: Threat family from alert

    Returns:
        True if known malware detected
    """
    combined = f"{detection_name} {threat_family}".lower()

    for malware in KNOWN_MALWARE_FAMILIES:
        if malware in combined:
            return True

    for keyword in MALWARE_KEYWORDS:
        if keyword in combined:
            return True

    return False


def is_trusted_edr_source(source: str) -> bool:
    """
    Check if alert source is a trusted EDR.

    Args:
        source: Alert source string

    Returns:
        True if from trusted EDR
    """
    source_lower = source.lower()
    for edr in TRUSTED_EDR_SOURCES:
        if edr in source_lower:
            return True
    return False


def estimate_tokens(text: str) -> int:
    """
    Estimate token count for text.
    Approximation: ~4 characters per token for English text.

    Args:
        text: Text to estimate

    Returns:
        Estimated token count
    """
    if not text:
        return 0
    return len(text) // 4
