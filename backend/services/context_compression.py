# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Context Compression Service

Provides functions to compress LLM context to stay within token budgets.
Implements tiered compression strategies for different content types.

Security Note: Maintains critical IOCs and verdicts while trimming verbosity.
"""

import json
import re
from typing import Dict, Any, List, Optional
from config.agent_limits import estimate_tokens, SAFE_DOMAINS


def compress_tool_result(result: Dict[str, Any], max_tokens: int = 400) -> Dict[str, Any]:
    """
    Compress a tool result to fit within token budget.

    Prioritizes:
    1. Verdict/status fields
    2. IOC-related data
    3. Error messages
    4. Truncates verbose descriptions

    Args:
        result: Raw tool result
        max_tokens: Maximum tokens for this result

    Returns:
        Compressed result dict
    """
    if not result:
        return {}

    # Convert to string to estimate current size
    result_str = json.dumps(result, default=str)
    current_tokens = estimate_tokens(result_str)

    if current_tokens <= max_tokens:
        return result

    compressed = {}

    # Priority 1: Always keep verdict/status fields
    priority_keys = [
        'verdict', 'status', 'malicious', 'suspicious', 'clean',
        'score', 'risk_score', 'confidence', 'threat_level',
        'detected', 'blocked', 'quarantined', 'action_taken',
        'error', 'message', 'success'
    ]

    for key in priority_keys:
        if key in result:
            compressed[key] = result[key]

    # Priority 2: IOC-related data (keep but truncate if needed)
    ioc_keys = [
        'ip', 'domain', 'url', 'hash', 'md5', 'sha1', 'sha256',
        'file_hash', 'hostname', 'username', 'email', 'c2', 'c2_ip', 'c2_domain'
    ]

    for key in ioc_keys:
        if key in result:
            value = result[key]
            if isinstance(value, str) and len(value) > 256:
                compressed[key] = value[:256] + '...'
            else:
                compressed[key] = value

    # Priority 3: Detection/threat info
    threat_keys = [
        'threat_name', 'threat_family', 'detection_name', 'category',
        'classification', 'tags', 'indicators'
    ]

    for key in threat_keys:
        if key in result:
            value = result[key]
            if isinstance(value, list) and len(value) > 5:
                compressed[key] = value[:5]
            elif isinstance(value, str) and len(value) > 200:
                compressed[key] = value[:200] + '...'
            else:
                compressed[key] = value

    # Check if we're under budget now
    compressed_str = json.dumps(compressed, default=str)
    if estimate_tokens(compressed_str) <= max_tokens:
        return compressed

    # Still over budget - keep only critical fields
    critical = {}
    critical_keys = ['verdict', 'status', 'malicious', 'score', 'error', 'detected']
    for key in critical_keys:
        if key in compressed:
            critical[key] = compressed[key]

    critical['_compressed'] = True
    return critical


def compress_enrichment(enrichment: Dict[str, Any], max_tokens: int = 300) -> Dict[str, Any]:
    """
    Compress enrichment data (VirusTotal, AbuseIPDB, etc.).

    Extracts only actionable intelligence:
    - Detection ratios
    - Malicious verdicts
    - Key reputation scores
    - First/last seen dates

    Args:
        enrichment: Raw enrichment data
        max_tokens: Maximum tokens for this enrichment

    Returns:
        Compressed enrichment dict
    """
    if not enrichment:
        return {}

    compressed = {}

    # VirusTotal compression
    if 'virustotal' in enrichment or 'vt' in enrichment:
        vt = enrichment.get('virustotal', enrichment.get('vt', {}))
        compressed['vt'] = {
            'detected': vt.get('detected', vt.get('positives', 0) > 0),
            'positives': vt.get('positives', vt.get('malicious', 0)),
            'total': vt.get('total', vt.get('total_engines', 0)),
        }
        if 'threat_names' in vt:
            threats = vt['threat_names']
            compressed['vt']['threats'] = threats[:3] if isinstance(threats, list) else threats

    # AbuseIPDB compression
    if 'abuseipdb' in enrichment:
        abuse = enrichment['abuseipdb']
        compressed['abuse'] = {
            'score': abuse.get('abuseConfidenceScore', abuse.get('score', 0)),
            'reports': abuse.get('totalReports', abuse.get('reports', 0)),
            'country': abuse.get('countryCode', abuse.get('country', '')),
        }

    # Shodan compression
    if 'shodan' in enrichment:
        shodan = enrichment['shodan']
        compressed['shodan'] = {
            'ports': shodan.get('ports', [])[:10],
            'vulns': len(shodan.get('vulns', [])),
            'os': shodan.get('os', ''),
        }

    # Generic threat intel compression
    if 'threat_intel' in enrichment:
        intel = enrichment['threat_intel']
        compressed['intel'] = {
            'malicious': intel.get('malicious', False),
            'score': intel.get('score', intel.get('risk_score', 0)),
            'category': intel.get('category', intel.get('classification', '')),
        }

    # Domain/URL analysis compression
    if 'domain_analysis' in enrichment:
        domain = enrichment['domain_analysis']
        compressed['domain'] = {
            'malicious': domain.get('malicious', False),
            'category': domain.get('category', ''),
            'registrar': domain.get('registrar', ''),
        }

    # If no specific fields found, do generic compression
    if not compressed:
        compressed = _generic_compress(enrichment, max_tokens)

    compressed_str = json.dumps(compressed, default=str)
    if estimate_tokens(compressed_str) > max_tokens:
        # Over budget - return minimal
        return {'_enrichment_summary': 'data_compressed', '_tokens_exceeded': True}

    return compressed


def compress_alert_context(alert: Dict[str, Any], max_tokens: int = 600) -> Dict[str, Any]:
    """
    Compress alert context for LLM consumption.

    Keeps:
    - Alert metadata (id, title, severity, source)
    - Key IOCs
    - Detection details
    - Removes verbose descriptions and raw logs

    Args:
        alert: Full alert data
        max_tokens: Maximum tokens for alert context

    Returns:
        Compressed alert dict
    """
    if not alert:
        return {}

    compressed = {
        'id': alert.get('id', alert.get('alert_id', '')),
        'title': _truncate(alert.get('title', ''), 150),
        'severity': alert.get('severity', 'medium'),
        'source': alert.get('source', ''),
        'category': alert.get('category', ''),
    }

    # Extract key IOCs from raw_event
    raw = alert.get('raw_event', {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except:
            raw = {}

    iocs = {}
    ioc_fields = [
        ('file_hash', 'hash'), ('md5', 'hash'), ('sha256', 'hash'),
        ('c2_ip', 'ip'), ('src_ip', 'ip'), ('dst_ip', 'ip'),
        ('c2_domain', 'domain'), ('domain', 'domain'),
        ('hostname', 'hostname'), ('username', 'user'),
        ('file_path', 'file'), ('process_name', 'process'),
    ]

    for field, ioc_type in ioc_fields:
        if field in raw and raw[field]:
            if ioc_type not in iocs:
                iocs[ioc_type] = []
            value = raw[field]
            if value not in iocs[ioc_type]:
                iocs[ioc_type].append(value)

    if iocs:
        compressed['iocs'] = iocs

    # Detection info
    detection_fields = ['detection_name', 'threat_family', 'action_taken', 'severity_level']
    detection = {}
    for field in detection_fields:
        if field in raw:
            detection[field] = raw[field]

    if detection:
        compressed['detection'] = detection

    # Truncate description
    if 'description' in alert:
        compressed['description'] = _truncate(alert['description'], 200)

    # Check size
    compressed_str = json.dumps(compressed, default=str)
    if estimate_tokens(compressed_str) > max_tokens:
        # Remove description if over budget
        compressed.pop('description', None)

    return compressed


def compress_conversation_history(
    messages: List[Dict[str, Any]],
    max_tokens: int = 2000,
    keep_last_n: int = 4
) -> List[Dict[str, Any]]:
    """
    Compress conversation history to fit within budget.

    Strategy:
    1. Always keep system message
    2. Always keep last N messages
    3. Summarize or drop middle messages
    4. Truncate long tool results

    Args:
        messages: Full conversation history
        max_tokens: Maximum tokens for history
        keep_last_n: Number of recent messages to always keep

    Returns:
        Compressed message list
    """
    if not messages:
        return []

    compressed = []

    # Always keep system message
    if messages and messages[0].get('role') == 'system':
        system_msg = messages[0].copy()
        system_content = system_msg.get('content', '')
        if estimate_tokens(system_content) > 800:
            system_msg['content'] = _truncate(system_content, 3000)  # ~750 tokens
        compressed.append(system_msg)
        messages = messages[1:]

    if not messages:
        return compressed

    # Keep last N messages (truncated)
    recent = messages[-keep_last_n:] if len(messages) > keep_last_n else messages
    older = messages[:-keep_last_n] if len(messages) > keep_last_n else []

    # Summarize older messages if they exist
    if older:
        summary_parts = []
        for msg in older:
            role = msg.get('role', 'unknown')
            content = msg.get('content', '')
            if role == 'assistant' and 'tool' in str(content).lower():
                summary_parts.append(f"[Tool call executed]")
            elif role == 'tool':
                summary_parts.append(f"[Tool result received]")
            elif role == 'user':
                summary_parts.append(f"[User input]")
            elif content:
                summary_parts.append(_truncate(content, 100))

        if summary_parts:
            compressed.append({
                'role': 'system',
                'content': f"[Previous context summarized: {'; '.join(summary_parts[:5])}]"
            })

    # Add recent messages with truncation
    for msg in recent:
        new_msg = msg.copy()
        content = new_msg.get('content', '')

        if isinstance(content, str) and estimate_tokens(content) > 500:
            new_msg['content'] = _truncate(content, 1800)  # ~450 tokens
        elif isinstance(content, list):
            # Handle tool use content
            new_content = []
            for item in content:
                if isinstance(item, dict) and 'text' in item:
                    item = item.copy()
                    if estimate_tokens(item['text']) > 300:
                        item['text'] = _truncate(item['text'], 1000)
                new_content.append(item)
            new_msg['content'] = new_content

        compressed.append(new_msg)

    return compressed


def build_compressed_context(
    alert: Dict[str, Any],
    enrichments: Dict[str, Any],
    previous_analysis: Optional[Dict[str, Any]] = None,
    tier: int = 1,
    budget: Optional[Dict[str, int]] = None
) -> str:
    """
    Build a compressed context string for LLM prompt.

    Args:
        alert: Alert data
        enrichments: Enrichment results
        previous_analysis: T1 analysis if this is T2/T3
        tier: Current tier (affects budget)
        budget: Optional custom budget override

    Returns:
        Compressed context string
    """
    from ..config.agent_limits import get_tier_limits

    limits = get_tier_limits(tier)
    ctx_budget = budget or limits.get('context_budget', {})

    parts = []

    # Alert context
    alert_budget = ctx_budget.get('alert_context', 600)
    compressed_alert = compress_alert_context(alert, alert_budget)
    parts.append(f"ALERT: {json.dumps(compressed_alert, indent=2)}")

    # Enrichment results
    if enrichments:
        enrich_budget = ctx_budget.get('tool_results', 400)
        per_enrich = enrich_budget // max(len(enrichments), 1)
        compressed_enrichments = {}
        for key, value in enrichments.items():
            compressed_enrichments[key] = compress_enrichment(value, per_enrich)
        parts.append(f"ENRICHMENTS: {json.dumps(compressed_enrichments, indent=2)}")

    # Previous tier analysis
    if previous_analysis:
        prev_compressed = {
            'verdict': previous_analysis.get('verdict', 'unknown'),
            'confidence': previous_analysis.get('confidence', 0.5),
            'key_findings': previous_analysis.get('key_findings',
                previous_analysis.get('findings', []))[:5],
        }
        parts.append(f"PREVIOUS_ANALYSIS: {json.dumps(prev_compressed, indent=2)}")

    return '\n\n'.join(parts)


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text to max characters with ellipsis."""
    if not text or len(text) <= max_chars:
        return text
    return text[:max_chars - 3] + '...'


def _generic_compress(data: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
    """Generic compression for unknown data structures."""
    compressed = {}

    for key, value in data.items():
        if isinstance(value, bool) or isinstance(value, (int, float)):
            compressed[key] = value
        elif isinstance(value, str):
            if len(value) > 100:
                compressed[key] = value[:100] + '...'
            else:
                compressed[key] = value
        elif isinstance(value, list):
            if len(value) > 3:
                compressed[key] = value[:3]
            else:
                compressed[key] = value
        elif isinstance(value, dict):
            if len(str(value)) > 200:
                compressed[key] = '[nested_object]'
            else:
                compressed[key] = value

        # Check if over budget
        if estimate_tokens(json.dumps(compressed, default=str)) > max_tokens:
            compressed['_truncated'] = True
            break

    return compressed
