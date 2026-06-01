# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Context Stratification - Token Optimization with Content Awareness

BALANCED MODE:
- System prompt: MAX 100 tokens (static for KV cache)
- Alert context: ~300-500 tokens (includes body preview for understanding)
- Tool descriptions: ~50 tokens (in user message)
- Target: 500-800 tokens per alert

TOKEN BUDGET (TIER 1):
- System prompt: ~80 tokens (frozen)
- Alert context: ~300-400 tokens (includes subject, sender, body preview)
- Tool descriptions: ~50 tokens
- Model output: ~50-100 tokens
- Total: ~500-700 tokens (single-shot)

KEY INSIGHT: The LLM needs to SEE the email content (subject + body) to make
intelligent decisions like "this is a receipt" vs "this is phishing".
Ultra-minimal prompts save tokens but produce useless generic verdicts.
"""

import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# ALERT TYPE DETECTION - Determines email vs endpoint vs network alerts
# ═══════════════════════════════════════════════════════════════════════════════

class AlertType:
    """Alert type classification for prompt selection."""
    EMAIL = "email"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    GENERIC = "generic"


def detect_alert_type(alert: Dict[str, Any]) -> str:
    """
    Detect the type of alert based on source, fields, and content.

    Returns one of: 'email', 'endpoint', 'network', 'generic'

    This drives:
    1. System prompt selection (email SOPs vs endpoint rules)
    2. Context field prioritization
    3. Enrichment strategy
    """
    raw_event = alert.get('raw_event', {})
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except (json.JSONDecodeError, ValueError):
            raw_event = {}

    source = str(alert.get('source', '') or alert.get('alert_source', '') or raw_event.get('source', '')).lower()
    category = str(alert.get('category', '') or raw_event.get('category', '')).lower()
    title = str(alert.get('title', '') or raw_event.get('title', '')).lower()

    # ═══════════════════════════════════════════════════════════════════════════
    # ENDPOINT DETECTION - EDR, AV, malware, process-related
    # ═══════════════════════════════════════════════════════════════════════════
    endpoint_sources = [
        'windowsdefenderatp', 'microsoft defender', 'defender atp', 'mde',
        'crowdstrike', 'falcon', 'sentinelone', 's1', 'carbon black', 'cb defense',
        'cortex xdr', 'cybereason', 'cylance', 'tanium', 'sophos', 'kaspersky',
        'eset', 'mcafee', 'trellix', 'symantec endpoint', 'trend micro',
        'elastic endpoint', 'velociraptor', 'osquery', 'sysmon', 'wineventlog',
        'malwarebytes', 'bitdefender', 'avast', 'avg'
    ]

    endpoint_categories = [
        'malware', 'ransomware', 'trojan', 'backdoor', 'rootkit', 'spyware',
        'worm', 'virus', 'pup', 'adware', 'cryptominer', 'miner', 'fileless',
        'process', 'execution', 'privilege escalation', 'defense evasion',
        'persistence', 'lateral movement', 'credential access', 'discovery',
        'collection', 'exfiltration', 'command and control', 'c2', 'impact'
    ]

    # Check for MDE-specific fields
    has_mde_fields = any([
        raw_event.get('evidence'),
        raw_event.get('mitreTechniques'),
        raw_event.get('detectionSource'),
        raw_event.get('machineId'),
        raw_event.get('computerDnsName'),
        raw_event.get('relatedUser'),
    ])

    # Check for generic endpoint fields
    has_endpoint_fields = any([
        raw_event.get('process_name') or raw_event.get('process'),
        raw_event.get('cmdline') or raw_event.get('command_line'),
        raw_event.get('parent_process'),
        raw_event.get('file_hash') or raw_event.get('sha256') or raw_event.get('sha1'),
        raw_event.get('hostname') or raw_event.get('computer_name'),
    ])

    if has_mde_fields or has_endpoint_fields:
        return AlertType.ENDPOINT

    if any(ep_src in source for ep_src in endpoint_sources):
        return AlertType.ENDPOINT

    if any(ep_cat in category for ep_cat in endpoint_categories):
        return AlertType.ENDPOINT

    if any(kw in title for kw in ['malware', 'suspicious file', 'ransomware', 'trojan', 'process', 'execution']):
        return AlertType.ENDPOINT

    # ═══════════════════════════════════════════════════════════════════════════
    # EMAIL DETECTION - Phishing, email gateways, spam
    # ═══════════════════════════════════════════════════════════════════════════
    email_sources = [
        'proofpoint', 'mimecast', 'ironport', 'barracuda', 'fortimail',
        'microsoft 365', 'office365', 'o365', 'exchange', 'google workspace',
        'gmail', 'abnormal security', 'cofense', 'knowbe4', 'agari',
        'phishlabs', 'email gateway', 'mail filter', 'spam filter'
    ]

    email_categories = [
        'phishing', 'spear phishing', 'bec', 'business email compromise',
        'credential harvesting', 'spam', 'malspam', 'email threat',
        'impersonation', 'spoofing', 'email fraud'
    ]

    # Check for email-specific fields
    has_email_fields = any([
        raw_event.get('sender') or raw_event.get('from') or raw_event.get('from_address'),
        raw_event.get('recipient') or raw_event.get('to') or raw_event.get('to_address'),
        raw_event.get('subject') or raw_event.get('original_subject'),
        raw_event.get('body') or raw_event.get('body_text') or raw_event.get('body_preview'),
        raw_event.get('message_id'),
        raw_event.get('reported_from'),  # User-reported phishing
    ])

    if has_email_fields:
        return AlertType.EMAIL

    if any(em_src in source for em_src in email_sources):
        return AlertType.EMAIL

    if any(em_cat in category for em_cat in email_categories):
        return AlertType.EMAIL

    if any(kw in title for kw in ['phishing', 'phish', 'spam', 'email', 'credential', 'impersonation']):
        return AlertType.EMAIL

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK DETECTION - Firewalls, IDS/IPS, proxy, SIEM network rules
    # ═══════════════════════════════════════════════════════════════════════════
    network_sources = [
        'palo alto', 'pan-os', 'fortinet', 'fortigate', 'cisco asa', 'firepower',
        'checkpoint', 'juniper', 'sonicwall', 'watchguard', 'zscaler',
        'snort', 'suricata', 'zeek', 'bro', 'darktrace', 'vectra',
        'extrahop', 'corelight', 'netflow', 'pcap', 'proxy', 'squid',
        'bluecoat', 'websense', 'umbrella', 'cloudflare'
    ]

    network_categories = [
        'intrusion', 'ids', 'ips', 'firewall', 'network threat',
        'c2 communication', 'beacon', 'dns tunneling', 'data exfiltration',
        'port scan', 'reconnaissance', 'brute force', 'ddos', 'dos'
    ]

    # Check for network-specific fields
    has_network_fields = any([
        raw_event.get('source_ip') or raw_event.get('src_ip'),
        raw_event.get('dest_ip') or raw_event.get('dst_ip') or raw_event.get('destination_ip'),
        raw_event.get('source_port') or raw_event.get('dest_port'),
        raw_event.get('protocol'),
        raw_event.get('bytes_in') or raw_event.get('bytes_out'),
        raw_event.get('rule_name') or raw_event.get('signature'),
    ])

    if has_network_fields and not has_email_fields:
        return AlertType.NETWORK

    if any(nw_src in source for nw_src in network_sources):
        return AlertType.NETWORK

    if any(nw_cat in category for nw_cat in network_categories):
        return AlertType.NETWORK

    # Default to generic if no specific type detected
    return AlertType.GENERIC


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 1 SUMMARY BUILDER - TARGET: ~80 tokens
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TITLE_LENGTH = 80
MAX_SUBJECT_LENGTH = 60


def build_tier1_summary(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build minimal Tier 1 summary. Target: ~80 tokens.
    """
    summary = {}

    summary['id'] = str(alert.get('alert_id') or alert.get('id', 'unknown'))[:16]
    summary['title'] = _truncate(alert.get('title', 'Alert'), MAX_TITLE_LENGTH)
    summary['severity'] = alert.get('severity', 'medium')
    summary['source'] = str(alert.get('alert_source') or alert.get('source', 'unknown'))[:20]

    # Extract key IOCs if present
    iocs = alert.get('iocs_extracted', {})
    if iocs:
        key_iocs = _extract_key_iocs(iocs, max_per_type=1)
        if key_iocs:
            summary['iocs'] = key_iocs

    # Email sender if present
    raw_event = alert.get('raw_event', {})
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except (json.JSONDecodeError, ValueError):
            raw_event = {}

    # Check multiple possible field names for sender
    sender = (
        raw_event.get('original_sender') or
        raw_event.get('reported_from') or
        raw_event.get('sender') or
        raw_event.get('from') or
        raw_event.get('from_address') or
        raw_event.get('sender_domain') or
        ''
    )
    if sender:
        summary['sender'] = str(sender)[:50]

    return summary


def build_tier1_prompt_context(alert: Dict[str, Any]) -> str:
    """
    Build alert context for user message with enough detail for intelligent analysis.
    Target: ~300-500 tokens - enough for LLM to understand the email content.

    Includes:
    - Basic metadata (severity, source)
    - Email subject and sender
    - Body preview (first 800 chars) - enough to understand the "ask"
    - Key IOCs with verdicts
    """
    summary = build_tier1_summary(alert)

    # Get raw event for email content
    raw_event = alert.get('raw_event', {})
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except (json.JSONDecodeError, ValueError):
            raw_event = {}

    parts = [
        f"[{summary.get('severity', 'MEDIUM').upper()}] {summary.get('source', 'unknown')}",
    ]

    # Alert title - always include
    title = alert.get('title') or summary.get('title', 'Alert')
    if title:
        parts.append(f"Title: {_truncate(title, 150)}")

    # Alert description - critical context for non-email alerts
    description = alert.get('description', '')
    if description:
        parts.append(f"Description: {_truncate(description, 300)}")

    # Email subject - critical for understanding context
    subject = (
        raw_event.get('original_subject') or
        raw_event.get('reported_subject') or
        raw_event.get('subject') or
        summary.get('title', 'Alert')
    )
    parts.append(f"Subject: {_truncate(subject, 150)}")

    # Sender - check multiple possible field names
    sender = (
        summary.get('sender') or
        raw_event.get('original_sender') or
        raw_event.get('reported_from') or
        raw_event.get('from') or
        raw_event.get('from_address') or
        raw_event.get('sender') or
        ''
    )
    if sender:
        parts.append(f"From: {_truncate(str(sender), 100)}")

    # Body preview - this is KEY for understanding what the email is about
    # Check multiple possible field names for email body
    body = (
        raw_event.get('body_text') or
        raw_event.get('body') or
        raw_event.get('text_body') or
        raw_event.get('reported_body_preview') or
        raw_event.get('body_preview') or
        raw_event.get('original_body') or
        ''
    )
    if body:
        # Clean up the body - remove excessive whitespace
        body_clean = ' '.join(body.split())
        body_preview = _truncate(body_clean, 800)
        if body_preview:
            parts.append(f"\nBody Preview:\n{body_preview}")

    # ═══════════════════════════════════════════════════════════════════════════
    # ENDPOINT/PROCESS ALERT FIELDS - critical for non-email alerts
    # ═══════════════════════════════════════════════════════════════════════════
    endpoint_fields = []

    # Host/hostname - check multiple naming conventions
    hostname = (raw_event.get('hostname') or raw_event.get('host') or
                raw_event.get('computer_name') or raw_event.get('HostName') or
                raw_event.get('ComputerName') or raw_event.get('computerDnsName'))
    if hostname:
        endpoint_fields.append(f"Host: {_truncate(str(hostname), 50)}")

    # Username - check multiple naming conventions
    user = (raw_event.get('username') or raw_event.get('user') or
            raw_event.get('user_name') or raw_event.get('account') or
            raw_event.get('User') or raw_event.get('UserName') or
            raw_event.get('AccountName'))
    if user:
        endpoint_fields.append(f"User: {_truncate(str(user), 50)}")

    # Process info - check both lowercase and PascalCase (Windows/Sysmon)
    process = (raw_event.get('process_name') or raw_event.get('process') or
               raw_event.get('image') or raw_event.get('Image') or
               raw_event.get('ProcessName'))
    if process:
        endpoint_fields.append(f"Process: {_truncate(str(process), 100)}")

    # Command line - CRITICAL for encoded payload detection
    cmdline = (raw_event.get('cmdline') or raw_event.get('command_line') or
               raw_event.get('process_command') or raw_event.get('CommandLine') or
               raw_event.get('ProcessCommandLine'))
    if cmdline:
        # Include more of the command line for encoded payload analysis
        endpoint_fields.append(f"Command: {_truncate(str(cmdline), 500)}")

    parent = (raw_event.get('parent_process') or raw_event.get('parent_image') or
              raw_event.get('parent_command_line') or raw_event.get('ParentImage') or
              raw_event.get('ParentProcessName') or raw_event.get('ParentCommandLine'))
    if parent:
        endpoint_fields.append(f"Parent: {_truncate(str(parent), 150)}")

    # File info
    file_path = raw_event.get('file_path') or raw_event.get('target_filename') or raw_event.get('file')
    if file_path:
        endpoint_fields.append(f"File: {_truncate(str(file_path), 150)}")

    file_hash = raw_event.get('file_hash') or raw_event.get('sha256') or raw_event.get('sha1') or raw_event.get('md5')
    if file_hash:
        endpoint_fields.append(f"Hash: {_truncate(str(file_hash), 70)}")

    # Network info
    src_ip = raw_event.get('source_ip') or raw_event.get('src_ip') or raw_event.get('client_ip')
    if src_ip:
        endpoint_fields.append(f"Src IP: {_truncate(str(src_ip), 40)}")

    dst_ip = raw_event.get('dest_ip') or raw_event.get('dst_ip') or raw_event.get('destination_ip')
    if dst_ip:
        endpoint_fields.append(f"Dst IP: {_truncate(str(dst_ip), 40)}")

    # Event type/action - CRITICAL for determining benign vs malicious
    event_type = raw_event.get('event_type') or raw_event.get('action') or raw_event.get('event_action')
    if event_type:
        endpoint_fields.append(f"Action: {_truncate(str(event_type), 50)}")

    # Firewall/network device rule name
    rule_name = raw_event.get('rule_name') or raw_event.get('policy_name') or raw_event.get('rule')
    if rule_name:
        endpoint_fields.append(f"Rule: {_truncate(str(rule_name), 80)}")

    # Source system (e.g., CrowdStrike, Palo Alto, etc.)
    source = raw_event.get('source') or alert.get('source') or alert.get('alert_source')
    if source:
        endpoint_fields.append(f"Source: {_truncate(str(source), 50)}")

    # Category/type
    category = raw_event.get('category') or alert.get('category')
    if category:
        endpoint_fields.append(f"Category: {_truncate(str(category), 50)}")

    # Destination domain (for network alerts)
    dest_domain = raw_event.get('dest_domain') or raw_event.get('domain') or raw_event.get('destination_domain')
    if dest_domain:
        endpoint_fields.append(f"Dest Domain: {_truncate(str(dest_domain), 80)}")

    # Tags - useful for quick classification hints
    tags = raw_event.get('tags', [])
    if tags and isinstance(tags, list):
        endpoint_fields.append(f"Tags: {', '.join(str(t) for t in tags[:5])}")

    # Threat intel hit info
    threat_intel = raw_event.get('threat_intel', {})
    if threat_intel and isinstance(threat_intel, dict):
        ti_category = threat_intel.get('category', '')
        ti_conf = threat_intel.get('confidence', 0)
        if ti_category:
            endpoint_fields.append(f"Threat Intel: {ti_category} (conf: {ti_conf}%)")

    # MITRE ATT&CK info (multiple formats)
    mitre = raw_event.get('mitre', {})
    if mitre and isinstance(mitre, dict):
        technique = mitre.get('technique_name') or mitre.get('technique')
        tactic = mitre.get('tactic')
        if technique:
            endpoint_fields.append(f"MITRE: {tactic} - {technique}" if tactic else f"MITRE: {technique}")

    # MDE/Defender format: mitreTechniques array
    mitre_techniques = raw_event.get('mitreTechniques', [])
    if mitre_techniques and isinstance(mitre_techniques, list):
        endpoint_fields.append(f"MITRE Techniques: {', '.join(str(t) for t in mitre_techniques[:5])}")

    # MDE detection source
    detection_source = raw_event.get('detectionSource')
    if detection_source:
        endpoint_fields.append(f"Detection: {detection_source}")

    # MDE classification/determination
    classification = raw_event.get('classification')
    determination = raw_event.get('determination')
    if classification:
        endpoint_fields.append(f"Classification: {classification}" + (f" / {determination}" if determination else ""))

    # Add endpoint fields if we have any
    if endpoint_fields:
        parts.append("\n=== Alert Details ===")
        parts.extend(endpoint_fields)

    # ═══════════════════════════════════════════════════════════════════════════
    # MDE EVIDENCE SECTION - Process/File/User entities from Windows Defender
    # ═══════════════════════════════════════════════════════════════════════════
    evidence = raw_event.get('evidence', [])
    if isinstance(evidence, list) and evidence:
        parts.append("\n=== Evidence (MDE) ===")

        # Group evidence by type
        processes = []
        files = []
        users = []

        for item in evidence:
            if not isinstance(item, dict):
                continue

            entity_type = item.get('entityType', 'Unknown')

            if entity_type == 'Process':
                proc_info = []
                filename = item.get('fileName', 'unknown')
                proc_info.append(f"Process: {filename}")

                cmdline = item.get('processCommandLine', '')
                if cmdline:
                    proc_info.append(f"  Cmd: {_truncate(cmdline, 200)}")

                parent = item.get('parentProcessFileName', '')
                parent_path = item.get('parentProcessFilePath', '')
                if parent:
                    proc_info.append(f"  Parent: {parent}" + (f" ({parent_path})" if parent_path else ""))

                sha256 = item.get('sha256', '')
                if sha256:
                    proc_info.append(f"  SHA256: {sha256}")

                account = item.get('accountName', '')
                domain = item.get('domainName', '')
                if account:
                    proc_info.append(f"  User: {domain}\\{account}" if domain else f"  User: {account}")

                detection = item.get('detectionStatus', '')
                if detection:
                    proc_info.append(f"  Detection: {detection}")

                processes.append('\n'.join(proc_info))

            elif entity_type == 'File':
                file_info = []
                filename = item.get('fileName', 'unknown')
                filepath = item.get('filePath', '')
                file_info.append(f"File: {filename}" + (f" at {filepath}" if filepath else ""))

                sha256 = item.get('sha256', '')
                if sha256:
                    file_info.append(f"  SHA256: {sha256}")

                detection = item.get('detectionStatus', '')
                if detection:
                    file_info.append(f"  Detection: {detection}")

                files.append('\n'.join(file_info))

            elif entity_type == 'User':
                account = item.get('accountName', '')
                domain = item.get('domainName', '')
                upn = item.get('userPrincipalName', '')
                if account:
                    user_str = f"User: {domain}\\{account}" if domain else f"User: {account}"
                    if upn:
                        user_str += f" ({upn})"
                    users.append(user_str)

        # Add evidence (limit to prevent token explosion)
        if processes:
            parts.append("\n[Processes]")
            for proc in processes[:3]:  # Max 3 processes
                parts.append(proc)

        if files:
            parts.append("\n[Files]")
            for f in files[:3]:  # Max 3 files
                parts.append(f)

        if users:
            parts.append("\n[Users]")
            for u in users[:2]:  # Max 2 users
                parts.append(u)

    # MDE relatedUser and loggedOnUsers
    related_user = raw_event.get('relatedUser', {})
    if isinstance(related_user, dict) and related_user.get('userName'):
        domain = related_user.get('domainName', '')
        user = related_user['userName']
        parts.append(f"\nRelated User: {domain}\\{user}" if domain else f"\nRelated User: {user}")

    # MDE computer info
    computer_dns = raw_event.get('computerDnsName')
    if computer_dns:
        parts.append(f"Computer: {computer_dns}")

    # IOCs with verdicts - helps LLM understand if there's something malicious
    iocs = summary.get('iocs', {})
    if iocs:
        ioc_parts = []
        for ioc_type, values in iocs.items():
            if values:
                ioc_parts.append(f"{ioc_type}: {values[0]}")
        if ioc_parts:
            parts.append(f"\nIOCs: {'; '.join(ioc_parts)}")

    # Include enrichment verdicts if available
    extracted = raw_event.get('_extracted', {}) or alert.get('_extracted', {})
    if extracted:
        enrichment = extracted.get('enrichment', {})
        results = enrichment.get('results', {})
        if results:
            verdicts = []
            for ioc_type, ioc_results in results.items():
                if isinstance(ioc_results, dict):
                    for ioc_val, ioc_data in list(ioc_results.items())[:2]:
                        if isinstance(ioc_data, dict):
                            verdict = ioc_data.get('verdict', '')
                            malicious = ioc_data.get('malicious', False)
                            if malicious:
                                verdicts.append(f"{ioc_type[:10]}:{ioc_val[:30]}=MALICIOUS")
                            elif verdict:
                                verdicts.append(f"{ioc_type[:10]}:{ioc_val[:30]}={verdict}")
            if verdicts:
                parts.append(f"Enrichment: {'; '.join(verdicts[:5])}")

    return "\n".join(parts)


def estimate_tier1_tokens(text: str) -> int:
    """Estimate token count (~4 chars per token)"""
    return len(text) // 4


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2 FULL CONTEXT - ON-DEMAND LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def build_tier2_full_context(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Build full alert context for Tier 2 analysis."""
    full = dict(alert)

    if 'raw_event' in full and full['raw_event']:
        raw = full['raw_event']
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                pass
        if isinstance(raw, dict):
            full['raw_event'] = _truncate_dict_values(raw, max_length=500)

    return full


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _truncate(text: str, max_length: int) -> str:
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def _extract_key_iocs(iocs: Dict[str, Any], max_per_type: int = 1) -> Dict[str, List[str]]:
    """Extract most important IOCs - 1 per type max"""
    key_iocs = {}
    priority = ['domain', 'ip', 'url', 'hash']

    for ioc_type in priority:
        if ioc_type in iocs:
            values = iocs[ioc_type]
            if isinstance(values, list) and values:
                key_iocs[ioc_type] = [str(values[0])[:50]]
            elif isinstance(values, str):
                key_iocs[ioc_type] = [str(values)[:50]]

    return key_iocs


def _truncate_dict_values(d: Dict, max_length: int = 500) -> Dict:
    """Recursively truncate string values"""
    result = {}
    for k, v in d.items():
        if isinstance(v, str) and len(v) > max_length:
            result[k] = v[:max_length] + "..."
        elif isinstance(v, dict):
            result[k] = _truncate_dict_values(v, max_length)
        elif isinstance(v, list):
            result[k] = v[:10]
        else:
            result[k] = v
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SMART CONTEXT TRUNCATION FOR LOCAL LLMs
# Reduces token count from 30K-50K to ~3K-5K while preserving decision-critical info
# ═══════════════════════════════════════════════════════════════════════════════

# Fields to always exclude (low signal, high token cost)
ALWAYS_EXCLUDE_FIELDS = {
    'html_body', 'body_html', 'html_content', 'raw_html',
    'html_body_raw', 'mime_content', 'full_headers',
    'base64_content', 'encoded_body', 'raw_mime',
    '_parsed_email', 'eml_content', 'original_eml',
}

# Fields to keep but truncate - increased for better context
# NOTE: Command lines need to be LONG to capture base64 encoded payloads!
TRUNCATE_FIELDS = {
    'body_text': 6000,      # Email body - need enough to understand the "ask"
    'body': 6000,
    'text_body': 6000,
    'description': 3000,    # Alert description can be important
    'summary': 2000,
    'content': 5000,
    'message': 3000,
    'cmdline': 4000,        # Command lines MUST be long for base64 payloads!
    'command_line': 4000,   # Base64 encoded PowerShell can be 1000+ chars
    'CommandLine': 4000,    # Windows/Sysmon format
    'process_command': 4000,
    'processCommandLine': 4000,  # MDE format
    'ProcessCommandLine': 4000,
}

# Key security fields to preserve fully (or with minimal truncation)
PRESERVE_FIELDS = {
    'original_sender', 'sender', 'from', 'from_address',
    'to', 'to_address', 'recipient', 'recipients',
    'subject', 'original_subject',
    'source_ip', 'src_ip', 'dest_ip', 'dst_ip', 'ip_address',
    'domain', 'url', 'urls', 'links',
    'hash', 'sha256', 'sha1', 'md5', 'file_hash',
    'filename', 'file_name', 'file_path',
    'user', 'username', 'user_name', 'account',
    'hostname', 'host', 'computer_name',
    'severity', 'priority', 'risk_score',
    'action', 'event_type', 'alert_type', 'category',
    'technique', 'tactic', 'mitre_attack',
    'verdict', 'confidence', 'status',
}


def truncate_for_tier1(raw_event: Dict[str, Any], max_total_chars: int = 8000) -> Dict[str, Any]:
    """
    Smart truncation for Tier 1 triage - preserve decision-critical fields.

    Target: ~2K tokens (~8000 chars) vs 30K+ tokens for full context.

    Strategy:
    1. Always exclude HTML/MIME content (high tokens, low signal for triage)
    2. Preserve security-relevant fields (sender, IPs, URLs, hashes)
    3. Truncate body text to first 2000 chars (enough to see the "ask")
    4. Limit URLs to first 10 (covers most phishing cases)
    5. Keep enrichment summary, drop detailed results
    """
    if not raw_event or not isinstance(raw_event, dict):
        return raw_event or {}

    result = {}
    current_size = 0

    # First pass: preserve critical security fields
    for key, value in raw_event.items():
        key_lower = key.lower()

        # Skip excluded fields entirely
        if key_lower in ALWAYS_EXCLUDE_FIELDS:
            continue

        # Handle nested _extracted enrichment data specially
        if key == '_extracted' and isinstance(value, dict):
            result['_extracted'] = _truncate_enrichment_data(value)
            current_size += len(json.dumps(result['_extracted']))
            continue

        # Preserve key security fields
        if key_lower in PRESERVE_FIELDS or any(p in key_lower for p in ['sender', 'ip', 'hash', 'url', 'domain']):
            if isinstance(value, str):
                result[key] = value[:500]  # Even preserved fields get max 500 chars
            elif isinstance(value, list):
                result[key] = value[:10]  # Max 10 items for lists (URLs, IPs, etc.)
            else:
                result[key] = value
            current_size += len(json.dumps({key: result[key]}))
            continue

        # Truncate known verbose fields
        if key_lower in TRUNCATE_FIELDS:
            max_len = TRUNCATE_FIELDS[key_lower]
            if isinstance(value, str) and len(value) > max_len:
                result[key] = value[:max_len] + f"... [truncated, {len(value)} chars total]"
            else:
                result[key] = value
            current_size += len(json.dumps({key: result[key]}))
            continue

        # For other fields, include if under budget
        field_json = json.dumps({key: value})
        if current_size + len(field_json) < max_total_chars:
            if isinstance(value, str) and len(value) > 1000:
                result[key] = value[:1000] + "..."
            elif isinstance(value, dict):
                result[key] = _truncate_dict_values(value, max_length=300)
            elif isinstance(value, list):
                result[key] = value[:10]
            else:
                result[key] = value
            current_size += len(json.dumps({key: result[key]}))

    # Add truncation metadata
    original_size = len(json.dumps(raw_event))
    if original_size > max_total_chars:
        result['_truncation_info'] = {
            'original_chars': original_size,
            'truncated_chars': current_size,
            'reduction_pct': round((1 - current_size / original_size) * 100, 1),
            'note': 'Use inspect_raw_event_data for full context if needed'
        }

    return result


def _truncate_enrichment_data(extracted: Dict[str, Any]) -> Dict[str, Any]:
    """
    Truncate enrichment data - keep summary, limit detailed results.
    """
    result = {}

    enrichment = extracted.get('enrichment', {})
    if enrichment:
        result['enrichment'] = {
            'status': enrichment.get('status', 'unknown'),
            'summary': enrichment.get('summary', {}),
        }

        # Include verdict counts but not full results
        results = enrichment.get('results', {})
        if results:
            verdict_summary = {}
            for ioc_type, ioc_results in results.items():
                if isinstance(ioc_results, dict):
                    for ioc_val, ioc_data in list(ioc_results.items())[:3]:  # Max 3 per type
                        verdict = ioc_data.get('verdict', 'unknown') if isinstance(ioc_data, dict) else 'unknown'
                        verdict_summary[f"{ioc_type}:{ioc_val[:50]}"] = verdict
            if verdict_summary:
                result['enrichment']['key_verdicts'] = verdict_summary

    # Keep trusted sender check result
    if 'trusted_sender_check' in extracted:
        result['trusted_sender_check'] = extracted['trusted_sender_check']

    return result


def truncate_for_tier2(raw_event: Dict[str, Any], max_total_chars: int = 16000) -> Dict[str, Any]:
    """
    Moderate truncation for Tier 2 - more context than T1 but still bounded.

    Target: ~4K tokens (~16000 chars)
    """
    return truncate_for_tier1(raw_event, max_total_chars=max_total_chars)


def truncate_raw_event_for_tool(raw_event: Dict[str, Any], tier: int = 1) -> Dict[str, Any]:
    """
    Main entry point for truncating raw_event before sending to LLM.

    Budget-aware truncation that preserves decision-critical fields while
    controlling total context size. Higher tiers get more detail.

    IMPORTANT: Agents need sufficient context to make good decisions.
    Aggressive truncation leads to poor verdicts and wasted resubmissions.
    Base64 encoded payloads can be 1000+ chars - preserve them!

    Args:
        raw_event: The raw event data
        tier: Agent tier (1, 2, or 3)

    Returns:
        Truncated raw_event suitable for the tier
    """
    if tier == 1:
        # T1: Triage budget for Claude API
        # ~4 chars/token, need ~2K tokens for prompt/output, so ~6K tokens = 24K chars max
        # But we also have phishing_email and instructions, so raw_event gets ~4K
        return truncate_for_tier1(raw_event, max_total_chars=4000)
    elif tier == 2:
        # T2: Investigation budget for Claude API
        return truncate_for_tier2(raw_event, max_total_chars=20000)
    else:
        # T3: Response - FULL context for incident handling
        return truncate_for_tier2(raw_event, max_total_chars=40000)


# ═══════════════════════════════════════════════════════════════════════════════
# STATIC SYSTEM PROMPTS - FROZEN FOR KV CACHE (ALL TIERS)
# Target: ~80-120 tokens - MUST BE IDENTICAL EVERY CALL per tier
# ═══════════════════════════════════════════════════════════════════════════════

TIER1_STATIC_SYSTEM_PROMPT = """You are a SOC Tier 1 Triage Agent.
Analyze the alert and call complete_analysis with a single verdict.

VERDICTS (choose ONE):
- benign: Legitimate activity, no threat (auto-close)
- false_positive: Alert fired incorrectly, not malicious (auto-close)
- true_positive: Confirmed malicious activity
- suspicious: Genuinely unclear, requires T2 review (RARE)
- needs_escalation: Active or critical incident requiring immediate T3 response

AUTO-CLOSE AS BENIGN when confidence >=0.85 and alert matches:
- User-initiated security actions (MFA enabled, password changed/reset)
- Informational emails from legitimate services (Google, Microsoft, Apple, etc.)
- Receipts, invoices, subscriptions, shipping, newsletters
- Known-good system activity (updates, backups, admin tools, AV scans)

AUTO-CLOSE AS FALSE_POSITIVE when confidence >=0.85 and alert matches:
- Known-good domains or IOCs (major vendors, CDNs)
- Duplicate alerts for resolved incidents
- Test, simulation, or pen-test traffic
- Misconfigured detection on normal behavior

TRUE_POSITIVE when confidence >=0.80 and ANY apply:
- IOC confirmed malicious by 2+ enrichment sources
- Lookalike or typosquat domain impersonating trusted brand
- Credential harvesting or urgent credential request
- Known malware hash, C2 behavior, or data exfiltration indicators

SUSPICIOUS (use sparingly):
- Conflicting enrichment results
- Insufficient context to confirm benign or malicious
- Do NOT default to suspicious when evidence leans benign

DECISION RULES (ordered):
1. User-initiated security confirmation -> benign
2. Legitimate sender + informational content -> benign
3. Malicious verdict from 2+ sources -> true_positive
4. Lookalike domain or credential request -> true_positive
5. Escalate ONLY if active impact or imminent risk

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary: max 2 sentences
- Be decisive; auto-close whenever safely possible

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


TIER2_STATIC_SYSTEM_PROMPT = """You are a SOC Tier 2 Investigator.
You only review alerts escalated from Tier 1.

MISSION:
Validate whether the alert represents a real security threat and determine if response is required.

VERDICTS (choose ONE):
- true_positive: Confirmed malicious activity requiring response
- false_positive: Alert is incorrect or benign in context (auto-close)
- benign: Legitimate activity, no threat (auto-close)
- suspicious: Insufficient evidence to confirm or dismiss (LOW confidence only)
- needs_escalation: Confirmed incident requiring Tier 3 response

INVESTIGATION RULES:
- Correlate IOCs, timelines, and affected entities
- Prefer raw event data over summaries
- Require corroboration for malicious conclusions
- Do NOT speculate beyond evidence
- DECODE any base64/encoded content and extract hidden IOCs

TOOL USAGE:
- Use tools only when they materially reduce uncertainty
- Max 3 tool calls
- Use decode_data tool for ANY encoded/obfuscated content
- Do NOT repeat enrichment already performed by T1 unless stale or conflicting

ESCALATION RULES:
- Escalate ONLY if confirmed malicious activity with impact or credible risk
- If impact is unclear, do NOT escalate

CONFIDENCE RULES:
- true_positive requires confidence >=0.80
- benign / false_positive require confidence >=0.85
- suspicious only when evidence is genuinely insufficient

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary MUST be detailed and analyst-friendly (4-6 sentences):
  1. What was detected and where (host, user, process)
  2. What the analysis revealed (decoded content, IOCs found)
  3. Why this verdict was chosen (specific evidence)
  4. Recommended next steps or actions
- Write as if briefing a senior analyst who will review your work

SUMMARY EXAMPLE:
"Detected encoded PowerShell execution on WS-JSMITH-01 by CORP\\jsmith. Decoded the base64 payload which revealed a reverse shell attempting to connect to 192.168.1.100:443 using TCPClient. This matches known Cobalt Strike beacon behavior. Recommend immediate host isolation and credential reset for affected user. The hidden C2 IP 192.168.1.100 should be blocked at the firewall."

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"...","key_findings":["finding1","finding2"]}}"""


TIER3_STATIC_SYSTEM_PROMPT = """You are a SOC Tier 3 Incident Responder.
You only handle alerts confirmed or escalated by Tier 2.

MISSION:
Assess impact, determine appropriate response actions, and ensure actions are justified and safe.

VERDICTS (choose ONE):
- true_positive: Confirmed incident under response
- false_positive: Incorrect escalation, no incident
- benign: No malicious activity or impact
- suspicious: Unclear impact, requires human oversight
- needs_escalation: Requires executive, legal, or external IR involvement

RESPONSE RULES:
- Prioritize containment over investigation
- Consider business impact and blast radius
- Destructive actions require strong justification

TOOL USAGE:
- Max 4 tool calls
- Use tools to validate impact or execute response
- Do NOT perform exploratory enrichment

ESCALATION RULES:
- needs_escalation is ONLY for non-technical escalation (legal, exec, breach)
- Do NOT re-escalate within SOC tiers

CONFIDENCE RULES:
- true_positive requires confidence >=0.85
- suspicious only if impact cannot be assessed safely

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary: max 3 sentences
- Include justification for any response actions

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


# ═══════════════════════════════════════════════════════════════════════════════
# ALERT-TYPE-SPECIFIC SYSTEM PROMPTS
# These provide domain-specific guidance without cross-referencing wrong SOPs
# ═══════════════════════════════════════════════════════════════════════════════

TIER1_ENDPOINT_PROMPT = """You are a SOC Tier 1 Triage Agent analyzing ENDPOINT/MALWARE alerts.
Analyze the alert and call complete_analysis with a single verdict.

VERDICTS (choose ONE):
- benign: Legitimate software/activity, no threat (auto-close)
- false_positive: Detection fired incorrectly on safe software (auto-close)
- true_positive: Confirmed malicious activity
- suspicious: Genuinely unclear, requires T2 review (RARE)
- needs_escalation: Active malware or critical incident requiring immediate T3 response

AUTO-CLOSE AS BENIGN when confidence >=0.85 and:
- Legitimate software updates (Windows Update, Chrome, Firefox, vendor updates)
- Known-good security tools (AV scans, backup agents, admin tools, patching)
- System maintenance (defrag, cleanup, indexing, scheduled tasks)
- Legitimate installers from official vendors (signed, expected location)

AUTO-CLOSE AS FALSE_POSITIVE when confidence >=0.85 and:
- Detection on known-good software with clean hash reputation
- PUP/adware bundled with legitimate software (user-installed)
- Dual-use admin tools in expected context (PowerShell by IT, PsExec on server)
- Already remediated (status: cleaned, quarantined, removed)

TRUE_POSITIVE when confidence >=0.80 and ANY apply:
- Hash confirmed malicious by enrichment (VT, reputation services)
- Process spawned from suspicious location (temp, appdata, downloads with execution)
- Known malware family identified (ransomware, trojan, backdoor, RAT)
- MITRE techniques indicative of attack (T1027 obfuscation, T1059 scripting, T1055 injection)
- Suspicious parent-child process chain (Office spawning PowerShell, browser spawning cmd)

DECISION RULES (ordered):
1. Clean hash + legitimate vendor + expected path -> benign
2. Hash malicious OR known malware family -> true_positive
3. Suspicious execution chain (e.g., browser->installer->update from temp) -> true_positive
4. Already remediated + no spread indicators -> false_positive
5. Escalate if: ransomware active, C2 confirmed, lateral movement detected

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary: max 2 sentences
- Reference process tree and hash verdicts in summary

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


# ═══════════════════════════════════════════════════════════════════════════════
# TIER1_EMAIL_PROMPT - Phishing/BEC Triage with Transactional Email Awareness
#
# DESIGN RATIONALE (v2 - 2026-01):
# Previous logic over-indexed on surface signals (multiple URLs, shipment language,
# CTAs) that are also present in legitimate transactional emails. This caused
# false positives on shipping notifications, order confirmations, and receipts.
#
# Key changes:
# 1. Added TRANSACTIONAL EMAIL COHERENCE TEST - evaluates whether content forms
#    a consistent transactional pattern before escalating
# 2. Explicit list of NON-INDICATORS that should not trigger escalation alone
# 3. Requires at least one TRUE phishing indicator (credential request, lookalike
#    domain, malicious IOC, account threat) before marking true_positive
# 4. "Unknown" URL reputation is treated as neutral, not suspicious
#
# This is evidence-based decision making, NOT allowlist/trust-based.
# ═══════════════════════════════════════════════════════════════════════════════
TIER1_EMAIL_PROMPT = """You are a SOC Tier 1 Triage Agent analyzing EMAIL/PHISHING alerts.
Analyze the alert and call complete_analysis with a single verdict.

VERDICTS (choose ONE):
- benign: Legitimate email, no threat (auto-close)
- false_positive: Alert fired incorrectly, not phishing (auto-close)
- true_positive: Confirmed phishing or malicious email
- suspicious: Genuinely unclear, requires T2 review (RARE)
- needs_escalation: Active credential compromise or ongoing campaign requiring T3

═══════════════════════════════════════════════════════════════════════════════
CRITICAL RULE: Do NOT escalate based on surface signals alone.
Transactional emails (shipping, order confirmations, receipts) naturally contain
multiple URLs, brand references, and call-to-action buttons. These are NOT
phishing indicators by themselves.
═══════════════════════════════════════════════════════════════════════════════

AUTO-CLOSE AS BENIGN when confidence >=0.85 and ALL apply:
- Pure transactional notification (shipping, order, receipt, subscription renewal)
- Contains coherent transaction data (tracking #, order #, dates, item details)
- No credential, login, password, or payment request
- No account threat language ("suspended", "verify immediately", "unusual activity")
- URL domains match the stated brand (ups.com for UPS shipment, etc.)
- Tone is informational, not urgent or threatening
- Only CTA is passive (track, view, learn more) - not login/verify/update

AUTO-CLOSE AS FALSE_POSITIVE when confidence >=0.85 and:
- User reported but email is clearly legitimate transactional notification
- Alert triggered on URL count or shipment language, no actual threat present
- Sender domain verified legitimate, content matches brand expectations
- Duplicate report for already-remediated email
- Test phishing simulation (known campaign ID or test indicator)

TRUE_POSITIVE when confidence >=0.80 and AT LEAST ONE applies:
- Sender domain is a lookalike/typosquat of the brand (warnindustries.phish.com, not partsvia.com)
- Email requests credentials, login, password reset, or account verification
- Email contains account threat ("suspended", "locked", "verify to restore")
- Links point to credential harvesting endpoints on a domain UNRELATED to the claimed brand
- Attachment or link confirmed malicious by enrichment
- BEC indicators: executive impersonation + wire transfer/gift card request
- Reply-To domain mismatches sender AND both differ from legitimate brand (compound mismatch)
- Urgency + threat + credential/payment request combined

IMPORTANT: "Sender is third-party platform (partsvia.com)" + "links go to brand domain (warn.com)"
= BENIGN e-commerce pattern. Do NOT classify as brand impersonation.

SUSPICIOUS (use sparingly - requires at least one TRUE concern):
- Reply-To mismatch but otherwise benign content
- Brand inconsistency: claims to be Brand X but ALL links go to unknown/unrelated domain
- Urgency language WITH some threat, but no credential request
- Do NOT mark suspicious just because URLs are "unknown" - absence of threat intel is neutral

WHAT IS NOT A PHISHING INDICATOR (do not escalate for these alone):
- Multiple URLs (normal in transactional emails)
- Shipment/delivery/package language (this is what shipping emails say)
- "Click here to track" buttons (legitimate tracking workflow)
- External sender domain (most transactional emails are external)
- Unknown URL reputation (neutral - not evidence of threat)
- Brand logos or imagery (both legitimate and phishing emails use these)
- Third-party platform as sender domain (e.g., PartsVia, Shopify, WooCommerce, Squarespace,
  Klaviyo, Mailchimp, SendGrid, etc. sending on behalf of a brand) — this is standard
  e-commerce practice. If the links go to the brand's actual domain, it is NOT spoofing.

THIRD-PARTY SENDER RULE:
Many legitimate businesses use e-commerce platforms and email services to send transactional
emails. The sending domain (customerservice@partsvia.com, orders@shopify.com, etc.) will
NOT match the brand domain (warn.com, shopify-merchant.com). This is expected and normal.
→ ONLY flag sender domain mismatch as a phishing indicator if the URLs ALSO go to a
  suspicious/unrelated domain, not the claimed brand's actual domain.
→ If the email is from partsvia.com but ALL links go to warn.com — this is normal e-commerce.

TRANSACTIONAL EMAIL COHERENCE TEST:
Before escalating a shipping/order email, verify it FAILS this test:
1. Has transaction reference (order #, tracking #)? → If yes, +benign
2. URLs match stated brand domain (warn.com for WARN Industries)? → If yes, +benign
   (Note: Sender domain may differ — third-party platforms are normal)
3. Only passive CTA (track, view, order details)? → If yes, +benign
4. No credential, login, or payment request? → If yes, +benign
5. Informational tone (no account threat, no urgency)? → If yes, +benign
→ If ALL 5 pass, this is BENIGN. Do NOT escalate even if sender domain differs from brand.

DECISION PRIORITY (apply in order):
1. Credential request OR account threat → true_positive
2. Lookalike domain OR malicious IOC → true_positive
3. BEC pattern (impersonation + financial request) → true_positive
4. Coherent transactional email, no threat signals → benign
5. User reported + no threat indicators → false_positive
6. Mixed signals with at least one real concern → suspicious
7. Escalate ONLY if: credentials entered, malware executed, active campaign

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary: max 2 sentences
- For benign transactional emails, state: "Legitimate [type] notification. No credential requests, threats, or malicious indicators."

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


TIER1_NETWORK_PROMPT = """You are a SOC Tier 1 Triage Agent analyzing NETWORK/FIREWALL alerts.
Analyze the alert and call complete_analysis with a single verdict.

VERDICTS (choose ONE):
- benign: Legitimate network activity, no threat (auto-close)
- false_positive: Alert fired incorrectly on normal traffic (auto-close)
- true_positive: Confirmed malicious network activity
- suspicious: Genuinely unclear, requires T2 review (RARE)
- needs_escalation: Active C2, data exfiltration, or intrusion requiring T3

AUTO-CLOSE AS BENIGN when confidence >=0.85 and:
- Traffic to known-good services (CDNs, cloud providers, SaaS applications)
- Expected administrative traffic (backup, monitoring, patching systems)
- Internal scanning by authorized security tools
- DNS queries to legitimate domains

AUTO-CLOSE AS FALSE_POSITIVE when confidence >=0.85 and:
- Signature false positive on legitimate application protocol
- Blocked traffic with no successful connection
- Known misconfigured rule triggering on normal behavior
- Penetration test or authorized security scan (in change window)

TRUE_POSITIVE when confidence >=0.80 and ANY apply:
- C2 beaconing pattern detected (regular intervals, encoded data)
- Connection to known malicious IP/domain (threat intel hit)
- Data exfiltration indicators (large outbound, unusual protocol, encryption to bad IP)
- Lateral movement (SMB/RDP to multiple hosts, credential abuse)
- Port scan followed by exploitation attempt

DECISION RULES (ordered):
1. Destination is known-good (CDN, cloud, internal) -> benign
2. Destination IP/domain malicious + successful connection -> true_positive
3. Blocked suspicious traffic, no connection -> false_positive
4. C2 pattern OR exfiltration indicators -> true_positive
5. Escalate if: active intrusion, data breach imminent, ransomware spreading

OUTPUT REQUIREMENTS:
- Tool call ONLY
- Summary: max 2 sentences
- Reference source/dest IPs and any threat intel hits

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


TIER2_ENDPOINT_PROMPT = """You are a SOC Tier 2 Investigator analyzing ENDPOINT/MALWARE alerts.
You only review alerts escalated from Tier 1.

MISSION:
Confirm malware verdict and assess blast radius/impact on endpoint.

VERDICTS (choose ONE):
- true_positive: Confirmed malware requiring containment/response
- false_positive: Detection was incorrect, no malware present (auto-close)
- benign: Legitimate activity misidentified (auto-close)
- suspicious: Cannot confirm verdict, requires deeper analysis
- needs_escalation: Confirmed malware with spread, C2, or data impact requiring T3

INVESTIGATION FOCUS:
- DECODE any base64/encoded command lines - use decode_data tool
- Validate hash reputation across multiple sources
- Analyze process tree for malicious patterns
- Check for persistence mechanisms created
- Look for lateral movement or C2 indicators
- Extract hidden IOCs from decoded content (IPs, URLs, domains)

TOOL USAGE:
- Max 3 tool calls
- ALWAYS use decode_data on encoded PowerShell (-enc, -encodedcommand)
- Enrich hashes not already enriched by T1
- Query for related alerts on same host or user

ESCALATION TRIGGERS:
- Ransomware: any file encryption activity
- RAT/C2: confirmed external communication (reverse shell, beacon)
- Credential theft: evidence of credential dumping or exfiltration
- Spread: same malware on multiple hosts

OUTPUT REQUIREMENTS:
- Summary MUST be detailed and analyst-friendly (4-6 sentences):
  1. What was detected: hostname, username, process, parent process
  2. What you found: decoded content, hidden IOCs, C2 infrastructure
  3. Threat classification: what type of attack/malware this represents
  4. Impact assessment: what the attacker could do or did do
  5. Recommended actions: containment, remediation, IOC blocking
- Include ALL extracted IOCs in the key_findings array
- Write like you're briefing an incident commander

SUMMARY EXAMPLE:
"Analyzed suspicious PowerShell on WS-JSMITH-01 executed by CORP\\jsmith via explorer.exe. Decoded the base64 payload revealing a reverse TCP shell connecting to 192.168.1.100 on port 443. This is consistent with initial access/C2 establishment - the attacker has remote command execution capability on this host. The user account may be compromised. Recommend: (1) Isolate host immediately, (2) Block 192.168.1.100 at perimeter, (3) Reset jsmith credentials, (4) Hunt for lateral movement from this host."

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"...","key_findings":["Decoded reverse shell payload","Hidden C2: 192.168.1.100:443","User: CORP\\\\jsmith potentially compromised"]}}"""


# ═══════════════════════════════════════════════════════════════════════════════
# TIER2_EMAIL_PROMPT - Deep Phishing Investigation
#
# NOTE: With improved T1 transactional email handling, T2 should only receive
# emails that have at least one genuine concern (credential request, lookalike
# domain, reply-to mismatch, etc.). Pure transactional emails should be closed
# at T1. If T2 receives a clearly benign transactional email, mark as
# false_positive and note that T1 escalation was incorrect.
# ═══════════════════════════════════════════════════════════════════════════════
TIER2_EMAIL_PROMPT = """You are a SOC Tier 2 Investigator analyzing EMAIL/PHISHING alerts.
You only review alerts escalated from Tier 1.

MISSION:
Confirm phishing verdict and assess user exposure/credential risk.

NOTE: T1 should have filtered out pure transactional emails (shipping, receipts, orders).
If you receive a clearly benign transactional email with no threat indicators,
mark as false_positive - the T1 escalation was incorrect.

VERDICTS (choose ONE):
- true_positive: Confirmed phishing requiring response
- false_positive: Not phishing, legitimate email (auto-close)
- benign: Safe email, no threat (auto-close)
- suspicious: Cannot confirm, requires additional context
- needs_escalation: Credentials compromised or active BEC requiring T3

INVESTIGATION FOCUS:
- Validate the T1 concern that triggered escalation
- Deep analysis of sender infrastructure (SPF, DKIM, hosting)
- URL detonation or sandbox results for links
- Attachment analysis for malware
- Check if user clicked/submitted credentials
- Look for related reports from other users (campaign indicator)

TOOL USAGE:
- Max 3 tool calls
- Query for same sender/domain across other alerts
- Check if links were clicked in proxy/firewall logs

TRANSACTIONAL EMAIL CHECK:
If the email appears to be a legitimate transactional notification (shipping,
order confirmation, receipt) with no actual threat indicators:
- Verify: No credential request, no account threat, URLs match brand
- If confirmed benign: Mark false_positive, note T1 over-escalated
- Do NOT investigate further if no threat exists

ESCALATION TRIGGERS:
- Credentials entered on phishing page
- Malware payload executed from attachment
- BEC with financial transaction initiated
- C-suite or privileged user targeted

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


TIER2_NETWORK_PROMPT = """You are a SOC Tier 2 Investigator analyzing NETWORK/FIREWALL alerts.
You only review alerts escalated from Tier 1.

MISSION:
Confirm malicious network activity and assess scope of intrusion.

VERDICTS (choose ONE):
- true_positive: Confirmed malicious network activity requiring response
- false_positive: Legitimate traffic, alert incorrect (auto-close)
- benign: Normal network activity (auto-close)
- suspicious: Cannot confirm verdict, monitoring recommended
- needs_escalation: Active intrusion or exfiltration requiring T3

INVESTIGATION FOCUS:
- Validate threat intel hits on IPs/domains
- Analyze traffic patterns for C2 or exfiltration
- Correlate with endpoint alerts on affected hosts
- Check for successful vs blocked connections
- Assess data volume and sensitivity

TOOL USAGE:
- Max 3 tool calls
- Enrich IPs/domains not already checked
- Query for related alerts on same source host

ESCALATION TRIGGERS:
- Confirmed C2 with bidirectional communication
- Data exfiltration to external destination
- Active lateral movement
- Ransomware communication detected

Call:
{"name":"complete_analysis","arguments":{"verdict":"X","confidence":0.N,"summary":"..."}}"""


def build_optimized_system_prompt(
    alert: Dict[str, Any] = None,
    kb_context: Optional[List[Dict[str, Any]]] = None,
    tier: int = 1
) -> str:
    """
    Return alert-type-aware system prompt for specified tier.
    Uses alert type detection to provide domain-specific guidance.
    """
    # Detect alert type for prompt selection
    alert_type = AlertType.GENERIC
    if alert:
        alert_type = detect_alert_type(alert)

    logger.info(f"[PROMPT] Alert type detected: {alert_type} for tier {tier}")

    if tier == 1:
        if alert_type == AlertType.ENDPOINT:
            return TIER1_ENDPOINT_PROMPT
        elif alert_type == AlertType.EMAIL:
            return TIER1_EMAIL_PROMPT
        elif alert_type == AlertType.NETWORK:
            return TIER1_NETWORK_PROMPT
        else:
            return TIER1_STATIC_SYSTEM_PROMPT  # Generic fallback

    elif tier == 2:
        if alert_type == AlertType.ENDPOINT:
            return TIER2_ENDPOINT_PROMPT
        elif alert_type == AlertType.EMAIL:
            return TIER2_EMAIL_PROMPT
        elif alert_type == AlertType.NETWORK:
            return TIER2_NETWORK_PROMPT
        else:
            return TIER2_STATIC_SYSTEM_PROMPT  # Generic fallback

    else:
        return TIER3_STATIC_SYSTEM_PROMPT  # T3 handles all types


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN BUDGET - HARD LIMITS
# ═══════════════════════════════════════════════════════════════════════════════

class TokenBudget:
    """
    Enforce token budgets during execution.

    TIER 1 LIMITS (with content awareness):
    - Max 1500 tokens total (allows body preview for intelligent analysis)
    - Max 2 tool calls
    - Max 2 LLM steps
    """

    # Limits - balanced for content awareness
    MAX_TOKENS_TIER1 = 3000  # Increased for multi-alert-type support
    MAX_TOKENS_TIER2 = 6000  # Increased for deeper T2 analysis
    MAX_TOOL_CALLS_TIER1 = 2
    MAX_STEPS_TIER1 = 2

    def __init__(self, tier: int = 1):
        self.tier = tier
        self.max_tokens = self.MAX_TOKENS_TIER1 if tier == 1 else self.MAX_TOKENS_TIER2
        self.max_tool_calls = self.MAX_TOOL_CALLS_TIER1 if tier == 1 else 10
        self.max_steps = self.MAX_STEPS_TIER1 if tier == 1 else 5
        self.tokens_used = 0
        self.tool_calls = 0
        self.steps = 0

    def can_continue(self) -> bool:
        """Check if we can continue execution"""
        return (
            self.tokens_used < self.max_tokens and
            self.tool_calls < self.max_tool_calls and
            self.steps < self.max_steps
        )

    def record_step(self, input_tokens: int, output_tokens: int, num_tool_calls: int = 0):
        """Record a step's token usage"""
        self.tokens_used += input_tokens + output_tokens
        self.tool_calls += num_tool_calls
        self.steps += 1

        if self.tier == 1 and self.tokens_used > 2000:
            logger.warning(f"[TOKEN_REGRESSION] Tier 1 exceeded 2000 tokens: {self.tokens_used}")

        logger.info(
            f"[TOKEN_BUDGET] Step {self.steps}/{self.max_steps}: "
            f"{self.tokens_used}/{self.max_tokens} tokens, "
            f"{self.tool_calls}/{self.max_tool_calls} tools"
        )

    def get_remaining(self) -> Dict[str, int]:
        """Get remaining budget"""
        return {
            'tokens': self.max_tokens - self.tokens_used,
            'tool_calls': self.max_tool_calls - self.tool_calls,
            'steps': self.max_steps - self.steps
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PRE-DIGESTED CONTEXT FOR T1 DECISION-ONLY MODE
# This builds a human-readable summary with all decision-critical data
# so the LLM can make a verdict without needing tools
# ═══════════════════════════════════════════════════════════════════════════════

def build_predigested_t1_context(
    alert: Dict[str, Any],
    enrichment_data: Optional[Dict[str, Any]] = None,
    phishing_email_content: Optional[Dict[str, Any]] = None,
    trusted_sender_info: Optional[Dict[str, Any]] = None
) -> str:
    """
    Build a pre-digested, decision-focused context for T1 triage.

    This provides ALL the information the LLM needs to make a verdict
    in a clear, structured format - no tools required.

    Target: ~800-1200 tokens with all decision-critical info

    Sections:
    1. ALERT METADATA - severity, source, category
    2. CONTENT - email subject/body or alert description
    3. SENDER ANALYSIS - domain reputation, trust status
    4. IOC ENRICHMENT - verdict summary with confidence
    5. SIGNALS - key indicators for decision making
    """
    parts = []

    # Get raw event
    raw_event = alert.get('raw_event', {})
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except (json.JSONDecodeError, ValueError):
            raw_event = {}

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 1: ALERT METADATA + TYPE DETECTION
    # ═══════════════════════════════════════════════════════════════════
    severity = (alert.get('severity') or 'medium').upper()
    source = alert.get('source') or alert.get('alert_source') or 'unknown'
    category = alert.get('category') or raw_event.get('category') or 'general'

    # Detect and include alert type for clarity
    alert_type = detect_alert_type(alert)
    alert_type_label = {
        AlertType.EMAIL: "EMAIL/PHISHING",
        AlertType.ENDPOINT: "ENDPOINT/MALWARE",
        AlertType.NETWORK: "NETWORK/FIREWALL",
        AlertType.GENERIC: "GENERAL"
    }.get(alert_type, "GENERAL")

    parts.append(f"## ALERT [{severity}] - {alert_type_label}")
    parts.append(f"Source: {source} | Category: {category}")

    # Title
    title = alert.get('title') or raw_event.get('subject') or 'No title'
    parts.append(f"Title: {_truncate(title, 150)}")

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 2: CONTENT
    # ═══════════════════════════════════════════════════════════════════
    parts.append("\n## CONTENT")

    # Email-specific content
    if phishing_email_content:
        sender = phishing_email_content.get('original_sender', 'unknown')
        sender_name = phishing_email_content.get('original_sender_name', '')
        subject = phishing_email_content.get('original_subject', 'No subject')
        body = phishing_email_content.get('email_body', '')

        parts.append(f"From: {sender}" + (f" ({sender_name})" if sender_name else ""))
        parts.append(f"Subject: {_truncate(subject, 120)}")

        if body:
            # Clean and truncate body
            body_clean = ' '.join(body.split())
            parts.append(f"\nBody Preview:\n{_truncate(body_clean, 1000)}")

        # Pre-extracted IOCs from phishing report
        extracted_iocs = phishing_email_content.get('extracted_iocs', {})
        if any(extracted_iocs.values()):
            ioc_summary = []
            for ioc_type, values in extracted_iocs.items():
                if values:
                    ioc_summary.append(f"{ioc_type}: {len(values)}")
            parts.append(f"\nExtracted IOCs: {', '.join(ioc_summary)}")

    else:
        # Non-email alert - use description and raw event fields
        sender = (
            raw_event.get('sender') or
            raw_event.get('from') or
            raw_event.get('original_sender') or
            raw_event.get('reporter') or
            ''
        )
        if sender:
            parts.append(f"From: {sender}")

        subject = raw_event.get('subject') or raw_event.get('original_subject')
        if subject:
            parts.append(f"Subject: {_truncate(subject, 120)}")

        description = alert.get('description') or ''
        if description:
            parts.append(f"Description: {_truncate(description, 500)}")

        body = raw_event.get('body') or raw_event.get('body_preview') or ''
        if body:
            body_clean = ' '.join(body.split())
            parts.append(f"\nBody Preview:\n{_truncate(body_clean, 800)}")

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 3: SENDER ANALYSIS
    # ═══════════════════════════════════════════════════════════════════
    if trusted_sender_info:
        parts.append("\n## SENDER ANALYSIS")
        if trusted_sender_info.get('is_trusted_sender'):
            ts = trusted_sender_info.get('trusted_sender_result', {})
            parts.append(f"STATUS: TRUSTED ({ts.get('trust_level', 'known')})")
            if ts.get('organization'):
                parts.append(f"Organization: {ts['organization']}")
        elif trusted_sender_info.get('is_phishing_test'):
            pt = trusted_sender_info.get('phishing_test_result', {})
            parts.append(f"STATUS: PHISHING TEST ({pt.get('vendor', 'internal')})")
            parts.append(f"Test Name: {pt.get('test_name', 'Unknown')}")
        else:
            parts.append("STATUS: NOT ON TRUSTED LIST")

        if trusted_sender_info.get('domain_age_valid') is not None:
            if trusted_sender_info['domain_age_valid']:
                parts.append("Domain Age: VALID (>1 year)")
            else:
                parts.append("Domain Age: SUSPICIOUS (new domain)")

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 4: IOC ENRICHMENT RESULTS
    # ═══════════════════════════════════════════════════════════════════
    if enrichment_data:
        parts.append("\n## IOC ENRICHMENT")

        summary = enrichment_data.get('summary', {})
        total = summary.get('total_enriched', 0)
        malicious = summary.get('malicious', 0)
        suspicious = summary.get('suspicious', 0)
        clean = summary.get('clean', 0)

        if total > 0:
            parts.append(f"Total: {total} IOCs | Malicious: {malicious} | Suspicious: {suspicious} | Clean: {clean}")

            # List specific IOC verdicts
            results = enrichment_data.get('results', {})
            ioc_lines = []

            for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
                for ioc in results.get(ioc_type, [])[:3]:  # Max 3 per type
                    if isinstance(ioc, dict):
                        value = ioc.get('value', 'unknown')
                        verdict = ioc.get('verdict', 'unknown')
                        feed = ioc.get('feed_name', '')

                        # Format: type: value = VERDICT (source)
                        line = f"  - {ioc_type[:-1]}: {_truncate(str(value), 40)} = {verdict.upper()}"
                        if feed:
                            line += f" (from {feed})"
                        ioc_lines.append(line)

            if ioc_lines:
                parts.append("\nIOC Details:")
                parts.extend(ioc_lines[:8])  # Max 8 IOCs total

        # Policy blocked
        blocked = enrichment_data.get('results', {}).get('_policy_blocked', [])
        if blocked:
            parts.append(f"\nPolicy Blocked: {len(blocked)} IOCs (internal/private)")

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 5: DECISION SIGNALS
    # ═══════════════════════════════════════════════════════════════════
    signals = []

    # Check for user-initiated security actions (benign signals)
    title_lower = (title or '').lower()

    # Get email body for checking 2FA patterns
    email_body_lower = ''
    if phishing_email_content:
        email_body_lower = (phishing_email_content.get('email_body', '') or '').lower()
    else:
        email_body_lower = (raw_event.get('body') or raw_event.get('body_preview') or '').lower()

    # 2FA/MFA code delivery patterns - check both subject AND body
    # NOTE: This is a LIKELY benign indicator, NOT definitive - attackers can mimic 2FA emails
    twofa_subject_keywords = [
        'verification code', 'security code', 'one-time code', 'otp',
        '2fa code', 'login code', 'access code', 'sign-in code',
        'authentication code', 'passcode'
    ]
    # Body patterns that indicate 2FA code delivery
    twofa_body_patterns = [
        'your verification code is', 'your security code is',
        'your code is', 'enter this code', 'use this code',
        'one-time password', 'one-time passcode'
    ]
    is_2fa_email = (
        any(kw in title_lower for kw in twofa_subject_keywords) or
        any(pattern in email_body_lower for pattern in twofa_body_patterns)
    )

    if is_2fa_email:
        signals.append("LIKELY_BENIGN: Appears to be 2FA/MFA code delivery (verify sender legitimacy)")

    # Other benign security notifications
    benign_keywords = [
        'mfa enabled', 'mfa setup', '2fa enabled', 'password changed',
        'password reset', 'sign-in notification', 'new device', 'account recovery',
        'login notification', 'new sign-in'
    ]
    for kw in benign_keywords:
        if kw in title_lower:
            signals.append(f"BENIGN_SIGNAL: User-initiated security action ({kw})")
            break

    # Check for legitimacy indicators - expanded list including 2FA providers
    legitimate_senders = [
        'noreply@google.com', 'no-reply@accounts.google.com',
        'account@microsoft.com', 'noreply@apple.com',
        'no-reply@dropbox.com', 'notify@amazon.com',
        # 2FA providers
        'meraki.com', 'cisco.com', 'duo.com', 'okta.com',
        'auth0.com', 'onelogin.com', 'ping.com'
    ]
    sender_email = (phishing_email_content or {}).get('original_sender', '') or raw_event.get('sender', '')
    sender_lower = sender_email.lower()
    if any(legit in sender_lower for legit in legitimate_senders):
        signals.append("BENIGN_SIGNAL: Legitimate service sender")

    # Check for malicious signals
    if enrichment_data and enrichment_data.get('summary', {}).get('malicious', 0) > 0:
        signals.append(f"MALICIOUS_SIGNAL: {enrichment_data['summary']['malicious']} malicious IOC(s)")

    # Check for phishing signals in subject - BUT NOT if this is a 2FA email
    # (2FA emails legitimately have urgency language like "expires in 10 minutes")
    if not is_2fa_email:
        phishing_keywords = [
            'urgent', 'immediately', 'suspended', 'verify your', 'confirm your',
            'unusual activity', 'final notice', 'action required'
        ]
        for kw in phishing_keywords:
            if kw in title_lower:
                signals.append(f"PHISHING_SIGNAL: Urgency language in subject ({kw})")
                break

    if signals:
        parts.append("\n## SIGNALS")
        for signal in signals[:5]:
            parts.append(f"- {signal}")

    # ═══════════════════════════════════════════════════════════════════
    # DECISION GUIDANCE
    # ═══════════════════════════════════════════════════════════════════
    parts.append("\n## REQUIRED ACTION")
    parts.append("Analyze the above and provide your verdict using complete_analysis.")
    parts.append("Format: {\"name\":\"complete_analysis\",\"arguments\":{\"verdict\":\"X\",\"confidence\":0.N,\"summary\":\"...\"}}")

    return "\n".join(parts)


def get_t1_decision_prompt(predigested_context: str) -> str:
    """
    Build the complete T1 decision-only prompt.

    This combines the static system prompt with the pre-digested context
    for a single-shot decision without tools.
    """
    return f"""{TIER1_STATIC_SYSTEM_PROMPT}

{predigested_context}"""
