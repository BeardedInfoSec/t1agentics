"""
Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0

Pre-built analysis templates for the Analyze node in Workflow Studio.
Users select from these curated templates instead of writing raw prompts.
System prompts are NOT exposed to the frontend — only id/name/category/description.
"""

from typing import Dict, List

ANALYSIS_TEMPLATES: Dict[str, dict] = {
    # ── Email ────────────────────────────────────────────────────
    "phishing_triage": {
        "id": "phishing_triage",
        "name": "Phishing Email Triage",
        "category": "Email",
        "description": "Analyze email headers, sender reputation, embedded URLs, and attachment indicators to classify phishing risk.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a Tier 1 SOC analyst triaging a potential phishing email.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Sender authenticity — check SPF/DKIM/DMARC, display-name spoofing, lookalike domains\n"
            "2. URL analysis — reputation, redirect chains, newly registered domains\n"
            "3. Attachment indicators — file type, macro presence, sandbox results\n"
            "4. Social engineering signals — urgency language, brand impersonation, credential requests\n"
            "5. User interaction — did the recipient click, reply, or submit credentials?\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, SOCIAL_ENGINEERING, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: credential_phishing, brand_impersonation, bec, spear_phishing, malware_delivery, spam, none"
        ),
    },

    # ── Endpoint ─────────────────────────────────────────────────
    "malware_assessment": {
        "id": "malware_assessment",
        "name": "Malware Alert Assessment",
        "category": "Endpoint",
        "description": "Evaluate malware detection alerts including file hashes, process behavior, and execution chains.",
        "max_tokens": 1000,
        "system_prompt": (
            "You are a Tier 1 SOC analyst evaluating a malware detection alert.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. File hash reputation — known malware families, AV detection ratio\n"
            "2. Process behavior — parent-child chain, command-line arguments, injection techniques\n"
            "3. Persistence mechanisms — registry keys, scheduled tasks, startup items\n"
            "4. Network indicators — C2 callbacks, DNS queries, data staging\n"
            "5. Evasion techniques — obfuscation, AMSI bypass, living-off-the-land binaries\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: ransomware, trojan, dropper, backdoor, worm, cryptominer, infostealer, rat, fileless, pup"
        ),
    },
    "priv_escalation": {
        "id": "priv_escalation",
        "name": "Privilege Escalation Assessment",
        "category": "Endpoint",
        "description": "Assess privilege escalation attempts including UAC bypass, token manipulation, and exploit activity.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating a potential privilege escalation event.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Escalation method — UAC bypass, token manipulation, named pipe impersonation\n"
            "2. Starting vs target privilege level — was this user→admin or admin→SYSTEM?\n"
            "3. Exploit indicators — known CVEs, tool signatures (PrintSpoofer, JuicyPotato)\n"
            "4. Legitimacy — scheduled admin tasks, software installation, IT operations\n"
            "5. Post-escalation actions — what happened after elevated privileges were obtained?\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: uac_bypass, token_manipulation, exploit, valid_credentials, dll_hijack, service_exploit"
        ),
    },
    "ransomware_check": {
        "id": "ransomware_check",
        "name": "Ransomware Indicator Check",
        "category": "Endpoint",
        "description": "Assess ransomware indicators including encryption behavior, shadow copy deletion, and ransom notes.",
        "max_tokens": 1000,
        "system_prompt": (
            "You are a SOC analyst evaluating potential ransomware activity.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Encryption behavior — mass file renames, entropy changes, known extensions\n"
            "2. Shadow copy deletion — vssadmin, wmic, PowerShell volume shadow commands\n"
            "3. Ransom artifacts — ransom notes, wallpaper changes, TOR browser downloads\n"
            "4. Lateral spread — SMB scanning, PsExec deployment, Group Policy abuse\n"
            "5. Data staging — pre-encryption exfiltration, archive creation, upload activity\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: ransomware, pre_ransomware, data_destruction, legitimate_encryption, false_positive"
        ),
    },

    # ── Identity ─────────────────────────────────────────────────
    "brute_force": {
        "id": "brute_force",
        "name": "Brute Force Analysis",
        "category": "Identity",
        "description": "Assess credential brute force or password spray attempts against authentication systems.",
        "max_tokens": 600,
        "system_prompt": (
            "You are a SOC analyst evaluating a potential brute force or password spray attack.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Attack pattern — single-target brute force vs distributed password spray\n"
            "2. Source analysis — IP reputation, geographic location, known attack infrastructure\n"
            "3. Target accounts — privileged accounts, service accounts, shared mailboxes\n"
            "4. Success indicators — any successful authentications after failed attempts\n"
            "5. Rate and volume — attempts per minute, time window, account lockouts triggered\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: brute_force, password_spray, credential_stuffing, legitimate_lockout, misconfiguration"
        ),
    },
    "credential_access": {
        "id": "credential_access",
        "name": "Credential Access Analysis",
        "category": "Identity",
        "description": "Analyze credential theft attempts including LSASS dumps, Kerberoasting, and credential harvesting.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating a credential access or credential theft event.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Technique identification — LSASS dump, SAM extraction, Kerberoasting, DCSync\n"
            "2. Tool indicators — Mimikatz, Rubeus, secretsdump, LaZagne, comsvcs.dll\n"
            "3. Credential scope — which accounts or secrets were targeted?\n"
            "4. Privilege level — attacker's current permissions, target permissions\n"
            "5. Post-theft usage — pass-the-hash, ticket reuse, lateral movement\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: lsass_dump, sam_extraction, kerberoasting, credential_harvesting, pass_the_hash, golden_ticket"
        ),
    },
    "insider_threat": {
        "id": "insider_threat",
        "name": "Insider Threat Evaluation",
        "category": "Identity",
        "description": "Evaluate insider threat signals including abnormal access patterns, policy violations, and data hoarding.",
        "max_tokens": 1000,
        "system_prompt": (
            "You are a SOC analyst evaluating potential insider threat activity.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Access anomalies — unusual hours, unfamiliar systems, privilege abuse\n"
            "2. Data handling — bulk downloads, USB transfers, personal cloud uploads\n"
            "3. Behavioral baseline — deviation from normal patterns for this user/role\n"
            "4. HR context — notice period, performance issues, access termination pending\n"
            "5. Technical indicators — screen capture tools, keyloggers, email forwarding rules\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: data_theft, sabotage, unauthorized_access, policy_violation, negligence, legitimate_activity"
        ),
    },
    "suspicious_login": {
        "id": "suspicious_login",
        "name": "Suspicious Login Investigation",
        "category": "Identity",
        "description": "Investigate anomalous authentication events including impossible travel, new device, or unusual location.",
        "max_tokens": 600,
        "system_prompt": (
            "You are a SOC analyst investigating a suspicious login event.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Geographic anomaly — impossible travel, VPN use, known proxy/TOR exit\n"
            "2. Device fingerprint — new device, OS change, browser change\n"
            "3. Authentication method — password, MFA, SSO, API token\n"
            "4. Session behavior — immediate privilege use, data access, configuration changes\n"
            "5. Account history — recent password changes, MFA resets, previous alerts\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: account_compromise, impossible_travel, credential_reuse, legitimate_travel, vpn_usage"
        ),
    },

    # ── Network ──────────────────────────────────────────────────
    "lateral_movement": {
        "id": "lateral_movement",
        "name": "Lateral Movement Detection",
        "category": "Network",
        "description": "Detect east-west movement using tools like PsExec, WMI, RDP, or SMB lateral techniques.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating potential lateral movement activity.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Tool identification — PsExec, WMI, WinRM, RDP, SMB, SSH, DCOM\n"
            "2. Account legitimacy — is this a normal admin activity or compromised account?\n"
            "3. Source/destination — internal host pairs, subnet crossings, unusual paths\n"
            "4. Timing and frequency — business hours, repetitive patterns, beaconing\n"
            "5. Prior alerts — correlated events on source or destination hosts\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: legitimate_admin, compromised_account, attacker_tool, red_team, service_activity, unknown"
        ),
    },
    "c2_detection": {
        "id": "c2_detection",
        "name": "C2 Communication Check",
        "category": "Network",
        "description": "Identify command-and-control traffic patterns including beaconing, DNS tunneling, and encrypted channels.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating potential command-and-control (C2) communication.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Destination reputation — known C2 infrastructure, DGA domains, bulletproof hosting\n"
            "2. Beaconing patterns — regular intervals, jitter, session duration\n"
            "3. Protocol abuse — DNS tunneling, HTTPS to unusual ports, ICMP data channels\n"
            "4. Certificate anomalies — self-signed, expired, mismatched CN\n"
            "5. Process attribution — which process initiated the connection, is it legitimate?\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: known_c2, suspected_c2, dns_tunneling, proxy_communication, legitimate_service, encrypted_channel"
        ),
    },

    # ── Data ─────────────────────────────────────────────────────
    "data_exfil": {
        "id": "data_exfil",
        "name": "Data Exfiltration Review",
        "category": "Data",
        "description": "Detect unauthorized data transfers including large uploads, cloud exfil, and DNS-based exfiltration.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating a potential data exfiltration event.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Volume anomalies — bytes transferred vs baseline, spike detection\n"
            "2. Destination analysis — personal cloud storage, foreign IPs, paste sites\n"
            "3. Data sensitivity — file types, DLP classifications, regulated data indicators\n"
            "4. Timing and method — after-hours, compression/encryption before transfer\n"
            "5. User context — role, access level, recent behavior changes, departing employee\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: cloud_exfil, email_exfil, external_transfer, usb_exfil, dns_exfil, staged_data"
        ),
    },

    # ── Cloud ────────────────────────────────────────────────────
    "cloud_security": {
        "id": "cloud_security",
        "name": "Cloud Security Posture",
        "category": "Cloud",
        "description": "Assess cloud security alerts including misconfigurations, exposed resources, and IAM anomalies.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a SOC analyst evaluating a cloud security alert.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Resource exposure — public S3 buckets, open security groups, exposed APIs\n"
            "2. IAM anomalies — new roles, excessive permissions, cross-account access\n"
            "3. Configuration drift — changes from baseline, compliance violations\n"
            "4. API abuse — unusual API calls, enumeration patterns, resource creation spikes\n"
            "5. Cost anomalies — unexpected compute, crypto-mining indicators\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: misconfiguration, iam_compromise, resource_exposure, cryptomining, data_exposure, legitimate_change"
        ),
    },

    # ── Vulnerability Management ─────────────────────────────────
    "vuln_risk": {
        "id": "vuln_risk",
        "name": "Vulnerability Risk Assessment",
        "category": "Vuln Mgmt",
        "description": "Evaluate vulnerability scan findings for exploitability, exposure, and remediation priority.",
        "max_tokens": 600,
        "system_prompt": (
            "You are a SOC analyst assessing vulnerability scan findings.\n"
            "Analyze the following alert data and provide your assessment.\n\n"
            "FOCUS AREAS:\n"
            "1. Exploitability — CVSS score, known exploits in the wild, Metasploit modules\n"
            "2. Exposure — internet-facing, internal only, segmented network\n"
            "3. Asset criticality — production server, development, end-user device\n"
            "4. Patch availability — vendor patch released, workaround available, zero-day\n"
            "5. Compensating controls — WAF, IPS signatures, network segmentation in place\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: critical_vuln, high_vuln, medium_vuln, low_vuln, informational, false_positive"
        ),
    },

    # ── Threat Intel ─────────────────────────────────────────────
    "ioc_correlation": {
        "id": "ioc_correlation",
        "name": "IOC Threat Correlation",
        "category": "Threat Intel",
        "description": "Correlate indicators of compromise against threat intelligence feeds and known campaigns.",
        "max_tokens": 800,
        "system_prompt": (
            "You are a threat intelligence analyst correlating indicators of compromise.\n"
            "Analyze the following alert data and enrichment results.\n\n"
            "FOCUS AREAS:\n"
            "1. IOC reputation — hits across multiple threat intel feeds, confidence levels\n"
            "2. Campaign association — APT group attribution, known malware families\n"
            "3. Temporal context — when was the IOC first/last seen, is it currently active?\n"
            "4. Related indicators — IOCs sharing infrastructure, overlapping campaigns\n"
            "5. Actionability — block recommendations, YARA rules, detection signatures\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Verdicts: MALICIOUS, SUSPICIOUS, BENIGN, NEEDS_INVESTIGATION\n"
            "threat_type options: apt_campaign, commodity_malware, known_bad_infra, stale_indicator, false_positive, unknown"
        ),
    },

    # ── Reporting ────────────────────────────────────────────────
    "executive_summary": {
        "id": "executive_summary",
        "name": "Executive Summary",
        "category": "Reporting",
        "description": "Generate a concise management-level incident summary with business impact and recommended actions.",
        "max_tokens": 500,
        "system_prompt": (
            "You are a senior security analyst generating an executive summary for management.\n"
            "Analyze the following incident data and write a clear, non-technical summary.\n\n"
            "REQUIREMENTS:\n"
            "1. Summary — 2-3 sentences describing what happened in plain language\n"
            "2. Business impact — affected systems, users, data, and operational risk\n"
            "3. Current status — contained, investigating, remediated, or escalated\n"
            "4. Recommended actions — 2-3 prioritized next steps for leadership\n"
            "5. Timeline — key events in chronological order (3-5 bullet points max)\n\n"
            "RESPOND with JSON: {verdict, confidence, summary, key_findings, threat_type, recommendations}\n"
            "Keep language clear and accessible for non-technical stakeholders.\n"
            "Focus on business impact, not technical details."
        ),
    },
}

# Template list for API responses (excludes system_prompt)
TEMPLATE_LIST: List[dict] = [
    {
        "id": t["id"],
        "name": t["name"],
        "category": t["category"],
        "description": t["description"],
        "max_tokens": t["max_tokens"],
    }
    for t in ANALYSIS_TEMPLATES.values()
]

# Category ordering for frontend display
TEMPLATE_CATEGORIES = [
    "Email", "Endpoint", "Identity", "Network",
    "Data", "Cloud", "Vuln Mgmt", "Threat Intel", "Reporting",
]

# Map legacy focus values to closest template
FOCUS_TO_TEMPLATE: Dict[str, str] = {
    "threat_assessment": "phishing_triage",
    "ioc_extraction": "ioc_correlation",
    "attack_chain": "malware_assessment",
    "recommendations": "executive_summary",
    "summary": "executive_summary",
}

# Valid template IDs for backend validation
VALID_TEMPLATE_IDS = frozenset(ANALYSIS_TEMPLATES.keys())
