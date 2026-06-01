# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Specialized Prompt Templates for Flag-Based T1 Triage.

Each alert type gets a focused prompt that:
1. Reduces token count by focusing on relevant fields
2. Improves accuracy by providing type-specific guidance
3. Requests type-specific threat_type classifications
"""

from .alert_classifier import AlertFlag

# Common response format instruction
# NOTE: Double curly braces {{ }} are used to escape them in .format() calls
# Updated 2026-01-26: Added SUSPICIOUS intermediate verdict to reduce FPs
RESPONSE_FORMAT = """
Respond with valid JSON only:
{{
    "verdict": "MALICIOUS|SUSPICIOUS|SOCIAL_ENGINEERING|BENIGN|NEEDS_INVESTIGATION",
    "confidence": 0.0-1.0,
    "key_findings": ["finding1", "finding2", ...],
    "threat_type": "<type_specific>",
    "risk_factors": ["factor1", ...],
    "recommended_actions": ["action1", ...],
    "uncertainty_factors": ["factor1", ...]
}}

VERDICT DEFINITIONS:
- MALICIOUS (90%+): Confirmed malicious IOCs from enrichment AND sender NOT from legitimate domain
- SUSPICIOUS (60-80%): Intent signals present BUT sender legitimacy NOT verified - REQUIRES HUMAN REVIEW
- SOCIAL_ENGINEERING (80%+): High-confidence social engineering FROM non-legitimate sender
- BENIGN (<40%): Legitimate sender OR clean enrichment with no intent signals
- NEEDS_INVESTIGATION (40-60%): Conflicting signals, insufficient evidence for verdict
"""

# Phishing-specific response format with SUSPICIOUS as intermediate verdict
# Updated 2026-01-26: Added SUSPICIOUS to prevent premature SOCIAL_ENGINEERING verdicts
PHISHING_RESPONSE_FORMAT = """
═══════════════════════════════════════════════════════════════════════════
VERDICT SELECTION (FOLLOW STRICTLY - UPDATED 2026-01-26)
═══════════════════════════════════════════════════════════════════════════
CRITICAL: NEVER mark as MALICIOUS or SOCIAL_ENGINEERING if sender domain is LEGITIMATE.
If intent_analysis_skipped=true, the sender is verified legitimate - return BENIGN.

- MALICIOUS (90%+):
    ALL of: Malicious IOCs confirmed + sender NOT from legitimate domain + at least 2 supporting signals
    NO auto-remediation unless confidence >= 0.85

- SUSPICIOUS (60-80%):
    Intent signals present BUT sender legitimacy NOT fully verified
    This verdict REQUIRES HUMAN REVIEW - NO automatic actions
    Use when: urgency/credential patterns detected but sender is unknown (not confirmed malicious OR legitimate)

- SOCIAL_ENGINEERING (80%+):
    ALL of: Brand impersonation + urgency + credential request + sender is NOT legitimate
    Only if confidence >= 0.80 AND sender verified as NOT a legitimate domain

- BENIGN (<40%):
    ANY of: Legitimate sender domain + Intent analysis skipped + Clean enrichment + No intent signals
    If sender is from LEGITIMATE_BRAND_DOMAINS, verdict MUST be BENIGN

- NEEDS_INVESTIGATION (40-60%):
    Conflicting signals require human analysis

Respond with valid JSON only:
{{
    "verdict": "MALICIOUS|SUSPICIOUS|SOCIAL_ENGINEERING|BENIGN|NEEDS_INVESTIGATION",
    "confidence": 0.0-1.0,
    "key_findings": ["finding1", "finding2", ...],
    "threat_type": "<type_specific>",
    "risk_factors": ["factor1", ...],
    "recommended_actions": ["action1", ...],
    "uncertainty_factors": ["factor1", ...],
    "sender_legitimacy_verified": true/false,
    "auto_remediation_allowed": true/false
}}
"""


SPECIALIZED_PROMPTS = {
    AlertFlag.PHISHING: """You are a security analyst triaging a phishing/email threat alert.

═══════════════════════════════════════════════════════════════════════════
CRITICAL RULES (UPDATED 2026-01-26 - FP REDUCTION)
═══════════════════════════════════════════════════════════════════════════
1. CHECK SENDER LEGITIMACY FIRST - before any intent analysis
2. If sender domain is LEGITIMATE (microsoft.com, google.com, etc.) → BENIGN
3. If intent_analysis_skipped=true → sender was verified legitimate → BENIGN
4. NEVER return MALICIOUS/SOCIAL_ENGINEERING for legitimate sender domains
5. Use SUSPICIOUS (not SOCIAL_ENGINEERING) when sender is UNKNOWN (not verified)
6. SUSPICIOUS = "needs human review" - NO automatic remediation

═══════════════════════════════════════════════════════════════════════════
SENDER LEGITIMACY CHECK (DO THIS FIRST)
═══════════════════════════════════════════════════════════════════════════
Check the context for:
- sender_is_legitimate: true → Return BENIGN immediately
- intent_analysis_skipped: true → Return BENIGN immediately
- sender_legitimacy_verified: true → Return BENIGN immediately

If any of the above are true, the sender domain has been verified as a
legitimate brand domain (microsoft.com, google.com, etc.). In this case:
- Intent signals (urgency, credential request) are EXPECTED business emails
- DO NOT analyze language patterns - they will cause false positives
- Return verdict: BENIGN with confidence 0.85+

═══════════════════════════════════════════════════════════════════════════
PHISHING EVIDENCE SIGNALS (only if sender NOT legitimate)
═══════════════════════════════════════════════════════════════════════════
{phishing_indicators}

ONLY analyze the following IF sender is NOT from a legitimate domain:
1. INTENT SIGNALS:
   - Brand impersonation: Does sender/content impersonate a known brand?
   - Urgency language: Account suspension, verify now, limited time
   - Credential requests: Login, password, verify, confirm identity
   - User interaction: Did they click? Download? Enter credentials?

2. EMAIL AUTHENTICATION:
   - SPF/DKIM/DMARC failures = sender spoofing (strong indicator)
   - Domain mismatch between sender display name and actual domain

3. IOC ENRICHMENT:
   - Malicious IOC verdicts from threat intel
   - Clean IOCs with intent signals → SUSPICIOUS (not SOCIAL_ENGINEERING)

ALERT DATA:
{alert_json}

IOC ENRICHMENT:
{enrichment_summary}

═══════════════════════════════════════════════════════════════════════════
EVIDENCE REQUIREMENTS FOR VERDICTS (STRICT)
═══════════════════════════════════════════════════════════════════════════
MALICIOUS (90%+) requires ALL of:
  ✓ Sender is NOT from legitimate brand domain
  ✓ At least 1 malicious IOC from enrichment OR confirmed credential compromise
  ✓ At least 2 of: suspicious TLD, domain age <30 days, auth failures, brand impersonation

SUSPICIOUS (60-80%) - USE THIS FOR UNCERTAIN CASES:
  ✓ Intent signals present (urgency, credential request)
  ✓ Sender legitimacy NOT verified (unknown domain)
  ✓ No confirmed malicious IOCs
  → This verdict flags for HUMAN REVIEW, no auto-remediation

SOCIAL_ENGINEERING (80%+) requires ALL of:
  ✓ Sender is NOT from legitimate brand domain (verified)
  ✓ Brand impersonation detected
  ✓ Urgency AND credential request language
  ✓ At least 1 supporting signal (suspicious TLD, new domain, auth failure)

BENIGN (<40%) if ANY of:
  ✓ Sender domain is verified legitimate brand
  ✓ intent_analysis_skipped = true
  ✓ No intent signals AND clean enrichment

NEEDS_INVESTIGATION (40-60%):
  ✓ Conflicting signals that require human analysis

threat_type options: credential_phishing, brand_impersonation, bec, spear_phishing, malware_delivery, spam, none
""" + PHISHING_RESPONSE_FORMAT,

    AlertFlag.MALWARE: """You are a security analyst triaging a malware detection alert.

FOCUS YOUR ANALYSIS ON:
- File hash reputation across threat intel sources
- Process behavior: file drops, registry modifications, network connections
- Execution chain: parent process, child processes, command line arguments
- Persistence mechanisms: run keys, scheduled tasks, services
- Evasion techniques: obfuscation, packing, living-off-the-land binaries
- Lateral movement indicators: network shares, remote execution

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: ransomware, trojan, dropper, backdoor, worm, cryptominer, infostealer, rat, fileless, pup
""" + RESPONSE_FORMAT,

    AlertFlag.LATERAL_MOVEMENT: """You are a security analyst triaging a lateral movement alert.

FOCUS YOUR ANALYSIS ON:
- Tool used: PsExec, WMI, WinRM, RDP, SMB, DCOM, SSH
- Source and destination hosts: Are they in the same security zone?
- User account: Is this a legitimate admin? Service account? Compromised account?
- Time of activity: Business hours? Weekend? Off-hours for this user?
- Prior alerts: Any previous suspicious activity from source host/user?
- Command executed: What was run on the remote system?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: legitimate_admin, compromised_account, attacker_tool, red_team, service_activity, unknown
""" + RESPONSE_FORMAT,

    AlertFlag.C2_COMMUNICATION: """You are a security analyst triaging a command and control (C2) communication alert.

FOCUS YOUR ANALYSIS ON:
- Destination IP/domain reputation and threat intel
- Communication patterns: beaconing interval, jitter, data volume
- Protocol analysis: HTTP/HTTPS, DNS tunneling, non-standard ports
- Certificate analysis: self-signed, expired, suspicious issuer
- Historical connections: first seen, frequency, other hosts connecting
- Process making connections: legitimate application or suspicious?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: known_c2, suspected_c2, dns_tunneling, proxy_communication, legitimate_service, encrypted_channel
""" + RESPONSE_FORMAT,

    AlertFlag.CREDENTIAL_ACCESS: """You are a security analyst triaging a credential access/theft alert.

FOCUS YOUR ANALYSIS ON:
- Technique used: LSASS dump, SAM extraction, Kerberoasting, credential harvesting
- Target credentials: local admin, domain admin, service accounts
- Tool indicators: Mimikatz, LaZagne, Rubeus, credential phishing
- Account lockouts or failed logins preceding this event
- Privilege level of the accessing account
- Data destination: where are credentials being sent/stored?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: lsass_dump, sam_extraction, kerberoasting, credential_harvesting, pass_the_hash, golden_ticket
""" + RESPONSE_FORMAT,

    AlertFlag.DATA_EXFIL: """You are a security analyst triaging a data exfiltration alert.

FOCUS YOUR ANALYSIS ON:
- Data volume: Is this normal for this user/system?
- Destination: cloud storage, personal email, external IP, USB
- Data sensitivity: file names, paths, classification labels
- Timing: after hours, during notice period, following access grant
- Compression/encryption: signs of staging data for exfil
- User context: role, recent access changes, HR status if known

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: cloud_exfil, email_exfil, external_transfer, usb_exfil, dns_exfil, staged_data
""" + RESPONSE_FORMAT,

    AlertFlag.PERSISTENCE: """You are a security analyst triaging a persistence mechanism alert.

FOCUS YOUR ANALYSIS ON:
- Mechanism type: scheduled task, registry run key, service, startup folder
- Payload: what is being persisted? Legitimate or suspicious?
- Creation context: who created it? When? From what process?
- Similar mechanisms: are there other persistence points for same payload?
- Removal attempts: has this been removed and recreated?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: scheduled_task, registry_runkey, service_creation, startup_item, wmi_subscription, legitimate_software
""" + RESPONSE_FORMAT,

    AlertFlag.PRIVILEGE_ESCALATION: """You are a security analyst triaging a privilege escalation alert.

FOCUS YOUR ANALYSIS ON:
- Escalation method: UAC bypass, token manipulation, exploit, valid credentials
- Target privilege level: local admin, domain admin, SYSTEM
- Starting privilege: what access did the attacker have before?
- Exploit indicators: CVE references, exploit toolkit signatures
- Subsequent actions: what was done with elevated privileges?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: uac_bypass, token_manipulation, exploit, valid_credentials, dll_hijack, service_exploit
""" + RESPONSE_FORMAT,

    AlertFlag.DEFENSE_EVASION: """You are a security analyst triaging a defense evasion alert.

FOCUS YOUR ANALYSIS ON:
- Evasion technique: process injection, obfuscation, timestomping, log clearing
- Target defense: AV, EDR, logging, AMSI, ETW
- Success indicators: was the evasion successful?
- Associated malicious activity: what is being hidden?
- Tool indicators: known evasion frameworks or techniques

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: process_injection, obfuscation, log_tampering, av_evasion, amsi_bypass, timestomping
""" + RESPONSE_FORMAT,

    AlertFlag.UNKNOWN: """You are a security analyst triaging an unclassified security alert.

Analyze the alert comprehensively:
- What type of threat or activity does this represent?
- What is the severity and potential impact?
- Are there any indicators of compromise (IOCs)?
- What enrichment data is available and what does it tell us?
- Does this require immediate action or further investigation?

ALERT DATA:
{alert_json}

IOC ENRICHMENT (if available):
{enrichment_summary}

threat_type options: suspicious_activity, policy_violation, misconfiguration, legitimate_activity, unknown
""" + RESPONSE_FORMAT,
}


def get_prompt_for_flag(flag: AlertFlag) -> str:
    """
    Get the specialized prompt template for a given alert flag.

    Args:
        flag: AlertFlag indicating the alert type

    Returns:
        Prompt template string with {alert_json} and {enrichment_summary} placeholders
    """
    return SPECIALIZED_PROMPTS.get(flag, SPECIALIZED_PROMPTS[AlertFlag.UNKNOWN])


def format_prompt(
    flag: AlertFlag,
    alert_json: str,
    enrichment_summary: str = "No enrichment data available",
    phishing_indicators: str = "No phishing indicators detected"
) -> str:
    """
    Get a fully formatted prompt ready for LLM submission.

    Args:
        flag: AlertFlag indicating the alert type
        alert_json: JSON string of the alert data
        enrichment_summary: Summary of IOC enrichment results
        phishing_indicators: Formatted phishing evidence signals for email threats

    Returns:
        Formatted prompt string
    """
    template = get_prompt_for_flag(flag)

    # For phishing alerts, include phishing indicators
    if flag == AlertFlag.PHISHING:
        return template.format(
            alert_json=alert_json,
            enrichment_summary=enrichment_summary,
            phishing_indicators=phishing_indicators
        )

    # For other alert types, use standard formatting
    return template.format(
        alert_json=alert_json,
        enrichment_summary=enrichment_summary
    )


def get_enrichment_summary(enrichment_data: dict) -> str:
    """
    Format enrichment data into a concise summary for the prompt.

    Args:
        enrichment_data: Dictionary of enrichment results

    Returns:
        Formatted summary string
    """
    if not enrichment_data:
        return "No enrichment data available"

    lines = []

    # Process IPs
    ips = enrichment_data.get("results", {}).get("ips", [])
    for ip in ips:
        verdict = ip.get("verdict", "unknown")
        value = ip.get("value", "")
        sources = ip.get("sources", [])
        confidence = ip.get("confidence", 0)
        if verdict in ("malicious", "suspicious"):
            lines.append(f"- IP {value}: {verdict.upper()} (confidence: {confidence}%, sources: {', '.join(sources)})")
        elif verdict == "clean":
            lines.append(f"- IP {value}: Clean")

    # Process domains
    domains = enrichment_data.get("results", {}).get("domains", [])
    for domain in domains:
        verdict = domain.get("verdict", "unknown")
        value = domain.get("value", "")
        sources = domain.get("sources", [])
        confidence = domain.get("confidence", 0)
        if verdict in ("malicious", "suspicious"):
            lines.append(f"- Domain {value}: {verdict.upper()} (confidence: {confidence}%, sources: {', '.join(sources)})")
        elif verdict == "clean":
            lines.append(f"- Domain {value}: Clean")

    # Process hashes
    hashes = enrichment_data.get("results", {}).get("hashes", [])
    for hash_data in hashes:
        verdict = hash_data.get("verdict", "unknown")
        value = hash_data.get("value", "")[:16] + "..."  # Truncate hash
        sources = hash_data.get("sources", [])
        confidence = hash_data.get("confidence", 0)
        if verdict in ("malicious", "suspicious"):
            lines.append(f"- Hash {value}: {verdict.upper()} (confidence: {confidence}%, sources: {', '.join(sources)})")
        elif verdict == "clean":
            lines.append(f"- Hash {value}: Clean")

    # Process URLs
    urls = enrichment_data.get("results", {}).get("urls", [])
    for url in urls:
        verdict = url.get("verdict", "unknown")
        value = url.get("value", "")[:50] + "..." if len(url.get("value", "")) > 50 else url.get("value", "")
        sources = url.get("sources", [])
        confidence = url.get("confidence", 0)
        if verdict in ("malicious", "suspicious"):
            lines.append(f"- URL {value}: {verdict.upper()} (confidence: {confidence}%, sources: {', '.join(sources)})")

    # Summary stats
    summary = enrichment_data.get("summary", {})
    if summary:
        malicious = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        clean = summary.get("clean", 0)
        unknown = summary.get("unknown", 0)
        lines.insert(0, f"Enrichment Summary: {malicious} malicious, {suspicious} suspicious, {clean} clean, {unknown} unknown")

    if not lines:
        return "Enrichment completed but no notable findings"

    return "\n".join(lines)


def get_phishing_indicators_summary(phishing_data: dict) -> str:
    """
    Format phishing indicator data into a concise summary for the prompt.

    This extracts social engineering signals that allow T1 to detect
    brand impersonation phishing even when IOCs are clean.

    Args:
        phishing_data: Dictionary of phishing evidence from _extract_phishing_evidence

    Returns:
        Formatted phishing indicators string
    """
    if not phishing_data or not phishing_data.get('detected'):
        return "No phishing indicators detected"

    lines = []

    # Brand impersonation
    brand_info = phishing_data.get('brand_impersonation', {})
    if brand_info.get('detected'):
        brand = brand_info.get('brand', 'Unknown')
        matches = brand_info.get('matches', [])
        lines.append(f"⚠️ BRAND IMPERSONATION: {brand.upper()}")
        if matches:
            lines.append(f"   Matched patterns: {', '.join(matches[:5])}")

    # Language signals
    lang_signals = phishing_data.get('language_signals', {})
    active_signals = []
    if lang_signals.get('urgency'):
        active_signals.append("URGENCY")
    if lang_signals.get('credential_request'):
        active_signals.append("CREDENTIAL_REQUEST")
    if lang_signals.get('account_threat'):
        active_signals.append("ACCOUNT_THREAT")
    if lang_signals.get('action_required'):
        active_signals.append("ACTION_REQUIRED")

    if active_signals:
        lines.append(f"⚠️ LANGUAGE SIGNALS: {', '.join(active_signals)}")

    # User interaction (critical for severity)
    user_action = phishing_data.get('user_interaction', {})
    if user_action.get('clicked'):
        lines.append("🚨 USER CLICKED: Link was clicked")
    if user_action.get('credentials_entered'):
        lines.append("🚨 CREDENTIALS ENTERED: User submitted credentials")
    if user_action.get('downloaded'):
        lines.append("🚨 ATTACHMENT DOWNLOADED: User downloaded attachment")

    # Email authentication failures
    auth_failures = phishing_data.get('email_auth_failures', {})
    auth_issues = []
    if auth_failures.get('spf_fail'):
        auth_issues.append("SPF_FAIL")
    if auth_failures.get('dkim_fail'):
        auth_issues.append("DKIM_FAIL")
    if auth_failures.get('dmarc_fail'):
        auth_issues.append("DMARC_FAIL")

    if auth_issues:
        lines.append(f"⚠️ EMAIL AUTH FAILURES: {', '.join(auth_issues)}")

    # Overall confidence from extraction
    confidence = phishing_data.get('overall_confidence', 0)
    if confidence > 0:
        lines.append(f"📊 Social Engineering Confidence: {confidence}%")

    if not lines:
        return "No phishing indicators detected"

    return "\n".join(lines)
