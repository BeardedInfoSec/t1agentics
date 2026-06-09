# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
AI Triage Service

Performs AI-powered L1 triage on alerts after enrichment completes.
Stores verdicts on alert records for visibility.

This service bridges the gap between:
- Enrichment completing (IOC data collected)
- AI analysis (understanding what the data means)
- User visibility (seeing the AI's decision)
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Static triage system prompt — eligible for Anthropic prompt caching.
# Sent in the `system` field with cache_control: ephemeral so subsequent calls
# read these ~1.5K tokens at 10% cost instead of full input rate.
# Do NOT interpolate per-alert data into this string — the cache hash is
# computed over the entire system block, so any variation breaks the cache.
# ══════════════════════════════════════════════════════════════════════════════
_TRIAGE_SYSTEM_PROMPT = """You are a Tier 1 SOC Analyst performing initial triage. Your job is to quickly classify alerts based on the evidence provided in each user message.

═══════════════════════════════════════════════════════════════════════════
DECISION CRITERIA (FOLLOW STRICTLY)
═══════════════════════════════════════════════════════════════════════════

VERDICT = MALICIOUS (confidence >= 0.85) if ANY:
  - Malicious IOC count > 0 (already flagged by threat intel)
  - Known malware family detected (emotet, trickbot, cobalt, etc.)
  - Command line contains: powershell -enc, IEX, DownloadString, reverse shell patterns
  - Decoded content reveals C2 communication, credential theft, or persistence
  - SOCIAL ENGINEERING: Brand impersonation + credential request (IOCs may be clean!)
  - SOCIAL ENGINEERING: Typosquatting domain detected
  - User clicked link AND credentials may have been entered

VERDICT = SOCIAL_ENGINEERING (confidence 0.70-0.90) if:
  - Brand impersonation detected (Microsoft, Google, Apple, etc.) AND clean IOCs
  - Credential request language + urgency tactics (2+ signals)
  - SPF/DKIM authentication failures (spoofing indicator)
  - Lookalike domain impersonating trusted brand
  IMPORTANT: This is a MALICIOUS intent, just not IOC-based. Treat as threat.

VERDICT = SUSPICIOUS (confidence 0.60-0.84) if ANY:
  - Suspicious IOC count > 0 but no malicious
  - Newly registered sender domain (< 1 year)
  - Subject line uses urgency tactics ("verify now", "account suspended")
  - Obfuscated/encoded content present but not clearly malicious
  - Unusual process spawning patterns (cmd.exe -> powershell.exe)
  - Only 1 social engineering signal (not enough for SOCIAL_ENGINEERING verdict)

VERDICT = BENIGN (confidence >= 0.80) if ALL:
  - Zero malicious IOCs AND zero suspicious IOCs
  - Sender is on trusted allowlist OR from known internal domain
  - No phishing indicators detected
  - No encoded/obfuscated content
  - Alert matches known false positive pattern

VERDICT = FALSE_POSITIVE (confidence >= 0.85) if:
  - Matches known phishing test pattern
  - Legitimate IT admin activity with approval
  - Security scanning tool triggering detection

VERDICT = NEEDS_INVESTIGATION (confidence 0.40-0.60) if:
  - Insufficient data to make determination
  - Mixed signals (some clean, some suspicious)
  - Requires additional context from Tier 2

═══════════════════════════════════════════════════════════════════════════
RESPONSE FORMAT (JSON ONLY)
═══════════════════════════════════════════════════════════════════════════
Respond with ONLY valid JSON, no explanation text:
{
  "verdict": "MALICIOUS|SOCIAL_ENGINEERING|SUSPICIOUS|BENIGN|FALSE_POSITIVE|NEEDS_INVESTIGATION",
  "confidence": 0.0-1.0,
  "summary": "2-3 sentence summary. Include: what the alert is (email/EDR/network/etc), the source/sender, key identifiers (subject, process, hostname), what was checked, and why you reached this verdict. Be specific - an analyst should understand the alert without expanding it.",
  "key_findings": ["Finding 1", "Finding 2", "Finding 3", "Finding 4", "Finding 5 (aim for 5-8 findings covering: source identity, authentication/trust signals, IOC analysis results, behavioral indicators, and risk assessment)"],
  "decoded_iocs": {"ips": [], "urls": [], "domains": []},
  "requires_escalation": true/false,
  "threat_type": "phishing|social_engineering|malware|c2|credential_theft|data_exfil|none|unknown",
  "display_widgets": [
    {
      "title": "Widget Title",
      "color": "#hex_color",
      "items": ["item1", "item2", {"label": "complex item", "priority": "high"}]
    }
  ]
}

DISPLAY_WIDGETS GUIDELINES:
- Create widgets for ANY important findings you want the analyst to see
- Each widget has: title (string), color (hex), items (array of strings or objects)
- Widget colors: #ef4444 (critical), #f59e0b (warning), #3b82f6 (info), #22c55e (good), #8b5cf6 (ioc)
- Be dynamic - create widgets based on what you actually found, not hardcoded categories
- Items can be simple strings or objects with {label, priority, icon, link}
- DO NOT create a widget that just says "Manual review recommended" - be specific about WHAT to review

SUGGESTED WIDGET TYPES (use as appropriate):
- Key Findings: Critical observations from analysis
- Malicious IOCs: Only include IOCs confirmed as malicious (not suspicious)
- MITRE Techniques: ATT&CK techniques identified
- Risk Factors: Why this alert is concerning
- Recommended Actions: Specific next steps
- Timeline Summary: Key events in sequence (e.g., "10:30 - Initial access", "10:32 - Lateral movement")
- Related Context: Any related alerts, campaigns, or patterns you identify
- Actor Info: Threat actor details if known"""


@asynccontextmanager
async def _admin_conn():
    """Get a DB connection with platform admin privileges for background triage.

    The triage service can be called from background jobs (outside HTTP request
    context), so RLS blocks queries. This sets app.is_platform_admin to bypass.
    """
    from services.postgres_db import postgres_db

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        try:
            yield conn
        finally:
            try:
                await conn.execute("RESET app.is_platform_admin")
            except Exception:
                pass

# Token tracking import (lazy loaded to avoid circular imports)
_token_tracker = None

async def _get_token_tracker():
    """Get token tracker instance (lazy load)"""
    global _token_tracker
    if _token_tracker is None:
        try:
            from services.token_tracking import get_token_tracker
            from services.postgres_db import postgres_db
            _token_tracker = get_token_tracker()
            if postgres_db and postgres_db.connected:
                _token_tracker.set_db(postgres_db)
        except Exception as e:
            logger.warning(f"Could not initialize token tracker: {e}")
    return _token_tracker


class AITriageService:
    """
    AI Triage Service

    Runs AI analysis on alerts after enrichment and stores verdicts.
    Makes the AI's decision visible to analysts.

    ═══════════════════════════════════════════════════════════════════════════════
    3-PHASE MICRO-STAGING ARCHITECTURE (FP Reduction)
    ═══════════════════════════════════════════════════════════════════════════════

    PHASE 1 - INSTANT RULES (No LLM, <10ms):
        - Phishing test allowlist → BENIGN
        - Known malware from trusted EDR → MALICIOUS (auto-confirm)
        - Internal domains (.corp, .local) → BENIGN
        - Exact legitimate brand domain + clean enrichment → BENIGN

    PHASE 2 - HEURISTIC PRE-FILTER (No LLM, <100ms):
        - Verified trusted sender + clean enrichment → BENIGN
        - Malicious IOC in enrichment → FLAG for Phase 3
        - Lookalike domain / new domain / suspicious TLD → FLAG for Phase 3
        - No flags triggered → BENIGN

    PHASE 3 - LLM ANALYSIS (Only if flagged, 1-2s):
        - Full context assembly with gated intent analysis
        - Specialized prompt based on alert flags
        - Verdict with confidence and uncertainty factors

    ═══════════════════════════════════════════════════════════════════════════════
    """

    def __init__(self):
        self.enabled = True
        self.min_confidence_for_auto_close = 0.90  # Auto-close if 90%+ confidence benign
        self.model = os.getenv('AI_TRIAGE_MODEL', 'claude-sonnet-4-20250514')
        # Database connection for AI provider config lookup
        try:
            from services.postgres_db import postgres_db
            self.db = postgres_db
        except Exception:
            self.db = None

    # ═══════════════════════════════════════════════════════════════════════════════
    # PHASE 1 & 2 HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════════════

    def _extract_sender_domain(self, email_sender: str) -> Optional[str]:
        """Extract domain from email address."""
        if not email_sender or '@' not in email_sender:
            return None
        return email_sender.lower().split('@')[-1].strip().rstrip('>')

    def _is_enrichment_clean(self, enrichment_data: Dict[str, Any]) -> bool:
        """
        Check if all IOC enrichment results are clean (no malicious indicators).

        Returns True if:
        - No malicious verdicts in any enrichment
        - No high-severity findings
        """
        if not enrichment_data:
            return True

        results = enrichment_data.get('results', {})

        # Check each IOC category
        for category in ['ips', 'domains', 'hashes', 'urls']:
            items = results.get(category, [])
            for item in items:
                if isinstance(item, dict):
                    verdict = item.get('verdict', '').lower()
                    if verdict in ('malicious', 'suspicious'):
                        return False
                    if item.get('malicious', False):
                        return False
                    # Check for high detection counts (VirusTotal style)
                    if item.get('positives', 0) >= 3:
                        return False

        # Check summary if available
        summary = enrichment_data.get('summary', {})
        if summary.get('malicious', 0) > 0:
            return False

        return True

    def _has_malicious_iocs(self, enrichment_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Check if enrichment contains malicious IOC verdicts.

        Returns:
            Tuple of (has_malicious: bool, malicious_iocs: List[str])
        """
        malicious_iocs = []
        if not enrichment_data:
            return False, malicious_iocs

        results = enrichment_data.get('results', {})

        for category in ['ips', 'domains', 'hashes', 'urls']:
            items = results.get(category, [])
            for item in items:
                if isinstance(item, dict):
                    verdict = item.get('verdict', '').lower()
                    value = item.get('value', item.get('ip', item.get('domain', item.get('hash', 'unknown'))))
                    if verdict == 'malicious' or item.get('malicious', False):
                        malicious_iocs.append(f"{category}:{value}")
                    # High VT detection count
                    if item.get('positives', 0) >= 5:
                        malicious_iocs.append(f"{category}:{value} (VT:{item.get('positives')})")

        return len(malicious_iocs) > 0, malicious_iocs

    # ═══════════════════════════════════════════════════════════════════════════════
    # SECURITY GUARDS - Added 2026-01-26 for edge case hardening
    # ═══════════════════════════════════════════════════════════════════════════════

    def _has_email_auth_failures(self, raw_event: Dict[str, Any]) -> Tuple[bool, Dict[str, bool]]:
        """
        SECURITY GUARD: Check for email authentication failures that indicate spoofing.

        If SPF/DKIM/DMARC fail, the email may be spoofed even if sender domain
        appears to be legitimate. This MUST block fast-path for legitimate domains.

        Args:
            raw_event: Raw event data containing email headers

        Returns:
            Tuple of (has_failures: bool, failure_details: dict)
        """
        failures = {
            'spf_fail': False,
            'dkim_fail': False,
            'dmarc_fail': False,
            'spoofing_likely': False
        }

        if not raw_event:
            return False, failures

        # Check authentication_results field
        auth_results = str(raw_event.get('authentication_results', '')).lower()

        # Check email_headers for auth results
        email_headers = raw_event.get('email_headers', {})
        if isinstance(email_headers, dict):
            auth_header = str(email_headers.get('Authentication-Results', '')).lower()
            auth_results = f"{auth_results} {auth_header}"

        # Parse authentication results
        failures['spf_fail'] = 'spf=fail' in auth_results or 'spf=softfail' in auth_results
        failures['dkim_fail'] = 'dkim=fail' in auth_results
        failures['dmarc_fail'] = 'dmarc=fail' in auth_results

        # High spoofing likelihood if both SPF and DKIM fail
        failures['spoofing_likely'] = failures['spf_fail'] and failures['dkim_fail']

        has_any_failure = any([failures['spf_fail'], failures['dkim_fail'], failures['dmarc_fail']])
        return has_any_failure, failures

    def _has_email_auth_passed(self, raw_event: Dict[str, Any]) -> Tuple[bool, Dict[str, bool]]:
        """
        AUTH-BASED TRUST: Check if email authentication (SPF+DKIM+DMARC) all passed.

        If all three pass, the sender is cryptographically verified as legitimate.
        This is MORE reliable than domain allowlists because it can't be spoofed.

        Args:
            raw_event: Raw event data containing email headers

        Returns:
            Tuple of (all_passed: bool, auth_details: dict)
        """
        auth_status = {
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False,
            'all_passed': False,
            'auth_present': False
        }

        if not raw_event:
            return False, auth_status

        # Check authentication_results field
        auth_results = str(raw_event.get('authentication_results', '')).lower()

        # Check email_headers for auth results
        email_headers = raw_event.get('email_headers', {})
        if isinstance(email_headers, dict):
            auth_header = str(email_headers.get('Authentication-Results', '')).lower()
            auth_results = f"{auth_results} {auth_header}"

        # Check if any authentication info is present
        auth_status['auth_present'] = bool(auth_results.strip())

        # Parse authentication results - check for explicit passes
        auth_status['spf_pass'] = 'spf=pass' in auth_results
        auth_status['dkim_pass'] = 'dkim=pass' in auth_results
        auth_status['dmarc_pass'] = 'dmarc=pass' in auth_results

        # All must pass for full authentication
        auth_status['all_passed'] = (
            auth_status['spf_pass'] and
            auth_status['dkim_pass'] and
            auth_status['dmarc_pass']
        )

        if auth_status['all_passed']:
            logger.info(f"[AUTH_TRUST] Email authentication PASSED: SPF={auth_status['spf_pass']}, DKIM={auth_status['dkim_pass']}, DMARC={auth_status['dmarc_pass']}")

        return auth_status['all_passed'], auth_status

    def _has_user_interaction_risk(self, raw_event: Dict[str, Any]) -> Tuple[bool, Dict[str, bool]]:
        """
        SECURITY GUARD: Check if user took risky actions (clicked, entered credentials).

        If user clicked links or entered credentials, this is a security incident
        regardless of sender legitimacy. MUST block fast-path.

        Args:
            raw_event: Raw event data

        Returns:
            Tuple of (has_risk: bool, interaction_details: dict)
        """
        interactions = {
            'clicked': False,
            'credentials_entered': False,
            'downloaded': False,
            'replied': False
        }

        if not raw_event:
            return False, interactions

        interactions['clicked'] = bool(raw_event.get('clicked') or raw_event.get('user_clicked'))
        interactions['credentials_entered'] = bool(raw_event.get('credentials_entered'))
        interactions['downloaded'] = bool(raw_event.get('attachment_downloaded') or raw_event.get('downloaded'))
        interactions['replied'] = bool(raw_event.get('replied'))

        # Credentials entered is HIGH RISK - always escalate
        # Clicked is MEDIUM RISK - should escalate for investigation
        has_risk = interactions['credentials_entered'] or interactions['clicked']
        return has_risk, interactions

    def _check_phase1_instant_rules(
        self,
        alert_id: str,
        sender_domain: Optional[str],
        sender_trust_info: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        raw_event: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        PHASE 1: Instant rules - no LLM required.

        SECURITY HARDENING (2026-01-26):
        - Auth failures (SPF/DKIM/DMARC) BLOCK fast-path for legitimate domains
        - User interaction (clicked/credentials) BLOCKS fast-path
        - These override domain legitimacy to catch spoofing and compromised accounts

        Returns verdict dict if rule matches, None otherwise.
        """
        from services.sender_trust_service import (
            is_legitimate_brand_domain,
            is_internal_domain,
            LEGITIMATE_BRAND_DOMAINS
        )

        # ═══════════════════════════════════════════════════════════════════════════
        # SECURITY GUARDS - Check for spoofing/risk signals BEFORE any fast-path
        # ═══════════════════════════════════════════════════════════════════════════

        # Guard 1: Email authentication failures indicate spoofing - BLOCK fast-path
        has_auth_failures, auth_details = self._has_email_auth_failures(raw_event)
        if has_auth_failures:
            logger.warning(
                f"Alert {alert_id}: SECURITY GUARD - Email auth failures detected, "
                f"blocking ALL fast-paths. SPF:{auth_details['spf_fail']} "
                f"DKIM:{auth_details['dkim_fail']} DMARC:{auth_details['dmarc_fail']}"
            )
            # Return None to force Phase 2/3 analysis
            return None

        # Guard 2: User interaction (clicked/credentials) - BLOCK fast-path
        has_user_risk, interaction_details = self._has_user_interaction_risk(raw_event)
        if has_user_risk:
            logger.warning(
                f"Alert {alert_id}: SECURITY GUARD - User interaction risk detected, "
                f"blocking fast-path. Clicked:{interaction_details['clicked']} "
                f"Credentials:{interaction_details['credentials_entered']}"
            )
            # Return None to force Phase 2/3 analysis
            return None

        # ═══════════════════════════════════════════════════════════════════════════
        # FAST-PATH RULES (only if security guards pass)
        # ═══════════════════════════════════════════════════════════════════════════

        # Rule 1: Phishing test already handled before this method is called

        # Rule 2: Internal domain → BENIGN (no external analysis needed)
        # GUARD: Only if email originated internally (check received chain if available)
        if sender_domain and is_internal_domain(sender_domain):
            # Additional check: Verify email didn't come from external source claiming internal
            received_chain = raw_event.get('received_chain', [])
            if received_chain and len(received_chain) > 0:
                first_hop = str(received_chain[0]).lower() if received_chain else ''
                # If first hop mentions external gateway, this might be external email with internal domain
                if any(ext in first_hop for ext in ['external', 'inbound', 'gateway']):
                    logger.warning(f"Alert {alert_id}: Internal domain but external origin detected - blocking fast-path")
                    return None

            logger.info(f"Alert {alert_id}: PHASE 1 FAST-PATH - Internal domain '{sender_domain}'")
            email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
            email_subject = raw_event.get('subject', '')
            email_recipient = raw_event.get('to') or raw_event.get('recipient', '')

            summary_parts = [f"Internal email from {sender_domain}."]
            if email_subject:
                summary_parts.append(f"Subject: \"{email_subject}\".")
            summary_parts.append("Internal communications are trusted by policy and do not require phishing analysis.")

            key_findings = [f"Sender domain '{sender_domain}' is internal"]
            if email_sender:
                key_findings.append(f"From: {email_sender}")
            if email_recipient:
                key_findings.append(f"To: {email_recipient}")
            if email_subject:
                key_findings.append(f"Subject: \"{email_subject}\"")
            key_findings.extend([
                "Internal domains are trusted by policy",
                "Email authentication passed (no SPF/DKIM/DMARC failures)",
            ])

            return {
                "status": "completed",
                "verdict": "BENIGN",
                "confidence": 0.95,
                "disposition": "FALSE_POSITIVE",
                "summary": " ".join(summary_parts),
                "key_findings": key_findings,
                "recommended_actions": [],
                "requires_escalation": False,
                # CANONICAL SCALE: high value = treating this as a real
                # threat would be a false positive. BENIGN -> high (0.9+);
                # MALICIOUS -> low (0.1-); SUSPICIOUS -> mid (0.4-0.6).
                # Was 0.02 (inverted: "low chance THIS BENIGN VERDICT is wrong").
                "false_positive_likelihood": 0.98,
                "threat_type": "none",
                "fast_path": True,
                "fast_path_phase": 1,
                "fast_path_reason": "internal_domain",
                "security_guards_passed": ["auth_check", "user_interaction_check"],
                "timestamp": datetime.utcnow().isoformat()
            }

        # Rule 3: Auth-Verified Sender (SPF+DKIM+DMARC pass) + Clean Enrichment → BENIGN
        # This is MORE secure than domain allowlists because auth can't be spoofed
        auth_passed, auth_status = self._has_email_auth_passed(raw_event)
        if auth_passed:
            enrichment_clean = self._is_enrichment_clean(enrichment_data)
            if enrichment_clean:
                logger.info(f"Alert {alert_id}: PHASE 1 FAST-PATH - Email auth PASSED (SPF+DKIM+DMARC) + clean enrichment")

                # Build enriched context for the summary
                email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
                email_subject = raw_event.get('subject', '')
                email_recipient = raw_event.get('to') or raw_event.get('recipient', '')
                extracted_iocs = raw_event.get('_extracted', {}).get('iocs', {})
                ioc_counts = {k: len(v) for k, v in extracted_iocs.items() if v} if extracted_iocs else {}
                total_iocs = sum(ioc_counts.values())
                enrichment_summary = enrichment_data.get('summary', {})
                total_enriched = enrichment_summary.get('total_enriched', 0)
                urls_found = len(extracted_iocs.get('urls', [])) if extracted_iocs else 0
                domains_found = len(extracted_iocs.get('domains', [])) if extracted_iocs else 0

                summary_parts = [
                    f"Email from cryptographically verified sender ({sender_domain}).",
                    "SPF/DKIM/DMARC all passed - sender cannot be spoofed.",
                ]
                if email_subject:
                    summary_parts.append(f"Subject: \"{email_subject}\".")
                if total_enriched > 0:
                    summary_parts.append(f"{total_enriched} IOCs enriched, all clean.")
                elif total_iocs > 0:
                    summary_parts.append(f"{total_iocs} IOCs extracted, no malicious indicators.")
                else:
                    summary_parts.append("No malicious indicators in IOC enrichment.")

                key_findings = [
                    f"Sender domain '{sender_domain}' is CRYPTOGRAPHICALLY VERIFIED via email auth",
                ]
                if email_sender:
                    key_findings.append(f"From: {email_sender}")
                if email_recipient:
                    key_findings.append(f"To: {email_recipient}")
                if email_subject:
                    key_findings.append(f"Subject: \"{email_subject}\"")
                key_findings.extend([
                    f"SPF: {auth_status.get('spf', 'PASS').upper()} - sender IP is authorized to send for this domain",
                    f"DKIM: {auth_status.get('dkim', 'PASS').upper()} - email signature is valid and unmodified",
                    f"DMARC: {auth_status.get('dmarc', 'PASS').upper()} - domain policy alignment verified",
                ])
                if total_enriched > 0:
                    clean_count = enrichment_summary.get('clean', 0)
                    unknown_count = enrichment_summary.get('unknown', 0)
                    parts = []
                    if clean_count: parts.append(f"{clean_count} clean")
                    if unknown_count: parts.append(f"{unknown_count} unknown")
                    key_findings.append(f"IOC enrichment: {total_enriched} checked ({', '.join(parts) if parts else 'all clean'})")
                elif total_iocs > 0:
                    ioc_detail = ', '.join(f"{v} {k}" for k, v in ioc_counts.items())
                    key_findings.append(f"IOCs extracted: {ioc_detail} - no malicious indicators")
                if urls_found:
                    key_findings.append(f"{urls_found} URLs found in email body - all clean")
                if domains_found:
                    key_findings.append(f"{domains_found} domains referenced - no threat intel hits")
                key_findings.append("No user interaction risk (no clicks, no credentials entered)")

                return {
                    "status": "completed",
                    "verdict": "BENIGN",
                    "confidence": 0.92,
                    "disposition": "FALSE_POSITIVE",
                    "summary": " ".join(summary_parts),
                    "key_findings": key_findings,
                    "recommended_actions": [],
                    "requires_escalation": False,
                    # Canonical scale: high = treating-as-threat-would-be-FP. Was 0.03.
                    "false_positive_likelihood": 0.95,
                    "threat_type": "none",
                    "fast_path": True,
                    "fast_path_phase": 1,
                    "fast_path_reason": "auth_verified_clean_enrichment",
                    "sender_legitimacy_verified": True,
                    "intent_analysis_skipped": True,
                    "email_auth_status": auth_status,
                    "security_guards_passed": ["auth_all_passed", "user_interaction_check", "enrichment_clean"],
                    "timestamp": datetime.utcnow().isoformat()
                }

        return None

    def _check_phase2_heuristic_prefilter(
        self,
        alert_id: str,
        sender_domain: Optional[str],
        sender_trust_info: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        raw_event: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """
        PHASE 2: Heuristic pre-filter - no LLM required.

        SECURITY HARDENING (2026-01-26):
        - Auth failures and user interactions are flagged for Phase 3
        - These signals escalate even for trusted senders

        Returns:
            Tuple of (verdict_dict or None, flags_for_phase3: List[str])
        """
        from services.sender_trust_service import (
            has_suspicious_tld,
            is_legitimate_brand_domain,
            LEGITIMATE_BRAND_DOMAINS
        )

        flags_for_phase3 = []

        # ═══════════════════════════════════════════════════════════════════════════
        # SECURITY GUARDS - Check for signals that MUST escalate to Phase 3
        # ═══════════════════════════════════════════════════════════════════════════

        # Guard 1: Email authentication failures - add as flag (Phase 1 may have blocked, but capture for Phase 3)
        has_auth_failures, auth_details = self._has_email_auth_failures(raw_event)
        if has_auth_failures:
            auth_flag = []
            if auth_details['spf_fail']:
                auth_flag.append('SPF_FAIL')
            if auth_details['dkim_fail']:
                auth_flag.append('DKIM_FAIL')
            if auth_details['dmarc_fail']:
                auth_flag.append('DMARC_FAIL')
            flags_for_phase3.append(f"auth_failures:{','.join(auth_flag)}")
            logger.warning(f"Alert {alert_id}: PHASE 2 - Auth failures detected: {auth_flag}")

        # Guard 2: User interaction risk - CRITICAL flag
        has_user_risk, interaction_details = self._has_user_interaction_risk(raw_event)
        if has_user_risk:
            interaction_flag = []
            if interaction_details['credentials_entered']:
                interaction_flag.append('CREDENTIALS_ENTERED')
            if interaction_details['clicked']:
                interaction_flag.append('CLICKED')
            if interaction_details['downloaded']:
                interaction_flag.append('DOWNLOADED')
            flags_for_phase3.append(f"user_interaction:{','.join(interaction_flag)}")
            logger.warning(f"Alert {alert_id}: PHASE 2 - User interaction risk: {interaction_flag}")

        # Check for malicious IOCs in enrichment
        has_malicious, malicious_iocs = self._has_malicious_iocs(enrichment_data)
        if has_malicious:
            flags_for_phase3.append(f"malicious_iocs:{','.join(malicious_iocs[:3])}")
            logger.info(f"Alert {alert_id}: PHASE 2 - Malicious IOCs detected, flagging for Phase 3")

        # SECURITY: If auth failures OR user risk, BLOCK Phase 2 fast-path even for trusted senders
        security_escalation_required = has_auth_failures or has_user_risk or has_malicious

        # Check for verified trusted sender + clean enrichment → BENIGN
        # BUT: Only if no security escalation is required
        if sender_trust_info.get('is_trusted_sender') and not security_escalation_required:
            trust_result = sender_trust_info.get('trusted_sender_result', {})
            trust_level = trust_result.get('trust_level', '')

            if trust_level == 'verified' and self._is_enrichment_clean(enrichment_data) and not has_malicious:
                logger.info(f"Alert {alert_id}: PHASE 2 FAST-PATH - Verified trusted sender + clean enrichment")
                org_name = trust_result.get('organization', 'Unknown')
                email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
                email_subject = raw_event.get('subject', '')
                email_recipient = raw_event.get('to') or raw_event.get('recipient', '')
                extracted_iocs = raw_event.get('_extracted', {}).get('iocs', {})
                total_iocs = sum(len(v) for v in extracted_iocs.values() if v) if extracted_iocs else 0
                enrichment_summary = enrichment_data.get('summary', {})
                total_enriched = enrichment_summary.get('total_enriched', 0)

                summary_parts = [f"Email from verified trusted sender ({org_name})."]
                if email_subject:
                    summary_parts.append(f"Subject: \"{email_subject}\".")
                if total_enriched > 0:
                    summary_parts.append(f"{total_enriched} IOCs enriched, all clean.")
                summary_parts.append("No malicious indicators detected.")

                key_findings = [
                    f"Sender is verified trusted: {trust_result.get('reason', 'Allowlist match')}",
                ]
                if email_sender:
                    key_findings.append(f"From: {email_sender}")
                if email_recipient:
                    key_findings.append(f"To: {email_recipient}")
                if email_subject:
                    key_findings.append(f"Subject: \"{email_subject}\"")
                key_findings.append(f"Trust level: verified ({org_name})")
                if total_enriched > 0:
                    clean_count = enrichment_summary.get('clean', 0)
                    unknown_count = enrichment_summary.get('unknown', 0)
                    parts = []
                    if clean_count: parts.append(f"{clean_count} clean")
                    if unknown_count: parts.append(f"{unknown_count} unknown")
                    key_findings.append(f"IOC enrichment: {total_enriched} checked ({', '.join(parts) if parts else 'all clean'})")
                elif total_iocs > 0:
                    key_findings.append(f"{total_iocs} IOCs extracted - no malicious indicators")

                return {
                    "status": "completed",
                    "verdict": "BENIGN",
                    "confidence": 0.90,
                    "disposition": "FALSE_POSITIVE",
                    "summary": " ".join(summary_parts),
                    "key_findings": key_findings,
                    "recommended_actions": [],
                    "requires_escalation": False,
                    # Canonical scale. Was 0.05 (inverted).
                    "false_positive_likelihood": 0.93,
                    "threat_type": "none",
                    "fast_path": True,
                    "fast_path_phase": 2,
                    "fast_path_reason": "verified_trusted_sender_clean_enrichment",
                    "trusted_sender": trust_result,
                    "timestamp": datetime.utcnow().isoformat()
                }, []

        # Check for suspicious TLD
        if sender_domain and has_suspicious_tld(sender_domain):
            flags_for_phase3.append(f"suspicious_tld:{sender_domain}")
            logger.info(f"Alert {alert_id}: PHASE 2 - Suspicious TLD detected: {sender_domain}")

        # Check for new domain (via WHOIS if available)
        domain_age_days = sender_trust_info.get('domain_age_days')
        if domain_age_days is not None and domain_age_days < 30:
            flags_for_phase3.append(f"new_domain:{domain_age_days}_days")
            logger.info(f"Alert {alert_id}: PHASE 2 - New domain detected: {domain_age_days} days old")

        # Check domain age validity from sender trust info
        if sender_trust_info.get('domain_age_valid') is False:
            domain_age_msg = sender_trust_info.get('domain_age_message', 'Unknown')
            flags_for_phase3.append(f"domain_age_invalid:{domain_age_msg}")

        # If no flags → Check auth-based trust for BENIGN (skip Phase 3)
        if not flags_for_phase3:
            # Auth-based trust: if SPF+DKIM+DMARC all pass, sender is verified
            auth_passed, auth_status = self._has_email_auth_passed(raw_event)
            if auth_passed:
                logger.info(f"Alert {alert_id}: PHASE 2 FAST-PATH - Email auth PASSED, no flags")

                # Build enriched context
                email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
                email_subject = raw_event.get('subject', '')
                email_recipient = raw_event.get('to') or raw_event.get('recipient', '')
                extracted_iocs = raw_event.get('_extracted', {}).get('iocs', {})
                ioc_counts = {k: len(v) for k, v in extracted_iocs.items() if v} if extracted_iocs else {}
                total_iocs = sum(ioc_counts.values())
                enrichment_summary = enrichment_data.get('summary', {})
                total_enriched = enrichment_summary.get('total_enriched', 0)

                summary_parts = [f"No suspicious indicators detected. Sender ({sender_domain}) is cryptographically verified (SPF+DKIM+DMARC pass)."]
                if email_subject:
                    summary_parts.append(f"Subject: \"{email_subject}\".")
                if total_enriched > 0:
                    summary_parts.append(f"{total_enriched} IOCs enriched, all clean.")
                elif total_iocs > 0:
                    summary_parts.append(f"{total_iocs} IOCs extracted, no threats found.")

                key_findings = [
                    "No suspicious signals in Phase 2 heuristic analysis",
                    f"Sender '{sender_domain}' CRYPTOGRAPHICALLY VERIFIED via email auth",
                ]
                if email_sender:
                    key_findings.append(f"From: {email_sender}")
                if email_recipient:
                    key_findings.append(f"To: {email_recipient}")
                if email_subject:
                    key_findings.append(f"Subject: \"{email_subject}\"")
                key_findings.append(f"SPF: {auth_status.get('spf', 'PASS').upper()}, DKIM: {auth_status.get('dkim', 'PASS').upper()}, DMARC: {auth_status.get('dmarc', 'PASS').upper()}")
                if total_enriched > 0:
                    clean_count = enrichment_summary.get('clean', 0)
                    unknown_count = enrichment_summary.get('unknown', 0)
                    parts = []
                    if clean_count: parts.append(f"{clean_count} clean")
                    if unknown_count: parts.append(f"{unknown_count} unknown")
                    key_findings.append(f"IOC enrichment: {total_enriched} checked ({', '.join(parts) if parts else 'all clean'})")
                elif total_iocs > 0:
                    ioc_detail = ', '.join(f"{v} {k}" for k, v in ioc_counts.items())
                    key_findings.append(f"IOCs extracted: {ioc_detail} - no threats found")

                return {
                    "status": "completed",
                    "verdict": "BENIGN",
                    "confidence": 0.88,
                    "disposition": "FALSE_POSITIVE",
                    "summary": " ".join(summary_parts),
                    "key_findings": key_findings,
                    "recommended_actions": [],
                    "requires_escalation": False,
                    # Canonical scale. Was 0.05 (inverted).
                    "false_positive_likelihood": 0.92,
                    "threat_type": "none",
                    "fast_path": True,
                    "fast_path_phase": 2,
                    "fast_path_reason": "no_flags_auth_verified",
                    "email_auth_status": auth_status,
                    "timestamp": datetime.utcnow().isoformat()
                }, []

        # Has flags → proceed to Phase 3
        return None, flags_for_phase3

    async def triage_alert(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        alert_flags: Optional[List[str]] = None,
        template_prompt: Optional[str] = None,
        template_max_tokens: Optional[int] = None,
        custom_instructions: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform AI triage on an alert after enrichment.

        Args:
            alert_id: The alert ID
            alert_data: The alert data
            enrichment_data: The enrichment results
            alert_flags: Optional list of alert classification flags (phishing, malware, etc.)
                        Used for selecting specialized prompts when ENABLE_FLAG_BASED_TRIAGE is enabled.
            template_prompt: Optional curated system prompt from analysis template (guardrails).
            template_max_tokens: Optional max token cap from template (guardrails).
            custom_instructions: Optional sanitized additional instructions (max 500 chars).

        Returns:
            Triage result with verdict, confidence, reasoning
        """
        if not self.enabled:
            return {"status": "disabled", "verdict": None}

        try:
            # NOTE: We no longer skip T1 for alerts linked to investigations.
            # The T1 verdict is valuable for investigation context and metrics.
            # Previously we skipped to avoid re-processing, but this caused
            # verdict=NULL for correlated alerts. Now we run T1 always.
            if alert_data.get('investigation_id'):
                logger.info(f"Alert {alert_id}: Linked to investigation {alert_data.get('investigation_id')} - proceeding with AI triage for verdict")

            logger.info(f"Alert {alert_id}: Starting AI triage")

            # Extract email info from alert for sender trust checks
            raw_event = alert_data.get('raw_event', {})
            if isinstance(raw_event, str):
                try:
                    raw_event = json.loads(raw_event)
                except:
                    raw_event = {}
            # Ensure raw_event is never None
            if raw_event is None:
                raw_event = {}

            email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
            email_subject = raw_event.get('subject', '')

            # ========== PRE-TRIAGE: Check sender trust and phishing tests ==========
            sender_trust_info = await self._check_sender_trust(
                alert_id, email_sender, email_subject, enrichment_data
            )

            # If this is a phishing test, auto-close immediately
            if sender_trust_info.get('is_phishing_test'):
                phishing_result = sender_trust_info['phishing_test_result']
                vendor = phishing_result.get('vendor', 'Unknown')
                test_name = phishing_result.get('test_name', 'N/A')

                triage_result = {
                    "status": "completed",
                    "verdict": "BENIGN",
                    "confidence": 0.99,
                    "disposition": phishing_result.get('disposition', 'BENIGN_POSITIVE'),
                    "summary": f"Phishing awareness test detected from {vendor}. Test name: {test_name}. Auto-closed per phishing test allowlist.",
                    "key_findings": [
                        f"Matched phishing test pattern: {test_name}",
                        f"Vendor: {vendor}",
                        "This is a security awareness test, not a real threat"
                    ],
                    "recommended_actions": [
                        {
                            "action": "No action required - phishing awareness test",
                            "priority": "low",
                            "reason": "Matched phishing test allowlist"
                        }
                    ],
                    "requires_escalation": False,
                    # Canonical scale. Phishing test = absolutely BENIGN.
                    # Was 0.01 (inverted).
                    "false_positive_likelihood": 0.99,
                    "threat_type": "none",
                    "is_phishing_test": True,
                    "skip_enrichment": phishing_result.get('skip_enrichment', True),
                    "auto_close": phishing_result.get('auto_close', True),
                    "timestamp": datetime.utcnow().isoformat(),
                    # Dynamic display widgets for Riggs Insights
                    "display_widgets": [
                        {
                            "title": "Phishing Test Detected",
                            "color": "#22c55e",
                            "items": [
                                {"label": f"Vendor: {vendor}", "icon": "✅"},
                                {"label": f"Test: {test_name}"},
                                "Security awareness training exercise"
                            ]
                        },
                        {
                            "title": "Auto-Classification",
                            "color": "#3b82f6",
                            "items": [
                                "Matched phishing test allowlist",
                                "Confidence: 99%",
                                "Auto-closed - no action required"
                            ]
                        }
                    ]
                }
                await self._store_verdict(alert_id, triage_result)
                logger.info(f"Alert {alert_id}: Auto-closed as phishing test ({vendor})")
                return triage_result

            # ========== PRE-TRIAGE: Check for known malware from trusted EDR ==========
            # This auto-confirms alerts that match known malware families from trusted sources
            # Saves tokens by skipping AI analysis for obvious true positives
            from services.verdict_convergence import check_auto_confirm
            should_auto_confirm, auto_verdict, auto_reason = check_auto_confirm(alert_data, enrichment_data)

            if should_auto_confirm:
                logger.info(f"Alert {alert_id}: Auto-confirm triggered - {auto_reason}")
                detection_name = raw_event.get('detection_name', 'N/A')
                threat_family = raw_event.get('threat_family', 'N/A')
                alert_source = alert_data.get('source', 'N/A')

                triage_result = {
                    "status": "completed",
                    "verdict": "MALICIOUS",
                    "confidence": 0.95,
                    "disposition": "TRUE_POSITIVE",
                    "summary": auto_reason,
                    "key_findings": [
                        f"Auto-confirmed: {auto_reason}",
                        f"Detection: {detection_name}",
                        f"Threat family: {threat_family}",
                        f"Source: {alert_source}"
                    ],
                    "recommended_actions": [
                        {
                            "action": "Isolate affected endpoint immediately",
                            "priority": "critical",
                            "reason": "Known malware detected"
                        },
                        {
                            "action": "Collect forensic evidence",
                            "priority": "high",
                            "reason": "Preserve for incident response"
                        },
                        {
                            "action": "Check for lateral movement indicators",
                            "priority": "high",
                            "reason": "Known malware may have spread"
                        }
                    ],
                    "requires_escalation": True,
                    "escalation_reason": "Known malware confirmed - immediate response required",
                    "false_positive_likelihood": 0.05,
                    "threat_type": raw_event.get('threat_family', 'malware'),
                    "auto_confirmed": True,
                    "auto_confirm_reason": auto_reason,
                    "timestamp": datetime.utcnow().isoformat(),
                    # Dynamic display widgets for Riggs Insights
                    "display_widgets": [
                        {
                            "title": "Threat Detection",
                            "color": "#ef4444",
                            "items": [
                                {"label": f"Family: {threat_family}", "icon": "🦠"},
                                {"label": f"Detection: {detection_name}"},
                                {"label": f"Source: {alert_source}"}
                            ]
                        },
                        {
                            "title": "Key Findings",
                            "color": "#f59e0b",
                            "items": [
                                f"Auto-confirmed: {auto_reason}",
                                f"Confidence: 95%",
                                "Known malware signature match"
                            ]
                        },
                        {
                            "title": "Immediate Actions",
                            "color": "#dc2626",
                            "items": [
                                {"label": "Isolate affected endpoint", "priority": "critical"},
                                {"label": "Collect forensic evidence", "priority": "high"},
                                {"label": "Check for lateral movement", "priority": "high"}
                            ]
                        }
                    ]
                }
                await self._store_verdict(alert_id, triage_result)
                return triage_result

            # ═══════════════════════════════════════════════════════════════════════════
            # PHASE 1: INSTANT RULES - No LLM Required (<10ms)
            # ═══════════════════════════════════════════════════════════════════════════
            sender_domain = self._extract_sender_domain(email_sender)

            phase1_result = self._check_phase1_instant_rules(
                alert_id=alert_id,
                sender_domain=sender_domain,
                sender_trust_info=sender_trust_info,
                enrichment_data=enrichment_data,
                raw_event=raw_event
            )

            if phase1_result:
                await self._store_verdict(alert_id, phase1_result)
                logger.info(f"Alert {alert_id}: PHASE 1 resolved - {phase1_result.get('fast_path_reason')}")
                return phase1_result

            # ═══════════════════════════════════════════════════════════════════════════
            # PHASE 2: HEURISTIC PRE-FILTER - No LLM Required (<100ms)
            # ═══════════════════════════════════════════════════════════════════════════
            phase2_result, flags_for_phase3 = self._check_phase2_heuristic_prefilter(
                alert_id=alert_id,
                sender_domain=sender_domain,
                sender_trust_info=sender_trust_info,
                enrichment_data=enrichment_data,
                raw_event=raw_event
            )

            if phase2_result:
                await self._store_verdict(alert_id, phase2_result)
                logger.info(f"Alert {alert_id}: PHASE 2 resolved - {phase2_result.get('fast_path_reason')}")
                return phase2_result

            # ═══════════════════════════════════════════════════════════════════════════
            # PHASE 3: LLM ANALYSIS - Only if flagged by Phase 2
            # ═══════════════════════════════════════════════════════════════════════════
            logger.info(f"Alert {alert_id}: Proceeding to PHASE 3 (LLM) - flags: {flags_for_phase3}")

            # Build context for the AI
            context = self._build_triage_context(alert_data, enrichment_data, alert_flags)

            # Add sender trust info to context for AI consideration
            context['sender_trust'] = sender_trust_info

            # Add Phase 2 flags to context so LLM knows why it was escalated
            context['phase2_flags'] = flags_for_phase3
            context['sender_domain'] = sender_domain

            # CRITICAL: Gate intent analysis based on EMAIL AUTHENTICATION (not domain list)
            # If email auth passed (SPF+DKIM+DMARC all pass), sender is cryptographically verified
            # This is more secure than domain allowlists because it can't be spoofed
            auth_passed, auth_status = self._has_email_auth_passed(raw_event)
            context['sender_is_legitimate'] = auth_passed
            context['skip_intent_analysis'] = auth_passed
            context['email_auth_status'] = auth_status
            if auth_passed:
                logger.info(f"Alert {alert_id}: Email auth PASSED - sender is cryptographically verified, skipping intent analysis")

            # Query knowledge base for relevant SOPs and procedures
            kb_context = await self._get_relevant_knowledge(alert_data, enrichment_data)
            if kb_context:
                context['knowledge_base_context'] = kb_context
                logger.info(f"Alert {alert_id}: Found {len(kb_context)} relevant KB entries")

            # Inject template guardrails into context if provided
            if template_prompt:
                context['template_prompt'] = template_prompt
            if template_max_tokens:
                context['template_max_tokens'] = template_max_tokens
            if custom_instructions:
                context['custom_instructions'] = custom_instructions

            # Call AI for triage
            triage_result = await self._call_ai_triage(context)

            # Safety check - _call_ai_triage should never return None, but handle it gracefully
            if triage_result is None:
                logger.error(f"Alert {alert_id}: _call_ai_triage returned None - using fallback")
                triage_result = {
                    "status": "error",
                    "verdict": "unknown",
                    "confidence": 0,
                    "summary": "AI triage returned no result",
                    "timestamp": datetime.utcnow().isoformat()
                }

            # ═══════════════════════════════════════════════════════════════════════════
            # APPLY VERDICT GUARDRAILS (Added 2026-01-26 for FP Reduction)
            # ═══════════════════════════════════════════════════════════════════════════
            # This validates evidence requirements and blocks premature verdicts
            from services.verdict_convergence import apply_verdict_guardrails
            triage_result = apply_verdict_guardrails(
                triage_result=triage_result,
                sender_domain=sender_domain,
                sender_is_legitimate=context.get('sender_is_legitimate', False),
                enrichment_data=enrichment_data
            )

            if triage_result.get('verdict_corrected'):
                logger.warning(
                    f"Alert {alert_id}: Verdict corrected by guardrails: "
                    f"{triage_result.get('original_verdict')} -> {triage_result.get('verdict')} "
                    f"({triage_result.get('correction_reason')})"
                )

            # Add sender trust metadata to result
            if sender_trust_info.get('is_trusted_sender'):
                triage_result['trusted_sender'] = sender_trust_info.get('trusted_sender_result')

            # Mark Phase 3 completion
            triage_result['phase'] = 3
            triage_result['phase2_flags'] = flags_for_phase3

            # Store the verdict on the alert
            await self._store_verdict(alert_id, triage_result)

            # Log the result
            verdict = triage_result.get('verdict', 'unknown')
            confidence = triage_result.get('confidence', 0)
            logger.info(f"Alert {alert_id}: AI verdict = {verdict} (confidence: {confidence:.0%})")

            return triage_result

        except Exception as e:
            import traceback
            logger.error(f"Alert {alert_id}: AI triage failed - {e}")
            logger.error(f"Alert {alert_id}: Traceback:\n{traceback.format_exc()}")
            return {
                "status": "error",
                "error": str(e),
                "verdict": None,
                "timestamp": datetime.utcnow().isoformat()
            }

    async def _check_sender_trust(
        self,
        alert_id: str,
        sender_email: str,
        subject: str,
        enrichment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check sender against trusted sender allowlist and phishing test patterns.

        Returns dict with:
        - is_phishing_test: bool
        - phishing_test_result: dict if phishing test
        - is_trusted_sender: bool
        - trusted_sender_result: dict if trusted
        - domain_age_valid: bool
        - whois_data: dict
        """
        result = {
            'is_phishing_test': False,
            'is_trusted_sender': False,
            'domain_age_valid': None,
            'whois_data': None
        }

        if not sender_email:
            return result

        try:
            from services.sender_trust_service import get_sender_trust_service
            sender_trust_service = get_sender_trust_service()

            # 1. Check phishing test list first (sender + subject must match)
            phishing_result = await sender_trust_service.check_phishing_test(sender_email, subject)
            if phishing_result.is_phishing_test:
                logger.info(f"Alert {alert_id}: Matched phishing test pattern - {phishing_result.test_name}")
                result['is_phishing_test'] = True
                result['phishing_test_result'] = {
                    'test_name': phishing_result.test_name,
                    'vendor': phishing_result.vendor,
                    'auto_close': phishing_result.auto_close,
                    'skip_enrichment': phishing_result.skip_enrichment,
                    'disposition': phishing_result.disposition
                }
                return result  # Early return for phishing tests

            # 2. Check trusted sender allowlist
            trusted_result = await sender_trust_service.check_trusted_sender(sender_email)
            if trusted_result.is_trusted:
                logger.info(f"Alert {alert_id}: Sender {sender_email} is trusted ({trusted_result.trust_level})")
                result['is_trusted_sender'] = True
                result['trusted_sender_result'] = {
                    'trust_level': trusted_result.trust_level,
                    'organization': trusted_result.organization,
                    'category': trusted_result.category,
                    'reason': trusted_result.reason
                }

            # 3. Extract WHOIS data from enrichment if available for domain age validation
            domains_enriched = enrichment_data.get('results', {}).get('domains', [])
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else None

            if sender_domain:
                for domain_data in domains_enriched:
                    if domain_data.get('domain', '').lower() == sender_domain.lower():
                        whois_data = domain_data.get('whois', {})
                        if whois_data:
                            result['whois_data'] = whois_data
                            # Validate domain age
                            is_valid, message = await sender_trust_service.validate_domain_age(
                                sender_domain, whois_data, min_age_days=365
                            )
                            result['domain_age_valid'] = is_valid
                            result['domain_age_message'] = message
                            logger.info(f"Alert {alert_id}: Domain age validation: {message}")
                        break

            return result

        except Exception as e:
            logger.warning(f"Alert {alert_id}: Sender trust check failed - {e}")
            return result

    def _truncate_enrichment_for_triage(self, enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aggressively truncate enrichment data for T1 triage.

        Target: <1000 chars total for all enrichment data
        Strategy: Keep only IOC value + verdict, max 3 per category
        """
        result = {"ips": [], "domains": [], "hashes": []}

        for category in ["ips", "domains", "hashes"]:
            items = enrichment.get(category, [])
            if not items:
                continue

            # Take max 3 items per category
            for item in items[:3]:
                if isinstance(item, dict):
                    # Extract just the essentials: value + verdict
                    ioc_value = item.get('ip') or item.get('domain') or item.get('hash') or item.get('value', 'unknown')
                    verdict = item.get('verdict', 'unknown')
                    malicious = item.get('malicious', False)

                    # Truncate IOC value if too long
                    if isinstance(ioc_value, str) and len(ioc_value) > 100:
                        ioc_value = ioc_value[:100] + "..."

                    result[category].append({
                        "value": ioc_value,
                        "verdict": verdict,
                        "malicious": malicious
                    })
                elif isinstance(item, str):
                    # Simple string IOC
                    result[category].append({"value": item[:100], "verdict": "unknown"})

        return result

    def _extract_phishing_evidence(
        self,
        email_sender: str,
        email_subject: str,
        email_body: str,
        raw_event: Dict[str, Any],
        skip_intent_analysis: bool = False
    ) -> Dict[str, Any]:
        """
        Extract phishing evidence signals that allow T1 to detect social engineering
        WITHOUT requiring malicious IOCs.

        CRITICAL SECURITY FIX (2026-01-26):
        Intent analysis is now GATED behind sender legitimacy verification.
        If sender domain is a verified legitimate brand domain, intent analysis
        is SKIPPED to prevent false positives on legitimate business emails.

        This is critical for brand impersonation phishing where:
        - Sender domain is technically "clean" (newly registered, not in threat feeds)
        - No malware payload (just credential harvesting link)
        - Traditional IOC enrichment returns "benign"

        But the EMAIL IS STILL MALICIOUS due to intent - ONLY when sender is NOT legitimate.

        Args:
            email_sender: Email sender address
            email_subject: Email subject line
            email_body: Email body text
            raw_event: Raw event data
            skip_intent_analysis: If True, skip all intent analysis (sender is legitimate)

        Returns:
            Dict with phishing indicators:
            - brand_impersonation: detected brand, domain similarity, visual indicators
            - language_signals: urgency, credential request, account threat
            - user_interaction: clicked, credentials entered (if available)
            - authentication_failures: SPF/DKIM/DMARC failures
            - intent_analysis_skipped: True if analysis was skipped due to legitimate sender
        """
        import re
        from difflib import SequenceMatcher
        from services.sender_trust_service import is_legitimate_brand_domain

        evidence = {
            'detected': False,
            'brand_impersonation': {},
            'language_signals': {},
            'user_interaction': {},
            'authentication_failures': {},
            'intent_analysis_skipped': False,
            'sender_legitimacy_verified': False
        }

        # ═══════════════════════════════════════════════════════════════════════════
        # CRITICAL GATE: Check sender legitimacy BEFORE any intent analysis
        # If sender is from a legitimate brand domain, SKIP all intent analysis
        # This prevents false positives on legitimate password reset emails, etc.
        # ═══════════════════════════════════════════════════════════════════════════
        sender_domain = ''
        if email_sender and '@' in email_sender:
            sender_domain = email_sender.lower().split('@')[-1].strip().rstrip('>')

        # Check if sender is from a verified legitimate brand domain
        if sender_domain and is_legitimate_brand_domain(sender_domain):
            logger.info(f"[INTENT_GATE] Sender domain '{sender_domain}' is LEGITIMATE - skipping intent analysis")
            evidence['intent_analysis_skipped'] = True
            evidence['sender_legitimacy_verified'] = True
            evidence['skipped_reason'] = f"Sender domain '{sender_domain}' is a verified legitimate brand domain"
            # Return early - no intent analysis for legitimate senders
            return evidence

        # Also respect explicit skip flag (set by Phase 1/2)
        if skip_intent_analysis:
            logger.info(f"[INTENT_GATE] Intent analysis explicitly skipped via flag")
            evidence['intent_analysis_skipped'] = True
            evidence['skipped_reason'] = "Analysis skipped by caller (sender verified)"
            return evidence

        # ═══════════════════════════════════════════════════════════════════════════
        # PROCEED WITH INTENT ANALYSIS - Sender is NOT from legitimate domain
        # ═══════════════════════════════════════════════════════════════════════════
        logger.debug(f"[INTENT_ANALYSIS] Proceeding for sender domain: {sender_domain or 'unknown'}")

        # Common brand targets for phishing
        BRAND_DOMAINS = {
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com', 'sharepoint.com', 'onedrive.com'],
            'google': ['google.com', 'gmail.com', 'googleapis.com', 'drive.google.com'],
            'apple': ['apple.com', 'icloud.com', 'itunes.com'],
            'amazon': ['amazon.com', 'amazonaws.com', 'aws.amazon.com'],
            'paypal': ['paypal.com', 'paypal.me'],
            'netflix': ['netflix.com'],
            'facebook': ['facebook.com', 'fb.com', 'meta.com'],
            'linkedin': ['linkedin.com'],
            'docusign': ['docusign.com', 'docusign.net'],
            'dropbox': ['dropbox.com'],
            'zoom': ['zoom.us', 'zoomgov.com'],
            'slack': ['slack.com'],
            'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'capitalone.com'],
        }

        # Brand keywords in subjects/body
        BRAND_KEYWORDS = {
            'microsoft': ['office 365', 'microsoft', 'outlook', 'sharepoint', 'onedrive', 'teams', 'azure'],
            'google': ['google', 'gmail', 'google drive', 'google docs'],
            'apple': ['apple', 'icloud', 'apple id', 'itunes'],
            'amazon': ['amazon', 'aws', 'prime', 'kindle'],
            'paypal': ['paypal'],
            'netflix': ['netflix'],
            'linkedin': ['linkedin', 'inmail'],
            'docusign': ['docusign', 'sign document'],
            'zoom': ['zoom', 'meeting invite'],
            'voicemail': ['voicemail', 'voice message', 'missed call'],
        }

        # Urgency patterns
        URGENCY_PATTERNS = [
            r'\b(urgent|immediately|asap|action required|expire|suspended|verify now|within 24 hours|limited time)\b',
            r'\b(your account (has been|will be|is) (suspended|locked|closed|terminated))\b',
            r'\b(failure to respond|if you do not|unless you)\b',
            r'\b(final notice|last chance|act now)\b',
        ]

        # Credential request patterns
        CREDENTIAL_PATTERNS = [
            r'\b(verify your (account|identity|password|credentials))\b',
            r'\b(confirm your (password|login|identity))\b',
            r'\b(update your (password|credentials|account))\b',
            r'\b(sign in|log in|login) (to|and) (verify|confirm|update)\b',
            r'\b(enter your (password|credentials|pin))\b',
            r'\b(click (here|below|the link) to (verify|confirm|secure))\b',
        ]

        # Account threat patterns
        ACCOUNT_THREAT_PATTERNS = [
            r'\b(unusual (activity|sign-in|login))\b',
            r'\b(suspicious (activity|login|access))\b',
            r'\b(unauthorized (access|attempt|login))\b',
            r'\b(security (alert|warning|notice))\b',
            r'\b(your account (may be|has been) compromised)\b',
            r'\b(password (has been|was) (changed|reset))\b',
        ]

        combined_text = f"{email_subject} {email_body}".lower()
        sender_lower = email_sender.lower()

        # Extract sender domain
        sender_domain = ''
        if '@' in sender_lower:
            sender_domain = sender_lower.split('@')[-1].strip('>')

        # 1. BRAND IMPERSONATION DETECTION
        detected_brand = None
        brand_confidence = 0

        for brand, keywords in BRAND_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined_text:
                    detected_brand = brand
                    brand_confidence = 0.7
                    break
            if detected_brand:
                break

        if detected_brand:
            # Check domain similarity to legitimate brand domains
            legit_domains = BRAND_DOMAINS.get(detected_brand, [])
            max_similarity = 0
            closest_legit = None

            for legit in legit_domains:
                # Check if sender is actually from legitimate domain
                if sender_domain == legit or sender_domain.endswith('.' + legit):
                    # This is actually from the legitimate brand
                    detected_brand = None
                    break

                # Calculate similarity (for typosquatting detection)
                similarity = SequenceMatcher(None, sender_domain, legit).ratio()
                if similarity > max_similarity:
                    max_similarity = similarity
                    closest_legit = legit

            if detected_brand:
                evidence['brand_impersonation'] = {
                    'brand': detected_brand,
                    'sender_domain': sender_domain,
                    'domain_similarity_score': round(max_similarity, 2),
                    'closest_legitimate_domain': closest_legit,
                    'is_typosquat': max_similarity > 0.6 and max_similarity < 1.0,
                    'confidence': brand_confidence
                }
                evidence['detected'] = True

        # 2. LANGUAGE SIGNALS DETECTION
        urgency = False
        credential_request = False
        account_threat = False

        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                urgency = True
                break

        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                credential_request = True
                break

        for pattern in ACCOUNT_THREAT_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                account_threat = True
                break

        if urgency or credential_request or account_threat:
            evidence['language_signals'] = {
                'urgency': urgency,
                'credential_request': credential_request,
                'account_threat': account_threat,
                'count': sum([urgency, credential_request, account_threat])
            }
            evidence['detected'] = True

        # 3. USER INTERACTION (from raw_event if available)
        clicked = raw_event.get('clicked') or raw_event.get('user_clicked', False)
        credentials_entered = raw_event.get('credentials_entered', False)
        reported_by_user = raw_event.get('reported_by_user', False)

        if clicked or credentials_entered or reported_by_user:
            evidence['user_interaction'] = {
                'clicked': bool(clicked),
                'credentials_entered': bool(credentials_entered),
                'reported_by_user': bool(reported_by_user)
            }
            evidence['detected'] = True

        # 4. AUTHENTICATION FAILURES (SPF/DKIM/DMARC)
        email_headers = raw_event.get('email_headers', {})
        auth_results = raw_event.get('authentication_results', '')

        # Parse authentication results
        spf_fail = 'spf=fail' in str(auth_results).lower() or 'spf=softfail' in str(auth_results).lower()
        dkim_fail = 'dkim=fail' in str(auth_results).lower()
        dmarc_fail = 'dmarc=fail' in str(auth_results).lower()

        if spf_fail or dkim_fail or dmarc_fail:
            evidence['authentication_failures'] = {
                'spf_fail': spf_fail,
                'dkim_fail': dkim_fail,
                'dmarc_fail': dmarc_fail,
                'spoofing_likely': spf_fail and dkim_fail
            }
            evidence['detected'] = True

        # Set overall confidence
        if evidence['detected']:
            confidence = 0.3  # Base confidence
            if evidence.get('brand_impersonation'):
                confidence += 0.25
            if evidence.get('language_signals', {}).get('count', 0) >= 2:
                confidence += 0.25
            if evidence.get('authentication_failures', {}).get('spoofing_likely'):
                confidence += 0.15
            if evidence.get('user_interaction', {}).get('clicked'):
                confidence += 0.05
            evidence['overall_confidence'] = min(confidence, 0.95)

        return evidence

    def _build_triage_context(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        alert_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Build context for AI triage prompt."""

        # Extract raw_event data if available (contains email sender, subject, etc.)
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}
        # Ensure raw_event is never None
        if raw_event is None:
            raw_event = {}

        # Extract email-specific fields
        email_sender = raw_event.get('reporter') or raw_event.get('from') or raw_event.get('sender', '')
        email_subject = raw_event.get('subject', '')
        # Full email body for AI analysis - don't truncate, AI needs full context for phishing detection
        email_body = raw_event.get('body', '') if raw_event.get('body') else ''

        # ═══════════════════════════════════════════════════════════════════════════
        # TOKEN OPTIMIZATION: Aggressive truncation for T1 triage
        # Target: ~1500 tokens TOTAL for the entire prompt
        # Each enrichment item gets max 200 chars, max 3 items per category
        # ═══════════════════════════════════════════════════════════════════════════
        raw_enrichment = {
            "ips": enrichment_data.get('results', {}).get('ips', []),
            "domains": enrichment_data.get('results', {}).get('domains', []),
            "hashes": enrichment_data.get('results', {}).get('hashes', []),
        }
        original_size = len(json.dumps(raw_enrichment, default=str))

        # Aggressively truncate enrichment - keep only verdict summary per IOC
        truncated_enrichment = self._truncate_enrichment_for_triage(raw_enrichment)
        truncated_size = len(json.dumps(truncated_enrichment, default=str))

        if original_size > 0:
            reduction_pct = round((1 - truncated_size / original_size) * 100, 1)
            logger.info(f"[TRIAGE_TRUNCATION] Original: {original_size} chars, Truncated: {truncated_size} chars, Reduction: {reduction_pct}%")

        # Extract key alert fields
        context = {
            "alert": {
                "title": alert_data.get('title', 'Unknown'),
                "description": alert_data.get('description', ''),
                "severity": alert_data.get('severity', 'medium'),
                "source": alert_data.get('source', 'unknown'),
                "category": alert_data.get('category', ''),  # Added for specialized prompts
            },
            "email": {
                "sender": email_sender,
                "subject": email_subject,
                "body_preview": email_body,
            },
            "enrichment_summary": enrichment_data.get('summary', {}),
            "enrichment_results": truncated_enrichment,  # Use truncated data
            "enrichment_data": enrichment_data,  # Full enrichment data for specialized prompts
            "policy_blocked": enrichment_data.get('results', {}).get('_policy_blocked', []),
            "knowledge_base_context": [],  # Will be populated with relevant SOPs
            "alert_flags": alert_flags or [],  # Alert classification flags for specialized prompts
            "playbook_results_summary": enrichment_data.get('playbook_results_summary', ''),  # Pre-triage playbook results
        }

        # ═══════════════════════════════════════════════════════════════════════════
        # INCLUDE RAW EVENT DATA FOR AI ANALYSIS OF ENCODED/OBFUSCATED CONTENT
        # The AI needs to see command lines, encoded payloads, etc. to analyze them
        # ═══════════════════════════════════════════════════════════════════════════
        raw_event_for_ai = {}

        # Include command line fields (critical for malware analysis)
        # NOTE: Base64 encoded payloads can be 1000+ chars - preserve them fully!
        for cmd_field in ['CommandLine', 'command_line', 'cmdline', 'cmd', 'process_command_line', 'ProcessCommandLine']:
            if raw_event.get(cmd_field):
                raw_event_for_ai['command_line'] = raw_event[cmd_field][:5000]  # Full command line for encoded payloads
                break

        # Include process/image info
        for img_field in ['Image', 'image', 'process_name', 'ProcessName', 'exe']:
            if raw_event.get(img_field):
                raw_event_for_ai['process_image'] = raw_event[img_field]
                break

        # Include parent process info
        for parent_field in ['ParentImage', 'parent_image', 'ParentProcessName', 'parent_process']:
            if raw_event.get(parent_field):
                raw_event_for_ai['parent_process'] = raw_event[parent_field]
                break

        # Include user info
        for user_field in ['User', 'user', 'UserName', 'username', 'AccountName']:
            if raw_event.get(user_field):
                raw_event_for_ai['user'] = raw_event[user_field]
                break

        # Include network connections if present
        if raw_event.get('network_connections'):
            raw_event_for_ai['network_connections'] = raw_event['network_connections'][:5]  # First 5

        # Include behaviors (EDR alerts)
        if raw_event.get('behaviors'):
            raw_event_for_ai['behaviors'] = raw_event['behaviors'][:3]  # First 3

        # Include quarantine/detection info
        if raw_event.get('quarantine_files'):
            raw_event_for_ai['quarantine_files'] = raw_event['quarantine_files']
        if raw_event.get('detection_name') or raw_event.get('threat_family'):
            raw_event_for_ai['detection'] = {
                'name': raw_event.get('detection_name'),
                'family': raw_event.get('threat_family')
            }

        # Include DNS/URL info for phishing
        if raw_event.get('urls'):
            raw_event_for_ai['urls'] = raw_event['urls'][:5]
        if raw_event.get('domain'):
            raw_event_for_ai['domain'] = raw_event['domain']

        # ═══════════════════════════════════════════════════════════════════════════
        # EMAIL HEADERS - Critical for phishing analysis (SPF, DKIM, Authentication)
        # These headers indicate whether the email legitimately came from claimed sender
        # ═══════════════════════════════════════════════════════════════════════════
        if raw_event.get('email_headers'):
            raw_event_for_ai['email_headers'] = raw_event['email_headers']
        if raw_event.get('received_chain'):
            # Include first 5 hops of email path - shows routing and potential spoofing
            raw_event_for_ai['received_chain'] = raw_event['received_chain'][:5]

        # Include raw binary/encoded data indicators
        if raw_event.get('raw_binary_dump'):
            raw_event_for_ai['has_binary_data'] = True
            raw_event_for_ai['binary_preview'] = raw_event['raw_binary_dump'][:100]

        # Include MITRE ATT&CK info
        for mitre_field in ['technique', 'RuleName', 'rule_name']:
            if raw_event.get(mitre_field):
                raw_event_for_ai['mitre_info'] = raw_event[mitre_field]
                break

        if raw_event_for_ai:
            context['raw_event_analysis'] = raw_event_for_ai

        # ═══════════════════════════════════════════════════════════════════════════
        # INCLUDE PRE-DECODED CONTENT FROM FIELD EXTRACTION
        # This provides the AI with already-decoded base64 and defanged IOCs
        # so it doesn't have to decode them itself (which is unreliable)
        # ═══════════════════════════════════════════════════════════════════════════
        extracted_data = raw_event.get('_extracted', {})
        if extracted_data:
            # Include decoded base64 content
            if extracted_data.get('decoded_content'):
                context['decoded_content'] = []
                for dc in extracted_data['decoded_content'][:5]:  # Limit to 5
                    context['decoded_content'].append({
                        'encoded': dc.get('encoded', '')[:60] + '...',
                        'decoded': dc.get('decoded', '')
                    })

            # Include IOCs found in decoded content
            if extracted_data.get('decoded_iocs'):
                decoded_iocs = extracted_data['decoded_iocs']
                # Only include if there are actual values
                has_values = any(decoded_iocs.get(k) for k in decoded_iocs)
                if has_values:
                    context['decoded_iocs'] = decoded_iocs

            # Include refanged IOCs (from defanged analyst notes, etc.)
            if extracted_data.get('defanged_iocs'):
                defanged = extracted_data['defanged_iocs']
                has_values = any(defanged.get(k) for k in defanged)
                if has_values:
                    context['refanged_iocs'] = defanged

            # Include all extracted IOCs
            if extracted_data.get('iocs'):
                context['extracted_iocs'] = extracted_data['iocs']

        # ═══════════════════════════════════════════════════════════════════════════
        # PHISHING EVIDENCE SIGNALS (P0 FIX)
        # These signals allow T1 to detect social engineering WITHOUT requiring
        # malicious IOCs. Brand phishing is often technically clean but socially malicious.
        # ═══════════════════════════════════════════════════════════════════════════
        phishing_evidence = self._extract_phishing_evidence(
            email_sender=email_sender,
            email_subject=email_subject,
            email_body=email_body,
            raw_event=raw_event
        )
        if phishing_evidence.get('detected'):
            context['phishing_indicators'] = phishing_evidence
            logger.info(f"[PHISHING_EVIDENCE] Detected: brand={phishing_evidence.get('brand_impersonation', {}).get('brand', 'none')}, "
                       f"urgency={phishing_evidence.get('language_signals', {}).get('urgency', False)}, "
                       f"credential_request={phishing_evidence.get('language_signals', {}).get('credential_request', False)}")

        return context

    async def _get_relevant_knowledge(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Query the knowledge base for relevant SOPs and procedures.

        This retrieves company-specific handling rules, SOPs, and playbooks
        that are relevant to the current alert being triaged.
        """
        try:
            from services.knowledge_base_service import get_knowledge_base_service

            kb_service = get_knowledge_base_service()

            # Extract IOC types from enrichment
            ioc_types = []
            results = enrichment_data.get('results', {})
            if results.get('ips'):
                ioc_types.append('ip')
            if results.get('domains'):
                ioc_types.append('domain')
            if results.get('hashes'):
                ioc_types.append('hash')

            # Extract keywords from alert
            title = alert_data.get('title', '')
            description = alert_data.get('description', '')
            keywords = []

            # Common incident keywords
            keyword_patterns = [
                'phishing', 'malware', 'ransomware', 'brute force',
                'data breach', 'exfiltration', 'unauthorized', 'suspicious',
                'c2', 'command and control', 'lateral movement'
            ]
            combined_text = f"{title} {description}".lower()
            for kw in keyword_patterns:
                if kw in combined_text:
                    keywords.append(kw)

            # Query knowledge base
            relevant_entries = await kb_service.query_for_context(
                alert_data=alert_data,
                severity=alert_data.get('severity'),
                ioc_types=ioc_types if ioc_types else None,
                keywords=keywords if keywords else None,
                limit=5  # Top 5 most relevant entries
            )

            return relevant_entries

        except Exception as e:
            logger.warning(f"Failed to query knowledge base: {e}")
            return []

    async def _call_ai_triage(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Call AI model for triage decision."""

        # ═══════════════════════════════════════════════════════════════════════════
        # AI PROVIDER SELECTION
        # Priority: Per-tenant BYO > Database config (AI Workbench) > AI_PROVIDER env > Claude > fallback
        # ═══════════════════════════════════════════════════════════════════════════

        logger.debug("[_call_ai_triage] Starting AI triage call")

        # ── PRIORITY 0: Per-tenant BYO LLM (tenant_ai_config) ────────────
        # When a tenant has BYO allowed + enabled + a stored key, route to
        # their own provider before consulting the global ai_providers
        # table or env vars. BYO calls bypass platform quota and write to
        # tenant_byo_usage instead of tenant_claude_usage.
        try:
            from middleware.tenant_middleware import current_tenant_id
            from services import ai_provider_resolver
            _tid = current_tenant_id.get()
            if _tid:
                ctx = await ai_provider_resolver.resolve_chat(str(_tid))
                if ctx.mode == "byo":
                    logger.info(
                        f"[AI_PROVIDER] Using tenant BYO config: provider={ctx.provider} "
                        f"style={ctx.api_style} model={ctx.model or 'default'}"
                    )
                    return await self._call_byo_triage(context, str(_tid), ctx)
        except Exception as e:
            logger.debug(f"[AI_PROVIDER] BYO resolve skipped: {e}")

        # Database config - PRIORITY 1 (from ai_providers table or agent_definitions)
        agent_config = await self._get_triage_agent_config()
        logger.debug(f"[_call_ai_triage] Agent config from DB: {agent_config}")
        if agent_config:
            provider = agent_config.get('provider', 'anthropic')
            model = agent_config.get('model', self.model)
            endpoint_url = agent_config.get('endpoint_url')
            api_key = agent_config.get('api_key')

            if provider == 'openai' or provider == 'openai_compatible':
                # OpenAI API from database config
                if api_key:
                    logger.info(f"[AI_PROVIDER] Using OpenAI from database config, model={model}")
                    return await self._call_llm_for_triage(context, 'openai', model, api_key=api_key)
            elif provider == 'lm_studio':
                logger.info(f"[AI_PROVIDER] Using LM Studio from database config: {endpoint_url} model={model}")
                return await self._call_lm_studio_triage(context, model, endpoint_url)
            elif provider == 'anthropic':
                key = api_key or os.getenv('ANTHROPIC_API_KEY')
                if key:
                    logger.info(f"[AI_PROVIDER] Using Anthropic from database config: {model}")
                    return await self._call_anthropic_triage(context, key, model)

        # Environment variable fallback - PRIORITY 2
        ai_provider = os.getenv('AI_PROVIDER', '').lower()

        # LM Studio - For development
        if ai_provider == 'lm_studio':
            lm_studio_url = os.getenv('LM_STUDIO_URL', 'http://host.docker.internal:1234')
            lm_studio_model = os.getenv('LM_STUDIO_MODEL', 'gpt-oss-20b')
            logger.info(f"[AI_PROVIDER] Using LM Studio from env var: {lm_studio_url} model={lm_studio_model}")
            return await self._call_lm_studio_triage(context, lm_studio_model, lm_studio_url)

        # Claude/Anthropic - Default provider
        if ai_provider in ('anthropic', 'claude', ''):
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                # Tier-aware model selection: Free→Haiku, Pro+→Sonnet
                tier_model = await self._get_tenant_default_model()
                effective_model = tier_model or self.model
                logger.info(f"[AI_PROVIDER] Using Anthropic from env var: {effective_model}")
                return await self._call_anthropic_triage(context, api_key, effective_model)

        # Final fallbacks - PRIORITY 3
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if api_key:
            tier_model = await self._get_tenant_default_model()
            effective_model = tier_model or self.model
            return await self._call_anthropic_triage(context, api_key, effective_model)

        lm_studio_url = os.getenv('LM_STUDIO_URL')
        if lm_studio_url:
            return await self._call_lm_studio_triage(context, 'default', lm_studio_url)

        logger.warning("No AI provider configured, using mock triage")
        return self._mock_triage(context)

    async def _get_triage_agent_config(self) -> Optional[Dict[str, Any]]:
        """Get the AI provider configuration from database.

        Priority:
        1. Default AI provider from ai_providers table (set via UI)
        2. Tier 1 agent config from agent_definitions table
        """
        try:
            if not self.db or not self.db.pool:
                return None

            async with _admin_conn() as conn:
                # PRIORITY 1: Check ai_providers table for default provider
                default_provider = await conn.fetchrow("""
                    SELECT
                        provider_type,
                        name,
                        api_key,
                        api_key_encrypted,
                        base_url,
                        selected_model
                    FROM ai_providers
                    WHERE is_default = true AND enabled = true
                    LIMIT 1
                """)

                if default_provider:
                    provider_type = default_provider['provider_type']
                    logger.info(f"[AI_PROVIDER] Using default from ai_providers: {provider_type} ({default_provider['name']})")

                    # Decrypt the stored key (preferring the encrypted column,
                    # falling back to legacy plaintext for un-backfilled rows).
                    try:
                        from routes.ai_providers import _provider_plaintext_key
                        plain_key = _provider_plaintext_key(dict(default_provider))
                    except Exception:
                        plain_key = default_provider['api_key'] or ''

                    # Map provider_type to internal provider names
                    if provider_type == 'openai' or provider_type == 'openai_compatible':
                        return {
                            'provider': 'openai',
                            'model': default_provider['selected_model'],
                            'api_key': plain_key,
                        }
                    elif provider_type == 'anthropic':
                        return {
                            'provider': 'anthropic',
                            'model': default_provider['selected_model'],
                            'api_key': plain_key,
                        }
                    elif provider_type == 'lm_studio':
                        return {
                            'provider': 'lm_studio',
                            'model': default_provider['selected_model'],
                            'endpoint_url': default_provider['base_url']
                        }

                # PRIORITY 2: Fall back to agent_definitions table
                row = await conn.fetchrow("""
                    SELECT
                        model_config->>'provider' as provider,
                        model_config->>'model' as model,
                        COALESCE(model_config->>'base_url', model_config->>'endpoint_url') as endpoint_url
                    FROM agent_definitions
                    WHERE tier = 1 AND enabled = true
                    ORDER BY created_at DESC
                    LIMIT 1
                """)

                if row:
                    logger.info(f"Using Tier 1 agent config: provider={row['provider']}, model={row['model']}, endpoint={row['endpoint_url']}")
                    return {
                        'provider': row['provider'],
                        'model': row['model'],
                        'endpoint_url': row['endpoint_url']
                    }
        except Exception as e:
            logger.debug(f"Failed to get agent config from DB: {e}")
        return None

    async def _get_tenant_default_model(self) -> Optional[str]:
        """
        Resolve the default AI model for the current tenant based on license tier.

        Free tier → Haiku 4.5 (~4x cheaper)
        Pro+ → Sonnet 4.5 (full power)

        Returns None if tier cannot be resolved (caller should use self.model fallback).
        """
        try:
            from middleware.tenant_middleware import current_tenant_id
            tenant_id = current_tenant_id.get()
            if not tenant_id:
                return None

            from dependencies.license_checks import _get_tenant_tier
            from services.licensing.default_plans import get_default_entitlements

            tier = await _get_tenant_tier(str(tenant_id))
            entitlements = get_default_entitlements(tier)
            model = entitlements.llm.default_model

            if model:
                logger.debug(f"Tier-aware model for tenant {tenant_id} ({tier.value}): {model}")
                return model
            return None
        except Exception as e:
            logger.debug(f"Failed to resolve tenant default model: {e}")
            return None

    async def _call_llm_for_triage(
        self,
        prompt: str,
        purpose: str = "generic",
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
        tenant_id=None
    ) -> Optional[str]:
        """
        Generic LLM call for any purpose (Riggs analysis, etc.)
        Returns raw response text for caller to parse.
        Uses configured AI provider (Claude, LM Studio, or OpenAI).

        When AI_PROVIDER=claude (or anthropic):
        - Routes through ClaudeService with quota enforcement and tenant billing
        - Requires ANTHROPIC_API_KEY to be set
        - tenant_id must be provided for quota tracking

        Args:
            prompt: The prompt to send to the LLM
            purpose: Purpose identifier for logging and token allocation
            max_tokens: Override max tokens (if None, uses purpose-based default)
            api_key: Optional API key override (for OpenAI)
            tenant_id: Tenant UUID for Claude quota enforcement and billing
        """
        from config.system_config import ENABLE_TIERED_ROUTING
        ai_provider = os.getenv('AI_PROVIDER', '').lower()

        try:
            import aiohttp

            # Claude/Anthropic - managed platform API
            if ai_provider in ('claude', 'anthropic'):
                from services.claude_service import get_claude_service, QuotaExceededError

                service = await get_claude_service()

                # Resolve tenant_id — use default if not provided
                resolved_tenant_id = tenant_id
                if not resolved_tenant_id:
                    from config.constants import PLATFORM_OWNER_TENANT_ID
                    resolved_tenant_id = PLATFORM_OWNER_TENANT_ID

                import uuid as _uuid
                if isinstance(resolved_tenant_id, str):
                    resolved_tenant_id = _uuid.UUID(resolved_tenant_id)

                # NOTE: Do NOT gate on service.is_configured (env ANTHROPIC_API_KEY)
                # alone. A tenant may be running BYO / self-hosted (e.g. Ollama),
                # in which case claude_service.complete() resolves the per-tenant
                # provider+endpoint and succeeds without any platform env key.
                # Only fail fast when there is neither an env key NOR an effective
                # BYO provider for this tenant.
                if not service.is_configured:
                    try:
                        from services import ai_provider_resolver
                        _ctx = await ai_provider_resolver.resolve_chat(str(resolved_tenant_id))
                        if _ctx.mode != "byo":
                            logger.error(f"[{purpose}] Claude selected but ANTHROPIC_API_KEY not set and tenant has no BYO provider")
                            return None
                    except Exception as _re:
                        logger.error(f"[{purpose}] Claude selected but ANTHROPIC_API_KEY not set (BYO resolve failed: {_re})")
                        return None

                if max_tokens is None:
                    if 'riggs' in purpose.lower():
                        max_tokens = 4000
                    else:
                        max_tokens = 2000

                try:
                    response = await service.complete(
                        tenant_id=resolved_tenant_id,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        temperature=0.1,
                        request_type=purpose,
                    )
                    logger.info(
                        f"[{purpose}] Claude response: {len(response.text)} chars, "
                        f"{response.total_tokens} tokens, {response.response_time_ms}ms"
                    )
                    return response.text
                except QuotaExceededError as qe:
                    logger.warning(f"[{purpose}] Token quota exceeded: {qe}")
                    return None
                except Exception as e:
                    logger.error(f"[{purpose}] Claude call failed: {e}")
                    return None

            # OpenAI API - cloud inference
            # Use passed-in api_key if provided, otherwise check env var and database
            if ai_provider == 'openai' or api_key:
                import openai

                # Priority: passed-in api_key > database > environment
                openai_key = api_key
                openai_model = os.getenv('OPENAI_MODEL', 'gpt-4o')

                if not openai_key:
                    try:
                        from services.postgres_db import postgres_db

                        # Look for OpenAI provider in ai_providers table
                        async with _admin_conn() as conn:
                            row = await conn.fetchrow(
                                """SELECT api_key, selected_model FROM ai_providers
                                   WHERE provider_type = 'openai' AND enabled = true
                                   LIMIT 1"""
                            )
                            if row and row['api_key']:
                                openai_key = row['api_key']
                                # Use selected model from DB if available
                                if row['selected_model']:
                                    openai_model = row['selected_model']
                                logger.info(f"[{purpose}] Using OpenAI API key from ai_providers table (model: {openai_model})")
                    except Exception as db_err:
                        logger.debug(f"[{purpose}] Could not fetch OpenAI key from ai_providers: {db_err}")

                # Fall back to environment variable
                if not openai_key:
                    openai_key = os.getenv('OPENAI_API_KEY')
                    if openai_key and openai_key != 'your-openai-api-key-here':
                        logger.info(f"[{purpose}] Using OpenAI API key from environment")

                if not openai_key or openai_key == 'your-openai-api-key-here':
                    logger.error(f"[{purpose}] OPENAI_API_KEY not found in ai_providers table or environment")
                    return None

                # Set max_tokens based on purpose if not provided
                if max_tokens is None:
                    if 'riggs' in purpose.lower():
                        max_tokens = 4000
                    else:
                        max_tokens = 2000

                logger.info(f"[{purpose}] Calling OpenAI ({openai_model}, max_tokens={max_tokens})")

                start_time = time.time()
                try:
                    client = openai.AsyncOpenAI(api_key=openai_key)
                    # Use max_completion_tokens for newer models (gpt-5+, o1+), max_tokens for older
                    use_new_param = any(x in openai_model.lower() for x in ['gpt-5', 'gpt-4.1', 'o1', 'o3', 'o4'])
                    if use_new_param:
                        response = await client.chat.completions.create(
                            model=openai_model,
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.1,
                            max_completion_tokens=max_tokens
                        )
                    else:
                        response = await client.chat.completions.create(
                            model=openai_model,
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.1,
                            max_tokens=max_tokens
                        )
                    response_time_ms = int((time.time() - start_time) * 1000)

                    # Handle potential None or empty response
                    response_text = response.choices[0].message.content if response.choices else None
                    finish_reason = response.choices[0].finish_reason if response.choices else 'unknown'

                    if response_text is None:
                        response_text = ''
                        # Check for refusal
                        if hasattr(response.choices[0].message, 'refusal') and response.choices[0].message.refusal:
                            logger.warning(f"[{purpose}] OpenAI refused: {response.choices[0].message.refusal}")

                    # Log full response structure for debugging
                    logger.info(f"[{purpose}] OpenAI finish_reason: {finish_reason}, content_len: {len(response_text)}")
                    if len(response_text) == 0:
                        logger.warning(f"[{purpose}] Empty response! Full choice: {response.choices[0]}")

                    # Track token usage
                    prompt_tokens = response.usage.prompt_tokens if response.usage else len(prompt) // 4
                    completion_tokens = response.usage.completion_tokens if response.usage else len(response_text) // 4

                    tracker = await _get_token_tracker()
                    if tracker:
                        await tracker.track(
                            provider='openai',
                            model=openai_model,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            request_type=purpose,
                            status='success',
                            response_time_ms=response_time_ms
                        )

                    logger.info(f"[{purpose}] OpenAI response received ({len(response_text)} chars, {response_time_ms}ms)")
                    return response_text

                except openai.APIError as e:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    logger.error(f"[{purpose}] OpenAI API error: {e}")
                    tracker = await _get_token_tracker()
                    if tracker:
                        await tracker.track(
                            provider='openai',
                            model=openai_model,
                            prompt_tokens=0,
                            completion_tokens=0,
                            request_type=purpose,
                            status='failed',
                            response_time_ms=response_time_ms,
                            error_message=str(e)
                        )
                    return None

            # LM Studio - for development
            if ai_provider == 'lm_studio':
                lm_studio_url = os.getenv('LM_STUDIO_URL', 'http://host.docker.internal:1234')
                lm_studio_model = os.getenv('LM_STUDIO_MODEL', 'gpt-oss-20b')

                if '/v1' in lm_studio_url:
                    api_url = f"{lm_studio_url.rstrip('/')}/chat/completions"
                else:
                    api_url = f"{lm_studio_url.rstrip('/')}/v1/chat/completions"

                payload = {
                    "model": lm_studio_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 4000
                }

                logger.info(f"[{purpose}] Calling LM Studio at {api_url}")

                start_time = time.time()
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        api_url,
                        headers={"Content-Type": "application/json"},
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=120)
                    ) as response:
                        response_time_ms = int((time.time() - start_time) * 1000)

                        if response.status != 200:
                            error_text = await response.text()
                            logger.error(f"[{purpose}] LM Studio error: {response.status} - {error_text}")
                            # Track failed request
                            tracker = await _get_token_tracker()
                            if tracker:
                                await tracker.track(
                                    provider='lmstudio',
                                    model=lm_studio_model,
                                    prompt_tokens=0,
                                    completion_tokens=0,
                                    request_type=purpose,
                                    status='failed',
                                    response_time_ms=response_time_ms,
                                    error_message=f"HTTP {response.status}"
                                )
                            return None
                        data = await response.json()
                        response_text = data['choices'][0]['message']['content']

                        # Track token usage
                        usage = data.get('usage', {})
                        prompt_tokens = usage.get('prompt_tokens', len(prompt) // 4)
                        completion_tokens = usage.get('completion_tokens', len(response_text) // 4)

                        tracker = await _get_token_tracker()
                        if tracker:
                            await tracker.track(
                                provider='lmstudio',
                                model=lm_studio_model,
                                prompt_tokens=prompt_tokens,
                                completion_tokens=completion_tokens,
                                request_type=purpose,
                                status='success',
                                response_time_ms=response_time_ms
                            )

                        return response_text

            # Ollama fallback
            ollama_host = os.getenv('OLLAMA_HOST', 'ollama')
            ollama_port = os.getenv('OLLAMA_PORT', '11434')
            ollama_model = os.getenv('OLLAMA_MODEL', 'qwen2.5:32b')
            ollama_url = f"http://{ollama_host}:{ollama_port}/api/generate"

            payload = {
                "model": ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 4000}
            }

            logger.info(f"[{purpose}] Calling Ollama at {ollama_url}")

            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    ollama_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=180)
                ) as response:
                    response_time_ms = int((time.time() - start_time) * 1000)

                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"[{purpose}] Ollama error: {response.status} - {error_text}")
                        # Track failed request
                        tracker = await _get_token_tracker()
                        if tracker:
                            await tracker.track(
                                provider='ollama',
                                model=ollama_model,
                                prompt_tokens=0,
                                completion_tokens=0,
                                request_type=purpose,
                                status='failed',
                                response_time_ms=response_time_ms,
                                error_message=f"HTTP {response.status}"
                            )
                        return None
                    data = await response.json()
                    response_text = data.get('response', '')

                    # Track token usage (Ollama provides actual token counts)
                    prompt_tokens = data.get('prompt_eval_count', len(prompt) // 4)
                    completion_tokens = data.get('eval_count', len(response_text) // 4)

                    tracker = await _get_token_tracker()
                    if tracker:
                        await tracker.track(
                            provider='ollama',
                            model=ollama_model,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            request_type=purpose,
                            status='success',
                            response_time_ms=response_time_ms
                        )

                    return response_text

        except Exception as e:
            logger.error(f"[{purpose}] LLM call failed: {e}")
            return None

    async def _call_lm_studio_triage(
        self,
        context: Dict[str, Any],
        model: str,
        endpoint_url: Optional[str] = None,
        api_key: Optional[str] = None,
        provider_label: str = "lmstudio",
    ) -> Dict[str, Any]:
        """
        Call any OpenAI-compatible /v1/chat/completions endpoint.

        Default is LM Studio (no auth). When an api_key is supplied, an
        Authorization Bearer header is added so this same function serves
        BYO OpenAI / Ollama / vLLM behind auth.
        """

        # Default to localhost LM Studio
        base_url = endpoint_url or os.getenv('LM_STUDIO_URL', 'http://host.docker.internal:1234')

        # Build the prompt
        prompt = self._build_triage_prompt(context)

        try:
            import aiohttp

            headers = {
                "Content-Type": "application/json"
            }
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            # LM Studio uses OpenAI-compatible API
            # NOTE: Some models (e.g., Mistral) don't support system role, so we merge it into user message
            system_instruction = "You are a security analyst AI assistant. Respond with valid JSON only."
            combined_prompt = f"[INSTRUCTIONS]\n{system_instruction}\n\n[USER REQUEST]\n{prompt}"

            payload = {
                "model": model or "default",
                "messages": [
                    {"role": "user", "content": combined_prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 2000
            }

            # Handle URLs that already have /v1 or don't
            if '/v1' in base_url:
                api_url = f"{base_url.rstrip('/')}/chat/completions"
            else:
                api_url = f"{base_url.rstrip('/')}/v1/chat/completions"
            logger.info(f"Calling LM Studio at {api_url}")

            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)  # LM Studio can be slower
                ) as response:
                    response_time_ms = int((time.time() - start_time) * 1000)

                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"{provider_label} API error: {response.status} - {error_text}")
                        # Track failed request
                        tracker = await _get_token_tracker()
                        if tracker:
                            await tracker.track(
                                provider=provider_label,
                                model=model or 'default',
                                prompt_tokens=0,
                                completion_tokens=0,
                                request_type='triage',
                                status='failed',
                                response_time_ms=response_time_ms,
                                error_message=f"HTTP {response.status}: {error_text[:200]}"
                            )
                        return self._mock_triage(context)

                    data = await response.json()
                    response_text = data['choices'][0]['message']['content']
                    logger.info(f"LM Studio response received ({len(response_text)} chars)")

                    # Track token usage from OpenAI-compatible response
                    usage = data.get('usage', {})
                    prompt_tokens = usage.get('prompt_tokens', len(combined_prompt) // 4)  # Estimate if not provided
                    completion_tokens = usage.get('completion_tokens', len(response_text) // 4)

                    tracker = await _get_token_tracker()
                    if tracker:
                        await tracker.track(
                            provider=provider_label,
                            model=model or 'default',
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            request_type='triage',
                            status='success',
                            response_time_ms=response_time_ms
                        )

                    parsed = self._parse_triage_response(response_text)
                    # Surface usage so BYO callers can write to tenant_byo_usage
                    if parsed is not None and isinstance(parsed, dict):
                        parsed["_usage"] = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                        }
                    return parsed

        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Cannot connect to LM Studio at {base_url}: {e}")
            return self._mock_triage(context)
        except Exception as e:
            logger.error(f"LM Studio triage call failed: {e}")
            return self._mock_triage(context)

    async def _call_ollama_triage(self, context: Dict[str, Any], model: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Call Ollama for triage decision. Returns None if Ollama unavailable."""

        # Build the prompt
        prompt = self._build_triage_prompt(context)

        try:
            import aiohttp

            headers = {"Content-Type": "application/json"}

            # Ollama uses OpenAI-compatible API at /v1/chat/completions
            api_url = f"{base_url}/v1/chat/completions"

            system_instruction = "You are a security analyst AI. Respond ONLY with valid JSON matching the requested format."

            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 512,  # Short responses for T1 triage
                "temperature": 0.1,
                "stream": False
            }

            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    response_time_ms = int((time.time() - start_time) * 1000)

                    if response.status != 200:
                        error_text = await response.text()
                        logger.warning(f"Ollama API error: {response.status} - {error_text}")
                        # Track failed request
                        tracker = await _get_token_tracker()
                        if tracker:
                            await tracker.track(
                                provider='ollama',
                                model=model,
                                prompt_tokens=0,
                                completion_tokens=0,
                                request_type='triage',
                                status='failed',
                                response_time_ms=response_time_ms,
                                error_message=f"HTTP {response.status}"
                            )
                        return None  # Return None to try fallback providers

                    data = await response.json()
                    response_text = data['choices'][0]['message']['content']
                    logger.info(f"Ollama triage response received ({len(response_text)} chars)")

                    # Track token usage
                    usage = data.get('usage', {})
                    prompt_tokens = usage.get('prompt_tokens', len(prompt) // 4)
                    completion_tokens = usage.get('completion_tokens', len(response_text) // 4)

                    tracker = await _get_token_tracker()
                    if tracker:
                        await tracker.track(
                            provider='ollama',
                            model=model,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            request_type='triage',
                            status='success',
                            response_time_ms=response_time_ms
                        )

                    # Parse the JSON response
                    return self._parse_triage_response(response_text)

        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Cannot connect to Ollama at {base_url}: {e}")
            return None  # Return None to try fallback
        except Exception as e:
            logger.error(f"Ollama triage call failed: {e}")
            return None

    async def _call_byo_triage(self, context: Dict[str, Any], tenant_id: str, ctx) -> Dict[str, Any]:
        """
        Run triage against a tenant's own BYO provider.

        Dispatches by api_style to the right HTTP shape, then records the
        round-trip in tenant_byo_usage so the tenant sees their own spend.
        Failures fall through to the next priority tier (raising would
        deny the tenant any triage at all when their own key has a
        transient issue).
        """
        try:
            if ctx.api_style == "anthropic":
                result = await self._call_anthropic_triage(
                    context, ctx.api_key, ctx.model or self.model,
                    base_url=ctx.base_url,
                )
            else:
                # OpenAI-compatible: OpenAI proper or self-hosted shim (LM Studio,
                # Ollama, vLLM). _call_lm_studio_triage already speaks this shape.
                base_url = ctx.base_url or "https://api.openai.com"
                result = await self._call_lm_studio_triage(
                    context, ctx.model or self.model, base_url,
                    api_key=ctx.api_key, provider_label=ctx.provider,
                )

            # Best-effort BYO usage tracking — never fail a successful call
            try:
                from services import tenant_ai_config_service as _cfg_svc
                usage = (result or {}).get("_usage") or {}
                await _cfg_svc.record_byo_usage(
                    tenant_id=tenant_id, provider=ctx.provider,
                    prompt_tokens=int(usage.get("prompt_tokens") or 0),
                    completion_tokens=int(usage.get("completion_tokens") or 0),
                    total_tokens=int(usage.get("total_tokens") or 0),
                )
            except Exception as e:
                logger.warning(f"[BYO] usage tracking failed: {e}")

            return result
        except Exception as e:
            logger.error(f"[BYO] triage call failed for tenant {tenant_id}: {e}")
            raise

    async def _call_anthropic_triage(
        self,
        context: Dict[str, Any],
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Call Anthropic API for triage decision."""

        # Use template prompt if provided (guardrailed), otherwise build standard prompt
        template_prompt = context.get('template_prompt')
        if template_prompt:
            # Template-based call: use curated system prompt + alert data as user message
            import json as _json
            alert_summary = _json.dumps(context.get('alert_details', {}), indent=2, default=str)[:4000]
            enrichment_summary = _json.dumps(context.get('enrichment_results', {}), indent=2, default=str)[:2000]
            user_content = f"ALERT DATA:\n{alert_summary}\n\nENRICHMENT DATA:\n{enrichment_summary}"
            custom_instr = context.get('custom_instructions', '')
            if custom_instr:
                template_prompt = f"{template_prompt}\n\nAdditional analyst context: {custom_instr}"
            prompt = f"{template_prompt}\n\n{user_content}"
        else:
            prompt = self._build_triage_prompt(context)

        # Cap max_tokens: use template cap if provided, otherwise default 2000
        max_tokens = min(context.get('template_max_tokens', 2000), 2000)

        try:
            import aiohttp

            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }

            # Send the static decision criteria + response format as a CACHED
            # system block. Per-alert content goes in the user message. The
            # cache_control marker tells Anthropic to cache the system block
            # for ~5 minutes; subsequent calls within that window read it at
            # 10% of normal input-token cost.
            #
            # Template-prompt callers (custom guardrails) bypass our system
            # prompt — they bring their own — so they don't get caching for
            # this call. That's by design; their prompts vary per alert.
            uses_default_system = not context.get('template_prompt')
            payload = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
            }
            if uses_default_system:
                payload["system"] = [{
                    "type": "text",
                    "text": _TRIAGE_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }]

            # base_url honors the BYO config (e.g. Anthropic-compatible proxy)
            api_url = ((base_url or "https://api.anthropic.com").rstrip("/")) + "/v1/messages"
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Anthropic API error: {response.status} - {error_text}")
                        return self._mock_triage(context)

                    data = await response.json()
                    response_text = data['content'][0]['text']

                    parsed = self._parse_triage_response(response_text)
                    # Stash provider usage so BYO callers can record it.
                    # Include cache metrics so we can verify caching is firing
                    # and the cost model is accurate.
                    usage = data.get("usage", {}) or {}
                    in_t = int(usage.get("input_tokens") or 0)
                    out_t = int(usage.get("output_tokens") or 0)
                    cache_create = int(usage.get("cache_creation_input_tokens") or 0)
                    cache_read = int(usage.get("cache_read_input_tokens") or 0)
                    if parsed is not None and isinstance(parsed, dict):
                        parsed["_usage"] = {
                            "prompt_tokens": in_t + cache_create + cache_read,
                            "completion_tokens": out_t,
                            "total_tokens": in_t + cache_create + cache_read + out_t,
                            "cache_creation_tokens": cache_create,
                            "cache_read_tokens": cache_read,
                        }
                        if cache_read > 0:
                            logger.info(
                                f"[CACHE_HIT] Triage cached {cache_read} input tokens "
                                f"(saved ~{cache_read * 0.9 * 3 / 1_000_000:.4f} USD)"
                            )

                    # Record to ai_token_usage. Anthropic triage was previously
                    # untracked, which is why the platform token-usage dashboard
                    # showed only OpenAI/LM Studio/Ollama numbers.
                    try:
                        tracker = await _get_token_tracker()
                        if tracker:
                            alert_id = (context.get('alert') or {}).get('id')
                            await tracker.track(
                                provider='anthropic',
                                model=model,
                                prompt_tokens=in_t,
                                completion_tokens=out_t,
                                request_type='triage',
                                alert_id=str(alert_id) if alert_id else None,
                                status='success',
                                response_time_ms=response_time_ms,
                                cache_creation_tokens=cache_create,
                                cache_read_tokens=cache_read,
                            )
                    except Exception as track_err:
                        logger.warning(f"[TRACK] failed to record Anthropic usage: {track_err}")

                    return parsed

        except Exception as e:
            logger.error(f"Anthropic triage API call failed: {e}")
            return self._mock_triage(context)

    def _format_playbook_results(self, context: Dict[str, Any]) -> str:
        """
        Format automated playbook results for inclusion in the triage prompt.

        Pre-triage playbooks run AFTER enrichment but BEFORE T1 triage.
        T1 sees what automated responses have already been taken.
        """
        # Get playbook results summary from enrichment data
        enrichment = context.get('enrichment_results', {})
        playbook_summary = enrichment.get('playbook_results_summary', '')

        # Also check raw playbook_results_summary in context
        if not playbook_summary:
            playbook_summary = context.get('playbook_results_summary', '')

        if not playbook_summary or playbook_summary == "No automated playbooks have run for this alert.":
            return ""

        return f"""

═══════════════════════════════════════════════════════════════════════════
AUTOMATED RESPONSE ACTIONS (ALREADY EXECUTED)
═══════════════════════════════════════════════════════════════════════════
The following playbooks ran automatically after enrichment. Review their
outcomes and note any failures that may require manual follow-up.

{playbook_summary}

IMPORTANT: If playbooks FAILED, you MUST note this in your key_findings.
If containment actions succeeded, factor this into your verdict confidence.
═══════════════════════════════════════════════════════════════════════════
"""

    def _format_phishing_indicators(self, context: Dict[str, Any]) -> str:
        """
        Format phishing indicators for inclusion in the triage prompt.

        These signals allow T1 to detect social engineering WITHOUT requiring
        malicious IOCs. This is critical for brand impersonation phishing.
        """
        indicators = context.get('phishing_indicators', {})
        if not indicators.get('detected'):
            return ""

        lines = ["\n\n═══════════════════════════════════════════════════════════════════════════"]
        lines.append("⚠️  PHISHING INDICATORS (Social Engineering Evidence)")
        lines.append("═══════════════════════════════════════════════════════════════════════════")
        lines.append("NOTE: These indicate INTENT-based maliciousness, not IOC-based.")
        lines.append("An email can be MALICIOUS due to social engineering even if IOCs are clean.")

        # Brand impersonation
        brand = indicators.get('brand_impersonation', {})
        if brand:
            lines.append(f"\n[BRAND IMPERSONATION DETECTED]")
            lines.append(f"  Target Brand: {brand.get('brand', 'unknown').upper()}")
            lines.append(f"  Sender Domain: {brand.get('sender_domain', 'unknown')}")
            lines.append(f"  Domain Similarity: {brand.get('domain_similarity_score', 0):.0%}")
            if brand.get('is_typosquat'):
                lines.append(f"  ⚠️  TYPOSQUAT DETECTED: similar to {brand.get('closest_legitimate_domain')}")
            lines.append(f"  Confidence: {brand.get('confidence', 0):.0%}")

        # Language signals
        lang = indicators.get('language_signals', {})
        if lang:
            lines.append(f"\n[SOCIAL ENGINEERING LANGUAGE SIGNALS]")
            if lang.get('urgency'):
                lines.append("  ✓ URGENCY TACTICS: Uses pressure language (act now, expire, suspended)")
            if lang.get('credential_request'):
                lines.append("  ✓ CREDENTIAL REQUEST: Asks to verify/confirm password or login")
            if lang.get('account_threat'):
                lines.append("  ✓ ACCOUNT THREAT: Claims suspicious activity or compromise")
            lines.append(f"  Signal Count: {lang.get('count', 0)}/3")

        # User interaction
        user = indicators.get('user_interaction', {})
        if user:
            lines.append(f"\n[USER INTERACTION EVIDENCE]")
            if user.get('clicked'):
                lines.append("  ⚠️  USER CLICKED THE LINK")
            if user.get('credentials_entered'):
                lines.append("  🚨 CREDENTIALS MAY HAVE BEEN ENTERED")
            if user.get('reported_by_user'):
                lines.append("  ℹ️  Reported by user (aware of potential threat)")

        # Authentication failures
        auth = indicators.get('authentication_failures', {})
        if auth:
            lines.append(f"\n[EMAIL AUTHENTICATION FAILURES]")
            if auth.get('spf_fail'):
                lines.append("  ❌ SPF FAIL: Sender IP not authorized")
            if auth.get('dkim_fail'):
                lines.append("  ❌ DKIM FAIL: Email signature invalid")
            if auth.get('dmarc_fail'):
                lines.append("  ❌ DMARC FAIL: Domain policy violation")
            if auth.get('spoofing_likely'):
                lines.append("  🚨 HIGH SPOOFING LIKELIHOOD: SPF + DKIM both failed")

        # Overall confidence
        overall = indicators.get('overall_confidence', 0)
        lines.append(f"\nPHISHING INDICATOR CONFIDENCE: {overall:.0%}")

        return "\n".join(lines)

    def _build_triage_prompt(self, context: Dict[str, Any]) -> str:
        """
        Build an enhanced L1 triage prompt with clear decision criteria.

        This prompt gives the AI explicit rules for making triage decisions,
        reducing ambiguity and improving consistency.

        When ENABLE_FLAG_BASED_TRIAGE is enabled and alert_flags are provided,
        uses specialized prompts for better accuracy and fewer tokens.
        """
        from config.system_config import ENABLE_FLAG_BASED_TRIAGE

        # Check if we should use specialized prompts
        alert_flags = context.get('alert_flags', [])
        if ENABLE_FLAG_BASED_TRIAGE and alert_flags:
            return self._build_specialized_prompt(context, alert_flags)

        # ═══════════════════════════════════════════════════════════════════════
        # DIRECTIVE §5: FULL IOC EVIDENCE (NOT JUST COUNTS)
        # ═══════════════════════════════════════════════════════════════════════
        # Per directive: T1 must receive full enrichment evidence with:
        # - Source name
        # - Verdict
        # - Confidence / score
        # - Detection details (e.g., VT positives, AbuseIPDB score)
        # - Labels / threat families where available
        # Counts-only summaries are PROHIBITED.
        # ═══════════════════════════════════════════════════════════════════════

        summary = context.get('enrichment_summary', {})
        malicious = summary.get('malicious', 0)
        suspicious = summary.get('suspicious', 0)
        clean = summary.get('clean', 0)
        total = summary.get('total_enriched', 0)

        # Build FULL IOC evidence (Directive §5 compliant)
        ioc_evidence_lines = []
        malicious_iocs = []
        suspicious_iocs = []

        def format_ioc_evidence(ioc: Dict[str, Any], ioc_type: str) -> str:
            """Format a single IOC with full evidence details."""
            v = ioc.get('value', 'unknown')
            if len(v) > 64:
                v = v[:64] + '...'
            verdict = ioc.get('verdict', 'unknown')
            confidence = ioc.get('confidence')
            sources = ioc.get('sources', [])
            score = ioc.get('score') or ioc.get('consensus_score')

            # Build evidence line with full details
            evidence_parts = [f"{ioc_type}:{v}"]
            evidence_parts.append(f"verdict={verdict}")

            if confidence is not None:
                evidence_parts.append(f"confidence={confidence}")
            if score is not None:
                evidence_parts.append(f"score={score}")
            if sources:
                source_str = ','.join(str(s)[:20] for s in sources[:3])
                evidence_parts.append(f"sources=[{source_str}]")

            # Add detection details if available
            detections = ioc.get('detections', [])
            if detections:
                det_str = ','.join(str(d)[:30] for d in detections[:3])
                evidence_parts.append(f"detections=[{det_str}]")

            # Add threat family if available
            threat_family = ioc.get('threat_family') or ioc.get('malware_family')
            if threat_family:
                evidence_parts.append(f"family={threat_family}")

            # Add VT-specific details if available
            vt_positives = ioc.get('vt_positives') or ioc.get('positives')
            vt_total = ioc.get('vt_total') or ioc.get('total')
            if vt_positives is not None and vt_total is not None:
                evidence_parts.append(f"VT={vt_positives}/{vt_total}")

            # Add AbuseIPDB score if available
            abuse_score = ioc.get('abuse_confidence_score') or ioc.get('abuseipdb_score')
            if abuse_score is not None:
                evidence_parts.append(f"AbuseIPDB={abuse_score}%")

            return ' | '.join(evidence_parts)

        # Process IPs with full evidence
        for ioc in context['enrichment_results'].get('ips', []):
            evidence_line = format_ioc_evidence(ioc, 'IP')
            ioc_evidence_lines.append(evidence_line)

            verdict = (ioc.get('verdict') or '').lower()
            v = ioc.get('value', 'unknown')
            if verdict == 'malicious' or ioc.get('malicious'):
                malicious_iocs.append(f"IP:{v}")
            elif verdict == 'suspicious':
                suspicious_iocs.append(f"IP:{v}")

        # Process domains with full evidence
        for ioc in context['enrichment_results'].get('domains', []):
            evidence_line = format_ioc_evidence(ioc, 'DOMAIN')
            ioc_evidence_lines.append(evidence_line)

            verdict = (ioc.get('verdict') or '').lower()
            v = ioc.get('value', 'unknown')
            if verdict == 'malicious' or ioc.get('malicious'):
                malicious_iocs.append(f"DOMAIN:{v}")
            elif verdict == 'suspicious':
                suspicious_iocs.append(f"DOMAIN:{v}")

        # Process hashes with full evidence
        for ioc in context['enrichment_results'].get('hashes', []):
            evidence_line = format_ioc_evidence(ioc, 'HASH')
            ioc_evidence_lines.append(evidence_line)

            verdict = (ioc.get('verdict') or '').lower()
            v = ioc.get('value', 'unknown')[:16]
            if verdict == 'malicious' or ioc.get('malicious'):
                malicious_iocs.append(f"HASH:{v}...")
            elif verdict == 'suspicious':
                suspicious_iocs.append(f"HASH:{v}...")

        # Process URLs with full evidence
        for ioc in context['enrichment_results'].get('urls', []):
            evidence_line = format_ioc_evidence(ioc, 'URL')
            ioc_evidence_lines.append(evidence_line)

            verdict = (ioc.get('verdict') or '').lower()
            v = ioc.get('value', 'unknown')[:50]
            if verdict == 'malicious' or ioc.get('malicious'):
                malicious_iocs.append(f"URL:{v}...")
            elif verdict == 'suspicious':
                suspicious_iocs.append(f"URL:{v}...")

        # Format full evidence (not just summary)
        if ioc_evidence_lines:
            ioc_summary = "\n".join(f"  - {line}" for line in ioc_evidence_lines[:20])  # Limit to 20 IOCs
        else:
            ioc_summary = "  No IOCs enriched"

        # Include failed enrichments for transparency (Directive §2.2)
        failed_enrichments = context.get('enrichment_results', {}).get('_errors', [])
        failed_section = ""
        if failed_enrichments:
            failed_lines = []
            for f in failed_enrichments[:5]:
                failed_lines.append(f"  - {f.get('type', 'unknown')}:{f.get('value', 'unknown')[:30]} | reason={f.get('reason', f.get('error', 'unknown'))}")
            failed_section = "\n\nFAILED ENRICHMENTS (explicit failures):\n" + "\n".join(failed_lines)

        # Sender trust context
        trust_context = ""
        sender_trust = context.get('sender_trust', {})
        if sender_trust.get('is_trusted_sender'):
            trust_level = sender_trust.get('trusted_sender_result', {}).get('trust_level', 'unknown')
            org = sender_trust.get('trusted_sender_result', {}).get('organization', '')
            trust_context = f"[TRUSTED SENDER: {trust_level}] Organization: {org}"
        elif sender_trust.get('domain_age_valid') is False:
            trust_context = "[WARNING] Sender domain is newly registered (< 1 year old)"

        # Email context - include full body for phishing analysis
        email_context = ""
        email = context.get('email', {})
        if email.get('sender') or email.get('subject'):
            body_text = email.get('body_preview', '')
            # Truncate extremely long bodies but keep most content for analysis
            if len(body_text) > 5000:
                body_text = body_text[:5000] + "\n[... truncated ...]"
            email_context = f"""
EMAIL CONTEXT:
  Sender: {email.get('sender', 'N/A')}
  Subject: {email.get('subject', 'N/A')}
  Body:
{body_text}"""

        # Build raw event analysis section (critical for EDR/endpoint alerts)
        raw_analysis = ""
        raw_event_data = context.get('raw_event_analysis', {})
        if raw_event_data:
            raw_lines = []
            if raw_event_data.get('command_line'):
                raw_lines.append(f"CMDLINE: {raw_event_data['command_line']}")
            if raw_event_data.get('process_image'):
                raw_lines.append(f"PROCESS: {raw_event_data['process_image']}")
            if raw_event_data.get('parent_process'):
                raw_lines.append(f"PARENT: {raw_event_data['parent_process']}")
            if raw_event_data.get('user'):
                raw_lines.append(f"USER: {raw_event_data['user']}")
            if raw_event_data.get('network_connections'):
                conns = raw_event_data['network_connections']
                conn_str = "; ".join([f"{c.get('dst_ip')}:{c.get('dst_port')}" for c in conns[:3]])
                raw_lines.append(f"NETWORK: {conn_str}")
            if raw_event_data.get('behaviors'):
                behaviors = raw_event_data['behaviors']
                beh_str = "; ".join([f"{b.get('tactic', '')}/{b.get('technique', '')}" for b in behaviors[:2]])
                raw_lines.append(f"MITRE: {beh_str}")
            if raw_event_data.get('urls'):
                urls = raw_event_data['urls'][:2]
                for url_obj in urls:
                    if isinstance(url_obj, dict):
                        raw_lines.append(f"URL: {url_obj.get('url', '')} -> {url_obj.get('expanded_url', '')}")
            if raw_event_data.get('quarantine_files'):
                for qf in raw_event_data['quarantine_files'][:2]:
                    raw_lines.append(f"QUARANTINED: {qf.get('path', '')} ({qf.get('sha256', '')[:16]}...)")
            if raw_event_data.get('detection'):
                det = raw_event_data['detection']
                raw_lines.append(f"DETECTION: {det.get('name', '')} | Family: {det.get('family', '')}")
            # Email authentication headers - critical for phishing analysis
            if raw_event_data.get('email_headers'):
                headers = raw_event_data['email_headers']
                header_lines = []
                # Prioritize security-critical headers
                for key in ['Authentication-Results', 'Received-SPF', 'DKIM-Signature', 'ARC-Authentication-Results',
                            'X-Spam-Status', 'X-Originating-IP', 'Return-Path', 'Reply-To']:
                    if key in headers:
                        value = str(headers[key])[:200]  # Truncate long values
                        header_lines.append(f"  {key}: {value}")
                if header_lines:
                    raw_lines.append("EMAIL AUTH HEADERS (check SPF/DKIM pass/fail):")
                    raw_lines.extend(header_lines)
            if raw_event_data.get('received_chain'):
                chain = raw_event_data['received_chain'][:3]  # First 3 hops
                raw_lines.append(f"EMAIL PATH ({len(raw_event_data['received_chain'])} hops): {' -> '.join([h[:50] for h in chain])}")
            if raw_lines:
                raw_analysis = "\n\nRAW EVENT DATA:\n" + "\n".join(raw_lines)

        # Build decoded content section (pre-decoded base64)
        decoded_section = ""
        if context.get('decoded_content'):
            decoded_section = "\n\n[DECODED BASE64 CONTENT - CRITICAL FOR ANALYSIS]:\n"
            for dc in context['decoded_content']:
                decoded_section += f"Encoded: {dc['encoded']}\n"
                decoded_section += f"DECODED: {dc['decoded']}\n\n"

        # Build decoded IOCs section
        decoded_iocs_section = ""
        if context.get('decoded_iocs'):
            decoded_iocs_section = "\n[IOCs EXTRACTED FROM DECODED CONTENT]:\n"
            for ioc_type, values in context['decoded_iocs'].items():
                if values:
                    decoded_iocs_section += f"  {ioc_type}: {', '.join(str(v) for v in values[:5])}\n"

        # Build refanged IOCs section
        refanged_section = ""
        if context.get('refanged_iocs'):
            refanged_section = "\n[REFANGED IOCs (originally defanged)]:\n"
            for ioc_type, values in context['refanged_iocs'].items():
                if values:
                    refanged_section += f"  {ioc_type}: {', '.join(str(v) for v in values[:5])}\n"

        # Knowledge base context (SOPs)
        kb_section = ""
        kb_entries = context.get('knowledge_base_context', [])
        if kb_entries:
            kb_section = "\n\n" + "="*70 + "\n"
            kb_section += "[COMPANY SOPs AND PLAYBOOKS]\n"
            kb_section += "="*70 + "\n"
            kb_section += f"Found {len(kb_entries)} relevant procedures in knowledge base:\n\n"

            for i, entry in enumerate(kb_entries[:5], 1):  # Show top 5 instead of 3
                kb_section += f"[SOP {i}] {entry.get('title', 'Untitled')}\n"
                kb_section += f"  Type: {entry.get('content_type', 'sop')} | Category: {entry.get('category', 'general')}\n"

                # Show similarity score if available (from semantic search)
                if 'similarity' in entry:
                    kb_section += f"  Relevance: {entry['similarity']:.0%}\n"

                # Show first 400 chars of content (increased from 100)
                content = entry.get('content', entry.get('summary', ''))
                if content:
                    content_preview = content[:400] + ('...' if len(content) > 400 else '')
                    kb_section += f"  Guidance: {content_preview}\n"

                # Show MITRE techniques if available
                if entry.get('mitre_techniques'):
                    kb_section += f"  MITRE: {', '.join(entry['mitre_techniques'][:5])}\n"

                # Show incident types if available
                if entry.get('incident_types'):
                    kb_section += f"  Applies to: {', '.join(entry['incident_types'][:5])}\n"

                kb_section += "\n"

            kb_section += "Use these SOPs as guidance when making your triage decision.\n"
            kb_section += "="*70 + "\n"

        # Per-alert user content. The static decision criteria + response
        # format live in _TRIAGE_SYSTEM_PROMPT (sent as a cached system block
        # by _call_anthropic_triage) — do NOT duplicate them here.
        return f"""═══════════════════════════════════════════════════════════════════════════
ALERT DETAILS
═══════════════════════════════════════════════════════════════════════════
Title: {context['alert']['title']}
Description: {context['alert']['description'][:300]}
Severity: {context['alert']['severity']}
Source: {context['alert'].get('source', 'unknown')}
{trust_context}{email_context}

═══════════════════════════════════════════════════════════════════════════
IOC ENRICHMENT EVIDENCE (FULL DETAILS - NOT JUST COUNTS)
═══════════════════════════════════════════════════════════════════════════
SUMMARY: Total={total} | Malicious={malicious} | Suspicious={suspicious} | Clean={clean}

FULL IOC EVIDENCE (source, verdict, score, detections):
{ioc_summary}
{failed_section}
{f"MALICIOUS IOCs REQUIRING ACTION: {', '.join(malicious_iocs)}" if malicious_iocs else ""}
{f"SUSPICIOUS IOCs FOR REVIEW: {', '.join(suspicious_iocs)}" if suspicious_iocs else ""}{self._format_playbook_results(context)}{self._format_phishing_indicators(context)}{raw_analysis}{decoded_section}{decoded_iocs_section}{refanged_section}{kb_section}

Classify per the decision criteria. Respond with the JSON format from the system prompt."""

    def _build_specialized_prompt(self, context: Dict[str, Any], alert_flags: List[str]) -> str:
        """
        Build a specialized prompt based on alert classification flags.

        Uses focused prompts for each alert type (phishing, malware, lateral movement, etc.)
        which are shorter, more accurate, and consume fewer tokens.

        Args:
            context: The triage context with alert, enrichment, etc.
            alert_flags: List of alert classification flags

        Returns:
            Specialized prompt string
        """
        from services.alert_classifier import AlertClassifier, AlertFlag
        from services.specialized_prompts import format_prompt, get_enrichment_summary, get_phishing_indicators_summary

        # Convert flag strings back to AlertFlag enum
        flags_set = AlertClassifier.list_to_flags(alert_flags)

        # Get primary flag for prompt selection
        primary_flag = AlertClassifier.get_primary_flag(flags_set)

        # Build alert JSON (compact)
        alert_json = json.dumps({
            'title': context['alert'].get('title', ''),
            'description': context['alert'].get('description', '')[:500],
            'severity': context['alert'].get('severity', ''),
            'source': context['alert'].get('source', ''),
            'category': context['alert'].get('category', ''),
            'raw_event': context.get('raw_event_analysis', {}),
            'indicators': context.get('alert', {}).get('indicators', [])
        }, indent=2)

        # Build enrichment summary
        enrichment_data = context.get('enrichment_data', {})
        if not enrichment_data:
            # Build from enrichment_results if enrichment_data not directly available
            enrichment_data = {
                'results': context.get('enrichment_results', {}),
                'summary': context.get('enrichment_summary', {})
            }

        enrichment_summary = get_enrichment_summary(enrichment_data)

        # Get phishing indicators if available (for PHISHING alerts)
        phishing_data = context.get('phishing_indicators', {})
        phishing_indicators = get_phishing_indicators_summary(phishing_data)

        # Get formatted prompt for this alert type
        prompt = format_prompt(primary_flag, alert_json, enrichment_summary, phishing_indicators)

        # Log phishing detection for visibility
        if primary_flag == AlertFlag.PHISHING and phishing_data.get('detected'):
            logger.info(f"[SPECIALIZED_PROMPT] Phishing prompt with indicators: brand={phishing_data.get('brand_impersonation', {}).get('brand', 'none')}")

        logger.info(f"[SPECIALIZED_PROMPT] Using {primary_flag.value} prompt for flags: {alert_flags}")

        return prompt

    def _parse_triage_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the AI response into structured triage result.

        Handles various LLM output formats including:
        - Clean JSON
        - JSON wrapped in markdown code blocks
        - JSON with extra text before/after
        - Malformed JSON with extractable fields
        """
        import re

        if not response_text:
            return self._fallback_result("Empty response from AI")

        text = response_text.strip()

        # METHOD 1: Remove markdown code blocks
        if '```' in text:
            # Handle ```json ... ``` or ``` ... ```
            match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
            if match:
                text = match.group(1).strip()
            else:
                # Just strip the backticks
                text = re.sub(r'```(?:json)?', '', text).strip()

        # METHOD 2: Try direct JSON parse
        try:
            result = json.loads(text)
            if isinstance(result, dict) and result.get('verdict'):
                result['timestamp'] = datetime.utcnow().isoformat()
                result['status'] = 'completed'
                result['ai_model'] = self.model
                logger.info(f"[TRIAGE_PARSE] Clean JSON parse: verdict={result.get('verdict')}")
                return result
        except json.JSONDecodeError:
            pass

        # METHOD 3: Find JSON object in text (LLM may add extra text)
        json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', text)
        if not json_match:
            # Try finding nested JSON
            json_match = re.search(r'\{[\s\S]*"verdict"[\s\S]*\}', text)

        if json_match:
            try:
                # Find the full JSON object with brace matching
                start = text.find('{')
                if start >= 0:
                    brace_count = 0
                    end = start
                    for i, char in enumerate(text[start:], start):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end = i + 1
                                break

                    json_str = text[start:end]
                    result = json.loads(json_str)
                    if isinstance(result, dict) and result.get('verdict'):
                        result['timestamp'] = datetime.utcnow().isoformat()
                        result['status'] = 'completed'
                        result['ai_model'] = self.model
                        logger.info(f"[TRIAGE_PARSE] Extracted JSON: verdict={result.get('verdict')}")
                        return result
            except json.JSONDecodeError:
                pass

        # METHOD 4: Regex extraction for malformed JSON
        verdict_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
        conf_match = re.search(r'"confidence"\s*:\s*([\d.]+)', text)
        summary_match = re.search(r'"summary"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text)

        # Also try to extract decoded_iocs
        decoded_iocs = {'ips': [], 'urls': [], 'domains': []}
        iocs_match = re.search(r'"decoded_iocs"\s*:\s*\{([^}]*)\}', text)
        if iocs_match:
            iocs_text = iocs_match.group(1)
            # Extract IPs
            ips_match = re.search(r'"ips"\s*:\s*\[([^\]]*)\]', iocs_text)
            if ips_match:
                decoded_iocs['ips'] = re.findall(r'"([^"]+)"', ips_match.group(1))
            # Extract URLs
            urls_match = re.search(r'"urls"\s*:\s*\[([^\]]*)\]', iocs_text)
            if urls_match:
                decoded_iocs['urls'] = re.findall(r'"([^"]+)"', urls_match.group(1))
            # Extract domains
            domains_match = re.search(r'"domains"\s*:\s*\[([^\]]*)\]', iocs_text)
            if domains_match:
                decoded_iocs['domains'] = re.findall(r'"([^"]+)"', domains_match.group(1))

        if verdict_match:
            verdict = verdict_match.group(1).upper()
            # Normalize verdict
            if verdict in ['MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'FALSE_POSITIVE', 'NEEDS_INVESTIGATION']:
                result = {
                    'verdict': verdict,
                    'confidence': float(conf_match.group(1)) if conf_match else 0.5,
                    'summary': summary_match.group(1).replace('\\"', '"') if summary_match else 'Analysis completed.',
                    'decoded_iocs': decoded_iocs if any(decoded_iocs.values()) else {},
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': 'completed',
                    'ai_model': self.model,
                    'parse_method': 'regex_extraction'
                }
                logger.info(f"[TRIAGE_PARSE] Regex extraction: verdict={verdict}, decoded_iocs={decoded_iocs}")
                return result

        # METHOD 5: Look for verdict keywords in plain text
        text_lower = text.lower()
        if 'malicious' in text_lower and ('reverse shell' in text_lower or 'c2' in text_lower or 'command and control' in text_lower):
            return {
                'verdict': 'MALICIOUS',
                'confidence': 0.7,
                'summary': text[:200],
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed',
                'ai_model': self.model,
                'parse_method': 'keyword_extraction'
            }
        elif 'suspicious' in text_lower or 'encoded' in text_lower:
            return {
                'verdict': 'SUSPICIOUS',
                'confidence': 0.6,
                'summary': text[:200],
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed',
                'ai_model': self.model,
                'parse_method': 'keyword_extraction'
            }
        elif 'benign' in text_lower or 'false positive' in text_lower:
            return {
                'verdict': 'BENIGN',
                'confidence': 0.6,
                'summary': text[:200],
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed',
                'ai_model': self.model,
                'parse_method': 'keyword_extraction'
            }

        logger.warning(f"[TRIAGE_PARSE] All parse methods failed, using fallback. Response: {text[:300]}...")
        return self._fallback_result(f"Could not parse AI response: {text[:100]}...")

    def _fallback_result(self, reason: str) -> Dict[str, Any]:
        """Return a fallback triage result when parsing fails."""
        return {
            "status": "parse_error",
            "verdict": "NEEDS_INVESTIGATION",
            "confidence": 0.3,
            "summary": f"AI response could not be parsed. {reason}",
            "timestamp": datetime.utcnow().isoformat(),
            "ai_model": self.model,
            "requires_escalation": True
        }

    def _mock_triage(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a mock triage result based on enrichment data and sender analysis."""
        import re
        import asyncio

        summary = context.get('enrichment_summary', {})
        malicious_count = summary.get('malicious', 0)
        suspicious_count = summary.get('suspicious', 0)

        key_findings = [
            f"Analyzed {summary.get('total_enriched', 0)} IOCs",
            f"Malicious indicators: {malicious_count}",
            f"Suspicious indicators: {suspicious_count}"
        ]

        # Check for phishing SOP in knowledge base context
        kb_entries = context.get('knowledge_base_context', [])
        phishing_sop_id = None
        for entry in kb_entries:
            if 'phishing' in entry.get('title', '').lower() or 'phishing' in str(entry.get('tags', [])).lower():
                phishing_sop_id = entry.get('kb_id')
                key_findings.append(f"Applied phishing investigation checklist ({phishing_sop_id})")
                break

        # ===== CHECK TRUSTED SENDER ALLOWLIST =====
        from services.sender_trust_service import get_sender_trust_service
        sender_trust_service = get_sender_trust_service()

        # Extract sender and subject for trust checks
        alert_data = context.get('alert', {})
        email_context = context.get('email', {})
        sender = email_context.get('sender', '')
        subject = email_context.get('subject', '') or alert_data.get('title', '')

        # Fallback sender extraction from description
        if not sender:
            description = alert_data.get('description', '')
            title = alert_data.get('title', '')
            sender_match = re.search(r'(?:from|sender|reporter)[:\s]+([^\s<>]+@[^\s<>,]+)',
                                     f"{title} {description}", re.IGNORECASE)
            if sender_match:
                sender = sender_match.group(1).lower()

        trusted_sender_result = None
        phishing_test_result = None
        is_trusted_sender = False
        is_phishing_test = False

        # Run async checks synchronously in mock context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're already in an async context, use run_coroutine_threadsafe
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        sender_trust_service.check_trusted_sender(sender)
                    )
                    trusted_sender_result = future.result(timeout=2)

                    future2 = executor.submit(
                        asyncio.run,
                        sender_trust_service.check_phishing_test(sender, subject)
                    )
                    phishing_test_result = future2.result(timeout=2)
            else:
                trusted_sender_result = loop.run_until_complete(
                    sender_trust_service.check_trusted_sender(sender)
                )
                phishing_test_result = loop.run_until_complete(
                    sender_trust_service.check_phishing_test(sender, subject)
                )
        except Exception as e:
            logger.debug(f"Could not check sender trust: {e}")

        # Check if this is a phishing test (auto-close)
        if phishing_test_result and phishing_test_result.is_phishing_test:
            is_phishing_test = True
            key_findings.append(f"Phishing awareness test detected: {phishing_test_result.test_name or 'Unknown'}")
            if phishing_test_result.vendor:
                key_findings.append(f"Test vendor: {phishing_test_result.vendor}")

            return {
                "status": "completed",
                "verdict": "BENIGN",
                "confidence": 0.95,
                "severity_recommendation": "low",
                "summary": f"Phishing awareness test from {phishing_test_result.vendor or 'internal security team'}. Auto-closed per phishing test policy.",
                "key_findings": key_findings,
                "recommended_actions": [{
                    "action": "Auto-close as phishing test",
                    "priority": "immediate",
                    "reason": f"Matches phishing test pattern: {phishing_test_result.test_name}"
                }],
                "requires_escalation": False,
                "escalation_reason": None,
                # Canonical scale. Was 0.01 (inverted).
                "false_positive_likelihood": 0.99,
                "threat_type": "phishing_test",
                "disposition": phishing_test_result.disposition or "BENIGN_POSITIVE",
                "sop_compliance": [phishing_sop_id] if phishing_sop_id else [],
                "timestamp": datetime.utcnow().isoformat(),
                "ai_model": "mock"
            }

        # Check if sender is on trusted allowlist
        if trusted_sender_result and trusted_sender_result.is_trusted:
            is_trusted_sender = True
            key_findings.append(f"Sender domain is on trusted allowlist ({trusted_sender_result.trust_level})")
            if trusted_sender_result.organization:
                key_findings.append(f"Organization: {trusted_sender_result.organization}")

        # ===== SENDER AUTHENTICATION ANALYSIS =====
        # This is critical for phishing detection per KB Phishing Checklist
        # BUT: Skip if sender is on trusted allowlist
        sender_suspicious = False
        sender_findings = []

        # Re-use sender extracted above for trust checks
        description = alert_data.get('description', '')
        title = alert_data.get('title', '')

        # If sender is trusted, skip the suspicious sender checks
        if is_trusted_sender and trusted_sender_result:
            sender_findings.append(
                f"Sender '{sender}' is on trusted allowlist - skipping suspicious sender checks"
            )
            # Still note the trust level - "verified" means we can auto-close benign
            # "trusted" means skip checks but continue analysis
            # "known" means note it but analyze normally

        if sender and not is_trusted_sender:
            sender_domain = sender.split('@')[-1] if '@' in sender else sender

            # Check 1: Random string local part (common in phishing)
            local_part = sender.split('@')[0] if '@' in sender else ''
            if len(local_part) > 15 and not any(c in local_part for c in ['.', '_', '-']):
                # Long random string without separators = suspicious
                consonants = sum(1 for c in local_part.lower() if c in 'bcdfghjklmnpqrstvwxyz')
                vowels = sum(1 for c in local_part.lower() if c in 'aeiou')
                if consonants > 0 and vowels / max(consonants, 1) < 0.3:
                    sender_suspicious = True
                    sender_findings.append(f"Sender local part '{local_part}' appears randomly generated")

            # Check 2: Suspicious TLDs commonly used in phishing
            suspicious_tlds = ['.my', '.xyz', '.top', '.work', '.click', '.loan', '.date',
                              '.racing', '.win', '.bid', '.stream', '.download', '.gq',
                              '.ml', '.ga', '.cf', '.tk', '.pw', '.cc', '.ws']
            if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
                sender_suspicious = True
                sender_findings.append(f"Sender uses suspicious TLD: {sender_domain}")

            # Check 3: Domain doesn't match common legitimate services
            trusted_domains = ['godaddy.com', 'e.godaddy.com', 'google.com', 'microsoft.com',
                              'amazon.com', 'paypal.com', 'apple.com', 'dropbox.com',
                              'outlook.com', 'gmail.com', 'yahoo.com', 'office.com']
            is_trusted = any(sender_domain == d or sender_domain.endswith('.' + d)
                           for d in trusted_domains)

            if not is_trusted:
                # Check if domain looks like a lookalike using comprehensive detection
                lookalike_check = sender_trust_service.check_lookalike_domain(sender_domain)
                if lookalike_check.get('is_lookalike'):
                    sender_suspicious = True
                    impersonated = lookalike_check.get('impersonated_brand', 'unknown brand')
                    sender_findings.append(f"PHISHING: Domain {sender_domain} impersonates {impersonated}")
                    # Force verdict to MALICIOUS for lookalike domains
                    malicious_count += 1
                else:
                    # Fallback patterns for edge cases
                    lookalike_patterns = ['g00gle', 'googIe', 'micros0ft', 'paypa1',
                                         'amaz0n', 'app1e', 'dr0pbox', 'go0gle',
                                         '-secure', '-verify', '-login', '-account']
                    for pattern in lookalike_patterns:
                        if pattern in sender_domain.lower():
                            sender_suspicious = True
                            sender_findings.append(f"Sender domain may be impersonating: {sender_domain}")
                            break

            # Check 4: Random-looking domain (high entropy)
            if not is_trusted and len(sender_domain.split('.')[0]) > 8:
                domain_base = sender_domain.split('.')[0]
                # Check for pronounceability (ratio of vowels)
                vowel_ratio = sum(1 for c in domain_base.lower() if c in 'aeiou') / max(len(domain_base), 1)
                if vowel_ratio < 0.2:
                    sender_suspicious = True
                    sender_findings.append(f"Sender domain appears randomly generated: {sender_domain}")

        # ===== SUBJECT LINE ANALYSIS =====
        subject_suspicious = False
        subject_findings = []

        # Urgency indicators per SOP
        urgency_patterns = [
            r'final\s+notice', r'account\s+suspend', r'urgent', r'immediate\s+action',
            r'will\s+be\s+deleted', r'verify\s+your', r'confirm\s+your\s+identity',
            r'unusual\s+activity', r'security\s+alert', r'password\s+expire',
            r'action\s+required', r'limited\s+time', r'act\s+now'
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, title.lower()):
                subject_suspicious = True
                subject_findings.append(f"Subject contains urgency language: '{pattern}'")
                break

        # Emoji spam (common in phishing)
        emoji_count = len(re.findall(r'[^\w\s,.\-!?@#$%^&*()+=<>:;\'\"\/\\]', title))
        if emoji_count >= 2:
            subject_suspicious = True
            subject_findings.append(f"Subject contains multiple emojis/special chars ({emoji_count})")

        # ===== SCAM CONTENT DETECTION =====
        # Check for 419 fraud, BEC, and other content-based scams
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        body_preview = raw_event.get('body_preview', '') or raw_event.get('body', '')
        scam_check = sender_trust_service.check_scam_content(subject or title, body_preview)
        if scam_check.get('is_scam'):
            scam_type = scam_check.get('scam_type', 'fraud')
            scam_findings_text = f"SCAM DETECTED: {scam_type} - {scam_check.get('reason', 'Content matches fraud patterns')}"
            subject_findings.append(scam_findings_text)
            malicious_count += 1  # Force malicious verdict

        # ===== FINAL VERDICT =====
        key_findings.extend(sender_findings)
        key_findings.extend(subject_findings)

        # Determine verdict based on all signals
        # Trust level impacts the verdict:
        #   - "verified" + no malicious IOCs = can auto-close as benign
        #   - "trusted" = skip sender checks but still analyze content
        #   - "known" = note but analyze normally

        auto_close_reason = None  # Will be set for benign cases that should auto-close

        if malicious_count > 0:
            # Malicious IOCs always take precedence
            verdict = "MALICIOUS"
            confidence = 0.85
            severity = "critical"
            fp_likelihood = 0.1
            threat_type = "malware"
        elif is_trusted_sender and trusted_sender_result:
            trust_level = trusted_sender_result.trust_level

            if trust_level == 'verified':
                # Verified sender + no malicious IOCs + no suspicious IOCs = BENIGN
                if suspicious_count == 0:
                    verdict = "BENIGN"
                    confidence = 0.90
                    severity = "low"
                    fp_likelihood = 0.95
                    threat_type = "none"
                    auto_close_reason = f"Auto-closed: Verified trusted sender ({trusted_sender_result.organization or sender}) with all clean IOCs"
                    key_findings.append(
                        f"Verified trusted sender ({trusted_sender_result.organization or sender}) - auto-closing as benign"
                    )
                else:
                    # Verified sender but has suspicious IOCs - still needs review
                    verdict = "SUSPICIOUS"
                    confidence = 0.60
                    severity = "medium"
                    fp_likelihood = 0.50
                    threat_type = "unknown"
            elif trust_level == 'trusted':
                # Trusted sender - if subject looks concerning, still flag
                if subject_suspicious:
                    verdict = "SUSPICIOUS"
                    confidence = 0.50
                    severity = "medium"
                    fp_likelihood = 0.60
                    threat_type = "phishing"
                else:
                    verdict = "BENIGN"
                    confidence = 0.80
                    severity = "low"
                    fp_likelihood = 0.85
                    threat_type = "none"
                    auto_close_reason = f"Auto-closed: Trusted sender ({trusted_sender_result.organization or sender}) with clean content"
            else:
                # "known" level - analyze normally but note it
                if subject_suspicious:
                    verdict = "SUSPICIOUS"
                    confidence = 0.55
                    severity = "medium"
                    fp_likelihood = 0.50
                    threat_type = "phishing"
                else:
                    verdict = "BENIGN"
                    confidence = 0.70
                    severity = "low"
                    fp_likelihood = 0.75
                    threat_type = "none"
        elif sender_suspicious and subject_suspicious:
            # Both sender AND subject are suspicious = likely phishing
            verdict = "MALICIOUS"
            confidence = 0.80
            severity = "high"
            fp_likelihood = 0.15
            threat_type = "phishing"
        elif sender_suspicious:
            # Just sender suspicious = needs investigation
            verdict = "SUSPICIOUS"
            confidence = 0.70
            severity = "high"
            fp_likelihood = 0.25
            threat_type = "phishing"
        elif subject_suspicious:
            # Just subject suspicious = could be legitimate alert
            verdict = "SUSPICIOUS"
            confidence = 0.55
            severity = "medium"
            fp_likelihood = 0.40
            threat_type = "phishing"
        elif suspicious_count > 0:
            verdict = "SUSPICIOUS"
            confidence = 0.65
            severity = "high"
            fp_likelihood = 0.3
            threat_type = "unknown"
        elif summary.get('total_enriched', 0) == 0:
            verdict = "NEEDS_INVESTIGATION"
            confidence = 0.4
            severity = context['alert']['severity']
            fp_likelihood = 0.5
            threat_type = "unknown"
        else:
            verdict = "BENIGN"
            confidence = 0.80  # Increased to meet auto-close threshold
            severity = "low"
            fp_likelihood = 0.85  # High FP likelihood for clean IOCs
            threat_type = "none"
            auto_close_reason = "Auto-closed: All IOCs enriched and found clean"

        requires_escalation = verdict in ["MALICIOUS", "SUSPICIOUS"]
        escalation_reason = None
        if sender_suspicious:
            escalation_reason = "Suspicious sender domain detected"
        elif malicious_count > 0:
            escalation_reason = "Malicious IOCs detected"
        elif subject_suspicious:
            escalation_reason = "Phishing indicators in subject line"

        # Build recommended actions based on findings
        recommended_actions = []
        if sender_suspicious or subject_suspicious:
            action = {
                "action": "Escalate for Tier 2 phishing analysis",
                "priority": "high",
                "reason": "Sender domain and/or subject match phishing indicators"
            }
            if phishing_sop_id:
                action["sop_reference"] = phishing_sop_id
            recommended_actions.append(action)

            if sender_suspicious:
                recommended_actions.append({
                    "action": "Block sender domain organization-wide",
                    "priority": "immediate" if verdict == "MALICIOUS" else "high",
                    "reason": "Suspicious/malicious sender identified",
                    "sop_reference": phishing_sop_id
                })

        # Track which SOPs were applied
        sop_compliance = []
        if phishing_sop_id:
            sop_compliance.append(phishing_sop_id)

        result = {
            "status": "completed",
            "verdict": verdict,
            "confidence": confidence,
            "severity_recommendation": severity,
            "summary": f"{'; '.join(sender_findings + subject_findings) if sender_findings or subject_findings else f'Found {malicious_count} malicious and {suspicious_count} suspicious IOCs.'}",
            "key_findings": key_findings,
            "recommended_actions": recommended_actions,
            "requires_escalation": requires_escalation,
            "escalation_reason": escalation_reason,
            "false_positive_likelihood": fp_likelihood,
            "threat_type": threat_type,
            "sop_compliance": sop_compliance,
            "timestamp": datetime.utcnow().isoformat(),
            "ai_model": "mock"
        }

        # Add auto_close_reason if this alert should be auto-closed
        if auto_close_reason:
            result["auto_close_reason"] = auto_close_reason

        return result

    async def _should_auto_close(
        self,
        triage_result: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> bool:
        """
        Determine if an alert should be auto-closed based on triage results.

        Auto-close criteria:
        1. Verdict is BENIGN or FALSE_POSITIVE
        2. Confidence >= tenant's auto_close_min_confidence (default 0.90)
        3. fp_likelihood >= tenant's auto_close_min_fp_likelihood (default 0 = off)
        4. No escalation required

        Tenant thresholds come from tenant_triage_config (migration 066).
        Missing tenant_id / missing row → historical defaults.
        For phishing tests, always return True (handled separately).
        """
        verdict = triage_result.get('verdict', '').upper()
        confidence = triage_result.get('confidence', 0)
        fp_likelihood = triage_result.get('false_positive_likelihood', 0)
        requires_escalation = triage_result.get('requires_escalation', False)
        is_phishing_test = triage_result.get('is_phishing_test', False)
        explicit_auto_close = triage_result.get('auto_close', False)

        # Phishing tests always auto-close
        if is_phishing_test or explicit_auto_close:
            return True

        # Don't auto-close if escalation is required
        if requires_escalation:
            return False

        # Only auto-close BENIGN or FALSE_POSITIVE verdicts
        if verdict not in ['BENIGN', 'FALSE_POSITIVE']:
            return False

        # Per-tenant thresholds (defaults match the historical hardcoded values)
        try:
            from services import tenant_triage_config_service as _ttc
            cfg = await _ttc.get_for_tenant(tenant_id)
        except Exception:
            cfg = {
                "auto_close_min_confidence": self.min_confidence_for_auto_close,
                "auto_close_min_fp_likelihood": 0.0,
            }
        min_conf = float(cfg["auto_close_min_confidence"])
        min_fp = float(cfg["auto_close_min_fp_likelihood"])

        # Check confidence threshold
        if confidence < min_conf:
            logger.debug(f"Not auto-closing: confidence {confidence:.0%} < threshold {min_conf:.0%}")
            return False

        # fp_likelihood gate is opt-in (default 0). When non-zero, require
        # that triage signaled a high FP probability before auto-closing.
        # fp_likelihood uses the canonical scale (high = high probability
        # the alert is benign / treating it as malicious would be a false
        # positive). See audit issue #7 history.
        if min_fp > 0 and float(fp_likelihood or 0) < min_fp:
            logger.debug(f"Not auto-closing: fp_likelihood {fp_likelihood:.0%} < threshold {min_fp:.0%}")
            return False

        # All criteria met - auto-close
        logger.info(f"Auto-close criteria met: verdict={verdict}, confidence={confidence:.0%}, FP={fp_likelihood:.0%}")
        return True

    async def _store_verdict(self, alert_id: str, triage_result: Dict[str, Any]):
        """Store the AI verdict on the alert record and auto-close if criteria met."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                logger.warning("PostgreSQL not connected, cannot store AI verdict")
                return

            verdict = triage_result.get('verdict', 'unknown')
            confidence = triage_result.get('confidence', 0)
            summary = triage_result.get('summary', '')

            # RIGGS_ALL_ALERTS env var = platform-wide override (legacy).
            # tenant_triage_config.force_all_to_investigation = per-tenant
            # override (BYO-gated at the route layer). Either flips the
            # whole auto-close path off for this tenant.
            force_all_investigations = os.getenv('RIGGS_ALL_ALERTS', 'false').lower() == 'true'
            if not force_all_investigations:
                try:
                    from middleware.tenant_middleware import current_tenant_id as _ctid
                    from services import tenant_triage_config_service as _ttc_svc
                    _force_tid = _ctid.get()
                    if _force_tid:
                        _force_cfg = await _ttc_svc.get_for_tenant(str(_force_tid))
                        if _force_cfg.get("force_all_to_investigation"):
                            force_all_investigations = True
                except Exception:
                    pass

            # Paid tenants normally skip the cheap T1 auto-close so that they
            # get full Riggs Deep Dive on every alert. BUT: when T1 is very
            # confident an alert is benign, holding the alert open just
            # breaches SLA -- the analyst opens it, sees BENIGN @ 92%, and
            # closes it manually. We close it for them. Deep Dive still
            # runs in the background and can revise the disposition.
            _paid_tenant = False
            _tid = None
            try:
                from middleware.tenant_middleware import current_tenant_id
                from dependencies.license_checks import _get_tenant_tier
                from services.licensing.models import LicenseTier
                _tid = current_tenant_id.get()
                if _tid:
                    _tier = await _get_tenant_tier(str(_tid))
                    _paid_tenant = _tier not in (LicenseTier.FREE,)
            except Exception:
                pass

            # T1's own auto-close gate (verdict + confidence + FP likelihood),
            # tunable per tenant via tenant_triage_config.
            t1_says_close = await self._should_auto_close(
                triage_result, tenant_id=str(_tid) if _tid else None
            )

            # Strong-confidence BENIGN: close even on paid tier so we don't
            # park "obviously benign" alerts in `triaged` until SLA breach.
            # Honors the tenant's auto_close_min_confidence so a tenant who
            # raised the bar (e.g. to 0.95) gets that respected here too.
            _strong_conf_floor = 0.90
            try:
                from services import tenant_triage_config_service as _ttc
                _cfg = await _ttc.get_for_tenant(str(_tid) if _tid else None)
                _strong_conf_floor = float(_cfg["auto_close_min_confidence"])
            except Exception:
                pass
            t1_verdict = (triage_result.get('verdict') or '').upper()
            t1_conf = float(triage_result.get('confidence') or 0)
            paid_tenant_strong_benign = (
                _paid_tenant
                and t1_verdict in ('BENIGN', 'FALSE_POSITIVE')
                and t1_conf >= _strong_conf_floor
                and not triage_result.get('requires_escalation', False)
            )

            should_auto_close = False
            if force_all_investigations:
                should_auto_close = False
            elif _paid_tenant:
                # Paid tenants close only on strong-confidence benign.
                should_auto_close = paid_tenant_strong_benign and t1_says_close
            else:
                # Free tenants: standard T1 auto-close rules.
                should_auto_close = t1_says_close

            # Update the alert with AI verdict
            async with _admin_conn() as conn:
                # First, get the current alert to update raw_event
                row = await conn.fetchrow(
                    'SELECT raw_event FROM alerts WHERE alert_id = $1',
                    alert_id
                )

                if not row:
                    logger.warning(f"Alert {alert_id} not found for verdict storage")
                    return

                # Parse existing raw_event
                raw_event = row['raw_event']
                if isinstance(raw_event, str):
                    raw_event = json.loads(raw_event)

                # Add AI triage data to _extracted
                if '_extracted' not in raw_event:
                    raw_event['_extracted'] = {}
                raw_event['_extracted']['ai_triage'] = triage_result

                # Check if this alert has already been processed by a real AI agent
                # Don't overwrite agent verdicts with mock triage results
                # EXCEPTION: Auto-confirm results (from verdict_convergence) should always be stored
                is_auto_confirm = triage_result.get('auto_confirmed', False)

                # NOTE: We removed the "preserve existing verdict" logic here.
                # If T1 ran (passed duplicate_execution check), its verdict should ALWAYS be stored.
                # The duplicate execution prevention via enrichment_hash already prevents T1 from
                # running multiple times. If T1 ran and returned a verdict, we should store it.
                #
                # The old logic was incorrectly preserving stale verdicts from earlier triage paths,
                # preventing T1 from updating alerts with SOCIAL_ENGINEERING or other new verdicts.

                # Update alert with verdict and enriched raw_event
                if should_auto_close:
                    # Auto-close the alert - set status to closed with resolution
                    resolution_reason = triage_result.get('auto_close_reason', 'Auto-closed by AI triage: Benign alert with clean IOCs')
                    await conn.execute('''
                        UPDATE alerts
                        SET
                            ai_verdict = $1,
                            ai_confidence = $2,
                            ai_summary = $3,
                            raw_event = $4,
                            status = 'closed',
                            resolution = $6,
                            resolved_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE alert_id = $5
                    ''',
                        verdict,
                        confidence,
                        summary,
                        json.dumps(raw_event),
                        alert_id,
                        resolution_reason
                    )
                    logger.info(f"Alert {alert_id}: AUTO-CLOSED by AI triage ({verdict}, {confidence:.0%})")
                else:
                    # Update alert with verdict and set status to 'triaged' to indicate T1 triage complete
                    await conn.execute('''
                        UPDATE alerts
                        SET
                            ai_verdict = $1,
                            ai_confidence = $2,
                            ai_summary = $3,
                            raw_event = $4,
                            status = 'triaged',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE alert_id = $5
                    ''',
                        verdict,
                        confidence,
                        summary,
                        json.dumps(raw_event),
                        alert_id
                    )
                    logger.info(f"Alert {alert_id}: AI verdict stored ({verdict}, {confidence:.0%}), status -> triaged")

                    # Check if alert has encoded content requiring Riggs deep analysis
                    extracted = raw_event.get('_extracted', {})
                    has_encoded_content = bool(extracted.get('decoded_content'))
                    has_decoded_iocs = any(extracted.get('decoded_iocs', {}).values())
                    needs_riggs_analysis = has_encoded_content or has_decoded_iocs

                    # =================================================================
                    # CONFIDENCE-BASED ESCALATION (not verdict-based)
                    # =================================================================
                    # Escalation should be based on UNCERTAINTY, not just disposition.
                    # If confidence is high, we don't need T2 - regardless of verdict.
                    #
                    # Thresholds:
                    #   T2_THRESHOLD = 0.75  (escalate to T2 if confidence < 75%)
                    #   AUTO_CLOSE_THRESHOLD = 0.90  (auto-close if BENIGN + >= 90%)
                    #
                    # Escalation Matrix:
                    #   BENIGN     + conf >= 0.90 → Auto-close
                    #   BENIGN     + conf <  0.90 → Close (no T2)
                    #   SUSPICIOUS + conf >= 0.75 → Close as suspicious (no T2)
                    #   SUSPICIOUS + conf <  0.75 → Escalate to T2
                    #   MALICIOUS  + conf >= 0.75 → Auto-resolve as malicious (no T2)
                    #   MALICIOUS  + conf <  0.75 → Escalate to T2
                    # =================================================================
                    T2_CONFIDENCE_THRESHOLD = 0.75  # Escalate if confidence < 75%

                    # Determine if T2 investigation is needed based on confidence
                    needs_t2_for_uncertainty = confidence < T2_CONFIDENCE_THRESHOLD

                    # Paid tenants get deep analysis on EVERY alert
                    is_paid_tenant = False
                    try:
                        from middleware.tenant_middleware import current_tenant_id
                        from dependencies.license_checks import _get_tenant_tier
                        from services.licensing.models import LicenseTier
                        _tid = current_tenant_id.get()
                        if _tid:
                            _tier = await _get_tenant_tier(str(_tid))
                            is_paid_tenant = _tier not in (LicenseTier.FREE,)
                            if is_paid_tenant:
                                logger.info(f"Alert {alert_id}: Paid tenant ({_tier.value}) - eligible for deep analysis")
                    except Exception:
                        pass  # Fall back to normal logic

                    # Special cases that always need investigation
                    # SUSPICIOUS and TRUE_POSITIVE/MALICIOUS should ALWAYS create investigation
                    # Paid tenants get deep analysis but NOT on high-confidence benign alerts
                    is_benign_high_confidence = (
                        verdict.upper() in ('BENIGN', 'FALSE_POSITIVE') and confidence >= 0.85
                    )
                    needs_investigation_override = (
                        verdict.upper() in ('SUSPICIOUS', 'TRUE_POSITIVE', 'MALICIOUS')  # Always investigate these
                        or verdict.upper() == 'NEEDS_INVESTIGATION'  # Explicitly uncertain
                        or needs_riggs_analysis  # Has encoded content needing deep analysis
                        or force_all_investigations  # Testing mode - force all to Riggs
                        or (is_paid_tenant and not is_benign_high_confidence)  # Paid tenants: skip obvious benign
                    )

                    should_create_investigation = needs_t2_for_uncertainty or needs_investigation_override

                    # Log the decision for debugging
                    if not should_create_investigation:
                        logger.info(
                            f"Alert {alert_id}: High confidence ({confidence:.0%}) - "
                            f"closing as {verdict} without T2 escalation"
                        )

                    if should_create_investigation:
                        if needs_riggs_analysis:
                            logger.info(f"Alert {alert_id}: Has encoded content - forcing Riggs analysis")
                        await self._create_investigation_from_triage(
                            conn, alert_id, triage_result, raw_event
                        )

        except Exception as e:
            logger.error(f"Failed to store AI verdict for {alert_id}: {e}")

    async def _create_investigation_from_triage(
        self,
        conn,
        alert_id: str,
        triage_result: Dict[str, Any],
        raw_event: Dict[str, Any]
    ):
        """
        Create investigation with proper tier1_analysis data when AI triage
        determines the alert warrants investigation.

        This ensures investigation_data is populated even when alerts are
        processed through auto_enrichment -> ai_triage_service path
        (bypassing agent_executor).
        """
        import uuid
        import secrets

        try:
            # Get alert details
            alert_row = await conn.fetchrow('''
                SELECT id, title, severity, source, investigation_id, tenant_id
                FROM alerts WHERE alert_id = $1
            ''', alert_id)

            if not alert_row:
                logger.warning(f"Alert {alert_id} not found for investigation creation")
                return

            # If investigation already exists, update it with triage results
            if alert_row['investigation_id']:
                await self._update_existing_investigation_from_triage(
                    conn, alert_id, alert_row, triage_result, raw_event
                )
                return

            # Generate investigation ID
            inv_uuid = uuid.uuid4()
            inv_number = f"INV-{secrets.token_hex(4).upper()}"

            # Map severity to priority
            severity_to_priority = {
                'critical': 'P1',
                'high': 'P2',
                'medium': 'P3',
                'low': 'P4'
            }
            priority = severity_to_priority.get(alert_row['severity'], 'P3')

            # Build investigation_data with tier1_analysis
            verdict = triage_result.get('verdict', 'NEEDS_INVESTIGATION')
            confidence = triage_result.get('confidence', 0.5)

            # Check for encoded content that needs Riggs deep analysis
            extracted = raw_event.get('_extracted', {})
            has_encoded_content = bool(extracted.get('decoded_content'))
            has_decoded_iocs = any(extracted.get('decoded_iocs', {}).values())

            # Flag for Riggs priority analysis
            needs_riggs_deep_analysis = has_encoded_content or has_decoded_iocs

            # Get alert_flags from extracted data (set during T1 classification)
            alert_flags = extracted.get('alert_flags', triage_result.get('alert_flags', ['unknown']))

            investigation_data = {
                'tier1_analysis': {
                    'agent_id': 'ai_triage_service',
                    'verdict': verdict,
                    'confidence': confidence,
                    'summary': triage_result.get('summary', ''),
                    'key_findings': triage_result.get('key_findings', []),
                    'recommended_actions': triage_result.get('recommended_actions', []),
                    'threat_type': triage_result.get('threat_type', 'unknown'),
                    'requires_escalation': triage_result.get('requires_escalation', True),
                    'source': 'ai_triage_service',
                    'timestamp': datetime.utcnow().isoformat()
                },
                'trigger': 'ai_triage_service',
                'raw_alert': raw_event,
                # Alert classification flags for Riggs flag-based prompts
                'alert_flags': alert_flags,
                # Riggs deep analysis flags
                'has_encoded_content': has_encoded_content,
                'has_decoded_iocs': has_decoded_iocs,
                'needs_riggs_deep_analysis': needs_riggs_deep_analysis,
                'riggs_priority': 'high' if needs_riggs_deep_analysis else 'normal'
            }

            # OPTIMIZED FLOW: Two-track triage
            # Track A (FAST): T1 produces provisional verdict immediately
            # Track B: Enrichment runs in parallel, merge engine combines results
            # State: TRIAGE_PROVISIONAL until enrichment completes and merge confirms
            next_state = 'TRIAGE_PROVISIONAL'

            # Create investigation with provisional verdict (Two-Track Triage)
            # Verdict is marked PROVISIONAL until enrichment completes and merge confirms
            await conn.execute('''
                INSERT INTO investigations (
                    id, investigation_id, alert_id, alert_title, severity, priority,
                    state, disposition, confidence, executive_summary,
                    investigation_data, created_at, updated_at,
                    triage_status, provisional_verdict, provisional_confidence, provisional_at,
                    enrichment_progress, enrichment_total_iocs, tenant_id
                ) VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $10, $11, $7, $8,
                    $9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                    'provisional', $11, $7, CURRENT_TIMESTAMP,
                    0, 0, $12
                )
            ''',
                inv_uuid,
                inv_number,
                alert_row['id'],
                alert_row['title'],
                alert_row['severity'],
                priority,
                confidence,
                triage_result.get('summary', f"AI triage: {verdict}"),
                json.dumps(investigation_data),
                next_state,
                verdict.upper(),  # Store the actual verdict (MALICIOUS, SUSPICIOUS, etc.)
                alert_row['tenant_id']  # RLS: must match tenant context
            )

            # Link alert to investigation and update status
            # Status 'triaged' means AI triage complete and investigation created
            # This removes it from work queue so analysts only see the investigation
            await conn.execute('''
                UPDATE alerts
                SET investigation_id = $1, status = 'triaged', updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = $2
            ''', inv_uuid, alert_id)

            logger.info(f"Alert {alert_id}: Created investigation {inv_number} (state={next_state}, verdict={verdict})")

            # In-app notification for investigation creation
            try:
                from routes.notifications import create_notification
                await create_notification(
                    tenant_id=str(alert_row['tenant_id']),
                    title=f"Investigation {inv_number} Created",
                    message=f"Alert '{alert_row['title']}' triaged as {verdict} ({confidence:.0%} confidence)",
                    category="investigation",
                    severity=alert_row['severity'].lower() if alert_row.get('severity') else 'medium',
                    link=f"/investigations/{inv_number}",
                )
            except Exception as notif_err:
                logger.debug(f"Notification failed (non-fatal): {notif_err}")

            # Auto-trigger Riggs analysis for all investigations after creation
            try:
                from services.auto_analysis_trigger import auto_trigger_analysis_for_investigation
                job_id = await auto_trigger_analysis_for_investigation(
                    investigation_id=str(inv_uuid),
                    tenant_id=str(alert_row['tenant_id']),
                    priority=5  # Normal priority for background analysis
                )
            except Exception as auto_err:
                logger.warning(f"Failed to auto-trigger analysis for investigation {inv_number}: {auto_err}")

            # Auto-trigger Deep Dive for paid tenants after investigation is committed
            try:
                from dependencies.license_checks import _get_tenant_tier
                from services.licensing.default_plans import get_default_entitlements

                tier = await _get_tenant_tier(str(alert_row['tenant_id']))
                entitlements = get_default_entitlements(tier)
                features = entitlements.features or {}

                if features.get('deep_dive'):
                    monthly_limit = features.get('deep_dive_monthly_limit', 0)
                    # 0 means unlimited; positive number means capped
                    if monthly_limit == 0:
                        # Unlimited deep dives (PRO/ENTERPRISE/PLATFORM/DEV)
                        logger.info(
                            f"Auto-triggering Deep Dive for tenant {alert_row['tenant_id']}, "
                            f"investigation {inv_number} (tier={tier.value}, unlimited)"
                        )
                        asyncio.create_task(
                            self.deep_dive_investigation(str(inv_uuid), str(alert_row['tenant_id']))
                        )
                    else:
                        # Limited deep dives (FREE tier) -- skip auto-trigger, manual only
                        # But still auto-generate recommendations from tier1 analysis
                        logger.debug(
                            f"Skipping auto Deep Dive for tenant {alert_row['tenant_id']} "
                            f"(tier={tier.value}, monthly_limit={monthly_limit} -- manual trigger only)"
                        )
                        tier1 = triage_result or {}
                        asyncio.create_task(
                            self._auto_generate_recommendations(
                                str(inv_uuid), str(alert_row['tenant_id']), tier1
                            )
                        )
                else:
                    # No deep dive feature at all — still generate recommendations from triage
                    tier1 = triage_result or {}
                    asyncio.create_task(
                        self._auto_generate_recommendations(
                            str(inv_uuid), str(alert_row['tenant_id']), tier1
                        )
                    )
            except Exception as dd_err:
                logger.warning(f"Failed to auto-trigger Deep Dive for {alert_id}: {dd_err}")

        except Exception as e:
            logger.error(f"Failed to create investigation from triage for {alert_id}: {e}")

    async def _update_existing_investigation_from_triage(
        self,
        conn,
        alert_id: str,
        alert_row,
        triage_result: Dict[str, Any],
        raw_event: Dict[str, Any]
    ):
        """
        Update an existing investigation with T1 triage results.

        When hypothesis_correlation creates the investigation before triage runs,
        the investigation lacks AI verdict data. This method backfills it.
        """
        try:
            inv_id = alert_row['investigation_id']
            verdict = triage_result.get('verdict', 'NEEDS_INVESTIGATION')
            confidence = triage_result.get('confidence', 0.5)
            summary = triage_result.get('summary', '')

            # Read-merge-write under a row lock so two alerts correlating
            # to the same investigation within milliseconds cannot drop a
            # verdict. Without the transaction + FOR UPDATE, both calls
            # could SELECT the same baseline, merge their own contribution,
            # and one UPDATE would overwrite the other. asyncpg's
            # conn.transaction() degrades to a savepoint when the caller
            # is already in a transaction, so this is safe to nest.
            async with conn.transaction():
                inv_row = await conn.fetchrow(
                    'SELECT investigation_data, state, disposition FROM investigations '
                    'WHERE id = $1 FOR UPDATE',
                    inv_id,
                )
                if not inv_row:
                    logger.warning(f"Alert {alert_id}: Investigation {inv_id} not found for update")
                    return

                existing_data = inv_row['investigation_data'] or {}
                if isinstance(existing_data, str):
                    try:
                        existing_data = json.loads(existing_data)
                    except:
                        existing_data = {}

                # Don't reopen an investigation the analyst already closed
                # with a benign-class disposition. A new correlated alert
                # shouldn't be able to override that decision; the analyst
                # already triaged this sender/pattern as not-a-threat. We
                # still merge the new tier1_analysis into investigation_data
                # so the history is preserved, but skip the state/disposition
                # overwrite.
                _prior_state = (inv_row['state'] or '').upper()
                _prior_disp = (inv_row['disposition'] or '').upper()
                _benign_dispositions = ('BENIGN', 'FALSE_POSITIVE', 'BENIGN_POSITIVE')
                _terminal_states = ('CLOSED', 'RESOLVED')
                _keep_closed = (_prior_state in _terminal_states
                                and _prior_disp in _benign_dispositions)

                # Get alert_flags from extracted data
                extracted = raw_event.get('_extracted', {})
                alert_flags = extracted.get('alert_flags', triage_result.get('alert_flags', ['unknown']))

                # Merge tier1_analysis into existing investigation_data
                existing_data['tier1_analysis'] = {
                    'agent_id': 'ai_triage_service',
                    'verdict': verdict,
                    'confidence': confidence,
                    'summary': summary,
                    'key_findings': triage_result.get('key_findings', []),
                    'recommended_actions': triage_result.get('recommended_actions', []),
                    'threat_type': triage_result.get('threat_type', 'unknown'),
                    'requires_escalation': triage_result.get('requires_escalation', True),
                    'source': 'ai_triage_service',
                    'timestamp': datetime.utcnow().isoformat()
                }
                existing_data['alert_flags'] = alert_flags
                existing_data['trigger'] = existing_data.get('trigger', 'hypothesis_correlation')

                # Map verdict to disposition
                verdict_to_disposition = {
                    'MALICIOUS': 'MALICIOUS',
                    'SUSPICIOUS': 'SUSPICIOUS',
                    'BENIGN': 'BENIGN',
                    'TRUE_POSITIVE': 'TRUE_POSITIVE',
                    'FALSE_POSITIVE': 'FALSE_POSITIVE',
                    'NEEDS_INVESTIGATION': 'NEEDS_INVESTIGATION',
                }
                disposition = verdict_to_disposition.get(verdict.upper(), 'NEEDS_INVESTIGATION')

                # Update investigation with triage results. If the prior
                # state is closed-as-benign, preserve state + disposition;
                # only attach the new tier1_analysis into investigation_data
                # so the audit trail is complete.
                if _keep_closed:
                    await conn.execute('''
                        UPDATE investigations
                        SET investigation_data = $2,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $1
                    ''', inv_id, json.dumps(existing_data))
                else:
                    await conn.execute('''
                        UPDATE investigations
                        SET
                            disposition = $2,
                            confidence = $3,
                            executive_summary = $4,
                            investigation_data = $5,
                            state = 'NEEDS_REVIEW',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $1
                    ''',
                        inv_id,
                        disposition,
                        confidence,
                        summary,
                        json.dumps(existing_data)
                    )

            if _keep_closed:
                logger.info(
                    f"Alert {alert_id}: Investigation was CLOSED with {_prior_disp} — "
                    f"new triage ({disposition}, {confidence:.0%}) attached as history, "
                    f"investigation kept closed"
                )
            else:
                logger.info(
                    f"Alert {alert_id}: Updated existing investigation with triage results "
                    f"(disposition={disposition}, confidence={confidence:.0%})"
                )

            # Ensure a Riggs analysis job is queued in job_queue. Without this,
            # alerts that get auto-correlated to an existing investigation never
            # receive Riggs analysis: the create-investigation path queues a job,
            # but this update path previously did not, leaving these alerts
            # silently un-analyzed (they relied on the agent_scheduler sweep,
            # which races with this method's tier1_analysis write).
            try:
                from services.auto_analysis_trigger import auto_trigger_analysis_for_investigation

                existing_job = await conn.fetchval(
                    """
                    SELECT 1 FROM job_queue
                    WHERE job_type IN ('agent_auto_triage', 'agent_analyze_investigation')
                      AND payload->>'investigation_id' = $1
                      AND status IN ('pending', 'processing', 'completed')
                    LIMIT 1
                    """,
                    str(inv_id),
                )
                if not existing_job:
                    new_job_id = await auto_trigger_analysis_for_investigation(
                        investigation_id=str(inv_id),
                        tenant_id=str(alert_row['tenant_id']),
                        priority=5,
                        alert_id=str(alert_row['id']) if alert_row.get('id') else None,
                    )
                    if new_job_id:
                        logger.info(
                            f"[UPDATE_EXISTING] Queued Riggs analysis for inv {inv_id} (job {new_job_id})"
                        )
                    else:
                        logger.warning(
                            f"[UPDATE_EXISTING] auto_trigger_analysis returned None for inv {inv_id} — alert may not be analyzed"
                        )
            except Exception as enqueue_err:
                logger.warning(
                    f"Failed to ensure Riggs analysis for inv {inv_id}: {enqueue_err}"
                )

            # Auto-trigger Deep Dive (premium) / lighter recommendations (free)
            # for existing investigations if not already run.
            try:
                async with _admin_conn() as conn:
                    inv_state = await conn.fetchrow(
                        "SELECT tenant_id, investigation_data->'riggs_deep_analysis' as deep FROM investigations WHERE id = $1",
                        inv_id,
                    )
                if inv_state and not inv_state.get("deep"):
                    tenant_id_str = str(inv_state["tenant_id"])
                    from dependencies.license_checks import _get_tenant_tier
                    from services.licensing.default_plans import get_default_entitlements
                    tier = await _get_tenant_tier(tenant_id_str)
                    entitlements = get_default_entitlements(tier)
                    features = entitlements.features or {}
                    if features.get('deep_dive') and features.get('deep_dive_monthly_limit', 0) == 0:
                        logger.info(f"[UPDATE_EXISTING] Premium tier - auto-triggering Deep Dive for {inv_id}")
                        asyncio.create_task(self.deep_dive_investigation(str(inv_id), tenant_id_str))
                    else:
                        logger.info(f"[UPDATE_EXISTING] Free/limited tier - generating lighter recommendations for {inv_id}")
                        asyncio.create_task(self._auto_generate_recommendations(str(inv_id), tenant_id_str, triage_result or {}))
            except Exception as dd_err:
                logger.warning(f"Deep Dive auto-trigger failed in update_existing for inv {inv_id}: {dd_err}")

        except Exception as e:
            logger.error(f"Failed to update investigation from triage for {alert_id}: {e}")

    async def get_alert_triage(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get AI triage result for an alert."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return None

            async with _admin_conn() as conn:
                row = await conn.fetchrow('''
                    SELECT
                        alert_id,
                        ai_verdict,
                        ai_confidence,
                        ai_summary,
                        raw_event
                    FROM alerts
                    WHERE alert_id = $1
                ''', alert_id)

                if not row:
                    return None

                # Extract full triage data from raw_event
                raw_event = row['raw_event']
                if isinstance(raw_event, str):
                    raw_event = json.loads(raw_event)

                ai_triage = raw_event.get('_extracted', {}).get('ai_triage', {})

                return {
                    "alert_id": row['alert_id'],
                    "verdict": row['ai_verdict'],
                    "confidence": float(row['ai_confidence']) if row['ai_confidence'] else None,
                    "summary": row['ai_summary'],
                    "full_analysis": ai_triage
                }

        except Exception as e:
            logger.error(f"Failed to get AI triage for {alert_id}: {e}")
            return None

    async def retriage_alert(self, alert_id: str) -> Dict[str, Any]:
        """Re-run AI triage on an existing alert."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with _admin_conn() as conn:
                row = await conn.fetchrow('''
                    SELECT raw_event FROM alerts WHERE alert_id = $1
                ''', alert_id)

                if not row:
                    return {"error": "Alert not found"}

                raw_event = row['raw_event']
                if isinstance(raw_event, str):
                    raw_event = json.loads(raw_event)

                # Get enrichment data
                enrichment_data = raw_event.get('_extracted', {}).get('enrichment', {})

                # Re-run triage
                return await self.triage_alert(alert_id, raw_event, enrichment_data)

        except Exception as e:
            logger.error(f"Failed to retriage alert {alert_id}: {e}")
            return {"error": str(e)}

    # ═══════════════════════════════════════════════════════════════════════════════
    # DEEP DIVE INVESTIGATION (Premium Feature — Pro+ Only)
    # ═══════════════════════════════════════════════════════════════════════════════

    async def deep_dive_investigation(self, investigation_id: str, tenant_id: str) -> Dict[str, Any]:
        """
        Perform an in-depth AI analysis of an investigation.

        Unlike fast triage (which is quick and cost-efficient), Deep Dive:
        - Uses the full Sonnet model (always — this is a premium feature)
        - Analyzes ALL linked alerts (up to 20) with full raw event data
        - Builds a comprehensive threat narrative
        - Maps to MITRE ATT&CK framework
        - Provides executive summary and response recommendations
        - Stores results in investigation_data.riggs_deep_analysis

        Args:
            investigation_id: The investigation UUID
            tenant_id: The tenant UUID (for Claude billing/quota)

        Returns:
            Deep dive analysis results dict
        """
        import uuid as _uuid
        start_time = time.time()

        try:
            from services.postgres_db import postgres_db
            from services.claude_service import get_claude_service, QuotaExceededError

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            service = await get_claude_service()
            # BYO/self-hosted tenants (e.g. Ollama) have no platform env key but
            # claude_service.complete() resolves their own provider+endpoint.
            # Only fail when there is no env key AND no effective BYO provider.
            _dd_byo = False
            if not service.is_configured:
                try:
                    from services import ai_provider_resolver as _dd_apr
                    _dd_ctx = await _dd_apr.resolve_chat(str(tenant_id))
                    _dd_byo = (_dd_ctx.mode == "byo")
                except Exception:
                    _dd_byo = False
                if not _dd_byo:
                    return {"error": "AI service not configured"}

            # Load investigation + all linked alerts
            async with _admin_conn() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")

                # Get investigation — try UUID first, fall back to human-readable investigation_id
                try:
                    inv_uuid = _uuid.UUID(investigation_id)
                    inv_row = await conn.fetchrow(
                        "SELECT * FROM investigations WHERE id = $1", inv_uuid
                    )
                except (ValueError, AttributeError):
                    inv_row = None

                if not inv_row:
                    # Look up by human-readable investigation_id (e.g. "INV-20250213-XXXX")
                    inv_row = await conn.fetchrow(
                        "SELECT * FROM investigations WHERE investigation_id = $1",
                        investigation_id
                    )

                if not inv_row:
                    return {"error": "Investigation not found"}

                investigation = dict(inv_row)
                inv_uuid = investigation['id']  # The actual UUID primary key

                # Get all linked alerts (up to 20)
                alert_rows = await conn.fetch(
                    """
                    SELECT alert_id, title, severity, source, ai_verdict,
                           ai_confidence, ai_summary, raw_event
                    FROM alerts
                    WHERE investigation_id = $1
                    ORDER BY created_at DESC
                    LIMIT 20
                    """,
                    inv_uuid
                )
                alerts = [dict(r) for r in alert_rows]

            # Build the deep dive prompt
            prompt = self._build_deep_dive_prompt(investigation, alerts)

            # Use Haiku for Deep Dive — fast enough for real-time UX (~10-15s vs ~70s with Sonnet).
            # For BYO/self-hosted tenants, pass model=None so complete() uses the
            # tenant's own configured model (e.g. the local Ollama model). Forcing an
            # Anthropic model id at a self-hosted endpoint would 404.
            deep_dive_model = None if _dd_byo else "claude-haiku-4-5-20251001"

            resolved_tenant = _uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id

            try:
                response = await service.complete(
                    tenant_id=resolved_tenant,
                    prompt=prompt,
                    model=deep_dive_model,
                    max_tokens=4000,
                    temperature=0.1,
                    request_type="deep_dive",
                )
            except QuotaExceededError:
                return {
                    "error": "quota_exceeded",
                    "message": "Monthly AI token quota exceeded. Please upgrade your plan or wait for the next billing cycle."
                }

            # Parse the response
            analysis = self._parse_deep_dive_response(response.text)

            elapsed_ms = int((time.time() - start_time) * 1000)
            analysis["analysis_time_ms"] = elapsed_ms
            analysis["analyzed_at"] = datetime.utcnow().isoformat()
            analysis["alert_count"] = len(alerts)

            # Store results in investigation_data
            await self._store_deep_dive_results(investigation_id, analysis)

            logger.info(
                f"Deep Dive completed for {investigation_id}: "
                f"verdict={analysis.get('verdict')}, "
                f"{response.total_tokens} tokens, {elapsed_ms}ms"
            )

            # Auto-generate recommended actions after deep dive
            try:
                asyncio.create_task(
                    self._auto_generate_recommendations(str(inv_uuid), tenant_id, analysis)
                )
            except Exception as rec_err:
                logger.warning(f"Failed to auto-generate recommendations for {investigation_id}: {rec_err}")

            return analysis

        except Exception as e:
            logger.error(f"Deep Dive failed for {investigation_id}: {e}")
            return {"error": f"Analysis failed: {str(e)}"}

    async def _auto_generate_recommendations(
        self, investigation_uuid: str, tenant_id: str, analysis: Dict[str, Any]
    ) -> None:
        """Auto-generate recommended actions after deep dive or triage completes."""
        try:
            from services import recommended_actions_service as ras
            from services.postgres_db import postgres_db
            import uuid as _uuid

            # Fetch IOCs from investigation_iocs table
            iocs: Dict[str, list] = {}
            async with postgres_db.tenant_acquire() as conn:
                ioc_rows = await conn.fetch(
                    """
                    SELECT ie.ioc_type, ie.ioc_value
                    FROM investigation_iocs ii
                    JOIN ioc_enrichments ie ON ii.ioc_enrichment_id = ie.id
                    WHERE ii.investigation_id = $1::uuid
                    """,
                    _uuid.UUID(investigation_uuid),
                )
            for row in ioc_rows:
                t, v = row["ioc_type"], row["ioc_value"]
                if t and v:
                    iocs.setdefault(t, [])
                    if v not in iocs[t]:
                        iocs[t].append(v)

            if not iocs:
                logger.debug(f"No IOCs found for {investigation_uuid}, skipping auto-recommendations")
                return

            recommendations = await ras.generate_recommendations(
                tenant_id=tenant_id,
                investigation_id=investigation_uuid,
                riggs_analysis=analysis,
                iocs=iocs,
            )
            if not recommendations:
                logger.debug(f"No matching connectors for IOCs in {investigation_uuid}")
                return

            saved = await ras.save_recommendations(
                tenant_id=tenant_id,
                investigation_id=investigation_uuid,
                recommendations=recommendations,
            )
            if saved:
                await ras.check_auto_response_and_execute(tenant_id, saved)
                logger.info(f"Auto-generated {len(saved)} recommendations for investigation {investigation_uuid}")

        except Exception as e:
            logger.error(f"Auto-generate recommendations failed for {investigation_uuid}: {e}")

    def _build_deep_dive_prompt(self, investigation: Dict, alerts: List[Dict]) -> str:
        """Build the full-context prompt for Deep Dive analysis."""

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, str):
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}

        # Build alert sections
        alert_sections = []
        all_iocs = []
        for i, alert in enumerate(alerts, 1):
            raw_event = alert.get('raw_event', {})
            if isinstance(raw_event, str):
                try:
                    raw_event = json.loads(raw_event)
                except:
                    raw_event = {}

            # Clean raw event for context (cap large fields)
            cleaned_event = self._clean_raw_event_for_deep_dive(raw_event)

            iocs = alert.get('iocs', [])
            if isinstance(iocs, str):
                try:
                    iocs = json.loads(iocs)
                except:
                    iocs = []
            all_iocs.extend(iocs if isinstance(iocs, list) else [])

            section = f"""
--- ALERT {i} ---
Title: {alert.get('title', 'N/A')}
Severity: {alert.get('severity', 'N/A')}
Source: {alert.get('source', 'N/A')}
Fast Triage Verdict: {alert.get('ai_verdict', 'N/A')} (confidence: {alert.get('ai_confidence', 'N/A')})
Fast Triage Summary: {alert.get('ai_summary', 'N/A')}

Raw Event Data:
{json.dumps(cleaned_event, indent=2, default=str)[:5000]}

IOCs: {json.dumps(iocs[:15], indent=2, default=str) if iocs else 'None extracted'}
"""
            alert_sections.append(section)

        # Build IOC summary (deduplicated)
        ioc_summary = self._build_full_ioc_section(all_iocs)

        # Existing triage context
        existing_verdict = inv_data.get('tier1_analysis', {}).get('verdict', 'unknown')
        existing_summary = inv_data.get('tier1_analysis', {}).get('summary', '')

        prompt = f"""You are a senior threat analyst performing an in-depth investigation review.

═══════════════════════════════════════════════════════════════════════════════
INVESTIGATION DEEP DIVE ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

Investigation: {investigation.get('title', 'Untitled')}
ID: {investigation.get('id', 'N/A')}
Severity: {investigation.get('severity', 'N/A')}
Status: {investigation.get('status', 'N/A')}
Created: {investigation.get('created_at', 'N/A')}

Previous Fast Triage Verdict: {existing_verdict}
Previous Fast Triage Summary: {existing_summary}

═══════════════════════════════════════════════════════════════════════════════
LINKED ALERTS ({len(alerts)} total)
═══════════════════════════════════════════════════════════════════════════════
{''.join(alert_sections)}

═══════════════════════════════════════════════════════════════════════════════
ALL IOCs (Deduplicated)
═══════════════════════════════════════════════════════════════════════════════
{ioc_summary}

═══════════════════════════════════════════════════════════════════════════════
ANALYSIS REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════

Provide a comprehensive investigation analysis in the following JSON format:

{{
    "verdict": "malicious|suspicious|benign|inconclusive",
    "confidence": 0.0-1.0,
    "verdict_title": "Short title for the verdict (e.g., 'Cobalt Strike C2 Beacon Activity')",
    "executive_summary": "2-3 sentence executive summary for management/CISO briefing",
    "threat_narrative": "Detailed narrative of what happened, how the attack progressed, and what the attacker's objectives were. Write this as a coherent story, not bullet points. 3-5 paragraphs.",
    "root_cause_analysis": "What was the initial access vector? How did the attacker get in? What vulnerability or human factor was exploited?",
    "mitre_attack": [
        {{
            "technique_id": "T1234.001",
            "technique_name": "Technique Name",
            "tactic": "Initial Access|Execution|Persistence|etc.",
            "evidence": "What evidence in the alerts maps to this technique"
        }}
    ],
    "threat_actor_assessment": "Assessment of the likely threat actor type (APT, cybercriminal, insider, automated). Include sophistication level and any attribution indicators.",
    "timeline": [
        {{
            "timestamp": "ISO timestamp or relative time",
            "event": "Description of what happened",
            "significance": "Why this matters"
        }}
    ],
    "response_recommendations": [
        {{
            "priority": "critical|high|medium|low",
            "action": "Specific action to take",
            "rationale": "Why this action is needed"
        }}
    ],
    "confidence_factors": {{
        "supporting": ["Evidence that supports the verdict"],
        "contradicting": ["Evidence that contradicts or creates uncertainty"],
        "gaps": ["Information we don't have that would increase confidence"]
    }}
}}

IMPORTANT:
- Base your analysis ONLY on the evidence provided. Do not speculate beyond what the data shows.
- If evidence is insufficient, say so — don't inflate confidence.
- Map ALL relevant MITRE ATT&CK techniques you can identify from the evidence.
- Response recommendations should be specific and actionable, not generic.
- The threat narrative should tell the full story of what happened.
- Return ONLY valid JSON, no markdown or extra text.
"""
        return prompt

    def _clean_raw_event_for_deep_dive(self, raw_event: Dict) -> Dict:
        """Clean raw event data for deep dive context — strip binary, cap strings."""
        if not raw_event:
            return {}

        cleaned = {}
        for key, value in raw_event.items():
            if isinstance(value, str):
                # Cap very long strings at 5K chars
                cleaned[key] = value[:5000] if len(value) > 5000 else value
            elif isinstance(value, (dict, list)):
                # Truncate nested structures to JSON string, capped
                try:
                    serialized = json.dumps(value, default=str)
                    if len(serialized) > 5000:
                        cleaned[key] = json.loads(serialized[:5000] + '..."}}')  # best effort
                    else:
                        cleaned[key] = value
                except:
                    cleaned[key] = str(value)[:5000]
            elif isinstance(value, bytes):
                cleaned[key] = f"<binary {len(value)} bytes>"
            else:
                cleaned[key] = value
        return cleaned

    def _build_full_ioc_section(self, iocs: List) -> str:
        """Build deduplicated IOC section for the deep dive prompt."""
        if not iocs:
            return "No IOCs extracted from alerts."

        # Deduplicate by value
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            if isinstance(ioc, dict):
                val = ioc.get('value', '')
                if val and val not in seen:
                    seen.add(val)
                    unique_iocs.append(ioc)

        # Group by type, limit per category
        by_type = {}
        for ioc in unique_iocs:
            ioc_type = ioc.get('type', 'unknown')
            if ioc_type not in by_type:
                by_type[ioc_type] = []
            if len(by_type[ioc_type]) < 15:
                by_type[ioc_type].append(ioc)

        lines = []
        for ioc_type, items in by_type.items():
            lines.append(f"\n[{ioc_type.upper()}] ({len(items)} indicators)")
            for item in items:
                context = item.get('context', '')
                lines.append(f"  - {item.get('value', 'N/A')}" + (f" ({context})" if context else ""))

        return '\n'.join(lines) if lines else "No IOCs extracted."

    def _parse_deep_dive_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the deep dive JSON response from Claude."""
        try:
            # Try to extract JSON from response
            text = response_text.strip()

            # Remove markdown code fences if present
            if text.startswith('```'):
                # Find the end of the first line (```json or ```)
                first_newline = text.index('\n')
                last_fence = text.rfind('```')
                if last_fence > first_newline:
                    text = text[first_newline + 1:last_fence].strip()

            result = json.loads(text)

            # Validate required fields
            required = ['verdict', 'confidence', 'threat_narrative']
            for field in required:
                if field not in result:
                    result[field] = 'unknown' if field != 'confidence' else 0.5

            return result

        except json.JSONDecodeError:
            logger.warning("Failed to parse deep dive response as JSON, attempting extraction")
            # Try to find JSON in the response
            import re
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except:
                    pass

            # Fallback: return raw text wrapped in structure
            return {
                "verdict": "inconclusive",
                "confidence": 0.5,
                "verdict_title": "Analysis Completed",
                "executive_summary": "Deep dive analysis completed but response could not be fully parsed.",
                "threat_narrative": response_text[:3000],
                "root_cause_analysis": "",
                "mitre_attack": [],
                "threat_actor_assessment": "",
                "timeline": [],
                "response_recommendations": [],
                "confidence_factors": {
                    "supporting": [],
                    "contradicting": [],
                    "gaps": ["Response parsing failed — review raw narrative"]
                },
                "parse_error": True
            }

    async def _store_deep_dive_results(self, investigation_id: str, analysis: Dict) -> None:
        """Store deep dive results in investigation_data JSONB.

        Also auto-closes investigation + source alert if deep dive verdict
        is BENIGN/FALSE_POSITIVE with high confidence (>=85%).
        """
        try:
            import uuid as _uuid
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return

            async with _admin_conn() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")

                # Try UUID first, fall back to human-readable investigation_id
                try:
                    inv_uuid = _uuid.UUID(investigation_id)
                    where_clause = "WHERE id = $1"
                    where_val = inv_uuid
                except (ValueError, AttributeError):
                    where_clause = "WHERE investigation_id = $1"
                    where_val = investigation_id

                # Check if deep dive verdict warrants auto-close
                deep_verdict = (analysis.get('verdict') or '').upper()
                deep_confidence = analysis.get('confidence', 0)
                if isinstance(deep_confidence, (int, float)) and deep_confidence <= 1:
                    deep_confidence = int(deep_confidence * 100)
                deep_confidence = int(deep_confidence)

                is_benign_high_conf = (
                    deep_verdict in ('BENIGN', 'FALSE_POSITIVE')
                    and deep_confidence >= 85
                )

                if is_benign_high_conf:
                    # Auto-close: update investigation_data + state + disposition + confidence + severity
                    confidence_decimal = deep_confidence / 100.0
                    await conn.execute(
                        f"""
                        UPDATE investigations
                        SET investigation_data = COALESCE(investigation_data, '{{}}'::jsonb)
                            || jsonb_build_object('riggs_deep_analysis', $2::jsonb),
                            state = 'CLOSED',
                            disposition = $3,
                            confidence = $4,
                            severity = 'low',
                            updated_at = CURRENT_TIMESTAMP
                        {where_clause}
                        """,
                        where_val,
                        json.dumps(analysis, default=str),
                        deep_verdict,
                        confidence_decimal,
                    )
                    logger.info(
                        f"[DEEP DIVE] Auto-closed investigation {investigation_id}: "
                        f"{deep_verdict} @ {deep_confidence}%"
                    )

                    # Also auto-close the source alert(s)
                    inv_row = await conn.fetchrow(
                        f"SELECT id FROM investigations {where_clause}", where_val
                    )
                    if inv_row:
                        closed_count = await conn.execute(
                            """
                            UPDATE alerts
                            SET status = 'closed',
                                ai_verdict = $1,
                                ai_confidence = $2,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE investigation_id = $3
                              AND status NOT IN ('closed', 'resolved')
                            """,
                            deep_verdict.lower(),
                            confidence_decimal,
                            inv_row['id'],
                        )
                        logger.info(
                            f"[DEEP DIVE] Auto-closed source alerts for {investigation_id}: {closed_count}"
                        )
                else:
                    # Just store results, don't change state
                    await conn.execute(
                        f"""
                        UPDATE investigations
                        SET investigation_data = COALESCE(investigation_data, '{{}}'::jsonb)
                            || jsonb_build_object('riggs_deep_analysis', $2::jsonb)
                        {where_clause}
                        """,
                        where_val,
                        json.dumps(analysis, default=str),
                    )

                logger.info(f"Stored deep dive results for investigation {investigation_id}")
        except Exception as e:
            logger.error(f"Failed to store deep dive results for {investigation_id}: {e}")


# Singleton instance
ai_triage_service = AITriageService()


async def triage_alert_background(alert_id: str, alert_data: Dict[str, Any], enrichment_data: Dict[str, Any]):
    """
    Background task to run AI triage on an alert.
    Called after enrichment completes.
    """
    try:
        await ai_triage_service.triage_alert(alert_id, alert_data, enrichment_data)
    except Exception as e:
        logger.error(f"Background AI triage failed for {alert_id}: {e}")


def get_ai_triage_service() -> AITriageService:
    """Get the singleton AI triage service instance."""
    return ai_triage_service
