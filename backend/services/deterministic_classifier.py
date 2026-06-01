# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Deterministic Pre-Classifier for T1 Triage

This service runs BEFORE the LLM agent to handle clear-cut alerts deterministically.
By catching obvious cases (trusted senders, known malicious IOCs, phishing tests),
we reduce token usage, improve latency, and ensure consistent decisions.

Decision Flow:
1. Check if sender is on trusted allowlist -> BENIGN
2. Check if this is a phishing awareness test -> BENIGN (auto-close)
3. Check enrichment for malicious IOCs from threat feeds -> TRUE_POSITIVE
4. Check for typosquat/lookalike domains -> TRUE_POSITIVE
5. Check for scam content patterns -> TRUE_POSITIVE
6. Otherwise -> DEFER to LLM agent

Returns:
- If confident: verdict, confidence, summary, should_auto_close
- If not confident: None (defer to LLM)
"""

import logging
import re
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# Use canonical Verdict enum for consistency
from models.verdict import Verdict

logger = logging.getLogger(__name__)


class DeterministicClassifier:
    """
    Pre-classifier that handles clear-cut alerts without LLM.

    Design principles:
    - High precision: Only classify when very confident
    - Fast: No API calls, pure pattern matching and DB lookups
    - Auditable: Clear reasoning for every decision
    """

    # Minimum confidence to auto-resolve (skip LLM entirely)
    MIN_CONFIDENCE_FOR_AUTO_RESOLVE = 0.85

    # Verdict constants - using canonical Verdict enum values
    VERDICT_BENIGN = Verdict.BENIGN.value
    VERDICT_TRUE_POSITIVE = Verdict.TRUE_POSITIVE.value
    VERDICT_SUSPICIOUS = Verdict.SUSPICIOUS.value
    VERDICT_FALSE_POSITIVE = Verdict.FALSE_POSITIVE.value
    VERDICT_MALICIOUS = Verdict.MALICIOUS.value

    def __init__(self):
        self.db = None

    def set_db(self, db):
        """Set database connection"""
        self.db = db

    async def classify(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None,
        phishing_email_content: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to classify an alert deterministically.

        Args:
            alert_data: Alert information including title, description, raw_event
            enrichment_data: IOC enrichment results if available
            phishing_email_content: Full phishing email content if this is a phishing report

        Returns:
            Classification result if confident, None to defer to LLM
            {
                "verdict": str,
                "confidence": float,
                "summary": str,
                "key_findings": List[str],
                "classification_method": str,
                "should_auto_close": bool,
                "should_create_investigation": bool,
                "skip_llm": bool
            }
        """
        try:
            # Extract email sender and subject
            raw_event = alert_data.get('raw_event', {})
            if isinstance(raw_event, str):
                import json
                try:
                    raw_event = json.loads(raw_event)
                except:
                    raw_event = {}

            sender = (
                raw_event.get('reporter') or
                raw_event.get('from') or
                raw_event.get('sender') or
                ''
            )
            subject = raw_event.get('subject', '') or alert_data.get('title', '')
            body_preview = raw_event.get('body', '') or raw_event.get('body_preview', '')

            # Get phishing content if available
            if phishing_email_content:
                sender = phishing_email_content.get('original_sender', sender)
                subject = phishing_email_content.get('original_subject', subject)
                body_preview = phishing_email_content.get('email_body', body_preview)

            # ================================================================
            # CHECK 1: Phishing awareness test
            # ================================================================
            phishing_test_result = await self._check_phishing_test(sender, subject)
            if phishing_test_result:
                logger.info(f"[DETERMINISTIC] Phishing test detected: {phishing_test_result['test_name']}")
                return {
                    "verdict": self.VERDICT_BENIGN,
                    "confidence": 0.99,
                    "summary": f"Phishing awareness test from {phishing_test_result['vendor']}. Auto-closed.",
                    "key_findings": [
                        f"Matched phishing test pattern: {phishing_test_result['test_name']}",
                        f"Vendor: {phishing_test_result['vendor']}",
                        "This is a security awareness test, not a real threat"
                    ],
                    "classification_method": "phishing_test_allowlist",
                    "should_auto_close": True,
                    "should_create_investigation": False,
                    "skip_llm": True,
                    "disposition": "BENIGN_POSITIVE"
                }

            # ================================================================
            # CHECK 2: Trusted sender allowlist
            # ================================================================
            trusted_sender_result = await self._check_trusted_sender(sender)
            if trusted_sender_result and trusted_sender_result.get('is_trusted'):
                trust_level = trusted_sender_result.get('trust_level', 'known')

                # Only auto-close for verified senders with clean enrichment
                has_malicious_iocs = self._check_for_malicious_iocs(enrichment_data)

                if trust_level == 'verified' and not has_malicious_iocs:
                    logger.info(f"[DETERMINISTIC] Verified trusted sender: {sender}")
                    return {
                        "verdict": self.VERDICT_BENIGN,
                        "confidence": 0.92,
                        "summary": f"Verified trusted sender ({trusted_sender_result.get('organization', sender)}). Clean IOCs.",
                        "key_findings": [
                            f"Sender {sender} is on verified trusted sender list",
                            f"Organization: {trusted_sender_result.get('organization', 'Unknown')}",
                            "No malicious indicators found in enrichment"
                        ],
                        "classification_method": "trusted_sender_verified",
                        "should_auto_close": True,
                        "should_create_investigation": False,
                        "skip_llm": True,
                        "trusted_sender": trusted_sender_result
                    }
                elif trust_level == 'trusted' and not has_malicious_iocs:
                    # Trusted but not verified - still high confidence but note it
                    logger.info(f"[DETERMINISTIC] Trusted sender (not verified): {sender}")
                    return {
                        "verdict": self.VERDICT_BENIGN,
                        "confidence": 0.85,
                        "summary": f"Trusted sender ({trusted_sender_result.get('organization', sender)}). No malicious IOCs.",
                        "key_findings": [
                            f"Sender {sender} is on trusted sender list",
                            "No malicious indicators found"
                        ],
                        "classification_method": "trusted_sender",
                        "should_auto_close": True,
                        "should_create_investigation": False,
                        "skip_llm": True,
                        "trusted_sender": trusted_sender_result
                    }

            # ================================================================
            # CHECK 3: Known malicious IOCs from threat feeds
            # ================================================================
            malicious_ioc_result = await self._check_threat_feed_iocs(enrichment_data)
            if malicious_ioc_result:
                logger.info(f"[DETERMINISTIC] Threat feed match: {malicious_ioc_result['ioc_value']}")
                return {
                    "verdict": self.VERDICT_TRUE_POSITIVE,
                    "confidence": malicious_ioc_result['confidence'],
                    "summary": f"Matched threat feed: {malicious_ioc_result['feed_name']}. IOC: {malicious_ioc_result['ioc_value'][:50]}",
                    "key_findings": [
                        f"IOC {malicious_ioc_result['ioc_value'][:50]} flagged by {malicious_ioc_result['feed_name']}",
                        f"IOC type: {malicious_ioc_result['ioc_type']}",
                        "Matched known threat intelligence"
                    ],
                    "classification_method": "threat_feed_match",
                    "should_auto_close": False,
                    "should_create_investigation": True,
                    "skip_llm": True,
                    "malicious_iocs": [malicious_ioc_result]
                }

            # ================================================================
            # CHECK 4: Domain in IOC Threat Center
            # ADDED 2026-01-21: Query IOC database for known malicious domains
            # This catches domains that are in our threat feed database
            # ================================================================
            if sender:
                sender_domain = sender.split('@')[-1] if '@' in sender else sender
                threat_feed_result = await self._check_domain_in_threat_feeds(sender_domain)
                if threat_feed_result and threat_feed_result.get('is_malicious'):
                    logger.info(f"[DETERMINISTIC] Domain {sender_domain} found in threat feeds as MALICIOUS")
                    return {
                        "verdict": self.VERDICT_TRUE_POSITIVE,
                        "confidence": threat_feed_result.get('confidence', 0.90),
                        "summary": f"Domain '{sender_domain}' found in threat intelligence as malicious (source: {threat_feed_result.get('feed_name', 'IOC database')})",
                        "key_findings": [
                            f"Domain {sender_domain} is flagged as malicious in threat feeds",
                            f"Source: {threat_feed_result.get('feed_name', 'IOC database')}",
                            f"Reason: {threat_feed_result.get('reason', 'Known malicious domain')}"
                        ],
                        "classification_method": "threat_feed_domain_match",
                        "should_auto_close": False,
                        "should_create_investigation": True,
                        "skip_llm": True,
                        "threat_type": "malicious_domain",
                        "ioc_data": threat_feed_result.get('ioc_data')
                    }
                elif threat_feed_result and threat_feed_result.get('is_suspicious'):
                    # Suspicious but not confirmed malicious - flag but don't auto-classify
                    logger.info(f"[DETERMINISTIC] Domain {sender_domain} found in threat feeds as SUSPICIOUS - deferring to LLM")
                    # Don't return here - let LLM analyze with this context

            # ================================================================
            # CHECK 5: Typosquat / lookalike domains
            # ================================================================
            if sender:
                sender_domain = sender.split('@')[-1] if '@' in sender else sender
                lookalike_result = self._check_lookalike_domain(sender_domain)
                if lookalike_result and lookalike_result.get('is_lookalike'):
                    logger.info(f"[DETERMINISTIC] Typosquat detected: {sender_domain} -> {lookalike_result['impersonated_brand']}")
                    return {
                        "verdict": self.VERDICT_TRUE_POSITIVE,
                        "confidence": 0.88,
                        "summary": f"Typosquat domain impersonating {lookalike_result['impersonated_brand']}: {sender_domain}",
                        "key_findings": [
                            f"Domain {sender_domain} impersonates {lookalike_result['impersonated_brand']}",
                            f"Detection method: {lookalike_result.get('method', 'pattern matching')}",
                            "High-confidence phishing indicator"
                        ],
                        "classification_method": "typosquat_detection",
                        "should_auto_close": False,
                        "should_create_investigation": True,
                        "skip_llm": True,
                        "threat_type": "phishing"
                    }

            # ================================================================
            # CHECK 6: Scam content patterns (419 fraud, BEC, etc.)
            # ================================================================
            scam_result = self._check_scam_content(subject, body_preview[:2000])
            if scam_result and scam_result.get('is_scam'):
                logger.info(f"[DETERMINISTIC] Scam detected: {scam_result['scam_type']}")
                return {
                    "verdict": self.VERDICT_TRUE_POSITIVE,
                    "confidence": 0.85,
                    "summary": f"Scam detected: {scam_result['scam_type']}. {scam_result.get('reason', '')}",
                    "key_findings": [
                        f"Scam type: {scam_result['scam_type']}",
                        f"Detection: {scam_result.get('reason', 'Content matches known scam patterns')}",
                        "Content matches known fraud patterns"
                    ],
                    "classification_method": "scam_detection",
                    "should_auto_close": False,
                    "should_create_investigation": True,
                    "skip_llm": True,
                    "threat_type": "scam"
                }

            # ================================================================
            # CHECK 7: Encoded/obfuscated content detection
            # If alert contains encoded content (base64, encoded PowerShell, etc.)
            # it needs deep analysis by Riggs - do NOT auto-close
            # ================================================================
            has_encoded_content = self._check_encoded_content(alert_data, raw_event)
            if has_encoded_content:
                logger.info(f"[DETERMINISTIC] Alert has encoded/obfuscated content - requires Riggs deep analysis")
                # Return None to defer to LLM, which will then trigger investigation + Riggs
                return None

            # ================================================================
            # CHECK 8: All IOCs enriched and clean
            # UPDATED 2026-01-21: More conservative auto-close for clean IOCs
            # - Require at least 2 IOCs for auto-close (was 1)
            # - Only auto-close if multiple enrichment sources confirm clean
            # - For single IOC, still report benign but defer to LLM for final decision
            # ================================================================
            clean_ioc_result = self._check_all_iocs_clean(enrichment_data)
            if clean_ioc_result and clean_ioc_result.get('all_clean'):
                ioc_count = clean_ioc_result['ioc_count']
                source_count = clean_ioc_result.get('source_count', 1)

                # Build a more informative summary with IOC breakdown
                ioc_breakdown = []
                iocs_by_type = clean_ioc_result.get('iocs_by_type', {})
                for ioc_type, iocs in iocs_by_type.items():
                    if iocs:
                        ioc_breakdown.append(f"{len(iocs)} {ioc_type}")

                # Conservative auto-close: require 2+ IOCs AND multiple sources
                # This prevents auto-closing alerts with minimal enrichment
                should_auto_close = (ioc_count >= 2 and source_count >= 2)

                if ioc_count >= 1:
                    logger.info(f"[DETERMINISTIC] All {ioc_count} IOCs clean (auto_close={should_auto_close})")

                    # Confidence scales with evidence: more IOCs and sources = higher confidence
                    base_confidence = 0.75
                    confidence = min(0.88, base_confidence + (ioc_count * 0.03) + (source_count * 0.02))

                    summary_parts = [
                        f"**T1 Triage: BENIGN** ({int(confidence*100)}% confidence)",
                        f"All {ioc_count} IOCs ({', '.join(ioc_breakdown) if ioc_breakdown else 'various types'}) enriched across {source_count} threat intel sources and found clean.",
                        "No malicious or suspicious indicators detected."
                    ]

                    return {
                        "verdict": self.VERDICT_BENIGN,
                        "confidence": confidence,
                        "summary": " ".join(summary_parts),
                        "key_findings": [
                            f"Enriched {ioc_count} IOCs across {source_count} sources",
                            "No malicious or suspicious indicators found",
                            "All IOCs have clean reputation"
                        ],
                        "classification_method": "clean_enrichment",
                        "should_auto_close": should_auto_close,
                        "should_create_investigation": not should_auto_close,  # Create investigation for review if not auto-closing
                        "skip_llm": should_auto_close  # Only skip LLM if we're confident enough to auto-close
                    }

            # ================================================================
            # No confident classification - defer to LLM
            # ================================================================
            logger.debug(f"[DETERMINISTIC] No confident classification, deferring to LLM")
            return None

        except Exception as e:
            logger.error(f"[DETERMINISTIC] Classification error: {e}")
            return None  # On error, always defer to LLM

    async def _check_phishing_test(self, sender: str, subject: str) -> Optional[Dict[str, Any]]:
        """Check if this matches a phishing awareness test pattern."""
        try:
            from services.sender_trust_service import get_sender_trust_service
            trust_service = get_sender_trust_service()

            result = await trust_service.check_phishing_test(sender, subject)
            if result.is_phishing_test:
                return {
                    "is_phishing_test": True,
                    "test_name": result.test_name,
                    "vendor": result.vendor,
                    "auto_close": result.auto_close
                }
        except Exception as e:
            logger.debug(f"Phishing test check failed: {e}")
        return None

    async def _check_trusted_sender(self, sender: str) -> Optional[Dict[str, Any]]:
        """Check if sender is on trusted allowlist."""
        if not sender:
            return None

        try:
            from services.sender_trust_service import get_sender_trust_service
            trust_service = get_sender_trust_service()

            result = await trust_service.check_trusted_sender(sender)
            if result.is_trusted:
                return {
                    "is_trusted": True,
                    "trust_level": result.trust_level,
                    "organization": result.organization,
                    "category": result.category
                }
        except Exception as e:
            logger.debug(f"Trusted sender check failed: {e}")
        return None

    async def _check_threat_feed_iocs(self, enrichment_data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if any IOCs are from threat feeds (already known malicious)."""
        if not enrichment_data:
            return None

        results = enrichment_data.get('results', {})

        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            for ioc in results.get(ioc_type, []):
                if not isinstance(ioc, dict):
                    continue

                # Check if this came from a threat feed
                feed_name = ioc.get('feed_name') or ioc.get('source_type') == 'threat_feed'
                verdict = (ioc.get('verdict') or '').lower()

                if feed_name or verdict in ['malicious', 'bad', 'malware']:
                    if ioc.get('from_cache') and 'threat_feed' in str(ioc.get('reason', '')):
                        return {
                            "ioc_value": ioc.get('value', 'unknown'),
                            "ioc_type": ioc_type.rstrip('s'),  # 'ips' -> 'ip'
                            "feed_name": ioc.get('feed_name', ioc.get('source', 'threat_intel')),
                            "confidence": 0.92,
                            "verdict": verdict
                        }
                    elif verdict == 'malicious':
                        return {
                            "ioc_value": ioc.get('value', 'unknown'),
                            "ioc_type": ioc_type.rstrip('s'),
                            "feed_name": ioc.get('source', 'enrichment'),
                            "confidence": 0.88,
                            "verdict": verdict
                        }
        return None

    def _check_for_malicious_iocs(self, enrichment_data: Optional[Dict[str, Any]]) -> bool:
        """Check if enrichment contains any malicious IOCs."""
        if not enrichment_data:
            return False

        summary = enrichment_data.get('summary', {})
        if summary.get('malicious', 0) > 0:
            return True

        results = enrichment_data.get('results', {})
        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            for ioc in results.get(ioc_type, []):
                if isinstance(ioc, dict):
                    verdict = (ioc.get('verdict') or '').lower()
                    if verdict in ['malicious', 'bad', 'malware']:
                        return True
        return False

    def _check_lookalike_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if domain is a typosquat/lookalike of known brands."""
        if not domain:
            return None

        try:
            from services.sender_trust_service import get_sender_trust_service
            trust_service = get_sender_trust_service()
            return trust_service.check_lookalike_domain(domain)
        except Exception as e:
            logger.debug(f"Lookalike check failed: {e}")
        return None

    def _check_scam_content(self, subject: str, body: str) -> Optional[Dict[str, Any]]:
        """Check for scam content patterns."""
        if not subject and not body:
            return None

        try:
            from services.sender_trust_service import get_sender_trust_service
            trust_service = get_sender_trust_service()
            return trust_service.check_scam_content(subject, body)
        except Exception as e:
            logger.debug(f"Scam content check failed: {e}")
        return None

    def _check_all_iocs_clean(self, enrichment_data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if all IOCs have been enriched and are clean."""
        if not enrichment_data:
            return None

        results = enrichment_data.get('results', {})
        summary = enrichment_data.get('summary', {})

        total_enriched = summary.get('total_enriched', 0)
        malicious = summary.get('malicious', 0)
        suspicious = summary.get('suspicious', 0)
        clean = summary.get('clean', 0)

        # Need at least 1 enriched IOC
        if total_enriched < 1:
            return None

        # All must be clean (no malicious or suspicious)
        if malicious > 0 or suspicious > 0:
            return None

        # Count unique sources and IOCs by type
        sources = set()
        iocs_by_type = {}
        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            type_iocs = results.get(ioc_type, [])
            if type_iocs:
                iocs_by_type[ioc_type] = [
                    ioc.get('value', ioc.get('ioc', str(ioc))) if isinstance(ioc, dict) else str(ioc)
                    for ioc in type_iocs
                ]
            for ioc in type_iocs:
                if isinstance(ioc, dict):
                    for src in ioc.get('sources', []):
                        sources.add(src)
                    if ioc.get('source'):
                        sources.add(ioc['source'])

        return {
            "all_clean": True,
            "ioc_count": total_enriched,
            "clean_count": clean,
            "source_count": len(sources) or 1,
            "iocs_by_type": iocs_by_type
        }

    def _check_encoded_content(self, alert_data: Dict[str, Any], raw_event: Dict[str, Any]) -> bool:
        """
        Check if the alert contains encoded/obfuscated content that requires
        deep analysis by Riggs. This prevents auto-closing alerts with clean IOCs
        but hidden malicious content.

        Returns True if encoded content is detected.
        """
        import re

        # Check various fields for encoded content indicators
        fields_to_check = []

        # Alert level fields
        fields_to_check.append(alert_data.get('title', ''))
        fields_to_check.append(alert_data.get('description', ''))

        # Raw event fields
        fields_to_check.append(str(raw_event.get('command_line', '')))
        fields_to_check.append(str(raw_event.get('commandLine', '')))
        fields_to_check.append(str(raw_event.get('process_command_line', '')))
        fields_to_check.append(str(raw_event.get('script_content', '')))
        fields_to_check.append(str(raw_event.get('body', '')))
        fields_to_check.append(str(raw_event.get('body_preview', '')))

        combined_text = ' '.join(fields_to_check).lower()

        # Pattern 1: PowerShell encoded command flags
        if re.search(r'-enc\s+[a-zA-Z0-9+/=]{20,}', combined_text, re.IGNORECASE):
            logger.debug("[ENCODED_CHECK] Found PowerShell -enc pattern")
            return True

        if re.search(r'-encodedcommand\s+[a-zA-Z0-9+/=]{20,}', combined_text, re.IGNORECASE):
            logger.debug("[ENCODED_CHECK] Found PowerShell -encodedcommand pattern")
            return True

        # Pattern 2: Base64 encoded strings (minimum 50 chars to avoid false positives)
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        if re.search(base64_pattern, combined_text):
            logger.debug("[ENCODED_CHECK] Found base64-like content")
            return True

        # Pattern 3: Common obfuscation keywords in command lines
        obfuscation_indicators = [
            'frombase64string',
            '[convert]::',
            'iex(',
            'invoke-expression',
            'downloadstring',
            '-nop -w hidden',
            '-windowstyle hidden',
            'bypass -exec',
            'invoke-webrequest',
            'net.webclient',
            'bitstransfer',
            'certutil -decode',
            'certutil /decode'
        ]

        for indicator in obfuscation_indicators:
            if indicator in combined_text:
                logger.debug(f"[ENCODED_CHECK] Found obfuscation indicator: {indicator}")
                return True

        # Pattern 4: Check raw_event _extracted for decoded content
        extracted = raw_event.get('_extracted', {})
        if extracted.get('decoded_content'):
            logger.debug("[ENCODED_CHECK] Found pre-decoded content in _extracted")
            return True

        if extracted.get('decoded_iocs') and any(extracted['decoded_iocs'].values()):
            logger.debug("[ENCODED_CHECK] Found IOCs in decoded content")
            return True

        return False

    async def _check_domain_in_threat_feeds(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Check if a domain exists in the IOC threat center as malicious.

        ADDED 2026-01-21: This method queries the IOC database for domains
        that have been flagged by threat feeds. This catches known-bad domains
        that might not match lookalike patterns.

        Args:
            domain: Domain to check

        Returns:
            Dict with is_malicious, is_suspicious, feed_name, confidence, ioc_data
            None if domain not found in threat feeds
        """
        if not domain:
            return None

        try:
            from services.sender_trust_service import get_sender_trust_service
            trust_service = get_sender_trust_service()
            return await trust_service.check_domain_in_threat_feeds(domain)
        except Exception as e:
            logger.debug(f"Threat feed domain check failed: {e}")
            return None


# Singleton instance
_deterministic_classifier: Optional[DeterministicClassifier] = None


def get_deterministic_classifier() -> DeterministicClassifier:
    """Get the singleton deterministic classifier instance."""
    global _deterministic_classifier
    if _deterministic_classifier is None:
        _deterministic_classifier = DeterministicClassifier()
    return _deterministic_classifier
