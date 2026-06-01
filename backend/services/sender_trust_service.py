# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Sender Trust Service

Manages trusted sender allowlist and phishing test detection.
Integrates with AI triage to:
1. Identify emails from trusted senders (reduce false positives)
2. Auto-close phishing awareness tests
3. Use WHOIS data to validate domain legitimacy

Key features:
- Trusted sender domain allowlist with trust levels
- Phishing test pattern matching (sender + subject)
- WHOIS-based domain age verification
- Hit tracking for audit
"""

import re
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONSTANTS FOR CROSS-SERVICE ACCESS
# These are exported for use by ai_triage_service and other consumers
# ═══════════════════════════════════════════════════════════════════════════════

# LEGITIMATE brand-related domains that should NEVER be flagged as phishing
# If sender domain is in this set, skip all intent analysis
LEGITIMATE_BRAND_DOMAINS: Set[str] = {
    # Microsoft legitimate domains
    'microsoftonline.com', 'office.com', 'office365.com', 'live.com',
    'hotmail.com', 'outlook.com', 'microsoft.com', 'azure.com',
    'onmicrosoft.com', 'sharepoint.com', 'skype.com', 'xbox.com',
    'bing.com', 'msn.com', 'windowsupdate.com', 'windows.com',
    'microsoft-ce.com', 'microsoft.net', 'microsoft.io',
    'microsoftstream.com', 'microsoftstore.com', 'microsoftteams.com',
    # Google legitimate domains
    'google.com', 'gmail.com', 'googlemail.com', 'googleapis.com',
    'gstatic.com', 'youtube.com', 'googlevideo.com', 'googleusercontent.com',
    'googleadservices.com', 'doubleclick.net', 'android.com', 'chrome.com',
    # Amazon legitimate domains
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.es',
    'amazon.it', 'amazon.ca', 'amazon.com.au', 'amazon.co.jp',
    'amazonaws.com', 'amazontrust.com', 'amazonses.com', 'amazonpay.com',
    'aboutamazon.com', 'a2z.com', 'primevideo.com', 'twitch.tv',
    # Apple legitimate domains
    'apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.com',
    'mzstatic.com', 'cdn-apple.com', 'apple-cloudkit.com', 'icloud-content.com',
    # PayPal legitimate domains
    'paypal.com', 'paypalobjects.com', 'paypal.me', 'braintreepayments.com',
    # Meta/Facebook legitimate domains
    'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
    'whatsapp.net', 'meta.com', 'messenger.com', 'oculus.com',
    # Other major services
    'netflix.com', 'nflxvideo.net', 'dropbox.com', 'dropboxapi.com',
    'linkedin.com', 'licdn.com', 'twitter.com', 'x.com', 't.co',
    'slack.com', 'slackb.com', 'zoom.us', 'zoom.com', 'zoomgov.com',
    'salesforce.com', 'force.com', 'github.com', 'githubusercontent.com',
    'gitlab.com', 'atlassian.com', 'atlassian.net', 'jira.com',
    'docusign.com', 'docusign.net', 'adobesign.com', 'adobe.com',
    # Common legitimate notification/email service domains
    'sendgrid.net', 'sendgrid.com', 'mailchimp.com', 'mailgun.com',
    'postmarkapp.com', 'sparkpostmail.com', 'constantcontact.com',
    'hubspot.com', 'intercom.io', 'zendesk.com',
}

# Internal/trusted TLDs that should auto-close as benign for email alerts
INTERNAL_TLDS: Set[str] = {'.corp', '.local', '.internal', '.lan', '.home', '.intranet'}

# Suspicious TLDs commonly used in phishing - require extra scrutiny
SUSPICIOUS_TLDS: Set[str] = {'.xyz', '.top', '.click', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.info', '.buzz', '.loan', '.racing'}


def is_legitimate_brand_domain(domain: str) -> bool:
    """
    Check if domain is a known legitimate brand domain.

    Args:
        domain: Domain to check (e.g., 'microsoft.com')

    Returns:
        True if domain is in LEGITIMATE_BRAND_DOMAINS or is a subdomain of one
    """
    if not domain:
        return False
    domain_lower = domain.lower().strip()

    # Exact match
    if domain_lower in LEGITIMATE_BRAND_DOMAINS:
        return True

    # Subdomain match (e.g., mail.google.com -> google.com)
    for legit_domain in LEGITIMATE_BRAND_DOMAINS:
        if domain_lower.endswith('.' + legit_domain):
            return True

    return False


def is_internal_domain(domain: str) -> bool:
    """
    Check if domain is an internal/corporate domain.

    Args:
        domain: Domain to check

    Returns:
        True if domain uses internal TLD (.corp, .local, etc.)
    """
    if not domain:
        return False
    domain_lower = domain.lower().strip()
    return any(domain_lower.endswith(tld) for tld in INTERNAL_TLDS)


def has_suspicious_tld(domain: str) -> bool:
    """
    Check if domain uses a suspicious TLD commonly associated with phishing.

    Args:
        domain: Domain to check

    Returns:
        True if domain uses suspicious TLD
    """
    if not domain:
        return False
    domain_lower = domain.lower().strip()
    return any(domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)


class TrustLevel(str, Enum):
    """Trust levels for sender domains"""
    VERIFIED = "verified"    # Fully trusted, can auto-close benign
    TRUSTED = "trusted"      # Skip suspicious checks but analyze
    KNOWN = "known"          # Note as known but still analyze fully


@dataclass
class TrustedSenderResult:
    """Result of checking trusted sender status"""
    is_trusted: bool
    trust_level: Optional[str] = None
    organization: Optional[str] = None
    category: Optional[str] = None
    reason: Optional[str] = None
    requires_whois: bool = False
    min_domain_age_days: int = 0


@dataclass
class PhishingTestResult:
    """Result of checking for phishing test match"""
    is_phishing_test: bool
    test_name: Optional[str] = None
    vendor: Optional[str] = None
    auto_close: bool = False
    skip_enrichment: bool = False
    disposition: Optional[str] = None


class SenderTrustService:
    """
    Service for managing sender trust and phishing test detection.

    Usage:
        service = SenderTrustService()

        # Check if sender is trusted
        result = await service.check_trusted_sender("notifications@discord.com")
        if result.is_trusted and result.trust_level == 'verified':
            # Sender is fully trusted

        # Check if email is a phishing test
        test = await service.check_phishing_test(
            sender="security-test@company.com",
            subject="Urgent: Verify your account"
        )
        if test.is_phishing_test:
            # Auto-close as phishing test
    """

    # TLDs that are inherently trustworthy (educational, government)
    TRUSTED_TLDS = {
        '.edu': ('known', 'Educational Institution', 'education'),
        '.gov': ('verified', 'Government Agency', 'government'),
        '.mil': ('verified', 'US Military', 'government'),
        '.ac.uk': ('known', 'UK Academic Institution', 'education'),
        '.edu.au': ('known', 'Australian Educational Institution', 'education'),
    }

    # Major brands that are commonly impersonated in phishing attacks
    # Used for lookalike domain detection
    PROTECTED_BRANDS = {
        'microsoft': ['microsoft', 'outlook', 'office365', 'azure', 'onedrive', 'sharepoint'],
        'google': ['google', 'gmail', 'drive', 'docs'],
        'amazon': ['amazon', 'aws', 'prime'],
        'apple': ['apple', 'icloud', 'itunes'],
        'paypal': ['paypal'],
        'facebook': ['facebook', 'meta', 'instagram', 'whatsapp'],
        'netflix': ['netflix'],
        'dropbox': ['dropbox'],
        'linkedin': ['linkedin'],
        'twitter': ['twitter'],
        'bank': ['chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank'],
    }

    # Reference module-level constants (avoid duplication)
    # Use module-level SUSPICIOUS_TLDS and LEGITIMATE_BRAND_DOMAINS directly
    SUSPICIOUS_TLDS = list(SUSPICIOUS_TLDS)  # Reference module-level constant

    # Content patterns indicating advance fee fraud / Nigerian scam
    SCAM_CONTENT_PATTERNS = [
        r'(?:prince|princess|minister|diplomat|barrister|attorney)\s+(?:of|from)\s+(?:nigeria|africa)',
        r'(?:million|billion)\s+(?:dollars?|usd|euros?|pounds?)',
        r'(?:inheritance|lottery|winning|beneficiary|next of kin)',
        r'(?:send|wire|transfer)\s+(?:your\s+)?(?:bank\s+)?(?:details?|information|account)',
        r'(?:urgent|confidential|private)\s+(?:business|matter|proposal)',
        r'(?:deceased|late)\s+(?:father|mother|husband|wife|client)',
        r'(?:share|split|percentage)\s+(?:of\s+)?(?:the\s+)?(?:money|funds|amount)',
    ]

    # BEC (Business Email Compromise) patterns
    BEC_PATTERNS = [
        r'(?:urgent|immediate)\s+(?:wire|bank)\s+(?:transfer|payment)',
        r'(?:ceo|cfo|president|director|boss)\s+(?:asked|requested|needs)',
        r'(?:process|handle|complete)\s+(?:this\s+)?(?:payment|transfer)\s+(?:immediately|today|now|asap)',
        r'(?:confidential|keep\s+this\s+quiet|don\'t\s+tell|between\s+us)',
        r'(?:vendor|supplier)\s+(?:payment|invoice)\s+(?:change|update)',
        r'(?:new\s+)?(?:bank\s+)?(?:account|routing)\s+(?:number|details?)\s+(?:change|update)',
    ]

    def __init__(self):
        self._trusted_cache: Dict[str, Dict] = {}
        self._test_cache: List[Dict] = []
        self._cache_loaded = False
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def _check_tld_trust(self, domain: str) -> Optional[TrustedSenderResult]:
        """Check if domain TLD indicates inherent trust (e.g., .edu, .gov)"""
        domain_lower = domain.lower()
        for tld, (trust_level, org_type, category) in self.TRUSTED_TLDS.items():
            if domain_lower.endswith(tld):
                return TrustedSenderResult(
                    is_trusted=True,
                    trust_level=trust_level,
                    organization=f"{domain} ({org_type})",
                    category=category,
                    reason=f"Domain uses trusted TLD: {tld}",
                    requires_whois=False,
                    min_domain_age_days=0
                )
        return None

    def check_lookalike_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check if a domain is trying to impersonate a known brand.

        Examples of lookalike domains:
        - microsoft-365-security.net (impersonating microsoft.com)
        - paypal-verify.com (impersonating paypal.com)
        - amazon-account-update.com (impersonating amazon.com)

        Updated 2026-01-21: Reduced false positives by:
        - Checking LEGITIMATE_BRAND_DOMAINS first
        - Requiring 3 indicators instead of 2
        - Better handling of legitimate subdomains

        Returns:
            Dict with is_lookalike, impersonated_brand, confidence, reason
        """
        domain_lower = domain.lower()

        # EARLY EXIT: Check if this is a known legitimate domain
        # This check happens BEFORE brand keyword detection to prevent false positives
        if domain_lower in LEGITIMATE_BRAND_DOMAINS:
            return {'is_lookalike': False, 'is_legitimate': True, 'reason': 'Known legitimate domain'}

        # Check if this is a subdomain of a known legitimate domain
        for legit_domain in LEGITIMATE_BRAND_DOMAINS:
            if domain_lower.endswith('.' + legit_domain):
                return {
                    'is_lookalike': False,
                    'is_legitimate': True,
                    'is_subdomain': True,
                    'parent_domain': legit_domain,
                    'reason': f'Subdomain of legitimate {legit_domain}'
                }

        # Remove TLD for analysis
        parts = domain_lower.split('.')
        if len(parts) < 2:
            return {'is_lookalike': False}

        domain_without_tld = '.'.join(parts[:-1])
        tld = '.' + parts[-1]

        # Check for suspicious TLD
        has_suspicious_tld = tld in self.SUSPICIOUS_TLDS

        for brand, keywords in self.PROTECTED_BRANDS.items():
            for keyword in keywords:
                # Check if brand keyword appears in domain
                if keyword in domain_without_tld:
                    # Now check if this is the REAL domain or a lookalike

                    # Real domains are simple: microsoft.com, paypal.com, amazon.com
                    real_domains = [f"{kw}.com" for kw in keywords] + [f"{kw}.net" for kw in keywords] + [f"{kw}.org" for kw in keywords]

                    if domain_lower in real_domains:
                        # This is a legitimate domain
                        return {'is_lookalike': False, 'is_legitimate': True, 'brand': brand}

                    # Check if this is a legitimate subdomain of a real brand domain
                    # e.g., email.pharmacy.amazon.com ends with .amazon.com
                    for real_domain in real_domains:
                        if domain_lower.endswith('.' + real_domain):
                            return {'is_lookalike': False, 'is_legitimate': True, 'brand': brand, 'is_subdomain': True}

                    # Check for common lookalike patterns
                    lookalike_indicators = [
                        '-' in domain_without_tld,  # microsoft-365.com
                        '_' in domain_without_tld,  # microsoft_365.com
                        'verify' in domain_without_tld,
                        'secure' in domain_without_tld,
                        'login' in domain_without_tld,
                        'account' in domain_without_tld,
                        'update' in domain_without_tld,
                        'support' in domain_without_tld,
                        'security' in domain_without_tld,
                        'confirm' in domain_without_tld,
                        'alert' in domain_without_tld,
                        has_suspicious_tld,
                    ]

                    indicator_count = sum(1 for i in lookalike_indicators if i)

                    # UPDATED 2026-01-21: Require at least 3 indicators (was 2)
                    # This reduces false positives for legitimate business emails
                    # that may contain hyphens or brand-related keywords
                    if indicator_count >= 3:
                        confidence = min(0.95, 0.5 + (indicator_count * 0.12))  # Slightly lower confidence scaling
                        reasons = []
                        if '-' in domain_without_tld:
                            reasons.append("contains hyphens")
                        if '_' in domain_without_tld:
                            reasons.append("contains underscores")
                        if has_suspicious_tld:
                            reasons.append(f"suspicious TLD ({tld})")
                        if any(x in domain_without_tld for x in ['verify', 'secure', 'login', 'account', 'update', 'security']):
                            reasons.append("contains phishing keywords")

                        return {
                            'is_lookalike': True,
                            'impersonated_brand': brand,
                            'impersonated_keyword': keyword,
                            'confidence': confidence,
                            'reason': f"Domain '{domain}' appears to impersonate {brand.upper()} ({', '.join(reasons)})",
                            'indicators': indicator_count
                        }

        return {'is_lookalike': False}

    def check_scam_content(self, subject: str, body: str = None) -> Dict[str, Any]:
        """
        Check email content for classic scam patterns (419 fraud, BEC).

        Args:
            subject: Email subject line
            body: Email body text (optional, if available)

        Returns:
            Dict with is_scam, scam_type, confidence, matched_patterns
        """
        text = f"{subject or ''} {body or ''}".lower()

        if not text.strip():
            return {'is_scam': False}

        matched_419 = []
        matched_bec = []

        # Check for advance fee fraud / Nigerian scam patterns
        for pattern in self.SCAM_CONTENT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matched_419.append(pattern)

        # Check for BEC patterns
        for pattern in self.BEC_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matched_bec.append(pattern)

        # UPDATED 2026-01-21: Require minimum thresholds to reduce false positives
        # - 419 fraud: 1 pattern is enough (these are very specific)
        # - BEC: Require at least 2 patterns (single BEC patterns can appear in legit emails)
        # - Mixed: Both types present
        has_419 = len(matched_419) >= 1
        has_bec = len(matched_bec) >= 2  # STRICTER: require 2+ BEC patterns

        if not has_419 and not has_bec:
            # If we have 1 BEC pattern, return low-confidence suspicious (not scam)
            if len(matched_bec) == 1:
                return {
                    'is_scam': False,
                    'is_suspicious': True,
                    'suspicious_reason': 'Single BEC-like pattern detected but insufficient for classification',
                    'matched_patterns': 1
                }
            return {'is_scam': False}

        matched_patterns = matched_419 + matched_bec
        total_matches = len(matched_patterns)

        # Determine scam type based on patterns
        if has_bec and has_419:
            scam_type = 'mixed_fraud'
        elif has_bec:
            scam_type = 'business_email_compromise'
        else:
            scam_type = 'advance_fee_fraud'

        # Confidence based on number of patterns matched
        # UPDATED: Start lower and scale more gradually
        confidence = min(0.92, 0.55 + (total_matches * 0.12))

        return {
            'is_scam': True,
            'scam_type': scam_type,
            'confidence': confidence,
            'matched_patterns': total_matches,
            'matched_419_patterns': len(matched_419),
            'matched_bec_patterns': len(matched_bec),
            'reason': f"Email matches {total_matches} {scam_type} pattern(s)"
        }

    async def _get_pool(self):
        """Get database instance for tenant-aware connections"""
        from services.postgres_db import postgres_db
        return postgres_db

    async def load_cache(self, force: bool = False) -> None:
        """Load trusted senders and phishing tests into cache"""
        if self._cache_loaded and not force:
            return

        try:
            pool = await self._get_pool()

            async with pool.tenant_acquire() as conn:
                # Load trusted senders
                rows = await conn.fetch("""
                    SELECT id, domain, sender_pattern, trust_level,
                           requires_whois_match, min_domain_age_days,
                           organization, category, reason
                    FROM trusted_senders
                    WHERE is_active = true
                    ORDER BY domain
                """)

                self._trusted_cache = {}
                for row in rows:
                    domain = row['domain'].lower()
                    if domain not in self._trusted_cache:
                        self._trusted_cache[domain] = []
                    self._trusted_cache[domain].append({
                        'id': str(row['id']),
                        'sender_pattern': row['sender_pattern'],
                        'trust_level': row['trust_level'],
                        'requires_whois': row['requires_whois_match'],
                        'min_domain_age_days': row['min_domain_age_days'] or 365,
                        'organization': row['organization'],
                        'category': row['category'],
                        'reason': row['reason']
                    })

                # Load phishing tests
                rows = await conn.fetch("""
                    SELECT id, sender_pattern, subject_pattern, match_type,
                           test_name, vendor, auto_close, skip_enrichment, disposition
                    FROM phishing_test_list
                    WHERE is_active = true
                    AND (valid_until IS NULL OR valid_until > NOW())
                    AND valid_from <= NOW()
                """)

                self._test_cache = []
                self._compiled_patterns = {}

                for row in rows:
                    test_id = str(row['id'])
                    self._test_cache.append({
                        'id': test_id,
                        'sender_pattern': row['sender_pattern'],
                        'subject_pattern': row['subject_pattern'],
                        'match_type': row['match_type'],
                        'test_name': row['test_name'],
                        'vendor': row['vendor'],
                        'auto_close': row['auto_close'],
                        'skip_enrichment': row['skip_enrichment'],
                        'disposition': row['disposition']
                    })

                    # Pre-compile regex patterns
                    if row['match_type'] == 'regex':
                        try:
                            self._compiled_patterns[f"{test_id}_sender"] = re.compile(
                                row['sender_pattern'], re.IGNORECASE
                            )
                            self._compiled_patterns[f"{test_id}_subject"] = re.compile(
                                row['subject_pattern'], re.IGNORECASE
                            )
                        except re.error as e:
                            logger.warning(f"Invalid regex pattern in phishing test {test_id}: {e}")

            self._cache_loaded = True
            logger.info(f"Loaded {len(self._trusted_cache)} trusted domains and {len(self._test_cache)} phishing tests")

        except Exception as e:
            logger.error(f"Failed to load sender trust cache: {e}")
            self._trusted_cache = {}
            self._test_cache = []
            self._cache_loaded = True

    async def check_trusted_sender(self, sender_email: str) -> TrustedSenderResult:
        """
        Check if a sender is in the trusted sender allowlist.

        Args:
            sender_email: Full email address (e.g., "notifications@discord.com")

        Returns:
            TrustedSenderResult with trust status and metadata
        """
        await self.load_cache()

        if not sender_email or '@' not in sender_email:
            return TrustedSenderResult(is_trusted=False)

        sender_email = sender_email.lower().strip()
        local_part, domain = sender_email.rsplit('@', 1)

        # Check for exact domain match
        entries = self._trusted_cache.get(domain, [])

        if not entries:
            # Try parent domain (e.g., e.godaddy.com -> godaddy.com)
            parts = domain.split('.')
            if len(parts) > 2:
                parent = '.'.join(parts[-2:])
                entries = self._trusted_cache.get(parent, [])

        if not entries:
            # Check for TLD-based trust (e.g., .edu, .gov domains)
            tld_trust = self._check_tld_trust(domain)
            if tld_trust:
                return tld_trust
            return TrustedSenderResult(is_trusted=False)

        # Find best matching entry
        for entry in entries:
            pattern = entry.get('sender_pattern')

            # If no sender pattern, domain match is enough
            if not pattern:
                await self._record_trusted_hit(entry['id'])
                return TrustedSenderResult(
                    is_trusted=True,
                    trust_level=entry['trust_level'],
                    organization=entry['organization'],
                    category=entry['category'],
                    reason=entry['reason'],
                    requires_whois=entry['requires_whois'],
                    min_domain_age_days=entry['min_domain_age_days']
                )

            # Check sender pattern match
            pattern = pattern.lower()
            if pattern.endswith('@'):
                # Prefix match (e.g., "notifications@")
                if local_part.startswith(pattern[:-1]):
                    await self._record_trusted_hit(entry['id'])
                    return TrustedSenderResult(
                        is_trusted=True,
                        trust_level=entry['trust_level'],
                        organization=entry['organization'],
                        category=entry['category'],
                        reason=entry['reason'],
                        requires_whois=entry['requires_whois'],
                        min_domain_age_days=entry['min_domain_age_days']
                    )
            elif pattern in sender_email:
                # Contains match
                await self._record_trusted_hit(entry['id'])
                return TrustedSenderResult(
                    is_trusted=True,
                    trust_level=entry['trust_level'],
                    organization=entry['organization'],
                    category=entry['category'],
                    reason=entry['reason'],
                    requires_whois=entry['requires_whois'],
                    min_domain_age_days=entry['min_domain_age_days']
                )

        return TrustedSenderResult(is_trusted=False)

    async def check_phishing_test(
        self,
        sender: str,
        subject: str
    ) -> PhishingTestResult:
        """
        Check if email matches a phishing awareness test pattern.
        Both sender AND subject must match.

        Args:
            sender: Email sender address
            subject: Email subject line

        Returns:
            PhishingTestResult with test details if matched
        """
        await self.load_cache()

        if not sender or not subject:
            return PhishingTestResult(is_phishing_test=False)

        sender = sender.lower().strip()
        subject = subject.strip()

        for test in self._test_cache:
            sender_match = False
            subject_match = False

            match_type = test['match_type']

            if match_type == 'exact':
                sender_match = test['sender_pattern'].lower() == sender
                subject_match = test['subject_pattern'].lower() == subject.lower()

            elif match_type == 'contains':
                sender_match = test['sender_pattern'].lower() in sender
                subject_match = test['subject_pattern'].lower() in subject.lower()

            elif match_type == 'regex':
                sender_pattern = self._compiled_patterns.get(f"{test['id']}_sender")
                subject_pattern = self._compiled_patterns.get(f"{test['id']}_subject")

                if sender_pattern and subject_pattern:
                    sender_match = bool(sender_pattern.search(sender))
                    subject_match = bool(subject_pattern.search(subject))

            # Both must match
            if sender_match and subject_match:
                await self._record_test_hit(test['id'])
                return PhishingTestResult(
                    is_phishing_test=True,
                    test_name=test['test_name'],
                    vendor=test['vendor'],
                    auto_close=test['auto_close'],
                    skip_enrichment=test['skip_enrichment'],
                    disposition=test['disposition']
                )

        return PhishingTestResult(is_phishing_test=False)

    async def validate_domain_age(
        self,
        domain: str,
        whois_data: Dict[str, Any],
        min_age_days: int = 365
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate domain age from WHOIS data.

        Args:
            domain: Domain to validate
            whois_data: WHOIS enrichment data
            min_age_days: Minimum age in days to be considered established

        Returns:
            Tuple of (is_valid, reason)
        """
        if not whois_data:
            return False, "No WHOIS data available"

        # Look for creation date in various formats
        creation_date = None
        for key in ['creation_date', 'created', 'registered', 'registration_date']:
            if key in whois_data:
                creation_date = whois_data[key]
                break

        if not creation_date:
            return False, "No creation date in WHOIS data"

        try:
            # Parse date - handle various formats
            if isinstance(creation_date, str):
                # Try common formats
                for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%d-%b-%Y', '%Y/%m/%d']:
                    try:
                        creation_dt = datetime.strptime(creation_date.split()[0], fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return False, f"Could not parse creation date: {creation_date}"
            elif isinstance(creation_date, datetime):
                creation_dt = creation_date
            else:
                return False, f"Unexpected date format: {type(creation_date)}"

            # Calculate age
            age_days = (datetime.now() - creation_dt).days

            if age_days >= min_age_days:
                return True, f"Domain is {age_days} days old (min: {min_age_days})"
            else:
                return False, f"Domain is only {age_days} days old (min: {min_age_days})"

        except Exception as e:
            return False, f"Error validating domain age: {e}"

    async def _record_trusted_hit(self, entry_id: str) -> None:
        """Record a hit on a trusted sender entry"""
        try:
            pool = await self._get_pool()
            async with pool.tenant_acquire() as conn:
                await conn.execute("""
                    UPDATE trusted_senders
                    SET hit_count = hit_count + 1,
                        last_hit_at = NOW()
                    WHERE id = $1
                """, entry_id)
        except Exception:
            pass

    async def _record_test_hit(self, test_id: str) -> None:
        """Record a hit on a phishing test entry"""
        try:
            pool = await self._get_pool()
            async with pool.tenant_acquire() as conn:
                await conn.execute("""
                    UPDATE phishing_test_list
                    SET hit_count = hit_count + 1,
                        last_hit_at = NOW()
                    WHERE id = $1
                """, test_id)
        except Exception:
            pass

    # ==================== CRUD Operations ====================

    async def add_trusted_sender(
        self,
        domain: str,
        sender_pattern: Optional[str] = None,
        trust_level: str = "trusted",
        organization: Optional[str] = None,
        category: Optional[str] = None,
        reason: Optional[str] = None,
        requires_whois: bool = False,
        min_domain_age_days: int = 365,
        added_by: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a trusted sender domain"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            # tenant_id must be in the INSERT — RLS WITH CHECK rejects rows
            # whose tenant_id doesn't match the connection's current setting,
            # so omitting this column was silently turning every POST into 500.
            row = await conn.fetchrow("""
                INSERT INTO trusted_senders
                    (domain, sender_pattern, trust_level, organization, category,
                     reason, requires_whois_match, min_domain_age_days, added_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid)
                ON CONFLICT (domain, sender_pattern) DO UPDATE SET
                    trust_level = EXCLUDED.trust_level,
                    organization = EXCLUDED.organization,
                    category = EXCLUDED.category,
                    reason = EXCLUDED.reason,
                    requires_whois_match = EXCLUDED.requires_whois_match,
                    min_domain_age_days = EXCLUDED.min_domain_age_days,
                    is_active = true,
                    updated_at = NOW()
                RETURNING id, created_at
            """, domain.lower(), sender_pattern, trust_level, organization,
                category, reason, requires_whois, min_domain_age_days, added_by, tenant_id)

        self._cache_loaded = False

        return {
            "id": str(row['id']),
            "domain": domain.lower(),
            "sender_pattern": sender_pattern,
            "trust_level": trust_level,
            "organization": organization,
            "category": category,
            "created_at": row['created_at'].isoformat() if row['created_at'] else None
        }

    async def add_phishing_test(
        self,
        sender_pattern: str,
        subject_pattern: str,
        match_type: str = "contains",
        test_name: Optional[str] = None,
        vendor: Optional[str] = None,
        auto_close: bool = True,
        skip_enrichment: bool = True,
        disposition: str = "BENIGN_POSITIVE",
        valid_until: Optional[datetime] = None,
        added_by: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a phishing test pattern"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO phishing_test_list
                    (sender_pattern, subject_pattern, match_type, test_name, vendor,
                     auto_close, skip_enrichment, disposition, valid_until, added_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid)
                RETURNING id, created_at
            """, sender_pattern, subject_pattern, match_type, test_name, vendor,
                auto_close, skip_enrichment, disposition, valid_until, added_by, tenant_id)

        self._cache_loaded = False

        return {
            "id": str(row['id']),
            "sender_pattern": sender_pattern,
            "subject_pattern": subject_pattern,
            "test_name": test_name,
            "created_at": row['created_at'].isoformat() if row['created_at'] else None
        }

    async def list_trusted_senders(
        self,
        include_inactive: bool = False,
        tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all trusted senders"""
        pool = await self._get_pool()

        params = []
        where_clauses = []

        if not include_inactive:
            where_clauses.append("is_active = true")

        if tenant_id:
            where_clauses.append(f"tenant_id = ${len(params) + 1}")
            params.append(tenant_id)

        where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        query = f"""
            SELECT id, domain, sender_pattern, trust_level, organization, category,
                   reason, requires_whois_match, min_domain_age_days, added_by,
                   is_active, hit_count, last_hit_at, created_at
            FROM trusted_senders
            {where_sql}
        """
        query += " ORDER BY hit_count DESC, domain"

        async with pool.tenant_acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            {
                "id": str(row['id']),
                "domain": row['domain'],
                "sender_pattern": row['sender_pattern'],
                "trust_level": row['trust_level'],
                "organization": row['organization'],
                "category": row['category'],
                "reason": row['reason'],
                "requires_whois_match": row['requires_whois_match'],
                "min_domain_age_days": row['min_domain_age_days'],
                "added_by": row['added_by'],
                "is_active": row['is_active'],
                "hit_count": row['hit_count'] or 0,
                "last_hit_at": row['last_hit_at'].isoformat() if row['last_hit_at'] else None,
                "created_at": row['created_at'].isoformat() if row['created_at'] else None
            }
            for row in rows
        ]

    async def list_phishing_tests(
        self,
        include_inactive: bool = False,
        tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all phishing test patterns"""
        pool = await self._get_pool()

        query = """
            SELECT id, sender_pattern, subject_pattern, match_type, test_name, vendor,
                   auto_close, skip_enrichment, disposition, valid_from, valid_until,
                   added_by, is_active, hit_count, last_hit_at, created_at
            FROM phishing_test_list
        """
        if not include_inactive:
            query += " WHERE is_active = true"
        query += " ORDER BY created_at DESC"

        async with pool.tenant_acquire() as conn:
            rows = await conn.fetch(query)

        return [
            {
                "id": str(row['id']),
                "sender_pattern": row['sender_pattern'],
                "subject_pattern": row['subject_pattern'],
                "match_type": row['match_type'],
                "test_name": row['test_name'],
                "vendor": row['vendor'],
                "auto_close": row['auto_close'],
                "skip_enrichment": row['skip_enrichment'],
                "disposition": row['disposition'],
                "valid_from": row['valid_from'].isoformat() if row['valid_from'] else None,
                "valid_until": row['valid_until'].isoformat() if row['valid_until'] else None,
                "added_by": row['added_by'],
                "is_active": row['is_active'],
                "hit_count": row['hit_count'] or 0,
                "last_hit_at": row['last_hit_at'].isoformat() if row['last_hit_at'] else None,
                "created_at": row['created_at'].isoformat() if row['created_at'] else None
            }
            for row in rows
        ]

    async def remove_trusted_sender(self, entry_id: str, tenant_id: Optional[str] = None) -> bool:
        """Deactivate a trusted sender entry"""
        pool = await self._get_pool()

        query = "UPDATE trusted_senders SET is_active = false, updated_at = NOW() WHERE id = $1"
        params = [entry_id]
        if tenant_id:
            query += " AND tenant_id = $2"
            params.append(tenant_id)

        async with pool.tenant_acquire() as conn:
            result = await conn.execute(query, *params)

        self._cache_loaded = False
        return "UPDATE 1" in result

    async def remove_phishing_test(self, test_id: str) -> bool:
        """Deactivate a phishing test entry"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            result = await conn.execute("""
                UPDATE phishing_test_list
                SET is_active = false, updated_at = NOW()
                WHERE id = $1
            """, test_id)

        self._cache_loaded = False
        return "UPDATE 1" in result

    async def check_domain_in_threat_feeds(self, domain: str) -> Dict[str, Any]:
        """
        Check if a domain exists in the IOC threat center as malicious.

        This queries the iocs table for domains that have been flagged by threat feeds
        as malicious or suspicious. This provides an additional layer of verification
        beyond pattern-based lookalike detection.

        Added: 2026-01-21 to improve email classification accuracy

        Args:
            domain: Domain to check (e.g., "malicious-domain.com")

        Returns:
            Dict with:
            - is_malicious: bool - True if domain found with malicious reputation
            - is_suspicious: bool - True if domain found with suspicious reputation
            - ioc_data: dict - Full IOC record if found
            - feed_name: str - Name of threat feed that flagged it
            - confidence: float - Confidence score from threat feed
        """
        if not domain:
            return {'is_malicious': False, 'is_suspicious': False}

        domain_lower = domain.lower().strip()

        try:
            pool = await self._get_pool()

            async with pool.tenant_acquire() as conn:
                # Check for exact domain match in IOCs
                row = await conn.fetchrow("""
                    SELECT id, ioc_value, ioc_type, reputation, confidence,
                           severity, feed_name, source_type, enrichment_data,
                           last_seen, occurrences
                    FROM iocs
                    WHERE ioc_value = $1
                    AND ioc_type = 'domain'
                    AND reputation IN ('malicious', 'suspicious')
                    ORDER BY last_seen DESC
                    LIMIT 1
                """, domain_lower)

                if row:
                    reputation = row['reputation']
                    logger.info(f"[THREAT_FEED] Domain '{domain}' found in IOC database with reputation: {reputation}")

                    return {
                        'is_malicious': reputation == 'malicious',
                        'is_suspicious': reputation == 'suspicious',
                        'ioc_data': {
                            'id': str(row['id']),
                            'ioc_value': row['ioc_value'],
                            'reputation': reputation,
                            'severity': row['severity'],
                            'confidence': float(row['confidence']) if row['confidence'] else 0.0,
                            'feed_name': row['feed_name'],
                            'source_type': row['source_type'],
                            'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
                            'occurrences': row['occurrences']
                        },
                        'feed_name': row['feed_name'] or row['source_type'] or 'unknown',
                        'confidence': float(row['confidence']) if row['confidence'] else 0.85,
                        'reason': f"Domain found in threat feed: {row['feed_name'] or 'IOC database'}"
                    }

                # Also check for subdomains - if parent domain is malicious
                parts = domain_lower.split('.')
                if len(parts) > 2:
                    # Check parent domain (e.g., sub.malicious.com -> malicious.com)
                    parent_domain = '.'.join(parts[-2:])
                    parent_row = await conn.fetchrow("""
                        SELECT id, ioc_value, reputation, feed_name, confidence
                        FROM iocs
                        WHERE ioc_value = $1
                        AND ioc_type = 'domain'
                        AND reputation = 'malicious'
                        LIMIT 1
                    """, parent_domain)

                    if parent_row:
                        logger.info(f"[THREAT_FEED] Parent domain '{parent_domain}' of '{domain}' is malicious")
                        return {
                            'is_malicious': True,
                            'is_suspicious': False,
                            'ioc_data': {
                                'id': str(parent_row['id']),
                                'ioc_value': parent_row['ioc_value'],
                                'reputation': 'malicious',
                                'matched_via': 'parent_domain'
                            },
                            'feed_name': parent_row['feed_name'] or 'IOC database',
                            'confidence': float(parent_row['confidence']) if parent_row['confidence'] else 0.80,
                            'reason': f"Parent domain {parent_domain} is flagged as malicious"
                        }

            return {'is_malicious': False, 'is_suspicious': False}

        except Exception as e:
            logger.error(f"[THREAT_FEED] Error checking domain in threat feeds: {e}")
            return {'is_malicious': False, 'is_suspicious': False, 'error': str(e)}


# Singleton instance
_sender_trust_service: Optional[SenderTrustService] = None


def get_sender_trust_service() -> SenderTrustService:
    """Get the global sender trust service instance"""
    global _sender_trust_service
    if _sender_trust_service is None:
        _sender_trust_service = SenderTrustService()
    return _sender_trust_service
