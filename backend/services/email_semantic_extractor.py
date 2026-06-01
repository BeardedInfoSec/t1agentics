# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Email Semantic Extractor Service

Extracts semantic security information from email headers BEFORE truncation.

═══════════════════════════════════════════════════════════════════════════════
DIRECTIVE §6 COMPLIANCE: EMAIL HANDLING - STRUCTURE OVER TRUNCATION
═══════════════════════════════════════════════════════════════════════════════

Per directive:
- Blind truncation of email data is PROHIBITED
- Full headers and body are preserved in storage
- T1 receives SEMANTIC EXTRACTION, not chopped text
- Truncation may ONLY occur AFTER semantic extraction, never before

Required email analysis fields:
- SPF / DKIM / DMARC outcomes
- ARC chain validity
- Sender vs return-path vs from-domain alignment
- Routing hop count
- Brand impersonation indicators
- Link and form extraction
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class EmailSemanticExtractor:
    """
    Extract semantic security information from email headers and body.

    This service ensures security-critical information is extracted
    BEFORE any truncation occurs, preserving the analytical value.
    """

    # Known brand domains for impersonation detection
    BRAND_DOMAINS = {
        'microsoft.com', 'office.com', 'outlook.com', 'live.com', 'azure.com',
        'google.com', 'gmail.com', 'accounts.google.com',
        'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com',
        'paypal.com', 'facebook.com', 'meta.com', 'instagram.com',
        'linkedin.com', 'twitter.com', 'dropbox.com', 'netflix.com',
        'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citi.com',
        'fedex.com', 'ups.com', 'usps.com', 'dhl.com'
    }

    # Common typosquatting patterns
    TYPOSQUAT_PATTERNS = [
        (r'micro.?soft', 'microsoft'),
        (r'm1crosoft', 'microsoft'),
        (r'micros0ft', 'microsoft'),
        (r'go+gle', 'google'),
        (r'goog1e', 'google'),
        (r'amaz[o0]n', 'amazon'),
        (r'pay.?pal', 'paypal'),
        (r'app1e', 'apple'),
        (r'faceb[o0][o0]k', 'facebook'),
    ]

    def extract_semantics(
        self,
        headers: Dict[str, Any],
        body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract all semantic security information from email.

        Args:
            headers: Email headers dictionary
            body: Email body text (optional)

        Returns:
            Semantic extraction with all security-relevant fields
        """
        semantics = {
            # Authentication results (Directive §6 required fields)
            'spf_result': self._parse_spf(headers),
            'dkim_result': self._parse_dkim(headers),
            'dmarc_result': self._parse_dmarc(headers),
            'arc_valid': self._validate_arc_chain(headers),

            # Sender analysis
            'sender_alignment': self._check_sender_alignment(headers),
            'return_path_match': self._check_return_path(headers),
            'from_domain': self._extract_from_domain(headers),

            # Routing analysis
            'hop_count': self._count_received_headers(headers),
            'routing_path': self._extract_routing_path(headers),
            'originating_ip': self._extract_originating_ip(headers),

            # Brand impersonation indicators
            'brand_indicators': self._detect_brand_impersonation(headers, body),

            # Content extraction
            'links': self._extract_links(body) if body else [],
            'forms': self._extract_forms(body) if body else [],
            'urgency_indicators': self._detect_urgency(headers, body),

            # Spam/threat scoring
            'spam_score': self._extract_spam_score(headers),
            'threat_headers': self._extract_threat_headers(headers),

            # Metadata
            'extraction_complete': True,
            'headers_processed': len(headers) if headers else 0,
            'body_processed': len(body) if body else 0
        }

        return semantics

    def _parse_spf(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Parse SPF authentication result."""
        spf_result = {
            'result': 'unknown',
            'domain': None,
            'ip': None,
            'raw': None
        }

        # Check Received-SPF header first
        received_spf = headers.get('Received-SPF', headers.get('received-spf', ''))
        if received_spf:
            spf_result['raw'] = str(received_spf)[:500]

            # Parse result
            result_match = re.search(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', str(received_spf).lower())
            if result_match:
                spf_result['result'] = result_match.group(1)

            # Extract domain
            domain_match = re.search(r'envelope-from=([^\s;]+)', str(received_spf), re.IGNORECASE)
            if domain_match:
                spf_result['domain'] = domain_match.group(1)

            # Extract IP
            ip_match = re.search(r'client-ip=([^\s;]+)', str(received_spf), re.IGNORECASE)
            if ip_match:
                spf_result['ip'] = ip_match.group(1)

        # Also check Authentication-Results for SPF
        auth_results = headers.get('Authentication-Results', headers.get('authentication-results', ''))
        if auth_results and spf_result['result'] == 'unknown':
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none)', str(auth_results).lower())
            if spf_match:
                spf_result['result'] = spf_match.group(1)

        return spf_result

    def _parse_dkim(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Parse DKIM authentication result."""
        dkim_result = {
            'result': 'unknown',
            'domain': None,
            'selector': None,
            'signature_present': False
        }

        # Check DKIM-Signature header
        dkim_sig = headers.get('DKIM-Signature', headers.get('dkim-signature', ''))
        if dkim_sig:
            dkim_result['signature_present'] = True

            # Extract domain
            domain_match = re.search(r'd=([^\s;]+)', str(dkim_sig))
            if domain_match:
                dkim_result['domain'] = domain_match.group(1)

            # Extract selector
            selector_match = re.search(r's=([^\s;]+)', str(dkim_sig))
            if selector_match:
                dkim_result['selector'] = selector_match.group(1)

        # Check Authentication-Results for DKIM result
        auth_results = headers.get('Authentication-Results', headers.get('authentication-results', ''))
        if auth_results:
            dkim_match = re.search(r'dkim=(pass|fail|neutral|none)', str(auth_results).lower())
            if dkim_match:
                dkim_result['result'] = dkim_match.group(1)

        return dkim_result

    def _parse_dmarc(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Parse DMARC authentication result."""
        dmarc_result = {
            'result': 'unknown',
            'policy': None,
            'action': None
        }

        auth_results = headers.get('Authentication-Results', headers.get('authentication-results', ''))
        if auth_results:
            # Parse DMARC result
            dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass)', str(auth_results).lower())
            if dmarc_match:
                dmarc_result['result'] = dmarc_match.group(1)

            # Parse policy
            policy_match = re.search(r'p=(none|quarantine|reject)', str(auth_results).lower())
            if policy_match:
                dmarc_result['policy'] = policy_match.group(1)

            # Parse action taken
            action_match = re.search(r'action=(none|quarantine|reject)', str(auth_results).lower())
            if action_match:
                dmarc_result['action'] = action_match.group(1)

        return dmarc_result

    def _validate_arc_chain(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Validate ARC (Authenticated Received Chain) headers."""
        arc_result = {
            'valid': None,
            'chain_length': 0,
            'seals': [],
            'results': []
        }

        # Count ARC headers
        arc_seal_count = 0
        arc_auth_count = 0

        for key in headers:
            key_lower = key.lower()
            if key_lower.startswith('arc-seal'):
                arc_seal_count += 1
            elif key_lower.startswith('arc-authentication-results'):
                arc_auth_count += 1
                # Parse ARC result
                value = str(headers[key])
                result_match = re.search(r'arc=(pass|fail|none)', value.lower())
                if result_match:
                    arc_result['results'].append(result_match.group(1))

        arc_result['chain_length'] = arc_seal_count

        # Check ARC validation result in Authentication-Results
        auth_results = headers.get('Authentication-Results', headers.get('authentication-results', ''))
        if auth_results:
            arc_match = re.search(r'arc=(pass|fail|none)', str(auth_results).lower())
            if arc_match:
                arc_result['valid'] = arc_match.group(1) == 'pass'

        return arc_result

    def _check_sender_alignment(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Check alignment between From, Sender, Return-Path, and Reply-To."""
        alignment = {
            'aligned': None,
            'from_domain': None,
            'return_path_domain': None,
            'reply_to_domain': None,
            'envelope_from_domain': None,
            'mismatches': []
        }

        # Extract From domain
        from_header = headers.get('From', headers.get('from', ''))
        from_domain = self._extract_domain_from_address(str(from_header))
        alignment['from_domain'] = from_domain

        # Extract Return-Path domain
        return_path = headers.get('Return-Path', headers.get('return-path', ''))
        return_path_domain = self._extract_domain_from_address(str(return_path))
        alignment['return_path_domain'] = return_path_domain

        # Extract Reply-To domain
        reply_to = headers.get('Reply-To', headers.get('reply-to', ''))
        reply_to_domain = self._extract_domain_from_address(str(reply_to))
        alignment['reply_to_domain'] = reply_to_domain

        # Check for mismatches
        if from_domain and return_path_domain and from_domain != return_path_domain:
            alignment['mismatches'].append(f"From/Return-Path mismatch: {from_domain} vs {return_path_domain}")

        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            alignment['mismatches'].append(f"From/Reply-To mismatch: {from_domain} vs {reply_to_domain}")

        alignment['aligned'] = len(alignment['mismatches']) == 0

        return alignment

    def _check_return_path(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Check Return-Path header for anomalies."""
        return_path = headers.get('Return-Path', headers.get('return-path', ''))
        result = {
            'present': bool(return_path),
            'address': None,
            'domain': None,
            'null_sender': False
        }

        if return_path:
            address = str(return_path).strip('<>')
            result['address'] = address
            result['domain'] = self._extract_domain_from_address(address)
            result['null_sender'] = address == '' or address == '<>'

        return result

    def _extract_from_domain(self, headers: Dict[str, Any]) -> Optional[str]:
        """Extract the domain from the From header."""
        from_header = headers.get('From', headers.get('from', ''))
        return self._extract_domain_from_address(str(from_header))

    def _extract_domain_from_address(self, address: str) -> Optional[str]:
        """Extract domain from an email address string."""
        if not address:
            return None

        # Handle "Name <email@domain.com>" format
        match = re.search(r'<([^>]+)>', address)
        if match:
            address = match.group(1)

        # Extract domain
        if '@' in address:
            return address.split('@')[-1].lower().strip()

        return None

    def _count_received_headers(self, headers: Dict[str, Any]) -> int:
        """Count the number of Received headers (routing hops)."""
        count = 0
        for key in headers:
            if key.lower() == 'received':
                if isinstance(headers[key], list):
                    count += len(headers[key])
                else:
                    count += 1
        return count

    def _extract_routing_path(self, headers: Dict[str, Any]) -> List[str]:
        """Extract the email routing path from Received headers."""
        path = []
        received = headers.get('Received', headers.get('received', []))

        if isinstance(received, str):
            received = [received]

        for hop in received[:10]:  # Limit to 10 hops
            # Extract "from" server
            from_match = re.search(r'from\s+([^\s\(]+)', str(hop))
            if from_match:
                path.append(from_match.group(1)[:100])

        return path

    def _extract_originating_ip(self, headers: Dict[str, Any]) -> Optional[str]:
        """Extract the originating IP address."""
        # Check X-Originating-IP header
        orig_ip = headers.get('X-Originating-IP', headers.get('x-originating-ip', ''))
        if orig_ip:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(orig_ip))
            if ip_match:
                return ip_match.group(1)

        # Check X-Sender-IP
        sender_ip = headers.get('X-Sender-IP', headers.get('x-sender-ip', ''))
        if sender_ip:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(sender_ip))
            if ip_match:
                return ip_match.group(1)

        return None

    def _detect_brand_impersonation(
        self,
        headers: Dict[str, Any],
        body: Optional[str]
    ) -> Dict[str, Any]:
        """Detect potential brand impersonation indicators."""
        indicators = {
            'detected': False,
            'impersonated_brand': None,
            'indicators': [],
            'typosquatting': []
        }

        # Get From domain
        from_domain = self._extract_from_domain(headers)

        # Check for typosquatting in From domain
        if from_domain:
            for pattern, brand in self.TYPOSQUAT_PATTERNS:
                if re.search(pattern, from_domain, re.IGNORECASE):
                    indicators['typosquatting'].append({
                        'domain': from_domain,
                        'impersonates': brand
                    })
                    indicators['detected'] = True
                    indicators['impersonated_brand'] = brand

        # Check subject line for brand mentions
        subject = headers.get('Subject', headers.get('subject', ''))
        for brand in ['Microsoft', 'Google', 'Apple', 'Amazon', 'PayPal', 'Netflix', 'Facebook']:
            if brand.lower() in str(subject).lower():
                # Check if From domain doesn't match the brand
                brand_domain = f"{brand.lower()}.com"
                if from_domain and brand_domain not in from_domain:
                    indicators['indicators'].append(f"Subject mentions {brand} but sender is {from_domain}")
                    indicators['detected'] = True
                    indicators['impersonated_brand'] = brand

        # Check body for login forms mentioning brands
        if body:
            for brand in ['Microsoft', 'Google', 'Apple', 'Amazon', 'PayPal']:
                if brand.lower() in body.lower() and ('password' in body.lower() or 'login' in body.lower()):
                    indicators['indicators'].append(f"Body mentions {brand} with login/password context")

        return indicators

    def _extract_links(self, body: Optional[str]) -> List[Dict[str, Any]]:
        """Extract all links from email body."""
        if not body:
            return []

        links = []
        # Find all URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s<>"\']*'

        for match in re.finditer(url_pattern, body):
            url = match.group()
            try:
                parsed = urlparse(url if url.startswith('http') else f'http://{url}')
                links.append({
                    'url': url[:500],  # Truncate very long URLs
                    'domain': parsed.netloc,
                    'path': parsed.path[:200],
                    'is_shortened': self._is_url_shortener(parsed.netloc)
                })
            except Exception:
                links.append({'url': url[:500], 'domain': None, 'path': None, 'is_shortened': False})

        return links[:20]  # Limit to 20 links

    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a known URL shortener."""
        shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'rb.gy',
            'short.io', 'cutt.ly', 'tiny.cc'
        }
        return domain.lower() in shorteners

    def _extract_forms(self, body: Optional[str]) -> List[Dict[str, Any]]:
        """Extract form elements from email body (HTML)."""
        if not body:
            return []

        forms = []

        # Find form tags
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>'
        for match in re.finditer(form_pattern, body, re.IGNORECASE):
            action_url = match.group(1)
            forms.append({
                'action': action_url[:500],
                'type': 'form'
            })

        # Find input fields (especially password)
        password_inputs = re.findall(r'<input[^>]*type=["\']?password["\']?[^>]*>', body, re.IGNORECASE)
        if password_inputs:
            forms.append({
                'type': 'password_input',
                'count': len(password_inputs)
            })

        return forms[:10]

    def _detect_urgency(
        self,
        headers: Dict[str, Any],
        body: Optional[str]
    ) -> Dict[str, Any]:
        """Detect urgency/pressure tactics in email."""
        urgency = {
            'detected': False,
            'indicators': [],
            'score': 0
        }

        # Urgency keywords
        urgency_keywords = [
            'urgent', 'immediately', 'action required', 'verify now',
            'account suspended', 'unauthorized', 'limited time',
            'expires today', 'within 24 hours', 'act now', 'confirm now',
            'your account will be', 'security alert', 'unusual activity'
        ]

        # Check subject
        subject = str(headers.get('Subject', headers.get('subject', ''))).lower()
        for keyword in urgency_keywords:
            if keyword in subject:
                urgency['indicators'].append(f"Subject contains: '{keyword}'")
                urgency['score'] += 1

        # Check body
        if body:
            body_lower = body.lower()
            for keyword in urgency_keywords:
                if keyword in body_lower:
                    urgency['indicators'].append(f"Body contains: '{keyword}'")
                    urgency['score'] += 1

        urgency['detected'] = urgency['score'] >= 2
        return urgency

    def _extract_spam_score(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Extract spam scoring from headers."""
        spam_info = {
            'score': None,
            'status': None,
            'tests': []
        }

        # SpamAssassin
        spam_status = headers.get('X-Spam-Status', headers.get('x-spam-status', ''))
        if spam_status:
            spam_info['status'] = str(spam_status)[:200]
            score_match = re.search(r'score=([\d.-]+)', str(spam_status))
            if score_match:
                try:
                    spam_info['score'] = float(score_match.group(1))
                except ValueError:
                    pass

            # Extract tests
            tests_match = re.search(r'tests=\[?([^\]]+)\]?', str(spam_status))
            if tests_match:
                tests = tests_match.group(1).split(',')
                spam_info['tests'] = [t.strip()[:50] for t in tests[:10]]

        # Microsoft SCL
        scl = headers.get('X-MS-Exchange-Organization-SCL', headers.get('x-ms-exchange-organization-scl', ''))
        if scl:
            try:
                spam_info['microsoft_scl'] = int(scl)
            except ValueError:
                pass

        return spam_info

    def _extract_threat_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat-related headers from various email security gateways."""
        threat_info = {
            'verdict': None,
            'category': None,
            'details': []
        }

        # Microsoft threat headers
        ms_threat = headers.get('X-MS-Exchange-Organization-AuthAs', '')
        if ms_threat:
            threat_info['details'].append(f"MS-AuthAs: {ms_threat}")

        # Proofpoint
        pp_threat = headers.get('X-Proofpoint-Spam-Details', '')
        if pp_threat:
            threat_info['details'].append(f"Proofpoint: {str(pp_threat)[:200]}")

        # Mimecast
        mc_threat = headers.get('X-Mimecast-Spam-Score', '')
        if mc_threat:
            threat_info['details'].append(f"Mimecast-Score: {mc_threat}")

        # Barracuda
        bc_threat = headers.get('X-Barracuda-Spam-Status', '')
        if bc_threat:
            threat_info['details'].append(f"Barracuda: {bc_threat}")

        return threat_info


# Singleton instance
_email_extractor = EmailSemanticExtractor()


def get_email_semantic_extractor() -> EmailSemanticExtractor:
    """Get the email semantic extractor instance."""
    return _email_extractor


def extract_email_semantics(
    headers: Dict[str, Any],
    body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to extract email semantics.

    Args:
        headers: Email headers dictionary
        body: Email body text (optional)

    Returns:
        Semantic extraction with all security-relevant fields
    """
    return _email_extractor.extract_semantics(headers, body)
