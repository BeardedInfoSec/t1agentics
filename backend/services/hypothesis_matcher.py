# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Hypothesis Matcher Service

Evaluates whether an alert supports an investigation's hypothesis.
Part of the hypothesis-driven correlation system.

The matcher determines:
1. Whether an alert SUPPORTS, is COMPATIBLE with, CONTRADICTS, or is UNRELATED to a hypothesis
2. The relationship type (ROOT_CAUSE, SUPPORTING, CONSEQUENCE, CONTEXT_ONLY)
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set, Tuple
from uuid import UUID

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class HypothesisMatchResult:
    """Result of hypothesis evaluation."""
    support_type: str  # SUPPORTS, COMPATIBLE, CONTRADICTS, UNRELATED
    confidence: float  # 0.0 - 1.0
    relationship_type: str  # ROOT_CAUSE, SUPPORTING, CONSEQUENCE, CONTEXT_ONLY
    reason: str  # Human-readable explanation


# ============================================================================
# Hypothesis Category Definitions
# ============================================================================

# MITRE techniques commonly associated with each hypothesis category
HYPOTHESIS_MITRE_MAP = {
    'MALWARE_INFECTION': {
        'tactics': ['TA0002', 'TA0003', 'TA0005', 'TA0011'],  # Execution, Persistence, Defense Evasion, C2
        'techniques': [
            'T1059', 'T1204', 'T1053', 'T1547',  # Execution
            'T1055', 'T1027', 'T1562',  # Evasion
            'T1071', 'T1095', 'T1105',  # C2
        ],
        'keywords': ['malware', 'dropper', 'payload', 'infection', 'trojan', 'ransomware', 'worm', 'backdoor'],
    },
    'CREDENTIAL_THEFT': {
        'tactics': ['TA0006', 'TA0008'],  # Credential Access, Lateral Movement
        'techniques': [
            'T1003', 'T1555', 'T1552', 'T1110', 'T1557',  # Credential Access
            'T1021', 'T1550', 'T1563',  # Lateral Movement
        ],
        'keywords': ['mimikatz', 'credential', 'password', 'hash', 'ntlm', 'kerberos', 'ticket', 'lsass', 'sam'],
    },
    'DATA_EXFIL': {
        'tactics': ['TA0010', 'TA0009'],  # Exfiltration, Collection
        'techniques': [
            'T1041', 'T1048', 'T1567', 'T1020',  # Exfiltration
            'T1005', 'T1039', 'T1560', 'T1119',  # Collection
        ],
        'keywords': ['exfil', 'upload', 'cloud storage', 'mega', 'dropbox', 'archive', 'compress', 'staging'],
    },
    'LATERAL_MOVEMENT': {
        'tactics': ['TA0008'],  # Lateral Movement
        'techniques': [
            'T1021', 'T1550', 'T1563', 'T1570', 'T1210',
        ],
        'keywords': ['rdp', 'psexec', 'wmi', 'smb', 'lateral', 'pivot', 'remote', 'spread'],
    },
    'PERSISTENCE': {
        'tactics': ['TA0003'],  # Persistence
        'techniques': [
            'T1547', 'T1053', 'T1136', 'T1078', 'T1543', 'T1546',
        ],
        'keywords': ['persistence', 'scheduled task', 'registry', 'startup', 'service', 'autorun', 'cron'],
    },
    'PHISHING_CAMPAIGN': {
        'tactics': ['TA0001'],  # Initial Access
        'techniques': [
            'T1566', 'T1598',
        ],
        'keywords': ['phishing', 'spearphishing', 'email', 'attachment', 'link', 'credential harvest', 'impersonation'],
    },
    'C2_COMMUNICATION': {
        'tactics': ['TA0011'],  # Command and Control
        'techniques': [
            'T1071', 'T1095', 'T1573', 'T1090', 'T1102', 'T1105',
        ],
        'keywords': ['c2', 'c&c', 'beacon', 'callback', 'command control', 'covert channel'],
    },
    'RECONNAISSANCE': {
        'tactics': ['TA0007', 'TA0043'],  # Discovery, Reconnaissance
        'techniques': [
            'T1087', 'T1082', 'T1083', 'T1135', 'T1046', 'T1018',
        ],
        'keywords': ['recon', 'discovery', 'scan', 'enumerate', 'probe', 'fingerprint'],
    },
    'INSIDER_THREAT': {
        'tactics': ['TA0010', 'TA0009'],  # Exfiltration, Collection
        'techniques': [
            'T1074', 'T1005', 'T1039', 'T1567',
        ],
        'keywords': ['insider', 'authorized', 'employee', 'internal', 'legitimate access', 'policy violation'],
    },
    'POLICY_VIOLATION': {
        'tactics': [],
        'techniques': [],
        'keywords': ['policy', 'compliance', 'unauthorized', 'violation', 'prohibited', 'restricted'],
    },
}


# ============================================================================
# Hypothesis Matcher Service
# ============================================================================

class HypothesisMatcher:
    """
    Evaluates whether an alert supports an investigation's hypothesis.

    The matcher uses multiple signals:
    1. MITRE technique alignment
    2. Keyword matching in alert content
    3. IOC verdict alignment (malicious IOCs should support malware hypotheses)
    4. Temporal/causal relationships
    """

    def evaluate_hypothesis_support(
        self,
        alert: Dict[str, Any],
        hypothesis: str,
        hypothesis_category: Optional[str] = None
    ) -> HypothesisMatchResult:
        """
        Evaluate how well an alert supports an investigation's hypothesis.

        Args:
            alert: Alert data dictionary
            hypothesis: The investigation's hypothesis text
            hypothesis_category: Optional category (MALWARE_INFECTION, etc.)

        Returns:
            HypothesisMatchResult with support type and relationship
        """
        try:
            # Extract alert signals
            alert_mitre = self._extract_mitre(alert)
            alert_keywords = self._extract_keywords(alert)
            alert_iocs = self._extract_iocs_with_verdicts(alert)
            alert_title = (alert.get('title') or '').lower()
            alert_category = (alert.get('category') or '').lower()

            # Calculate support scores
            mitre_score = 0.0
            keyword_score = 0.0
            ioc_score = 0.0
            reasons = []

            # 1. MITRE alignment
            if hypothesis_category and hypothesis_category in HYPOTHESIS_MITRE_MAP:
                hyp_config = HYPOTHESIS_MITRE_MAP[hypothesis_category]
                mitre_score, mitre_reason = self._score_mitre_alignment(
                    alert_mitre, hyp_config
                )
                if mitre_reason:
                    reasons.append(mitre_reason)

            # 2. Keyword matching
            if hypothesis_category and hypothesis_category in HYPOTHESIS_MITRE_MAP:
                hyp_config = HYPOTHESIS_MITRE_MAP[hypothesis_category]
                keyword_score, keyword_reason = self._score_keyword_match(
                    alert_title + ' ' + ' '.join(alert_keywords),
                    hyp_config.get('keywords', [])
                )
                if keyword_reason:
                    reasons.append(keyword_reason)

            # 3. Also check hypothesis text directly
            if hypothesis:
                direct_match = self._check_direct_hypothesis_match(
                    alert, hypothesis
                )
                if direct_match > 0:
                    keyword_score = max(keyword_score, direct_match)
                    reasons.append("Alert content aligns with hypothesis text")

            # 4. IOC verdict alignment (malicious IOCs support malware hypotheses)
            if hypothesis_category in ['MALWARE_INFECTION', 'C2_COMMUNICATION']:
                ioc_score, ioc_reason = self._score_ioc_alignment(alert_iocs)
                if ioc_reason:
                    reasons.append(ioc_reason)

            # Calculate combined score
            combined_score = max(mitre_score, keyword_score, ioc_score)

            # Determine support type
            support_type = self._determine_support_type(
                combined_score, alert, hypothesis_category
            )

            # Determine relationship type
            relationship_type = self._determine_relationship_type(
                alert, hypothesis_category, alert_mitre, combined_score
            )

            reason_text = '; '.join(reasons) if reasons else 'No strong signals detected'

            return HypothesisMatchResult(
                support_type=support_type,
                confidence=combined_score,
                relationship_type=relationship_type,
                reason=reason_text
            )

        except Exception as e:
            logger.error(f"Hypothesis matching failed: {e}")
            return HypothesisMatchResult(
                support_type='COMPATIBLE',  # Default to compatible on error
                confidence=0.3,
                relationship_type='CONTEXT_ONLY',
                reason=f"Evaluation error: {str(e)}"
            )

    def _extract_mitre(self, alert: Dict[str, Any]) -> Set[str]:
        """Extract MITRE techniques from alert."""
        techniques = set()

        # Check raw_event._extracted.mitre
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            extracted = raw_event.get('_extracted', {})
            if extracted:
                mitre = extracted.get('mitre', {})
                if isinstance(mitre, dict):
                    techniques.update(mitre.get('techniques', []))
                    techniques.update(mitre.get('tactics', []))

        # Check direct fields
        if alert.get('mitre_techniques'):
            techniques.update(alert['mitre_techniques'])
        if alert.get('mitre_tactics'):
            techniques.update(alert['mitre_tactics'])

        return techniques

    def _extract_keywords(self, alert: Dict[str, Any]) -> List[str]:
        """Extract relevant keywords from alert content."""
        keywords = []

        title = alert.get('title', '')
        description = alert.get('description', '')
        category = alert.get('category', '')

        # Combine and extract words
        text = f"{title} {description} {category}".lower()
        # Simple word extraction (could be enhanced with NLP)
        words = re.findall(r'\b\w+\b', text)
        keywords.extend(words)

        return keywords

    def _extract_iocs_with_verdicts(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs with their verdicts from alert."""
        iocs = []

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            extracted = raw_event.get('_extracted', {})
            if extracted:
                iocs_data = extracted.get('iocs', {})
                if isinstance(iocs_data, dict):
                    for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
                        for ioc in iocs_data.get(ioc_type, []):
                            if isinstance(ioc, dict):
                                iocs.append(ioc)
                            else:
                                iocs.append({'value': ioc, 'verdict': 'unknown'})

                # Also check enrichment results
                enrichment = extracted.get('enrichment_summary', {})
                if enrichment:
                    if enrichment.get('malicious', 0) > 0:
                        iocs.append({'verdict': 'MALICIOUS', 'synthetic': True})
                    if enrichment.get('suspicious', 0) > 0:
                        iocs.append({'verdict': 'SUSPICIOUS', 'synthetic': True})

        return iocs

    def _score_mitre_alignment(
        self,
        alert_mitre: Set[str],
        hyp_config: Dict[str, Any]
    ) -> Tuple[float, Optional[str]]:
        """Score MITRE technique alignment."""
        if not alert_mitre:
            return 0.0, None

        hyp_tactics = set(hyp_config.get('tactics', []))
        hyp_techniques = set(hyp_config.get('techniques', []))

        # Check for technique matches
        technique_matches = alert_mitre.intersection(hyp_techniques)
        tactic_matches = alert_mitre.intersection(hyp_tactics)

        if technique_matches:
            return 0.8, f"MITRE technique match: {', '.join(technique_matches)}"
        elif tactic_matches:
            return 0.5, f"MITRE tactic match: {', '.join(tactic_matches)}"

        return 0.0, None

    def _score_keyword_match(
        self,
        text: str,
        keywords: List[str]
    ) -> Tuple[float, Optional[str]]:
        """Score keyword matches in alert text."""
        text_lower = text.lower()
        matches = [kw for kw in keywords if kw.lower() in text_lower]

        if len(matches) >= 3:
            return 0.8, f"Strong keyword matches: {', '.join(matches[:5])}"
        elif len(matches) >= 1:
            return 0.5, f"Keyword matches: {', '.join(matches)}"

        return 0.0, None

    def _check_direct_hypothesis_match(
        self,
        alert: Dict[str, Any],
        hypothesis: str
    ) -> float:
        """Check if alert directly matches hypothesis text."""
        if not hypothesis:
            return 0.0

        hypothesis_lower = hypothesis.lower()
        alert_text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()

        # Extract key terms from hypothesis
        hyp_words = set(re.findall(r'\b\w{4,}\b', hypothesis_lower))
        alert_words = set(re.findall(r'\b\w{4,}\b', alert_text))

        overlap = hyp_words.intersection(alert_words)
        if len(overlap) >= 3:
            return 0.6
        elif len(overlap) >= 1:
            return 0.3

        return 0.0

    def _score_ioc_alignment(
        self,
        iocs: List[Dict[str, Any]]
    ) -> Tuple[float, Optional[str]]:
        """Score IOC verdicts - malicious IOCs support malware hypotheses."""
        malicious_count = sum(1 for ioc in iocs if ioc.get('verdict', '').upper() == 'MALICIOUS')
        suspicious_count = sum(1 for ioc in iocs if ioc.get('verdict', '').upper() == 'SUSPICIOUS')

        if malicious_count > 0:
            return 0.9, f"{malicious_count} malicious IOC(s) detected"
        elif suspicious_count > 0:
            return 0.5, f"{suspicious_count} suspicious IOC(s) detected"

        return 0.0, None

    def _determine_support_type(
        self,
        score: float,
        alert: Dict[str, Any],
        hypothesis_category: Optional[str]
    ) -> str:
        """Determine how the alert supports the hypothesis."""
        # Check for contradictions
        if self._check_contradiction(alert, hypothesis_category):
            return 'CONTRADICTS'

        # Score-based determination
        if score >= 0.7:
            return 'SUPPORTS'
        elif score >= 0.3:
            return 'COMPATIBLE'
        else:
            return 'UNRELATED'

    def _check_contradiction(
        self,
        alert: Dict[str, Any],
        hypothesis_category: Optional[str]
    ) -> bool:
        """Check if alert contradicts the hypothesis."""
        # Example: BENIGN verdict contradicts MALWARE_INFECTION hypothesis
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            extracted = raw_event.get('_extracted', {})
            if extracted:
                ai_triage = extracted.get('ai_triage', {})
                verdict = ai_triage.get('verdict', '').upper()

                # BENIGN verdict contradicts malware-related hypotheses
                if verdict == 'BENIGN':
                    if hypothesis_category in ['MALWARE_INFECTION', 'C2_COMMUNICATION', 'CREDENTIAL_THEFT']:
                        return True

        return False

    def _determine_relationship_type(
        self,
        alert: Dict[str, Any],
        hypothesis_category: Optional[str],
        alert_mitre: Set[str],
        score: float
    ) -> str:
        """Determine the relationship type within the investigation."""
        # Check for initial access (ROOT_CAUSE candidates)
        initial_access_techniques = {'T1566', 'T1190', 'T1189', 'T1195', 'T1199'}
        if alert_mitre.intersection(initial_access_techniques):
            return 'ROOT_CAUSE'

        # Check for consequences (post-exploitation)
        consequence_techniques = {'T1041', 'T1048', 'T1567', 'T1485', 'T1490', 'T1486'}
        if alert_mitre.intersection(consequence_techniques):
            return 'CONSEQUENCE'

        # Strong matches are SUPPORTING
        if score >= 0.6:
            return 'SUPPORTING'

        return 'CONTEXT_ONLY'

    async def evaluate_hypothesis_support_ai(
        self,
        alert: Dict[str, Any],
        hypothesis: str,
        hypothesis_category: Optional[str],
        tenant_id: str
    ) -> HypothesisMatchResult:
        """
        Use Claude to evaluate whether an alert supports an investigation's hypothesis.

        Falls back to keyword-based evaluation if Claude is unavailable or fails.

        Args:
            alert: Alert data dictionary
            hypothesis: The investigation's hypothesis text
            hypothesis_category: Optional category (MALWARE_INFECTION, etc.)
            tenant_id: Tenant ID for quota tracking

        Returns:
            HypothesisMatchResult with AI-powered assessment
        """
        try:
            from services.claude_service import get_claude_service

            claude = get_claude_service()
            if not claude.is_configured():
                return self.evaluate_hypothesis_support(alert, hypothesis, hypothesis_category)

            # Build concise prompt
            alert_summary = {
                'title': alert.get('title', ''),
                'severity': alert.get('severity', ''),
                'category': alert.get('category', ''),
                'source': alert.get('source', ''),
            }
            # Add MITRE if available
            mitre = list(self._extract_mitre(alert))
            if mitre:
                alert_summary['mitre_techniques'] = mitre[:5]

            prompt = f"""Evaluate if this alert supports the investigation hypothesis.

Alert: {json.dumps(alert_summary)}
Hypothesis: {hypothesis}
Category: {hypothesis_category or 'unknown'}

Respond ONLY with valid JSON:
{{"support_type": "SUPPORTS|COMPATIBLE|CONTRADICTS|UNRELATED", "confidence": 0.0-1.0, "relationship_type": "ROOT_CAUSE|SUPPORTING|CONSEQUENCE|CONTEXT_ONLY", "reason": "brief explanation"}}"""

            response = await claude.complete(
                tenant_id=UUID(tenant_id),
                prompt=prompt,
                system="You are a SOC analyst evaluating alert-to-investigation hypothesis correlation. Respond only with the requested JSON.",
                max_tokens=200,
                temperature=0.0,
                request_type="correlation",
            )

            # Parse response
            text = response.text.strip()
            # Handle potential markdown code blocks
            if text.startswith('```'):
                text = text.split('\n', 1)[1].rsplit('```', 1)[0].strip()

            result = json.loads(text)
            return HypothesisMatchResult(
                support_type=result.get('support_type', 'COMPATIBLE'),
                confidence=float(result.get('confidence', 0.5)),
                relationship_type=result.get('relationship_type', 'CONTEXT_ONLY'),
                reason=result.get('reason', 'AI-evaluated')
            )

        except Exception as e:
            logger.warning(f"AI hypothesis evaluation failed, using keyword fallback: {e}")
            return self.evaluate_hypothesis_support(alert, hypothesis, hypothesis_category)


# ============================================================================
# Singleton
# ============================================================================

_hypothesis_matcher: Optional[HypothesisMatcher] = None


def get_hypothesis_matcher() -> HypothesisMatcher:
    """Get or create the hypothesis matcher singleton."""
    global _hypothesis_matcher
    if _hypothesis_matcher is None:
        _hypothesis_matcher = HypothesisMatcher()
    return _hypothesis_matcher
