# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Evidence Scorer Service

Calculates correlation scores based on EVIDENCE, not entity overlap.
Part of the hypothesis-driven correlation system.

Key principle: Entities (user, host) are used for VALIDATION only.
Scoring is based on:
- Shared malicious IOCs
- MITRE technique chains
- Causal sequences
- Threat actor fingerprints
- Malware family matches
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# ============================================================================
# Scoring Configuration (from environment)
# ============================================================================

class ScoringConfig:
    """Evidence-based scoring configuration."""

    # Evidence scores
    SCORE_MALICIOUS_IOC = int(os.getenv('CORRELATION_SCORE_MALICIOUS_IOC', '50'))
    SCORE_SUSPICIOUS_IOC = int(os.getenv('CORRELATION_SCORE_SUSPICIOUS_IOC', '20'))
    SCORE_MITRE_CHAIN = int(os.getenv('CORRELATION_SCORE_MITRE_CHAIN', '40'))
    SCORE_CAUSAL_SEQUENCE = int(os.getenv('CORRELATION_SCORE_CAUSAL_SEQUENCE', '60'))
    SCORE_THREAT_FINGERPRINT = int(os.getenv('CORRELATION_SCORE_THREAT_FINGERPRINT', '70'))
    SCORE_MALWARE_FAMILY = int(os.getenv('CORRELATION_SCORE_MALWARE_FAMILY', '80'))

    # Thresholds
    MINIMUM_EVIDENCE_SCORE = int(os.getenv('CORRELATION_MINIMUM_EVIDENCE', '40'))
    AUTO_CONFIRM_THRESHOLD = int(os.getenv('CORRELATION_AUTO_CONFIRM_THRESHOLD', '100'))

    # Entity risk scores - contribute to entity risk accumulation
    SCORE_USER = int(os.getenv('CORRELATION_SCORE_USER', '30'))
    SCORE_HOST = int(os.getenv('CORRELATION_SCORE_HOST', '25'))
    SCORE_INTERNAL_IP = int(os.getenv('CORRELATION_SCORE_INTERNAL_IP', '15'))
    SCORE_EXTERNAL_IOC = int(os.getenv('CORRELATION_SCORE_EXTERNAL_IOC', '20'))


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Evidence:
    """Single piece of correlation evidence."""
    type: str  # MALICIOUS_IOC, MITRE_CHAIN, etc.
    value: str
    source: str  # Where the evidence came from (VirusTotal, T1 inference, etc.)
    confidence: float = 0.8
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoringResult:
    """Result of evidence-based scoring."""
    score: int
    evidence: List[Evidence]
    has_malicious_evidence: bool = False
    has_causal_evidence: bool = False
    recommendation: str = 'SOFT_LINK'  # SOFT_LINK, AUTO_CONFIRM, CREATE_NEW


# ============================================================================
# MITRE Chain Detection
# ============================================================================

# Known attack chains (predecessor -> successors) covering all 14 MITRE tactics
MITRE_ATTACK_CHAINS = {
    # Reconnaissance -> Resource Development / Initial Access
    'T1595': ['T1190', 'T1133'],  # Active Scanning -> Exploit Public-Facing, External Remote Services
    'T1592': ['T1566', 'T1189'],  # Gather Victim Host Info -> Phishing, Drive-by
    'T1589': ['T1566', 'T1110'],  # Gather Victim Identity -> Phishing, Brute Force

    # Resource Development -> Initial Access
    'T1583': ['T1566', 'T1189'],  # Acquire Infrastructure -> Phishing, Drive-by Compromise
    'T1587': ['T1204', 'T1059'],  # Develop Capabilities -> User Execution, Scripting
    'T1588': ['T1059', 'T1055'],  # Obtain Capabilities -> Scripting, Process Injection

    # Initial Access -> Execution
    'T1566': ['T1204', 'T1059'],  # Phishing -> User Execution, Scripting
    'T1190': ['T1059', 'T1203'],  # Exploit Public-Facing -> Scripting, Exploitation
    'T1189': ['T1203', 'T1059'],  # Drive-by Compromise -> Exploitation, Scripting
    'T1133': ['T1078', 'T1059'],  # External Remote Services -> Valid Accounts, Scripting
    'T1195': ['T1059', 'T1204'],  # Supply Chain Compromise -> Scripting, User Execution
    'T1199': ['T1078', 'T1021'],  # Trusted Relationship -> Valid Accounts, Remote Services

    # Execution -> Persistence/Defense Evasion
    'T1059': ['T1547', 'T1055', 'T1027'],  # Scripting -> Boot/Logon, Process Injection, Obfuscation
    'T1204': ['T1105', 'T1059'],  # User Execution -> Ingress Transfer, Scripting
    'T1203': ['T1055', 'T1059', 'T1547'],  # Exploitation for Client Exec -> Injection, Scripting, Persistence

    # Persistence -> C2 / Execution
    'T1547': ['T1071', 'T1095', 'T1059'],  # Boot/Logon Autostart -> App Layer C2, Non-App C2, Scripting
    'T1053': ['T1071', 'T1095', 'T1059'],  # Scheduled Task -> C2 protocols, Scripting
    'T1136': ['T1078', 'T1021'],  # Create Account -> Valid Accounts, Remote Services
    'T1543': ['T1071', 'T1059'],  # Create/Modify System Process -> C2, Scripting
    'T1546': ['T1059', 'T1055'],  # Event Triggered Execution -> Scripting, Injection

    # Privilege Escalation -> Credential Access / Lateral Movement
    'T1068': ['T1003', 'T1021'],  # Exploitation for Priv Esc -> Credential Dumping, Remote Services
    'T1078': ['T1021', 'T1003'],  # Valid Accounts -> Remote Services, Credential Dumping
    'T1055': ['T1003', 'T1027'],  # Process Injection -> Credential Dumping, Obfuscation

    # Defense Evasion -> Execution / Persistence
    'T1027': ['T1059', 'T1055'],  # Obfuscated Files -> Scripting, Injection
    'T1562': ['T1059', 'T1003'],  # Impair Defenses -> Scripting, Credential Dumping
    'T1070': ['T1059', 'T1041'],  # Indicator Removal -> Scripting, Exfil (covering tracks)

    # Credential Access -> Lateral Movement
    'T1003': ['T1021', 'T1550'],  # OS Credential Dumping -> Remote Services, Pass the Hash
    'T1555': ['T1021', 'T1550'],  # Credentials from Password Stores -> Remote Services
    'T1110': ['T1078', 'T1021'],  # Brute Force -> Valid Accounts, Remote Services
    'T1557': ['T1550', 'T1021'],  # Adversary-in-the-Middle -> Use Alternate Auth, Remote Services
    'T1552': ['T1078', 'T1021'],  # Unsecured Credentials -> Valid Accounts, Remote Services

    # Discovery -> Lateral Movement / Collection
    'T1087': ['T1021', 'T1078'],  # Account Discovery -> Remote Services, Valid Accounts
    'T1082': ['T1005', 'T1083'],  # System Info Discovery -> Data from Local System, File Discovery
    'T1083': ['T1005', 'T1039'],  # File and Directory Discovery -> Local Data, Network Share Data
    'T1135': ['T1039', 'T1021'],  # Network Share Discovery -> Network Share Data, Remote Services
    'T1046': ['T1021', 'T1210'],  # Network Service Discovery -> Remote Services, Exploitation
    'T1018': ['T1021', 'T1570'],  # Remote System Discovery -> Remote Services, Lateral Tool Transfer

    # Lateral Movement -> Collection / Actions on Objectives
    'T1021': ['T1039', 'T1041', 'T1486'],  # Remote Services -> Collection, Exfil, Ransomware
    'T1570': ['T1039', 'T1041'],  # Lateral Tool Transfer -> Collection, Exfil
    'T1550': ['T1021', 'T1039'],  # Use Alternate Auth Material -> Remote Services, Collection
    'T1210': ['T1059', 'T1003'],  # Exploitation of Remote Services -> Scripting, Credential Dumping

    # Collection -> Exfiltration
    'T1005': ['T1041', 'T1048', 'T1567'],  # Data from Local System -> Exfil
    'T1039': ['T1041', 'T1048'],  # Data from Network Shared Drive -> Exfil
    'T1560': ['T1041', 'T1048'],  # Archive Collected Data -> Exfil
    'T1074': ['T1560', 'T1041'],  # Data Staged -> Archive, Exfil
    'T1119': ['T1560', 'T1041'],  # Automated Collection -> Archive, Exfil

    # Command and Control -> Exfiltration / Execution
    'T1071': ['T1041', 'T1105'],  # Application Layer Protocol -> Exfil, Ingress Tool Transfer
    'T1095': ['T1041', 'T1105'],  # Non-Application Layer Protocol -> Exfil, Ingress Tool Transfer
    'T1573': ['T1041', 'T1105'],  # Encrypted Channel -> Exfil, Ingress Tool Transfer
    'T1090': ['T1071', 'T1041'],  # Proxy -> App Layer Protocol, Exfil
    'T1102': ['T1041', 'T1105'],  # Web Service -> Exfil, Ingress Tool Transfer

    # Exfiltration -> Impact (data theft -> destruction/disruption)
    'T1041': ['T1486', 'T1485'],  # Exfil Over C2 -> Ransomware, Data Destruction
    'T1048': ['T1486', 'T1485'],  # Exfil Over Alternative Protocol -> Ransomware, Destruction
    'T1567': ['T1486', 'T1485'],  # Exfil Over Web Service -> Ransomware, Destruction

    # Ingress -> Multiple follow-ups
    'T1105': ['T1059', 'T1055', 'T1547'],  # Ingress Tool Transfer -> Execution, Injection, Persistence
}

# Chain length scoring weights: longer chains indicate more advanced attack progression
CHAIN_LENGTH_WEIGHTS = {
    2: 1.0,   # Two-step chain (standard)
    3: 1.3,   # Three-step chain (elevated)
    4: 1.6,   # Four-step chain (advanced)
    5: 2.0,   # Five+ step chain (APT-like)
}


class MitreChainDetector:
    """Detects logical MITRE technique chains."""

    def find_chain(
        self,
        new_techniques: Set[str],
        existing_techniques: Set[str]
    ) -> Optional[Tuple[List[str], str, float]]:
        """
        Check if new techniques form a logical chain with existing ones.

        Args:
            new_techniques: MITRE techniques from new alert
            existing_techniques: MITRE techniques from investigation

        Returns:
            Tuple of (chain sequence, explanation, weight) if chain found, None otherwise
        """
        if not new_techniques or not existing_techniques:
            return None

        best_chain = None
        best_length = 0

        # Check if any new technique is a logical successor
        for existing in existing_techniques:
            successors = MITRE_ATTACK_CHAINS.get(existing, [])
            matches = new_techniques.intersection(set(successors))
            if matches:
                chain = [existing] + list(matches)
                if len(chain) > best_length:
                    best_chain = chain
                    best_length = len(chain)

        # Check if any new technique is a predecessor
        for new in new_techniques:
            successors = MITRE_ATTACK_CHAINS.get(new, [])
            matches = existing_techniques.intersection(set(successors))
            if matches:
                chain = [new] + list(matches)
                if len(chain) > best_length:
                    best_chain = chain
                    best_length = len(chain)

        # Check for multi-hop chains (A->B->C where B is shared)
        for existing in existing_techniques:
            for successor in MITRE_ATTACK_CHAINS.get(existing, []):
                next_successors = MITRE_ATTACK_CHAINS.get(successor, [])
                deep_matches = new_techniques.intersection(set(next_successors))
                if deep_matches:
                    chain = [existing, successor] + list(deep_matches)
                    if len(chain) > best_length:
                        best_chain = chain
                        best_length = len(chain)

        if best_chain:
            weight = CHAIN_LENGTH_WEIGHTS.get(
                min(len(best_chain), 5), 2.0
            )
            explanation = f"Attack chain ({len(best_chain)} steps): {' -> '.join(best_chain)}"
            return best_chain, explanation, weight

        return None


# ============================================================================
# Evidence Scorer Service
# ============================================================================

class EvidenceScorer:
    """
    Calculates correlation scores based on evidence, not entity overlap.

    Scoring principles:
    1. Shared malicious IOCs = strong signal (+50 per IOC)
    2. MITRE technique chains = causal relationship (+40)
    3. Causal sequences (parent-child) = direct link (+60)
    4. Same threat fingerprint = same attacker (+70)
    5. Same malware family = definitive (+80)

    Entity overlap (user, host) is used for VALIDATION, not scoring.
    """

    def __init__(self):
        self.config = ScoringConfig()
        self.mitre_detector = MitreChainDetector()

    def calculate_score(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> ScoringResult:
        """
        Calculate evidence-based correlation score.

        Args:
            alert: New alert data
            investigation: Candidate investigation data

        Returns:
            ScoringResult with score, evidence list, and recommendation
        """
        score = 0
        evidence = []
        has_malicious = False
        has_causal = False

        # 1. Check for shared malicious IOCs
        ioc_score, ioc_evidence = self._score_shared_iocs(alert, investigation)
        score += ioc_score
        evidence.extend(ioc_evidence)
        if any(e.type == 'MALICIOUS_IOC' for e in ioc_evidence):
            has_malicious = True

        # 2. Check for MITRE technique chain
        chain_score, chain_evidence = self._score_mitre_chain(alert, investigation)
        score += chain_score
        evidence.extend(chain_evidence)

        # 3. Check for causal sequence (parent-child relationships)
        causal_score, causal_evidence = self._score_causal_sequence(alert, investigation)
        score += causal_score
        evidence.extend(causal_evidence)
        if causal_evidence:
            has_causal = True

        # 4. Check for threat actor fingerprint
        fingerprint_score, fingerprint_evidence = self._score_threat_fingerprint(alert, investigation)
        score += fingerprint_score
        evidence.extend(fingerprint_evidence)

        # 5. Check for malware family match
        malware_score, malware_evidence = self._score_malware_family(alert, investigation)
        score += malware_score
        evidence.extend(malware_evidence)
        if malware_evidence:
            has_malicious = True

        # 6. Entity overlap scoring (user, host, IP, IOC)
        entity_score, entity_evidence = self._score_entity_overlap(alert, investigation)
        score += entity_score
        evidence.extend(entity_evidence)

        # Determine recommendation
        recommendation = self._get_recommendation(score, has_malicious, has_causal)

        return ScoringResult(
            score=score,
            evidence=evidence,
            has_malicious_evidence=has_malicious,
            has_causal_evidence=has_causal,
            recommendation=recommendation
        )

    def _score_shared_iocs(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on shared IOCs with verdicts."""
        score = 0
        evidence = []

        # Extract IOCs from alert
        alert_iocs = self._extract_iocs_with_verdicts(alert)

        # Extract IOCs from investigation
        inv_iocs = self._extract_investigation_iocs(investigation)

        # Find shared IOCs
        for alert_ioc in alert_iocs:
            ioc_value = alert_ioc.get('value', '').lower()
            ioc_type = alert_ioc.get('type', 'unknown')
            verdict = alert_ioc.get('verdict', '').upper()

            # Check if this IOC exists in investigation
            for inv_ioc in inv_iocs:
                if inv_ioc.get('value', '').lower() == ioc_value:
                    # Shared IOC found!
                    if verdict == 'MALICIOUS' or inv_ioc.get('verdict', '').upper() == 'MALICIOUS':
                        score += self.config.SCORE_MALICIOUS_IOC
                        evidence.append(Evidence(
                            type='MALICIOUS_IOC',
                            value=ioc_value,
                            source=alert_ioc.get('source', 'enrichment'),
                            confidence=0.95,
                            details={
                                'ioc_type': ioc_type,
                                'verdict': 'MALICIOUS',
                                'detection_source': alert_ioc.get('source'),
                            }
                        ))
                    elif verdict == 'SUSPICIOUS' or inv_ioc.get('verdict', '').upper() == 'SUSPICIOUS':
                        score += self.config.SCORE_SUSPICIOUS_IOC
                        evidence.append(Evidence(
                            type='SUSPICIOUS_IOC',
                            value=ioc_value,
                            source=alert_ioc.get('source', 'enrichment'),
                            confidence=0.7,
                            details={
                                'ioc_type': ioc_type,
                                'verdict': 'SUSPICIOUS',
                            }
                        ))
                    break

        return score, evidence

    def _score_mitre_chain(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on MITRE technique chain."""
        score = 0
        evidence = []

        alert_mitre = self._extract_mitre_techniques(alert)
        inv_mitre = self._extract_investigation_mitre(investigation)

        chain_result = self.mitre_detector.find_chain(alert_mitre, inv_mitre)

        if chain_result:
            chain, explanation, weight = chain_result
            score += int(self.config.SCORE_MITRE_CHAIN * weight)
            evidence.append(Evidence(
                type='MITRE_CHAIN',
                value=' -> '.join(chain),
                source='T1 inference',
                confidence=min(0.6 + (len(chain) * 0.1), 0.95),
                details={
                    'chain': chain,
                    'chain_length': len(chain),
                    'weight': weight,
                    'explanation': explanation,
                }
            ))

        return score, evidence

    def _score_causal_sequence(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on causal relationships (parent-child processes, etc.)."""
        score = 0
        evidence = []

        raw_event = alert.get('raw_event', {})
        if not isinstance(raw_event, dict):
            return score, evidence

        # Check for parent process relationship
        parent_hash = raw_event.get('parent_hash') or raw_event.get('parent_process_hash')
        if parent_hash:
            # Check if parent hash exists in investigation
            inv_hashes = self._extract_investigation_hashes(investigation)
            if parent_hash.lower() in inv_hashes:
                score += self.config.SCORE_CAUSAL_SEQUENCE
                evidence.append(Evidence(
                    type='CAUSAL_SEQUENCE',
                    value=parent_hash,
                    source='process tree',
                    confidence=0.9,
                    details={
                        'relationship': 'CAUSED_BY',
                        'parent_hash': parent_hash,
                    }
                ))

        # Check for triggered alerts (alert references another alert)
        triggered_by = raw_event.get('triggered_by_alert') or raw_event.get('parent_alert_id')
        if triggered_by:
            inv_alerts = investigation.get('alert_ids', [])
            if triggered_by in inv_alerts:
                score += self.config.SCORE_CAUSAL_SEQUENCE
                evidence.append(Evidence(
                    type='CAUSAL_SEQUENCE',
                    value=triggered_by,
                    source='alert chain',
                    confidence=0.95,
                    details={
                        'relationship': 'TRIGGERED_BY',
                        'parent_alert': triggered_by,
                    }
                ))

        return score, evidence

    def _score_threat_fingerprint(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on threat actor fingerprint match."""
        score = 0
        evidence = []

        # Extract threat actor attribution
        alert_actors = self._extract_threat_actors(alert)
        inv_actors = self._extract_investigation_actors(investigation)

        # Check for matches
        common_actors = alert_actors.intersection(inv_actors)
        if common_actors:
            score += self.config.SCORE_THREAT_FINGERPRINT
            evidence.append(Evidence(
                type='THREAT_FINGERPRINT',
                value=', '.join(common_actors),
                source='threat intel',
                confidence=0.85,
                details={
                    'actors': list(common_actors),
                }
            ))

        return score, evidence

    def _score_malware_family(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on malware family match."""
        score = 0
        evidence = []

        alert_families = self._extract_malware_families(alert)
        inv_families = self._extract_investigation_families(investigation)

        common_families = alert_families.intersection(inv_families)
        if common_families:
            score += self.config.SCORE_MALWARE_FAMILY
            evidence.append(Evidence(
                type='MALWARE_FAMILY',
                value=', '.join(common_families),
                source='detection engine',
                confidence=0.95,
                details={
                    'families': list(common_families),
                }
            ))

        return score, evidence

    def _get_recommendation(
        self,
        score: int,
        has_malicious: bool,
        has_causal: bool
    ) -> str:
        """Determine correlation recommendation."""
        if score >= self.config.AUTO_CONFIRM_THRESHOLD:
            # Auto-confirm requires strong evidence
            if has_malicious or has_causal:
                return 'AUTO_CONFIRM'
            else:
                return 'SOFT_LINK'  # High score but weak evidence
        elif score >= self.config.MINIMUM_EVIDENCE_SCORE:
            return 'SOFT_LINK'
        else:
            return 'CREATE_NEW'

    def _score_entity_overlap(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Tuple[int, List[Evidence]]:
        """Score based on shared entities (users, hosts, IPs)."""
        score = 0
        evidence = []

        alert_entities = self._extract_alert_entities(alert)
        inv_entities = self._extract_inv_entities(investigation)

        # User overlap
        common_users = alert_entities['users'].intersection(inv_entities['users'])
        if common_users:
            score += self.config.SCORE_USER
            evidence.append(Evidence(
                type='ENTITY_USER',
                value=', '.join(list(common_users)[:5]),
                source='entity extraction',
                confidence=0.8,
                details={'entity_type': 'user', 'count': len(common_users)}
            ))

        # Host overlap
        common_hosts = alert_entities['hosts'].intersection(inv_entities['hosts'])
        if common_hosts:
            score += self.config.SCORE_HOST
            evidence.append(Evidence(
                type='ENTITY_HOST',
                value=', '.join(list(common_hosts)[:5]),
                source='entity extraction',
                confidence=0.8,
                details={'entity_type': 'host', 'count': len(common_hosts)}
            ))

        # IP overlap
        common_ips = alert_entities['ips'].intersection(inv_entities['ips'])
        if common_ips:
            score += self.config.SCORE_INTERNAL_IP
            evidence.append(Evidence(
                type='ENTITY_IP',
                value=', '.join(list(common_ips)[:5]),
                source='entity extraction',
                confidence=0.7,
                details={'entity_type': 'ip', 'count': len(common_ips)}
            ))

        return score, evidence

    def _extract_alert_entities(self, alert: Dict[str, Any]) -> Dict[str, set]:
        """Extract entity sets from alert for overlap scoring."""
        entities = {'users': set(), 'hosts': set(), 'ips': set()}
        raw_event = alert.get('raw_event', {})
        if not isinstance(raw_event, dict):
            return entities

        for extracted_src in [raw_event.get('_extracted', {}),
                              (raw_event.get('raw_event', {}) or {}).get('_extracted', {})]:
            if not isinstance(extracted_src, dict):
                continue
            ent = extracted_src.get('entities', {})
            if isinstance(ent, dict):
                for u in ent.get('users', []):
                    entities['users'].add(str(u).lower())
                if ent.get('user'):
                    entities['users'].add(str(ent['user']).lower())
                for h in ent.get('hosts', []):
                    entities['hosts'].add(str(h).lower())
                if ent.get('host'):
                    entities['hosts'].add(str(ent['host']).lower())
                for ip in ent.get('ips', []):
                    entities['ips'].add(str(ip))

        # Direct raw_event fields
        if raw_event.get('user'):
            entities['users'].add(str(raw_event['user']).lower())
        for f in ['hostname', 'host']:
            if raw_event.get(f):
                entities['hosts'].add(str(raw_event[f]).lower())
        if raw_event.get('source_ip'):
            entities['ips'].add(str(raw_event['source_ip']))

        return entities

    def _extract_inv_entities(self, investigation: Dict[str, Any]) -> Dict[str, set]:
        """Extract entity sets from investigation for overlap scoring."""
        entities = {'users': set(), 'hosts': set(), 'ips': set()}
        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, str):
            import json
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}

        ent = inv_data.get('entities', {})
        if isinstance(ent, dict):
            entities['users'] = set(str(u).lower() for u in ent.get('users', []))
            entities['hosts'] = set(str(h).lower() for h in ent.get('hosts', []))
            entities['ips'] = set(str(ip) for ip in ent.get('ips', []))

        ioc_summary = inv_data.get('ioc_summary', {})
        for u in ioc_summary.get('users', []):
            entities['users'].add(str(u).lower())
        for h in ioc_summary.get('hosts', []):
            entities['hosts'].add(str(h).lower())
        for ip in ioc_summary.get('ips', []):
            entities['ips'].add(str(ip))

        return entities

    # ========================================================================
    # Helper extraction methods
    # ========================================================================

    def _extract_iocs_with_verdicts(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs with their verdicts from alert."""
        iocs = []

        raw_event = alert.get('raw_event', {})
        if not isinstance(raw_event, dict):
            return iocs

        # Look for _extracted at multiple levels:
        # 1. raw_event._extracted (from enrichment)
        # 2. raw_event.raw_event._extracted (from original webhook payload)
        extracted = raw_event.get('_extracted', {})
        nested_raw = raw_event.get('raw_event', {})
        if isinstance(nested_raw, dict):
            nested_extracted = nested_raw.get('_extracted', {})
            if nested_extracted and not extracted:
                extracted = nested_extracted
            elif nested_extracted:
                # Merge nested extracted into extracted
                for key in ['iocs', 'enrichment_results']:
                    if key in nested_extracted and key not in extracted:
                        extracted[key] = nested_extracted[key]

        if not extracted:
            return iocs

        # Check enrichment_results for IOCs with verdicts
        enrichment = extracted.get('enrichment_results', {})
        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            for ioc_data in enrichment.get(ioc_type, []):
                if isinstance(ioc_data, dict):
                    iocs.append({
                        'value': ioc_data.get('value', ioc_data.get('ip', ioc_data.get('domain', ''))),
                        'type': ioc_type.rstrip('s'),  # ips -> ip
                        'verdict': ioc_data.get('verdict', 'unknown'),
                        'source': ioc_data.get('source', 'enrichment'),
                    })

        # Also check iocs directly
        iocs_obj = extracted.get('iocs', {})
        if iocs_obj:
            for ioc_type in ['ips', 'domains', 'file_hashes', 'urls']:
                for value in iocs_obj.get(ioc_type, []):
                    if isinstance(value, str):
                        iocs.append({'value': value, 'type': ioc_type.rstrip('s'), 'verdict': 'unknown'})

        return iocs

    def _extract_investigation_iocs(self, investigation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from investigation data."""
        iocs = []

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, str):
            import json
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}

        # Check for IOC summary in investigation data
        ioc_summary = inv_data.get('ioc_summary', {})
        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            for value in ioc_summary.get(ioc_type, []):
                iocs.append({'value': value, 'type': ioc_type.rstrip('s'), 'verdict': 'unknown'})

        # Check correlated_alerts for their IOCs
        for corr_alert in inv_data.get('correlated_alerts', []):
            for ioc in corr_alert.get('shared_iocs', []):
                iocs.append({'value': ioc, 'type': 'unknown', 'verdict': 'unknown'})

        return iocs

    def _extract_mitre_techniques(self, alert: Dict[str, Any]) -> Set[str]:
        """Extract MITRE techniques from alert."""
        techniques = set()

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            # Check both extraction paths
            extracted = raw_event.get('_extracted', {})
            nested_raw = raw_event.get('raw_event', {})
            if isinstance(nested_raw, dict):
                nested_extracted = nested_raw.get('_extracted', {})
                if nested_extracted:
                    mitre = nested_extracted.get('mitre', {})
                    if isinstance(mitre, dict):
                        techniques.update(mitre.get('techniques', []))

            if extracted:
                mitre = extracted.get('mitre', {})
                if isinstance(mitre, dict):
                    techniques.update(mitre.get('techniques', []))

        if alert.get('mitre_techniques'):
            techniques.update(alert['mitre_techniques'])

        return techniques

    def _extract_investigation_mitre(self, investigation: Dict[str, Any]) -> Set[str]:
        """Extract MITRE techniques from investigation."""
        techniques = set()

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, dict):
            for key in ['mitre_techniques', 'mitre_tactics', 'mitre']:
                if key in inv_data:
                    value = inv_data[key]
                    if isinstance(value, list):
                        techniques.update(value)
                    elif isinstance(value, dict):
                        techniques.update(value.get('techniques', []))

        return techniques

    def _extract_investigation_hashes(self, investigation: Dict[str, Any]) -> Set[str]:
        """Extract file hashes from investigation."""
        hashes = set()

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, dict):
            ioc_summary = inv_data.get('ioc_summary', {})
            for h in ioc_summary.get('hashes', []):
                hashes.add(h.lower())

        return hashes

    def _extract_threat_actors(self, alert: Dict[str, Any]) -> Set[str]:
        """Extract threat actor attributions from alert."""
        actors = set()

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            extracted = raw_event.get('_extracted', {})
            if extracted:
                # Check enrichment for threat intel
                for ioc_type in ['ips', 'domains', 'hashes']:
                    for ioc_data in extracted.get('enrichment_results', {}).get(ioc_type, []):
                        if isinstance(ioc_data, dict):
                            # Look for actor attribution
                            actor = ioc_data.get('threat_actor') or ioc_data.get('attributed_to')
                            if actor:
                                actors.add(actor.lower())

        return actors

    def _extract_investigation_actors(self, investigation: Dict[str, Any]) -> Set[str]:
        """Extract threat actors from investigation."""
        actors = set()

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, dict):
            # Check for threat actor in investigation
            actor = inv_data.get('threat_actor') or inv_data.get('attributed_to')
            if actor:
                actors.add(actor.lower())

        return actors

    def _extract_malware_families(self, alert: Dict[str, Any]) -> Set[str]:
        """Extract malware family names from alert."""
        families = set()

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            extracted = raw_event.get('_extracted', {})
            if extracted:
                # Check enrichment for malware classification
                for ioc_type in ['hashes']:
                    for ioc_data in extracted.get('enrichment_results', {}).get(ioc_type, []):
                        if isinstance(ioc_data, dict):
                            family = ioc_data.get('malware_family') or ioc_data.get('family')
                            if family:
                                families.add(family.lower())

                            # Also check detections
                            for det in ioc_data.get('detections', []):
                                if 'emotet' in det.lower():
                                    families.add('emotet')
                                elif 'trickbot' in det.lower():
                                    families.add('trickbot')
                                elif 'cobalt' in det.lower():
                                    families.add('cobaltstrike')

        return families

    def _extract_investigation_families(self, investigation: Dict[str, Any]) -> Set[str]:
        """Extract malware families from investigation."""
        families = set()

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, dict):
            family = inv_data.get('malware_family')
            if family:
                families.add(family.lower())

            # Check hypothesis for malware family hints
            hypothesis = inv_data.get('hypothesis', '')
            for known_family in ['emotet', 'trickbot', 'cobaltstrike', 'qakbot', 'ryuk']:
                if known_family in hypothesis.lower():
                    families.add(known_family)

        return families


# ============================================================================
# Singleton
# ============================================================================

_evidence_scorer: Optional[EvidenceScorer] = None


def get_evidence_scorer() -> EvidenceScorer:
    """Get or create the evidence scorer singleton."""
    global _evidence_scorer
    if _evidence_scorer is None:
        _evidence_scorer = EvidenceScorer()
    return _evidence_scorer
