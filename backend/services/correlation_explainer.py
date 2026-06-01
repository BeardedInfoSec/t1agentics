# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Correlation Explainer Service

Generates human-readable explanations for correlation decisions.
Part of the hypothesis-driven correlation system.

Every correlation MUST include:
- why_correlated: Human-readable explanation
- score: Numeric confidence
- evidence: Structured evidence list
- gates_passed: Which eligibility gates passed
- hypothesis_support: How alert supports hypothesis
- relationship_type: Alert's role in investigation
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CorrelationExplanation:
    """Complete explanation for a correlation decision."""
    why_correlated: str
    score: int
    evidence: List[Dict[str, Any]]
    gates_passed: List[str]
    gates_failed: List[str]
    hypothesis_support: str
    relationship_type: str


class CorrelationExplainer:
    """
    Generates human-readable explanations for correlation decisions.

    All correlations must be explainable. This service ensures analysts
    understand WHY an alert was correlated to an investigation.
    """

    def generate_explanation(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any],
        evidence_list: List[Any],  # List of Evidence objects from EvidenceScorer
        score: int,
        gates_passed: List[str],
        gates_failed: List[str],
        hypothesis_support: str,
        relationship_type: str
    ) -> CorrelationExplanation:
        """
        Generate a complete correlation explanation.

        Args:
            alert: Alert data
            investigation: Investigation data
            evidence_list: Evidence objects from EvidenceScorer
            score: Total correlation score
            gates_passed: List of eligibility gates that passed
            gates_failed: List of eligibility gates that failed
            hypothesis_support: How alert supports hypothesis
            relationship_type: Alert's relationship to investigation

        Returns:
            CorrelationExplanation with all explanation fields
        """
        # Generate human-readable explanation
        why_correlated = self._generate_why_text(
            alert, investigation, evidence_list, score, hypothesis_support
        )

        # Convert evidence to dict format
        evidence_dicts = self._convert_evidence_to_dicts(evidence_list)

        return CorrelationExplanation(
            why_correlated=why_correlated,
            score=score,
            evidence=evidence_dicts,
            gates_passed=gates_passed,
            gates_failed=gates_failed,
            hypothesis_support=hypothesis_support,
            relationship_type=relationship_type
        )

    def _generate_why_text(
        self,
        alert: Dict[str, Any],
        investigation: Dict[str, Any],
        evidence_list: List[Any],
        score: int,
        hypothesis_support: str
    ) -> str:
        """Generate human-readable why_correlated text."""
        parts = [f"Score: {score}."]

        if not evidence_list:
            parts.append("No direct evidence found, correlation based on context.")
            return ' '.join(parts)

        parts.append("Evidence:")

        for evidence in evidence_list:
            # Handle both dataclass Evidence objects and dicts
            if hasattr(evidence, 'type'):
                evidence_type = evidence.type
                value = getattr(evidence, 'value', '')
                source = getattr(evidence, 'source', 'unknown')
                details = getattr(evidence, 'details', {})
            elif isinstance(evidence, dict):
                evidence_type = evidence.get('type', 'UNKNOWN')
                value = evidence.get('value', '')
                source = evidence.get('source', 'unknown')
                details = evidence.get('details', {})
            else:
                evidence_type = 'UNKNOWN'
                value = str(evidence)
                source = 'unknown'
                details = {}

            if evidence_type == 'MALICIOUS_IOC':
                ioc_type = details.get('ioc_type', 'IOC')
                parts.append(
                    f"Shares malicious {ioc_type} '{self._truncate(value, 50)}' "
                    f"(verdict: malicious from {source})"
                )

            elif evidence_type == 'SUSPICIOUS_IOC':
                ioc_type = details.get('ioc_type', 'IOC')
                parts.append(
                    f"Shares suspicious {ioc_type} '{self._truncate(value, 50)}' "
                    f"(verdict: suspicious from {source})"
                )

            elif evidence_type == 'MITRE_CHAIN':
                explanation = details.get('explanation', 'logical progression')
                parts.append(f"Extends MITRE chain: {value} ({explanation})")

            elif evidence_type == 'CAUSAL_SEQUENCE':
                relationship = details.get('relationship', 'related')
                parts.append(f"Causal relationship: {relationship} - {value}")

            elif evidence_type == 'THREAT_FINGERPRINT':
                actors = details.get('actors', [])
                parts.append(
                    f"Matches threat actor fingerprint: {', '.join(actors) if actors else value}"
                )

            elif evidence_type == 'MALWARE_FAMILY':
                families = details.get('families', [])
                parts.append(
                    f"Same malware family: {', '.join(families) if families else value}"
                )

            else:
                parts.append(f"{evidence_type}: {self._truncate(value, 50)}")

        # Add hypothesis support info
        if hypothesis_support == 'SUPPORTS':
            parts.append("Alert directly supports investigation hypothesis.")
        elif hypothesis_support == 'COMPATIBLE':
            parts.append("Alert is compatible with investigation hypothesis.")

        return ' '.join(parts)

    def _convert_evidence_to_dicts(self, evidence_list: List[Any]) -> List[Dict[str, Any]]:
        """Convert Evidence objects to dictionaries."""
        result = []

        for evidence in evidence_list:
            if hasattr(evidence, '__dict__'):
                # It's a dataclass or similar
                result.append({
                    'type': getattr(evidence, 'type', 'UNKNOWN'),
                    'value': getattr(evidence, 'value', ''),
                    'source': getattr(evidence, 'source', 'unknown'),
                    'confidence': getattr(evidence, 'confidence', 0.5),
                    'details': getattr(evidence, 'details', {}),
                })
            elif isinstance(evidence, dict):
                result.append(evidence)

        return result

    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text to max length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + '...'

    def generate_rejection_explanation(
        self,
        alert: Dict[str, Any],
        gates_failed: List[str],
        reason: str
    ) -> str:
        """
        Generate explanation for why correlation was rejected/blocked.

        Args:
            alert: Alert data
            gates_failed: Which eligibility gates failed
            reason: Primary reason for rejection

        Returns:
            Human-readable explanation
        """
        parts = [f"Correlation blocked: {reason}."]

        if gates_failed:
            parts.append(f"Failed eligibility gates: {', '.join(gates_failed)}.")

        alert_id = alert.get('alert_id', 'unknown')
        parts.append(f"Alert {alert_id} will be processed independently.")

        return ' '.join(parts)

    def generate_standalone_explanation(
        self,
        alert: Dict[str, Any],
        reason: str
    ) -> str:
        """
        Generate explanation for why an alert remains standalone.

        Args:
            alert: Alert data
            reason: Why no correlation was made

        Returns:
            Human-readable explanation
        """
        alert_id = alert.get('alert_id', 'unknown')
        return (
            f"Alert {alert_id} will remain standalone. "
            f"Reason: {reason}. "
            f"No existing investigation meets correlation criteria."
        )

    def generate_new_investigation_explanation(
        self,
        alert: Dict[str, Any],
        hypothesis: str,
        hypothesis_category: str
    ) -> str:
        """
        Generate explanation for new investigation creation.

        Args:
            alert: Alert that triggered investigation creation
            hypothesis: Generated hypothesis
            hypothesis_category: Hypothesis category

        Returns:
            Human-readable explanation
        """
        alert_id = alert.get('alert_id', 'unknown')
        alert_title = alert.get('title', 'Unknown alert')

        return (
            f"New investigation created for alert {alert_id} ({self._truncate(alert_title, 50)}). "
            f"Hypothesis category: {hypothesis_category}. "
            f"Initial hypothesis: {self._truncate(hypothesis, 100)}."
        )


# ============================================================================
# Gate Descriptions for Human-Readable Output
# ============================================================================

GATE_DESCRIPTIONS = {
    'SAME_TENANT': 'Alerts must belong to the same tenant/organization',
    'SAME_ENVIRONMENT': 'Alerts must be from the same environment (prod/staging)',
    'SAME_DOMAIN': 'Alerts must be from compatible threat domains (email, endpoint, etc.)',
    'TIME_WINDOW': 'Alert must be within 24h of investigation seed time',
    'CAPACITY': 'Investigation must not exceed maximum alert count',
    'ENTITY_OVERLAP': 'Alert must share at least one entity (user, host, or IP)',
    'HYPOTHESIS_COMPATIBLE': 'Alert must not contradict investigation hypothesis',
}


def get_gate_description(gate_name: str) -> str:
    """Get human-readable description for an eligibility gate."""
    return GATE_DESCRIPTIONS.get(gate_name, f'Gate: {gate_name}')


# ============================================================================
# Singleton
# ============================================================================

_correlation_explainer: Optional[CorrelationExplainer] = None


def get_correlation_explainer() -> CorrelationExplainer:
    """Get or create the correlation explainer singleton."""
    global _correlation_explainer
    if _correlation_explainer is None:
        _correlation_explainer = CorrelationExplainer()
    return _correlation_explainer
