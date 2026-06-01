# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Verdict Convergence Service

Implements rules to prevent verdict stagnation and ensure
convergence within iteration limits.

Key Features:
- Auto-confirmation for known malware from trusted EDRs
- Forced escalation/completion at iteration limits
- Confidence boosting based on signal strength
- Prevents infinite "suspicious @ 0.6" loops

Security Note: These rules encode security domain expertise
to ensure timely and accurate verdicts.
"""

from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
from config.agent_limits import (
    is_known_malware,
    is_trusted_edr_source,
    get_tier_limits,
    KNOWN_MALWARE_FAMILIES,
    TRUSTED_EDR_SOURCES
)
from models.verdict import Verdict, normalize_verdict_safe


@dataclass
class ConvergenceState:
    """
    Tracks verdict convergence state across iterations.
    """
    iteration: int = 0
    current_verdict: str = 'unknown'
    current_confidence: float = 0.5
    verdict_history: List[Tuple[str, float]] = field(default_factory=list)
    evidence_count: int = 0
    malware_detected: bool = False
    trusted_source: bool = False
    force_complete: bool = False
    forced_verdict: Optional[str] = None
    forced_reason: Optional[str] = None

    def record_verdict(self, verdict: str, confidence: float) -> None:
        """Record a verdict observation."""
        self.verdict_history.append((verdict, confidence))
        self.current_verdict = verdict
        self.current_confidence = confidence

    def is_stuck(self, min_iterations: int = 2) -> bool:
        """Check if verdict is stuck (same verdict repeated)."""
        if len(self.verdict_history) < min_iterations:
            return False

        recent = self.verdict_history[-min_iterations:]
        return all(v == recent[0][0] for v, _ in recent)

    def get_verdict_trend(self) -> str:
        """Analyze verdict trend: escalating, de-escalating, or stuck."""
        if len(self.verdict_history) < 2:
            return 'unknown'

        verdict_scores = {
            'benign': 0, 'false_positive': 0,
            'suspicious': 1, 'needs_escalation': 2,
            'true_positive': 3, 'malicious': 3
        }

        scores = [verdict_scores.get(v, 1) for v, _ in self.verdict_history[-3:]]

        if all(s == scores[0] for s in scores):
            return 'stuck'
        elif scores[-1] > scores[0]:
            return 'escalating'
        else:
            return 'de_escalating'


def check_auto_confirm(
    alert: Optional[Dict[str, Any]],
    enrichments: Optional[Dict[str, Any]] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if alert should be auto-confirmed as true positive.

    Conditions for auto-confirm:
    1. Known malware family detected by trusted EDR
    2. High-confidence detection from trusted source
    3. Multiple threat intel sources confirm malicious

    Args:
        alert: Alert data (can be None if no alert associated)
        enrichments: Optional enrichment results

    Returns:
        Tuple of (should_auto_confirm, verdict, reason)
    """
    # Handle case where alert is None (e.g., investigation without associated alert)
    if alert is None:
        return (False, None, None)

    raw = alert.get('raw_event') or {}
    if isinstance(raw, str):
        import json
        try:
            raw = json.loads(raw)
        except:
            raw = {}
    # Ensure raw is never None
    if raw is None:
        raw = {}

    source = alert.get('source', '')
    detection_name = raw.get('detection_name', '')
    threat_family = raw.get('threat_family', '')

    # Check 1: Known malware from trusted EDR
    if is_trusted_edr_source(source) and is_known_malware(detection_name, threat_family):
        return (
            True,
            'true_positive',
            f"Known malware '{threat_family or detection_name}' detected by trusted EDR '{source}'"
        )

    # Check 2: Severity Severe/Critical from trusted EDR
    severity_level = raw.get('severity_level', '').lower()
    alert_severity = alert.get('severity', '').lower()

    if is_trusted_edr_source(source):
        if severity_level in ('severe', 'critical', 'high') or alert_severity in ('critical', 'high'):
            # If also has malware keywords, auto-confirm
            if is_known_malware(detection_name, threat_family):
                return (
                    True,
                    'true_positive',
                    f"High-severity detection from trusted EDR with malware indicators"
                )

    # Check 3: Multiple enrichments confirm malicious
    if enrichments:
        malicious_count = 0
        for key, data in enrichments.items():
            if isinstance(data, dict):
                if data.get('malicious') or data.get('detected'):
                    malicious_count += 1
                if data.get('positives', 0) > 5:  # VT detections
                    malicious_count += 1
                if data.get('abuseConfidenceScore', data.get('score', 0)) > 80:
                    malicious_count += 1

        if malicious_count >= 3:
            return (
                True,
                'true_positive',
                f"Multiple ({malicious_count}) threat intel sources confirm malicious"
            )

    return (False, None, None)


def check_force_completion(
    state: ConvergenceState,
    tier: int = 1
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if agent should be forced to complete.

    Triggered when:
    1. At or past force_complete_at iteration
    2. Verdict is stuck and evidence is sufficient
    3. Malware detected but not converging

    Args:
        state: Current convergence state
        tier: Agent tier

    Returns:
        Tuple of (should_force, verdict, reason)
    """
    limits = get_tier_limits(tier)
    force_at = limits.get('force_complete_at', 3)
    max_iter = limits.get('max_iterations', 5)

    # Check if at force completion point
    if state.iteration >= force_at:
        # Determine forced verdict based on state
        if state.malware_detected or state.current_verdict in ('true_positive', 'malicious'):
            return (
                True,
                'true_positive',
                f"Forced completion at iteration {state.iteration}: malware indicators present"
            )

        if state.trusted_source and state.current_confidence >= 0.7:
            return (
                True,
                state.current_verdict,
                f"Forced completion at iteration {state.iteration}: trusted source with high confidence"
            )

        # Stuck at suspicious - decide based on evidence
        if state.current_verdict == 'suspicious':
            if state.evidence_count >= 3:
                if tier < 3:
                    return (
                        True,
                        'needs_escalation',
                        f"Forced escalation at iteration {state.iteration}: stuck suspicious with {state.evidence_count} signals"
                    )
                else:
                    # T3 can't escalate further - make a call
                    return (
                        True,
                        'true_positive' if state.current_confidence >= 0.6 else 'suspicious',
                        f"T3 forced completion: {state.evidence_count} signals, confidence {state.current_confidence}"
                    )
            else:
                # Low evidence - lean towards benign
                return (
                    True,
                    'benign',
                    f"Forced completion at iteration {state.iteration}: insufficient evidence ({state.evidence_count} signals)"
                )

        # Default: if verdict is unknown and we have some evidence, escalate
        if state.current_verdict == 'unknown':
            if state.evidence_count >= 1 and tier < 3:
                return (
                    True,
                    'needs_escalation',
                    f"Forced completion at iteration {state.iteration}: unknown verdict with evidence, escalating for deeper analysis"
                )
            else:
                # No evidence - likely benign
                return (
                    True,
                    'benign',
                    f"Forced completion at iteration {state.iteration}: no strong indicators"
                )

        # Otherwise accept current verdict
        return (
            True,
            state.current_verdict,
            f"Forced completion at iteration {state.iteration}"
        )

    # Check if stuck and should force early
    if state.is_stuck(min_iterations=2) and state.iteration >= 2:
        trend = state.get_verdict_trend()
        if trend == 'stuck':
            # Nudge towards resolution
            if state.current_verdict == 'suspicious' and tier < 3:
                return (
                    True,
                    'needs_escalation',
                    f"Breaking verdict stagnation: escalating stuck suspicious case"
                )

    return (False, None, None)


def calculate_confidence_boost(
    base_confidence: float,
    alert: Optional[Dict[str, Any]],
    enrichments: Optional[Dict[str, Any]] = None,
    state: Optional[ConvergenceState] = None
) -> float:
    """
    Calculate confidence boost based on evidence strength.

    Factors:
    - Trusted EDR source: +0.15
    - Known malware: +0.20
    - Multiple malicious enrichments: +0.10 each
    - High severity: +0.10
    - Corroborating evidence: +0.05 each

    Args:
        base_confidence: Starting confidence
        alert: Alert data (can be None if no alert associated)
        enrichments: Enrichment results
        state: Convergence state

    Returns:
        Boosted confidence (capped at 0.95)
    """
    confidence = base_confidence

    # Handle case where alert is None
    if alert is None:
        return confidence

    raw = alert.get('raw_event') or {}
    if isinstance(raw, str):
        import json
        try:
            raw = json.loads(raw)
        except:
            raw = {}
    # Ensure raw is never None
    if raw is None:
        raw = {}

    source = alert.get('source', '')
    detection_name = raw.get('detection_name', '')
    threat_family = raw.get('threat_family', '')

    # Trusted source boost
    if is_trusted_edr_source(source):
        confidence += 0.15

    # Known malware boost
    if is_known_malware(detection_name, threat_family):
        confidence += 0.20

    # Severity boost
    severity = alert.get('severity', '').lower()
    if severity in ('critical', 'high'):
        confidence += 0.10

    # Enrichment boosts
    if enrichments:
        for key, data in enrichments.items():
            if isinstance(data, dict):
                if data.get('malicious') or data.get('detected'):
                    confidence += 0.10
                if data.get('positives', 0) > 10:
                    confidence += 0.10
                if data.get('abuseConfidenceScore', data.get('score', 0)) > 50:
                    confidence += 0.05

    # Evidence count boost from state
    if state and state.evidence_count > 0:
        confidence += min(state.evidence_count * 0.05, 0.15)

    # Cap at 0.95 (never 100% without human review)
    return min(confidence, 0.95)


def get_escalation_recommendation(
    verdict: str,
    confidence: float,
    tier: int,
    state: ConvergenceState
) -> Dict[str, Any]:
    """
    Get recommendation for next action based on verdict.

    Args:
        verdict: Current verdict
        confidence: Current confidence
        tier: Current tier
        state: Convergence state

    Returns:
        Dict with recommendation details
    """
    recommendation = {
        'action': 'complete',
        'escalate': False,
        'reason': '',
        'next_tier': None,
        'priority': 'normal'
    }

    # True positive / malicious - complete with high priority
    if verdict in ('true_positive', 'malicious'):
        recommendation['action'] = 'complete'
        recommendation['priority'] = 'high'
        recommendation['reason'] = 'Confirmed malicious - immediate response required'
        return recommendation

    # Needs escalation
    if verdict == 'needs_escalation':
        if tier < 3:
            recommendation['action'] = 'escalate'
            recommendation['escalate'] = True
            recommendation['next_tier'] = tier + 1
            recommendation['reason'] = f'Escalating to Tier {tier + 1} for deeper analysis'
            recommendation['priority'] = 'high' if confidence >= 0.7 else 'normal'
        else:
            # T3 can't escalate - force decision
            recommendation['action'] = 'complete'
            recommendation['reason'] = 'T3 maximum - completing with current assessment'
        return recommendation

    # Suspicious with low confidence
    if verdict == 'suspicious':
        if confidence < 0.5 and state.evidence_count < 2:
            recommendation['action'] = 'complete'
            recommendation['reason'] = 'Low confidence suspicious - likely benign'
        elif tier < 3 and (confidence >= 0.6 or state.evidence_count >= 3):
            recommendation['action'] = 'escalate'
            recommendation['escalate'] = True
            recommendation['next_tier'] = tier + 1
            recommendation['reason'] = f'Suspicious with signals - escalating for review'
        else:
            recommendation['action'] = 'complete'
            recommendation['reason'] = 'Completing at current assessment level'
        return recommendation

    # Benign / false positive - complete
    if verdict in ('benign', 'false_positive'):
        recommendation['action'] = 'complete'
        recommendation['priority'] = 'low'
        recommendation['reason'] = 'No threat indicators found'
        return recommendation

    return recommendation


def create_convergence_state(
    alert: Optional[Dict[str, Any]],
    tier: int = 1,
    ml_prediction: Optional[Dict[str, Any]] = None
) -> ConvergenceState:
    """
    Create a convergence state initialized from alert data.

    ML predictions INFORM the initial state but don't override security signals.
    ML never decides alone - it nudges confidence, Riggs reasons.

    Args:
        alert: Alert data (can be None if no alert associated)
        tier: Agent tier
        ml_prediction: Optional ML classifier prediction with:
            - disposition: predicted disposition (benign, suspicious, malicious, etc.)
            - confidence: ML confidence (0.0-1.0)
            - probabilities: per-class probabilities

    Returns:
        Initialized ConvergenceState
    """
    state = ConvergenceState()

    # Handle case where alert is None (e.g., investigation without associated alert)
    if alert is None:
        alert = {}

    raw = alert.get('raw_event') or {}
    if isinstance(raw, str):
        import json
        try:
            raw = json.loads(raw)
        except:
            raw = {}
    # Ensure raw is never None
    if raw is None:
        raw = {}

    source = alert.get('source', '')
    detection_name = raw.get('detection_name', '')
    threat_family = raw.get('threat_family', '')

    state.trusted_source = is_trusted_edr_source(source)
    state.malware_detected = is_known_malware(detection_name, threat_family)

    # Set initial verdict based on alert characteristics
    if state.malware_detected and state.trusted_source:
        state.current_verdict = 'suspicious'
        state.current_confidence = 0.8  # Start high for known malware
    elif state.trusted_source:
        state.current_verdict = 'suspicious'
        state.current_confidence = 0.6
    else:
        state.current_verdict = 'unknown'
        state.current_confidence = 0.5

    # ═══════════════════════════════════════════════════════════════════════════
    # ML LAYER INTEGRATION: ML predictions nudge initial confidence
    # ML never decides alone - it informs, Riggs reasons
    # HARD CAP: ML influence limited to ±15-20% maximum
    # ═══════════════════════════════════════════════════════════════════════════
    MAX_ML_INFLUENCE = 0.15  # Maximum confidence adjustment (±15%)
    ML_CONFIDENCE_THRESHOLD = 0.6  # Minimum ML confidence to apply any nudge

    if ml_prediction and ml_prediction.get('confidence', 0) > ML_CONFIDENCE_THRESHOLD:
        ml_disposition = ml_prediction.get('disposition', '').lower()
        ml_confidence = ml_prediction.get('confidence', 0.5)

        # Only apply ML influence if no hard security signals already present
        if not state.malware_detected:
            # Categorize ML disposition
            benign_dispositions = ('benign', 'false_positive')
            suspicious_dispositions = ('suspicious', 'inconclusive')
            malicious_dispositions = ('malicious', 'true_positive')

            # Calculate nudge based on ML confidence (scaled to max influence)
            # Higher ML confidence = larger nudge, but CAPPED at MAX_ML_INFLUENCE
            confidence_scale = min((ml_confidence - ML_CONFIDENCE_THRESHOLD) / (1.0 - ML_CONFIDENCE_THRESHOLD), 1.0)
            nudge = MAX_ML_INFLUENCE * confidence_scale

            original_confidence = state.current_confidence

            if ml_disposition in benign_dispositions:
                # ML thinks benign - nudge DOWN (lower suspicion)
                state.current_confidence = max(0.3, state.current_confidence - nudge)
            elif ml_disposition in malicious_dispositions:
                # ML thinks malicious - nudge UP (raise suspicion)
                state.current_confidence = min(0.85, state.current_confidence + nudge)
            elif ml_disposition in suspicious_dispositions:
                # ML uncertain - minimal nudge toward suspicious baseline
                if state.current_confidence < 0.5:
                    state.current_confidence = min(0.6, state.current_confidence + nudge * 0.5)

            # Log the ML influence for transparency
            import logging
            logger = logging.getLogger(__name__)
            if abs(state.current_confidence - original_confidence) > 0.01:
                logger.info(
                    f"[ML_INFLUENCE] {ml_disposition}@{ml_confidence:.0%} -> "
                    f"confidence {original_confidence:.0%} -> {state.current_confidence:.0%} "
                    f"(delta: {state.current_confidence - original_confidence:+.0%}, max: ±{MAX_ML_INFLUENCE:.0%})"
                )

    return state


def apply_convergence_rules(
    state: ConvergenceState,
    alert: Dict[str, Any],
    enrichments: Optional[Dict[str, Any]] = None,
    tier: int = 1
) -> Dict[str, Any]:
    """
    Apply all convergence rules and return final recommendation.

    This is the main entry point for convergence logic.

    Args:
        state: Current convergence state
        alert: Alert data
        enrichments: Enrichment results
        tier: Agent tier

    Returns:
        Dict with verdict, confidence, action, and reasoning
    """
    result = {
        'verdict': state.current_verdict,
        'confidence': state.current_confidence,
        'action': 'continue',
        'reason': '',
        'forced': False
    }

    # Check auto-confirm first
    should_auto, auto_verdict, auto_reason = check_auto_confirm(alert, enrichments)
    if should_auto:
        result['verdict'] = auto_verdict
        result['confidence'] = 0.95
        result['action'] = 'complete'
        result['reason'] = auto_reason
        result['forced'] = True
        return result

    # Check force completion
    should_force, force_verdict, force_reason = check_force_completion(state, tier)
    if should_force:
        result['verdict'] = force_verdict
        result['confidence'] = calculate_confidence_boost(
            state.current_confidence, alert, enrichments, state
        )
        result['action'] = 'complete' if force_verdict not in ('needs_escalation',) else 'escalate'
        result['reason'] = force_reason
        result['forced'] = True
        return result

    # Apply confidence boost
    boosted_confidence = calculate_confidence_boost(
        state.current_confidence, alert, enrichments, state
    )
    result['confidence'] = boosted_confidence

    # Get escalation recommendation
    recommendation = get_escalation_recommendation(
        state.current_verdict,
        boosted_confidence,
        tier,
        state
    )

    result['action'] = recommendation['action']
    result['reason'] = recommendation['reason']

    if recommendation['escalate']:
        result['action'] = 'escalate'
        result['next_tier'] = recommendation['next_tier']

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-REMEDIATION GUARDRAILS (Added 2026-01-26 for FP Reduction)
# ═══════════════════════════════════════════════════════════════════════════════

# Verdicts that are NEVER allowed to trigger auto-remediation
# Using canonical Verdict enum values for consistency
REVIEW_ONLY_VERDICTS = {
    Verdict.SUSPICIOUS.value,
    Verdict.NEEDS_INVESTIGATION.value,
    Verdict.UNKNOWN.value,
    Verdict.INCONCLUSIVE.value,
}

# Minimum confidence thresholds for auto-remediation per verdict
# Using canonical Verdict enum values
AUTO_REMEDIATION_THRESHOLDS = {
    Verdict.MALICIOUS.value: 0.85,
    Verdict.TRUE_POSITIVE.value: 0.85,
}

# Threat types that should use phishing-specific evidence validation.
# All other classified threat types (C2, malware, credential, lateral, etc.)
# use behavioral evidence validation instead.
PHISHING_THREAT_TYPES = {
    'phishing', 'social_engineering', 'credential_phishing',
    'brand_impersonation', 'bec', 'spear_phishing',
    'malware_delivery', 'spam',
}


def can_auto_remediate(
    verdict: str,
    confidence: float,
    sender_is_legitimate: bool = False
) -> Tuple[bool, str]:
    """
    Check if a verdict is allowed to trigger automatic remediation.

    GUARDRAIL: Prevents premature auto-remediation for uncertain verdicts.

    Rules:
    1. SUSPICIOUS → NEVER auto-remediate (requires human review)
    2. NEEDS_INVESTIGATION → NEVER auto-remediate
    3. If sender is from legitimate domain → NEVER auto-remediate malicious verdicts
    4. MALICIOUS/TRUE_POSITIVE → Only if confidence >= 0.85
    5. SOCIAL_ENGINEERING → Only if confidence >= 0.85

    Args:
        verdict: The verdict string
        confidence: Confidence score (0.0-1.0)
        sender_is_legitimate: Whether sender domain is verified legitimate

    Returns:
        Tuple of (allowed: bool, reason: str)
    """
    verdict_upper = verdict.upper() if verdict else 'UNKNOWN'

    # Rule 1 & 2: SUSPICIOUS and NEEDS_INVESTIGATION never auto-remediate
    if verdict_upper in REVIEW_ONLY_VERDICTS:
        return False, f"Verdict '{verdict}' requires human review - auto-remediation blocked"

    # Rule 3: If sender is legitimate, block auto-remediation for malicious verdicts
    # This is a safety catch for any edge cases that slip through
    if sender_is_legitimate and verdict_upper in ('MALICIOUS', 'TRUE_POSITIVE', 'SOCIAL_ENGINEERING'):
        return False, f"Sender is from legitimate domain - cannot auto-remediate '{verdict}'"

    # Rule 4 & 5: Check confidence thresholds
    threshold = AUTO_REMEDIATION_THRESHOLDS.get(verdict_upper)
    if threshold is not None:
        if confidence < threshold:
            return False, f"Confidence {confidence:.0%} below threshold {threshold:.0%} for '{verdict}'"
        return True, f"Auto-remediation allowed: {verdict} @ {confidence:.0%}"

    # BENIGN verdicts don't need remediation
    if verdict_upper in ('BENIGN', 'FALSE_POSITIVE'):
        return False, "Benign verdict - no remediation needed"

    # Unknown verdict type - block by default
    return False, f"Unknown verdict type '{verdict}' - auto-remediation blocked for safety"


def validate_phishing_verdict_evidence(
    verdict: str,
    confidence: float,
    sender_domain: Optional[str],
    has_malicious_ioc: bool,
    intent_signals_count: int,
    supporting_signals: List[str],
    sender_is_legitimate: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """
    Validate that a phishing verdict has sufficient evidence.

    GUARDRAIL: Enforces evidence requirements before allowing high-severity verdicts.

    Evidence Requirements:
    - MALICIOUS requires: sender NOT legitimate + (malicious IOC OR credentials compromised) + 2 supporting signals
    - SOCIAL_ENGINEERING requires: sender NOT legitimate + brand impersonation + urgency + credential request + 1 supporting signal
    - SUSPICIOUS: allowed with lower evidence (this is the "uncertain" state)

    Args:
        verdict: The proposed verdict
        confidence: Proposed confidence
        sender_domain: Sender's domain
        has_malicious_ioc: Whether malicious IOC was found in enrichment
        intent_signals_count: Number of intent signals detected
        supporting_signals: List of supporting signals (suspicious_tld, domain_age, auth_failure, etc.)
        sender_is_legitimate: Whether sender is from legitimate brand domain

    Returns:
        Tuple of (is_valid: bool, reason: str, corrected_verdict: Optional[str])
    """
    import logging
    logger = logging.getLogger(__name__)

    verdict_upper = verdict.upper() if verdict else 'UNKNOWN'
    supporting_count = len(supporting_signals)

    # CRITICAL: If sender is legitimate, verdict MUST be BENIGN
    if sender_is_legitimate:
        if verdict_upper in ('MALICIOUS', 'SOCIAL_ENGINEERING', 'SUSPICIOUS'):
            logger.warning(
                f"[EVIDENCE_GUARD] Blocking {verdict} for legitimate sender '{sender_domain}' - forcing BENIGN"
            )
            return False, f"Sender '{sender_domain}' is legitimate - cannot be {verdict}", 'BENIGN'
        return True, "Verdict valid for legitimate sender", None

    # Validate MALICIOUS evidence
    if verdict_upper == 'MALICIOUS':
        if not has_malicious_ioc:
            logger.warning(f"[EVIDENCE_GUARD] MALICIOUS without malicious IOC - downgrading")
            # Downgrade to SUSPICIOUS if intent signals present, else NEEDS_INVESTIGATION
            if intent_signals_count >= 2:
                return False, "MALICIOUS requires malicious IOC - downgraded to SUSPICIOUS", 'SUSPICIOUS'
            return False, "MALICIOUS requires malicious IOC - downgraded to NEEDS_INVESTIGATION", 'NEEDS_INVESTIGATION'

        if supporting_count < 2:
            logger.warning(f"[EVIDENCE_GUARD] MALICIOUS with only {supporting_count} supporting signals")
            if supporting_count >= 1:
                return False, f"MALICIOUS requires 2+ supporting signals (found {supporting_count}) - downgraded to SUSPICIOUS", 'SUSPICIOUS'
            return False, f"MALICIOUS requires 2+ supporting signals - downgraded to NEEDS_INVESTIGATION", 'NEEDS_INVESTIGATION'

        if confidence < 0.85:
            return False, f"MALICIOUS confidence {confidence:.0%} below 85% threshold - downgraded to SUSPICIOUS", 'SUSPICIOUS'

        return True, "MALICIOUS verdict evidence validated", None

    # Validate SOCIAL_ENGINEERING evidence
    if verdict_upper == 'SOCIAL_ENGINEERING':
        if intent_signals_count < 2:
            logger.warning(f"[EVIDENCE_GUARD] SOCIAL_ENGINEERING with only {intent_signals_count} intent signals")
            return False, f"SOCIAL_ENGINEERING requires 2+ intent signals - downgraded to SUSPICIOUS", 'SUSPICIOUS'

        if supporting_count < 1:
            logger.warning(f"[EVIDENCE_GUARD] SOCIAL_ENGINEERING with no supporting signals")
            return False, "SOCIAL_ENGINEERING requires 1+ supporting signal - downgraded to SUSPICIOUS", 'SUSPICIOUS'

        if confidence < 0.80:
            return False, f"SOCIAL_ENGINEERING confidence {confidence:.0%} below 80% threshold - downgraded to SUSPICIOUS", 'SUSPICIOUS'

        return True, "SOCIAL_ENGINEERING verdict evidence validated", None

    # SUSPICIOUS doesn't require additional validation - it's the "uncertain" state
    if verdict_upper == 'SUSPICIOUS':
        return True, "SUSPICIOUS verdict accepted - requires human review", None

    # Other verdicts pass through
    return True, f"Verdict {verdict} accepted", None


def validate_non_phishing_verdict(
    verdict: str,
    confidence: float,
    key_findings: List[str],
) -> Tuple[bool, str, Optional[str]]:
    """
    Validate verdict evidence for non-phishing threats (C2, malware, credential,
    lateral movement, exfiltration, persistence, etc.).

    For these threat types, behavioral evidence from key_findings IS the primary
    signal. We do NOT require enrichment-confirmed IOCs or phishing intent keywords.

    Rules:
    - MALICIOUS: requires confidence >= 0.70 AND 2+ key_findings
    - SUSPICIOUS: accepted at any confidence
    - SOCIAL_ENGINEERING: downgraded to SUSPICIOUS (wrong verdict for non-phishing)
    - Others: pass through
    """
    import logging
    logger = logging.getLogger(__name__)

    verdict_upper = verdict.upper() if verdict else 'UNKNOWN'
    findings_count = len([f for f in key_findings if isinstance(f, str) and len(f.strip()) > 0])

    if verdict_upper == 'MALICIOUS':
        if confidence < 0.70:
            logger.warning(
                f"[NON_PHISHING_GUARD] MALICIOUS with confidence {confidence:.0%} < 70% - "
                f"downgrading to SUSPICIOUS"
            )
            return False, (
                f"Non-phishing MALICIOUS requires confidence >= 70% "
                f"(got {confidence:.0%}) - downgraded to SUSPICIOUS"
            ), 'SUSPICIOUS'

        if findings_count < 2:
            logger.warning(
                f"[NON_PHISHING_GUARD] MALICIOUS with only {findings_count} key_findings - "
                f"downgrading to SUSPICIOUS"
            )
            return False, (
                f"Non-phishing MALICIOUS requires 2+ key_findings "
                f"(got {findings_count}) - downgraded to SUSPICIOUS"
            ), 'SUSPICIOUS'

        return True, f"Non-phishing MALICIOUS validated: confidence {confidence:.0%}, {findings_count} findings", None

    if verdict_upper == 'SOCIAL_ENGINEERING':
        logger.warning(
            f"[NON_PHISHING_GUARD] SOCIAL_ENGINEERING verdict on non-phishing threat - "
            f"downgrading to SUSPICIOUS"
        )
        return False, "SOCIAL_ENGINEERING invalid for non-phishing threat type - downgraded to SUSPICIOUS", 'SUSPICIOUS'

    if verdict_upper == 'SUSPICIOUS':
        return True, "SUSPICIOUS verdict accepted for non-phishing threat - requires human review", None

    return True, f"Verdict {verdict} accepted for non-phishing threat", None


def apply_verdict_guardrails(
    triage_result: Dict[str, Any],
    sender_domain: Optional[str] = None,
    sender_is_legitimate: bool = False,
    enrichment_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Apply all verdict guardrails to a triage result.

    This is the main entry point for verdict validation after LLM triage.
    It ensures:
    1. Evidence requirements are met for high-severity verdicts
    2. Auto-remediation is blocked for uncertain verdicts
    3. Legitimate senders are not marked as malicious

    Args:
        triage_result: The triage result from LLM
        sender_domain: Sender's domain
        sender_is_legitimate: Whether sender is from legitimate brand domain
        enrichment_data: IOC enrichment data

    Returns:
        Modified triage result with guardrails applied
    """
    import logging
    logger = logging.getLogger(__name__)

    result = triage_result.copy()
    verdict = result.get('verdict', 'unknown')
    confidence = result.get('confidence', 0.5)

    # ═══════════════════════════════════════════════════════════════════════════
    # THREAT-TYPE ROUTING: Use appropriate validation for threat category
    # ═══════════════════════════════════════════════════════════════════════════
    threat_type = result.get('threat_type', 'unknown').lower().strip()

    # Non-phishing threats (C2, malware, credential, lateral, exfil, etc.)
    # use behavioral evidence validation — NOT phishing-specific checks
    is_phishing_threat = (
        threat_type in PHISHING_THREAT_TYPES
        or threat_type in ('none', 'unknown', '')
    )

    if not is_phishing_threat:
        logger.info(
            f"[VERDICT_GUARDRAIL] Non-phishing threat_type='{threat_type}' - "
            f"using behavioral evidence validation"
        )
        key_findings = result.get('key_findings', [])

        is_valid, reason, corrected_verdict = validate_non_phishing_verdict(
            verdict=verdict,
            confidence=confidence,
            key_findings=key_findings,
        )

        if not is_valid and corrected_verdict:
            logger.warning(f"[VERDICT_GUARDRAIL] {verdict} -> {corrected_verdict}: {reason}")
            result['verdict'] = corrected_verdict
            result['verdict_corrected'] = True
            result['original_verdict'] = verdict
            result['correction_reason'] = reason
            if corrected_verdict == 'SUSPICIOUS':
                result['confidence'] = min(confidence, 0.75)
            elif corrected_verdict == 'NEEDS_INVESTIGATION':
                result['confidence'] = min(confidence, 0.55)

        # Check auto-remediation eligibility
        final_verdict = result.get('verdict', 'unknown')
        final_confidence = result.get('confidence', 0.5)
        can_remediate, remediation_reason = can_auto_remediate(
            verdict=final_verdict,
            confidence=final_confidence,
            sender_is_legitimate=False
        )
        result['auto_remediation_allowed'] = can_remediate
        result['auto_remediation_reason'] = remediation_reason

        if final_verdict.upper() == 'SUSPICIOUS':
            uncertainty_factors = result.get('uncertainty_factors', [])
            if not uncertainty_factors:
                uncertainty_factors = [
                    "Behavioral indicators present but insufficient for high-confidence verdict",
                    "Requires human review before any remediation action"
                ]
            result['uncertainty_factors'] = uncertainty_factors
            result['requires_human_review'] = True

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # PHISHING PATH: Original phishing-specific evidence validation
    # ═══════════════════════════════════════════════════════════════════════════

    # Extract evidence info
    has_malicious_ioc = False
    if enrichment_data:
        summary = enrichment_data.get('summary', {})
        has_malicious_ioc = summary.get('malicious', 0) > 0

    # Count intent signals from key_findings
    intent_signals_count = 0
    key_findings = result.get('key_findings', [])
    intent_keywords = ['urgency', 'credential', 'brand impersonation', 'phishing', 'spoofing']
    for finding in key_findings:
        if isinstance(finding, str):
            if any(kw in finding.lower() for kw in intent_keywords):
                intent_signals_count += 1

    # Extract supporting signals
    supporting_signals = []
    risk_factors = result.get('risk_factors', [])
    for factor in risk_factors:
        if isinstance(factor, str):
            supporting_signals.append(factor)

    # Validate evidence requirements
    is_valid, reason, corrected_verdict = validate_phishing_verdict_evidence(
        verdict=verdict,
        confidence=confidence,
        sender_domain=sender_domain,
        has_malicious_ioc=has_malicious_ioc,
        intent_signals_count=intent_signals_count,
        supporting_signals=supporting_signals,
        sender_is_legitimate=sender_is_legitimate
    )

    if not is_valid and corrected_verdict:
        logger.warning(f"[VERDICT_GUARDRAIL] {verdict} -> {corrected_verdict}: {reason}")
        result['verdict'] = corrected_verdict
        result['verdict_corrected'] = True
        result['original_verdict'] = verdict
        result['correction_reason'] = reason
        # Adjust confidence for downgraded verdicts
        if corrected_verdict == 'SUSPICIOUS':
            result['confidence'] = min(confidence, 0.75)
        elif corrected_verdict == 'NEEDS_INVESTIGATION':
            result['confidence'] = min(confidence, 0.55)
        elif corrected_verdict == 'BENIGN':
            result['confidence'] = max(confidence, 0.85)

    # Check auto-remediation eligibility
    final_verdict = result.get('verdict', 'unknown')
    final_confidence = result.get('confidence', 0.5)
    can_remediate, remediation_reason = can_auto_remediate(
        verdict=final_verdict,
        confidence=final_confidence,
        sender_is_legitimate=sender_is_legitimate
    )

    result['auto_remediation_allowed'] = can_remediate
    result['auto_remediation_reason'] = remediation_reason

    # Add uncertainty factors for SUSPICIOUS verdict
    if final_verdict.upper() == 'SUSPICIOUS':
        uncertainty_factors = result.get('uncertainty_factors', [])
        if not uncertainty_factors:
            uncertainty_factors = [
                "Sender domain not verified as legitimate or malicious",
                "Intent signals present but insufficient evidence for high-confidence verdict",
                "Requires human review before any remediation action"
            ]
        result['uncertainty_factors'] = uncertainty_factors
        result['requires_human_review'] = True

    return result
