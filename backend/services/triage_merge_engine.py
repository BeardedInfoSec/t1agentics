# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Two-Track Triage Merge Engine

Implements the merge rules for combining provisional (FAST) verdicts
with enrichment results to produce final confirmed verdicts.

Core principles:
1. Never downgrade severity before enrichment completes
2. MALICIOUS provisional can only stay MALICIOUS or go NEEDS_REVIEW
3. Enrichment can only: increase confidence, trigger escalation, or mark NEEDS_REVIEW
4. Auto-downgrade to BENIGN only if confidence >= 95 and no high-risk indicators
"""

import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Use canonical Verdict enum from models.verdict (single source of truth)
from models.verdict import Verdict, get_verdict_severity

logger = logging.getLogger(__name__)


class TriageStatus(Enum):
    NOT_STARTED = "not_started"
    PROVISIONAL = "provisional"
    ENRICHING = "enriching"
    MERGE_PENDING = "merge_pending"
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"


@dataclass
class ProvisionalVerdict:
    """Output from FAST triage (Track A)."""
    verdict: str
    confidence: float  # 0-100
    reasoning_summary: str
    actions_suggested: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EnrichmentResult:
    """Aggregated enrichment results (Track B)."""
    total_iocs: int
    completed_iocs: int
    progress_percent: int
    high_risk_hits: int  # IOCs with malicious verdict
    medium_risk_hits: int  # IOCs with suspicious verdict
    sources_flagged: List[str] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MergeResult:
    """Output from merge engine."""
    final_verdict: str
    final_confidence: float
    delta_explanation: str  # What changed and why
    should_escalate_to_deep: bool
    needs_human_review: bool
    merge_version: int
    evidence_summary: Dict[str, Any] = field(default_factory=dict)


# Verdict severity levels (higher = more severe)
# Using canonical Verdict enum values for consistency
VERDICT_SEVERITY = {
    Verdict.MALICIOUS.value: 5,
    Verdict.TRUE_POSITIVE.value: 5,
    Verdict.SUSPICIOUS.value: 4,
    Verdict.NEEDS_INVESTIGATION.value: 3,
    Verdict.INCONCLUSIVE.value: 2,
    Verdict.BENIGN.value: 1,
    Verdict.FALSE_POSITIVE.value: 1,
    Verdict.BENIGN_POSITIVE.value: 1,
    Verdict.UNKNOWN.value: 0
}


class TriageMergeEngine:
    """
    Merges provisional verdicts with enrichment results.

    Merge rules:
    - Never downgrade before enrichment completes (80%+ IOCs enriched)
    - MALICIOUS can only stay MALICIOUS or go NEEDS_REVIEW until enrichment
    - Auto-upgrade to MALICIOUS if confidence >= 90 with strong signals
    - Auto-downgrade to BENIGN only if confidence >= 95 and no high-risk indicators
    """

    # Thresholds
    ENRICHMENT_COMPLETE_THRESHOLD = 80  # % of IOCs needed for "complete"
    ENRICHMENT_TIMEOUT_SECONDS = 8  # Force merge after this timeout
    AUTO_UPGRADE_MALICIOUS_CONFIDENCE = 90
    AUTO_DOWNGRADE_BENIGN_CONFIDENCE = 95
    ESCALATE_TO_DEEP_CONFIDENCE_MIN = 40
    ESCALATE_TO_DEEP_CONFIDENCE_MAX = 75

    # DEEP triggers
    DEEP_TRIGGERS = [
        "confidence_in_uncertain_range",  # 40-75%
        "decoded_content_exists",
        "lateral_movement_indicators",
        "multiple_hosts_involved",
        "multiple_users_involved",
        "enrichment_high_risk_hit",
    ]

    def __init__(self):
        self._postgres = None

    async def initialize(self):
        """Initialize database connection."""
        if self._postgres is None:
            from services.postgres_db import postgres_db
            self._postgres = postgres_db

    async def merge(
        self,
        investigation_id: str,
        provisional: ProvisionalVerdict,
        enrichment: EnrichmentResult,
        raw_context: Optional[Dict[str, Any]] = None
    ) -> MergeResult:
        """
        Execute merge of provisional verdict with enrichment results.

        Args:
            investigation_id: Investigation ID
            provisional: Provisional verdict from FAST triage
            enrichment: Aggregated enrichment results
            raw_context: Optional raw alert/investigation context

        Returns:
            MergeResult with final verdict and delta explanation
        """
        await self.initialize()

        # Check if enrichment is complete enough
        enrichment_complete = enrichment.progress_percent >= self.ENRICHMENT_COMPLETE_THRESHOLD

        # Detect DEEP triggers
        deep_triggers = self._detect_deep_triggers(provisional, enrichment, raw_context)
        should_escalate = len(deep_triggers) > 0

        # Calculate confidence delta from enrichment
        confidence_delta = self._calculate_confidence_delta(enrichment)

        # Start with provisional values
        final_verdict = provisional.verdict
        final_confidence = provisional.confidence + confidence_delta
        final_confidence = max(0, min(100, final_confidence))  # Clamp to 0-100

        # Apply merge rules
        needs_human_review = False
        delta_reasons = []

        # Rule 1: High-risk enrichment hits upgrade to MALICIOUS
        if enrichment.high_risk_hits > 0:
            if final_verdict not in ["MALICIOUS", "TRUE_POSITIVE"]:
                if final_confidence >= self.AUTO_UPGRADE_MALICIOUS_CONFIDENCE:
                    delta_reasons.append(
                        f"Upgraded to MALICIOUS: {enrichment.high_risk_hits} high-risk IOC(s) detected "
                        f"with confidence {final_confidence:.0f}%"
                    )
                    final_verdict = "MALICIOUS"
                else:
                    delta_reasons.append(
                        f"High-risk IOCs detected but confidence ({final_confidence:.0f}%) below threshold. "
                        f"Marking NEEDS_REVIEW."
                    )
                    needs_human_review = True

        # Rule 2: Check for downgrade attempt (prohibited before enrichment complete)
        if not enrichment_complete:
            if self._is_downgrade(provisional.verdict, final_verdict):
                logger.warning(
                    f"[MERGE] Blocked downgrade from {provisional.verdict} to {final_verdict} "
                    f"(enrichment {enrichment.progress_percent}% < {self.ENRICHMENT_COMPLETE_THRESHOLD}%)"
                )
                final_verdict = provisional.verdict
                delta_reasons.append(
                    f"Downgrade blocked: Enrichment incomplete ({enrichment.progress_percent}%). "
                    f"Maintaining {provisional.verdict}."
                )
                needs_human_review = True

        # Rule 3: MALICIOUS can only go to NEEDS_REVIEW (not BENIGN) before full enrichment
        if provisional.verdict == "MALICIOUS" and not enrichment_complete:
            if final_verdict not in ["MALICIOUS", "TRUE_POSITIVE"]:
                final_verdict = provisional.verdict  # Keep MALICIOUS
                needs_human_review = True
                delta_reasons.append(
                    f"MALICIOUS verdict maintained (enrichment incomplete). "
                    f"Flagged for review."
                )

        # Rule 4: Auto-downgrade to BENIGN only with very high confidence
        if final_verdict in ["BENIGN", "FALSE_POSITIVE"]:
            if final_confidence < self.AUTO_DOWNGRADE_BENIGN_CONFIDENCE:
                needs_human_review = True
                delta_reasons.append(
                    f"Auto-close blocked: Confidence {final_confidence:.0f}% < {self.AUTO_DOWNGRADE_BENIGN_CONFIDENCE}% "
                    f"required for benign verdict."
                )
            elif enrichment.high_risk_hits > 0:
                # Can't be BENIGN with high-risk IOCs
                final_verdict = "SUSPICIOUS"
                needs_human_review = True
                delta_reasons.append(
                    f"Benign override blocked: {enrichment.high_risk_hits} high-risk IOC(s) present."
                )

        # Rule 5: Conflicting signals → NEEDS_REVIEW
        if self._has_conflicting_signals(provisional, enrichment):
            needs_human_review = True
            delta_reasons.append(
                f"Conflicting signals detected between provisional verdict and enrichment."
            )

        # Build delta explanation
        if not delta_reasons:
            if enrichment_complete:
                delta_reasons.append(f"Enrichment complete. Verdict confirmed: {final_verdict}.")
            else:
                delta_reasons.append(
                    f"Enrichment {enrichment.progress_percent}% complete. "
                    f"Provisional verdict maintained."
                )

        # Add confidence change explanation
        if abs(confidence_delta) >= 5:
            delta_reasons.append(
                f"Confidence adjusted by {confidence_delta:+.0f}% based on enrichment "
                f"({enrichment.high_risk_hits} high-risk, {enrichment.medium_risk_hits} medium-risk hits)."
            )

        # Build evidence summary
        evidence_summary = {
            "provisional_verdict": provisional.verdict,
            "provisional_confidence": provisional.confidence,
            "enrichment_progress": enrichment.progress_percent,
            "high_risk_iocs": enrichment.high_risk_hits,
            "medium_risk_iocs": enrichment.medium_risk_hits,
            "sources_flagged": enrichment.sources_flagged,
            "key_findings": enrichment.key_findings,
            "deep_triggers": deep_triggers,
            "enrichment_complete": enrichment_complete
        }

        # Get current merge version
        merge_version = await self._get_next_merge_version(investigation_id)

        result = MergeResult(
            final_verdict=final_verdict,
            final_confidence=final_confidence,
            delta_explanation=" | ".join(delta_reasons),
            should_escalate_to_deep=should_escalate and not needs_human_review,
            needs_human_review=needs_human_review,
            merge_version=merge_version,
            evidence_summary=evidence_summary
        )

        # Persist merge result
        await self._persist_merge(investigation_id, result, provisional, enrichment)

        logger.info(
            f"[MERGE] Investigation {investigation_id}: "
            f"{provisional.verdict}→{final_verdict} "
            f"(conf: {provisional.confidence:.0f}%→{final_confidence:.0f}%, "
            f"enrichment: {enrichment.progress_percent}%, "
            f"review: {needs_human_review}, deep: {should_escalate})"
        )

        return result

    def _is_downgrade(self, from_verdict: str, to_verdict: str) -> bool:
        """Check if this is a severity downgrade."""
        from_severity = VERDICT_SEVERITY.get(from_verdict.upper(), 0)
        to_severity = VERDICT_SEVERITY.get(to_verdict.upper(), 0)
        return to_severity < from_severity

    def _calculate_confidence_delta(self, enrichment: EnrichmentResult) -> float:
        """Calculate confidence adjustment from enrichment results."""
        delta = 0.0

        # High-risk hits increase confidence
        if enrichment.high_risk_hits > 0:
            delta += min(20, enrichment.high_risk_hits * 8)  # +8% per hit, max +20%

        # Medium-risk hits slightly increase confidence
        if enrichment.medium_risk_hits > 0:
            delta += min(10, enrichment.medium_risk_hits * 3)  # +3% per hit, max +10%

        # No hits from known sources slightly decrease confidence
        if enrichment.high_risk_hits == 0 and enrichment.medium_risk_hits == 0:
            if enrichment.completed_iocs > 0:
                delta -= 5  # -5% if all IOCs came back clean

        return delta

    def _detect_deep_triggers(
        self,
        provisional: ProvisionalVerdict,
        enrichment: EnrichmentResult,
        raw_context: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Detect conditions that should trigger DEEP analysis."""
        triggers = []

        # Confidence in uncertain range
        if self.ESCALATE_TO_DEEP_CONFIDENCE_MIN <= provisional.confidence <= self.ESCALATE_TO_DEEP_CONFIDENCE_MAX:
            triggers.append("confidence_in_uncertain_range")

        # High-risk enrichment hits
        if enrichment.high_risk_hits > 0:
            triggers.append("enrichment_high_risk_hit")

        # Check raw context for additional triggers
        if raw_context:
            # Decoded content exists
            if raw_context.get("decoded_content") or raw_context.get("_extracted", {}).get("decoded"):
                triggers.append("decoded_content_exists")

            # Multiple hosts
            hosts = raw_context.get("affected_hosts", [])
            if len(hosts) > 1:
                triggers.append("multiple_hosts_involved")

            # Multiple users
            users = raw_context.get("affected_users", [])
            if len(users) > 1:
                triggers.append("multiple_users_involved")

            # Lateral movement indicators
            mitre = raw_context.get("mitre_techniques", [])
            lateral_techniques = ["T1021", "T1550", "T1072", "T1570"]  # Common lateral movement
            if any(t.startswith(lat) for t in mitre for lat in lateral_techniques):
                triggers.append("lateral_movement_indicators")

            # Check missing evidence requests
            if provisional.missing_evidence:
                for missing in provisional.missing_evidence:
                    if "lateral" in missing.lower() or "spread" in missing.lower():
                        triggers.append("lateral_movement_indicators")
                        break

        return triggers

    def _has_conflicting_signals(
        self,
        provisional: ProvisionalVerdict,
        enrichment: EnrichmentResult
    ) -> bool:
        """Check if provisional verdict conflicts with enrichment."""
        # BENIGN provisional but high-risk IOCs found
        if provisional.verdict in ["BENIGN", "FALSE_POSITIVE"]:
            if enrichment.high_risk_hits > 0:
                return True

        # MALICIOUS provisional but all IOCs clean
        if provisional.verdict == "MALICIOUS":
            if enrichment.completed_iocs > 0 and enrichment.high_risk_hits == 0 and enrichment.medium_risk_hits == 0:
                return True

        return False

    async def _get_next_merge_version(self, investigation_id: str) -> int:
        """Get next merge version for an investigation."""
        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT merge_version FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                if row:
                    return (row['merge_version'] or 0) + 1
                return 1
        except Exception as e:
            logger.error(f"Failed to get merge version: {e}")
            return 1

    async def _persist_merge(
        self,
        investigation_id: str,
        result: MergeResult,
        provisional: ProvisionalVerdict,
        enrichment: EnrichmentResult
    ) -> None:
        """Persist merge result to database."""
        try:
            import json
            async with self._postgres.tenant_acquire() as conn:
                # Determine new triage status
                if result.needs_human_review:
                    new_status = 'needs_review'
                    new_state = 'NEEDS_REVIEW'
                elif enrichment.progress_percent >= self.ENRICHMENT_COMPLETE_THRESHOLD:
                    new_status = 'confirmed'
                    new_state = 'CONFIRMED'
                else:
                    new_status = 'provisional'
                    new_state = 'TRIAGE_PROVISIONAL'

                # Build verdict delta entry
                delta_entry = {
                    "version": result.merge_version,
                    "timestamp": datetime.utcnow().isoformat(),
                    "provisional_verdict": provisional.verdict,
                    "provisional_confidence": provisional.confidence,
                    "final_verdict": result.final_verdict,
                    "final_confidence": result.final_confidence,
                    "delta_explanation": result.delta_explanation,
                    "enrichment_progress": enrichment.progress_percent,
                    "high_risk_hits": enrichment.high_risk_hits
                }

                # Update investigation
                await conn.execute("""
                    UPDATE investigations SET
                        state = $2::varchar,
                        triage_status = $3::varchar,
                        disposition = $4::varchar,
                        confidence = $5,
                        final_verdict = $6::varchar,
                        final_confidence = $7,
                        final_reasoning = $8,
                        enrichment_progress = $9,
                        enrichment_completed_iocs = $10,
                        enrichment_high_risk_hits = $11,
                        merge_version = $12,
                        last_merge_at = NOW(),
                        verdict_delta = COALESCE(verdict_delta, '[]'::jsonb) || $13::jsonb,
                        updated_at = NOW(),
                        confirmed_at = CASE WHEN $3::varchar = 'confirmed' THEN NOW() ELSE confirmed_at END
                    WHERE investigation_id = $1
                """,
                    investigation_id,
                    new_state,
                    new_status,
                    result.final_verdict,
                    result.final_confidence,
                    result.final_verdict,
                    result.final_confidence,
                    result.delta_explanation,
                    enrichment.progress_percent,
                    enrichment.completed_iocs,
                    enrichment.high_risk_hits,
                    result.merge_version,
                    json.dumps([delta_entry])
                )

                # Log to audit table
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                await conn.execute("""
                    INSERT INTO verdict_audit_log (
                        investigation_id,
                        change_type,
                        previous_verdict,
                        previous_confidence,
                        new_verdict,
                        new_confidence,
                        reason,
                        evidence_summary,
                        triggered_by,
                        merge_version,
                        tenant_id
                    )
                    SELECT
                        id,
                        'merge_executed',
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        'merge_engine',
                        $8,
                        $9
                    FROM investigations WHERE investigation_id = $1
                """,
                    investigation_id,
                    provisional.verdict,
                    provisional.confidence,
                    result.final_verdict,
                    result.final_confidence,
                    result.delta_explanation,
                    json.dumps(result.evidence_summary),
                    result.merge_version,
                    _tid
                )

                logger.info(f"[MERGE] Persisted merge v{result.merge_version} for {investigation_id}")

        except Exception as e:
            logger.error(f"Failed to persist merge for {investigation_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())


# Singleton instance
_merge_engine = None


def get_merge_engine() -> TriageMergeEngine:
    """Get the singleton merge engine instance."""
    global _merge_engine
    if _merge_engine is None:
        _merge_engine = TriageMergeEngine()
    return _merge_engine
