# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Hypothesis-Driven Correlation Service (v3.0)

This service implements the hypothesis-driven correlation algorithm.
It replaces entity-based correlation with evidence-based correlation.

Guiding Principle: "It is better to miss a correlation than to create a false one."

Key Changes from v2:
- Entities (user, host) are used for VALIDATION only, not scoring
- Scoring is based on evidence: malicious IOCs, MITRE chains, causal sequences
- Cross-domain correlation is BLOCKED by default
- Soft-join by default; hard-join requires strong evidence or analyst confirmation
- Every decision is explainable with why_correlated
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
from enum import Enum

from services.hypothesis_matcher import get_hypothesis_matcher, HypothesisMatchResult
from services.evidence_scorer import get_evidence_scorer, ScoringResult, ScoringConfig
from services.correlation_explainer import get_correlation_explainer, CorrelationExplanation

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

class CorrelationConfig:
    """
    Configuration for hypothesis-driven correlation.

    Loads from correlation_settings table per-tenant, falls back to env vars.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        s = settings or {}
        self.ENABLE_HYPOTHESIS_CORRELATION = s.get(
            'correlation_enabled',
            os.getenv('ENABLE_HYPOTHESIS_CORRELATION', 'true').lower() == 'true'
        )
        self.AI_HYPOTHESIS_ENABLED = s.get(
            'ai_hypothesis_enabled', True
        )
        self.MAX_TIME_WINDOW_HOURS = s.get(
            'time_window_hours',
            int(os.getenv('CORRELATION_MAX_TIME_WINDOW_HOURS', '24'))
        )
        self.MAX_ALERTS_PER_INVESTIGATION = s.get(
            'max_alerts_per_investigation',
            int(os.getenv('CORRELATION_MAX_ALERTS', '25'))
        )
        self.MAX_USERS_PER_INVESTIGATION = int(os.getenv('CORRELATION_MAX_USERS', '5'))
        self.MAX_HOSTS_PER_INVESTIGATION = int(os.getenv('CORRELATION_MAX_HOSTS', '10'))
        self.ALLOW_CROSS_DOMAIN = s.get(
            'allow_cross_domain',
            os.getenv('CORRELATION_ALLOW_CROSS_DOMAIN', 'false').lower() == 'true'
        )
        self.MINIMUM_EVIDENCE_SCORE = s.get(
            'min_evidence_score',
            int(os.getenv('CORRELATION_MINIMUM_EVIDENCE', '40'))
        )
        self.AUTO_CONFIRM_THRESHOLD = s.get(
            'auto_confirm_threshold',
            int(os.getenv('CORRELATION_AUTO_CONFIRM_THRESHOLD', '100'))
        )
        self.SUGGESTED_TIMEOUT_HOURS = int(os.getenv('CORRELATION_SUGGESTED_TIMEOUT_HOURS', '48'))


# ============================================================================
# Domain Definitions
# ============================================================================

class ThreatDomain:
    """Threat domain classifications."""
    EMAIL = 'EMAIL'
    ENDPOINT = 'ENDPOINT'
    IDENTITY = 'IDENTITY'
    NETWORK = 'NETWORK'
    CLOUD = 'CLOUD'

    # Domain isolation rules
    ALLOWED_CORRELATIONS = {
        'EMAIL': ['EMAIL'],
        'ENDPOINT': ['ENDPOINT'],
        'IDENTITY': ['IDENTITY'],
        'NETWORK': ['NETWORK', 'ENDPOINT'],  # Network can cross to endpoint
        'CLOUD': ['CLOUD'],
    }


# ============================================================================
# Data Classes
# ============================================================================

class DecisionType(Enum):
    """Correlation decision types."""
    SUGGESTED = 'SUGGESTED'      # Soft-link created
    CONFIRMED = 'CONFIRMED'      # Hard-link (auto-confirmed)
    REJECTED = 'REJECTED'        # Blocked by gate or hypothesis
    CREATE_NEW = 'CREATE_NEW'    # New investigation created
    STANDALONE = 'STANDALONE'    # Alert remains standalone


@dataclass
class CorrelationResult:
    """Result of correlation attempt."""
    decision: DecisionType
    investigation_id: Optional[str] = None
    investigation_number: Optional[str] = None
    score: int = 0
    relationship_type: str = 'CONTEXT_ONLY'
    hypothesis_support: str = 'COMPATIBLE'
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    gates_passed: List[str] = field(default_factory=list)
    gates_failed: List[str] = field(default_factory=list)
    why_correlated: str = ''
    reason: str = ''
    processing_time_ms: int = 0


@dataclass
class EligibilityGateResult:
    """Result of eligibility gate check."""
    passed: bool
    gate_name: str
    reason: str = ''


# ============================================================================
# Hypothesis Correlation Service
# ============================================================================

class HypothesisCorrelationService:
    """
    Hypothesis-driven correlation service (v3.0).

    Implements the complete correlation algorithm:
    1. Eligibility Gates (binary - all must pass)
    2. Hypothesis Matching (mandatory)
    3. Evidence-Based Scoring (not entity-based)
    4. Entity Validation (NOT scoring)
    5. Decision (soft-link or auto-confirm)
    """

    def __init__(self, db=None):
        self.db = db
        self.config = CorrelationConfig()
        self.hypothesis_matcher = get_hypothesis_matcher()
        self.evidence_scorer = get_evidence_scorer()
        self.explainer = get_correlation_explainer()
        self._config_cache: Dict[str, Tuple[CorrelationConfig, float]] = {}
        self._config_cache_ttl = 300  # 5 minutes

    def set_db(self, db):
        """Set database connection."""
        self.db = db

    async def _load_tenant_config(self, tenant_id: str) -> CorrelationConfig:
        """
        Load correlation config from DB for a tenant, cached with 5-min TTL.
        Falls back to env-var defaults if no DB settings exist.
        """
        now = time.time()
        cached = self._config_cache.get(tenant_id)
        if cached and (now - cached[1]) < self._config_cache_ttl:
            return cached[0]

        try:
            pool = await self._get_pool()
            if pool:
                async with pool.tenant_acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT * FROM correlation_settings WHERE tenant_id = $1::uuid",
                        tenant_id
                    )
                    if row:
                        config = CorrelationConfig(dict(row))
                        self._config_cache[tenant_id] = (config, now)
                        return config
        except Exception as e:
            logger.debug(f"Could not load tenant correlation settings: {e}")

        config = CorrelationConfig()
        self._config_cache[tenant_id] = (config, now)
        return config

    async def correlate_alert(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        create_investigation: bool = True
    ) -> CorrelationResult:
        """
        Main entry point: Correlate an alert using hypothesis-driven logic.

        Args:
            alert_id: Alert identifier
            alert_data: Full alert data dictionary
            create_investigation: Whether to create new investigation if no match

        Returns:
            CorrelationResult with decision and details
        """
        start_time = time.time()

        try:
            logger.info(f"Alert {alert_id}: Starting hypothesis-driven correlation")

            # Get database connection
            pool = await self._get_pool()
            if not pool:
                logger.warning(f"Alert {alert_id}: No database pool, creating standalone")
                return CorrelationResult(
                    decision=DecisionType.STANDALONE,
                    reason="Database unavailable"
                )

            async with pool.tenant_acquire() as conn:
                # Load tenant-specific config
                tenant_id = alert_data.get('tenant_id')
                if tenant_id:
                    self.config = await self._load_tenant_config(str(tenant_id))

                if not self.config.ENABLE_HYPOTHESIS_CORRELATION:
                    return CorrelationResult(
                        decision=DecisionType.STANDALONE,
                        reason="Correlation disabled for this tenant"
                    )

                # Extract alert properties
                alert_domain = self._classify_threat_domain(alert_data)
                alert_time = self._get_alert_time(alert_data)

                # Find candidate investigations
                candidates = await self._find_candidate_investigations(
                    conn, alert_data, alert_domain, alert_time
                )

                if not candidates:
                    logger.info(f"Alert {alert_id}: No candidate investigations found")
                    if create_investigation:
                        return await self._create_new_investigation(
                            conn, alert_id, alert_data, alert_domain, start_time
                        )
                    return CorrelationResult(
                        decision=DecisionType.STANDALONE,
                        reason="No matching investigations found",
                        processing_time_ms=int((time.time() - start_time) * 1000)
                    )

                # Evaluate each candidate
                best_match = None
                best_score = 0

                for candidate in candidates:
                    result = await self._evaluate_candidate(
                        alert_data, candidate, alert_domain, alert_time
                    )

                    if result and result.score > best_score:
                        best_score = result.score
                        best_match = result

                # Decision based on best match
                if best_match and best_match.decision != DecisionType.REJECTED:
                    # Create correlation link
                    await self._create_correlation_link(
                        conn, alert_id, best_match
                    )

                    # Record audit
                    await self._record_audit(
                        conn, alert_id, best_match
                    )

                    processing_time = int((time.time() - start_time) * 1000)
                    best_match.processing_time_ms = processing_time

                    logger.info(
                        f"Alert {alert_id}: Correlated to {best_match.investigation_number} "
                        f"(decision={best_match.decision.value}, score={best_match.score})"
                    )
                    return best_match

                # No valid match - create new investigation or standalone
                if create_investigation:
                    return await self._create_new_investigation(
                        conn, alert_id, alert_data, alert_domain, start_time
                    )

                return CorrelationResult(
                    decision=DecisionType.STANDALONE,
                    reason="No matching investigations met threshold",
                    processing_time_ms=int((time.time() - start_time) * 1000)
                )

        except Exception as e:
            logger.error(f"Alert {alert_id}: Correlation failed - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return CorrelationResult(
                decision=DecisionType.STANDALONE,
                reason=f"Error: {str(e)}",
                processing_time_ms=int((time.time() - start_time) * 1000)
            )

    async def _evaluate_candidate(
        self,
        alert: Dict[str, Any],
        candidate: Dict[str, Any],
        alert_domain: str,
        alert_time: datetime
    ) -> Optional[CorrelationResult]:
        """
        Evaluate a candidate investigation for correlation.

        Implements the 5-phase algorithm:
        1. Eligibility Gates
        2. Hypothesis Matching
        3. Evidence-Based Scoring
        4. Entity Validation
        5. Decision
        """
        gates_passed = []
        gates_failed = []
        inv_id = str(candidate.get('id', ''))
        inv_number = candidate.get('investigation_id', '')

        # =====================================================================
        # PHASE 1: ELIGIBILITY GATES (all must pass)
        # =====================================================================

        # Gate 1: Same threat domain (cross-domain blocked by default)
        inv_domain = candidate.get('threat_domain') or self._infer_domain_from_investigation(candidate)
        domain_gate = self._check_domain_gate(alert_domain, inv_domain)
        if domain_gate.passed:
            gates_passed.append('SAME_DOMAIN')
        else:
            gates_failed.append('SAME_DOMAIN')
            logger.debug(f"Investigation {inv_number}: Domain gate failed - {domain_gate.reason}")
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                reason=domain_gate.reason
            )

        # Gate 2: Time window (max 24h from investigation seed time)
        time_gate = self._check_time_window_gate(alert_time, candidate)
        if time_gate.passed:
            gates_passed.append('TIME_WINDOW')
        else:
            gates_failed.append('TIME_WINDOW')
            logger.debug(f"Investigation {inv_number}: Time gate failed - {time_gate.reason}")
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                reason=time_gate.reason
            )

        # Gate 3: Investigation capacity
        capacity_gate = self._check_capacity_gate(candidate)
        if capacity_gate.passed:
            gates_passed.append('CAPACITY')
        else:
            gates_failed.append('CAPACITY')
            logger.debug(f"Investigation {inv_number}: Capacity gate failed - {capacity_gate.reason}")
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                reason=capacity_gate.reason
            )

        # =====================================================================
        # PHASE 2: HYPOTHESIS MATCHING
        # =====================================================================

        hypothesis = candidate.get('hypothesis', '')
        hypothesis_category = candidate.get('hypothesis_category', '')

        # Use AI-powered evaluation if enabled and tenant_id available
        tenant_id = alert.get('tenant_id')
        if self.config.AI_HYPOTHESIS_ENABLED and tenant_id and hypothesis:
            hypothesis_result = await self.hypothesis_matcher.evaluate_hypothesis_support_ai(
                alert, hypothesis, hypothesis_category, str(tenant_id)
            )
        else:
            hypothesis_result = self.hypothesis_matcher.evaluate_hypothesis_support(
                alert, hypothesis, hypothesis_category
            )

        if hypothesis_result.support_type == 'CONTRADICTS':
            gates_failed.append('HYPOTHESIS_COMPATIBLE')
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                hypothesis_support='CONTRADICTS',
                reason=f"Alert contradicts hypothesis: {hypothesis_result.reason}"
            )

        if hypothesis_result.support_type == 'UNRELATED':
            gates_failed.append('HYPOTHESIS_COMPATIBLE')
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                hypothesis_support='UNRELATED',
                reason="Alert does not support investigation hypothesis"
            )

        gates_passed.append('HYPOTHESIS_COMPATIBLE')

        # =====================================================================
        # PHASE 3: EVIDENCE-BASED SCORING
        # =====================================================================

        scoring_result = self.evidence_scorer.calculate_score(alert, candidate)

        # =====================================================================
        # PHASE 4: ENTITY VALIDATION (NOT scoring)
        # =====================================================================

        entity_overlap = self._check_entity_overlap(alert, candidate)
        if not entity_overlap.passed:
            gates_failed.append('ENTITY_OVERLAP')
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                score=scoring_result.score,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                hypothesis_support=hypothesis_result.support_type,
                reason="No entity overlap to anchor correlation"
            )

        gates_passed.append('ENTITY_OVERLAP')

        # =====================================================================
        # PHASE 5: DECISION
        # =====================================================================

        # Minimum evidence threshold
        if scoring_result.score < self.config.MINIMUM_EVIDENCE_SCORE:
            return CorrelationResult(
                decision=DecisionType.REJECTED,
                investigation_id=inv_id,
                investigation_number=inv_number,
                score=scoring_result.score,
                gates_passed=gates_passed,
                gates_failed=['MINIMUM_SCORE'],
                hypothesis_support=hypothesis_result.support_type,
                evidence=[e.__dict__ if hasattr(e, '__dict__') else e for e in scoring_result.evidence],
                reason=f"Score {scoring_result.score} below minimum {self.config.MINIMUM_EVIDENCE_SCORE}"
            )

        # Determine decision type (SUGGESTED or CONFIRMED)
        decision = DecisionType.SUGGESTED
        if (
            scoring_result.score >= self.config.AUTO_CONFIRM_THRESHOLD
            and (scoring_result.has_malicious_evidence or scoring_result.has_causal_evidence)
            and hypothesis_result.support_type == 'SUPPORTS'
        ):
            decision = DecisionType.CONFIRMED

        # Generate explanation
        explanation = self.explainer.generate_explanation(
            alert=alert,
            investigation=candidate,
            evidence_list=scoring_result.evidence,
            score=scoring_result.score,
            gates_passed=gates_passed,
            gates_failed=gates_failed,
            hypothesis_support=hypothesis_result.support_type,
            relationship_type=hypothesis_result.relationship_type
        )

        return CorrelationResult(
            decision=decision,
            investigation_id=inv_id,
            investigation_number=inv_number,
            score=scoring_result.score,
            relationship_type=hypothesis_result.relationship_type,
            hypothesis_support=hypothesis_result.support_type,
            evidence=explanation.evidence,
            gates_passed=gates_passed,
            gates_failed=gates_failed,
            why_correlated=explanation.why_correlated,
            reason=f"Matched with score {scoring_result.score}"
        )

    # =========================================================================
    # Gate Checks
    # =========================================================================

    def _check_domain_gate(self, alert_domain: str, inv_domain: str) -> EligibilityGateResult:
        """Check if alert domain is compatible with investigation domain."""
        if self.config.ALLOW_CROSS_DOMAIN:
            return EligibilityGateResult(passed=True, gate_name='SAME_DOMAIN')

        if not inv_domain:
            # Investigation has no domain set - allow
            return EligibilityGateResult(passed=True, gate_name='SAME_DOMAIN')

        allowed = ThreatDomain.ALLOWED_CORRELATIONS.get(alert_domain, [alert_domain])
        if inv_domain in allowed:
            return EligibilityGateResult(passed=True, gate_name='SAME_DOMAIN')

        return EligibilityGateResult(
            passed=False,
            gate_name='SAME_DOMAIN',
            reason=f"Cross-domain blocked: {alert_domain} cannot correlate with {inv_domain}"
        )

    def _check_time_window_gate(
        self,
        alert_time: datetime,
        candidate: Dict[str, Any]
    ) -> EligibilityGateResult:
        """Check if alert is within investigation's time window."""
        seed_time = candidate.get('seed_alert_time') or candidate.get('created_at')

        if not seed_time:
            return EligibilityGateResult(passed=True, gate_name='TIME_WINDOW')

        if isinstance(seed_time, str):
            try:
                seed_time = datetime.fromisoformat(seed_time.replace('Z', '+00:00'))
            except:
                return EligibilityGateResult(passed=True, gate_name='TIME_WINDOW')

        # Ensure both are timezone-aware or both naive
        if alert_time.tzinfo is None and seed_time.tzinfo is not None:
            alert_time = alert_time.replace(tzinfo=seed_time.tzinfo)
        elif alert_time.tzinfo is not None and seed_time.tzinfo is None:
            seed_time = seed_time.replace(tzinfo=alert_time.tzinfo)

        time_diff = abs((alert_time - seed_time).total_seconds())
        max_seconds = self.config.MAX_TIME_WINDOW_HOURS * 3600

        if time_diff <= max_seconds:
            return EligibilityGateResult(passed=True, gate_name='TIME_WINDOW')

        hours_diff = time_diff / 3600
        return EligibilityGateResult(
            passed=False,
            gate_name='TIME_WINDOW',
            reason=f"Outside {self.config.MAX_TIME_WINDOW_HOURS}h window ({hours_diff:.1f}h from seed)"
        )

    def _check_capacity_gate(self, candidate: Dict[str, Any]) -> EligibilityGateResult:
        """Check if investigation has capacity for more alerts."""
        alert_count = candidate.get('alert_count', 0)

        if alert_count >= self.config.MAX_ALERTS_PER_INVESTIGATION:
            return EligibilityGateResult(
                passed=False,
                gate_name='CAPACITY',
                reason=f"Investigation at capacity ({alert_count}/{self.config.MAX_ALERTS_PER_INVESTIGATION} alerts)"
            )

        return EligibilityGateResult(passed=True, gate_name='CAPACITY')

    def _check_entity_overlap(
        self,
        alert: Dict[str, Any],
        candidate: Dict[str, Any]
    ) -> EligibilityGateResult:
        """
        Check for entity overlap (user, host, or IP).

        NOTE: This is VALIDATION only - entities do not contribute to score.
        """
        alert_entities = self._extract_entities(alert)
        inv_entities = self._extract_investigation_entities(candidate)

        # Check for any overlap
        for entity_type in ['users', 'hosts', 'ips']:
            alert_set = set(alert_entities.get(entity_type, []))
            inv_set = set(inv_entities.get(entity_type, []))
            if alert_set.intersection(inv_set):
                return EligibilityGateResult(passed=True, gate_name='ENTITY_OVERLAP')

        return EligibilityGateResult(
            passed=False,
            gate_name='ENTITY_OVERLAP',
            reason="No entity overlap (user, host, or IP) to anchor correlation"
        )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _classify_threat_domain(self, alert: Dict[str, Any]) -> str:
        """Classify alert into a threat domain."""
        source = (alert.get('source') or '').lower()
        category = (alert.get('category') or '').lower()
        title = (alert.get('title') or '').lower()

        # Email domain
        if any(kw in source or kw in category or kw in title
               for kw in ['email', 'phishing', 'spam', 'mail']):
            return ThreatDomain.EMAIL

        # Identity domain
        if any(kw in source or kw in category
               for kw in ['identity', 'azure ad', 'okta', 'authentication', 'sso']):
            return ThreatDomain.IDENTITY

        # Cloud domain
        if any(kw in source or kw in category
               for kw in ['cloud', 'aws', 'gcp', 'azure', 's3', 'lambda']):
            return ThreatDomain.CLOUD

        # Network domain
        if any(kw in source or kw in category
               for kw in ['network', 'firewall', 'ids', 'nids', 'netflow']):
            return ThreatDomain.NETWORK

        # Default to endpoint
        return ThreatDomain.ENDPOINT

    def _infer_domain_from_investigation(self, investigation: Dict[str, Any]) -> str:
        """Infer threat domain from investigation data."""
        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, str):
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}

        # Check hypothesis category (hydrated from investigation_data or from JSONB)
        hypothesis_category = investigation.get('hypothesis_category', '') or inv_data.get('hypothesis_category', '')
        if hypothesis_category == 'PHISHING_CAMPAIGN':
            return ThreatDomain.EMAIL
        if hypothesis_category in ['CREDENTIAL_THEFT', 'INSIDER_THREAT']:
            return ThreatDomain.IDENTITY

        # Check alert title
        alert_title = investigation.get('alert_title', '').lower()
        if 'phishing' in alert_title or 'email' in alert_title:
            return ThreatDomain.EMAIL

        return ThreatDomain.ENDPOINT

    def _get_alert_time(self, alert: Dict[str, Any]) -> datetime:
        """Extract alert timestamp."""
        for field in ['created_at', 'detected_at', 'timestamp']:
            value = alert.get(field)
            if value:
                if isinstance(value, datetime):
                    return value
                if isinstance(value, str):
                    try:
                        return datetime.fromisoformat(value.replace('Z', '+00:00'))
                    except:
                        pass
        return datetime.now(timezone.utc)

    def _extract_entities(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract entities (users, hosts, IPs) from alert."""
        entities = {'users': [], 'hosts': [], 'ips': []}

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            # Check both extraction paths
            extracted = raw_event.get('_extracted', {})
            nested_raw = raw_event.get('raw_event', {})
            if isinstance(nested_raw, dict):
                nested_extracted = nested_raw.get('_extracted', {})
                if nested_extracted:
                    entities_data = nested_extracted.get('entities', {})
                    if entities_data:
                        if entities_data.get('users'):
                            entities['users'].extend([u.lower() for u in entities_data.get('users', [])])
                        if entities_data.get('hosts'):
                            entities['hosts'].extend([h.lower() for h in entities_data.get('hosts', [])])
                        if entities_data.get('ips'):
                            entities['ips'].extend(entities_data.get('ips', []))
                        # Also check for singular fields
                        if entities_data.get('user'):
                            entities['users'].append(entities_data['user'].lower())
                        if entities_data.get('host'):
                            entities['hosts'].append(entities_data['host'].lower())

                    # Check IOCs in nested
                    iocs = nested_extracted.get('iocs', {})
                    if iocs:
                        entities['ips'].extend(iocs.get('ips', []))

                # Check direct fields in nested raw_event
                if nested_raw.get('user'):
                    entities['users'].append(nested_raw['user'].lower())
                if nested_raw.get('hostname') or nested_raw.get('host'):
                    host = nested_raw.get('hostname') or nested_raw.get('host')
                    entities['hosts'].append(host.lower())
                if nested_raw.get('source_ip'):
                    entities['ips'].append(nested_raw['source_ip'])

            if extracted:
                entities_data = extracted.get('entities', {})
                if entities_data:
                    entities['users'].extend([u.lower() for u in entities_data.get('users', [])])
                    entities['hosts'].extend([h.lower() for h in entities_data.get('hosts', [])])
                    entities['ips'].extend(entities_data.get('ips', []))

                # Also check IOCs for IPs
                iocs = extracted.get('iocs', {})
                if iocs:
                    entities['ips'].extend(iocs.get('ips', []))

            # Check direct fields in top-level raw_event
            if raw_event.get('user'):
                entities['users'].append(raw_event['user'].lower())
            if raw_event.get('hostname') or raw_event.get('host'):
                host = raw_event.get('hostname') or raw_event.get('host')
                entities['hosts'].append(host.lower())
            if raw_event.get('source_ip'):
                entities['ips'].append(raw_event['source_ip'])

        # Deduplicate
        entities['users'] = list(set(entities['users']))
        entities['hosts'] = list(set(entities['hosts']))
        entities['ips'] = list(set(entities['ips']))

        return entities

    def _extract_investigation_entities(self, investigation: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract entities from investigation data."""
        entities = {'users': [], 'hosts': [], 'ips': []}

        inv_data = investigation.get('investigation_data', {})
        if isinstance(inv_data, str):
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}

        # Check for entity summary
        if 'entities' in inv_data:
            ent = inv_data['entities']
            entities['users'] = [u.lower() for u in ent.get('users', [])]
            entities['hosts'] = [h.lower() for h in ent.get('hosts', [])]
            entities['ips'] = ent.get('ips', [])

        # Check IOC summary
        ioc_summary = inv_data.get('ioc_summary', {})
        if 'users' in ioc_summary:
            entities['users'].extend([u.lower() for u in ioc_summary['users']])
        if 'hosts' in ioc_summary:
            entities['hosts'].extend([h.lower() for h in ioc_summary['hosts']])
        if 'ips' in ioc_summary:
            entities['ips'].extend(ioc_summary['ips'])

        return entities

    def _build_investigation_data(
        self,
        alert: Dict[str, Any],
        hypothesis: str
    ) -> Dict[str, Any]:
        """
        Build investigation_data from seed alert.

        This populates the ioc_summary and entities that the evidence scorer
        uses to find shared IOCs between alerts.
        """
        # Extract entities
        entities = self._extract_entities(alert)

        # Extract IOCs
        ioc_summary = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'urls': [],
        }

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, dict):
            # Look for _extracted at multiple levels:
            # 1. raw_event._extracted (from enrichment - may not exist yet)
            # 2. raw_event.raw_event._extracted (from original webhook payload)
            extracted = raw_event.get('_extracted', {})
            nested_raw = raw_event.get('raw_event', {})
            if isinstance(nested_raw, dict):
                nested_extracted = nested_raw.get('_extracted', {})
                if nested_extracted and not extracted:
                    extracted = nested_extracted
                elif nested_extracted:
                    # Merge nested extracted into extracted if both exist
                    for key in ['iocs', 'enrichment_results', 'mitre', 'entities']:
                        if key in nested_extracted and key not in extracted:
                            extracted[key] = nested_extracted[key]

            if extracted:
                # Get IOCs from enrichment_results (includes verdicts)
                enrichment = extracted.get('enrichment_results', {})
                for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
                    for ioc_data in enrichment.get(ioc_type, []):
                        if isinstance(ioc_data, dict):
                            value = ioc_data.get('value') or ioc_data.get('ip') or ioc_data.get('domain', '')
                            if value:
                                ioc_summary[ioc_type].append(value)

                # Also get IOCs from direct extraction
                iocs = extracted.get('iocs', {})
                if iocs:
                    for ioc_type in ['ips', 'domains', 'urls']:
                        ioc_summary[ioc_type].extend(iocs.get(ioc_type, []))
                    # Handle file_hashes -> hashes
                    ioc_summary['hashes'].extend(iocs.get('file_hashes', []))
                    ioc_summary['hashes'].extend(iocs.get('hashes', []))

        # Deduplicate and lowercase
        for key in ioc_summary:
            ioc_summary[key] = list(set(str(v).lower() for v in ioc_summary[key] if v))

        # Extract MITRE techniques
        mitre_techniques = list(self.evidence_scorer._extract_mitre_techniques(alert))

        return {
            'hypothesis': hypothesis,
            'entities': entities,
            'ioc_summary': ioc_summary,
            'mitre_techniques': mitre_techniques,
            'seed_alert_id': alert.get('alert_id'),
            'seed_alert_title': alert.get('title'),
        }

    # =========================================================================
    # Database Operations
    # =========================================================================

    async def _get_pool(self):
        """Get database instance for tenant-aware connections."""
        try:
            from services.postgres_db import postgres_db
            if postgres_db.pool:
                return postgres_db
        except Exception as e:
            logger.error(f"Failed to get database pool: {e}")
        return None

    async def _find_candidate_investigations(
        self,
        conn,
        alert: Dict[str, Any],
        alert_domain: str,
        alert_time: datetime
    ) -> List[Dict[str, Any]]:
        """Find candidate investigations for correlation."""
        # Time window
        window_start = alert_time - timedelta(hours=self.config.MAX_TIME_WINDOW_HOURS * 2)

        # Query for open investigations (use only columns that exist in the table)
        query = """
            SELECT
                i.id,
                i.investigation_id,
                i.alert_title,
                i.state,
                i.severity,
                i.created_at,
                i.investigation_data,
                (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id) AS alert_count
            FROM investigations i
            WHERE i.state NOT IN ('CLOSED', 'RESOLVED')
              AND i.created_at >= $1
            ORDER BY i.created_at DESC
            LIMIT 50
        """

        try:
            rows = await conn.fetch(query, window_start)
            candidates = []
            for row in rows:
                c = dict(row)
                # Hydrate hypothesis fields from investigation_data JSONB
                inv_data = c.get('investigation_data', {})
                if isinstance(inv_data, str):
                    try:
                        inv_data = json.loads(inv_data)
                    except:
                        inv_data = {}
                c['hypothesis'] = inv_data.get('hypothesis', '')
                c['hypothesis_category'] = inv_data.get('hypothesis_category', '')
                c['threat_domain'] = inv_data.get('threat_domain', '')
                c['seed_alert_time'] = inv_data.get('seed_alert_time') or c.get('created_at')
                candidates.append(c)
            return candidates
        except Exception as e:
            logger.error(f"Failed to find candidate investigations: {e}")
            return []

    async def _create_correlation_link(
        self,
        conn,
        alert_id: str,
        result: CorrelationResult
    ):
        """Create correlation link in database."""
        try:
            # Get alert UUID
            alert_row = await conn.fetchrow(
                "SELECT id FROM alerts WHERE alert_id = $1",
                alert_id
            )
            if not alert_row:
                logger.warning(f"Alert {alert_id} not found for correlation link")
                return

            alert_uuid = alert_row['id']

            # Insert correlation link
            link_state = 'CONFIRMED' if result.decision == DecisionType.CONFIRMED else 'SUGGESTED'

            # Use separate parameters for confirmed_at and confirmed_by instead of CASE
            confirmed_at = datetime.now(timezone.utc) if link_state == 'CONFIRMED' else None
            confirmed_by = 'SYSTEM' if link_state == 'CONFIRMED' else None

            await conn.execute("""
                INSERT INTO correlation_links (
                    alert_id, investigation_id, link_state, relationship_type,
                    correlation_score, why_correlated, evidence_json,
                    gates_passed, gates_failed, hypothesis_support,
                    suggested_at, confirmed_at, confirmed_by
                ) VALUES (
                    $1, $2::uuid, $3::varchar, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10,
                    CURRENT_TIMESTAMP, $11, $12
                )
                ON CONFLICT (alert_id, investigation_id) DO UPDATE SET
                    link_state = EXCLUDED.link_state,
                    correlation_score = EXCLUDED.correlation_score,
                    why_correlated = EXCLUDED.why_correlated,
                    evidence_json = EXCLUDED.evidence_json
            """,
                alert_uuid,
                result.investigation_id,
                link_state,
                result.relationship_type or 'SUPPORTING',
                result.score,
                result.why_correlated or '',
                json.dumps(result.evidence or []),
                json.dumps(result.gates_passed or []),
                json.dumps(result.gates_failed or []),
                result.hypothesis_support or 'COMPATIBLE',
                confirmed_at,
                confirmed_by
            )

            # If confirmed, also update alert's investigation_id
            if result.decision == DecisionType.CONFIRMED:
                await conn.execute("""
                    UPDATE alerts
                    SET investigation_id = $1::uuid,
                        status = 'investigating',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE alert_id = $2
                """, result.investigation_id, alert_id)

            logger.info(
                f"Alert {alert_id}: Created {link_state} link to {result.investigation_number}"
            )

        except Exception as e:
            logger.error(f"Failed to create correlation link for {alert_id}: {e}")

    async def _record_audit(
        self,
        conn,
        alert_id: str,
        result: CorrelationResult
    ):
        """Record correlation decision in audit table."""
        try:
            # Get alert UUID
            alert_row = await conn.fetchrow(
                "SELECT id FROM alerts WHERE alert_id = $1",
                alert_id
            )
            if not alert_row:
                return

            await conn.execute("""
                INSERT INTO correlation_audit (
                    alert_id, decision, investigation_id, investigation_number,
                    score, threshold_used, gates_passed, gates_failed,
                    evidence, hypothesis_support, reason, processing_time_ms
                ) VALUES (
                    $1, $2, $3::uuid, $4, $5, $6, $7::jsonb, $8::jsonb,
                    $9::jsonb, $10, $11, $12
                )
            """,
                alert_row['id'],
                result.decision.value,
                result.investigation_id,
                result.investigation_number,
                result.score,
                self.config.MINIMUM_EVIDENCE_SCORE,
                json.dumps(result.gates_passed),
                json.dumps(result.gates_failed),
                json.dumps(result.evidence),
                result.hypothesis_support,
                result.reason,
                result.processing_time_ms
            )

        except Exception as e:
            logger.error(f"Failed to record audit: {e}")

    async def _create_new_investigation(
        self,
        conn,
        alert_id: str,
        alert_data: Dict[str, Any],
        alert_domain: str,
        start_time: float
    ) -> CorrelationResult:
        """Create a new investigation for the alert."""
        try:
            # Generate hypothesis
            hypothesis, hypothesis_category = self._generate_hypothesis(alert_data)

            # Get alert details
            alert_title = alert_data.get('title', 'Unknown alert')

            # Generate investigation ID
            import secrets
            investigation_number = f"INV-{secrets.token_hex(4).upper()}"

            # Extract IOCs and entities from seed alert to populate investigation_data
            investigation_data = self._build_investigation_data(alert_data, hypothesis)

            # Store hypothesis in investigation_data (columns don't exist on table)
            investigation_data['hypothesis'] = hypothesis
            investigation_data['hypothesis_category'] = hypothesis_category
            investigation_data['threat_domain'] = alert_domain

            # Get tenant_id and alert UUID from alert data or from the alert row in DB.
            # Both are needed: investigations.alert_id is a UUID FK to alerts.id (not the
            # string alert_id like "IAM-..."), and without it the analyze job handler
            # cannot load the seed alert (job_queue.py:handle_agent_analyze_investigation
            # skips alert loading when payload alert_id is None).
            import uuid as _uuid
            tenant_id = alert_data.get('tenant_id')
            if tenant_id and isinstance(tenant_id, str):
                try:
                    tenant_id = _uuid.UUID(tenant_id)
                except (ValueError, AttributeError):
                    pass

            seed_alert_uuid = alert_data.get('id')
            if seed_alert_uuid and isinstance(seed_alert_uuid, str):
                try:
                    seed_alert_uuid = _uuid.UUID(seed_alert_uuid)
                except (ValueError, AttributeError):
                    seed_alert_uuid = None

            if not tenant_id or not seed_alert_uuid:
                alert_row = await conn.fetchrow(
                    "SELECT id, tenant_id FROM alerts WHERE alert_id = $1", alert_id
                )
                if alert_row:
                    if not tenant_id:
                        tenant_id = alert_row['tenant_id']
                    if not seed_alert_uuid:
                        seed_alert_uuid = alert_row['id']

            row = await conn.fetchrow("""
                INSERT INTO investigations (
                    investigation_id, alert_id, alert_title, state, severity,
                    created_at, investigation_data, tenant_id
                ) VALUES (
                    $1, $2, $3, 'NEW', $4,
                    CURRENT_TIMESTAMP, $5::jsonb, $6
                )
                RETURNING id
            """,
                investigation_number,
                seed_alert_uuid,
                alert_title,
                alert_data.get('severity', 'medium'),
                json.dumps(investigation_data),
                tenant_id
            )

            inv_id = str(row['id'])

            # Link alert to investigation
            await conn.execute("""
                UPDATE alerts
                SET investigation_id = $1::uuid,
                    status = 'investigating',
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = $2
            """, inv_id, alert_id)

            processing_time = int((time.time() - start_time) * 1000)

            logger.info(
                f"Alert {alert_id}: Created new investigation {investigation_number} "
                f"(category={hypothesis_category})"
            )

            return CorrelationResult(
                decision=DecisionType.CREATE_NEW,
                investigation_id=inv_id,
                investigation_number=investigation_number,
                hypothesis_support='INITIAL_EVIDENCE',
                relationship_type='ROOT_CAUSE',
                why_correlated=self.explainer.generate_new_investigation_explanation(
                    alert_data, hypothesis, hypothesis_category
                ),
                reason="New investigation created",
                processing_time_ms=processing_time
            )

        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
            return CorrelationResult(
                decision=DecisionType.STANDALONE,
                reason=f"Failed to create investigation: {str(e)}",
                processing_time_ms=int((time.time() - start_time) * 1000)
            )

    def _generate_hypothesis(self, alert: Dict[str, Any]) -> Tuple[str, str]:
        """Generate hypothesis for new investigation."""
        title = (alert.get('title') or '').lower()
        category = (alert.get('category') or '').lower()
        source = (alert.get('source') or '').lower()

        # Determine category
        if 'phishing' in title or 'phishing' in category:
            return (
                f"Potential phishing attack targeting organization users",
                'PHISHING_CAMPAIGN'
            )

        if 'malware' in title or 'trojan' in title or 'ransomware' in title:
            return (
                f"Potential malware infection requiring investigation",
                'MALWARE_INFECTION'
            )

        if 'credential' in title or 'password' in title or 'mimikatz' in title:
            return (
                f"Potential credential theft or abuse",
                'CREDENTIAL_THEFT'
            )

        if 'exfil' in title or 'data loss' in title:
            return (
                f"Potential data exfiltration attempt",
                'DATA_EXFIL'
            )

        if 'lateral' in title or 'psexec' in title or 'wmi' in title:
            return (
                f"Potential lateral movement activity",
                'LATERAL_MOVEMENT'
            )

        if 'c2' in title or 'beacon' in title or 'command and control' in title:
            return (
                f"Potential C2 communication detected",
                'C2_COMMUNICATION'
            )

        # Default
        return (
            f"Security incident requiring investigation: {alert.get('title', 'Unknown')}",
            'MALWARE_INFECTION'
        )


# ============================================================================
# Singleton and Integration
# ============================================================================

_hypothesis_correlation_service: Optional[HypothesisCorrelationService] = None


def get_hypothesis_correlation_service() -> HypothesisCorrelationService:
    """Get or create the hypothesis correlation service singleton."""
    global _hypothesis_correlation_service
    if _hypothesis_correlation_service is None:
        _hypothesis_correlation_service = HypothesisCorrelationService()
    return _hypothesis_correlation_service


async def correlate_alert_v3(alert: Dict[str, Any]) -> Optional[str]:
    """
    Hypothesis-driven correlation (v3.0) - Entry point.

    This function replaces correlate_alert_v2() for hypothesis-driven correlation.

    Args:
        alert: The alert dict

    Returns:
        Investigation ID if linked/created, None on error
    """
    service = get_hypothesis_correlation_service()

    alert_id = alert.get('alert_id') or alert.get('id') or alert.get('external_id')
    if not alert_id:
        logger.warning("Alert missing ID field - cannot correlate")
        return None

    result = await service.correlate_alert(
        alert_id=str(alert_id),
        alert_data=alert,
        create_investigation=True
    )

    logger.info(
        f"Alert {alert_id}: Hypothesis correlation decision={result.decision.value}, "
        f"investigation={result.investigation_id}, score={result.score}"
    )

    if result.investigation_id:
        return str(result.investigation_id)

    return None
