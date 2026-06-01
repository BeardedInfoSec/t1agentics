# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs-Playbook Integration Service

Connects Riggs investigations with automated playbook execution.
Allows Riggs to:
1. Recommend playbooks based on investigation findings
2. Automatically trigger response playbooks
3. Wait for playbook results to enhance investigation
4. Learn from playbook outcomes
"""

import json
import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================

class PlaybookRecommendation(BaseModel):
    """Playbook recommendation from Riggs."""
    playbook_id: str
    playbook_name: str
    match_score: float
    reasoning: str
    auto_execute: bool = False
    requires_approval: bool = True
    estimated_duration_minutes: Optional[int] = None
    expected_actions: List[str] = Field(default_factory=list)


class PlaybookExecutionIntent(BaseModel):
    """Riggs's intent to execute a playbook."""
    investigation_id: str
    playbook_id: str
    execution_reason: str
    auto_execute: bool = False
    wait_for_completion: bool = False
    context_overrides: Dict[str, Any] = Field(default_factory=dict)


class RiggsPlaybookResult(BaseModel):
    """Result of Riggs-triggered playbook execution."""
    execution_id: str
    playbook_id: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    outcome: Optional[Dict[str, Any]] = None
    actions_taken: List[str] = Field(default_factory=list)
    enhanced_findings: Optional[Dict[str, Any]] = None


# ============================================================================
# Integration Service
# ============================================================================

class RiggsPlaybookIntegration:
    """
    Integrates Riggs investigations with playbook execution.

    Key capabilities:
    - Selects relevant playbooks based on Riggs findings
    - Triggers playbook execution automatically or with approval
    - Enhances Riggs output with playbook recommendations
    - Provides feedback loop for learning
    """

    def __init__(self):
        from agents.riggs_playbook import get_riggs_playbook_agent
        from services.playbook_engine import get_playbook_engine

        self.playbook_agent = get_riggs_playbook_agent()
        self.playbook_engine = get_playbook_engine()

    # ========================================================================
    # Playbook Selection Based on Riggs Findings
    # ========================================================================

    async def recommend_playbooks(
        self,
        riggs_analysis: Dict[str, Any],
        alert: Dict[str, Any],
        investigation: Dict[str, Any],
        max_recommendations: int = 3
    ) -> List[PlaybookRecommendation]:
        """
        Recommend playbooks based on Riggs investigation findings.

        Selection criteria:
        1. Verdict (MALICIOUS → containment playbooks, SUSPICIOUS → investigation playbooks)
        2. Threat type (phishing, malware, etc.)
        3. Affected entities (users, hosts)
        4. MITRE techniques
        5. Alert severity and confidence
        """
        recommendations = []

        try:
            verdict = riggs_analysis.get('verdict', '').upper()
            threat_type = riggs_analysis.get('threat_type', '').lower()
            confidence = riggs_analysis.get('confidence', 0)
            mitre_techniques = riggs_analysis.get('mitre', [])
            affected_entities = riggs_analysis.get('affected_entities', [])

            # Augment alert with Riggs findings for better matching
            enriched_alert = alert.copy()
            enriched_alert['riggs_verdict'] = verdict
            enriched_alert['riggs_threat_type'] = threat_type
            enriched_alert['riggs_confidence'] = confidence

            # Add tags based on threat type
            if threat_type:
                enriched_alert['tags'] = enriched_alert.get('tags', []) + [threat_type]

            # Use RiggsPlaybookAgent to select matching playbooks
            selection = await self.playbook_agent.select_playbook_for_alert(enriched_alert)

            if selection.selected_playbook:
                # Primary recommendation
                primary = self._build_recommendation(
                    playbook=selection.selected_playbook,
                    score=selection.match_score,
                    verdict=verdict,
                    confidence=confidence,
                    reasoning="; ".join(selection.match_reasons)
                )
                recommendations.append(primary)

            # Alternative recommendations
            for alt_playbook in selection.alternatives[:max_recommendations - 1]:
                alt_rec = self._build_recommendation(
                    playbook=alt_playbook,
                    score=alt_playbook.get('match_score', 50),
                    verdict=verdict,
                    confidence=confidence,
                    reasoning="Alternative response option"
                )
                recommendations.append(alt_rec)

            # Add threat-type-specific playbooks
            additional = await self._get_threat_type_playbooks(
                threat_type=threat_type,
                verdict=verdict,
                existing_ids=[r.playbook_id for r in recommendations]
            )
            recommendations.extend(additional[:max_recommendations - len(recommendations)])

            return recommendations[:max_recommendations]

        except Exception as e:
            logger.error(f"Failed to recommend playbooks: {e}")
            return []

    def _build_recommendation(
        self,
        playbook: Dict[str, Any],
        score: float,
        verdict: str,
        confidence: int,
        reasoning: str
    ) -> PlaybookRecommendation:
        """Build a playbook recommendation object."""

        # Determine if can auto-execute
        auto_execute = (
            playbook.get('riggs_allowed', False) and
            not playbook.get('requires_approval', True) and
            verdict == 'MALICIOUS' and
            confidence >= 80
        )

        # Estimate duration from canvas nodes
        canvas_data = playbook.get('canvas_data', {})
        node_count = len(canvas_data.get('nodes', [])) if canvas_data else 0
        estimated_minutes = max(5, node_count * 2)  # Rough estimate

        # Extract expected actions
        expected_actions = []
        if canvas_data:
            for node in canvas_data.get('nodes', []):
                node_type = node.get('type', '')
                if node_type in ['action', 'enrich', 'notify']:
                    label = node.get('data', {}).get('label', node_type)
                    expected_actions.append(label)

        return PlaybookRecommendation(
            playbook_id=str(playbook.get('id', '')),
            playbook_name=playbook.get('name', 'Unknown'),
            match_score=score,
            reasoning=reasoning,
            auto_execute=auto_execute,
            requires_approval=playbook.get('requires_approval', True),
            estimated_duration_minutes=estimated_minutes,
            expected_actions=expected_actions[:5]  # Top 5 actions
        )

    async def _get_threat_type_playbooks(
        self,
        threat_type: str,
        verdict: str,
        existing_ids: List[str]
    ) -> List[PlaybookRecommendation]:
        """Get playbooks specific to threat type."""
        from services.postgres_db import postgres_db

        if not threat_type or not postgres_db.connected:
            return []

        try:
            async with postgres_db.tenant_acquire() as conn:
                # Query playbooks with matching tags
                rows = await conn.fetch('''
                    SELECT * FROM playbooks
                    WHERE is_enabled = TRUE
                    AND (
                        $1 = ANY(tags)
                        OR $2 = ANY(tags)
                        OR $3 = ANY(alert_types)
                    )
                    AND id::text != ALL($4)
                    LIMIT 3
                ''', threat_type, verdict.lower(), threat_type, existing_ids)

                recommendations = []
                for row in rows:
                    playbook = dict(row)
                    rec = self._build_recommendation(
                        playbook=playbook,
                        score=60.0,  # Medium score for tag-based matches
                        verdict=verdict,
                        confidence=70,
                        reasoning=f"Matches threat type: {threat_type}"
                    )
                    recommendations.append(rec)

                return recommendations

        except Exception as e:
            logger.error(f"Failed to get threat type playbooks: {e}")
            return []

    # ========================================================================
    # Playbook Execution
    # ========================================================================

    async def execute_recommended_playbook(
        self,
        recommendation: PlaybookRecommendation,
        investigation: Dict[str, Any],
        alert: Dict[str, Any],
        riggs_analysis: Dict[str, Any],
        triggered_by: str = "riggs_auto"
    ) -> RiggsPlaybookResult:
        """
        Execute a recommended playbook.

        Handles:
        - Approval checks
        - Context preparation
        - Execution triggering
        - Status monitoring
        """
        try:
            execution_id = None

            # Check if requires approval
            if recommendation.requires_approval and not recommendation.auto_execute:
                # Create approval request
                approval_result = await self._request_execution_approval(
                    recommendation=recommendation,
                    investigation=investigation,
                    riggs_analysis=riggs_analysis
                )
                return RiggsPlaybookResult(
                    execution_id=approval_result.get('approval_id', 'pending'),
                    playbook_id=recommendation.playbook_id,
                    status='pending_approval',
                    started_at=datetime.utcnow().isoformat(),
                    outcome={'message': 'Waiting for analyst approval'}
                )

            # Prepare execution context
            context = self._prepare_execution_context(
                investigation=investigation,
                alert=alert,
                riggs_analysis=riggs_analysis
            )

            # Execute playbook
            result = await self.playbook_engine.start_execution(
                playbook_id=recommendation.playbook_id,
                trigger_context=context,
                triggered_by=triggered_by
            )

            execution_id = result.get('execution_id', 'unknown')

            # Log execution
            await self._log_playbook_execution(
                investigation_id=investigation.get('investigation_id'),
                playbook_id=recommendation.playbook_id,
                execution_id=execution_id,
                triggered_by=triggered_by,
                riggs_verdict=riggs_analysis.get('verdict')
            )

            return RiggsPlaybookResult(
                execution_id=execution_id,
                playbook_id=recommendation.playbook_id,
                status=result.get('status', 'running'),
                started_at=datetime.utcnow().isoformat(),
                outcome=result.get('initial_output')
            )

        except Exception as e:
            logger.error(f"Failed to execute playbook: {e}")
            return RiggsPlaybookResult(
                execution_id='failed',
                playbook_id=recommendation.playbook_id,
                status='failed',
                started_at=datetime.utcnow().isoformat(),
                outcome={'error': str(e)}
            )

    def _prepare_execution_context(
        self,
        investigation: Dict[str, Any],
        alert: Dict[str, Any],
        riggs_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Prepare context for playbook execution."""
        return {
            "alert": alert,
            "investigation": investigation,
            "riggs_analysis": riggs_analysis,
            "alert_id": alert.get('alert_id'),
            "investigation_id": investigation.get('investigation_id'),
            "verdict": riggs_analysis.get('verdict'),
            "confidence": riggs_analysis.get('confidence'),
            "threat_type": riggs_analysis.get('threat_type'),
            "iocs": riggs_analysis.get('iocs', []),
            "affected_entities": riggs_analysis.get('affected_entities', []),
            "mitre_techniques": [t.get('id', t) if isinstance(t, dict) else t
                                for t in riggs_analysis.get('mitre', [])],
            "triggered_by": "riggs_investigation"
        }

    async def _request_execution_approval(
        self,
        recommendation: PlaybookRecommendation,
        investigation: Dict[str, Any],
        riggs_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create approval request for playbook execution."""
        from services.postgres_db import postgres_db

        try:
            async with postgres_db.tenant_acquire() as conn:
                approval_id = str(uuid.uuid4())

                await conn.execute('''
                    INSERT INTO playbook_execution_approvals
                    (id, investigation_id, playbook_id, playbook_name,
                     riggs_verdict, riggs_confidence, riggs_reasoning,
                     status, created_at, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
                ''',
                    approval_id,
                    investigation.get('investigation_id'),
                    recommendation.playbook_id,
                    recommendation.playbook_name,
                    riggs_analysis.get('verdict'),
                    riggs_analysis.get('confidence'),
                    recommendation.reasoning,
                    'pending',
                    investigation.get('tenant_id')
                )

                return {
                    'approval_id': approval_id,
                    'status': 'pending',
                    'message': f'Approval requested for playbook: {recommendation.playbook_name}'
                }

        except Exception as e:
            logger.error(f"Failed to request approval: {e}")
            return {'error': str(e)}

    async def _log_playbook_execution(
        self,
        investigation_id: str,
        playbook_id: str,
        execution_id: str,
        triggered_by: str,
        riggs_verdict: str
    ):
        """Log playbook execution for audit and learning."""
        from services.postgres_db import postgres_db

        try:
            from middleware.tenant_middleware import get_optional_tenant_id
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO riggs_playbook_executions
                    (investigation_id, playbook_id, execution_id,
                     triggered_by, riggs_verdict, created_at, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, NOW(), $6)
                    ON CONFLICT (investigation_id, execution_id) DO NOTHING
                ''',
                    investigation_id,
                    playbook_id,
                    execution_id,
                    triggered_by,
                    riggs_verdict,
                    get_optional_tenant_id()
                )
        except Exception as e:
            logger.warning(f"Failed to log playbook execution: {e}")

    # ========================================================================
    # Enhanced Riggs Output
    # ========================================================================

    async def enhance_riggs_output(
        self,
        riggs_analysis: Dict[str, Any],
        alert: Dict[str, Any],
        investigation: Dict[str, Any],
        auto_recommend: bool = True
    ) -> Dict[str, Any]:
        """
        Enhance Riggs output with playbook recommendations.

        Adds a 'playbook_recommendations' field to Riggs analysis.
        """
        if not auto_recommend:
            return riggs_analysis

        try:
            recommendations = await self.recommend_playbooks(
                riggs_analysis=riggs_analysis,
                alert=alert,
                investigation=investigation
            )

            riggs_analysis['playbook_recommendations'] = [
                {
                    'playbook_id': rec.playbook_id,
                    'playbook_name': rec.playbook_name,
                    'match_score': rec.match_score,
                    'reasoning': rec.reasoning,
                    'auto_execute': rec.auto_execute,
                    'requires_approval': rec.requires_approval,
                    'estimated_duration_minutes': rec.estimated_duration_minutes,
                    'expected_actions': rec.expected_actions
                }
                for rec in recommendations
            ]

            # Auto-execute if allowed
            if recommendations and recommendations[0].auto_execute:
                execution_result = await self.execute_recommended_playbook(
                    recommendation=recommendations[0],
                    investigation=investigation,
                    alert=alert,
                    riggs_analysis=riggs_analysis
                )

                riggs_analysis['playbook_auto_executed'] = {
                    'playbook_id': execution_result.playbook_id,
                    'execution_id': execution_result.execution_id,
                    'status': execution_result.status
                }

            return riggs_analysis

        except Exception as e:
            logger.error(f"Failed to enhance Riggs output: {e}")
            return riggs_analysis

    # ========================================================================
    # Playbook Result Integration
    # ========================================================================

    async def get_playbook_results(
        self,
        execution_id: str
    ) -> Optional[RiggsPlaybookResult]:
        """Get results from a playbook execution."""
        try:
            # Query playbook execution status
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                execution = await conn.fetchrow('''
                    SELECT * FROM playbook_executions
                    WHERE execution_id = $1
                ''', execution_id)

                if not execution:
                    return None

                # Extract actions taken
                execution_state = execution.get('execution_state', {})
                if isinstance(execution_state, str):
                    execution_state = json.loads(execution_state)

                actions_taken = []
                nodes = execution_state.get('nodes', {})
                for node_id, node_result in nodes.items():
                    if node_result.get('node_type') in ['action', 'enrich']:
                        actions_taken.append(node_result.get('label', node_id))

                return RiggsPlaybookResult(
                    execution_id=execution_id,
                    playbook_id=str(execution.get('playbook_id')),
                    status=execution.get('status'),
                    started_at=execution.get('started_at').isoformat(),
                    completed_at=execution.get('completed_at').isoformat() if execution.get('completed_at') else None,
                    outcome=execution.get('final_output'),
                    actions_taken=actions_taken
                )

        except Exception as e:
            logger.error(f"Failed to get playbook results: {e}")
            return None

    # ========================================================================
    # Learning & Feedback
    # ========================================================================

    async def record_playbook_feedback(
        self,
        investigation_id: str,
        execution_id: str,
        outcome: str,
        effectiveness_score: int,
        analyst_notes: str = None
    ):
        """
        Record feedback on playbook execution for learning.

        Helps improve:
        - Playbook selection accuracy
        - Auto-execution decisions
        - Playbook effectiveness ratings
        """
        from services.postgres_db import postgres_db

        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE riggs_playbook_executions
                    SET outcome = $3,
                        effectiveness_score = $4,
                        analyst_notes = $5,
                        feedback_recorded_at = NOW()
                    WHERE investigation_id = $1 AND execution_id = $2
                ''',
                    investigation_id,
                    execution_id,
                    outcome,
                    effectiveness_score,
                    analyst_notes
                )

                logger.info(f"Recorded playbook feedback: {investigation_id} -> {outcome}")

        except Exception as e:
            logger.error(f"Failed to record playbook feedback: {e}")


# ============================================================================
# Singleton
# ============================================================================

_integration: Optional[RiggsPlaybookIntegration] = None


def get_riggs_playbook_integration() -> RiggsPlaybookIntegration:
    """Get singleton Riggs-Playbook integration instance."""
    global _integration
    if _integration is None:
        _integration = RiggsPlaybookIntegration()
    return _integration
