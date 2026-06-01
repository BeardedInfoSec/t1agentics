# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Orchestrator Service

Coordinates playbook execution timing relative to the triage pipeline.
Ensures playbooks run at the right time and results are visible to T1/T2.

Flow:
    WEBHOOK → ENRICH → [PRE-TRIAGE PLAYBOOKS] → T1 → RIGGS → [POST-TRIAGE PLAYBOOKS]
                              ↓
                    Results stored on alert
                              ↓
                    T1 sees: "Playbook X blocked 3 IPs"
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PlaybookOrchestrator:
    """
    Orchestrates playbook execution in the alert processing pipeline.

    Responsibilities:
    - Execute pre-triage playbooks after enrichment completes
    - Store playbook results on alerts for T1/T2 visibility
    - Prevent duplicate playbook executions
    - Support Riggs-triggered playbook recommendations
    """

    def __init__(self):
        self._engine = None

    async def _get_engine(self):
        """Lazy-load playbook engine to avoid circular imports."""
        if self._engine is None:
            from services.playbook_engine import get_playbook_engine
            self._engine = get_playbook_engine()
        return self._engine

    async def execute_pre_triage_playbooks(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute playbooks configured to run before T1 triage.

        Called after enrichment completes, before T1 runs.
        Results are stored on the alert for T1 visibility.

        Args:
            alert_id: Alert UUID
            alert_data: Full alert record
            enrichment_data: Enrichment results (IOC verdicts, etc.)

        Returns:
            List of playbook execution results
        """
        logger.info(f"[PlaybookOrchestrator] Running pre-triage playbooks for alert {alert_id}")

        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                logger.warning("[PlaybookOrchestrator] Database not connected")
                return []

            # Find matching pre-triage playbooks
            playbooks = await self._find_matching_playbooks(
                alert_data=alert_data,
                trigger_timing='pre_triage'
            )

            if not playbooks:
                logger.debug(f"[PlaybookOrchestrator] No pre-triage playbooks match alert {alert_id}")
                return []

            logger.info(f"[PlaybookOrchestrator] Found {len(playbooks)} pre-triage playbooks for alert {alert_id}")

            # Check which playbooks have already run (deduplication)
            already_run = await self._get_already_run_playbooks(alert_id)

            # Execute each matching playbook
            results = []
            for playbook in playbooks:
                playbook_id = str(playbook['id'])

                # Skip if already executed
                if playbook_id in already_run:
                    logger.info(f"[PlaybookOrchestrator] Skipping {playbook['name']} - already executed")
                    results.append({
                        "playbook_id": playbook_id,
                        "playbook_name": playbook['name'],
                        "status": "skipped",
                        "reason": "already_executed"
                    })
                    continue

                # Execute playbook
                result = await self._execute_and_track(
                    playbook=playbook,
                    alert_id=alert_id,
                    alert_data=alert_data,
                    enrichment_data=enrichment_data,
                    trigger_timing='pre_triage'
                )
                results.append(result)

            # Store results on alert
            if results:
                await self._store_results_on_alert(alert_id, results)

            return results

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error in pre-triage execution: {e}")
            return []

    async def execute_post_triage_playbooks(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        investigation_id: Optional[str] = None,
        t1_verdict: Optional[str] = None,
        riggs_analysis: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute playbooks configured to run after T1/Riggs completes.

        Called after triage is complete.

        Args:
            alert_id: Alert UUID
            alert_data: Full alert record
            investigation_id: Investigation ID if created
            t1_verdict: T1 triage verdict
            riggs_analysis: Riggs analysis results

        Returns:
            List of playbook execution results
        """
        logger.info(f"[PlaybookOrchestrator] Running post-triage playbooks for alert {alert_id}")

        try:
            playbooks = await self._find_matching_playbooks(
                alert_data=alert_data,
                trigger_timing='post_triage',
                verdict=t1_verdict
            )

            if not playbooks:
                return []

            already_run = await self._get_already_run_playbooks(alert_id)

            results = []
            for playbook in playbooks:
                playbook_id = str(playbook['id'])

                if playbook_id in already_run:
                    continue

                result = await self._execute_and_track(
                    playbook=playbook,
                    alert_id=alert_id,
                    alert_data=alert_data,
                    investigation_id=investigation_id,
                    trigger_timing='post_triage'
                )
                results.append(result)

            if results:
                await self._store_results_on_alert(alert_id, results)

            return results

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error in post-triage execution: {e}")
            return []

    async def execute_recommended_playbook(
        self,
        playbook_id: str,
        alert_id: str,
        alert_data: Dict[str, Any],
        recommended_by: str = "riggs",
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a playbook recommended by Riggs or an analyst.

        Used when Riggs recommends a specific playbook during analysis.

        Args:
            playbook_id: Playbook to execute
            alert_id: Alert UUID
            alert_data: Alert record
            recommended_by: Who recommended (riggs, analyst, etc.)
            reason: Why this playbook was recommended

        Returns:
            Execution result
        """
        logger.info(f"[PlaybookOrchestrator] Executing recommended playbook {playbook_id} for alert {alert_id}")

        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                playbook = await conn.fetchrow(
                    "SELECT * FROM playbooks WHERE id = $1 AND is_enabled = true",
                    uuid.UUID(playbook_id)
                )

                if not playbook:
                    return {"error": f"Playbook {playbook_id} not found or disabled"}

            result = await self._execute_and_track(
                playbook=dict(playbook),
                alert_id=alert_id,
                alert_data=alert_data,
                trigger_timing='on_demand',
                metadata={"recommended_by": recommended_by, "reason": reason}
            )

            await self._store_results_on_alert(alert_id, [result])
            return result

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error executing recommended playbook: {e}")
            return {"error": str(e)}

    async def get_playbook_results_for_alert(self, alert_id: str) -> List[Dict[str, Any]]:
        """
        Get all playbook results for an alert.

        Used by T1 and Riggs to see what automated actions have been taken.
        """
        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT playbook_results FROM alerts WHERE alert_id = $1",
                    alert_id
                )

                if not row or not row['playbook_results']:
                    return []

                results = row['playbook_results']
                if isinstance(results, str):
                    results = json.loads(results)

                return results

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error getting playbook results: {e}")
            return []

    async def format_playbook_results_for_triage(self, alert_id: str) -> str:
        """
        Format playbook results as a human-readable summary for T1/Riggs prompts.

        Returns:
            Formatted string describing what playbooks did
        """
        results = await self.get_playbook_results_for_alert(alert_id)

        if not results:
            return "No automated playbooks have run for this alert."

        lines = ["## Automated Response Summary\n"]

        for result in results:
            status_emoji = {
                "completed": "✓",
                "failed": "✗",
                "partial": "⚠",
                "running": "⏳",
                "skipped": "○"
            }.get(result.get('status', 'unknown'), "?")

            lines.append(f"### {status_emoji} {result.get('playbook_name', 'Unknown Playbook')}")
            lines.append(f"- Status: {result.get('status', 'unknown')}")

            if result.get('summary'):
                lines.append(f"- Summary: {result['summary']}")

            if result.get('error'):
                lines.append(f"- Error: {result['error']}")

            actions = result.get('actions_taken', [])
            if actions:
                lines.append("- Actions taken:")
                for action in actions:
                    success = "✓" if action.get('success') else "✗"
                    action_type = action.get('action_type', 'action')
                    target = action.get('target', '')
                    msg = action.get('message') or action.get('error', '')
                    lines.append(f"  - {success} {action_type}: {target}")
                    if msg:
                        lines.append(f"    {msg}")

            lines.append("")

        # Add summary of overall status
        completed = sum(1 for r in results if r.get('status') == 'completed')
        failed = sum(1 for r in results if r.get('status') in ('failed', 'partial'))

        if failed > 0:
            lines.append(f"**Note:** {failed} playbook(s) had failures - manual review recommended.")
        elif completed > 0:
            lines.append(f"**Note:** {completed} playbook(s) completed successfully.")

        return "\n".join(lines)

    # =========================================================================
    # Private Methods
    # =========================================================================

    async def _find_matching_playbooks(
        self,
        alert_data: Dict[str, Any],
        trigger_timing: str,
        verdict: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find playbooks that match the alert and trigger timing."""
        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                # Get enabled playbooks with matching trigger timing
                rows = await conn.fetch('''
                    SELECT id, name, description, trigger_conditions, trigger_timing,
                           alert_types, severity_filter, data_sources, canvas_data
                    FROM playbooks
                    WHERE is_enabled = true
                    AND trigger_timing = $1
                ''', trigger_timing)

            matching = []
            for row in rows:
                playbook = dict(row)

                # Check trigger conditions
                trigger_conditions = playbook.get('trigger_conditions') or {}
                if isinstance(trigger_conditions, str):
                    trigger_conditions = json.loads(trigger_conditions)

                # For pre_triage, check on_alert_created or on_enrichment_complete
                if trigger_timing == 'pre_triage':
                    if not trigger_conditions.get('on_alert_created') and \
                       not trigger_conditions.get('on_enrichment_complete'):
                        continue

                # Check alert type filter
                alert_types = playbook.get('alert_types') or []
                if alert_types:
                    alert_type = alert_data.get('alert_type') or alert_data.get('type')
                    if alert_type and alert_type not in alert_types:
                        continue

                # Check severity filter
                severity_filter = playbook.get('severity_filter') or []
                if severity_filter:
                    severity = alert_data.get('severity')
                    if severity and severity not in severity_filter:
                        continue

                # Check data source filter
                data_sources = playbook.get('data_sources') or []
                if data_sources:
                    data_source = alert_data.get('data_source') or alert_data.get('source')
                    if data_source and data_source not in data_sources:
                        continue

                # Check verdict filter (for post-triage)
                if verdict and trigger_conditions.get('verdict_filter'):
                    verdict_filter = trigger_conditions['verdict_filter']
                    if verdict not in verdict_filter:
                        continue

                matching.append(playbook)

            return matching

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error finding playbooks: {e}")
            return []

    async def _get_already_run_playbooks(self, alert_id: str) -> set:
        """Get set of playbook IDs already executed for this alert."""
        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT playbook_executions_run FROM alerts WHERE alert_id = $1",
                    alert_id
                )

                if row and row['playbook_executions_run']:
                    return set(row['playbook_executions_run'])
                return set()

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error getting already run playbooks: {e}")
            return set()

    async def _execute_and_track(
        self,
        playbook: Dict[str, Any],
        alert_id: str,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None,
        trigger_timing: str = 'pre_triage',
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a playbook and track its results."""
        started_at = datetime.now(timezone.utc)
        playbook_id = str(playbook['id'])
        playbook_name = playbook.get('name', 'Unknown')

        result = {
            "playbook_id": playbook_id,
            "playbook_name": playbook_name,
            "trigger_timing": trigger_timing,
            "status": "running",
            "started_at": started_at.isoformat(),
            "completed_at": None,
            "duration_ms": 0,
            "execution_id": None,
            "summary": None,
            "actions_taken": [],
            "error": None
        }

        if metadata:
            result["metadata"] = metadata

        try:
            engine = await self._get_engine()

            # Build trigger context
            trigger_context = {
                "event_type": f"playbook_{trigger_timing}",
                "alert": alert_data,
                "alert_id": alert_id,
                "investigation_id": investigation_id,
                "enrichment": enrichment_data
            }

            # Execute playbook
            exec_result = await engine.start_execution(
                playbook_id=playbook_id,
                trigger_context=trigger_context,
                triggered_by=f"orchestrator_{trigger_timing}"
            )

            if "error" in exec_result:
                result["status"] = "failed"
                result["error"] = exec_result["error"]
            else:
                result["execution_id"] = exec_result.get("execution_id")

                # Wait for execution to complete (with timeout)
                final_status = await self._wait_for_execution(
                    exec_result.get("execution_id"),
                    timeout_seconds=60
                )

                result["status"] = final_status.get("status", "completed")
                result["actions_taken"] = final_status.get("actions_taken", [])
                result["summary"] = self._generate_summary(final_status)

                if final_status.get("error"):
                    result["error"] = final_status["error"]

            # Mark playbook as run for this alert
            await self._mark_playbook_run(alert_id, playbook_id)

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Execution error for {playbook_name}: {e}")
            result["status"] = "failed"
            result["error"] = str(e)

        # Finalize timing
        completed_at = datetime.now(timezone.utc)
        result["completed_at"] = completed_at.isoformat()
        result["duration_ms"] = int((completed_at - started_at).total_seconds() * 1000)

        return result

    async def _wait_for_execution(
        self,
        execution_id: str,
        timeout_seconds: int = 60
    ) -> Dict[str, Any]:
        """Wait for a playbook execution to complete."""
        if not execution_id:
            return {"status": "unknown"}

        try:
            from services.postgres_db import postgres_db

            start_time = datetime.now(timezone.utc)

            while True:
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if elapsed > timeout_seconds:
                    return {"status": "timeout", "error": f"Execution timed out after {timeout_seconds}s"}

                async with postgres_db.tenant_acquire() as conn:
                    row = await conn.fetchrow('''
                        SELECT status, node_results, error
                        FROM playbook_executions
                        WHERE execution_id = $1
                    ''', execution_id)

                if not row:
                    await asyncio.sleep(1)
                    continue

                status = row['status']

                # Terminal states
                if status in ('completed', 'failed', 'cancelled', 'timeout'):
                    node_results = row['node_results']
                    if isinstance(node_results, str):
                        node_results = json.loads(node_results)

                    actions_taken = self._extract_actions_from_results(node_results)

                    return {
                        "status": status,
                        "actions_taken": actions_taken,
                        "error": row.get('error')
                    }

                # Still running or waiting
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error waiting for execution: {e}")
            return {"status": "error", "error": str(e)}

    def _extract_actions_from_results(self, node_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract action summaries from node results."""
        actions = []

        for node_id, result in (node_results or {}).items():
            kind = result.get('kind', '')

            # Only track action-type nodes
            if kind in ('action', 'notify', 'create_ticket', 'edl_add', 'edl_remove'):
                action = {
                    "node_id": node_id,
                    "action_type": result.get('outputs', {}).get('action_type') or kind,
                    "target": result.get('outputs', {}).get('target') or
                              result.get('inputs', {}).get('target_value', ''),
                    "success": result.get('status') == 'success',
                    "message": result.get('outputs', {}).get('message', ''),
                    "error": result.get('error')
                }
                actions.append(action)

        return actions

    def _generate_summary(self, final_status: Dict[str, Any]) -> str:
        """Generate a human-readable summary of playbook execution."""
        actions = final_status.get('actions_taken', [])

        if not actions:
            return "Playbook completed with no response actions"

        successful = sum(1 for a in actions if a.get('success'))
        failed = len(actions) - successful

        if failed == 0:
            return f"All {successful} action(s) completed successfully"
        elif successful == 0:
            return f"All {failed} action(s) failed"
        else:
            return f"{successful} action(s) succeeded, {failed} failed"

    async def _mark_playbook_run(self, alert_id: str, playbook_id: str):
        """Mark a playbook as having run for this alert (for deduplication)."""
        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE alerts
                    SET playbook_executions_run = array_append(
                        COALESCE(playbook_executions_run, '{}'),
                        $1
                    )
                    WHERE alert_id = $2
                    AND NOT ($1 = ANY(COALESCE(playbook_executions_run, '{}')))
                ''', playbook_id, alert_id)

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error marking playbook run: {e}")

    async def _store_results_on_alert(
        self,
        alert_id: str,
        results: List[Dict[str, Any]]
    ):
        """Store playbook execution results on the alert record."""
        try:
            from services.postgres_db import postgres_db

            async with postgres_db.tenant_acquire() as conn:
                # Get existing results
                row = await conn.fetchrow(
                    "SELECT playbook_results FROM alerts WHERE alert_id = $1",
                    alert_id
                )

                existing = []
                if row and row['playbook_results']:
                    existing = row['playbook_results']
                    if isinstance(existing, str):
                        existing = json.loads(existing)

                # Append new results
                combined = existing + results

                # Update alert
                await conn.execute('''
                    UPDATE alerts
                    SET playbook_results = $1,
                        updated_at = NOW()
                    WHERE alert_id = $2
                ''', json.dumps(combined), alert_id)

                logger.info(f"[PlaybookOrchestrator] Stored {len(results)} playbook results on alert {alert_id}")

        except Exception as e:
            logger.error(f"[PlaybookOrchestrator] Error storing results on alert: {e}")


# Singleton instance
_orchestrator: Optional[PlaybookOrchestrator] = None


def get_playbook_orchestrator() -> PlaybookOrchestrator:
    """Get singleton orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = PlaybookOrchestrator()
    return _orchestrator
