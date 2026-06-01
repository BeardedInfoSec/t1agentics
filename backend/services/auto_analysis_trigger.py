# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Auto-trigger Riggs analysis when investigations are created.

Queues an `agent_analyze_investigation` job on the AGENT queue, assigned to
an enabled Tier 1 agent. The job handler (job_queue.handle_agent_analyze_
investigation) will load the investigation + linked alert and run the agent.

History: this module had two bugs that caused every call to fail silently
and the broad except to swallow it:
  1. wrong import: `get_job_queue` -> should be `get_job_queue_service`
  2. wrong enqueue signature: missing `queue_name`, used non-existent
     `target_type` / `target_id` kwargs
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def auto_trigger_analysis_for_investigation(
    investigation_id: str,
    tenant_id: str,
    priority: int = 5,
    alert_id: Optional[str] = None,
) -> Optional[str]:
    """Queue an analysis job for the given investigation.

    Args:
        investigation_id: UUID of the investigation to analyze.
        tenant_id: Tenant UUID (used for license-tier-aware logging).
        priority: 1 (highest) to 10 (lowest). Default 5.
        alert_id: Optional UUID of the seed alert. If not provided, the
            handler will look it up from investigations.alert_id.

    Returns:
        Job ID if successfully queued, None on any failure.
    """
    try:
        from services.job_queue import get_job_queue_service, QueueName
        from services.agent_service import get_agent_service
        from dependencies.license_checks import _get_tenant_tier

        try:
            tier = await _get_tenant_tier(str(tenant_id))
            tier_str = (
                tier.value if hasattr(tier, "value") else (tier or "community")
            ).lower()
        except Exception as e:
            logger.warning(
                f"[AUTO_ANALYSIS] Failed to resolve tier for tenant {tenant_id}: {e}. "
                f"Defaulting to community."
            )
            tier_str = "community"

        # Look up an enabled Tier 1 agent via platform-admin bypass — Tier 1
        # agents are typically platform-global (tenant_id IS NULL) and are
        # invisible from a tenant-scoped RLS context.
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            logger.error(
                f"[AUTO_ANALYSIS] postgres_db.pool unavailable for inv {investigation_id}"
            )
            return None
        async with postgres_db.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
                agent_row = await conn.fetchrow(
                    """
                    SELECT id::text AS id, system_name
                    FROM agent_definitions
                    WHERE tier = 1 AND enabled = true
                    ORDER BY created_at ASC
                    LIMIT 1
                    """
                )
        if not agent_row:
            logger.warning(
                f"[AUTO_ANALYSIS] No enabled Tier 1 agents — investigation "
                f"{investigation_id} will not be analyzed."
            )
            return None
        agent_id = agent_row["id"]

        job_queue = await get_job_queue_service()
        if not job_queue:
            logger.error(
                f"[AUTO_ANALYSIS] Job queue service unavailable; cannot queue "
                f"analysis for investigation {investigation_id}"
            )
            return None

        job_id = await job_queue.enqueue(
            queue_name=QueueName.AGENT,
            job_type="agent_analyze_investigation",
            payload={
                "agent_id": agent_id,
                "investigation_id": str(investigation_id),
                "alert_id": str(alert_id) if alert_id else None,
                "auto_trigger": True,
                "license_tier": tier_str,
                "tier": 1,
                "scheduled_by": "auto_analysis_trigger",
            },
            priority=priority,
        )

        if job_id is None:
            logger.warning(
                f"[AUTO_ANALYSIS] enqueue returned None (queue full?) for "
                f"investigation {investigation_id}"
            )
            return None

        logger.info(
            f"[AUTO_ANALYSIS] Queued {tier_str} tier analysis for investigation "
            f"{investigation_id} (job {job_id}, agent {agent_id})"
        )
        return job_id

    except Exception as e:
        logger.error(
            f"[AUTO_ANALYSIS] Failed to queue auto-analysis for investigation "
            f"{investigation_id}: {e}",
            exc_info=True,
        )
        return None
