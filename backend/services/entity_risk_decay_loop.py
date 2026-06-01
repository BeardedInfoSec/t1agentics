# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Entity Risk Decay Loop

Periodic background task that decays entity risk scores so quiet
entities don't stay flagged forever. Without this, every entity's
score only ever grows and the threshold gradually becomes meaningless.

Decay formula (in entity_risk_service.apply_decay):
    new_score = old_score * (0.5 ^ (hours_since_last_seen / decay_hours))

Runs every hour. Idempotent — running more often just decays faster
than configured, which is harmless. Uses platform-admin mode to
process every tenant in one pass.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 3600  # 1 hour


async def cleanup_loop() -> None:
    """Sleep-then-decay loop, designed to be launched once at app startup."""
    # Stagger first run so we don't compete with other startup tasks.
    await asyncio.sleep(60)

    while True:
        try:
            from services.entity_risk_service import get_entity_risk_service
            svc = get_entity_risk_service()
            # tenant_id=None → decay every tenant (uses platform-admin bypass internally)
            result = await svc.apply_decay(tenant_id=None)
            if isinstance(result, dict):
                if result.get("error"):
                    logger.warning(f"[ENTITY_RISK_DECAY] apply_decay error: {result['error']}")
                else:
                    touched = int(result.get("updated", 0))
                    if touched:
                        logger.info(
                            f"[ENTITY_RISK_DECAY] decayed {touched} entit{'y' if touched == 1 else 'ies'} across all tenants"
                        )
        except Exception as e:
            logger.warning(f"[ENTITY_RISK_DECAY] loop iteration failed: {e}")
        await asyncio.sleep(INTERVAL_SECONDS)
