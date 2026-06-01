# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Analyst Insights Service

Stores and retrieves analyst knowledge/feedback for Riggs to learn from.
This allows Riggs to reference past analyst corrections and insights.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


class InsightType(str, Enum):
    """Types of analyst insights."""
    PATTERN = "pattern"                    # General pattern knowledge
    SENDER = "sender"                      # Known sender info
    DOMAIN = "domain"                      # Domain reputation info
    IOC_BEHAVIOR = "ioc_behavior"          # How to interpret IOCs
    FALSE_POSITIVE_INDICATOR = "false_positive_indicator"  # FP patterns
    ANALYSIS_TIP = "analysis_tip"          # General analysis guidance


class AnalystInsightsService:
    """
    Service for storing and retrieving analyst insights.
    These are used to augment Riggs' analysis with human knowledge.
    """

    def __init__(self):
        self._initialized = False

    async def add_insight(
        self,
        insight_type: str,
        subject: str,
        insight: str,
        created_by: str,
        investigation_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        is_safe: Optional[bool] = None,
        confidence_adjustment: float = 0.0,
        applies_to_sender: bool = False,
        applies_to_domain: bool = False,
        applies_to_subject_pattern: bool = False,
        applies_to_ioc_type: Optional[str] = None
    ) -> Optional[str]:
        """
        Add a new analyst insight.

        Args:
            insight_type: Type of insight (pattern, sender, domain, etc.)
            subject: What the insight is about
            insight: The actual knowledge/learning
            created_by: Username of analyst
            investigation_id: Source investigation if applicable
            alert_id: Source alert if applicable
            is_safe: True=benign, False=malicious, None=depends
            confidence_adjustment: How much to adjust AI confidence (-1 to +1)
            applies_to_sender: Apply when this sender seen
            applies_to_domain: Apply when this domain seen
            applies_to_subject_pattern: Apply when subject pattern matches
            applies_to_ioc_type: Apply to specific IOC type

        Returns:
            The insight ID or None on failure
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            logger.warning("[INSIGHTS] Database not connected")
            return None

        try:
            async with postgres_db.tenant_acquire() as conn:
                result = await conn.fetchval("""
                    INSERT INTO analyst_insights (
                        insight_type, subject, insight, created_by,
                        investigation_id, alert_id, is_safe, confidence_adjustment,
                        applies_to_sender, applies_to_domain,
                        applies_to_subject_pattern, applies_to_ioc_type
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (insight_hash) DO UPDATE
                    SET insight = EXCLUDED.insight,
                        is_safe = COALESCE(EXCLUDED.is_safe, analyst_insights.is_safe),
                        confidence_adjustment = EXCLUDED.confidence_adjustment,
                        last_used_at = NOW()
                    RETURNING id::text
                """,
                    insight_type, subject, insight, created_by,
                    investigation_id, alert_id, is_safe, confidence_adjustment,
                    applies_to_sender, applies_to_domain,
                    applies_to_subject_pattern, applies_to_ioc_type
                )

                logger.info(f"[INSIGHTS] Added insight: {insight_type}/{subject} by {created_by}")
                return result

        except Exception as e:
            logger.error(f"[INSIGHTS] Failed to add insight: {e}")
            return None

    async def get_relevant_insights(
        self,
        sender: Optional[str] = None,
        domain: Optional[str] = None,
        subject: Optional[str] = None,
        ioc_type: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get insights relevant to the current analysis context.

        Args:
            sender: Email sender to check
            domain: Domain to check
            subject: Email subject to check
            ioc_type: IOC type being analyzed
            limit: Max insights to return

        Returns:
            List of relevant insights
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return []

        insights = []

        try:
            async with postgres_db.tenant_acquire() as conn:
                # Check for sender insights
                if sender:
                    rows = await conn.fetch("""
                        SELECT id::text, insight_type, subject, insight, is_safe,
                               confidence_adjustment, times_applied, created_by, created_at
                        FROM analyst_insights
                        WHERE applies_to_sender = TRUE
                          AND lower(subject) = lower($1)
                        ORDER BY times_applied DESC, created_at DESC
                        LIMIT $2
                    """, sender, limit)
                    insights.extend([dict(r) for r in rows])

                # Check for domain insights
                if domain:
                    rows = await conn.fetch("""
                        SELECT id::text, insight_type, subject, insight, is_safe,
                               confidence_adjustment, times_applied, created_by, created_at
                        FROM analyst_insights
                        WHERE applies_to_domain = TRUE
                          AND (lower(subject) = lower($1) OR $1 LIKE '%' || lower(subject))
                        ORDER BY times_applied DESC, created_at DESC
                        LIMIT $2
                    """, domain, limit)
                    insights.extend([dict(r) for r in rows])

                # Check for general pattern insights (always included)
                rows = await conn.fetch("""
                    SELECT id::text, insight_type, subject, insight, is_safe,
                           confidence_adjustment, times_applied, created_by, created_at
                    FROM analyst_insights
                    WHERE insight_type IN ('pattern', 'false_positive_indicator', 'analysis_tip')
                    ORDER BY times_applied DESC, created_at DESC
                    LIMIT $1
                """, limit)
                insights.extend([dict(r) for r in rows])

                # Dedupe and sort
                seen = set()
                unique = []
                for i in insights:
                    if i['id'] not in seen:
                        seen.add(i['id'])
                        unique.append(i)

                return unique[:limit]

        except Exception as e:
            logger.error(f"[INSIGHTS] Failed to get insights: {e}")
            return []

    async def record_insight_used(self, insight_id: str):
        """Record that an insight was used in analysis."""
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return

        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute("""
                    UPDATE analyst_insights
                    SET times_applied = times_applied + 1,
                        last_used_at = NOW()
                    WHERE id = $1::uuid
                """, insight_id)
        except Exception as e:
            logger.error(f"[INSIGHTS] Failed to record insight use: {e}")

    async def get_all_insights(
        self,
        insight_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get all insights, optionally filtered by type."""
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return []

        try:
            async with postgres_db.tenant_acquire() as conn:
                if insight_type:
                    rows = await conn.fetch("""
                        SELECT id::text, insight_type, subject, insight, is_safe,
                               confidence_adjustment, times_applied, created_by,
                               created_at, last_used_at
                        FROM analyst_insights
                        WHERE insight_type = $1
                        ORDER BY created_at DESC
                        LIMIT $2 OFFSET $3
                    """, insight_type, limit, offset)
                else:
                    rows = await conn.fetch("""
                        SELECT id::text, insight_type, subject, insight, is_safe,
                               confidence_adjustment, times_applied, created_by,
                               created_at, last_used_at
                        FROM analyst_insights
                        ORDER BY created_at DESC
                        LIMIT $1 OFFSET $2
                    """, limit, offset)

                return [dict(r) for r in rows]

        except Exception as e:
            logger.error(f"[INSIGHTS] Failed to get all insights: {e}")
            return []


# Singleton
_insights_service: Optional[AnalystInsightsService] = None


def get_insights_service() -> AnalystInsightsService:
    """Get or create the insights service singleton."""
    global _insights_service
    if _insights_service is None:
        _insights_service = AnalystInsightsService()
    return _insights_service
