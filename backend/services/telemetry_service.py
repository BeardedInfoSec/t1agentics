# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
UX Telemetry Service

Tracks feature usage, investigation decision times, error rates, and analyst workflows.
Stores events in ClickHouse for high-performance analytics.
Falls back to logging when ClickHouse is unavailable.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

logger = logging.getLogger(__name__)


class TelemetryService:
    """Service for tracking and querying UX telemetry events."""

    def __init__(self):
        self._schema_initialized = False

    def _get_client(self):
        from services.clickhouse_client import get_clickhouse_client
        return get_clickhouse_client()

    def init_schema(self):
        """Create ClickHouse tables if they don't exist."""
        client = self._get_client()
        if not client:
            logger.warning("ClickHouse unavailable, skipping schema init")
            return False

        try:
            client.execute('''
                CREATE TABLE IF NOT EXISTS ux_events (
                    tenant_id UUID,
                    user_id UUID,
                    event_type String,
                    event_name String,
                    properties String,
                    page String,
                    session_id String,
                    timestamp DateTime64(3),
                    created_date Date DEFAULT toDate(timestamp)
                ) ENGINE = MergeTree()
                PARTITION BY toYYYYMM(created_date)
                ORDER BY (tenant_id, timestamp, event_type)
                TTL created_date + INTERVAL 90 DAY
            ''')
            self._schema_initialized = True
            logger.info("UX telemetry schema initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize telemetry schema: {e}")
            return False

    def track_batch(self, tenant_id: str, user_id: str, events: List[Dict[str, Any]]) -> int:
        """Insert a batch of UX events. Returns count of inserted events."""
        client = self._get_client()

        if not self._schema_initialized:
            self.init_schema()

        if not client:
            # Fallback: log events
            for evt in events:
                logger.info(f"UX event (no CH): {evt.get('event_type')}.{evt.get('event_name')}")
            return 0

        try:
            rows = []
            for evt in events:
                ts = evt.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        ts = datetime.utcnow()
                elif not isinstance(ts, datetime):
                    ts = datetime.utcnow()

                rows.append((
                    tenant_id,
                    user_id,
                    evt.get("event_type", ""),
                    evt.get("event_name", ""),
                    json.dumps(evt.get("properties", {})),
                    evt.get("page", ""),
                    evt.get("session_id", ""),
                    ts,
                ))

            if rows:
                client.execute(
                    "INSERT INTO ux_events (tenant_id, user_id, event_type, event_name, properties, page, session_id, timestamp) VALUES",
                    rows,
                )
            return len(rows)
        except Exception as e:
            logger.error(f"Failed to insert telemetry events: {e}")
            return 0

    def get_feature_usage(self, tenant_id: str, days: int = 30) -> List[Dict]:
        """Aggregate feature usage for a tenant."""
        client = self._get_client()
        if not client:
            return []

        try:
            since = datetime.utcnow() - timedelta(days=days)
            result = client.execute('''
                SELECT
                    event_type,
                    event_name,
                    count() as count,
                    uniqExact(user_id) as unique_users
                FROM ux_events
                WHERE tenant_id = %(tenant_id)s
                  AND timestamp >= %(since)s
                GROUP BY event_type, event_name
                ORDER BY count DESC
                LIMIT 100
            ''', {"tenant_id": tenant_id, "since": since})

            return [
                {"event_type": r[0], "event_name": r[1], "count": r[2], "unique_users": r[3]}
                for r in result
            ]
        except Exception as e:
            logger.error(f"Failed to query feature usage: {e}")
            return []

    def get_investigation_metrics(self, tenant_id: str, days: int = 30) -> Dict:
        """Get investigation decision-time metrics."""
        client = self._get_client()
        if not client:
            return {}

        try:
            since = datetime.utcnow() - timedelta(days=days)
            result = client.execute('''
                SELECT
                    count() as total_verdicts,
                    avg(JSONExtractFloat(properties, 'time_to_decision_ms')) as avg_decision_ms,
                    quantile(0.5)(JSONExtractFloat(properties, 'time_to_decision_ms')) as p50_decision_ms,
                    quantile(0.95)(JSONExtractFloat(properties, 'time_to_decision_ms')) as p95_decision_ms
                FROM ux_events
                WHERE tenant_id = %(tenant_id)s
                  AND event_name = 'investigation.verdict_set'
                  AND timestamp >= %(since)s
            ''', {"tenant_id": tenant_id, "since": since})

            if result and result[0]:
                r = result[0]
                return {
                    "total_verdicts": r[0],
                    "avg_decision_ms": round(r[1] or 0, 0),
                    "p50_decision_ms": round(r[2] or 0, 0),
                    "p95_decision_ms": round(r[3] or 0, 0),
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to query investigation metrics: {e}")
            return {}


# Singleton
telemetry_service = TelemetryService()
