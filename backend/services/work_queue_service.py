# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Work Queue Service for T1 Agentics
Manages analyst workload, assignments, and work distribution.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class WorkItemType(str, Enum):
    ALERT = "alert"
    INVESTIGATION = "investigation"
    ESCALATION = "escalation"
    APPROVAL = "approval"


class WorkItemPriority(str, Enum):
    CRITICAL = "critical"  # P1 - Immediate
    HIGH = "high"          # P2 - 1 hour
    MEDIUM = "medium"      # P3 - 4 hours
    LOW = "low"            # P4 - 24 hours


@dataclass
class WorkItem:
    """Represents a work item in the queue"""
    id: str
    item_type: str
    title: str
    severity: str
    priority: str
    status: str
    source: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    sla_due: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class WorkQueueService:
    """
    Manages analyst work queue and assignments.

    Features:
    - Unified work queue across alerts, investigations, escalations
    - Round-robin and skill-based assignment
    - SLA tracking
    - Analyst availability management
    - Workload balancing
    """

    def __init__(self):
        self._initialized = False
        self._postgres = None

        # SLA definitions (in minutes)
        self.sla_times = {
            "critical": 15,    # 15 minutes
            "high": 60,        # 1 hour
            "medium": 240,     # 4 hours
            "low": 1440        # 24 hours
        }

    async def initialize(self):
        """Initialize the service"""
        if self._initialized:
            return

        try:
            from services.postgres_db import postgres_db
            self._postgres = postgres_db
            self._initialized = True
            logger.info("Work queue service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize work queue service: {e}")
            raise

    async def get_work_queue(
        self,
        analyst_id: Optional[str] = None,
        item_types: Optional[List[str]] = None,
        status_filter: Optional[List[str]] = None,
        priority_filter: Optional[List[str]] = None,
        unassigned_only: bool = False,
        include_linked: bool = False,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get the unified work queue.

        Returns alerts and investigations that need analyst attention.

        Args:
            include_linked: If True, show alerts even if linked to an investigation
        """
        await self.initialize()

        work_items = []

        # Default item types
        if not item_types:
            item_types = ["alert", "investigation", "escalation", "approval"]

        # Default status filter (open items)
        # Excludes 'converted_to_investigation' to avoid duplicate work items
        if not status_filter:
            status_filter = ["open", "investigating", "OPEN", "INVESTIGATING", "NEW", "ESCALATED"]

        async with self._postgres.tenant_acquire() as conn:
            # Get alerts
            if "alert" in item_types:
                alert_query = """
                    SELECT
                        a.id::text,
                        'alert' as item_type,
                        a.title,
                        a.severity,
                        CASE a.severity
                            WHEN 'critical' THEN 'critical'
                            WHEN 'high' THEN 'high'
                            WHEN 'medium' THEN 'medium'
                            ELSE 'low'
                        END as priority,
                        a.status,
                        a.source,
                        a.assigned_to,
                        a.assigned_at,
                        a.created_at,
                        a.updated_at,
                        a.raw_event as metadata,
                        a.investigation_id::text as investigation_id,
                        i.investigation_id as linked_investigation_id
                    FROM alerts a
                    LEFT JOIN investigations i ON a.investigation_id = i.id
                    WHERE a.status = ANY($1)
                """

                # Only filter out linked alerts if include_linked is False
                if not include_linked:
                    alert_query += " AND a.investigation_id IS NULL"
                params = [status_filter]

                if analyst_id:
                    alert_query += " AND (a.assigned_to = $2 OR a.assigned_to IS NULL)"
                    params.append(analyst_id)
                elif unassigned_only:
                    alert_query += " AND a.assigned_to IS NULL"

                alert_query += " ORDER BY CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, a.created_at ASC"
                alert_query += f" LIMIT {limit}"

                rows = await conn.fetch(alert_query, *params)
                for row in rows:
                    item = dict(row)
                    item['sla_due'] = self._calculate_sla(item['created_at'], item['severity'])
                    item['sla_status'] = self._get_sla_status(item['sla_due'])
                    work_items.append(item)

            # Get investigations
            if "investigation" in item_types:
                inv_query = """
                    SELECT
                        i.id::text,
                        'investigation' as item_type,
                        COALESCE(i.alert_title, 'Investigation ' || i.investigation_id) as title,
                        COALESCE(i.severity, 'medium') as severity,
                        CASE i.priority
                            WHEN 'P1' THEN 'critical'
                            WHEN 'P2' THEN 'high'
                            WHEN 'P3' THEN 'medium'
                            ELSE 'low'
                        END as priority,
                        i.state as status,
                        COALESCE(a.source, 'Investigation') as source,
                        i.owner as assigned_to,
                        i.assigned_at,
                        i.created_at,
                        i.updated_at,
                        i.investigation_data as metadata
                    FROM investigations i
                    LEFT JOIN alerts a ON i.alert_id = a.id
                    WHERE i.state = ANY($1)
                """
                params = [status_filter]

                if analyst_id:
                    inv_query += " AND (owner = $2 OR owner IS NULL)"
                    params.append(analyst_id)
                elif unassigned_only:
                    inv_query += " AND owner IS NULL"

                inv_query += " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, created_at ASC"
                inv_query += f" LIMIT {limit}"

                rows = await conn.fetch(inv_query, *params)
                for row in rows:
                    item = dict(row)
                    item['sla_due'] = self._calculate_sla(item['created_at'], item['severity'])
                    item['sla_status'] = self._get_sla_status(item['sla_due'])
                    work_items.append(item)

            # Get escalations (investigations that were escalated)
            if "escalation" in item_types:
                esc_query = """
                    SELECT
                        i.id::text,
                        'escalation' as item_type,
                        COALESCE(i.alert_title, 'Escalation ' || i.investigation_id) as title,
                        COALESCE(i.severity, 'high') as severity,
                        'high' as priority,
                        i.state as status,
                        'Tier ' || COALESCE(i.escalated_to_tier::text, '2') as source,
                        i.owner as assigned_to,
                        i.escalated_at as assigned_at,
                        i.created_at,
                        i.updated_at,
                        jsonb_build_object(
                            'escalation_reason', i.escalation_reason,
                            'escalated_by', i.escalated_by,
                            'escalated_to_tier', i.escalated_to_tier
                        ) as metadata
                    FROM investigations i
                    WHERE i.escalated_at IS NOT NULL
                      AND i.state NOT IN ('CLOSED', 'RESOLVED')
                """

                if analyst_id:
                    esc_query += f" AND (i.owner = '{analyst_id}' OR i.owner IS NULL)"
                elif unassigned_only:
                    esc_query += " AND i.owner IS NULL"

                esc_query += " ORDER BY i.escalated_at DESC"
                esc_query += f" LIMIT {limit}"

                rows = await conn.fetch(esc_query)
                for row in rows:
                    item = dict(row)
                    # Escalations have shorter SLA
                    item['sla_due'] = self._calculate_sla(item['assigned_at'] or item['created_at'], 'high')
                    item['sla_status'] = self._get_sla_status(item['sla_due'])
                    work_items.append(item)

            # Get pending approvals
            if "approval" in item_types:
                approval_query = """
                    SELECT
                        ar.id::text,
                        'approval' as item_type,
                        'Approval: ' || ar.action || ' on ' || ar.target_id as title,
                        'high' as severity,
                        'high' as priority,
                        ar.status,
                        'Agent: ' || ad.codename as source,
                        NULL as assigned_to,
                        ar.created_at as assigned_at,
                        ar.created_at,
                        ar.created_at as updated_at,
                        jsonb_build_object(
                            'action', ar.action,
                            'target_type', ar.target_type,
                            'target_id', ar.target_id,
                            'reasoning', ar.reasoning,
                            'agent_name', ad.codename
                        ) as metadata
                    FROM agent_approval_requests ar
                    JOIN agent_definitions ad ON ar.agent_id = ad.id
                    WHERE ar.status = 'pending'
                    ORDER BY ar.created_at ASC
                """
                approval_query += f" LIMIT {limit}"

                rows = await conn.fetch(approval_query)
                for row in rows:
                    item = dict(row)
                    # Approvals have urgent SLA
                    item['sla_due'] = self._calculate_sla(item['created_at'], 'high')
                    item['sla_status'] = self._get_sla_status(item['sla_due'])
                    work_items.append(item)

        # Sort by priority and SLA
        work_items.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('priority'), 4),
            x.get('sla_due') or datetime.max.replace(tzinfo=None)
        ))

        return work_items[:limit]

    def _calculate_sla(self, created_at: datetime, severity: str) -> Optional[datetime]:
        """Calculate SLA due time based on severity"""
        if not created_at:
            return None

        sla_minutes = self.sla_times.get(severity.lower(), self.sla_times['medium'])

        # Handle timezone-aware datetime
        if created_at.tzinfo:
            from datetime import timezone
            return created_at + timedelta(minutes=sla_minutes)
        return created_at + timedelta(minutes=sla_minutes)

    def _get_sla_status(self, sla_due: Optional[datetime]) -> str:
        """Get SLA status (ok, warning, breached)"""
        if not sla_due:
            return "unknown"

        now = datetime.now(sla_due.tzinfo) if sla_due.tzinfo else datetime.utcnow()

        if now > sla_due:
            return "breached"
        elif now > sla_due - timedelta(minutes=15):
            return "warning"
        return "ok"

    async def assign_work_item(
        self,
        item_id: str,
        item_type: str,
        analyst_id: str
    ) -> Dict[str, Any]:
        """Assign a work item to an analyst"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            if item_type == "alert":
                await conn.execute("""
                    UPDATE alerts
                    SET assigned_to = $1, assigned_at = CURRENT_TIMESTAMP, status = 'investigating'
                    WHERE id = $2
                """, analyst_id, item_id)
            elif item_type in ["investigation", "escalation"]:
                await conn.execute("""
                    UPDATE investigations
                    SET owner = $1, assigned_at = CURRENT_TIMESTAMP, state = 'IN_PROGRESS'
                    WHERE id = $2
                """, analyst_id, item_id)

        logger.info(f"Assigned {item_type} {item_id} to analyst {analyst_id}")
        return {"success": True, "item_id": item_id, "assigned_to": analyst_id}

    async def claim_next_work_item(
        self,
        analyst_id: str,
        item_types: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Claim the next available work item from the queue.
        Uses priority and SLA to determine the most urgent item.
        """
        await self.initialize()

        # Get unassigned items
        items = await self.get_work_queue(
            item_types=item_types,
            unassigned_only=True,
            limit=1
        )

        if not items:
            return None

        item = items[0]

        # Assign to analyst
        await self.assign_work_item(
            item_id=item['id'],
            item_type=item['item_type'],
            analyst_id=analyst_id
        )

        return item

    async def release_work_item(
        self,
        item_id: str,
        item_type: str
    ) -> Dict[str, Any]:
        """Release a work item back to the queue"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            if item_type == "alert":
                await conn.execute("""
                    UPDATE alerts
                    SET assigned_to = NULL, assigned_at = NULL, status = 'open'
                    WHERE id = $1
                """, item_id)
            elif item_type in ["investigation", "escalation"]:
                await conn.execute("""
                    UPDATE investigations
                    SET owner = NULL, assigned_at = NULL, state = 'NEW'
                    WHERE id = $1
                """, item_id)

        logger.info(f"Released {item_type} {item_id} back to queue")
        return {"success": True, "item_id": item_id, "released": True}

    async def get_analyst_workload(self, analyst_id: str) -> Dict[str, Any]:
        """Get current workload for an analyst"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            # Count assigned alerts (exclude converted to investigations)
            alert_count = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE assigned_to = $1
                  AND status NOT IN ('resolved', 'closed', 'false_positive')
                  AND investigation_id IS NULL
            """, analyst_id)

            # Count assigned investigations
            inv_count = await conn.fetchval("""
                SELECT COUNT(*) FROM investigations
                WHERE owner = $1 AND state NOT IN ('CLOSED', 'RESOLVED')
            """, analyst_id)

            # Get severity breakdown
            alert_severity = await conn.fetch("""
                SELECT severity, COUNT(*) as count FROM alerts
                WHERE assigned_to = $1
                  AND status NOT IN ('resolved', 'closed', 'false_positive')
                  AND investigation_id IS NULL
                GROUP BY severity
            """, analyst_id)

            # Get SLA breaches
            now = datetime.utcnow()
            breached_alerts = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE assigned_to = $1
                  AND status NOT IN ('resolved', 'closed', 'false_positive')
                  AND investigation_id IS NULL
                  AND created_at < $2
            """, analyst_id, now - timedelta(hours=4))  # Medium SLA default

        return {
            "analyst_id": analyst_id,
            "total_items": alert_count + inv_count,
            "alerts": alert_count,
            "investigations": inv_count,
            "severity_breakdown": {row['severity']: row['count'] for row in alert_severity},
            "sla_breaches": breached_alerts,
            "capacity_status": self._get_capacity_status(alert_count + inv_count)
        }

    def _get_capacity_status(self, item_count: int) -> str:
        """Determine analyst capacity status"""
        if item_count >= 15:
            return "overloaded"
        elif item_count >= 10:
            return "high"
        elif item_count >= 5:
            return "normal"
        return "available"

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get overall queue statistics"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            # Total open alerts (exclude converted to investigations)
            open_alerts = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE status IN ('open', 'investigating')
                  AND investigation_id IS NULL
            """)

            # Unassigned alerts
            unassigned_alerts = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE status = 'open'
                  AND assigned_to IS NULL
                  AND investigation_id IS NULL
            """)

            # Open investigations
            open_investigations = await conn.fetchval("""
                SELECT COUNT(*) FROM investigations
                WHERE state NOT IN ('CLOSED', 'RESOLVED')
            """)

            # Unassigned investigations
            unassigned_investigations = await conn.fetchval("""
                SELECT COUNT(*) FROM investigations
                WHERE state IN ('NEW') AND owner IS NULL
            """)

            # Pending escalations
            pending_escalations = await conn.fetchval("""
                SELECT COUNT(*) FROM investigations
                WHERE escalated_at IS NOT NULL AND state NOT IN ('CLOSED', 'RESOLVED')
            """)

            # Pending approvals
            pending_approvals = await conn.fetchval("""
                SELECT COUNT(*) FROM agent_approval_requests WHERE status = 'pending'
            """)

            # Alerts by severity
            severity_breakdown = await conn.fetch("""
                SELECT severity, COUNT(*) as count FROM alerts
                WHERE status IN ('open', 'investigating')
                  AND investigation_id IS NULL
                GROUP BY severity
            """)

            # SLA breaches (using medium SLA as default - 4 hours)
            now = datetime.utcnow()
            sla_breaches = await conn.fetchval("""
                SELECT COUNT(*) FROM alerts
                WHERE status IN ('open', 'investigating')
                  AND investigation_id IS NULL
                  AND created_at < $1
            """, now - timedelta(hours=4))

        return {
            "total_open_items": open_alerts + open_investigations,
            "alerts": {
                "total": open_alerts,
                "unassigned": unassigned_alerts,
                "by_severity": {row['severity']: row['count'] for row in severity_breakdown}
            },
            "investigations": {
                "total": open_investigations,
                "unassigned": unassigned_investigations
            },
            "escalations": pending_escalations,
            "pending_approvals": pending_approvals,
            "sla_breaches": sla_breaches,
            "queue_health": self._get_queue_health(unassigned_alerts, sla_breaches)
        }

    def _get_queue_health(self, unassigned: int, breaches: int) -> str:
        """Determine overall queue health"""
        if breaches > 10 or unassigned > 50:
            return "critical"
        elif breaches > 5 or unassigned > 20:
            return "warning"
        elif breaches > 0 or unassigned > 10:
            return "attention"
        return "healthy"

    async def auto_assign_round_robin(
        self,
        analyst_ids: List[str],
        max_items_per_analyst: int = 10
    ) -> Dict[str, Any]:
        """
        Auto-assign unassigned items to analysts using round-robin.
        Respects max capacity per analyst.
        """
        await self.initialize()

        assigned_count = 0
        assignments = []

        # Get unassigned items
        unassigned_items = await self.get_work_queue(unassigned_only=True, limit=100)

        if not unassigned_items:
            return {"assigned": 0, "message": "No unassigned items"}

        # Get current workload for each analyst
        workloads = {}
        for analyst_id in analyst_ids:
            workload = await self.get_analyst_workload(analyst_id)
            workloads[analyst_id] = workload['total_items']

        # Round-robin assignment
        analyst_index = 0
        for item in unassigned_items:
            # Find next available analyst
            attempts = 0
            while attempts < len(analyst_ids):
                analyst_id = analyst_ids[analyst_index % len(analyst_ids)]

                if workloads.get(analyst_id, 0) < max_items_per_analyst:
                    # Assign item
                    await self.assign_work_item(
                        item_id=item['id'],
                        item_type=item['item_type'],
                        analyst_id=analyst_id
                    )

                    workloads[analyst_id] = workloads.get(analyst_id, 0) + 1
                    assigned_count += 1
                    assignments.append({
                        "item_id": item['id'],
                        "item_type": item['item_type'],
                        "assigned_to": analyst_id
                    })
                    break

                analyst_index += 1
                attempts += 1

            analyst_index += 1

        return {
            "assigned": assigned_count,
            "assignments": assignments,
            "remaining_unassigned": len(unassigned_items) - assigned_count
        }


# Singleton instance
_work_queue_service: Optional[WorkQueueService] = None


def get_work_queue_service() -> WorkQueueService:
    """Get the work queue service instance"""
    global _work_queue_service
    if _work_queue_service is None:
        _work_queue_service = WorkQueueService()
    return _work_queue_service
