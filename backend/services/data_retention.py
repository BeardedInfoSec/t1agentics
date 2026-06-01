# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Data Retention Service

Manages data lifecycle and cleanup based on license tier retention policies.
Runs as a scheduled job (nightly at 2 AM UTC).
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Retention periods in days by license tier
RETENTION_POLICIES: Dict[str, Dict[str, int]] = {
    "community": {
        "alerts": 7,
        "investigations": 7,
        "playbook_executions": 7,
        "playbook_node_results": 7,
        "attachments": 7,
        "chat_messages": 7,
        "audit_logs": 30,
        "iocs": 30,
        "threat_intel": 30,
    },
    "professional": {
        "alerts": 90,
        "investigations": 90,
        "playbook_executions": 90,
        "playbook_node_results": 90,
        "attachments": 90,
        "chat_messages": 90,
        "audit_logs": 365,
        "iocs": 365,
        "threat_intel": 365,
    },
    "enterprise": {
        "alerts": 365,
        "investigations": 365,
        "playbook_executions": 365,
        "playbook_node_results": 365,
        "attachments": 365,
        "chat_messages": 365,
        "audit_logs": 2555,  # 7 years for compliance
        "iocs": -1,  # Never expire
        "threat_intel": -1,  # Never expire
    },
}

# Tables and their timestamp columns for cleanup
TABLE_CONFIG = {
    "alerts": {"timestamp_col": "created_at", "cascade": ["alert_observables", "alert_enrichments"]},
    "investigations": {"timestamp_col": "created_at", "cascade": ["investigation_findings"]},
    "playbook_executions": {"timestamp_col": "started_at", "cascade": ["playbook_node_results"]},
    "playbook_node_results": {"timestamp_col": "started_at", "cascade": []},
    "chat_messages": {"timestamp_col": "created_at", "cascade": []},
    "audit_logs": {"timestamp_col": "created_at", "cascade": []},
    "iocs": {"timestamp_col": "created_at", "cascade": []},
}


@dataclass
class RetentionStats:
    """Statistics from a retention cleanup run."""
    table: str
    rows_deleted: int
    rows_archived: int
    retention_days: int
    cutoff_date: datetime
    duration_ms: float


class DataRetentionService:
    """
    Manages data retention and cleanup operations.
    """

    def __init__(self):
        self._dry_run = False
        self._archive_enabled = False
        self._s3_archive_bucket: Optional[str] = None

    async def run_cleanup(
        self,
        tier: str = "community",
        dry_run: bool = False,
        archive_before_delete: bool = False,
        archive_bucket: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run retention cleanup for all tables.

        Enables platform admin mode to bypass RLS — cleanup runs across
        all tenants without HTTP request context.

        Args:
            tier: License tier (community, professional, enterprise)
            dry_run: If True, only report what would be deleted
            archive_before_delete: If True, archive to S3 before deleting
            archive_bucket: S3 bucket for archival

        Returns:
            Summary of cleanup operations
        """
        from services.postgres_db import set_platform_admin_mode

        self._dry_run = dry_run
        self._archive_enabled = archive_before_delete
        self._s3_archive_bucket = archive_bucket

        # Enable platform admin mode — cleanup runs across all tenants.
        set_platform_admin_mode(True)

        if tier not in RETENTION_POLICIES:
            tier = "community"

        policy = RETENTION_POLICIES[tier]
        results = []
        total_deleted = 0
        total_archived = 0

        logger.info(f"Starting retention cleanup: tier={tier}, dry_run={dry_run}")

        try:
            return await self._run_cleanup_inner(policy, dry_run, tier, total_deleted, total_archived, results)
        finally:
            set_platform_admin_mode(False)

    async def _run_cleanup_inner(self, policy, dry_run, tier, total_deleted, total_archived, results):
        for table, retention_days in policy.items():
            if retention_days < 0:
                # -1 means never expire
                logger.info(f"Skipping {table}: no expiration policy")
                continue

            if table not in TABLE_CONFIG:
                continue

            try:
                stats = await self._cleanup_table(table, retention_days)
                results.append(stats)
                total_deleted += stats.rows_deleted
                total_archived += stats.rows_archived
            except Exception as e:
                logger.error(f"Error cleaning up {table}: {e}")
                results.append(RetentionStats(
                    table=table,
                    rows_deleted=0,
                    rows_archived=0,
                    retention_days=retention_days,
                    cutoff_date=datetime.now(timezone.utc) - timedelta(days=retention_days),
                    duration_ms=0
                ))

        return {
            "success": True,
            "tier": tier,
            "dry_run": dry_run,
            "total_rows_deleted": total_deleted,
            "total_rows_archived": total_archived,
            "tables": [
                {
                    "table": s.table,
                    "deleted": s.rows_deleted,
                    "archived": s.rows_archived,
                    "retention_days": s.retention_days,
                    "cutoff_date": s.cutoff_date.isoformat(),
                    "duration_ms": s.duration_ms
                }
                for s in results
            ],
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

    async def _cleanup_table(self, table: str, retention_days: int) -> RetentionStats:
        """Clean up a single table based on retention policy."""
        from services.postgres_db import postgres_db

        config = TABLE_CONFIG[table]
        timestamp_col = config["timestamp_col"]
        cascade_tables = config["cascade"]

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        start_time = datetime.now(timezone.utc)

        rows_deleted = 0
        rows_archived = 0

        if not postgres_db.connected or postgres_db.pool is None:
            logger.warning(f"Database not connected, skipping {table}")
            return RetentionStats(
                table=table,
                rows_deleted=0,
                rows_archived=0,
                retention_days=retention_days,
                cutoff_date=cutoff_date,
                duration_ms=0
            )

        async with postgres_db.tenant_acquire() as conn:
            # Count rows to be deleted
            count_query = f"""
                SELECT COUNT(*) FROM {table}
                WHERE {timestamp_col} < $1
            """
            count = await conn.fetchval(count_query, cutoff_date)

            if count == 0:
                logger.info(f"No rows to delete in {table}")
                return RetentionStats(
                    table=table,
                    rows_deleted=0,
                    rows_archived=0,
                    retention_days=retention_days,
                    cutoff_date=cutoff_date,
                    duration_ms=(datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                )

            logger.info(f"Found {count} rows to delete in {table} (older than {cutoff_date})")

            if self._dry_run:
                rows_deleted = count
            else:
                # Archive if enabled
                if self._archive_enabled and self._s3_archive_bucket:
                    archived = await self._archive_to_s3(conn, table, timestamp_col, cutoff_date)
                    rows_archived = archived

                # Delete cascade tables first
                for cascade_table in cascade_tables:
                    # Assuming foreign key relationship
                    cascade_delete = f"""
                        DELETE FROM {cascade_table}
                        WHERE {table.rstrip('s')}_id IN (
                            SELECT id FROM {table}
                            WHERE {timestamp_col} < $1
                        )
                    """
                    try:
                        await conn.execute(cascade_delete, cutoff_date)
                    except Exception as e:
                        logger.warning(f"Cascade delete for {cascade_table} failed: {e}")

                # Delete from main table
                delete_query = f"""
                    DELETE FROM {table}
                    WHERE {timestamp_col} < $1
                """
                result = await conn.execute(delete_query, cutoff_date)
                rows_deleted = int(result.split()[-1]) if result else count

                logger.info(f"Deleted {rows_deleted} rows from {table}")

        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return RetentionStats(
            table=table,
            rows_deleted=rows_deleted,
            rows_archived=rows_archived,
            retention_days=retention_days,
            cutoff_date=cutoff_date,
            duration_ms=duration_ms
        )

    async def _archive_to_s3(
        self,
        conn,
        table: str,
        timestamp_col: str,
        cutoff_date: datetime
    ) -> int:
        """Archive rows to S3 before deletion."""
        try:
            import boto3
            import json

            s3 = boto3.client('s3')

            # Fetch rows to archive
            query = f"""
                SELECT * FROM {table}
                WHERE {timestamp_col} < $1
                LIMIT 10000
            """
            rows = await conn.fetch(query, cutoff_date)

            if not rows:
                return 0

            # Convert to JSON
            archive_data = [dict(row) for row in rows]

            # Upload to S3
            date_str = cutoff_date.strftime("%Y/%m/%d")
            key = f"archives/{table}/{date_str}/{table}_{int(datetime.now().timestamp())}.json"

            s3.put_object(
                Bucket=self._s3_archive_bucket,
                Key=key,
                Body=json.dumps(archive_data, default=str),
                ContentType='application/json'
            )

            logger.info(f"Archived {len(archive_data)} rows from {table} to s3://{self._s3_archive_bucket}/{key}")
            return len(archive_data)

        except Exception as e:
            logger.error(f"Failed to archive {table} to S3: {e}")
            return 0

    async def get_retention_status(self, tier: str = "community") -> Dict[str, Any]:
        """Get current retention status and storage usage."""
        from services.postgres_db import postgres_db, set_platform_admin_mode

        # Retention status queries across all tenants — need admin mode.
        set_platform_admin_mode(True)

        if tier not in RETENTION_POLICIES:
            tier = "community"

        policy = RETENTION_POLICIES[tier]
        status = {"tier": tier, "tables": {}}

        if not postgres_db.connected or postgres_db.pool is None:
            set_platform_admin_mode(False)
            return {"error": "Database not connected", "tier": tier}

        try:
            async with postgres_db.tenant_acquire() as conn:
                for table, retention_days in policy.items():
                    if table not in TABLE_CONFIG:
                        continue

                    config = TABLE_CONFIG[table]
                    timestamp_col = config["timestamp_col"]

                    try:
                        # Get table stats
                        stats_query = f"""
                            SELECT
                                COUNT(*) as total_rows,
                                MIN({timestamp_col}) as oldest_record,
                                MAX({timestamp_col}) as newest_record,
                                pg_total_relation_size('{table}') as size_bytes
                            FROM {table}
                        """
                        row = await conn.fetchrow(stats_query)

                        # Count rows that would be deleted
                        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days) if retention_days > 0 else None
                        expired_count = 0
                        if cutoff:
                            expired_query = f"""
                                SELECT COUNT(*) FROM {table}
                                WHERE {timestamp_col} < $1
                            """
                            expired_count = await conn.fetchval(expired_query, cutoff)

                        status["tables"][table] = {
                            "retention_days": retention_days if retention_days > 0 else "never",
                            "total_rows": row["total_rows"],
                            "expired_rows": expired_count,
                            "oldest_record": row["oldest_record"].isoformat() if row["oldest_record"] else None,
                            "newest_record": row["newest_record"].isoformat() if row["newest_record"] else None,
                            "size_mb": round(row["size_bytes"] / (1024 * 1024), 2) if row["size_bytes"] else 0,
                            "cutoff_date": cutoff.isoformat() if cutoff else None
                        }

                    except Exception as e:
                        logger.warning(f"Error getting stats for {table}: {e}")
                        status["tables"][table] = {"error": str(e)}

            return status
        finally:
            set_platform_admin_mode(False)


# Singleton instance
_retention_service: Optional[DataRetentionService] = None


def get_retention_service() -> DataRetentionService:
    """Get singleton retention service instance."""
    global _retention_service
    if _retention_service is None:
        _retention_service = DataRetentionService()
    return _retention_service
