# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Deduplication Service - Phase 2.4

Groups and deduplicates alerts based on configurable rules.
"I don't want to see the same alert 47 times" - Every analyst, ever

Key features:
- Fingerprint-based deduplication using configurable fields
- Time-window grouping (group duplicates within X minutes)
- Configurable actions: group, suppress, merge, count_only
- Rule priority for complex matching scenarios
- Statistics tracking for duplicate detection
"""

import hashlib
import json
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class DedupeAction(str, Enum):
    GROUP = "group"        # Group duplicates under primary alert
    SUPPRESS = "suppress"  # Don't create duplicate alert at all
    MERGE = "merge"       # Merge data into existing alert
    COUNT_ONLY = "count_only"  # Create alert but mark as duplicate


@dataclass
class DedupeRule:
    """A deduplication rule configuration"""
    id: str
    name: str
    description: Optional[str]
    enabled: bool
    source_filter: Optional[str]
    category_filter: Optional[str]
    severity_filter: Optional[List[str]]
    fingerprint_fields: List[str]
    window_minutes: int
    action: str
    priority: int
    total_matches: int = 0
    duplicates_suppressed: int = 0


@dataclass
class DedupeCheckResult:
    """Result of checking if an alert is a duplicate"""
    is_duplicate: bool
    action: Optional[str] = None
    existing_group_id: Optional[str] = None
    existing_alert_id: Optional[str] = None
    fingerprint: Optional[str] = None
    rule_matched: Optional[DedupeRule] = None
    group_alert_count: int = 0


@dataclass
class AlertGroup:
    """A group of deduplicated alerts"""
    id: str
    fingerprint: str
    primary_alert_id: str
    dedupe_config_id: Optional[str]
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    status: str


class AlertDeduplicationService:
    """
    Service for deduplicating alerts.

    Usage:
        service = AlertDeduplicationService()

        # Check if incoming alert is a duplicate
        result = await service.check_duplicate(alert_data)

        if result.is_duplicate:
            if result.action == "suppress":
                # Don't create the alert
                return None
            elif result.action == "group":
                # Create alert linked to group
                alert_data["alert_group_id"] = result.existing_group_id
                alert_data["is_primary"] = False
    """

    def __init__(self):
        # Per-tenant cache. Each tenant gets its own rule list because
        # dedupe_config is now tenant-scoped (migration 074) and the
        # singleton service serves requests from many tenants.
        self._rules_by_tenant: Dict[str, List[DedupeRule]] = {}
        self._tenants_loaded: set = set()
        # Backwards-compat: legacy code paths read self._rules. Resolved
        # lazily via the property below to the current tenant's list.
        self._default_fields = ["source", "category", "title"]
        self._stats = {
            "checks": 0,
            "duplicates_found": 0,
            "suppressed": 0,
            "grouped": 0
        }

    def _current_tenant_id(self) -> Optional[str]:
        """Resolve current tenant from the tenant middleware ContextVar."""
        try:
            from middleware.tenant_middleware import current_tenant_id
            tid = current_tenant_id.get()
            return str(tid) if tid else None
        except Exception:
            return None

    @property
    def _rules(self) -> List[DedupeRule]:
        """Current tenant's rules (empty list if none cached)."""
        tid = self._current_tenant_id()
        if not tid:
            return []
        return self._rules_by_tenant.get(tid, [])

    @_rules.setter
    def _rules(self, value: List[DedupeRule]) -> None:
        tid = self._current_tenant_id()
        if tid:
            self._rules_by_tenant[tid] = value

    def _invalidate_cache(self, tenant_id: Optional[str] = None) -> None:
        """Drop cached rules for one tenant (or all if None)."""
        if tenant_id:
            self._rules_by_tenant.pop(tenant_id, None)
            self._tenants_loaded.discard(tenant_id)
        else:
            self._rules_by_tenant.clear()
            self._tenants_loaded.clear()

    async def _get_pool(self):
        """Get database instance for tenant-aware connections"""
        from services.postgres_db import postgres_db
        return postgres_db

    async def load_rules(self, force: bool = False) -> None:
        """Load deduplication rules from database for the current tenant."""
        tid = self._current_tenant_id()
        if not tid:
            # No tenant context — nothing to load (dedupe is per-tenant)
            return

        if tid in self._tenants_loaded and not force:
            return

        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                # RLS scopes this to the current tenant automatically.
                rows = await conn.fetch("""
                    SELECT id, name, description, enabled, source_filter, category_filter,
                           severity_filter, fingerprint_fields, window_minutes, action,
                           priority, total_matches, duplicates_suppressed
                    FROM dedupe_config
                    WHERE enabled = true
                    ORDER BY priority ASC
                """)

            self._rules_by_tenant[tid] = [
                DedupeRule(
                    id=str(row['id']),
                    name=row['name'],
                    description=row['description'],
                    enabled=row['enabled'],
                    source_filter=row['source_filter'],
                    category_filter=row['category_filter'],
                    severity_filter=row['severity_filter'],
                    fingerprint_fields=row['fingerprint_fields'] or self._default_fields,
                    window_minutes=row['window_minutes'] or 60,
                    action=row['action'] or 'group',
                    priority=row['priority'] or 100,
                    total_matches=row['total_matches'] or 0,
                    duplicates_suppressed=row['duplicates_suppressed'] or 0
                )
                for row in rows
            ]
            self._tenants_loaded.add(tid)

        except Exception as e:
            print(f"[DEDUPE] Warning: Could not load rules for tenant {tid}: {e}")
            self._rules_by_tenant[tid] = []
            self._tenants_loaded.add(tid)

    def calculate_fingerprint(
        self,
        alert_data: Dict[str, Any],
        fields: List[str]
    ) -> str:
        """
        Calculate a fingerprint hash for an alert based on specified fields.

        Args:
            alert_data: The alert data dict
            fields: List of field names to include in fingerprint

        Returns:
            SHA-256 hash of the concatenated field values
        """
        values = []

        for field_name in sorted(fields):
            value = self._get_nested_field(alert_data, field_name)
            if value is not None:
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, sort_keys=True)
                values.append(f"{field_name}:{value}")

        fingerprint_str = "|".join(values)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

    def _get_nested_field(self, data: Dict[str, Any], field_path: str) -> Any:
        """Get a potentially nested field from alert data"""
        parts = field_path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None

        return current

    async def check_duplicate(self, alert_data: Dict[str, Any]) -> DedupeCheckResult:
        """
        Check if an incoming alert is a duplicate of an existing alert.

        Args:
            alert_data: The incoming alert data

        Returns:
            DedupeCheckResult with duplicate status and recommended action
        """
        logger.info(f"[DEDUPE] Checking duplicate for alert: {alert_data.get('alert_id', 'unknown')}")
        await self.load_rules()
        self._stats["checks"] += 1

        # If no rules, no deduplication
        if not self._rules:
            logger.info(f"[DEDUPE] No rules loaded, skipping dedup check")
            return DedupeCheckResult(is_duplicate=False)

        logger.info(f"[DEDUPE] Found {len(self._rules)} active rules")

        # Find matching rule
        rule = self._find_matching_rule(alert_data)
        if not rule:
            logger.info(f"[DEDUPE] No matching rule found for alert")
            return DedupeCheckResult(is_duplicate=False)

        logger.info(f"[DEDUPE] Rule '{rule.name}' matched, calculating fingerprint with fields: {rule.fingerprint_fields}")

        # This was previously returning here incorrectly
        # Now we continue to check fingerprint
        if False:  # dummy block to fix diff
            return DedupeCheckResult(is_duplicate=False)

        # Calculate fingerprint
        fingerprint = self.calculate_fingerprint(alert_data, rule.fingerprint_fields)
        logger.info(f"[DEDUPE] Calculated fingerprint: {fingerprint[:16]}...")

        # Check for existing group with this fingerprint
        existing = await self._find_existing_group(fingerprint, rule.window_minutes)
        logger.info(f"[DEDUPE] Existing group check: {'Found' if existing else 'Not found'}")

        if existing:
            self._stats["duplicates_found"] += 1

            # Update group stats
            await self._update_group(
                existing["group_id"],
                existing["alert_id"],
                rule.id
            )

            if rule.action == DedupeAction.SUPPRESS:
                self._stats["suppressed"] += 1
            else:
                self._stats["grouped"] += 1

            return DedupeCheckResult(
                is_duplicate=True,
                action=rule.action,
                existing_group_id=existing["group_id"],
                existing_alert_id=existing["alert_id"],
                fingerprint=fingerprint,
                rule_matched=rule,
                group_alert_count=existing["count"]
            )

        # No existing group - create one for this first alert
        # This allows future alerts with same fingerprint to be grouped
        try:
            group_id = await self.create_group(alert_data.get('alert_id'), fingerprint, rule.id)
            logger.info(f"[DEDUPE] Created new group {group_id} for first alert with fingerprint")
        except Exception as e:
            logger.warning(f"[DEDUPE] Failed to create group: {e}")
            group_id = None

        return DedupeCheckResult(
            is_duplicate=False,
            fingerprint=fingerprint,
            rule_matched=rule,
            existing_group_id=group_id  # Return group_id so alert can be linked
        )

    def _find_matching_rule(self, alert_data: Dict[str, Any]) -> Optional[DedupeRule]:
        """Find the first matching dedupe rule for an alert"""
        for rule in self._rules:
            if not rule.enabled:
                continue

            # Check source filter
            if rule.source_filter:
                source = alert_data.get("source", "")
                if not self._matches_filter(source, rule.source_filter):
                    continue

            # Check category filter
            if rule.category_filter:
                category = alert_data.get("category", "")
                if not self._matches_filter(category, rule.category_filter):
                    continue

            # Check severity filter
            if rule.severity_filter:
                severity = alert_data.get("severity", "")
                if severity not in rule.severity_filter:
                    continue

            return rule

        return None

    def _matches_filter(self, value: str, pattern: str) -> bool:
        """Check if a value matches a filter pattern (supports glob/regex)"""
        if not pattern:
            return True

        # Convert glob pattern to regex
        if "*" in pattern and not pattern.startswith("^"):
            regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
            regex_pattern = f"^{regex_pattern}$"
        else:
            regex_pattern = pattern

        try:
            return bool(re.match(regex_pattern, value, re.IGNORECASE))
        except re.error:
            return value.lower() == pattern.lower()

    async def _find_existing_group(
        self,
        fingerprint: str,
        window_minutes: int
    ) -> Optional[Dict[str, Any]]:
        """Find an existing alert group with this fingerprint within the time window"""
        pool = await self._get_pool()

        try:
            window_start = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT id as group_id, primary_alert_id, alert_count
                    FROM alert_groups
                    WHERE fingerprint = $1
                    AND status = 'active'
                    AND last_seen > $2
                    LIMIT 1
                """, fingerprint, window_start)

            if row:
                return {
                    "group_id": str(row['group_id']),
                    "alert_id": str(row['primary_alert_id']),
                    "count": row['alert_count']
                }

            return None

        except Exception as e:
            print(f"[DEDUPE] Error finding existing group: {e}")
            return None

    async def _update_group(
        self,
        group_id: str,
        primary_alert_id: str,
        rule_id: str
    ) -> None:
        """Update group statistics when a duplicate is found"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                # Update alert group
                await conn.execute("""
                    UPDATE alert_groups
                    SET alert_count = alert_count + 1,
                        last_seen = NOW()
                    WHERE id = $1
                """, group_id)

                # Update primary alert duplicate count (primary_alert_id is a VARCHAR)
                await conn.execute("""
                    UPDATE alerts
                    SET duplicate_count = duplicate_count + 1,
                        last_seen = NOW()
                    WHERE alert_id = $1
                """, primary_alert_id)

                # Update rule statistics
                await conn.execute("""
                    UPDATE dedupe_config
                    SET total_matches = total_matches + 1,
                        duplicates_suppressed = duplicates_suppressed + 1,
                        updated_at = NOW()
                    WHERE id = $1
                """, rule_id)

        except Exception as e:
            print(f"[DEDUPE] Error updating group: {e}")

    async def create_group(
        self,
        alert_id: str,
        fingerprint: str,
        rule_id: Optional[str] = None
    ) -> str:
        """
        Create a new alert group for the first alert with a fingerprint.

        Args:
            alert_id: The primary alert ID (string like "ALT-XXXX")
            fingerprint: The calculated fingerprint
            rule_id: Optional rule ID that triggered the group

        Returns:
            The new group ID
        """
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                row = await conn.fetchrow("""
                    INSERT INTO alert_groups
                        (fingerprint, primary_alert_id, dedupe_config_id, alert_count, first_seen, last_seen, tenant_id)
                    VALUES ($1, $2, $3, 1, NOW(), NOW(), $4)
                    ON CONFLICT (fingerprint) DO UPDATE SET
                        last_seen = NOW(),
                        alert_count = alert_groups.alert_count + 1
                    RETURNING id
                """, fingerprint, alert_id, rule_id, _tid)

                group_id = str(row['id'])
                # NOTE: We don't update the alert here because it hasn't been saved yet
                # The webhook handler will include fingerprint and group_id when saving

            return group_id

        except Exception as e:
            logger.error(f"[DEDUPE] Error creating group: {e}")
            raise

    async def add_rule(
        self,
        name: str,
        fingerprint_fields: List[str],
        window_minutes: int = 60,
        action: str = "group",
        source_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        description: Optional[str] = None,
        priority: int = 100,
        created_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a new deduplication rule"""
        pool = await self._get_pool()

        tid = self._current_tenant_id()
        if not tid:
            raise RuntimeError("tenant context required to add a dedupe rule")

        async with pool.tenant_acquire() as conn:
            # Idempotent per-tenant: re-clicking Quick Add updates the
            # tenant's existing rule rather than 500ing on UNIQUE violation.
            # The UNIQUE is now (tenant_id, name) per migration 074 so
            # different tenants can have rules with the same name.
            row = await conn.fetchrow("""
                INSERT INTO dedupe_config
                    (name, description, source_filter, category_filter, severity_filter,
                     fingerprint_fields, window_minutes, action, priority, created_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid)
                ON CONFLICT (tenant_id, name) DO UPDATE SET
                    description        = EXCLUDED.description,
                    source_filter      = EXCLUDED.source_filter,
                    category_filter    = EXCLUDED.category_filter,
                    severity_filter    = EXCLUDED.severity_filter,
                    fingerprint_fields = EXCLUDED.fingerprint_fields,
                    window_minutes     = EXCLUDED.window_minutes,
                    action             = EXCLUDED.action,
                    priority           = EXCLUDED.priority,
                    enabled            = TRUE,
                    updated_at         = NOW()
                RETURNING id, created_at
            """,
                name, description, source_filter, category_filter, severity_filter,
                fingerprint_fields, window_minutes, action, priority, created_by, tid
            )

        self._invalidate_cache(tid)

        return {
            "id": str(row['id']),
            "name": name,
            "fingerprint_fields": fingerprint_fields,
            "window_minutes": window_minutes,
            "action": action,
            "created_at": row['created_at']
        }

    async def delete_rule(self, rule_id: str) -> bool:
        """Hard-delete a deduplication rule by id. RLS scopes to current tenant."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM dedupe_config WHERE id = $1::uuid",
                rule_id,
            )
        self._invalidate_cache(self._current_tenant_id())
        return "DELETE 1" in result

    async def update_rule(
        self,
        rule_id: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        fingerprint_fields: Optional[List[str]] = None,
        window_minutes: Optional[int] = None,
        action: Optional[str] = None,
        source_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        priority: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Partial update of a dedupe rule. Returns the new row, or None if not found."""
        sets: List[str] = []
        args: List[Any] = []
        for col, val in [
            ("name", name),
            ("description", description),
            ("enabled", enabled),
            ("fingerprint_fields", fingerprint_fields),
            ("window_minutes", window_minutes),
            ("action", action),
            ("source_filter", source_filter),
            ("category_filter", category_filter),
            ("severity_filter", severity_filter),
            ("priority", priority),
        ]:
            if val is not None:
                args.append(val)
                sets.append(f"{col} = ${len(args)}")
        if not sets:
            return None
        sets.append("updated_at = NOW()")
        args.append(rule_id)
        sql = (
            f"UPDATE dedupe_config SET {', '.join(sets)} "
            f"WHERE id = ${len(args)}::uuid "
            "RETURNING id, name, description, enabled, source_filter, category_filter, "
            "severity_filter, fingerprint_fields, window_minutes, action, priority, "
            "total_matches, duplicates_suppressed, created_at, updated_at, created_by"
        )
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow(sql, *args)
        if not row:
            return None
        self._invalidate_cache(self._current_tenant_id())
        return {
            "id": str(row["id"]),
            "name": row["name"],
            "description": row["description"],
            "enabled": row["enabled"],
            "source_filter": row["source_filter"],
            "category_filter": row["category_filter"],
            "severity_filter": row["severity_filter"],
            "fingerprint_fields": row["fingerprint_fields"],
            "window_minutes": row["window_minutes"],
            "action": row["action"],
            "priority": row["priority"],
            "total_matches": row["total_matches"] or 0,
            "duplicates_suppressed": row["duplicates_suppressed"] or 0,
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "created_by": row["created_by"],
        }

    async def list_rules(self, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """List all deduplication rules"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            if include_disabled:
                rows = await conn.fetch("""
                    SELECT id, name, description, enabled, source_filter, category_filter,
                           severity_filter, fingerprint_fields, window_minutes, action,
                           priority, total_matches, duplicates_suppressed,
                           created_at, updated_at, created_by
                    FROM dedupe_config
                    ORDER BY priority ASC
                """)
            else:
                rows = await conn.fetch("""
                    SELECT id, name, description, enabled, source_filter, category_filter,
                           severity_filter, fingerprint_fields, window_minutes, action,
                           priority, total_matches, duplicates_suppressed,
                           created_at, updated_at, created_by
                    FROM dedupe_config
                    WHERE enabled = true
                    ORDER BY priority ASC
                """)

        return [
            {
                "id": str(row['id']),
                "name": row['name'],
                "description": row['description'],
                "enabled": row['enabled'],
                "source_filter": row['source_filter'],
                "category_filter": row['category_filter'],
                "severity_filter": row['severity_filter'],
                "fingerprint_fields": row['fingerprint_fields'],
                "window_minutes": row['window_minutes'],
                "action": row['action'],
                "priority": row['priority'],
                "total_matches": row['total_matches'] or 0,
                "duplicates_suppressed": row['duplicates_suppressed'] or 0,
                "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                "created_by": row['created_by']
            }
            for row in rows
        ]

    async def get_group(self, group_id: str) -> Optional[AlertGroup]:
        """Get an alert group by ID"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT id, fingerprint, primary_alert_id, dedupe_config_id,
                           alert_count, first_seen, last_seen, status
                    FROM alert_groups
                    WHERE id = $1
                """, group_id)

            if not row:
                return None

            return AlertGroup(
                id=str(row['id']),
                fingerprint=row['fingerprint'],
                primary_alert_id=str(row['primary_alert_id']),
                dedupe_config_id=str(row['dedupe_config_id']) if row['dedupe_config_id'] else None,
                alert_count=row['alert_count'],
                first_seen=row['first_seen'],
                last_seen=row['last_seen'],
                status=row['status']
            )

        except Exception as e:
            print(f"[DEDUPE] Error getting group: {e}")
            return None

    async def get_group_alerts(self, group_id: str) -> List[Dict[str, Any]]:
        """Get all alerts in a group"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, alert_id, title, severity, status, source, category,
                           is_primary, created_at
                    FROM alerts
                    WHERE alert_group_id = $1
                    ORDER BY is_primary DESC, created_at DESC
                """, group_id)

            return [
                {
                    "id": str(row['id']),
                    "alert_id": row['alert_id'],
                    "title": row['title'],
                    "severity": row['severity'],
                    "status": row['status'],
                    "source": row['source'],
                    "category": row['category'],
                    "is_primary": row['is_primary'],
                    "created_at": row['created_at'].isoformat() if row['created_at'] else None
                }
                for row in rows
            ]

        except Exception as e:
            print(f"[DEDUPE] Error getting group alerts: {e}")
            return []

    async def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT
                        COUNT(*) as total_groups,
                        COALESCE(SUM(alert_count), 0) as total_alerts_grouped,
                        COALESCE(SUM(alert_count), 0) - COUNT(*) as duplicates_suppressed,
                        AVG(alert_count) as avg_group_size,
                        MAX(alert_count) as max_group_size
                    FROM alert_groups
                    WHERE status = 'active'
                """)

            return {
                "database": {
                    "total_groups": row['total_groups'] or 0,
                    "total_alerts_grouped": row['total_alerts_grouped'] or 0,
                    "duplicates_suppressed": row['duplicates_suppressed'] or 0,
                    "avg_group_size": float(row['avg_group_size'] or 0),
                    "max_group_size": row['max_group_size'] or 0
                },
                "session": self._stats.copy(),
                "rules_loaded": len(self._rules)
            }

        except Exception as e:
            print(f"[DEDUPE] Error getting stats: {e}")
            return {
                "database": {},
                "session": self._stats.copy(),
                "rules_loaded": len(self._rules)
            }


# Singleton instance
_dedupe_service: Optional[AlertDeduplicationService] = None


def get_dedupe_service() -> AlertDeduplicationService:
    """Get the global deduplication service instance"""
    global _dedupe_service
    if _dedupe_service is None:
        _dedupe_service = AlertDeduplicationService()
    return _dedupe_service


async def check_alert_duplicate(alert_data: Dict[str, Any]) -> DedupeCheckResult:
    """
    Convenience function to check if an alert is a duplicate.

    Returns:
        DedupeCheckResult with duplicate status and action
    """
    service = get_dedupe_service()
    return await service.check_duplicate(alert_data)
