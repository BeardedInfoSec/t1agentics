# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Exclusion Service - Phase 2.1

Manages IOC exclusion list for enrichment.
Supports CIDR notation, regex patterns, and various match types.

Key features:
- RFC1918 private IP blocking
- CIDR range matching
- Regex pattern matching for domains
- Configurable categories (internal, vendor, false_positive, whitelist, custom)
- TTL support for temporary exclusions
"""

import ipaddress
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum


class MatchType(str, Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    CONTAINS = "contains"
    CIDR = "cidr"
    REGEX = "regex"


class ExclusionCategory(str, Enum):
    INTERNAL = "internal"
    VENDOR = "vendor"
    FALSE_POSITIVE = "false_positive"
    WHITELIST = "whitelist"
    CUSTOM = "custom"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    EMAIL = "email"
    HASH = "hash"
    CIDR = "cidr"
    REGEX = "regex"


@dataclass
class ExclusionEntry:
    """An entry in the exclusion list"""
    id: str
    ioc_type: str
    ioc_value: str
    match_type: str
    reason: Optional[str]
    category: str
    added_by: Optional[str]
    expires_at: Optional[datetime]
    is_active: bool
    hit_count: int
    created_at: datetime


@dataclass
class ExclusionCheckResult:
    """Result of checking if an IOC is excluded"""
    is_excluded: bool
    reason: Optional[str] = None
    matched_rule: Optional[ExclusionEntry] = None
    match_type: Optional[str] = None


class ExclusionService:
    """
    Service for managing and checking IOC exclusions.

    Usage:
        service = ExclusionService()
        result = await service.check_excluded("192.168.1.100", "ip")
        if result.is_excluded:
            print(f"Excluded: {result.reason}")
    """

    def __init__(self):
        self._cache: Dict[str, List[ExclusionEntry]] = {}
        self._cache_loaded = False
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._cidr_networks: Dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}

    async def _get_pool(self):
        """Get database instance for tenant-aware connections"""
        from services.postgres_db import postgres_db
        return postgres_db

    async def load_exclusions(self, force: bool = False) -> None:
        """Load exclusion list from database into cache"""
        if self._cache_loaded and not force:
            return

        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, ioc_type, ioc_value, match_type, reason, category,
                           added_by, expires_at, is_active, hit_count, created_at
                    FROM exclusion_list
                    WHERE is_active = true
                    AND (expires_at IS NULL OR expires_at > NOW())
                    ORDER BY match_type, ioc_type
                """)

            self._cache = {}
            self._compiled_patterns = {}
            self._cidr_networks = {}

            for row in rows:
                entry = ExclusionEntry(
                    id=str(row['id']),
                    ioc_type=row['ioc_type'],
                    ioc_value=row['ioc_value'],
                    match_type=row['match_type'],
                    reason=row['reason'],
                    category=row['category'],
                    added_by=row['added_by'],
                    expires_at=row['expires_at'],
                    is_active=row['is_active'],
                    hit_count=row['hit_count'] or 0,
                    created_at=row['created_at']
                )

                # Group by IOC type for faster lookups
                if entry.ioc_type not in self._cache:
                    self._cache[entry.ioc_type] = []
                self._cache[entry.ioc_type].append(entry)

                # Also store CIDR entries under 'ip' for IP lookups
                if entry.match_type == MatchType.CIDR and entry.ioc_type == 'cidr':
                    if 'ip' not in self._cache:
                        self._cache['ip'] = []
                    self._cache['ip'].append(entry)

                # Pre-compile regex patterns
                if entry.match_type == MatchType.REGEX:
                    try:
                        pattern = entry.ioc_value.replace('.', r'\.')
                        pattern = pattern.replace('*', '.*')
                        self._compiled_patterns[entry.id] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        pass

                # Pre-parse CIDR networks
                if entry.match_type == MatchType.CIDR:
                    try:
                        self._cidr_networks[entry.id] = ipaddress.ip_network(entry.ioc_value, strict=False)
                    except ValueError:
                        pass

            self._cache_loaded = True

        except Exception as e:
            print(f"[EXCLUSION] Warning: Could not load exclusions: {e}")
            self._cache = {}
            self._cache_loaded = True

    async def check_excluded(self, ioc_value: str, ioc_type: str) -> ExclusionCheckResult:
        """
        Check if an IOC is in the exclusion list.

        Args:
            ioc_value: The IOC value to check (e.g., "192.168.1.100")
            ioc_type: Type of IOC (ip, domain, email, hash)

        Returns:
            ExclusionCheckResult with is_excluded=True/False and details
        """
        await self.load_exclusions()

        ioc_type = ioc_type.lower()
        ioc_value_lower = ioc_value.lower()

        entries = self._cache.get(ioc_type, [])

        for entry in entries:
            matched = False

            if entry.match_type == MatchType.EXACT:
                matched = entry.ioc_value.lower() == ioc_value_lower

            elif entry.match_type == MatchType.PREFIX:
                matched = ioc_value_lower.startswith(entry.ioc_value.lower())

            elif entry.match_type == MatchType.SUFFIX:
                matched = ioc_value_lower.endswith(entry.ioc_value.lower())

            elif entry.match_type == MatchType.CONTAINS:
                matched = entry.ioc_value.lower() in ioc_value_lower

            elif entry.match_type == MatchType.CIDR:
                matched = self._check_cidr(ioc_value, entry)

            elif entry.match_type == MatchType.REGEX:
                matched = self._check_regex(ioc_value, entry)

            if matched:
                await self._record_hit(entry.id)
                return ExclusionCheckResult(
                    is_excluded=True,
                    reason=entry.reason or f"Matches exclusion rule: {entry.ioc_value}",
                    matched_rule=entry,
                    match_type=entry.match_type
                )

        return ExclusionCheckResult(is_excluded=False)

    def _check_cidr(self, ip_value: str, entry: ExclusionEntry) -> bool:
        """Check if an IP is within a CIDR range"""
        try:
            network = self._cidr_networks.get(entry.id)
            if network is None:
                return False
            ip = ipaddress.ip_address(ip_value)
            return ip in network
        except ValueError:
            return False

    def _check_regex(self, value: str, entry: ExclusionEntry) -> bool:
        """Check if value matches a regex pattern"""
        pattern = self._compiled_patterns.get(entry.id)
        if pattern is None:
            return False
        return bool(pattern.match(value))

    async def _record_hit(self, entry_id: str) -> None:
        """Record a hit on an exclusion entry"""
        try:
            pool = await self._get_pool()
            async with pool.tenant_acquire() as conn:
                await conn.execute("""
                    UPDATE exclusion_list
                    SET hit_count = hit_count + 1,
                        last_hit_at = NOW()
                    WHERE id = $1
                """, entry_id)
        except Exception:
            pass

    async def add_exclusion(
        self,
        ioc_value: str,
        ioc_type: str,
        match_type: str = "exact",
        reason: Optional[str] = None,
        category: str = "custom",
        added_by: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Add a new exclusion to the list"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            from middleware.tenant_middleware import get_optional_tenant_id
            _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
            row = await conn.fetchrow("""
                INSERT INTO exclusion_list
                    (ioc_type, ioc_value, match_type, reason, category, added_by, expires_at, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (ioc_type, ioc_value, match_type)
                DO UPDATE SET
                    reason = EXCLUDED.reason,
                    category = EXCLUDED.category,
                    updated_at = NOW(),
                    is_active = true
                RETURNING id, created_at
            """, ioc_type, ioc_value, match_type, reason, category, added_by, expires_at, _tid)

        self._cache_loaded = False

        return {
            "id": str(row['id']),
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "match_type": match_type,
            "reason": reason,
            "category": category,
            "added_by": added_by,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "is_active": True,
            "hit_count": 0,
            "last_hit_at": None,
            "created_at": row['created_at'].isoformat() if row['created_at'] else None
        }

    async def remove_exclusion(self, entry_id: str) -> bool:
        """Remove an exclusion from the list"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            result = await conn.execute("""
                UPDATE exclusion_list
                SET is_active = false, updated_at = NOW()
                WHERE id = $1
            """, entry_id)

        self._cache_loaded = False
        return "UPDATE 1" in result

    async def list_exclusions(
        self,
        ioc_type: Optional[str] = None,
        category: Optional[str] = None,
        include_inactive: bool = False
    ) -> List[Dict[str, Any]]:
        """List all exclusions with optional filters"""
        pool = await self._get_pool()

        query = """
            SELECT id, ioc_type, ioc_value, match_type, reason, category,
                   added_by, expires_at, is_active, hit_count, last_hit_at,
                   created_at, updated_at
            FROM exclusion_list
            WHERE 1=1
        """
        params = []

        if not include_inactive:
            query += " AND is_active = true"

        if ioc_type:
            params.append(ioc_type)
            query += f" AND ioc_type = ${len(params)}"

        if category:
            params.append(category)
            query += f" AND category = ${len(params)}"

        query += " ORDER BY created_at DESC"

        async with pool.tenant_acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            {
                "id": str(row['id']),
                "ioc_type": row['ioc_type'],
                "ioc_value": row['ioc_value'],
                "match_type": row['match_type'],
                "reason": row['reason'],
                "category": row['category'],
                "added_by": row['added_by'],
                "expires_at": row['expires_at'].isoformat() if row['expires_at'] else None,
                "is_active": row['is_active'],
                "hit_count": row['hit_count'] or 0,
                "last_hit_at": row['last_hit_at'].isoformat() if row['last_hit_at'] else None,
                "created_at": row['created_at'].isoformat() if row['created_at'] else None
            }
            for row in rows
        ]

    async def bulk_add_exclusions(
        self,
        entries: List[Dict[str, Any]],
        added_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Bulk add exclusions from a list."""
        added = 0
        updated = 0
        failed = 0
        errors = []

        for entry in entries:
            try:
                ioc_value = entry.get('ioc_value', '').strip()
                ioc_type = entry.get('ioc_type', 'ip')

                if not ioc_value:
                    failed += 1
                    errors.append({"entry": entry, "error": "Empty IOC value"})
                    continue

                if ioc_type == 'auto':
                    ioc_type = self._detect_ioc_type(ioc_value)

                await self.add_exclusion(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    match_type=entry.get('match_type', 'exact'),
                    reason=entry.get('reason'),
                    category=entry.get('category', 'custom'),
                    added_by=added_by
                )
                added += 1

            except Exception as e:
                failed += 1
                errors.append({"entry": entry, "error": str(e)})

        return {
            "added": added,
            "updated": updated,
            "failed": failed,
            "errors": errors[:10]
        }

    def _detect_ioc_type(self, value: str) -> str:
        """Auto-detect IOC type from value"""
        if '/' in value and any(c.isdigit() for c in value.split('/')[-1]):
            try:
                ipaddress.ip_network(value, strict=False)
                return 'cidr'
            except ValueError:
                pass

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'

        if ':' in value and re.match(r'^[a-fA-F0-9:]+$', value):
            return 'ip'

        if '@' in value and '.' in value:
            return 'email'

        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'hash'
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'hash'
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'hash'

        if '*' in value:
            return 'regex'

        return 'domain'

    async def get_stats(self) -> Dict[str, Any]:
        """Get exclusion list statistics"""
        pool = await self._get_pool()

        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_active = true) as active,
                    COUNT(*) FILTER (WHERE is_active = false) as inactive,
                    COUNT(*) FILTER (WHERE category = 'internal') as internal,
                    COUNT(*) FILTER (WHERE category = 'vendor') as vendor,
                    COUNT(*) FILTER (WHERE category = 'false_positive') as false_positive,
                    COUNT(*) FILTER (WHERE category = 'whitelist') as whitelist,
                    COUNT(*) FILTER (WHERE category = 'custom') as custom,
                    COALESCE(SUM(hit_count), 0) as total_hits
                FROM exclusion_list
            """)

        return {
            "total": row['total'] or 0,
            "active": row['active'] or 0,
            "inactive": row['inactive'] or 0,
            "by_category": {
                "internal": row['internal'] or 0,
                "vendor": row['vendor'] or 0,
                "false_positive": row['false_positive'] or 0,
                "whitelist": row['whitelist'] or 0,
                "custom": row['custom'] or 0
            },
            "total_hits": row['total_hits'] or 0
        }


# Singleton instance
_exclusion_service: Optional[ExclusionService] = None


def get_exclusion_service() -> ExclusionService:
    """Get the global exclusion service instance"""
    global _exclusion_service
    if _exclusion_service is None:
        _exclusion_service = ExclusionService()
    return _exclusion_service


async def is_excluded(ioc_value: str, ioc_type: str) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to check if an IOC is excluded.

    Returns:
        Tuple of (is_excluded, reason)
    """
    service = get_exclusion_service()
    result = await service.check_excluded(ioc_value, ioc_type)
    return result.is_excluded, result.reason
