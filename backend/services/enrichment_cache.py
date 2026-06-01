# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enrichment Cache Service - Phase 2.2

Caches enrichment results with configurable TTL per IOC type.
Reduces API calls to threat intel providers.

TTL Configuration (default):
- IP: 7 days (can change quickly)
- Domain: 14 days
- Hash: 30 days (rarely changes)
- URL: 1 day (pages change frequently)
- Email: 30 days
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
import json


# Default TTL per IOC type (in days)
DEFAULT_TTL = {
    "ip": 7,
    "domain": 14,
    "hash": 30,
    "url": 1,
    "email": 30,
}


def _parse_enrichment_data(data: Any) -> Dict[str, Any]:
    """
    Parse enrichment data from database, handling both dict and string formats.

    JSONB columns may return strings if data was double-serialized.
    """
    if data is None:
        return {}
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}

# Global TTL override (None = use per-type TTL)
GLOBAL_TTL_OVERRIDE: Optional[int] = None


@dataclass
class CachedEnrichment:
    """A cached enrichment result"""
    id: str
    ioc_type: str
    ioc_value: str
    provider: str
    enrichment_data: Dict[str, Any]
    is_malicious: Optional[bool]
    threat_score: Optional[int]
    confidence: Optional[float]
    cached_at: datetime
    expires_at: datetime
    hit_count: int = 0
    last_accessed_at: Optional[datetime] = None

    @property
    def is_expired(self) -> bool:
        """Check if this cache entry has expired"""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_stale(self) -> bool:
        """
        Check if this cache entry is stale (> 80% of TTL elapsed).
        Stale entries should be refreshed in background.
        """
        total_ttl = (self.expires_at - self.cached_at).total_seconds()
        elapsed = (datetime.now(timezone.utc) - self.cached_at).total_seconds()
        return elapsed > (total_ttl * 0.8)


@dataclass
class CacheLookupResult:
    """Result of a cache lookup"""
    found: bool
    data: Optional[CachedEnrichment] = None
    is_stale: bool = False
    is_expired: bool = False
    ttl_remaining_seconds: int = 0


class EnrichmentCacheService:
    """
    Service for caching enrichment results.

    Usage:
        cache = EnrichmentCacheService()

        # Check cache before calling API
        result = await cache.get("8.8.8.8", "ip", "virustotal")
        if result.found and not result.is_expired:
            return result.data

        # After getting fresh data, store in cache
        await cache.store(
            ioc_value="8.8.8.8",
            ioc_type="ip",
            provider="virustotal",
            data={...},
            is_malicious=False,
            threat_score=0,
            confidence=0.95
        )
    """

    def __init__(self):
        self.ttl_config = DEFAULT_TTL.copy()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "stores": 0,
            "expirations": 0
        }

    async def _get_pool(self):
        """Get database instance for tenant-aware connections"""
        from services.postgres_db import postgres_db
        return postgres_db

    def get_ttl_days(self, ioc_type: str) -> int:
        """Get TTL in days for an IOC type"""
        if GLOBAL_TTL_OVERRIDE is not None:
            return GLOBAL_TTL_OVERRIDE
        return self.ttl_config.get(ioc_type.lower(), 7)

    def set_ttl(self, ioc_type: str, days: int) -> None:
        """Set TTL for an IOC type"""
        self.ttl_config[ioc_type.lower()] = days

    async def get(
        self,
        ioc_value: str,
        ioc_type: str,
        provider: Optional[str] = None
    ) -> CacheLookupResult:
        """
        Look up a cached enrichment result.

        Args:
            ioc_value: The IOC value (e.g., "8.8.8.8")
            ioc_type: Type of IOC (ip, domain, hash, url, email)
            provider: Optional specific provider to look up

        Returns:
            CacheLookupResult with found=True/False and data if found
        """
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                if provider:
                    row = await conn.fetchrow("""
                        SELECT id, ioc_type, ioc_value, provider, enrichment_data,
                               is_malicious, threat_score, confidence,
                               cached_at, expires_at, hit_count, last_accessed_at
                        FROM enrichment_cache
                        WHERE ioc_type = $1 AND ioc_value = $2 AND provider = $3
                        ORDER BY cached_at DESC LIMIT 1
                    """, ioc_type.lower(), ioc_value, provider)
                else:
                    row = await conn.fetchrow("""
                        SELECT id, ioc_type, ioc_value, provider, enrichment_data,
                               is_malicious, threat_score, confidence,
                               cached_at, expires_at, hit_count, last_accessed_at
                        FROM enrichment_cache
                        WHERE ioc_type = $1 AND ioc_value = $2
                        ORDER BY cached_at DESC LIMIT 1
                    """, ioc_type.lower(), ioc_value)

            if not row:
                self._stats["misses"] += 1
                return CacheLookupResult(found=False)

            cached = CachedEnrichment(
                id=str(row['id']),
                ioc_type=row['ioc_type'],
                ioc_value=row['ioc_value'],
                provider=row['provider'],
                enrichment_data=_parse_enrichment_data(row['enrichment_data']),
                is_malicious=row['is_malicious'],
                threat_score=row['threat_score'],
                confidence=float(row['confidence']) if row['confidence'] else None,
                cached_at=row['cached_at'],
                expires_at=row['expires_at'],
                hit_count=row['hit_count'] or 0,
                last_accessed_at=row['last_accessed_at']
            )

            # Check expiration
            now = datetime.now(timezone.utc)
            expires_at = cached.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            is_expired = now > expires_at
            ttl_remaining = max(0, int((expires_at - now).total_seconds()))

            if is_expired:
                self._stats["expirations"] += 1
                return CacheLookupResult(
                    found=True,
                    data=cached,
                    is_expired=True,
                    is_stale=True,
                    ttl_remaining_seconds=0
                )

            # Record cache hit
            await self._record_hit(cached.id)
            self._stats["hits"] += 1

            return CacheLookupResult(
                found=True,
                data=cached,
                is_expired=False,
                is_stale=cached.is_stale,
                ttl_remaining_seconds=ttl_remaining
            )

        except Exception as e:
            print(f"[CACHE] Error looking up cache: {e}")
            self._stats["misses"] += 1
            return CacheLookupResult(found=False)

    async def get_all_providers(
        self,
        ioc_value: str,
        ioc_type: str
    ) -> List[CachedEnrichment]:
        """
        Get cached results from all providers for an IOC.

        Returns:
            List of cached enrichment results, newest first
        """
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, ioc_type, ioc_value, provider, enrichment_data,
                           is_malicious, threat_score, confidence,
                           cached_at, expires_at, hit_count, last_accessed_at
                    FROM enrichment_cache
                    WHERE ioc_type = $1 AND ioc_value = $2
                    AND expires_at > NOW()
                    ORDER BY cached_at DESC
                """, ioc_type.lower(), ioc_value)

            return [
                CachedEnrichment(
                    id=str(row['id']),
                    ioc_type=row['ioc_type'],
                    ioc_value=row['ioc_value'],
                    provider=row['provider'],
                    enrichment_data=_parse_enrichment_data(row['enrichment_data']),
                    is_malicious=row['is_malicious'],
                    threat_score=row['threat_score'],
                    confidence=float(row['confidence']) if row['confidence'] else None,
                    cached_at=row['cached_at'],
                    expires_at=row['expires_at'],
                    hit_count=row['hit_count'] or 0,
                    last_accessed_at=row['last_accessed_at']
                )
                for row in rows
            ]

        except Exception as e:
            print(f"[CACHE] Error getting all providers: {e}")
            return []

    async def store(
        self,
        ioc_value: str,
        ioc_type: str,
        provider: str,
        data: Dict[str, Any],
        is_malicious: Optional[bool] = None,
        threat_score: Optional[int] = None,
        confidence: Optional[float] = None,
        ttl_days: Optional[int] = None
    ) -> str:
        """
        Store an enrichment result in cache.

        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            provider: Provider that supplied the data
            data: The enrichment data to cache
            is_malicious: Whether the IOC is malicious
            threat_score: Threat score (0-100)
            confidence: Confidence level (0-1)
            ttl_days: Optional override for TTL in days

        Returns:
            The cache entry ID
        """
        pool = await self._get_pool()

        # Calculate expiration
        if ttl_days is None:
            ttl_days = self.get_ttl_days(ioc_type)

        expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    INSERT INTO enrichment_cache
                        (ioc_type, ioc_value, provider, enrichment_data,
                         is_malicious, threat_score, confidence, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (ioc_type, ioc_value, provider)
                    DO UPDATE SET
                        enrichment_data = EXCLUDED.enrichment_data,
                        is_malicious = EXCLUDED.is_malicious,
                        threat_score = EXCLUDED.threat_score,
                        confidence = EXCLUDED.confidence,
                        cached_at = NOW(),
                        expires_at = EXCLUDED.expires_at,
                        hit_count = 0
                    RETURNING id
                """,
                    ioc_type.lower(),
                    ioc_value,
                    provider,
                    json.dumps(data) if isinstance(data, dict) else data,
                    is_malicious,
                    threat_score,
                    confidence,
                    expires_at
                )

            self._stats["stores"] += 1
            return str(row['id']) if row else None

        except Exception as e:
            print(f"[CACHE] Error storing cache entry: {e}")
            raise

    async def invalidate(
        self,
        ioc_value: str,
        ioc_type: str,
        provider: Optional[str] = None
    ) -> int:
        """
        Invalidate (delete) cached entries for an IOC.

        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            provider: Optional specific provider to invalidate

        Returns:
            Number of entries deleted
        """
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                if provider:
                    result = await conn.execute("""
                        DELETE FROM enrichment_cache
                        WHERE ioc_type = $1 AND ioc_value = $2 AND provider = $3
                    """, ioc_type.lower(), ioc_value, provider)
                else:
                    result = await conn.execute("""
                        DELETE FROM enrichment_cache
                        WHERE ioc_type = $1 AND ioc_value = $2
                    """, ioc_type.lower(), ioc_value)

            # Parse "DELETE X" to get count
            count = int(result.split()[-1]) if result else 0
            return count

        except Exception as e:
            print(f"[CACHE] Error invalidating cache: {e}")
            return 0

    async def cleanup_expired(self) -> int:
        """
        Delete expired cache entries.

        Returns:
            Number of entries deleted
        """
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                result = await conn.execute("""
                    DELETE FROM enrichment_cache
                    WHERE expires_at < NOW()
                """)

            count = int(result.split()[-1]) if result else 0
            if count > 0:
                print(f"[CACHE] Cleaned up {count} expired entries")
            return count

        except Exception as e:
            print(f"[CACHE] Error cleaning up expired entries: {e}")
            return 0

    async def _record_hit(self, entry_id: str) -> None:
        """Record a cache hit"""
        try:
            pool = await self._get_pool()
            async with pool.tenant_acquire() as conn:
                await conn.execute("""
                    UPDATE enrichment_cache
                    SET hit_count = hit_count + 1,
                        last_accessed_at = NOW()
                    WHERE id = $1
                """, entry_id)
        except Exception:
            pass  # Non-critical

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT
                        COUNT(*) as total_entries,
                        COUNT(*) FILTER (WHERE expires_at > NOW()) as active_entries,
                        COUNT(*) FILTER (WHERE expires_at <= NOW()) as expired_entries,
                        COALESCE(SUM(hit_count), 0) as total_hits,
                        AVG(hit_count) as avg_hits_per_entry,
                        COUNT(DISTINCT provider) as providers,
                        COUNT(DISTINCT ioc_type) as ioc_types
                    FROM enrichment_cache
                """)

            return {
                "database": {
                    "total_entries": row['total_entries'] or 0,
                    "active_entries": row['active_entries'] or 0,
                    "expired_entries": row['expired_entries'] or 0,
                    "total_hits": row['total_hits'] or 0,
                    "avg_hits_per_entry": float(row['avg_hits_per_entry'] or 0),
                    "providers": row['providers'] or 0,
                    "ioc_types": row['ioc_types'] or 0
                },
                "session": self._stats.copy(),
                "config": {
                    "ttl": self.ttl_config,
                    "global_override": GLOBAL_TTL_OVERRIDE
                }
            }

        except Exception as e:
            print(f"[CACHE] Error getting stats: {e}")
            return {
                "database": {},
                "session": self._stats.copy(),
                "config": {
                    "ttl": self.ttl_config,
                    "global_override": GLOBAL_TTL_OVERRIDE
                }
            }

    async def get_by_provider(
        self,
        provider: str,
        limit: int = 100
    ) -> List[CachedEnrichment]:
        """Get cached entries for a specific provider"""
        pool = await self._get_pool()

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, ioc_type, ioc_value, provider, enrichment_data,
                           is_malicious, threat_score, confidence,
                           cached_at, expires_at, hit_count, last_accessed_at
                    FROM enrichment_cache
                    WHERE provider = $1
                    AND expires_at > NOW()
                    ORDER BY cached_at DESC
                    LIMIT $2
                """, provider, limit)

            return [
                CachedEnrichment(
                    id=str(row['id']),
                    ioc_type=row['ioc_type'],
                    ioc_value=row['ioc_value'],
                    provider=row['provider'],
                    enrichment_data=_parse_enrichment_data(row['enrichment_data']),
                    is_malicious=row['is_malicious'],
                    threat_score=row['threat_score'],
                    confidence=float(row['confidence']) if row['confidence'] else None,
                    cached_at=row['cached_at'],
                    expires_at=row['expires_at'],
                    hit_count=row['hit_count'] or 0,
                    last_accessed_at=row['last_accessed_at']
                )
                for row in rows
            ]

        except Exception as e:
            print(f"[CACHE] Error getting by provider: {e}")
            return []


# Singleton instance
_cache_service: Optional[EnrichmentCacheService] = None


def get_cache_service() -> EnrichmentCacheService:
    """Get the global cache service instance"""
    global _cache_service
    if _cache_service is None:
        _cache_service = EnrichmentCacheService()
    return _cache_service


async def get_cached_enrichment(
    ioc_value: str,
    ioc_type: str,
    provider: Optional[str] = None
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Convenience function to get cached enrichment data.

    Returns:
        Tuple of (data_dict_or_None, was_cache_hit)
    """
    service = get_cache_service()
    result = await service.get(ioc_value, ioc_type, provider)

    if result.found and not result.is_expired:
        return result.data.enrichment_data, True

    return None, False


async def cache_enrichment(
    ioc_value: str,
    ioc_type: str,
    provider: str,
    data: Dict[str, Any],
    **kwargs
) -> str:
    """
    Convenience function to store enrichment data in cache.

    Returns:
        Cache entry ID
    """
    service = get_cache_service()
    return await service.store(ioc_value, ioc_type, provider, data, **kwargs)
