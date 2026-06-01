# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Token blacklist for JWT session revocation.

Uses PostgreSQL for persistence (tokens stay revoked across server restarts).
Falls back to in-memory storage if the database is unavailable.
"""
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Dict

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """Database-backed JWT token blacklist with in-memory fallback."""

    def __init__(self):
        # In-memory fallback (used when DB is unavailable)
        self._memory_blacklist: Dict[str, float] = {}
        self._lock = threading.Lock()

    async def _get_pool(self):
        """Get database instance for tenant-aware connections."""
        try:
            from services.postgres_db import postgres_db
            if postgres_db.connected and postgres_db.pool is not None:
                return postgres_db
        except Exception:
            pass
        return None

    def revoke(self, jti: str, expires_at: float):
        """Add a token JTI to the blacklist (sync - uses memory, schedules DB write)."""
        with self._lock:
            self._memory_blacklist[jti] = expires_at
            self._cleanup_memory()

    async def revoke_async(self, jti: str, expires_at: float, reason: str = None):
        """Add a token JTI to the blacklist with database persistence."""
        # Always store in memory for fast lookups
        with self._lock:
            self._memory_blacklist[jti] = expires_at

        # Persist to database
        pool = await self._get_pool()
        if pool:
            try:
                expires_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
                async with pool.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO token_blacklist (jti, token_type, expires_at, reason)
                        VALUES ($1, 'token', $2, $3)
                        ON CONFLICT (jti) DO NOTHING
                        """,
                        jti, expires_dt, reason
                    )
            except Exception as e:
                logger.warning(f"Failed to persist token revocation to DB: {e}")

    def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked (sync - memory only)."""
        with self._lock:
            return jti in self._memory_blacklist

    async def is_revoked_async(self, jti: str) -> bool:
        """Check if a token JTI has been revoked (checks DB if not in memory)."""
        # Fast path: check memory first
        with self._lock:
            if jti in self._memory_blacklist:
                return True

        # Slow path: check database
        pool = await self._get_pool()
        if pool:
            try:
                async with pool.tenant_acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT 1 FROM token_blacklist WHERE jti = $1 AND expires_at > NOW()",
                        jti
                    )
                    if row:
                        # Cache in memory for future fast lookups
                        with self._lock:
                            self._memory_blacklist[jti] = time.time() + 3600  # Cache for 1hr
                        return True
            except Exception as e:
                logger.debug(f"DB blacklist check failed, using memory only: {e}")

        return False

    def revoke_all_for_user(self, username: str, before_timestamp: float):
        """Revoke all tokens issued before a timestamp (logout all devices)."""
        with self._lock:
            self._memory_blacklist[f"user:{username}"] = before_timestamp

    async def revoke_all_for_user_async(self, username: str, before_timestamp: float, reason: str = "logout_all"):
        """Revoke all tokens for a user with database persistence."""
        with self._lock:
            self._memory_blacklist[f"user:{username}"] = before_timestamp

        pool = await self._get_pool()
        if pool:
            try:
                expires_dt = datetime.fromtimestamp(before_timestamp, tz=timezone.utc)
                async with pool.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO token_blacklist (jti, token_type, username, expires_at, reason)
                        VALUES ($1, 'user', $2, $3, $4)
                        ON CONFLICT (jti) DO UPDATE SET expires_at = $3
                        """,
                        f"user:{username}", username, expires_dt, reason
                    )
            except Exception as e:
                logger.warning(f"Failed to persist user revocation to DB: {e}")

    def is_user_revoked(self, username: str, issued_at: float) -> bool:
        """Check if a user's tokens issued before a certain time are revoked."""
        with self._lock:
            key = f"user:{username}"
            if key in self._memory_blacklist:
                return issued_at < self._memory_blacklist[key]
            return False

    async def is_user_revoked_async(self, username: str, issued_at: float) -> bool:
        """Check user revocation with database fallback."""
        # Fast path: memory
        with self._lock:
            key = f"user:{username}"
            if key in self._memory_blacklist:
                return issued_at < self._memory_blacklist[key]

        # Slow path: database
        pool = await self._get_pool()
        if pool:
            try:
                async with pool.tenant_acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT expires_at FROM token_blacklist
                        WHERE jti = $1 AND token_type = 'user'
                        """,
                        f"user:{username}"
                    )
                    if row:
                        revoke_ts = row["expires_at"].timestamp()
                        # Cache in memory
                        with self._lock:
                            self._memory_blacklist[key] = revoke_ts
                        return issued_at < revoke_ts
            except Exception as e:
                logger.debug(f"DB user revocation check failed: {e}")

        return False

    async def load_from_db(self):
        """Load active blacklist entries from database into memory on startup."""
        pool = await self._get_pool()
        if not pool:
            return

        try:
            async with pool.tenant_acquire() as conn:
                rows = await conn.fetch(
                    "SELECT jti, token_type, expires_at FROM token_blacklist WHERE expires_at > NOW()"
                )
                with self._lock:
                    for row in rows:
                        self._memory_blacklist[row["jti"]] = row["expires_at"].timestamp()
                logger.info(f"Loaded {len(rows)} blacklist entries from database")
        except Exception as e:
            logger.warning(f"Failed to load blacklist from DB (table may not exist yet): {e}")

    async def cleanup_expired(self):
        """Remove expired entries from both memory and database."""
        self._cleanup_memory()

        pool = await self._get_pool()
        if pool:
            try:
                async with pool.tenant_acquire() as conn:
                    result = await conn.execute(
                        "DELETE FROM token_blacklist WHERE expires_at < NOW()"
                    )
                    logger.debug(f"Cleaned up expired blacklist entries: {result}")
            except Exception as e:
                logger.debug(f"DB blacklist cleanup failed: {e}")

    def _cleanup_memory(self):
        """Remove expired entries from in-memory store."""
        now = time.time()
        expired = [
            k for k, v in self._memory_blacklist.items()
            if isinstance(v, float) and v < now and not k.startswith("user:")
        ]
        for k in expired:
            del self._memory_blacklist[k]


# Singleton
_blacklist = TokenBlacklist()


def get_token_blacklist() -> TokenBlacklist:
    return _blacklist
