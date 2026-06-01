# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
EDL (External Dynamic List) Service

Core service for managing EDL lists, items, credentials, and content delivery.
Handles IOC normalization, deduplication, TTL expiration, and cache generation.

Type-restricted: each list is strictly IP, domain, or URL.
No mixed-type lists - firewalls require homogeneous lists.
"""

import hashlib
import ipaddress
import logging
import re
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import bcrypt

logger = logging.getLogger(__name__)


# ============================================================================
# IOC VALIDATION & NORMALIZATION
# ============================================================================

IOC_VALIDATORS = {
    'ip': re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'  # IPv4 with optional CIDR
    ),
    'domain': re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    ),
    'url': re.compile(r'^https?://.+'),
}

# Max items per type (safety limits)
MAX_LIST_SIZES = {
    'ip': 1_000_000,
    'domain': 500_000,
    'url': 100_000,
}


def validate_ioc(value: str, ioc_type: str) -> bool:
    """Validate an IOC value against its declared type."""
    value = value.strip()
    if not value:
        return False

    validator = IOC_VALIDATORS.get(ioc_type)
    if not validator:
        return False

    if not validator.match(value):
        return False

    # Extra validation for IPs
    if ioc_type == 'ip':
        try:
            parts = value.split('/')
            ip = ipaddress.ip_address(parts[0])
            if parts[0] != str(ip):
                pass  # Will normalize later
            if len(parts) == 2:
                prefix = int(parts[1])
                if prefix < 0 or prefix > 32:
                    return False
                # Block overly broad CIDRs (wider than /8 = 16M+ IPs)
                if prefix < 8:
                    return False
        except ValueError:
            return False

    return True


def normalize_ioc(value: str, ioc_type: str) -> str:
    """
    Normalize an IOC for deduplication.

    Rules:
    - IPs: Standard format, no leading zeros
    - Domains: Lowercase, strip www., remove trailing dot
    - URLs: Lowercase domain, normalize path
    """
    value = value.strip()

    if ioc_type == 'ip':
        parts = value.split('/')
        try:
            normalized_ip = str(ipaddress.ip_address(parts[0]))
            if len(parts) == 2:
                return f"{normalized_ip}/{parts[1]}"
            return normalized_ip
        except ValueError:
            return value.lower()

    elif ioc_type == 'domain':
        normalized = value.lower().rstrip('.')
        if normalized.startswith('www.'):
            normalized = normalized[4:]
        return normalized

    elif ioc_type == 'url':
        try:
            parsed = urllib.parse.urlparse(value)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            path = parsed.path.rstrip('/') or '/'
            query = parsed.query
            normalized = f"{parsed.scheme}://{domain}{path}"
            if query:
                normalized += f"?{query}"
            return normalized
        except Exception:
            return value.lower()

    return value.lower()


def generate_token() -> Tuple[str, str, str]:
    """
    Generate a secure EDL access token.
    Returns (raw_token, token_hash, token_prefix).
    """
    raw = f"edl_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    hashed = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()
    return raw, hashed, prefix


def verify_token_hash(raw_token: str, stored_hash: str) -> bool:
    """Verify a raw token against its bcrypt hash."""
    try:
        return bcrypt.checkpw(raw_token.encode(), stored_hash.encode())
    except Exception:
        return False


# ============================================================================
# EDL SERVICE
# ============================================================================

class EDLService:
    """
    Core service for EDL list management and content delivery.

    Handles:
    - List CRUD operations
    - Item add/remove with normalization and dedup
    - Credential management (multi-credential per list)
    - Content cache generation and delivery
    - Access authentication
    - Change logging
    """

    def __init__(self):
        self._initialized = False

    async def _get_pool(self):
        from services.postgres_db import postgres_db
        if not postgres_db.pool:
            raise RuntimeError("Database not available")
        return postgres_db

    # ========================================================================
    # LIST MANAGEMENT
    # ========================================================================

    async def create_list(
        self,
        name: str,
        slug: str,
        ioc_type: str,
        description: str = None,
        list_type: str = 'static',
        max_items: int = 150000,
        ttl_default_seconds: int = 0,
        include_comments: bool = True,
        tenant_id: str = 'default',
        created_by: str = None,
        tags: List[str] = None,
    ) -> Dict[str, Any]:
        """Create a new EDL list."""
        if ioc_type not in ('ip', 'domain', 'url'):
            raise ValueError(f"Invalid ioc_type '{ioc_type}'. Must be: ip, domain, url")

        if list_type not in ('static', 'dynamic', 'hybrid'):
            raise ValueError(f"Invalid list_type '{list_type}'")

        # Store tags in the description as a structured prefix if provided,
        # since the schema doesn't have a tags column yet.
        # Format: [tags:ransomware,c2,phishing] Description text here
        effective_description = description or ''
        if tags:
            clean_tags = [t.strip() for t in tags if t.strip()]
            if clean_tags:
                tag_prefix = f"[tags:{','.join(clean_tags)}]"
                effective_description = f"{tag_prefix} {effective_description}".strip()

        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO edl_lists (
                    name, slug, description, ioc_type, list_type,
                    max_items, ttl_default_seconds, include_comments,
                    tenant_id, created_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING *
            ''',
                name, slug, effective_description, ioc_type, list_type,
                max_items, ttl_default_seconds, include_comments,
                tenant_id, created_by
            )
            result = dict(row)
            # Parse tags back out for API response
            if tags:
                result['tags'] = [t.strip() for t in tags if t.strip()]
            logger.info(f"EDL list created: {name} (type={ioc_type}, slug={slug}, tags={tags})")
            return result

    async def get_list(self, list_id: str, tenant_id: str = None) -> Optional[Dict[str, Any]]:
        """Get a list by ID, optionally filtered by tenant_id."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            if tenant_id:
                row = await conn.fetchrow(
                    'SELECT * FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                row = await conn.fetchrow(
                    'SELECT * FROM edl_lists WHERE list_id = $1', list_id
                )
            return dict(row) if row else None

    async def get_list_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Get a list by its URL slug."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM edl_lists WHERE slug = $1 AND enabled = TRUE', slug
            )
            return dict(row) if row else None

    async def list_all(
        self,
        tenant_id: str = 'default',
        ioc_type: str = None,
        enabled_only: bool = True,
        page: int = 1,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List all EDL lists with pagination."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            where = ["tenant_id = $1"]
            params: list = [tenant_id]
            idx = 2

            if enabled_only:
                where.append("enabled = TRUE")

            if ioc_type:
                where.append(f"ioc_type = ${idx}")
                params.append(ioc_type)
                idx += 1

            where_clause = " AND ".join(where)

            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM edl_lists WHERE {where_clause}",
                *params
            )

            offset = (page - 1) * limit
            params.extend([limit, offset])
            rows = await conn.fetch(f'''
                SELECT * FROM edl_lists
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ${idx} OFFSET ${idx + 1}
            ''', *params)

            return {
                "lists": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "limit": limit,
                "pages": max(1, (total + limit - 1) // limit),
            }

    async def update_list(self, list_id: str, updates: Dict[str, Any], tenant_id: str = None) -> Optional[Dict[str, Any]]:
        """Update list properties (not items)."""
        allowed = {
            'name', 'description', 'max_items', 'ttl_default_seconds',
            'include_comments', 'enabled', 'refresh_interval_seconds',
        }
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            raise ValueError("No valid fields to update")

        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            sets = []
            params = []
            idx = 1
            for key, val in filtered.items():
                sets.append(f"{key} = ${idx}")
                params.append(val)
                idx += 1

            sets.append(f"updated_at = CURRENT_TIMESTAMP")
            params.append(list_id)
            where = f"list_id = ${idx}"
            idx += 1

            if tenant_id:
                params.append(tenant_id)
                where += f" AND tenant_id = ${idx}"

            row = await conn.fetchrow(f'''
                UPDATE edl_lists
                SET {", ".join(sets)}
                WHERE {where}
                RETURNING *
            ''', *params)

            if row:
                logger.info(f"EDL list updated: {list_id}")
            return dict(row) if row else None

    async def delete_list(self, list_id: str, tenant_id: str = None) -> bool:
        """Delete a list and all associated data (cascades)."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            if tenant_id:
                result = await conn.execute(
                    'DELETE FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                result = await conn.execute(
                    'DELETE FROM edl_lists WHERE list_id = $1', list_id
                )
            deleted = result.split()[-1]
            if deleted != '0':
                logger.info(f"EDL list deleted: {list_id}")
            return deleted != '0'

    # ========================================================================
    # ITEM MANAGEMENT
    # ========================================================================

    async def add_item(
        self,
        list_id: str,
        ioc_value: str,
        tenant_id: str = None,
        source_type: str = 'manual',
        source_id: str = None,
        added_by: str = None,
        comment: str = None,
        confidence: float = None,
        severity: str = None,
        ttl_seconds: int = None,
    ) -> Dict[str, Any]:
        """
        Add a single IOC to a list.
        Validates type, normalizes, deduplicates via ON CONFLICT.
        """
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            # Get list to check type (with tenant_id filter if provided)
            if tenant_id:
                edl = await conn.fetchrow(
                    'SELECT ioc_type, max_items, item_count, ttl_default_seconds FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                edl = await conn.fetchrow(
                    'SELECT ioc_type, max_items, item_count, ttl_default_seconds FROM edl_lists WHERE list_id = $1',
                    list_id
                )
            if not edl:
                raise ValueError(f"EDL list not found: {list_id}")

            list_ioc_type = edl['ioc_type']

            # Validate IOC matches list type
            if not validate_ioc(ioc_value, list_ioc_type):
                raise ValueError(
                    f"Invalid {list_ioc_type} value: '{ioc_value}'"
                )

            # Check list capacity
            if edl['item_count'] >= edl['max_items']:
                raise ValueError(
                    f"List at capacity ({edl['max_items']} items)"
                )

            normalized = normalize_ioc(ioc_value, list_ioc_type)

            # Calculate expiration
            ttl = ttl_seconds or edl['ttl_default_seconds']
            expires_at = None
            if ttl and ttl > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

            row = await conn.fetchrow('''
                INSERT INTO edl_items (
                    list_id, ioc_value, ioc_type, ioc_normalized,
                    confidence, severity, source_label, comment,
                    source_type, source_id, added_by, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (list_id, ioc_normalized) DO UPDATE SET
                    confidence = COALESCE(EXCLUDED.confidence, edl_items.confidence),
                    severity = COALESCE(EXCLUDED.severity, edl_items.severity),
                    comment = COALESCE(EXCLUDED.comment, edl_items.comment),
                    expires_at = GREATEST(EXCLUDED.expires_at, edl_items.expires_at),
                    added_at = CURRENT_TIMESTAMP
                RETURNING *
            ''',
                list_id, ioc_value.strip(), list_ioc_type, normalized,
                confidence, severity, source_type, comment,
                source_type, source_id, added_by, expires_at
            )

            # Update item count
            await self._refresh_item_count(conn, list_id)

            # Log change
            await self._log_change(
                conn, list_id, 'add', ioc_value.strip(), list_ioc_type,
                changed_by=added_by, source_type=source_type, source_id=source_id
            )

            return dict(row)

    async def add_items_bulk(
        self,
        list_id: str,
        ioc_values: List[str],
        tenant_id: str = None,
        source_type: str = 'manual',
        source_id: str = None,
        added_by: str = None,
        comment: str = None,
        ttl_seconds: int = None,
        confidence: float = None,
        severity: str = None,
    ) -> Dict[str, Any]:
        """Add multiple IOCs to a list. Returns counts of added/skipped."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            if tenant_id:
                edl = await conn.fetchrow(
                    'SELECT ioc_type, max_items, item_count, ttl_default_seconds FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                edl = await conn.fetchrow(
                    'SELECT ioc_type, max_items, item_count, ttl_default_seconds FROM edl_lists WHERE list_id = $1',
                    list_id
                )
            if not edl:
                raise ValueError(f"EDL list not found: {list_id}")

            list_ioc_type = edl['ioc_type']
            ttl = ttl_seconds or edl['ttl_default_seconds']
            expires_at = None
            if ttl and ttl > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

            added = 0
            skipped = 0
            invalid = 0
            capacity_remaining = edl['max_items'] - edl['item_count']

            for raw_value in ioc_values:
                value = raw_value.strip()
                if not value or value.startswith('#'):
                    continue

                if added >= capacity_remaining:
                    skipped += len(ioc_values) - added - invalid
                    break

                if not validate_ioc(value, list_ioc_type):
                    invalid += 1
                    continue

                normalized = normalize_ioc(value, list_ioc_type)

                try:
                    await conn.execute('''
                        INSERT INTO edl_items (
                            list_id, ioc_value, ioc_type, ioc_normalized,
                            source_label, comment, source_type, source_id,
                            added_by, expires_at, confidence, severity
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        ON CONFLICT (list_id, ioc_normalized) DO UPDATE SET
                            expires_at = GREATEST(EXCLUDED.expires_at, edl_items.expires_at),
                            confidence = COALESCE(EXCLUDED.confidence, edl_items.confidence),
                            severity = COALESCE(EXCLUDED.severity, edl_items.severity),
                            added_at = CURRENT_TIMESTAMP
                    ''',
                        list_id, value, list_ioc_type, normalized,
                        source_type, comment, source_type, source_id,
                        added_by, expires_at, confidence, severity
                    )
                    added += 1
                except Exception as e:
                    logger.warning(f"EDL bulk add skip: {value} - {e}")
                    skipped += 1

            await self._refresh_item_count(conn, list_id)

            # Log bulk change
            await self._log_change(
                conn, list_id, 'bulk_add',
                f"{added} items", list_ioc_type,
                changed_by=added_by, source_type=source_type, source_id=source_id,
                reason=comment
            )

            return {"added": added, "skipped": skipped, "invalid": invalid}

    async def remove_item(
        self,
        list_id: str,
        ioc_value: str,
        tenant_id: str = None,
        removed_by: str = None,
        reason: str = None,
    ) -> bool:
        """Remove an IOC from a list by value."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            if tenant_id:
                edl = await conn.fetchrow(
                    'SELECT ioc_type FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                edl = await conn.fetchrow(
                    'SELECT ioc_type FROM edl_lists WHERE list_id = $1', list_id
                )
            if not edl:
                raise ValueError(f"EDL list not found: {list_id}")

            normalized = normalize_ioc(ioc_value.strip(), edl['ioc_type'])

            result = await conn.execute('''
                DELETE FROM edl_items
                WHERE list_id = $1 AND ioc_normalized = $2
            ''', list_id, normalized)

            deleted = result.split()[-1]
            removed = deleted != '0'

            if removed:
                await self._refresh_item_count(conn, list_id)
                await self._log_change(
                    conn, list_id, 'remove', ioc_value.strip(), edl['ioc_type'],
                    changed_by=removed_by, reason=reason
                )

            return removed

    async def remove_items_bulk(
        self,
        list_id: str,
        ioc_values: List[str],
        tenant_id: str = None,
        removed_by: str = None,
        reason: str = None,
    ) -> Dict[str, int]:
        """Remove multiple IOCs from a list."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            if tenant_id:
                edl = await conn.fetchrow(
                    'SELECT ioc_type FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
            else:
                edl = await conn.fetchrow(
                    'SELECT ioc_type FROM edl_lists WHERE list_id = $1', list_id
                )
            if not edl:
                raise ValueError(f"EDL list not found: {list_id}")

            removed = 0
            not_found = 0

            for raw_value in ioc_values:
                value = raw_value.strip()
                if not value:
                    continue

                normalized = normalize_ioc(value, edl['ioc_type'])
                result = await conn.execute(
                    'DELETE FROM edl_items WHERE list_id = $1 AND ioc_normalized = $2',
                    list_id, normalized
                )
                if result.split()[-1] != '0':
                    removed += 1
                else:
                    not_found += 1

            await self._refresh_item_count(conn, list_id)
            await self._log_change(
                conn, list_id, 'bulk_remove',
                f"{removed} items", edl['ioc_type'],
                changed_by=removed_by, reason=reason
            )

            return {"removed": removed, "not_found": not_found}

    async def get_items(
        self,
        list_id: str,
        tenant_id: str = None,
        page: int = 1,
        limit: int = 100,
        include_expired: bool = False,
        search: str = None,
    ) -> Dict[str, Any]:
        """Get items in a list with pagination and optional search."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            # Verify list belongs to tenant if tenant_id provided
            if tenant_id:
                edl = await conn.fetchrow(
                    'SELECT list_id FROM edl_lists WHERE list_id = $1 AND tenant_id = $2',
                    list_id, tenant_id
                )
                if not edl:
                    raise ValueError(f"EDL list not found: {list_id}")

            where = "list_id = $1"
            params: list = [list_id]
            idx = 2
            if not include_expired:
                where += " AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"

            if search:
                where += f" AND ioc_value ILIKE ${idx}"
                params.append(f"%{search}%")
                idx += 1

            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM edl_items WHERE {where}", *params
            )

            offset = (page - 1) * limit
            params.extend([limit, offset])
            rows = await conn.fetch(f'''
                SELECT * FROM edl_items
                WHERE {where}
                ORDER BY added_at DESC
                LIMIT ${idx} OFFSET ${idx + 1}
            ''', *params)

            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "limit": limit,
            }

    async def expire_items(self) -> int:
        """Remove expired items across all lists. Run as background job."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            result = await conn.execute('''
                DELETE FROM edl_items
                WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
            ''')
            deleted = int(result.split()[-1])

            if deleted > 0:
                logger.info(f"EDL: expired {deleted} items")
                # Refresh counts for affected lists
                await conn.execute('''
                    UPDATE edl_lists SET
                        item_count = (
                            SELECT COUNT(*) FROM edl_items
                            WHERE edl_items.list_id = edl_lists.list_id
                              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                        ),
                        updated_at = CURRENT_TIMESTAMP
                ''')

            return deleted

    # ========================================================================
    # CONTENT GENERATION & DELIVERY
    # ========================================================================

    async def generate_content(self, list_id: str) -> str:
        """
        Generate plain-text EDL content and cache it.
        Returns the text content ready for firewall consumption.
        """
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            edl = await conn.fetchrow(
                'SELECT * FROM edl_lists WHERE list_id = $1', list_id
            )
            if not edl:
                raise ValueError(f"EDL list not found: {list_id}")

            # Fetch active items
            rows = await conn.fetch('''
                SELECT ioc_value, comment FROM edl_items
                WHERE list_id = $1
                  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ORDER BY added_at ASC
                LIMIT $2
            ''', list_id, edl['max_items'])

            # Build plain-text content
            lines = []
            if edl['include_comments']:
                lines.append(f"# {edl['name']}")
                lines.append(f"# Type: {edl['ioc_type']}")
                lines.append(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
                lines.append(f"# Items: {len(rows)}")
                lines.append(f"# Source: T1 Agentics EDL")
                lines.append("")

            for row in rows:
                lines.append(row['ioc_value'])

            content = "\n".join(lines) + "\n"
            content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

            # Cache the generated content
            await conn.execute('''
                INSERT INTO edl_content_cache (
                    list_id, content_text, item_count, content_hash,
                    generated_at, expires_at
                ) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP + $5 * INTERVAL '1 second')
                ON CONFLICT (list_id) DO UPDATE SET
                    content_text = EXCLUDED.content_text,
                    item_count = EXCLUDED.item_count,
                    content_hash = EXCLUDED.content_hash,
                    generated_at = CURRENT_TIMESTAMP,
                    expires_at = CURRENT_TIMESTAMP + $5 * INTERVAL '1 second'
            ''', list_id, content, len(rows), content_hash,
                edl['refresh_interval_seconds'])

            # Update list metadata
            await conn.execute('''
                UPDATE edl_lists SET
                    last_generated_at = CURRENT_TIMESTAMP,
                    item_count = $2,
                    content_hash = $3
                WHERE list_id = $1
            ''', list_id, len(rows), content_hash)

            return content

    async def get_cached_content(self, list_id: str) -> Optional[Dict[str, Any]]:
        """Get cached content if still valid, otherwise regenerate."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            cached = await conn.fetchrow('''
                SELECT content_text, content_hash, item_count, generated_at
                FROM edl_content_cache
                WHERE list_id = $1
                  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ''', list_id)

            if cached:
                return {
                    "content": cached['content_text'],
                    "content_hash": cached['content_hash'],
                    "item_count": cached['item_count'],
                    "generated_at": cached['generated_at'],
                    "cache_hit": True,
                }

        # Cache miss - regenerate
        content = await self.generate_content(list_id)
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            cached = await conn.fetchrow(
                'SELECT content_hash, item_count, generated_at FROM edl_content_cache WHERE list_id = $1',
                list_id
            )
            return {
                "content": content,
                "content_hash": cached['content_hash'] if cached else None,
                "item_count": cached['item_count'] if cached else 0,
                "generated_at": cached['generated_at'] if cached else datetime.now(timezone.utc),
                "cache_hit": False,
            }

    # ========================================================================
    # CREDENTIAL MANAGEMENT
    # ========================================================================

    async def create_credential(
        self,
        list_id: str,
        name: str,
        auth_type: str,
        created_by: str = None,
        description: str = None,
        expires_at: datetime = None,
        ip_allowlist: List[str] = None,
        basic_username: str = None,
        basic_password: str = None,
    ) -> Dict[str, Any]:
        """
        Create an access credential for a list.
        For token auth, returns the raw token (only shown once).
        """
        pool = await self._get_pool()

        raw_token = None
        token_hash = None
        token_prefix = None
        password_hash = None

        if auth_type == 'token':
            raw_token, token_hash, token_prefix = generate_token()
        elif auth_type == 'basic':
            if not basic_username or not basic_password:
                raise ValueError("basic_username and basic_password required for basic auth")
            password_hash = bcrypt.hashpw(basic_password.encode(), bcrypt.gensalt()).decode()
        elif auth_type == 'ip_allowlist':
            if not ip_allowlist:
                raise ValueError("ip_allowlist required for ip_allowlist auth")

        async with pool.tenant_acquire() as conn:
            import json
            import uuid as _uuid
            from middleware.tenant_middleware import get_optional_tenant_id
            _tenant_id = get_optional_tenant_id()

            row = await conn.fetchrow('''
                INSERT INTO edl_credentials (
                    list_id, auth_type, token_hash, token_prefix,
                    basic_username, basic_password_hash, ip_allowlist,
                    name, description, expires_at, created_by,
                    tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING credential_id, list_id, auth_type, token_prefix,
                    basic_username, name, description, enabled,
                    expires_at, created_at
            ''',
                list_id, auth_type, token_hash, token_prefix,
                basic_username, password_hash,
                json.dumps(ip_allowlist) if ip_allowlist else None,
                name, description, expires_at, created_by,
                _uuid.UUID(str(_tenant_id)) if _tenant_id else None
            )

            result = dict(row)
            if raw_token:
                result['token'] = raw_token  # Only returned on creation
            return result

    async def authenticate_request(
        self,
        list_id: str,
        client_ip: str,
        auth_header: str = None,
        edl_token_header: str = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Authenticate an EDL request against all active credentials for a list.
        Returns (is_authenticated, credential_id).
        """
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            creds = await conn.fetch('''
                SELECT * FROM edl_credentials
                WHERE list_id = $1 AND enabled = TRUE
                  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ORDER BY created_at DESC
            ''', list_id)

            if not creds:
                # No credentials = public list
                return (True, None)

            for cred in creds:
                cred = dict(cred)
                auth_type = cred['auth_type']

                if auth_type == 'none':
                    await self._record_cred_use(conn, cred['credential_id'])
                    return (True, str(cred['credential_id']))

                if auth_type == 'ip_allowlist':
                    if self._check_ip_allowlist(client_ip, cred.get('ip_allowlist')):
                        await self._record_cred_use(conn, cred['credential_id'])
                        return (True, str(cred['credential_id']))

                if auth_type == 'token' and cred.get('token_hash'):
                    raw = None
                    if auth_header and auth_header.startswith('Bearer '):
                        raw = auth_header[7:]
                    elif edl_token_header:
                        raw = edl_token_header
                    if raw and verify_token_hash(raw, cred['token_hash']):
                        await self._record_cred_use(conn, cred['credential_id'])
                        return (True, str(cred['credential_id']))

                if auth_type == 'basic' and auth_header and auth_header.startswith('Basic '):
                    import base64
                    try:
                        decoded = base64.b64decode(auth_header[6:]).decode()
                        username, password = decoded.split(':', 1)
                        if (username == cred.get('basic_username') and
                                cred.get('basic_password_hash') and
                                bcrypt.checkpw(password.encode(), cred['basic_password_hash'].encode())):
                            await self._record_cred_use(conn, cred['credential_id'])
                            return (True, str(cred['credential_id']))
                    except Exception:
                        pass

            return (False, None)

    async def list_credentials(self, list_id: str) -> List[Dict[str, Any]]:
        """List all credentials for a list (without secrets)."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT credential_id, list_id, auth_type, token_prefix,
                    basic_username, ip_allowlist, name, description,
                    enabled, expires_at, last_used_at, use_count,
                    created_at, created_by
                FROM edl_credentials
                WHERE list_id = $1
                ORDER BY created_at DESC
            ''', list_id)
            return [dict(r) for r in rows]

    async def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            result = await conn.execute(
                'DELETE FROM edl_credentials WHERE credential_id = $1',
                credential_id
            )
            return result.split()[-1] != '0'

    async def rotate_credential(
        self,
        credential_id: str,
        created_by: str = None,
    ) -> Dict[str, Any]:
        """
        Rotate a token credential: create a new one on the same list, keep old active.
        Returns new credential with raw token.
        """
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            old = await conn.fetchrow(
                'SELECT * FROM edl_credentials WHERE credential_id = $1', credential_id
            )
            if not old:
                raise ValueError("Credential not found")
            if old['auth_type'] != 'token':
                raise ValueError("Rotation only supported for token credentials")

            # Create new credential on same list
            return await self.create_credential(
                list_id=str(old['list_id']),
                name=f"{old['name']} (rotated)",
                auth_type='token',
                created_by=created_by,
                description=f"Rotated from {str(old['credential_id'])[:8]}",
            )

    # ========================================================================
    # ACCESS LOGGING
    # ========================================================================

    async def log_access(
        self,
        list_id: str,
        client_ip: str,
        status_code: int,
        auth_method: str = None,
        auth_success: bool = True,
        credential_id: str = None,
        user_agent: str = None,
        request_path: str = None,
        items_returned: int = 0,
        response_time_ms: int = 0,
        cache_hit: bool = False,
    ):
        """Log an EDL access attempt."""
        try:
            pool = await self._get_pool()
            async with pool.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO edl_access_log (
                        list_id, credential_id, client_ip, user_agent,
                        request_path, status_code, items_returned,
                        response_time_ms, cache_hit, auth_method, auth_success
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ''',
                    list_id, credential_id, client_ip, user_agent,
                    request_path, status_code, items_returned,
                    response_time_ms, cache_hit, auth_method, auth_success
                )
        except Exception as e:
            # Access logging should never block delivery
            logger.error(f"EDL access log failed: {e}")

    async def get_access_logs(
        self,
        list_id: str,
        page: int = 1,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get access logs for a list."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            total = await conn.fetchval(
                'SELECT COUNT(*) FROM edl_access_log WHERE list_id = $1', list_id
            )
            offset = (page - 1) * limit
            rows = await conn.fetch('''
                SELECT * FROM edl_access_log
                WHERE list_id = $1
                ORDER BY accessed_at DESC
                LIMIT $2 OFFSET $3
            ''', list_id, limit, offset)

            return {
                "logs": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "limit": limit,
            }

    async def get_change_log(
        self,
        list_id: str,
        page: int = 1,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get change history for a list."""
        pool = await self._get_pool()
        async with pool.tenant_acquire() as conn:
            total = await conn.fetchval(
                'SELECT COUNT(*) FROM edl_change_log WHERE list_id = $1', list_id
            )
            offset = (page - 1) * limit
            rows = await conn.fetch('''
                SELECT * FROM edl_change_log
                WHERE list_id = $1
                ORDER BY changed_at DESC
                LIMIT $2 OFFSET $3
            ''', list_id, limit, offset)

            return {
                "changes": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "limit": limit,
            }

    # ========================================================================
    # INTERNAL HELPERS
    # ========================================================================

    async def _refresh_item_count(self, conn, list_id: str):
        """Refresh the item count on a list."""
        await conn.execute('''
            UPDATE edl_lists SET
                item_count = (
                    SELECT COUNT(*) FROM edl_items
                    WHERE list_id = $1
                      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE list_id = $1
        ''', list_id)

    async def _log_change(
        self, conn, list_id, operation, ioc_value, ioc_type,
        changed_by=None, source_type=None, source_id=None, reason=None,
        approval_required=False, approval_id=None, approved_by=None,
    ):
        """Write to the change log."""
        try:
            await conn.execute('''
                INSERT INTO edl_change_log (
                    list_id, operation, ioc_value, ioc_type,
                    changed_by, source_type, source_id, reason,
                    approval_required, approval_id, approved_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ''',
                list_id, operation, ioc_value, ioc_type,
                changed_by, source_type, source_id, reason,
                approval_required, approval_id, approved_by
            )
        except Exception as e:
            logger.error(f"EDL change log failed: {e}")

    async def _record_cred_use(self, conn, credential_id):
        """Update last_used_at and use_count on a credential."""
        await conn.execute('''
            UPDATE edl_credentials SET
                last_used_at = CURRENT_TIMESTAMP,
                use_count = use_count + 1
            WHERE credential_id = $1
        ''', credential_id)

    def _check_ip_allowlist(self, client_ip: str, allowlist) -> bool:
        """Check if client IP is in the allowlist (supports CIDR)."""
        if not allowlist:
            return False

        import json
        if isinstance(allowlist, str):
            try:
                allowlist = json.loads(allowlist)
            except Exception:
                return False

        try:
            client = ipaddress.ip_address(client_ip)
            for entry in allowlist:
                entry = entry.strip()
                if '/' in entry:
                    if client in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if client == ipaddress.ip_address(entry):
                        return True
        except (ValueError, TypeError):
            return False

        return False


# ============================================================================
# SINGLETON
# ============================================================================

_edl_service: Optional[EDLService] = None


def get_edl_service() -> EDLService:
    """Get singleton EDL service instance."""
    global _edl_service
    if _edl_service is None:
        _edl_service = EDLService()
    return _edl_service
