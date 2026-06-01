# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Log Index Service
=================

Manages Splunk-style log indexes with role-based access control.
Provides the core logic for:
- Index management (CRUD)
- Role-based permission checking
- User permission overrides
- Search audit logging
- Field-level security

Similar to Splunk indexes, these are logical groupings of logs that
map to OpenSearch index patterns and have associated permissions.
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class LogIndex:
    """Represents a logical log index (similar to Splunk index)"""
    id: str
    name: str
    display_name: str
    description: Optional[str]
    index_pattern: str  # OpenSearch pattern like 'logs-security-*'
    data_classification: str  # 'public', 'internal', 'confidential', 'restricted'
    retention_days: int
    is_active: bool
    is_default: bool
    source_types: List[str]
    tags: List[str]
    created_at: datetime
    created_by: Optional[str]


@dataclass
class IndexPermission:
    """Permission for a role/user on an index"""
    index_name: str
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False
    can_admin: bool = False
    allowed_fields: Optional[List[str]] = None  # None = all fields
    denied_fields: Optional[List[str]] = None  # Fields to exclude


@dataclass
class UserIndexAccess:
    """Computed access for a specific user to indexes"""
    username: str
    role: str
    accessible_indexes: Dict[str, IndexPermission] = field(default_factory=dict)
    accessible_patterns: List[str] = field(default_factory=list)  # OpenSearch patterns


class LogIndexService:
    """
    Service for managing log indexes and RBAC permissions.

    This service acts as the single source of truth for:
    - Which indexes exist
    - Who can access what
    - What fields are visible to whom
    """

    def __init__(self):
        self._indexes_cache: Dict[str, LogIndex] = {}
        self._role_permissions_cache: Dict[str, Dict[str, IndexPermission]] = {}
        self._cache_loaded = False

    async def _ensure_cache_loaded(self):
        """Load cache from database if not already loaded"""
        if self._cache_loaded:
            return
        await self.refresh_cache()

    async def refresh_cache(self):
        """Refresh the in-memory cache from database"""
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            logger.warning("[LogIndex] Database not connected, using empty cache")
            self._cache_loaded = True
            return

        try:
            # Load indexes
            indexes = await postgres_db.execute_query(
                "SELECT * FROM log_indexes WHERE is_active = true"
            )
            self._indexes_cache = {
                idx['name']: LogIndex(
                    id=str(idx['id']),
                    name=idx['name'],
                    display_name=idx['display_name'],
                    description=idx.get('description'),
                    index_pattern=idx['index_pattern'],
                    data_classification=idx.get('data_classification', 'internal'),
                    retention_days=idx.get('retention_days', 90),
                    is_active=idx['is_active'],
                    is_default=idx.get('is_default', False),
                    source_types=idx.get('source_types') or [],
                    tags=idx.get('tags') or [],
                    created_at=idx['created_at'],
                    created_by=idx.get('created_by')
                )
                for idx in (indexes or [])
            }

            # Load role permissions
            perms = await postgres_db.execute_query(
                "SELECT * FROM role_index_permissions"
            )
            self._role_permissions_cache = {}
            for perm in (perms or []):
                role = perm['role']
                if role not in self._role_permissions_cache:
                    self._role_permissions_cache[role] = {}
                self._role_permissions_cache[role][perm['index_name']] = IndexPermission(
                    index_name=perm['index_name'],
                    can_read=perm.get('can_read', False),
                    can_write=perm.get('can_write', False),
                    can_delete=perm.get('can_delete', False),
                    can_admin=perm.get('can_admin', False),
                    allowed_fields=perm.get('allowed_fields'),
                    denied_fields=perm.get('denied_fields')
                )

            self._cache_loaded = True
            logger.info(f"[LogIndex] Cache loaded: {len(self._indexes_cache)} indexes, {len(self._role_permissions_cache)} roles")

        except Exception as e:
            logger.error(f"[LogIndex] Failed to load cache: {e}")
            self._cache_loaded = True  # Mark as loaded to avoid repeated failures

    # =========================================================================
    # INDEX MANAGEMENT
    # =========================================================================

    async def get_all_indexes(self) -> List[LogIndex]:
        """Get all active log indexes"""
        await self._ensure_cache_loaded()
        return list(self._indexes_cache.values())

    async def get_index(self, name: str) -> Optional[LogIndex]:
        """Get a specific index by name"""
        await self._ensure_cache_loaded()
        return self._indexes_cache.get(name)

    async def create_index(
        self,
        name: str,
        display_name: str,
        index_pattern: str,
        description: Optional[str] = None,
        data_classification: str = 'internal',
        retention_days: int = 90,
        source_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        created_by: Optional[str] = None
    ) -> LogIndex:
        """Create a new log index"""
        from services.postgres_db import postgres_db

        result = await postgres_db.execute_query(
            """
            INSERT INTO log_indexes
            (name, display_name, description, index_pattern, data_classification,
             retention_days, source_types, tags, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            """,
            name, display_name, description, index_pattern, data_classification,
            retention_days, source_types or [], tags or [], created_by
        )

        if result:
            await self.refresh_cache()
            return self._indexes_cache.get(name)

        raise Exception(f"Failed to create index {name}")

    async def update_index(
        self,
        name: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None
    ) -> Optional[LogIndex]:
        """Update an existing index"""
        from services.postgres_db import postgres_db

        # Build dynamic UPDATE query
        set_clauses = []
        values = []
        param_count = 1

        allowed_fields = ['display_name', 'description', 'index_pattern',
                         'data_classification', 'retention_days', 'source_types',
                         'tags', 'is_active']

        for key, value in updates.items():
            if key in allowed_fields:
                set_clauses.append(f"{key} = ${param_count}")
                values.append(value)
                param_count += 1

        if not set_clauses:
            return await self.get_index(name)

        set_clauses.append(f"updated_at = ${param_count}")
        values.append(datetime.utcnow())
        param_count += 1

        values.append(name)  # WHERE clause

        query = f"""
            UPDATE log_indexes
            SET {', '.join(set_clauses)}
            WHERE name = ${param_count}
            RETURNING *
        """

        result = await postgres_db.execute_query(query, *values)

        if result:
            await self.refresh_cache()
            return self._indexes_cache.get(name)

        return None

    async def delete_index(self, name: str) -> bool:
        """Soft-delete an index (set is_active = false)"""
        from services.postgres_db import postgres_db

        result = await postgres_db.execute_query(
            "UPDATE log_indexes SET is_active = false WHERE name = $1",
            name
        )

        if result is not None:
            await self.refresh_cache()
            return True

        return False

    # =========================================================================
    # PERMISSION MANAGEMENT
    # =========================================================================

    async def get_role_permissions(self, role: str) -> Dict[str, IndexPermission]:
        """Get all index permissions for a role"""
        await self._ensure_cache_loaded()
        return self._role_permissions_cache.get(role, {})

    async def set_role_permission(
        self,
        role: str,
        index_name: str,
        can_read: bool = False,
        can_write: bool = False,
        can_delete: bool = False,
        can_admin: bool = False,
        allowed_fields: Optional[List[str]] = None,
        denied_fields: Optional[List[str]] = None,
        created_by: Optional[str] = None
    ) -> bool:
        """Set or update permission for a role on an index"""
        from services.postgres_db import postgres_db

        # Get index ID
        index = await self.get_index(index_name)
        if not index:
            raise ValueError(f"Index '{index_name}' not found")

        result = await postgres_db.execute_query(
            """
            INSERT INTO role_index_permissions
            (role, index_id, index_name, can_read, can_write, can_delete, can_admin,
             allowed_fields, denied_fields, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (role, index_id) DO UPDATE SET
                can_read = EXCLUDED.can_read,
                can_write = EXCLUDED.can_write,
                can_delete = EXCLUDED.can_delete,
                can_admin = EXCLUDED.can_admin,
                allowed_fields = EXCLUDED.allowed_fields,
                denied_fields = EXCLUDED.denied_fields,
                updated_at = CURRENT_TIMESTAMP
            """,
            role, index.id, index_name, can_read, can_write, can_delete, can_admin,
            allowed_fields, denied_fields, created_by
        )

        if result is not None:
            await self.refresh_cache()
            return True

        return False

    async def get_user_permission_overrides(
        self,
        username: str
    ) -> Dict[str, IndexPermission]:
        """Get user-specific permission overrides"""
        from services.postgres_db import postgres_db

        perms = await postgres_db.execute_query(
            """
            SELECT * FROM user_index_permissions
            WHERE username = $1
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            """,
            username
        )

        overrides = {}
        for perm in (perms or []):
            overrides[perm['index_name']] = IndexPermission(
                index_name=perm['index_name'],
                can_read=perm.get('can_read'),
                can_write=perm.get('can_write'),
                can_delete=perm.get('can_delete'),
                can_admin=False  # Users can't get admin via override
            )

        return overrides

    async def set_user_permission_override(
        self,
        user_id: str,
        username: str,
        index_name: str,
        can_read: Optional[bool] = None,
        can_write: Optional[bool] = None,
        can_delete: Optional[bool] = None,
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None
    ) -> bool:
        """Set user-specific permission override"""
        from services.postgres_db import postgres_db

        index = await self.get_index(index_name)
        if not index:
            raise ValueError(f"Index '{index_name}' not found")

        result = await postgres_db.execute_query(
            """
            INSERT INTO user_index_permissions
            (user_id, username, index_id, index_name, can_read, can_write, can_delete,
             reason, expires_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (user_id, index_id) DO UPDATE SET
                can_read = EXCLUDED.can_read,
                can_write = EXCLUDED.can_write,
                can_delete = EXCLUDED.can_delete,
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at
            """,
            user_id, username, index.id, index_name, can_read, can_write, can_delete,
            reason, expires_at, created_by
        )

        return result is not None

    # =========================================================================
    # ACCESS COMPUTATION
    # =========================================================================

    async def compute_user_access(
        self,
        username: str,
        role: str,
        user_id: Optional[str] = None
    ) -> UserIndexAccess:
        """
        Compute effective index access for a user.

        Combines:
        1. Role-based permissions (base)
        2. User-specific overrides (grants/denies)
        3. Admin bypass (admins get full access to everything)

        Returns a UserIndexAccess object with all accessible indexes
        and their OpenSearch patterns.
        """
        await self._ensure_cache_loaded()

        # Admin bypass - admins get full access to all indexes
        if role in ('admin', 'platform_owner'):
            accessible = {}
            patterns = []
            for index_name, index in self._indexes_cache.items():
                accessible[index_name] = IndexPermission(
                    index_name=index_name,
                    can_read=True,
                    can_write=True,
                    can_delete=True,
                    can_admin=True,
                    allowed_fields=None,
                    denied_fields=None
                )
                patterns.append(index.index_pattern)

            # If no indexes exist yet, give access to default pattern
            if not patterns:
                patterns = ["logs-*"]

            return UserIndexAccess(
                username=username,
                role=role,
                accessible_indexes=accessible,
                accessible_patterns=patterns
            )

        # Start with role permissions
        role_perms = self._role_permissions_cache.get(role, {})

        # Get user overrides
        user_overrides = {}
        if user_id:
            user_overrides = await self.get_user_permission_overrides(username)

        # Compute effective permissions
        accessible = {}
        patterns = []

        for index_name, index in self._indexes_cache.items():
            # Start with role permission
            role_perm = role_perms.get(index_name)
            user_override = user_overrides.get(index_name)

            # Determine effective permission
            can_read = False
            can_write = False
            can_delete = False
            can_admin = False
            allowed_fields = None
            denied_fields = None

            if role_perm:
                can_read = role_perm.can_read
                can_write = role_perm.can_write
                can_delete = role_perm.can_delete
                can_admin = role_perm.can_admin
                allowed_fields = role_perm.allowed_fields
                denied_fields = role_perm.denied_fields

            # Apply user overrides (None = inherit, True/False = override)
            if user_override:
                if user_override.can_read is not None:
                    can_read = user_override.can_read
                if user_override.can_write is not None:
                    can_write = user_override.can_write
                if user_override.can_delete is not None:
                    can_delete = user_override.can_delete

            # If user has read access, add to accessible
            if can_read:
                accessible[index_name] = IndexPermission(
                    index_name=index_name,
                    can_read=can_read,
                    can_write=can_write,
                    can_delete=can_delete,
                    can_admin=can_admin,
                    allowed_fields=allowed_fields,
                    denied_fields=denied_fields
                )
                patterns.append(index.index_pattern)

        return UserIndexAccess(
            username=username,
            role=role,
            accessible_indexes=accessible,
            accessible_patterns=patterns
        )

    async def check_index_access(
        self,
        username: str,
        role: str,
        index_name: str,
        permission: str = 'read',
        user_id: Optional[str] = None
    ) -> Tuple[bool, Optional[IndexPermission]]:
        """
        Check if a user has specific access to an index.

        Args:
            username: User's username
            role: User's role
            index_name: Index to check
            permission: 'read', 'write', 'delete', or 'admin'
            user_id: Optional user ID for overrides

        Returns:
            Tuple of (has_access: bool, permission_details: IndexPermission or None)
        """
        access = await self.compute_user_access(username, role, user_id)

        if index_name not in access.accessible_indexes:
            return False, None

        perm = access.accessible_indexes[index_name]

        if permission == 'read':
            return perm.can_read, perm
        elif permission == 'write':
            return perm.can_write, perm
        elif permission == 'delete':
            return perm.can_delete, perm
        elif permission == 'admin':
            return perm.can_admin, perm

        return False, None

    async def get_accessible_patterns(
        self,
        username: str,
        role: str,
        user_id: Optional[str] = None
    ) -> List[str]:
        """Get list of OpenSearch index patterns user can access"""
        access = await self.compute_user_access(username, role, user_id)
        return access.accessible_patterns

    # =========================================================================
    # AUDIT LOGGING
    # =========================================================================

    async def log_search(
        self,
        username: str,
        user_role: str,
        search_query: str,
        index_names: List[str],
        time_range: str,
        results_count: int,
        execution_time_ms: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Log a search operation for audit purposes"""
        from services.postgres_db import postgres_db

        try:
            await postgres_db.execute_query(
                """
                INSERT INTO log_search_audit
                (user_id, username, user_role, search_query, index_names, time_range,
                 results_count, execution_time_ms, ip_address, user_agent, success, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                """,
                user_id, username, user_role, search_query, index_names, time_range,
                results_count, execution_time_ms, ip_address, user_agent, success, error_message
            )
        except Exception as e:
            logger.error(f"[LogIndex] Failed to log search audit: {e}")

    async def get_search_audit(
        self,
        username: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get search audit logs"""
        from services.postgres_db import postgres_db

        if username:
            results = await postgres_db.execute_query(
                """
                SELECT * FROM log_search_audit
                WHERE username = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                """,
                username, limit, offset
            )
        else:
            results = await postgres_db.execute_query(
                """
                SELECT * FROM log_search_audit
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                """,
                limit, offset
            )

        return results or []


# Singleton instance
_log_index_service: Optional[LogIndexService] = None


def get_log_index_service() -> LogIndexService:
    """Get or create the log index service singleton"""
    global _log_index_service
    if _log_index_service is None:
        _log_index_service = LogIndexService()
    return _log_index_service
