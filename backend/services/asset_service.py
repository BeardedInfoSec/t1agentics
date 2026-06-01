# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Asset Service - CMDB Core Operations
Phase 9: Configuration Management Database

Provides asset CRUD, identifier management, relationship tracking,
and asset lookup for security investigations.
"""

import logging
import json
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from uuid import UUID
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Asset:
    """Asset data model"""
    id: Optional[str] = None
    asset_type: str = "unknown"
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    display_name: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    os_family: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    criticality: str = "tier4"
    status: str = "active"
    environment: str = "unknown"
    owner: Optional[str] = None
    owner_team: Optional[str] = None
    department: Optional[str] = None
    cost_center: Optional[str] = None
    location: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    custom_tags: List[str] = field(default_factory=list)
    discovery_sources: Dict[str, str] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "asset_type": self.asset_type,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "display_name": self.display_name,
            "ip_addresses": self.ip_addresses,
            "mac_addresses": self.mac_addresses,
            "os_family": self.os_family,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "criticality": self.criticality,
            "status": self.status,
            "environment": self.environment,
            "owner": self.owner,
            "owner_team": self.owner_team,
            "department": self.department,
            "cost_center": self.cost_center,
            "location": self.location,
            "compliance_tags": self.compliance_tags,
            "custom_tags": self.custom_tags,
            "discovery_sources": self.discovery_sources,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class AssetIdentifier:
    """Asset identifier data model"""
    id: Optional[str] = None
    asset_id: str = ""
    identifier_type: str = ""
    identifier_value: str = ""
    source: Optional[str] = None
    is_primary: bool = False
    confidence: int = 100
    last_verified: Optional[datetime] = None


@dataclass
class AssetRelationship:
    """Asset relationship data model"""
    id: Optional[str] = None
    source_asset_id: str = ""
    target_asset_id: str = ""
    relationship_type: str = ""
    discovered_by: Optional[str] = None
    confidence: int = 100
    bidirectional: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class AssetService:
    """
    Service for managing assets in the CMDB.
    Provides CRUD operations, lookup, and reconciliation.
    """

    def __init__(self):
        self.db = None

    def set_db(self, db):
        """Set the database connection"""
        self.db = db

    # =========================================================================
    # ASSET CRUD OPERATIONS
    # =========================================================================

    async def create_asset(
        self,
        asset_type: str = "unknown",
        hostname: Optional[str] = None,
        fqdn: Optional[str] = None,
        display_name: Optional[str] = None,
        ip_addresses: Optional[List[str]] = None,
        mac_addresses: Optional[List[str]] = None,
        os_family: Optional[str] = None,
        os_name: Optional[str] = None,
        os_version: Optional[str] = None,
        criticality: str = "tier4",
        status: str = "active",
        environment: str = "unknown",
        owner: Optional[str] = None,
        owner_team: Optional[str] = None,
        department: Optional[str] = None,
        location: Optional[str] = None,
        compliance_tags: Optional[List[str]] = None,
        custom_tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_by: Optional[str] = None,
        source: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a new asset"""
        if not self.db or not self.db.pool:
            logger.error("Database not available")
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                now = datetime.now(timezone.utc)
                discovery_sources = {source: now.isoformat()} if source else {}

                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                row = await conn.fetchrow("""
                    INSERT INTO assets (
                        asset_type, hostname, fqdn, display_name,
                        ip_addresses, mac_addresses,
                        os_family, os_name, os_version,
                        criticality, status, environment,
                        owner, owner_team, department, location,
                        compliance_tags, custom_tags,
                        discovery_sources, metadata,
                        first_seen, last_seen,
                        created_by, updated_by,
                        tenant_id
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                        $21, $22, $23, $24,
                        $25
                    )
                    RETURNING *
                """,
                    asset_type,
                    hostname,
                    fqdn,
                    display_name or hostname,
                    json.dumps(ip_addresses or []),
                    json.dumps(mac_addresses or []),
                    os_family,
                    os_name,
                    os_version,
                    criticality,
                    status,
                    environment,
                    owner,
                    owner_team,
                    department,
                    location,
                    json.dumps(compliance_tags or []),
                    json.dumps(custom_tags or []),
                    json.dumps(discovery_sources),
                    json.dumps(metadata or {}),
                    now,
                    now,
                    created_by,
                    created_by,
                    UUID(_tenant_id) if _tenant_id else None
                )

                if row:
                    logger.info(f"Created asset: {row['id']} ({hostname or fqdn or 'unknown'})")
                    return self._row_to_asset_dict(row)

                return None

        except Exception as e:
            logger.error(f"Error creating asset: {e}")
            return None

    async def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset by ID"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM assets WHERE id = $1",
                    UUID(asset_id)
                )
                if row:
                    return self._row_to_asset_dict(row)
                return None
        except Exception as e:
            logger.error(f"Error getting asset {asset_id}: {e}")
            return None

    async def update_asset(
        self,
        asset_id: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Update an existing asset"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                # Build dynamic update query
                set_parts = []
                values = []
                param_idx = 1

                for field, value in updates.items():
                    if field in ['id', 'created_at', 'created_by']:
                        continue  # Skip immutable fields

                    if field in ['ip_addresses', 'mac_addresses', 'compliance_tags',
                                 'custom_tags', 'discovery_sources', 'metadata']:
                        set_parts.append(f"{field} = ${param_idx}")
                        values.append(json.dumps(value))
                    else:
                        set_parts.append(f"{field} = ${param_idx}")
                        values.append(value)
                    param_idx += 1

                if not set_parts:
                    return await self.get_asset(asset_id)

                # Add updated_by and updated_at
                set_parts.append(f"updated_by = ${param_idx}")
                values.append(updated_by)
                param_idx += 1

                set_parts.append(f"updated_at = ${param_idx}")
                values.append(datetime.now(timezone.utc))
                param_idx += 1

                values.append(UUID(asset_id))

                query = f"""
                    UPDATE assets
                    SET {', '.join(set_parts)}
                    WHERE id = ${param_idx}
                    RETURNING *
                """

                row = await conn.fetchrow(query, *values)
                if row:
                    logger.info(f"Updated asset: {asset_id}")
                    return self._row_to_asset_dict(row)

                return None

        except Exception as e:
            logger.error(f"Error updating asset {asset_id}: {e}")
            return None

    async def delete_asset(self, asset_id: str, hard_delete: bool = False) -> bool:
        """Delete an asset (soft delete by default)"""
        if not self.db or not self.db.pool:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                if hard_delete:
                    result = await conn.execute(
                        "DELETE FROM assets WHERE id = $1",
                        UUID(asset_id)
                    )
                else:
                    result = await conn.execute("""
                        UPDATE assets
                        SET status = 'decommissioned', updated_at = $2
                        WHERE id = $1
                    """, UUID(asset_id), datetime.now(timezone.utc))

                logger.info(f"{'Deleted' if hard_delete else 'Decommissioned'} asset: {asset_id}")
                return True

        except Exception as e:
            logger.error(f"Error deleting asset {asset_id}: {e}")
            return False

    async def list_assets(
        self,
        limit: int = 100,
        offset: int = 0,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        status: Optional[str] = None,
        environment: Optional[str] = None,
        owner: Optional[str] = None,
        department: Optional[str] = None,
        search: Optional[str] = None,
        include_decommissioned: bool = False
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List assets with filtering"""
        if not self.db or not self.db.pool:
            return [], 0

        try:
            async with self.db.tenant_acquire() as conn:
                conditions = []
                values = []
                param_idx = 1

                if not include_decommissioned:
                    conditions.append(f"status != 'decommissioned'")

                if asset_type:
                    conditions.append(f"asset_type = ${param_idx}")
                    values.append(asset_type)
                    param_idx += 1

                if criticality:
                    conditions.append(f"criticality = ${param_idx}")
                    values.append(criticality)
                    param_idx += 1

                if status:
                    conditions.append(f"status = ${param_idx}")
                    values.append(status)
                    param_idx += 1

                if environment:
                    conditions.append(f"environment = ${param_idx}")
                    values.append(environment)
                    param_idx += 1

                if owner:
                    conditions.append(f"owner ILIKE ${param_idx}")
                    values.append(f"%{owner}%")
                    param_idx += 1

                if department:
                    conditions.append(f"department ILIKE ${param_idx}")
                    values.append(f"%{department}%")
                    param_idx += 1

                if search:
                    conditions.append(f"""
                        (hostname ILIKE ${param_idx}
                        OR fqdn ILIKE ${param_idx}
                        OR display_name ILIKE ${param_idx}
                        OR owner ILIKE ${param_idx})
                    """)
                    values.append(f"%{search}%")
                    param_idx += 1

                where_clause = " AND ".join(conditions) if conditions else "1=1"

                # Get total count
                count_query = f"SELECT COUNT(*) FROM assets WHERE {where_clause}"
                total = await conn.fetchval(count_query, *values)

                # Get assets
                values.extend([limit, offset])
                query = f"""
                    SELECT * FROM assets
                    WHERE {where_clause}
                    ORDER BY last_seen DESC, hostname
                    LIMIT ${param_idx} OFFSET ${param_idx + 1}
                """

                rows = await conn.fetch(query, *values)

                assets = [self._row_to_asset_dict(row) for row in rows]
                return assets, total

        except Exception as e:
            logger.error(f"Error listing assets: {e}")
            return [], 0

    # =========================================================================
    # ASSET LOOKUP OPERATIONS
    # =========================================================================

    async def find_asset_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Find asset by IP address"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT * FROM assets
                    WHERE ip_addresses @> $1::jsonb
                    LIMIT 1
                """, json.dumps([ip_address]))

                if row:
                    return self._row_to_asset_dict(row)
                return None

        except Exception as e:
            logger.error(f"Error finding asset by IP {ip_address}: {e}")
            return None

    async def find_asset_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Find asset by hostname or FQDN"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT * FROM assets
                    WHERE LOWER(hostname) = LOWER($1)
                       OR LOWER(fqdn) = LOWER($1)
                    LIMIT 1
                """, hostname)

                if row:
                    return self._row_to_asset_dict(row)
                return None

        except Exception as e:
            logger.error(f"Error finding asset by hostname {hostname}: {e}")
            return None

    async def find_asset_by_identifier(
        self,
        identifier_type: str,
        identifier_value: str
    ) -> Optional[Dict[str, Any]]:
        """Find asset by any identifier"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT a.* FROM assets a
                    JOIN asset_identifiers ai ON ai.asset_id = a.id
                    WHERE ai.identifier_type = $1
                      AND ai.identifier_value = $2
                    LIMIT 1
                """, identifier_type, identifier_value)

                if row:
                    return self._row_to_asset_dict(row)
                return None

        except Exception as e:
            logger.error(f"Error finding asset by identifier: {e}")
            return None

    async def lookup_asset(
        self,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        identifier_type: Optional[str] = None,
        identifier_value: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Unified asset lookup - tries multiple methods.
        Used for investigation enrichment.
        """
        # Try IP first (most reliable)
        if ip:
            asset = await self.find_asset_by_ip(ip)
            if asset:
                return asset

        # Try hostname
        if hostname:
            asset = await self.find_asset_by_hostname(hostname)
            if asset:
                return asset

        # Try identifier
        if identifier_type and identifier_value:
            asset = await self.find_asset_by_identifier(identifier_type, identifier_value)
            if asset:
                return asset

        return None

    # =========================================================================
    # IDENTIFIER OPERATIONS
    # =========================================================================

    async def add_identifier(
        self,
        asset_id: str,
        identifier_type: str,
        identifier_value: str,
        source: Optional[str] = None,
        is_primary: bool = False,
        confidence: int = 100
    ) -> Optional[Dict[str, Any]]:
        """Add an identifier to an asset"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                row = await conn.fetchrow("""
                    INSERT INTO asset_identifiers (
                        asset_id, identifier_type, identifier_value,
                        source, is_primary, confidence,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (identifier_type, identifier_value)
                    DO UPDATE SET
                        last_verified = CURRENT_TIMESTAMP,
                        confidence = GREATEST(asset_identifiers.confidence, EXCLUDED.confidence)
                    RETURNING *
                """,
                    UUID(asset_id), identifier_type, identifier_value,
                    source, is_primary, confidence,
                    UUID(_tenant_id) if _tenant_id else None
                )

                if row:
                    return dict(row)
                return None

        except Exception as e:
            logger.error(f"Error adding identifier: {e}")
            return None

    async def get_asset_identifiers(self, asset_id: str) -> List[Dict[str, Any]]:
        """Get all identifiers for an asset"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT * FROM asset_identifiers
                    WHERE asset_id = $1
                    ORDER BY is_primary DESC, identifier_type
                """, UUID(asset_id))

                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting identifiers: {e}")
            return []

    # =========================================================================
    # RELATIONSHIP OPERATIONS
    # =========================================================================

    async def add_relationship(
        self,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: str,
        discovered_by: Optional[str] = None,
        confidence: int = 100,
        bidirectional: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Add a relationship between assets"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                row = await conn.fetchrow("""
                    INSERT INTO asset_relationships (
                        source_asset_id, target_asset_id, relationship_type,
                        discovered_by, confidence, bidirectional, metadata,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (source_asset_id, target_asset_id, relationship_type)
                    DO UPDATE SET
                        updated_at = CURRENT_TIMESTAMP,
                        confidence = GREATEST(asset_relationships.confidence, EXCLUDED.confidence)
                    RETURNING *
                """,
                    UUID(source_asset_id), UUID(target_asset_id), relationship_type,
                    discovered_by, confidence, bidirectional, json.dumps(metadata or {}),
                    UUID(_tenant_id) if _tenant_id else None
                )

                if row:
                    logger.info(f"Added relationship: {source_asset_id} -> {target_asset_id} ({relationship_type})")
                    return dict(row)
                return None

        except Exception as e:
            logger.error(f"Error adding relationship: {e}")
            return None

    async def get_asset_relationships(
        self,
        asset_id: str,
        direction: str = "both"  # "outgoing", "incoming", "both"
    ) -> List[Dict[str, Any]]:
        """Get relationships for an asset"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                relationships = []

                if direction in ["outgoing", "both"]:
                    outgoing = await conn.fetch("""
                        SELECT ar.*, a.hostname as target_hostname, a.display_name as target_display_name
                        FROM asset_relationships ar
                        JOIN assets a ON a.id = ar.target_asset_id
                        WHERE ar.source_asset_id = $1
                    """, UUID(asset_id))
                    relationships.extend([{**dict(r), "direction": "outgoing"} for r in outgoing])

                if direction in ["incoming", "both"]:
                    incoming = await conn.fetch("""
                        SELECT ar.*, a.hostname as source_hostname, a.display_name as source_display_name
                        FROM asset_relationships ar
                        JOIN assets a ON a.id = ar.source_asset_id
                        WHERE ar.target_asset_id = $1
                    """, UUID(asset_id))
                    relationships.extend([{**dict(r), "direction": "incoming"} for r in incoming])

                return relationships

        except Exception as e:
            logger.error(f"Error getting relationships: {e}")
            return []

    # =========================================================================
    # HISTORY OPERATIONS
    # =========================================================================

    async def get_asset_history(
        self,
        asset_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get change history for an asset"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch("""
                    SELECT * FROM asset_history
                    WHERE asset_id = $1
                    ORDER BY timestamp DESC
                    LIMIT $2
                """, UUID(asset_id), limit)

                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting asset history: {e}")
            return []

    # =========================================================================
    # STATISTICS
    # =========================================================================

    async def get_asset_stats(self) -> Dict[str, Any]:
        """Get overall asset statistics"""
        if not self.db or not self.db.pool:
            return {}

        try:
            async with self.db.tenant_acquire() as conn:
                stats = await conn.fetchrow("""
                    SELECT
                        COUNT(*) as total_assets,
                        COUNT(*) FILTER (WHERE status = 'active') as active_assets,
                        COUNT(*) FILTER (WHERE status = 'inactive') as inactive_assets,
                        COUNT(*) FILTER (WHERE status = 'decommissioned') as decommissioned_assets,
                        COUNT(*) FILTER (WHERE criticality = 'tier1') as tier1_assets,
                        COUNT(*) FILTER (WHERE criticality = 'tier2') as tier2_assets,
                        COUNT(*) FILTER (WHERE criticality = 'tier3') as tier3_assets,
                        COUNT(*) FILTER (WHERE criticality = 'tier4') as tier4_assets,
                        COUNT(*) FILTER (WHERE last_seen < CURRENT_TIMESTAMP - INTERVAL '7 days' AND status = 'active') as stale_assets
                    FROM assets
                """)

                by_type = await conn.fetch("""
                    SELECT asset_type, COUNT(*) as count
                    FROM assets
                    WHERE status != 'decommissioned'
                    GROUP BY asset_type
                    ORDER BY count DESC
                """)

                by_environment = await conn.fetch("""
                    SELECT environment, COUNT(*) as count
                    FROM assets
                    WHERE status != 'decommissioned'
                    GROUP BY environment
                    ORDER BY count DESC
                """)

                return {
                    "total": stats['total_assets'],
                    "by_status": {
                        "active": stats['active_assets'],
                        "inactive": stats['inactive_assets'],
                        "decommissioned": stats['decommissioned_assets']
                    },
                    "by_criticality": {
                        "tier1": stats['tier1_assets'],
                        "tier2": stats['tier2_assets'],
                        "tier3": stats['tier3_assets'],
                        "tier4": stats['tier4_assets']
                    },
                    "by_type": {r['asset_type']: r['count'] for r in by_type},
                    "by_environment": {r['environment']: r['count'] for r in by_environment},
                    "stale_assets": stats['stale_assets']
                }

        except Exception as e:
            logger.error(f"Error getting asset stats: {e}")
            return {}

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _row_to_asset_dict(self, row) -> Dict[str, Any]:
        """Convert database row to asset dictionary"""
        return {
            "id": str(row['id']),
            "asset_type": row['asset_type'],
            "hostname": row['hostname'],
            "fqdn": row['fqdn'],
            "display_name": row['display_name'],
            "ip_addresses": row['ip_addresses'] if isinstance(row['ip_addresses'], list) else json.loads(row['ip_addresses'] or '[]'),
            "mac_addresses": row['mac_addresses'] if isinstance(row['mac_addresses'], list) else json.loads(row['mac_addresses'] or '[]'),
            "os_family": row['os_family'],
            "os_name": row['os_name'],
            "os_version": row['os_version'],
            "criticality": row['criticality'],
            "status": row['status'],
            "environment": row['environment'],
            "owner": row['owner'],
            "owner_team": row['owner_team'],
            "department": row['department'],
            "cost_center": row.get('cost_center'),
            "location": row['location'],
            "compliance_tags": row['compliance_tags'] if isinstance(row['compliance_tags'], list) else json.loads(row['compliance_tags'] or '[]'),
            "custom_tags": row['custom_tags'] if isinstance(row['custom_tags'], list) else json.loads(row['custom_tags'] or '[]'),
            "discovery_sources": row['discovery_sources'] if isinstance(row['discovery_sources'], dict) else json.loads(row['discovery_sources'] or '{}'),
            "first_seen": row['first_seen'].isoformat() if row['first_seen'] else None,
            "last_seen": row['last_seen'].isoformat() if row['last_seen'] else None,
            "metadata": row['metadata'] if isinstance(row['metadata'], dict) else json.loads(row['metadata'] or '{}'),
            "created_at": row['created_at'].isoformat() if row['created_at'] else None,
            "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None,
        }


# Singleton instance
_asset_service: Optional[AssetService] = None


def get_asset_service() -> AssetService:
    """Get the global asset service instance"""
    global _asset_service
    if _asset_service is None:
        _asset_service = AssetService()
    return _asset_service
