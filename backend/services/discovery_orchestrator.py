# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Asset Discovery Orchestrator
Phase 9.2: CMDB & Asset Discovery

Orchestrates asset discovery from multiple sources:
- Active Directory
- CrowdStrike Falcon
- AWS EC2
- Azure VMs
- VMware vSphere
- Custom sources via API

Handles scheduling, execution, reconciliation, and conflict resolution.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import json
import uuid

logger = logging.getLogger(__name__)


class DiscoverySourceType(str, Enum):
    """Types of discovery sources"""
    ACTIVE_DIRECTORY = "active_directory"
    CROWDSTRIKE = "crowdstrike"
    AWS = "aws"
    AZURE = "azure"
    VMWARE = "vmware"
    NETWORK_SCAN = "network_scan"
    CUSTOM = "custom"


class ReconciliationStrategy(str, Enum):
    """Strategy for handling duplicate assets"""
    MERGE = "merge"  # Merge attributes from all sources
    PREFER_SOURCE = "prefer_source"  # Prefer specific source
    NEWEST_WINS = "newest_wins"  # Most recent data wins
    MANUAL = "manual"  # Flag for manual resolution


class DiscoveryOrchestrator:
    """
    Orchestrates asset discovery from multiple sources.

    Features:
    - Source configuration and scheduling
    - Asset matching and deduplication
    - Conflict resolution
    - History tracking
    """

    def __init__(self):
        self.db = None
        self.asset_service = None
        self._discovery_handlers: Dict[str, callable] = {}
        self._running_discoveries: Dict[str, asyncio.Task] = {}

    def set_db(self, db):
        """Set database connection"""
        self.db = db

    def set_asset_service(self, service):
        """Set asset service for creating/updating assets"""
        self.asset_service = service

    # =========================================================================
    # DISCOVERY SOURCE MANAGEMENT
    # =========================================================================

    async def create_discovery_source(
        self,
        source_type: str,
        name: str,
        config: Dict[str, Any],
        schedule_cron: Optional[str] = None,
        priority: int = 50,
        enabled: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Create a new discovery source configuration"""
        if not self.db or not self.db.pool:
            return None

        try:
            source_id = str(uuid.uuid4())

            query = """
                INSERT INTO discovery_sources (
                    id, source_type, name, config, sync_cron,
                    source_priority, enabled, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
                RETURNING *
            """

            now = datetime.now(timezone.utc)

            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    query,
                    source_id, source_type, name, json.dumps(config),
                    schedule_cron, priority, enabled, now
                )

                if row:
                    return dict(row)
            return None

        except Exception as e:
            logger.error(f"Failed to create discovery source: {e}")
            return None

    async def get_discovery_sources(
        self,
        enabled_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all discovery sources"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                if enabled_only:
                    query = """
                        SELECT * FROM discovery_sources
                        WHERE enabled = true
                        ORDER BY source_priority DESC, name
                    """
                else:
                    query = """
                        SELECT * FROM discovery_sources
                        ORDER BY source_priority DESC, name
                    """
                rows = await conn.fetch(query)

            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get discovery sources: {e}")
            return []

    async def update_discovery_source(
        self,
        source_id: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a discovery source"""
        if not self.db or not self.db.pool:
            return None

        try:
            # Map API field names to database column names
            field_mapping = {
                'name': 'name',
                'config': 'config',
                'schedule_cron': 'sync_cron',
                'priority': 'source_priority',
                'enabled': 'enabled'
            }

            set_clauses = []
            values = []
            param_idx = 1

            for field, value in updates.items():
                if field in field_mapping:
                    db_field = field_mapping[field]
                    if field == 'config':
                        value = json.dumps(value)
                    set_clauses.append(f"{db_field} = ${param_idx}")
                    values.append(value)
                    param_idx += 1

            if not set_clauses:
                return None

            set_clauses.append(f"updated_at = ${param_idx}")
            values.append(datetime.now(timezone.utc))
            param_idx += 1

            values.append(source_id)

            query = f"""
                UPDATE discovery_sources
                SET {', '.join(set_clauses)}
                WHERE id = ${param_idx}
                RETURNING *
            """

            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(query, *values)

                if row:
                    return dict(row)
            return None

        except Exception as e:
            logger.error(f"Failed to update discovery source: {e}")
            return None

    async def delete_discovery_source(self, source_id: str) -> bool:
        """Delete a discovery source"""
        if not self.db or not self.db.pool:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM discovery_sources WHERE id = $1",
                    source_id
                )
            return "DELETE 1" in result
        except Exception as e:
            logger.error(f"Failed to delete discovery source: {e}")
            return False

    # =========================================================================
    # DISCOVERY EXECUTION
    # =========================================================================

    async def run_discovery(
        self,
        source_id: str,
        triggered_by: str = "manual"
    ) -> Dict[str, Any]:
        """Run discovery for a specific source"""
        if not self.db or not self.db.pool:
            return {"success": False, "error": "Database not connected"}

        try:
            async with self.db.tenant_acquire() as conn:
                # Get source config
                source = await conn.fetchrow(
                    "SELECT * FROM discovery_sources WHERE id = $1",
                    source_id
                )

                if not source:
                    return {"success": False, "error": "Source not found"}

                source = dict(source)

                # Check if already running
                if source_id in self._running_discoveries:
                    return {
                        "success": False,
                        "error": "Discovery already running for this source"
                    }

                # Create discovery run record
                run_id = str(uuid.uuid4())
                now = datetime.now(timezone.utc)

                await conn.execute("""
                    INSERT INTO discovery_queue (
                        id, source_id, status, triggered_by, started_at
                    )
                    VALUES ($1, $2, 'running', $3, $4)
                """, run_id, source_id, triggered_by, now)

            # Execute discovery based on source type
            result = await self._execute_discovery(source, run_id)

            async with self.db.tenant_acquire() as conn:
                # Update run record
                await conn.execute("""
                    UPDATE discovery_queue
                    SET status = $1, completed_at = $2,
                        assets_discovered = $3, assets_created = $4,
                        assets_updated = $5, assets_failed = $6,
                        error_message = $7
                    WHERE id = $8
                """,
                    result.get("status", "completed"),
                    datetime.now(timezone.utc),
                    result.get("discovered", 0),
                    result.get("created", 0),
                    result.get("updated", 0),
                    result.get("failed", 0),
                    result.get("error"),
                    run_id
                )

                # Update source last_sync
                await conn.execute("""
                    UPDATE discovery_sources
                    SET last_sync = $1, last_sync_status = $2
                    WHERE id = $3
                """, now, result.get("status", "completed"), source_id)

            return result

        except Exception as e:
            logger.error(f"Discovery run failed: {e}")
            return {"success": False, "error": str(e)}

    async def _execute_discovery(
        self,
        source: Dict[str, Any],
        run_id: str
    ) -> Dict[str, Any]:
        """Execute discovery for a source type"""
        source_type = source.get("source_type")
        config = source.get("config", {})

        if isinstance(config, str):
            config = json.loads(config)

        handler = self._discovery_handlers.get(source_type)

        if handler:
            return await handler(source, config, run_id)
        else:
            # Use built-in handlers
            if source_type == DiscoverySourceType.CROWDSTRIKE:
                return await self._discover_crowdstrike(source, config, run_id)
            elif source_type == DiscoverySourceType.AWS:
                return await self._discover_aws(source, config, run_id)
            elif source_type == DiscoverySourceType.AZURE:
                return await self._discover_azure(source, config, run_id)
            elif source_type == DiscoverySourceType.ACTIVE_DIRECTORY:
                return await self._discover_ad(source, config, run_id)
            else:
                return {
                    "success": False,
                    "status": "failed",
                    "error": f"No handler for source type: {source_type}"
                }

    def register_discovery_handler(
        self,
        source_type: str,
        handler: callable
    ):
        """Register a custom discovery handler"""
        self._discovery_handlers[source_type] = handler

    # =========================================================================
    # BUILT-IN DISCOVERY HANDLERS
    # =========================================================================

    async def _discover_crowdstrike(
        self,
        source: Dict[str, Any],
        config: Dict[str, Any],
        run_id: str
    ) -> Dict[str, Any]:
        """Discover assets from CrowdStrike Falcon"""
        try:
            # Check for CrowdStrike integration
            from integrations.registry.integration_registry import get_registry
            registry = get_registry()

            cs_integration = None
            integrations = registry.list(enabled_only=False)
            for integration in integrations:
                if "crowdstrike" in integration.id.lower():
                    cs_integration = integration
                    break

            if not cs_integration:
                return {
                    "success": False,
                    "status": "failed",
                    "error": "CrowdStrike integration not configured"
                }

            # Execute host search action
            from integrations.engines.execution_engine import get_execution_engine
            engine = get_execution_engine()

            result = await engine.execute(
                integration_id=cs_integration.id,
                action_name="list_hosts",
                parameters={"limit": 5000}
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "status": "failed",
                    "error": result.get("error", "Failed to query CrowdStrike")
                }

            # Process hosts
            hosts = result.get("data", {}).get("resources", [])

            created = 0
            updated = 0
            failed = 0

            for host in hosts:
                try:
                    asset_result = await self._process_crowdstrike_host(
                        host, source["id"]
                    )
                    if asset_result.get("created"):
                        created += 1
                    elif asset_result.get("updated"):
                        updated += 1
                except Exception as e:
                    logger.error(f"Failed to process CrowdStrike host: {e}")
                    failed += 1

            return {
                "success": True,
                "status": "completed",
                "discovered": len(hosts),
                "created": created,
                "updated": updated,
                "failed": failed
            }

        except Exception as e:
            logger.error(f"CrowdStrike discovery failed: {e}")
            return {
                "success": False,
                "status": "failed",
                "error": str(e)
            }

    async def _process_crowdstrike_host(
        self,
        host: Dict[str, Any],
        source_id: str
    ) -> Dict[str, Any]:
        """Process a CrowdStrike host into an asset"""
        if not self.asset_service:
            return {"error": "Asset service not configured"}

        # Extract fields
        hostname = host.get("hostname")
        device_id = host.get("device_id")

        # Try to find existing asset
        existing = await self.asset_service.find_asset_by_identifier(
            "crowdstrike_aid", device_id
        )

        if not existing:
            existing = await self.asset_service.find_asset_by_hostname(hostname)

        asset_data = {
            "asset_type": self._map_cs_device_type(host.get("product_type")),
            "hostname": hostname,
            "ip_addresses": [host.get("local_ip")] if host.get("local_ip") else [],
            "mac_addresses": [host.get("mac_address")] if host.get("mac_address") else [],
            "os_family": host.get("platform_name", "").lower(),
            "os_name": host.get("os_product_name"),
            "os_version": host.get("os_version"),
            "status": "active" if host.get("status") == "normal" else "inactive"
        }

        if existing:
            # Update existing asset
            result = await self.asset_service.update_asset(
                asset_id=existing["id"],
                updates=asset_data,
                updated_by="discovery:crowdstrike",
                source="crowdstrike"
            )

            # Add identifier if not present
            identifiers = await self.asset_service.get_asset_identifiers(existing["id"])
            has_cs_id = any(
                i["identifier_type"] == "crowdstrike_aid"
                for i in identifiers
            )

            if not has_cs_id:
                await self.asset_service.add_identifier(
                    asset_id=existing["id"],
                    identifier_type="crowdstrike_aid",
                    identifier_value=device_id,
                    source="crowdstrike"
                )

            return {"updated": True, "asset_id": existing["id"]}
        else:
            # Create new asset
            result = await self.asset_service.create_asset(
                **asset_data,
                created_by="discovery:crowdstrike",
                source="crowdstrike"
            )

            if result:
                # Add CrowdStrike identifier
                await self.asset_service.add_identifier(
                    asset_id=result["id"],
                    identifier_type="crowdstrike_aid",
                    identifier_value=device_id,
                    source="crowdstrike"
                )

            return {"created": True, "asset_id": result["id"] if result else None}

    def _map_cs_device_type(self, product_type: str) -> str:
        """Map CrowdStrike product type to asset type"""
        mapping = {
            "1": "workstation",
            "2": "server",
            "3": "domain_controller"
        }
        return mapping.get(str(product_type), "endpoint")

    async def _discover_aws(
        self,
        source: Dict[str, Any],
        config: Dict[str, Any],
        run_id: str
    ) -> Dict[str, Any]:
        """Discover assets from AWS EC2"""
        try:
            # Check for AWS integration
            from integrations.registry.integration_registry import get_registry
            registry = get_registry()

            aws_integration = None
            integrations = registry.list(enabled_only=False)
            for integration in integrations:
                if "aws" in integration.id.lower():
                    aws_integration = integration
                    break

            if not aws_integration:
                return {
                    "success": False,
                    "status": "failed",
                    "error": "AWS integration not configured"
                }

            from integrations.engines.execution_engine import get_execution_engine
            engine = get_execution_engine()

            result = await engine.execute(
                integration_id=aws_integration.id,
                action_name="describe_instances",
                parameters={}
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "status": "failed",
                    "error": result.get("error", "Failed to query AWS")
                }

            instances = result.get("data", {}).get("Reservations", [])

            created = 0
            updated = 0
            failed = 0
            total = 0

            for reservation in instances:
                for instance in reservation.get("Instances", []):
                    total += 1
                    try:
                        asset_result = await self._process_aws_instance(
                            instance, source["id"]
                        )
                        if asset_result.get("created"):
                            created += 1
                        elif asset_result.get("updated"):
                            updated += 1
                    except Exception as e:
                        logger.error(f"Failed to process AWS instance: {e}")
                        failed += 1

            return {
                "success": True,
                "status": "completed",
                "discovered": total,
                "created": created,
                "updated": updated,
                "failed": failed
            }

        except Exception as e:
            logger.error(f"AWS discovery failed: {e}")
            return {
                "success": False,
                "status": "failed",
                "error": str(e)
            }

    async def _process_aws_instance(
        self,
        instance: Dict[str, Any],
        source_id: str
    ) -> Dict[str, Any]:
        """Process an AWS EC2 instance into an asset"""
        if not self.asset_service:
            return {"error": "Asset service not configured"}

        instance_id = instance.get("InstanceId")

        # Get name from tags
        name = None
        for tag in instance.get("Tags", []):
            if tag.get("Key") == "Name":
                name = tag.get("Value")
                break

        # Try to find existing asset
        existing = await self.asset_service.find_asset_by_identifier(
            "aws_instance_id", instance_id
        )

        if not existing and name:
            existing = await self.asset_service.find_asset_by_hostname(name)

        private_ips = []
        public_ips = []

        for ni in instance.get("NetworkInterfaces", []):
            if ni.get("PrivateIpAddress"):
                private_ips.append(ni["PrivateIpAddress"])
            if ni.get("Association", {}).get("PublicIp"):
                public_ips.append(ni["Association"]["PublicIp"])

        asset_data = {
            "asset_type": "cloud_instance",
            "hostname": name or instance_id,
            "ip_addresses": private_ips + public_ips,
            "os_family": "linux" if "linux" in instance.get("PlatformDetails", "").lower() else "windows",
            "environment": "cloud",
            "status": "active" if instance.get("State", {}).get("Name") == "running" else "inactive",
            "metadata": {
                "aws_instance_type": instance.get("InstanceType"),
                "aws_region": instance.get("Placement", {}).get("AvailabilityZone", "")[:-1],
                "aws_vpc_id": instance.get("VpcId"),
                "aws_subnet_id": instance.get("SubnetId")
            }
        }

        if existing:
            result = await self.asset_service.update_asset(
                asset_id=existing["id"],
                updates=asset_data,
                updated_by="discovery:aws",
                source="aws"
            )
            return {"updated": True, "asset_id": existing["id"]}
        else:
            result = await self.asset_service.create_asset(
                **asset_data,
                created_by="discovery:aws",
                source="aws"
            )

            if result:
                await self.asset_service.add_identifier(
                    asset_id=result["id"],
                    identifier_type="aws_instance_id",
                    identifier_value=instance_id,
                    source="aws"
                )

            return {"created": True, "asset_id": result["id"] if result else None}

    async def _discover_azure(
        self,
        source: Dict[str, Any],
        config: Dict[str, Any],
        run_id: str
    ) -> Dict[str, Any]:
        """Discover assets from Azure VMs"""
        # Similar pattern to AWS - placeholder for now
        return {
            "success": False,
            "status": "failed",
            "error": "Azure discovery not yet implemented"
        }

    async def _discover_ad(
        self,
        source: Dict[str, Any],
        config: Dict[str, Any],
        run_id: str
    ) -> Dict[str, Any]:
        """Discover assets from Active Directory"""
        # Would use LDAP queries - placeholder for now
        return {
            "success": False,
            "status": "failed",
            "error": "Active Directory discovery not yet implemented"
        }

    # =========================================================================
    # ASSET RECONCILIATION
    # =========================================================================

    async def reconcile_asset(
        self,
        asset_id: str,
        source_data: Dict[str, Dict[str, Any]],
        strategy: ReconciliationStrategy = ReconciliationStrategy.MERGE
    ) -> Optional[Dict[str, Any]]:
        """
        Reconcile asset data from multiple sources.

        source_data format:
        {
            "crowdstrike": {"hostname": "srv1", "ip_addresses": ["10.0.0.1"]},
            "aws": {"hostname": "srv1", "ip_addresses": ["10.0.0.2"]}
        }
        """
        if not self.asset_service:
            return None

        try:
            existing = await self.asset_service.get_asset(asset_id)
            if not existing:
                return None

            if strategy == ReconciliationStrategy.MERGE:
                merged = await self._merge_sources(existing, source_data)
            elif strategy == ReconciliationStrategy.NEWEST_WINS:
                merged = await self._newest_wins(existing, source_data)
            elif strategy == ReconciliationStrategy.PREFER_SOURCE:
                # Would need to specify which source to prefer
                merged = source_data.get(list(source_data.keys())[0], {})
            else:
                # Manual - flag for review
                await self._create_conflict(asset_id, source_data)
                return existing

            # Update asset with merged data
            result = await self.asset_service.update_asset(
                asset_id=asset_id,
                updates=merged,
                updated_by="reconciliation"
            )

            return result

        except Exception as e:
            logger.error(f"Asset reconciliation failed: {e}")
            return None

    async def _merge_sources(
        self,
        existing: Dict[str, Any],
        source_data: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Merge data from all sources"""
        merged = {}

        # Fields that should be merged (union)
        union_fields = ["ip_addresses", "mac_addresses", "compliance_tags", "custom_tags"]

        # Fields that take the most recent non-null value
        latest_fields = [
            "hostname", "fqdn", "display_name", "os_family",
            "os_name", "os_version", "owner", "department", "location"
        ]

        for field in union_fields:
            values = set(existing.get(field, []) or [])
            for source, data in source_data.items():
                for v in (data.get(field) or []):
                    values.add(v)
            if values:
                merged[field] = list(values)

        for field in latest_fields:
            # Take first non-null value from sources, fall back to existing
            for source, data in source_data.items():
                if data.get(field):
                    merged[field] = data[field]
                    break

        # Merge metadata
        merged_metadata = dict(existing.get("metadata") or {})
        for source, data in source_data.items():
            if data.get("metadata"):
                merged_metadata.update(data["metadata"])
        merged["metadata"] = merged_metadata

        return merged

    async def _newest_wins(
        self,
        existing: Dict[str, Any],
        source_data: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use data from the most recently updated source"""
        # Would need timestamp info in source_data
        # For now, just use the last source
        if source_data:
            return list(source_data.values())[-1]
        return {}

    async def _create_conflict(
        self,
        asset_id: str,
        source_data: Dict[str, Dict[str, Any]]
    ) -> None:
        """Create a conflict record for manual resolution"""
        if not self.db or not self.db.pool:
            return

        try:
            async with self.db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                await conn.execute("""
                    INSERT INTO asset_conflicts (
                        id, asset_id, conflicting_sources, conflict_data,
                        status, created_at,
                        tenant_id
                    )
                    VALUES ($1, $2, $3, $4, 'pending', $5, $6)
                """,
                    str(uuid.uuid4()),
                    asset_id,
                    list(source_data.keys()),
                    json.dumps(source_data),
                    datetime.now(timezone.utc),
                    uuid.UUID(_tenant_id) if _tenant_id else None
                )
        except Exception as e:
            logger.error(f"Failed to create conflict record: {e}")

    # =========================================================================
    # DISCOVERY QUEUE AND SCHEDULING
    # =========================================================================

    async def get_discovery_history(
        self,
        source_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get discovery run history"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                if source_id:
                    query = """
                        SELECT dq.*, ds.name as source_name, ds.source_type
                        FROM discovery_queue dq
                        JOIN discovery_sources ds ON dq.source_id = ds.id
                        WHERE dq.source_id = $1
                        ORDER BY dq.started_at DESC
                        LIMIT $2
                    """
                    rows = await conn.fetch(query, source_id, limit)
                else:
                    query = """
                        SELECT dq.*, ds.name as source_name, ds.source_type
                        FROM discovery_queue dq
                        JOIN discovery_sources ds ON dq.source_id = ds.id
                        ORDER BY dq.started_at DESC
                        LIMIT $1
                    """
                    rows = await conn.fetch(query, limit)

            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get discovery history: {e}")
            return []

    async def get_pending_conflicts(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get pending asset conflicts"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                query = """
                    SELECT ac.*, a.hostname, a.display_name
                    FROM asset_conflicts ac
                    JOIN assets a ON ac.asset_id = a.id
                    WHERE ac.status = 'pending'
                    ORDER BY ac.created_at DESC
                    LIMIT $1
                """
                rows = await conn.fetch(query, limit)
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get pending conflicts: {e}")
            return []

    async def resolve_conflict(
        self,
        conflict_id: str,
        resolution: Dict[str, Any],
        resolved_by: str
    ) -> bool:
        """Resolve an asset conflict"""
        if not self.db or not self.db.pool or not self.asset_service:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                # Get conflict
                conflict = await conn.fetchrow(
                    "SELECT * FROM asset_conflicts WHERE id = $1",
                    conflict_id
                )

                if not conflict:
                    return False

            # Apply resolution to asset
            result = await self.asset_service.update_asset(
                asset_id=conflict["asset_id"],
                updates=resolution,
                updated_by=resolved_by
            )

            if result:
                async with self.db.tenant_acquire() as conn:
                    # Mark conflict as resolved
                    await conn.execute("""
                        UPDATE asset_conflicts
                        SET status = 'resolved',
                            resolution = $1,
                            resolved_by = $2,
                            resolved_at = $3
                        WHERE id = $4
                    """,
                        json.dumps(resolution),
                        resolved_by,
                        datetime.now(timezone.utc),
                        conflict_id
                    )
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to resolve conflict: {e}")
            return False

    async def get_discovery_stats(self) -> Dict[str, Any]:
        """Get discovery statistics"""
        if not self.db or not self.db.pool:
            return {}

        try:
            stats = {}

            async with self.db.tenant_acquire() as conn:
                # Source counts
                source_count = await conn.fetchrow("""
                    SELECT
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE enabled = true) as enabled
                    FROM discovery_sources
                """)
                stats["sources"] = dict(source_count) if source_count else {"total": 0, "enabled": 0}

                # Recent discovery stats
                recent_runs = await conn.fetchrow("""
                    SELECT
                        COUNT(*) as total_runs,
                        COALESCE(SUM(assets_discovered), 0) as total_discovered,
                        COALESCE(SUM(assets_created), 0) as total_created,
                        COALESCE(SUM(assets_updated), 0) as total_updated,
                        COUNT(*) FILTER (WHERE status = 'failed') as failed_runs
                    FROM discovery_queue
                    WHERE started_at > NOW() - INTERVAL '7 days'
                """)
                stats["last_7_days"] = dict(recent_runs) if recent_runs else {}

                # Pending conflicts - table may not exist yet
                try:
                    conflict_count = await conn.fetchval("""
                        SELECT COUNT(*) FROM asset_conflicts WHERE status = 'pending'
                    """)
                    stats["pending_conflicts"] = conflict_count or 0
                except Exception:
                    stats["pending_conflicts"] = 0

            return stats

        except Exception as e:
            logger.error(f"Failed to get discovery stats: {e}")
            return {}


# Singleton instance
_discovery_orchestrator = None


def get_discovery_orchestrator() -> DiscoveryOrchestrator:
    """Get the singleton discovery orchestrator instance"""
    global _discovery_orchestrator
    if _discovery_orchestrator is None:
        _discovery_orchestrator = DiscoveryOrchestrator()
    return _discovery_orchestrator
