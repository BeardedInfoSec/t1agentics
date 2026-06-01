# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent-Asset Linker Service
===========================

Phase 9: Automatically links deployed agents (EDR, log collectors) to CMDB assets.

This service:
1. Monitors agent registrations and heartbeats
2. Matches agents to existing CMDB assets by hostname/IP/identifiers
3. Creates new assets if none exist (auto-discovery)
4. Maintains agent-to-asset relationships
5. Enriches agents with asset metadata (criticality, owner, etc.)
6. Tracks agent coverage across the asset inventory

Benefits:
- Automatic asset discovery from deployed agents
- Investigation enrichment with asset context
- Visibility into agent coverage gaps
- Asset criticality-based alert prioritization
"""

import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class CMDBAsset:
    """Represents a CMDB asset"""
    id: str
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    asset_type: str = "server"  # server, workstation, network, cloud
    environment: str = "production"  # production, staging, development
    criticality: str = "medium"  # critical, high, medium, low
    owner: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AgentAssetLink:
    """Represents a link between an agent and a CMDB asset"""
    agent_id: str
    asset_id: Optional[str]  # Can be None if unlinked
    agent_type: str  # 'edr', 'log_collector', 'unified', 'collector'
    match_method: Optional[str] = None  # 'hostname', 'ip', 'mac', 'identifier', 'manual'
    match_confidence: int = 0  # 0-100
    linked_at: Optional[datetime] = None
    linked_by: Optional[str] = None  # username for manual links
    auto_discovered: bool = False
    last_verified: Optional[datetime] = None
    notes: Optional[str] = None
    # Legacy compatibility
    link_method: Optional[str] = None
    link_confidence: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentAssetLinkerService:
    """
    Service for linking agents to CMDB assets.
    Provides automatic discovery, matching, and relationship management.

    Can operate in two modes:
    1. Standalone mode: Uses internal in-memory asset storage
    2. Integrated mode: Uses external asset_service for CMDB integration
    """

    def __init__(self):
        self._links: Dict[str, AgentAssetLink] = {}  # agent_id -> link
        self._assets: Dict[str, CMDBAsset] = {}  # asset_id -> asset (standalone mode)
        self._asset_agents: Dict[str, List[str]] = {}  # asset_id -> [agent_ids]
        self._unlinked_agents: Dict[str, Dict[str, Any]] = {}  # agent_id -> agent_data
        self._db = None
        self._asset_service = None
        self._standalone_mode = True  # Default to standalone until asset service available

    def set_db(self, db):
        """Set database connection"""
        self._db = db

    def set_asset_service(self, asset_service):
        """Set asset service reference"""
        self._asset_service = asset_service
        self._standalone_mode = False

    async def _get_asset_service(self):
        """Lazy load asset service"""
        if self._asset_service is None:
            try:
                from services.asset_service import get_asset_service
                self._asset_service = get_asset_service()
                if self._db:
                    self._asset_service.set_db(self._db)
                self._standalone_mode = False
            except ImportError:
                # Asset service not available, use standalone mode
                self._standalone_mode = True
                return None
        return self._asset_service

    # =========================================================================
    # ASSET MANAGEMENT (Standalone Mode)
    # =========================================================================

    async def create_asset(
        self,
        hostname: str,
        ip_addresses: List[str] = None,
        mac_addresses: List[str] = None,
        asset_type: str = "server",
        environment: str = "production",
        criticality: str = "medium",
        owner: Optional[str] = None,
        department: Optional[str] = None,
        location: Optional[str] = None,
        tags: List[str] = None,
        custom_attributes: Dict[str, Any] = None
    ) -> CMDBAsset:
        """Create a new CMDB asset in standalone mode"""
        asset_id = f"asset-{uuid.uuid4().hex[:12]}"
        asset = CMDBAsset(
            id=asset_id,
            hostname=hostname,
            ip_addresses=ip_addresses or [],
            mac_addresses=mac_addresses or [],
            asset_type=asset_type,
            environment=environment,
            criticality=criticality,
            owner=owner,
            department=department,
            location=location,
            tags=tags or [],
            custom_attributes=custom_attributes or {}
        )
        self._assets[asset_id] = asset
        logger.info(f"[AgentLinker] Created asset: {hostname} ({asset_id})")
        return asset

    async def get_uncovered_assets(self) -> List[Dict[str, Any]]:
        """Get list of assets without any linked agents"""
        uncovered = []
        for asset_id, asset in self._assets.items():
            if asset_id not in self._asset_agents or not self._asset_agents[asset_id]:
                uncovered.append({
                    "id": asset.id,
                    "hostname": asset.hostname,
                    "ip_addresses": asset.ip_addresses,
                    "asset_type": asset.asset_type,
                    "environment": asset.environment,
                    "criticality": asset.criticality,
                    "owner": asset.owner
                })
        return uncovered

    async def manual_link(
        self,
        agent_id: str,
        asset_id: str,
        agent_type: str = "collector",
        linked_by: Optional[str] = None,
        notes: Optional[str] = None
    ) -> AgentAssetLink:
        """Manually link an agent to an asset"""
        now = datetime.utcnow()
        link = AgentAssetLink(
            agent_id=agent_id,
            asset_id=asset_id,
            agent_type=agent_type,
            match_method="manual",
            match_confidence=100,
            linked_at=now,
            linked_by=linked_by,
            auto_discovered=False,
            last_verified=now,
            notes=notes,
            # Legacy fields
            link_method="manual",
            link_confidence=100
        )
        self._links[agent_id] = link

        # Update asset->agents mapping
        if asset_id not in self._asset_agents:
            self._asset_agents[asset_id] = []
        if agent_id not in self._asset_agents[asset_id]:
            self._asset_agents[asset_id].append(agent_id)

        # Remove from unlinked if present
        if agent_id in self._unlinked_agents:
            del self._unlinked_agents[agent_id]

        return link

    # =========================================================================
    # AGENT LINKING
    # =========================================================================

    async def link_agent_to_asset(
        self,
        agent_id: str,
        agent_data: Dict[str, Any],
        agent_type: str = "unified"
    ) -> Optional[AgentAssetLink]:
        """
        Attempt to link an agent to a CMDB asset.

        Process:
        1. Try to find existing asset by hostname
        2. Try to find by IP address
        3. Try to find by MAC address
        4. If no match, create new asset (auto-discovery)

        Works in both standalone mode (internal storage) and integrated mode (asset service).
        Returns the link if successful, None otherwise.
        """
        hostname = agent_data.get("hostname", "").lower()
        ip_address = agent_data.get("ip_address")
        mac_addresses = agent_data.get("mac_addresses", [])

        asset = None
        link_method = None
        confidence = 0
        now = datetime.utcnow()

        # Try to use external asset service first
        asset_service = await self._get_asset_service()

        if asset_service and not self._standalone_mode:
            # Integrated mode - use asset service
            # Try hostname match (highest confidence)
            if hostname and hostname != "unknown":
                asset = await asset_service.find_asset_by_hostname(hostname)
                if asset:
                    link_method = "hostname"
                    confidence = 95
                    logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by hostname: {hostname}")

            # Try IP match
            if not asset and ip_address:
                asset = await asset_service.find_asset_by_ip(ip_address)
                if asset:
                    link_method = "ip"
                    confidence = 85
                    logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by IP: {ip_address}")

            # Try MAC match
            if not asset and mac_addresses:
                for mac in mac_addresses:
                    asset = await asset_service.find_asset_by_identifier("mac", mac)
                    if asset:
                        link_method = "mac"
                        confidence = 80
                        logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by MAC: {mac}")
                        break

            # Try EDR agent ID match (for agents already in CMDB)
            if not asset:
                asset = await asset_service.find_asset_by_identifier("edr_agent_id", agent_id)
                if asset:
                    link_method = "identifier"
                    confidence = 100
                    logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by EDR agent ID")

            # If no match found, create new asset (auto-discovery)
            if not asset:
                asset = await self._create_asset_from_agent(agent_id, agent_data, agent_type)
                if asset:
                    link_method = "auto_created"
                    confidence = 70
                    logger.info(f"[AgentLinker] Created new asset for agent {agent_id}: {hostname or ip_address}")

            if asset and link_method:
                # Create the link
                link = AgentAssetLink(
                    agent_id=agent_id,
                    asset_id=str(asset.get("id")),
                    agent_type=agent_type,
                    match_method=link_method,
                    match_confidence=confidence,
                    linked_at=now,
                    auto_discovered=True,
                    last_verified=now,
                    link_method=link_method,
                    link_confidence=confidence,
                    metadata={
                        "agent_hostname": hostname,
                        "agent_ip": ip_address,
                        "asset_hostname": asset.get("hostname"),
                        "asset_criticality": asset.get("criticality"),
                        "asset_environment": asset.get("environment")
                    }
                )

                # Store link
                self._links[agent_id] = link

                # Update asset -> agents mapping
                asset_id_str = str(asset.get("id"))
                if asset_id_str not in self._asset_agents:
                    self._asset_agents[asset_id_str] = []
                if agent_id not in self._asset_agents[asset_id_str]:
                    self._asset_agents[asset_id_str].append(agent_id)

                # Add agent ID as identifier on the asset
                try:
                    await asset_service.add_identifier(
                        asset_id=asset_id_str,
                        identifier_type="edr_agent_id" if agent_type == "edr" else "log_agent_id",
                        identifier_value=agent_id,
                        source="agent_linker",
                        confidence=confidence
                    )
                except Exception as e:
                    logger.warning(f"[AgentLinker] Could not add identifier: {e}")

                # Remove from unlinked
                if agent_id in self._unlinked_agents:
                    del self._unlinked_agents[agent_id]

                return link

        else:
            # Standalone mode - use internal asset storage
            # Try hostname match
            if hostname and hostname != "unknown":
                for asset_id, cmdb_asset in self._assets.items():
                    if cmdb_asset.hostname.lower() == hostname:
                        asset = {"id": asset_id, "hostname": cmdb_asset.hostname,
                                 "criticality": cmdb_asset.criticality, "environment": cmdb_asset.environment}
                        link_method = "hostname"
                        confidence = 95
                        logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by hostname: {hostname}")
                        break

            # Try IP match
            if not asset and ip_address:
                for asset_id, cmdb_asset in self._assets.items():
                    if ip_address in cmdb_asset.ip_addresses:
                        asset = {"id": asset_id, "hostname": cmdb_asset.hostname,
                                 "criticality": cmdb_asset.criticality, "environment": cmdb_asset.environment}
                        link_method = "ip"
                        confidence = 85
                        logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by IP: {ip_address}")
                        break

            # Try MAC match
            if not asset and mac_addresses:
                for mac in mac_addresses:
                    for asset_id, cmdb_asset in self._assets.items():
                        if mac in cmdb_asset.mac_addresses:
                            asset = {"id": asset_id, "hostname": cmdb_asset.hostname,
                                     "criticality": cmdb_asset.criticality, "environment": cmdb_asset.environment}
                            link_method = "mac"
                            confidence = 80
                            logger.info(f"[AgentLinker] Matched agent {agent_id} to asset by MAC: {mac}")
                            break
                    if asset:
                        break

            # Auto-create asset if no match
            if not asset:
                new_asset = await self.create_asset(
                    hostname=hostname or ip_address or agent_id,
                    ip_addresses=[ip_address] if ip_address else [],
                    mac_addresses=mac_addresses,
                    asset_type="server",
                    environment="unknown",
                    criticality="medium",
                    tags=[f"agent:{agent_type}", "auto-discovered"]
                )
                asset = {"id": new_asset.id, "hostname": new_asset.hostname,
                         "criticality": new_asset.criticality, "environment": new_asset.environment}
                link_method = "auto_created"
                confidence = 70
                logger.info(f"[AgentLinker] Auto-created asset for agent {agent_id}: {hostname or ip_address}")

            if asset and link_method:
                # Create the link
                link = AgentAssetLink(
                    agent_id=agent_id,
                    asset_id=str(asset.get("id")),
                    agent_type=agent_type,
                    match_method=link_method,
                    match_confidence=confidence,
                    linked_at=now,
                    auto_discovered=True,
                    last_verified=now,
                    link_method=link_method,
                    link_confidence=confidence,
                    metadata={
                        "agent_hostname": hostname,
                        "agent_ip": ip_address,
                        "asset_hostname": asset.get("hostname"),
                        "asset_criticality": asset.get("criticality"),
                        "asset_environment": asset.get("environment")
                    }
                )

                # Store link
                self._links[agent_id] = link

                # Update asset -> agents mapping
                asset_id_str = str(asset.get("id"))
                if asset_id_str not in self._asset_agents:
                    self._asset_agents[asset_id_str] = []
                if agent_id not in self._asset_agents[asset_id_str]:
                    self._asset_agents[asset_id_str].append(agent_id)

                # Remove from unlinked
                if agent_id in self._unlinked_agents:
                    del self._unlinked_agents[agent_id]

                return link

        # No match - track as unlinked
        self._unlinked_agents[agent_id] = {
            **agent_data,
            "agent_type": agent_type,
            "link_attempted_at": datetime.utcnow().isoformat()
        }
        logger.warning(f"[AgentLinker] Could not link agent {agent_id} ({hostname}) to any asset")
        return None

    async def _create_asset_from_agent(
        self,
        agent_id: str,
        agent_data: Dict[str, Any],
        agent_type: str
    ) -> Optional[Dict[str, Any]]:
        """Create a new CMDB asset from agent data (auto-discovery)"""
        asset_service = await self._get_asset_service()
        if not asset_service:
            return None

        hostname = agent_data.get("hostname", "unknown")
        ip_address = agent_data.get("ip_address")
        os_type = agent_data.get("os_type", "unknown").lower()
        os_version = agent_data.get("os_version", "")
        system_info = agent_data.get("system_info", {})

        # Determine OS family
        os_family = "unknown"
        if os_type in ["linux", "ubuntu", "debian", "centos", "rhel", "fedora"]:
            os_family = "linux"
        elif os_type in ["windows", "win32", "win64"]:
            os_family = "windows"
        elif os_type in ["darwin", "macos", "mac"]:
            os_family = "darwin"

        # Build IP list
        ip_addresses = []
        if ip_address:
            ip_addresses.append(ip_address)

        # Extract MAC addresses if available
        mac_addresses = agent_data.get("mac_addresses", [])

        try:
            asset = await asset_service.create_asset(
                asset_type="endpoint",
                hostname=hostname if hostname != "unknown" else None,
                display_name=hostname or ip_address or agent_id,
                ip_addresses=ip_addresses,
                mac_addresses=mac_addresses,
                os_family=os_family,
                os_name=os_type,
                os_version=os_version,
                criticality="tier4",  # Default - can be updated
                status="active",
                environment="unknown",  # Can be updated based on rules
                custom_tags=[f"agent:{agent_type}", "auto-discovered"],
                metadata={
                    "discovered_by": "agent_linker",
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                    "system_info": system_info,
                    "discovery_time": datetime.utcnow().isoformat()
                },
                source="agent_auto_discovery"
            )
            return asset
        except Exception as e:
            logger.error(f"[AgentLinker] Failed to create asset for agent {agent_id}: {e}")
            return None

    async def update_link_verification(self, agent_id: str) -> bool:
        """Update last_verified timestamp for a link (called on heartbeat)"""
        if agent_id in self._links:
            self._links[agent_id].last_verified = datetime.utcnow()
            return True
        return False

    async def unlink_agent(self, agent_id: str) -> bool:
        """Remove link between agent and asset"""
        if agent_id in self._links:
            link = self._links[agent_id]

            # Remove from asset -> agents mapping
            asset_id = link.asset_id
            if asset_id in self._asset_agents:
                if agent_id in self._asset_agents[asset_id]:
                    self._asset_agents[asset_id].remove(agent_id)

            del self._links[agent_id]
            logger.info(f"[AgentLinker] Unlinked agent {agent_id} from asset {asset_id}")
            return True
        return False

    # =========================================================================
    # LINK QUERIES
    # =========================================================================

    def get_link(self, agent_id: str) -> Optional[AgentAssetLink]:
        """Get link for an agent"""
        return self._links.get(agent_id)

    def get_asset_for_agent(self, agent_id: str) -> Optional[str]:
        """Get asset ID for an agent"""
        link = self._links.get(agent_id)
        return link.asset_id if link else None

    def get_agents_for_asset(self, asset_id: str) -> List[str]:
        """Get all agent IDs linked to an asset"""
        return self._asset_agents.get(asset_id, [])

    def get_all_links(self) -> List[Dict[str, Any]]:
        """Get all agent-asset links"""
        return [
            {
                "agent_id": link.agent_id,
                "asset_id": link.asset_id,
                "agent_type": link.agent_type,
                "link_method": link.link_method,
                "link_confidence": link.link_confidence,
                "created_at": link.created_at.isoformat(),
                "last_verified": link.last_verified.isoformat(),
                "metadata": link.metadata
            }
            for link in self._links.values()
        ]

    def get_unlinked_agents(self) -> List[Dict[str, Any]]:
        """Get agents that couldn't be linked to assets"""
        return [
            {
                "agent_id": agent_id,
                **agent_data
            }
            for agent_id, agent_data in self._unlinked_agents.items()
        ]

    # =========================================================================
    # COVERAGE ANALYSIS
    # =========================================================================

    async def get_coverage_stats(self) -> Dict[str, Any]:
        """
        Get agent coverage statistics across CMDB assets.

        Returns:
        - Total assets
        - Assets with agents
        - Assets without agents (coverage gap)
        - Coverage by environment
        - Coverage by criticality

        Works in both standalone mode and integrated mode.
        """
        # Count assets with agents
        assets_with_agents = set(self._asset_agents.keys())

        # Analyze coverage gaps
        coverage_by_env = {}
        coverage_by_criticality = {}
        uncovered_critical = []

        # Try integrated mode first
        asset_service = await self._get_asset_service()
        if asset_service and not self._standalone_mode:
            try:
                # Get all assets from asset service
                assets, total_assets = await asset_service.list_assets(limit=10000)
                covered_count = len([a for a in assets_with_agents if a])

                for asset in assets:
                    asset_id = str(asset.get("id"))
                    env = asset.get("environment", "unknown")
                    crit = asset.get("criticality", "tier4")
                    has_agent = asset_id in assets_with_agents

                    # By environment
                    if env not in coverage_by_env:
                        coverage_by_env[env] = {"total": 0, "covered": 0}
                    coverage_by_env[env]["total"] += 1
                    if has_agent:
                        coverage_by_env[env]["covered"] += 1

                    # By criticality
                    if crit not in coverage_by_criticality:
                        coverage_by_criticality[crit] = {"total": 0, "covered": 0}
                    coverage_by_criticality[crit]["total"] += 1
                    if has_agent:
                        coverage_by_criticality[crit]["covered"] += 1

                    # Track uncovered critical assets
                    if not has_agent and crit in ["tier1", "tier2", "critical", "high"]:
                        uncovered_critical.append({
                            "asset_id": asset_id,
                            "hostname": asset.get("hostname"),
                            "display_name": asset.get("display_name"),
                            "criticality": crit,
                            "environment": env
                        })
            except Exception as e:
                logger.error(f"[AgentLinker] Coverage stats error (integrated): {e}")
                # Fall through to standalone mode
                self._standalone_mode = True

        # Standalone mode - use internal asset storage
        if self._standalone_mode or not asset_service:
            total_assets = len(self._assets)
            covered_count = len([aid for aid in self._asset_agents if self._asset_agents[aid]])

            for asset_id, asset in self._assets.items():
                env = asset.environment
                crit = asset.criticality
                has_agent = asset_id in assets_with_agents and len(self._asset_agents.get(asset_id, [])) > 0

                # By environment
                if env not in coverage_by_env:
                    coverage_by_env[env] = {"total": 0, "covered": 0}
                coverage_by_env[env]["total"] += 1
                if has_agent:
                    coverage_by_env[env]["covered"] += 1

                # By criticality
                if crit not in coverage_by_criticality:
                    coverage_by_criticality[crit] = {"total": 0, "covered": 0}
                coverage_by_criticality[crit]["total"] += 1
                if has_agent:
                    coverage_by_criticality[crit]["covered"] += 1

                # Track uncovered critical assets
                if not has_agent and crit in ["critical", "high"]:
                    uncovered_critical.append({
                        "asset_id": asset_id,
                        "hostname": asset.hostname,
                        "display_name": asset.hostname,
                        "criticality": crit,
                        "environment": env
                    })

        # Return coverage stats
        return {
            "total_assets": total_assets,
            "assets_with_agents": covered_count,
            "covered_assets": covered_count,
            "uncovered_assets": total_assets - covered_count,
            "coverage_percentage": round((covered_count / total_assets * 100) if total_assets > 0 else 0, 1),
            "total_linked_agents": len(self._links),
            "unlinked_agents": len(self._unlinked_agents),
            "coverage_by_environment": {
                env: {
                    **data,
                    "percentage": round((data["covered"] / data["total"] * 100) if data["total"] > 0 else 0, 1)
                }
                for env, data in coverage_by_env.items()
            },
            "coverage_by_criticality": {
                crit: {
                    **data,
                    "percentage": round((data["covered"] / data["total"] * 100) if data["total"] > 0 else 0, 1)
                }
                for crit, data in coverage_by_criticality.items()
            },
            "uncovered_critical_assets": uncovered_critical[:20],  # Top 20
            "uncovered_critical_count": len(uncovered_critical)
        }

    # =========================================================================
    # ENRICHMENT
    # =========================================================================

    async def enrich_agent_with_asset_context(
        self,
        agent_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Enrich agent data with linked asset context.

        Adds:
        - Asset criticality
        - Asset owner/team
        - Asset environment
        - Compliance tags
        """
        link = self._links.get(agent_id)
        if not link:
            return None

        asset_service = await self._get_asset_service()
        if not asset_service:
            return None

        try:
            asset = await asset_service.get_asset(link.asset_id)
            if not asset:
                return None

            return {
                "asset_id": link.asset_id,
                "asset_hostname": asset.get("hostname"),
                "asset_display_name": asset.get("display_name"),
                "criticality": asset.get("criticality"),
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "owner_team": asset.get("owner_team"),
                "department": asset.get("department"),
                "location": asset.get("location"),
                "compliance_tags": asset.get("compliance_tags", []),
                "custom_tags": asset.get("custom_tags", []),
                "link_confidence": link.link_confidence,
                "link_method": link.link_method
            }

        except Exception as e:
            logger.error(f"[AgentLinker] Enrichment error for agent {agent_id}: {e}")
            return None

    async def enrich_event_with_asset_context(
        self,
        event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich a security event with asset context based on host info.

        Extracts hostname/IP from event and looks up asset.
        """
        # Extract host info from event
        host = event.get("host", {})
        hostname = None
        ip_address = None

        if isinstance(host, dict):
            hostname = host.get("name") or host.get("hostname")
            ip_list = host.get("ip")
            ip_address = ip_list[0] if isinstance(ip_list, list) and ip_list else ip_list
        elif isinstance(host, str):
            hostname = host

        if not hostname and not ip_address:
            return event

        asset_service = await self._get_asset_service()
        if not asset_service:
            return event

        # Look up asset
        asset = await asset_service.lookup_asset(ip=ip_address, hostname=hostname)
        if asset:
            # Add asset context to event
            event["asset"] = {
                "id": str(asset.get("id")),
                "hostname": asset.get("hostname"),
                "display_name": asset.get("display_name"),
                "criticality": asset.get("criticality"),
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "owner_team": asset.get("owner_team"),
                "compliance_tags": asset.get("compliance_tags", [])
            }

            # Add priority boost based on criticality
            criticality = asset.get("criticality", "tier4")
            priority_boost = {
                "tier1": 3,
                "tier2": 2,
                "tier3": 1,
                "tier4": 0
            }.get(criticality, 0)

            if priority_boost > 0:
                event["_priority_boost"] = priority_boost
                event["_priority_reason"] = f"Asset criticality: {criticality}"

        return event

    # =========================================================================
    # BATCH OPERATIONS
    # =========================================================================

    async def link_all_agents(self) -> Dict[str, Any]:
        """
        Attempt to link all unlinked agents to assets.
        Called periodically or manually to reconcile.
        """
        results = {
            "attempted": 0,
            "linked": 0,
            "failed": 0,
            "links": []
        }

        # Get current agents from both sources
        try:
            from routes.logs import _registered_agents
            from routes.edr import _edr_agents
        except ImportError as e:
            logger.warning(f"[AgentLinker] Could not import agent stores: {e}")
            return results

        # Process log collection agents
        for agent_id, agent_data in _registered_agents.items():
            if agent_id not in self._links:
                results["attempted"] += 1
                link = await self.link_agent_to_asset(agent_id, agent_data, "log_collector")
                if link:
                    results["linked"] += 1
                    results["links"].append({
                        "agent_id": agent_id,
                        "asset_id": link.asset_id,
                        "method": link.link_method
                    })
                else:
                    results["failed"] += 1

        # Process EDR agents
        for agent_id, agent_data in _edr_agents.items():
            if agent_id not in self._links:
                results["attempted"] += 1
                link = await self.link_agent_to_asset(agent_id, agent_data, "edr")
                if link:
                    results["linked"] += 1
                    results["links"].append({
                        "agent_id": agent_id,
                        "asset_id": link.asset_id,
                        "method": link.link_method
                    })
                else:
                    results["failed"] += 1

        logger.info(f"[AgentLinker] Batch link complete: {results['linked']}/{results['attempted']} linked")
        return results

    async def cleanup_stale_links(self, stale_hours: int = 24) -> int:
        """Remove links for agents that haven't been verified recently"""
        cutoff = datetime.utcnow() - timedelta(hours=stale_hours)
        stale_agent_ids = [
            agent_id for agent_id, link in self._links.items()
            if link.last_verified < cutoff
        ]

        for agent_id in stale_agent_ids:
            await self.unlink_agent(agent_id)

        if stale_agent_ids:
            logger.info(f"[AgentLinker] Cleaned up {len(stale_agent_ids)} stale links")

        return len(stale_agent_ids)


# Singleton instance
_agent_asset_linker: Optional[AgentAssetLinkerService] = None


def get_agent_asset_linker() -> AgentAssetLinkerService:
    """Get the agent-asset linker service singleton"""
    global _agent_asset_linker
    if _agent_asset_linker is None:
        _agent_asset_linker = AgentAssetLinkerService()
    return _agent_asset_linker


async def initialize_agent_asset_linker(db=None, asset_service=None):
    """Initialize the linker with dependencies"""
    linker = get_agent_asset_linker()
    if db:
        linker.set_db(db)
    if asset_service:
        linker.set_asset_service(asset_service)
    return linker
