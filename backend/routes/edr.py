# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
EDR (Endpoint Detection and Response) API Routes
=================================================
Handles EDR agent registration, event ingestion, IOC distribution,
response actions, and asset inventory.
"""

from fastapi import APIRouter, HTTPException, Header, Request, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import logging
import uuid
import re
import ipaddress
from dependencies.auth import get_current_user

# Optional OpenSearch integration
try:
    from services.log_collection.opensearch_client import get_opensearch_client
    HAS_OPENSEARCH = True
except ImportError:
    HAS_OPENSEARCH = False
    get_opensearch_client = None

# Agent-Asset Linker (Phase 9)
try:
    from services.agent_asset_linker import get_agent_asset_linker
    HAS_ASSET_LINKER = True
except ImportError:
    HAS_ASSET_LINKER = False
    get_agent_asset_linker = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/edr", tags=["EDR"], dependencies=[Depends(get_current_user)])

# ============================================================================
# In-Memory Stores (Replace with database in production)
# ============================================================================

# Registered EDR agents
_edr_agents: Dict[str, Dict[str, Any]] = {}

# Pending EDR agents (awaiting approval)
_pending_edr_agents: Dict[str, Dict[str, Any]] = {}

# Agent inventories (agent_id -> inventory)
_agent_inventories: Dict[str, Dict[str, Any]] = {}

# IOC database
_ioc_database: Dict[str, Any] = {
    "hashes": [],       # SHA256 file hashes
    "ips": [],          # IP addresses
    "domains": [],      # Domain names
    "process_names": [],  # Malicious process names
    "file_paths": [],   # Malicious file paths
    "last_updated": None
}

# Pending response actions for agents
_pending_actions: Dict[str, List[Dict]] = {}  # agent_id -> [actions]

# EDR events (in-memory, limited)
_edr_events: List[Dict] = []
MAX_EVENTS = 10000

# Metrics history for agents (agent_id -> list of metric snapshots, max 60)
_edr_metrics_history: Dict[str, List[Dict[str, Any]]] = {}

# Auto-approve settings for EDR
# SECURITY: Auto-approve is DISABLED by default. Enable only after configuring
# specific hostname patterns and required tags. Never use wildcard patterns.
_edr_auto_approve: Dict[str, Any] = {
    "enabled": False,  # SECURITY: Disabled by default - require manual approval
    "allowed_networks": [],  # SECURITY: Empty by default - configure specific networks
    "allowed_hostname_patterns": [],  # SECURITY: Empty by default - no wildcards allowed
    "required_tags": ["edr-approved"]  # SECURITY: Require explicit approval tag
}


# ============================================================================
# Models
# ============================================================================

class EDRAgentRegisterRequest(BaseModel):
    """EDR agent registration request"""
    hostname: str
    os_type: str = "linux"
    os_version: str = ""
    agent_type: str = "t1-linux-edr"
    agent_version: str
    ip_address: str
    tags: List[str] = []
    agent_key: str
    capabilities: Dict[str, Any] = {}


class EDREventBatch(BaseModel):
    """Batch of EDR events"""
    events: List[Dict[str, Any]]
    agent_id: str


class IOCUpdate(BaseModel):
    """IOC database update"""
    hashes: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    process_names: Optional[List[str]] = None
    file_paths: Optional[List[str]] = None
    replace: bool = False  # If true, replace all; if false, append


class ResponseAction(BaseModel):
    """Response action to execute on agent"""
    type: str  # kill_process, quarantine_file, block_ip, unblock_ip
    target: str  # PID, filepath, IP
    reason: str = ""


class AgentActionRequest(BaseModel):
    """Request to queue an action for an agent"""
    action: ResponseAction


class InventoryData(BaseModel):
    """Asset inventory data from agent"""
    hostname: str
    ip_addresses: List[str] = []
    mac_addresses: List[str] = []
    os: Dict[str, str] = {}
    hardware: Dict[str, Any] = {}
    network: Dict[str, Any] = {}
    software: Dict[str, Any] = {}
    users: List[Dict] = []
    last_boot: str = ""
    collected_at: str = ""


# ============================================================================
# Helper Functions
# ============================================================================

def _check_edr_auto_approve(hostname: str, ip_address: str, tags: List[str]) -> bool:
    """Check if agent should be auto-approved"""
    if not _edr_auto_approve.get("enabled"):
        return False

    # Check IP network
    if _edr_auto_approve.get("allowed_networks"):
        try:
            agent_ip = ipaddress.ip_address(ip_address)
            for network_str in _edr_auto_approve["allowed_networks"]:
                network = ipaddress.ip_network(network_str, strict=False)
                if agent_ip in network:
                    return True
        except ValueError:
            pass

    # Check hostname pattern
    if _edr_auto_approve.get("allowed_hostname_patterns"):
        for pattern in _edr_auto_approve["allowed_hostname_patterns"]:
            if re.match(pattern, hostname, re.IGNORECASE):
                return True

    # Check required tags
    if _edr_auto_approve.get("required_tags"):
        required = set(_edr_auto_approve["required_tags"])
        if required.issubset(set(tags)):
            return True

    return False


def _get_agent_by_token(token: str) -> Optional[Dict]:
    """Get agent by token (agent_key)"""
    for agent_id, agent in _edr_agents.items():
        if agent.get("agent_key") == token:
            return agent
    return None


# ============================================================================
# Agent Registration Endpoints
# ============================================================================

@router.post("/agents/register")
async def register_edr_agent(request: EDRAgentRegisterRequest):
    """
    Register a new EDR agent (self-registration)
    No authentication required - agents self-register and await approval.
    """
    agent_key = request.agent_key

    # Check if already registered
    for agent_id, agent in _edr_agents.items():
        if agent.get("agent_key") == agent_key:
            return {
                "status": "approved",
                "agent_id": agent_id,
                "message": "Agent already registered"
            }

    # Check if pending
    if agent_key in _pending_edr_agents:
        return {
            "status": "pending",
            "agent_id": _pending_edr_agents[agent_key].get("agent_id"),
            "message": "Awaiting admin approval"
        }

    # Generate agent ID
    agent_id = f"edr-{request.hostname}-{uuid.uuid4().hex[:8]}"

    agent_data = {
        "agent_id": agent_id,
        "agent_key": agent_key,
        "hostname": request.hostname,
        "os_type": request.os_type,
        "os_version": request.os_version,
        "agent_type": request.agent_type,
        "agent_version": request.agent_version,
        "ip_address": request.ip_address,
        "tags": request.tags,
        "capabilities": request.capabilities,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }

    # Check auto-approve
    if _check_edr_auto_approve(request.hostname, request.ip_address, request.tags):
        agent_data["status"] = "active"
        agent_data["approved_at"] = datetime.now(timezone.utc).isoformat()
        agent_data["auto_approved"] = True
        _edr_agents[agent_id] = agent_data
        logger.info(f"EDR agent auto-approved: {agent_id} ({request.hostname})")

        # Link agent to CMDB asset (Phase 9)
        if HAS_ASSET_LINKER and get_agent_asset_linker:
            try:
                linker = get_agent_asset_linker()
                link = await linker.link_agent_to_asset(agent_id, agent_data, agent_type="edr")
                if link:
                    agent_data["asset_id"] = link.asset_id
                    agent_data["asset_link_method"] = link.match_method
                    logger.info(f"EDR agent {agent_id} linked to asset {link.asset_id}")
            except Exception as e:
                logger.warning(f"Could not link EDR agent to asset: {e}")

        return {
            "status": "approved",
            "agent_id": agent_id,
            "message": "Agent auto-approved"
        }

    # Add to pending
    _pending_edr_agents[agent_key] = agent_data
    logger.info(f"EDR agent pending approval: {agent_id} ({request.hostname})")

    return {
        "status": "pending",
        "agent_id": agent_id,
        "message": "Registration pending admin approval"
    }


@router.get("/agents/check/{agent_key}")
async def check_edr_agent_status(agent_key: str):
    """
    Check registration status of an EDR agent.
    Used by agents to poll for approval.
    """
    # Check if approved
    for agent_id, agent in _edr_agents.items():
        if agent.get("agent_key") == agent_key:
            return {
                "status": "approved",
                "agent_id": agent_id,
                "config": agent.get("config", {})
            }

    # Check if pending
    if agent_key in _pending_edr_agents:
        return {
            "status": "pending",
            "agent_id": _pending_edr_agents[agent_key].get("agent_id")
        }

    return {"status": "unknown"}


@router.get("/agents/pending")
async def list_pending_edr_agents():
    """List all EDR agents pending approval"""
    return {
        "pending_agents": list(_pending_edr_agents.values()),
        "count": len(_pending_edr_agents)
    }


@router.post("/agents/pending/{agent_key}/approve")
async def approve_edr_agent(agent_key: str):
    """Approve a pending EDR agent"""
    if agent_key not in _pending_edr_agents:
        raise HTTPException(status_code=404, detail="Pending agent not found")

    agent_data = _pending_edr_agents.pop(agent_key)
    agent_data["status"] = "active"
    agent_data["approved_at"] = datetime.now(timezone.utc).isoformat()

    agent_id = agent_data["agent_id"]
    _edr_agents[agent_id] = agent_data

    logger.info(f"EDR agent approved: {agent_id}")
    return {"status": "approved", "agent_id": agent_id}


@router.post("/agents/pending/{agent_key}/reject")
async def reject_edr_agent(agent_key: str):
    """Reject a pending EDR agent"""
    if agent_key not in _pending_edr_agents:
        raise HTTPException(status_code=404, detail="Pending agent not found")

    agent_data = _pending_edr_agents.pop(agent_key)
    logger.info(f"EDR agent rejected: {agent_data.get('agent_id')}")
    return {"status": "rejected"}


@router.get("/agents")
async def list_edr_agents():
    """List all registered EDR agents"""
    return {
        "agents": list(_edr_agents.values()),
        "count": len(_edr_agents)
    }


@router.get("/agents/{agent_id}/metrics")
async def get_edr_agent_metrics(
    agent_id: str,
    limit: int = 60
):
    """
    Get historical metrics for an EDR agent.
    Returns CPU, memory, disk, and network metrics over time.
    """
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _edr_agents[agent_id]
    metrics_history = _edr_metrics_history.get(agent_id, [])

    return {
        "agent_id": agent_id,
        "hostname": agent.get("hostname"),
        "current": agent.get("system_info", {}),
        "history": metrics_history[-limit:] if metrics_history else [],
        "history_count": len(metrics_history)
    }


@router.get("/agents/{agent_id}")
async def get_edr_agent(agent_id: str):
    """Get details for a specific EDR agent"""
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _edr_agents[agent_id]
    inventory = _agent_inventories.get(agent_id)

    return {
        "agent": agent,
        "inventory": inventory
    }


@router.delete("/agents/{agent_id}")
async def delete_edr_agent(agent_id: str):
    """Remove an EDR agent"""
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    del _edr_agents[agent_id]
    _agent_inventories.pop(agent_id, None)
    _pending_actions.pop(agent_id, None)

    logger.info(f"EDR agent removed: {agent_id}")
    return {"status": "deleted", "agent_id": agent_id}


# ============================================================================
# Heartbeat and Communication
# ============================================================================

@router.post("/agents/{agent_id}/heartbeat")
async def edr_agent_heartbeat(
    agent_id: str,
    request: Request,
    x_agent_token: str = Header(None)
):
    """
    Process agent heartbeat and return any pending actions/config.
    """
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _edr_agents[agent_id]
    if agent.get("agent_key") != x_agent_token:
        raise HTTPException(status_code=401, detail="Invalid agent token")

    # Update last seen
    agent["last_seen"] = datetime.now(timezone.utc).isoformat()

    # Update agent-asset link verification (Phase 9)
    if HAS_ASSET_LINKER and get_agent_asset_linker:
        try:
            linker = get_agent_asset_linker()
            await linker.update_link_verification(agent_id)
        except Exception:
            pass  # Non-critical

    # Update stats from heartbeat
    try:
        body = await request.json()
        agent["events_sent"] = body.get("events_sent", 0)
        agent["threats_detected"] = body.get("threats_detected", 0)
        agent["actions_taken"] = body.get("actions_taken", 0)
        agent["monitors"] = body.get("monitors", {})
        agent["ioc_count"] = body.get("ioc_count", 0)
        # Update agent version if provided
        if body.get("agent_version"):
            agent["agent_version"] = body.get("agent_version")
        # Update system info if provided
        if body.get("system_info"):
            agent["system_info"] = body.get("system_info")

            # Store metrics history for trending
            system_info = body.get("system_info")
            if agent_id not in _edr_metrics_history:
                _edr_metrics_history[agent_id] = []

            # Create metrics snapshot with timestamp
            metrics_snapshot = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu_percent": system_info.get("cpu_percent"),
                "memory_percent": system_info.get("memory_percent"),
                "memory_used_gb": system_info.get("memory_used_gb"),
                "disk_percent": system_info.get("disk_percent"),
                "network_bytes_sent": system_info.get("network_bytes_sent"),
                "network_bytes_recv": system_info.get("network_bytes_recv"),
                "process_count": system_info.get("process_count"),
                "load_average": system_info.get("load_average")
            }
            _edr_metrics_history[agent_id].append(metrics_snapshot)

            # Keep only last 60 data points
            if len(_edr_metrics_history[agent_id]) > 60:
                _edr_metrics_history[agent_id] = _edr_metrics_history[agent_id][-60:]
    except:
        pass

    # Get pending actions
    pending = _pending_actions.pop(agent_id, [])

    response = {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    if pending:
        response["pending_actions"] = pending

    if agent.get("pending_config"):
        response["config"] = agent.pop("pending_config")

    return response


# ============================================================================
# Event Ingestion
# ============================================================================

@router.post("/events")
async def ingest_edr_events(
    batch: EDREventBatch,
    x_agent_token: str = Header(None),
    background_tasks: BackgroundTasks = None
):
    """
    Ingest EDR events from agent.
    Returns any pending response actions.
    """
    agent = _get_agent_by_token(x_agent_token)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")

    agent_id = agent["agent_id"]

    # Process events
    threat_events = []
    events_to_index = []

    for event in batch.events:
        event["agent_id"] = agent_id
        event["received_at"] = datetime.now(timezone.utc).isoformat()

        # Store event in memory
        _edr_events.append(event)
        if len(_edr_events) > MAX_EVENTS:
            _edr_events.pop(0)

        # Prepare for OpenSearch indexing
        events_to_index.append(event)

        # Track threats
        if event.get("threat_detected"):
            threat_events.append(event)

    # Index events to OpenSearch in background
    if background_tasks and events_to_index:
        background_tasks.add_task(_index_edr_events_to_opensearch, events_to_index)

    # Log threats
    if threat_events:
        logger.warning(f"EDR threats detected from {agent_id}: {len(threat_events)} events")

    # Return any pending actions
    pending = _pending_actions.pop(agent_id, [])

    return {
        "status": "ok",
        "received": len(batch.events),
        "threats": len(threat_events),
        "actions": pending
    }


async def _index_edr_events_to_opensearch(events: List[Dict]):
    """Background task to index EDR events to OpenSearch"""
    if not HAS_OPENSEARCH:
        return

    try:
        client = await get_opensearch_client()
        indexed = 0
        for event in events:
            # Ensure source_type is set for filtering in Security Log Viewer
            if "source_type" not in event:
                event["source_type"] = event.get("event", {}).get("category", ["edr"])[0] if event.get("event", {}).get("category") else "edr"

            success = await client.index_event(event, index="logs-security")
            if success:
                indexed += 1

        if indexed > 0:
            logger.debug(f"[EDR] Indexed {indexed}/{len(events)} events to OpenSearch")
    except Exception as e:
        logger.warning(f"[EDR] Failed to index events to OpenSearch: {e}")


@router.get("/events")
async def get_edr_events(
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    threats_only: bool = False,
    limit: int = 100
):
    """Query EDR events"""
    events = _edr_events.copy()

    if agent_id:
        events = [e for e in events if e.get("agent_id") == agent_id]

    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]

    if threats_only:
        events = [e for e in events if e.get("threat_detected")]

    # Return most recent first
    events = sorted(events, key=lambda x: x.get("@timestamp", ""), reverse=True)

    return {
        "events": events[:limit],
        "total": len(events)
    }


# ============================================================================
# IOC Management
# ============================================================================

@router.get("/iocs")
async def get_iocs(x_agent_token: str = Header(None)):
    """
    Get current IOC database.
    Used by agents to sync IOCs.
    """
    # Verify token if provided
    if x_agent_token:
        agent = _get_agent_by_token(x_agent_token)
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")

    return {
        "hashes": _ioc_database["hashes"],
        "ips": _ioc_database["ips"],
        "domains": _ioc_database["domains"],
        "process_names": _ioc_database["process_names"],
        "file_paths": _ioc_database["file_paths"],
        "last_updated": _ioc_database["last_updated"],
        "counts": {
            "hashes": len(_ioc_database["hashes"]),
            "ips": len(_ioc_database["ips"]),
            "domains": len(_ioc_database["domains"]),
            "process_names": len(_ioc_database["process_names"]),
            "file_paths": len(_ioc_database["file_paths"])
        }
    }


@router.put("/iocs")
async def update_iocs(update: IOCUpdate):
    """
    Update IOC database.
    Admin endpoint to add/replace IOCs.
    """
    if update.replace:
        # Replace all
        if update.hashes is not None:
            _ioc_database["hashes"] = update.hashes
        if update.ips is not None:
            _ioc_database["ips"] = update.ips
        if update.domains is not None:
            _ioc_database["domains"] = update.domains
        if update.process_names is not None:
            _ioc_database["process_names"] = update.process_names
        if update.file_paths is not None:
            _ioc_database["file_paths"] = update.file_paths
    else:
        # Append (deduplicated)
        if update.hashes:
            _ioc_database["hashes"] = list(set(_ioc_database["hashes"] + update.hashes))
        if update.ips:
            _ioc_database["ips"] = list(set(_ioc_database["ips"] + update.ips))
        if update.domains:
            _ioc_database["domains"] = list(set(_ioc_database["domains"] + update.domains))
        if update.process_names:
            _ioc_database["process_names"] = list(set(_ioc_database["process_names"] + update.process_names))
        if update.file_paths:
            _ioc_database["file_paths"] = list(set(_ioc_database["file_paths"] + update.file_paths))

    _ioc_database["last_updated"] = datetime.now(timezone.utc).isoformat()

    total = (len(_ioc_database["hashes"]) + len(_ioc_database["ips"]) +
             len(_ioc_database["domains"]) + len(_ioc_database["process_names"]) +
             len(_ioc_database["file_paths"]))

    logger.info(f"IOC database updated: {total} total IOCs")

    return {
        "status": "updated",
        "counts": {
            "hashes": len(_ioc_database["hashes"]),
            "ips": len(_ioc_database["ips"]),
            "domains": len(_ioc_database["domains"]),
            "process_names": len(_ioc_database["process_names"]),
            "file_paths": len(_ioc_database["file_paths"])
        }
    }


@router.post("/iocs/bulk-import")
async def bulk_import_iocs(request: Request):
    """
    Bulk import IOCs from various formats.
    Accepts JSON with typed IOCs or plain text (one per line).
    """
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        data = await request.json()
        update = IOCUpdate(**data)
        return await update_iocs(update)
    else:
        # Plain text - try to auto-detect type
        body = await request.body()
        lines = body.decode().strip().split("\n")

        hashes = []
        ips = []
        domains = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Detect type
            if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
                hashes.append(line.lower())
            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                ips.append(line)
            elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$", line):
                domains.append(line.lower())

        update = IOCUpdate(hashes=hashes, ips=ips, domains=domains)
        return await update_iocs(update)


# ============================================================================
# Response Actions
# ============================================================================

@router.post("/agents/{agent_id}/action")
async def queue_agent_action(agent_id: str, action_request: AgentActionRequest):
    """
    Queue a response action for an agent.
    Action will be delivered on next heartbeat.
    """
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    action = action_request.action

    # Validate action type
    valid_actions = ["kill_process", "quarantine_file", "block_ip", "unblock_ip"]
    if action.type not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action type. Must be one of: {valid_actions}")

    # Build action payload
    action_payload = {
        "type": action.type,
        "reason": action.reason,
        "queued_at": datetime.now(timezone.utc).isoformat()
    }

    # Map target to appropriate field
    if action.type == "kill_process":
        action_payload["pid"] = int(action.target)
    elif action.type == "quarantine_file":
        action_payload["filepath"] = action.target
    elif action.type in ["block_ip", "unblock_ip"]:
        action_payload["ip"] = action.target

    # Queue action
    if agent_id not in _pending_actions:
        _pending_actions[agent_id] = []
    _pending_actions[agent_id].append(action_payload)

    logger.info(f"Queued action for {agent_id}: {action.type} - {action.target}")

    return {
        "status": "queued",
        "agent_id": agent_id,
        "action": action_payload
    }


@router.get("/agents/{agent_id}/actions")
async def get_pending_actions(agent_id: str):
    """Get pending actions for an agent"""
    return {
        "agent_id": agent_id,
        "pending_actions": _pending_actions.get(agent_id, [])
    }


# ============================================================================
# Asset Inventory
# ============================================================================

@router.post("/agents/{agent_id}/inventory")
async def submit_inventory(
    agent_id: str,
    inventory: InventoryData,
    x_agent_token: str = Header(None)
):
    """
    Submit asset inventory from EDR agent.
    """
    if agent_id not in _edr_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _edr_agents[agent_id]
    if agent.get("agent_key") != x_agent_token:
        raise HTTPException(status_code=401, detail="Invalid agent token")

    # Store inventory
    inventory_data = inventory.dict()
    inventory_data["agent_id"] = agent_id
    inventory_data["submitted_at"] = datetime.now(timezone.utc).isoformat()

    _agent_inventories[agent_id] = inventory_data

    logger.info(f"Inventory received from {agent_id}: {len(inventory.software.get('packages', []))} packages")

    return {"status": "received", "agent_id": agent_id}


@router.get("/inventory")
async def get_all_inventory():
    """Get inventory for all agents (asset database)"""
    return {
        "assets": list(_agent_inventories.values()),
        "count": len(_agent_inventories)
    }


@router.get("/inventory/{agent_id}")
async def get_agent_inventory(agent_id: str):
    """Get inventory for a specific agent"""
    if agent_id not in _agent_inventories:
        raise HTTPException(status_code=404, detail="Inventory not found")

    return _agent_inventories[agent_id]


@router.get("/inventory/search")
async def search_inventory(
    package: Optional[str] = None,
    service: Optional[str] = None,
    user: Optional[str] = None,
    port: Optional[int] = None,
    ip: Optional[str] = None
):
    """
    Search across all asset inventories.
    Find which hosts have a specific package, service, user, or open port.
    """
    results = []

    for agent_id, inv in _agent_inventories.items():
        match = False
        match_details = {}

        # Search packages
        if package:
            packages = inv.get("software", {}).get("packages", [])
            matching_pkgs = [p for p in packages if package.lower() in p.get("name", "").lower()]
            if matching_pkgs:
                match = True
                match_details["packages"] = matching_pkgs

        # Search services
        if service:
            services = inv.get("software", {}).get("services", [])
            matching_svcs = [s for s in services if service.lower() in s.get("name", "").lower()]
            if matching_svcs:
                match = True
                match_details["services"] = matching_svcs

        # Search users
        if user:
            users = inv.get("users", [])
            matching_users = [u for u in users if user.lower() in u.get("username", "").lower()]
            if matching_users:
                match = True
                match_details["users"] = matching_users

        # Search ports
        if port:
            ports = inv.get("network", {}).get("open_ports", [])
            matching_ports = [p for p in ports if p.get("port") == port]
            if matching_ports:
                match = True
                match_details["ports"] = matching_ports

        # Search IP
        if ip:
            ips = inv.get("ip_addresses", [])
            if ip in ips:
                match = True
                match_details["ip"] = ip

        if match:
            results.append({
                "agent_id": agent_id,
                "hostname": inv.get("hostname"),
                "ip_addresses": inv.get("ip_addresses", []),
                "matches": match_details
            })

    return {
        "results": results,
        "count": len(results)
    }


# ============================================================================
# Dashboard / Statistics
# ============================================================================

@router.get("/stats")
async def get_edr_stats():
    """Get EDR dashboard statistics"""
    # Count threats in last 24 hours
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(days=1)).isoformat()

    recent_threats = [e for e in _edr_events
                      if e.get("threat_detected") and e.get("@timestamp", "") > day_ago]

    # Agent status
    active_agents = [a for a in _edr_agents.values() if a.get("status") == "active"]
    offline_threshold = (now - timedelta(minutes=5)).isoformat()
    online_agents = [a for a in active_agents if a.get("last_seen", "") > offline_threshold]

    return {
        "agents": {
            "total": len(_edr_agents),
            "active": len(active_agents),
            "online": len(online_agents),
            "pending": len(_pending_edr_agents)
        },
        "events": {
            "total": len(_edr_events),
            "threats_24h": len(recent_threats)
        },
        "iocs": {
            "hashes": len(_ioc_database["hashes"]),
            "ips": len(_ioc_database["ips"]),
            "domains": len(_ioc_database["domains"]),
            "total": (len(_ioc_database["hashes"]) + len(_ioc_database["ips"]) +
                     len(_ioc_database["domains"]) + len(_ioc_database["process_names"]) +
                     len(_ioc_database["file_paths"]))
        },
        "inventory": {
            "assets": len(_agent_inventories)
        }
    }


# ============================================================================
# Auto-Approve Settings
# ============================================================================

@router.get("/auto-approve")
async def get_edr_auto_approve():
    """Get EDR auto-approve settings"""
    return _edr_auto_approve


@router.put("/auto-approve")
async def update_edr_auto_approve(settings: Dict[str, Any]):
    """
    Update EDR auto-approve settings.

    SECURITY: Wildcard patterns are rejected to prevent unauthorized agent enrollment.
    """
    # SECURITY: Validate hostname patterns - reject wildcards
    if "allowed_hostname_patterns" in settings:
        dangerous_patterns = [".*", ".+", "^.*$", "^.+$", ".*$", "^.*", "."]
        for pattern in settings["allowed_hostname_patterns"]:
            if pattern in dangerous_patterns or pattern.strip() == "":
                raise HTTPException(
                    status_code=400,
                    detail=f"Wildcard hostname patterns are not allowed for security reasons: '{pattern}'"
                )

    if "enabled" in settings:
        _edr_auto_approve["enabled"] = settings["enabled"]
    if "allowed_networks" in settings:
        _edr_auto_approve["allowed_networks"] = settings["allowed_networks"]
    if "allowed_hostname_patterns" in settings:
        _edr_auto_approve["allowed_hostname_patterns"] = settings["allowed_hostname_patterns"]
    if "required_tags" in settings:
        _edr_auto_approve["required_tags"] = settings["required_tags"]

    logger.info(f"EDR auto-approve settings updated: enabled={_edr_auto_approve['enabled']}")
    return _edr_auto_approve
