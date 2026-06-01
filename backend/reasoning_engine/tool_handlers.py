# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tool Handlers - Bridge Reasoning Engine to Real Integrations

This module registers tool handlers that connect the ToolBroker to
actual integration implementations (VirusTotal, AbuseIPDB, etc.)

The handlers are called when the reasoning engine requests a tool
and the ToolBroker approves the request based on authority level.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from .tool_broker import ToolBroker, ToolDefinition, AuthorityLevel, get_tool_broker

logger = logging.getLogger(__name__)


async def _handler_lookup_ip_reputation(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Look up IP reputation using configured threat intel integrations."""
    ip = parameters.get("ip")
    if not ip:
        return {"error": "IP address is required"}

    results = []

    # Try AbuseIPDB
    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        abuseipdb = registry.get("abuseipdb")

        if abuseipdb and abuseipdb.enabled:
            engine = ExecutionEngine()
            result = await engine.execute(
                integration_id="abuseipdb",
                action_id="check_ip",
                parameters={"ipAddress": ip}
            )
            if result.get("success"):
                results.append({
                    "source": "AbuseIPDB",
                    "data": result.get("data", {})
                })
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed: {e}")

    # Try VirusTotal
    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        vt = registry.get("virustotal")

        if vt and vt.enabled:
            engine = ExecutionEngine()
            result = await engine.execute(
                integration_id="virustotal",
                action_id="lookup_ip",
                parameters={"ip": ip}
            )
            if result.get("success"):
                results.append({
                    "source": "VirusTotal",
                    "data": result.get("data", {})
                })
    except Exception as e:
        logger.warning(f"VirusTotal IP lookup failed: {e}")

    # Aggregate results
    if not results:
        return {"error": "No threat intel sources available or all lookups failed", "ip": ip}

    return {
        "ip": ip,
        "results": results,
        "sources_queried": len(results),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def _handler_lookup_domain_whois(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Look up domain WHOIS information."""
    domain = parameters.get("domain")
    if not domain:
        return {"error": "Domain is required"}

    results = []

    # Try Shodan DNS lookup
    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        shodan = registry.get("shodan")

        if shodan and shodan.enabled:
            engine = ExecutionEngine()
            result = await engine.execute(
                integration_id="shodan",
                action_id="search_domain",
                parameters={"domain": domain}
            )
            if result.get("success"):
                results.append({
                    "source": "Shodan",
                    "data": result.get("data", {})
                })
    except Exception as e:
        logger.warning(f"Shodan domain lookup failed: {e}")

    # Try VirusTotal domain lookup
    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        vt = registry.get("virustotal")

        if vt and vt.enabled:
            engine = ExecutionEngine()
            result = await engine.execute(
                integration_id="virustotal",
                action_id="lookup_domain",
                parameters={"domain": domain}
            )
            if result.get("success"):
                results.append({
                    "source": "VirusTotal",
                    "data": result.get("data", {})
                })
    except Exception as e:
        logger.warning(f"VirusTotal domain lookup failed: {e}")

    if not results:
        return {"error": "No domain lookup sources available", "domain": domain}

    return {
        "domain": domain,
        "results": results,
        "sources_queried": len(results),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def _handler_lookup_file_hash(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Look up file hash reputation."""
    hash_value = parameters.get("hash") or parameters.get("file_hash")
    if not hash_value:
        return {"error": "File hash is required"}

    results = []

    # Try VirusTotal
    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        vt = registry.get("virustotal")

        if vt and vt.enabled:
            engine = ExecutionEngine()
            result = await engine.execute(
                integration_id="virustotal",
                action_id="lookup_hash",
                parameters={"hash": hash_value}
            )
            if result.get("success"):
                results.append({
                    "source": "VirusTotal",
                    "data": result.get("data", {})
                })
    except Exception as e:
        logger.warning(f"VirusTotal hash lookup failed: {e}")

    if not results:
        return {"error": "No hash lookup sources available", "hash": hash_value}

    return {
        "hash": hash_value,
        "results": results,
        "sources_queried": len(results),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def _handler_query_threat_intel(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Query threat intelligence feeds for an IOC."""
    ioc = parameters.get("ioc") or parameters.get("indicator")
    ioc_type = parameters.get("type", "auto")

    if not ioc:
        return {"error": "IOC is required"}

    # Use the threat intel service
    try:
        from services.threat_intel_service import ThreatIntelService
        ti_service = ThreatIntelService()

        result = await ti_service.enrich_ioc(ioc, ioc_type)
        return {
            "ioc": ioc,
            "type": ioc_type,
            "enrichment": result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Threat intel query failed: {e}")
        return {"error": str(e), "ioc": ioc}


async def _handler_enrich_ioc(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Enrich an IOC using all available sources."""
    return await _handler_query_threat_intel(parameters, investigation_context)


async def _handler_search_virustotal(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Search VirusTotal for an indicator."""
    indicator = parameters.get("indicator") or parameters.get("query")
    indicator_type = parameters.get("type", "auto")

    if not indicator:
        return {"error": "Indicator is required"}

    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        vt = registry.get("virustotal")

        if not vt or not vt.enabled:
            return {"error": "VirusTotal integration not configured or disabled"}

        engine = ExecutionEngine()

        # Determine action based on indicator type
        if indicator_type in ["ip", "ipv4", "ipv6"]:
            action_id = "lookup_ip"
            params = {"ip": indicator}
        elif indicator_type in ["domain", "hostname"]:
            action_id = "lookup_domain"
            params = {"domain": indicator}
        elif indicator_type in ["hash", "md5", "sha1", "sha256"]:
            action_id = "lookup_hash"
            params = {"hash": indicator}
        elif indicator_type in ["url"]:
            action_id = "lookup_url"
            params = {"url": indicator}
        else:
            # Auto-detect
            if "." in indicator and all(c.isdigit() or c == "." for c in indicator):
                action_id = "lookup_ip"
                params = {"ip": indicator}
            elif len(indicator) in [32, 40, 64] and all(c in "0123456789abcdef" for c in indicator.lower()):
                action_id = "lookup_hash"
                params = {"hash": indicator}
            elif "." in indicator:
                action_id = "lookup_domain"
                params = {"domain": indicator}
            else:
                return {"error": f"Cannot determine indicator type for: {indicator}"}

        result = await engine.execute(
            integration_id="virustotal",
            action_id=action_id,
            parameters=params
        )

        return result

    except Exception as e:
        logger.error(f"VirusTotal search failed: {e}")
        return {"error": str(e)}


async def _handler_search_abuseipdb(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Search AbuseIPDB for an IP address."""
    ip = parameters.get("ip")
    if not ip:
        return {"error": "IP address is required"}

    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        abuseipdb = registry.get("abuseipdb")

        if not abuseipdb or not abuseipdb.enabled:
            return {"error": "AbuseIPDB integration not configured or disabled"}

        engine = ExecutionEngine()
        result = await engine.execute(
            integration_id="abuseipdb",
            action_id="check_ip",
            parameters={"ipAddress": ip}
        )

        return result

    except Exception as e:
        logger.error(f"AbuseIPDB search failed: {e}")
        return {"error": str(e)}


async def _handler_search_shodan(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Search Shodan for an IP or domain."""
    ip = parameters.get("ip")
    domain = parameters.get("domain")

    if not ip and not domain:
        return {"error": "IP or domain is required"}

    try:
        from integrations.registry.integration_registry import get_registry
        from integrations.engines.execution_engine import ExecutionEngine

        registry = get_registry()
        shodan = registry.get("shodan")

        if not shodan or not shodan.enabled:
            return {"error": "Shodan integration not configured or disabled"}

        engine = ExecutionEngine()

        if ip:
            result = await engine.execute(
                integration_id="shodan",
                action_id="lookup_ip",
                parameters={"ip": ip}
            )
        else:
            result = await engine.execute(
                integration_id="shodan",
                action_id="search_domain",
                parameters={"domain": domain}
            )

        return result

    except Exception as e:
        logger.error(f"Shodan search failed: {e}")
        return {"error": str(e)}


async def _handler_get_alert_details(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Get detailed information about an alert."""
    alert_id = parameters.get("alert_id") or investigation_context.get("alert_id")
    if not alert_id:
        return {"error": "Alert ID is required"}

    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1",
                alert_id
            )
            if row:
                return dict(row)
            return {"error": f"Alert not found: {alert_id}"}

    except Exception as e:
        logger.error(f"Get alert details failed: {e}")
        return {"error": str(e)}


async def _handler_search_logs(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Search security logs using simple query syntax.

    Query Syntax Examples:
    - Simple text: "failed login"
    - Field search: host:wotlkserver, user:root, process:sshd
    - Wildcards: host:web-*, process:*python*
    - Boolean: failed AND login, ssh OR rdp, NOT success
    - Time range: last:1h, last:24h, last:7d (auto-added if not specified)
    - Combined: host:prod-* AND process:python AND NOT user:root last:24h

    Returns top matching events with summary statistics.
    """
    from services.log_search import get_log_search_service

    query = parameters.get("query", "")
    time_range = parameters.get("time_range", "24h")
    limit = min(parameters.get("limit", 50), 200)  # Cap at 200

    try:
        search_service = get_log_search_service()
        result = await search_service.search(
            query=query,
            time_range=time_range,
            limit=limit
        )

        # Summarize events for LLM consumption
        events_summary = []
        for event in result.events[:20]:  # Summarize top 20
            summary = {
                "time": event.get("@timestamp", "")[:19],  # Truncate timestamp
                "host": event.get("host", {}).get("name", "-"),
                "source": event.get("source_type", "-"),
            }

            # Add process info if available
            if event.get("process"):
                summary["process"] = event["process"].get("name", "-")
                if event["process"].get("cmdline"):
                    summary["cmdline"] = event["process"]["cmdline"][:100]

            # Add user info if available
            if event.get("user", {}).get("name"):
                summary["user"] = event["user"]["name"]

            # Add action
            if event.get("event", {}).get("action"):
                summary["action"] = event["event"]["action"]

            events_summary.append(summary)

        return {
            "total": result.total,
            "query": query,
            "time_range": time_range,
            "returned": len(result.events),
            "query_time_ms": result.query_time_ms,
            "events": events_summary,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Log search failed: {e}")
        return {
            "error": str(e),
            "query": query,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def _handler_get_log_stats(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Get aggregated statistics from security logs.

    Use for:
    - Understanding log volume and distribution
    - Building dashboards and reports
    - Identifying top hosts, users, sources
    - Timeline analysis

    Returns breakdowns by source type, host, action, user, and timeline.
    """
    from services.log_search import get_log_search_service

    query = parameters.get("query", "")
    time_range = parameters.get("time_range", "24h")

    try:
        search_service = get_log_search_service()
        stats = await search_service.get_stats(query=query, time_range=time_range)

        return {
            "total_events": stats.get("total_events", 0),
            "time_range": time_range,
            "query": query,
            "by_source": stats.get("by_source", [])[:10],
            "by_host": stats.get("by_host", [])[:10],
            "by_action": stats.get("by_action", [])[:10],
            "by_user": stats.get("by_user", [])[:10],
            "timeline": stats.get("timeline", [])[-24:],  # Last 24 data points
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Log stats failed: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def _handler_generate_log_report(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a formatted report from log data.

    Report types:
    - executive: High-level summary for management
    - technical: Detailed technical findings
    - compliance: Formatted for compliance requirements
    - incident: Incident-focused timeline and IOCs

    Returns structured report data that can be rendered to various formats.
    """
    from services.log_search import get_log_search_service

    query = parameters.get("query", "")
    time_range = parameters.get("time_range", "24h")
    report_type = parameters.get("report_type", "technical")
    title = parameters.get("title", "Security Log Report")

    try:
        search_service = get_log_search_service()

        # Get stats for the report
        stats = await search_service.get_stats(query=query, time_range=time_range)

        # Get sample events
        result = await search_service.search(query=query, time_range=time_range, limit=100)

        # Build report structure
        report = {
            "title": title,
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": time_range,
            "query": query,
            "summary": {
                "total_events": stats.get("total_events", 0),
                "unique_hosts": len(stats.get("by_host", [])),
                "unique_users": len(stats.get("by_user", [])),
                "source_types": len(stats.get("by_source", [])),
            },
            "top_sources": stats.get("by_source", [])[:5],
            "top_hosts": stats.get("by_host", [])[:5],
            "top_users": stats.get("by_user", [])[:5],
            "top_actions": stats.get("by_action", [])[:5],
            "timeline_summary": {
                "data_points": len(stats.get("timeline", [])),
                "peak_hour": max(stats.get("timeline", [{"count": 0}]), key=lambda x: x.get("count", 0)) if stats.get("timeline") else None
            }
        }

        # Add type-specific content
        if report_type == "executive":
            report["findings"] = [
                f"Analyzed {stats.get('total_events', 0):,} events over {time_range}",
                f"Activity from {len(stats.get('by_host', []))} unique hosts",
                f"Top source: {stats.get('by_source', [{}])[0].get('source', 'N/A')} ({stats.get('by_source', [{}])[0].get('count', 0):,} events)" if stats.get('by_source') else "No source data"
            ]
        elif report_type == "incident":
            # Extract potential IOCs from events
            ips = set()
            users = set()
            processes = set()
            for event in result.events[:50]:
                if event.get("source", {}).get("ip"):
                    ips.add(event["source"]["ip"])
                if event.get("destination", {}).get("ip"):
                    ips.add(event["destination"]["ip"])
                if event.get("user", {}).get("name"):
                    users.add(event["user"]["name"])
                if event.get("process", {}).get("name"):
                    processes.add(event["process"]["name"])

            report["iocs"] = {
                "ips": list(ips)[:20],
                "users": list(users)[:10],
                "processes": list(processes)[:10]
            }

        return report

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def _handler_recommend_containment(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate containment recommendations based on investigation."""
    action = parameters.get("action")
    target = parameters.get("target")
    reason = parameters.get("reason")

    return {
        "recommendation": {
            "action": action,
            "target": target,
            "reason": reason,
            "status": "pending_approval",
            "requires_approval": True
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def _handler_create_ticket(
    parameters: Dict[str, Any],
    investigation_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Create a ticket in the configured ticketing system."""
    title = parameters.get("title")
    description = parameters.get("description")
    priority = parameters.get("priority", "medium")

    # Would integrate with ServiceNow, Jira, etc.
    return {
        "note": "Ticketing integration not yet implemented",
        "title": title,
        "priority": priority,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def register_tool_handlers(broker: Optional[ToolBroker] = None) -> None:
    """
    Register all tool handlers with the ToolBroker.

    Call this at startup to wire the reasoning engine to real integrations.
    """
    if broker is None:
        broker = get_tool_broker()

    # OBSERVE level tools
    broker.register_tool(ToolDefinition(
        id="get_alert_details",
        name="Get Alert Details",
        description="Get detailed information about an alert",
        required_authority=AuthorityLevel.OBSERVE,
        handler=_handler_get_alert_details
    ))

    broker.register_tool(ToolDefinition(
        id="search_logs",
        name="Search Logs",
        description="Search security logs. Syntax: 'host:name', 'user:root', 'process:sshd', wildcards (*), AND/OR/NOT, 'last:24h'",
        required_authority=AuthorityLevel.OBSERVE,
        handler=_handler_search_logs
    ))

    broker.register_tool(ToolDefinition(
        id="get_log_stats",
        name="Get Log Statistics",
        description="Get aggregated log statistics: event counts by host, user, source, action, and timeline",
        required_authority=AuthorityLevel.OBSERVE,
        handler=_handler_get_log_stats
    ))

    broker.register_tool(ToolDefinition(
        id="generate_log_report",
        name="Generate Log Report",
        description="Generate formatted report from logs. Types: executive, technical, compliance, incident",
        required_authority=AuthorityLevel.OBSERVE,
        handler=_handler_generate_log_report
    ))

    # INVESTIGATE level tools
    broker.register_tool(ToolDefinition(
        id="lookup_ip_reputation",
        name="Lookup IP Reputation",
        description="Look up IP reputation using threat intel integrations",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_lookup_ip_reputation
    ))

    broker.register_tool(ToolDefinition(
        id="lookup_domain_whois",
        name="Lookup Domain WHOIS",
        description="Look up domain WHOIS and DNS information",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_lookup_domain_whois
    ))

    broker.register_tool(ToolDefinition(
        id="lookup_file_hash",
        name="Lookup File Hash",
        description="Look up file hash reputation",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_lookup_file_hash
    ))

    broker.register_tool(ToolDefinition(
        id="query_threat_intel",
        name="Query Threat Intel",
        description="Query threat intelligence for an IOC",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_query_threat_intel
    ))

    broker.register_tool(ToolDefinition(
        id="enrich_ioc",
        name="Enrich IOC",
        description="Enrich an IOC using all available sources",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_enrich_ioc
    ))

    broker.register_tool(ToolDefinition(
        id="search_virustotal",
        name="Search VirusTotal",
        description="Search VirusTotal for an indicator",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_search_virustotal
    ))

    broker.register_tool(ToolDefinition(
        id="search_abuseipdb",
        name="Search AbuseIPDB",
        description="Search AbuseIPDB for an IP address",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_search_abuseipdb
    ))

    broker.register_tool(ToolDefinition(
        id="search_shodan",
        name="Search Shodan",
        description="Search Shodan for an IP or domain",
        required_authority=AuthorityLevel.INVESTIGATE,
        handler=_handler_search_shodan
    ))

    # RESPOND level tools
    broker.register_tool(ToolDefinition(
        id="recommend_containment",
        name="Recommend Containment",
        description="Generate containment recommendations",
        required_authority=AuthorityLevel.RESPOND,
        min_confidence=70,
        handler=_handler_recommend_containment
    ))

    broker.register_tool(ToolDefinition(
        id="create_ticket",
        name="Create Ticket",
        description="Create a ticket in the ticketing system",
        required_authority=AuthorityLevel.RESPOND,
        handler=_handler_create_ticket
    ))

    logger.info("[TOOL_HANDLERS] Registered 12 tool handlers with ToolBroker")


def initialize_tool_handlers() -> None:
    """Initialize and register all tool handlers."""
    register_tool_handlers()
