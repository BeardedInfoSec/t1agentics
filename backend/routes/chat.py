# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Chat Routes - Phase 6
REST API endpoints for investigation chat.

Note: Real-time chat is primarily via WebSocket.
These REST endpoints are for:
- Initial history load
- Fallback for WebSocket issues
- Admin/audit operations

Analytics endpoints require admin role.
"""

from fastapi import APIRouter, HTTPException, Header, Query, Depends, Request
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime
import logging
import uuid

from services.chat_service import get_chat_service
from dependencies.auth import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["chat"], dependencies=[Depends(get_current_user)])


# ==================== TENANT VERIFICATION ====================

async def verify_investigation_tenant(investigation_id: str, tenant_id: str):
    """Verify investigation belongs to the given tenant."""
    try:
        uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid investigation ID format")

    from services.postgres_db import postgres_db
    result = await postgres_db.fetchval(
        "SELECT tenant_id FROM investigations WHERE investigation_id = $1", investigation_id
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if str(result) != str(tenant_id):
        raise HTTPException(status_code=403, detail="Access denied")


# ==================== MODELS ====================

class SendMessageRequest(BaseModel):
    message: str
    message_type: str = 'text'
    metadata: Optional[Dict[str, Any]] = None
    parent_message_id: Optional[str] = None


class MessageResponse(BaseModel):
    id: str
    investigation_id: str
    sender_type: str
    sender_id: str
    sender_name: str
    message: str
    message_type: str
    metadata: Dict[str, Any]
    parent_message_id: Optional[str]
    read_by: List[str]
    is_streaming: bool
    created_at: str


# ==================== MESSAGES ====================

@router.get("/investigations/{investigation_id}/messages")
async def get_messages(
    request: Request,
    investigation_id: str,
    limit: int = Query(default=50, le=200),
    before_id: Optional[str] = None,
    after_id: Optional[str] = None,
    message_type: Optional[str] = None,
    authorization: str = Header(None)
):
    """
    Get chat messages for an investigation.

    Supports pagination via before_id/after_id.
    """
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])

    chat_service = get_chat_service()

    messages = await chat_service.get_messages(
        investigation_id=investigation_id,
        limit=limit,
        before_id=before_id,
        after_id=after_id,
        message_type=message_type
    )

    return {
        "messages": messages,
        "count": len(messages),
        "has_more": len(messages) == limit
    }


@router.post("/investigations/{investigation_id}/messages")
async def send_message(
    request: Request,
    investigation_id: str,
    body: SendMessageRequest,
    authorization: str = Header(None)
):
    """
    Send a chat message.

    For human users - agents should use the chat service directly.
    """
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])
    username = current_user["username"]

    chat_service = get_chat_service()

    result = await chat_service.send_message(
        investigation_id=investigation_id,
        sender_type='human',
        sender_id=username,
        sender_name=username,
        message=body.message,
        message_type=body.message_type,
        metadata=body.metadata,
        parent_message_id=body.parent_message_id
    )

    if not result['success']:
        raise HTTPException(status_code=400, detail=result.get('error', 'Failed to send message'))

    return result['message']


@router.get("/investigations/{investigation_id}/messages/{message_id}")
async def get_message(
    request: Request,
    investigation_id: str,
    message_id: str,
    authorization: str = Header(None)
):
    """Get a specific message by ID."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])

    chat_service = get_chat_service()

    message = await chat_service.get_message_by_id(message_id)

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if message['investigation_id'] != investigation_id:
        raise HTTPException(status_code=404, detail="Message not in this investigation")

    return message


# Note: Message deletion is disabled for audit compliance
# All chat messages are retained for investigation audit trail


# ==================== READ TRACKING ====================

@router.post("/investigations/{investigation_id}/messages/read")
async def mark_messages_read(
    request: Request,
    investigation_id: str,
    message_id: Optional[str] = None,
    authorization: str = Header(None)
):
    """Mark messages as read up to a specific message ID."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])
    username = current_user["username"]

    chat_service = get_chat_service()

    count = await chat_service.mark_messages_read(
        investigation_id=investigation_id,
        user_id=username,
        up_to_message_id=message_id
    )

    return {"success": True, "messages_marked": count}


@router.get("/investigations/{investigation_id}/unread")
async def get_unread_count(
    request: Request,
    investigation_id: str,
    authorization: str = Header(None)
):
    """Get unread message count for the current user."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])
    username = current_user["username"]

    chat_service = get_chat_service()

    count = await chat_service.get_unread_count(
        investigation_id=investigation_id,
        user_id=username
    )

    return {"unread_count": count}


# ==================== TYPING INDICATORS ====================

@router.post("/investigations/{investigation_id}/typing")
async def set_typing(
    request: Request,
    investigation_id: str,
    is_typing: bool = True,
    authorization: str = Header(None)
):
    """Set typing indicator (for REST fallback)."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])
    username = current_user["username"]

    chat_service = get_chat_service()

    if is_typing:
        await chat_service.set_typing(
            investigation_id=investigation_id,
            user_id=username,
            user_name=username,
            is_agent=False
        )
    else:
        await chat_service.clear_typing(
            investigation_id=investigation_id,
            user_id=username
        )

    return {"success": True}


@router.get("/investigations/{investigation_id}/typing")
async def get_typing_users(
    request: Request,
    investigation_id: str,
    authorization: str = Header(None)
):
    """Get users currently typing."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])

    chat_service = get_chat_service()

    users = await chat_service.get_typing_users(investigation_id)

    return {"typing_users": users}


# ==================== STATS ====================

@router.get("/investigations/{investigation_id}/stats")
async def get_chat_stats(
    request: Request,
    investigation_id: str,
    authorization: str = Header(None)
):
    """Get chat statistics for an investigation."""
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])

    chat_service = get_chat_service()

    stats = await chat_service.get_chat_stats(investigation_id)

    return stats


# ==================== ANALYTICS & AUDIT (Admin) ====================

@router.get("/analytics/summary")
async def get_analytics_summary(
    days: int = Query(default=30, le=365),
    current_user: dict = Depends(require_admin)
):
    """Get overall chat activity summary. ADMIN ONLY."""

    try:
        from services.chat_analytics_service import get_chat_analytics_service
        analytics_service = get_chat_analytics_service()
        return await analytics_service.get_chat_activity_summary(days=days)
    except Exception as e:
        logger.error(f"Error fetching analytics summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analytics/users")
async def get_user_analytics(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
    sort_by: str = Query(default='total_messages'),
    order: str = Query(default='DESC'),
    current_user: dict = Depends(require_admin)
):
    """Get chat usage statistics for all users. ADMIN ONLY."""

    try:
        from services.chat_analytics_service import get_chat_analytics_service
        analytics_service = get_chat_analytics_service()
        users = await analytics_service.get_all_user_statistics(
            limit=limit, offset=offset, sort_by=sort_by, order=order
        )
        return {"users": users, "count": len(users)}
    except Exception as e:
        logger.error(f"Error fetching user analytics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analytics/users/{user_id}")
async def get_user_statistics(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get chat statistics for a specific user. Users can view their own stats, admins can view anyone."""
    # Users can view their own stats, admins can view anyone
    username = current_user.get("username")
    role = current_user.get("role")
    if user_id != username and role != "admin":
        raise HTTPException(status_code=403, detail="Can only view your own statistics")

    try:
        from services.chat_analytics_service import get_chat_analytics_service
        analytics_service = get_chat_analytics_service()
        return await analytics_service.get_user_statistics(user_id)
    except Exception as e:
        logger.error(f"Error fetching user statistics for {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analytics/users/{user_id}/conversations")
async def get_user_conversations(
    user_id: str,
    investigation_id: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0),
    current_user: dict = Depends(require_admin)
):
    """Get a user's conversation history. ADMIN ONLY."""

    try:
        from services.chat_analytics_service import get_chat_analytics_service
        analytics_service = get_chat_analytics_service()
        conversations = await analytics_service.get_user_conversation_history(
            user_id=user_id,
            investigation_id=investigation_id,
            limit=limit,
            offset=offset
        )
        return {"conversations": conversations, "count": len(conversations)}
    except Exception as e:
        logger.error(f"Error fetching conversations for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analytics/users/{user_id}/actions")
async def get_user_action_history(
    user_id: str,
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
    current_user: dict = Depends(require_admin)
):
    """Get a user's action request history from chat. ADMIN ONLY."""

    try:
        from services.chat_analytics_service import get_chat_analytics_service
        analytics_service = get_chat_analytics_service()
        actions = await analytics_service.get_user_action_history(
            user_id=user_id,
            status=status,
            limit=limit,
            offset=offset
        )
        return {"actions": actions, "count": len(actions)}
    except Exception as e:
        logger.error(f"Error fetching action history for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ==================== INVESTIGATION AUDIT TRAIL ====================

@router.get("/investigations/{investigation_id}/audit")
async def get_investigation_audit_trail(
    request: Request,
    investigation_id: str,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0),
    category: Optional[str] = Query(
        default=None,
        description="Filter by category: status, disposition, priority, assignment, note, ai, system"
    ),
    authorization: str = Header(None)
):
    """
    Get the immutable audit trail for an investigation.

    This returns all actions taken on the investigation in reverse chronological order.
    The audit log is append-only and cannot be modified or deleted.

    Categories:
    - status: State changes (created, closed, reopened)
    - disposition: Verdict changes (benign, malicious, etc.)
    - priority: Priority changes (P1-P4)
    - assignment: Ownership changes
    - note: Notes and findings added
    - ai: AI agent actions
    - system: Automated system actions
    """
    current_user = await get_current_user(request, authorization)
    await verify_investigation_tenant(investigation_id, current_user["tenant_id"])

    try:
        from services.investigation_audit_service import get_audit_service
        audit_service = get_audit_service()

        entries = await audit_service.get_audit_trail(
            investigation_id=investigation_id,
            limit=limit,
            offset=offset,
            category=category
        )

        return {
            "investigation_id": investigation_id,
            "audit_trail": entries,
            "count": len(entries),
            "has_more": len(entries) == limit,
            "immutable": True,
            "description": "This audit log cannot be modified or deleted"
        }

    except Exception as e:
        logger.error(f"Error fetching audit trail: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ==================== SEARCH ASSIST (Riggs AI) ====================

# Create a secondary router for /api/chat (without v1) for frontend compatibility
search_assist_router = APIRouter(prefix="/api/chat", tags=["Search Assist"], dependencies=[Depends(get_current_user)])


class SearchAssistRequest(BaseModel):
    """Request for AI search assistance"""
    message: str
    context: Optional[Dict[str, Any]] = None


class SearchAssistResponse(BaseModel):
    """Response with suggested search query"""
    suggestedQuery: str
    explanation: str
    syntax_help: Optional[Dict[str, Any]] = None


# Search syntax documentation for Riggs
SEARCH_SYNTAX_DOCS = """
## T1 Agentics Log Search Syntax

The search engine uses a Splunk/Elastic-inspired syntax that's powerful yet simple.

### Basic Text Search
Just type any text to search across all fields:
- `failed login` - Finds events containing "failed" and "login"
- `ssh connection` - Finds SSH connection events

### Field-Specific Search
Use `field:value` syntax to search specific fields:
- `host:wotlkserver` - Events from host "wotlkserver"
- `user:root` - Events involving user "root"
- `process:sshd` - Events with process "sshd"
- `source:windows_security` - Windows Security events

### Field Shortcuts
Common fields have shortcuts:
| Shortcut | Full Field |
|----------|------------|
| host | host.name |
| user | user.name |
| process | process.name |
| pid | process.pid |
| cmd | process.cmdline |
| action | event.action |
| source | source_type |
| ip | host.ip |
| src_ip | source.ip |
| dst_ip | destination.ip |

### Wildcards
Use `*` for pattern matching:
- `host:web-*` - All hosts starting with "web-"
- `process:*python*` - Processes containing "python"
- `user:admin*` - Users starting with "admin"

### Boolean Operators
Combine searches with AND, OR, NOT:
- `failed AND login` - Both terms must match
- `ssh OR rdp` - Either term matches
- `NOT success` - Exclude matching events
- `host:prod-* AND NOT user:root` - Complex combinations

### Time Ranges
Filter by time using `last:`:
- `last:1h` - Last hour
- `last:24h` - Last 24 hours
- `last:7d` - Last 7 days
- `last:30d` - Last 30 days

### Examples
| Natural Language | Query |
|------------------|-------|
| Failed logins in the last hour | `event.outcome:failure "logon" last:1h` |
| PowerShell activity | `process.name:powershell.exe OR process.name:pwsh.exe` |
| SSH from external IPs | `process:sshd AND -source.ip:192.168.* AND -source.ip:10.*` |
| Admin account usage | `user.name:admin* OR user.name:*administrator*` |
| Process spawned by Office | `process.parent.name:winword.exe OR process.parent.name:excel.exe` |
| Events on domain controllers | `host.name:dc* OR host.name:*-dc*` |
| High severity events | `severity:critical OR severity:high` |

### ECS Field Reference
Events are normalized to Elastic Common Schema (ECS):
- `@timestamp` - Event time
- `event.category` - Category (authentication, process, file, network)
- `event.action` - Specific action
- `event.outcome` - Result (success, failure)
- `host.name` - Hostname
- `host.ip` - IP address
- `user.name` - Username
- `process.name` - Process name
- `process.pid` - Process ID
- `process.cmdline` - Command line
- `process.parent.name` - Parent process
- `file.path` - File path
- `source.ip` / `destination.ip` - Network endpoints
"""

# Pattern matching for natural language to query conversion
SEARCH_PATTERNS = [
    # Authentication
    {"keywords": ["failed login", "failed logon", "failed authentication", "login failure"],
     "query": 'event.outcome:failure "logon"',
     "explanation": "Searching for failed authentication events"},
    {"keywords": ["successful login", "successful logon", "successful authentication"],
     "query": 'event.outcome:success "logon"',
     "explanation": "Searching for successful authentication events"},
    {"keywords": ["brute force", "password spray", "credential stuffing"],
     "query": 'event.outcome:failure "logon" | stats count by source.ip | where count > 10',
     "explanation": "Looking for potential brute force attacks (multiple failed logins)"},

    # PowerShell
    {"keywords": ["powershell", "pwsh"],
     "query": 'process.name:powershell.exe OR process.name:pwsh.exe',
     "explanation": "Searching for PowerShell process activity"},
    {"keywords": ["encoded command", "encoded powershell", "base64 powershell"],
     "query": 'process.cmdline:*-enc* OR process.cmdline:*-encoded* OR process.cmdline:*-e *',
     "explanation": "Searching for encoded PowerShell commands (potential obfuscation)"},
    {"keywords": ["powershell download", "invoke-webrequest", "webclient"],
     "query": '(process.name:powershell.exe OR process.name:pwsh.exe) AND (process.cmdline:*invoke-webrequest* OR process.cmdline:*webclient* OR process.cmdline:*downloadstring*)',
     "explanation": "Searching for PowerShell download activity"},

    # Processes
    {"keywords": ["cmd.exe", "command prompt"],
     "query": 'process.name:cmd.exe',
     "explanation": "Searching for Command Prompt activity"},
    {"keywords": ["suspicious process", "unusual process"],
     "query": 'process.parent.name:winword.exe OR process.parent.name:excel.exe OR process.parent.name:outlook.exe',
     "explanation": "Searching for potentially suspicious child processes from Office apps"},
    {"keywords": ["office spawn", "office child", "macro"],
     "query": 'process.parent.name:winword.exe OR process.parent.name:excel.exe OR process.parent.name:outlook.exe OR process.parent.name:powerpnt.exe',
     "explanation": "Searching for processes spawned by Microsoft Office applications"},
    {"keywords": ["lolbin", "living off the land"],
     "query": 'process.name:certutil.exe OR process.name:mshta.exe OR process.name:regsvr32.exe OR process.name:rundll32.exe OR process.name:wmic.exe',
     "explanation": "Searching for commonly abused Windows binaries (LOLBins)"},

    # Network
    {"keywords": ["external ip", "external connection", "external traffic"],
     "query": '-source.ip:10.* -source.ip:192.168.* -source.ip:172.16.* -source.ip:172.17.* -source.ip:172.18.* -source.ip:172.19.* -source.ip:172.2* -source.ip:172.30.* -source.ip:172.31.*',
     "explanation": "Searching for connections from external (non-RFC1918) IP addresses"},
    {"keywords": ["dns", "dns query", "domain lookup"],
     "query": 'source_type:dns OR event.category:dns',
     "explanation": "Searching for DNS activity"},
    {"keywords": ["lateral movement", "internal traffic"],
     "query": 'source.ip:10.* OR source.ip:192.168.* destination.ip:10.* OR destination.ip:192.168.*',
     "explanation": "Searching for internal-to-internal network connections"},

    # Users
    {"keywords": ["admin user", "admin account", "administrator"],
     "query": 'user.name:admin* OR user.name:*administrator*',
     "explanation": "Searching for administrator account activity"},
    {"keywords": ["service account", "svc account"],
     "query": 'user.name:svc* OR user.name:*service*',
     "explanation": "Searching for service account activity"},
    {"keywords": ["new user", "user created", "account created"],
     "query": 'event.action:*created* user.name:*',
     "explanation": "Searching for user account creation events"},
    {"keywords": ["privilege escalation", "privesc", "sudo"],
     "query": 'event.action:*privilege* OR event.action:*escalat* OR process.name:sudo',
     "explanation": "Searching for privilege escalation activity"},

    # Files
    {"keywords": ["file deleted", "file deletion", "file removed"],
     "query": 'event.action:*delete* file.path:*',
     "explanation": "Searching for file deletion events"},
    {"keywords": ["executable", ".exe file"],
     "query": 'file.name:*.exe OR process.executable:*',
     "explanation": "Searching for executable file activity"},
    {"keywords": ["script", "vbs", "js file", "bat file"],
     "query": 'file.name:*.vbs OR file.name:*.js OR file.name:*.bat OR file.name:*.ps1',
     "explanation": "Searching for script file activity"},

    # Sources
    {"keywords": ["windows security", "security log"],
     "query": 'source_type:windows_security',
     "explanation": "Searching Windows Security event logs"},
    {"keywords": ["sysmon"],
     "query": 'source_type:sysmon OR source_type:windows_sysmon',
     "explanation": "Searching Sysmon logs"},
    {"keywords": ["linux", "syslog"],
     "query": 'source_type:linux_syslog OR source_type:linux_auditd',
     "explanation": "Searching Linux logs"},
    {"keywords": ["registry", "reg key"],
     "query": 'registry.path:* OR event.category:registry',
     "explanation": "Searching for Windows registry activity"},

    # Severity
    {"keywords": ["critical", "high severity", "urgent"],
     "query": 'severity:critical OR severity:high',
     "explanation": "Searching for critical and high severity events"},

    # Time-based
    {"keywords": ["last hour", "past hour"],
     "query_suffix": ' last:1h',
     "explanation": "Filtering to the last hour"},
    {"keywords": ["today", "last 24 hours"],
     "query_suffix": ' last:24h',
     "explanation": "Filtering to the last 24 hours"},
    {"keywords": ["this week", "last 7 days"],
     "query_suffix": ' last:7d',
     "explanation": "Filtering to the last 7 days"},

    # Hosts
    {"keywords": ["domain controller", "domain controllers"],
     "query": 'host.name:dc* OR host.name:*-dc*',
     "explanation": "Searching for events on domain controllers"},

    # System/Host Discovery
    {"keywords": ["list of systems", "list of hosts", "all systems", "all hosts", "system names", "host names", "hostnames", "what systems", "which systems", "which hosts", "hosts i have", "hosts reporting", "systems reporting", "reporting hosts", "connected hosts", "active hosts", "hosts sending", "hosts sending logs", "what hosts are", "my hosts"],
     "query": '*',
     "explanation": "Listing all hosts with events (check the 'host' column for unique system names)",
     "aggregation": "host.name"},
    {"keywords": ["unique hosts", "distinct hosts", "how many hosts", "how many systems", "number of hosts", "count hosts"],
     "query": '*',
     "explanation": "Querying for unique host names",
     "aggregation": "host.name"},

    # User Discovery
    {"keywords": ["list of users", "all users", "user names", "usernames", "what users", "which users", "who logged in", "active users"],
     "query": 'user.name:*',
     "explanation": "Listing all users with activity",
     "aggregation": "user.name"},
    {"keywords": ["unique users", "distinct users", "how many users"],
     "query": 'user.name:*',
     "explanation": "Querying for unique user names",
     "aggregation": "user.name"},

    # Process Discovery
    {"keywords": ["list of processes", "all processes", "running processes", "what processes", "which processes"],
     "query": 'process.name:*',
     "explanation": "Listing all processes with events",
     "aggregation": "process.name"},

    # Source/Event Type Discovery
    {"keywords": ["list of sources", "all sources", "source types", "event types", "data sources", "what sources"],
     "query": '*',
     "explanation": "Listing all event source types",
     "aggregation": "source_type"},

    # Network Discovery
    {"keywords": ["list of ips", "all ips", "ip addresses", "what ips", "network activity"],
     "query": 'source.ip:* OR destination.ip:*',
     "explanation": "Listing IP addresses with network activity",
     "aggregation": "source.ip"},

    # Actions/Events
    {"keywords": ["list of actions", "all actions", "event actions", "what actions", "types of events"],
     "query": '*',
     "explanation": "Listing all event action types",
     "aggregation": "event.action"},
]


def generate_search_query(user_message: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Generate a search query from natural language input.
    Uses pattern matching with AI-enhancement potential.
    """
    message_lower = user_message.lower().strip()

    # Look for pattern matches
    matched_patterns = []
    time_suffix = ""

    for pattern in SEARCH_PATTERNS:
        for keyword in pattern.get("keywords", []):
            if keyword in message_lower:
                if "query_suffix" in pattern:
                    time_suffix = pattern["query_suffix"]
                else:
                    matched_patterns.append(pattern)
                break

    # Build query from matched patterns
    if matched_patterns:
        queries = [p["query"] for p in matched_patterns]
        explanations = [p["explanation"] for p in matched_patterns]
        aggregations = [p.get("aggregation") for p in matched_patterns if p.get("aggregation")]

        # Combine with AND if multiple patterns matched
        if len(queries) > 1:
            final_query = " AND ".join(f"({q})" for q in queries)
            explanation = " and ".join(explanations)
        else:
            final_query = queries[0]
            explanation = explanations[0]

        # Add time suffix if found
        final_query += time_suffix

        result = {
            "suggestedQuery": final_query,
            "explanation": explanation
        }

        # Include aggregation hint if present
        if aggregations:
            result["aggregateBy"] = aggregations[0]

        return result

    # Extract potential field values from the message
    # Look for hostnames, usernames, IPs, etc.
    import re

    # Check for IP mentions FIRST (most specific)
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message_lower)
    if ip_match:
        ip = ip_match.group(1)
        return {
            "suggestedQuery": f'(source.ip:{ip} OR destination.ip:{ip} OR host.ip:{ip}){time_suffix}',
            "explanation": f"Searching for events involving IP address {ip}"
        }

    # Check for process mentions BEFORE hostname (more specific patterns first)
    # "activity from process python", "process python", "app notepad"
    process_match = re.search(r'(?:from\s+)?(?:process|program|app|application)\s+["\']?([a-zA-Z][a-zA-Z0-9_.-]+(?:\.exe)?)["\']?', message_lower)
    if process_match:
        process = process_match.group(1)
        if process not in ['the', 'our', 'my', 'this', 'that', 'all', 'any', 'name', 'names', 'activity', 'on', 'from']:
            if not process.endswith('.exe'):
                process = f"*{process}*"
            return {
                "suggestedQuery": f'process.name:{process}{time_suffix}',
                "explanation": f"Searching for events with process '{process}'"
            }

    # Check for "host X" or "server X" or "machine X" patterns (specific host lookup)
    # Must have actual hostname after the keyword
    host_specific_match = re.search(r'(?:host|server|machine)\s+["\']?([a-zA-Z0-9][a-zA-Z0-9_.-]+)["\']?', message_lower)
    if host_specific_match:
        hostname = host_specific_match.group(1)
        if hostname not in ['on', 'from', 'the', 'our', 'my', 'this', 'that', 'all', 'any', 'name', 'names']:
            return {
                "suggestedQuery": f'host.name:*{hostname}*{time_suffix}',
                "explanation": f"Searching for events on host containing '{hostname}'"
            }

    # Check for "on X" or "from X" patterns where X is a hostname
    # "events on wotlkserver", "activity from dc01", "logs from prod-db"
    on_from_match = re.search(r'(?:on|from)\s+["\']?([a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9])["\']?(?:\s|$)', message_lower)
    if on_from_match:
        hostname = on_from_match.group(1)
        # Exclude common words and prepositions
        if hostname not in ['the', 'our', 'my', 'this', 'that', 'all', 'any', 'host', 'server', 'machine',
                           'user', 'account', 'process', 'network', 'system', 'today', 'yesterday']:
            return {
                "suggestedQuery": f'host.name:*{hostname}*{time_suffix}',
                "explanation": f"Searching for events on host containing '{hostname}'"
            }

    # Check for username mentions
    user_match = re.search(r'(?:user|account|by user|for user)\s+["\']?([a-zA-Z][a-zA-Z0-9_.-]+)["\']?', message_lower)
    if user_match:
        username = user_match.group(1)
        if username not in ['the', 'our', 'my', 'this', 'that', 'all', 'any', 'name', 'names', 'activity']:
            return {
                "suggestedQuery": f'user.name:*{username}*{time_suffix}',
                "explanation": f"Searching for events by user '{username}'"
            }

    # Fall back to cleaned text search
    # Remove common question words
    cleaned = re.sub(r'^(show me|find|search for|look for|get|list|display|what are|where are)\s+', '', message_lower)
    cleaned = re.sub(r'\s+(from the last|in the last|over the past)\s+\d+\s*(hour|day|week|month)s?', '', cleaned)
    cleaned = re.sub(r'\s+(on|in|at|from)\s+(our|the|my)\s+(network|systems?|servers?|hosts?)', '', cleaned)
    cleaned = cleaned.strip()

    if len(cleaned) < 3:
        return {
            "suggestedQuery": None,
            "explanation": "I need more specific search terms. Try mentioning:\n- A hostname or IP address\n- A username or process name\n- A type of activity (login, file access, network connection)\n- A time range (last hour, today, this week)"
        }

    return {
        "suggestedQuery": f'{cleaned}{time_suffix}',
        "explanation": f"Searching for: {cleaned}"
    }


@search_assist_router.post("/search-assist")
async def search_assist(
    request: Request,
    body: SearchAssistRequest,
    authorization: str = Header(None)
):
    """
    AI-powered search assistance for Riggs.

    Converts natural language queries into the T1 search syntax.
    Provides explanations and syntax help.
    """
    try:
        # Generate query from natural language
        result = generate_search_query(body.message, body.context)

        # Add syntax documentation if no query was generated
        if not result.get("suggestedQuery"):
            result["syntax_help"] = {
                "examples": [
                    {"description": "Failed logins", "query": 'event.outcome:failure "logon"'},
                    {"description": "PowerShell activity", "query": "process.name:powershell.exe"},
                    {"description": "Events from a host", "query": "host.name:yourhost"},
                    {"description": "Activity by user", "query": "user.name:username"},
                ],
                "time_ranges": ["last:1h", "last:24h", "last:7d", "last:30d"],
                "operators": ["AND", "OR", "NOT"],
                "wildcards": "Use * for pattern matching"
            }

        return result

    except Exception as e:
        logger.error(f"Search assist error: {e}")
        return {
            "suggestedQuery": body.message,
            "explanation": f"Could not parse request, using as literal search: {body.message}"
        }


@search_assist_router.get("/search-syntax")
async def get_search_syntax():
    """
    Get full search syntax documentation.

    Returns comprehensive documentation for the search query language.
    """
    return {
        "documentation": SEARCH_SYNTAX_DOCS,
        "field_shortcuts": {
            "host": "host.name",
            "hostname": "host.name",
            "ip": "host.ip",
            "user": "user.name",
            "username": "user.name",
            "process": "process.name",
            "pid": "process.pid",
            "cmd": "process.cmdline",
            "cmdline": "process.cmdline",
            "action": "event.action",
            "category": "event.category",
            "outcome": "event.outcome",
            "source": "source_type",
            "src_ip": "source.ip",
            "dst_ip": "destination.ip",
        },
        "time_ranges": {
            "1m": "1 minute",
            "5m": "5 minutes",
            "15m": "15 minutes",
            "30m": "30 minutes",
            "1h": "1 hour",
            "4h": "4 hours",
            "12h": "12 hours",
            "24h": "24 hours",
            "1d": "1 day",
            "3d": "3 days",
            "7d": "7 days",
            "14d": "14 days",
            "30d": "30 days",
            "90d": "90 days",
        },
        "operators": {
            "AND": "Both terms must match",
            "OR": "Either term matches",
            "NOT": "Exclude matching events",
            "-field:value": "Exclude specific field value"
        },
        "examples": [
            {
                "description": "Failed logins from external IPs in the last hour",
                "query": 'event.outcome:failure "logon" -source.ip:10.* -source.ip:192.168.* last:1h'
            },
            {
                "description": "PowerShell with encoded commands",
                "query": 'process.name:powershell.exe AND (process.cmdline:*-enc* OR process.cmdline:*-e *)'
            },
            {
                "description": "Admin activity on domain controllers",
                "query": 'user.name:admin* AND (host.name:dc* OR host.name:*-dc*)'
            },
            {
                "description": "Process spawned from Office applications",
                "query": 'process.parent.name:winword.exe OR process.parent.name:excel.exe OR process.parent.name:outlook.exe'
            }
        ]
    }
