# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
WebSocket Chat Handler - Phase 6

Handles real-time chat connections for investigation workbench.
Features:
- Connection management per investigation
- Message broadcasting
- Typing indicators
- Connection heartbeat
- Riggs tool use (close investigations, update status, etc.)
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect
import jwt
import os

logger = logging.getLogger(__name__)


# =============================================================================
# RIGGS CHAT TOOLS - Actions Riggs can take during conversation
# =============================================================================

RIGGS_CHAT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "close_investigation",
            "description": "Close/resolve the current investigation with a final disposition. Use when the user confirms it's a false positive, benign, or when investigation is complete.",
            "parameters": {
                "type": "object",
                "properties": {
                    "disposition": {
                        "type": "string",
                        "enum": ["false_positive", "benign", "true_positive", "malicious", "inconclusive"],
                        "description": "Final disposition for the investigation"
                    },
                    "resolution_notes": {
                        "type": "string",
                        "description": "Brief notes explaining the resolution"
                    }
                },
                "required": ["disposition", "resolution_notes"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "update_disposition",
            "description": "Update the disposition/verdict of the investigation without closing it",
            "parameters": {
                "type": "object",
                "properties": {
                    "disposition": {
                        "type": "string",
                        "enum": ["benign", "suspicious", "malicious", "false_positive", "true_positive", "inconclusive"],
                        "description": "New disposition for the investigation"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for the disposition change"
                    }
                },
                "required": ["disposition"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "update_priority",
            "description": "Change the priority level of the investigation",
            "parameters": {
                "type": "object",
                "properties": {
                    "priority": {
                        "type": "string",
                        "enum": ["P1", "P2", "P3", "P4"],
                        "description": "New priority (P1=Critical, P2=High, P3=Medium, P4=Low)"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for priority change"
                    }
                },
                "required": ["priority"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "add_investigation_note",
            "description": "Add a note or finding to the investigation record",
            "parameters": {
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The note content to add"
                    },
                    "note_type": {
                        "type": "string",
                        "enum": ["finding", "action_taken", "analyst_note", "recommendation"],
                        "description": "Type of note"
                    }
                },
                "required": ["note"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "reopen_investigation",
            "description": "Reopen a closed investigation for further analysis. Use when the analyst wants to revisit a case.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Reason for reopening (optional)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_analyst_insight",
            "description": "Save a piece of knowledge or insight shared by the analyst for future reference. Use when the analyst teaches you something about how to analyze certain patterns, senders, domains, or IOC behaviors.",
            "parameters": {
                "type": "object",
                "properties": {
                    "insight_type": {
                        "type": "string",
                        "enum": ["pattern", "sender", "domain", "ioc_behavior", "false_positive_indicator", "analysis_tip"],
                        "description": "Type of insight: pattern (general), sender (about specific sender), domain (about specific domain), ioc_behavior (how to interpret IOCs), false_positive_indicator (FP patterns), analysis_tip (general guidance)"
                    },
                    "subject": {
                        "type": "string",
                        "description": "What the insight is about (e.g., 'high IOC count', 'walmart.com', 'review request emails')"
                    },
                    "insight": {
                        "type": "string",
                        "description": "The actual knowledge to remember (what the analyst taught)"
                    },
                    "is_safe": {
                        "type": "boolean",
                        "description": "If known: true means benign/safe, false means malicious. Omit if context-dependent."
                    }
                },
                "required": ["insight_type", "subject", "insight"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "override_analysis",
            "description": "Override the T1 automated analysis with Riggs' own assessment. Use when you disagree with the automated analysis and the analyst approves your recommendation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "new_disposition": {
                        "type": "string",
                        "enum": ["benign", "suspicious", "malicious", "false_positive", "true_positive", "inconclusive"],
                        "description": "Riggs' recommended disposition"
                    },
                    "new_confidence": {
                        "type": "number",
                        "description": "Riggs' confidence score (0.0 to 1.0)"
                    },
                    "override_reason": {
                        "type": "string",
                        "description": "Explanation for why the automated analysis was wrong and Riggs' assessment is better"
                    }
                },
                "required": ["new_disposition", "new_confidence", "override_reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_investigation_summary",
            "description": """Get a summary of the current investigation including alert count, entities, and key metrics.
Use this tool to answer questions like:
- "How many alerts are in this investigation?"
- "What entities are involved?"
- "What's the severity breakdown?"
- "When was the first/last alert?"

Returns alert count, user/host entities, MITRE techniques, severity breakdown, and a text summary.""",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_investigation_alerts",
            "description": """Search for specific alerts within the current investigation.
Use this to find alerts by:
- Text query (searches title, description, entities)
- Severity level (critical, high, medium, low)
- Source system
- Specific user or host
- MITRE technique
- Time range

Examples:
- "Find all high severity alerts"
- "Show alerts involving user jsmith"
- "Find alerts with T1059 technique"
- "Search for PowerShell related alerts" """,
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Text to search in alert title, description, or entities"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Filter by severity level"
                    },
                    "user": {
                        "type": "string",
                        "description": "Filter by user entity"
                    },
                    "host": {
                        "type": "string",
                        "description": "Filter by host entity"
                    },
                    "mitre": {
                        "type": "string",
                        "description": "Filter by MITRE technique ID (e.g., T1059.001)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default: 20)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_logs",
            "description": """Search security logs using query syntax. Use to find related events, investigate IOCs, or answer analyst questions about activity.

QUERY SYNTAX:
- Text search: "failed login" (searches all fields)
- Field search: host:wotlkserver, user:root, process:sshd, action:start
- Wildcards: host:web-*, process:*python*, user:admin*
- Boolean: failed AND login, ssh OR rdp, NOT success
- Combine: host:prod-* AND process:python AND NOT user:root

FIELD SHORTCUTS:
- host → host.name
- user → user.name
- process → process.name
- pid → process.pid
- cmd → process.cmdline
- action → event.action
- source → source_type
- src_ip → source.ip
- dst_ip → destination.ip

TIME RANGES: last:1h, last:24h, last:7d, last:30d

EXAMPLES:
- "show me ssh logins" → user:* AND (process:sshd OR action:*login*)
- "activity from 192.168.1.50" → src_ip:192.168.1.50 OR dst_ip:192.168.1.50
- "failed authentications" → action:*fail* OR outcome:failure
- "powershell on webserver" → host:web* AND process:powershell*""",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query using the syntax above"
                    },
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "4h", "12h", "24h", "7d", "30d"],
                        "description": "Time range to search (default: 24h)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default: 50, max: 200)"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_related_investigations",
            "description": """Find prior investigations that share an entity (user / host / IOC) with the current one.

Use this when an analyst asks questions like:
- "Has this user shown up in alerts before?"
- "Have we seen this domain in any other investigations?"
- "Is this part of a larger campaign?"
- "What other cases touched this host in the last N days?"

Returns a list of matching investigations with their disposition + severity + when they closed,
so you can spot patterns ("this user has been linked to 4 phishing cases this month, all benign")
or correlate ongoing campaigns ("3 open investigations all touch host X").""",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "enum": ["user", "host", "ip", "domain", "hash", "email"],
                        "description": "Type of entity to match on."
                    },
                    "entity_value": {
                        "type": "string",
                        "description": "The value to search for (case-insensitive)."
                    },
                    "days": {
                        "type": "integer",
                        "description": "How far back to look. Default 30, max 365."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max investigations to return. Default 10, max 50."
                    }
                },
                "required": ["entity_type", "entity_value"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_available_actions",
            "description": """List the connector actions this tenant can actually execute right now (e.g. "Block IP via CrowdStrike", "Disable user via Okta").

Use this BEFORE recommending a remediation so you ground your suggestions in what's actually wired up. Don't recommend "Block this IP via Palo Alto" if the tenant has no Palo Alto connector — instead recommend an action from this list, or note the connector gap.

Optional `ioc_type` filter narrows to actions relevant for a specific indicator type (ip / domain / hash / url / email / hostname / username).""",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "url", "email", "hostname", "username"],
                        "description": "Optional: filter to actions that operate on this IOC type."
                    }
                },
                "required": []
            }
        }
    }
]


async def execute_chat_tool(
    tool_name: str,
    tool_args: Dict,
    investigation_id: str,
    user_id: str,
    username: str,
    user_role: str = "read_only"
) -> Dict[str, any]:
    """
    Execute a chat tool and return the result.
    All actions are logged to the immutable investigation_audit_log.

    RBAC ENFORCEMENT: Tools are restricted based on user role.
    - read_only: Can only use save_analyst_insight
    - analyst: Can use all investigation tools
    - admin: Full access

    Returns:
        Dict with 'success', 'message', and optionally 'data'
    """
    from services.postgres_db import postgres_db
    from services.investigation_audit_service import get_audit_service
    from services.soc_rbac import SOCPermission, has_permission

    audit = get_audit_service()

    # =================================================================
    # RBAC ENFORCEMENT - Check user permissions BEFORE executing tool
    # =================================================================

    # Define which tools require which permissions
    TOOL_PERMISSIONS = {
        'close_investigation': SOCPermission.CLOSE_INVESTIGATION,
        'update_disposition': SOCPermission.UPDATE_DISPOSITION,
        'update_priority': SOCPermission.UPDATE_INVESTIGATION_STATE,
        'add_investigation_note': SOCPermission.ADD_NOTES,
        'reopen_investigation': SOCPermission.UPDATE_INVESTIGATION_STATE,
        'override_analysis': SOCPermission.UPDATE_DISPOSITION,
        'save_analyst_insight': SOCPermission.VIEW_INVESTIGATIONS,  # Low permission - anyone can save insights
    }

    required_permission = TOOL_PERMISSIONS.get(tool_name)

    if required_permission and not has_permission(user_role, required_permission):
        logger.warning(
            f"[RIGGS_RBAC] User {username} (role={user_role}) denied access to tool '{tool_name}' "
            f"- requires {required_permission.value}"
        )
        return {
            "success": False,
            "message": f"Permission denied. Your role ({user_role}) cannot perform this action. "
                       f"Contact an administrator if you need {required_permission.value} permission.",
            "rbac_denied": True
        }

    logger.info(f"[RIGGS_RBAC] User {username} (role={user_role}) authorized for tool '{tool_name}'")

    try:
        if tool_name == "close_investigation":
            disposition = tool_args.get('disposition', 'FALSE_POSITIVE').upper()
            notes = tool_args.get('resolution_notes', '')

            async with postgres_db.tenant_acquire() as conn:
                # Get current state for audit
                current = await conn.fetchrow(
                    "SELECT state, disposition FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                old_disposition = current['disposition'] if current else None

                # Update investigation to closed
                await conn.execute("""
                    UPDATE investigations
                    SET state = 'CLOSED',
                        disposition = $1,
                        resolution_notes = $2,
                        resolved_at = NOW(),
                        resolved_by = $3,
                        updated_at = NOW()
                    WHERE investigation_id = $4
                """, disposition, notes, user_id, investigation_id)

                # Also update the linked alert if exists
                await conn.execute("""
                    UPDATE alerts a
                    SET status = 'resolved',
                        disposition = $1,
                        resolved_at = NOW()
                    FROM investigations i
                    WHERE i.alert_id = a.id
                      AND i.investigation_id = $2
                """, disposition, investigation_id)

            # Log to immutable audit trail
            await audit.log_close(
                investigation_id=investigation_id,
                disposition=disposition,
                actor_type="human",
                actor_name=username,
                actor_id=user_id,
                resolution_notes=notes
            )

            logger.info(f"[RIGGS_TOOL] Closed investigation {investigation_id} as {disposition} by {username}")
            return {
                "success": True,
                "message": f"Investigation closed as **{disposition}**. Notes: {notes}",
                "data": {"new_state": "closed", "disposition": disposition}
            }

        elif tool_name == "update_disposition":
            disposition = tool_args.get('disposition', 'SUSPICIOUS').upper()
            reason = tool_args.get('reason', '')

            async with postgres_db.tenant_acquire() as conn:
                # Get current disposition for audit
                current = await conn.fetchrow(
                    "SELECT disposition FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                old_disposition = current['disposition'] if current else None

                await conn.execute("""
                    UPDATE investigations
                    SET disposition = $1,
                        updated_at = NOW()
                    WHERE investigation_id = $2
                """, disposition, investigation_id)

            # Log to immutable audit trail
            await audit.log_disposition_change(
                investigation_id=investigation_id,
                old_disposition=old_disposition,
                new_disposition=disposition,
                actor_type="human",
                actor_name=username,
                actor_id=user_id,
                reason=reason
            )

            logger.info(f"[RIGGS_TOOL] Updated disposition to {disposition} for {investigation_id}")
            return {
                "success": True,
                "message": f"Disposition updated to **{disposition}**" + (f". Reason: {reason}" if reason else ""),
                "data": {"disposition": disposition}
            }

        elif tool_name == "update_priority":
            priority = tool_args.get('priority', 'P3')
            reason = tool_args.get('reason', '')

            async with postgres_db.tenant_acquire() as conn:
                # Get current priority for audit
                current = await conn.fetchrow(
                    "SELECT priority FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                old_priority = current['priority'] if current else None

                await conn.execute("""
                    UPDATE investigations
                    SET priority = $1,
                        updated_at = NOW()
                    WHERE investigation_id = $2
                """, priority, investigation_id)

            # Log to immutable audit trail
            await audit.log_priority_change(
                investigation_id=investigation_id,
                old_priority=old_priority,
                new_priority=priority,
                actor_type="human",
                actor_name=username,
                actor_id=user_id,
                reason=reason
            )

            logger.info(f"[RIGGS_TOOL] Updated priority to {priority} for {investigation_id}")
            return {
                "success": True,
                "message": f"Priority updated to **{priority}**" + (f". Reason: {reason}" if reason else ""),
                "data": {"priority": priority}
            }

        elif tool_name == "add_investigation_note":
            note = tool_args.get('note', '')
            note_type_input = tool_args.get('note_type', 'analyst_note')

            if not note:
                return {"success": False, "message": "Note content is required"}

            # Map user-friendly types to DB enum values
            note_type_map = {
                'finding': 'AI_OBSERVATION',
                'action_taken': 'SYSTEM_NOTE',
                'analyst_note': 'HUMAN_NOTE',
                'recommendation': 'AI_RECOMMENDATION'
            }
            note_type = note_type_map.get(note_type_input, 'HUMAN_NOTE')

            async with postgres_db.tenant_acquire() as conn:
                await conn.execute("""
                    INSERT INTO investigation_notes (
                        investigation_id, note_type, author, author_type,
                        content, created_at
                    ) VALUES ($1, $2, $3, 'HUMAN', $4, NOW())
                """, investigation_id, note_type, username, note)

            # Log to immutable audit trail
            await audit.log_note_added(
                investigation_id=investigation_id,
                note_type=note_type_input,
                note_preview=note,
                actor_type="human",
                actor_name=username,
                actor_id=user_id
            )

            logger.info(f"[RIGGS_TOOL] Added {note_type} note to {investigation_id}")
            return {
                "success": True,
                "message": f"Added {note_type_input}: {note[:100]}{'...' if len(note) > 100 else ''}",
                "data": {"note_type": note_type_input}
            }

        elif tool_name == "reopen_investigation":
            reason = tool_args.get('reason', 'Reopened by analyst request')

            async with postgres_db.tenant_acquire() as conn:
                # Check current state
                current = await conn.fetchrow(
                    "SELECT state, disposition FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

                if not current:
                    return {"success": False, "message": "Investigation not found"}

                previous_state = current['state']

                # Reopen the investigation
                await conn.execute("""
                    UPDATE investigations
                    SET state = 'in_progress',
                        resolved_at = NULL,
                        resolved_by = NULL,
                        updated_at = NOW()
                    WHERE investigation_id = $1
                """, investigation_id)

                # Also update the linked alert if exists
                await conn.execute("""
                    UPDATE alerts a
                    SET status = 'in_progress',
                        resolved_at = NULL
                    FROM investigations i
                    WHERE i.alert_id = a.id
                      AND i.investigation_id = $1
                """, investigation_id)

                # Add a note about reopening
                await conn.execute("""
                    INSERT INTO investigation_notes (
                        investigation_id, note_type, author, author_type,
                        content, created_at
                    ) VALUES ($1, 'SYSTEM_NOTE', $2, 'HUMAN', $3, NOW())
                """, investigation_id, username, f"Investigation reopened: {reason}")

            # Log to immutable audit trail
            await audit.log_reopen(
                investigation_id=investigation_id,
                previous_state=previous_state,
                actor_type="human",
                actor_name=username,
                actor_id=user_id,
                reason=reason
            )

            logger.info(f"[RIGGS_TOOL] Reopened investigation {investigation_id} by {username}: {reason}")
            return {
                "success": True,
                "message": f"Investigation reopened. Reason: {reason}",
                "data": {"new_state": "in_progress", "previous_state": previous_state}
            }

        elif tool_name == "save_analyst_insight":
            from services.analyst_insights_service import get_insights_service

            insight_type = tool_args.get('insight_type', 'pattern')
            subject = tool_args.get('subject', '')
            insight = tool_args.get('insight', '')
            is_safe = tool_args.get('is_safe')  # Can be None

            if not subject or not insight:
                return {"success": False, "message": "Subject and insight are required"}

            insights_service = get_insights_service()
            result = await insights_service.add_insight(
                insight_type=insight_type,
                subject=subject,
                insight=insight,
                created_by=username,
                investigation_id=investigation_id,
                is_safe=is_safe,
                applies_to_sender=(insight_type == 'sender'),
                applies_to_domain=(insight_type == 'domain'),
                applies_to_subject_pattern=(insight_type == 'pattern'),
                applies_to_ioc_type='ioc' if insight_type == 'ioc_behavior' else None
            )

            if result:
                logger.info(f"[RIGGS_TOOL] Saved analyst insight: {insight_type}/{subject} by {username}")
                return {
                    "success": True,
                    "message": f"Got it! I've saved this insight about **{subject}** and will remember it for future analysis.",
                    "data": {"insight_id": result, "insight_type": insight_type, "subject": subject}
                }
            else:
                return {"success": False, "message": "Failed to save insight"}

        elif tool_name == "override_analysis":
            new_disposition = tool_args.get('new_disposition', 'FALSE_POSITIVE').upper()
            new_confidence = tool_args.get('new_confidence', 0.9)
            override_reason = tool_args.get('override_reason', '')

            async with postgres_db.tenant_acquire() as conn:
                # Get current analysis data from investigation
                current = await conn.fetchrow(
                    "SELECT disposition, confidence, investigation_data FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )
                old_disposition = current['disposition'] if current else None
                old_confidence = current['confidence'] if current else None

                # Get alert analysis if available
                alert_analysis = await conn.fetchrow("""
                    SELECT a.ai_analysis, a.analysis_result
                    FROM alerts a
                    JOIN investigations i ON i.alert_id = a.id
                    WHERE i.investigation_id = $1
                """, investigation_id)

                # Build the override record
                import json as json_module
                override_record = {
                    "overridden_by": "riggs",
                    "approved_by": username,
                    "timestamp": datetime.now().isoformat(),
                    "new_disposition": new_disposition,
                    "new_confidence": new_confidence,
                    "reason": override_reason,
                    "original_disposition": old_disposition,
                    "original_confidence": float(old_confidence) if old_confidence else None,
                    "original_analysis": alert_analysis['ai_analysis'] if alert_analysis else None
                }

                # Update investigation with Riggs' override
                await conn.execute("""
                    UPDATE investigations
                    SET disposition = $1,
                        confidence = $2,
                        riggs_override = $3,
                        updated_at = NOW()
                    WHERE investigation_id = $4
                """, new_disposition, new_confidence, json_module.dumps(override_record), investigation_id)

                # Add a note about the override
                await conn.execute("""
                    INSERT INTO investigation_notes (
                        investigation_id, note_type, author, author_type,
                        content, created_at
                    ) VALUES ($1, 'AI_RECOMMENDATION', 'Riggs', 'AI', $2, NOW())
                """, investigation_id, f"OVERRIDE: Changed to {new_disposition} ({new_confidence*100:.0f}% confidence). Reason: {override_reason}")

            # Log to immutable audit trail
            await audit.log_disposition_change(
                investigation_id=investigation_id,
                old_disposition=old_disposition,
                new_disposition=new_disposition,
                actor_type="ai",
                actor_name="Riggs (approved by " + username + ")",
                actor_id=user_id,
                reason=f"AI Override: {override_reason}"
            )

            logger.info(f"[RIGGS_TOOL] Override analysis for {investigation_id}: {new_disposition} ({new_confidence}) - {override_reason}")
            return {
                "success": True,
                "message": f"Done! I've overridden the T1 analysis. New disposition: **{new_disposition}** ({new_confidence*100:.0f}% confidence). Reason: {override_reason}",
                "data": {"disposition": new_disposition, "confidence": new_confidence, "override_reason": override_reason}
            }

        elif tool_name == "search_logs":
            # Search security logs - available to all authenticated users
            from services.log_search import get_log_search_service

            query = tool_args.get('query', '*')
            time_range = tool_args.get('time_range', '24h')
            limit = min(tool_args.get('limit', 50), 200)

            search_service = get_log_search_service()
            result = await search_service.search(
                query=query,
                time_range=time_range,
                limit=limit
            )

            # Format events for display
            events_summary = []
            for event in result.events[:20]:  # Show top 20 in summary
                summary = {
                    "time": event.get("@timestamp", "")[:19],
                    "host": event.get("host", {}).get("name", "-"),
                    "source": event.get("source_type", "-"),
                }
                if event.get("process", {}).get("name"):
                    summary["process"] = event["process"]["name"]
                if event.get("user", {}).get("name"):
                    summary["user"] = event["user"]["name"]
                if event.get("event", {}).get("action"):
                    summary["action"] = event["event"]["action"]
                events_summary.append(summary)

            logger.info(f"[RIGGS_TOOL] Search logs: '{query}' returned {result.total} results")
            return {
                "success": True,
                "message": f"Found **{result.total}** events matching `{query}` in the last {time_range}",
                "data": {
                    "total": result.total,
                    "query": query,
                    "time_range": time_range,
                    "events": events_summary,
                    "query_time_ms": result.query_time_ms
                }
            }

        elif tool_name == "get_investigation_summary":
            # Get investigation summary with alert count and entities
            async with postgres_db.tenant_acquire() as conn:
                # Get investigation with alert count
                row = await conn.fetchrow("""
                    SELECT
                        i.id,
                        i.investigation_id,
                        i.state,
                        i.disposition,
                        i.priority,
                        i.severity,
                        i.alert_title,
                        i.user_count,
                        i.host_count,
                        COALESCE(
                            (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id),
                            0
                        ) as alert_count
                    FROM investigations i
                    WHERE i.investigation_id = $1
                """, investigation_id)

                if not row:
                    return {"success": False, "message": f"Investigation not found: {investigation_id}"}

                investigation_uuid = row["id"]

                # Get severity breakdown
                severity_breakdown = await conn.fetch("""
                    SELECT severity, COUNT(*) as count
                    FROM alerts
                    WHERE investigation_id = $1
                    GROUP BY severity
                """, investigation_uuid)

                # Get top entities
                top_entities = await conn.fetch("""
                    SELECT entity_type, entity_value, confidence
                    FROM investigation_entities
                    WHERE investigation_id = $1
                    ORDER BY confidence DESC
                    LIMIT 10
                """, investigation_uuid)

                # Get time range
                time_range_row = await conn.fetchrow("""
                    SELECT MIN(created_at) as first_alert, MAX(created_at) as last_alert
                    FROM alerts
                    WHERE investigation_id = $1
                """, investigation_uuid)

            # Build severity summary
            severities = {s["severity"]: s["count"] for s in severity_breakdown}

            # Build entity lists
            users = [e["entity_value"] for e in top_entities if e["entity_type"] == "user"]
            hosts = [e["entity_value"] for e in top_entities if e["entity_type"] == "host"]
            mitre = [e["entity_value"] for e in top_entities if e["entity_type"] == "mitre_technique"]

            # Format time range
            first_alert = time_range_row["first_alert"] if time_range_row else None
            last_alert = time_range_row["last_alert"] if time_range_row else None

            # Build text summary
            text_summary = f"This investigation contains **{row['alert_count']} alert(s)**. "
            if severities:
                sev_parts = []
                for sev in ['critical', 'high', 'medium', 'low']:
                    if severities.get(sev, 0) > 0:
                        sev_parts.append(f"{severities[sev]} {sev}")
                if sev_parts:
                    text_summary += f"Severity breakdown: {', '.join(sev_parts)}. "

            if users:
                text_summary += f"Users involved: {', '.join(users[:3])}" + (f" (+{len(users)-3} more)" if len(users) > 3 else "") + ". "
            if hosts:
                text_summary += f"Hosts: {', '.join(hosts[:3])}" + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "") + ". "
            if mitre:
                text_summary += f"MITRE techniques: {', '.join(mitre[:3])}. "
            if first_alert and last_alert:
                text_summary += f"Time span: {first_alert.strftime('%Y-%m-%d %H:%M')} to {last_alert.strftime('%Y-%m-%d %H:%M')}."

            logger.info(f"[RIGGS_TOOL] Investigation summary for {investigation_id}: {row['alert_count']} alerts")
            return {
                "success": True,
                "message": text_summary,
                "data": {
                    "investigation_id": investigation_id,
                    "alert_count": row["alert_count"],
                    "state": row["state"],
                    "severity": row["severity"],
                    "priority": row["priority"],
                    "user_count": row["user_count"] or 0,
                    "host_count": row["host_count"] or 0,
                    "alerts_by_severity": severities,
                    "users": users,
                    "hosts": hosts,
                    "mitre_techniques": mitre,
                    "first_alert_at": first_alert.isoformat() if first_alert else None,
                    "last_alert_at": last_alert.isoformat() if last_alert else None
                }
            }

        elif tool_name == "search_investigation_alerts":
            # Search alerts within the current investigation
            import json as json_module

            query_text = tool_args.get('query')
            severity = tool_args.get('severity')
            user_filter = tool_args.get('user')
            host_filter = tool_args.get('host')
            mitre_filter = tool_args.get('mitre')
            limit = min(tool_args.get('limit', 20), 50)

            async with postgres_db.tenant_acquire() as conn:
                # Get investigation UUID
                inv_row = await conn.fetchrow("""
                    SELECT id FROM investigations WHERE investigation_id = $1
                """, investigation_id)

                if not inv_row:
                    return {"success": False, "message": f"Investigation not found: {investigation_id}"}

                investigation_uuid = inv_row["id"]

                # Build query
                conditions = ["a.investigation_id = $1"]
                params = [investigation_uuid]
                param_idx = 2

                if query_text:
                    conditions.append(f"""
                        (a.title ILIKE ${param_idx}
                         OR a.description ILIKE ${param_idx}
                         OR a.extracted_entities::text ILIKE ${param_idx})
                    """)
                    params.append(f"%{query_text}%")
                    param_idx += 1

                if severity:
                    conditions.append(f"a.severity = ${param_idx}")
                    params.append(severity.lower())
                    param_idx += 1

                if user_filter:
                    conditions.append(f"a.extracted_entities->'user' ? ${param_idx}")
                    params.append(user_filter)
                    param_idx += 1

                if host_filter:
                    conditions.append(f"a.extracted_entities->'host' ? ${param_idx}")
                    params.append(host_filter)
                    param_idx += 1

                if mitre_filter:
                    conditions.append(f"a.raw_event::text ILIKE ${param_idx}")
                    params.append(f"%{mitre_filter}%")
                    param_idx += 1

                where_clause = " AND ".join(conditions)

                # Get count
                count_row = await conn.fetchrow(f"SELECT COUNT(*) as total FROM alerts a WHERE {where_clause}", *params)
                total = count_row["total"] if count_row else 0

                # Get alerts
                params.append(limit)
                rows = await conn.fetch(f"""
                    SELECT
                        a.alert_id,
                        a.title,
                        a.severity,
                        a.source,
                        a.created_at,
                        a.extracted_entities
                    FROM alerts a
                    WHERE {where_clause}
                    ORDER BY a.created_at DESC
                    LIMIT ${param_idx}
                """, *params)

            # Format results
            alerts_summary = []
            for row in rows:
                entities = row["extracted_entities"] if row["extracted_entities"] else {}
                if isinstance(entities, str):
                    try:
                        entities = json_module.loads(entities)
                    except Exception as e:
                        logger.warning(f"Failed to parse extracted_entities for alert {row.get('alert_id')}: {e}")
                        entities = {}

                alert_info = {
                    "alert_id": row["alert_id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "source": row["source"],
                    "time": row["created_at"].strftime("%Y-%m-%d %H:%M") if row["created_at"] else "-"
                }
                if entities.get("user"):
                    alert_info["users"] = entities["user"][:3]
                if entities.get("host"):
                    alert_info["hosts"] = entities["host"][:3]
                alerts_summary.append(alert_info)

            # Build message
            filter_desc = []
            if query_text:
                filter_desc.append(f"matching '{query_text}'")
            if severity:
                filter_desc.append(f"severity={severity}")
            if user_filter:
                filter_desc.append(f"user={user_filter}")
            if host_filter:
                filter_desc.append(f"host={host_filter}")
            if mitre_filter:
                filter_desc.append(f"mitre={mitre_filter}")

            filter_str = " ".join(filter_desc) if filter_desc else "all"
            message = f"Found **{total}** alert(s) {filter_str}."

            if alerts_summary:
                message += "\n\n**Top results:**\n"
                for i, alert in enumerate(alerts_summary[:5], 1):
                    message += f"{i}. [{alert['severity'].upper()}] {alert['title'][:60]}... ({alert['time']})\n"
                if total > 5:
                    message += f"\n_...and {total - 5} more alerts_"

            logger.info(f"[RIGGS_TOOL] Search investigation alerts: found {total} results")
            return {
                "success": True,
                "message": message,
                "data": {
                    "total": total,
                    "alerts": alerts_summary,
                    "filters": {
                        "query": query_text,
                        "severity": severity,
                        "user": user_filter,
                        "host": host_filter,
                        "mitre": mitre_filter
                    }
                }
            }

        elif tool_name == "find_related_investigations":
            # Cross-investigation correlation by shared entity. Pulls
            # investigations that touch a given user/host/ioc within the
            # last `days` window so Riggs can answer "have we seen this
            # before?" without escalating to a full log search.
            entity_type = (tool_args.get("entity_type") or "").lower().strip()
            entity_value = (tool_args.get("entity_value") or "").strip()
            days = max(1, min(365, int(tool_args.get("days") or 30)))
            limit = max(1, min(50, int(tool_args.get("limit") or 10)))
            if not entity_type or not entity_value:
                return {"success": False, "message": "entity_type and entity_value are required"}

            from services.postgres_db import postgres_db
            async with postgres_db.tenant_acquire() as conn:
                # We match the raw_event JSON for the entity value. This is
                # cheap because each tenant's alerts are well-bounded under
                # RLS. We also skip the current investigation so the model
                # doesn't double-count it.
                rows = await conn.fetch(
                    """
                    SELECT i.investigation_id,
                           i.alert_title,
                           i.state,
                           i.disposition,
                           i.severity,
                           i.created_at,
                           i.completed_at
                      FROM investigations i
                      JOIN alerts a ON a.investigation_id = i.id
                     WHERE i.investigation_id != $1
                       AND i.created_at >= NOW() - ($2 || ' days')::interval
                       AND (
                            LOWER(COALESCE(a.raw_event::text, '')) LIKE '%' || LOWER($3) || '%'
                            OR LOWER(COALESCE(a.title, '')) LIKE '%' || LOWER($3) || '%'
                       )
                     ORDER BY i.created_at DESC
                     LIMIT $4
                    """,
                    investigation_id, str(days), entity_value, limit,
                )
            results = [
                {
                    "investigation_id": r["investigation_id"],
                    "title": (r["alert_title"] or "")[:120],
                    "state": r["state"],
                    "disposition": r["disposition"],
                    "severity": r["severity"],
                    "opened_at": r["created_at"].isoformat() if r["created_at"] else None,
                    "closed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
                }
                for r in rows
            ]
            return {
                "success": True,
                "message": f"Found {len(results)} prior investigation(s) touching {entity_type}={entity_value} in the last {days} days.",
                "data": {
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "days": days,
                    "results": results,
                },
            }

        elif tool_name == "list_available_actions":
            # What connector actions can this tenant actually fire? Riggs
            # uses this to ground its remediation recommendations in
            # installed-and-enabled connectors rather than generic advice.
            ioc_filter = (tool_args.get("ioc_type") or "").lower().strip() or None

            from services.postgres_db import postgres_db
            async with postgres_db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT cd.name AS connector_name,
                           ca.action_id,
                           ca.display_name,
                           ca.description,
                           ca.ioc_types
                      FROM connect_instances ci
                      JOIN connector_definitions cd ON cd.id = ci.connector_id
                 LEFT JOIN connector_actions ca ON ca.connector_id = cd.id
                     WHERE ci.enabled = TRUE
                       AND ca.action_id IS NOT NULL
                     ORDER BY cd.name, ca.display_name
                     LIMIT 100
                    """
                )
            actions = []
            for r in rows:
                ioc_types = r["ioc_types"] or []
                if isinstance(ioc_types, str):
                    try:
                        import json as _json
                        ioc_types = _json.loads(ioc_types)
                    except Exception:
                        ioc_types = []
                if ioc_filter and ioc_filter not in [str(t).lower() for t in (ioc_types or [])]:
                    continue
                actions.append({
                    "connector": r["connector_name"],
                    "action_id": r["action_id"],
                    "action": r["display_name"] or r["action_id"],
                    "description": (r["description"] or "")[:160],
                    "ioc_types": ioc_types,
                })
            return {
                "success": True,
                "message": f"{len(actions)} available action(s)" + (f" for {ioc_filter} IOCs" if ioc_filter else "."),
                "data": {"actions": actions, "ioc_filter": ioc_filter},
            }

        else:
            return {"success": False, "message": f"Unknown tool: {tool_name}"}

    except Exception as e:
        logger.error(f"[RIGGS_TOOL] Error executing {tool_name}: {e}")
        return {"success": False, "message": f"Error: {str(e)}"}

# JWT Configuration - use dependencies.auth module (DB-backed, strict key)
from dependencies.auth import JWT_SECRET_KEY, JWT_ALGORITHM


class ConnectionManager:
    """
    Manages WebSocket connections grouped by investigation ID.
    """

    def __init__(self):
        # investigation_id -> {connection_id -> websocket}
        self.connections: Dict[str, Dict[str, WebSocket]] = {}
        # connection_id -> user_info
        self.connection_users: Dict[str, Dict] = {}
        # investigation_id -> {user_id -> typing_status}
        self.typing_status: Dict[str, Dict[str, bool]] = {}

    async def connect(
        self,
        websocket: WebSocket,
        investigation_id: str,
        user_id: str,
        username: str
    ) -> str:
        """
        Accept and register a new WebSocket connection.
        Returns connection_id.
        """
        await websocket.accept()

        connection_id = str(uuid.uuid4())

        if investigation_id not in self.connections:
            self.connections[investigation_id] = {}
            self.typing_status[investigation_id] = {}

        self.connections[investigation_id][connection_id] = websocket
        self.connection_users[connection_id] = {
            'user_id': user_id,
            'username': username,
            'investigation_id': investigation_id,
            'connected_at': datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"WebSocket connected: {connection_id} for user {username} to investigation {investigation_id}")

        # Broadcast user joined
        await self.broadcast(investigation_id, {
            'type': 'user_joined',
            'user_id': user_id,
            'username': username,
            'connection_id': connection_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, exclude_connection=connection_id)

        # Send current users list to new connection
        await self.send_personal({
            'type': 'users_list',
            'users': self.get_connected_users(investigation_id)
        }, websocket)

        return connection_id

    async def disconnect(self, connection_id: str):
        """Disconnect and cleanup a connection."""
        user_info = self.connection_users.get(connection_id)
        if not user_info:
            return

        investigation_id = user_info['investigation_id']
        user_id = user_info['user_id']
        username = user_info['username']

        # Remove from connections
        if investigation_id in self.connections:
            if connection_id in self.connections[investigation_id]:
                del self.connections[investigation_id][connection_id]

            # Clean up empty investigations
            if not self.connections[investigation_id]:
                del self.connections[investigation_id]
                if investigation_id in self.typing_status:
                    del self.typing_status[investigation_id]

        # Remove typing status
        if investigation_id in self.typing_status:
            if user_id in self.typing_status[investigation_id]:
                del self.typing_status[investigation_id][user_id]

        # Remove connection user info
        if connection_id in self.connection_users:
            del self.connection_users[connection_id]

        logger.info(f"WebSocket disconnected: {connection_id} ({username})")

        # Broadcast user left
        await self.broadcast(investigation_id, {
            'type': 'user_left',
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    @staticmethod
    def _serialize(message: Dict) -> str:
        """Serialize message to JSON, handling UUID and datetime objects."""
        def default(obj):
            if isinstance(obj, uuid.UUID):
                return str(obj)
            if isinstance(obj, (datetime,)):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
        return json.dumps(message, default=default)

    async def broadcast(
        self,
        investigation_id: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Broadcast a message to all connections in an investigation."""
        if investigation_id not in self.connections:
            return

        failed_connections = []
        payload = self._serialize(message)

        for connection_id, websocket in self.connections[investigation_id].items():
            if exclude_connection and connection_id == exclude_connection:
                continue

            try:
                await websocket.send_text(payload)
            except Exception as e:
                logger.error(f"Error broadcasting to {connection_id}: {e}")
                failed_connections.append(connection_id)

        # Clean up failed connections
        for connection_id in failed_connections:
            await self.disconnect(connection_id)

    async def send_personal(self, message: Dict, websocket: WebSocket):
        """Send a message to a specific connection."""
        try:
            await websocket.send_text(self._serialize(message))
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    def get_connected_users(self, investigation_id: str) -> List[Dict]:
        """Get list of users connected to an investigation."""
        if investigation_id not in self.connections:
            return []

        users = []
        seen_users = set()

        for connection_id in self.connections[investigation_id]:
            user_info = self.connection_users.get(connection_id)
            if user_info and user_info['user_id'] not in seen_users:
                users.append({
                    'user_id': user_info['user_id'],
                    'username': user_info['username'],
                    'is_typing': self.typing_status.get(investigation_id, {}).get(user_info['user_id'], False)
                })
                seen_users.add(user_info['user_id'])

        return users

    async def set_typing(self, investigation_id: str, user_id: str, username: str, is_typing: bool):
        """Set typing status for a user."""
        if investigation_id not in self.typing_status:
            self.typing_status[investigation_id] = {}

        self.typing_status[investigation_id][user_id] = is_typing

        await self.broadcast(investigation_id, {
            'type': 'typing_indicator',
            'user_id': user_id,
            'username': username,
            'is_typing': is_typing,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })


# Global connection manager
manager = ConnectionManager()


class ChatWebSocket:
    """
    WebSocket endpoint handler for investigation chat.
    """

    def __init__(self):
        self.manager = manager

    async def handle_connection(self, websocket: WebSocket, investigation_id: str, token: Optional[str] = None):
        """
        Handle a WebSocket connection.

        Authentication is done via token query parameter.
        """
        print(f"[WS] New WebSocket connection attempt for investigation {investigation_id}")

        # Authenticate (query token or cookie)
        user_info = self._verify_token(token, websocket)
        if not user_info:
            print(f"[WS] Token verification FAILED for investigation {investigation_id}")
            await websocket.close(code=4001, reason="Invalid or missing token")
            return

        print(f"[WS] Token verified: user={user_info.get('username', 'unknown')}, tenant={user_info.get('tenant_id', 'none')}")

        user_id = user_info.get('sub', 'anonymous')
        username = user_info.get('username', user_id)
        user_role = user_info.get('role', 'read_only')  # RBAC enforcement

        # Set tenant context for RLS — WebSocket connections bypass TenantMiddleware,
        # so we must set the ContextVar manually from the JWT tenant_id claim.
        from middleware.tenant_middleware import current_tenant_id as _tenant_ctx_var
        ws_tenant_id = user_info.get('tenant_id')
        tenant_ctx_token = None
        if ws_tenant_id:
            tenant_ctx_token = _tenant_ctx_var.set(ws_tenant_id)
            print(f"[WS] Tenant context set: {ws_tenant_id}")
        else:
            print(f"[WS] WARNING: No tenant_id in JWT for user {username}")

        connection_id = None

        try:
            connection_id = await self.manager.connect(
                websocket,
                investigation_id,
                user_id,
                username
            )

            # Track session start
            await self._track_session_start(user_id, investigation_id, connection_id, username)

            # Main message loop
            while True:
                try:
                    data = await websocket.receive_json()
                    await self._handle_message(connection_id, investigation_id, user_id, username, user_role, data)
                except WebSocketDisconnect:
                    break
                except json.JSONDecodeError:
                    await self.manager.send_personal({
                        'type': 'error',
                        'message': 'Invalid JSON'
                    }, websocket)
                except Exception as e:
                    logger.error(f"Error handling WebSocket message: {e}")
                    await self.manager.send_personal({
                        'type': 'error',
                        'message': str(e)
                    }, websocket)

        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error(f"WebSocket error: {e}", exc_info=True)
        finally:
            if connection_id:
                # Track session end
                await self._track_session_end(user_id, investigation_id, connection_id)
                await self.manager.disconnect(connection_id)
            # Reset tenant context when WebSocket disconnects
            if tenant_ctx_token:
                _tenant_ctx_var.reset(tenant_ctx_token)

    async def _handle_message(
        self,
        connection_id: str,
        investigation_id: str,
        user_id: str,
        username: str,
        user_role: str,
        data: Dict
    ):
        """Handle incoming WebSocket messages."""
        msg_type = data.get('type')
        print(f"[WS] Received message type='{msg_type}' from {username} (role={user_role}) in {investigation_id}")

        if msg_type == 'chat_message':
            print(f"[WS] Chat message: '{data.get('message', '')[:50]}...' from {username}")
            # Handle chat message - save to DB and broadcast
            await self._handle_chat_message(
                investigation_id,
                user_id,
                username,
                user_role,
                data.get('message', ''),
                data.get('metadata')
            )

        elif msg_type == 'typing_start':
            await self.manager.set_typing(investigation_id, user_id, username, True)

        elif msg_type == 'typing_stop':
            await self.manager.set_typing(investigation_id, user_id, username, False)

        elif msg_type == 'mark_read':
            # Mark messages as read
            await self._handle_mark_read(
                investigation_id,
                user_id,
                data.get('message_id')
            )

        elif msg_type == 'ping':
            # Heartbeat
            await self.manager.send_personal({
                'type': 'pong',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, self.manager.connections.get(investigation_id, {}).get(connection_id))

        elif msg_type == 'get_history':
            # Send chat history
            await self._handle_get_history(
                connection_id,
                investigation_id,
                data.get('before_id'),
                data.get('limit', 50)
            )

    async def _handle_chat_message(
        self,
        investigation_id: str,
        user_id: str,
        username: str,
        user_role: str,
        message: str,
        metadata: Optional[Dict] = None
    ):
        """Save chat message to DB and broadcast."""
        from services.chat_service import get_chat_service

        try:
            chat_service = get_chat_service()

            # Send message (this will also notify handlers which broadcast)
            result = await chat_service.send_message(
                investigation_id=investigation_id,
                sender_type='human',
                sender_id=user_id,
                sender_name=username,
                message=message,
                message_type='text',
                metadata=metadata
            )

            if result['success']:
                # Note: Broadcast happens via the registered on_chat_message callback
                # which is triggered by chat_service._notify_handlers()

                # Clear typing indicator
                await self.manager.set_typing(investigation_id, user_id, username, False)

                # Track message for analytics
                await self._track_message_sent(
                    user_id=user_id,
                    investigation_id=investigation_id,
                    message=message,
                    message_type='text',
                    username=username
                )

                # Track if this was a quick action (check for known prompts)
                if metadata and metadata.get('quick_action'):
                    try:
                        from services.chat_analytics_service import get_chat_analytics_service
                        analytics = get_chat_analytics_service()
                        await analytics.track_quick_action(
                            user_id=user_id,
                            investigation_id=investigation_id,
                            category=metadata.get('quick_action_category', 'Unknown'),
                            label=metadata.get('quick_action_label', 'Unknown'),
                            username=username
                        )
                    except Exception as e:
                        logger.debug(f"Analytics tracking error (quick action): {e}")

                # Trigger AI agent response (pass user_role for RBAC enforcement)
                asyncio.create_task(self._get_ai_response(
                    investigation_id=investigation_id,
                    user_message=message,
                    user_id=user_id,
                    username=username,
                    user_role=user_role
                ))
            else:
                logger.error(f"Failed to save chat message: {result.get('error')}")

        except Exception as e:
            logger.error(f"Error handling chat message: {e}")

    async def _get_ai_response(
        self,
        investigation_id: str,
        user_message: str,
        user_id: str,
        username: str,
        user_role: str = "read_only"
    ):
        """
        Get AI agent response for user message.
        This calls the configured LLM and streams the response back to chat.
        """
        from services.chat_service import get_chat_service
        from services.agent_executor import AgentExecutor
        from services.chat_guardrails import get_chat_guardrails

        print(f"[CHAT] Getting AI response for investigation {investigation_id}, message: '{user_message[:50]}...' from {username}")

        # =====================================================================
        # INPUT GUARDRAILS - Validate before processing
        # =====================================================================
        guardrails = get_chat_guardrails()
        input_result = guardrails.validate_input(user_message, user_id, investigation_id)

        if not input_result.allowed:
            # Input blocked by guardrails - send user-friendly message
            print(f"[CHAT GUARDRAIL] Input blocked: {input_result.reason}")
            chat_service = get_chat_service()

            # Map violation types to user-friendly messages
            user_messages = {
                "prompt_injection": "I can't process that request. Please rephrase your question about this investigation.",
                "jailbreak_attempt": "I'm here to help with security investigations. What would you like to know about this case?",
                "persona_injection": "Nice try, but I'm Riggs - your SOC analyst partner. I can't take on a different character or profile. Let's focus on this investigation instead.",
                "pii_exfiltration": "I can't search for or retrieve bulk PII data like SSNs, credit cards, or passwords. This request has been logged. Let me know how I can help with this investigation in a different way.",
                "offensive_request": "I can help analyze threats but can't provide offensive security guidance. What would you like me to investigate?",
                "rate_limit": f"Slow down! {input_result.reason}. Please wait a moment.",
                "input_too_long": "That message is too long. Please break it into smaller questions.",
            }

            violation_key = input_result.violation_type.value if input_result.violation_type else "default"
            friendly_msg = user_messages.get(violation_key, "I couldn't process that request. Please try rephrasing.")

            # Flag the chat if this violation requires security review
            if input_result.should_flag_chat:
                from services.chat_guardrails import flag_chat_for_security_review
                await flag_chat_for_security_review(
                    investigation_id=investigation_id,
                    user_id=user_id,
                    username=username,
                    violation_type=input_result.violation_type,
                    reason=input_result.reason,
                    matched_pattern=input_result.matched_pattern
                )
                print(f"[CHAT GUARDRAIL] Chat flagged for security review: {investigation_id}")

            error_result = await chat_service.send_message(
                investigation_id=investigation_id,
                sender_type='agent_t1',  # Valid constraint: agent_t1, agent_t2, agent_t3
                sender_id='ai_assistant',
                sender_name='Riggs',
                message=friendly_msg,
                message_type='text'
            )
            if error_result.get('success'):
                await self.manager.broadcast(investigation_id, {
                    'type': 'new_message',
                    'message': error_result['message']
                })
            return

        # Use sanitized message if sensitive data was redacted
        processed_message = input_result.sanitized_content or user_message
        if input_result.redactions:
            print(f"[CHAT GUARDRAIL] Input sanitized, redactions: {input_result.redactions}")

        try:
            chat_service = get_chat_service()

            # Show typing indicator for AI
            await chat_service.set_typing(
                investigation_id=investigation_id,
                user_id='ai_assistant',
                user_name='Riggs',
                is_agent=True
            )

            # Broadcast typing indicator
            await self.manager.broadcast(investigation_id, {
                'type': 'typing_update',
                'user_id': 'ai_assistant',
                'user_name': 'Riggs',
                'is_typing': True,
                'is_agent': True
            })

            # Get investigation context with phishing report data for full email body
            from services.postgres_db import postgres_db
            async with postgres_db.tenant_acquire() as conn:
                inv = await conn.fetchrow(
                    """SELECT i.*, a.raw_event as alert_data,
                              pr.reported_subject as phishing_subject,
                              pr.reported_from as phishing_sender,
                              pr.reporter_email as phishing_reporter,
                              pr.reported_body_preview as phishing_body_preview,
                              ie.body_text as email_body_text,
                              ie.body_html as email_body_html,
                              ie.from_address as email_from,
                              ie.subject as email_subject
                       FROM investigations i
                       LEFT JOIN alerts a ON i.alert_id = a.id
                       LEFT JOIN phishing_reports pr ON pr.investigation_id = i.id
                       LEFT JOIN inbound_email_queue ie ON pr.inbound_email_id = ie.id
                       WHERE i.investigation_id = $1""",
                    investigation_id
                )

            if not inv:
                # Try by UUID
                async with postgres_db.tenant_acquire() as conn:
                    try:
                        inv = await conn.fetchrow(
                            """SELECT i.*, a.raw_event as alert_data,
                                      pr.reported_subject as phishing_subject,
                                      pr.reported_from as phishing_sender,
                                      pr.reporter_email as phishing_reporter,
                                      pr.reported_body_preview as phishing_body_preview,
                                      ie.body_text as email_body_text,
                                      ie.body_html as email_body_html,
                                      ie.from_address as email_from,
                                      ie.subject as email_subject
                               FROM investigations i
                               LEFT JOIN alerts a ON i.alert_id = a.id
                               LEFT JOIN phishing_reports pr ON pr.investigation_id = i.id
                               LEFT JOIN inbound_email_queue ie ON pr.inbound_email_id = ie.id
                               WHERE i.id = $1""",
                            uuid.UUID(investigation_id)
                        )
                    except Exception as e:
                        logger.error(f"Failed to fetch investigation context for {investigation_id}: {e}", exc_info=True)
                        inv = None

            # Build COMPACT context for AI - optimized for low token usage
            # Target: ~500-800 tokens max to keep costs down
            context_info = ""
            if inv:
                # Compact investigation header - keep full investigation_id (don't truncate UUIDs)
                alert_title = inv.get('alert_title') or 'N/A'
                context_info = f"[INV] {inv.get('investigation_id', investigation_id)} | {inv.get('state', '?')} | {inv.get('priority', 'P3')} | {inv.get('disposition', '-')}\nAlert: {alert_title[:80]}\n"

                # Add phishing email content (compact format)
                if inv.get('email_body_text') or inv.get('email_body_html') or inv.get('phishing_subject'):
                    import re
                    subj = (inv.get('phishing_subject') or inv.get('email_subject') or '')[:100]
                    sender = (inv.get('phishing_sender') or inv.get('email_from') or '')[:50]
                    if subj or sender:
                        context_info += f"Email: {subj} | From: {sender}\n"

                    # Get email body - need enough to actually analyze the content
                    # 2000 chars is ~500 words, enough to understand most emails
                    email_body = inv.get('email_body_text') or ''
                    if not email_body and inv.get('email_body_html'):
                        html_body = inv.get('email_body_html', '')
                        html_body = re.sub(r'<script[^>]*>.*?</script>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
                        html_body = re.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
                        email_body = re.sub(r'<[^>]+>', ' ', html_body)
                        email_body = re.sub(r'\s+', ' ', email_body).strip()

                    if email_body:
                        context_info += f"Body: {email_body[:2000]}{'...' if len(email_body) > 2000 else ''}\n"
                    elif inv.get('phishing_body_preview'):
                        context_info += f"Body: {inv.get('phishing_body_preview', '')[:2000]}\n"

                # Add alert data (compact - skip if already have email content above)
                alert_iocs = []
                if inv.get('alert_data'):
                    import json as json_module
                    try:
                        alert_data = inv['alert_data'] if isinstance(inv['alert_data'], dict) else json_module.loads(inv['alert_data'])

                        # Extract IOCs first
                        if alert_data.get('iocs') and isinstance(alert_data['iocs'], list):
                            alert_iocs = alert_data['iocs']

                        # Only add alert body if we didn't get email content above
                        if not (inv.get('email_body_text') or inv.get('email_body_html')):
                            if alert_data.get('body') or alert_data.get('message'):
                                body = (alert_data.get('body') or alert_data.get('message', ''))[:2000]
                                context_info += f"Content: {body}{'...' if len(body) >= 2000 else ''}\n"
                            # For non-email alerts, compact JSON dump
                            elif not any(k in alert_data for k in ['subject', 'body', 'from', 'sender', 'reporter']):
                                alert_str = json_module.dumps(alert_data, indent=None, default=str)[:500]
                                context_info += f"Data: {alert_str}\n"
                    except Exception as e:
                        logger.debug(f"Could not parse alert_data: {e}")

                # Add tier analysis (compact format)
                if inv.get('investigation_data'):
                    import json as json_module
                    try:
                        inv_data = inv['investigation_data'] if isinstance(inv['investigation_data'], dict) else json_module.loads(inv['investigation_data'])

                        # Compact tier summaries - just verdict and key summary
                        # Helper to normalize confidence: if <= 1, it's decimal (0.75), multiply by 100
                        def norm_conf(c):
                            return round(c * 100) if c and c <= 1 else round(c or 0)

                        if inv_data.get('tier1_analysis'):
                            t1 = inv_data['tier1_analysis']
                            verdict = t1.get('verdict', '?')
                            conf = norm_conf(t1.get('confidence', 0))
                            summary = (t1.get('summary', '') or '')[:150]
                            context_info += f"T1: {verdict} ({conf}%) - {summary}\n"

                        if inv_data.get('tier2_analysis'):
                            t2 = inv_data['tier2_analysis']
                            verdict = t2.get('verdict', '?')
                            conf = norm_conf(t2.get('confidence', 0))
                            summary = (t2.get('summary', '') or '')[:150]
                            context_info += f"T2: {verdict} ({conf}%) - {summary}\n"

                            # T2 MITRE techniques if available (fallback if riggs not present)
                            t2_mitre = t2.get('mitre_techniques', []) or t2.get('mitre', [])
                            if t2_mitre and not inv_data.get('riggs_analysis', {}).get('mitre'):
                                mitre_strs = []
                                for t in t2_mitre[:4]:
                                    if isinstance(t, dict):
                                        tid = t.get('technique_id', t.get('id', ''))
                                        tname = t.get('name', '')
                                        if tid:
                                            mitre_strs.append(f"{tid}" + (f"({tname[:20]})" if tname else ""))
                                    elif isinstance(t, str):
                                        mitre_strs.append(t[:25])
                                if mitre_strs:
                                    context_info += f"MITRE: {', '.join(mitre_strs)}\n"

                        if inv_data.get('tier3_analysis'):
                            t3 = inv_data['tier3_analysis']
                            verdict = t3.get('verdict', '?')
                            summary = (t3.get('summary', '') or '')[:150]
                            context_info += f"T3: {verdict} - {summary}\n"

                        # Compact IOCs - just 3 key ones
                        iocs_to_display = inv_data.get('iocs', []) or alert_iocs
                        if iocs_to_display:
                            ioc_strs = [f"{i.get('type','?')}:{i.get('value', i.get('indicator', '?'))[:30]}" for i in iocs_to_display[:3]]
                            context_info += f"IOCs: {', '.join(ioc_strs)}" + (f" (+{len(iocs_to_display)-3} more)" if len(iocs_to_display) > 3 else "") + "\n"

                        # Check for ML prediction data in investigation
                        ml_data = inv_data.get('ml_prediction', {})
                        if ml_data and ml_data.get('disposition'):
                            ml_disp = ml_data.get('disposition', '?')
                            ml_conf = ml_data.get('confidence', 0)
                            ml_anomaly = ml_data.get('anomaly_score', 0.5)
                            context_info += f"ML: {ml_disp} ({ml_conf:.0%} conf, anomaly={ml_anomaly:.2f})\n"
                        else:
                            # Run ML prediction on-demand if alert_data available
                            try:
                                from services.ml_classifier import get_ml_classifier
                                ml_classifier = get_ml_classifier()
                                if ml_classifier.is_ready() and inv.get('alert_data'):
                                    alert_for_ml = inv['alert_data'] if isinstance(inv['alert_data'], dict) else json_module.loads(inv['alert_data'])
                                    ml_prediction = ml_classifier.predict(alert_for_ml)
                                    if ml_prediction:
                                        context_info += f"ML: {ml_prediction.disposition} ({ml_prediction.confidence:.0%} conf, anomaly={ml_prediction.anomaly_score:.2f})\n"
                            except Exception as ml_err:
                                logger.debug(f"ML prediction in chat skipped: {ml_err}")

                        # Add Riggs analysis if available (comprehensive analysis)
                        riggs = inv_data.get('riggs_analysis', {})
                        if riggs:
                            # Riggs verdict if different from T1/T2
                            if riggs.get('verdict') and riggs.get('summary'):
                                r_summary = (riggs.get('summary', '') or '')[:200]
                                context_info += f"Riggs: {riggs.get('verdict')} - {r_summary}\n"

                            # MITRE techniques - critical for threat context
                            mitre = riggs.get('mitre', []) or riggs.get('mitre_techniques', [])
                            if mitre:
                                mitre_strs = []
                                for t in mitre[:5]:  # Top 5 techniques
                                    if isinstance(t, dict):
                                        tid = t.get('id', t.get('technique_id', ''))
                                        tname = t.get('name', t.get('technique_name', ''))
                                        if tid:
                                            mitre_strs.append(f"{tid}" + (f"({tname[:25]})" if tname else ""))
                                        elif tname:
                                            mitre_strs.append(tname[:30])
                                    elif isinstance(t, str):
                                        mitre_strs.append(t[:30])
                                if mitre_strs:
                                    context_info += f"MITRE: {', '.join(mitre_strs)}\n"

                            # Affected entities
                            entities = riggs.get('affected_entities', [])
                            if entities:
                                ent_strs = [f"{e.get('type', '?')}:{e.get('value', '?')[:20]}" for e in entities[:4]]
                                context_info += f"Entities: {', '.join(ent_strs)}\n"

                            # Key findings
                            findings = riggs.get('key_findings', [])
                            if findings:
                                # Just top 2 findings
                                for f in findings[:2]:
                                    f_text = (f.get('finding', f) if isinstance(f, dict) else str(f))[:100]
                                    context_info += f"Finding: {f_text}\n"

                    except Exception as e:
                        logger.debug(f"Could not parse investigation_data: {e}")
                elif alert_iocs:
                    # Compact IOCs from alert_data
                    ioc_strs = [f"{i.get('type','?')}:{i.get('value', i.get('indicator', '?'))[:30]}" for i in alert_iocs[:3]]
                    context_info += f"IOCs: {', '.join(ioc_strs)}" + (f" (+{len(alert_iocs)-3} more)" if len(alert_iocs) > 3 else "") + "\n"

                # Fetch campaign/correlation context
                try:
                    async with postgres_db.tenant_acquire() as conn:
                        # Get campaigns this investigation belongs to
                        campaign_rows = await conn.fetch(
                            """
                            SELECT c.campaign_id, c.name, c.campaign_type, c.severity,
                                   c.alert_count, c.status
                            FROM campaign_members cm
                            JOIN campaigns c ON c.id = cm.campaign_id
                            WHERE cm.investigation_id = $1 AND cm.member_type = 'investigation'
                            ORDER BY c.alert_count DESC
                            LIMIT 3
                            """,
                            inv['id']
                        )

                        if campaign_rows:
                            camp_strs = []
                            for cr in campaign_rows:
                                camp_strs.append(f"{cr['campaign_id']}({cr['campaign_type']},{cr['severity']},{cr['alert_count']}alerts)")
                            context_info += f"Campaigns: {', '.join(camp_strs)}\n"

                        # Get related alerts from same campaigns
                        if campaign_rows and inv.get('alert_id'):
                            related = await conn.fetch(
                                """
                                SELECT DISTINCT a.title, a.severity
                                FROM campaign_members cm
                                JOIN campaigns c ON c.id = cm.campaign_id
                                JOIN alerts a ON a.id = cm.alert_id
                                WHERE c.campaign_id = ANY($1)
                                  AND cm.member_type = 'alert'
                                  AND a.id != $2
                                LIMIT 3
                                """,
                                [cr['campaign_id'] for cr in campaign_rows],
                                inv['alert_id']
                            )
                            if related:
                                rel_strs = [f"{r['title'][:40]}({r['severity']})" for r in related]
                                context_info += f"Related: {'; '.join(rel_strs)}\n"

                except Exception as camp_err:
                    logger.debug(f"Campaign context fetch failed: {camp_err}")

            # Fetch tenant's connected integrations so Riggs knows what tools are available
            try:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id()
                if _tid:
                    async with postgres_db.tenant_acquire() as conn:
                        int_rows = await conn.fetch(
                            """
                            SELECT c.name, c.category, c.vendor, i.status
                            FROM connect_instances i
                            JOIN connector_definitions c
                              ON c.id = i.connector_id
                              AND (c.tenant_id IS NULL OR c.tenant_id = i.tenant_id)
                            WHERE i.tenant_id = $1
                            ORDER BY c.category, c.name
                            """,
                            uuid.UUID(_tid),
                        )
                    if int_rows:
                        active = [r for r in int_rows if r['status'] in ('healthy', 'active', 'connected')]
                        if active:
                            int_list = ", ".join(f"{r['name']} ({r['category']})" for r in active)
                            context_info += f"Connected integrations: {int_list}\n"
                        else:
                            context_info += "Connected integrations: None active\n"
                    else:
                        context_info += "Connected integrations: None configured\n"
            except Exception as int_err:
                logger.debug(f"Integration context fetch failed: {int_err}")

            # Get recent chat history for context (excluding the current message we just sent)
            # Fetch enough messages to preserve full conversation context (10 exchanges)
            recent_messages = await chat_service.get_messages(
                investigation_id=investigation_id,
                limit=30
            )

            # The current message was just saved to DB and will be the last item
            # in the chronological list. Remove it by position (not content match)
            # so we don't accidentally skip earlier messages with the same text
            # (e.g. user saying "sure" twice in a conversation).
            if (recent_messages
                    and recent_messages[-1].get('sender_type', '') == 'human'
                    and recent_messages[-1].get('message', '').strip() == user_message):
                recent_messages = recent_messages[:-1]

            # Build chat history with proper role alternation
            # LLMs require strict user/assistant/user/assistant alternation
            chat_history = []
            last_role = None

            for msg in recent_messages:
                msg_content = msg.get('message', '').strip()
                sender_type = msg.get('sender_type', '')

                # Skip empty messages and system messages
                if not msg_content or sender_type == 'system':
                    continue

                # Determine role: agent messages = assistant, human messages = user
                if sender_type.startswith('agent'):
                    role = "assistant"
                else:
                    role = "user"

                # Ensure alternation - if same role as last, merge or skip
                if role == last_role:
                    # Merge consecutive messages from same role
                    if chat_history:
                        chat_history[-1]["content"] += "\n\n" + msg_content
                    continue

                chat_history.append({
                    "role": role,
                    "content": msg_content
                })
                last_role = role

            # Keep last 20 messages for context (10 exchanges)
            # Enough to preserve full conversation flow so Riggs remembers
            # its own suggestions and the analyst's responses
            chat_history = chat_history[-20:]

            # Ensure proper alternation for LLM:
            # 1. History must START with user (after system prompt)
            # 2. History must NOT end with user (since we're about to add one)
            while chat_history and chat_history[0]["role"] == "assistant":
                chat_history = chat_history[1:]

            while chat_history and chat_history[-1]["role"] == "user":
                chat_history = chat_history[:-1]

            # Determine tier FIRST (before building prompt that uses it)
            highest_tier = 1
            agent_tier_name = "T1"
            inv_data_parsed = {}
            if inv and inv.get('investigation_data'):
                try:
                    inv_data_parsed = inv['investigation_data'] if isinstance(inv['investigation_data'], dict) else json.loads(inv['investigation_data'])
                    if inv_data_parsed.get('tier3_analysis'):
                        highest_tier = 3
                        agent_tier_name = "T3"
                    elif inv_data_parsed.get('tier2_analysis'):
                        highest_tier = 2
                        agent_tier_name = "T2"
                    elif inv_data_parsed.get('tier1_analysis'):
                        highest_tier = 1
                        agent_tier_name = "T1"
                except Exception as e:
                    logger.warning(f"Could not parse investigation_data for tier detection: {e}")

            # Build dynamic greeting example based on investigation data
            inv_severity = (inv.get('severity') or 'unknown') if inv else 'unknown'
            inv_title_short = ((inv.get('title') or 'this alert') if inv else 'this alert')[:60]

            # Get T1 verdict for greeting if available
            t1_verdict_info = ""
            if inv_data_parsed.get('tier1_analysis'):
                t1_v = inv_data_parsed['tier1_analysis'].get('verdict', '')
                if t1_v:
                    t1_verdict_info = f" Our T1 analysis shows this is **{t1_v}**."

            # Detect if this is a greeting message (broader detection)
            user_msg_lower = user_message.lower().strip().rstrip('!?.')
            greeting_words = ['hi', 'hey', 'hello', 'yo', 'sup', 'hiya', 'howdy', 'whats up', "what's up", 'wassup', 'greetings', 'good morning', 'good afternoon', 'good evening']
            is_greeting = user_msg_lower in greeting_words or any(user_msg_lower.startswith(g + ' ') for g in greeting_words)

            # Build the system context
            system_context = f"""You are Riggs, {username}'s security analyst partner. You work WITH them, not FOR them - you're teammates.

CRITICAL PERSONALITY RULES:
- You are ACTION-ORIENTED. When {username} asks you to do something, you DO IT immediately using your tools
- NEVER give procedural pushback like "I can't reopen it because..." or "Why we can't do that..."
- NEVER question or second-guess the analyst's judgment. They're the expert - you EXECUTE their decisions
- If they say "change to true positive" - you use update_disposition immediately
- If they say "reopen this" - you use reopen_investigation immediately
- If they say "close it" - you use close_investigation immediately
- Be brief and action-focused. Don't lecture or explain why something can't be done - MAKE IT HAPPEN

ALERT CONTEXT:
{context_info}

INTEGRATION AWARENESS (CRITICAL):
The "Connected integrations" line in the alert context above shows what tools this tenant actually has.
- ONLY offer to perform actions that the connected integrations support.
- If there is no SIEM, log management, or EDR integration connected, do NOT offer to "search logs" or "look up events" — you physically cannot.
- If there is no threat intel integration, do NOT offer to "check threat feeds" — you cannot.
- You CAN always: analyze the alert data already present, use investigation tools (close, update, note, search_investigation_alerts), and provide your expert opinion.
- When the tenant has limited integrations, focus your recommendations on what they CAN do (e.g., "Based on what we have here..." or "I'd recommend checking your EDR console for...") rather than offering to do things you can't.
- It's fine to RECOMMEND the analyst check something manually in their tools, just don't offer to do it yourself unless you have the integration.
- INTEGRATION SUGGESTION: When you hit a gap where a missing integration would help, briefly mention it once per conversation. Keep it natural and helpful, not salesy. Examples:
  * "I can't search your SIEM logs directly, but if you connect your Splunk instance to T1 I'd be able to pull those events for you in real time."
  * "Right now I can only work with the alert data we have. Connecting your CrowdStrike EDR would let me dig into process trees and lateral movement for you."
  * "I'd love to check that hash reputation but we don't have a threat intel feed connected. Hook up VirusTotal in **Settings > Connect** and I can do that automatically."
  Keep it to ONE suggestion per conversation — don't nag. Frame it as unlocking YOUR capability, not selling a feature.

YOUR RESPONSE RULES:
1. ONLY use tools when the analyst EXPLICITLY asks you to take action
2. Discussing or agreeing with something is NOT a request to change it
3. If they say "this looks benign" - just AGREE, don't change disposition unless they say "change it" or "mark it"
4. Reference specific details from the alert when relevant
5. Use markdown formatting: **bold** for emphasis, `code` for technical values
6. Keep responses SHORT - answer their question, don't take unsolicited actions
7. NEVER output raw JSON or code blocks with tool results - summarize findings in clean bullet points
8. When analyzing alerts, present findings as a readable summary, NOT as JSON dumps

DISPOSITION TERMINOLOGY (IMPORTANT):
- FALSE_POSITIVE: The alert fired but there was NO actual threat - it was a mistake/benign activity
- TRUE_POSITIVE: The alert correctly identified a REAL threat that needs response
- BENIGN: Activity is harmless/safe - similar to false_positive
- MALICIOUS: Confirmed threat/attack

If activity is "safe" or "benign" = FALSE_POSITIVE (no real threat)
If activity is a "real threat" or "attack" = TRUE_POSITIVE

YOUR TOOLS (USE THEM!):
- close_investigation: Close with disposition (false_positive, benign, true_positive, malicious, etc.)
- update_disposition: Change verdict/disposition without closing
- update_priority: Change priority (P1-P4)
- add_investigation_note: Record a finding or note
- reopen_investigation: Reopen a closed case for more analysis
- override_analysis: Override T1 analysis with YOUR assessment AND confidence score
  * This changes BOTH the disposition AND the confidence percentage!
  * Use when analyst wants to change the suspicious/confidence % or override T1 verdict
  * Example: override_analysis(new_disposition="false_positive", new_confidence=0.95, override_reason="...")
- search_logs: Search security logs to find related events or investigate IOCs
  * Query syntax: host:name, user:root, process:sshd, wildcards (*), AND/OR/NOT
  * Examples: "host:webserver AND process:python", "src_ip:192.168.1.*", "action:*login* AND NOT user:admin"
  * Use when analyst asks about activity, wants to find related events, or investigate an IP/user/host
- get_investigation_summary: Get a summary of this investigation including alert count, key entities, and metrics
  * Use when asked "how many alerts?", "what entities?", "summarize this investigation"
- search_investigation_alerts: Search and retrieve FULL alert details from this investigation
  * Returns complete alert data: raw_event, entities, AI analysis, MITRE techniques, correlation reasons
  * CRITICAL: USE THIS PROACTIVELY when analyst asks:
    - "what do the alerts have in common?" -> search_investigation_alerts() to get all alerts, then analyze patterns
    - "what patterns do you see?" -> search_investigation_alerts() to retrieve alerts and identify commonalities
    - "show me the alerts" -> search_investigation_alerts() to get full alert details
    - "are these related?" -> search_investigation_alerts() to compare entities and techniques
    - Any question about alert CONTENT, patterns, or relationships requires this tool!

WHEN TO USE TOOLS - on explicit requests OR analyst approval:
- "change to true positive" -> update_disposition(disposition="true_positive")
- "mark it as malicious" -> update_disposition(disposition="malicious")
- "close it as FP" -> close_investigation(disposition="false_positive")
- "reopen this" -> reopen_investigation()
- "mark it benign and close" -> close_investigation(disposition="benign")
- "change the percentage" / "change the confidence" -> Ask what they think it should be, then use override_analysis
- "this should be false positive at 95%" -> override_analysis(new_disposition="false_positive", new_confidence=0.95, ...)
- "search for activity from this IP" -> search_logs(query="src_ip:x.x.x.x OR dst_ip:x.x.x.x")
- "what else did this user do" -> search_logs(query="user:username")
- "show me events from that host" -> search_logs(query="host:hostname")
- "find related network connections" -> search_logs(query="source:edr_network AND host:hostname")
- "what do the alerts have in common?" -> search_investigation_alerts() then analyze the shared users/hosts/techniques
- "what patterns do you see?" -> search_investigation_alerts() then identify commonalities in the alert data
- "are these alerts related?" -> search_investigation_alerts() then compare entities across alerts
- "summarize the alerts" -> search_investigation_alerts() then provide analysis
- "how many alerts?" -> get_investigation_summary() for quick count and breakdown

CRITICAL - AFFIRMATIVE RESPONSES HANDLING:
When you suggest a SINGLE SPECIFIC action (like "Should we change it to false_positive?") and the analyst responds with:
- "yeah", "yes", "yep", "sure", "do it", "go ahead", "ok", "okay", "sounds good", "agreed", "correct", "right"
This means they are APPROVING your suggestion - USE THE TOOL IMMEDIATELY!

Example flow:
You: "T1 flagged www.w3.org as suspicious but that's just HTML namespace. I think this is a false positive. Should I override?"
Analyst: "yeah"
You: [USE override_analysis tool with your recommendation] -> "Done! I've overridden..."

DO NOT just acknowledge and ask again! When they say "yeah" after you suggest something, EXECUTE IT.

CRITICAL - AMBIGUOUS SUGGESTIONS REQUIRE CLARIFICATION:
If you gave the analyst MULTIPLE options (like "A or B?") and they respond with just "yes" or "yes please":
- DO NOT assume which option they meant!
- DO NOT pick the destructive option (like closing an investigation)
- ASK them to clarify: "Sure! Did you want me to search the logs, or close the investigation?"
- ALWAYS default to the INVESTIGATION option when unclear - analysts want to investigate, not close

Example of WRONG behavior:
You: "Would you like me to search the logs or close the investigation?"
Analyst: "yes please"
You: [CLOSES INVESTIGATION] <- WRONG! You don't know which option they wanted!

Example of CORRECT behavior:
You: "Would you like me to search the logs or close the investigation?"
Analyst: "yes please"
You: "Sure! Which would you prefer - searching the logs for more evidence, or closing this investigation?"

WHEN NOT TO USE TOOLS - just have a conversation:
- "this looks benign" -> Agree, DON'T change anything
- "none of them were malicious" -> Acknowledge, DON'T change disposition
- "why is this suspicious?" -> Explain, DON'T take action
- "what do you think?" -> Give YOUR OWN opinion based on the email content, DON'T take action
- "which IOCs were suspicious?" -> Answer the question, DON'T add notes
- Any question or observation -> Just ANSWER it, don't add notes or change things

CRITICAL - WHEN ASKED FOR YOUR OPINION:
When the analyst asks "what do you think?", "do you agree?", "is this really malicious?", etc:
- Actually READ the email body/content and THINK about it
- Form YOUR OWN opinion - don't just repeat what T1 said
- T1 analysis can be WRONG - you should critically evaluate their findings
- Be specific: reference actual content from the email, not just metadata
- Common false positive patterns to recognize:
  * http://www.w3.org/1999/xhtml = HTML namespace (NOT a real IOC!)
  * Truncated URLs like "sendgrid.n" = just display truncation
  * High IOC count from legitimate marketing emails = normal
  * 2FA/verification codes from known providers = benign
- If T1 flagged something dumb, SAY SO: "T1 flagged www.w3.org/1999/xhtml as suspicious, but that's just an HTML namespace, not a real threat."

CRITICAL - BE PROACTIVE ABOUT FIXING BAD ANALYSIS:
If you review the alert and determine T1 got it wrong:
- Don't just explain what you found - RECOMMEND a specific action
- Say something like: "I've reviewed this and T1 got it wrong. The IOCs are benign HTML namespaces. **Should I override to false_positive?**"
- When the analyst agrees ("yes", "do it", "yeah"), USE override_analysis or update_disposition immediately

YOU ARE RIGGS - THE HUMAN-AI COLLABORATION LAYER:
As the human-AI collaboration layer, YOU have authority to recommend changes.
- If T1 says SUSPICIOUS but you see it's actually benign → recommend override
- If T1 says MALICIOUS but evidence doesn't support it → recommend override
- Don't be passive! Be assertive about your analysis and offer to fix incorrect verdicts
- The analyst shouldn't have to ask "can you change it?" - YOU should offer!

CRITICAL: Do NOT use add_investigation_note unless they explicitly say "add a note" or "record this"
CRITICAL: Do NOT use update_disposition unless they explicitly say "change", "mark", or "update"

LEARNING FROM MISTAKES:
When you identify a pattern that caused a false positive (like www.w3.org/1999/xhtml being flagged), you CAN offer to save this as an insight for future analysis.

If the analyst asks "how do we prevent this?" or "can you learn from this?" or "remember this for next time":
- Use save_analyst_insight to record the pattern
- Example: save_analyst_insight(insight_type="false_positive_indicator", subject="www.w3.org/1999/xhtml", insight="This is an HTML namespace declaration, not a real IOC. Should never be flagged as suspicious.", is_safe=true)

You can also OFFER to save insights after closing an investigation where you identified a pattern, like:
"Done! I closed it as false_positive. Want me to save an insight about the www.w3.org namespace so I remember it's benign for future alerts?"

"""

            # Add specific greeting instruction if this is a greeting
            if is_greeting:
                # Get more specific context for greeting
                t2_verdict = ""
                if inv_data_parsed.get('tier2_analysis'):
                    t2_v = inv_data_parsed['tier2_analysis'].get('verdict', '')
                    t2_conf = inv_data_parsed['tier2_analysis'].get('confidence', 0)
                    t2_summary = inv_data_parsed['tier2_analysis'].get('summary', '')[:100]
                    if t2_v:
                        t2_verdict = f"T2 analysis verdict: **{t2_v}** ({t2_conf}% confidence). {t2_summary}"

                system_context += f"""
*** CRITICAL INSTRUCTION - READ CAREFULLY ***
The user said "{user_message}" - this is a greeting. You MUST NOT respond with generic phrases like:
- "How can I help you?"
- "What can I assist you with?"
- "How can I assist you with this alert?"

INSTEAD, respond with SPECIFIC details from the ALERT CONTEXT above. Your response MUST include:
1. A brief greeting to {username}
2. The alert subject/title: {inv_title_short}
3. The current verdict/status: {t2_verdict or t1_verdict_info or 'Pending analysis'}
4. One specific finding from the investigation data

GOOD EXAMPLE:
"Hey {username}! Looking at this Webull phishing report - T2 analysis came back **benign** with 95% confidence. The sender domain webull.com is legitimate and all links check out. Safe to close as false positive unless you spotted something I missed."

BAD EXAMPLE (DO NOT DO THIS):
"Hey! How can I assist you with this alert?"

*** END CRITICAL INSTRUCTION ***
"""

            # Build messages - Gemma requires strict user/assistant alternation
            # without system messages, so we embed system context in first user message
            messages = []

            # ALWAYS include system context with the current message
            # The context contains the actual investigation data the model MUST use
            # Previously we only included it when there was no history, which caused
            # the model to hallucinate/speculate when responding to follow-up questions
            current_message_with_context = f"""{system_context}

User question: {user_message}

Remember: Answer ONLY based on the investigation data provided above. Do not make up any IOCs, domains, IPs, or findings."""

            messages.extend(chat_history)
            messages.append({"role": "user", "content": current_message_with_context})

            # Debug: show context info being sent
            print(f"[CHAT] Context length: {len(context_info)} chars, is_greeting={is_greeting}")
            if is_greeting:
                print(f"[CHAT] Greeting detected - inv_title: {inv_title_short[:40]}")

            # Call LLM using configured AI provider
            executor = AgentExecutor()
            await executor.initialize()

            # Check license limits and cap tier if needed (tier already determined above)
            try:
                from services.licensing.entitlement_service import get_entitlement_service
                ent_service = get_entitlement_service()
                entitlements = await ent_service.get_current_entitlements()
                if entitlements:
                    agents_ent = entitlements.agents
                    # Cap tier based on license
                    if highest_tier == 3 and agents_ent.runs_per_month_tier3 <= 0:
                        highest_tier = 2
                        agent_tier_name = "T2"
                        logger.info("License doesn't include T3 agents, falling back to T2")
                    if highest_tier == 2 and agents_ent.runs_per_month_tier2 <= 0:
                        highest_tier = 1
                        agent_tier_name = "T1"
                        logger.info("License doesn't include T2 agents, falling back to T1")
            except Exception as e:
                logger.warning(f"Could not check license entitlements: {e}")

            # Get the default provider to use its configured model
            provider = await executor.get_ai_provider(None)  # None gets default

            # For chat, prefer chat_model if configured, otherwise fall back to tier model
            model_name = None
            if provider:
                # First try chat_model (specific model for conversational chat)
                model_name = provider.get('chat_model')

                # If no chat model, fall back to tier-specific model
                if not model_name:
                    tier_model_key = f'tier{highest_tier}_model'
                    model_name = provider.get(tier_model_key) or provider.get('tier1_model') or provider.get('selected_model')

                # Last resort: use first available model
                if not model_name:
                    models = provider.get('models') or []  # Handle None explicitly
                    if models and len(models) > 0:
                        model_name = models[0].get('id') if isinstance(models[0], dict) else models[0]

            using_chat_model = provider and provider.get('chat_model') == model_name
            logger.info(f"Chat using {'dedicated chat model' if using_chat_model else f'{agent_tier_name} model'}: {model_name}")

            model_config = {
                'model': model_name or 'default',
                'temperature': 0.3,
                'max_tokens_per_task': 2048,
                'skip_tier_override': True,  # Don't let call_llm override with tier-specific model
                'severity': 'chat',  # Chat priority = 0, preempts T2 investigations
                'request_type': 'riggs_chat'  # Track for monthly usage limits
            }

            logger.info(f"Chat AI calling LLM with model: {model_config['model']}")
            # Debug: log context size to verify data is being included
            context_preview = context_info[:500] if context_info else "NO CONTEXT"
            logger.info(f"Chat context size: {len(context_info)} chars, preview: {context_preview}...")

            # Pass tools so Riggs can take action
            response = await executor.call_llm(
                messages=messages,
                model_config=model_config,
                tools=RIGGS_CHAT_TOOLS
            )

            # Check if Riggs wants to use a tool
            tool_calls = response.get('tool_calls', [])
            if not tool_calls and response.get('choices'):
                # Check OpenAI format
                msg = response['choices'][0].get('message', {})
                tool_calls = msg.get('tool_calls', [])

            # Execute any tool calls
            tool_results = []
            if tool_calls:
                logger.info(f"[CHAT] Riggs requested {len(tool_calls)} tool(s)")
                for tc in tool_calls:
                    # Handle different formats
                    if isinstance(tc, dict):
                        func = tc.get('function', tc)
                        tool_name = func.get('name', '')
                        try:
                            tool_args = json.loads(func.get('arguments', '{}')) if isinstance(func.get('arguments'), str) else func.get('arguments', {})
                        except Exception as e:
                            logger.warning(f"Failed to parse tool arguments for {tool_name}: {e}")
                            tool_args = {}
                    else:
                        continue

                    if tool_name:
                        logger.info(f"[CHAT] Executing tool: {tool_name} with args: {tool_args} (user_role={user_role})")
                        result = await execute_chat_tool(
                            tool_name=tool_name,
                            tool_args=tool_args,
                            investigation_id=investigation_id,
                            user_id=user_id,
                            username=username,
                            user_role=user_role  # RBAC enforcement
                        )
                        tool_results.append({
                            "tool": tool_name,
                            "result": result
                        })

                        # Broadcast the tool action result
                        if result.get('success'):
                            await self.manager.broadcast(investigation_id, {
                                'type': 'investigation_updated',
                                'action': tool_name,
                                'data': result.get('data', {}),
                                'message': result.get('message', '')
                            })
                        elif result.get('rbac_denied'):
                            # Broadcast RBAC denial so Riggs can inform the user
                            await self.manager.broadcast(investigation_id, {
                                'type': 'permission_denied',
                                'action': tool_name,
                                'message': result.get('message', 'Permission denied')
                            })

            # Clear typing indicator
            await chat_service.clear_typing(investigation_id, 'ai_assistant')
            await self.manager.broadcast(investigation_id, {
                'type': 'typing_update',
                'user_id': 'ai_assistant',
                'user_name': 'Riggs',
                'is_typing': False,
                'is_agent': True,
                'tier': highest_tier
            })

            if response.get('error'):
                # Send error message
                error_result = await chat_service.send_message(
                    investigation_id=investigation_id,
                    sender_type='agent_t1',  # Valid constraint: agent_t1, agent_t2, agent_t3
                    sender_id='ai_assistant',
                    sender_name='Riggs',
                    message=f"I ran into an issue: {response.get('error')}",
                    message_type='error'
                )
                if error_result['success']:
                    await self.manager.broadcast(investigation_id, {
                        'type': 'new_message',
                        'message': error_result['message']
                    })
                return

            # Extract response content
            # Use `or ''` to handle None values (response.get default only applies when key missing)
            ai_content = response.get('content') or ''
            if not ai_content and response.get('choices'):
                ai_content = response['choices'][0].get('message', {}).get('content') or ''

            # Strip whitespace and detect empty/useless JSON-like responses
            # Some models output {} or [] when they have nothing to say
            ai_content = ai_content.strip() if ai_content else ''
            if ai_content in ['{}', '[]', 'null', '""', "''", '{""}', "{''}"] or not ai_content:
                ai_content = ''  # Treat as empty, will be handled below

            # If tools were executed, build response from tool results
            if tool_results and not ai_content:
                # Model used tools but didn't provide text - generate response from tool results
                tool_messages = []
                for tr in tool_results:
                    if tr['result'].get('success'):
                        tool_messages.append(tr['result']['message'])
                    else:
                        tool_messages.append(f"Failed to {tr['tool']}: {tr['result'].get('message', 'Unknown error')}")
                ai_content = "\n".join(tool_messages) if tool_messages else "Action completed."
            elif tool_results and ai_content:
                # Model provided text AND used tools - append tool results
                tool_messages = [tr['result']['message'] for tr in tool_results if tr['result'].get('success')]
                if tool_messages:
                    ai_content += "\n\n**Actions taken:** " + "; ".join(tool_messages)

            # Fallback: If still no content after tool handling, provide a meaningful response
            if not ai_content:
                logger.warning(f"[CHAT] No AI content generated for message: '{user_message[:50]}...'")
                ai_content = "I wasn't able to generate a response to that. Could you please rephrase your question or provide more context about what you'd like to know about this investigation?"

            # =====================================================================
            # OUTPUT GUARDRAILS - Filter AI response before sending to user
            # =====================================================================
            if ai_content:
                output_result = guardrails.filter_output(ai_content, user_id, investigation_id)

                if not output_result.allowed:
                    # Output completely blocked - replace with safe message
                    print(f"[CHAT GUARDRAIL] Output blocked: {output_result.reason}")
                    ai_content = "I generated a response that was filtered for safety reasons. Please rephrase your question or ask about a different aspect of this investigation."
                elif output_result.sanitized_content:
                    # Output was sanitized (e.g., secrets/PII redacted)
                    print(f"[CHAT GUARDRAIL] Output sanitized, redactions: {output_result.redactions}")
                    ai_content = output_result.sanitized_content

            if ai_content:
                # Save AI response to chat with correct tier
                sender_type = f'agent_t{highest_tier}'  # e.g., agent_t1, agent_t2, agent_t3
                ai_result = await chat_service.send_message(
                    investigation_id=investigation_id,
                    sender_type=sender_type,
                    sender_id='ai_assistant',
                    sender_name='Riggs',
                    message=ai_content,
                    message_type='text'
                )

                if ai_result['success']:
                    await self.manager.broadcast(investigation_id, {
                        'type': 'new_message',
                        'message': ai_result['message']
                    })

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error getting AI response: {error_msg}", exc_info=True)
            print(f"[CHAT ERROR] AI response failed: {error_msg}")  # Direct print for visibility

            # Clear typing indicator on error
            try:
                chat_service = get_chat_service()
                await chat_service.clear_typing(investigation_id, 'ai_assistant')
                await self.manager.broadcast(investigation_id, {
                    'type': 'typing_update',
                    'user_id': 'ai_assistant',
                    'is_typing': False,
                    'is_agent': True
                })

                # Send error message to chat so user can see what happened
                error_result = await chat_service.send_message(
                    investigation_id=investigation_id,
                    sender_type='agent_t1',  # Valid constraint: agent_t1, agent_t2, agent_t3
                    sender_id='ai_assistant',
                    sender_name='Riggs',
                    message=f"I encountered an error: {error_msg[:200]}",
                    message_type='error'
                )
                if error_result.get('success'):
                    await self.manager.broadcast(investigation_id, {
                        'type': 'new_message',
                        'message': error_result['message']
                    })
            except Exception as inner_e:
                print(f"[CHAT ERROR] Failed to send error message: {inner_e}")

    async def _handle_mark_read(
        self,
        investigation_id: str,
        user_id: str,
        message_id: Optional[str]
    ):
        """Mark messages as read."""
        from services.chat_service import get_chat_service

        try:
            chat_service = get_chat_service()
            await chat_service.mark_messages_read(
                investigation_id=investigation_id,
                user_id=user_id,
                up_to_message_id=message_id
            )
        except Exception as e:
            logger.error(f"Error marking messages read: {e}")

    async def _handle_get_history(
        self,
        connection_id: str,
        investigation_id: str,
        before_id: Optional[str],
        limit: int
    ):
        """Send chat history to requesting client."""
        from services.chat_service import get_chat_service

        try:
            chat_service = get_chat_service()
            messages = await chat_service.get_messages(
                investigation_id=investigation_id,
                limit=limit,
                before_id=before_id
            )

            websocket = self.manager.connections.get(investigation_id, {}).get(connection_id)
            if websocket:
                await self.manager.send_personal({
                    'type': 'chat_history',
                    'messages': messages,
                    'has_more': len(messages) == limit
                }, websocket)

        except Exception as e:
            logger.error(f"Error getting chat history: {e}")

    def _verify_token(self, token: Optional[str], websocket: Optional[WebSocket] = None) -> Optional[Dict]:
        """
        Verify JWT token and return user info.

        SECURITY: Cookie-based auth is preferred. Query param auth is deprecated
        and will be removed in a future version.
        """
        token_source = "query"  # Track where token came from

        # SECURITY: Try cookie-based auth FIRST (preferred method)
        if websocket:
            cookie_header = websocket.headers.get("cookie", "")
            if cookie_header:
                cookies = {}
                for part in cookie_header.split(";"):
                    if "=" in part:
                        key, value = part.split("=", 1)
                        cookies[key.strip()] = value.strip()
                cookie_token = cookies.get("t1_access_token")
                if cookie_token:
                    token = cookie_token
                    token_source = "cookie"

        # SECURITY: Log deprecation warning for query param tokens
        if token and token_source == "query":
            logger.warning(
                "SECURITY: WebSocket auth via query param is deprecated. "
                "Use cookie-based auth instead to prevent token leakage in logs/referrers."
            )

        if not token:
            return None

        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return {
                'sub': payload.get('sub'),
                'username': payload.get('sub'),  # Usually the same
                'role': payload.get('role'),
                'tenant_id': payload.get('tenant_id')
            }
        except jwt.ExpiredSignatureError:
            logger.debug("WebSocket token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"WebSocket invalid token: {e}")
            return None

    # =========================================================================
    # ANALYTICS TRACKING
    # =========================================================================

    async def _track_session_start(
        self,
        user_id: str,
        investigation_id: str,
        session_id: str,
        username: str
    ):
        """Track when a user opens the chat."""
        try:
            from services.chat_analytics_service import get_chat_analytics_service
            analytics = get_chat_analytics_service()
            await analytics.track_session_start(
                user_id=user_id,
                investigation_id=investigation_id,
                session_id=session_id,
                username=username
            )
        except Exception as e:
            logger.debug(f"Analytics tracking error (session start): {e}")

    async def _track_session_end(
        self,
        user_id: str,
        investigation_id: str,
        session_id: str
    ):
        """Track when a user closes the chat."""
        try:
            from services.chat_analytics_service import get_chat_analytics_service
            analytics = get_chat_analytics_service()
            await analytics.track_session_end(
                user_id=user_id,
                investigation_id=investigation_id,
                session_id=session_id
            )
        except Exception as e:
            logger.debug(f"Analytics tracking error (session end): {e}")

    async def _track_message_sent(
        self,
        user_id: str,
        investigation_id: str,
        message: str,
        message_type: str = 'text',
        session_id: Optional[str] = None,
        username: Optional[str] = None
    ):
        """Track when a user sends a message."""
        try:
            from services.chat_analytics_service import get_chat_analytics_service
            analytics = get_chat_analytics_service()
            await analytics.track_message_sent(
                user_id=user_id,
                investigation_id=investigation_id,
                message_type=message_type,
                message_length=len(message),
                session_id=session_id,
                username=username
            )
        except Exception as e:
            logger.debug(f"Analytics tracking error (message): {e}")


# Register chat service handler callback
async def on_chat_message(investigation_id: str, message: Dict):
    """
    Callback for chat service to broadcast messages.
    This is called when agents or system send messages.
    """
    event_type = message.get('_event')

    if event_type == 'message_deleted':
        await manager.broadcast(investigation_id, {
            'type': 'message_deleted',
            'message_id': message.get('id')
        })
    elif event_type == 'message_updated':
        await manager.broadcast(investigation_id, {
            'type': 'message_updated',
            'message': {k: v for k, v in message.items() if not k.startswith('_')}
        })
    elif event_type == 'typing_start':
        await manager.broadcast(investigation_id, {
            'type': 'typing_indicator',
            'user_id': message.get('user_id'),
            'user_name': message.get('user_name'),
            'is_typing': True,
            'is_agent': message.get('is_agent', False)
        })
    elif event_type == 'typing_stop':
        await manager.broadcast(investigation_id, {
            'type': 'typing_indicator',
            'user_id': message.get('user_id'),
            'is_typing': False
        })
    else:
        # New message
        await manager.broadcast(investigation_id, {
            'type': 'new_message',
            'message': message
        })


# Chat websocket instance
chat_websocket = ChatWebSocket()
