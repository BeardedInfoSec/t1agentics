# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Built-in API Documentation
Interactive documentation with examples and testing capabilities.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from dependencies.auth import get_current_user
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/docs/interactive", tags=["documentation"])


# API Documentation Data
API_DOCS = {
    "authentication": {
        "title": "Authentication & Authorization",
        "description": "T1 Agentics uses JWT tokens and API keys for authentication with role-based access control.",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/v1/admin/login",
                "summary": "Login with username and password",
                "description": "Authenticate and receive a JWT token set as an HTTP-only cookie. Supports multi-tenant login via the tenant slug field. Account locks after 3 failed attempts for 10 minutes.",
                "request_body": {
                    "username": "analyst@company.com",
                    "password": "your-password",
                    "tenant": "your-org-slug"
                },
                "response_example": {
                    "username": "analyst@company.com",
                    "role": "user",
                    "tenant_id": "550e8400-...",
                    "tenant_name": "Acme Corp",
                    "license_tier": "professional"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/login \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"username\":\"analyst@company.com\",\"password\":\"your-password\",\"tenant\":\"acme-corp\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/verify-mfa",
                "summary": "Verify MFA code",
                "description": "Complete login by verifying a TOTP code when MFA is enabled. Called after login returns mfa_required=true.",
                "request_body": {
                    "mfa_token": "eyJhbGc...",
                    "code": "123456"
                },
                "response_example": {
                    "username": "analyst@company.com",
                    "role": "user",
                    "mfa_verified": True
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/verify-mfa \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"mfa_token\":\"eyJhbGc...\",\"code\":\"123456\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/logout",
                "summary": "Logout and clear session",
                "description": "Clear authentication cookies and end the session.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/logout \\\n  -b cookies.txt"
            },
            {
                "method": "GET",
                "path": "/api/v1/users/me",
                "summary": "Get current user info",
                "description": "Get information about the currently authenticated user including role, tenant, and license tier.",
                "response_example": {
                    "username": "analyst@company.com",
                    "role": "user",
                    "tenant_id": "550e8400-...",
                    "license_tier": "professional"
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/users/me \\\n  -H \"Authorization: Bearer YOUR_JWT_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/password-change",
                "summary": "Change password",
                "description": "Change the current user's password. Requires the current password for verification.",
                "request_body": {
                    "current_password": "old-password",
                    "new_password": "new-secure-password"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/password-change \\\n  -H \"Content-Type: application/json\" \\\n  -H \"Authorization: Bearer YOUR_JWT_TOKEN\" \\\n  -d '{\"current_password\":\"old\",\"new_password\":\"new\"}'"
            }
        ]
    },
    "work_queue": {
        "title": "Security Event Queue",
        "description": "The unified security event queue for ingesting, triaging, and managing alerts. This is the primary interface for SOC analysts.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/work-queue",
                "summary": "List alerts in the queue",
                "description": "List alerts with filtering by severity, status, assignment, source, and date range. Supports pagination via limit and offset.",
                "response_example": {
                    "items": [
                        {
                            "id": "550e8400-...",
                            "title": "Suspicious PowerShell Execution",
                            "severity": "critical",
                            "status": "new",
                            "source": "crowdstrike",
                            "created_at": "2026-02-12T08:30:00Z",
                            "ai_triage": {"verdict": "true_positive", "confidence": 0.92}
                        }
                    ],
                    "total": 142,
                    "limit": 25,
                    "offset": 0
                },
                "curl_example": "curl \"https://your-instance.t1agentics.ai/api/v1/work-queue?severity=critical&limit=25\" \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/work-queue/{alert_id}",
                "summary": "Get alert details",
                "description": "Get full details for a specific alert including enrichment results, MITRE mappings, AI triage output, and timeline events.",
                "response_example": {
                    "id": "550e8400-...",
                    "title": "Suspicious PowerShell Execution",
                    "severity": "critical",
                    "status": "in_progress",
                    "enrichments": {"iocs_found": 3, "mitre_techniques": ["T1059.001"]},
                    "ai_triage": {"verdict": "true_positive", "confidence": 0.92, "summary": "..."}
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/work-queue/550e8400-... \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "PUT",
                "path": "/api/v1/work-queue/{alert_id}",
                "summary": "Update alert",
                "description": "Update alert fields such as status, severity, assignment, notes, or custom tags.",
                "request_body": {
                    "status": "in_progress",
                    "assigned_to": "analyst@company.com",
                    "notes": "Investigating lateral movement"
                },
                "curl_example": "curl -X PUT https://your-instance.t1agentics.ai/api/v1/work-queue/550e8400-... \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"status\":\"in_progress\",\"assigned_to\":\"analyst@company.com\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/work-queue/{alert_id}/triage",
                "summary": "AI-assisted triage",
                "description": "Trigger Riggs AI triage on an alert. Analyzes the alert, enriches IOCs, and returns a verdict with confidence score and recommended actions.",
                "response_example": {
                    "verdict": "true_positive",
                    "confidence": 0.92,
                    "summary": "High-confidence credential theft followed by lateral movement.",
                    "recommended_actions": ["Isolate host", "Reset credentials", "Check adjacent systems"]
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/work-queue/550e8400-.../triage \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/work-queue/{alert_id}/close",
                "summary": "Close alert",
                "description": "Close an alert with a resolution status (true_positive, false_positive, benign, duplicate) and optional analyst notes.",
                "request_body": {
                    "resolution": "false_positive",
                    "notes": "Approved admin activity"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/work-queue/550e8400-.../close \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"resolution\":\"false_positive\",\"notes\":\"Approved admin activity\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/alerts/ingest",
                "summary": "Ingest alert (async)",
                "description": "Submit an alert for async processing. The investigation runs in background.",
                "request_body": {
                    "title": "Suspicious Login Attempt",
                    "description": "Multiple failed logins from 192.168.1.100",
                    "source": "auth_logs",
                    "severity": "high",
                    "metadata": {"user": "admin", "ip": "192.168.1.100", "attempts": 15}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/alerts/ingest \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"title\":\"Suspicious Login\",\"description\":\"Multiple failed logins\",\"severity\":\"high\"}'"
            }
        ]
    },
    "investigations": {
        "title": "Investigations",
        "description": "Investigations group correlated alerts into unified cases for deeper analysis. Riggs automatically creates investigations when it identifies related alerts.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/investigation-details",
                "summary": "List investigations",
                "description": "List investigations with filtering by state, priority, and owner. Returns paginated results with summary data.",
                "response_example": {
                    "items": [
                        {
                            "id": "inv-001",
                            "title": "Lateral Movement - WORKSTATION-01 to DC-02",
                            "state": "active",
                            "priority": "critical",
                            "owner": "analyst@company.com",
                            "alert_count": 5,
                            "hypothesis": "Credential theft followed by lateral movement"
                        }
                    ],
                    "total": 3,
                    "has_more": False
                },
                "curl_example": "curl \"https://your-instance.t1agentics.ai/api/v1/investigation-details?state=active&limit=10\" \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/investigation-details/{investigation_id}",
                "summary": "Get investigation details",
                "description": "Get full investigation details including correlated alerts, timeline, evidence, and AI analysis. Use ?include_alerts=true to include the full alert list.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/investigation-details/inv-001?include_alerts=true \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/investigation-details/{investigation_id}/alerts",
                "summary": "List correlated alerts",
                "description": "List all correlated alerts for an investigation with pagination and correlation scores.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/investigation-details/inv-001/alerts \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/investigate",
                "summary": "Submit alert for investigation",
                "description": "Submit a security alert and get immediate synchronous investigation results from Riggs.",
                "request_body": {
                    "title": "Suspicious Login Attempt",
                    "description": "Multiple failed logins from 192.168.1.100",
                    "source": "auth_logs",
                    "metadata": {"user": "admin", "ip": "192.168.1.100", "attempts": 15}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/investigate \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"title\":\"Suspicious Login\",\"description\":\"Multiple failed logins from 192.168.1.100\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/investigations/{id}/forward",
                "summary": "Forward investigation",
                "description": "Forward investigation results to external systems like Splunk or Elasticsearch.",
                "request_body": {
                    "integrations": ["splunk", "elasticsearch"]
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/investigations/inv-001/forward \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"integrations\":[\"splunk\"]}'"
            }
        ]
    },
    "webhooks": {
        "title": "Webhook Ingestion",
        "description": "Ingest security events from any source via webhooks. Supports JSON, XML, CSV, Syslog, CEF, LEEF, and plain text with auto-detection.",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/v1/webhooks/ingest/{webhook_name}",
                "summary": "Universal ingestion endpoint",
                "description": "Send events in any supported format. Auto-detects format or specify with X-Log-Format header. Includes deduplication, PII obfuscation, and rate limiting.",
                "request_body": {
                    "event_type": "DetectionSummaryEvent",
                    "severity": "high",
                    "hostname": "WORKSTATION-01",
                    "description": "Suspicious PowerShell activity detected"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/webhooks/ingest/crowdstrike \\\n  -H \"Authorization: HEC your-webhook-token\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"event_type\":\"DetectionSummaryEvent\",\"severity\":\"high\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/webhooks/splunk/alert",
                "summary": "Splunk webhook",
                "description": "Dedicated endpoint for Splunk alert actions.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/webhooks/splunk/alert \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"search_name\":\"Malware Detection\",\"result\":{\"_raw\":\"...\"}}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/admin/webhooks",
                "summary": "List webhooks",
                "description": "List all configured webhooks with their tokens and rate limit settings. (Admin)",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/admin/webhooks \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/webhooks",
                "summary": "Create webhook",
                "description": "Create a new webhook endpoint with a unique authentication token. (Admin)",
                "request_body": {
                    "name": "crowdstrike-prod",
                    "description": "CrowdStrike production alerts"
                },
                "response_example": {
                    "webhook_id": "crowdstrike-prod",
                    "token": "whk_abc123...",
                    "ingest_url": "/api/v1/webhooks/ingest/crowdstrike-prod"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/webhooks \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"crowdstrike-prod\",\"description\":\"CrowdStrike production alerts\"}'"
            },
            {
                "method": "DELETE",
                "path": "/api/v1/admin/webhooks/{webhook_id}",
                "summary": "Delete webhook",
                "description": "Delete a webhook and revoke its authentication token. (Admin)",
                "curl_example": "curl -X DELETE https://your-instance.t1agentics.ai/api/v1/admin/webhooks/crowdstrike-prod \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "knowledge_base": {
        "title": "Knowledge Base",
        "description": "274 built-in articles covering security procedures, response playbooks, and analyst guides. Supports semantic search via pgvector, community submissions, and Riggs AI integration.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/knowledge-base/",
                "summary": "List KB entries",
                "description": "List all knowledge base entries with filtering by category, content type, and search query.",
                "response_example": {
                    "items": [
                        {
                            "id": "kb-001",
                            "title": "Ransomware Response Playbook",
                            "category": "incident_response",
                            "content_type": "playbook",
                            "source": "builtin"
                        }
                    ],
                    "total": 274
                },
                "curl_example": "curl \"https://your-instance.t1agentics.ai/api/v1/knowledge-base/?category=incident_response&limit=20\" \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/knowledge-base/",
                "summary": "Create KB entry",
                "description": "Create a new knowledge base article. Supports markdown content with automatic embedding generation for semantic search.",
                "request_body": {
                    "title": "Custom Phishing Response SOP",
                    "content": "# Phishing Response\n\n1. Isolate the affected mailbox...",
                    "category": "incident_response",
                    "content_type": "sop",
                    "tags": ["phishing", "email"]
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/knowledge-base/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"title\":\"Custom SOP\",\"content\":\"...\",\"category\":\"incident_response\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/knowledge-base/{kb_id}",
                "summary": "Get KB entry",
                "description": "Get a specific knowledge base entry by ID with full content.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/knowledge-base/kb-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "PATCH",
                "path": "/api/v1/knowledge-base/{kb_id}",
                "summary": "Update KB entry",
                "description": "Update a knowledge base entry. Automatically creates a version checkpoint.",
                "curl_example": "curl -X PATCH https://your-instance.t1agentics.ai/api/v1/knowledge-base/kb-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"content\":\"Updated content...\"}'"
            },
            {
                "method": "DELETE",
                "path": "/api/v1/knowledge-base/{kb_id}",
                "summary": "Delete KB entry",
                "description": "Delete a knowledge base entry. Only organization-created entries can be deleted; built-in articles are read-only.",
                "curl_example": "curl -X DELETE https://your-instance.t1agentics.ai/api/v1/knowledge-base/kb-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/knowledge-base/semantic-search",
                "summary": "Semantic search",
                "description": "Search the knowledge base using natural language queries. Uses pgvector embeddings for semantic similarity matching.",
                "request_body": {
                    "query": "How do I respond to a ransomware attack?",
                    "limit": 5
                },
                "response_example": {
                    "results": [
                        {
                            "id": "kb-001",
                            "title": "Ransomware Response Playbook",
                            "similarity": 0.94,
                            "snippet": "Immediately isolate affected systems..."
                        }
                    ]
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/knowledge-base/semantic-search \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"query\":\"ransomware response steps\",\"limit\":5}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/knowledge-base/recommendations/for-alert/{alert_id}",
                "summary": "Get recommendations for alert",
                "description": "Get KB article recommendations relevant to a specific alert based on its type, IOCs, and MITRE techniques.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/knowledge-base/recommendations/for-alert/550e8400-... \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/knowledge-base/stats",
                "summary": "Get KB statistics",
                "description": "Get knowledge base statistics including total articles, categories, and usage metrics.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/knowledge-base/stats \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "connect": {
        "title": "T1 Connect",
        "description": "733 built-in connectors across 31 categories. Configure connections to SIEMs, EDR, firewalls, cloud platforms, ticketing systems, and any tool with a REST API.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/integrations",
                "summary": "List integrations",
                "description": "List all configured integrations with status and health information. Filter by type or enabled status.",
                "response_example": {
                    "integrations": [
                        {
                            "id": "int-001",
                            "name": "CrowdStrike Falcon",
                            "type": "edr",
                            "status": "connected",
                            "last_sync": "2026-02-12T10:00:00Z"
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/integrations \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/integrations",
                "summary": "Create integration",
                "description": "Create a new integration with connection parameters and credentials.",
                "request_body": {
                    "name": "CrowdStrike Falcon",
                    "type": "crowdstrike",
                    "config": {
                        "base_url": "https://api.crowdstrike.com",
                        "client_id": "your-client-id",
                        "client_secret": "your-client-secret"
                    }
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/integrations \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"CrowdStrike\",\"type\":\"crowdstrike\",\"config\":{\"base_url\":\"...\"}}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/integrations/{integration_id}",
                "summary": "Get integration details",
                "description": "Get integration details and configuration. Secrets are redacted in the response.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/integrations/int-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "PUT",
                "path": "/api/v1/integrations/{integration_id}",
                "summary": "Update integration",
                "description": "Update integration settings and connection parameters.",
                "curl_example": "curl -X PUT https://your-instance.t1agentics.ai/api/v1/integrations/int-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"config\":{\"base_url\":\"https://new-api.crowdstrike.com\"}}'"
            },
            {
                "method": "DELETE",
                "path": "/api/v1/integrations/{integration_id}",
                "summary": "Delete integration",
                "description": "Delete an integration and its stored credentials.",
                "curl_example": "curl -X DELETE https://your-instance.t1agentics.ai/api/v1/integrations/int-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/integration-config/test",
                "summary": "Test integration connection",
                "description": "Test an integration configuration for connectivity and authentication before saving.",
                "request_body": {
                    "integration_type": "crowdstrike",
                    "config": {
                        "base_url": "https://api.crowdstrike.com",
                        "client_id": "your-client-id",
                        "client_secret": "your-client-secret"
                    }
                },
                "response_example": {
                    "success": True,
                    "message": "Connection successful",
                    "latency_ms": 245
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/integration-config/test \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"integration_type\":\"crowdstrike\",\"config\":{\"base_url\":\"...\"}}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/actions/execute",
                "summary": "Execute API action",
                "description": "Execute an API action against a configured integration synchronously. Actions are logged for audit purposes.",
                "request_body": {
                    "integration_id": "int-001",
                    "action": "get_detections",
                    "parameters": {"limit": 10}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/actions/execute \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"integration_id\":\"int-001\",\"action\":\"get_detections\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/actions/history",
                "summary": "Action execution history",
                "description": "Get action execution history with filtering by integration, status, and date.",
                "curl_example": "curl \"https://your-instance.t1agentics.ai/api/v1/actions/history?limit=20\" \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "credentials": {
        "title": "Credential Vault",
        "description": "Securely store and manage credentials for integrations. All secrets are encrypted at rest with Fernet symmetric encryption.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/credentials/",
                "summary": "List credentials",
                "description": "List all stored credentials. Secret values are never returned in the response.",
                "response_example": {
                    "credentials": [
                        {
                            "id": "cred-001",
                            "name": "CrowdStrike API Key",
                            "auth_type": "oauth2_client",
                            "linked_integrations": ["int-001"]
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/credentials/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/credentials/",
                "summary": "Create credential",
                "description": "Create a new stored credential. Supports API key, basic auth, OAuth2 client credentials, bearer token, and custom header auth types.",
                "request_body": {
                    "name": "CrowdStrike API Key",
                    "auth_type": "oauth2_client",
                    "credentials": {
                        "client_id": "your-client-id",
                        "client_secret": "your-client-secret",
                        "token_url": "https://api.crowdstrike.com/oauth2/token"
                    }
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/credentials/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"CrowdStrike\",\"auth_type\":\"oauth2_client\",\"credentials\":{...}}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/credentials/{credential_id}/test",
                "summary": "Test credential",
                "description": "Test a stored credential by attempting authentication against the configured endpoint.",
                "response_example": {
                    "success": True,
                    "message": "Authentication successful",
                    "latency_ms": 180
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/credentials/cred-001/test \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "DELETE",
                "path": "/api/v1/credentials/{credential_id}",
                "summary": "Delete credential",
                "description": "Delete a stored credential. Fails if the credential is linked to active integrations.",
                "curl_example": "curl -X DELETE https://your-instance.t1agentics.ai/api/v1/credentials/cred-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/credentials/auth-types",
                "summary": "List auth types",
                "description": "List all supported authentication types with their required fields.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/credentials/auth-types \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "soar": {
        "title": "SOAR Engine",
        "description": "The Security Orchestration, Automation, and Response engine. Manage playbooks, executions, approval gates, and automated response workflows.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/playbooks/",
                "summary": "List playbooks",
                "description": "List playbooks with optional filtering by tags and enabled status.",
                "response_example": {
                    "playbooks": [
                        {
                            "id": "pb-001",
                            "name": "Ransomware Response",
                            "enabled": True,
                            "riggs_allowed": True,
                            "execution_count": 42,
                            "tags": ["ransomware", "critical"]
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/playbooks/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/",
                "summary": "Create playbook",
                "description": "Create a new playbook with trigger conditions, visual canvas data, alert type filters, and severity filters.",
                "request_body": {
                    "name": "Phishing Response",
                    "description": "Automated phishing email response workflow",
                    "trigger_conditions": {"alert_types": ["phishing"], "min_severity": "medium"},
                    "canvas_data": {}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"Phishing Response\",\"trigger_conditions\":{\"alert_types\":[\"phishing\"]}}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/{playbook_id}/execute",
                "summary": "Execute playbook",
                "description": "Execute a playbook with a trigger context. Optionally bind to an alert or investigation.",
                "request_body": {
                    "alert_id": "550e8400-...",
                    "context": {"source_ip": "203.0.113.50"}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/pb-001/execute \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"alert_id\":\"550e8400-...\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/auto-execute",
                "summary": "Auto-select and execute",
                "description": "Let Riggs auto-select the best matching playbook for an alert based on type, severity, and trigger conditions.",
                "request_body": {
                    "alert_id": "550e8400-..."
                },
                "response_example": {
                    "playbook_id": "pb-001",
                    "playbook_name": "Ransomware Response",
                    "execution_id": "exec-abc123",
                    "status": "running"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/auto-execute \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"alert_id\":\"550e8400-...\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/playbooks/executions/{execution_id}",
                "summary": "Get execution details",
                "description": "Get execution status and step-by-step results including node outputs and timing.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/playbooks/executions/exec-abc123 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/executions/{execution_id}/approve/{node_id}",
                "summary": "Approve pending action",
                "description": "Approve a pending action in a playbook that requires analyst approval before proceeding.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/executions/exec-abc123/approve/node-5 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/executions/{execution_id}/reject/{node_id}",
                "summary": "Reject pending action",
                "description": "Reject a pending action and halt the playbook execution at this step.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/executions/exec-abc123/reject/node-5 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/executions/{execution_id}/cancel",
                "summary": "Cancel execution",
                "description": "Cancel a running playbook execution.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/executions/exec-abc123/cancel \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/playbooks/marketplace/browse",
                "summary": "Browse playbook marketplace",
                "description": "Browse the playbook marketplace with 200+ pre-built templates across incident response, threat hunting, and compliance categories.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/playbooks/marketplace/browse \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/playbooks/marketplace/{template_id}/install",
                "summary": "Install marketplace playbook",
                "description": "Install a playbook from the marketplace into your organization.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/playbooks/marketplace/pb-ransomware-response/install \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "correlation": {
        "title": "Alert Correlation",
        "description": "Correlate alerts into campaigns and investigations using shared IOCs, MITRE technique chains, entity risk scoring, and custom correlation rules.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/correlation/campaigns",
                "summary": "List campaigns",
                "description": "List all correlation campaigns with member counts and status.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/correlation/campaigns \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/correlation/campaigns",
                "summary": "Create campaign",
                "description": "Create a new correlation campaign to group related alerts and investigations.",
                "request_body": {
                    "name": "APT29 Activity - Feb 2026",
                    "description": "Suspected APT29 campaign targeting finance department"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/correlation/campaigns \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"APT29 Activity\",\"description\":\"...\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/correlation/rules",
                "summary": "List correlation rules",
                "description": "List all correlation rules with their match criteria and action settings.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/correlation/rules \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/correlation/rules",
                "summary": "Create correlation rule",
                "description": "Create a custom correlation rule with match conditions and automatic actions.",
                "request_body": {
                    "name": "Shared C2 IP Correlation",
                    "match_type": "shared_ioc",
                    "conditions": {"ioc_type": "ip", "min_alerts": 3},
                    "action": "create_investigation"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/correlation/rules \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"Shared C2 IP\",\"match_type\":\"shared_ioc\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/correlation/trigger/{alert_id}",
                "summary": "Trigger correlation",
                "description": "Manually trigger correlation analysis for a specific alert.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/correlation/trigger/550e8400-... \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/correlation/entity-risk",
                "summary": "Get high-risk entities",
                "description": "Get entities (users, hosts, IPs) with elevated risk scores based on correlated alert activity.",
                "response_example": {
                    "entities": [
                        {
                            "entity_type": "host",
                            "entity_value": "WORKSTATION-01",
                            "risk_score": 92,
                            "alert_count": 7,
                            "techniques": ["T1059.001", "T1021.001"]
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/correlation/entity-risk \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/correlation/stats",
                "summary": "Correlation statistics",
                "description": "Get overall correlation statistics including campaign counts, rule match rates, and link volumes.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/correlation/stats \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "agents": {
        "title": "AI Agents",
        "description": "Manage autonomous AI agents that handle alert triage, investigation, and response. Agents use the Riggs reasoning engine with configurable autonomy levels.",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/v1/agents/",
                "summary": "Create agent",
                "description": "Create a new AI agent with custom configuration, autonomy level, and alert type assignments.",
                "request_body": {
                    "name": "Phishing Triage Agent",
                    "description": "Handles phishing alert triage and enrichment",
                    "template_id": "phishing-triage",
                    "auto_close_policy": {"max_confidence": 0.95, "allowed_verdicts": ["false_positive"]}
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/ \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"Phishing Triage\",\"template_id\":\"phishing-triage\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/agents/{agent_id}",
                "summary": "Get agent details",
                "description": "Get agent configuration, status, and performance metrics.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/agents/agent-001 \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/{agent_id}/enable",
                "summary": "Enable agent",
                "description": "Enable an agent to begin processing alerts automatically.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/agent-001/enable \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/{agent_id}/disable",
                "summary": "Disable agent",
                "description": "Disable an agent. In-progress work completes but no new alerts are assigned.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/agent-001/disable \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/{agent_id}/run",
                "summary": "Trigger manual execution",
                "description": "Manually trigger an agent run outside its normal schedule.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/agent-001/run \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/{agent_id}/analyze-alert",
                "summary": "Run agent on alert",
                "description": "Run a specific agent against a specific alert for targeted analysis.",
                "request_body": {
                    "alert_id": "550e8400-..."
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/agent-001/analyze-alert \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"alert_id\":\"550e8400-...\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/agents/templates/list",
                "summary": "List agent templates",
                "description": "List available agent templates for quick agent creation.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/agents/templates/list \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/agents/ops/metrics",
                "summary": "Agent operations metrics",
                "description": "Get comprehensive agent metrics including execution counts, latency, token usage, and accuracy rates.",
                "response_example": {
                    "total_agents": 3,
                    "active_agents": 2,
                    "executions_24h": 156,
                    "avg_latency_ms": 3200,
                    "tokens_used_24h": 45000,
                    "accuracy_rate": 0.94
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/agents/ops/metrics \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/ops/emergency-stop",
                "summary": "Emergency stop all agents",
                "description": "Immediately halt all agent activity. Use in case of AI misbehavior or unexpected actions.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/ops/emergency-stop \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/agents/ops/emergency-resume",
                "summary": "Resume agents after emergency stop",
                "description": "Resume agent operations after an emergency stop.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/ops/emergency-resume \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "ai_riggs": {
        "title": "AI & Riggs",
        "description": "Riggs is the AI reasoning engine powering T1 Agentics. It performs alert triage, investigation analysis, search assistance, and knowledge base drafting.",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/v1/agents/queue/auto-triage",
                "summary": "Queue alert for AI triage",
                "description": "Queue an alert for Riggs auto-triage. Riggs analyzes the alert, enriches IOCs, maps MITRE techniques, and returns a verdict.",
                "request_body": {
                    "alert_id": "550e8400-..."
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/agents/queue/auto-triage \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"alert_id\":\"550e8400-...\"}'"
            },
            {
                "method": "POST",
                "path": "/api/chat/search-assist",
                "summary": "AI search assistant",
                "description": "Ask Riggs a natural language question to search alerts, investigations, and IOCs. Returns structured search results with AI-generated summaries.",
                "request_body": {
                    "query": "Show me all critical alerts from CrowdStrike this week",
                    "context": "security_queue"
                },
                "response_example": {
                    "interpreted_query": {"severity": "critical", "source": "crowdstrike", "timeframe": "7d"},
                    "results": [],
                    "summary": "Found 3 critical CrowdStrike alerts..."
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/chat/search-assist \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"query\":\"critical alerts from CrowdStrike this week\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/chat/investigations/{investigation_id}/messages",
                "summary": "Get investigation chat",
                "description": "Get chat messages for an investigation including Riggs AI analysis messages and analyst notes.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/messages \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/chat/investigations/{investigation_id}/messages",
                "summary": "Send chat message",
                "description": "Send a message in an investigation chat. Can be an analyst note or a question for Riggs to analyze.",
                "request_body": {
                    "content": "Riggs, check if this IP has been seen in other investigations",
                    "type": "analyst_message"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/messages \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"content\":\"Check related IOCs\",\"type\":\"analyst_message\"}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/agents/ops/token-usage",
                "summary": "AI token usage",
                "description": "Get token usage statistics for your tenant including per-model breakdown and quota remaining.",
                "response_example": {
                    "total_tokens_used": 450000,
                    "quota_limit": 500000,
                    "quota_remaining": 50000,
                    "by_model": {
                        "claude-sonnet-4-5": {"input": 300000, "output": 150000}
                    }
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/agents/ops/token-usage \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/knowledge-base/riggs/drafts",
                "summary": "List Riggs KB drafts",
                "description": "List knowledge base articles drafted by Riggs AI from investigation learnings. Drafts require analyst approval before publishing.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/knowledge-base/riggs/drafts \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "iam": {
        "title": "Users & Access Control",
        "description": "Manage users, roles, permissions, and API keys. T1 Agentics uses role-based access control (RBAC) with customizable roles.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/admin/users",
                "summary": "List users",
                "description": "Get all users in the tenant. (Admin role required)",
                "response_example": {
                    "users": [
                        {
                            "username": "analyst@company.com",
                            "role": "user",
                            "last_login": "2026-02-12T10:00:00Z",
                            "disabled": False
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/admin/users \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/users",
                "summary": "Create user",
                "description": "Create a new user account with role assignment. (Admin role required)",
                "request_body": {
                    "username": "analyst@company.com",
                    "email": "analyst@company.com",
                    "password": "secure_password",
                    "role": "user"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/users \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"username\":\"analyst@company.com\",\"email\":\"analyst@company.com\",\"password\":\"...\",\"role\":\"user\"}'"
            },
            {
                "method": "DELETE",
                "path": "/api/v1/admin/users/{username}",
                "summary": "Delete user",
                "description": "Delete a user account. (Admin role required)",
                "curl_example": "curl -X DELETE https://your-instance.t1agentics.ai/api/v1/admin/users/analyst@company.com \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/users/{username}/unlock",
                "summary": "Unlock user account",
                "description": "Unlock a locked user account. Resets failed login attempts and clears the lockout timer. (Admin)",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/users/analyst@company.com/unlock \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/admin/roles",
                "summary": "List roles",
                "description": "List all roles including built-in (admin, user, viewer) and custom roles with their permissions.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/admin/roles \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/roles",
                "summary": "Create custom role",
                "description": "Create a custom role with specific permissions. (Admin role required)",
                "request_body": {
                    "name": "soc_lead",
                    "description": "SOC Team Lead",
                    "permissions": ["view_alerts", "triage_alerts", "manage_playbooks", "view_reports"]
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/roles \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"soc_lead\",\"permissions\":[\"view_alerts\",\"triage_alerts\"]}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/admin/permissions",
                "summary": "List permissions",
                "description": "List all available permissions that can be assigned to roles.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/admin/permissions \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/admin/api-keys",
                "summary": "Create API key",
                "description": "Create a new API key for machine-to-machine access. The key is only shown once in the response.",
                "request_body": {
                    "name": "Production API Key",
                    "role": "user",
                    "expires_days": 365
                },
                "response_example": {
                    "key_id": "ak-001",
                    "api_key": "t1k_abc123...",
                    "name": "Production API Key",
                    "expires_at": "2027-02-12T00:00:00Z"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/admin/api-keys \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"name\":\"Production API Key\",\"role\":\"user\",\"expires_days\":365}'"
            },
            {
                "method": "GET",
                "path": "/api/v1/admin/api-keys",
                "summary": "List API keys",
                "description": "List all API keys for the tenant with their status and expiration dates.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/admin/api-keys \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/admin/audit-log",
                "summary": "Get audit log",
                "description": "Get the system audit log with filtering by user, action type, and date range.",
                "curl_example": "curl \"https://your-instance.t1agentics.ai/api/v1/admin/audit-log?limit=50\" \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "chat": {
        "title": "Investigation Chat",
        "description": "Real-time collaboration on investigations with built-in AI assistance. Chat messages create an immutable audit trail for compliance.",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/chat/investigations/{investigation_id}/messages",
                "summary": "Get chat messages",
                "description": "Get all chat messages for an investigation with pagination. Includes analyst notes, Riggs analysis, and system events.",
                "response_example": {
                    "messages": [
                        {
                            "id": "msg-001",
                            "author": "analyst@company.com",
                            "content": "Found additional C2 indicators on host",
                            "type": "analyst_message",
                            "created_at": "2026-02-12T10:30:00Z"
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/messages \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/chat/investigations/{investigation_id}/messages",
                "summary": "Send message",
                "description": "Send a chat message in an investigation. Messages are immutable once created for audit compliance.",
                "request_body": {
                    "content": "Escalating to incident response team",
                    "type": "analyst_message"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/messages \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"content\":\"Escalating to IR team\",\"type\":\"analyst_message\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/chat/investigations/{investigation_id}/messages/read",
                "summary": "Mark messages as read",
                "description": "Mark messages as read for the current user. Used for unread badge tracking.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/messages/read \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/chat/investigations/{investigation_id}/audit",
                "summary": "Get audit trail",
                "description": "Get the immutable, append-only audit trail for an investigation including all actions and decisions.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/chat/investigations/inv-001/audit \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "GET",
                "path": "/api/v1/chat/analytics/summary",
                "summary": "Chat analytics summary",
                "description": "Get chat activity summary across all investigations. (Admin)",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/chat/analytics/summary \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    },
    "billing": {
        "title": "Billing & Licensing",
        "description": "Manage subscription plans, view usage, and access the Stripe customer portal. Tiers: Community (free), Professional ($2,499/mo), Enterprise ($7,499/mo), Enterprise Plus ($19,999/mo).",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/billing/config",
                "summary": "Get billing configuration",
                "description": "Get available plans, pricing, and feature comparison. This endpoint is public (no auth required).",
                "response_example": {
                    "plans": [
                        {
                            "tier": "professional",
                            "name": "Professional",
                            "price_monthly": 2499,
                            "token_quota": 500000,
                            "features": ["Unlimited users", "500K AI tokens/mo", "Priority support"]
                        }
                    ]
                },
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/billing/config"
            },
            {
                "method": "GET",
                "path": "/api/v1/billing/status",
                "summary": "Get billing status",
                "description": "Get current tenant billing status including plan, usage, and renewal date.",
                "curl_example": "curl https://your-instance.t1agentics.ai/api/v1/billing/status \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            },
            {
                "method": "POST",
                "path": "/api/v1/billing/create-checkout-session",
                "summary": "Start checkout",
                "description": "Create a Stripe checkout session for plan upgrade or new subscription.",
                "request_body": {
                    "tier": "professional",
                    "billing_period": "monthly"
                },
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/billing/create-checkout-session \\\n  -H \"Authorization: Bearer YOUR_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"tier\":\"professional\",\"billing_period\":\"monthly\"}'"
            },
            {
                "method": "POST",
                "path": "/api/v1/billing/create-portal-session",
                "summary": "Open customer portal",
                "description": "Create a Stripe customer portal session for managing payment methods, invoices, and subscription changes.",
                "curl_example": "curl -X POST https://your-instance.t1agentics.ai/api/v1/billing/create-portal-session \\\n  -H \"Authorization: Bearer YOUR_TOKEN\""
            }
        ]
    }
}


@router.get("/")
async def get_documentation_index(
    current_user: dict = Depends(get_current_user)
):
    """Get documentation index"""
    try:
        categories = []

        for category_key, category_data in API_DOCS.items():
            categories.append({
                "key": category_key,
                "title": category_data["title"],
                "description": category_data["description"],
                "endpoint_count": len(category_data["endpoints"])
            })

        return {
            "welcome": "Welcome to T1 Agentics Interactive API Documentation",
            "user": current_user.get("username", ""),
            "role": current_user.get("role", ""),
            "categories": categories
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_documentation_index: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{category}")
async def get_category_documentation(
    category: str,
    current_user: dict = Depends(get_current_user)
):
    """Get documentation for a specific category"""
    try:
        if category not in API_DOCS:
            raise HTTPException(status_code=404, detail="Category not found")

        return API_DOCS[category]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_category_documentation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{category}/{endpoint_index}")
async def get_endpoint_documentation(
    category: str,
    endpoint_index: int,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed documentation for a specific endpoint"""
    try:
        if category not in API_DOCS:
            raise HTTPException(status_code=404, detail="Category not found")

        endpoints = API_DOCS[category]["endpoints"]

        if endpoint_index >= len(endpoints):
            raise HTTPException(status_code=404, detail="Endpoint not found")

        return endpoints[endpoint_index]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_endpoint_documentation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
