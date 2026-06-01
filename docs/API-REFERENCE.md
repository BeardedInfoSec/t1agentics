# T1 Agentics API Reference

Complete API documentation for all backend endpoints.

**Base URL:** `http://localhost:8000`
**Authentication:** Most endpoints require JWT Bearer token (`Authorization: Bearer <token>`)

---

## Quick Reference: Getting a Token

```bash
curl -X POST "http://localhost:8000/api/v1/admin/login" \
 -H "Content-Type: application/json" \
 -d '{"username":"admin","password":"admin123"}'
```

Response:
```json
{
 "access_token": "eyJhbG...",
 "token_type": "bearer",
 "username": "admin",
 "role": "admin"
}
```

---

## Health & Diagnostics

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/health` | Basic health check | No |
| GET | `/health/live` | Kubernetes liveness probe | No |
| GET | `/health/ready` | Kubernetes readiness probe | No |
| GET | `/health/detailed` | Detailed health with all services | No |
| GET | `/api/v1/health` | API v1 health endpoint | No |
| GET | `/metrics` | Prometheus metrics | No |

---

## Authentication & Users

### Login & Tokens

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/admin/login` | Login, returns JWT token | No |
| POST | `/api/v1/auth/login` | Alternative login (no token) | No |

**Login Request:**
```json
{"username": "admin", "password": "admin123"}
```

### User Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/users` | List all users | Yes |
| POST | `/api/v1/admin/users` | Create new user | Yes |
| PUT | `/api/v1/admin/users/{username}` | Update user | Yes |
| DELETE | `/api/v1/admin/users/{username}` | Delete user | Yes |
| POST | `/api/v1/admin/users/{username}/reset-password` | Trigger password reset | Yes |
| POST | `/api/v1/admin/users/{username}/unlock` | Unlock locked account | Yes |
| GET | `/api/v1/users/me` | Get current user info | Yes |

### API Keys

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/api-keys` | List API keys | Yes |
| POST | `/api/v1/admin/api-keys` | Create API key | Yes |
| DELETE | `/api/v1/admin/api-keys/{key_id}` | Delete API key | Yes |
| PUT | `/api/v1/admin/api-keys/{key_id}/toggle` | Enable/disable key | Yes |

### User Preferences

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/preferences` | Get user preferences | Yes |
| PUT | `/api/v1/admin/preferences` | Update preferences | Yes |

---

## Alerts

### Alert Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/alerts` | List alerts with filters | Yes |
| POST | `/api/v1/alerts/ingest` | Ingest new alert | No |
| GET | `/api/v1/alerts/{alert_id}` | Get alert details | Yes |
| PATCH | `/api/v1/alerts/{alert_id}/status` | Update alert status | Yes |
| PATCH | `/api/v1/alerts/{alert_id}/severity` | Update alert severity | Yes |
| PATCH | `/api/v1/alerts/bulk-update` | Bulk update alerts | Yes |
| GET | `/api/v1/alerts/{alert_id}/investigation` | Get investigation for alert | Yes |
| POST | `/api/v1/alerts/{alert_id}/enrich` | Enrich alert IOCs | Yes |

**Query Parameters for GET /api/v1/alerts:**
- `status` - Filter by status (open, in_progress, closed)
- `severity` - Filter by severity (critical, high, medium, low)
- `source` - Filter by source
- `limit` - Results per page (default: 50)
- `offset` - Pagination offset
- `sort` - Sort field

### AI Triage

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/alerts/ai-verdicts` | Get AI verdicts | Yes |
| GET | `/api/v1/alerts/{alert_id}/ai-triage` | Get AI triage results | Yes |
| POST | `/api/v1/alerts/{alert_id}/ai-triage/rerun` | Re-run AI triage | Yes |
| GET | `/api/v1/ai-triage/stats` | Get triage statistics | Yes |

---

## Investigations

### Investigation Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/investigations` | List investigations | Yes |
| GET | `/api/v1/investigations/{id}` | Get investigation details | Yes |
| PATCH | `/api/v1/investigations/{id}` | Update investigation | Yes |
| DELETE | `/api/v1/investigations/{id}` | Delete investigation | Yes |
| POST | `/api/v1/investigate` | Run synchronous investigation | Yes |

### Investigation Workflow (Phase 3.4)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/investigations/{id}/claim` | Claim investigation | Yes |
| POST | `/api/v1/investigations/{id}/release` | Release investigation | Yes |
| POST | `/api/v1/investigations/{id}/assign` | Assign to user/team | Yes |
| POST | `/api/v1/investigations/{id}/escalate` | Escalate to higher tier | Yes |
| POST | `/api/v1/investigations/{id}/block` | Block investigation | Yes |
| POST | `/api/v1/investigations/{id}/unblock` | Unblock investigation | Yes |
| POST | `/api/v1/investigations/{id}/resolve` | Resolve investigation | Yes |
| POST | `/api/v1/investigations/{id}/close` | Close investigation | Yes |

**Resolve Request:**
```json
{
 "resolution_type": "true_positive",
 "resolution_notes": "Confirmed malicious activity"
}
```

**Block Request:**
```json
{
 "reason": "Waiting for customer response"
}
```

### Investigation State

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| PATCH | `/api/v1/investigations/{id}/disposition` | Set disposition | Yes |
| PATCH | `/api/v1/investigations/{id}/priority` | Update priority | Yes |
| PATCH | `/api/v1/investigations/{id}/owner` | Assign owner | Yes |
| PATCH | `/api/v1/investigations/{id}/state` | Update state | Yes |

### Investigation Queues

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/investigations/queue/mine` | Get my work queue | Yes |
| GET | `/api/v1/investigations/queue/team/{team_id}` | Get team queue | Yes |
| GET | `/api/v1/investigations/orphaned` | Get unassigned investigations | Yes |
| GET | `/api/v1/investigations/{id}/ownership-history` | Get ownership audit trail | Yes |

### Investigation Notes & Timeline

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/investigations/{id}/notes` | Add note | Yes |
| GET | `/api/v1/investigations/{id}/notes` | Get all notes | Yes |
| GET | `/api/v1/investigations/{id}/timeline` | Get event timeline | Yes |
| GET | `/api/v1/investigations/{id}/related` | Get related investigations | Yes |

---

## Teams & Assignment (Phase 3.4)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/teams` | List all teams | Yes |
| GET | `/api/v1/teams/{team_id}` | Get team details | Yes |
| PUT | `/api/v1/teams/{team_id}` | Update team | Yes |
| GET | `/api/v1/assignment-rules` | List assignment rules | Yes |
| GET | `/api/v1/sla-config` | Get SLA configuration | Yes |
| GET | `/api/v1/escalation-config` | Get escalation rules | Yes |

**Team Update Request:**
```json
{
 "members": ["user1", "user2"],
 "lead_user_id": "user1",
 "max_concurrent_investigations": 15
}
```

---

## Threat Intelligence

### IOC Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/threat-intel/iocs` | Create IOC | Yes |
| POST | `/api/v1/threat-intel/iocs/bulk` | Bulk create IOCs | Yes |
| GET | `/api/v1/threat-intel/iocs` | Search IOCs | Yes |
| GET | `/api/v1/threat-intel/iocs/{ioc_value}` | Get IOC details | Yes |
| DELETE | `/api/v1/threat-intel/iocs/{ioc_value}` | Delete IOC | Yes |
| GET | `/api/v1/threat-intel/stats` | Get threat intel stats | Yes |

### IOC Lookups

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/threat-intel/lookup/ip/{ip}` | Lookup IP | Yes |
| GET | `/api/v1/threat-intel/lookup/domain/{domain}` | Lookup domain | Yes |
| GET | `/api/v1/threat-intel/lookup/hash/{hash}` | Lookup hash | Yes |
| POST | `/api/v1/threat-intel/lookup/url` | Lookup URL | Yes |

### Enrichment

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/threat-intel/enrich` | Enrich single IOC | Yes |
| POST | `/api/v1/threat-intel/enrich/bulk` | Bulk enrich IOCs | Yes |
| POST | `/api/v1/enrich/ip` | Enrich IP address | Yes |
| POST | `/api/v1/enrich/domain` | Enrich domain | Yes |
| POST | `/api/v1/enrich/hash` | Enrich file hash | Yes |

### Whitelist

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/ioc-management/whitelist` | Get whitelist entries | Yes |
| POST | `/api/v1/ioc-management/whitelist` | Add to whitelist | Yes |
| POST | `/api/v1/ioc-management/whitelist/bulk` | Bulk add to whitelist | Yes |
| DELETE | `/api/v1/ioc-management/whitelist/{entry_id}` | Remove from whitelist | Yes |
| GET | `/api/v1/ioc-management/whitelist/check/{ioc}` | Check if whitelisted | Yes |

---

## Correlation & Campaigns

### Campaigns

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/correlation/campaigns` | List campaigns | Yes |
| POST | `/api/v1/correlation/campaigns` | Create campaign | Yes |
| GET | `/api/v1/correlation/campaigns/{id}` | Get campaign | Yes |
| PATCH | `/api/v1/correlation/campaigns/{id}` | Update campaign | Yes |
| DELETE | `/api/v1/correlation/campaigns/{id}` | Delete campaign | Yes |
| POST | `/api/v1/correlation/campaigns/{id}/members` | Add members | Yes |
| POST | `/api/v1/correlation/campaigns/{id}/iocs` | Add IOCs | Yes |

### Correlation Rules

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/correlation/rules` | List rules | Yes |
| POST | `/api/v1/correlation/rules` | Create rule | Yes |
| PATCH | `/api/v1/correlation/rules/{id}` | Update rule | Yes |
| PATCH | `/api/v1/correlation/rules/{id}/toggle` | Enable/disable | Yes |
| DELETE | `/api/v1/correlation/rules/{id}` | Delete rule | Yes |

---

## Integrations

### Integration Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/integrations/` | List integrations | Yes |
| POST | `/api/v1/integrations/` | Create integration | Yes |
| GET | `/api/v1/integrations/{id}` | Get integration | Yes |
| PUT | `/api/v1/integrations/{id}` | Update integration | Yes |
| DELETE | `/api/v1/integrations/{id}` | Delete integration | Yes |
| POST | `/api/v1/integrations/{id}/enable` | Enable integration | Yes |
| POST | `/api/v1/integrations/{id}/disable` | Disable integration | Yes |
| POST | `/api/v1/integrations/{id}/test` | Test connection | Yes |

### Integration Actions

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/integrations/{id}/actions` | List actions | Yes |
| POST | `/api/v1/integrations/{id}/actions` | Create action | Yes |
| POST | `/api/v1/integrations/{id}/actions/{action_id}/execute` | Execute action | Yes |

### Integration Catalog

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/catalog/connectors` | List connectors | Yes |
| GET | `/api/v1/catalog/connectors/search` | Search connectors | Yes |
| GET | `/api/v1/catalog/categories` | Get categories | Yes |
| POST | `/api/v1/catalog/connectors/import` | Import connector | Yes |

---

## Credentials

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/credentials/` | List credentials | Yes |
| POST | `/api/v1/credentials/` | Create credential | Yes |
| GET | `/api/v1/credentials/{id}` | Get credential | Yes |
| PUT | `/api/v1/credentials/{id}` | Update credential | Yes |
| DELETE | `/api/v1/credentials/{id}` | Delete credential | Yes |
| POST | `/api/v1/credentials/{id}/test` | Test credential | Yes |
| POST | `/api/v1/credentials/{id}/link/{integration_id}` | Link to integration | Yes |
| GET | `/api/v1/credentials/auth-types` | Get auth types | Yes |

---

## Actions & Execution

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/actions/execute` | Execute action (sync) | Yes |
| POST | `/api/v1/actions/execute/async` | Execute action (async) | Yes |
| GET | `/api/v1/actions/jobs/{job_id}` | Get job status | Yes |
| GET | `/api/v1/actions/jobs` | List all jobs | Yes |
| GET | `/api/v1/actions/stats` | Get execution stats | Yes |

**Execute Request:**
```json
{
 "integration_id": "virustotal",
 "action_id": "lookup_ip",
 "parameters": {"ip": "8.8.8.8"}
}
```

---

## Agents & Automation

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/agents` | List agents | Yes |
| POST | `/api/v1/agents` | Create agent | Yes |
| GET | `/api/v1/agents/{id}` | Get agent | Yes |
| PUT | `/api/v1/agents/{id}` | Update agent | Yes |
| DELETE | `/api/v1/agents/{id}` | Delete agent | Yes |
| POST | `/api/v1/agents/{id}/enable` | Enable agent | Yes |
| POST | `/api/v1/agents/{id}/disable` | Disable agent | Yes |
| POST | `/api/v1/agents/{id}/run` | Run agent | Yes |
| POST | `/api/v1/agents/{id}/analyze-alert` | Analyze alert | Yes |
| GET | `/api/v1/agents/templates/list` | List templates | Yes |
| POST | `/api/v1/agents/from-template` | Create from template | Yes |

---

## Webhooks

### Webhook Ingestion

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/webhooks/ingest/{webhook_name}` | Ingest via webhook | HEC Token |
| POST | `/api/v1/webhooks/alerts` | Generic alert webhook | HEC Token |
| GET | `/api/v1/webhooks/health` | Webhook health | No |

### Webhook Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/webhooks` | List webhooks | Yes |
| POST | `/api/v1/admin/webhooks` | Create webhook | Yes |
| GET | `/api/v1/admin/webhooks/{name}` | Get webhook | Yes |
| DELETE | `/api/v1/admin/webhooks/{name}` | Delete webhook | Yes |

---

## Threat Feeds

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/threat-feeds` | List feeds | Yes |
| POST | `/api/v1/threat-feeds` | Create feed | Yes |
| GET | `/api/v1/threat-feeds/{id}` | Get feed | Yes |
| DELETE | `/api/v1/threat-feeds/{id}` | Delete feed | Yes |
| PATCH | `/api/v1/threat-feeds/{id}/enable` | Enable feed | Yes |
| POST | `/api/v1/threat-feeds/{id}/poll` | Poll feed now | Yes |
| GET | `/api/v1/threat-feeds/stats` | Get feed stats | Yes |
| GET | `/api/v1/threat-feeds/scheduler/status` | Scheduler status | Yes |
| POST | `/api/v1/threat-feeds/scheduler/start` | Start scheduler | Yes |
| POST | `/api/v1/threat-feeds/scheduler/stop` | Stop scheduler | Yes |

---

## Deduplication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/deduplication/rules` | List rules | Yes |
| POST | `/api/v1/deduplication/rules` | Create rule | Yes |
| GET | `/api/v1/deduplication/stats` | Get stats | Yes |
| POST | `/api/v1/deduplication/check` | Check for duplicates | Yes |
| POST | `/api/v1/deduplication/fingerprint` | Generate fingerprint | Yes |
| GET | `/api/v1/deduplication/groups/{id}` | Get duplicate group | Yes |

---

## Notifications

### SMTP Configuration

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/notifications/smtp` | Get SMTP config | Yes |
| POST | `/api/v1/notifications/smtp` | Configure SMTP | Yes |
| POST | `/api/v1/notifications/smtp/test` | Test SMTP | Yes |
| POST | `/api/v1/notifications/smtp/test-email` | Send test email | Yes |

### Notification Rules

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/notifications/rules` | List rules | Yes |
| POST | `/api/v1/notifications/rules` | Create rule | Yes |
| PUT | `/api/v1/notifications/rules/{id}` | Update rule | Yes |
| DELETE | `/api/v1/notifications/rules/{id}` | Delete rule | Yes |

### Notification Channels

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/notifications/channels` | List channels | Yes |
| POST | `/api/v1/notifications/channels` | Create channel | Yes |
| PUT | `/api/v1/notifications/channels/{id}` | Update channel | Yes |
| DELETE | `/api/v1/notifications/channels/{id}` | Delete channel | Yes |
| POST | `/api/v1/notifications/channels/{id}/test` | Test channel | Yes |

---

## Knowledge Base

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/knowledge-base/` | List entries | Yes |
| POST | `/api/v1/knowledge-base/` | Create entry | Yes |
| GET | `/api/v1/knowledge-base/{id}` | Get entry | Yes |
| PATCH | `/api/v1/knowledge-base/{id}` | Update entry | Yes |
| DELETE | `/api/v1/knowledge-base/{id}` | Delete entry | Yes |
| POST | `/api/v1/knowledge-base/query` | Search KB | Yes |
| POST | `/api/v1/knowledge-base/upload` | Upload file | Yes |
| GET | `/api/v1/knowledge-base/stats` | Get stats | Yes |
| GET | `/api/v1/knowledge-base/categories` | Get categories | Yes |

---

## Attachments

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/attachments/upload/{alert_id}` | Upload attachment | Yes |
| GET | `/api/v1/attachments/alert/{alert_id}` | List attachments | Yes |
| GET | `/api/v1/attachments/{id}` | Get attachment | Yes |
| GET | `/api/v1/attachments/{id}/download` | Download file | Yes |
| DELETE | `/api/v1/attachments/{id}` | Delete attachment | Yes |
| POST | `/api/v1/attachments/{id}/analyze` | Analyze file | Yes |
| POST | `/api/v1/attachments/{id}/sandbox` | Submit to sandbox | Yes |
| GET | `/api/v1/attachments/{id}/sandbox` | Get sandbox results | Yes |

---

## Exclusions

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/exclusions` | List exclusions | Yes |
| POST | `/api/v1/exclusions` | Create exclusion | Yes |
| POST | `/api/v1/exclusions/bulk` | Bulk create | Yes |
| DELETE | `/api/v1/exclusions/{id}` | Delete exclusion | Yes |
| GET | `/api/v1/exclusions/check/{ioc}` | Check if excluded | Yes |
| GET | `/api/v1/exclusions/stats` | Get stats | Yes |

---

## PII Settings

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/pii/settings` | Get PII settings | Yes |
| PUT | `/api/v1/pii/settings` | Update settings | Yes |
| GET | `/api/v1/pii/types` | Get PII types | Yes |
| POST | `/api/v1/pii/test` | Test PII detection | Yes |

---

## AI Providers

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/ai-providers` | List providers | Yes |
| POST | `/api/v1/ai-providers` | Create provider | Yes |
| DELETE | `/api/v1/ai-providers/{id}` | Delete provider | Yes |
| PATCH | `/api/v1/ai-providers/{id}` | Update provider | Yes |
| POST | `/api/v1/ai-providers/{id}/set-default` | Set as default | Yes |
| POST | `/api/v1/ai-providers/{id}/test` | Test provider | Yes |
| POST | `/api/v1/ai-providers/{id}/fetch-models` | Fetch models | Yes |

---

## Token Usage

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/ai/tokens/summary` | Usage summary | Yes |
| GET | `/api/v1/ai/tokens/daily` | Daily usage | Yes |
| GET | `/api/v1/ai/tokens/by-provider` | By provider | Yes |
| GET | `/api/v1/ai/tokens/by-model` | By model | Yes |
| GET | `/api/v1/ai/tokens/recent` | Recent usage | Yes |
| GET | `/api/v1/ai/tokens/quota` | Quota info | Yes |

---

## Assets (CMDB) - Phase 9

### Asset Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/assets` | List assets with filters | Yes |
| POST | `/api/v1/assets` | Create new asset | Yes |
| GET | `/api/v1/assets/stats` | Get asset statistics | Yes |
| GET | `/api/v1/assets/{id}` | Get asset by ID | Yes |
| PATCH | `/api/v1/assets/{id}` | Update asset | Yes |
| DELETE | `/api/v1/assets/{id}` | Delete asset | Yes |
| GET | `/api/v1/assets/search` | Search assets | Yes |
| GET | `/api/v1/assets/hostname/{hostname}` | Get by hostname | Yes |
| GET | `/api/v1/assets/ip/{ip}` | Get by IP address | Yes |

**Query Parameters for GET /api/v1/assets:**
- `asset_type` - Filter by type (server, workstation, network_device, etc.)
- `criticality` - Filter by tier (tier1, tier2, tier3, tier4)
- `environment` - Filter by environment (production, development, staging)
- `status` - Filter by status (active, inactive, decommissioned)
- `search` - Search hostname, display name, IP addresses
- `limit` - Results per page (default: 50)
- `offset` - Pagination offset

**Create Asset Request:**
```json
{
 "hostname": "web-server-01",
 "display_name": "Production Web Server",
 "asset_type": "server",
 "ip_addresses": ["10.0.1.10", "192.168.1.100"],
 "mac_addresses": ["00:1A:2B:3C:4D:5E"],
 "os_family": "linux",
 "os_name": "Ubuntu Server",
 "os_version": "22.04 LTS",
 "criticality": "tier1",
 "environment": "production",
 "owner": "platform-team",
 "department": "Engineering",
 "location": "DC-EAST",
 "compliance_tags": ["PCI-DSS", "SOC2"],
 "custom_tags": ["web-tier", "public-facing"]
}
```

### Asset Discovery

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/asset-discovery/sources` | List discovery sources | Yes |
| POST | `/api/v1/asset-discovery/sources` | Create discovery source | Yes |
| GET | `/api/v1/asset-discovery/sources/{id}` | Get source details | Yes |
| PATCH | `/api/v1/asset-discovery/sources/{id}` | Update source | Yes |
| DELETE | `/api/v1/asset-discovery/sources/{id}` | Delete source | Yes |
| POST | `/api/v1/asset-discovery/run/{id}` | Run discovery for source | Yes |
| POST | `/api/v1/asset-discovery/run-all` | Run all enabled sources | Yes |
| GET | `/api/v1/asset-discovery/history` | Get discovery history | Yes |
| GET | `/api/v1/asset-discovery/conflicts` | Get pending conflicts | Yes |
| POST | `/api/v1/asset-discovery/conflicts/{id}/resolve` | Resolve conflict | Yes |
| GET | `/api/v1/asset-discovery/stats` | Get discovery stats | Yes |
| GET | `/api/v1/asset-discovery/source-types` | Get available source types | Yes |

**Supported Discovery Source Types:**
- `crowdstrike` - CrowdStrike Falcon
- `aws` - AWS EC2
- `azure` - Azure VMs
- `active_directory` - Active Directory
- `vmware` - VMware vSphere
- `network_scan` - Network scanning
- `custom` - Custom webhook

**Create Discovery Source Request:**
```json
{
 "source_type": "crowdstrike",
 "name": "CrowdStrike Production",
 "config": {
 "integration_id": "crowdstrike_v3"
 },
 "schedule_cron": "0 */4 * * *",
 "priority": 80,
 "enabled": true
}
```

### Asset Criticality Tiers

| Tier | Label | Description |
|------|-------|-------------|
| tier1 | Critical | Domain controllers, critical infrastructure, PII databases |
| tier2 | High | Production servers, network devices |
| tier3 | Standard | Workstations, dev servers |
| tier4 | Low | Test systems, isolated assets |

---

## Statistics & Search

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/stats` | System statistics | Yes |
| GET | `/api/v1/search` | Global search | Yes |
| GET | `/api/v1/database/stats` | Database stats | Yes |
| GET | `/api/v1/iocs/stats` | IOC statistics | Yes |

---

## System Logs

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/logs` | Get system logs | Yes |

**Query Parameters:**
- `level` - Filter by level (info, warning, error)
- `source` - Filter by source
- `limit` - Results per page
- `offset` - Pagination offset

---

## Error Responses

All endpoints return errors in this format:

```json
{
 "detail": "Error message here"
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized (missing/invalid token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

---

## Rate Limiting

Some endpoints have rate limits configured. Check the `X-RateLimit-*` headers:
- `X-RateLimit-Limit` - Requests allowed per window
- `X-RateLimit-Remaining` - Requests remaining
- `X-RateLimit-Reset` - Timestamp when limit resets

---

*Generated: 2025-12-22*
*Total Endpoints: 400+*
