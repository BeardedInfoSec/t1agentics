# T1 Agentics - User Guide

Welcome to T1 Agentics, your AI-powered Security Operations Center (SOC). This guide will help you navigate the platform and make the most of its capabilities.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Security Queue](#security-queue)
4. [Alert Management](#alert-management)
5. [Investigations](#investigations)
6. [Threat Intelligence](#threat-intelligence)
7. [SOAR Playbooks](#soar-playbooks)
8. [AI Agents](#ai-agents)
9. [Riggs - AI Investigation Assistant](#riggs)
10. [Search](#search)
11. [Settings & Preferences](#settings)
12. [Keyboard Shortcuts](#keyboard-shortcuts)
13. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Logging In

1. Navigate to your T1 Agentics instance (e.g., `https://your-domain.com`)
2. Enter your **username** and **password**
3. If MFA is enabled, enter your 6-digit authenticator code
4. You'll be taken to the **Dashboard**

### First-Time Setup

After your first login, we recommend:
- **Change your password**: Click your name in the top-right corner > Profile > Change Password
- **Set up MFA**: Profile > Security > Enable Two-Factor Authentication
- **Configure theme**: Use the sun/moon icon in the top bar to switch between dark and light mode

---

## Dashboard Overview

The Dashboard provides a real-time overview of your security posture:

| Widget | Description |
|--------|-------------|
| **Alert Summary** | Total open alerts by severity (Critical, High, Medium, Low) |
| **Investigation Status** | Active investigations and their current state |
| **MTTR** | Mean Time to Respond - how quickly alerts are being handled |
| **Agent Activity** | AI agent performance and recent actions |
| **Threat Feed Status** | Active feeds and IOC ingestion rates |
| **SLA Compliance** | Alerts approaching or breaching SLA deadlines |

### Quick Actions from Dashboard

- Click any severity count to jump to filtered alerts
- Click an investigation to open it directly
- Use the refresh button to update metrics in real-time

---

## Security Queue

The Security Queue is your primary workspace for triaging security events.

### View Modes

| Mode | Description | URL |
|------|-------------|-----|
| **Combined** | All alerts + investigations in one view | `/queue` |
| **Alerts Only** | Only security alerts | `/events` |
| **Investigations** | Only grouped investigations | `/investigations` |

### Filtering

Use the filter bar to narrow down events:
- **Severity**: Critical, High, Medium, Low
- **Status**: New, In Progress, Escalated, Resolved, Closed
- **Source**: Filter by alert source (EDR, SIEM, Firewall, etc.)
- **Time Range**: Today, Last 24h, Last 7 days, Custom
- **Assignee**: Filter by analyst assignment

### Bulk Actions

1. Select multiple items using checkboxes
2. The bulk action bar appears at the top
3. Available actions:
- **Assign**: Assign selected items to an analyst
- **Change Status**: Update status in bulk
- **Change Severity**: Reclassify severity
- **Close**: Close selected items with a reason

### Column Customization

Click the column settings icon to show/hide table columns. Your selection is saved automatically.

---

## Alert Management

### Alert Lifecycle

```
New --> T1 Triage (AI) --> Enriched --> Analyst Review --> Resolved/Escalated
```

1. **New**: Alert arrives from a connected source
2. **T1 Triage**: AI agent automatically analyzes the alert (~1.3 seconds)
3. **Enriched**: IOCs are looked up against threat feeds
4. **Analyst Review**: Human reviews AI findings and makes a decision
5. **Resolved/Escalated**: Alert is closed or escalated to an investigation

### Alert Details

Click any alert to see its full details:

- **Summary**: AI-generated summary of the alert
- **Timeline**: Chronological view of all events and actions
- **IOCs**: Extracted Indicators of Compromise (IPs, domains, hashes, etc.)
- **MITRE ATT&CK**: Mapped tactics and techniques
- **Enrichment Results**: Threat feed lookups, reputation scores
- **Related Alerts**: Other alerts that may be connected
- **AI Analysis**: T1 triage results with confidence scores

### Taking Action

From an alert detail view, you can:
- **Assign** to yourself or another analyst
- **Change severity** if the AI assessment needs adjustment
- **Escalate** to create or join an investigation
- **Run a Playbook** to automate response actions
- **Add Notes** for your team
- **Close** with a verdict (True Positive, False Positive, Benign)

---

## Investigations

Investigations group related alerts together for deeper analysis.

### How Investigations Are Created

- **Automatic Correlation**: The hypothesis-driven correlation engine groups related alerts based on shared IOCs, MITRE chains, and causal relationships
- **Manual Escalation**: Analysts can escalate alerts into new or existing investigations
- **AI-Initiated**: When Riggs identifies a pattern across multiple alerts

### Investigation States

| State | Description |
|-------|-------------|
| **OPEN** | Investigation is active and being worked |
| **NEEDS_REVIEW** | AI has completed analysis, needs human review |
| **AWAITING_HUMAN** | Paused pending analyst decision |
| **RIGGS_REVIEW** | Riggs (AI) is conducting deep analysis |
| **RESOLVED** | Investigation concluded with findings |
| **CLOSED** | Fully closed and documented |

### Working an Investigation

1. **Review the summary**: AI provides a hypothesis and initial findings
2. **Examine correlated alerts**: See how alerts were grouped and why
3. **Check IOC enrichment**: Review reputation data for all indicators
4. **Run Riggs**: Click "Investigate with Riggs" for deep AI analysis
5. **Execute playbooks**: Automate containment or remediation steps
6. **Document findings**: Add notes, attach evidence, update status
7. **Close with verdict**: Mark as confirmed threat, false positive, etc.

---

## Threat Intelligence

### IOC Database

The IOC (Indicators of Compromise) database stores threat indicators from your configured feeds.

- **Types**: IP addresses, domains, URLs, file hashes (MD5, SHA1, SHA256), email addresses
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Enrichment**: Automatic reputation lookups from multiple sources
- **Search**: Find any IOC by value, type, or source feed

### Threat Feeds

Manage your threat intelligence feeds from **Settings > Threat Feeds**:

- **Preconfigured Feeds**: AlienVault OTX, Abuse.ch, EmergingThreats, and more
- **Custom Feeds**: Add your own TAXII, STIX, or plain-text URL feeds
- **Polling**: Feeds are polled automatically on schedule
- **Manual Poll**: Force an immediate update for any feed

### External Dynamic Lists (EDLs)

EDLs allow firewalls (Palo Alto, Fortinet, etc.) to pull blocklists directly from T1 Agentics:

- Navigate to **Threat Intel > EDL Manager**
- Create lists filtered by IOC type, severity, and feed source
- Share the EDL URL with your firewall for automatic updates

---

## SOAR Playbooks

### What Are Playbooks?

Playbooks are automated response workflows that execute a series of steps when triggered. They can:
- Enrich IOCs from external sources
- Block IPs on firewalls
- Disable compromised user accounts
- Send notifications to your team
- Create tickets in your ITSM system

### Creating a Playbook

1. Navigate to **SOAR > Playbooks**
2. Click **Create Playbook**
3. Use the visual editor to:
- Add steps (enrichment, action, decision, notification)
- Connect steps with conditions
- Configure each step's parameters
4. Save and optionally enable auto-trigger

### Execution Monitoring

- View running executions in **SOAR > Executions**
- Each execution shows a timeline of steps with status
- Failed steps can be retried or skipped
- Paused executions wait for human approval before continuing

### Approval Workflows

For destructive actions (blocking, disabling accounts), playbooks can pause and request approval:
- Email notifications are sent to designated approvers
- Approvers can approve/reject from the email or the UI
- Approvals expire after the configured timeout

---

## AI Agents

T1 Agentics uses tiered AI agents for automated security operations:

### Agent Tiers

| Tier | Name | Purpose | Speed |
|------|------|---------|-------|
| **T1** | Alert Triage | Automated initial analysis of every alert | ~1.3 sec/alert |
| **T2** | Riggs | Deep investigation and correlation | ~24 sec/investigation |

### Agent Configuration

Admins can configure agents from **Settings > AI Agents**:
- **Enable/Disable**: Turn agents on or off
- **Guardrails**: Set confidence thresholds, never-do rules, escalation triggers
- **Model Selection**: Choose which AI model each agent uses
- **Auto-Close Policy**: Allow agents to automatically close benign alerts
- **Rate Limits**: Control how many investigations per hour

### Understanding Agent Decisions

Every agent action includes:
- **Confidence Score**: How certain the agent is (0-100%)
- **Reasoning**: Step-by-step explanation of the analysis
- **Evidence**: Specific data points that support the conclusion
- **Recommended Actions**: What the agent suggests doing next

---

## Riggs

Riggs is your AI investigation assistant, designed for deep-dive analysis.

### Starting a Riggs Investigation

- From an alert: Click **"Investigate with Riggs"**
- From an investigation: Click **"Run Riggs Analysis"**
- Riggs will analyze all available data and produce a comprehensive report

### Riggs Report Contents

- **Executive Summary**: High-level findings
- **Attack Chain Analysis**: MITRE ATT&CK mapping
- **IOC Analysis**: Detailed indicator reputation and context
- **Hypothesis**: What Riggs believes happened and why
- **Confidence Assessment**: How certain Riggs is
- **Recommended Actions**: Specific remediation steps

---

## Search

### Global Search

Press `/` anywhere to focus the search bar, or click the search icon in the top bar.

Search across:
- **Alerts**: By title, description, or any field
- **IOCs**: By IP, domain, hash, or URL value
- **Investigations**: By title or content
- **Users**: By username or email

### Advanced Search

Use search operators for precise queries:
- `severity:critical` - Filter by severity
- `status:open` - Filter by status
- `source:crowdstrike` - Filter by source
- `ioc:192.168.1.1` - Search for specific IOC
- `assignee:john` - Find items assigned to a user

---

## Settings

### Profile Settings

Access from the user menu (top-right):
- **Change Password**: Update your password (requires current password)
- **Two-Factor Authentication**: Enable/disable MFA with TOTP
- **Theme**: Switch between dark and light mode
- **Notification Preferences**: Configure how you receive alerts

### Admin Settings

Available to administrators:
- **User Management**: Create, edit, and disable user accounts
- **AI Providers**: Configure AI inference endpoints
- **SMTP Configuration**: Set up email notifications
- **Threat Feeds**: Enable/disable and configure feeds
- **Notification Rules**: Set up automated notifications
- **License Management**: View and activate licenses
- **System Health**: Monitor backend services

---

## Keyboard Shortcuts

Press `?` anywhere to see the full shortcut list.

| Shortcut | Action |
|----------|--------|
| `/` | Focus search bar |
| `?` | Show keyboard shortcuts |
| `Ctrl+Shift+L` | Toggle dark/light mode |
| `Esc` | Close modal/dialog |
| `j` / `k` | Navigate up/down in lists |
| `Enter` | Open selected item |
| `r` | Refresh current view |

---

## Troubleshooting

### Common Issues

**Can't log in?**
- Check that your password meets complexity requirements (12+ chars, mixed case, number, symbol)
- After 3 failed attempts, your account is locked for 10 minutes
- Contact your admin to unlock your account

**Alerts not appearing?**
- Check that alert sources are connected (Settings > Integrations)
- Verify the ingestion service is running (check health indicator)
- Check if filters are hiding the alerts you're looking for

**AI analysis not working?**
- Verify AI provider is configured (Settings > AI Providers)
- Check that the AI server is reachable
- Look for errors in the agent execution log

**Emails not sending?**
- Verify SMTP is configured (Settings > Notifications > SMTP)
- Use the "Test Connection" button to verify
- Check spam/junk folders

### Getting Help

- **In-App Help**: Press `?` for keyboard shortcuts
- **API Documentation**: Visit `/api/docs` for the Swagger UI
- **Issues / Support**: Open an issue on the project's GitHub repository.

---

*T1 Agentics - Autonomous Security Operations*
*Licensed under the Apache License, Version 2.0. See the root LICENSE file.*
