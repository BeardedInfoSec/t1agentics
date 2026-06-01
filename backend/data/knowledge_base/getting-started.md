# Getting Started with T1 Agentics

## Overview

T1 Agentics is a vendor-neutral, AI-assisted Security Operations Center (SOC) and Security Orchestration, Automation, and Response (SOAR) platform. It helps security teams triage alerts, investigate incidents, and automate response actions using AI-powered workflows.

## First Steps

### 1. Log In

Navigate to your T1 Agentics instance and sign in with the credentials provided by your administrator. If your organization uses SSO, click the appropriate provider button on the login page.

### 2. Explore the Dashboard

After logging in you will land on the **Dashboard**. The dashboard provides a real-time overview of your security posture:

- **Alert Volume** -- total open alerts broken down by severity.
- **Investigation Pipeline** -- active investigations and their current states.
- **AI Agent Activity** -- a live feed of actions taken by the Riggs AI engine.
- **Mean Time to Respond (MTTR)** -- key performance metrics for your SOC.

### 3. Review the Security Queue

Click **Queue** in the left navigation to view all incoming security events. The queue consolidates alerts from every connected integration (SIEM, EDR, email gateway, etc.) into a single prioritized list. You can:

- Filter by severity, source, status, or owner.
- Bulk-select events for triage actions.
- Click any row to open the **Investigation Workbench** for deep analysis.

### 4. Connect Integrations

Go to **Integrations** to connect your existing security tools. T1 Agentics ships with pre-built connectors for:

- SIEMs (Splunk, Elastic, Microsoft Sentinel)
- EDR / XDR (CrowdStrike, SentinelOne, Microsoft Defender)
- Ticketing (ServiceNow, Jira)
- Threat Intelligence (VirusTotal, AbuseIPDB, MISP)
- Cloud (AWS, Azure, GCP)
- Identity (Okta, Azure AD)

Use the **Integration Builder** to create custom connectors for any REST API.

### 5. Configure AI Agents

Navigate to **Agents** to view and configure the AI agents that power automated triage and response. The default agent -- **Riggs** -- analyzes alerts, correlates IOCs, and recommends dispositions. You can tune agent behavior through:

- Confidence thresholds for auto-closure.
- Escalation rules for high-severity findings.
- Allowed response actions and approval requirements.

### 6. Build Playbooks

Open **Playbooks** to create visual automation workflows. Playbooks let you define step-by-step response procedures that execute automatically when triggered by alerts or on a schedule. The drag-and-drop editor supports:

- Conditional branching
- Integration actions (block IP, disable user, create ticket)
- Human approval gates
- Loop and delay nodes

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Alert** | A raw security event ingested from an integration source. |
| **Investigation** | A case created from one or more correlated alerts for analyst review. |
| **Disposition** | The verdict assigned to an investigation (e.g., True Positive, False Positive, Benign). |
| **Playbook** | A reusable automation workflow triggered by events or schedules. |
| **IOC** | Indicator of Compromise -- an observable (IP, hash, domain, URL) linked to threat activity. |
| **Agent** | An AI-powered worker that performs analysis, enrichment, or response actions. |

## Getting Help

- Use the **Knowledge Base** (accessible from the left nav) to search SOPs and runbooks.
- Press `Ctrl+K` (or `Cmd+K` on macOS) to open **Global Search** across alerts, investigations, IOCs, and documentation.
- Contact your administrator or reach out to T1 Agentics support at support@t1agentics.ai.
