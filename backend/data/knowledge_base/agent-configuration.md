# Agent Configuration

## Overview

T1 Agentics uses AI-powered agents to automate alert triage, investigation enrichment, and response actions. The primary agent -- **Riggs** -- is a reasoning engine that analyzes security events using large language models (LLMs) combined with structured tool calls.

This guide covers how to configure, tune, and monitor AI agents within the platform.

## Agent Architecture

```
Alert --> Agent Planner --> Tool Calls --> Reasoning --> Verdict + Actions
```

1. **Alert Ingestion** -- An alert or investigation triggers agent analysis.
2. **Planner** -- The agent planner selects which tools and data sources to query.
3. **Tool Calls** -- The agent executes enrichment actions (IOC lookups, reputation checks, WHOIS, sandbox analysis).
4. **Reasoning** -- The LLM synthesizes all gathered evidence into a verdict.
5. **Output** -- A disposition recommendation, confidence score, executive summary, and optional response actions.

## Configuring Riggs

Navigate to **Agents** in the left navigation to access agent configuration.

### Analysis Modes

Riggs supports two analysis modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| **FAST** | Quick analysis with limited tool calls. Lower token usage. | High-volume, low-severity alerts. |
| **DEEP** | Comprehensive analysis with full enrichment chain. | Critical alerts, complex investigations. |

You can set the default mode and override it per-severity level.

### Confidence Thresholds

Configure how Riggs handles its own analysis results:

- **Auto-Close Threshold** (default: 85%) -- Alerts where Riggs confidence exceeds this value and the verdict is Benign or False Positive are automatically closed.
- **Escalation Threshold** (default: 40%) -- Alerts where Riggs confidence is below this value are escalated for human review regardless of verdict.
- **Human Review Required** -- Toggle to require human approval for all AI-generated verdicts.

### Allowed Actions

Control what response actions Riggs can take autonomously:

- **Block IP** -- Add malicious IPs to firewall blocklists.
- **Disable User Account** -- Lock compromised accounts via identity provider integration.
- **Isolate Host** -- Quarantine an endpoint via EDR integration.
- **Create Ticket** -- Open an incident ticket in ServiceNow or Jira.
- **Send Notification** -- Alert the on-call team via email, Slack, or PagerDuty.

Each action can be set to:
- **Autonomous** -- Agent executes without approval.
- **Approval Required** -- Agent requests human approval before executing.
- **Disabled** -- Agent cannot take this action.

### Tool Configuration

Agents use tools to gather evidence. Available tools include:

- **IOC Lookup** -- Query threat intelligence feeds (VirusTotal, AbuseIPDB, OTX).
- **WHOIS** -- Domain and IP registration lookups.
- **DNS Resolution** -- Forward and reverse DNS queries.
- **Sandbox Analysis** -- Submit files or URLs to sandbox environments.
- **SIEM Query** -- Search historical logs for related activity.
- **Asset Lookup** -- Check the asset inventory for host context.
- **User Lookup** -- Query identity providers for user account details.

## LLM Mesh Configuration

T1 Agentics supports multiple LLM backends for flexibility and redundancy:

- **vLLM** -- Self-hosted open-source models (default).
- **OpenAI** -- GPT-4 and compatible models via API.
- **Anthropic** -- Claude models via API.
- **Custom** -- Any OpenAI-compatible endpoint.

Navigate to **Dashboard > vLLM Mesh** to manage LLM nodes:

1. Add or remove model endpoints.
2. Set routing weights for load balancing.
3. Monitor latency, throughput, and error rates.
4. Configure failover behavior.

## Approval Workflows

For high-impact actions, configure approval gates:

1. Go to **Workbench > Approvals**.
2. Set which actions require approval and who can approve them.
3. Approvers receive notifications via email or Slack with one-click approve/deny links.
4. Pending approvals time out after a configurable window (default: 4 hours).

## Monitoring Agent Performance

Track agent effectiveness on the **Dashboard > Operations** view:

- **Verdict Accuracy** -- Compare AI verdicts against human analyst overrides.
- **Auto-Close Rate** -- Percentage of alerts resolved without human intervention.
- **Mean Analysis Time** -- Average time from alert ingestion to AI verdict.
- **Token Usage** -- LLM token consumption over time.
- **Escalation Rate** -- Frequency of low-confidence escalations.

Use the **Riggs Feedback** system to provide corrections. Every time an analyst overrides an AI verdict, the feedback is recorded and used to improve future analysis.

## Best Practices

1. **Start conservative.** Begin with approval-required mode for all response actions, then relax as you build confidence.
2. **Review AI decisions daily.** Check the Operations dashboard for accuracy trends and provide feedback on incorrect verdicts.
3. **Tune per-source.** Different alert sources have different false-positive rates. Adjust confidence thresholds accordingly.
4. **Use FAST mode for volume.** Reserve DEEP mode for critical and high-severity alerts to manage LLM costs.
5. **Keep the Knowledge Base current.** Agents reference SOPs during analysis. Up-to-date runbooks lead to better verdicts.
6. **Monitor token usage.** Set budget alerts to avoid unexpected LLM costs, especially when using cloud-hosted models.
