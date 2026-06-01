# Alert Management

## Overview

Alerts are the primary input to T1 Agentics. Every security event ingested from your connected integrations appears in the **Security Queue** for triage. This guide covers how alerts flow through the platform and how to manage them effectively.

## Alert Lifecycle

```
Ingestion --> Queue --> Triage --> Investigation --> Disposition --> Closed
```

1. **Ingestion** -- Alerts arrive via webhooks, API polling, or direct integration connectors.
2. **Queue** -- New alerts appear in the Security Queue with an initial severity and source tag.
3. **Triage** -- Analysts (or the Riggs AI agent) review the alert, enrich IOCs, and decide next steps.
4. **Investigation** -- If the alert warrants deeper analysis, it is promoted to an Investigation.
5. **Disposition** -- A verdict is assigned: True Positive, False Positive, Benign, Suspicious, etc.
6. **Closed** -- The investigation is closed and metrics are recorded.

## Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| **Critical** | Red | Immediate action required. Active compromise or data exfiltration. |
| **High** | Orange | Significant threat. Requires prompt analyst review. |
| **Medium** | Yellow | Moderate risk. Should be reviewed within SLA window. |
| **Low** | Blue | Informational or low-confidence finding. May be auto-closed. |

## Filtering and Sorting

The Security Queue supports rich filtering:

- **Severity** -- Filter by one or more severity levels.
- **Source** -- Show alerts from a specific integration (e.g., only CrowdStrike).
- **Status** -- Open, In Progress, Closed.
- **Owner** -- Assigned analyst or unassigned.
- **Time Range** -- Filter by creation date.
- **Search** -- Free-text search across alert title, description, and IOCs.

Click column headers to sort ascending or descending.

## Bulk Actions

Select multiple alerts using the checkboxes, then use the **Bulk Actions Bar**:

- **Assign** -- Assign selected alerts to an analyst.
- **Change Severity** -- Upgrade or downgrade severity in bulk.
- **Close as False Positive** -- Mark selected alerts as false positives.
- **Merge** -- Combine related alerts into a single investigation.
- **Run Playbook** -- Trigger an automation playbook on all selected alerts.

## Alert Tuning

Repeated false positives waste analyst time. Use **Alert Tuning** (Settings > Alert Tuning) to:

- Create **suppression rules** that auto-close alerts matching specific patterns.
- Adjust severity mappings for specific alert sources.
- Set **correlation rules** that group related alerts into a single investigation.

## AI-Assisted Triage

When the Riggs AI agent is enabled, new alerts are automatically analyzed:

1. IOCs are extracted and enriched against threat intelligence feeds.
2. The alert is correlated with recent investigations for context.
3. A confidence score and recommended disposition are generated.
4. If confidence exceeds the auto-close threshold, the alert is resolved automatically.
5. Otherwise, it is flagged for human review with the AI's analysis attached.

You can review AI decisions in the **Investigation Workbench** and provide feedback to improve future accuracy.

## Alert Sources

T1 Agentics accepts alerts from:

- **Webhooks** -- Any tool that can send HTTP POST requests.
- **SIEM Forwarding** -- Splunk, Elastic, QRadar, Sentinel.
- **EDR Connectors** -- CrowdStrike, SentinelOne, Defender for Endpoint.
- **Email Gateway** -- Phishing report analysis via inbound email.
- **Custom Collectors** -- Deploy the T1 agent on endpoints to forward logs.
- **API Ingestion** -- Programmatic alert submission via the REST API.

## Best Practices

1. **Tune early and often.** Review the top false-positive sources weekly and add suppression rules.
2. **Use correlation rules.** Group related alerts to reduce noise and provide better context.
3. **Set SLA targets.** Define response time goals per severity level and track them on the dashboard.
4. **Leverage AI triage.** Let Riggs handle low-severity alerts so analysts can focus on critical threats.
5. **Document your SOPs.** Add runbooks to the Knowledge Base so analysts have clear procedures for common alert types.
