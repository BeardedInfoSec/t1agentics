# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
AI Agent Prompt Templates

Reusable, tested prompts for security analysis tasks.
"""

# System prompts
SECURITY_ANALYST_SYSTEM = """You are an expert security analyst with deep knowledge of:
- Threat detection and analysis
- Incident response procedures
- MITRE ATT&CK framework
- IOC analysis and threat intelligence
- Network security and forensics

You provide clear, actionable security analysis. You are thorough but concise.
You always consider false positives and provide confidence levels."""

TRIAGE_SYSTEM = """You are a security triage system. Your job is to quickly classify alerts as:
- BENIGN: No security concern
- SUSPICIOUS: Requires investigation
- MALICIOUS: Clear threat detected

Be decisive and provide brief reasoning."""

# Investigation prompts
INVESTIGATE_ALERT_PROMPT = """Analyze this security alert and provide a comprehensive investigation:

**Alert Details:**
Title: {alert_title}
Description: {alert_description}
Source: {alert_source}
Timestamp: {alert_timestamp}

**Indicators:**
{indicators}

**Enrichment Data:**
{enrichment_data}

**Provide:**
1. Executive Summary (2-3 sentences)
2. Technical Findings (detailed analysis)
3. Verdict (BENIGN, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)
4. Confidence Level (LOW, MEDIUM, HIGH)
5. Severity (LOW, MEDIUM, HIGH, CRITICAL)
6. Recommended Actions (prioritized list)
7. IOC Analysis (for each indicator)
8. Timeline of Events

Format as structured JSON."""

TRIAGE_ALERT_PROMPT = """Triage this security alert:

Title: {alert_title}
Description: {alert_description}

Classify as:
- BENIGN
- SUSPICIOUS  
- MALICIOUS

Respond in JSON:
{{
  "verdict": "...",
  "confidence": "LOW|MEDIUM|HIGH",
  "reason": "brief explanation"
}}"""

ENRICH_IOC_PROMPT = """Analyze this Indicator of Compromise:

Type: {ioc_type}
Value: {ioc_value}
Context: {context}

**Provide:**
1. What this IOC represents
2. Known associations (malware, campaigns, threat actors)
3. Risk level
4. Recommended actions

**Known Data:**
{enrichment_data}

Be factual and cite sources when available."""

# Response parsing prompts
EXTRACT_JSON_PROMPT = """Extract the JSON object from this response and return ONLY valid JSON:

{response}

Return ONLY the JSON object, no markdown, no explanation."""

# Correlation prompts
CORRELATE_IOCS_PROMPT = """Analyze these IOCs for correlations:

{iocs}

Identify:
1. Related indicators (same campaign, malware family, etc.)
2. Temporal correlations
3. Behavioral patterns
4. Threat actor associations

Provide correlation score (0-100) and explanation."""

# Timeline prompts
GENERATE_TIMELINE_PROMPT = """Generate an attack timeline from this data:

**Alert:** {alert_title}
**Indicators:** {indicators}
**Events:** {events}

Create a chronological timeline showing:
1. Initial compromise vector
2. Persistence mechanisms
3. Lateral movement
4. Data access/exfiltration
5. Command & control

Format as JSON timeline events."""

# Recommendation prompts
RECOMMEND_ACTIONS_PROMPT = """Given this investigation:

**Verdict:** {verdict}
**Severity:** {severity}
**Findings:** {findings}

Provide prioritized recommended actions:
1. Immediate actions (stop the threat)
2. Investigation actions (gather more data)
3. Remediation actions (fix vulnerabilities)
4. Prevention actions (prevent recurrence)

For each action, specify:
- Priority (Critical, High, Medium, Low)
- Rationale
- Whether it can be automated

Format as JSON array."""

# Summary prompts
EXECUTIVE_SUMMARY_PROMPT = """Create an executive summary for this investigation:

**Alert:** {alert_title}
**Verdict:** {verdict}
**Severity:** {severity}
**Key Findings:** {key_findings}

Write a 2-3 sentence executive summary suitable for management.
Focus on business impact and required actions."""


def format_prompt(template: str, **kwargs) -> str:
    """Format a prompt template with variables"""
    return template.format(**kwargs)


def build_investigation_prompt(alert, indicators, enrichment_data):
    """Build a complete investigation prompt"""
    indicators_str = "\n".join([
        f"- {ind.type}: {ind.value}" 
        for ind in indicators
    ]) if indicators else "None"
    
    enrichment_str = str(enrichment_data) if enrichment_data else "None available"
    
    return format_prompt(
        INVESTIGATE_ALERT_PROMPT,
        alert_title=alert.title,
        alert_description=alert.description or "N/A",
        alert_source=alert.source or "Unknown",
        alert_timestamp=alert.timestamp.isoformat() if hasattr(alert, 'timestamp') else "Unknown",
        indicators=indicators_str,
        enrichment_data=enrichment_str
    )


def build_triage_prompt(alert):
    """Build a triage prompt"""
    return format_prompt(
        TRIAGE_ALERT_PROMPT,
        alert_title=alert.title,
        alert_description=alert.description or "N/A"
    )


def build_ioc_enrichment_prompt(ioc_type, ioc_value, context, enrichment_data):
    """Build IOC enrichment prompt"""
    enrichment_str = str(enrichment_data) if enrichment_data else "No enrichment data available"
    
    return format_prompt(
        ENRICH_IOC_PROMPT,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        context=context or "None",
        enrichment_data=enrichment_str
    )
