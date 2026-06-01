#!/usr/bin/env python3
"""
Seed script: Generate SOC playbooks with the new consolidated node system.

Usage (inside backend container):
    python scripts/seed_playbooks.py

Builds canvas_data directly using the new node types:
  - analyze (mode: ai_analysis | enrich)
  - respond (response_type: integration_action | notify | create_ticket)
  - decision, approval (unchanged)

No LLM dependency — deterministic and fast.
"""
import asyncio
import json
import logging
import uuid
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("seed_playbooks")


# ---- Helpers ----
def _id():
    return str(uuid.uuid4())


def _node(kind, label, config, x, y, description=""):
    return {
        "id": _id(),
        "type": "signal",
        "position": {"x": x, "y": y},
        "data": {
            "kind": kind,
            "title": label,
            "summary": description,
            "config": config,
        },
    }


def _edge(source_id, target_id, label=None, source_handle=None):
    e = {
        "id": _id(),
        "source": source_id,
        "target": target_id,
        "animated": True,
        "type": "smoothstep",
    }
    if label:
        e["data"] = {"label": label}
    if source_handle:
        e["sourceHandle"] = source_handle
    return e


def _trigger(alert_type, x=100, y=50, description=""):
    return _node("trigger", f"{alert_type.replace('_', ' ').title()} Trigger", {
        "trigger_type": "alert",
        "alert_filter": f"type:{alert_type}",
    }, x, y, description)


def _ai_analysis(label, prompt, focus="threat_assessment", x=100, y=200):
    return _node("analyze", label, {
        "mode": "ai_analysis",
        "prompt": prompt,
        "alert_path": "$.trigger.alert",
        "focus": focus,
        "include_context": True,
    }, x, y, "Riggs AI threat analysis")


def _enrich(label, obs_type="ip", obs_path="$.trigger.alert.src_ip", sources=None, x=100, y=200):
    return _node("analyze", label, {
        "mode": "enrich",
        "observable_type": obs_type,
        "observable_path": obs_path,
        "sources": sources or ["virustotal", "abuseipdb"],
        "aggregate_results": True,
    }, x, y, f"Enrich {obs_type} via threat intel")


def _decision(label, expression="", x=100, y=400, branches=None):
    return _node("decision", label, {
        "conditions": {
            "id": _id(),
            "operator": "AND",
            "conditions": [{
                "id": _id(),
                "left": {"type": "path", "value": "$.nodes.*.output.verdict"},
                "operator": "equals",
                "right": {"type": "value", "value": "malicious"},
            }],
            "groups": [],
        },
        "expression": expression or "verdict == malicious",
        "branches": branches or [
            {"id": "yes", "label": "Yes"},
            {"id": "no", "label": "No"},
        ],
    }, x, y, "Conditional branching")


def _action(label, integration="", action_type="", x=100, y=600, approval=True):
    return _node("respond", label, {
        "response_type": "integration_action",
        "integration_instance_id": integration,
        "endpoint_id": action_type,
        "action_type": action_type,
        "params": {},
        "target_path": "$.trigger.alert.entity",
        "requires_approval": approval,
        "priority": "high",
    }, x, y, f"Execute {action_type or 'integration action'}")


def _notify(label, channel="slack", slack_channel="#security-alerts", message="", x=100, y=600):
    return _node("respond", label, {
        "response_type": "notify",
        "channel": channel,
        "slack_channel": slack_channel,
        "teams_webhook": "",
        "email_recipients": "",
        "email_subject": "",
        "webhook_url": "",
        "message": message or "Alert: {{$.trigger.alert.title}}",
    }, x, y, f"Notify via {channel}")


def _ticket(label, system="jira", project_key="SEC", title="", x=100, y=600):
    return _node("respond", label, {
        "response_type": "create_ticket",
        "system": system,
        "project_key": project_key,
        "issue_type": "Incident",
        "table": "incident",
        "title": title or "Security Alert: {{$.trigger.alert.title}}",
        "description": "Auto-generated from playbook execution.\n\nAlert: {{$.trigger.alert.title}}\nSeverity: {{$.trigger.alert.severity}}",
        "priority": "high",
    }, x, y, f"Create {system} ticket")


def _approval(label, message="", x=100, y=500):
    return _node("approval", label, {
        "message": message or "Approval required before executing response action",
        "assign_to": "soc-lead",
        "timeout_minutes": "30",
        "auto_decision": "none",
        "escalation": "on-call",
    }, x, y, "Human approval gate")


def _end(disposition="completed", x=100, y=800):
    return _node("end", "End", {
        "disposition": disposition,
        "summary": "",
    }, x, y, "Playbook complete")


def _utility(label, operation, x=100, y=700, **kwargs):
    config = {"operation": operation}
    config.update(kwargs)
    return _node("utility", label, config, x, y, f"Utility: {operation}")


# ---- Playbook Builders ----

def build_phishing_response():
    trigger = _trigger("phishing", 300, 50, "Phishing alert received")
    ai = _ai_analysis("AI Threat Analysis", "Analyze this phishing email for sender reputation, URL safety, attachment analysis, and recommend response actions.", "threat_assessment", 300, 180)
    enrich_ip = _enrich("Enrich Sender IP", "ip", "$.trigger.alert.src_ip", ["virustotal", "abuseipdb", "greynoise"], 100, 340)
    enrich_domain = _enrich("Enrich URLs/Domains", "domain", "$.trigger.alert.indicators.domains[0]", ["virustotal", "abuseipdb"], 500, 340)
    decision = _decision("Malicious?", "verdict == malicious", 300, 500)
    approval = _approval("Approve Block", "Block sender domain and quarantine email?", 150, 660)
    block = _action("Block Sender Domain", "", "block_domain", 50, 830, False)
    notify = _notify("Notify SOC", "slack", "#soc-alerts", "Phishing confirmed: {{$.trigger.alert.title}} — sender domain blocked", 300, 830)
    ticket = _ticket("Create Incident Ticket", "jira", "SEC", "Phishing: {{$.trigger.alert.title}}", 550, 830)
    end_m = _end("mitigated", 300, 1000)
    end_b = _end("benign", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich_ip["id"]),
        _edge(ai["id"], enrich_domain["id"]),
        _edge(enrich_ip["id"], decision["id"]),
        _edge(enrich_domain["id"], decision["id"]),
        _edge(decision["id"], approval["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(approval["id"], block["id"]),
        _edge(approval["id"], notify["id"]),
        _edge(approval["id"], ticket["id"]),
        _edge(block["id"], end_m["id"]),
        _edge(notify["id"], end_m["id"]),
        _edge(ticket["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich_ip, enrich_domain, decision, approval, block, notify, ticket, end_m, end_b],
        "edges": edges,
    }


def build_malware_triage():
    trigger = _trigger("malware", 300, 50, "Malware detection alert")
    ai = _ai_analysis("Classify & Extract IOCs", "Classify the malware severity, extract file hashes, IPs, and domains. Determine if immediate containment is needed.", "ioc_extraction", 300, 180)
    enrich = _enrich("Enrich File Hashes", "hash", "$.trigger.alert.file_hash", ["virustotal", "crowdstrike"], 300, 340)
    decision = _decision("Confirmed Malicious?", "verdict == malicious", 300, 500)
    action = _action("Isolate Host", "", "isolate_endpoint", 150, 660, True)
    notify = _notify("Notify IR Team", "slack", "#incident-response", "MALWARE CONFIRMED on {{$.trigger.alert.hostname}} — host isolated", 400, 660)
    ticket = _ticket("Create IR Ticket", "jira", "SEC", "Malware: {{$.trigger.alert.title}}", 300, 830)
    escalate = _utility("Escalate Alert", "update_severity", 100, 830, severity="critical")
    end_m = _end("mitigated", 300, 1000)
    end_b = _end("benign", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich["id"]),
        _edge(enrich["id"], decision["id"]),
        _edge(decision["id"], action["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(action["id"], notify["id"]),
        _edge(notify["id"], ticket["id"]),
        _edge(action["id"], escalate["id"]),
        _edge(ticket["id"], end_m["id"]),
        _edge(escalate["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich, decision, action, notify, ticket, escalate, end_m, end_b],
        "edges": edges,
    }


def build_brute_force():
    trigger = _trigger("brute_force", 300, 50, "Multiple failed login attempts")
    ai = _ai_analysis("Analyze Login Pattern", "Analyze the authentication failure pattern. Determine if this is a targeted brute force attack, credential stuffing, or normal failures.", "threat_assessment", 300, 180)
    enrich = _enrich("Enrich Source IP", "ip", "$.trigger.alert.src_ip", ["virustotal", "abuseipdb", "greynoise"], 300, 340)
    decision = _decision("Brute Force Confirmed?", "is_brute_force == true AND ip_reputation == malicious", 300, 500)
    approval = _approval("Approve IP Block", "Block source IP at firewall?", 200, 660)
    block = _action("Block IP at Firewall", "", "block_ip", 100, 830, False)
    notify = _notify("Notify Security", "slack", "#soc-alerts", "Brute force attack blocked: {{$.trigger.alert.src_ip}}", 350, 830)
    end_m = _end("mitigated", 300, 1000)
    end_b = _end("benign", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich["id"]),
        _edge(enrich["id"], decision["id"]),
        _edge(decision["id"], approval["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(approval["id"], block["id"]),
        _edge(approval["id"], notify["id"]),
        _edge(block["id"], end_m["id"]),
        _edge(notify["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich, decision, approval, block, notify, end_m, end_b],
        "edges": edges,
    }


def build_suspicious_login():
    trigger = _trigger("suspicious_login", 300, 50, "Impossible travel or unusual login")
    ai = _ai_analysis("Assess Login Risk", "Analyze the login for impossible travel, device fingerprint mismatch, unusual geo-location, or VPN hop. Calculate risk score.", "threat_assessment", 300, 180)
    enrich = _enrich("Enrich Login IP", "ip", "$.trigger.alert.src_ip", ["virustotal", "abuseipdb", "shodan"], 300, 340)
    decision = _decision("High Risk?", "risk_score >= 0.7", 300, 500)
    action = _action("Force Password Reset", "", "reset_password", 150, 660, True)
    notify = _notify("Notify Manager", "email", "", "Suspicious login detected for {{$.trigger.alert.username}} from {{$.trigger.alert.src_ip}}", 400, 660)
    ticket = _ticket("Create Review Ticket", "jira", "SEC", "Suspicious login: {{$.trigger.alert.username}}", 300, 830)
    end_m = _end("under_review", 300, 1000)
    end_b = _end("benign", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich["id"]),
        _edge(enrich["id"], decision["id"]),
        _edge(decision["id"], action["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(action["id"], notify["id"]),
        _edge(notify["id"], ticket["id"]),
        _edge(ticket["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich, decision, action, notify, ticket, end_m, end_b],
        "edges": edges,
    }


def build_ioc_enrichment():
    trigger = _trigger("security_alert", 300, 50, "Any security alert")
    ai = _ai_analysis("Extract IOCs", "Extract all indicators of compromise from the alert: IPs, domains, file hashes, URLs, email addresses. Classify each by type.", "ioc_extraction", 300, 180)
    enrich_ip = _enrich("Enrich IPs", "ip", "$.trigger.alert.indicators.ips[0]", ["virustotal", "abuseipdb", "shodan", "greynoise"], 100, 340)
    enrich_domain = _enrich("Enrich Domains", "domain", "$.trigger.alert.indicators.domains[0]", ["virustotal", "abuseipdb"], 300, 340)
    enrich_hash = _enrich("Enrich Hashes", "hash", "$.trigger.alert.indicators.hashes[0]", ["virustotal", "crowdstrike"], 500, 340)
    decision = _decision("Any High-Risk IOC?", "max_threat_score >= 70", 300, 520)
    escalate = _utility("Escalate Alert", "update_severity", 150, 680, severity="high")
    notify = _notify("Notify SOC", "slack", "#threat-intel", "High-risk IOCs detected in {{$.trigger.alert.title}}", 400, 680)
    end_e = _end("escalated", 300, 850)
    end_b = _end("informational", 600, 680)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich_ip["id"]),
        _edge(ai["id"], enrich_domain["id"]),
        _edge(ai["id"], enrich_hash["id"]),
        _edge(enrich_ip["id"], decision["id"]),
        _edge(enrich_domain["id"], decision["id"]),
        _edge(enrich_hash["id"], decision["id"]),
        _edge(decision["id"], escalate["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(escalate["id"], notify["id"]),
        _edge(notify["id"], end_e["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich_ip, enrich_domain, enrich_hash, decision, escalate, notify, end_e, end_b],
        "edges": edges,
    }


def build_ransomware_response():
    trigger = _trigger("ransomware", 300, 50, "Ransomware detection alert")
    ai = _ai_analysis("Confirm Ransomware", "Confirm ransomware indicators. Identify the variant, encryption status, lateral movement, and C2 communication. Prioritize containment.", "attack_chain", 300, 180)
    enrich_hash = _enrich("Enrich File Hashes", "hash", "$.trigger.alert.file_hash", ["virustotal", "crowdstrike"], 150, 340)
    enrich_c2 = _enrich("Enrich C2 Domains", "domain", "$.trigger.alert.c2_domain", ["virustotal", "abuseipdb"], 500, 340)
    decision = _decision("Ransomware Confirmed?", "is_ransomware == true", 300, 520)
    approval = _approval("Approve Network Isolation", "Isolate affected segment from network? This will disrupt services.", 200, 680)
    isolate = _action("Isolate Hosts", "", "isolate_endpoint", 50, 850, False)
    block_c2 = _action("Block C2 Communication", "", "block_domain", 250, 850, False)
    notify_ir = _notify("Notify IR Team", "slack", "#incident-response", "RANSOMWARE CONFIRMED — containment in progress", 450, 850)
    notify_mgmt = _notify("Notify Management", "email", "", "CRITICAL: Ransomware incident detected. IR team engaged.", 650, 850)
    ticket = _ticket("Create P1 Ticket", "jira", "SEC", "CRITICAL: Ransomware — {{$.trigger.alert.title}}", 300, 1020)
    end_m = _end("contained", 300, 1180)
    end_b = _end("false_positive", 600, 680)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich_hash["id"]),
        _edge(ai["id"], enrich_c2["id"]),
        _edge(enrich_hash["id"], decision["id"]),
        _edge(enrich_c2["id"], decision["id"]),
        _edge(decision["id"], approval["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(approval["id"], isolate["id"]),
        _edge(approval["id"], block_c2["id"]),
        _edge(approval["id"], notify_ir["id"]),
        _edge(approval["id"], notify_mgmt["id"]),
        _edge(isolate["id"], ticket["id"]),
        _edge(block_c2["id"], ticket["id"]),
        _edge(notify_ir["id"], ticket["id"]),
        _edge(notify_mgmt["id"], ticket["id"]),
        _edge(ticket["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich_hash, enrich_c2, decision, approval, isolate, block_c2, notify_ir, notify_mgmt, ticket, end_m, end_b],
        "edges": edges,
    }


def build_data_exfiltration():
    trigger = _trigger("data_exfiltration", 300, 50, "DLP or anomalous data transfer")
    ai = _ai_analysis("Analyze Transfer", "Analyze the data transfer pattern. Is the volume unusual? Is the destination suspicious? Is this a sanctioned business process?", "threat_assessment", 300, 180)
    enrich = _enrich("Enrich Destination", "ip", "$.trigger.alert.dst_ip", ["virustotal", "abuseipdb", "shodan"], 300, 340)
    decision = _decision("Suspicious Exfiltration?", "is_exfiltration == true", 300, 500)
    action = _action("Throttle Transfer", "", "throttle_traffic", 150, 660, True)
    notify = _notify("Notify Security", "slack", "#dlp-alerts", "Potential data exfiltration detected: {{$.trigger.alert.title}}", 400, 660)
    ticket = _ticket("Create Compliance Ticket", "jira", "COMP", "Data exfiltration: {{$.trigger.alert.title}}", 300, 830)
    end_m = _end("under_investigation", 300, 1000)
    end_b = _end("legitimate", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich["id"]),
        _edge(enrich["id"], decision["id"]),
        _edge(decision["id"], action["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(action["id"], notify["id"]),
        _edge(notify["id"], ticket["id"]),
        _edge(ticket["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich, decision, action, notify, ticket, end_m, end_b],
        "edges": edges,
    }


def build_vuln_scan_response():
    trigger = _trigger("vulnerability", 300, 50, "Vulnerability scan completed")
    ai = _ai_analysis("Prioritize Vulns", "Prioritize discovered vulnerabilities by CVSS score, exploitability, asset criticality, and active threat landscape. Generate executive summary.", "recommendations", 300, 180)
    decision = _decision("Critical Vulns Found?", "max_cvss >= 9.0", 300, 340, [
        {"id": "critical", "label": "Critical"},
        {"id": "high", "label": "High"},
        {"id": "low", "label": "Low/None"},
    ])
    ticket_crit = _ticket("Create P1 Ticket", "jira", "SEC", "CRITICAL Vuln: {{$.trigger.alert.cve}}", 80, 520)
    ticket_high = _ticket("Create P2 Ticket", "jira", "SEC", "HIGH Vuln: {{$.trigger.alert.cve}}", 300, 520)
    notify = _notify("Notify Asset Owner", "email", "", "Vulnerability found on your asset: {{$.trigger.alert.hostname}}", 150, 700)
    notify_team = _notify("Notify Security Team", "slack", "#vulnerability-mgmt", "Scan complete: {{$.trigger.alert.title}}", 400, 700)
    end = _end("completed", 300, 870)
    end_low = _end("informational", 550, 520)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], decision["id"]),
        _edge(decision["id"], ticket_crit["id"], "Critical", "critical"),
        _edge(decision["id"], ticket_high["id"], "High", "high"),
        _edge(decision["id"], end_low["id"], "Low/None", "low"),
        _edge(ticket_crit["id"], notify["id"]),
        _edge(ticket_high["id"], notify["id"]),
        _edge(notify["id"], notify_team["id"]),
        _edge(notify_team["id"], end["id"]),
    ]
    return {
        "nodes": [trigger, ai, decision, ticket_crit, ticket_high, notify, notify_team, end, end_low],
        "edges": edges,
    }


def build_insider_threat():
    trigger = _trigger("insider_threat", 300, 50, "User behavior anomaly")
    ai = _ai_analysis("Correlate Activities", "Correlate user activities across systems. Assess data access patterns, off-hours activity, large downloads, and communication with external parties.", "threat_assessment", 300, 180)
    enrich = _enrich("Enrich External IPs", "ip", "$.trigger.alert.external_ips[0]", ["virustotal", "abuseipdb"], 300, 340)
    decision = _decision("Elevated Risk?", "risk_score >= 0.8", 300, 500)
    approval = _approval("Approve Access Restriction", "Restrict this user's access? This will impact their work.", 200, 660)
    action = _action("Restrict User Access", "", "restrict_access", 100, 830, False)
    notify_hr = _notify("Notify HR", "email", "", "Insider threat alert for {{$.trigger.alert.username}} — access restricted pending investigation", 350, 830)
    notify_mgmt = _notify("Notify Security Mgmt", "slack", "#security-leadership", "Insider threat investigation opened: {{$.trigger.alert.username}}", 550, 830)
    ticket = _ticket("Create Investigation Ticket", "jira", "SEC", "Insider Threat: {{$.trigger.alert.username}}", 300, 1000)
    end_m = _end("under_investigation", 300, 1160)
    end_b = _end("cleared", 600, 660)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], enrich["id"]),
        _edge(enrich["id"], decision["id"]),
        _edge(decision["id"], approval["id"], "Yes", "yes"),
        _edge(decision["id"], end_b["id"], "No", "no"),
        _edge(approval["id"], action["id"]),
        _edge(approval["id"], notify_hr["id"]),
        _edge(approval["id"], notify_mgmt["id"]),
        _edge(action["id"], ticket["id"]),
        _edge(notify_hr["id"], ticket["id"]),
        _edge(notify_mgmt["id"], ticket["id"]),
        _edge(ticket["id"], end_m["id"]),
    ]
    return {
        "nodes": [trigger, ai, enrich, decision, approval, action, notify_hr, notify_mgmt, ticket, end_m, end_b],
        "edges": edges,
    }


def build_cloud_security():
    trigger = _trigger("cloud_security", 300, 50, "Cloud infrastructure alert")
    ai = _ai_analysis("Classify Cloud Threat", "Classify this cloud security alert. Is it a misconfiguration, unauthorized access, or active attack? Recommend response actions.", "threat_assessment", 300, 180)
    decision = _decision("Threat Type?", "threat_class", 300, 340, [
        {"id": "attack", "label": "Active Attack"},
        {"id": "unauth", "label": "Unauthorized Access"},
        {"id": "misconfig", "label": "Misconfiguration"},
    ])
    # Active Attack path
    escalate = _utility("Escalate to IR", "update_severity", 50, 520, severity="critical")
    notify_ir = _notify("Alert IR Team", "slack", "#incident-response", "ACTIVE CLOUD ATTACK: {{$.trigger.alert.title}}", 50, 700)
    # Unauthorized Access path
    action = _action("Revoke Credentials", "", "revoke_credentials", 300, 520, True)
    notify_ops = _notify("Notify Cloud Ops", "slack", "#cloud-ops", "Unauthorized access detected: {{$.trigger.alert.title}} — credentials revoked", 300, 700)
    # Misconfiguration path
    ticket = _ticket("Create Remediation Ticket", "jira", "CLOUD", "Misconfiguration: {{$.trigger.alert.title}}", 550, 520)
    notify_owner = _notify("Notify Resource Owner", "email", "", "Cloud misconfiguration found on your resource: {{$.trigger.alert.resource}}", 550, 700)
    end = _end("completed", 300, 870)

    edges = [
        _edge(trigger["id"], ai["id"]),
        _edge(ai["id"], decision["id"]),
        _edge(decision["id"], escalate["id"], "Active Attack", "attack"),
        _edge(decision["id"], action["id"], "Unauthorized Access", "unauth"),
        _edge(decision["id"], ticket["id"], "Misconfiguration", "misconfig"),
        _edge(escalate["id"], notify_ir["id"]),
        _edge(action["id"], notify_ops["id"]),
        _edge(ticket["id"], notify_owner["id"]),
        _edge(notify_ir["id"], end["id"]),
        _edge(notify_ops["id"], end["id"]),
        _edge(notify_owner["id"], end["id"]),
    ]
    return {
        "nodes": [trigger, ai, decision, escalate, notify_ir, action, notify_ops, ticket, notify_owner, end],
        "edges": edges,
    }


# ---- Playbook registry ----
PLAYBOOKS = [
    {
        "name": "Phishing Email Response",
        "description": "Automated phishing email detection, analysis, enrichment, domain blocking, and incident tracking.",
        "builder": build_phishing_response,
        "tags": ["phishing", "email", "automated"],
        "alert_types": ["phishing"],
        "severity": "high",
    },
    {
        "name": "Malware Alert Triage",
        "description": "Automated malware classification, IOC extraction, host isolation, and incident response notification.",
        "builder": build_malware_triage,
        "tags": ["malware", "triage", "containment"],
        "alert_types": ["malware"],
        "severity": "critical",
    },
    {
        "name": "Brute Force Detection & Response",
        "description": "Detect brute force attacks, enrich attacker IP, and block with approval workflow.",
        "builder": build_brute_force,
        "tags": ["brute_force", "authentication", "blocking"],
        "alert_types": ["brute_force"],
        "severity": "high",
    },
    {
        "name": "Suspicious Login Investigation",
        "description": "Investigate impossible travel and anomalous logins with risk scoring and automated response.",
        "builder": build_suspicious_login,
        "tags": ["authentication", "account_compromise", "investigation"],
        "alert_types": ["suspicious_login"],
        "severity": "medium",
    },
    {
        "name": "IOC Enrichment Pipeline",
        "description": "Multi-source IOC enrichment pipeline with automatic escalation for high-risk indicators.",
        "builder": build_ioc_enrichment,
        "tags": ["enrichment", "threat_intel", "ioc"],
        "alert_types": ["security_alert"],
        "severity": "medium",
    },
    {
        "name": "Ransomware Response",
        "description": "Critical ransomware incident response with network isolation, C2 blocking, and multi-channel notification.",
        "builder": build_ransomware_response,
        "tags": ["ransomware", "critical", "containment", "incident_response"],
        "alert_types": ["ransomware"],
        "severity": "critical",
    },
    {
        "name": "Data Exfiltration Detection",
        "description": "Detect and respond to potential data exfiltration with traffic throttling and compliance tracking.",
        "builder": build_data_exfiltration,
        "tags": ["dlp", "data_loss", "compliance"],
        "alert_types": ["data_exfiltration"],
        "severity": "high",
    },
    {
        "name": "Vulnerability Scan Response",
        "description": "Process vulnerability scan results with AI prioritization, tiered ticketing, and owner notification.",
        "builder": build_vuln_scan_response,
        "tags": ["vulnerability", "remediation", "compliance"],
        "alert_types": ["vulnerability"],
        "severity": "medium",
    },
    {
        "name": "Insider Threat Investigation",
        "description": "Investigate insider threat indicators with access restriction, HR notification, and confidential tracking.",
        "builder": build_insider_threat,
        "tags": ["insider_threat", "investigation", "hr"],
        "alert_types": ["insider_threat"],
        "severity": "high",
    },
    {
        "name": "Cloud Security Alert Response",
        "description": "Tri-path cloud security response: active attack escalation, unauthorized access remediation, or misconfiguration ticketing.",
        "builder": build_cloud_security,
        "tags": ["cloud", "aws", "azure", "gcp", "misconfiguration"],
        "alert_types": ["cloud_security"],
        "severity": "high",
    },
]


async def main():
    """Delete all existing playbooks and generate fresh ones."""
    from config.constants import PLATFORM_OWNER_TENANT_ID
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        await postgres_db.connect()

    tenant_id = uuid.UUID(PLATFORM_OWNER_TENANT_ID)

    # Step 1: Delete all existing playbooks (CASCADE handles executions/versions/approvals)
    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant_id))
        await conn.execute("SELECT set_config('app.is_platform_admin', 'true', false)")
        deleted = await conn.execute("DELETE FROM playbooks WHERE tenant_id = $1", tenant_id)
        logger.info(f"Deleted existing playbooks: {deleted}")

    # Step 2: Generate and insert new playbooks
    logger.info(f"Generating {len(PLAYBOOKS)} playbooks for tenant {tenant_id}")
    success = 0

    for i, pb_def in enumerate(PLAYBOOKS, 1):
        name = pb_def["name"]
        logger.info(f"[{i}/{len(PLAYBOOKS)}] Building: {name}")

        try:
            canvas_data = pb_def["builder"]()
            playbook_id = uuid.uuid4()
            node_count = len(canvas_data.get("nodes", []))

            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant_id))
                await conn.execute("SELECT set_config('app.is_platform_admin', 'true', false)")
                await conn.execute('''
                    INSERT INTO playbooks (
                        id, name, description, canvas_data, tags, alert_types,
                        riggs_confidence, is_enabled, tenant_id, created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                ''',
                    playbook_id,
                    name,
                    pb_def["description"],
                    json.dumps(canvas_data),
                    pb_def["tags"],
                    pb_def["alert_types"],
                    0.90,
                    True,
                    tenant_id,
                )

            logger.info(f"  -> {playbook_id} ({node_count} nodes)")
            success += 1

        except Exception as e:
            logger.error(f"  -> FAILED: {name}: {e}", exc_info=True)

    logger.info(f"\nDone! {success}/{len(PLAYBOOKS)} playbooks created.")
    await postgres_db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
