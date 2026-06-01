# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Cybersecurity Framework Mapping Data
Contains mapping rules for automatic framework assignment
"""

# MITRE ATT&CK Techniques Mapping
MITRE_ATTACK_MAPPINGS = {
    # Initial Access
    "phishing": ["T1566", "T1566.001", "T1566.002"],
    "exploit": ["T1190", "T1203"],
    "brute_force": ["T1110", "T1110.001", "T1110.002"],
    "login": ["T1078", "T1078.001", "T1078.002"],
    
    # Execution
    "powershell": ["T1059.001"],
    "command_line": ["T1059.003"],
    "script": ["T1059", "T1059.006"],
    "malware": ["T1204", "T1204.002"],
    
    # Persistence
    "registry": ["T1547.001"],
    "scheduled_task": ["T1053.005"],
    "service": ["T1543.003"],
    
    # Privilege Escalation
    "sudo": ["T1548.003"],
    "token": ["T1134"],
    
    # Defense Evasion
    "obfuscation": ["T1027"],
    "disable_security": ["T1562.001"],
    
    # Credential Access
    "credential_dump": ["T1003"],
    "keylogger": ["T1056.001"],
    
    # Discovery
    "network_scan": ["T1046"],
    "process_discovery": ["T1057"],
    "system_info": ["T1082"],
    
    # Lateral Movement
    "rdp": ["T1021.001"],
    "ssh": ["T1021.004"],
    
    # Collection
    "screen_capture": ["T1113"],
    "data_staged": ["T1074"],
    
    # Exfiltration
    "exfiltration": ["T1041"],
    "dns_tunnel": ["T1048.003"],
    
    # Impact
    "ransomware": ["T1486"],
    "data_destruction": ["T1485"]
}

# MITRE ATT&CK Tactics
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact"
}

# NIST CSF Functions and Categories
NIST_CSF_MAPPINGS = {
    "detect": {
        "anomaly": "DE.AE-2",
        "security_event": "DE.AE-3",
        "impact": "DE.AE-5",
        "monitoring": "DE.CM-1",
        "network": "DE.CM-7",
        "malware": "DE.CM-4"
    },
    "respond": {
        "incident": "RS.AN-1",
        "analysis": "RS.AN-2",
        "mitigation": "RS.MI-1",
        "improvement": "RS.IM-1"
    },
    "protect": {
        "access": "PR.AC-1",
        "data": "PR.DS-1",
        "security": "PR.PT-1"
    },
    "identify": {
        "asset": "ID.AM-1",
        "risk": "ID.RA-1"
    },
    "recover": {
        "plan": "RC.RP-1",
        "improvement": "RC.IM-1"
    }
}

# CIS Controls v8
CIS_CONTROLS_MAPPINGS = {
    "malware": ["CSC 10.1", "CSC 10.5"],
    "login": ["CSC 5.1", "CSC 5.2", "CSC 6.1"],
    "authentication": ["CSC 6.1", "CSC 6.2"],
    "network": ["CSC 13.1", "CSC 13.2"],
    "monitoring": ["CSC 8.1", "CSC 8.2"],
    "email": ["CSC 7.1", "CSC 7.2"],
    "audit": ["CSC 8.1", "CSC 8.5"],
    "vulnerability": ["CSC 7.1", "CSC 7.2"],
    "incident": ["CSC 17.1", "CSC 17.2"]
}

# Cyber Kill Chain Phases
KILL_CHAIN_MAPPINGS = {
    "recon": ["Reconnaissance"],
    "phishing": ["Weaponization", "Delivery"],
    "exploit": ["Exploitation"],
    "malware": ["Installation"],
    "c2": ["Command and Control"],
    "command_control": ["Command and Control"],
    "exfiltration": ["Actions on Objectives"],
    "lateral": ["Lateral Movement"]
}

# NIST 800-61 Incident Handling
NIST_800_61_PHASES = {
    "preparation": ["Detection tools deployed", "Response plan ready"],
    "detection": ["Alert triggered", "Anomaly detected"],
    "analysis": ["Investigation ongoing", "IOC analysis"],
    "containment": ["Threat isolated", "Access blocked"],
    "eradication": ["Malware removed", "Vulnerability patched"],
    "recovery": ["Systems restored", "Monitoring active"],
    "post_incident": ["Lessons learned", "Documentation complete"]
}

# ISO 27001 Controls
ISO_27001_MAPPINGS = {
    "access_control": ["A.9.1.1", "A.9.2.1"],
    "cryptography": ["A.10.1.1"],
    "physical": ["A.11.1.1"],
    "operations": ["A.12.1.1"],
    "communications": ["A.13.1.1"],
    "incident": ["A.16.1.1", "A.16.1.2"],
    "compliance": ["A.18.1.1"]
}

# SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons)
SANS_PICERL_MAPPINGS = {
    "preparation": ["Alert monitoring", "Response readiness"],
    "identification": ["Threat detected", "Scope determined"],
    "containment": ["Threat isolated", "Spread prevented"],
    "eradication": ["Threat removed", "Root cause addressed"],
    "recovery": ["Systems restored", "Normal operations"],
    "lessons": ["Documentation", "Process improvement"]
}

# Zero Trust (NIST 800-207)
ZERO_TRUST_MAPPINGS = {
    "identity": ["ZT-ID-1", "ZT-ID-2"],
    "device": ["ZT-DV-1", "ZT-DV-2"],
    "network": ["ZT-NW-1", "ZT-NW-2"],
    "data": ["ZT-DT-1", "ZT-DT-2"],
    "application": ["ZT-AP-1", "ZT-AP-2"],
    "visibility": ["ZT-VS-1", "ZT-VS-2"]
}

# Severity-based framework priorities
SEVERITY_FRAMEWORK_PRIORITY = {
    "critical": ["MITRE ATT&CK", "NIST CSF", "Kill Chain"],
    "high": ["MITRE ATT&CK", "NIST CSF", "CIS Controls"],
    "medium": ["NIST CSF", "CIS Controls", "ISO 27001"],
    "low": ["CIS Controls", "ISO 27001"]
}

# IOC Type to Framework mapping
IOC_FRAMEWORK_MAPPING = {
    "ip": ["MITRE ATT&CK: C2", "NIST CSF: DE.CM-7"],
    "domain": ["MITRE ATT&CK: C2", "Kill Chain: Command and Control"],
    "url": ["MITRE ATT&CK: Initial Access", "NIST CSF: DE.AE-2"],
    "hash": ["MITRE ATT&CK: Execution", "CIS Controls: CSC 10.1"],
    "email": ["MITRE ATT&CK: T1566", "CIS Controls: CSC 7.1"],
    "cve": ["NIST CSF: PR.PT-1", "CIS Controls: CSC 7.1"]
}


def get_framework_matches(investigation_data):
    """
    Analyze investigation and return matched frameworks
    
    Args:
        investigation_data: Dict containing alert, IOCs, severity, etc.
    
    Returns:
        Dict with matched frameworks and controls
    """
    matches = {
        "mitre_attack": [],
        "mitre_tactics": [],
        "nist_csf": [],
        "cis_controls": [],
        "kill_chain": [],
        "nist_800_61": [],
        "iso_27001": [],
        "sans_picerl": [],
        "zero_trust": []
    }
    
    # Extract data
    title = investigation_data.get("title", "").lower()
    description = investigation_data.get("description", "").lower()
    severity = investigation_data.get("severity", "medium").lower()
    iocs = investigation_data.get("indicators", [])
    
    combined_text = f"{title} {description}"
    
    # Match MITRE ATT&CK
    for keyword, techniques in MITRE_ATTACK_MAPPINGS.items():
        if keyword in combined_text:
            matches["mitre_attack"].extend(techniques)
    
    # Match NIST CSF
    for category, mappings in NIST_CSF_MAPPINGS.items():
        for keyword, control in mappings.items():
            if keyword in combined_text:
                if control not in matches["nist_csf"]:
                    matches["nist_csf"].append(control)
    
    # Match CIS Controls
    for keyword, controls in CIS_CONTROLS_MAPPINGS.items():
        if keyword in combined_text:
            matches["cis_controls"].extend(controls)
    
    # Match Kill Chain
    for keyword, phases in KILL_CHAIN_MAPPINGS.items():
        if keyword in combined_text:
            matches["kill_chain"].extend(phases)
    
    # Match based on IOC types
    for ioc in iocs:
        ioc_type = ioc.get("type", "").lower()
        if ioc_type in IOC_FRAMEWORK_MAPPING:
            for framework_ref in IOC_FRAMEWORK_MAPPING[ioc_type]:
                if "MITRE" in framework_ref:
                    technique = framework_ref.split(": ")[1]
                    if technique not in matches["mitre_attack"]:
                        matches["mitre_attack"].append(technique)
    
    # NIST 800-61 phase (default to analysis)
    matches["nist_800_61"] = ["analysis"]
    
    # SANS PICERL phase (default to identification)
    matches["sans_picerl"] = ["identification"]
    
    # Remove duplicates
    for key in matches:
        matches[key] = list(set(matches[key]))
    
    return matches
