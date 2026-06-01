# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Classification System for T1 Triage Optimization.

Classifies alerts into categories based on source, category, title, and MITRE techniques
to enable specialized prompt selection and enrichment-aware processing.
"""

from enum import Enum
from typing import Set, Dict, Any, List


class AlertFlag(Enum):
    """Alert classification flags for specialized triage handling."""

    PHISHING = "phishing"           # Email threats, credential harvesting
    EMAIL_TRIAGE = "email_triage"   # General email classification (spam vs phishing vs legitimate)
    MALWARE = "malware"             # Malicious files, executables
    LATERAL_MOVEMENT = "lateral"    # PsExec, RDP, SMB lateral movement
    C2_COMMUNICATION = "c2"         # Command & control traffic
    CREDENTIAL_ACCESS = "creds"     # Credential dumping, theft
    DATA_EXFIL = "exfil"            # Data exfiltration indicators
    PERSISTENCE = "persistence"     # Scheduled tasks, registry, services
    PRIVILEGE_ESCALATION = "privesc"  # Privilege escalation attempts
    DEFENSE_EVASION = "evasion"     # Defense evasion techniques
    UNKNOWN = "unknown"             # Cannot classify


# High-risk flags that should wait for enrichment before triage
HIGH_RISK_FLAGS = {
    AlertFlag.MALWARE,
    AlertFlag.C2_COMMUNICATION,
    AlertFlag.CREDENTIAL_ACCESS,
    AlertFlag.DATA_EXFIL
}


class AlertClassifier:
    """Classify alerts based on source, category, and indicators."""

    # Source to flag mappings - default classification based on alert source
    SOURCE_FLAGS: Dict[str, AlertFlag] = {
        "proofpoint": AlertFlag.PHISHING,
        "microsoft_defender": AlertFlag.MALWARE,
        "crowdstrike": AlertFlag.LATERAL_MOVEMENT,
        "carbon_black": AlertFlag.MALWARE,
        "zscaler": AlertFlag.C2_COMMUNICATION,
        "sentinel_one": AlertFlag.MALWARE,
        "palo_alto": AlertFlag.C2_COMMUNICATION,
        "cisco_umbrella": AlertFlag.C2_COMMUNICATION,
        "mimecast": AlertFlag.PHISHING,
        "abnormal_security": AlertFlag.PHISHING,
    }

    # Category keywords to flags - matches against category and title
    CATEGORY_KEYWORDS: Dict[str, AlertFlag] = {
        "phishing": AlertFlag.PHISHING,
        "email": AlertFlag.EMAIL_TRIAGE,  # General email uses EMAIL_TRIAGE for spam/phishing/legitimate classification
        "spam": AlertFlag.EMAIL_TRIAGE,
        "suspicious email": AlertFlag.EMAIL_TRIAGE,
        "email report": AlertFlag.EMAIL_TRIAGE,
        "user reported": AlertFlag.EMAIL_TRIAGE,
        "credential": AlertFlag.CREDENTIAL_ACCESS,
        "password": AlertFlag.CREDENTIAL_ACCESS,
        "malware": AlertFlag.MALWARE,
        "ransomware": AlertFlag.MALWARE,
        "trojan": AlertFlag.MALWARE,
        "virus": AlertFlag.MALWARE,
        "lateral": AlertFlag.LATERAL_MOVEMENT,
        "psexec": AlertFlag.LATERAL_MOVEMENT,
        "remote execution": AlertFlag.LATERAL_MOVEMENT,
        "c2": AlertFlag.C2_COMMUNICATION,
        "command and control": AlertFlag.C2_COMMUNICATION,
        "beacon": AlertFlag.C2_COMMUNICATION,
        "exfil": AlertFlag.DATA_EXFIL,
        "data theft": AlertFlag.DATA_EXFIL,
        "persist": AlertFlag.PERSISTENCE,
        "scheduled task": AlertFlag.PERSISTENCE,
        "registry": AlertFlag.PERSISTENCE,
        "privilege": AlertFlag.PRIVILEGE_ESCALATION,
        "escalation": AlertFlag.PRIVILEGE_ESCALATION,
        "evasion": AlertFlag.DEFENSE_EVASION,
        "obfuscat": AlertFlag.DEFENSE_EVASION,
    }

    # MITRE ATT&CK technique mappings
    MITRE_FLAGS: Dict[str, AlertFlag] = {
        # Phishing
        "T1566": AlertFlag.PHISHING,      # Phishing
        "T1566.001": AlertFlag.PHISHING,  # Spearphishing Attachment
        "T1566.002": AlertFlag.PHISHING,  # Spearphishing Link
        "T1566.003": AlertFlag.PHISHING,  # Spearphishing via Service

        # Execution / Malware
        "T1059": AlertFlag.MALWARE,       # Command and Scripting Interpreter
        "T1059.001": AlertFlag.MALWARE,   # PowerShell
        "T1059.003": AlertFlag.MALWARE,   # Windows Command Shell
        "T1059.005": AlertFlag.MALWARE,   # Visual Basic
        "T1059.007": AlertFlag.MALWARE,   # JavaScript
        "T1204": AlertFlag.MALWARE,       # User Execution
        "T1204.001": AlertFlag.MALWARE,   # Malicious Link
        "T1204.002": AlertFlag.MALWARE,   # Malicious File

        # Lateral Movement
        "T1021": AlertFlag.LATERAL_MOVEMENT,   # Remote Services
        "T1021.001": AlertFlag.LATERAL_MOVEMENT,  # Remote Desktop Protocol
        "T1021.002": AlertFlag.LATERAL_MOVEMENT,  # SMB/Windows Admin Shares
        "T1021.003": AlertFlag.LATERAL_MOVEMENT,  # DCOM
        "T1021.004": AlertFlag.LATERAL_MOVEMENT,  # SSH
        "T1021.006": AlertFlag.LATERAL_MOVEMENT,  # Windows Remote Management
        "T1570": AlertFlag.LATERAL_MOVEMENT,   # Lateral Tool Transfer
        "T1080": AlertFlag.LATERAL_MOVEMENT,   # Taint Shared Content

        # Command and Control
        "T1071": AlertFlag.C2_COMMUNICATION,   # Application Layer Protocol
        "T1071.001": AlertFlag.C2_COMMUNICATION,  # Web Protocols
        "T1071.004": AlertFlag.C2_COMMUNICATION,  # DNS
        "T1573": AlertFlag.C2_COMMUNICATION,   # Encrypted Channel
        "T1095": AlertFlag.C2_COMMUNICATION,   # Non-Application Layer Protocol
        "T1572": AlertFlag.C2_COMMUNICATION,   # Protocol Tunneling
        "T1090": AlertFlag.C2_COMMUNICATION,   # Proxy

        # Credential Access
        "T1003": AlertFlag.CREDENTIAL_ACCESS,  # OS Credential Dumping
        "T1003.001": AlertFlag.CREDENTIAL_ACCESS,  # LSASS Memory
        "T1003.002": AlertFlag.CREDENTIAL_ACCESS,  # SAM
        "T1003.003": AlertFlag.CREDENTIAL_ACCESS,  # NTDS
        "T1110": AlertFlag.CREDENTIAL_ACCESS,  # Brute Force
        "T1555": AlertFlag.CREDENTIAL_ACCESS,  # Credentials from Password Stores
        "T1558": AlertFlag.CREDENTIAL_ACCESS,  # Steal or Forge Kerberos Tickets

        # Data Exfiltration
        "T1041": AlertFlag.DATA_EXFIL,    # Exfiltration Over C2 Channel
        "T1048": AlertFlag.DATA_EXFIL,    # Exfiltration Over Alternative Protocol
        "T1567": AlertFlag.DATA_EXFIL,    # Exfiltration Over Web Service
        "T1020": AlertFlag.DATA_EXFIL,    # Automated Exfiltration

        # Persistence
        "T1053": AlertFlag.PERSISTENCE,   # Scheduled Task/Job
        "T1053.005": AlertFlag.PERSISTENCE,  # Scheduled Task
        "T1547": AlertFlag.PERSISTENCE,   # Boot or Logon Autostart Execution
        "T1547.001": AlertFlag.PERSISTENCE,  # Registry Run Keys
        "T1543": AlertFlag.PERSISTENCE,   # Create or Modify System Process
        "T1543.003": AlertFlag.PERSISTENCE,  # Windows Service
        "T1136": AlertFlag.PERSISTENCE,   # Create Account

        # Privilege Escalation
        "T1548": AlertFlag.PRIVILEGE_ESCALATION,  # Abuse Elevation Control
        "T1548.002": AlertFlag.PRIVILEGE_ESCALATION,  # Bypass UAC
        "T1068": AlertFlag.PRIVILEGE_ESCALATION,  # Exploitation for Privilege Escalation
        "T1134": AlertFlag.PRIVILEGE_ESCALATION,  # Access Token Manipulation
        "T1078": AlertFlag.PRIVILEGE_ESCALATION,  # Valid Accounts

        # Defense Evasion
        "T1055": AlertFlag.DEFENSE_EVASION,  # Process Injection
        "T1027": AlertFlag.DEFENSE_EVASION,  # Obfuscated Files or Information
        "T1140": AlertFlag.DEFENSE_EVASION,  # Deobfuscate/Decode Files
        "T1070": AlertFlag.DEFENSE_EVASION,  # Indicator Removal
        "T1562": AlertFlag.DEFENSE_EVASION,  # Impair Defenses
    }

    @classmethod
    def classify(cls, alert_data: Dict[str, Any]) -> Set[AlertFlag]:
        """
        Classify an alert and return set of applicable flags.

        Args:
            alert_data: Alert dictionary containing source, category, title, raw_event, etc.

        Returns:
            Set of AlertFlag values applicable to this alert
        """
        flags: Set[AlertFlag] = set()

        # 1. Check source
        source = alert_data.get("source", "").lower()
        if source in cls.SOURCE_FLAGS:
            flags.add(cls.SOURCE_FLAGS[source])

        # 2. Check category and title for keywords
        category = alert_data.get("category", "").lower()
        title = alert_data.get("title", "").lower()
        description = alert_data.get("description", "").lower()
        combined_text = f"{category} {title} {description}"

        for keyword, flag in cls.CATEGORY_KEYWORDS.items():
            if keyword in combined_text:
                flags.add(flag)

        # 3. Check MITRE techniques in raw_event
        raw_event = alert_data.get("raw_event", {})
        behaviors = raw_event.get("behaviors", [])
        for behavior in behaviors:
            technique = behavior.get("technique", "")
            tactic = behavior.get("tactic", "").lower()

            # Check technique ID
            if technique in cls.MITRE_FLAGS:
                flags.add(cls.MITRE_FLAGS[technique])

            # Also check tactic name as fallback
            if "lateral" in tactic:
                flags.add(AlertFlag.LATERAL_MOVEMENT)
            elif "credential" in tactic:
                flags.add(AlertFlag.CREDENTIAL_ACCESS)
            elif "exfil" in tactic:
                flags.add(AlertFlag.DATA_EXFIL)
            elif "persist" in tactic:
                flags.add(AlertFlag.PERSISTENCE)
            elif "privilege" in tactic or "escalation" in tactic:
                flags.add(AlertFlag.PRIVILEGE_ESCALATION)
            elif "evasion" in tactic or "defense" in tactic:
                flags.add(AlertFlag.DEFENSE_EVASION)

        # 4. Check indicators for IOC-based classification
        indicators = alert_data.get("indicators", [])
        for indicator in indicators:
            ioc_type = indicator.get("type", "").lower()
            value = indicator.get("value", "").lower()

            # URL patterns suggesting phishing or C2
            if ioc_type == "url":
                if any(kw in value for kw in ["login", "verify", "account", "secure", "auth"]):
                    flags.add(AlertFlag.PHISHING)
                if any(kw in value for kw in ["c2", "beacon", "callback"]):
                    flags.add(AlertFlag.C2_COMMUNICATION)

            # Domain patterns
            if ioc_type == "domain":
                if any(kw in value for kw in ["phish", "login", "secure-"]):
                    flags.add(AlertFlag.PHISHING)

        # 5. Default to UNKNOWN if no flags
        if not flags:
            flags.add(AlertFlag.UNKNOWN)

        return flags

    @classmethod
    def is_high_risk(cls, flags: Set[AlertFlag]) -> bool:
        """
        Check if any flags indicate high-risk alert that should wait for enrichment.

        Args:
            flags: Set of AlertFlag values

        Returns:
            True if alert should wait for enrichment before triage
        """
        return bool(flags & HIGH_RISK_FLAGS)

    @classmethod
    def get_primary_flag(cls, flags: Set[AlertFlag]) -> AlertFlag:
        """
        Get the most specific/important flag from a set.

        Priority order: High-risk flags > specific flags > UNKNOWN

        Args:
            flags: Set of AlertFlag values

        Returns:
            Single primary AlertFlag for prompt selection
        """
        # Priority order for prompt selection
        priority_order = [
            AlertFlag.CREDENTIAL_ACCESS,  # Most critical
            AlertFlag.C2_COMMUNICATION,
            AlertFlag.DATA_EXFIL,
            AlertFlag.MALWARE,
            AlertFlag.LATERAL_MOVEMENT,
            AlertFlag.PHISHING,
            AlertFlag.PERSISTENCE,
            AlertFlag.PRIVILEGE_ESCALATION,
            AlertFlag.DEFENSE_EVASION,
            AlertFlag.UNKNOWN,
        ]

        for flag in priority_order:
            if flag in flags:
                return flag

        return AlertFlag.UNKNOWN

    @classmethod
    def flags_to_list(cls, flags: Set[AlertFlag]) -> List[str]:
        """Convert flags set to list of string values for JSON serialization."""
        return sorted([f.value for f in flags])

    @classmethod
    def list_to_flags(cls, flag_list: List[str]) -> Set[AlertFlag]:
        """Convert list of string values back to flags set."""
        flags = set()
        for value in flag_list:
            try:
                flags.add(AlertFlag(value))
            except ValueError:
                pass
        return flags if flags else {AlertFlag.UNKNOWN}
