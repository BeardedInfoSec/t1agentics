#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
End-to-End Test for Hypothesis-Driven Correlation System

This script tests the new correlation system with real alerts to verify:
1. Malware infection chains correlate correctly
2. Cross-domain alerts are blocked
3. Same user, different attacks stay separate
4. Same malicious IOC creates correlations
5. Entity overlap without evidence doesn't correlate

Run: python3 scripts/test_hypothesis_correlation_e2e.py
"""

import requests
import json
import time
import uuid
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000"
WEBHOOK_NAME = "custom_siem"
WEBHOOK_TOKEN = "custom_6e45b9577489bfaae6449466b56941c8"
WEBHOOK_URL = f"{BASE_URL}/api/v1/webhooks/ingest/{WEBHOOK_NAME}"

# Admin credentials for API access
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Global JWT token
JWT_TOKEN = None

def login():
    """Login and get JWT token."""
    global JWT_TOKEN
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/admin/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            JWT_TOKEN = result.get("access_token")
            print(f"Logged in as {ADMIN_USERNAME}")
            return True
        else:
            print(f"Login failed: {response.text}")
            return False
    except Exception as e:
        print(f"Login exception: {e}")
        return False

def get_auth_headers():
    """Get headers with JWT authentication."""
    return {
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json"
    }

def generate_uuid():
    return str(uuid.uuid4())

def send_alert(alert_data, description=""):
    """Send an alert via webhook and return the response."""
    print(f"\n{'='*60}")
    print(f"SENDING: {description}")
    print(f"Title: {alert_data.get('title', 'N/A')}")

    try:
        response = requests.post(
            WEBHOOK_URL,
            json=alert_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"HEC {WEBHOOK_TOKEN}"
            },
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Alert ID: {result.get('alert_id', 'N/A')}")
            return result
        else:
            print(f"Error: {response.text}")
            return None
    except Exception as e:
        print(f"Exception: {e}")
        return None

def wait_for_processing(seconds=5):
    """Wait for alert processing (enrichment + triage)."""
    print(f"\nWaiting {seconds}s for processing...")
    time.sleep(seconds)

def check_investigations():
    """Check current investigations and their alerts."""
    print(f"\n{'='*60}")
    print("CHECKING INVESTIGATIONS")

    try:
        response = requests.get(f"{BASE_URL}/api/v1/investigations", headers=get_auth_headers(), timeout=10)
        if response.status_code == 200:
            investigations = response.json()
            print(f"Total investigations: {len(investigations)}")
            for inv in investigations:
                print(f"\n  Investigation: {inv.get('id', 'N/A')[:8]}...")
                print(f"    Hypothesis: {inv.get('hypothesis', 'N/A')[:50]}...")
                print(f"    Category: {inv.get('hypothesis_category', 'N/A')}")
                print(f"    Alert count: {inv.get('alert_count', 0)}")
            return investigations
        else:
            print(f"Error: {response.text}")
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

def check_correlation_links():
    """Check correlation links (soft-joins)."""
    print(f"\n{'='*60}")
    print("CHECKING CORRELATION LINKS")

    try:
        response = requests.get(f"{BASE_URL}/api/v1/correlation/links/pending", headers=get_auth_headers(), timeout=10)
        if response.status_code == 200:
            links = response.json()
            print(f"Pending correlation links: {len(links)}")
            for link in links:
                print(f"\n  Link: {link.get('id', 'N/A')[:8]}...")
                print(f"    Alert -> Investigation")
                print(f"    Score: {link.get('correlation_score', 'N/A')}")
                print(f"    State: {link.get('link_state', 'N/A')}")
                print(f"    Why: {link.get('why_correlated', 'N/A')[:80]}...")
            return links
        else:
            print(f"Error fetching links: {response.status_code}")
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

def check_alerts():
    """Check all alerts."""
    print(f"\n{'='*60}")
    print("CHECKING ALERTS")

    try:
        response = requests.get(f"{BASE_URL}/api/v1/alerts", headers=get_auth_headers(), timeout=10)
        if response.status_code == 200:
            alerts = response.json()
            print(f"Total alerts: {len(alerts)}")
            for alert in alerts[:10]:  # Show first 10
                print(f"\n  Alert: {alert.get('id', 'N/A')[:8]}...")
                print(f"    Title: {alert.get('title', 'N/A')[:50]}")
                print(f"    Investigation: {alert.get('investigation_id', 'STANDALONE')}")
            return alerts
        else:
            print(f"Error: {response.text}")
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

# ============================================================================
# TEST SCENARIOS
# ============================================================================

def scenario_1_malware_chain():
    """
    SCENARIO 1: Malware Infection Chain
    These alerts SHOULD correlate - same host, MITRE chain, malicious IOCs
    """
    print("\n" + "="*80)
    print("SCENARIO 1: MALWARE INFECTION CHAIN (Should Correlate)")
    print("="*80)

    malicious_ip = "185.234.72.19"
    emotet_hash = "a1b2c3d4e5f6789012345678901234567890abcd"
    victim_host = "VICTIM-PC-01"
    victim_user = "john.doe@acme.com"

    # Alert 1: Emotet dropper executed
    alert1 = {
        "source": "CrowdStrike",
        "title": "Malicious Executable Detected - Emotet Dropper",
        "description": f"Emotet malware dropper executed on {victim_host}. Process created suspicious child processes and attempted C2 communication.",
        "severity": "critical",
        "category": "malware",
        "raw_event": {
            "event_type": "ProcessCreate",
            "host": victim_host,
            "user": victim_user,
            "process_name": "invoice_2024.exe",
            "process_hash": emotet_hash,
            "parent_process": "outlook.exe",
            "command_line": "C:\\Users\\john.doe\\Downloads\\invoice_2024.exe",
            "network_connections": [
                {"destination_ip": malicious_ip, "destination_port": 443}
            ],
            "_extracted": {
                "mitre": {
                    "techniques": ["T1204.002", "T1059.001"],
                    "tactics": ["TA0002"]
                },
                "iocs": {
                    "ips": [malicious_ip],
                    "hashes": [emotet_hash]
                },
                "entities": {
                    "user": victim_user,
                    "host": victim_host
                }
            }
        }
    }
    result1 = send_alert(alert1, "Alert 1: Emotet dropper execution")
    wait_for_processing(8)

    # Alert 2: Trickbot download (child of emotet)
    trickbot_hash = "b2c3d4e5f67890123456789012345678901234ef"
    alert2 = {
        "source": "CrowdStrike",
        "title": "Malware Download Detected - Trickbot Payload",
        "description": f"Trickbot payload downloaded by child process of emotet on {victim_host}.",
        "severity": "critical",
        "category": "malware",
        "raw_event": {
            "event_type": "FileCreate",
            "host": victim_host,
            "user": victim_user,
            "file_name": "payload.dll",
            "file_hash": trickbot_hash,
            "parent_process": "invoice_2024.exe",
            "parent_hash": emotet_hash,
            "download_url": f"https://{malicious_ip}/payload.dll",
            "_extracted": {
                "mitre": {
                    "techniques": ["T1105", "T1055.001"],
                    "tactics": ["TA0011", "TA0005"]
                },
                "iocs": {
                    "ips": [malicious_ip],
                    "hashes": [trickbot_hash, emotet_hash]
                },
                "entities": {
                    "user": victim_user,
                    "host": victim_host
                },
                "enrichment_results": {
                    "hashes": [
                        {"value": trickbot_hash, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["Trickbot.Gen", "Trojan.Win32.Trickbot"]},
                        {"value": emotet_hash, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["Emotet.A", "Trojan.Emotet"]}
                    ],
                    "ips": [
                        {"value": malicious_ip, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["Malware C2"]}
                    ]
                }
            }
        }
    }
    result2 = send_alert(alert2, "Alert 2: Trickbot download (child of emotet)")
    wait_for_processing(8)

    # Alert 3: C2 beacon from same host
    alert3 = {
        "source": "PaloAlto",
        "title": "Command and Control Communication Detected",
        "description": f"Periodic beaconing to known C2 infrastructure from {victim_host}.",
        "severity": "high",
        "category": "c2",
        "raw_event": {
            "event_type": "NetworkConnection",
            "host": victim_host,
            "user": victim_user,
            "destination_ip": malicious_ip,
            "destination_port": 443,
            "bytes_sent": 1024,
            "bytes_received": 2048,
            "protocol": "HTTPS",
            "_extracted": {
                "mitre": {
                    "techniques": ["T1071.001", "T1573.002"],
                    "tactics": ["TA0011"]
                },
                "iocs": {
                    "ips": [malicious_ip]
                },
                "entities": {
                    "user": victim_user,
                    "host": victim_host
                },
                "enrichment_results": {
                    "ips": [
                        {"value": malicious_ip, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["Emotet C2", "Trickbot C2"]}
                    ]
                }
            }
        }
    }
    result3 = send_alert(alert3, "Alert 3: C2 beacon (same host, same malicious IP)")
    wait_for_processing(8)

    return [result1, result2, result3]

def scenario_2_cross_domain():
    """
    SCENARIO 2: Cross-Domain Alerts
    These alerts should NOT correlate - EMAIL domain vs ENDPOINT domain
    """
    print("\n" + "="*80)
    print("SCENARIO 2: CROSS-DOMAIN BLOCKING (Should NOT Correlate)")
    print("="*80)

    # Alert 4: Phishing email (EMAIL domain)
    alert4 = {
        "source": "Proofpoint",
        "title": "Phishing Email Detected - Credential Harvesting",
        "description": "Phishing email with credential harvesting link detected targeting finance department.",
        "severity": "high",
        "category": "phishing",
        "raw_event": {
            "event_type": "EmailReceived",
            "recipient": "finance@acme.com",
            "sender": "payroll@acme-payrol1.com",
            "subject": "Urgent: Update Your Direct Deposit Information",
            "link_url": "https://acme-payrol1.com/login",
            "_extracted": {
                "mitre": {
                    "techniques": ["T1566.002"],
                    "tactics": ["TA0001"]
                },
                "iocs": {
                    "domains": ["acme-payrol1.com"],
                    "urls": ["https://acme-payrol1.com/login"]
                },
                "entities": {
                    "user": "finance@acme.com"
                },
                "enrichment_results": {
                    "domains": [
                        {"value": "acme-payrol1.com", "verdict": "MALICIOUS", "source": "URLScan", "detections": ["Phishing", "Credential Harvesting"]}
                    ]
                }
            }
        }
    }
    result4 = send_alert(alert4, "Alert 4: Phishing email (EMAIL domain)")
    wait_for_processing(8)

    # Alert 5: Endpoint malware (ENDPOINT domain) - DIFFERENT attack, DIFFERENT user
    alert5 = {
        "source": "SentinelOne",
        "title": "Ransomware Activity Detected",
        "description": "Ransomware encryption activity detected on WORKSTATION-05.",
        "severity": "critical",
        "category": "malware",
        "raw_event": {
            "event_type": "FileEncryption",
            "host": "WORKSTATION-05",
            "user": "sales.rep@acme.com",
            "process_name": "cryptolocker.exe",
            "files_encrypted": 150,
            "_extracted": {
                "mitre": {
                    "techniques": ["T1486"],
                    "tactics": ["TA0040"]
                },
                "iocs": {
                    "hashes": ["ransomware123456789abcdef"]
                },
                "entities": {
                    "user": "sales.rep@acme.com",
                    "host": "WORKSTATION-05"
                },
                "enrichment_results": {
                    "hashes": [
                        {"value": "ransomware123456789abcdef", "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["Ransom.CryptoLocker"]}
                    ]
                }
            }
        }
    }
    result5 = send_alert(alert5, "Alert 5: Ransomware on endpoint (ENDPOINT domain)")
    wait_for_processing(8)

    return [result4, result5]

def scenario_3_same_user_different_attacks():
    """
    SCENARIO 3: Same User, Different Attack Types
    These alerts should NOT correlate - same user but unrelated activities
    """
    print("\n" + "="*80)
    print("SCENARIO 3: SAME USER, DIFFERENT ATTACKS (Should NOT Correlate)")
    print("="*80)

    shared_user = "admin@acme.com"

    # Alert 6: Failed login brute force
    alert6 = {
        "source": "Azure AD",
        "title": "Brute Force Login Attempt Detected",
        "description": f"Multiple failed login attempts detected for {shared_user} from suspicious IP.",
        "severity": "high",
        "category": "credential_access",
        "raw_event": {
            "event_type": "FailedLogin",
            "user": shared_user,
            "source_ip": "203.0.113.50",
            "failed_attempts": 25,
            "time_window": "5 minutes",
            "_extracted": {
                "mitre": {
                    "techniques": ["T1110.001"],
                    "tactics": ["TA0006"]
                },
                "iocs": {
                    "ips": ["203.0.113.50"]
                },
                "entities": {
                    "user": shared_user
                },
                "enrichment_results": {
                    "ips": [
                        {"value": "203.0.113.50", "verdict": "SUSPICIOUS", "source": "AbuseIPDB", "confidence": 75}
                    ]
                }
            }
        }
    }
    result6 = send_alert(alert6, "Alert 6: Brute force login (credential access)")
    wait_for_processing(8)

    # Alert 7: Software policy violation by SAME user (different attack type)
    alert7 = {
        "source": "Carbon Black",
        "title": "Unauthorized Software Installation",
        "description": f"Pirated software installation detected by {shared_user}.",
        "severity": "medium",
        "category": "policy_violation",
        "raw_event": {
            "event_type": "SoftwareInstall",
            "user": shared_user,
            "host": "ADMIN-WS-01",
            "software": "Adobe Photoshop (Cracked)",
            "file_path": "C:\\Users\\admin\\Downloads\\photoshop_crack.exe",
            "_extracted": {
                "mitre": {
                    "techniques": ["T1204.002"],
                    "tactics": ["TA0002"]
                },
                "iocs": {
                    "hashes": ["pirated_software_hash_12345"]
                },
                "entities": {
                    "user": shared_user,
                    "host": "ADMIN-WS-01"
                },
                "enrichment_results": {
                    "hashes": [
                        {"value": "pirated_software_hash_12345", "verdict": "SUSPICIOUS", "source": "VirusTotal", "detections": ["PUP.Optional.Crack"]}
                    ]
                }
            }
        }
    }
    result7 = send_alert(alert7, "Alert 7: Policy violation by same user")
    wait_for_processing(8)

    return [result6, result7]

def scenario_4_shared_malicious_ioc():
    """
    SCENARIO 4: Shared Malicious IOC Across Different Hosts
    These alerts SHOULD correlate - same C2 infrastructure = same campaign
    """
    print("\n" + "="*80)
    print("SCENARIO 4: SHARED MALICIOUS IOC (Should Correlate)")
    print("="*80)

    shared_c2_domain = "evil-c2-infrastructure.net"
    shared_c2_ip = "198.51.100.99"

    # Alert 8: C2 from HOST-A
    alert8 = {
        "source": "PaloAlto",
        "title": "C2 Communication - APT Infrastructure",
        "description": f"Communication with known APT C2 infrastructure from HOST-ALPHA.",
        "severity": "critical",
        "category": "c2",
        "raw_event": {
            "event_type": "NetworkConnection",
            "host": "HOST-ALPHA",
            "user": "user.alpha@acme.com",
            "destination_domain": shared_c2_domain,
            "destination_ip": shared_c2_ip,
            "destination_port": 443,
            "_extracted": {
                "mitre": {
                    "techniques": ["T1071.001"],
                    "tactics": ["TA0011"]
                },
                "iocs": {
                    "domains": [shared_c2_domain],
                    "ips": [shared_c2_ip]
                },
                "entities": {
                    "user": "user.alpha@acme.com",
                    "host": "HOST-ALPHA"
                },
                "enrichment_results": {
                    "domains": [
                        {"value": shared_c2_domain, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["APT29 C2", "CozyBear Infrastructure"]}
                    ],
                    "ips": [
                        {"value": shared_c2_ip, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["APT29 C2"]}
                    ]
                }
            }
        }
    }
    result8 = send_alert(alert8, "Alert 8: C2 to shared infrastructure from HOST-A")
    wait_for_processing(8)

    # Alert 9: C2 from HOST-B to SAME C2 infrastructure
    alert9 = {
        "source": "PaloAlto",
        "title": "C2 Communication - Same APT Infrastructure",
        "description": f"Communication with same APT C2 infrastructure from HOST-BETA.",
        "severity": "critical",
        "category": "c2",
        "raw_event": {
            "event_type": "NetworkConnection",
            "host": "HOST-BETA",
            "user": "user.beta@acme.com",
            "destination_domain": shared_c2_domain,
            "destination_ip": shared_c2_ip,
            "destination_port": 443,
            "_extracted": {
                "mitre": {
                    "techniques": ["T1071.001"],
                    "tactics": ["TA0011"]
                },
                "iocs": {
                    "domains": [shared_c2_domain],
                    "ips": [shared_c2_ip]
                },
                "entities": {
                    "user": "user.beta@acme.com",
                    "host": "HOST-BETA"
                },
                "enrichment_results": {
                    "domains": [
                        {"value": shared_c2_domain, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["APT29 C2", "CozyBear Infrastructure"]}
                    ],
                    "ips": [
                        {"value": shared_c2_ip, "verdict": "MALICIOUS", "source": "VirusTotal", "detections": ["APT29 C2"]}
                    ]
                }
            }
        }
    }
    result9 = send_alert(alert9, "Alert 9: C2 to SAME infrastructure from HOST-B")
    wait_for_processing(8)

    return [result8, result9]

def run_all_scenarios():
    """Run all test scenarios and summarize results."""
    print("\n" + "#"*80)
    print("# HYPOTHESIS-DRIVEN CORRELATION E2E TEST")
    print("# Testing correlation system with real alert scenarios")
    print("#"*80)

    # Login first
    if not login():
        print("FATAL: Could not login. Aborting tests.")
        return None

    # Run scenarios
    results1 = scenario_1_malware_chain()
    results2 = scenario_2_cross_domain()
    results3 = scenario_3_same_user_different_attacks()
    results4 = scenario_4_shared_malicious_ioc()

    # Wait for all processing to complete
    print("\n" + "="*80)
    print("WAITING FOR FINAL PROCESSING...")
    wait_for_processing(15)

    # Check results
    investigations = check_investigations()
    alerts = check_alerts()
    links = check_correlation_links()

    # Summary
    print("\n" + "#"*80)
    print("# TEST SUMMARY")
    print("#"*80)
    print(f"\nTotal alerts ingested: 9")
    print(f"Total investigations created: {len(investigations)}")
    print(f"Pending correlation links: {len(links)}")

    print("\n" + "-"*40)
    print("EXPECTED OUTCOMES:")
    print("-"*40)
    print("Scenario 1 (Malware Chain): 3 alerts -> 1 investigation (correlate)")
    print("Scenario 2 (Cross-Domain): 2 alerts -> 2 investigations (no correlation)")
    print("Scenario 3 (Same User): 2 alerts -> 2 investigations (no correlation)")
    print("Scenario 4 (Shared IOC): 2 alerts -> 1 investigation (correlate)")
    print("-"*40)
    print("Total expected investigations: 6 (if no correlation)")
    print("Total expected investigations: 4 (with proper correlation)")

    return {
        "investigations": investigations,
        "alerts": alerts,
        "links": links
    }

if __name__ == "__main__":
    run_all_scenarios()
