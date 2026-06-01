#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics - Demo Data Seeder

Creates realistic demo data via webhook for instant "wow moment":
- 20 diverse alerts (phishing, malware, network, IAM)

Usage:
    python scripts/seed-demo-data.py
    python scripts/seed-demo-data.py --url http://192.168.128.5:8000  # Custom backend URL

Target: 60 seconds to value
"""

import requests
import argparse
from datetime import datetime, timezone
import random
import uuid
import time


# Configuration
WEBHOOK_NAME = "test"
HEC_TOKEN = "hec_ewl6y5YyBu_CUzWLcmR-xxJaDSXzBi_7kqgpEGZSvIA"
DEFAULT_BASE_URL = "http://localhost:8000"


# Demo alert templates
DEMO_ALERTS = [
    {
        "title": "Phishing email detected - CEO impersonation",
        "description": "Email from external sender impersonating CEO requesting wire transfer",
        "source": "Email Gateway",
        "severity": "high",
        "category": "phishing",
        "raw_event": {
            "from": "ceo@evil-domain.com",
            "to": "finance@company.com",
            "subject": "URGENT: Wire Transfer Required",
            "body": "Please wire $50,000 to account 123-456-7890 immediately.",
            "iocs": ["evil-domain.com", "phishing-link.com"]
        }
    },
    {
        "title": "Malware detected on workstation WKS-5472",
        "description": "CrowdStrike detected Emotet malware attempting to establish C2",
        "source": "CrowdStrike Falcon",
        "severity": "critical",
        "category": "malware",
        "raw_event": {
            "hostname": "WKS-5472",
            "user": "jsmith",
            "malware_family": "Emotet",
            "process": "invoice_2024.exe",
            "c2_domain": "malicious-c2.net",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    },
    {
        "title": "Multiple failed login attempts - admin account",
        "description": "50 failed SSH login attempts for root user from 185.220.101.42",
        "source": "SIEM",
        "severity": "medium",
        "category": "authentication",
        "raw_event": {
            "source_ip": "185.220.101.42",
            "destination": "prod-web-01",
            "username": "root",
            "failed_attempts": 50,
            "timespan_minutes": 5
        }
    },
    {
        "title": "Suspicious PowerShell execution",
        "description": "Obfuscated PowerShell script with base64 encoding detected",
        "source": "EDR",
        "severity": "high",
        "category": "execution",
        "raw_event": {
            "hostname": "WKS-8821",
            "user": "mjones",
            "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...",
            "parent_process": "winword.exe"
        }
    },
    {
        "title": "Data exfiltration detected",
        "description": "Large outbound data transfer to unknown cloud storage",
        "source": "DLP",
        "severity": "critical",
        "category": "exfiltration",
        "raw_event": {
            "user": "contractor_temp",
            "destination": "file-share.suspicious.net",
            "data_size_gb": 15.3,
            "file_types": ["xlsx", "pdf", "docx"],
            "sensitive_data": True
        }
    },
    {
        "title": "Unauthorized admin account creation",
        "description": "New admin account created outside business hours",
        "source": "Active Directory",
        "severity": "high",
        "category": "iam",
        "raw_event": {
            "account_created": "admin_backup",
            "created_by": "IT_Admin",
            "timestamp": "2024-01-12T02:15:00Z",
            "groups": ["Domain Admins", "Enterprise Admins"]
        }
    },
    {
        "title": "Port scan detected from internal host",
        "description": "Host 10.50.20.15 scanning internal network",
        "source": "Firewall",
        "severity": "medium",
        "category": "reconnaissance",
        "raw_event": {
            "source_ip": "10.50.20.15",
            "ports_scanned": 65535,
            "targets": 254,
            "duration_seconds": 120
        }
    },
    {
        "title": "Impossible travel - user login anomaly",
        "description": "User logged in from New York and London within 2 hours",
        "source": "UEBA",
        "severity": "medium",
        "category": "anomaly",
        "raw_event": {
            "user": "exec_vp",
            "location_1": {"city": "New York", "ip": "8.8.8.8", "time": "08:00"},
            "location_2": {"city": "London", "ip": "1.2.3.4", "time": "09:30"}
        }
    },
    {
        "title": "SQL injection attempt blocked",
        "description": "WAF blocked SQL injection targeting customer portal",
        "source": "WAF",
        "severity": "low",
        "category": "web_attack",
        "raw_event": {
            "source_ip": "203.0.113.42",
            "target_url": "/customer/search?id=1' OR '1'='1",
            "payload": "' OR '1'='1--",
            "blocked": True
        }
    },
    {
        "title": "Ransomware encryption activity",
        "description": "Mass file encryption detected on file server",
        "source": "EDR",
        "severity": "critical",
        "category": "ransomware",
        "raw_event": {
            "hostname": "FILE-SRV-02",
            "files_encrypted": 8472,
            "extension": ".locked",
            "ransom_note": "README_DECRYPT.txt",
            "bitcoin_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        }
    },
    {
        "title": "Certificate expiring soon",
        "description": "SSL certificate for prod.company.com expires in 7 days",
        "source": "Certificate Monitor",
        "severity": "low",
        "category": "compliance",
        "raw_event": {
            "domain": "prod.company.com",
            "expires": "2024-01-20",
            "days_remaining": 7
        }
    },
    {
        "title": "Cloud resource access from Tor exit node",
        "description": "AWS S3 bucket accessed from known Tor network",
        "source": "AWS CloudTrail",
        "severity": "high",
        "category": "cloud",
        "raw_event": {
            "source_ip": "185.220.101.1",
            "tor_exit_node": True,
            "resource": "s3://company-backups",
            "action": "ListBucket"
        }
    },
    {
        "title": "Privilege escalation attempt",
        "description": "User attempted to elevate privileges using known exploit",
        "source": "EDR",
        "severity": "high",
        "category": "privilege_escalation",
        "raw_event": {
            "user": "standard_user",
            "technique": "T1068 - Exploitation for Privilege Escalation",
            "exploit": "CVE-2023-12345",
            "success": False
        }
    },
    {
        "title": "Sensitive data access anomaly",
        "description": "User accessed 500+ customer records in 10 minutes",
        "source": "DLP",
        "severity": "medium",
        "category": "data_access",
        "raw_event": {
            "user": "sales_rep",
            "records_accessed": 537,
            "data_type": "PII",
            "normal_baseline": 20
        }
    },
    {
        "title": "DNS tunneling detected",
        "description": "Suspicious DNS queries indicating data exfiltration",
        "source": "DNS Security",
        "severity": "high",
        "category": "exfiltration",
        "raw_event": {
            "source_host": "WKS-3391",
            "domain": "data.exfil.bad-domain.com",
            "query_count": 10000,
            "subdomain_length": 255
        }
    },
    {
        "title": "Unauthorized application installed",
        "description": "Remote admin tool installed without approval",
        "source": "Endpoint Management",
        "severity": "medium",
        "category": "policy_violation",
        "raw_event": {
            "hostname": "WKS-7722",
            "application": "TeamViewer",
            "installed_by": "unknown",
            "approved": False
        }
    },
    {
        "title": "API rate limit exceeded",
        "description": "External service exceeding API rate limits",
        "source": "API Gateway",
        "severity": "low",
        "category": "abuse",
        "raw_event": {
            "client_ip": "192.0.2.100",
            "api_key": "ak_live_xxxxxxxxxxxx",
            "requests_per_minute": 10000,
            "limit": 1000
        }
    },
    {
        "title": "Insider threat indicator - after hours access",
        "description": "Terminated employee badge used at 3 AM",
        "source": "Physical Security",
        "severity": "high",
        "category": "insider_threat",
        "raw_event": {
            "employee_id": "E12345",
            "termination_date": "2024-01-01",
            "access_time": "2024-01-12T03:00:00Z",
            "location": "Server Room"
        }
    },
    {
        "title": "Malicious browser extension detected",
        "description": "Chrome extension with C2 capability found",
        "source": "Browser Security",
        "severity": "medium",
        "category": "malware",
        "raw_event": {
            "extension_name": "PDF Converter Pro",
            "extension_id": "abcdefghijklmnop",
            "permissions": ["all_urls", "webRequest", "cookies"],
            "c2_domain": "command.evil.net"
        }
    },
    {
        "title": "Compliance violation - unencrypted data",
        "description": "Database with PII found without encryption",
        "source": "Compliance Scanner",
        "severity": "high",
        "category": "compliance",
        "raw_event": {
            "database": "customer_data_old",
            "records": 50000,
            "encryption": False,
            "pii_types": ["SSN", "Credit Card", "Email"]
        }
    }
]


def send_alert_webhook(base_url: str, alert_data: dict) -> tuple[bool, str]:
    """Send an alert via webhook endpoint"""
    webhook_url = f"{base_url}/api/v1/webhooks/ingest/{WEBHOOK_NAME}"

    # Build the payload matching the webhook format
    payload = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "title": alert_data["title"],
        "description": alert_data["description"],
        "severity": alert_data["severity"],
        "category": alert_data.get("category", "general"),
        "source": alert_data["source"],
        "tags": ["demo", "seed-data"],
        **alert_data.get("raw_event", {})
    }

    try:
        response = requests.post(
            webhook_url,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"HEC {HEC_TOKEN}"
            },
            json=payload,
            timeout=30
        )

        if response.status_code < 400:
            result = response.json()
            return True, result.get("alert_id", "unknown")
        else:
            return False, f"HTTP {response.status_code}: {response.text[:100]}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused - is the backend running?"
    except Exception as e:
        return False, str(e)[:100]


def seed_demo_data(base_url: str):
    """Seed demo alerts via webhook"""

    print("🌱 T1 Agentics - Demo Data Seeder (Webhook)")
    print("=" * 50)
    print(f"Target: {base_url}")
    print(f"Webhook: {WEBHOOK_NAME}")
    print()

    # Send alerts via webhook
    print(f"📧 Sending {len(DEMO_ALERTS)} demo alerts via webhook...")
    success_count = 0
    failed_count = 0

    for i, alert_template in enumerate(DEMO_ALERTS):
        success, result = send_alert_webhook(base_url, alert_template)

        if success:
            success_count += 1
            status = "✓"
        else:
            failed_count += 1
            status = "✗"
            print(f"\n   {status} Alert {i+1}: {result}")
            continue

        print(f"\r   {status} Sent {i+1}/{len(DEMO_ALERTS)} alerts...", end="", flush=True)

        # Small delay between alerts to avoid overwhelming the system
        time.sleep(0.2)

    print()
    print()
    print(f"   ✓ Successfully sent: {success_count}")
    if failed_count > 0:
        print(f"   ✗ Failed: {failed_count}")
    print()

    if success_count > 0:
        print("✅ Demo data seeded successfully!")
        print()
        print("Quick Start:")
        print("  1. Open http://localhost:3000 (or your frontend URL)")
        print("  2. Login as admin/admin123")
        print(f"  3. View {success_count} alerts on dashboard")
        print("  4. Click any alert to investigate")
    else:
        print("❌ No alerts were created. Check that:")
        print(f"  1. The backend is running at {base_url}")
        print(f"  2. The webhook '{WEBHOOK_NAME}' exists in the database")
        print(f"  3. The HEC token is correct")
        print()
        print("To create the webhook, run:")
        print(f"  curl -X POST {base_url}/api/v1/admin/webhooks \\")
        print('       -H "Content-Type: application/json" \\')
        print('       -H "Authorization: Bearer <your-jwt-token>" \\')
        print(f'       -d \'{{"name": "{WEBHOOK_NAME}", "description": "Demo webhook"}}\'')

    print()


def main():
    parser = argparse.ArgumentParser(description="Seed T1 Agentics with demo data via webhook")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="Backend URL (default: http://localhost:8000)")
    args = parser.parse_args()

    seed_demo_data(base_url=args.url)


if __name__ == "__main__":
    main()
