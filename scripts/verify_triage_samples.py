"""Verify the public triage prompt against all 5 sample alerts.

Bypasses rate limiting + Turnstile (calls the service primitives directly).
Run inside the t1agentics-backend container. Used to sanity-check the
output schema and grounding after prompt changes.
"""

import asyncio
import json
import sys

sys.path.insert(0, "/app")

from services.public_triage_service import (
    _build_user_prompt,
    _call_claude,
    _parse_result,
    DEMO_MODEL,
)

SAMPLES = {
    "windows_brute_force": {
        "source": "Microsoft-Windows-Security-Auditing", "event_id": 4625,
        "timestamp": "2026-05-18T22:14:03Z", "target_user": "svc_backup",
        "target_domain": "CORP", "workstation": "WEB-DMZ-01", "logon_type": 3,
        "source_network_address": "203.0.113.47", "source_port": "49812",
        "failure_reason": "Unknown user name or bad password",
        "sub_status": "0xC000006A", "process_name": "-",
        "authentication_package": "NTLM",
        "failed_attempt_count_last_5min": 142,
        "preceded_by_successful_login": False,
        "asset_criticality": "high",
        "asset_tags": ["dmz", "production", "web-tier"],
    },
    "aws_guardduty_cryptomining": {
        "source": "aws.guardduty",
        "finding_type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": 8.5, "account_id": "111122223333", "region": "us-east-1",
        "resource": {"resource_type": "Instance", "instance_id": "i-0a1b2c3d4e5f67890",
                     "instance_type": "t3.2xlarge", "instance_state": "running",
                     "tags": [{"key": "Environment", "value": "staging"}]},
        "action": {"action_type": "DNS_REQUEST",
                   "dns_request_action": {"domain": "xmr-pool.minexmr.com",
                                          "protocol": "UDP", "blocked": False}},
        "count": 318,
    },
    "edr_powershell_encoded": {
        "source": "crowdstrike.falcon",
        "timestamp": "2026-05-18T22:01:55Z", "hostname": "FINANCE-LT-042",
        "user": "CORP\\jdoe", "severity_name": "High",
        "parent_process": {"name": "outlook.exe", "pid": 4124},
        "process": {"name": "powershell.exe", "pid": 8842,
                    "command_line": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA="},
        "network": {"remote_ip": "198.51.100.92", "remote_port": 4444,
                    "direction": "outbound"},
        "detection_signature": "EncodedCommand_NetCat_Pattern",
    },
    "phishing_credential_harvest": {
        "source": "email.gateway",
        "from": '"IT Helpdesk" <it-helpdesk@micr0soft-support.com>',
        "to": "jdoe@yourcompany.com",
        "subject": "URGENT: Your Microsoft 365 password expires in 24 hours",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "sender_country": "RU", "sender_ip": "198.51.100.214",
        "links": [{"url": "https://micr0soft-365-secure.com/login?u=jdoe%40yourcompany.com",
                   "domain_age_days": 4}],
        "body_snippet": "Your Microsoft 365 password will expire in 24 hours. Click the link below to verify your account and reset your password.",
        "contains_urgency_language": True,
        "lookalike_domain_score": 0.91,
    },
    "spam_marketing": {
        "source": "email.gateway",
        "from": '"Acme Widgets Deals" <deals@newsletter.acmewidgets.com>',
        "to": "jdoe@yourcompany.com",
        "subject": "50% off everything this weekend only",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "sender_country": "US", "sender_ip": "203.0.113.18",
        "sender_reputation": "good",
        "links": [{"url": "https://www.acmewidgets.com/sale",
                   "domain_age_days": 4218}],
        "body_snippet": "This weekend only - take 50% off everything. Use code SAVE50.",
        "list_unsubscribe_header_present": True,
        "recipient_subscribed": True,
        "previous_emails_from_sender": 47,
    },
}


async def run_one(name, payload):
    alert_json = json.dumps(payload, separators=(",", ":"))
    prompt = _build_user_prompt(alert_json)
    resp = await _call_claude(prompt)
    result = _parse_result(resp["text"])
    print(f"\n{'=' * 70}\n{name}  ({resp['input_tokens']} in / {resp['output_tokens']} out)\n{'=' * 70}")
    print(f"  disposition:  {result['disposition']}")
    print(f"  severity:     {result['severity']}")
    print(f"  priority:     {result['priority']}")
    print(f"  category:     {result['alert_category']}")
    print(f"  confidence:   {result['confidence_percent']}%")
    print(f"  FP likelihood: {result['false_positive_likelihood_percent']}%")
    print(f"\n  SUMMARY:\n  {result['summary']}")
    print(f"\n  KEY INDICATORS:")
    for k in result["key_indicators"]:
        print(f"    - {k}")
    print(f"\n  IOCs ({len(result['iocs'])}):")
    for ioc in result["iocs"]:
        print(f"    [{ioc['type']:6}] {ioc['value'][:50]:50}  {ioc.get('context','')[:60]}")
    print(f"\n  RECOMMENDED ACTIONS:")
    for a in result["recommended_actions"]:
        print(f"    [{a['priority']}] {a['action']}")
        print(f"          reason: {a.get('rationale','')}")


async def main():
    print(f"Using model: {DEMO_MODEL}\n")
    for name, payload in SAMPLES.items():
        try:
            await run_one(name, payload)
        except Exception as e:
            print(f"\n!! {name} FAILED: {e}")


if __name__ == "__main__":
    asyncio.run(main())
