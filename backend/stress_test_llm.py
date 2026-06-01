#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
LLM Concurrency Stress Test
===========================
Tests the LLM concurrency limiter by sending multiple alerts simultaneously
and measuring MTTR (Mean Time To Resolution).

This script:
1. Sends N alerts via webhook (concurrently)
2. Monitors investigation state progression
3. Measures time from alert creation to AI analysis completion
4. Reports MTTR and queue behavior

Usage:
    python stress_test_llm.py [num_alerts] [--watch]

Examples:
    python stress_test_llm.py 5          # Send 5 alerts, measure MTTR
    python stress_test_llm.py 10 --watch # Send 10 alerts, watch progress live
"""

import asyncio
import aiohttp
import json
import time
import sys
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Configuration
WEBHOOK_URL = "http://localhost:8000/api/v1/webhooks/alerts"
WEBHOOK_TOKEN = "whtoken_zlRaz-MCcxhODkMzRi3zRK7o7rWxGgL5MscoyCxdpQA"
INVESTIGATIONS_URL = "http://localhost:8000/api/v1/investigations"
LLM_QUEUE_URL = "http://localhost:8000/api/v1/agents/ops/llm/queue-status"
SCHEDULER_URL = "http://localhost:8000/api/v1/agents/ops/scheduler/status"

# Test scenarios - variety of alert types
ALERT_SCENARIOS = [
    {
        "title": "Suspicious PowerShell Execution",
        "severity": "high",
        "description": "PowerShell.exe spawned with encoded command parameter -enc",
        "source": "CrowdStrike",
        "mitre_techniques": ["T1059.001"],
        "iocs": ["192.168.1.100", "evil.com", "d41d8cd98f00b204e9800998ecf8427e"]
    },
    {
        "title": "Failed Login Brute Force",
        "severity": "medium",
        "description": "Multiple failed login attempts from single IP address",
        "source": "Azure AD",
        "mitre_techniques": ["T1110.001"],
        "iocs": ["10.0.0.55", "attacker@suspicious.com"]
    },
    {
        "title": "Ransomware Behavior Detected",
        "severity": "critical",
        "description": "Process encrypting files with .locked extension",
        "source": "SentinelOne",
        "mitre_techniques": ["T1486"],
        "iocs": ["ransomware.exe", "abc123def456"]
    },
    {
        "title": "Data Exfiltration via DNS",
        "severity": "high",
        "description": "Unusual DNS query patterns indicating data exfiltration",
        "source": "Palo Alto",
        "mitre_techniques": ["T1048.003"],
        "iocs": ["exfil.badactor.net", "172.16.0.99"]
    },
    {
        "title": "Phishing Email Clicked",
        "severity": "medium",
        "description": "User clicked link in suspected phishing email",
        "source": "Proofpoint",
        "mitre_techniques": ["T1566.002"],
        "iocs": ["phish@evil.com", "http://malicious-login.com/steal"]
    },
    {
        "title": "Lateral Movement Detected",
        "severity": "high",
        "description": "PsExec used to connect to remote system",
        "source": "Microsoft Defender",
        "mitre_techniques": ["T1570"],
        "iocs": ["WORKSTATION-42", "admin_compromised"]
    },
    {
        "title": "Credential Dumping Attempt",
        "severity": "critical",
        "description": "Mimikatz-like behavior accessing LSASS memory",
        "source": "CrowdStrike",
        "mitre_techniques": ["T1003.001"],
        "iocs": ["lsass.exe", "sekurlsa::logonpasswords"]
    },
    {
        "title": "Suspicious Registry Modification",
        "severity": "low",
        "description": "Run key modified for persistence",
        "source": "Carbon Black",
        "mitre_techniques": ["T1547.001"],
        "iocs": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
    }
]


def create_test_alert(index: int) -> Dict[str, Any]:
    """Create a unique test alert from scenarios"""
    scenario = ALERT_SCENARIOS[index % len(ALERT_SCENARIOS)]
    timestamp = datetime.utcnow().isoformat() + "Z"
    unique_id = f"stress-test-{index}-{int(time.time() * 1000)}"

    return {
        "id": unique_id,
        "title": f"[STRESS-{index}] {scenario['title']}",
        "description": scenario['description'],
        "severity": scenario['severity'],
        "source": scenario['source'],
        "source_type": "stress_test",
        "timestamp": timestamp,
        "raw_event": {
            "mitre_techniques": scenario.get('mitre_techniques', []),
            "iocs": scenario.get('iocs', []),
            "test_index": index,
            "stress_test": True
        },
        "user": {
            "username": f"testuser{index}",
            "email": f"user{index}@company.com"
        },
        "host": {
            "hostname": f"WORKSTATION-{100 + index}",
            "ip": f"192.168.1.{100 + index}"
        },
        "tags": ["stress-test", f"batch-{int(time.time())}"]
    }


class StressTestResults:
    """Track stress test results"""
    def __init__(self):
        self.alerts_sent = 0
        self.alerts_created = []
        self.investigations_created = []
        self.times = {}  # alert_id -> {created, t1_started, t1_completed, t2_completed}
        self.start_time = None
        self.end_time = None

    def record_alert_sent(self, alert_id: str):
        self.alerts_sent += 1
        self.times[alert_id] = {"sent": time.time()}

    def record_alert_created(self, alert_id: str, db_id: str):
        self.alerts_created.append({"alert_id": alert_id, "db_id": db_id})
        if alert_id in self.times:
            self.times[alert_id]["created"] = time.time()

    def record_investigation_created(self, alert_id: str, inv_id: str):
        self.investigations_created.append({"alert_id": alert_id, "investigation_id": inv_id})
        if alert_id in self.times:
            self.times[alert_id]["investigation_created"] = time.time()

    def record_t1_complete(self, alert_id: str):
        if alert_id in self.times:
            self.times[alert_id]["t1_complete"] = time.time()

    def record_riggs_review(self, alert_id: str):
        if alert_id in self.times:
            self.times[alert_id]["riggs_review"] = time.time()

    def calculate_mttr(self) -> Dict[str, Any]:
        """Calculate Mean Time To Resolution metrics"""
        mttrs = []
        t1_times = []

        for alert_id, times in self.times.items():
            if "sent" in times and "t1_complete" in times:
                mttr = times["t1_complete"] - times["sent"]
                mttrs.append(mttr)
            if "sent" in times and "riggs_review" in times:
                t1_time = times["riggs_review"] - times["sent"]
                t1_times.append(t1_time)

        return {
            "alerts_sent": self.alerts_sent,
            "alerts_created": len(self.alerts_created),
            "investigations_created": len(self.investigations_created),
            "avg_mttr_seconds": sum(mttrs) / len(mttrs) if mttrs else None,
            "min_mttr_seconds": min(mttrs) if mttrs else None,
            "max_mttr_seconds": max(mttrs) if mttrs else None,
            "avg_time_to_riggs": sum(t1_times) / len(t1_times) if t1_times else None,
            "total_test_time": self.end_time - self.start_time if self.end_time and self.start_time else None
        }


async def send_alert(session: aiohttp.ClientSession, alert: Dict, results: StressTestResults) -> Optional[Dict]:
    """Send a single alert via webhook"""
    alert_id = alert["id"]
    results.record_alert_sent(alert_id)

    try:
        async with session.post(
            WEBHOOK_URL,
            headers={
                "X-Webhook-Token": WEBHOOK_TOKEN,
                "Content-Type": "application/json"
            },
            json={"alert_data": alert},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            result = await resp.json()

            if result.get("status") == "success":
                results.record_alert_created(alert_id, result.get("alert_id", ""))
                print(f"  [OK] Alert {alert_id[:20]}... created -> {result.get('alert_id', '')[:8]}")
                return result
            else:
                print(f"  [FAIL] Alert {alert_id[:20]}... failed: {result}")
                return None

    except Exception as e:
        print(f"  [FAIL] Alert {alert_id[:20]}... error: {e}")
        return None


async def send_alerts_batch(num_alerts: int, results: StressTestResults) -> List[Dict]:
    """Send multiple alerts concurrently"""
    print(f"\n[SEND] Sending {num_alerts} alerts concurrently...")

    alerts = [create_test_alert(i) for i in range(num_alerts)]

    async with aiohttp.ClientSession() as session:
        tasks = [send_alert(session, alert, results) for alert in alerts]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    successful = [r for r in responses if r and not isinstance(r, Exception)]
    print(f"\n[OK] {len(successful)}/{num_alerts} alerts created successfully")

    return successful


async def monitor_investigations(results: StressTestResults, timeout_seconds: int = 300, watch_mode: bool = False):
    """Monitor investigation progress until all reach RIGGS_REVIEW or timeout"""
    print(f"\n[WATCH]  Monitoring investigations (timeout: {timeout_seconds}s)...")

    start_time = time.time()
    last_status = {}

    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < timeout_seconds:
            try:
                # Get all recent investigations
                async with session.get(
                    f"{INVESTIGATIONS_URL}?limit=50&sort=created_at:desc",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        investigations = data.get("investigations", data) if isinstance(data, dict) else data

                        # Filter to our stress test investigations
                        stress_invs = [
                            inv for inv in investigations
                            if inv.get("title", "").startswith("[STRESS-")
                        ]

                        # Count by state
                        states = {}
                        for inv in stress_invs:
                            state = inv.get("state", "UNKNOWN")
                            states[state] = states.get(state, 0) + 1

                            # Track timing
                            inv_id = inv.get("investigation_id", "")
                            alert_id = next(
                                (a["alert_id"] for a in results.alerts_created
                                 if a.get("db_id") == str(inv.get("alert_id"))),
                                None
                            )

                            if alert_id:
                                if state in ("RIGGS_REVIEW", "RIGGS_ANALYZED", "CLOSED"):
                                    results.record_riggs_review(alert_id)
                                if state == "CLOSED":
                                    results.record_t1_complete(alert_id)

                        # Print status if changed
                        if states != last_status or watch_mode:
                            elapsed = int(time.time() - start_time)
                            status_str = " | ".join([f"{k}: {v}" for k, v in sorted(states.items())])
                            print(f"  [{elapsed:3d}s] {status_str}")
                            last_status = states.copy()

                        # Check if all reached RIGGS_REVIEW or beyond
                        target_states = {"RIGGS_REVIEW", "RIGGS_ANALYZED", "AWAITING_HUMAN", "CLOSED"}
                        if stress_invs and all(inv.get("state") in target_states for inv in stress_invs):
                            print(f"\n[OK] All {len(stress_invs)} investigations reached target state!")
                            return stress_invs

            except Exception as e:
                print(f"  [!] Monitor error: {e}")

            await asyncio.sleep(2 if not watch_mode else 1)

    print(f"\n⚠️  Timeout reached after {timeout_seconds}s")
    return []


async def check_llm_queue(session: aiohttp.ClientSession) -> Optional[Dict]:
    """Check LLM queue status"""
    try:
        async with session.get(LLM_QUEUE_URL, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                return await resp.json()
    except:
        pass
    return None


async def run_stress_test(num_alerts: int, watch_mode: bool = False):
    """Run the full stress test"""
    print("=" * 60)
    print("[STRESS] LLM CONCURRENCY STRESS TEST")
    print("=" * 60)
    print(f"Alerts to send: {num_alerts}")
    print(f"Watch mode: {watch_mode}")
    print(f"Webhook URL: {WEBHOOK_URL}")
    print()

    results = StressTestResults()
    results.start_time = time.time()

    # Step 1: Send all alerts
    await send_alerts_batch(num_alerts, results)

    # Step 2: Monitor progress
    await monitor_investigations(results, timeout_seconds=300, watch_mode=watch_mode)

    results.end_time = time.time()

    # Step 3: Print results
    print("\n" + "=" * 60)
    print("[RESULTS] STRESS TEST RESULTS")
    print("=" * 60)

    metrics = results.calculate_mttr()

    print(f"\nAlerts:")
    print(f"  Sent:    {metrics['alerts_sent']}")
    print(f"  Created: {metrics['alerts_created']}")
    print(f"  → Investigations: {metrics['investigations_created']}")

    print(f"\nTiming:")
    if metrics['avg_time_to_riggs']:
        print(f"  Avg time to RIGGS_REVIEW: {metrics['avg_time_to_riggs']:.1f}s")
    if metrics['avg_mttr_seconds']:
        print(f"  Avg MTTR (to CLOSED):     {metrics['avg_mttr_seconds']:.1f}s")
        print(f"  Min MTTR: {metrics['min_mttr_seconds']:.1f}s")
        print(f"  Max MTTR: {metrics['max_mttr_seconds']:.1f}s")
    if metrics['total_test_time']:
        print(f"  Total test time: {metrics['total_test_time']:.1f}s")

    # Calculate throughput
    if metrics['total_test_time'] and metrics['investigations_created']:
        throughput = metrics['investigations_created'] / metrics['total_test_time'] * 60
        print(f"\n  Throughput: {throughput:.1f} investigations/minute")

    print("\n" + "=" * 60)

    return metrics


async def quick_test():
    """Quick sanity test with 3 alerts"""
    print("[TEST] Quick Test (3 alerts)")
    return await run_stress_test(3, watch_mode=True)


async def medium_test():
    """Medium test with 5 alerts"""
    print("[TEST] Medium Test (5 alerts)")
    return await run_stress_test(5, watch_mode=True)


async def heavy_test():
    """Heavy test with 10 alerts"""
    print("[TEST] Heavy Test (10 alerts)")
    return await run_stress_test(10, watch_mode=True)


if __name__ == "__main__":
    num_alerts = 5  # default
    watch_mode = False

    if len(sys.argv) > 1:
        if sys.argv[1] == "--quick":
            asyncio.run(quick_test())
            sys.exit(0)
        elif sys.argv[1] == "--medium":
            asyncio.run(medium_test())
            sys.exit(0)
        elif sys.argv[1] == "--heavy":
            asyncio.run(heavy_test())
            sys.exit(0)
        else:
            try:
                num_alerts = int(sys.argv[1])
            except ValueError:
                print(f"Usage: {sys.argv[0]} [num_alerts] [--watch]")
                sys.exit(1)

    if "--watch" in sys.argv:
        watch_mode = True

    asyncio.run(run_stress_test(num_alerts, watch_mode))
