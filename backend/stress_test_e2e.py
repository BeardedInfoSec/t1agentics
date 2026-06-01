#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
End-to-End Alert Stress Test
=============================

Sends realistic alerts through the full AgentCore pipeline:
  Webhook -> Alert Ingestion -> Enrichment -> AI Triage -> Investigation

Tracks metrics at each stage for realistic throughput measurements.

Usage:
    python stress_test_e2e.py --count 100 --rate 5 --duration 60
    python stress_test_e2e.py --mode burst --count 50
    python stress_test_e2e.py --mode sustained --rate 2 --duration 300
"""

import argparse
import asyncio
import json
import logging
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

API_BASE = os.getenv('API_BASE_URL', 'http://localhost:8000')
WEBHOOK_BASE = f"{API_BASE}/api/v1/webhooks/ingest"

# Alert templates for realistic test data
ALERT_TEMPLATES = [
    {
        "type": "phishing",
        "title": "Suspicious Email: {subject}",
        "severity": "high",
        "category": "email_security",
        "templates": {
            "subject": [
                "Urgent: Password Reset Required",
                "Invoice #INV-{num} Attached",
                "Your Account Has Been Compromised",
                "Verify Your Identity Now",
                "Payment Confirmation Required"
            ],
            "sender": [
                "security-alert@microsoft-support.com",
                "helpdesk@g00gle.com",
                "admin@paypa1.com",
                "support@amaz0n-security.net",
                "noreply@apple-id-verify.com"
            ]
        }
    },
    {
        "type": "malware",
        "title": "Malware Detection: {process}",
        "severity": "critical",
        "category": "endpoint_security",
        "templates": {
            "process": [
                "mimikatz.exe",
                "cobaltstrike.dll",
                "ransomware.bin",
                "cryptominer.exe",
                "backdoor.dll"
            ],
            "action": [
                "process_created",
                "file_written",
                "registry_modified",
                "network_connection",
                "memory_injected"
            ]
        }
    },
    {
        "type": "brute_force",
        "title": "Multiple Failed Logins: {user}",
        "severity": "medium",
        "category": "authentication",
        "templates": {
            "user": [
                "admin",
                "administrator",
                "root",
                "service_account",
                "backup_user"
            ],
            "source": [
                "192.168.1.{ip}",
                "10.0.0.{ip}",
                "172.16.0.{ip}"
            ]
        }
    },
    {
        "type": "data_exfil",
        "title": "Large Data Transfer: {destination}",
        "severity": "high",
        "category": "data_loss_prevention",
        "templates": {
            "destination": [
                "pastebin.com",
                "dropbox.com",
                "mega.nz",
                "anonfiles.com",
                "external-ftp.suspicious.net"
            ],
            "size_mb": [50, 100, 250, 500, 1000]
        }
    },
    {
        "type": "privilege_escalation",
        "title": "Privilege Escalation: {user} -> {target}",
        "severity": "critical",
        "category": "identity_security",
        "templates": {
            "user": ["jsmith", "mwilson", "agarcia", "blee", "cjohnson"],
            "target": ["Domain Admins", "Enterprise Admins", "SYSTEM", "root", "Administrator"]
        }
    },
    {
        "type": "lateral_movement",
        "title": "Lateral Movement Detected: {source} -> {destination}",
        "severity": "high",
        "category": "network_security",
        "templates": {
            "source": ["workstation-{num}", "laptop-{num}", "server-{num}"],
            "destination": ["dc01", "fileserver", "sqlserver", "exchange", "sharepoint"]
        }
    },
    {
        "type": "suspicious_process",
        "title": "Suspicious Process: {process} spawned by {parent}",
        "severity": "medium",
        "category": "endpoint_security",
        "templates": {
            "process": ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "certutil.exe"],
            "parent": ["outlook.exe", "winword.exe", "excel.exe", "chrome.exe", "firefox.exe"]
        }
    },
    {
        "type": "network_anomaly",
        "title": "Network Anomaly: {description}",
        "severity": "medium",
        "category": "network_security",
        "templates": {
            "description": [
                "Unusual DNS query volume",
                "Connection to known C2 server",
                "Beaconing behavior detected",
                "Port scanning activity",
                "Unusual outbound traffic pattern"
            ]
        }
    }
]

WEBHOOKS = [
    "crowdstrike_detections",
    "sentinel_alerts",
    "defender_incidents",
    "proofpoint_alerts"
]


# =============================================================================
# Alert Generator
# =============================================================================

def generate_alert(template_idx: Optional[int] = None) -> Dict[str, Any]:
    """Generate a realistic alert payload"""
    template = ALERT_TEMPLATES[template_idx] if template_idx is not None else random.choice(ALERT_TEMPLATES)

    # Build title with template substitution
    title = template["title"]
    raw_event = {
        "type": template["type"],
        "timestamp": datetime.utcnow().isoformat(),
        "host": f"workstation-{random.randint(1, 500)}.corp.local",
        "user": f"user{random.randint(1, 100)}@corp.local",
    }

    for key, values in template.get("templates", {}).items():
        if isinstance(values, list):
            value = random.choice(values)
            if "{num}" in str(value):
                value = value.replace("{num}", str(random.randint(100, 999)))
            if "{ip}" in str(value):
                value = value.replace("{ip}", str(random.randint(1, 254)))
            raw_event[key] = value
            title = title.replace("{" + key + "}", str(value))

    # Add IOCs based on alert type
    iocs = []
    if template["type"] == "phishing":
        iocs = [
            {"type": "email", "value": raw_event.get("sender", "unknown@suspicious.com")},
            {"type": "url", "value": f"http://malicious-{random.randint(1000, 9999)}.com/phish"}
        ]
    elif template["type"] == "malware":
        iocs = [
            {"type": "hash_sha256", "value": f"{random.randbytes(32).hex()}"},
            {"type": "file_path", "value": f"C:\\Users\\{raw_event['user'].split('@')[0]}\\Downloads\\{raw_event.get('process', 'malware.exe')}"}
        ]
    elif template["type"] in ["data_exfil", "network_anomaly", "lateral_movement"]:
        iocs = [
            {"type": "ip", "value": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"},
            {"type": "domain", "value": raw_event.get("destination", "suspicious-domain.com")}
        ]

    raw_event["indicators"] = iocs

    return {
        "title": title,
        "description": f"Automated test alert: {title}. Generated at {datetime.utcnow().isoformat()}",
        "severity": template["severity"],
        "category": template["category"],
        "source_type": template["type"],
        "raw_event": raw_event,
        "indicators": iocs
    }


# =============================================================================
# Metrics Tracking
# =============================================================================

@dataclass
class AlertMetrics:
    """Tracks metrics for a single alert"""
    alert_id: str
    webhook_name: str
    sent_at: float
    ingested_at: Optional[float] = None
    triaged_at: Optional[float] = None
    verdict: Optional[str] = None
    investigation_id: Optional[str] = None
    error: Optional[str] = None

    @property
    def ingestion_latency_ms(self) -> Optional[float]:
        if self.ingested_at and self.sent_at:
            return (self.ingested_at - self.sent_at) * 1000
        return None

    @property
    def triage_latency_ms(self) -> Optional[float]:
        if self.triaged_at and self.sent_at:
            return (self.triaged_at - self.sent_at) * 1000
        return None

    @property
    def total_latency_ms(self) -> Optional[float]:
        if self.triaged_at and self.sent_at:
            return (self.triaged_at - self.sent_at) * 1000
        return None


@dataclass
class TestResults:
    """Aggregated test results"""
    alerts_sent: int = 0
    alerts_ingested: int = 0
    alerts_triaged: int = 0
    alerts_failed: int = 0
    investigations_created: int = 0

    metrics: List[AlertMetrics] = field(default_factory=list)
    verdicts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    start_time: float = 0
    end_time: float = 0

    def add_metric(self, metric: AlertMetrics):
        self.metrics.append(metric)
        self.alerts_sent += 1

        if metric.ingested_at:
            self.alerts_ingested += 1
        if metric.triaged_at:
            self.alerts_triaged += 1
            if metric.verdict:
                self.verdicts[metric.verdict] += 1
        if metric.investigation_id:
            self.investigations_created += 1
        if metric.error:
            self.alerts_failed += 1
            self.errors[metric.error] += 1

    def summary(self) -> Dict[str, Any]:
        duration = self.end_time - self.start_time if self.end_time else 1

        ingestion_latencies = [m.ingestion_latency_ms for m in self.metrics if m.ingestion_latency_ms]
        triage_latencies = [m.triage_latency_ms for m in self.metrics if m.triage_latency_ms]

        summary = {
            "duration_seconds": round(duration, 2),
            "alerts": {
                "sent": self.alerts_sent,
                "ingested": self.alerts_ingested,
                "triaged": self.alerts_triaged,
                "failed": self.alerts_failed,
                "success_rate": f"{(self.alerts_ingested / max(1, self.alerts_sent)) * 100:.1f}%"
            },
            "throughput": {
                "alerts_per_second": round(self.alerts_sent / duration, 2),
                "triaged_per_second": round(self.alerts_triaged / duration, 2),
                "alerts_per_hour": round(self.alerts_sent / duration * 3600, 0),
                "triaged_per_hour": round(self.alerts_triaged / duration * 3600, 0)
            },
            "investigations": {
                "created": self.investigations_created,
                "escalation_rate": f"{(self.investigations_created / max(1, self.alerts_triaged)) * 100:.1f}%"
            },
            "verdicts": dict(self.verdicts)
        }

        if ingestion_latencies:
            summary["ingestion_latency_ms"] = {
                "min": round(min(ingestion_latencies), 1),
                "max": round(max(ingestion_latencies), 1),
                "avg": round(statistics.mean(ingestion_latencies), 1),
                "median": round(statistics.median(ingestion_latencies), 1),
                "p95": round(sorted(ingestion_latencies)[int(len(ingestion_latencies) * 0.95)] if len(ingestion_latencies) > 1 else ingestion_latencies[0], 1)
            }

        if triage_latencies:
            summary["triage_latency_ms"] = {
                "min": round(min(triage_latencies), 1),
                "max": round(max(triage_latencies), 1),
                "avg": round(statistics.mean(triage_latencies), 1),
                "median": round(statistics.median(triage_latencies), 1),
                "p95": round(sorted(triage_latencies)[int(len(triage_latencies) * 0.95)] if len(triage_latencies) > 1 else triage_latencies[0], 1)
            }

        if self.errors:
            summary["errors"] = dict(self.errors)

        return summary


# =============================================================================
# Alert Sender
# =============================================================================

class AlertSender:
    """Sends alerts through webhooks"""

    def __init__(self, api_base: str = API_BASE):
        self.api_base = api_base
        self.webhook_base = f"{api_base}/api/v1/webhooks/ingest"
        self.webhooks = {}  # name -> token mapping

    async def load_webhooks(self):
        """Load webhook tokens from the API"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Try to get webhooks from admin API
            try:
                resp = await client.get(
                    f"{self.api_base}/api/v1/admin/webhooks",
                    headers={"Authorization": "Bearer admin"}  # Will need proper auth
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for wh in data.get('webhooks', []):
                        self.webhooks[wh['name']] = wh['token']
            except Exception as e:
                logger.warning(f"Could not load webhooks from API: {e}")

        # Fallback: use known webhook names with default tokens
        if not self.webhooks:
            # These are the default tokens from the database
            self.webhooks = {
                "crowdstrike_detections": "cs_30041aaf68a355415e72973169ae6cad",
                "sentinel_alerts": "sentinel_79c8e5de4226d7f10f7653aedfcaaef8",
                "defender_incidents": "defender_f49f11e3fd016ed340d73739f15f2177",
            }
            logger.info(f"Using default webhook tokens for {list(self.webhooks.keys())}")

    async def send_alert(self, alert_data: Dict[str, Any], webhook_name: Optional[str] = None) -> AlertMetrics:
        """Send an alert through a webhook"""
        if not webhook_name:
            webhook_name = random.choice(list(self.webhooks.keys()))

        token = self.webhooks.get(webhook_name, "")
        metric = AlertMetrics(
            alert_id="pending",
            webhook_name=webhook_name,
            sent_at=time.time()
        )

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self.webhook_base}/{webhook_name}",
                    json={"alert_data": alert_data},
                    headers={
                        "Authorization": f"HEC {token}",
                        "Content-Type": "application/json"
                    }
                )

                metric.ingested_at = time.time()

                if resp.status_code == 200:
                    data = resp.json()
                    metric.alert_id = data.get('alert_id', 'unknown')
                    logger.debug(f"Alert sent: {metric.alert_id}")
                else:
                    metric.error = f"HTTP {resp.status_code}: {resp.text[:100]}"
                    logger.warning(f"Alert failed: {metric.error}")

        except Exception as e:
            metric.error = str(e)[:100]
            logger.error(f"Alert send error: {e}")

        return metric


# =============================================================================
# Status Checker
# =============================================================================

class StatusChecker:
    """Checks alert processing status"""

    def __init__(self, api_base: str = API_BASE):
        self.api_base = api_base

    async def check_alert_status(self, alert_id: str) -> Dict[str, Any]:
        """Check the processing status of an alert"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.api_base}/api/v1/alerts/{alert_id}",
                    headers={"Authorization": "Bearer admin"}
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.debug(f"Status check failed for {alert_id}: {e}")
        return {}

    async def check_processing_stats(self) -> Dict[str, Any]:
        """Get overall processing statistics"""
        stats = {
            "open_alerts": 0,
            "triaged_alerts": 0,
            "investigations": 0,
            "queue_depth": 0
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get alert counts
                resp = await client.get(
                    f"{self.api_base}/api/v1/alerts?limit=1",
                    headers={"Authorization": "Bearer admin"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    stats["total_alerts"] = data.get("total", 0)

                # Get investigation counts
                resp = await client.get(
                    f"{self.api_base}/api/v1/investigations?limit=1",
                    headers={"Authorization": "Bearer admin"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    stats["investigations"] = data.get("total", 0)
        except Exception as e:
            logger.debug(f"Stats check failed: {e}")

        return stats


# =============================================================================
# Test Runners
# =============================================================================

async def run_burst_test(sender: AlertSender, count: int, results: TestResults):
    """Send alerts as fast as possible"""
    logger.info(f"Running burst test: {count} alerts...")

    async def send_one(i: int):
        alert_data = generate_alert()
        metric = await sender.send_alert(alert_data)
        results.add_metric(metric)

        if (i + 1) % 10 == 0:
            logger.info(f"  Progress: {i + 1}/{count} alerts sent")

    # Send all alerts concurrently (in batches to avoid overwhelming)
    batch_size = 20
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        tasks = [send_one(i) for i in range(batch_start, batch_end)]
        await asyncio.gather(*tasks)


async def run_sustained_test(sender: AlertSender, rate: float, duration: int, results: TestResults):
    """Send alerts at a sustained rate"""
    logger.info(f"Running sustained test: {rate}/s for {duration}s...")

    interval = 1.0 / rate
    start = time.time()
    alert_num = 0

    while time.time() - start < duration:
        send_start = time.time()

        alert_data = generate_alert()
        metric = await sender.send_alert(alert_data)
        results.add_metric(metric)

        alert_num += 1
        if alert_num % 10 == 0:
            elapsed = time.time() - start
            actual_rate = alert_num / elapsed
            logger.info(f"  {int(elapsed)}s: {alert_num} alerts sent ({actual_rate:.1f}/s actual)")

        # Sleep to maintain rate
        elapsed = time.time() - send_start
        sleep_time = max(0, interval - elapsed)
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)


async def run_ramp_test(sender: AlertSender, max_rate: float, duration: int, results: TestResults):
    """Gradually increase rate to find breaking point"""
    logger.info(f"Running ramp test: 0 -> {max_rate}/s over {duration}s...")

    start = time.time()
    alert_num = 0
    last_log = start

    while time.time() - start < duration:
        elapsed = time.time() - start
        current_rate = (elapsed / duration) * max_rate
        if current_rate < 0.1:
            current_rate = 0.1

        interval = 1.0 / current_rate
        send_start = time.time()

        alert_data = generate_alert()
        metric = await sender.send_alert(alert_data)
        results.add_metric(metric)
        alert_num += 1

        # Log every 10 seconds
        if time.time() - last_log >= 10:
            actual_rate = alert_num / elapsed
            logger.info(f"  {int(elapsed)}s: {alert_num} alerts, target {current_rate:.1f}/s, actual {actual_rate:.1f}/s")
            last_log = time.time()

        sleep_time = max(0, interval - (time.time() - send_start))
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)


async def monitor_processing(checker: StatusChecker, results: TestResults, duration: int):
    """Background task to monitor processing progress"""
    start = time.time()

    while time.time() - start < duration + 30:  # Extra time for processing
        await asyncio.sleep(5)

        # Update metrics with processing status
        pending_checks = [m for m in results.metrics if not m.triaged_at and m.alert_id != "pending"]

        for metric in pending_checks[:10]:  # Check up to 10 at a time
            status = await checker.check_alert_status(metric.alert_id)
            if status:
                # Check for triage verdict
                verdict = status.get('ai_verdict') or status.get('triage_verdict')
                if verdict:
                    metric.triaged_at = time.time()
                    metric.verdict = verdict.get('verdict') if isinstance(verdict, dict) else verdict

                # Check for investigation
                inv_id = status.get('investigation_id')
                if inv_id:
                    metric.investigation_id = inv_id

        # Log progress
        triaged = sum(1 for m in results.metrics if m.triaged_at)
        total = len(results.metrics)
        logger.info(f"  Processing: {triaged}/{total} triaged")


# =============================================================================
# Main
# =============================================================================

async def main():
    parser = argparse.ArgumentParser(description="End-to-End Alert Stress Test")
    parser.add_argument("--mode", choices=["burst", "sustained", "ramp"], default="sustained",
                        help="Test mode")
    parser.add_argument("--count", type=int, default=50, help="Number of alerts (burst mode)")
    parser.add_argument("--rate", type=float, default=2.0, help="Alerts per second (sustained mode)")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--max-rate", type=float, default=10.0, help="Max rate (ramp mode)")
    parser.add_argument("--api-base", type=str, default=API_BASE, help="API base URL")
    parser.add_argument("--monitor", action="store_true", help="Monitor processing status")

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("END-TO-END ALERT STRESS TEST")
    print("=" * 60)
    print(f"Mode: {args.mode}")
    print(f"API Base: {args.api_base}")
    print("=" * 60 + "\n")

    # Initialize
    sender = AlertSender(args.api_base)
    await sender.load_webhooks()

    checker = StatusChecker(args.api_base)
    results = TestResults()
    results.start_time = time.time()

    # Get initial stats
    initial_stats = await checker.check_processing_stats()
    print(f"Initial system state: {initial_stats}\n")

    # Start monitoring in background if requested
    monitor_task = None
    if args.monitor:
        monitor_task = asyncio.create_task(
            monitor_processing(checker, results, args.duration if args.mode != "burst" else 30)
        )

    # Run test
    if args.mode == "burst":
        await run_burst_test(sender, args.count, results)
    elif args.mode == "sustained":
        await run_sustained_test(sender, args.rate, args.duration, results)
    elif args.mode == "ramp":
        await run_ramp_test(sender, args.max_rate, args.duration, results)

    results.end_time = time.time()

    # Wait for monitoring to finish
    if monitor_task:
        logger.info("Waiting for processing to complete...")
        await asyncio.sleep(10)  # Give some time for final processing
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

    # Get final stats
    final_stats = await checker.check_processing_stats()

    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    summary = results.summary()
    for key, value in summary.items():
        if isinstance(value, dict):
            print(f"\n{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")

    print("\n" + "=" * 60)
    print("SYSTEM STATE")
    print("=" * 60)
    print(f"Before: {initial_stats}")
    print(f"After:  {final_stats}")

    # Capacity estimates
    print("\n" + "=" * 60)
    print("CAPACITY ESTIMATES")
    print("=" * 60)

    throughput = summary.get("throughput", {})
    alerts_per_hour = throughput.get("alerts_per_hour", 0)
    triaged_per_hour = throughput.get("triaged_per_hour", 0)

    print(f"Sustained alert ingestion: {alerts_per_hour:,.0f} alerts/hour")
    print(f"Sustained triage capacity: {triaged_per_hour:,.0f} alerts/hour")
    print(f"Daily capacity (24h): {alerts_per_hour * 24:,.0f} alerts/day")

    escalation = summary.get("investigations", {}).get("escalation_rate", "N/A")
    print(f"Escalation rate: {escalation}")

    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
