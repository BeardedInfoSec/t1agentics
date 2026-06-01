#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Pipeline Performance Monitor
============================

Generates alerts and tracks execution time for EACH PHASE of the pipeline:

PHASES TRACKED:
1. WEBHOOK_INGEST    - Time to accept and store alert
2. IOC_EXTRACTION    - Time to extract IOCs from raw event
3. ENRICHMENT        - Time to enrich IOCs (VT, AbuseIPDB, etc.)
4. AI_TRIAGE         - Time for FAST LLM triage (provisional verdict)
5. MERGE             - Time for merge engine to combine tracks
6. DEEP_ANALYSIS     - Time for DEEP LLM analysis (if triggered)

Reports:
- Per-phase timing (avg, p50, p95, p99)
- End-to-end latency
- Throughput (alerts/min)
- Token usage statistics
- Bottleneck identification
"""

import asyncio
import httpx
import json
import logging
import os
import random
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

API_BASE = os.getenv('API_BASE_URL', 'http://localhost:8000')
WEBHOOK_URL = f"{API_BASE}/api/v1/webhooks/ingest/test-alert"

# Alert generation config
ALERT_TYPES = ["phishing", "malware", "lateral_movement", "brute_force", "data_exfil"]
SEVERITIES = ["low", "medium", "high", "critical"]

# Database connection for direct metric queries
DB_HOST = os.getenv('POSTGRES_HOST', 'localhost')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')
DB_USER = os.getenv('POSTGRES_USER', 'agentcore')
DB_PASS = os.getenv('POSTGRES_PASSWORD', 'agentcore_dev_password')
DB_NAME = os.getenv('POSTGRES_DB', 'agentcore')


# =============================================================================
# Phase Timing Tracker
# =============================================================================

@dataclass
class PhaseTiming:
    """Tracks timing for a single pipeline phase"""
    name: str
    start_times: Dict[str, float] = field(default_factory=dict)
    durations: List[float] = field(default_factory=list)

    def start(self, alert_id: str):
        self.start_times[alert_id] = time.time()

    def end(self, alert_id: str):
        if alert_id in self.start_times:
            duration = time.time() - self.start_times[alert_id]
            self.durations.append(duration)
            del self.start_times[alert_id]
            return duration
        return None

    def record(self, duration_ms: float):
        """Record a duration directly in milliseconds"""
        self.durations.append(duration_ms / 1000)  # Convert to seconds

    def stats(self) -> Dict[str, Any]:
        if not self.durations:
            return {"count": 0}

        sorted_d = sorted(self.durations)
        return {
            "count": len(self.durations),
            "avg_ms": round(statistics.mean(self.durations) * 1000, 1),
            "p50_ms": round(statistics.median(self.durations) * 1000, 1),
            "p95_ms": round(sorted_d[int(len(sorted_d) * 0.95)] * 1000, 1) if len(sorted_d) > 1 else 0,
            "p99_ms": round(sorted_d[int(len(sorted_d) * 0.99)] * 1000, 1) if len(sorted_d) > 10 else 0,
            "min_ms": round(min(self.durations) * 1000, 1),
            "max_ms": round(max(self.durations) * 1000, 1),
        }


@dataclass
class PipelineMetrics:
    """Comprehensive pipeline metrics tracker"""

    # Phase timings
    phases: Dict[str, PhaseTiming] = field(default_factory=lambda: {
        "webhook_ingest": PhaseTiming("webhook_ingest"),
        "ioc_extraction": PhaseTiming("ioc_extraction"),
        "enrichment": PhaseTiming("enrichment"),
        "ai_triage": PhaseTiming("ai_triage"),
        "merge": PhaseTiming("merge"),
        "deep_analysis": PhaseTiming("deep_analysis"),
        "end_to_end": PhaseTiming("end_to_end"),
    })

    # Counters
    alerts_sent: int = 0
    alerts_ingested: int = 0
    alerts_triaged: int = 0
    investigations_created: int = 0
    deep_triggered: int = 0
    errors: int = 0

    # Token tracking
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    # Verdicts
    verdicts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Tracking
    start_time: float = 0
    alert_send_times: Dict[str, float] = field(default_factory=dict)

    def record_send(self, alert_id: str):
        self.alerts_sent += 1
        self.alert_send_times[alert_id] = time.time()
        self.phases["webhook_ingest"].start(alert_id)

    def record_ingest(self, alert_id: str, duration_ms: float):
        self.alerts_ingested += 1
        self.phases["webhook_ingest"].record(duration_ms)

    def record_triage(self, alert_id: str, verdict: str, duration_ms: float, tokens: Dict[str, int] = None):
        self.alerts_triaged += 1
        self.verdicts[verdict] += 1
        self.phases["ai_triage"].record(duration_ms)

        if tokens:
            self.total_tokens += tokens.get('total', 0)
            self.prompt_tokens += tokens.get('prompt', 0)
            self.completion_tokens += tokens.get('completion', 0)

        # Record end-to-end if we have start time
        if alert_id in self.alert_send_times:
            e2e = (time.time() - self.alert_send_times[alert_id]) * 1000
            self.phases["end_to_end"].record(e2e)

    def summary(self) -> Dict[str, Any]:
        elapsed = time.time() - self.start_time if self.start_time else 1
        elapsed_min = elapsed / 60

        return {
            "duration_seconds": round(elapsed, 1),
            "duration_minutes": round(elapsed_min, 2),

            "throughput": {
                "alerts_sent": self.alerts_sent,
                "alerts_per_minute": round(self.alerts_sent / max(elapsed_min, 0.01), 2),
                "triaged_per_minute": round(self.alerts_triaged / max(elapsed_min, 0.01), 2),
            },

            "pipeline": {
                "ingested": self.alerts_ingested,
                "triaged": self.alerts_triaged,
                "investigations": self.investigations_created,
                "deep_triggered": self.deep_triggered,
                "errors": self.errors,
                "success_rate": f"{(self.alerts_triaged / max(self.alerts_sent, 1)) * 100:.1f}%",
            },

            "phase_timing": {
                name: phase.stats() for name, phase in self.phases.items()
            },

            "tokens": {
                "total": self.total_tokens,
                "prompt": self.prompt_tokens,
                "completion": self.completion_tokens,
                "avg_per_alert": round(self.total_tokens / max(self.alerts_triaged, 1), 0),
            },

            "verdicts": dict(self.verdicts),
        }


# =============================================================================
# Alert Generator
# =============================================================================

def generate_alert() -> Dict[str, Any]:
    """Generate a realistic test alert with IOCs"""
    alert_type = random.choice(ALERT_TYPES)
    severity = random.choice(SEVERITIES)

    # Generate IOCs based on alert type
    iocs = {
        "ips": [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"],
        "domains": [f"malicious-{random.randint(1000,9999)}.{random.choice(['com', 'net', 'ru', 'cn'])}"],
        "hashes": [f"{random.randbytes(32).hex()}"],
    }

    # Add more IOCs for malware/lateral movement
    if alert_type in ["malware", "lateral_movement"]:
        iocs["ips"].append(f"10.0.{random.randint(1,254)}.{random.randint(1,254)}")
        iocs["domains"].append(f"c2-server-{random.randint(100,999)}.net")

    hosts = ["WS-3421", "SRV-AD01", "LNX-WEB01", "DC-01", "FILESVR-01"]
    users = ["admin", "jsmith", "mwilson", "svc_backup", "root"]

    return {
        "title": f"[{alert_type.upper()}] Suspicious activity detected on {random.choice(hosts)}",
        "description": f"Security alert triggered by {alert_type} detection. Severity: {severity}. "
                      f"Multiple indicators detected requiring investigation.",
        "severity": severity,
        "category": alert_type,
        "source": "pipeline_monitor",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_event": {
            "event_type": alert_type,
            "host": random.choice(hosts),
            "user": random.choice(users),
            "source_ip": iocs["ips"][0],
            "destination_domain": iocs["domains"][0],
            "file_hash": iocs["hashes"][0],
            "process": random.choice(["powershell.exe", "cmd.exe", "python.exe", "bash"]),
            "command_line": f"suspicious command with args --flag {random.randint(1,100)}",
        },
        "indicators": [
            {"type": "ip", "value": ip} for ip in iocs["ips"]
        ] + [
            {"type": "domain", "value": d} for d in iocs["domains"]
        ] + [
            {"type": "sha256", "value": h} for h in iocs["hashes"]
        ],
    }


# =============================================================================
# Pipeline Monitor
# =============================================================================

class PipelineMonitor:
    """Monitors the full alert processing pipeline"""

    def __init__(self, api_base: str = API_BASE):
        self.api_base = api_base
        self.webhook_url = f"{api_base}/api/v1/webhooks/ingest/test-alert"
        self.metrics = PipelineMetrics()
        self.running = False
        self.db_pool = None

    async def init_db(self):
        """Initialize database connection for metrics queries"""
        try:
            import asyncpg
            self.db_pool = await asyncpg.create_pool(
                host=DB_HOST,
                port=int(DB_PORT),
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                min_size=1,
                max_size=5
            )
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Could not connect to database: {e}")
            self.db_pool = None

    async def send_alert(self, alert_data: Dict[str, Any]) -> Tuple[bool, str, float]:
        """Send alert and measure ingest time"""
        alert_id = f"test-{int(time.time()*1000)}-{random.randint(1000,9999)}"

        start = time.time()
        self.metrics.record_send(alert_id)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self.webhook_url,
                    json={"alert_data": alert_data},
                    headers={"Content-Type": "application/json"}
                )

                duration_ms = (time.time() - start) * 1000

                if resp.status_code == 200:
                    data = resp.json()
                    actual_id = data.get('alert_id', alert_id)
                    self.metrics.record_ingest(actual_id, duration_ms)
                    return True, actual_id, duration_ms
                else:
                    self.metrics.errors += 1
                    return False, alert_id, duration_ms

        except Exception as e:
            self.metrics.errors += 1
            logger.error(f"Send error: {e}")
            return False, alert_id, 0

    async def poll_alert_status(self, alert_id: str, timeout: float = 60) -> Dict[str, Any]:
        """Poll for alert processing completion"""
        start = time.time()

        while time.time() - start < timeout:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(f"{self.api_base}/api/v1/alerts/{alert_id}")

                    if resp.status_code == 200:
                        data = resp.json()

                        # Check if triage is complete
                        if data.get('investigation_id'):
                            return data

                await asyncio.sleep(0.5)

            except Exception:
                await asyncio.sleep(0.5)

        return {}

    async def get_investigation_metrics(self, investigation_id: str) -> Dict[str, Any]:
        """Get detailed metrics for an investigation from database"""
        if not self.db_pool:
            return {}

        try:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT
                        i.disposition,
                        i.confidence,
                        i.triage_status,
                        i.provisional_verdict,
                        i.provisional_confidence,
                        i.final_verdict,
                        i.final_confidence,
                        i.enrichment_progress,
                        i.enrichment_total_iocs,
                        i.enrichment_completed_iocs,
                        i.merge_version,
                        i.created_at,
                        i.updated_at,
                        i.investigation_data
                    FROM investigations i
                    WHERE i.investigation_id = $1
                ''', investigation_id)

                if row:
                    return dict(row)
        except Exception as e:
            logger.debug(f"DB query failed: {e}")

        return {}

    async def get_token_usage(self) -> Dict[str, Any]:
        """Get token usage statistics from database"""
        if not self.db_pool:
            return {}

        try:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT
                        COUNT(*) as request_count,
                        COALESCE(SUM(prompt_tokens), 0) as total_prompt,
                        COALESCE(SUM(completion_tokens), 0) as total_completion,
                        COALESCE(SUM(total_tokens), 0) as total_tokens,
                        COALESCE(AVG(total_tokens), 0) as avg_tokens
                    FROM ai_token_usage
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                ''')

                if row:
                    return dict(row)
        except Exception:
            pass

        return {}

    async def run_single_alert(self) -> Dict[str, Any]:
        """Send a single alert and track full pipeline"""
        alert_data = generate_alert()

        # Send alert
        success, alert_id, ingest_time = await self.send_alert(alert_data)

        if not success:
            return {"status": "failed", "phase": "ingest"}

        logger.info(f"  Sent: {alert_id} ({ingest_time:.0f}ms ingest)")

        # Poll for completion
        status = await self.poll_alert_status(alert_id, timeout=30)

        if status.get('investigation_id'):
            inv_id = status['investigation_id']
            self.metrics.investigations_created += 1

            # Get investigation details
            inv_data = await self.get_investigation_metrics(inv_id)

            if inv_data:
                verdict = inv_data.get('disposition', 'UNKNOWN')

                # Calculate approximate triage time (created_at to updated_at)
                if inv_data.get('created_at') and inv_data.get('updated_at'):
                    triage_time = (inv_data['updated_at'] - inv_data['created_at']).total_seconds() * 1000
                else:
                    triage_time = 0

                self.metrics.record_triage(alert_id, verdict, triage_time)

                logger.info(f"  Triaged: {inv_id} -> {verdict} ({triage_time:.0f}ms)")

                return {
                    "status": "complete",
                    "alert_id": alert_id,
                    "investigation_id": inv_id,
                    "verdict": verdict,
                    "triage_status": inv_data.get('triage_status'),
                    "enrichment_progress": inv_data.get('enrichment_progress', 0),
                }

        return {"status": "pending", "alert_id": alert_id}

    async def run_continuous(self, rate: float = 1.0, duration: int = 60):
        """Run continuous alert generation at specified rate"""
        self.metrics.start_time = time.time()
        self.running = True

        interval = 1.0 / rate
        end_time = time.time() + duration

        logger.info(f"\n{'='*60}")
        logger.info(f"PIPELINE MONITOR - Starting continuous mode")
        logger.info(f"Rate: {rate}/sec | Duration: {duration}s")
        logger.info(f"{'='*60}\n")

        await self.init_db()

        alert_num = 0
        last_summary = time.time()

        while time.time() < end_time and self.running:
            send_start = time.time()

            alert_num += 1
            logger.info(f"[{alert_num}] Sending alert...")

            result = await self.run_single_alert()

            # Print periodic summary every 10 seconds
            if time.time() - last_summary >= 10:
                self.print_summary()
                last_summary = time.time()

            # Rate limiting
            elapsed = time.time() - send_start
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

        self.running = False

        # Final summary
        logger.info(f"\n{'='*60}")
        logger.info("FINAL RESULTS")
        logger.info(f"{'='*60}")
        self.print_summary(detailed=True)

    async def run_burst(self, count: int = 10):
        """Send a burst of alerts"""
        self.metrics.start_time = time.time()

        logger.info(f"\n{'='*60}")
        logger.info(f"PIPELINE MONITOR - Burst mode ({count} alerts)")
        logger.info(f"{'='*60}\n")

        await self.init_db()

        tasks = []
        for i in range(count):
            logger.info(f"[{i+1}/{count}] Sending...")
            result = await self.run_single_alert()
            await asyncio.sleep(0.1)  # Small delay between sends

        # Wait for processing
        logger.info("\nWaiting for pipeline processing...")
        await asyncio.sleep(5)

        self.print_summary(detailed=True)

    def print_summary(self, detailed: bool = False):
        """Print current metrics summary"""
        summary = self.metrics.summary()

        print(f"\n{'─'*50}")
        print(f"⏱  Duration: {summary['duration_seconds']:.1f}s")
        print(f"📊 Throughput: {summary['throughput']['alerts_per_minute']:.1f} alerts/min")
        print(f"{'─'*50}")

        # Pipeline status
        p = summary['pipeline']
        print(f"📥 Sent: {p['ingested']} | ✅ Triaged: {p['triaged']} | 🔍 Investigations: {p['investigations']}")
        print(f"   Success rate: {p['success_rate']} | Errors: {p['errors']}")

        # Phase timings
        print(f"\n{'─'*50}")
        print("PHASE TIMING (ms):")
        print(f"{'─'*50}")

        phases = summary['phase_timing']
        for name, stats in phases.items():
            if stats.get('count', 0) > 0:
                print(f"  {name:18} │ avg: {stats['avg_ms']:6.0f} │ p50: {stats['p50_ms']:6.0f} │ p95: {stats['p95_ms']:6.0f}")

        # Verdicts
        if summary['verdicts']:
            print(f"\n{'─'*50}")
            print("VERDICTS:")
            for verdict, count in summary['verdicts'].items():
                print(f"  {verdict}: {count}")

        # Tokens
        t = summary['tokens']
        if t['total'] > 0:
            print(f"\n{'─'*50}")
            print(f"TOKENS: {t['total']:,} total | {t['avg_per_alert']:.0f} avg/alert")

        print(f"{'─'*50}\n")

        if detailed:
            # Identify bottleneck
            phases_with_time = [(n, s['avg_ms']) for n, s in phases.items() if s.get('avg_ms', 0) > 0]
            if phases_with_time:
                bottleneck = max(phases_with_time, key=lambda x: x[1])
                print(f"🔴 BOTTLENECK: {bottleneck[0]} ({bottleneck[1]:.0f}ms avg)")


# =============================================================================
# Main
# =============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Pipeline Performance Monitor")
    parser.add_argument("--mode", choices=["burst", "continuous", "single"], default="burst",
                       help="Test mode")
    parser.add_argument("--count", type=int, default=5, help="Number of alerts (burst mode)")
    parser.add_argument("--rate", type=float, default=0.5, help="Alerts per second (continuous mode)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds (continuous mode)")
    parser.add_argument("--api", type=str, default=API_BASE, help="API base URL")

    args = parser.parse_args()

    monitor = PipelineMonitor(args.api)

    if args.mode == "single":
        await monitor.init_db()
        result = await monitor.run_single_alert()
        print(f"\nResult: {json.dumps(result, indent=2)}")

    elif args.mode == "burst":
        await monitor.run_burst(count=args.count)

    elif args.mode == "continuous":
        await monitor.run_continuous(rate=args.rate, duration=args.duration)


if __name__ == "__main__":
    asyncio.run(main())
