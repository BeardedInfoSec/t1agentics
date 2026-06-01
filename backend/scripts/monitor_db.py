#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Database-Based Pipeline Monitor
================================

Sends alerts and monitors pipeline metrics directly from the database.
No API authentication required - reads metrics straight from PostgreSQL.

Reports:
- Webhook ingest time
- AI Triage time (from token usage logs)
- Token consumption
- Enrichment progress
- Investigation verdicts
"""

import asyncio
import asyncpg
import httpx
import json
import random
import statistics
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

# Configuration
API_BASE = 'http://localhost:8000'
WEBHOOK_URL = f"{API_BASE}/api/v1/webhooks/ingest/test-alert"

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'user': 'agentcore',
    'password': 'agentcore_dev_password',
    'database': 'agentcore'
}


def generate_alert() -> Dict[str, Any]:
    """Generate a test alert"""
    alert_types = ["phishing", "malware", "lateral_movement", "brute_force"]
    alert_type = random.choice(alert_types)

    return {
        "title": f"[{alert_type.upper()}] Test alert on host-{random.randint(1,100)}",
        "description": f"Test alert for pipeline monitoring - {alert_type}",
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "category": alert_type,
        "source": "pipeline_monitor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_event": {
            "event_type": alert_type,
            "host": f"host-{random.randint(1, 100)}",
            "user": f"user{random.randint(1, 50)}@corp.local",
            "source_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "destination_domain": f"malicious-{random.randint(1000, 9999)}.com",
            "file_hash": random.randbytes(32).hex(),
        },
        "indicators": [
            {"type": "ip", "value": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"},
            {"type": "domain", "value": f"malicious-{random.randint(1000, 9999)}.com"},
            {"type": "sha256", "value": random.randbytes(32).hex()},
        ],
    }


async def send_alert(alert_data: Dict[str, Any]) -> tuple[bool, str, float]:
    """Send alert through webhook"""
    start = time.time()

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            WEBHOOK_URL,
            json={"alert_data": alert_data},
            headers={"Content-Type": "application/json"}
        )

        duration_ms = (time.time() - start) * 1000

        if resp.status_code == 200:
            data = resp.json()
            return True, data.get('alert_id', ''), duration_ms
        else:
            return False, '', duration_ms


async def get_metrics(pool: asyncpg.Pool, start_time: datetime) -> Dict[str, Any]:
    """Get pipeline metrics from database"""
    async with pool.acquire() as conn:
        # Alert counts
        alert_stats = await conn.fetchrow('''
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'triaged') as triaged,
                COUNT(*) FILTER (WHERE status = 'investigating') as investigating,
                COUNT(*) FILTER (WHERE investigation_id IS NOT NULL) as with_investigation
            FROM alerts
            WHERE created_at > $1
        ''', start_time)

        # Investigation stats
        inv_stats = await conn.fetchrow('''
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE triage_status = 'provisional') as provisional,
                COUNT(*) FILTER (WHERE triage_status = 'confirmed') as confirmed,
                COUNT(*) FILTER (WHERE enrichment_progress >= 100) as enrichment_complete
            FROM investigations
            WHERE created_at > $1
        ''', start_time)

        # Token usage
        token_stats = await conn.fetchrow('''
            SELECT
                COUNT(*) as requests,
                COALESCE(SUM(total_tokens), 0) as total_tokens,
                COALESCE(AVG(total_tokens), 0) as avg_tokens,
                COALESCE(AVG(response_time_ms), 0) as avg_response_ms,
                COALESCE(MAX(response_time_ms), 0) as max_response_ms
            FROM ai_token_usage
            WHERE created_at > $1
        ''', start_time)

        # Verdict distribution
        verdicts = await conn.fetch('''
            SELECT disposition, COUNT(*) as count
            FROM investigations
            WHERE created_at > $1
            GROUP BY disposition
        ''', start_time)

        return {
            'alerts': dict(alert_stats) if alert_stats else {},
            'investigations': dict(inv_stats) if inv_stats else {},
            'tokens': dict(token_stats) if token_stats else {},
            'verdicts': {r['disposition']: r['count'] for r in verdicts},
        }


async def run_test(count: int = 5, delay: float = 2.0):
    """Run pipeline test and report metrics"""
    print("\n" + "="*60)
    print("PIPELINE PERFORMANCE MONITOR")
    print("="*60)
    print(f"Sending {count} alerts with {delay}s delay")
    print("="*60 + "\n")

    # Connect to database
    pool = await asyncpg.create_pool(**DB_CONFIG)

    start_time = datetime.now(timezone.utc)
    ingest_times = []
    sent_alerts = []

    # Send alerts
    for i in range(count):
        alert = generate_alert()
        success, alert_id, ingest_ms = await send_alert(alert)

        if success:
            ingest_times.append(ingest_ms)
            sent_alerts.append(alert_id)
            print(f"[{i+1}/{count}] Sent: {alert_id} ({ingest_ms:.0f}ms)")
        else:
            print(f"[{i+1}/{count}] FAILED")

        if i < count - 1:
            await asyncio.sleep(delay)

    # Wait for processing
    print("\nWaiting for pipeline processing...")
    await asyncio.sleep(10)

    # Get metrics
    metrics = await get_metrics(pool, start_time)

    # Print report
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    print(f"\n⏱  Duration: {elapsed:.1f}s")
    print(f"📤 Alerts sent: {len(sent_alerts)}")

    if ingest_times:
        print(f"\n📥 WEBHOOK INGEST:")
        print(f"   Avg: {statistics.mean(ingest_times):.0f}ms")
        print(f"   Min: {min(ingest_times):.0f}ms")
        print(f"   Max: {max(ingest_times):.0f}ms")

    a = metrics['alerts']
    if a:
        print(f"\n🔔 ALERTS:")
        print(f"   Total: {a.get('total', 0)}")
        print(f"   Triaged: {a.get('triaged', 0)}")
        print(f"   Investigating: {a.get('investigating', 0)}")
        print(f"   With investigation: {a.get('with_investigation', 0)}")

    inv = metrics['investigations']
    if inv:
        print(f"\n🔍 INVESTIGATIONS:")
        print(f"   Total: {inv.get('total', 0)}")
        print(f"   Provisional: {inv.get('provisional', 0)}")
        print(f"   Confirmed: {inv.get('confirmed', 0)}")
        print(f"   Enrichment complete: {inv.get('enrichment_complete', 0)}")

    t = metrics['tokens']
    if t and t.get('requests', 0) > 0:
        print(f"\n🤖 AI TRIAGE (LLM):")
        print(f"   Requests: {t.get('requests', 0)}")
        print(f"   Total tokens: {int(t.get('total_tokens', 0)):,}")
        print(f"   Avg tokens/request: {int(t.get('avg_tokens', 0)):,}")
        print(f"   Avg response time: {t.get('avg_response_ms', 0):.0f}ms")
        print(f"   Max response time: {t.get('max_response_ms', 0):.0f}ms")

    v = metrics['verdicts']
    if v:
        print(f"\n⚖️  VERDICTS:")
        for verdict, count in v.items():
            print(f"   {verdict or 'NULL'}: {count}")

    # Throughput
    if elapsed > 0 and a:
        triaged_per_min = (a.get('triaged', 0) / elapsed) * 60
        print(f"\n📊 THROUGHPUT:")
        print(f"   Triaged/minute: {triaged_per_min:.1f}")
        print(f"   Projected/hour: {triaged_per_min * 60:.0f}")

    print("\n" + "="*60)

    await pool.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5, help="Number of alerts to send")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between alerts (seconds)")
    args = parser.parse_args()

    asyncio.run(run_test(count=args.count, delay=args.delay))
