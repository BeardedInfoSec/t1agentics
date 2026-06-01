#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
High-Throughput Pipeline Stress Test
=====================================

Sends alerts as fast as possible to measure actual pipeline capacity.
Uses concurrent requests to stress test the system.
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


def generate_alert(idx: int) -> Dict[str, Any]:
    """Generate a unique test alert"""
    alert_types = ["phishing", "malware", "lateral_movement", "brute_force"]
    alert_type = random.choice(alert_types)

    # Use unique IPs to prevent correlation
    unique_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{idx % 256}"
    unique_domain = f"test-{idx}-{random.randint(10000, 99999)}.com"

    return {
        "title": f"[{alert_type.upper()}] Stress test #{idx}",
        "description": f"Stress test alert {idx} - {alert_type}",
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "category": alert_type,
        "source": f"stress_test_{idx}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_event": {
            "event_type": alert_type,
            "host": f"stress-host-{idx}",
            "user": f"user{idx}@test.local",
            "source_ip": unique_ip,
            "destination_domain": unique_domain,
            "file_hash": f"{idx:064x}",
        },
        "indicators": [
            {"type": "ip", "value": unique_ip},
            {"type": "domain", "value": unique_domain},
        ],
    }


async def send_alert(client: httpx.AsyncClient, alert_data: Dict[str, Any], idx: int) -> tuple[bool, float]:
    """Send alert through webhook"""
    start = time.time()
    try:
        resp = await client.post(
            WEBHOOK_URL,
            json={"alert_data": alert_data},
            headers={"Content-Type": "application/json"}
        )
        duration_ms = (time.time() - start) * 1000
        return resp.status_code == 200, duration_ms
    except Exception as e:
        duration_ms = (time.time() - start) * 1000
        return False, duration_ms


async def run_stress_test(count: int = 20, concurrency: int = 5):
    """Run high-throughput stress test"""
    print("\n" + "="*70)
    print("HIGH-THROUGHPUT PIPELINE STRESS TEST")
    print("="*70)
    print(f"Total alerts: {count}")
    print(f"Concurrency: {concurrency}")
    print("="*70 + "\n")

    # Connect to database
    pool = await asyncpg.create_pool(**DB_CONFIG)

    # Get initial counts
    async with pool.acquire() as conn:
        initial_alerts = await conn.fetchval('SELECT COUNT(*) FROM alerts')
        initial_invs = await conn.fetchval('SELECT COUNT(*) FROM investigations')

    start_time = time.time()
    ingest_times = []
    successes = 0
    failures = 0

    # Create semaphore for concurrency control
    semaphore = asyncio.Semaphore(concurrency)

    async def send_with_semaphore(client: httpx.AsyncClient, idx: int):
        nonlocal successes, failures
        async with semaphore:
            alert = generate_alert(idx)
            success, duration = await send_alert(client, alert, idx)
            ingest_times.append(duration)
            if success:
                successes += 1
            else:
                failures += 1

            # Progress indicator
            total = successes + failures
            if total % 10 == 0 or total == count:
                elapsed = time.time() - start_time
                rate = total / elapsed if elapsed > 0 else 0
                print(f"  Progress: {total}/{count} ({rate:.1f}/sec)")

    # Send all alerts concurrently
    async with httpx.AsyncClient(timeout=60.0) as client:
        tasks = [send_with_semaphore(client, i) for i in range(count)]
        await asyncio.gather(*tasks)

    send_elapsed = time.time() - start_time

    print(f"\n📤 All {count} alerts sent in {send_elapsed:.1f}s")
    print("   Waiting for pipeline processing...")

    # Wait for processing to complete
    await asyncio.sleep(15)

    # Get final counts
    async with pool.acquire() as conn:
        final_alerts = await conn.fetchval('SELECT COUNT(*) FROM alerts')
        triaged = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'triaged'")
        investigating = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'investigating'")
        with_inv = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE investigation_id IS NOT NULL")
        final_invs = await conn.fetchval('SELECT COUNT(*) FROM investigations')

        # Token stats
        token_stats = await conn.fetchrow('''
            SELECT
                COUNT(*) as requests,
                COALESCE(SUM(total_tokens), 0) as total_tokens,
                COALESCE(AVG(total_tokens), 0) as avg_tokens,
                COALESCE(AVG(response_time_ms), 0) as avg_response_ms
            FROM ai_token_usage
            WHERE created_at > NOW() - INTERVAL '5 minutes'
        ''')

    total_elapsed = time.time() - start_time
    new_alerts = final_alerts - initial_alerts
    new_invs = final_invs - initial_invs

    # Print results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)

    print(f"\n⏱️  TIMING:")
    print(f"   Send phase: {send_elapsed:.1f}s")
    print(f"   Total test: {total_elapsed:.1f}s")

    print(f"\n📥 WEBHOOK INGEST:")
    if ingest_times:
        print(f"   Avg: {statistics.mean(ingest_times):.0f}ms")
        print(f"   Min: {min(ingest_times):.0f}ms")
        print(f"   Max: {max(ingest_times):.0f}ms")
        print(f"   P95: {sorted(ingest_times)[int(len(ingest_times)*0.95)]:.0f}ms")

    print(f"\n📊 SEND THROUGHPUT:")
    print(f"   Successes: {successes}")
    print(f"   Failures: {failures}")
    print(f"   Rate: {successes / send_elapsed:.1f} alerts/sec")
    print(f"   Projected: {successes / send_elapsed * 60:.0f} alerts/min")
    print(f"   Projected: {successes / send_elapsed * 3600:.0f} alerts/hour")

    print(f"\n🔔 PIPELINE PROCESSING:")
    print(f"   New alerts: {new_alerts}")
    print(f"   Triaged: {triaged}")
    print(f"   Investigating: {investigating}")
    print(f"   With investigation: {with_inv}")
    print(f"   New investigations: {new_invs}")

    if token_stats and token_stats['requests'] > 0:
        print(f"\n🤖 AI TRIAGE (LLM):")
        print(f"   LLM requests: {token_stats['requests']}")
        print(f"   Total tokens: {int(token_stats['total_tokens']):,}")
        print(f"   Avg tokens/request: {int(token_stats['avg_tokens']):,}")
        print(f"   Avg LLM response time: {token_stats['avg_response_ms']:.0f}ms")

    # Calculate actual triage throughput
    if triaged > 0:
        triage_rate = triaged / total_elapsed
        print(f"\n📈 TRIAGE THROUGHPUT:")
        print(f"   Triaged/sec: {triage_rate:.2f}")
        print(f"   Triaged/min: {triage_rate * 60:.1f}")
        print(f"   Triaged/hour: {triage_rate * 3600:.0f}")
        print(f"   Projected/day: {triage_rate * 86400:.0f}")

    print("\n" + "="*70)

    await pool.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=20, help="Number of alerts to send")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent requests")
    args = parser.parse_args()

    asyncio.run(run_stress_test(count=args.count, concurrency=args.concurrency))
