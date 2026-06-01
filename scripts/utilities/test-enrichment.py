#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test enrichment directly
"""
import asyncio
import sys

async def test_enrichment():
    # Add backend to path
    sys.path.insert(0, '/app')

    from services.auto_enrichment import auto_enrichment_service
    from services.postgres_db import postgres_db

    # Get a recent alert
    async with postgres_db.pool.acquire() as conn:
        alert = await conn.fetchrow("""
            SELECT alert_id, raw_event
            FROM alerts
            WHERE raw_event IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
        """)

        if not alert:
            print("No alerts found")
            return

        alert_id = alert['alert_id']
        raw_event = alert['raw_event']

        print(f"Testing enrichment for alert: {alert_id}")
        print(f"Raw event keys: {list(raw_event.keys())}")
        print(f"Observables: {raw_event.get('observables', [])}")

        # Try to enrich
        print("\nStarting enrichment...")
        try:
            result = await auto_enrichment_service.enrich_alert(alert_id, raw_event)
            print(f"\n✅ Enrichment completed!")
            print(f"Result keys: {list(result.keys())}")
            print(f"IPs enriched: {len(result.get('ips', []))}")
            print(f"Domains enriched: {len(result.get('domains', []))}")
            print(f"Hashes enriched: {len(result.get('hashes', []))}")
        except Exception as e:
            print(f"\n❌ Enrichment failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_enrichment())
