# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Feature Verification Script
"""

import asyncio

async def test_features():
    from services.postgres_db import postgres_db
    await postgres_db.connect()
    async with postgres_db.pool.acquire() as conn:
        print("=" * 60)
        print("T1 Agentics FEATURE VERIFICATION")
        print("=" * 60)

        # Alert ID System
        print("\n[1] SYSTEMATIC ALERT IDS")
        new_ids = await conn.fetch("""
            SELECT alert_id, title, created_at
            FROM alerts
            WHERE alert_id ~ '^[A-Z]{2,3}-[0-9]{6}-[0-9]{4}$'
            ORDER BY created_at DESC LIMIT 5
        """)
        print(f"  New systematic IDs: {len(new_ids)}")
        for r in new_ids:
            print(f"    {r[0]} - {r[1][:35]}")

        # AI Agents
        print("\n[2] AI AGENT SYSTEM")
        agents = await conn.fetch("SELECT tier, enabled FROM agent_definitions ORDER BY tier")
        for a in agents:
            print(f"  Tier {a[0]} Agent - {'ENABLED' if a[1] else 'disabled'}")

        executions = await conn.fetchval("SELECT COUNT(*) FROM agent_executions")
        print(f"  Total executions: {executions}")

        # Token Usage
        print("\n[3] TOKEN TRACKING")
        token_stats = await conn.fetchrow("""
            SELECT SUM(prompt_tokens), SUM(completion_tokens), COUNT(*)
            FROM ai_token_usage
        """)
        if token_stats and token_stats[2]:
            total_tokens = (token_stats[0] or 0) + (token_stats[1] or 0)
            print(f"  API calls: {token_stats[2]:,}")
            print(f"  Total tokens: {total_tokens:,}")

        # Investigations
        print("\n[4] INVESTIGATIONS")
        states = await conn.fetch("""
            SELECT state, COUNT(*) FROM investigations GROUP BY state ORDER BY COUNT(*) DESC
        """)
        for s in states:
            print(f"  {s[0]}: {s[1]}")

        # Threat Intelligence
        print("\n[5] THREAT INTELLIGENCE")
        ioc_count = await conn.fetchval("SELECT COUNT(*) FROM iocs")
        feed_count = await conn.fetchval("SELECT COUNT(*) FROM threat_feeds")
        enabled_feeds = await conn.fetchval("SELECT COUNT(*) FROM threat_feeds WHERE enabled = true")
        print(f"  IOCs tracked: {ioc_count:,}")
        print(f"  Threat feeds: {enabled_feeds}/{feed_count} enabled")

        # IOC types
        ioc_types = await conn.fetch("""
            SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type ORDER BY COUNT(*) DESC LIMIT 5
        """)
        for t in ioc_types:
            print(f"    {t[0]}: {t[1]:,}")

        # Integrations
        print("\n[6] INTEGRATIONS")
        int_count = await conn.fetchval("SELECT COUNT(*) FROM integrations")
        enabled_ints = await conn.fetchval("SELECT COUNT(*) FROM integrations WHERE enabled = true")
        print(f"  Integrations: {enabled_ints}/{int_count} enabled")

        # Webhooks
        print("\n[7] WEBHOOKS")
        webhooks = await conn.fetchval("SELECT COUNT(*) FROM webhooks")
        enabled_webhooks = await conn.fetchval("SELECT COUNT(*) FROM webhooks WHERE enabled = true")
        print(f"  Webhooks: {enabled_webhooks}/{webhooks} enabled")

        # Job Queue
        print("\n[8] JOB QUEUE")
        jobs = await conn.fetch("""
            SELECT status, COUNT(*) FROM job_queue GROUP BY status
        """)
        for j in jobs:
            print(f"  {j[0]}: {j[1]}")

        # Correlation
        print("\n[9] CORRELATION ENGINE")
        rules = await conn.fetchval("SELECT COUNT(*) FROM correlation_rules")
        campaigns = await conn.fetchval("SELECT COUNT(*) FROM campaigns")
        print(f"  Correlation rules: {rules}")
        print(f"  Campaigns detected: {campaigns}")

        # Assets
        print("\n[10] ASSET MANAGEMENT")
        assets = await conn.fetchval("SELECT COUNT(*) FROM assets")
        print(f"  Assets tracked: {assets}")

        print("\n" + "=" * 60)
        print("VERIFICATION COMPLETE")
        print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_features())
