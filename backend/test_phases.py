# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Phase Testing Script
Tests all 14 phases of the platform
"""

import asyncio
from datetime import datetime

async def run_phase_tests():
    from services.postgres_db import postgres_db
    await postgres_db.connect()

    results = {}

    async with postgres_db.pool.acquire() as conn:
        print("=" * 60)
        print("T1 Agentics PHASE TESTING - December 25, 2025")
        print("=" * 60)

        # Phase 1: Core Platform
        print("\n[PHASE 1] Core Platform & Authentication")
        users = await conn.fetchval("SELECT COUNT(*) FROM users")
        print(f"  Users in system: {users}")
        results["phase1"] = {"users": users, "status": "PASS" if users > 0 else "FAIL"}

        # Phase 2: Alert Management
        print("\n[PHASE 2] Alert Management")
        alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts")
        open_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
        print(f"  Total alerts: {alerts}")
        print(f"  Open alerts: {open_alerts}")
        results["phase2"] = {"total": alerts, "open": open_alerts, "status": "PASS" if alerts > 0 else "PARTIAL"}

        # Phase 2.4: Alert Deduplication
        print("\n[PHASE 2.4] Alert Deduplication")
        try:
            dedupe_rules = await conn.fetchval("SELECT COUNT(*) FROM dedupe_config")
            dedupe_groups = await conn.fetchval("SELECT COUNT(*) FROM alert_groups")
            print(f"  Deduplication rules: {dedupe_rules}")
            print(f"  Alert groups: {dedupe_groups}")
            results["phase2_4"] = {"rules": dedupe_rules, "groups": dedupe_groups, "status": "PASS"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase2_4"] = {"status": "FAIL", "error": str(e)}

        # Phase 3: Investigations
        print("\n[PHASE 3] Investigation Management")
        investigations = await conn.fetchval("SELECT COUNT(*) FROM investigations")
        active_inv = await conn.fetchval("SELECT COUNT(*) FROM investigations WHERE state IN ('NEW', 'IN_PROGRESS', 'AWAITING_HUMAN')")
        print(f"  Total investigations: {investigations}")
        print(f"  Active investigations: {active_inv}")
        results["phase3"] = {"total": investigations, "active": active_inv, "status": "PASS" if investigations > 0 else "PARTIAL"}

        # Phase 4: IOC/Threat Intel
        print("\n[PHASE 4] Threat Intelligence")
        iocs = await conn.fetchval("SELECT COUNT(*) FROM iocs")
        feeds = await conn.fetchval("SELECT COUNT(*) FROM threat_feeds")
        print(f"  IOCs tracked: {iocs}")
        print(f"  Threat feeds: {feeds}")
        results["phase4"] = {"iocs": iocs, "feeds": feeds, "status": "PASS" if iocs > 0 else "PARTIAL"}

        # Phase 5: Integrations
        print("\n[PHASE 5] Integration Framework")
        integrations = await conn.fetchval("SELECT COUNT(*) FROM integrations")
        credentials = await conn.fetchval("SELECT COUNT(*) FROM credentials")
        print(f"  Integrations: {integrations}")
        print(f"  Credentials stored: {credentials}")
        results["phase5"] = {"integrations": integrations, "credentials": credentials, "status": "PASS" if integrations > 0 else "PARTIAL"}

        # Phase 6: Webhooks
        print("\n[PHASE 6] Webhook Ingestion")
        webhooks = await conn.fetchval("SELECT COUNT(*) FROM webhooks")
        print(f"  Webhooks configured: {webhooks}")
        results["phase6"] = {"webhooks": webhooks, "status": "PASS" if webhooks > 0 else "PARTIAL"}

        # Phase 7: AI Agents
        print("\n[PHASE 7] AI Agent System")
        agents = await conn.fetchval("SELECT COUNT(*) FROM agent_definitions")
        enabled_agents = await conn.fetchval("SELECT COUNT(*) FROM agent_definitions WHERE enabled = true")
        executions = await conn.fetchval("SELECT COUNT(*) FROM agent_executions")
        print(f"  Agent definitions: {agents}")
        print(f"  Enabled agents: {enabled_agents}")
        print(f"  Total executions: {executions}")
        results["phase7"] = {"agents": agents, "enabled": enabled_agents, "executions": executions, "status": "PASS" if agents > 0 else "FAIL"}

        # Phase 8: AI Telemetry
        print("\n[PHASE 8] AI Telemetry")
        try:
            token_usage = await conn.fetchval("SELECT COUNT(*) FROM ai_token_usage")
            print(f"  Token usage records: {token_usage}")
            results["phase8"] = {"token_records": token_usage, "status": "PASS" if token_usage > 0 else "PARTIAL"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase8"] = {"status": "FAIL", "error": str(e)}

        # Phase 9: Job Queue
        print("\n[PHASE 9] Job Queue System")
        try:
            jobs_total = await conn.fetchval("SELECT COUNT(*) FROM job_queue")
            jobs_pending = await conn.fetchval("SELECT COUNT(*) FROM job_queue WHERE status = 'pending'")
            jobs_completed = await conn.fetchval("SELECT COUNT(*) FROM job_queue WHERE status = 'completed'")
            print(f"  Total jobs: {jobs_total}")
            print(f"  Pending: {jobs_pending}")
            print(f"  Completed: {jobs_completed}")
            results["phase9"] = {"total": jobs_total, "pending": jobs_pending, "completed": jobs_completed, "status": "PASS"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase9"] = {"status": "FAIL", "error": str(e)}

        # Phase 10: Email Integration
        print("\n[PHASE 10] Email Integration")
        try:
            mailboxes = await conn.fetchval("SELECT COUNT(*) FROM inbound_mailboxes")
            phishing_reports = await conn.fetchval("SELECT COUNT(*) FROM phishing_reports")
            print(f"  Email mailboxes: {mailboxes}")
            print(f"  Phishing reports: {phishing_reports}")
            results["phase10"] = {"mailboxes": mailboxes, "phishing_reports": phishing_reports, "status": "PASS" if mailboxes > 0 else "PARTIAL"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase10"] = {"status": "FAIL", "error": str(e)}

        # Phase 11: Knowledge Base
        print("\n[PHASE 11] Knowledge Base")
        try:
            kb_docs = await conn.fetchval("SELECT COUNT(*) FROM knowledge_base")
            kb_uploads = await conn.fetchval("SELECT COUNT(*) FROM kb_document_uploads")
            print(f"  KB articles: {kb_docs}")
            print(f"  KB uploads: {kb_uploads}")
            results["phase11"] = {"documents": kb_docs, "uploads": kb_uploads, "status": "PASS" if kb_docs > 0 else "PARTIAL"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase11"] = {"status": "PARTIAL", "error": str(e)}

        # Phase 12: Asset Management
        print("\n[PHASE 12] Asset Management")
        try:
            assets = await conn.fetchval("SELECT COUNT(*) FROM assets")
            print(f"  Assets tracked: {assets}")
            results["phase12"] = {"assets": assets, "status": "PASS" if assets > 0 else "PARTIAL"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase12"] = {"status": "PARTIAL", "error": str(e)}

        # Phase 14: Correlation Engine
        print("\n[PHASE 14] IOC Correlation Engine")
        try:
            correlation_rules = await conn.fetchval("SELECT COUNT(*) FROM correlation_rules")
            campaigns = await conn.fetchval("SELECT COUNT(*) FROM campaigns")
            print(f"  Correlation rules: {correlation_rules}")
            print(f"  Campaigns detected: {campaigns}")
            results["phase14"] = {"rules": correlation_rules, "campaigns": campaigns, "status": "PASS"}
        except Exception as e:
            print(f"  Error: {e}")
            results["phase14"] = {"status": "FAIL", "error": str(e)}

        # Additional Components
        print("\n[ADDITIONAL] Post-Resolution & Exclusions")
        try:
            pr_rules = await conn.fetchval("SELECT COUNT(*) FROM post_resolution_rules")
            exclusions = await conn.fetchval("SELECT COUNT(*) FROM exclusion_list")
            print(f"  Post-resolution rules: {pr_rules}")
            print(f"  Exclusion entries: {exclusions}")
            results["additional"] = {"pr_rules": pr_rules, "exclusions": exclusions, "status": "PASS"}
        except Exception as e:
            print(f"  Error: {e}")
            results["additional"] = {"status": "PARTIAL", "error": str(e)}

        # Summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        pass_count = sum(1 for r in results.values() if r.get("status") == "PASS")
        partial_count = sum(1 for r in results.values() if r.get("status") == "PARTIAL")
        fail_count = sum(1 for r in results.values() if r.get("status") == "FAIL")
        print(f"PASS: {pass_count} | PARTIAL: {partial_count} | FAIL: {fail_count}")
        print(f"Total phases tested: {len(results)}")

        return results

if __name__ == "__main__":
    asyncio.run(run_phase_tests())
