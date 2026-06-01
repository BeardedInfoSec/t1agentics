"""Check state of stuck investigations and optionally fix them."""
import asyncio
import json
import sys
sys.path.insert(0, ".")

from services.postgres_db import postgres_db, set_platform_admin_mode

STUCK_IDS = ["INV-EF55DD9D", "INV-9C4B0664"]

async def check():
    await postgres_db.connect()
    set_platform_admin_mode(True)
    async with postgres_db.tenant_acquire() as conn:
        # Check each stuck investigation
        for inv_id in STUCK_IDS:
            row = await conn.fetchrow(
                "SELECT investigation_id, state, investigation_data FROM investigations WHERE investigation_id = $1",
                inv_id,
            )
            if not row:
                print(f"{inv_id}: NOT FOUND")
                continue

            data = row["investigation_data"] or {}
            if isinstance(data, str):
                data = json.loads(data)

            print(f"\n{inv_id}:")
            print(f"  state          = {row['state']}")
            print(f"  riggs_status   = {data.get('riggs_status')}")
            print(f"  riggs_started  = {data.get('riggs_started_at')}")
            print(f"  has_analysis   = {bool(data.get('riggs_analysis'))}")
            print(f"  riggs_completed= {data.get('riggs_completed_at')}")

        # Fix: if ANALYZING and riggs already complete/failed, move to NEEDS_REVIEW
        print("\n--- Fixing stuck investigations ---")
        for inv_id in STUCK_IDS:
            row = await conn.fetchrow(
                "SELECT id, investigation_id, state, investigation_data FROM investigations WHERE investigation_id = $1",
                inv_id,
            )
            if not row:
                continue

            data = row["investigation_data"] or {}
            if isinstance(data, str):
                data = json.loads(data)

            riggs_status = data.get("riggs_status", "")
            has_analysis = bool(data.get("riggs_analysis"))

            if row["state"] == "ANALYZING":
                if has_analysis or riggs_status in ("COMPLETE", "FAILED"):
                    await conn.execute(
                        "UPDATE investigations SET state = 'NEEDS_REVIEW' WHERE investigation_id = $1",
                        inv_id,
                    )
                    print(f"  {inv_id}: ANALYZING -> NEEDS_REVIEW (riggs_status={riggs_status}, has_analysis={has_analysis})")
                elif riggs_status == "RUNNING":
                    data["riggs_status"] = "TIMEOUT"
                    data["riggs_timeout_at"] = "manual_cleanup"
                    await conn.execute(
                        "UPDATE investigations SET investigation_data = $2, state = 'NEEDS_REVIEW' WHERE investigation_id = $1",
                        inv_id,
                        json.dumps(data),
                    )
                    print(f"  {inv_id}: ANALYZING+RUNNING -> NEEDS_REVIEW (reset riggs_status to TIMEOUT)")
                else:
                    print(f"  {inv_id}: ANALYZING but riggs_status={riggs_status} — leaving as-is")
            else:
                print(f"  {inv_id}: state={row['state']} — not ANALYZING, no fix needed")

        # Also check all ANALYZING investigations for staleness
        stale = await conn.fetch("""
            SELECT investigation_id, state, investigation_data,
                   EXTRACT(EPOCH FROM (NOW() - updated_at)) / 60 as minutes_stale
            FROM investigations
            WHERE state = 'ANALYZING'
            ORDER BY updated_at ASC
        """)
        print(f"\nAll ANALYZING investigations: {len(stale)}")
        for s in stale:
            data = s["investigation_data"] or {}
            if isinstance(data, str):
                data = json.loads(data)
            print(f"  {s['investigation_id']}: {s['minutes_stale']:.0f}m stale, riggs={data.get('riggs_status')}, has_analysis={bool(data.get('riggs_analysis'))}")

asyncio.run(check())
