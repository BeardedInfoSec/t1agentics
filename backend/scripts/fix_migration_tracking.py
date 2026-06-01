"""Mark already-applied migrations in schema_migrations so they stop retrying."""
import asyncio
from services.postgres_db import postgres_db, set_platform_admin_mode

UNRECORDED = [
    "001_hypothesis_correlation.sql",
    "001_riggs_schema.sql",
    "002_multitenancy.sql",
    "002_riggs_review_state.sql",
    "004_playbooks.sql",
    "010_playbook_lists_functions.sql",
    "011_hypothesis_correlation.sql",
    "012_multitenancy.sql",
    "015_playbook_versions.sql",
    "036_fix_migration_ordering.sql",
    "add_log_tables.sql",
    "add_sample_collectors.sql",
    "add_two_track_triage.sql",
    "rls_hardening.sql",
]

async def fix():
    await postgres_db.connect()
    set_platform_admin_mode(True)
    async with postgres_db.tenant_acquire() as conn:
        for name in UNRECORDED:
            await conn.execute(
                "INSERT INTO schema_migrations (migration_name) VALUES ($1) ON CONFLICT DO NOTHING",
                name,
            )
            print(f"Marked as applied: {name}")

        total = await conn.fetchval("SELECT COUNT(*) FROM schema_migrations")
        print(f"\nTotal recorded migrations: {total}")

asyncio.run(fix())
