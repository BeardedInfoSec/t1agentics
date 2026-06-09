"""Backfill schema_migrations so already-satisfied migrations stop retrying.

On a fresh install the base schema (backend/init-db.sql) already creates the
current schema. The numbered migrations under backend/migrations/ are historical
and therefore conflict with that base ("already exists", "column ... does not
exist"), so the runner re-attempts and warns about them on every connect --
noise that makes a healthy install look broken.

This marks every shipped migration file as applied (idempotent). The runner then
skips them. New migrations added in later releases are not present at install
time on an upgraded host, so they still run normally on upgrade.

Safe to run repeatedly. Intended to run once during install, right after the
backend is healthy (so its first-connect run has finished) and before the
bootstrap-admin step (so that step's connect is quiet).
"""
import asyncio
import pathlib
import sys

BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from services.postgres_db import postgres_db, set_platform_admin_mode  # noqa: E402

MIGRATIONS_DIR = BACKEND_DIR / "migrations"


async def fix():
    await postgres_db.connect()
    set_platform_admin_mode(True)

    names = sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql"))
    if not names:
        print("No migration files found; nothing to backfill.")
        return

    marked = 0
    async with postgres_db.tenant_acquire() as conn:
        for name in names:
            result = await conn.execute(
                "INSERT INTO schema_migrations (migration_name) VALUES ($1) "
                "ON CONFLICT DO NOTHING",
                name,
            )
            # asyncpg returns e.g. "INSERT 0 1" on insert, "INSERT 0 0" on conflict.
            if result.endswith(" 1"):
                marked += 1
        total = await conn.fetchval("SELECT COUNT(*) FROM schema_migrations")

    print(f"Backfilled {marked} migration(s); {total} recorded of {len(names)} shipped.")


if __name__ == "__main__":
    asyncio.run(fix())
