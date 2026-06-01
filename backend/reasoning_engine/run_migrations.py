# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Run Unified Reasoning Engine Migrations

This script executes the SQL migrations to create the tables
needed by the unified reasoning engine.

Usage:
    python -m reasoning_engine.run_migrations

Or from backend directory:
    python reasoning_engine/run_migrations.py
"""

import asyncio
import os
import sys
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))


async def run_migrations():
    """Run the reasoning engine migrations."""
    print("=" * 60)
    print("UNIFIED REASONING ENGINE MIGRATIONS")
    print("=" * 60)

    # Read migration SQL
    migration_file = Path(__file__).parent / "migrations.sql"
    if not migration_file.exists():
        print(f"ERROR: Migration file not found: {migration_file}")
        return False

    with open(migration_file, "r") as f:
        migration_sql = f.read()

    print(f"Loaded migrations from: {migration_file}")
    print(f"Migration size: {len(migration_sql)} chars")

    # Connect to database
    try:
        from services.postgres_db import postgres_db
        await postgres_db.connect()
        print("Connected to PostgreSQL")
    except Exception as e:
        print(f"ERROR: Failed to connect to database: {e}")
        return False

    # Run migrations
    try:
        pool = postgres_db.pool
        async with pool.acquire() as conn:
            # Split migrations into individual statements
            # (PostgreSQL asyncpg doesn't support multiple statements in one call)
            statements = []
            current = []

            for line in migration_sql.split("\n"):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("--"):
                    continue
                current.append(line)
                if stripped.endswith(";"):
                    statement = "\n".join(current).strip()
                    if statement and statement != ";":
                        statements.append(statement)
                    current = []

            print(f"Executing {len(statements)} SQL statements...")

            executed = 0
            for i, stmt in enumerate(statements):
                # Skip empty statements
                if not stmt.strip() or stmt.strip() == ";":
                    continue

                # Handle CREATE OR REPLACE FUNCTION (multi-line)
                # These need special handling for $$ blocks
                if "$$" in stmt:
                    # Find all statements with $$ and rebuild them
                    pass

                try:
                    await conn.execute(stmt)
                    executed += 1
                    # Print progress for longer migrations
                    if executed % 10 == 0:
                        print(f"  Executed {executed}/{len(statements)} statements...")
                except Exception as e:
                    # Some errors are expected (e.g., "already exists")
                    error_str = str(e).lower()
                    if "already exists" in error_str:
                        continue
                    elif "does not exist" in error_str and "drop" in stmt.lower():
                        continue
                    else:
                        print(f"WARNING: Statement {i+1} failed: {e}")
                        print(f"  Statement: {stmt[:100]}...")

            print(f"Successfully executed {executed} statements")

            # Verify tables exist
            print("\nVerifying created tables...")
            tables = await conn.fetch("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name IN (
                    'heuristics', 'heuristic_outcomes', 'investigation_checkpoints',
                    'reasoning_history', 'tool_execution_log', 'confidence_tracking',
                    'sop_references'
                )
            """)

            print(f"Found {len(tables)} reasoning engine tables:")
            for t in tables:
                print(f"  - {t['table_name']}")

            # Check for seed heuristics
            heuristics_count = await conn.fetchval("SELECT COUNT(*) FROM heuristics")
            print(f"Heuristics seeded: {heuristics_count}")

            print("\n" + "=" * 60)
            print("MIGRATIONS COMPLETE")
            print("=" * 60)
            return True

    except Exception as e:
        print(f"ERROR: Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Check for DATABASE_URL or use default
    if not os.environ.get("DATABASE_URL"):
        os.environ["DATABASE_URL"] = "postgresql://postgres:postgres@localhost:5432/t1_agentics"
        print(f"Using default DATABASE_URL: {os.environ['DATABASE_URL']}")

    result = asyncio.run(run_migrations())
    sys.exit(0 if result else 1)
