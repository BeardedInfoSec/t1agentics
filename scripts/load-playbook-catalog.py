#!/usr/bin/env python3
# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
"""
Load playbook templates from playbook-store-output/ into playbook_templates table.

This script directly inserts into the database (no API dependency).
Run inside the backend container or with POSTGRES_* env vars set.

Usage:
    python scripts/load-playbook-catalog.py [--dir playbook-store-output/playbooks]

Or use the service auto-loader (preferred for production):
    The PlaybookCatalogService.load_builtin_catalog() is called on backend startup.
"""

import os
import sys
import json
import glob
import uuid
import asyncio
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


async def load_catalog(content_dir: str, db_url: str, dry_run: bool = False):
    """Load playbook templates from disk into database."""
    import asyncpg

    # Scan for JSON files
    pattern = os.path.join(content_dir, "**", "*.json")
    files = sorted(glob.glob(pattern, recursive=True))

    if not files:
        logger.error(f"No JSON files found in {content_dir}")
        return

    logger.info(f"Found {len(files)} playbook templates to load")

    if dry_run:
        for f in files:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            logger.info(f"  DRY: {data.get('name', 'Untitled')} [{data.get('category', 'general')}]")
        logger.info(f"\nDry run complete. {len(files)} templates would be loaded.")
        return

    # Connect to database
    pool = await asyncpg.create_pool(db_url, min_size=1, max_size=5)

    success = 0
    failed = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"  SKIP (bad JSON): {filepath}: {e}")
            failed += 1
            continue

        slug = data.get("slug") or os.path.splitext(os.path.basename(filepath))[0]
        name = data.get("name")
        if not name:
            logger.warning(f"  SKIP (no name): {filepath}")
            failed += 1
            continue

        canvas_data = data.get("canvas_data", {"nodes": [], "edges": []})
        tags = data.get("tags", [])
        alert_types = data.get("alert_types", [])
        severity_filter = data.get("severity_filter", [])
        required_integrations = data.get("required_integrations", [])

        try:
            async with pool.acquire() as conn:
                # Need platform admin to bypass RLS
                await conn.execute("SET app.is_platform_admin = 'true'")
                await conn.execute(
                    """
                    INSERT INTO playbook_templates (
                        name, slug, description, category, subcategory,
                        canvas_data, trigger_conditions, tags, alert_types,
                        severity_filter, required_integrations,
                        difficulty, estimated_time, author, version,
                        source, tenant_id,
                        created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5,
                        $6::jsonb, $7::jsonb, $8, $9,
                        $10, $11::jsonb,
                        $12, $13, $14, $15,
                        'builtin', NULL,
                        NOW(), NOW()
                    )
                    ON CONFLICT (slug) WHERE tenant_id IS NULL
                    DO UPDATE SET
                        name                 = EXCLUDED.name,
                        description          = EXCLUDED.description,
                        category             = EXCLUDED.category,
                        subcategory          = EXCLUDED.subcategory,
                        canvas_data          = EXCLUDED.canvas_data,
                        trigger_conditions   = EXCLUDED.trigger_conditions,
                        tags                 = EXCLUDED.tags,
                        alert_types          = EXCLUDED.alert_types,
                        severity_filter      = EXCLUDED.severity_filter,
                        required_integrations = EXCLUDED.required_integrations,
                        difficulty           = EXCLUDED.difficulty,
                        estimated_time       = EXCLUDED.estimated_time,
                        author               = EXCLUDED.author,
                        version              = EXCLUDED.version,
                        updated_at           = NOW()
                    """,
                    name,
                    slug,
                    data.get("description", ""),
                    data.get("category", "general"),
                    data.get("subcategory"),
                    json.dumps(canvas_data),
                    json.dumps(data.get("trigger_conditions", {})),
                    tags,
                    alert_types,
                    severity_filter,
                    json.dumps(required_integrations),
                    data.get("difficulty", "intermediate"),
                    data.get("estimated_time"),
                    data.get("author", "T1 Agentics"),
                    data.get("version", "1.0.0"),
                )
            logger.info(f"  OK: [{data.get('category', 'general')}] {name}")
            success += 1
        except Exception as e:
            logger.error(f"  FAIL: {name} — {e}")
            failed += 1

    await pool.close()
    logger.info(f"\nDone! Loaded: {success}, Failed: {failed}")


def main():
    parser = argparse.ArgumentParser(description="Load playbook templates into database")
    parser.add_argument("--dir", default=None,
                        help="Override playbook content directory")
    parser.add_argument("--db-url", default=None,
                        help="PostgreSQL connection URL (or set DATABASE_URL env var)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be loaded")
    args = parser.parse_args()

    # Find content directory
    if args.dir:
        content_dir = args.dir
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        content_dir = os.path.join(project_root, "playbook-store-output", "playbooks")

    if not os.path.isdir(content_dir):
        logger.error(f"Content directory not found: {content_dir}")
        sys.exit(1)

    # Database URL
    db_url = args.db_url or os.environ.get("DATABASE_URL")
    if not db_url and not args.dry_run:
        # Try to build from individual env vars
        host = os.environ.get("POSTGRES_HOST", "localhost")
        port = os.environ.get("POSTGRES_PORT", "5432")
        user = os.environ.get("POSTGRES_USER", "agentcore")
        password = os.environ.get("POSTGRES_PASSWORD", "")
        db = os.environ.get("POSTGRES_DB", "agentcore")
        db_url = f"postgresql://{user}:{password}@{host}:{port}/{db}"

    if not db_url and not args.dry_run:
        logger.error("No database URL. Set --db-url or DATABASE_URL env var.")
        sys.exit(1)

    asyncio.run(load_catalog(content_dir, db_url, args.dry_run))


if __name__ == "__main__":
    main()
