#!/usr/bin/env python3
# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
"""Load KB articles directly into database (no API dependency)."""
import os
import sys
import json
import glob
import uuid
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


async def load_kb(content_dir, db_url):
    import asyncpg

    pattern = os.path.join(content_dir, "**", "*.json")
    files = sorted(glob.glob(pattern, recursive=True))
    if not files:
        logger.error(f"No JSON files found in {content_dir}")
        return

    logger.info(f"Found {len(files)} KB articles to load")
    pool = await asyncpg.create_pool(db_url, min_size=1, max_size=5)
    success = 0
    skipped = 0
    failed = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"  SKIP (bad JSON): {filepath}: {e}")
            failed += 1
            continue

        title = data.get("title", "Untitled")
        cat = data.get("category", "general")
        kb_id = f"KB-{uuid.uuid4().hex[:8].upper()}"

        try:
            async with pool.acquire() as conn:
                existing = await conn.fetchrow(
                    "SELECT kb_id FROM knowledge_base WHERE title = $1", title
                )
                if existing:
                    logger.info(f"  SKIP (exists): {title}")
                    skipped += 1
                    continue

                await conn.execute(
                    """
                    INSERT INTO knowledge_base (
                        kb_id, title, content, content_type,
                        category, subcategory, tags, severity_filter,
                        incident_types, ioc_types, mitre_techniques,
                        compliance_frameworks, priority, created_by,
                        is_active, ai_processed, source,
                        approved_by, approved_at
                    ) VALUES (
                        $1, $2, $3, $4,
                        $5, $6, $7, $8,
                        $9, $10, $11,
                        $12, $13, $14,
                        $15, $16, 'builtin',
                        'system', NOW()
                    )
                    """,
                    kb_id,
                    title,
                    data.get("content", ""),
                    data.get("content_type", "sop"),
                    cat,
                    data.get("subcategory"),
                    data.get("tags", []),
                    data.get("severity_filter", []),
                    data.get("incident_types", []),
                    data.get("ioc_types", []),
                    data.get("mitre_techniques", []),
                    data.get("compliance_frameworks", []),
                    data.get("priority", 50),
                    "admin",
                    True,
                    False,
                )
            logger.info(f"  OK: [{cat}] {title}")
            success += 1
        except Exception as e:
            logger.error(f"  FAIL: {title} - {e}")
            failed += 1

    await pool.close()
    logger.info(f"\nDone! Loaded: {success}, Skipped: {skipped}, Failed: {failed}")


if __name__ == "__main__":
    content_dir = sys.argv[1] if len(sys.argv) > 1 else "/app/kb-content-output/articles"
    db_host = os.environ.get("POSTGRES_HOST", "postgres")
    db_port = os.environ.get("POSTGRES_PORT", "5432")
    db_user = os.environ.get("POSTGRES_USER", "agentcore")
    db_pass = os.environ.get("POSTGRES_PASSWORD", "")
    db_name = os.environ.get("POSTGRES_DB", "agentcore")
    db_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    asyncio.run(load_kb(content_dir, db_url))
