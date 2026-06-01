#!/usr/bin/env python3
# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Backfill embeddings for existing knowledge_base rows.

Run inside the backend container after migration 064 has applied and
OPENAI_API_KEY is set in the environment:

    docker exec -it t1agentics-backend \\
        python scripts/backfill_kb_embeddings.py [--limit N] [--batch 25]

Re-running is safe; rows that already have an embedding are skipped.
"""

import argparse
import asyncio
import logging
import os
import sys

# Allow running as `python scripts/backfill_kb_embeddings.py` from /app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("backfill_kb_embeddings")


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None,
                        help="Max rows to backfill (default: all)")
    parser.add_argument("--batch", type=int, default=25,
                        help="Rows per batch progress log")
    parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        help=(
            "When set, run embeddings under this tenant's BYO config "
            "(tenant_ai_config) instead of the platform OPENAI_API_KEY. "
            "Also scopes the backfill to that tenant's rows only."
        ),
    )
    args = parser.parse_args()

    if not args.tenant_id and not os.getenv("OPENAI_API_KEY"):
        # Without a tenant-id we'd fall back to platform OpenAI; without
        # that key the service's local fallback returns 384-dim vectors
        # which won't fit VECTOR(1536). Bail loudly so the operator picks
        # a path explicitly.
        logger.error("OPENAI_API_KEY not set and no --tenant-id provided; "
                     "refusing to run (local fallback would mismatch column width).")
        return 2

    from services.postgres_db import postgres_db
    from services.knowledge_base_service import KnowledgeBaseService

    # When running under a tenant's BYO config, set the RLS context so
    # the SELECT below sees that tenant's rows and the resolver finds
    # the right tenant_ai_config row.
    if args.tenant_id:
        from middleware.tenant_middleware import current_tenant_id
        current_tenant_id.set(args.tenant_id)
        logger.info(f"Running backfill scoped to tenant {args.tenant_id}")

    await postgres_db.connect()
    try:
        async with postgres_db.tenant_acquire() as conn:
            sql = """
                SELECT kb_id, title, content
                  FROM knowledge_base
                 WHERE is_active = TRUE
                   AND embedding IS NULL
                 ORDER BY created_at NULLS LAST
            """
            if args.limit:
                sql += f" LIMIT {int(args.limit)}"
            rows = await conn.fetch(sql)

        if not rows:
            logger.info("No rows need backfill — done.")
            return 0

        logger.info(f"Backfilling {len(rows)} knowledge_base row(s).")
        kb = KnowledgeBaseService()
        ok = 0
        fail = 0

        for i, row in enumerate(rows, 1):
            text = f"{row['title']}\n\n{row['content'] or ''}"[:8000]
            try:
                emb = await kb._generate_embedding(text)
            except Exception as e:
                logger.warning(f"  {row['kb_id']}: embedding error: {e}")
                emb = None

            if not emb:
                fail += 1
                continue

            try:
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute(
                        "UPDATE knowledge_base SET embedding = $1::vector "
                        "WHERE kb_id = $2",
                        str(emb), row["kb_id"],
                    )
                ok += 1
            except Exception as e:
                logger.warning(f"  {row['kb_id']}: write error: {e}")
                fail += 1

            if i % args.batch == 0:
                logger.info(f"  progress: {i}/{len(rows)} (ok={ok} fail={fail})")

        logger.info(f"Backfill complete: ok={ok}, failed={fail}")
        return 0 if fail == 0 else 1
    finally:
        await postgres_db.disconnect()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
