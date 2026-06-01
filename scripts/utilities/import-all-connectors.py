#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Import all connectors from catalog to integrations table
"""
import asyncio
import sys

async def import_all_connectors():
    sys.path.insert(0, '/app')

    from services.connector_catalog import get_connector_catalog
    from services.postgres_db import postgres_db

    catalog = get_connector_catalog()
    connectors = catalog.get_all_connectors()

    print("=== Importing All Connectors ===")
    print(f"Total connectors in catalog: {len(connectors)}")

    imported = 0
    skipped = 0
    errors = 0

    async with postgres_db.pool.acquire() as conn:
        for connector in connectors:
            connector_id = connector.get('id')
            try:
                # Check if already exists
                exists = await conn.fetchval(
                    "SELECT COUNT(*) FROM integrations WHERE integration_id = $1",
                    connector_id
                )

                if exists:
                    skipped += 1
                    continue

                # Import connector
                await conn.execute("""
                    INSERT INTO integrations (
                        integration_id, name, category, description,
                        capabilities, auth_type, enabled, config
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                    connector_id,
                    connector.get('name', connector_id),
                    connector.get('category', 'other'),
                    connector.get('description', ''),
                    connector.get('capabilities', []),
                    connector.get('auth_type', 'none'),
                    False,  # Disabled by default
                    connector.get('config_schema', {})
                )

                imported += 1
                if imported % 50 == 0:
                    print(f"Imported {imported} connectors...")

            except Exception as e:
                errors += 1
                if errors <= 5:  # Only show first 5 errors
                    print(f"Error importing {connector_id}: {e}")

    print(f"\n✅ Import complete!")
    print(f"  - Imported: {imported}")
    print(f"  - Skipped (already exists): {skipped}")
    print(f"  - Errors: {errors}")
    print(f"  - Total in catalog: {len(connectors)}")

if __name__ == "__main__":
    asyncio.run(import_all_connectors())
