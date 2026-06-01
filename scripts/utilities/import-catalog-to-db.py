#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Import connectors from catalog into database
Uses the backend API to properly import each connector
"""
import requests
import time

BASE_URL = "http://localhost:8000"

def import_all_connectors():
    # Get all connectors from catalog
    print("=== Fetching connectors from catalog ===")
    resp = requests.get(f"{BASE_URL}/api/v1/catalog/connectors", params={"limit": 500})
    resp.raise_for_status()

    data = resp.json()
    connectors = data.get('connectors', [])
    total = data.get('total', 0)

    print(f"Found {len(connectors)} connectors to import (total in catalog: {total})")

    # Import each connector
    imported = 0
    skipped = 0
    errors = 0

    for connector in connectors:
        connector_id = connector.get('id')
        name = connector.get('name')

        try:
            # Import via API
            import_resp = requests.post(
                f"{BASE_URL}/api/v1/catalog/connectors/import",
                json={
                    "connector_id": connector_id,
                    "enabled": False  # Disabled by default
                },
                timeout=30
            )

            if import_resp.status_code == 200:
                imported += 1
                if imported % 50 == 0:
                    print(f"  Imported {imported} connectors...")
            elif import_resp.status_code == 409:
                # Already exists
                skipped += 1
            else:
                errors += 1
                if errors <= 5:
                    print(f"  Error importing {connector_id}: {import_resp.status_code} - {import_resp.text[:100]}")

        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Exception importing {connector_id}: {e}")

        # Small delay to avoid overwhelming the backend
        time.sleep(0.05)

    print(f"\n✅ Import complete!")
    print(f"  - Imported: {imported}")
    print(f"  - Skipped (already exists): {skipped}")
    print(f"  - Errors: {errors}")
    print(f"  - Total in catalog: {total}")

if __name__ == "__main__":
    import_all_connectors()
