#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Verification Script for Integration Loading

Tests that the new JSON-based integration loader works correctly
and integrations are properly registered in the registry.
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.integration_loader import load_prebuilt_integrations_from_json
from integrations.registry.integration_registry import get_registry


def verify_integration_loading():
    """Verify that integrations load correctly."""
    print("="*60)
    print("Integration Loading Verification")
    print("="*60)

    # Load integrations from JSON
    print("\n[1] Loading integrations from JSON files...")
    count = load_prebuilt_integrations_from_json("integration-store-output/integrations")

    if count == 0:
        print("[ERROR] No integrations loaded!")
        return False

    # Get registry
    registry = get_registry()

    # Verify integrations in registry
    print(f"\n[2] Verifying registry...")
    all_integrations = registry.list()
    print(f"  Total integrations in registry: {len(all_integrations)}")

    # Test specific integrations we migrated
    test_integrations = [
        "virustotal",
        "abuseipdb",
        "shodan",
        "crowdstrike",
        "splunk",
        "jira"
    ]

    print(f"\n[3] Testing specific integrations...")
    for integration_id in test_integrations:
        integration = registry.get(integration_id)
        if integration:
            print(f"  [OK] {integration_id}: {integration.name} ({len(integration.actions)} actions)")
        else:
            print(f"  [FAIL] {integration_id} not found in registry!")
            return False

    # Verify integration details
    print(f"\n[4] Verifying integration details...")
    virustotal = registry.get("virustotal")
    if virustotal:
        print(f"  VirusTotal:")
        print(f"    - Type: {virustotal.type}")
        print(f"    - Auth Type: {virustotal.auth_type}")
        print(f"    - Base URL: {virustotal.base_url}")
        print(f"    - Actions: {len(virustotal.actions)}")
        for action in virustotal.actions:
            print(f"      * {action.id}: {action.name} ({action.http_method} {action.endpoint})")

    print(f"\n{'='*60}")
    print(f"[SUCCESS] All verifications passed!")
    print(f"{'='*60}\n")
    return True


if __name__ == "__main__":
    success = verify_integration_loading()
    sys.exit(0 if success else 1)
