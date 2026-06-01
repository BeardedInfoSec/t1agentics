#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Migration Test Suite
Tests migrated integrations to ensure they have valid JSON format.

Usage:
    python test_migrated_integrations.py                    # Test all integrations
    python test_migrated_integrations.py --integration virustotal  # Test specific integration
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional


class MigrationTester:
    """Test migrated integrations."""

    def __init__(self):
        self.results = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": []
        }

    def test_integration(self, json_path: Path) -> bool:
        """Test a single integration."""
        integration_name = json_path.parent.name
        print(f"\nTesting: {integration_name}")

        try:
            # 1. Load and validate JSON syntax
            with open(json_path) as f:
                integration_data = json.load(f)

            print(f"  [OK] JSON syntax valid")

            # 2. Validate required fields
            required_fields = ['id', 'name', 'category', 'vendor', 'auth_type', 'auth_config', 'base_url', 'actions']
            for field in required_fields:
                if field not in integration_data:
                    print(f"  [ERROR] Missing required field: {field}")
                    self.results["failed"] += 1
                    self.results["errors"].append({
                        "integration": integration_name,
                        "error": f"Missing field: {field}"
                    })
                    return False

            print(f"  [OK] All required fields present")

            # 3. Validate actions
            actions = integration_data.get('actions', [])
            if not actions:
                print(f"  [WARN] No actions defined")

            action_ids = set()
            for i, action in enumerate(actions):
                # Check required action fields
                action_required_fields = ['id', 'name', 'http_method', 'endpoint', 'read_only', 'cacheable', 'cache_ttl_days']
                for field in action_required_fields:
                    if field not in action:
                        print(f"  [ERROR] Action {i} missing field: {field}")
                        self.results["failed"] += 1
                        self.results["errors"].append({
                            "integration": integration_name,
                            "error": f"Action {i} missing field: {field}"
                        })
                        return False

                # Check for duplicate action IDs
                action_id = action['id']
                if action_id in action_ids:
                    print(f"  [ERROR] Duplicate action ID: {action_id}")
                    self.results["failed"] += 1
                    self.results["errors"].append({
                        "integration": integration_name,
                        "error": f"Duplicate action ID: {action_id}"
                    })
                    return False
                action_ids.add(action_id)

            print(f"  [OK] All {len(actions)} actions valid")

            # 4. Load and validate manifest.json
            manifest_path = json_path.parent / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest_data = json.load(f)
                print(f"  [OK] Manifest valid")
            else:
                print(f"  [WARN] No manifest.json found")

            self.results["passed"] += 1
            return True

        except json.JSONDecodeError as e:
            print(f"  [ERROR] Invalid JSON: {e}")
            self.results["failed"] += 1
            self.results["errors"].append({
                "integration": integration_name,
                "error": f"Invalid JSON: {e}"
            })
            return False

        except Exception as e:
            print(f"  [ERROR] Exception: {e}")
            self.results["failed"] += 1
            self.results["errors"].append({
                "integration": integration_name,
                "error": str(e)
            })
            return False

    def test_all(self, integrations_dir: Path, specific_integration: Optional[str] = None) -> bool:
        """Test all migrated integrations."""
        print(f"\n{'='*60}")
        print(f"Integration Migration Test Suite")
        print(f"{'='*60}")

        # Find all integration.json files
        if specific_integration:
            integration_files = list(integrations_dir.glob(f"*/{specific_integration}/integration.json"))
            if not integration_files:
                print(f"[ERROR] Integration '{specific_integration}' not found")
                return False
        else:
            integration_files = list(integrations_dir.glob("*/*/integration.json"))

        self.results["total"] = len(integration_files)

        print(f"Found {len(integration_files)} integration(s) to test")
        print(f"{'='*60}")

        for json_file in sorted(integration_files):
            self.test_integration(json_file)

        print(f"\n{'='*60}")
        print(f"Test Summary")
        print(f"{'='*60}")
        print(f"Total: {self.results['total']}")
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")

        if self.results["errors"]:
            print(f"\nErrors:")
            for error in self.results["errors"]:
                print(f"  - {error['integration']}: {error['error']}")

        print(f"{'='*60}\n")

        return self.results["failed"] == 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test migrated integrations")
    parser.add_argument("--dir", default="integration-store-output/integrations",
                       help="Integrations directory")
    parser.add_argument("--integration", help="Test specific integration by ID")

    args = parser.parse_args()

    tester = MigrationTester()
    success = tester.test_all(Path(args.dir), args.integration)

    sys.exit(0 if success else 1)
