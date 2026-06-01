#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Migration Tool
Converts integrations from prebuilt.py to JSON format in integration-store-output/

Usage:
    python migrate_integrations.py --dry-run  # Preview migration
    python migrate_integrations.py            # Run migration
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path to import integration models
sys.path.insert(0, str(Path(__file__).parent.parent))

from integrations.registry.integration_registry import (
    Integration,
    ActionSchema,
    IntegrationType,
    AuthType,
    get_registry
)
from integrations.observables import ObservableType

# Import all register functions
from integrations.connectors.prebuilt import (
    register_virustotal,
    register_abuseipdb,
    register_shodan,
    register_greynoise,
    register_urlhaus,
    register_malwarebazaar,
    register_urlscan,
    register_otx,
    register_have_i_been_pwned,
    register_ipinfo,
    register_rdap_arin,
    register_rdap_verisign,
    register_hybrid_analysis,
    register_crowdstrike,
    register_microsoft_defender,
    register_sentinel_one,
    register_splunk,
    register_elastic_security,
    register_datadog,
    register_microsoft_graph_security,
    register_cisco_meraki,
    register_rapid7_insightvm,
    register_tenable,
    register_qualys,
    register_okta,
    register_jira,
    register_servicenow,
    register_slack,
    register_pagerduty,
    register_microsoft_teams
)


class IntegrationMigrator:
    """Migrates integrations from Python to JSON format."""

    # Enum mapping dictionaries
    CATEGORY_MAP = {
        IntegrationType.THREAT_INTEL: "threat_intel",
        IntegrationType.SIEM: "siem",
        IntegrationType.EDR: "edr",
        IntegrationType.TICKETING: "ticketing",
        IntegrationType.COMMUNICATION: "communication",
        IntegrationType.ENRICHMENT: "enrichment",
        IntegrationType.SANDBOX: "sandbox",
        IntegrationType.SOAR: "soar",
        IntegrationType.CASE_MANAGEMENT: "case_management",
        IntegrationType.FIREWALL: "firewall",
        IntegrationType.NETWORK: "network",
        IntegrationType.VULNERABILITY: "vulnerability",
        IntegrationType.IDENTITY: "identity",
        IntegrationType.CUSTOM: "custom"
    }

    AUTH_TYPE_MAP = {
        AuthType.API_KEY: "api_key",
        AuthType.BASIC_AUTH: "basic_auth",
        AuthType.BEARER_TOKEN: "bearer_token",
        AuthType.OAUTH2: "oauth2",
        AuthType.CUSTOM_HEADER: "custom_header",
        AuthType.NONE: "none"
    }

    VENDOR_MAP = {
        "VirusTotal": "VirusTotal",
        "AbuseIPDB": "AbuseIPDB",
        "Shodan": "Shodan",
        "GreyNoise": "GreyNoise",
        "URLhaus": "URLhaus",
        "Malware Bazaar": "MalwareBazaar",
        "URLscan": "URLscan.io",
        "OTX": "AlienVault",
        "Have I Been Pwned": "Have I Been Pwned",
        "IPinfo": "IPinfo",
        "RDAP ARIN": "ARIN",
        "RDAP Verisign": "Verisign",
        "Hybrid Analysis": "CrowdStrike",
        "CrowdStrike": "CrowdStrike",
        "Microsoft Defender": "Microsoft",
        "SentinelOne": "SentinelOne",
        "Splunk": "Splunk",
        "Elastic Security": "Elastic",
        "Datadog": "Datadog",
        "Microsoft Graph": "Microsoft",
        "Cisco Meraki": "Cisco",
        "Rapid7": "Rapid7",
        "Tenable": "Tenable",
        "Qualys": "Qualys",
        "Okta": "Okta",
        "Jira": "Atlassian",
        "ServiceNow": "ServiceNow",
        "Slack": "Slack",
        "PagerDuty": "PagerDuty",
        "Microsoft Teams": "Microsoft"
    }

    def __init__(self, output_dir: str = "integration-store-output/integrations"):
        self.output_dir = Path(output_dir)
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "errors": []
        }

    def extract_vendor(self, name: str) -> str:
        """Extract vendor from integration name."""
        for key, vendor in self.VENDOR_MAP.items():
            if key.lower() in name.lower():
                return vendor
        # Default to the name itself if no match
        return name.split()[0] if name else "Unknown"

    def generate_tags(self, integration: Integration) -> List[str]:
        """Generate tags for integration."""
        tags = []

        # Add category tag
        category = self.CATEGORY_MAP.get(integration.type, "other")
        tags.append(category.replace("_", "-"))

        # Add auth type tag
        auth_type = self.AUTH_TYPE_MAP.get(integration.auth_type, "unknown")
        tags.append(f"auth-{auth_type}")

        # Add vendor tag
        vendor = self.extract_vendor(integration.name)
        tags.append(vendor.lower().replace(" ", "-"))

        return tags

    def convert_auth_config(self, auth_type: AuthType, auth_config: Dict) -> Dict:
        """Convert auth config from Python format to JSON format."""
        if auth_type == AuthType.API_KEY:
            return {
                "type": "api_key",
                "header_name": auth_config.get("key_name", "X-API-Key"),
                "location": auth_config.get("key_location", "header")
            }
        elif auth_type == AuthType.BEARER_TOKEN:
            return {
                "type": "bearer_token",
                "header_name": "Authorization",
                "location": "header"
            }
        elif auth_type == AuthType.BASIC_AUTH:
            return {
                "type": "basic_auth",
                "username_field": auth_config.get("username_field", "username"),
                "password_field": auth_config.get("password_field", "password")
            }
        elif auth_type == AuthType.OAUTH2:
            return {
                "type": "oauth2",
                **auth_config  # Pass through OAuth2 config as-is
            }
        elif auth_type == AuthType.CUSTOM_HEADER:
            return {
                "type": "custom_header",
                **auth_config  # Pass through custom header config
            }
        elif auth_type == AuthType.NONE:
            return {"type": "none"}
        else:
            return {"type": "unknown"}

    def convert_integration(self, integration: Integration) -> Dict:
        """Convert Python Integration object to JSON format."""

        # Convert actions
        actions = []
        for action in integration.actions:
            json_action = {
                "id": action.id,
                "name": action.name,
                "http_method": action.http_method,
                "endpoint": action.endpoint,
                "read_only": action.read_only,
                "cacheable": action.cacheable,
                "cache_ttl_days": action.cache_ttl_days
            }

            # Add optional fields
            if hasattr(action, 'description') and action.description:
                json_action["description"] = action.description

            if hasattr(action, 'action_type') and action.action_type:
                json_action["action_type"] = action.action_type

            # Add observable_type if present (single type, not list)
            if hasattr(action, 'observable_type') and action.observable_type:
                # Convert ObservableType enum to string
                if isinstance(action.observable_type, str):
                    json_action["observable_type"] = action.observable_type
                else:
                    json_action["observable_type"] = action.observable_type.value

            # Parameters are already dicts in the actual code
            if hasattr(action, 'parameters') and action.parameters:
                json_action["parameters"] = action.parameters

            actions.append(json_action)

        # Build final JSON
        return {
            "id": integration.id,
            "name": integration.name,
            "description": f"Integration with {integration.name} for security operations",
            "version": "1.0.0",
            "category": self.CATEGORY_MAP.get(integration.type, "other"),
            "vendor": self.extract_vendor(integration.name),
            "auth_type": self.AUTH_TYPE_MAP.get(integration.auth_type, "api_key"),
            "auth_config": self.convert_auth_config(integration.auth_type, integration.auth_config),
            "base_url": integration.base_url,
            "actions": actions
        }

    def create_manifest(self, integration: Integration) -> Dict:
        """Create manifest.json for integration."""
        return {
            "id": integration.id,
            "name": integration.name,
            "version": "1.0.0",
            "description": f"Integration with {integration.name} for security operations",
            "category": self.CATEGORY_MAP.get(integration.type, "other"),
            "vendor": self.extract_vendor(integration.name),
            "author": "T1 Agentics",
            "created_at": "2026-02-03",
            "updated_at": "2026-02-03",
            "changelog": [
                {
                    "version": "1.0.0",
                    "date": "2026-02-03",
                    "changes": ["Initial migration from Python format"]
                }
            ],
            "tags": self.generate_tags(integration),
            "documentation_url": "",
            "support_url": ""
        }

    def migrate_integration(self, register_func, dry_run: bool = False) -> bool:
        """Migrate a single integration."""
        try:
            # Call the register function to get Integration object
            integration = register_func()

            # Convert to JSON format
            integration_json = self.convert_integration(integration)
            manifest_json = self.create_manifest(integration)

            if not dry_run:
                # Create directory
                category = self.CATEGORY_MAP.get(integration.type, "other")
                integration_dir = self.output_dir / category / integration.id
                integration_dir.mkdir(parents=True, exist_ok=True)

                # Write files
                with open(integration_dir / "integration.json", "w") as f:
                    json.dump(integration_json, f, indent=2)

                with open(integration_dir / "manifest.json", "w") as f:
                    json.dump(manifest_json, f, indent=2)

                print(f"[OK] Migrated {integration.name} ({len(integration.actions)} actions)")
            else:
                print(f"[DRY RUN] Would migrate {integration.name} ({len(integration.actions)} actions)")

            self.stats["success"] += 1
            return True

        except Exception as e:
            print(f"[ERROR] Failed to migrate {register_func.__name__}: {e}")
            self.stats["failed"] += 1
            self.stats["errors"].append({
                "integration": register_func.__name__,
                "error": str(e)
            })
            return False

    def migrate_all(self, dry_run: bool = False) -> bool:
        """Migrate all 30 integrations."""
        integrations = [
            register_virustotal,
            register_abuseipdb,
            register_shodan,
            register_greynoise,
            register_urlhaus,
            register_malwarebazaar,
            register_urlscan,
            register_otx,
            register_have_i_been_pwned,
            register_ipinfo,
            register_rdap_arin,
            register_rdap_verisign,
            register_hybrid_analysis,
            register_crowdstrike,
            register_microsoft_defender,
            register_sentinel_one,
            register_splunk,
            register_elastic_security,
            register_datadog,
            register_microsoft_graph_security,
            register_cisco_meraki,
            register_rapid7_insightvm,
            register_tenable,
            register_qualys,
            register_okta,
            register_jira,
            register_servicenow,
            register_slack,
            register_pagerduty,
            register_microsoft_teams
        ]

        self.stats["total"] = len(integrations)

        print(f"\n{'='*60}")
        print(f"Integration Migration Tool")
        print(f"{'='*60}")
        print(f"Mode: {'DRY RUN' if dry_run else 'LIVE MIGRATION'}")
        print(f"Total integrations: {len(integrations)}")
        print(f"Output directory: {self.output_dir}")
        print(f"{'='*60}\n")

        for register_func in integrations:
            self.migrate_integration(register_func, dry_run)

        print(f"\n{'='*60}")
        print(f"Migration Summary")
        print(f"{'='*60}")
        print(f"Total: {self.stats['total']}")
        print(f"Success: {self.stats['success']}")
        print(f"Failed: {self.stats['failed']}")

        if self.stats["errors"]:
            print(f"\nErrors:")
            for error in self.stats["errors"]:
                print(f"  - {error['integration']}: {error['error']}")

        print(f"{'='*60}\n")

        return self.stats["failed"] == 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate integrations to JSON format")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing files")
    parser.add_argument("--output", default="integration-store-output/integrations", help="Output directory")

    args = parser.parse_args()

    migrator = IntegrationMigrator(output_dir=args.output)
    success = migrator.migrate_all(dry_run=args.dry_run)

    sys.exit(0 if success else 1)
