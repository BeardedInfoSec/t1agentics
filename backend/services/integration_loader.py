# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Loader

Loads integration definitions from JSON files in integration-store-output/
and registers them in the in-memory IntegrationRegistry so that
threat_intel_service can discover enrichment providers dynamically.
"""

import json
import logging
import os
from pathlib import Path
from typing import List

from integrations.registry.integration_registry import (
    Integration,
    IntegrationType,
    AuthType,
    ActionSchema,
    get_registry,
)

logger = logging.getLogger(__name__)

# Categories that map to IntegrationType enum values
CATEGORY_MAP = {
    "threat_intel": IntegrationType.THREAT_INTEL,
    "enrichment": IntegrationType.ENRICHMENT,
    "sandbox": IntegrationType.SANDBOX,
    "ticketing": IntegrationType.TICKETING,
    "siem": IntegrationType.SIEM,
    "soar": IntegrationType.SOAR,
    "communication": IntegrationType.COMMUNICATION,
    "case_management": IntegrationType.CASE_MANAGEMENT,
    "edr": IntegrationType.EDR,
    "firewall": IntegrationType.FIREWALL,
    "network": IntegrationType.NETWORK,
    "vulnerability": IntegrationType.VULNERABILITY,
    "identity": IntegrationType.IDENTITY,
    "custom": IntegrationType.CUSTOM,
}

AUTH_TYPE_MAP = {
    "api_key": AuthType.API_KEY,
    "bearer_token": AuthType.BEARER_TOKEN,
    "oauth2": AuthType.OAUTH2,
    "basic_auth": AuthType.BASIC_AUTH,
    "custom_header": AuthType.CUSTOM_HEADER,
    "none": AuthType.NONE,
}

# Categories relevant to IOC enrichment (loaded into the registry)
ENRICHMENT_CATEGORIES = {"threat_intel", "enrichment", "sandbox"}


def _parse_action(action_data: dict) -> ActionSchema:
    """Parse a JSON action definition into an ActionSchema."""
    return ActionSchema(
        id=action_data.get("id", "unknown"),
        name=action_data.get("name", ""),
        description=action_data.get("description"),
        observable_type=action_data.get("observable_type"),
        http_method=action_data.get("http_method", "GET"),
        endpoint=action_data.get("endpoint", ""),
        requires_auth=action_data.get("requires_auth", True),
        read_only=action_data.get("read_only", True),
        cacheable=action_data.get("cacheable", False),
        cache_ttl_days=action_data.get("cache_ttl_days", 30),
        parameters=action_data.get("parameters", []),
        input_schema=action_data.get("input_schema", {}),
        output_schema=action_data.get("output_schema", {}),
        headers=action_data.get("headers", {}),
        query_params=action_data.get("query_params", {}),
        rate_limit_per_minute=action_data.get("rate_limit_per_minute"),
    )


def _parse_integration(data: dict) -> Integration:
    """Parse a JSON integration definition into an Integration model."""
    category = data.get("category", "custom")
    int_type = CATEGORY_MAP.get(category, IntegrationType.CUSTOM)

    auth_type_str = data.get("auth_type", "api_key")
    auth_type = AUTH_TYPE_MAP.get(auth_type_str, AuthType.API_KEY)

    # All integrations start disabled -- only enabled when user configures them
    enabled = data.get("enabled", False)

    actions = [_parse_action(a) for a in data.get("actions", [])]

    return Integration(
        id=data["id"],
        name=data.get("name", data["id"]),
        type=int_type,
        description=data.get("description"),
        version=data.get("version", "1.0.0"),
        auth_type=auth_type,
        auth_config=data.get("auth_config", {}),
        base_url=data.get("base_url", ""),
        enabled=enabled,
        actions=actions,
        vendor=data.get("vendor"),
        documentation_url=data.get("documentation_url"),
        tags=data.get("tags", []),
    )


def load_integrations_into_registry(
    base_dir: str = None,
    categories: set = None,
) -> int:
    """
    Load integration JSON definitions into the in-memory registry.

    Args:
        base_dir: Path to integration-store-output/integrations/ directory.
                  Defaults to auto-detection relative to this file.
        categories: Set of category names to load. Defaults to enrichment-
                    related categories (threat_intel, enrichment, sandbox).

    Returns:
        Number of integrations loaded.
    """
    if categories is None:
        categories = ENRICHMENT_CATEGORIES

    if base_dir is None:
        # integration-store-output/integrations/ is at backend root
        backend_dir = Path(__file__).resolve().parent.parent
        base_dir = backend_dir / "integration-store-output" / "integrations"
    else:
        base_dir = Path(base_dir)

    if not base_dir.exists():
        logger.warning(f"Integration store directory not found: {base_dir}")
        return 0

    registry = get_registry()
    loaded = 0

    for category in sorted(categories):
        category_dir = base_dir / category
        if not category_dir.exists():
            continue

        for integration_dir in sorted(category_dir.iterdir()):
            if not integration_dir.is_dir():
                continue

            integration_file = integration_dir / "integration.json"
            if not integration_file.exists():
                continue

            try:
                with open(integration_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                integration = _parse_integration(data)
                registry.register(integration)
                loaded += 1
                logger.debug(f"Loaded integration: {integration.id} ({integration.type.value})")
            except Exception as e:
                logger.warning(f"Failed to load {integration_file}: {e}")

    logger.info(f"Loaded {loaded} integrations into registry from {len(categories)} categories")
    return loaded
