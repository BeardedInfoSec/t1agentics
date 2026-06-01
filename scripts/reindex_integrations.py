#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Reindex Integration Store

Scans the integration-store-output directory and regenerates:
- index.json (master catalog)
- version.json (repo version)
- README.md (updated stats)
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


def reindex(store_dir: str) -> Dict[str, Any]:
    """Reindex all integrations in the store directory."""
    store_path = Path(store_dir)
    integrations_path = store_path / 'integrations'

    integrations = []
    categories = {}

    # Scan all category directories
    for category_dir in integrations_path.iterdir():
        if not category_dir.is_dir():
            continue

        category = category_dir.name

        # Scan all integration directories in this category
        for integration_dir in category_dir.iterdir():
            if not integration_dir.is_dir():
                continue

            # Check for integration.json
            integration_file = integration_dir / 'integration.json'
            manifest_file = integration_dir / 'manifest.json'

            if integration_file.exists():
                try:
                    with open(integration_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    integration_id = data.get('id', integration_dir.name)
                    name = data.get('name', integration_id)

                    integrations.append({
                        'id': integration_id,
                        'name': name,
                        'category': category,
                        'path': f"integrations/{category}/{integration_dir.name}"
                    })

                    # Count categories
                    categories[category] = categories.get(category, 0) + 1

                except Exception as e:
                    print(f"Error reading {integration_file}: {e}")

    # Sort integrations by name
    integrations.sort(key=lambda x: x['name'])

    # Build index
    index = {
        'version': '1.0.1',
        'last_updated': datetime.utcnow().isoformat(),
        'total_integrations': len(integrations),
        'categories': [
            {'id': cat, 'name': cat.replace('_', ' ').title(), 'count': count}
            for cat, count in sorted(categories.items())
        ],
        'integrations': integrations
    }

    # Save index.json
    index_file = store_path / 'index.json'
    with open(index_file, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)
    print(f"Saved index.json with {len(integrations)} integrations")

    # Save version.json
    version_file = store_path / 'version.json'
    with open(version_file, 'w', encoding='utf-8') as f:
        json.dump({
            'version': '1.0.1',
            'build_date': datetime.utcnow().isoformat(),
            'integrations_count': len(integrations)
        }, f, indent=2)
    print(f"Saved version.json")

    # Generate README
    readme_content = generate_readme(len(integrations), categories)
    readme_file = store_path / 'README.md'
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print(f"Saved README.md")

    return {
        'total': len(integrations),
        'categories': categories
    }


def generate_readme(total: int, categories: Dict[str, int]) -> str:
    """Generate README.md content."""

    # Sort categories by count descending
    sorted_cats = sorted(categories.items(), key=lambda x: -x[1])

    cat_table = "\n".join([
        f"| {cat.replace('_', ' ').title()} | {count} |"
        for cat, count in sorted_cats
    ])

    return f"""# AgentCore Integration Store

Pre-built integration definitions for AgentCore. Browse, install, and update integrations without writing code.

## Quick Stats

- **Total Integrations**: {total}
- **Categories**: {len(categories)}
- **Last Updated**: {datetime.utcnow().strftime('%Y-%m-%d')}

## Categories

| Category | Count |
|----------|-------|
{cat_table}

## Repository Structure

```
agentcore-integrations/
├── README.md                     # This file
├── index.json                    # Master catalog of all integrations
├── version.json                  # Repository version info
└── integrations/
    ├── threat_intel/             # Threat intelligence feeds
    ├── edr/                      # Endpoint detection & response
    ├── siem/                     # Security monitoring
    ├── network/                  # Network security
    ├── sandbox/                  # Malware analysis
    ├── ticketing/                # Case management
    ├── identity/                 # Identity & access
    ├── email_security/           # Email protection
    ├── devops/                   # DevOps tools
    └── utility/                  # General utilities
```

## Integration Format

Each integration contains:

### manifest.json
```json
{{
  "id": "integration_id",
  "name": "Integration Name",
  "version": "1.0.0",
  "category": "threat_intel",
  "vendor": "Vendor Name",
  "description": "What this integration does",
  "auth_type": "api_key",
  "base_url": "https://api.example.com/v1"
}}
```

### integration.json
```json
{{
  "id": "integration_id",
  "actions": [
    {{
      "id": "action_name",
      "name": "Action Name",
      "http_method": "GET",
      "endpoint": "/endpoint/path",
      "parameters": [...]
    }}
  ]
}}
```

## How It Works

1. **Sync**: AgentCore fetches `index.json` to discover integrations
2. **Install**: User selects an integration to install
3. **Configure**: User provides API credentials
4. **Use**: Integration actions are available to AI agents

## Contributing

1. Fork this repository
2. Create integration under appropriate category
3. Add `manifest.json` and `integration.json`
4. Submit pull request

## License

Apache 2.0 License. APIs are owned by their respective vendors.
"""


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        store_dir = sys.argv[1]
    else:
        store_dir = 'integration-store-output'

    result = reindex(store_dir)
    print(f"\nReindexing complete:")
    print(f"  Total integrations: {result['total']}")
    print(f"  Categories: {len(result['categories'])}")
