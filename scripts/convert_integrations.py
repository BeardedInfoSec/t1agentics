#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Converter Script

Converts source connector files into AgentCore-compatible integration definitions.
Extracts:
- Metadata from JSON files
- Real API endpoints from Python connector files
- Authentication configuration
- Action definitions with parameters

Output: AgentCore-format JSON files ready for the Integration Store.
"""

import json
import os
import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class IntegrationConverter:
    """Converts source connector files to AgentCore format."""

    # Category mapping - normalize to AgentCore categories
    CATEGORY_MAP = {
        'reputation': 'threat_intel',
        'information': 'threat_intel',
        'investigative': 'threat_intel',
        'investigate': 'threat_intel',
        'sandbox': 'sandbox',
        'siem': 'siem',
        'endpoint': 'edr',
        'ticketing': 'ticketing',
        'ticket': 'ticketing',
        'network security': 'network',
        'firewall': 'network',
        'identity': 'identity',
        'authentication': 'identity',
        'vulnerability': 'vulnerability',
        'email': 'email_security',
        'communication': 'communication',
        'messaging': 'communication',
        'devops': 'devops',
        'generic': 'utility',
        'utilities': 'utility',
        'cloud': 'cloud_security',
    }

    # Auth type mapping
    AUTH_MAP = {
        'api_key': 'api_key',
        'apikey': 'api_key',
        'oauth': 'oauth2',
        'oauth2': 'oauth2',
        'basic': 'basic_auth',
        'basic_auth': 'basic_auth',
        'bearer': 'bearer_token',
        'token': 'bearer_token',
    }

    def __init__(self, source_dir: str, output_dir: str):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.results = {
            'success': [],
            'failed': [],
            'skipped': []
        }

    def convert_all(self) -> Dict[str, Any]:
        """Convert all connectors in the source directory."""
        print(f"Scanning {self.source_dir}...")

        # Find all connector directories
        connector_dirs = [d for d in self.source_dir.iterdir() if d.is_dir()]
        print(f"Found {len(connector_dirs)} connector directories")

        for connector_dir in connector_dirs:
            try:
                result = self.convert_connector(connector_dir)
                if result:
                    self.results['success'].append(result)
                else:
                    self.results['skipped'].append(connector_dir.name)
            except Exception as e:
                print(f"  ERROR converting {connector_dir.name}: {e}")
                self.results['failed'].append({
                    'dir': connector_dir.name,
                    'error': str(e)
                })

        # Generate index.json
        self._generate_index()

        return self.results

    def convert_connector(self, connector_dir: Path) -> Optional[Dict]:
        """Convert a single connector directory."""
        print(f"\nProcessing: {connector_dir.name}")

        # Find the main JSON file
        json_files = list(connector_dir.glob("*.json"))
        if not json_files:
            print(f"  No JSON file found, skipping")
            return None

        # Use the first JSON file (usually named after the connector)
        json_file = json_files[0]

        # Find Python connector file
        py_files = list(connector_dir.glob("*_connector.py"))
        consts_files = list(connector_dir.glob("*_consts.py"))

        # Parse JSON metadata
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                metadata = json.load(f)
            except json.JSONDecodeError as e:
                print(f"  Invalid JSON: {e}")
                return None

        # Extract basic info
        connector_id = self._normalize_id(metadata.get('name', connector_dir.name))
        name = metadata.get('name', connector_dir.name)
        description = metadata.get('description', '')
        vendor = metadata.get('product_vendor', 'Unknown')
        version = metadata.get('app_version', '1.0.0')
        category = self._normalize_category(metadata.get('type', 'generic'))

        print(f"  ID: {connector_id}")
        print(f"  Name: {name}")
        print(f"  Category: {category}")

        # Extract endpoints from Python files
        endpoints = {}
        base_url = None
        auth_header = None

        if consts_files:
            base_url, endpoints = self._extract_from_consts(consts_files[0])
            print(f"  Found {len(endpoints)} endpoints in consts file")

        if py_files:
            py_base_url, py_endpoints, py_auth = self._extract_from_connector(py_files[0])
            if py_base_url and not base_url:
                base_url = py_base_url
            if py_auth:
                auth_header = py_auth
            endpoints.update(py_endpoints)
            print(f"  Found {len(py_endpoints)} additional endpoints in connector")

        # Extract auth configuration
        auth_config = self._extract_auth_config(metadata.get('configuration', {}), auth_header)

        # Convert actions
        actions = self._convert_actions(
            metadata.get('actions', []),
            endpoints,
            base_url
        )
        print(f"  Converted {len(actions)} actions")

        # Build the integration definition
        integration = {
            'id': connector_id,
            'name': name,
            'description': description,
            'version': version,
            'category': category,
            'vendor': vendor,
            'auth_type': auth_config.get('type', 'api_key'),
            'auth_config': auth_config,
            'base_url': base_url or '',
            'actions': actions,
            'source_metadata': {
                'original_name': metadata.get('name'),
                'original_type': metadata.get('type'),
                'converted_at': datetime.utcnow().isoformat(),
                'source_version': version
            }
        }

        # Build manifest
        manifest = {
            'id': connector_id,
            'name': name,
            'version': version,
            'category': category,
            'vendor': vendor,
            'description': description,
            'auth_type': auth_config.get('type', 'api_key'),
            'base_url': base_url or '',
            'documentation_url': '',
            'requires_paid_tier': False,
            'min_agentcore_version': '1.0.0',
            'changelog': [{
                'version': version,
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'changes': ['Initial conversion from source connector']
            }]
        }

        # Save files
        self._save_integration(connector_id, category, integration, manifest)

        return {
            'id': connector_id,
            'name': name,
            'category': category,
            'actions': len(actions),
            'has_endpoints': bool(base_url)
        }

    def _normalize_id(self, name: str) -> str:
        """Normalize name to a valid ID."""
        # Remove special characters, lowercase, replace spaces with underscores
        id_str = re.sub(r'[^a-zA-Z0-9\s_-]', '', name)
        id_str = id_str.lower().replace(' ', '_').replace('-', '_')
        id_str = re.sub(r'_+', '_', id_str)  # Remove duplicate underscores
        return id_str.strip('_')

    def _normalize_category(self, category: str) -> str:
        """Normalize category to AgentCore categories."""
        category_lower = category.lower()

        for key, value in self.CATEGORY_MAP.items():
            if key in category_lower:
                return value

        return 'utility'

    def _extract_from_consts(self, consts_file: Path) -> Tuple[Optional[str], Dict[str, str]]:
        """Extract base URL and endpoints from consts file."""
        endpoints = {}
        base_url = None

        try:
            content = consts_file.read_text(encoding='utf-8')

            # Look for BASE_URL pattern
            base_url_match = re.search(
                r'(?:BASE_URL|API_URL|BASE_ENDPOINT)\s*=\s*["\']([^"\']+)["\']',
                content,
                re.IGNORECASE
            )
            if base_url_match:
                base_url = base_url_match.group(1)

            # Look for endpoint definitions
            endpoint_pattern = re.compile(
                r'(\w+(?:_ENDPOINT|_APIPATH|_API_ENDPOINT|_URL))\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE
            )

            for match in endpoint_pattern.finditer(content):
                name = match.group(1)
                path = match.group(2)
                # Normalize endpoint name
                endpoint_key = name.lower().replace('_endpoint', '').replace('_apipath', '').replace('_api_endpoint', '').replace('_url', '')
                endpoints[endpoint_key] = path

        except Exception as e:
            print(f"    Error parsing consts file: {e}")

        return base_url, endpoints

    def _extract_from_connector(self, connector_file: Path) -> Tuple[Optional[str], Dict[str, str], Optional[str]]:
        """Extract base URL, endpoints, and auth info from connector file."""
        endpoints = {}
        base_url = None
        auth_header = None

        try:
            content = connector_file.read_text(encoding='utf-8')

            # Look for base URL in initialize method or class
            base_url_patterns = [
                r'self\._base_url\s*=\s*["\']([^"\']+)["\']',
                r'base_url\s*=\s*["\']([^"\']+)["\']',
                r'BASE_URL\s*=\s*["\']([^"\']+)["\']',
            ]

            for pattern in base_url_patterns:
                match = re.search(pattern, content)
                if match:
                    base_url = match.group(1)
                    break

            # Look for auth header
            auth_patterns = [
                r'headers\[["\']([^"\']+)["\']\]\s*=\s*self\._api_key',
                r'headers\[["\']([^"\']+)["\']\]\s*=.*api_key',
                r'["\']([xX]-[aA]pi[kK]ey)["\']',
                r'["\']([aA]uthorization)["\']',
            ]

            for pattern in auth_patterns:
                match = re.search(pattern, content)
                if match:
                    auth_header = match.group(1)
                    break

            # Look for endpoint paths in _make_rest_call calls
            rest_call_pattern = re.compile(
                r'_make_rest_call\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE
            )

            for match in rest_call_pattern.finditer(content):
                path = match.group(1)
                # Generate a name from the path
                endpoint_name = path.strip('/').replace('/', '_').replace('{', '').replace('}', '')
                if endpoint_name:
                    endpoints[endpoint_name] = path

        except Exception as e:
            print(f"    Error parsing connector file: {e}")

        return base_url, endpoints, auth_header

    def _extract_auth_config(self, config: Dict, auth_header: Optional[str]) -> Dict[str, Any]:
        """Extract authentication configuration."""
        auth_config = {
            'type': 'api_key',
            'header_name': auth_header or 'Authorization',
            'location': 'header'
        }

        # Check config fields for auth type hints
        config_lower = {k.lower(): v for k, v in config.items()}

        if 'client_id' in config_lower and 'client_secret' in config_lower:
            auth_config['type'] = 'oauth2'
        elif 'username' in config_lower and 'password' in config_lower:
            auth_config['type'] = 'basic_auth'
        elif 'api_key' in config_lower or 'apikey' in config_lower:
            auth_config['type'] = 'api_key'
            # Check for specific header name
            for key, val in config.items():
                if 'key' in key.lower():
                    desc = val.get('description', '') if isinstance(val, dict) else ''
                    if 'header' in desc.lower():
                        auth_config['location'] = 'header'
                    elif 'query' in desc.lower():
                        auth_config['location'] = 'query'
        elif 'token' in config_lower:
            auth_config['type'] = 'bearer_token'

        return auth_config

    def _convert_actions(self, actions: List[Dict], endpoints: Dict[str, str], base_url: Optional[str]) -> List[Dict]:
        """Convert action definitions to AgentCore format."""
        converted = []

        for action in actions:
            action_id = action.get('identifier', action.get('action', '')).lower().replace(' ', '_')
            action_name = action.get('action', action_id)

            # Skip test connectivity actions
            if 'test' in action_id.lower() and 'connectivity' in action_id.lower():
                continue

            # Try to find matching endpoint
            endpoint = self._find_endpoint(action_id, endpoints)

            # Determine HTTP method from action type
            action_type = action.get('type', 'generic')
            read_only = action.get('read_only', True)

            if read_only or action_type in ['investigate', 'information', 'generic']:
                http_method = 'GET'
            else:
                http_method = 'POST'

            # Determine observable type
            observable_type = self._infer_observable_type(action_id, action.get('parameters', {}))

            # Convert parameters
            parameters = self._convert_parameters(action.get('parameters', {}))

            # Build action
            converted_action = {
                'id': action_id,
                'name': action_name.title(),
                'description': action.get('description', ''),
                'http_method': http_method,
                'endpoint': endpoint or f'/actions/{action_id}',
                'action_type': action_type,
                'read_only': read_only,
                'cacheable': read_only,  # Read-only actions can be cached
                'cache_ttl_days': 7 if read_only else 0,
                'parameters': parameters,
            }

            if observable_type:
                converted_action['observable_type'] = observable_type

            converted.append(converted_action)

        return converted

    def _find_endpoint(self, action_id: str, endpoints: Dict[str, str]) -> Optional[str]:
        """Find matching endpoint for an action."""
        action_lower = action_id.lower()

        # Direct match
        if action_lower in endpoints:
            return endpoints[action_lower]

        # Partial match
        for key, value in endpoints.items():
            if action_lower in key or key in action_lower:
                return value

        # Try common mappings
        mappings = {
            'lookup_ip': ['ip', 'check', 'ip_address'],
            'lookup_domain': ['domain', 'domains'],
            'lookup_hash': ['file', 'files', 'hash'],
            'lookup_url': ['url', 'urls'],
            'get_report': ['report', 'reports'],
            'list': ['list', 'query', 'queries'],
        }

        for action_key, endpoint_keys in mappings.items():
            if action_key in action_lower:
                for ek in endpoint_keys:
                    for key, value in endpoints.items():
                        if ek in key.lower():
                            return value

        return None

    def _infer_observable_type(self, action_id: str, parameters: Dict) -> Optional[str]:
        """Infer the observable type from action ID and parameters."""
        action_lower = action_id.lower()

        # Check action name
        if 'ip' in action_lower:
            return 'ip'
        if 'domain' in action_lower:
            return 'domain'
        if 'url' in action_lower:
            return 'url'
        if 'hash' in action_lower or 'file' in action_lower:
            return 'file_hash'
        if 'email' in action_lower:
            return 'email'

        # Check parameter names
        for param_name in parameters.keys():
            param_lower = param_name.lower()
            if param_lower in ['ip', 'ipaddress', 'ip_address']:
                return 'ip'
            if param_lower in ['domain', 'hostname']:
                return 'domain'
            if param_lower in ['url', 'uri']:
                return 'url'
            if param_lower in ['hash', 'md5', 'sha1', 'sha256', 'file_hash']:
                return 'file_hash'

        return None

    def _convert_parameters(self, parameters: Dict) -> List[Dict]:
        """Convert parameter definitions."""
        converted = []

        for name, config in parameters.items():
            if isinstance(config, dict):
                param = {
                    'name': name,
                    'type': self._map_data_type(config.get('data_type', 'string')),
                    'description': config.get('description', ''),
                    'required': config.get('required', False),
                }

                if 'default' in config:
                    param['default'] = config['default']

                if config.get('contains'):
                    param['contains'] = config['contains']

                converted.append(param)

        return converted

    def _map_data_type(self, data_type: str) -> str:
        """Map source data types to standard types."""
        type_map = {
            'string': 'string',
            'numeric': 'number',
            'boolean': 'boolean',
            'password': 'password',
            'file': 'file',
            'ph': 'string',  # Phantom-specific
        }
        return type_map.get(data_type.lower(), 'string')

    def _save_integration(self, connector_id: str, category: str, integration: Dict, manifest: Dict):
        """Save integration files to output directory."""
        # Create category directory
        category_dir = self.output_dir / 'integrations' / category / connector_id
        category_dir.mkdir(parents=True, exist_ok=True)

        # Save integration.json
        integration_file = category_dir / 'integration.json'
        with open(integration_file, 'w', encoding='utf-8') as f:
            json.dump(integration, f, indent=2)

        # Save manifest.json
        manifest_file = category_dir / 'manifest.json'
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        print(f"  Saved to {category_dir}")

    def _generate_index(self):
        """Generate the master index.json file."""
        integrations = []
        categories = {}

        for result in self.results['success']:
            integrations.append({
                'id': result['id'],
                'name': result['name'],
                'category': result['category'],
                'path': f"integrations/{result['category']}/{result['id']}"
            })

            # Count categories
            cat = result['category']
            categories[cat] = categories.get(cat, 0) + 1

        index = {
            'version': '1.0.0',
            'last_updated': datetime.utcnow().isoformat(),
            'total_integrations': len(integrations),
            'categories': [
                {'id': cat, 'name': cat.replace('_', ' ').title(), 'count': count}
                for cat, count in sorted(categories.items())
            ],
            'integrations': sorted(integrations, key=lambda x: x['name'])
        }

        # Save index.json
        self.output_dir.mkdir(parents=True, exist_ok=True)
        index_file = self.output_dir / 'index.json'
        with open(index_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2)

        # Save version.json
        version_file = self.output_dir / 'version.json'
        with open(version_file, 'w', encoding='utf-8') as f:
            json.dump({
                'version': '1.0.0',
                'build_date': datetime.utcnow().isoformat(),
                'integrations_count': len(integrations)
            }, f, indent=2)

        print(f"\nGenerated index.json with {len(integrations)} integrations")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Convert source connectors to AgentCore format')
    parser.add_argument('source', help='Source directory containing connector folders')
    parser.add_argument('output', help='Output directory for converted integrations')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    converter = IntegrationConverter(args.source, args.output)
    results = converter.convert_all()

    print("\n" + "="*60)
    print("CONVERSION COMPLETE")
    print("="*60)
    print(f"Success: {len(results['success'])}")
    print(f"Failed:  {len(results['failed'])}")
    print(f"Skipped: {len(results['skipped'])}")

    if results['failed']:
        print("\nFailed conversions:")
        for fail in results['failed'][:10]:
            print(f"  - {fail['dir']}: {fail['error']}")
        if len(results['failed']) > 10:
            print(f"  ... and {len(results['failed']) - 10} more")


if __name__ == '__main__':
    main()
