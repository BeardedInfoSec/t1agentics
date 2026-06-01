# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
LogicHub Playbook Converter

Converts LogicHub SOAR/SIEM playbooks to T1 Agentics native format.

LogicHub playbook structure:
- Top-level: { name, description, playbook_id, version, nodes, edges, inputs, outputs }
- Nodes array: [{ id, name, type, integration: { name, action }, config, position }]
- Node types: integration, decision, script, input, output, transform, batch, alert, notification
- Integration references: integration.name = vendor, integration.action = command
- Edges: [{ id, source, target, label }]
- Decision nodes: config.conditions with true_output / false_output branching
- Script nodes: config.language + config.code for custom logic
- Batch nodes: config.batch_size + config.input_field for batch processing
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import LOGICHUB_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Integration-to-vendor normalization
# ============================================================================

_INTEGRATION_VENDOR_MAP = {
    'virustotal': 'virustotal',
    'virus_total': 'virustotal',
    'vt': 'virustotal',
    'crowdstrike': 'crowdstrike',
    'crowd_strike': 'crowdstrike',
    'falcon': 'crowdstrike',
    'splunk': 'splunk',
    'servicenow': 'servicenow',
    'service_now': 'servicenow',
    'snow': 'servicenow',
    'okta': 'okta',
    'pan-os': 'palo_alto',
    'pan_os': 'palo_alto',
    'panos': 'palo_alto',
    'palo alto': 'palo_alto',
    'paloalto': 'palo_alto',
    'active_directory': 'active_directory',
    'activedirectory': 'active_directory',
    'ad': 'active_directory',
    'ldap': 'active_directory',
    'sentinelone': 'sentinelone',
    'sentinel_one': 'sentinelone',
    'carbon_black': 'carbon_black',
    'carbonblack': 'carbon_black',
    'cb': 'carbon_black',
    'urlscan': 'urlscan',
    'url_scan': 'urlscan',
    'shodan': 'shodan',
    'abuseipdb': 'abuseipdb',
    'abuse_ipdb': 'abuseipdb',
    'whois': 'whois',
    'misp': 'misp',
    'jira': 'jira',
    'slack': 'slack',
    'teams': 'teams',
    'microsoft_teams': 'teams',
    'pagerduty': 'pagerduty',
    'email': 'email',
    'smtp': 'email',
    'aws': 'aws',
    'azure': 'azure',
    'gcp': 'gcp',
    'google_cloud': 'gcp',
}


def _normalize_vendor(vendor_name: str) -> str:
    """Normalize an integration vendor name to canonical form."""
    if not vendor_name:
        return ''
    normalized = vendor_name.lower().strip().replace('-', '_').replace(' ', '_')
    return _INTEGRATION_VENDOR_MAP.get(normalized, normalized)


class LogicHubConverter(PlaybookConverter):
    """
    Converter for LogicHub SOAR/SIEM playbooks.

    Node Types:
    - integration: External tool calls (VirusTotal, CrowdStrike, Splunk, etc.)
    - decision: Conditional branching with true_output / false_output
    - script: Custom Python/JavaScript code execution
    - input: Playbook entry points / parameter collection
    - output: Playbook exit points / result emission
    - transform: Data transformation (field mapping, enrichment merging, etc.)
    - batch: Batch processing of items in configurable chunk sizes
    - alert: Alert creation and routing
    - notification: Send notifications via various channels
    """

    PLATFORM = SourcePlatform.LOGICHUB

    def __init__(self):
        super().__init__(LOGICHUB_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from LogicHub."""
        try:
            data = json.loads(content)

            indicators = [
                'playbook_id' in data,
                isinstance(data.get('nodes'), list),
                isinstance(data.get('edges'), list),
                'logichub' in str(data).lower()[:2000],
                isinstance(data.get('inputs'), dict),
                isinstance(data.get('outputs'), dict),
            ]

            # Check node structure for LogicHub-specific patterns
            nodes = data.get('nodes', [])
            if isinstance(nodes, list) and nodes:
                # LogicHub nodes have integration dict with name + action
                has_integration_struct = any(
                    isinstance(n, dict) and isinstance(n.get('integration'), dict)
                    for n in nodes[:10]
                )
                if has_integration_struct:
                    indicators.append(True)

                # LogicHub node types include 'integration', 'batch', 'transform'
                node_types = {n.get('type', '') for n in nodes[:20] if isinstance(n, dict)}
                logichub_types = {'integration', 'batch', 'transform', 'decision', 'script'}
                if node_types & logichub_types:
                    indicators.append(True)

            return sum(indicators) >= 3

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse LogicHub playbook JSON."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported LogicHub Playbook'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Parse variables from inputs
        inputs = data.get('inputs', {})
        if isinstance(inputs, dict):
            parsed.variables = inputs.copy()

        # Parse nodes
        nodes = data.get('nodes', [])
        node_map: Dict[str, ParsedStep] = {}

        for node in nodes:
            if not isinstance(node, dict):
                continue
            step = self._parse_node(node)
            if step:
                parsed.steps.append(step)
                node_map[step.id] = step

        # Parse edges and wire up next_steps
        edges = data.get('edges', [])
        for edge in edges:
            if not isinstance(edge, dict):
                continue

            source_id = str(edge.get('source', ''))
            target_id = str(edge.get('target', ''))
            label = edge.get('label', '')

            source_step = node_map.get(source_id)
            if source_step and target_id:
                if target_id not in source_step.next_steps:
                    source_step.next_steps.append(target_id)

                # For decision nodes, tag edges with their condition branch
                if source_step.step_type == 'decision' and label:
                    label_lower = label.lower().strip()
                    if label_lower in ('true', 'yes', 'pass', 'match'):
                        source_step.condition = 'true'
                    elif label_lower in ('false', 'no', 'fail', 'no_match'):
                        source_step.condition = 'false'

        # Wire up decision node true/false outputs from config
        for step in parsed.steps:
            if step.step_type == 'decision':
                true_output = step.config.get('true_output', '')
                false_output = step.config.get('false_output', '')
                if true_output and true_output not in step.next_steps:
                    step.next_steps.append(true_output)
                if false_output and false_output not in step.next_steps:
                    step.next_steps.append(false_output)

        # Detect triggers (input nodes serve as triggers)
        for step in parsed.steps:
            if step.step_type == 'input':
                parsed.triggers.append({
                    'node_id': step.id,
                    'type': 'input',
                    'name': step.name
                })

        return parsed

    def _parse_node(self, node: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single LogicHub node into a ParsedStep."""
        node_id = str(node.get('id', ''))
        if not node_id:
            return None

        node_name = node.get('name', f'Node {node_id[:8]}')
        node_type = node.get('type', 'unknown')

        step = ParsedStep(
            id=node_id,
            name=node_name,
            step_type=node_type,
            raw=node
        )

        # Extract position
        position = node.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract config based on node type
        config = node.get('config', {})
        if not isinstance(config, dict):
            config = {}

        integration = node.get('integration', {})
        if not isinstance(integration, dict):
            integration = {}

        step.config = self._extract_node_config(node_type, config, integration, node)

        return step

    def _extract_node_config(
        self,
        node_type: str,
        config: Dict[str, Any],
        integration: Dict[str, Any],
        node: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a LogicHub node."""
        result: Dict[str, Any] = {}

        if node_type == 'integration':
            vendor = _normalize_vendor(integration.get('name', ''))
            action = integration.get('action', '')

            result = {
                'vendor': vendor,
                'action': action,
                'vendor_raw': integration.get('name', ''),
                'action_raw': action,
                'parameters': config.get('parameters', config),
            }

        elif node_type == 'decision':
            conditions = config.get('conditions', [])
            result = {
                'conditions': conditions if isinstance(conditions, list) else [],
                'true_output': str(config.get('true_output', '')),
                'false_output': str(config.get('false_output', '')),
            }

        elif node_type == 'script':
            result = {
                'language': config.get('language', 'python'),
                'code': config.get('code', ''),
            }

        elif node_type == 'input':
            result = {
                'trigger_type': 'input',
                'fields': config.get('fields', []),
                'parameters': config.get('parameters', {}),
            }

        elif node_type == 'output':
            result = {
                'output_fields': config.get('fields', config.get('output_fields', [])),
            }

        elif node_type == 'transform':
            result = {
                'transform_type': config.get('transform_type', config.get('type', 'generic')),
                'field_mapping': config.get('field_mapping', config.get('mapping', {})),
                'expression': config.get('expression', ''),
            }

        elif node_type == 'batch':
            result = {
                'batch_size': config.get('batch_size', 100),
                'input_field': config.get('input_field', ''),
                'transform_type': 'batch',
            }

        elif node_type == 'alert':
            result = {
                'alert_type': config.get('alert_type', ''),
                'severity': config.get('severity', 'medium'),
                'message': config.get('message', ''),
            }

        elif node_type == 'notification':
            result = {
                'channel': config.get('channel', config.get('notification_type', '')),
                'recipients': config.get('recipients', []),
                'subject': config.get('subject', ''),
                'message': config.get('message', config.get('body', '')),
            }

        else:
            # Unknown type -- preserve all config
            result = config.copy() if isinstance(config, dict) else {}

        return result

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map LogicHub node type to native node type."""
        node_type = step.step_type
        config = step.config.copy()

        # Input → trigger
        if node_type == 'input':
            return 'trigger', {
                'trigger_type': 'input',
                'fields': config.get('fields', []),
            }

        # Output → end
        if node_type == 'output':
            return 'end', {
                'disposition': 'completed',
                'output_fields': config.get('output_fields', []),
            }

        # Decision → condition
        if node_type == 'decision':
            conditions = config.get('conditions', [])
            if conditions and isinstance(conditions, list):
                first_condition = conditions[0] if isinstance(conditions[0], dict) else {}
                return 'condition', {
                    'field': first_condition.get('field', ''),
                    'operator': self._map_operator(first_condition.get('operator', 'equals')),
                    'value': first_condition.get('value', ''),
                    'all_conditions': conditions,
                }
            return 'condition', {}

        # Script → python_code
        if node_type == 'script':
            language = config.get('language', 'python').lower()
            if language in ('python', 'python3', 'py'):
                return 'python_code', {
                    'code': config.get('code', ''),
                }
            # Non-Python scripts get a note
            return 'python_code', {
                'code': config.get('code', ''),
                'original_language': language,
                'requires_review': True,
            }

        # Transform → transform
        if node_type == 'transform':
            return 'transform', {
                'transform_type': config.get('transform_type', 'generic'),
                'field_mapping': config.get('field_mapping', {}),
                'expression': config.get('expression', ''),
            }

        # Batch → transform (batch)
        if node_type == 'batch':
            return 'transform', {
                'transform_type': 'batch',
                'batch_size': config.get('batch_size', 100),
                'input_field': config.get('input_field', ''),
            }

        # Alert → notify
        if node_type == 'alert':
            return 'notify', {
                'channel': 'alert',
                'severity': config.get('severity', 'medium'),
                'message': config.get('message', ''),
            }

        # Notification → notify
        if node_type == 'notification':
            return 'notify', {
                'channel': config.get('channel', ''),
                'recipients': config.get('recipients', []),
                'subject': config.get('subject', ''),
                'message': config.get('message', ''),
            }

        # Integration → map by vendor.action
        if node_type == 'integration':
            return self._map_integration_step(config)

        # Fallback: try action maps
        return find_best_mapping(node_type, 'logichub')

    def _map_integration_step(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Map a LogicHub integration node to a native node type.

        Uses vendor + action to look up the most specific mapping,
        falling back to vendor-only, then action-only, then heuristics.
        """
        vendor = config.get('vendor', '')
        action = config.get('action', '')
        vendor_raw = config.get('vendor_raw', vendor)
        parameters = config.get('parameters', {})

        # Build composite key: "vendor.action"
        composite_key = ''
        if vendor and action:
            composite_key = f"{vendor}.{action.lower().replace('-', '_').replace(' ', '_')}"

        # Try composite key first
        if composite_key:
            node_type, base_config = self._map_action_from_table(composite_key, parameters)
            if node_type != 'unmapped':
                return node_type, base_config

        # Try action alone
        if action:
            normalized_action = action.lower().replace('-', '_').replace(' ', '_')
            node_type, base_config = self._map_action_from_table(normalized_action, parameters)
            if node_type != 'unmapped':
                if vendor:
                    base_config['integration'] = vendor
                return node_type, base_config

        # Try vendor alone
        if vendor:
            node_type, base_config = self._map_action_from_table(vendor, parameters)
            if node_type != 'unmapped':
                return node_type, base_config

        # Heuristic: infer from action name keywords
        if action:
            action_lower = action.lower()

            # Enrichment-like actions
            if any(kw in action_lower for kw in ('lookup', 'get', 'search', 'scan', 'check', 'query', 'enrich', 'reputation')):
                return 'enrich', {
                    'integration': vendor or vendor_raw,
                    'auto_mapped': True,
                }

            # Containment-like actions
            if any(kw in action_lower for kw in ('contain', 'isolate', 'block', 'disable', 'quarantine', 'kill', 'terminate', 'revoke')):
                return 'action', {
                    'action_type': action_lower.replace(' ', '_').replace('-', '_'),
                    'integration': vendor or vendor_raw,
                    'requires_approval': True,
                    'auto_mapped': True,
                }

            # Ticket-like actions
            if any(kw in action_lower for kw in ('create_incident', 'create_ticket', 'create_case', 'open_ticket')):
                return 'create_ticket', {
                    'integration': vendor or vendor_raw,
                    'auto_mapped': True,
                }

            # Update-like actions
            if any(kw in action_lower for kw in ('update', 'modify', 'set')):
                return 'action', {
                    'action_type': action_lower.replace(' ', '_').replace('-', '_'),
                    'integration': vendor or vendor_raw,
                    'auto_mapped': True,
                }

            # Notification-like actions
            if any(kw in action_lower for kw in ('send', 'notify', 'alert', 'email', 'message', 'post')):
                return 'notify', {
                    'integration': vendor or vendor_raw,
                    'auto_mapped': True,
                }

            # Close/resolve actions
            if any(kw in action_lower for kw in ('close', 'resolve', 'complete', 'archive')):
                return 'action', {
                    'action_type': action_lower.replace(' ', '_').replace('-', '_'),
                    'integration': vendor or vendor_raw,
                    'auto_mapped': True,
                }

        # Generic unmapped integration
        logger.warning(
            f"No mapping for LogicHub integration: vendor={vendor_raw}, action={action}"
        )
        return 'action', {
            'integration': vendor or vendor_raw or 'unknown',
            'action': action,
            'auto_mapped': True,
            'requires_review': True,
        }

    def _map_operator(self, operator: str) -> str:
        """Map LogicHub condition operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'eq': 'equals',
            '==': 'equals',
            'not_equals': 'not_equals',
            'ne': 'not_equals',
            'neq': 'not_equals',
            '!=': 'not_equals',
            'contains': 'contains',
            'not_contains': 'not_contains',
            'does_not_contain': 'not_contains',
            'greater_than': 'greater_than',
            'gt': 'greater_than',
            '>': 'greater_than',
            'less_than': 'less_than',
            'lt': 'less_than',
            '<': 'less_than',
            'greater_or_equal': 'greater_or_equal',
            'gte': 'greater_or_equal',
            '>=': 'greater_or_equal',
            'less_or_equal': 'less_or_equal',
            'lte': 'less_or_equal',
            '<=': 'less_or_equal',
            'is_empty': 'is_empty',
            'is_not_empty': 'is_not_empty',
            'in': 'in',
            'not_in': 'not_in',
            'matches': 'matches',
            'regex': 'matches',
            'starts_with': 'starts_with',
            'ends_with': 'ends_with',
            'exists': 'is_not_empty',
            'not_exists': 'is_empty',
        }
        return operator_map.get(
            operator.lower().strip() if isinstance(operator, str) else 'equals',
            'equals'
        )
