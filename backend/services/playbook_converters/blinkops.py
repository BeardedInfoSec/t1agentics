# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
BlinkOps Playbook (Automation) Converter

Converts BlinkOps no-code security automations to T1 Agentics native format.

BlinkOps automation structure:
- name/description/automation_id: Top-level metadata
- steps: Array of step definitions with plugin references
- trigger: Trigger configuration (webhook, schedule, alert, manual, event)
- connections: Edges between steps using from/to UUIDs

Step types: action, condition, loop, delay, approval, script, http, transform
Plugin references: plugin.name = vendor, plugin.action = specific action
Condition steps use true_next/false_next for branching paths.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import BLINKOPS_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Operator Mapping
# ============================================================================

BLINKOPS_OPERATOR_MAP = {
    'equals': 'equals',
    'not_equals': 'not_equals',
    'contains': 'contains',
    'not_contains': 'not_contains',
    'greater_than': 'greater_than',
    'less_than': 'less_than',
    'greater_than_or_equal': 'greater_or_equal',
    'less_than_or_equal': 'less_or_equal',
    'in': 'in',
    'not_in': 'not_in',
    'is_empty': 'is_empty',
    'is_not_empty': 'is_not_empty',
    'starts_with': 'starts_with',
    'ends_with': 'ends_with',
    'matches': 'matches',
    'regex': 'matches',
}


def _parse_content(content: str) -> Dict[str, Any]:
    """
    Parse BlinkOps content from JSON or YAML.

    Args:
        content: Raw playbook content string

    Returns:
        Parsed dictionary

    Raises:
        ValueError: If content cannot be parsed as JSON or YAML
    """
    # Try JSON first (most common)
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try YAML
    if HAS_YAML:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
        except (yaml.YAMLError, AttributeError):
            pass

    raise ValueError("Content is not valid JSON or YAML")


def _build_plugin_action_key(plugin_name: str, action_name: str) -> str:
    """
    Build a normalized action key from plugin name and action.

    BlinkOps uses plugin.name = "CrowdStrike" and plugin.action = "Contain Host",
    which we normalize to "crowdstrike.contain_host" for action map lookups.

    Args:
        plugin_name: Plugin vendor name (e.g., "CrowdStrike", "AWS")
        action_name: Plugin action name (e.g., "Contain Host", "List EC2 Instances")

    Returns:
        Normalized key like "crowdstrike.contain_host"
    """
    norm_plugin = plugin_name.lower().replace(' ', '_').replace('-', '_')
    norm_action = action_name.lower().replace(' ', '_').replace('-', '_')
    return f"{norm_plugin}.{norm_action}"


class BlinkOpsConverter(PlaybookConverter):
    """
    Converter for BlinkOps no-code security automations.

    Step Types:
    - action: Plugin-based action (vendor integration)
    - condition: Conditional branching with true_next/false_next
    - loop: Iterate over items
    - delay: Wait/pause for duration
    - approval: Manual approval gate
    - script: Custom script execution
    - http: Raw HTTP request
    - transform: Data transformation

    Plugin Structure:
    - plugin.name: Integration vendor (e.g., "AWS", "CrowdStrike", "Okta")
    - plugin.action: Specific action (e.g., "Contain Host", "Suspend User")

    Trigger Types:
    - webhook: Incoming webhook
    - schedule: Cron-based schedule
    - alert: Alert-triggered
    - manual: Manual execution
    - event: Event-driven
    """

    PLATFORM = SourcePlatform.BLINKOPS

    def __init__(self):
        super().__init__(BLINKOPS_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from BlinkOps."""
        try:
            data = _parse_content(content)

            indicators = [
                'automation_id' in data,
                isinstance(data.get('steps'), list),
                isinstance(data.get('connections'), list),
                isinstance(data.get('trigger'), dict),
                # Check for plugin structure in steps
                any(
                    isinstance(s, dict) and isinstance(s.get('plugin'), dict)
                    for s in (data.get('steps', []) or [])[:5]
                ),
                # Check for BlinkOps-specific step types
                any(
                    isinstance(s, dict) and s.get('type') in (
                        'action', 'condition', 'loop', 'delay',
                        'approval', 'script', 'http', 'transform'
                    )
                    for s in (data.get('steps', []) or [])[:10]
                ),
                # Check for from/to connections
                any(
                    isinstance(c, dict) and 'from' in c and 'to' in c
                    for c in (data.get('connections', []) or [])[:5]
                ),
                'blinkops' in str(data).lower()[:2000],
                'blink' in str(data).lower()[:2000],
                # Check for on_error field (BlinkOps error handling)
                any(
                    isinstance(s, dict) and 'on_error' in s
                    for s in (data.get('steps', []) or [])[:5]
                ),
            ]

            return sum(indicators) >= 2

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse BlinkOps automation JSON/YAML."""
        data = _parse_content(content)

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported BlinkOps Automation'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Parse steps
        steps = data.get('steps', [])
        step_map: Dict[str, ParsedStep] = {}

        for step_data in steps:
            if not isinstance(step_data, dict):
                continue

            step = self._parse_step(step_data)
            if step:
                parsed.steps.append(step)
                step_map[step.id] = step

        # Parse connections (edges)
        connections = data.get('connections', [])
        for conn in connections:
            if not isinstance(conn, dict):
                continue

            source_id = str(conn.get('from', ''))
            target_id = str(conn.get('to', ''))

            if source_id in step_map and target_id:
                if target_id not in step_map[source_id].next_steps:
                    step_map[source_id].next_steps.append(target_id)

        # Also parse next/true_next/false_next from step definitions
        for step_data in steps:
            if not isinstance(step_data, dict):
                continue

            step_id = str(step_data.get('id', ''))
            if step_id not in step_map:
                continue

            step = step_map[step_id]

            # Parse direct next references
            next_refs = step_data.get('next', [])
            if isinstance(next_refs, str):
                next_refs = [next_refs]
            elif not isinstance(next_refs, list):
                next_refs = []

            for next_id in next_refs:
                next_id = str(next_id)
                if next_id and next_id not in step.next_steps:
                    step.next_steps.append(next_id)

            # Parse condition branching
            if step_data.get('type') == 'condition':
                true_next = step_data.get('true_next')
                false_next = step_data.get('false_next')

                if true_next:
                    true_id = str(true_next)
                    if true_id not in step.next_steps:
                        step.next_steps.append(true_id)

                if false_next:
                    false_id = str(false_next)
                    if false_id not in step.next_steps:
                        step.next_steps.append(false_id)

            # Parse on_error reference
            on_error = step_data.get('on_error')
            if on_error and isinstance(on_error, str):
                if on_error not in step.next_steps:
                    step.next_steps.append(on_error)

        # Parse trigger
        trigger_data = data.get('trigger', {})
        if isinstance(trigger_data, dict) and trigger_data:
            trigger_type = trigger_data.get('type', 'manual')
            parsed.triggers.append({
                'type': trigger_type,
                'config': trigger_data.get('config', {})
            })

        # Extract variables if present
        variables = data.get('variables', data.get('parameters', {}))
        if isinstance(variables, dict):
            parsed.variables = variables

        return parsed

    def _parse_step(self, step_data: Dict[str, Any]) -> Optional[ParsedStep]:
        """
        Parse a single BlinkOps step.

        Args:
            step_data: Raw step dictionary from the automation

        Returns:
            ParsedStep or None if step is invalid
        """
        step_id = str(step_data.get('id', ''))
        if not step_id:
            return None

        step_name = step_data.get('name', f'Step {step_id[:8]}')
        step_type = step_data.get('type', 'action')

        step = ParsedStep(
            id=step_id,
            name=step_name,
            step_type=step_type,
            raw=step_data
        )

        # Extract position
        position = step_data.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract configuration based on step type
        step.config = self._extract_step_config(step_type, step_data)

        # Extract inputs/outputs
        step.inputs = step_data.get('parameters', step_data.get('inputs', {}))
        if not isinstance(step.inputs, dict):
            step.inputs = {}
        step.outputs = step_data.get('outputs', {})
        if not isinstance(step.outputs, dict):
            step.outputs = {}

        return step

    def _extract_step_config(
        self,
        step_type: str,
        step_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract configuration from a BlinkOps step.

        Args:
            step_type: The step type string
            step_data: Raw step dictionary

        Returns:
            Extracted configuration dictionary
        """
        config: Dict[str, Any] = {}
        plugin = step_data.get('plugin', {})
        params = step_data.get('parameters', {})

        if not isinstance(plugin, dict):
            plugin = {}
        if not isinstance(params, dict):
            params = {}

        if step_type == 'action' and plugin:
            config = {
                'plugin_name': plugin.get('name', ''),
                'plugin_action': plugin.get('action', ''),
                'parameters': params,
            }

        elif step_type == 'condition':
            condition = step_data.get('condition', {})
            if isinstance(condition, dict):
                config = {
                    'left': condition.get('left', ''),
                    'operator': condition.get('operator', 'equals'),
                    'right': condition.get('right', ''),
                    'true_next': step_data.get('true_next', ''),
                    'false_next': step_data.get('false_next', ''),
                }
            else:
                config = {'condition_expression': str(condition)}

        elif step_type == 'loop':
            config = {
                'items': params.get('items', params.get('collection', '')),
                'variable': params.get('variable', params.get('item_name', 'item')),
                'max_iterations': params.get('max_iterations', 1000),
            }

        elif step_type == 'delay':
            config = {
                'duration_seconds': self._parse_delay(step_data),
            }

        elif step_type == 'approval':
            config = {
                'message': params.get('message', params.get('description', '')),
                'approvers': params.get('approvers', params.get('recipients', [])),
                'timeout_minutes': params.get('timeout_minutes', params.get('timeout', 1440)),
            }

        elif step_type == 'script':
            config = {
                'language': params.get('language', 'python'),
                'code': params.get('code', params.get('script', '')),
            }

        elif step_type == 'http':
            config = {
                'url': params.get('url', ''),
                'method': params.get('method', 'GET'),
                'headers': params.get('headers', {}),
                'body': params.get('body', params.get('payload', '')),
                'content_type': params.get('content_type', 'application/json'),
            }

        elif step_type == 'transform':
            config = {
                'expression': params.get('expression', params.get('template', '')),
                'output_variable': params.get('output_variable', params.get('output', '')),
            }

        else:
            # Generic — include plugin info if present
            if plugin:
                config['plugin_name'] = plugin.get('name', '')
                config['plugin_action'] = plugin.get('action', '')
            config['parameters'] = params

        return config

    def _parse_delay(self, step_data: Dict[str, Any]) -> int:
        """
        Parse delay duration from a BlinkOps step.

        Supports seconds, minutes, hours in parameters or direct duration fields.

        Args:
            step_data: Raw step dictionary

        Returns:
            Duration in seconds
        """
        params = step_data.get('parameters', {})
        if not isinstance(params, dict):
            params = {}

        # Direct seconds
        if 'duration_seconds' in params:
            try:
                return int(params['duration_seconds'])
            except (ValueError, TypeError):
                pass

        # Direct minutes
        if 'duration_minutes' in params:
            try:
                return int(params['duration_minutes']) * 60
            except (ValueError, TypeError):
                pass

        # Direct hours
        if 'duration_hours' in params:
            try:
                return int(params['duration_hours']) * 3600
            except (ValueError, TypeError):
                pass

        # Generic delay/duration field
        for key in ('delay', 'duration', 'wait', 'seconds'):
            if key in params:
                try:
                    return int(params[key])
                except (ValueError, TypeError):
                    pass

        # Step-level fields
        for key in ('delay_seconds', 'delay_minutes', 'delay'):
            if key in step_data:
                try:
                    val = int(step_data[key])
                    if 'minute' in key:
                        return val * 60
                    return val
                except (ValueError, TypeError):
                    pass

        return 60  # Default: 60 seconds

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map BlinkOps step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # ====================================================================
        # Condition steps → condition node
        # ====================================================================
        if step_type == 'condition':
            operator = config.get('operator', 'equals')
            mapped_op = BLINKOPS_OPERATOR_MAP.get(operator, 'equals')
            return 'condition', {
                'field': config.get('left', ''),
                'operator': mapped_op,
                'value': config.get('right', ''),
            }

        # ====================================================================
        # Loop steps → transform node with loop
        # ====================================================================
        if step_type == 'loop':
            return 'transform', {
                'transform_type': 'loop',
                'items': config.get('items', ''),
                'variable': config.get('variable', 'item'),
            }

        # ====================================================================
        # Delay steps → delay node
        # ====================================================================
        if step_type == 'delay':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # ====================================================================
        # Approval steps → approval_gate node
        # ====================================================================
        if step_type == 'approval':
            return 'approval_gate', {
                'message': config.get('message', ''),
                'timeout_minutes': config.get('timeout_minutes', 1440),
            }

        # ====================================================================
        # Script steps → python_code node
        # ====================================================================
        if step_type == 'script':
            return 'python_code', {
                'language': config.get('language', 'python'),
                'code': config.get('code', ''),
            }

        # ====================================================================
        # HTTP steps → webhook_call node
        # ====================================================================
        if step_type == 'http':
            url = config.get('url', '').lower()

            # Try to infer integration from URL
            if 'virustotal' in url:
                return 'enrich', {'integration': 'virustotal'}
            elif 'urlscan' in url:
                return 'enrich', {'integration': 'urlscan'}
            elif 'shodan' in url:
                return 'enrich', {'integration': 'shodan'}
            elif 'abuseipdb' in url:
                return 'enrich', {'integration': 'abuseipdb'}
            elif 'crowdstrike' in url:
                return 'action', {'integration': 'crowdstrike', 'requires_approval': True}
            elif 'okta' in url:
                return 'action', {'integration': 'okta', 'requires_approval': True}
            elif 'servicenow' in url or 'service-now' in url:
                return 'action', {'integration': 'servicenow'}
            elif 'jira' in url or 'atlassian' in url:
                return 'create_ticket', {'integration': 'jira'}
            elif 'pagerduty' in url:
                return 'notify', {'integration': 'pagerduty'}
            elif 'slack' in url:
                return 'notify', {'channel': 'slack'}

            return 'webhook_call', {
                'url': config.get('url', ''),
                'method': config.get('method', 'GET'),
                'headers': config.get('headers', {}),
                'body': config.get('body', ''),
            }

        # ====================================================================
        # Transform steps → transform node
        # ====================================================================
        if step_type == 'transform':
            return 'transform', {
                'transform_type': 'template',
                'expression': config.get('expression', ''),
            }

        # ====================================================================
        # Action steps with plugin — use plugin name + action for mapping
        # ====================================================================
        if step_type == 'action' or (config.get('plugin_name') and config.get('plugin_action')):
            plugin_name = config.get('plugin_name', '')
            plugin_action = config.get('plugin_action', '')

            if plugin_name and plugin_action:
                action_key = _build_plugin_action_key(plugin_name, plugin_action)

                # Try exact action map lookup
                result = self._map_action_from_table(action_key, config.get('parameters'))
                if result[0] != 'unmapped':
                    return result

                # Try find_best_mapping with the key
                result = find_best_mapping(action_key, 'blinkops')
                if result[0] != 'unmapped':
                    return result

                # Try just the action name
                result = find_best_mapping(plugin_action, 'blinkops')
                if result[0] != 'unmapped':
                    return result

                # Infer from plugin name (vendor)
                return self._infer_from_plugin_name(plugin_name, plugin_action, config)

            # Action without plugin — try step name
            if step.name:
                result = find_best_mapping(step.name, 'blinkops')
                if result[0] != 'unmapped':
                    return result

        # ====================================================================
        # Fallback — try action map with step type
        # ====================================================================
        return find_best_mapping(step_type, 'blinkops')

    def _infer_from_plugin_name(
        self,
        plugin_name: str,
        plugin_action: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Infer native node type from the BlinkOps plugin vendor name.

        When there is no direct action mapping, we use the plugin name
        to determine whether this is likely an enrichment, action, notification,
        or ticketing operation.

        Args:
            plugin_name: Plugin vendor name
            plugin_action: Plugin action name
            config: Step configuration

        Returns:
            Tuple of (node_type, node_config)
        """
        name_lower = plugin_name.lower()
        action_lower = plugin_action.lower()

        # Enrichment vendors
        enrichment_vendors = {
            'virustotal', 'urlscan', 'shodan', 'abuseipdb', 'greynoise',
            'hybrid analysis', 'hybrid_analysis', 'alienvault', 'otx',
            'threatcrowd', 'ipinfo', 'whois', 'dns', 'pulsedive', 'misp',
        }
        if name_lower in enrichment_vendors or any(v in name_lower for v in enrichment_vendors):
            return 'enrich', {'integration': name_lower.replace(' ', '_')}

        # EDR/Endpoint vendors — usually containment actions
        edr_vendors = {
            'crowdstrike', 'sentinelone', 'carbon black', 'carbonblack',
            'microsoft defender', 'cortex xdr', 'cybereason',
        }
        if name_lower in edr_vendors or any(v in name_lower for v in edr_vendors):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': plugin_action,
            }

        # Identity vendors
        identity_vendors = {'okta', 'azure ad', 'active directory', 'onelogin', 'ping'}
        if name_lower in identity_vendors or any(v in name_lower for v in identity_vendors):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': plugin_action,
            }

        # Ticketing vendors
        ticket_vendors = {'jira', 'servicenow', 'zendesk', 'freshdesk', 'connectwise'}
        if name_lower in ticket_vendors or any(v in name_lower for v in ticket_vendors):
            # Distinguish create vs update
            if any(word in action_lower for word in ['create', 'new', 'open']):
                return 'create_ticket', {'integration': name_lower.replace(' ', '_')}
            return 'action', {
                'action_type': 'update_ticket',
                'integration': name_lower.replace(' ', '_'),
            }

        # Notification vendors
        notif_vendors = {'slack', 'teams', 'microsoft teams', 'pagerduty', 'opsgenie', 'email'}
        if name_lower in notif_vendors or any(v in name_lower for v in notif_vendors):
            channel = name_lower.replace('microsoft ', '').replace(' ', '_')
            return 'notify', {'channel': channel}

        # Cloud providers — treat as actions
        cloud_vendors = {'aws', 'azure', 'gcp', 'google cloud'}
        if name_lower in cloud_vendors or any(v in name_lower for v in cloud_vendors):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
                'original_action': plugin_action,
            }

        # Firewall vendors
        fw_vendors = {'palo alto', 'fortinet', 'fortigate', 'checkpoint', 'cisco'}
        if name_lower in fw_vendors or any(v in name_lower for v in fw_vendors):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': plugin_action,
            }

        # Try inferring from action name keywords
        if any(word in action_lower for word in ['scan', 'lookup', 'get', 'search', 'check', 'query', 'report']):
            return 'enrich', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        if any(word in action_lower for word in ['block', 'disable', 'isolate', 'contain', 'quarantine', 'kill', 'terminate', 'revoke', 'suspend']):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'auto_mapped': True,
            }

        if any(word in action_lower for word in ['send', 'notify', 'post', 'message', 'alert']):
            return 'notify', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        if any(word in action_lower for word in ['create', 'ticket', 'incident', 'issue']):
            return 'create_ticket', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        # Truly unmapped
        return 'unmapped', {
            'original_action': f"{plugin_name}.{plugin_action}",
        }
