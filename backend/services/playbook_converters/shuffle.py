# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Shuffle Playbook (Workflow) Converter

Converts Shuffle open-source SOAR workflows to T1 Agentics native format.

Shuffle workflow structure:
- actions: Array of action/node definitions with app_name, app_id, parameters
- triggers: Array of trigger definitions (WEBHOOK, SCHEDULE, USERINPUT, SUBFLOW)
- branches: Connections between nodes (edges) with optional conditions
- workflow_variables: Shared variables across the workflow
- Top-level metadata: name, description, id

Shuffle actions use app_name (e.g., "Shuffle Tools", "HTTP", "TheHive", "VirusTotal")
and label fields to identify what each node does. Parameters are key-value pairs.
Branches use source_id/destination_id UUIDs with optional condition arrays.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import SHUFFLE_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Known app_name to integration mapping
# ============================================================================

_APP_NAME_TO_INTEGRATION = {
    'shuffle tools': 'shuffle_tools',
    'http': 'http',
    'email': 'email',
    'thehive': 'thehive',
    'thehive4': 'thehive',
    'thehive5': 'thehive',
    'cortex': 'cortex',
    'virustotal': 'virustotal',
    'crowdstrike': 'crowdstrike',
    'crowdstrike falcon': 'crowdstrike',
    'misp': 'misp',
    'slack': 'slack',
    'microsoft teams': 'teams',
    'servicenow': 'servicenow',
    'jira': 'jira',
    'splunk': 'splunk',
    'qradar': 'qradar',
    'pagerduty': 'pagerduty',
    'okta': 'okta',
    'active directory': 'active_directory',
    'ldap': 'ldap',
    'urlscan': 'urlscan',
    'urlscan.io': 'urlscan',
    'shodan': 'shodan',
    'abuseipdb': 'abuseipdb',
    'whois': 'whois',
    'carbon black': 'carbon_black',
    'sentinelone': 'sentinelone',
    'microsoft defender': 'microsoft_defender',
    'aws': 'aws',
    'aws security hub': 'aws_security_hub',
    'google chronicle': 'chronicle',
    'elasticsearch': 'elastic',
    'palo alto networks': 'palo_alto',
    'fortinet': 'fortinet',
    'fortigate': 'fortigate',
    'opsgenie': 'opsgenie',
    'hybrid analysis': 'hybrid_analysis',
    'greynoise': 'greynoise',
    'alienvault otx': 'alienvault_otx',
    'abuse.ch': 'abuse_ch',
    'ip api': 'ipinfo',
    'ipinfo': 'ipinfo',
}


def _normalize_app_name(app_name: str) -> str:
    """
    Normalize a Shuffle app_name to a lowercase underscore key for action map lookups.

    Examples:
        "Shuffle Tools" -> "shuffle_tools"
        "VirusTotal" -> "virustotal"
        "TheHive" -> "thehive"
    """
    if not app_name:
        return 'unknown'
    return app_name.lower().replace(' ', '_').replace('-', '_')


def _build_action_key(app_name: str, label: str) -> str:
    """
    Build a composite action key from app_name and action label.

    Shuffle actions are identified by (app_name, label/name). We combine them
    for action map lookups, e.g., "virustotal_get_ip_report".
    """
    normalized_app = _normalize_app_name(app_name)
    if not label:
        return normalized_app

    normalized_label = label.lower().replace(' ', '_').replace('-', '_')

    # If the label already starts with the app name, don't duplicate
    if normalized_label.startswith(normalized_app):
        return normalized_label

    return f"{normalized_app}_{normalized_label}"


class ShuffleConverter(PlaybookConverter):
    """
    Converter for Shuffle open-source SOAR workflows.

    Shuffle apps and their common actions:
    - Shuffle Tools: execute_python, filter_list, parse_ioc, regex, set_cache, etc.
    - HTTP: Generic HTTP requests (curl)
    - TheHive: Case management (create_case, update_case, search_cases, etc.)
    - VirusTotal: Threat intel lookups (get_ip_report, scan_file, etc.)
    - CrowdStrike: EDR actions (contain_host, get_device, search_detections)
    - MISP: Threat intel platform (search_events, add_event, add_attribute)
    - Slack / Teams: Notification (send_message, post_message)
    - ServiceNow / Jira: Ticketing (create_incident, update_issue)
    - Cortex: Analyzer-based enrichment
    """

    PLATFORM = SourcePlatform.SHUFFLE

    def __init__(self):
        super().__init__(SHUFFLE_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from Shuffle."""
        try:
            data = json.loads(content)

            indicators = [
                isinstance(data.get('actions'), list),
                isinstance(data.get('branches'), list),
                isinstance(data.get('triggers'), list),
                'shuffle' in str(data).lower()[:2000],
                # Shuffle-specific: actions have app_name
                any(
                    isinstance(a, dict) and 'app_name' in a
                    for a in (data.get('actions', []) or [])[:5]
                ),
                # Shuffle-specific: actions have app_id
                any(
                    isinstance(a, dict) and 'app_id' in a
                    for a in (data.get('actions', []) or [])[:5]
                ),
                # Shuffle-specific: actions have isStartNode
                any(
                    isinstance(a, dict) and 'isStartNode' in a
                    for a in (data.get('actions', []) or [])[:5]
                ),
                # Shuffle-specific: branches have source_id/destination_id
                any(
                    isinstance(b, dict) and 'source_id' in b and 'destination_id' in b
                    for b in (data.get('branches', []) or [])[:5]
                ),
                # Shuffle-specific: triggers have trigger_type
                any(
                    isinstance(t, dict) and 'trigger_type' in t
                    for t in (data.get('triggers', []) or [])[:5]
                ),
                isinstance(data.get('workflow_variables'), list),
            ]

            return sum(indicators) >= 3

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Shuffle workflow JSON."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported Shuffle Workflow'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('workflow_type', '1.0')),
            raw=data
        )

        # Parse workflow variables
        workflow_vars = data.get('workflow_variables', [])
        if isinstance(workflow_vars, list):
            for var in workflow_vars:
                if isinstance(var, dict):
                    var_name = var.get('name', var.get('id', ''))
                    if var_name:
                        parsed.variables[var_name] = var.get('value', '')

        # Parse actions
        actions = data.get('actions', [])
        action_map: Dict[str, ParsedStep] = {}

        for action in actions:
            if not isinstance(action, dict):
                continue

            step = self._parse_action(action)
            if step:
                parsed.steps.append(step)
                action_map[step.id] = step

        # Parse triggers and add them as steps too
        triggers = data.get('triggers', [])
        for trigger in triggers:
            if not isinstance(trigger, dict):
                continue

            step = self._parse_trigger(trigger)
            if step:
                parsed.steps.append(step)
                action_map[step.id] = step

                # Record trigger metadata
                parsed.triggers.append({
                    'trigger_id': step.id,
                    'type': trigger.get('trigger_type', 'WEBHOOK'),
                    'name': step.name
                })

        # Parse branches (edges) to build next_steps
        branches = data.get('branches', [])
        for branch in branches:
            if not isinstance(branch, dict):
                continue

            source_id = branch.get('source_id', '')
            dest_id = branch.get('destination_id', '')

            source_step = action_map.get(source_id)
            if source_step and dest_id:
                if dest_id not in source_step.next_steps:
                    source_step.next_steps.append(dest_id)

                # Store condition information on the source step for edge labels
                conditions = branch.get('conditions', [])
                has_errors = branch.get('hasErrors', False)

                if has_errors:
                    # Error branch — mark as error path
                    source_step.condition = 'on_error'
                elif conditions:
                    # Conditional branch — store for edge annotation
                    condition_summary = self._summarize_conditions(conditions)
                    if condition_summary and not source_step.condition:
                        source_step.condition = condition_summary

        # Identify start nodes
        for step in parsed.steps:
            if step.raw.get('isStartNode', False):
                # Move start nodes to front
                parsed.steps.remove(step)
                parsed.steps.insert(0, step)
                break

        return parsed

    def _parse_action(self, action: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Shuffle action node."""
        action_id = str(action.get('id', ''))
        if not action_id:
            return None

        app_name = action.get('app_name', '')
        action_label = action.get('label', action.get('name', ''))
        action_name = action.get('name', f'Action {action_id[:8]}')

        # Determine the step type from app_name + label
        action_key = _build_action_key(app_name, action_label)

        step = ParsedStep(
            id=action_id,
            name=action_name,
            step_type=action_key,
            raw=action
        )

        # Extract position
        position = action.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract parameters into config
        step.config = self._extract_action_config(action)

        # Store inputs from parameters
        parameters = action.get('parameters', [])
        if isinstance(parameters, list):
            for param in parameters:
                if isinstance(param, dict):
                    param_name = param.get('name', '')
                    if param_name:
                        step.inputs[param_name] = param.get('value', '')

        return step

    def _parse_trigger(self, trigger: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a Shuffle trigger node."""
        trigger_id = str(trigger.get('id', ''))
        if not trigger_id:
            return None

        trigger_type = trigger.get('trigger_type', 'WEBHOOK').upper()
        trigger_name = trigger.get('name', f'{trigger_type} Trigger')

        # Map trigger_type to step_type
        type_map = {
            'WEBHOOK': 'webhook',
            'SCHEDULE': 'schedule',
            'USERINPUT': 'userinput',
            'SUBFLOW': 'subflow',
            'EMAIL': 'email',
        }
        step_type = type_map.get(trigger_type, 'webhook')

        step = ParsedStep(
            id=trigger_id,
            name=trigger_name,
            step_type=step_type,
            raw=trigger
        )

        # Extract position
        position = trigger.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract trigger-specific config
        step.config = self._extract_trigger_config(trigger_type, trigger)

        return step

    def _extract_action_config(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a Shuffle action."""
        config: Dict[str, Any] = {}

        app_name = action.get('app_name', '')
        app_name_lower = app_name.lower()
        label = action.get('label', action.get('name', '')).lower()

        # Extract parameters as key-value dict
        parameters = action.get('parameters', [])
        params: Dict[str, str] = {}
        if isinstance(parameters, list):
            for param in parameters:
                if isinstance(param, dict):
                    pname = param.get('name', '')
                    pvalue = param.get('value', '')
                    if pname:
                        params[pname] = pvalue

        # Map app_name to integration
        integration = _APP_NAME_TO_INTEGRATION.get(app_name_lower, '')
        if integration:
            config['integration'] = integration

        # App-specific config extraction
        if app_name_lower == 'http':
            config.update({
                'url': params.get('url', ''),
                'method': params.get('method', 'GET'),
                'headers': params.get('headers', ''),
                'body': params.get('body', params.get('data', '')),
            })

        elif app_name_lower == 'shuffle tools':
            config.update({
                'function': label,
                'input': params.get('input', params.get('input_data', '')),
            })
            # Capture key params for specific tools
            if 'python' in label or 'execute' in label:
                config['code'] = params.get('code', params.get('python_code', ''))
            elif 'filter' in label:
                config['filter_field'] = params.get('field', '')
                config['filter_value'] = params.get('value', '')
            elif 'regex' in label:
                config['pattern'] = params.get('regex', params.get('pattern', ''))
            elif 'cache' in label:
                config['cache_key'] = params.get('key', '')
                config['cache_value'] = params.get('value', '')

        elif app_name_lower in ('thehive', 'thehive4', 'thehive5'):
            config.update({
                'title': params.get('title', ''),
                'description': params.get('description', ''),
                'severity': params.get('severity', ''),
                'case_id': params.get('id', params.get('case_id', '')),
            })

        elif app_name_lower == 'virustotal':
            config.update({
                'resource': params.get('resource', params.get('hash', params.get('ip', params.get('domain', params.get('url', ''))))),
            })

        elif app_name_lower in ('slack', 'microsoft teams'):
            config.update({
                'channel': params.get('channel', ''),
                'message': params.get('message', params.get('text', '')),
            })

        elif app_name_lower in ('email',):
            config.update({
                'to': params.get('recipient', params.get('to', '')),
                'subject': params.get('subject', ''),
                'body': params.get('body', params.get('message', '')),
            })

        elif app_name_lower in ('servicenow',):
            config.update({
                'table': params.get('table', 'incident'),
                'short_description': params.get('short_description', ''),
                'description': params.get('description', ''),
            })

        elif app_name_lower in ('jira',):
            config.update({
                'project': params.get('project', params.get('project_key', '')),
                'summary': params.get('summary', ''),
                'description': params.get('description', ''),
                'issue_type': params.get('issue_type', params.get('issuetype', 'Task')),
            })

        elif app_name_lower in ('crowdstrike', 'crowdstrike falcon'):
            config.update({
                'host_id': params.get('host_id', params.get('device_id', '')),
                'detection_id': params.get('detection_id', ''),
            })

        elif app_name_lower == 'misp':
            config.update({
                'event_id': params.get('event_id', ''),
                'value': params.get('value', ''),
                'type': params.get('type', ''),
                'category': params.get('category', ''),
            })

        else:
            # Generic: store all params
            config.update(params)

        # Store environment info
        env = action.get('environment', '')
        if env:
            config['environment'] = env

        # Store app version
        app_version = action.get('app_version', '')
        if app_version:
            config['app_version'] = app_version

        return config

    def _extract_trigger_config(
        self,
        trigger_type: str,
        trigger: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a Shuffle trigger."""
        config: Dict[str, Any] = {
            'trigger_type': trigger_type.lower()
        }

        if trigger_type == 'WEBHOOK':
            config.update({
                'path': trigger.get('path', ''),
                'auth': trigger.get('auth', ''),
            })

        elif trigger_type == 'SCHEDULE':
            config.update({
                'schedule': trigger.get('schedule', ''),
                'frequency': trigger.get('frequency', ''),
                'interval': trigger.get('interval', 0),
            })

        elif trigger_type == 'USERINPUT':
            config.update({
                'message': trigger.get('message', ''),
                'information': trigger.get('information', []),
            })

        elif trigger_type == 'SUBFLOW':
            config.update({
                'source_workflow': trigger.get('source_workflow', ''),
            })

        return config

    def _summarize_conditions(self, conditions: List[Dict[str, Any]]) -> str:
        """
        Summarize branch conditions into a human-readable string.

        Shuffle conditions are structured as:
        [{ "source": { "id": "...", "value": "..." },
           "condition": { "value": "equals|larger_than|..." },
           "destination": { "value": "..." } }]
        """
        if not conditions:
            return ''

        parts = []
        for cond in conditions:
            if not isinstance(cond, dict):
                continue

            source = cond.get('source', {})
            condition = cond.get('condition', {})
            destination = cond.get('destination', {})

            source_val = source.get('value', '?') if isinstance(source, dict) else '?'
            operator = condition.get('value', 'equals') if isinstance(condition, dict) else 'equals'
            dest_val = destination.get('value', '?') if isinstance(destination, dict) else '?'

            parts.append(f"{source_val} {operator} {dest_val}")

        return ' AND '.join(parts) if parts else ''

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map Shuffle action type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # Check if this is a trigger type
        trigger_types = {'webhook', 'schedule', 'userinput', 'subflow', 'email'}
        if step_type in trigger_types:
            trigger_type = config.get('trigger_type', step_type)
            if step_type == 'userinput':
                return 'approval_gate', {
                    'message': config.get('message', ''),
                }
            if step_type == 'subflow':
                return 'action', {
                    'action_type': 'run_playbook',
                    'source_workflow': config.get('source_workflow', ''),
                }
            return 'trigger', {
                'trigger_type': trigger_type,
            }

        # Reconstruct app_name from raw data for URL-based inference
        app_name = step.raw.get('app_name', '').lower()
        label = step.raw.get('label', step.raw.get('name', '')).lower()

        # HTTP app: infer purpose from URL (like Tines httpRequestAgent)
        if app_name == 'http':
            url = config.get('url', '').lower()
            return self._map_http_action(url, config)

        # Shuffle Tools: map by specific function label
        if app_name == 'shuffle tools':
            return self._map_shuffle_tools(label, config)

        # Try direct mapping from action map table
        node_type, mapped_config = self._map_action_from_table(step_type, config)
        if node_type != 'unmapped':
            return node_type, mapped_config

        # Try just the app name as a key
        app_key = _normalize_app_name(app_name)
        if app_key:
            node_type, mapped_config = self._map_action_from_table(app_key, config)
            if node_type != 'unmapped':
                return node_type, mapped_config

        # Try find_best_mapping as final fallback
        return find_best_mapping(step_type, 'shuffle')

    def _map_http_action(
        self,
        url: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map HTTP action based on URL to determine enrichment/action target."""
        # Enrichment APIs
        enrichment_apis = {
            'virustotal': ('enrich', {'integration': 'virustotal'}),
            'urlscan': ('enrich', {'integration': 'urlscan'}),
            'shodan': ('enrich', {'integration': 'shodan'}),
            'abuseipdb': ('enrich', {'integration': 'abuseipdb'}),
            'greynoise': ('enrich', {'integration': 'greynoise'}),
            'hybrid-analysis': ('enrich', {'integration': 'hybrid_analysis'}),
            'hybridanalysis': ('enrich', {'integration': 'hybrid_analysis'}),
            'pulsedive': ('enrich', {'integration': 'pulsedive'}),
            'otx.alienvault': ('enrich', {'integration': 'alienvault_otx'}),
            'ipinfo': ('enrich', {'integration': 'ipinfo'}),
        }

        for keyword, mapping in enrichment_apis.items():
            if keyword in url:
                return mapping

        # Action APIs
        action_apis = {
            'crowdstrike': ('action', {'integration': 'crowdstrike', 'requires_approval': True}),
            'sentinelone': ('action', {'integration': 'sentinelone', 'requires_approval': True}),
            'defender': ('action', {'integration': 'microsoft_defender', 'requires_approval': True}),
            'okta': ('action', {'integration': 'okta', 'requires_approval': True}),
        }

        for keyword, mapping in action_apis.items():
            if keyword in url:
                return mapping

        # Ticketing APIs
        if 'servicenow' in url or 'service-now' in url:
            return 'action', {'integration': 'servicenow'}
        if 'jira' in url or 'atlassian' in url:
            return 'create_ticket', {'integration': 'jira'}

        # Notification APIs
        if 'slack' in url:
            return 'notify', {'channel': 'slack'}
        if 'teams' in url or 'microsoft.com/webhook' in url:
            return 'notify', {'channel': 'teams'}

        # Cloud providers
        if 'amazonaws.com' in url or 'aws.' in url:
            return 'action', {'integration': 'aws', 'auto_mapped': True}
        if 'azure' in url or 'microsoft.com/v1' in url:
            return 'action', {'integration': 'azure', 'auto_mapped': True}
        if 'googleapis.com' in url:
            return 'action', {'integration': 'gcp', 'auto_mapped': True}

        # Generic HTTP call
        return 'webhook_call', {
            'url': config.get('url', ''),
            'method': config.get('method', 'GET'),
        }

    def _map_shuffle_tools(
        self,
        label: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map Shuffle Tools functions to native node types."""
        # Python execution
        if 'execute_python' in label or 'python' in label or 'execute_bash' in label:
            return 'python_code', {
                'code': config.get('code', ''),
            }

        # Filtering / conditions
        if 'filter' in label:
            return 'condition', {
                'field': config.get('filter_field', ''),
                'value': config.get('filter_value', ''),
            }

        # Regex operations
        if 'regex' in label:
            return 'transform', {
                'transform_type': 'regex',
                'pattern': config.get('pattern', ''),
            }

        # IOC parsing / enrichment
        if 'parse_ioc' in label:
            return 'enrich', {
                'observable_type': 'ioc',
            }

        # Cache operations (variable set/get)
        if 'set_cache' in label:
            return 'variable_set', {
                'name': config.get('cache_key', ''),
                'static_value': config.get('cache_value', ''),
            }
        if 'get_cache' in label:
            return 'variable_get', {
                'name': config.get('cache_key', ''),
            }
        if 'delete_cache' in label:
            return 'variable_set', {
                'name': config.get('cache_key', ''),
                'action': 'delete',
            }

        # Date/time transforms
        if 'date' in label or 'epoch' in label:
            return 'transform', {
                'transform_type': 'date_convert',
            }

        # Email/SMS notification
        if 'send_email' in label or 'send_sms' in label:
            channel = 'sms' if 'sms' in label else 'email'
            return 'notify', {
                'channel': channel,
            }

        # List operations
        if 'merge' in label or 'parse_list' in label or 'list' in label:
            return 'transform', {
                'transform_type': 'list_operation',
            }

        # CIDR match
        if 'cidr' in label:
            return 'condition', {
                'condition_type': 'cidr_match',
            }

        # Translation / value mapping
        if 'translate' in label:
            return 'transform', {
                'transform_type': 'translate',
            }

        # Passthrough / repeat
        if 'repeat_back' in label:
            return 'transform', {
                'transform_type': 'passthrough',
            }

        # Default: generic transform
        return 'transform', {
            'function': label,
        }

    def _map_operator(self, operator: str) -> str:
        """Map Shuffle condition operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'does_not_equal': 'not_equals',
            'not_equals': 'not_equals',
            'larger_than': 'greater_than',
            'less_than': 'less_than',
            'contains': 'contains',
            'does_not_contain': 'not_contains',
            'starts_with': 'starts_with',
            'ends_with': 'ends_with',
            'is_empty': 'is_empty',
            'is_not_empty': 'is_not_empty',
            'matches_regex': 'matches',
            'regex': 'matches',
        }
        return operator_map.get(
            operator.lower() if isinstance(operator, str) else 'equals',
            'equals'
        )
