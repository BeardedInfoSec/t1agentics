# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Torq Playbook (Workflow) Converter

Converts Torq hyperautomation workflows to T1 Agentics native format.

Torq workflow structure:
- steps: Array of step definitions with type, integration, inputs, outputs, next
- trigger: Single trigger definition (webhook, schedule, alert, manual)
- Top-level metadata: name, description, workflow_id

Torq steps use a type field (integration, condition, loop, transform, human_task,
subworkflow, http, script, delay) combined with integration.name and integration.action
to identify what each step does. Steps connect via "next" arrays of step IDs,
with optional "on_error" step IDs for error handling.

Torq supports both YAML and JSON exports.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import TORQ_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


def _safe_yaml_load(content: str) -> Optional[Dict[str, Any]]:
    """
    Attempt to parse content as YAML, returning None on failure.

    Torq workflows can be exported as YAML or JSON. This helper
    tries YAML parsing (which also handles JSON since JSON is valid YAML).
    """
    try:
        import yaml
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _parse_content(content: str) -> Dict[str, Any]:
    """
    Parse workflow content from JSON or YAML.

    Tries JSON first (faster, more common), then falls back to YAML.

    Raises:
        ValueError: If content cannot be parsed as JSON or YAML.
    """
    # Try JSON first
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # Try YAML
    data = _safe_yaml_load(content)
    if data is not None:
        return data

    raise ValueError("Content is not valid JSON or YAML")


def _build_integration_key(integration_name: str, integration_action: str) -> str:
    """
    Build a composite key from integration name and action.

    Torq integrations are identified by (name, action). We combine them
    using dot notation for action map lookups, e.g., "crowdstrike.contain_host".
    """
    if not integration_name:
        return integration_action or 'unknown'

    name = integration_name.lower().replace(' ', '_').replace('-', '_')
    if not integration_action:
        return name

    action = integration_action.lower().replace(' ', '_').replace('-', '_')
    return f"{name}.{action}"


class TorqConverter(PlaybookConverter):
    """
    Converter for Torq hyperautomation workflows.

    Step Types:
    - integration: Calls an external integration (CrowdStrike, Okta, etc.)
    - condition: If/else branching based on field comparisons
    - loop: Iterate over a list/array
    - transform: Data transformation (jq, JSONPath, template)
    - human_task: Manual approval / assignment with optional timeout
    - subworkflow: Call another Torq workflow
    - http: Generic HTTP request
    - script: Execute Python/JavaScript code
    - delay: Wait for a specified duration

    Integration references use:
    - integration.name: Vendor name (e.g., "CrowdStrike", "SentinelOne", "Okta")
    - integration.action: Specific action (e.g., "contain_host", "lookup_ip", "send_message")
    """

    PLATFORM = SourcePlatform.TORQ

    def __init__(self):
        super().__init__(TORQ_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from Torq."""
        try:
            data = _parse_content(content)

            indicators = [
                # Torq-specific: workflow_id field
                'workflow_id' in data,
                # Steps array with integration objects
                isinstance(data.get('steps'), list),
                # Single trigger object (not array)
                isinstance(data.get('trigger'), dict),
                # Torq keyword in content
                'torq' in str(data).lower()[:2000],
                # Steps have integration objects
                any(
                    isinstance(s, dict) and isinstance(s.get('integration'), dict)
                    for s in (data.get('steps', []) or [])[:5]
                ),
                # Steps have on_error field (Torq-specific)
                any(
                    isinstance(s, dict) and 'on_error' in s
                    for s in (data.get('steps', []) or [])[:5]
                ),
                # Steps have "next" array of step IDs
                any(
                    isinstance(s, dict) and isinstance(s.get('next'), list)
                    for s in (data.get('steps', []) or [])[:5]
                ),
                # Torq step types
                any(
                    isinstance(s, dict) and s.get('type') in (
                        'integration', 'condition', 'loop', 'transform',
                        'human_task', 'subworkflow', 'http', 'script', 'delay'
                    )
                    for s in (data.get('steps', []) or [])[:10]
                ),
                # Trigger has Torq-specific types
                data.get('trigger', {}).get('type') in (
                    'webhook', 'schedule', 'alert', 'manual'
                ) if isinstance(data.get('trigger'), dict) else False,
            ]

            return sum(indicators) >= 3

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Torq workflow (JSON or YAML)."""
        data = _parse_content(content)

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported Torq Workflow'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Store workflow_id as metadata
        workflow_id = data.get('workflow_id', '')
        if workflow_id:
            parsed.variables['workflow_id'] = workflow_id

        # Parse trigger
        trigger = data.get('trigger', {})
        if isinstance(trigger, dict) and trigger:
            trigger_step = self._parse_trigger(trigger)
            if trigger_step:
                parsed.steps.insert(0, trigger_step)
                parsed.triggers.append({
                    'trigger_id': trigger_step.id,
                    'type': trigger.get('type', 'webhook'),
                    'config': trigger.get('config', {})
                })

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

        # Build next_steps from "next" arrays and "on_error" fields
        for step_data in steps:
            if not isinstance(step_data, dict):
                continue

            step_id = str(step_data.get('id', ''))
            step = step_map.get(step_id)
            if not step:
                continue

            # Normal next steps
            next_ids = step_data.get('next', [])
            if isinstance(next_ids, list):
                for next_id in next_ids:
                    next_id_str = str(next_id)
                    if next_id_str in step_map and next_id_str not in step.next_steps:
                        step.next_steps.append(next_id_str)

            # Error handler step
            on_error = step_data.get('on_error', '')
            if on_error:
                on_error_str = str(on_error)
                if on_error_str in step_map and on_error_str not in step.next_steps:
                    step.next_steps.append(on_error_str)

        # Handle condition steps: connect then/else branches
        for step_data in steps:
            if not isinstance(step_data, dict):
                continue

            if step_data.get('type') != 'condition':
                continue

            step_id = str(step_data.get('id', ''))
            step = step_map.get(step_id)
            if not step:
                continue

            then_id = step_data.get('then', '')
            else_id = step_data.get('else', '')

            if then_id:
                then_id_str = str(then_id)
                if then_id_str in step_map and then_id_str not in step.next_steps:
                    step.next_steps.append(then_id_str)

            if else_id:
                else_id_str = str(else_id)
                if else_id_str in step_map and else_id_str not in step.next_steps:
                    step.next_steps.append(else_id_str)

        # Connect trigger to first non-trigger step if they have next IDs
        trigger_data = data.get('trigger', {})
        if isinstance(trigger_data, dict):
            trigger_next = trigger_data.get('next', [])
            if isinstance(trigger_next, list) and parsed.steps:
                trigger_step_obj = parsed.steps[0] if parsed.steps and parsed.steps[0].step_type.startswith(('webhook', 'schedule', 'alert', 'manual')) else None
                if trigger_step_obj:
                    for next_id in trigger_next:
                        next_id_str = str(next_id)
                        if next_id_str in step_map and next_id_str not in trigger_step_obj.next_steps:
                            trigger_step_obj.next_steps.append(next_id_str)

        return parsed

    def _parse_trigger(self, trigger: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a Torq trigger into a ParsedStep."""
        trigger_type = trigger.get('type', 'webhook').lower()
        trigger_id = str(trigger.get('id', f'trigger_{trigger_type}'))
        trigger_name = trigger.get('name', f'{trigger_type.title()} Trigger')

        step = ParsedStep(
            id=trigger_id,
            name=trigger_name,
            step_type=f'{trigger_type}_trigger',
            raw=trigger
        )

        # Extract trigger config
        config_data = trigger.get('config', {})
        step.config = {
            'trigger_type': trigger_type,
        }

        if isinstance(config_data, dict):
            if trigger_type == 'webhook':
                step.config.update({
                    'path': config_data.get('path', ''),
                    'method': config_data.get('method', 'POST'),
                    'auth_type': config_data.get('auth_type', ''),
                })
            elif trigger_type == 'schedule':
                step.config.update({
                    'cron': config_data.get('cron', ''),
                    'interval': config_data.get('interval', ''),
                    'timezone': config_data.get('timezone', 'UTC'),
                })
            elif trigger_type == 'alert':
                step.config.update({
                    'alert_source': config_data.get('source', ''),
                    'alert_type': config_data.get('type', ''),
                    'filter': config_data.get('filter', ''),
                })
            elif trigger_type == 'manual':
                step.config.update({
                    'description': config_data.get('description', ''),
                })

        return step

    def _parse_step(self, step_data: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Torq step."""
        step_id = str(step_data.get('id', ''))
        if not step_id:
            return None

        step_type = step_data.get('type', 'unknown')
        step_name = step_data.get('name', f'Step {step_id[:8]}')

        # For integration steps, build a composite type from integration.name + integration.action
        integration = step_data.get('integration', {})
        if step_type == 'integration' and isinstance(integration, dict):
            integration_name = integration.get('name', '')
            integration_action = integration.get('action', '')
            composite_type = _build_integration_key(integration_name, integration_action)
        else:
            composite_type = step_type

        step = ParsedStep(
            id=step_id,
            name=step_name,
            step_type=composite_type,
            raw=step_data
        )

        # Extract inputs
        inputs = step_data.get('inputs', {})
        if isinstance(inputs, dict):
            step.inputs = inputs.copy()

        # Extract outputs
        outputs = step_data.get('outputs', {})
        if isinstance(outputs, dict):
            step.outputs = outputs.copy()

        # Extract configuration based on step type
        step.config = self._extract_step_config(step_type, step_data)

        return step

    def _extract_step_config(
        self,
        step_type: str,
        step_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a Torq step based on its type."""
        config: Dict[str, Any] = {}
        inputs = step_data.get('inputs', {})
        if not isinstance(inputs, dict):
            inputs = {}

        if step_type == 'integration':
            integration = step_data.get('integration', {})
            if isinstance(integration, dict):
                config.update({
                    'integration_name': integration.get('name', ''),
                    'integration_action': integration.get('action', ''),
                    'integration_version': integration.get('version', ''),
                })
            # Copy all inputs as config parameters
            config.update(inputs)

        elif step_type == 'condition':
            condition = step_data.get('condition', {})
            if isinstance(condition, dict):
                config.update({
                    'field': condition.get('field', ''),
                    'operator': self._map_operator(condition.get('operator', 'eq')),
                    'value': condition.get('value', ''),
                })
            # Store then/else references
            then_ref = step_data.get('then', '')
            else_ref = step_data.get('else', '')
            if then_ref:
                config['then_step'] = str(then_ref)
            if else_ref:
                config['else_step'] = str(else_ref)

        elif step_type == 'loop':
            config.update({
                'items': inputs.get('items', inputs.get('list', '')),
                'item_variable': inputs.get('item_variable', inputs.get('item', 'item')),
                'max_iterations': inputs.get('max_iterations', 1000),
            })

        elif step_type == 'transform':
            config.update({
                'expression': inputs.get('expression', inputs.get('jq', '')),
                'template': inputs.get('template', ''),
                'transform_type': inputs.get('type', 'jq'),
            })

        elif step_type == 'human_task':
            assignees = step_data.get('assignees', [])
            config.update({
                'message': step_data.get('message', inputs.get('message', '')),
                'assignees': assignees if isinstance(assignees, list) else [],
                'timeout_hours': step_data.get('timeout_hours', inputs.get('timeout_hours', 168)),
            })

        elif step_type == 'subworkflow':
            config.update({
                'workflow_id': inputs.get('workflow_id', step_data.get('workflow_id', '')),
                'workflow_name': inputs.get('workflow_name', step_data.get('workflow_name', '')),
                'wait_for_completion': inputs.get('wait_for_completion', True),
            })

        elif step_type == 'http':
            config.update({
                'url': inputs.get('url', ''),
                'method': inputs.get('method', 'GET'),
                'headers': inputs.get('headers', {}),
                'body': inputs.get('body', inputs.get('data', '')),
                'timeout_seconds': inputs.get('timeout', 30),
            })

        elif step_type == 'script':
            config.update({
                'language': inputs.get('language', 'python'),
                'code': inputs.get('code', inputs.get('script', '')),
            })

        elif step_type == 'delay':
            config.update({
                'duration_seconds': self._parse_delay(
                    inputs.get('duration', inputs.get('seconds', 60))
                ),
            })

        else:
            # Generic: store all inputs
            config.update(inputs)

        # Store error handler reference
        on_error = step_data.get('on_error', '')
        if on_error:
            config['on_error_step'] = str(on_error)

        return config

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map Torq step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # Handle trigger steps
        if step_type.endswith('_trigger'):
            trigger_type = step_type.replace('_trigger', '')
            return 'trigger', {
                'trigger_type': trigger_type,
            }

        # Get the base type from raw data
        raw_type = step.raw.get('type', '')

        # Handle each Torq step type
        if raw_type == 'condition':
            return 'condition', {
                'field': config.get('field', ''),
                'operator': config.get('operator', 'equals'),
                'value': config.get('value', ''),
            }

        elif raw_type == 'loop':
            return 'transform', {
                'transform_type': 'loop',
                'items': config.get('items', ''),
                'item_variable': config.get('item_variable', 'item'),
            }

        elif raw_type == 'transform':
            return 'transform', {
                'transform_type': config.get('transform_type', 'jq'),
                'expression': config.get('expression', ''),
                'template': config.get('template', ''),
            }

        elif raw_type == 'human_task':
            timeout_hours = config.get('timeout_hours', 168)
            timeout_minutes = timeout_hours * 60 if isinstance(timeout_hours, (int, float)) else 168 * 60
            return 'approval_gate', {
                'message': config.get('message', ''),
                'assignees': config.get('assignees', []),
                'timeout_minutes': timeout_minutes,
            }

        elif raw_type == 'subworkflow':
            return 'action', {
                'action_type': 'run_playbook',
                'workflow_id': config.get('workflow_id', ''),
                'workflow_name': config.get('workflow_name', ''),
                'wait_for_completion': config.get('wait_for_completion', True),
            }

        elif raw_type == 'http':
            url = config.get('url', '').lower()
            return self._map_http_step(url, config)

        elif raw_type == 'script':
            return 'python_code', {
                'language': config.get('language', 'python'),
                'code': config.get('code', ''),
            }

        elif raw_type == 'delay':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        elif raw_type == 'integration':
            # Integration step: map based on integration.name + integration.action
            return self._map_integration_step(step)

        # Try action map table as fallback
        node_type, mapped_config = self._map_action_from_table(step_type, config)
        if node_type != 'unmapped':
            return node_type, mapped_config

        # Final fallback: find_best_mapping
        return find_best_mapping(step_type, 'torq')

    def _map_integration_step(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a Torq integration step to a native node type."""
        config = step.config.copy()
        integration_name = config.get('integration_name', '').lower()
        integration_action = config.get('integration_action', '').lower()
        composite_key = _build_integration_key(integration_name, integration_action)

        # Try exact composite key in action map
        node_type, mapped_config = self._map_action_from_table(composite_key, config)
        if node_type != 'unmapped':
            return node_type, mapped_config

        # Try just the integration name
        if integration_name:
            node_type, mapped_config = self._map_action_from_table(integration_name, config)
            if node_type != 'unmapped':
                return node_type, mapped_config

        # Try find_best_mapping with composite key
        node_type, mapped_config = find_best_mapping(composite_key, 'torq')
        if node_type != 'unmapped':
            return node_type, mapped_config

        # Infer from integration name if we know it
        return self._infer_from_integration_name(integration_name, integration_action, config)

    def _infer_from_integration_name(
        self,
        integration_name: str,
        integration_action: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Infer native node type from well-known integration names and actions."""
        # Enrichment integrations
        enrichment_integrations = {
            'virustotal', 'urlscan', 'shodan', 'abuseipdb', 'greynoise',
            'hybrid_analysis', 'pulsedive', 'whois', 'ipinfo', 'alienvault_otx',
        }
        if integration_name in enrichment_integrations:
            return 'enrich', {
                'integration': integration_name,
                'action': integration_action,
            }

        # EDR / containment integrations
        edr_integrations = {
            'crowdstrike', 'sentinelone', 'microsoft_defender',
            'carbon_black', 'cortex_xdr', 'cybereason',
        }
        if integration_name in edr_integrations:
            # Determine if this is enrichment or containment action
            containment_actions = {
                'contain', 'isolate', 'disconnect', 'quarantine',
                'block', 'disable', 'kill', 'terminate',
            }
            uncontainment_actions = {
                'uncontain', 'unisolate', 'connect', 'unquarantine',
                'unblock', 'enable', 'lift',
            }

            if any(word in integration_action for word in containment_actions):
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'contain_host',
                    'requires_approval': True,
                }
            elif any(word in integration_action for word in uncontainment_actions):
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'uncontain_host',
                    'requires_approval': True,
                }
            else:
                return 'enrich', {
                    'integration': integration_name,
                    'action': integration_action,
                }

        # Identity integrations
        identity_integrations = {
            'okta', 'active_directory', 'azure_ad', 'onelogin', 'ping_identity',
        }
        if integration_name in identity_integrations:
            disable_actions = {'disable', 'suspend', 'deactivate', 'lock'}
            enable_actions = {'enable', 'unsuspend', 'activate', 'unlock'}

            if any(word in integration_action for word in disable_actions):
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'disable_user',
                    'requires_approval': True,
                }
            elif any(word in integration_action for word in enable_actions):
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'enable_user',
                    'requires_approval': True,
                }
            elif 'password' in integration_action:
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'reset_password',
                    'requires_approval': True,
                }
            elif 'session' in integration_action:
                return 'action', {
                    'integration': integration_name,
                    'action_type': 'revoke_sessions',
                    'requires_approval': True,
                }
            else:
                return 'enrich', {
                    'integration': integration_name,
                    'observable_type': 'user',
                }

        # Notification integrations
        notification_integrations = {
            'slack': 'slack',
            'teams': 'teams',
            'microsoft_teams': 'teams',
            'email': 'email',
            'pagerduty': 'pagerduty',
            'opsgenie': 'opsgenie',
        }
        if integration_name in notification_integrations:
            return 'notify', {
                'channel': notification_integrations[integration_name],
            }

        # Ticketing integrations
        ticketing_integrations = {'servicenow', 'jira', 'zendesk', 'freshservice'}
        if integration_name in ticketing_integrations:
            if 'create' in integration_action:
                return 'create_ticket', {'integration': integration_name}
            elif 'close' in integration_action:
                return 'action', {
                    'action_type': 'close_ticket',
                    'integration': integration_name,
                }
            elif 'update' in integration_action:
                return 'action', {
                    'action_type': 'update_ticket',
                    'integration': integration_name,
                }
            elif 'get' in integration_action or 'search' in integration_action:
                return 'enrich', {
                    'integration': integration_name,
                    'observable_type': 'ticket',
                }
            return 'action', {'integration': integration_name}

        # SIEM integrations
        siem_integrations = {
            'splunk', 'qradar', 'elastic', 'elasticsearch',
            'chronicle', 'microsoft_sentinel', 'logrhythm',
        }
        if integration_name in siem_integrations:
            return 'enrich', {
                'integration': integration_name,
                'observable_type': 'query',
            }

        # Firewall / network integrations
        firewall_integrations = {
            'palo_alto', 'fortinet', 'fortigate', 'checkpoint',
            'cisco_asa', 'cisco_firepower',
        }
        if integration_name in firewall_integrations:
            return 'action', {
                'integration': integration_name,
                'requires_approval': True,
                'auto_mapped': True,
            }

        # Cloud integrations
        cloud_integrations = {'aws', 'azure', 'gcp', 'google_cloud'}
        if integration_name in cloud_integrations:
            return 'action', {
                'integration': integration_name,
                'auto_mapped': True,
            }

        # Unknown integration — return unmapped with context
        return 'unmapped', {
            'original_action': f"{integration_name}.{integration_action}",
            'integration': integration_name,
        }

    def _map_http_step(
        self,
        url: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map HTTP step based on URL to determine enrichment/action target."""
        # Enrichment APIs
        enrichment_keywords = {
            'virustotal': ('enrich', {'integration': 'virustotal'}),
            'urlscan': ('enrich', {'integration': 'urlscan'}),
            'shodan': ('enrich', {'integration': 'shodan'}),
            'abuseipdb': ('enrich', {'integration': 'abuseipdb'}),
            'greynoise': ('enrich', {'integration': 'greynoise'}),
            'hybrid-analysis': ('enrich', {'integration': 'hybrid_analysis'}),
            'hybridanalysis': ('enrich', {'integration': 'hybrid_analysis'}),
            'pulsedive': ('enrich', {'integration': 'pulsedive'}),
            'otx.alienvault': ('enrich', {'integration': 'alienvault_otx'}),
        }

        for keyword, mapping in enrichment_keywords.items():
            if keyword in url:
                return mapping

        # Action APIs
        action_keywords = {
            'crowdstrike': ('action', {'integration': 'crowdstrike', 'requires_approval': True}),
            'sentinelone': ('action', {'integration': 'sentinelone', 'requires_approval': True}),
            'okta': ('action', {'integration': 'okta', 'requires_approval': True}),
        }

        for keyword, mapping in action_keywords.items():
            if keyword in url:
                return mapping

        # Ticketing
        if 'servicenow' in url or 'service-now' in url:
            return 'action', {'integration': 'servicenow'}
        if 'jira' in url or 'atlassian' in url:
            return 'create_ticket', {'integration': 'jira'}

        # Notification
        if 'slack' in url:
            return 'notify', {'channel': 'slack'}
        if 'teams' in url or 'microsoft.com/webhook' in url:
            return 'notify', {'channel': 'teams'}

        # Cloud
        if 'amazonaws.com' in url:
            return 'action', {'integration': 'aws', 'auto_mapped': True}
        if 'azure' in url:
            return 'action', {'integration': 'azure', 'auto_mapped': True}
        if 'googleapis.com' in url:
            return 'action', {'integration': 'gcp', 'auto_mapped': True}

        # Generic HTTP call
        return 'webhook_call', {
            'url': config.get('url', ''),
            'method': config.get('method', 'GET'),
        }

    def _map_operator(self, operator: str) -> str:
        """Map Torq condition operator to native operator."""
        operator_map = {
            'eq': 'equals',
            'ne': 'not_equals',
            'gt': 'greater_than',
            'lt': 'less_than',
            'gte': 'greater_or_equal',
            'ge': 'greater_or_equal',
            'lte': 'less_or_equal',
            'le': 'less_or_equal',
            'contains': 'contains',
            'not_contains': 'not_contains',
            'in': 'in',
            'not_in': 'not_in',
            'starts_with': 'starts_with',
            'ends_with': 'ends_with',
            'is_empty': 'is_empty',
            'is_not_empty': 'is_not_empty',
            'matches': 'matches',
            'regex': 'matches',
            'exists': 'is_not_empty',
            'not_exists': 'is_empty',
            # Full-word variants
            'equals': 'equals',
            'not_equals': 'not_equals',
            'greater_than': 'greater_than',
            'less_than': 'less_than',
        }
        return operator_map.get(
            operator.lower() if isinstance(operator, str) else 'eq',
            'equals'
        )

    def _parse_delay(self, delay_value) -> int:
        """Parse a Torq delay value to seconds."""
        if isinstance(delay_value, (int, float)):
            return int(delay_value)

        try:
            delay_str = str(delay_value).lower().strip()

            if delay_str.endswith('d'):
                return int(delay_str[:-1]) * 86400
            elif delay_str.endswith('h'):
                return int(delay_str[:-1]) * 3600
            elif delay_str.endswith('m'):
                return int(delay_str[:-1]) * 60
            elif delay_str.endswith('s'):
                return int(delay_str[:-1])
            else:
                return int(delay_str)
        except (ValueError, TypeError):
            return 60
