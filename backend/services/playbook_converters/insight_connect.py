# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Rapid7 InsightConnect (Komand) Playbook Converter

Converts InsightConnect workflows (.icon / JSON) to T1 Agentics native format.

InsightConnect workflow structure:
- Top-level: { "kom": { "komandVersion": "...", ... }, "name": "...", "type": "basic",
               "steps": { ... }, "triggers": [...], "tags": [...] }
- Steps are a dict keyed by step name, each containing:
    { "id": "uuid", "type": "action|trigger|decision|loop|artifact|delay|human_decision",
      "plugin": { "name": "...", "slugVendor": "..." },
      "action": { "name": "..." }, "inputs": { ... }, "next": ["step_name"] }
- Triggers array: [{ "type": "api|alert|manual", "name": "...", "stepId": "uuid" }]
- Plugin references: plugin.name = integration name (e.g., "VirusTotal", "CrowdStrike Falcon")
- Action references: action.name = specific action (e.g., "Lookup Hash", "Contain Host")
- Decision steps: type "decision", conditions array with left, operator, right
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import INSIGHT_CONNECT_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


def _build_action_key(plugin_name: str, action_name: str) -> str:
    """
    Build a normalized action key from plugin and action names.

    InsightConnect uses plugin.name + action.name to identify what an action does.
    We normalize these into a dotted key for lookup in the action maps.

    Examples:
        ("VirusTotal", "Lookup Hash")  -> "virustotal.lookup_hash"
        ("CrowdStrike Falcon", "Contain Host")  -> "crowdstrike_falcon.contain_host"
        ("Active Directory LDAP", "Search") -> "active_directory_ldap.search"
    """
    plugin = plugin_name.lower().replace(' ', '_').replace('-', '_')
    action = action_name.lower().replace(' ', '_').replace('-', '_')
    return f"{plugin}.{action}"


class InsightConnectConverter(PlaybookConverter):
    """
    Converter for Rapid7 InsightConnect (Komand) workflows.

    Step Types:
    - action: Plugin-based action step (enrichment, containment, etc.)
    - trigger: Trigger step (api, alert, manual)
    - decision: Conditional branching with conditions array
    - loop: Iteration over a collection
    - artifact: Artifact creation/enrichment step
    - delay: Wait/pause step
    - human_decision: Manual approval gate
    - filter: Data filtering step

    Steps reference each other by step name strings via the "next" array.
    Triggers reference steps by stepId (UUID).
    """

    PLATFORM = SourcePlatform.INSIGHT_CONNECT

    def __init__(self):
        super().__init__(INSIGHT_CONNECT_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from Rapid7 InsightConnect."""
        try:
            data = json.loads(content)

            indicators = [
                # Primary: kom metadata block
                isinstance(data.get('kom'), dict),
                # komandVersion / komandCoreVersion in kom block
                'komandVersion' in data.get('kom', {}),
                'komandCoreVersion' in data.get('kom', {}),
                # Steps as a dict (not a list)
                isinstance(data.get('steps'), dict),
                # Steps with plugin/action structure
                self._has_plugin_steps(data),
                # slugVendor in step plugin metadata
                self._has_slug_vendor(data),
                # Triggers array
                isinstance(data.get('triggers'), list),
                # Workflow type field
                data.get('type') in ('basic', 'workflow', 'standard'),
                # Platform keywords
                'komand' in str(data).lower()[:2000],
                'insightconnect' in str(data).lower()[:2000],
                'rapid7' in str(data).lower()[:2000],
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    def _has_plugin_steps(self, data: Dict[str, Any]) -> bool:
        """Check if steps contain plugin/action structure."""
        steps = data.get('steps', {})
        if not isinstance(steps, dict):
            return False
        for step_data in list(steps.values())[:5]:
            if isinstance(step_data, dict):
                if 'plugin' in step_data and 'action' in step_data:
                    return True
        return False

    def _has_slug_vendor(self, data: Dict[str, Any]) -> bool:
        """Check if any step has slugVendor in its plugin metadata."""
        steps = data.get('steps', {})
        if not isinstance(steps, dict):
            return False
        for step_data in list(steps.values())[:5]:
            if isinstance(step_data, dict):
                plugin = step_data.get('plugin', {})
                if isinstance(plugin, dict) and 'slugVendor' in plugin:
                    return True
        return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse InsightConnect workflow JSON."""
        data = json.loads(content)

        # Extract metadata
        kom = data.get('kom', {})
        komand_version = kom.get('komandVersion', kom.get('komandCoreVersion', ''))

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported InsightConnect Workflow'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(komand_version) if komand_version else '1.0',
            raw=data
        )

        # Parse steps — keyed by step name
        steps_dict = data.get('steps', {})
        step_name_to_id: Dict[str, str] = {}  # step_name -> step.id (UUID)

        for step_name, step_data in steps_dict.items():
            if not isinstance(step_data, dict):
                logger.warning(f"Skipping non-dict step: {step_name}")
                continue

            step = self._parse_step(step_name, step_data)
            if step:
                parsed.steps.append(step)
                step_name_to_id[step_name] = step.id

        # Resolve next_steps from step names to step IDs
        for step in parsed.steps:
            raw_next = step.raw.get('_next_step_names', [])
            resolved_next = []
            for next_name in raw_next:
                if next_name in step_name_to_id:
                    resolved_next.append(step_name_to_id[next_name])
                else:
                    logger.warning(
                        f"Step '{step.name}' references unknown next step: '{next_name}'"
                    )
            step.next_steps = resolved_next

        # Parse trigger definitions
        triggers_list = data.get('triggers', [])
        for trigger in triggers_list:
            if isinstance(trigger, dict):
                parsed.triggers.append({
                    'type': trigger.get('type', 'manual'),
                    'name': trigger.get('name', ''),
                    'step_id': trigger.get('stepId', ''),
                })

        # Extract tags
        tags = data.get('tags', [])
        if isinstance(tags, list):
            parsed.variables['tags'] = tags

        return parsed

    def _parse_step(
        self,
        step_name: str,
        step_data: Dict[str, Any]
    ) -> Optional[ParsedStep]:
        """Parse a single InsightConnect step."""
        step_id = str(step_data.get('id', step_name))
        step_type = step_data.get('type', 'action')

        # Build display name: prefer the step's title, fall back to step_name
        display_name = step_data.get('title', step_data.get('name', step_name))

        step = ParsedStep(
            id=step_id,
            name=display_name,
            step_type=step_type,
            raw=step_data
        )

        # Store next step names for later resolution
        next_steps = step_data.get('next', [])
        if isinstance(next_steps, str):
            next_steps = [next_steps]
        step.raw['_next_step_names'] = next_steps if isinstance(next_steps, list) else []

        # Extract plugin and action info
        plugin = step_data.get('plugin', {})
        action = step_data.get('action', {})

        if isinstance(plugin, dict):
            step.config['plugin_name'] = plugin.get('name', '')
            step.config['plugin_vendor'] = plugin.get('slugVendor', '')
            step.config['plugin_slug'] = plugin.get('slug', '')

        if isinstance(action, dict):
            step.config['action_name'] = action.get('name', '')

        # Extract inputs
        inputs = step_data.get('inputs', step_data.get('input', {}))
        if isinstance(inputs, dict):
            step.inputs = inputs

        # Extract outputs
        outputs = step_data.get('outputs', step_data.get('output', {}))
        if isinstance(outputs, dict):
            step.outputs = outputs

        # Handle decision step conditions
        if step_type == 'decision':
            conditions = step_data.get('conditions', [])
            step.config['conditions'] = self._parse_conditions(conditions)
            # Decision steps may have branch-specific next steps
            branches = step_data.get('branches', {})
            if isinstance(branches, dict):
                step.config['branches'] = branches
                # True/false branch next steps
                true_next = branches.get('true', branches.get('yes', ''))
                false_next = branches.get('false', branches.get('no', ''))
                if true_next and true_next not in step.raw['_next_step_names']:
                    step.raw['_next_step_names'].append(true_next)
                if false_next and false_next not in step.raw['_next_step_names']:
                    step.raw['_next_step_names'].append(false_next)

        # Handle loop step
        if step_type == 'loop':
            step.config['loop_over'] = step_data.get('loopOver', step_data.get('loop_over', ''))
            step.config['loop_variable'] = step_data.get('loopVariable', step_data.get('loop_variable', ''))

        # Handle delay step
        if step_type == 'delay':
            step.config['duration_seconds'] = self._parse_delay_duration(step_data)

        # Handle human_decision step
        if step_type == 'human_decision':
            step.config['message'] = step_data.get('message', step_data.get('description', ''))
            step.config['recipients'] = step_data.get('recipients', [])
            timeout = step_data.get('timeout', step_data.get('timeoutSeconds', 0))
            step.config['timeout_seconds'] = int(timeout) if timeout else 604800  # Default 7 days

        # Position (if provided)
        position = step_data.get('position', step_data.get('graph', {}).get('position', {}))
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        return step

    def _parse_conditions(self, conditions: Any) -> List[Dict[str, Any]]:
        """Parse InsightConnect decision conditions."""
        parsed_conditions = []

        if not isinstance(conditions, list):
            return parsed_conditions

        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            parsed_conditions.append({
                'left': condition.get('left', ''),
                'operator': condition.get('operator', condition.get('type', 'equals')),
                'right': condition.get('right', ''),
            })

        return parsed_conditions

    def _parse_delay_duration(self, step_data: Dict[str, Any]) -> int:
        """Parse delay duration from step data into seconds."""
        # Try direct seconds field
        seconds = step_data.get('seconds', step_data.get('duration', None))
        if seconds is not None:
            try:
                return int(seconds)
            except (ValueError, TypeError):
                pass

        # Try duration + unit pattern
        duration = step_data.get('delayDuration', step_data.get('delay_duration', 0))
        unit = step_data.get('delayUnit', step_data.get('delay_unit', 'seconds')).lower()

        try:
            duration = int(duration)
        except (ValueError, TypeError):
            return 60  # Default 1 minute

        multipliers = {
            'seconds': 1, 'second': 1,
            'minutes': 60, 'minute': 60,
            'hours': 3600, 'hour': 3600,
            'days': 86400, 'day': 86400,
        }
        return duration * multipliers.get(unit, 1)

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map InsightConnect step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # ---- Trigger ----
        if step_type == 'trigger':
            trigger_type = config.get('trigger_subtype', 'alert')
            return 'trigger', {'trigger_type': trigger_type}

        # ---- Decision ----
        if step_type == 'decision':
            conditions = config.get('conditions', [])
            if conditions:
                first = conditions[0]
                return 'condition', {
                    'field': first.get('left', ''),
                    'operator': self._map_operator(first.get('operator', 'equals')),
                    'value': first.get('right', ''),
                    'all_conditions': conditions,
                }
            return 'condition', {}

        # ---- Loop ----
        if step_type == 'loop':
            return 'transform', {
                'transform_type': 'loop',
                'loop_over': config.get('loop_over', ''),
                'loop_variable': config.get('loop_variable', ''),
            }

        # ---- Delay ----
        if step_type == 'delay':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # ---- Human Decision / Approval ----
        if step_type == 'human_decision':
            return 'approval_gate', {
                'message': config.get('message', ''),
                'timeout_minutes': config.get('timeout_seconds', 604800) // 60,
            }

        # ---- Artifact ----
        if step_type == 'artifact':
            return 'enrich', {
                'artifact_type': True,
                'auto_mapped': True,
            }

        # ---- Filter ----
        if step_type == 'filter':
            return 'condition', {
                'condition_type': 'filter',
            }

        # ---- Action (plugin-based) ----
        if step_type == 'action' or step_type not in (
            'trigger', 'decision', 'loop', 'delay', 'human_decision',
            'artifact', 'filter'
        ):
            plugin_name = config.get('plugin_name', '')
            action_name = config.get('action_name', '')

            if plugin_name and action_name:
                # Build dotted key and look up in action maps
                action_key = _build_action_key(plugin_name, action_name)
                result = find_best_mapping(action_key, 'insight_connect')

                if result[0] != 'unmapped':
                    node_type, node_config = result
                    # Preserve plugin/action metadata
                    node_config = {**node_config}
                    node_config['plugin'] = plugin_name
                    node_config['action'] = action_name
                    return node_type, node_config

                # Fallback: infer from plugin name alone
                plugin_lower = plugin_name.lower()
                inferred = self._infer_from_plugin_name(plugin_lower, action_name)
                if inferred:
                    return inferred

            elif plugin_name:
                # Action name missing but plugin present
                plugin_lower = plugin_name.lower()
                inferred = self._infer_from_plugin_name(plugin_lower, '')
                if inferred:
                    return inferred

            # Last resort: try step type mapping directly
            return find_best_mapping(step_type, 'insight_connect')

        # Catch-all
        return find_best_mapping(step_type, 'insight_connect')

    def _infer_from_plugin_name(
        self,
        plugin_lower: str,
        action_name: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Infer node type from plugin name when action map lookup fails."""
        action_lower = action_name.lower() if action_name else ''

        # Enrichment plugins
        enrichment_plugins = {
            'virustotal': 'virustotal',
            'urlscan': 'urlscan',
            'shodan': 'shodan',
            'abuseipdb': 'abuseipdb',
            'greynoise': 'greynoise',
            'whois': 'whois',
            'hybrid analysis': 'hybrid_analysis',
            'hybridanalysis': 'hybrid_analysis',
            'maxmind': 'maxmind',
            'ipinfo': 'ipinfo',
            'threatcrowd': 'threatcrowd',
            'threatminer': 'threatminer',
            'misp': 'misp',
            'otx': 'otx',
            'censys': 'censys',
            'passivetotal': 'passivetotal',
            'recorded future': 'recorded_future',
        }
        for pattern, integration in enrichment_plugins.items():
            if pattern in plugin_lower:
                return 'enrich', {'integration': integration, 'plugin': plugin_lower}

        # EDR / containment plugins
        edr_plugins = {
            'crowdstrike': 'crowdstrike',
            'sentinelone': 'sentinelone',
            'carbon black': 'carbon_black',
            'microsoft defender': 'microsoft_defender',
            'cortex xdr': 'cortex_xdr',
            'cylance': 'cylance',
        }
        for pattern, integration in edr_plugins.items():
            if pattern in plugin_lower:
                # Check if the action implies enrichment or containment
                if any(w in action_lower for w in ['get', 'search', 'list', 'query', 'find', 'lookup']):
                    return 'enrich', {'integration': integration, 'plugin': plugin_lower}
                return 'action', {
                    'integration': integration,
                    'requires_approval': True,
                    'plugin': plugin_lower,
                }

        # Identity plugins
        identity_plugins = {
            'active directory': 'active_directory',
            'ldap': 'active_directory',
            'azure ad': 'azure_ad',
            'okta': 'okta',
            'duo': 'duo',
            'onelogin': 'onelogin',
        }
        for pattern, integration in identity_plugins.items():
            if pattern in plugin_lower:
                if any(w in action_lower for w in ['get', 'search', 'list', 'query', 'find', 'lookup']):
                    return 'enrich', {'integration': integration, 'plugin': plugin_lower}
                return 'action', {
                    'integration': integration,
                    'requires_approval': True,
                    'plugin': plugin_lower,
                }

        # Ticketing plugins
        ticketing_plugins = {
            'servicenow': 'servicenow',
            'jira': 'jira',
            'zendesk': 'zendesk',
            'pagerduty': 'pagerduty',
            'opsgenie': 'opsgenie',
        }
        for pattern, integration in ticketing_plugins.items():
            if pattern in plugin_lower:
                if any(w in action_lower for w in ['create', 'open', 'new']):
                    return 'create_ticket', {'integration': integration, 'plugin': plugin_lower}
                if any(w in action_lower for w in ['get', 'search', 'list', 'query', 'find']):
                    return 'enrich', {'integration': integration, 'observable_type': 'ticket'}
                return 'action', {'integration': integration, 'plugin': plugin_lower}

        # Notification plugins
        notification_plugins = {
            'slack': 'slack',
            'microsoft teams': 'teams',
            'teams': 'teams',
            'smtp': 'email',
            'email': 'email',
            'twilio': 'sms',
        }
        for pattern, channel in notification_plugins.items():
            if pattern in plugin_lower:
                return 'notify', {'channel': channel, 'plugin': plugin_lower}

        # Firewall plugins
        firewall_plugins = {
            'palo alto': 'palo_alto',
            'pan-os': 'palo_alto',
            'cisco': 'cisco',
            'fortinet': 'fortinet',
            'fortigate': 'fortigate',
            'checkpoint': 'checkpoint',
        }
        for pattern, integration in firewall_plugins.items():
            if pattern in plugin_lower:
                return 'action', {
                    'integration': integration,
                    'requires_approval': True,
                    'plugin': plugin_lower,
                }

        # SIEM plugins
        siem_plugins = {
            'splunk': 'splunk',
            'elasticsearch': 'elasticsearch',
            'qradar': 'qradar',
            'logrhythm': 'logrhythm',
            'sentinel': 'sentinel',
            'rapid7 insightidr': 'insightidr',
        }
        for pattern, integration in siem_plugins.items():
            if pattern in plugin_lower:
                return 'enrich', {'integration': integration, 'observable_type': 'query'}

        # Scripting / utility plugins
        if any(p in plugin_lower for p in ['python', 'script', 'powershell', 'bash']):
            return 'python_code', {'plugin': plugin_lower}

        if any(p in plugin_lower for p in ['type converter', 'string', 'math', 'base64', 'json']):
            return 'transform', {'plugin': plugin_lower}

        return None

    def _map_operator(self, operator: str) -> str:
        """Map InsightConnect operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'equal_to': 'equals',
            '==': 'equals',
            'not_equals': 'not_equals',
            'not_equal_to': 'not_equals',
            '!=': 'not_equals',
            'contains': 'contains',
            'not_contains': 'not_contains',
            'does_not_contain': 'not_contains',
            'greater_than': 'greater_than',
            '>': 'greater_than',
            'greater_or_equal': 'greater_or_equal',
            '>=': 'greater_or_equal',
            'less_than': 'less_than',
            '<': 'less_than',
            'less_or_equal': 'less_or_equal',
            '<=': 'less_or_equal',
            'starts_with': 'starts_with',
            'ends_with': 'ends_with',
            'matches_regex': 'matches',
            'regex': 'matches',
            'is_empty': 'is_empty',
            'is_not_empty': 'is_not_empty',
            'in': 'in_list',
            'not_in': 'not_in_list',
            'is_true': 'equals',
            'is_false': 'not_equals',
        }
        return operator_map.get(
            operator.lower() if isinstance(operator, str) else 'equals',
            'equals'
        )
