# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
D3 Security (Smart SOAR) Playbook Converter

Converts D3 Security Smart SOAR playbooks to T1 Agentics native format.

D3 Security playbook structure:
- playbook_name/playbook_id/description/category: Top-level metadata
- commands: Array of command definitions (steps)
- connections: Edges between commands using source_command_id/target_command_id
- variables: Playbook-level variable definitions

Command types: integration, condition, manual_task, timer, set_variable,
              sub_playbook, notification, script
Integration references: integration_name = vendor, command_name = specific action
Connections use condition labels: success, failure, always
Condition commands use condition_rules with true_path/false_path.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import D3_SECURITY_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Operator Mapping
# ============================================================================

D3_OPERATOR_MAP = {
    'equals': 'equals',
    'not_equals': 'not_equals',
    'contains': 'contains',
    'not_contains': 'not_contains',
    'greater_than': 'greater_than',
    'less_than': 'less_than',
    'greater_or_equal': 'greater_or_equal',
    'less_or_equal': 'less_or_equal',
    'in': 'in',
    'not_in': 'not_in',
    'is_empty': 'is_empty',
    'is_not_empty': 'is_not_empty',
    'starts_with': 'starts_with',
    'ends_with': 'ends_with',
    'matches': 'matches',
    'regex': 'matches',
    'is_true': 'equals',
    'is_false': 'not_equals',
    'exists': 'is_not_empty',
    'not_exists': 'is_empty',
}


def _build_integration_action_key(integration_name: str, command_name: str) -> str:
    """
    Build a normalized action key from D3 Security integration and command names.

    D3 uses integration_name = "CrowdStrike Falcon" and command_name = "Isolate Endpoint",
    which we normalize to "crowdstrike_falcon.isolate_endpoint" for action map lookups.

    Args:
        integration_name: Integration vendor name
        command_name: Command action name

    Returns:
        Normalized key like "crowdstrike_falcon.isolate_endpoint"
    """
    norm_integration = integration_name.lower().replace(' ', '_').replace('-', '_')
    norm_command = command_name.lower().replace(' ', '_').replace('-', '_')
    return f"{norm_integration}.{norm_command}"


class D3SecurityConverter(PlaybookConverter):
    """
    Converter for D3 Security Smart SOAR playbooks.

    Command Types:
    - integration: Vendor integration action (e.g., CrowdStrike, VirusTotal)
    - condition: Conditional branching with condition_rules
    - manual_task: Manual analyst task (approval/review)
    - timer: Wait/delay for specified duration
    - set_variable: Set a playbook variable
    - sub_playbook: Execute a sub-playbook
    - notification: Send notification (email, Slack, Teams)
    - script: Custom script execution

    Connection Conditions:
    - success: Execute on success of source command
    - failure: Execute on failure of source command
    - always: Execute regardless of source outcome

    Integration References:
    - integration_name: Vendor name (e.g., "VirusTotal", "CrowdStrike Falcon")
    - command_name: Specific action (e.g., "Scan IP", "Isolate Endpoint")
    """

    PLATFORM = SourcePlatform.D3_SECURITY

    def __init__(self):
        super().__init__(D3_SECURITY_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from D3 Security Smart SOAR."""
        try:
            data = json.loads(content)

            indicators = [
                'playbook_name' in data,
                'playbook_id' in data,
                isinstance(data.get('commands'), list),
                isinstance(data.get('connections'), list),
                isinstance(data.get('variables'), dict),
                'category' in data,
                # Check for command_id in commands
                any(
                    isinstance(c, dict) and 'command_id' in c
                    for c in (data.get('commands', []) or [])[:5]
                ),
                # Check for integration_name in commands
                any(
                    isinstance(c, dict) and 'integration_name' in c
                    for c in (data.get('commands', []) or [])[:5]
                ),
                # Check for command_name in commands
                any(
                    isinstance(c, dict) and 'command_name' in c
                    for c in (data.get('commands', []) or [])[:5]
                ),
                # Check for source_command_id/target_command_id in connections
                any(
                    isinstance(c, dict) and 'source_command_id' in c and 'target_command_id' in c
                    for c in (data.get('connections', []) or [])[:5]
                ),
                # Check for D3-specific command types
                any(
                    isinstance(c, dict) and c.get('type') in (
                        'integration', 'condition', 'manual_task', 'timer',
                        'set_variable', 'sub_playbook', 'notification', 'script'
                    )
                    for c in (data.get('commands', []) or [])[:10]
                ),
                'd3' in str(data).lower()[:2000],
                'smart soar' in str(data).lower()[:2000],
            ]

            return sum(indicators) >= 2

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse D3 Security Smart SOAR playbook JSON."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('playbook_name', 'Imported D3 Security Playbook'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Parse commands (steps)
        commands = data.get('commands', [])
        command_map: Dict[str, ParsedStep] = {}

        for cmd_data in commands:
            if not isinstance(cmd_data, dict):
                continue

            step = self._parse_command(cmd_data)
            if step:
                parsed.steps.append(step)
                command_map[step.id] = step

        # Parse connections (edges)
        connections = data.get('connections', [])
        for conn in connections:
            if not isinstance(conn, dict):
                continue

            source_id = str(conn.get('source_command_id', ''))
            target_id = str(conn.get('target_command_id', ''))

            if source_id in command_map and target_id:
                step = command_map[source_id]
                if target_id not in step.next_steps:
                    step.next_steps.append(target_id)

                # Store connection condition as edge metadata
                condition = conn.get('condition', 'always')
                condition_expr = conn.get('condition_expression', '')

                # For condition commands, mark the true/false path
                if step.step_type == 'condition':
                    if condition == 'success' or self._is_true_path(conn, step):
                        if not step.condition:
                            step.condition = 'true'

        # Parse condition command branching (true_path/false_path)
        for cmd_data in commands:
            if not isinstance(cmd_data, dict):
                continue

            if cmd_data.get('type') != 'condition':
                continue

            cmd_id = str(cmd_data.get('command_id', ''))
            if cmd_id not in command_map:
                continue

            step = command_map[cmd_id]

            true_path = cmd_data.get('true_path')
            false_path = cmd_data.get('false_path')

            if true_path:
                true_id = str(true_path)
                if true_id not in step.next_steps:
                    step.next_steps.append(true_id)

            if false_path:
                false_id = str(false_path)
                if false_id not in step.next_steps:
                    step.next_steps.append(false_id)

        # Parse variables
        variables = data.get('variables', {})
        if isinstance(variables, dict):
            parsed.variables = variables

        # Extract category as tag info
        category = data.get('category', '')
        if category:
            parsed.variables['_category'] = category

        return parsed

    def _parse_command(self, cmd_data: Dict[str, Any]) -> Optional[ParsedStep]:
        """
        Parse a single D3 Security command.

        Args:
            cmd_data: Raw command dictionary from the playbook

        Returns:
            ParsedStep or None if command is invalid
        """
        cmd_id = str(cmd_data.get('command_id', ''))
        if not cmd_id:
            return None

        cmd_name = cmd_data.get('name', f'Command {cmd_id[:8]}')
        cmd_type = cmd_data.get('type', 'integration')

        step = ParsedStep(
            id=cmd_id,
            name=cmd_name,
            step_type=cmd_type,
            raw=cmd_data
        )

        # Extract position
        position = cmd_data.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract configuration based on command type
        step.config = self._extract_command_config(cmd_type, cmd_data)

        # Extract input/output parameters
        step.inputs = cmd_data.get('input_parameters', {})
        if not isinstance(step.inputs, dict):
            step.inputs = {}
        step.outputs = cmd_data.get('output_parameters', {})
        if not isinstance(step.outputs, dict):
            step.outputs = {}

        return step

    def _extract_command_config(
        self,
        cmd_type: str,
        cmd_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract configuration from a D3 Security command.

        Args:
            cmd_type: The command type string
            cmd_data: Raw command dictionary

        Returns:
            Extracted configuration dictionary
        """
        config: Dict[str, Any] = {}
        input_params = cmd_data.get('input_parameters', {})
        if not isinstance(input_params, dict):
            input_params = {}

        if cmd_type == 'integration':
            config = {
                'integration_name': cmd_data.get('integration_name', ''),
                'command_name': cmd_data.get('command_name', ''),
                'parameters': input_params,
            }

        elif cmd_type == 'condition':
            condition_rules = cmd_data.get('condition_rules', [])
            if isinstance(condition_rules, list) and condition_rules:
                # Use the first rule for primary condition
                first_rule = condition_rules[0] if isinstance(condition_rules[0], dict) else {}
                config = {
                    'field': first_rule.get('field', ''),
                    'operator': first_rule.get('operator', 'equals'),
                    'value': first_rule.get('value', ''),
                    'all_rules': condition_rules,
                    'true_path': cmd_data.get('true_path', ''),
                    'false_path': cmd_data.get('false_path', ''),
                }
            else:
                config = {
                    'true_path': cmd_data.get('true_path', ''),
                    'false_path': cmd_data.get('false_path', ''),
                }

        elif cmd_type == 'manual_task':
            config = {
                'description': cmd_data.get('description', input_params.get('description', '')),
                'assignee': input_params.get('assignee', input_params.get('assigned_to', '')),
                'instructions': input_params.get('instructions', ''),
                'timeout_minutes': input_params.get('timeout_minutes', input_params.get('timeout', 1440)),
            }

        elif cmd_type == 'timer':
            config = {
                'duration_seconds': self._parse_timer_duration(cmd_data),
            }

        elif cmd_type == 'set_variable':
            config = {
                'variable_name': input_params.get('variable_name', input_params.get('name', '')),
                'variable_value': input_params.get('variable_value', input_params.get('value', '')),
            }

        elif cmd_type == 'sub_playbook':
            config = {
                'playbook_name': input_params.get('playbook_name', input_params.get('playbook_id', '')),
                'input_mapping': input_params.get('input_mapping', {}),
                'wait_for_completion': input_params.get('wait_for_completion', True),
            }

        elif cmd_type == 'notification':
            channel = self._infer_notification_channel(cmd_data)
            config = {
                'channel': channel,
                'recipients': input_params.get('recipients', input_params.get('to', [])),
                'subject': input_params.get('subject', ''),
                'message': input_params.get('message', input_params.get('body', '')),
                'template': input_params.get('template', ''),
            }

        elif cmd_type == 'script':
            config = {
                'language': input_params.get('language', 'python'),
                'code': input_params.get('code', input_params.get('script', '')),
                'timeout_seconds': input_params.get('timeout_seconds', 300),
            }

        else:
            # Generic — include integration info if present
            integration_name = cmd_data.get('integration_name', '')
            command_name = cmd_data.get('command_name', '')
            if integration_name:
                config['integration_name'] = integration_name
            if command_name:
                config['command_name'] = command_name
            config['parameters'] = input_params

        return config

    def _parse_timer_duration(self, cmd_data: Dict[str, Any]) -> int:
        """
        Parse timer duration from a D3 Security timer command.

        Args:
            cmd_data: Raw command dictionary

        Returns:
            Duration in seconds
        """
        input_params = cmd_data.get('input_parameters', {})
        if not isinstance(input_params, dict):
            input_params = {}

        # Direct seconds
        for key in ('delay_seconds', 'duration_seconds', 'seconds'):
            if key in cmd_data:
                try:
                    return int(cmd_data[key])
                except (ValueError, TypeError):
                    pass
            if key in input_params:
                try:
                    return int(input_params[key])
                except (ValueError, TypeError):
                    pass

        # Minutes
        for key in ('delay_minutes', 'duration_minutes', 'minutes'):
            if key in cmd_data:
                try:
                    return int(cmd_data[key]) * 60
                except (ValueError, TypeError):
                    pass
            if key in input_params:
                try:
                    return int(input_params[key]) * 60
                except (ValueError, TypeError):
                    pass

        # Hours
        for key in ('delay_hours', 'duration_hours', 'hours'):
            if key in cmd_data:
                try:
                    return int(cmd_data[key]) * 3600
                except (ValueError, TypeError):
                    pass
            if key in input_params:
                try:
                    return int(input_params[key]) * 3600
                except (ValueError, TypeError):
                    pass

        # Generic delay field
        for key in ('delay', 'duration', 'wait'):
            if key in input_params:
                try:
                    return int(input_params[key])
                except (ValueError, TypeError):
                    pass

        return 60  # Default: 60 seconds

    def _infer_notification_channel(self, cmd_data: Dict[str, Any]) -> str:
        """
        Infer notification channel from D3 Security notification command.

        Args:
            cmd_data: Raw command dictionary

        Returns:
            Channel name string
        """
        input_params = cmd_data.get('input_parameters', {})
        if not isinstance(input_params, dict):
            input_params = {}

        # Check explicit channel field
        channel = input_params.get('channel', input_params.get('notification_type', ''))
        if channel:
            return channel.lower()

        # Infer from command name or integration name
        cmd_name = cmd_data.get('command_name', cmd_data.get('name', '')).lower()
        integration = cmd_data.get('integration_name', '').lower()

        if 'slack' in cmd_name or 'slack' in integration:
            return 'slack'
        elif 'teams' in cmd_name or 'teams' in integration or 'microsoft' in integration:
            return 'teams'
        elif 'email' in cmd_name or 'smtp' in integration or 'mail' in cmd_name:
            return 'email'
        elif 'pagerduty' in cmd_name or 'pagerduty' in integration:
            return 'pagerduty'
        elif 'webhook' in cmd_name:
            return 'webhook'

        return 'email'  # Default to email

    def _is_true_path(self, conn: Dict[str, Any], step: ParsedStep) -> bool:
        """
        Determine if a connection represents the 'true' path of a condition.

        Args:
            conn: Connection dictionary
            step: The source step

        Returns:
            True if this connection is the true/success path
        """
        condition = conn.get('condition', '').lower()
        condition_expr = conn.get('condition_expression', '').lower()
        label = conn.get('label', '').lower()

        return any(indicator in (condition + condition_expr + label)
                    for indicator in ['success', 'true', 'yes', 'pass'])

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map D3 Security command type to native node type."""
        cmd_type = step.step_type
        config = step.config.copy()

        # ====================================================================
        # Condition commands → condition node
        # ====================================================================
        if cmd_type == 'condition':
            operator = config.get('operator', 'equals')
            mapped_op = D3_OPERATOR_MAP.get(operator, 'equals')
            return 'condition', {
                'field': config.get('field', ''),
                'operator': mapped_op,
                'value': config.get('value', ''),
            }

        # ====================================================================
        # Manual task commands → approval_gate node
        # ====================================================================
        if cmd_type == 'manual_task':
            return 'approval_gate', {
                'message': config.get('description', config.get('instructions', '')),
                'assignee': config.get('assignee', ''),
                'timeout_minutes': config.get('timeout_minutes', 1440),
            }

        # ====================================================================
        # Timer commands → delay node
        # ====================================================================
        if cmd_type == 'timer':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # ====================================================================
        # Set variable commands → variable_set node
        # ====================================================================
        if cmd_type == 'set_variable':
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('variable_value', ''),
            }

        # ====================================================================
        # Sub-playbook commands → action node with run_playbook type
        # ====================================================================
        if cmd_type == 'sub_playbook':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', ''),
                'wait_for_completion': config.get('wait_for_completion', True),
            }

        # ====================================================================
        # Notification commands → notify node
        # ====================================================================
        if cmd_type == 'notification':
            return 'notify', {
                'channel': config.get('channel', 'email'),
                'recipients': config.get('recipients', ''),
                'subject': config.get('subject', ''),
                'message': config.get('message', ''),
            }

        # ====================================================================
        # Script commands → python_code node
        # ====================================================================
        if cmd_type == 'script':
            return 'python_code', {
                'language': config.get('language', 'python'),
                'code': config.get('code', ''),
            }

        # ====================================================================
        # Integration commands — use integration_name + command_name for mapping
        # ====================================================================
        if cmd_type == 'integration' or (config.get('integration_name') and config.get('command_name')):
            integration_name = config.get('integration_name', '')
            command_name = config.get('command_name', '')

            if integration_name and command_name:
                action_key = _build_integration_action_key(integration_name, command_name)

                # Try exact action map lookup
                result = self._map_action_from_table(action_key, config.get('parameters'))
                if result[0] != 'unmapped':
                    return result

                # Try find_best_mapping with the full key
                result = find_best_mapping(action_key, 'd3_security')
                if result[0] != 'unmapped':
                    return result

                # Try just the command name
                result = find_best_mapping(command_name, 'd3_security')
                if result[0] != 'unmapped':
                    return result

                # Infer from integration name (vendor)
                return self._infer_from_integration(integration_name, command_name, config)

            # Integration without names — try step name
            if step.name:
                result = find_best_mapping(step.name, 'd3_security')
                if result[0] != 'unmapped':
                    return result

        # ====================================================================
        # Fallback — try action map with command type
        # ====================================================================
        return find_best_mapping(cmd_type, 'd3_security')

    def _infer_from_integration(
        self,
        integration_name: str,
        command_name: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Infer native node type from the D3 Security integration vendor name.

        When there is no direct action mapping, we use the integration name
        to determine whether this is likely an enrichment, action, notification,
        or ticketing operation.

        Args:
            integration_name: Integration vendor name
            command_name: Command action name
            config: Step configuration

        Returns:
            Tuple of (node_type, node_config)
        """
        name_lower = integration_name.lower()
        cmd_lower = command_name.lower()

        # Enrichment vendors
        enrichment_vendors = {
            'virustotal', 'urlscan', 'shodan', 'abuseipdb', 'greynoise',
            'hybrid analysis', 'hybrid_analysis', 'alienvault', 'otx',
            'threatcrowd', 'ipinfo', 'whois', 'dns', 'pulsedive', 'misp',
            'maxmind', 'passive total', 'passivetotal', 'censys',
        }
        if name_lower in enrichment_vendors or any(v in name_lower for v in enrichment_vendors):
            return 'enrich', {'integration': name_lower.replace(' ', '_')}

        # EDR/Endpoint vendors
        edr_vendors = {
            'crowdstrike', 'crowdstrike falcon', 'sentinelone', 'carbon black',
            'carbonblack', 'microsoft defender', 'cortex xdr', 'cybereason',
            'cylance', 'tanium', 'trend micro',
        }
        if name_lower in edr_vendors or any(v in name_lower for v in edr_vendors):
            # Distinguish enrichment vs containment actions
            if any(word in cmd_lower for word in ['get', 'search', 'list', 'query', 'find', 'lookup']):
                return 'enrich', {
                    'integration': name_lower.replace(' ', '_'),
                    'original_action': command_name,
                }
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': command_name,
            }

        # Identity vendors
        identity_vendors = {'okta', 'azure ad', 'active directory', 'onelogin', 'ping identity', 'duo'}
        if name_lower in identity_vendors or any(v in name_lower for v in identity_vendors):
            if any(word in cmd_lower for word in ['get', 'search', 'list', 'lookup', 'find']):
                return 'enrich', {
                    'integration': name_lower.replace(' ', '_'),
                    'observable_type': 'user',
                    'original_action': command_name,
                }
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': command_name,
            }

        # Ticketing vendors
        ticket_vendors = {'servicenow', 'jira', 'zendesk', 'freshdesk', 'connectwise', 'remedy'}
        if name_lower in ticket_vendors or any(v in name_lower for v in ticket_vendors):
            if any(word in cmd_lower for word in ['create', 'new', 'open']):
                return 'create_ticket', {'integration': name_lower.replace(' ', '_')}
            if any(word in cmd_lower for word in ['get', 'search', 'list', 'find']):
                return 'enrich', {
                    'integration': name_lower.replace(' ', '_'),
                    'observable_type': 'ticket',
                }
            return 'action', {
                'action_type': 'update_ticket',
                'integration': name_lower.replace(' ', '_'),
            }

        # Notification vendors
        notif_vendors = {'slack', 'teams', 'microsoft teams', 'pagerduty', 'opsgenie', 'email', 'smtp'}
        if name_lower in notif_vendors or any(v in name_lower for v in notif_vendors):
            channel = name_lower.replace('microsoft ', '').replace(' ', '_')
            return 'notify', {'channel': channel}

        # SIEM vendors
        siem_vendors = {'splunk', 'qradar', 'elastic', 'elasticsearch', 'sentinel', 'chronicle', 'logrhythm', 'sumo logic'}
        if name_lower in siem_vendors or any(v in name_lower for v in siem_vendors):
            return 'enrich', {
                'integration': name_lower.replace(' ', '_'),
                'observable_type': 'query',
            }

        # Cloud providers
        cloud_vendors = {'aws', 'azure', 'gcp', 'google cloud'}
        if name_lower in cloud_vendors or any(v in name_lower for v in cloud_vendors):
            if any(word in cmd_lower for word in ['get', 'list', 'describe', 'search']):
                return 'enrich', {
                    'integration': name_lower.replace(' ', '_'),
                    'auto_mapped': True,
                }
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
                'original_action': command_name,
            }

        # Firewall vendors
        fw_vendors = {'palo alto', 'fortinet', 'fortigate', 'checkpoint', 'cisco', 'cisco asa'}
        if name_lower in fw_vendors or any(v in name_lower for v in fw_vendors):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'original_action': command_name,
            }

        # Email security vendors
        email_vendors = {'proofpoint', 'mimecast', 'barracuda', 'microsoft 365', 'exchange', 'google workspace'}
        if name_lower in email_vendors or any(v in name_lower for v in email_vendors):
            if any(word in cmd_lower for word in ['get', 'search', 'trace', 'find']):
                return 'enrich', {
                    'integration': name_lower.replace(' ', '_'),
                    'observable_type': 'email',
                }
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'original_action': command_name,
            }

        # Try inferring from command name keywords
        if any(word in cmd_lower for word in ['scan', 'lookup', 'get', 'search', 'check', 'query', 'report', 'find', 'list', 'describe']):
            return 'enrich', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        if any(word in cmd_lower for word in ['block', 'disable', 'isolate', 'contain', 'quarantine', 'kill', 'terminate', 'revoke', 'suspend', 'delete', 'remove']):
            return 'action', {
                'integration': name_lower.replace(' ', '_'),
                'requires_approval': True,
                'auto_mapped': True,
            }

        if any(word in cmd_lower for word in ['send', 'notify', 'post', 'message', 'alert']):
            return 'notify', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        if any(word in cmd_lower for word in ['create', 'ticket', 'incident', 'issue', 'case']):
            return 'create_ticket', {
                'integration': name_lower.replace(' ', '_'),
                'auto_mapped': True,
            }

        if any(word in cmd_lower for word in ['close', 'resolve', 'complete']):
            return 'end', {
                'disposition': 'completed',
                'auto_mapped': True,
            }

        # Truly unmapped
        return 'unmapped', {
            'original_action': f"{integration_name}.{command_name}",
        }
