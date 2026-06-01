# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
FortiSOAR (Fortinet) Playbook Converter

Converts FortiSOAR playbook exports to T1 Agentics native format.

FortiSOAR playbook structure:
- Top-level: { "type": "workflow", "name": "...", "steps": [...], "routes": [...] }
- Steps have: uuid, name, type, arguments, status
- Step types: startStep, endStep, executePlaybook, approval, manualInput,
  setVariable, api, connector, decision, delay
- Connector steps: arguments.connector (e.g., "VirusTotal", "CrowdStrike"),
  arguments.operation (e.g., "get_ip_reputation")
- API steps: arguments.uri, arguments.method
- Routes connect steps: { "sourceStep": "uuid", "targetStep": "uuid",
  "condition": "...", "label": "..." }
- Decision steps produce routes with conditions (e.g., "{{vars.result}} == true")
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import FORTISOAR_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# FortiSOAR-specific helpers
# ============================================================================

def _normalize_connector_name(connector: str) -> str:
    """
    Normalize FortiSOAR connector name to lowercase with underscores.

    FortiSOAR uses mixed case like "VirusTotal", "CrowdStrike Falcon",
    "Active Directory". Normalize for action map lookups.
    """
    if not connector:
        return ''
    # Insert underscore before uppercase runs, then lowercase everything
    normalized = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', connector)
    normalized = re.sub(r'\s+', '_', normalized)
    normalized = re.sub(r'_+', '_', normalized)
    return normalized.lower().strip('_')


def _build_lookup_key(connector: str, operation: str) -> str:
    """
    Build a lookup key from connector name and operation.

    E.g., ("VirusTotal", "get_ip_reputation") -> "virustotal_get_ip_reputation"
    """
    norm_connector = _normalize_connector_name(connector)
    norm_operation = operation.lower().replace('-', '_').replace(' ', '_') if operation else ''

    if norm_connector and norm_operation:
        return f"{norm_connector}_{norm_operation}"
    return norm_connector or norm_operation or ''


def _sanitize_step_name(name: str) -> str:
    """Clean up FortiSOAR step name for use as a label."""
    if not name:
        return 'Unnamed Step'
    # Replace underscores, collapse whitespace
    label = name.replace('_', ' ')
    label = re.sub(r'\s+', ' ', label).strip()
    return label


def _extract_step_position(step: Dict[str, Any]) -> Dict[str, int]:
    """
    Extract position coordinates from a FortiSOAR step.

    FortiSOAR may store position in 'left'/'top' or 'x'/'y' within the step
    or in a nested 'position' dict.
    """
    # Direct x/y on step
    if 'x' in step and 'y' in step:
        try:
            return {'x': int(step['x']), 'y': int(step['y'])}
        except (ValueError, TypeError):
            pass

    # left/top format
    if 'left' in step and 'top' in step:
        try:
            left = step['left']
            top = step['top']
            # May be strings like "250px"
            if isinstance(left, str):
                left = int(re.sub(r'[^\d-]', '', left) or 0)
            if isinstance(top, str):
                top = int(re.sub(r'[^\d-]', '', top) or 0)
            return {'x': int(left), 'y': int(top)}
        except (ValueError, TypeError):
            pass

    # Nested position dict
    position = step.get('position', {})
    if isinstance(position, dict):
        try:
            x = position.get('x', position.get('left', 0))
            y = position.get('y', position.get('top', 0))
            if isinstance(x, str):
                x = int(re.sub(r'[^\d-]', '', x) or 0)
            if isinstance(y, str):
                y = int(re.sub(r'[^\d-]', '', y) or 0)
            return {'x': int(x), 'y': int(y)}
        except (ValueError, TypeError):
            pass

    return {}


# ============================================================================
# FortiSOAR Converter
# ============================================================================

class FortiSOARConverter(PlaybookConverter):
    """
    Converter for FortiSOAR (Fortinet) playbooks.

    Step types handled:
    - startStep: Entry point of the playbook
    - endStep: Terminal step
    - connector: Integration call (VirusTotal, CrowdStrike, AD, FortiGate, etc.)
    - api: Raw HTTP API call
    - decision: Conditional branch
    - setVariable: Set workflow variable
    - delay: Wait/pause
    - approval: Human approval gate
    - manualInput: Manual analyst input
    - executePlaybook: Run a sub-playbook
    - createRecord / updateRecord / fetchRecord: CRUD on FortiSOAR records
    - codeSnippet: Custom Python/Jinja code
    """

    PLATFORM = SourcePlatform.FORTISOAR

    def __init__(self):
        super().__init__(FORTISOAR_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is a FortiSOAR playbook export."""
        try:
            data = json.loads(content)
            content_lower = str(data).lower()[:3000]

            indicators = [
                data.get('type') == 'workflow',
                isinstance(data.get('steps'), list),
                isinstance(data.get('routes'), list),
                # Routes contain sourceStep/targetStep
                any(
                    'sourceStep' in str(r) and 'targetStep' in str(r)
                    for r in data.get('routes', [])[:10]
                    if isinstance(r, dict)
                ),
                # Steps have uuid and type
                any(
                    'uuid' in str(s) and 'type' in str(s)
                    for s in data.get('steps', [])[:10]
                    if isinstance(s, dict)
                ),
                'fortisoar' in content_lower,
                'fortinet' in content_lower,
                # Step types typical of FortiSOAR
                any(
                    s.get('type') in ('startStep', 'endStep', 'connector', 'executePlaybook')
                    for s in data.get('steps', [])[:20]
                    if isinstance(s, dict)
                ),
                'arguments' in content_lower and 'connector' in content_lower,
            ]

            return sum(bool(i) for i in indicators) >= 3

        except Exception:
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse FortiSOAR playbook JSON into intermediate format."""
        data = json.loads(content)

        # Handle both single playbook and collection formats
        if isinstance(data, list) and data:
            # Array of playbooks — take the first one
            data = data[0]

        # Some exports wrap the playbook under a 'data' key
        if 'data' in data and isinstance(data['data'], dict):
            if 'steps' in data['data'] and 'routes' in data['data']:
                metadata_name = data.get('name', '')
                metadata_desc = data.get('description', '')
                data = data['data']
                data.setdefault('name', metadata_name)
                data.setdefault('description', metadata_desc)

        parsed = ParsedPlaybook(
            name=data.get('name', data.get('title', 'Imported FortiSOAR Playbook')),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', data.get('playbook_version', '1.0'))),
            raw=data
        )

        # Parse steps
        steps_list = data.get('steps', [])
        step_map: Dict[str, ParsedStep] = {}  # uuid → ParsedStep

        if isinstance(steps_list, list):
            for step_data in steps_list:
                step = self._parse_step(step_data)
                if step:
                    parsed.steps.append(step)
                    step_map[step.id] = step
        elif isinstance(steps_list, dict):
            # Some exports use dict keyed by UUID
            for step_uuid, step_data in steps_list.items():
                if isinstance(step_data, dict):
                    step_data.setdefault('uuid', step_uuid)
                    step = self._parse_step(step_data)
                    if step:
                        parsed.steps.append(step)
                        step_map[step.id] = step

        # Parse routes (edges between steps)
        routes = data.get('routes', [])
        if isinstance(routes, list):
            for route in routes:
                self._apply_route(route, step_map)

        # Identify triggers
        for step in parsed.steps:
            if step.step_type == 'startstep':
                trigger_type = 'alert'
                # Extract trigger type from startStep config
                if step.config.get('trigger_type'):
                    trigger_type = step.config['trigger_type']
                parsed.triggers.append({
                    'step_id': step.id,
                    'type': trigger_type,
                    'name': step.name,
                })

        # Extract workflow-level variables
        variables = data.get('variables', data.get('globalVariables', {}))
        if isinstance(variables, (dict, list)):
            if isinstance(variables, list):
                # Array of {name, value} dicts
                parsed.variables = {
                    v.get('name', f'var_{i}'): v.get('value', '')
                    for i, v in enumerate(variables)
                    if isinstance(v, dict)
                }
            else:
                parsed.variables = variables

        return parsed

    def _parse_step(self, step_data: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single FortiSOAR step into a ParsedStep."""
        if not isinstance(step_data, dict):
            return None

        step_uuid = str(step_data.get('uuid', step_data.get('id', step_data.get('@id', ''))))
        if not step_uuid:
            return None

        step_type = str(step_data.get('type', step_data.get('stepType', 'unknown'))).lower()
        step_name = step_data.get('name', step_data.get('title', f'Step {step_uuid[:8]}'))

        step = ParsedStep(
            id=step_uuid,
            name=_sanitize_step_name(step_name),
            step_type=step_type,
            position=_extract_step_position(step_data),
            raw=step_data
        )

        # Extract configuration based on step type
        arguments = step_data.get('arguments', {})
        if not isinstance(arguments, dict):
            arguments = {}

        if step_type == 'startstep':
            step.config = self._parse_start_step(step_data, arguments)

        elif step_type == 'endstep':
            step.config = self._parse_end_step(step_data, arguments)

        elif step_type == 'connector':
            step.config = self._parse_connector_step(arguments, step_data)

        elif step_type == 'api':
            step.config = self._parse_api_step(arguments)

        elif step_type == 'decision':
            step.config = self._parse_decision_step(step_data, arguments)

        elif step_type in ('setvariable', 'set_variable'):
            step.config = self._parse_set_variable_step(arguments)

        elif step_type == 'delay':
            step.config = self._parse_delay_step(arguments)

        elif step_type == 'approval':
            step.config = self._parse_approval_step(arguments, step_data)

        elif step_type in ('manualinput', 'manual_input'):
            step.config = self._parse_manual_input_step(arguments, step_data)

        elif step_type in ('executeplaybook', 'execute_playbook'):
            step.config = self._parse_execute_playbook_step(arguments)

        elif step_type in ('createrecord', 'create_record'):
            step.config = self._parse_record_step('create', arguments)

        elif step_type in ('updaterecord', 'update_record'):
            step.config = self._parse_record_step('update', arguments)

        elif step_type in ('fetchrecord', 'fetch_record'):
            step.config = self._parse_record_step('fetch', arguments)

        elif step_type in ('codesnippet', 'code_snippet'):
            step.config = self._parse_code_snippet_step(arguments)

        else:
            # Unknown step type — preserve arguments
            step.config = {'original_arguments': arguments}

        return step

    def _parse_start_step(self, step_data: Dict[str, Any], arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a startStep's configuration."""
        config: Dict[str, Any] = {'trigger_type': 'alert'}

        # FortiSOAR may specify a trigger type
        trigger_type = arguments.get('triggerType', arguments.get('trigger_type', ''))
        if trigger_type:
            trigger_type_lower = trigger_type.lower()
            if 'schedule' in trigger_type_lower or 'cron' in trigger_type_lower:
                config['trigger_type'] = 'schedule'
            elif 'manual' in trigger_type_lower:
                config['trigger_type'] = 'manual'
            elif 'webhook' in trigger_type_lower or 'api' in trigger_type_lower:
                config['trigger_type'] = 'webhook'
            elif 'record' in trigger_type_lower:
                config['trigger_type'] = 'record_event'
            else:
                config['trigger_type'] = trigger_type_lower

        # Record type / module trigger
        resource = arguments.get('resource', arguments.get('module', ''))
        if resource:
            config['resource'] = resource

        # Schedule
        schedule = arguments.get('schedule', arguments.get('cron', ''))
        if schedule:
            config['schedule'] = schedule

        # Conditions / filters
        conditions = arguments.get('conditions', arguments.get('filters', []))
        if conditions:
            config['conditions'] = conditions

        return config

    def _parse_end_step(self, step_data: Dict[str, Any], arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an endStep's configuration."""
        return {
            'disposition': arguments.get('status', arguments.get('disposition', 'completed')).lower(),
        }

    def _parse_connector_step(self, arguments: Dict[str, Any], step_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a connector step's configuration."""
        config: Dict[str, Any] = {}

        connector = arguments.get('connector', arguments.get('connectorName', ''))
        operation = arguments.get('operation', arguments.get('action', ''))

        config['connector'] = connector
        config['operation'] = operation
        config['connector_normalized'] = _normalize_connector_name(connector)

        # Extract input parameters
        params = arguments.get('params', arguments.get('parameters', arguments.get('input', {})))
        if isinstance(params, dict):
            config['params'] = params
        elif isinstance(params, list):
            # Some connectors use positional params
            config['params_list'] = params

        # Connector version
        config['connector_version'] = arguments.get('version', arguments.get('connectorVersion', ''))

        # Timeout
        timeout = arguments.get('timeout', arguments.get('operationTimeout', ''))
        if timeout:
            config['timeout'] = timeout

        return config

    def _parse_api_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an API step's configuration."""
        return {
            'uri': arguments.get('uri', arguments.get('url', '')),
            'method': arguments.get('method', 'GET').upper(),
            'headers': arguments.get('headers', {}),
            'body': arguments.get('body', arguments.get('payload', '')),
            'auth': arguments.get('auth', arguments.get('authentication', {})),
            'verify_ssl': arguments.get('verify', arguments.get('verify_ssl', True)),
        }

    def _parse_decision_step(self, step_data: Dict[str, Any], arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a decision step's configuration."""
        config: Dict[str, Any] = {'condition_type': 'decision'}

        # FortiSOAR decisions can have conditions in arguments or in the step itself
        conditions = arguments.get('conditions', arguments.get('rules', []))
        if isinstance(conditions, list) and conditions:
            parsed_conditions = []
            for cond in conditions:
                if isinstance(cond, dict):
                    parsed_conditions.append({
                        'field': cond.get('field', cond.get('input', '')),
                        'operator': cond.get('operator', cond.get('condition', 'equals')),
                        'value': cond.get('value', cond.get('expected', '')),
                    })
                elif isinstance(cond, str):
                    # Expression string like "{{vars.result}} == true"
                    parsed_conditions.append({'expression': cond})
            config['conditions'] = parsed_conditions

        # Single expression
        expression = arguments.get('expression', arguments.get('condition', ''))
        if expression and not conditions:
            config['expression'] = str(expression)

        return config

    def _parse_set_variable_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a setVariable step's configuration."""
        config: Dict[str, Any] = {}

        # May set a single variable or multiple
        variable_name = arguments.get('name', arguments.get('variable', ''))
        value = arguments.get('value', arguments.get('expression', ''))

        if variable_name:
            config['variable_name'] = variable_name
            config['value'] = value
        else:
            # Multiple variables
            variables = arguments.get('variables', {})
            if isinstance(variables, dict):
                config['variables'] = variables
            elif isinstance(variables, list):
                config['variables'] = {
                    v.get('name', f'var_{i}'): v.get('value', '')
                    for i, v in enumerate(variables)
                    if isinstance(v, dict)
                }

        return config

    def _parse_delay_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a delay step's configuration."""
        duration = arguments.get('delay', arguments.get('duration', arguments.get('seconds', 60)))
        unit = arguments.get('unit', arguments.get('delayUnit', 'seconds')).lower()

        # Convert to seconds
        try:
            duration_val = int(duration)
        except (ValueError, TypeError):
            duration_val = 60

        multipliers = {'seconds': 1, 'second': 1, 'minutes': 60, 'minute': 60,
                       'hours': 3600, 'hour': 3600, 'days': 86400, 'day': 86400}
        duration_seconds = duration_val * multipliers.get(unit, 1)

        return {
            'duration_seconds': duration_seconds,
            'original_duration': duration,
            'original_unit': unit,
        }

    def _parse_approval_step(self, arguments: Dict[str, Any], step_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an approval step's configuration."""
        return {
            'message': arguments.get('message', arguments.get('description', '')),
            'title': arguments.get('title', step_data.get('name', 'Approval Required')),
            'assignees': arguments.get('assignees', arguments.get('approvers', [])),
            'timeout_minutes': self._parse_timeout(arguments.get('timeout', arguments.get('expiresIn', ''))),
            'approval_type': arguments.get('type', arguments.get('approvalType', 'manual')),
        }

    def _parse_manual_input_step(self, arguments: Dict[str, Any], step_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a manualInput step's configuration."""
        config: Dict[str, Any] = {
            'message': arguments.get('message', arguments.get('description', '')),
            'title': arguments.get('title', step_data.get('name', 'Manual Input Required')),
            'assignees': arguments.get('assignees', arguments.get('owners', [])),
            'input_type': 'manual',
        }

        # Extract form fields if present
        fields = arguments.get('fields', arguments.get('inputs', arguments.get('questions', [])))
        if isinstance(fields, list):
            config['fields'] = [
                {
                    'name': f.get('name', f.get('id', '')),
                    'label': f.get('label', f.get('title', '')),
                    'type': f.get('type', 'text'),
                    'required': f.get('required', False),
                }
                for f in fields
                if isinstance(f, dict)
            ]

        return config

    def _parse_execute_playbook_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an executePlaybook step's configuration."""
        return {
            'playbook_name': arguments.get('playbook', arguments.get('playbookName', arguments.get('name', ''))),
            'playbook_id': arguments.get('playbookId', arguments.get('playbook_id', '')),
            'input_params': arguments.get('input', arguments.get('params', arguments.get('parameters', {}))),
            'wait_for_completion': arguments.get('waitForCompletion', arguments.get('synchronous', True)),
        }

    def _parse_record_step(self, operation: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a record CRUD step's configuration."""
        return {
            'operation': operation,
            'module': arguments.get('module', arguments.get('resource', arguments.get('type', ''))),
            'record_id': arguments.get('id', arguments.get('recordId', arguments.get('@id', ''))),
            'data': arguments.get('data', arguments.get('body', arguments.get('fields', {}))),
            'filters': arguments.get('filters', arguments.get('conditions', [])),
        }

    def _parse_code_snippet_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a codeSnippet step's configuration."""
        return {
            'code': arguments.get('code', arguments.get('script', arguments.get('snippet', ''))),
            'language': arguments.get('language', arguments.get('lang', 'python')),
            'inputs': arguments.get('inputs', arguments.get('params', {})),
        }

    def _apply_route(self, route: Dict[str, Any], step_map: Dict[str, ParsedStep]):
        """Apply a route (edge) between two steps."""
        if not isinstance(route, dict):
            return

        source_id = str(route.get('sourceStep', route.get('source', route.get('from', ''))))
        target_id = str(route.get('targetStep', route.get('target', route.get('to', ''))))

        if not source_id or not target_id:
            return

        source_step = step_map.get(source_id)
        if not source_step:
            return

        # Check target exists
        if target_id not in step_map:
            return

        # Add the connection
        if target_id not in source_step.next_steps:
            source_step.next_steps.append(target_id)

        # Store condition on the source step if present
        condition = route.get('condition', route.get('expression', ''))
        label = route.get('label', route.get('name', ''))
        if condition:
            # For decision steps, store condition info
            if not source_step.condition:
                source_step.condition = str(condition)
            # Also store labeled conditions for multi-branch decisions
            if label:
                conditions_map = source_step.config.setdefault('route_conditions', {})
                conditions_map[target_id] = {
                    'condition': str(condition),
                    'label': label,
                }

    def _parse_timeout(self, timeout_value) -> int:
        """Parse timeout value to minutes."""
        if not timeout_value:
            return 10080  # 7 days default

        if isinstance(timeout_value, (int, float)):
            return int(timeout_value)

        try:
            timeout_str = str(timeout_value).lower().strip()

            if timeout_str.endswith('d'):
                return int(timeout_str[:-1]) * 1440
            elif timeout_str.endswith('h'):
                return int(timeout_str[:-1]) * 60
            elif timeout_str.endswith('m'):
                return int(timeout_str[:-1])
            elif timeout_str.endswith('s'):
                return max(1, int(timeout_str[:-1]) // 60)
            else:
                return int(timeout_str)
        except (ValueError, TypeError):
            return 10080

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a FortiSOAR step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # ---- Start Step ----
        if step_type == 'startstep':
            return 'trigger', {
                'trigger_type': config.get('trigger_type', 'alert'),
            }

        # ---- End Step ----
        if step_type == 'endstep':
            return 'end', {
                'disposition': config.get('disposition', 'completed'),
            }

        # ---- Connector Step ----
        if step_type == 'connector':
            return self._map_connector_step(step)

        # ---- API Step ----
        if step_type == 'api':
            return self._map_api_step(step)

        # ---- Decision ----
        if step_type == 'decision':
            conditions = config.get('conditions', [])
            if conditions and isinstance(conditions, list) and isinstance(conditions[0], dict):
                first = conditions[0]
                if 'expression' in first:
                    return 'condition', {
                        'expression': first['expression'],
                    }
                return 'condition', {
                    'field': first.get('field', ''),
                    'operator': self._map_fortisoar_operator(first.get('operator', 'equals')),
                    'value': first.get('value', ''),
                }
            expression = config.get('expression', '')
            if expression:
                return 'condition', {'expression': expression}
            return 'condition', {}

        # ---- Set Variable ----
        if step_type in ('setvariable', 'set_variable'):
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('value', ''),
                'variables': config.get('variables', {}),
            }

        # ---- Delay ----
        if step_type == 'delay':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # ---- Approval ----
        if step_type == 'approval':
            return 'approval_gate', {
                'message': config.get('message', ''),
                'title': config.get('title', ''),
                'timeout_minutes': config.get('timeout_minutes', 10080),
            }

        # ---- Manual Input ----
        if step_type in ('manualinput', 'manual_input'):
            fields = config.get('fields', [])
            if fields:
                return 'webform', {
                    'fields': fields,
                    'message': config.get('message', ''),
                }
            return 'approval_gate', {
                'message': config.get('message', ''),
                'input_type': 'manual',
            }

        # ---- Execute Playbook ----
        if step_type in ('executeplaybook', 'execute_playbook'):
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', ''),
                'playbook_id': config.get('playbook_id', ''),
            }

        # ---- Record Operations ----
        if step_type in ('createrecord', 'create_record'):
            return 'action', {
                'action_type': 'create_record',
                'module': config.get('module', ''),
            }

        if step_type in ('updaterecord', 'update_record'):
            return 'action', {
                'action_type': 'update_record',
                'module': config.get('module', ''),
            }

        if step_type in ('fetchrecord', 'fetch_record'):
            return 'enrich', {
                'observable_type': 'record',
                'module': config.get('module', ''),
            }

        # ---- Code Snippet ----
        if step_type in ('codesnippet', 'code_snippet'):
            return 'python_code', {
                'code': config.get('code', ''),
                'language': config.get('language', 'python'),
            }

        # ---- Fallback: use action maps ----
        return find_best_mapping(step_type, 'fortisoar')

    def _map_connector_step(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a FortiSOAR connector step based on connector name and operation."""
        config = step.config
        connector = config.get('connector', '')
        operation = config.get('operation', '')
        connector_norm = config.get('connector_normalized', _normalize_connector_name(connector))

        # Build lookup key and try action maps
        lookup_key = _build_lookup_key(connector, operation)
        if lookup_key:
            node_type, node_config = find_best_mapping(lookup_key, 'fortisoar')
            if node_type != 'unmapped':
                return node_type, node_config

        # Try just the connector name
        if connector_norm:
            node_type, node_config = find_best_mapping(connector_norm, 'fortisoar')
            if node_type != 'unmapped':
                return node_type, node_config

        # Connector-specific heuristics based on known families
        return self._map_connector_by_name(connector_norm, operation, config)

    def _map_connector_by_name(
        self,
        connector: str,
        operation: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map a connector step using connector name heuristics."""
        operation_lower = operation.lower() if operation else ''

        # Enrichment connectors
        enrichment_connectors = {
            'virustotal', 'virus_total', 'urlscan', 'url_scan', 'shodan',
            'abuseipdb', 'abuse_ip_db', 'whois', 'greynoise', 'grey_noise',
            'hybrid_analysis', 'pulsedive', 'misp', 'otx', 'alien_vault',
            'maxmind', 'ip_info', 'ipinfo', 'recorded_future', 'anomali',
            'threat_connect',
        }
        for enrich_name in enrichment_connectors:
            if enrich_name in connector:
                return 'enrich', {
                    'integration': connector.replace('_', ''),
                    'operation': operation,
                }

        # EDR / Endpoint connectors
        edr_connectors = {
            'crowdstrike': 'crowdstrike',
            'crowd_strike': 'crowdstrike',
            'sentinelone': 'sentinelone',
            'sentinel_one': 'sentinelone',
            'carbon_black': 'carbon_black',
            'microsoft_defender': 'microsoft_defender',
            'cortex_xdr': 'cortex_xdr',
            'cylance': 'cylance',
        }
        for edr_key, edr_integration in edr_connectors.items():
            if edr_key in connector:
                # Determine if enrichment or containment action
                if any(word in operation_lower for word in ['get', 'search', 'list', 'query', 'find', 'lookup']):
                    return 'enrich', {'integration': edr_integration, 'observable_type': 'host'}
                if any(word in operation_lower for word in ['contain', 'isolate', 'disconnect']):
                    return 'action', {'action_type': 'contain_host', 'integration': edr_integration, 'requires_approval': True}
                if any(word in operation_lower for word in ['uncontain', 'unisolate', 'reconnect', 'lift']):
                    return 'action', {'action_type': 'uncontain_host', 'integration': edr_integration, 'requires_approval': True}
                return 'action', {'integration': edr_integration, 'requires_approval': True}

        # Firewall / Network connectors
        firewall_connectors = {'fortigate', 'forti_gate', 'palo_alto', 'panorama', 'cisco_asa', 'fortios'}
        for fw_name in firewall_connectors:
            if fw_name in connector:
                if any(word in operation_lower for word in ['block', 'deny', 'quarantine']):
                    return 'action', {'action_type': 'block_ip', 'integration': connector, 'requires_approval': True}
                if any(word in operation_lower for word in ['unblock', 'allow', 'permit']):
                    return 'action', {'action_type': 'unblock_ip', 'integration': connector, 'requires_approval': True}
                if any(word in operation_lower for word in ['get', 'list', 'search']):
                    return 'enrich', {'integration': connector, 'observable_type': 'policy'}
                return 'action', {'integration': connector, 'requires_approval': True}

        # Identity connectors
        identity_connectors = {
            'active_directory', 'activedirectory', 'ldap', 'okta', 'azure_ad',
            'azure_active_directory', 'one_identity', 'ping_identity',
        }
        for id_name in identity_connectors:
            if id_name in connector:
                if any(word in operation_lower for word in ['disable', 'deactivate', 'suspend']):
                    return 'action', {'action_type': 'disable_user', 'integration': connector, 'requires_approval': True}
                if any(word in operation_lower for word in ['enable', 'activate']):
                    return 'action', {'action_type': 'enable_user', 'integration': connector, 'requires_approval': True}
                if 'reset' in operation_lower and 'password' in operation_lower:
                    return 'action', {'action_type': 'reset_password', 'integration': connector, 'requires_approval': True}
                if 'revoke' in operation_lower or 'clear_session' in operation_lower:
                    return 'action', {'action_type': 'revoke_sessions', 'integration': connector, 'requires_approval': True}
                if any(word in operation_lower for word in ['get', 'search', 'list', 'lookup', 'find']):
                    return 'enrich', {'integration': connector, 'observable_type': 'user'}
                return 'action', {'integration': connector}

        # SIEM connectors
        siem_connectors = {'fortisiem', 'forti_siem', 'splunk', 'qradar', 'elastic', 'sentinel', 'chronicle'}
        for siem_name in siem_connectors:
            if siem_name in connector:
                return 'enrich', {'integration': connector, 'observable_type': 'events'}

        # Ticketing connectors
        ticketing_connectors = {'servicenow', 'service_now', 'jira', 'zendesk', 'bmc_remedy'}
        for ticket_name in ticketing_connectors:
            if ticket_name in connector:
                if any(word in operation_lower for word in ['create', 'open', 'new']):
                    return 'create_ticket', {'integration': connector}
                if any(word in operation_lower for word in ['update', 'modify', 'edit']):
                    return 'action', {'action_type': 'update_ticket', 'integration': connector}
                if any(word in operation_lower for word in ['close', 'resolve']):
                    return 'action', {'action_type': 'close_ticket', 'integration': connector}
                if any(word in operation_lower for word in ['get', 'search', 'list', 'fetch']):
                    return 'enrich', {'integration': connector, 'observable_type': 'ticket'}
                return 'create_ticket', {'integration': connector}

        # Notification connectors
        notification_connectors = {
            'smtp': 'email', 'email': 'email', 'exchange': 'email',
            'slack': 'slack', 'teams': 'teams', 'microsoft_teams': 'teams',
            'pagerduty': 'pagerduty', 'opsgenie': 'opsgenie',
        }
        for notif_name, channel in notification_connectors.items():
            if notif_name in connector:
                return 'notify', {'channel': channel, 'integration': connector}

        # Generic fallback — try to guess from operation name
        if any(word in operation_lower for word in ['enrich', 'lookup', 'reputation', 'get_', 'scan', 'search', 'check']):
            return 'enrich', {'integration': connector, 'auto_mapped': True}
        if any(word in operation_lower for word in ['block', 'disable', 'quarantine', 'isolate', 'contain']):
            return 'action', {'integration': connector, 'requires_approval': True, 'auto_mapped': True}
        if any(word in operation_lower for word in ['notify', 'send', 'email', 'message']):
            return 'notify', {'integration': connector, 'auto_mapped': True}
        if any(word in operation_lower for word in ['create_ticket', 'create_incident', 'open_ticket']):
            return 'create_ticket', {'integration': connector, 'auto_mapped': True}

        # Complete fallback
        return 'action', {
            'integration': connector or 'fortisoar',
            'operation': operation,
            'auto_mapped': True,
        }

    def _map_api_step(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a FortiSOAR API step based on URI and method."""
        config = step.config
        uri = str(config.get('uri', '')).lower()
        method = config.get('method', 'GET')

        # Check for known services in the URI
        if 'virustotal' in uri:
            return 'enrich', {'integration': 'virustotal'}
        if 'urlscan' in uri:
            return 'enrich', {'integration': 'urlscan'}
        if 'shodan' in uri:
            return 'enrich', {'integration': 'shodan'}
        if 'abuseipdb' in uri:
            return 'enrich', {'integration': 'abuseipdb'}
        if 'greynoise' in uri:
            return 'enrich', {'integration': 'greynoise'}

        if 'crowdstrike' in uri:
            return 'action', {'integration': 'crowdstrike', 'requires_approval': True}
        if 'sentinelone' in uri:
            return 'action', {'integration': 'sentinelone', 'requires_approval': True}
        if 'servicenow' in uri or 'service-now' in uri:
            return 'create_ticket', {'integration': 'servicenow'}
        if 'jira' in uri or 'atlassian' in uri:
            return 'create_ticket', {'integration': 'jira'}
        if 'slack' in uri:
            return 'notify', {'channel': 'slack'}
        if 'teams' in uri or 'microsoft.com/webhook' in uri:
            return 'notify', {'channel': 'teams'}

        # Generic HTTP call
        return 'webhook_call', {
            'url': config.get('uri', ''),
            'method': method,
        }

    def _map_fortisoar_operator(self, operator: str) -> str:
        """Map FortiSOAR condition operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'eq': 'equals',
            '==': 'equals',
            'not_equals': 'not_equals',
            'neq': 'not_equals',
            '!=': 'not_equals',
            'contains': 'contains',
            'not_contains': 'not_contains',
            'does_not_contain': 'not_contains',
            'starts_with': 'starts_with',
            'ends_with': 'ends_with',
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
        }
        return operator_map.get(operator.lower() if isinstance(operator, str) else 'equals', 'equals')
