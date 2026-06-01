# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Microsoft Sentinel (Azure Logic Apps) Playbook Converter

Converts Azure Logic Apps / Sentinel playbooks (exported as ARM templates)
to T1 Agentics native format.

Microsoft Sentinel playbooks are Azure Logic Apps exported as ARM templates (JSON).
Key structure:
- Top-level ARM template: { "$schema": "...", "resources": [{ "type": "Microsoft.Logic/workflows", ... }] }
- Or direct workflow: { "type": "Microsoft.Logic/workflows", "properties": { "definition": { ... } } }
- Or bare definition: { "definition": { "triggers": {...}, "actions": {...} } }
- Definition contains: triggers (dict), actions (flat dict), parameters, $connections
- Action types: ApiConnection, If, Foreach, Switch, Http, Compose, SetVariable,
  InitializeVariable, Terminate, ParseJson, Select, Join, Response, Delay, Wait
- Connector refs in: inputs.host.connection.name, inputs.host.apiId
  (e.g., azuresentinel, office365, azuread, teams, wdatp)
- runAfter dict on each action specifies dependencies: { "Previous_Action": ["Succeeded"] }
- Triggers: When_a_response_to_an_Azure_Sentinel_alert_is_triggered, Recurrence,
  When_Azure_Sentinel_incident_creation_rule_was_triggered
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import SENTINEL_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Sentinel-specific helpers
# ============================================================================

# Known Sentinel / Logic Apps connector API IDs (last segment of the managedApis path)
CONNECTOR_CATEGORIES: Dict[str, str] = {
    'azuresentinel': 'siem',
    'office365': 'email',
    'azuread': 'identity',
    'microsoftgraphsecurity': 'siem',
    'wdatp': 'edr',
    'teams': 'collaboration',
    'slack': 'collaboration',
    'virustotal': 'enrichment',
    'servicenow': 'ticketing',
    'jira': 'ticketing',
    'azureblob': 'storage',
    'azuremonitorlogs': 'siem',
    'keyvault': 'security',
}


def _sanitize_action_name(name: str) -> str:
    """
    Convert Logic Apps action name to a human-readable label.

    Logic Apps use underscored names like "Get_Incident_-_Entities" or
    "For_each_-_IP_Entity". Convert to readable form.
    """
    # Replace underscores and hyphens with spaces, collapse multiple spaces
    label = name.replace('_', ' ').replace('-', ' ')
    label = re.sub(r'\s+', ' ', label).strip()
    return label


def _extract_connection_name(inputs: Dict[str, Any]) -> Optional[str]:
    """
    Extract the connector / connection name from a Logic Apps action's inputs.

    Checks:
    - inputs.host.connection.name (ARM parameter reference or literal)
    - inputs.host.apiId (full resource path, e.g. /subscriptions/.../managedApis/azuresentinel)
    """
    host = inputs.get('host', {})
    if not isinstance(host, dict):
        return None

    # Try connection.name (may be an ARM expression or literal)
    connection = host.get('connection', {})
    if isinstance(connection, dict):
        conn_name = connection.get('name', '')
        if isinstance(conn_name, str) and conn_name:
            # ARM expression like "@parameters('$connections')['azuresentinel']['connectionId']"
            match = re.search(r"\['(\w+)'\]", conn_name)
            if match:
                return match.group(1).lower()
            # Literal name
            return conn_name.lower()

    # Try apiId (full resource path)
    api_id = host.get('apiId', '')
    if isinstance(api_id, str) and api_id:
        # Extract last path segment: .../managedApis/azuresentinel
        parts = api_id.rstrip('/').split('/')
        if parts:
            return parts[-1].lower()

    return None


def _resolve_run_after(actions: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Build a forward adjacency map from runAfter dependencies.

    Logic Apps encode edges via runAfter on each action:
      "Action_B": { "runAfter": { "Action_A": ["Succeeded"] } }

    Returns: { "Action_A": ["Action_B"], ... } (forward edges)
    """
    forward: Dict[str, List[str]] = {}
    for action_name, action_def in actions.items():
        if not isinstance(action_def, dict):
            continue
        run_after = action_def.get('runAfter', {})
        if not isinstance(run_after, dict):
            continue
        for predecessor in run_after:
            forward.setdefault(predecessor, []).append(action_name)
    return forward


def _find_root_actions(actions: Dict[str, Any]) -> List[str]:
    """Find actions with empty or missing runAfter (entry points)."""
    roots = []
    for action_name, action_def in actions.items():
        if not isinstance(action_def, dict):
            continue
        run_after = action_def.get('runAfter', {})
        if not run_after:
            roots.append(action_name)
    return roots


# ============================================================================
# Sentinel Converter
# ============================================================================

class SentinelConverter(PlaybookConverter):
    """
    Converter for Microsoft Sentinel playbooks (Azure Logic Apps).

    Handles three export formats:
    1. Full ARM template with resources array
    2. Direct Microsoft.Logic/workflows resource object
    3. Bare workflow definition (triggers + actions)

    Action types mapped:
    - ApiConnection: calls to Azure connectors (Sentinel, O365, AD, Defender, etc.)
    - Http: raw HTTP requests
    - If / Switch: conditional logic
    - Foreach / Until: iteration
    - Compose / ParseJson / Select / Join: data transformation
    - InitializeVariable / SetVariable / AppendToArrayVariable / IncrementVariable: variables
    - Terminate: end workflow
    - Delay / Wait: timing
    - Response: return data to caller
    """

    PLATFORM = SourcePlatform.SENTINEL

    def __init__(self):
        super().__init__(SENTINEL_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is a Microsoft Sentinel / Azure Logic Apps playbook."""
        try:
            data = json.loads(content)
            content_str = str(data).lower()[:3000]

            indicators = [
                'microsoft.logic/workflows' in content_str,
                '$connections' in content_str,
                'azuresentinel' in content_str,
                'managedapis' in content_str,
                'runafter' in content_str,
                'apiconnection' in content_str,
                # Direct definition format
                isinstance(data.get('properties', {}).get('definition'), dict),
                isinstance(data.get('definition'), dict),
                # ARM template with Logic Apps resource
                any(
                    'Microsoft.Logic/workflows' in str(r.get('type', ''))
                    for r in data.get('resources', [])
                    if isinstance(r, dict)
                ),
            ]

            return sum(bool(i) for i in indicators) >= 2

        except Exception:
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Sentinel / Logic Apps playbook JSON into intermediate format."""
        data = json.loads(content)

        # Extract the workflow definition from whichever format we received
        definition, metadata = self._extract_definition(data)

        if not definition:
            raise ValueError("Could not extract Logic Apps workflow definition from content")

        parsed = ParsedPlaybook(
            name=metadata.get('name', 'Imported Sentinel Playbook'),
            description=metadata.get('description', ''),
            platform=self.PLATFORM,
            version=metadata.get('version', '1.0'),
            raw=data
        )

        # Parse triggers
        triggers = definition.get('triggers', {})
        if isinstance(triggers, dict):
            for trigger_name, trigger_def in triggers.items():
                self._parse_trigger(trigger_name, trigger_def, parsed)

        # Parse actions (flat dict with runAfter-based ordering)
        actions = definition.get('actions', {})
        if isinstance(actions, dict):
            # Build forward adjacency map
            forward_edges = _resolve_run_after(actions)
            root_actions = _find_root_actions(actions)

            # Parse each action into a ParsedStep
            action_step_map: Dict[str, ParsedStep] = {}
            for action_name, action_def in actions.items():
                step = self._parse_action(action_name, action_def)
                if step:
                    parsed.steps.append(step)
                    action_step_map[action_name] = step

            # Wire up next_steps from forward adjacency
            for source_name, target_names in forward_edges.items():
                if source_name in action_step_map:
                    source_step = action_step_map[source_name]
                    for target_name in target_names:
                        if target_name in action_step_map:
                            target_step = action_step_map[target_name]
                            if target_step.id not in source_step.next_steps:
                                source_step.next_steps.append(target_step.id)

            # Connect triggers to root actions
            for trigger_info in parsed.triggers:
                trigger_step_id = trigger_info.get('step_id')
                if trigger_step_id:
                    # Find the trigger step in parsed.steps
                    for step in parsed.steps:
                        if step.id == trigger_step_id:
                            for root_name in root_actions:
                                if root_name in action_step_map:
                                    root_id = action_step_map[root_name].id
                                    if root_id not in step.next_steps:
                                        step.next_steps.append(root_id)

        # Extract parameters / variables
        parameters = definition.get('parameters', {})
        if isinstance(parameters, dict):
            parsed.variables = {
                k: v.get('defaultValue', v) if isinstance(v, dict) else v
                for k, v in parameters.items()
                if k != '$connections'  # Skip connection parameter
            }

        return parsed

    def _extract_definition(self, data: Dict[str, Any]) -> Tuple[Optional[Dict], Dict[str, Any]]:
        """
        Extract the Logic Apps workflow definition from various export formats.

        Returns: (definition_dict, metadata_dict)
        """
        metadata: Dict[str, Any] = {}

        # Format 1: ARM template with resources array
        resources = data.get('resources', [])
        if isinstance(resources, list):
            for resource in resources:
                if not isinstance(resource, dict):
                    continue
                res_type = resource.get('type', '')
                if 'Microsoft.Logic/workflows' in res_type:
                    props = resource.get('properties', {})
                    definition = props.get('definition', {})
                    metadata['name'] = resource.get('name', '').replace("'", '').strip('[]')
                    # Clean ARM parameter references from name
                    name = metadata['name']
                    if 'parameters(' in name:
                        # Try to extract the parameter name
                        match = re.search(r"parameters\('([^']+)'\)", name)
                        if match:
                            metadata['name'] = match.group(1).replace('PlaybookName', 'Sentinel Playbook')
                    metadata['description'] = props.get('description', '')
                    metadata['version'] = str(resource.get('apiVersion', '1.0'))
                    return definition, metadata

        # Format 2: Direct workflow object { "type": "Microsoft.Logic/workflows", "properties": { "definition": {...} } }
        if 'Microsoft.Logic/workflows' in str(data.get('type', '')):
            props = data.get('properties', {})
            definition = props.get('definition', {})
            metadata['name'] = data.get('name', 'Sentinel Playbook')
            metadata['description'] = props.get('description', '')
            return definition, metadata

        # Format 3: properties.definition at top level
        props = data.get('properties', {})
        if isinstance(props, dict) and 'definition' in props:
            definition = props.get('definition', {})
            metadata['name'] = data.get('name', props.get('name', 'Sentinel Playbook'))
            metadata['description'] = props.get('description', props.get('description', ''))
            return definition, metadata

        # Format 4: Bare definition (triggers + actions at top level or under 'definition')
        if 'definition' in data and isinstance(data['definition'], dict):
            definition = data['definition']
            metadata['name'] = data.get('name', 'Sentinel Playbook')
            metadata['description'] = data.get('description', '')
            return definition, metadata

        # Format 5: triggers and actions directly at top level
        if 'triggers' in data and 'actions' in data:
            metadata['name'] = data.get('name', 'Sentinel Playbook')
            metadata['description'] = data.get('description', '')
            return data, metadata

        return None, metadata

    def _parse_trigger(self, trigger_name: str, trigger_def: Dict[str, Any], parsed: ParsedPlaybook):
        """Parse a Logic Apps trigger into a ParsedStep and trigger metadata."""
        if not isinstance(trigger_def, dict):
            return

        trigger_type = trigger_def.get('type', 'unknown').lower()
        kind = trigger_def.get('kind', '').lower()

        # Determine T1 trigger type
        t1_trigger_type = 'alert'
        if 'recurrence' in trigger_type:
            t1_trigger_type = 'schedule'
        elif 'sentinel' in trigger_name.lower() or 'sentinel' in str(trigger_def).lower()[:500]:
            if 'incident' in trigger_name.lower():
                t1_trigger_type = 'sentinel_incident'
            else:
                t1_trigger_type = 'sentinel_alert'
        elif 'http' in trigger_type:
            t1_trigger_type = 'webhook'

        # Create step
        step = ParsedStep(
            id=f"trigger_{trigger_name}",
            name=_sanitize_action_name(trigger_name),
            step_type='trigger',
            config={
                'trigger_type': t1_trigger_type,
                'original_type': trigger_type,
                'kind': kind,
            },
            raw=trigger_def
        )

        # Extract recurrence details
        if t1_trigger_type == 'schedule':
            recurrence = trigger_def.get('recurrence', {})
            if isinstance(recurrence, dict):
                step.config['frequency'] = recurrence.get('frequency', '')
                step.config['interval'] = recurrence.get('interval', 1)

        parsed.steps.insert(0, step)
        parsed.triggers.append({
            'name': trigger_name,
            'type': t1_trigger_type,
            'step_id': step.id,
        })

    def _parse_action(self, action_name: str, action_def: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Logic Apps action into a ParsedStep."""
        if not isinstance(action_def, dict):
            return None

        action_type = action_def.get('type', 'unknown')
        action_type_lower = action_type.lower()
        inputs = action_def.get('inputs', {})
        if not isinstance(inputs, dict):
            inputs = {}

        step = ParsedStep(
            id=action_name,
            name=_sanitize_action_name(action_name),
            step_type=action_type_lower,
            raw=action_def
        )

        # Extract configuration based on action type
        if action_type_lower == 'apiconnection':
            step.config = self._parse_api_connection(action_name, inputs, action_def)
            # Resolve step_type to the connector name for better mapping
            connector = _extract_connection_name(inputs)
            if connector:
                step.step_type = f"apiconnection_{connector}"
                step.config['connector'] = connector

        elif action_type_lower == 'http':
            step.config = self._parse_http_action(inputs)

        elif action_type_lower == 'if':
            step.config = self._parse_if_action(action_def)
            # Parse nested branches
            self._parse_nested_branches(action_def, step)

        elif action_type_lower == 'switch':
            step.config = self._parse_switch_action(action_def)

        elif action_type_lower == 'foreach':
            step.config = self._parse_foreach_action(action_def)

        elif action_type_lower == 'until':
            step.config = {
                'limit_count': action_def.get('limit', {}).get('count', 60),
                'limit_timeout': action_def.get('limit', {}).get('timeout', 'PT1H'),
                'expression': str(action_def.get('expression', '')),
            }

        elif action_type_lower == 'compose':
            step.config = {
                'compose_input': inputs if not isinstance(inputs, dict) else inputs,
            }

        elif action_type_lower == 'parsejson':
            step.config = {
                'content': inputs.get('content', ''),
                'schema': inputs.get('schema', {}),
            }

        elif action_type_lower == 'select':
            step.config = {
                'from': inputs.get('from', ''),
                'select': inputs.get('select', {}),
            }

        elif action_type_lower in ('initializevariable', 'initialize_variable'):
            step.config = {
                'variable_name': inputs.get('variables', [{}])[0].get('name', '') if isinstance(inputs.get('variables'), list) and inputs.get('variables') else '',
                'variable_type': inputs.get('variables', [{}])[0].get('type', 'String') if isinstance(inputs.get('variables'), list) and inputs.get('variables') else 'String',
                'initial_value': inputs.get('variables', [{}])[0].get('value', '') if isinstance(inputs.get('variables'), list) and inputs.get('variables') else '',
            }

        elif action_type_lower in ('setvariable', 'set_variable'):
            step.config = {
                'variable_name': inputs.get('name', ''),
                'value': inputs.get('value', ''),
            }

        elif action_type_lower in ('appendtoarrayvariable', 'append_to_array_variable'):
            step.config = {
                'variable_name': inputs.get('name', ''),
                'value': inputs.get('value', ''),
                'append': True,
            }

        elif action_type_lower in ('incrementvariable', 'increment_variable'):
            step.config = {
                'variable_name': inputs.get('name', ''),
                'value': inputs.get('value', 1),
                'increment': True,
            }

        elif action_type_lower == 'terminate':
            step.config = {
                'status': inputs.get('runStatus', 'Succeeded'),
                'code': inputs.get('runError', {}).get('code', '') if isinstance(inputs.get('runError'), dict) else '',
                'message': inputs.get('runError', {}).get('message', '') if isinstance(inputs.get('runError'), dict) else '',
            }

        elif action_type_lower in ('delay', 'wait'):
            step.config = self._parse_delay_action(inputs)

        elif action_type_lower == 'response':
            step.config = {
                'status_code': inputs.get('statusCode', 200),
                'body': inputs.get('body', ''),
                'headers': inputs.get('headers', {}),
            }

        elif action_type_lower == 'scope':
            # Scope groups actions but has no direct equivalent; treat as passthrough
            step.config = {'scope_actions': list(action_def.get('actions', {}).keys())}

        else:
            # Unknown type: preserve inputs
            step.config = {'original_inputs': inputs}

        return step

    def _parse_api_connection(
        self,
        action_name: str,
        inputs: Dict[str, Any],
        action_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse an ApiConnection action's configuration."""
        config: Dict[str, Any] = {}

        # Method and path
        config['method'] = inputs.get('method', 'POST')
        path = inputs.get('path', '')
        config['path'] = path

        # Body
        body = inputs.get('body', {})
        if isinstance(body, dict):
            config['body'] = body
        elif body:
            config['body'] = str(body)

        # Headers
        headers = inputs.get('headers', {})
        if isinstance(headers, dict):
            config['headers'] = headers

        # Query parameters
        queries = inputs.get('queries', {})
        if isinstance(queries, dict) and queries:
            config['queries'] = queries

        # Extract connector info
        connector = _extract_connection_name(inputs)
        if connector:
            config['connector'] = connector
            config['connector_category'] = CONNECTOR_CATEGORIES.get(connector, 'unknown')

        # Try to determine the specific operation from the path
        if path:
            config['operation'] = self._infer_operation_from_path(path, config.get('method', 'POST'))

        return config

    def _parse_http_action(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an HTTP action's configuration."""
        return {
            'url': inputs.get('uri', inputs.get('url', '')),
            'method': inputs.get('method', 'GET'),
            'headers': inputs.get('headers', {}),
            'body': inputs.get('body', ''),
            'queries': inputs.get('queries', {}),
            'authentication': inputs.get('authentication', {}),
        }

    def _parse_if_action(self, action_def: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an If (condition) action."""
        expression = action_def.get('expression', {})
        config: Dict[str, Any] = {'condition_type': 'if'}

        if isinstance(expression, dict):
            # Logic Apps condition format: { "and": [{ "equals": ["@field", "value"] }] }
            for operator in ('and', 'or'):
                conditions = expression.get(operator, [])
                if isinstance(conditions, list) and conditions:
                    parsed_conditions = []
                    for cond in conditions:
                        if isinstance(cond, dict):
                            for op_name, operands in cond.items():
                                if isinstance(operands, list) and len(operands) >= 2:
                                    parsed_conditions.append({
                                        'field': str(operands[0]),
                                        'operator': op_name,
                                        'value': str(operands[1]),
                                    })
                    config['conditions'] = parsed_conditions
                    config['logic'] = operator
                    break

            # Single condition (no and/or wrapper)
            if 'conditions' not in config:
                for op_name, operands in expression.items():
                    if isinstance(operands, list) and len(operands) >= 2:
                        config['conditions'] = [{
                            'field': str(operands[0]),
                            'operator': op_name,
                            'value': str(operands[1]),
                        }]
                        break
        elif isinstance(expression, str):
            config['expression_raw'] = expression

        return config

    def _parse_switch_action(self, action_def: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Switch action."""
        expression = action_def.get('expression', '')
        cases = action_def.get('cases', {})
        default = action_def.get('default', {})

        config: Dict[str, Any] = {
            'condition_type': 'switch',
            'expression': str(expression),
            'cases': {},
        }

        if isinstance(cases, dict):
            for case_name, case_def in cases.items():
                if isinstance(case_def, dict):
                    config['cases'][case_name] = {
                        'value': case_def.get('case', ''),
                        'actions': list(case_def.get('actions', {}).keys()),
                    }

        if isinstance(default, dict) and 'actions' in default:
            config['default_actions'] = list(default['actions'].keys())

        return config

    def _parse_foreach_action(self, action_def: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Foreach loop action."""
        foreach_expr = action_def.get('foreach', '')
        actions = action_def.get('actions', {})

        return {
            'loop_type': 'foreach',
            'collection': str(foreach_expr),
            'child_actions': list(actions.keys()) if isinstance(actions, dict) else [],
            'concurrency': action_def.get('runtimeConfiguration', {}).get('concurrency', {}).get('repetitions', 1),
        }

    def _parse_delay_action(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Delay / Wait action inputs to seconds."""
        config: Dict[str, Any] = {}

        # Delay format: { "interval": { "count": 5, "unit": "Minute" } }
        interval = inputs.get('interval', {})
        if isinstance(interval, dict):
            count = interval.get('count', 0)
            unit = str(interval.get('unit', 'Second')).lower()
            multipliers = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400, 'week': 604800}
            config['duration_seconds'] = int(count) * multipliers.get(unit, 1)
        else:
            # ISO 8601 duration in 'until' field
            until = inputs.get('until', {})
            if isinstance(until, dict):
                config['until_timestamp'] = until.get('timestamp', '')
            config['duration_seconds'] = 60  # Default fallback

        return config

    def _parse_nested_branches(self, action_def: Dict[str, Any], parent_step: ParsedStep):
        """
        Record child actions from If/Switch branches for reference.

        Nested actions inside If branches are stored as metadata;
        the base converter's edge wiring handles the flat action list.
        """
        actions_if_true = action_def.get('actions', {})
        actions_if_false = action_def.get('else', {}).get('actions', {})

        if isinstance(actions_if_true, dict):
            parent_step.config['true_branch_actions'] = list(actions_if_true.keys())
        if isinstance(actions_if_false, dict):
            parent_step.config['false_branch_actions'] = list(actions_if_false.keys())

    def _infer_operation_from_path(self, path: str, method: str) -> str:
        """Infer a human-readable operation name from the API path."""
        path_lower = path.lower()

        # Sentinel-specific paths
        if '/incidents/' in path_lower:
            if method.upper() == 'GET':
                return 'get_incident'
            elif method.upper() in ('PUT', 'PATCH'):
                return 'update_incident'
        if '/entities/' in path_lower:
            return 'get_entities'
        if '/comments/' in path_lower:
            return 'add_comment'
        if '/bookmarks/' in path_lower:
            return 'manage_bookmark'

        # AD paths
        if '/users/' in path_lower:
            if 'revokeSignInSessions' in path:
                return 'revoke_sessions'
            if method.upper() == 'GET':
                return 'get_user'
            elif method.upper() in ('PATCH', 'PUT'):
                return 'update_user'
        if '/groups/' in path_lower:
            return 'manage_group'

        # Defender paths
        if '/machines/' in path_lower:
            if 'isolate' in path_lower:
                return 'isolate_machine'
            if 'unisolate' in path_lower:
                return 'unisolate_machine'
            if 'runAntivirusScan' in path:
                return 'run_antivirus_scan'
            return 'get_machine_info'

        # Generic
        if method.upper() == 'GET':
            return 'get_data'
        elif method.upper() == 'POST':
            return 'create_or_execute'
        elif method.upper() in ('PUT', 'PATCH'):
            return 'update'
        elif method.upper() == 'DELETE':
            return 'delete'

        return 'unknown_operation'

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a Sentinel / Logic Apps action type to native node type."""
        action_type = step.step_type
        config = step.config.copy()

        # ---- Trigger ----
        if action_type == 'trigger':
            return 'trigger', {
                'trigger_type': config.get('trigger_type', 'alert'),
            }

        # ---- ApiConnection (connector calls) ----
        if action_type.startswith('apiconnection'):
            return self._map_api_connection(step)

        # ---- HTTP ----
        if action_type == 'http':
            return self._map_http_action(step)

        # ---- Conditions ----
        if action_type == 'if':
            conditions = config.get('conditions', [])
            if conditions:
                first = conditions[0]
                return 'condition', {
                    'field': first.get('field', ''),
                    'operator': self._map_logic_apps_operator(first.get('operator', 'equals')),
                    'value': first.get('value', ''),
                    'logic': config.get('logic', 'and'),
                }
            return 'condition', {}

        if action_type == 'switch':
            return 'condition', {
                'condition_type': 'switch',
                'expression': config.get('expression', ''),
            }

        # ---- Loops ----
        if action_type in ('foreach', 'until'):
            return 'transform', {
                'transform_type': 'loop',
                'loop_type': config.get('loop_type', action_type),
                'collection': config.get('collection', ''),
            }

        # ---- Data transformation ----
        if action_type == 'compose':
            return 'transform', {
                'transform_type': 'compose',
            }

        if action_type == 'parsejson':
            return 'transform', {
                'transform_type': 'parse_json',
            }

        if action_type == 'select':
            return 'transform', {
                'transform_type': 'select',
            }

        if action_type == 'join':
            return 'transform', {
                'transform_type': 'join',
            }

        # ---- Variables ----
        if action_type in ('initializevariable', 'initialize_variable'):
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'variable_type': config.get('variable_type', 'String'),
                'static_value': config.get('initial_value', ''),
            }

        if action_type in ('setvariable', 'set_variable'):
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('value', ''),
            }

        if action_type in ('appendtoarrayvariable', 'append_to_array_variable'):
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('value', ''),
                'append': True,
            }

        if action_type in ('incrementvariable', 'increment_variable'):
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('value', 1),
                'increment': True,
            }

        # ---- Terminate ----
        if action_type == 'terminate':
            status = config.get('status', 'Succeeded').lower()
            disposition = 'completed' if status == 'succeeded' else 'failed'
            return 'end', {'disposition': disposition}

        # ---- Delay ----
        if action_type in ('delay', 'wait'):
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # ---- Response ----
        if action_type == 'response':
            return 'notify', {
                'channel': 'webhook_response',
                'status_code': config.get('status_code', 200),
            }

        # ---- Scope (group of actions) ----
        if action_type == 'scope':
            return 'transform', {
                'transform_type': 'scope',
                'child_actions': config.get('scope_actions', []),
            }

        # ---- Fallback: use action maps ----
        return find_best_mapping(action_type, 'sentinel')

    def _map_api_connection(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map an ApiConnection step based on its connector."""
        config = step.config
        connector = config.get('connector', '')
        operation = config.get('operation', '')
        path = config.get('path', '')

        # Build a lookup key for action maps: connector_operation
        if connector and operation:
            lookup_key = f"{connector}_{operation}"
            node_type, node_config = find_best_mapping(lookup_key, 'sentinel')
            if node_type != 'unmapped':
                return node_type, node_config

        # Try just the connector name
        if connector:
            node_type, node_config = find_best_mapping(connector, 'sentinel')
            if node_type != 'unmapped':
                return node_type, node_config

        # Connector-specific heuristics
        if connector == 'azuresentinel':
            return self._map_sentinel_connector(config)

        if connector in ('azuread', 'microsoftgraphidentity'):
            return self._map_ad_connector(config)

        if connector == 'wdatp':
            return self._map_defender_connector(config)

        if connector == 'office365':
            return self._map_office365_connector(config)

        if connector == 'teams':
            return 'notify', {'channel': 'teams'}

        if connector == 'slack':
            return 'notify', {'channel': 'slack'}

        if connector in ('servicenow', 'servicenowtable'):
            return 'create_ticket', {'integration': 'servicenow'}

        if connector == 'jira':
            return 'create_ticket', {'integration': 'jira'}

        if connector == 'virustotal':
            return 'enrich', {'integration': 'virustotal'}

        if connector in ('azuremonitorlogs', 'azureloganalytics'):
            return 'enrich', {'integration': 'azure_monitor', 'observable_type': 'query'}

        # Generic API connection - preserve connector info
        return 'action', {
            'integration': connector or 'azure_logic_apps',
            'auto_mapped': True,
            'original_connector': connector,
            'operation': operation,
        }

    def _map_sentinel_connector(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Map Azure Sentinel connector actions based on path."""
        path = config.get('path', '').lower()
        method = config.get('method', 'GET').upper()

        if '/entities/' in path:
            return 'enrich', {'integration': 'sentinel', 'observable_type': 'entities'}
        if '/comments/' in path:
            return 'action', {'action_type': 'add_comment', 'integration': 'sentinel'}
        if '/incidents/' in path:
            if method in ('PUT', 'PATCH'):
                return 'action', {'action_type': 'update_incident', 'integration': 'sentinel'}
            return 'enrich', {'integration': 'sentinel', 'observable_type': 'incident'}
        if '/bookmarks/' in path:
            return 'action', {'action_type': 'manage_bookmark', 'integration': 'sentinel'}

        return 'enrich', {'integration': 'sentinel'}

    def _map_ad_connector(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Map Azure AD connector actions."""
        path = config.get('path', '').lower()
        method = config.get('method', 'GET').upper()

        if 'revokesigninsessions' in path:
            return 'action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}
        if '/users/' in path:
            if method == 'GET':
                return 'enrich', {'integration': 'azure_ad', 'observable_type': 'user'}
            if method in ('PATCH', 'PUT'):
                # Could be disable or update
                body = config.get('body', {})
                if isinstance(body, dict) and body.get('accountEnabled') is False:
                    return 'action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}
                return 'action', {'action_type': 'update_user', 'integration': 'azure_ad'}
        if '/groups/' in path:
            return 'enrich', {'integration': 'azure_ad', 'observable_type': 'group'}

        return 'action', {'integration': 'azure_ad', 'auto_mapped': True}

    def _map_defender_connector(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Map Microsoft Defender for Endpoint connector actions."""
        path = config.get('path', '').lower()

        if 'isolate' in path:
            return 'action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}
        if 'unisolate' in path:
            return 'action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}
        if 'antivirusscan' in path or 'runantivirus' in path:
            return 'action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}
        if 'stopandquarantine' in path:
            return 'action', {'action_type': 'quarantine_file', 'integration': 'microsoft_defender', 'requires_approval': True}
        if 'investigationpackage' in path:
            return 'enrich', {'integration': 'microsoft_defender', 'observable_type': 'forensics'}
        if '/machines/' in path:
            return 'enrich', {'integration': 'microsoft_defender', 'observable_type': 'host'}

        return 'action', {'integration': 'microsoft_defender', 'auto_mapped': True}

    def _map_office365_connector(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Map Office 365 connector actions."""
        path = config.get('path', '').lower()
        method = config.get('method', 'GET').upper()

        if 'sendmail' in path or (method == 'POST' and '/mail/' in path):
            return 'notify', {'channel': 'email', 'integration': 'office365'}
        if 'delete' in path:
            return 'action', {'action_type': 'delete_email', 'integration': 'office365', 'requires_approval': True}
        if method == 'GET':
            return 'enrich', {'integration': 'office365', 'observable_type': 'email'}

        return 'action', {'integration': 'office365', 'auto_mapped': True}

    def _map_http_action(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map an HTTP action, trying to detect known services from URL."""
        config = step.config
        url = str(config.get('url', '')).lower()

        # Known enrichment services
        if 'virustotal' in url:
            return 'enrich', {'integration': 'virustotal'}
        if 'urlscan' in url:
            return 'enrich', {'integration': 'urlscan'}
        if 'shodan' in url:
            return 'enrich', {'integration': 'shodan'}
        if 'abuseipdb' in url:
            return 'enrich', {'integration': 'abuseipdb'}
        if 'greynoise' in url:
            return 'enrich', {'integration': 'greynoise'}
        if 'hybrid-analysis' in url or 'hybridanalysis' in url:
            return 'enrich', {'integration': 'hybrid_analysis'}

        # Known action services
        if 'crowdstrike' in url:
            return 'action', {'integration': 'crowdstrike', 'requires_approval': True}
        if 'sentinelone' in url:
            return 'action', {'integration': 'sentinelone', 'requires_approval': True}
        if 'servicenow' in url or 'service-now' in url:
            return 'create_ticket', {'integration': 'servicenow'}
        if 'jira' in url or 'atlassian' in url:
            return 'create_ticket', {'integration': 'jira'}
        if 'pagerduty' in url:
            return 'notify', {'integration': 'pagerduty'}
        if 'slack' in url:
            return 'notify', {'channel': 'slack'}
        if 'teams' in url or 'microsoft.com/webhook' in url:
            return 'notify', {'channel': 'teams'}

        # Azure-specific
        if 'management.azure.com' in url:
            return 'action', {'integration': 'azure', 'auto_mapped': True}
        if 'graph.microsoft.com' in url:
            return 'action', {'integration': 'microsoft_graph', 'auto_mapped': True}

        # Generic HTTP call
        return 'webhook_call', {
            'url': config.get('url', ''),
            'method': config.get('method', 'GET'),
        }

    def _map_logic_apps_operator(self, operator: str) -> str:
        """Map Logic Apps condition operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'not_equals': 'not_equals',
            'notequals': 'not_equals',
            'greater': 'greater_than',
            'greater_or_equals': 'greater_or_equal',
            'greaterorequals': 'greater_or_equal',
            'less': 'less_than',
            'less_or_equals': 'less_or_equal',
            'lessorequals': 'less_or_equal',
            'contains': 'contains',
            'not_contains': 'not_contains',
            'notcontains': 'not_contains',
            'startswith': 'starts_with',
            'endswith': 'ends_with',
            'isempty': 'is_empty',
            'isnotempty': 'is_not_empty',
        }
        return operator_map.get(operator.lower() if isinstance(operator, str) else 'equals', 'equals')
