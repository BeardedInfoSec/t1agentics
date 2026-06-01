# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ServiceNow Security Operations (Flow Designer) Playbook Converter

Converts ServiceNow SecOps Flow Designer workflows to T1 Agentics native format.

ServiceNow Security Operations uses Flow Designer to define automated workflows
for security incident response, vulnerability management, and threat intelligence.

Export formats supported:
1. Flow Designer JSON export:
   {
     "sys_id": "...", "name": "...", "description": "...",
     "flow_type": "flow|subflow|action",
     "trigger": { "type": "...", "conditions": [...] },
     "operations": [ { "sys_id": "...", "name": "...", "type_id": "...", ... } ],
     "data_model": { ... }
   }

2. Update set XML converted to JSON:
   {
     "sys_class_name": "sys_hub_flow",
     "name": "...",
     "operations": "..."
   }

Operations structure:
- Each operation has: sys_id, name, type_id (action|flow_logic|subflow),
  action_type, inputs, outputs, order
- Action types: sn_si.create_security_incident, sn_si.update_security_incident,
  sn_si.add_observable, global.run_script, global.http, global.send_email,
  global.slack_post, global.approval, global.wait_for, global.if, etc.
- Flow logic: if_then, else_if, for_each, do_until, parallel, try_catch
- Trigger types: record_created, record_updated, scheduled, inbound_email, rest_api
- Data pillars: {{trigger.current.field_name}}
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import SERVICENOW_SECOPS_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# ServiceNow flow logic type -> native node type
# ============================================================================

FLOW_LOGIC_MAP: Dict[str, str] = {
    'if_then': 'condition',
    'else_if': 'condition',
    'else': 'condition',
    'for_each': 'transform',
    'do_until': 'transform',
    'parallel': 'transform',
    'try_catch': 'transform',
    'try': 'transform',
    'catch': 'action',
    'finally': 'action',
    'break': 'action',
    'return': 'end',
}


# ============================================================================
# Trigger type normalization
# ============================================================================

TRIGGER_TYPE_MAP: Dict[str, str] = {
    'record_created': 'alert',
    'record_updated': 'alert',
    'scheduled': 'schedule',
    'inbound_email': 'email',
    'rest_api': 'webhook',
    'si_incident_created': 'alert',
    'si_incident_updated': 'alert',
    'manual': 'manual',
    'service_catalog': 'webhook',
    'metric_trigger': 'alert',
    'inbound_action': 'webhook',
}


class ServiceNowSecOpsConverter(PlaybookConverter):
    """
    Converter for ServiceNow Security Operations (Flow Designer) workflows.

    ServiceNow SecOps uses Flow Designer to build automated security response
    workflows. These are exported as JSON with an operations array containing
    sequenced actions, flow logic (conditionals, loops), and subflow calls.

    Operation type_id values:
    - "action": Execute a specific spoke/built-in action
    - "flow_logic": Conditionals, loops, parallel branching
    - "subflow": Invoke another flow as a child

    Action types are namespaced:
    - sn_si.*: Security Incident Response actions
    - sn_vul.*: Vulnerability Response actions
    - sn_ti.*: Threat Intelligence actions
    - global.*: Built-in Flow Designer actions (HTTP, email, scripts)
    - Spoke actions: crowdstrike.*, palo_alto.*, okta.*, etc.
    """

    PLATFORM = SourcePlatform.SERVICENOW_SECOPS

    def __init__(self):
        super().__init__(SERVICENOW_SECOPS_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is from ServiceNow Security Operations Flow Designer."""
        try:
            data = json.loads(content)

            if not isinstance(data, dict):
                return False

            content_lower = str(data).lower()[:3000]

            indicators = [
                # Primary: sys_id + operations array
                'sys_id' in data and isinstance(data.get('operations'), list),
                # Flow type field
                data.get('flow_type') in ('flow', 'subflow', 'action'),
                # Update set format
                data.get('sys_class_name') in (
                    'sys_hub_flow', 'sys_hub_action_type_definition',
                    'sys_hub_sub_flow'
                ),
                # Operations with type_id
                isinstance(data.get('operations'), list) and any(
                    isinstance(op, dict) and 'type_id' in op
                    for op in data.get('operations', [])[:10]
                ),
                # sn_si. prefixed action types
                'sn_si.' in content_lower,
                # sn_vul. prefixed action types
                'sn_vul.' in content_lower,
                # sn_ti. prefixed action types
                'sn_ti.' in content_lower,
                # ServiceNow naming conventions
                'servicenow' in content_lower or 'service-now' in content_lower,
                # Data pillar references
                '{{trigger.' in str(data)[:2000],
                # sys_hub prefix in class names
                'sys_hub' in content_lower,
                # Flow designer metadata
                'data_model' in data,
                # Operations with action_type containing dots (namespace.action)
                isinstance(data.get('operations'), list) and any(
                    isinstance(op, dict) and '.' in str(op.get('action_type', ''))
                    for op in data.get('operations', [])[:10]
                ),
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse ServiceNow Flow Designer workflow export."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('name', data.get('title', 'ServiceNow SecOps Flow')),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', data.get('sys_mod_count', '1.0'))),
            raw=data,
        )

        # Parse trigger
        trigger_data = data.get('trigger', {})
        if trigger_data:
            parsed.triggers.append(self._parse_trigger(trigger_data))

        # Parse operations
        operations = self._extract_operations(data)
        step_map: Dict[str, ParsedStep] = {}

        for i, op in enumerate(operations):
            step = self._parse_operation(op, i)
            if step:
                parsed.steps.append(step)
                step_map[step.id] = step

        # Build edges from sequential order and flow logic nesting
        self._build_edges(parsed.steps, operations, step_map)

        # Extract variables from data_model
        data_model = data.get('data_model', {})
        if isinstance(data_model, dict):
            for var_name, var_def in data_model.items():
                parsed.variables[var_name] = {
                    'type': var_def.get('type', 'string') if isinstance(var_def, dict) else 'string',
                    'default': var_def.get('default', '') if isinstance(var_def, dict) else var_def,
                }

        return parsed

    def _extract_operations(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract the operations array from various ServiceNow export formats.

        Handles:
        - Direct operations array
        - Serialized operations string (update set format)
        - Nested operations within flow definition
        """
        operations = data.get('operations', [])

        # Handle serialized string (update set XML → JSON conversion)
        if isinstance(operations, str):
            try:
                operations = json.loads(operations)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Failed to parse serialized operations string")
                operations = []

        if not isinstance(operations, list):
            operations = []

        # Filter out None entries and ensure dicts
        return [op for op in operations if isinstance(op, dict)]

    def _parse_trigger(self, trigger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a ServiceNow flow trigger definition."""
        if not isinstance(trigger_data, dict):
            return {'type': 'alert'}

        trigger_type_raw = trigger_data.get('type', trigger_data.get('trigger_type', 'record_created'))
        trigger_type = str(trigger_type_raw).lower()
        native_type = TRIGGER_TYPE_MAP.get(trigger_type, 'alert')

        trigger = {
            'type': native_type,
            'original_type': trigger_type,
        }

        # Extract table/record context
        table = trigger_data.get('table', trigger_data.get('target_table', ''))
        if table:
            trigger['table'] = table

        # Extract conditions/filters
        conditions = trigger_data.get('conditions', trigger_data.get('filters', []))
        if conditions:
            trigger['conditions'] = conditions if isinstance(conditions, list) else [conditions]

        # Schedule-specific fields
        if trigger_type == 'scheduled':
            trigger['schedule'] = trigger_data.get('schedule', trigger_data.get('run_time', ''))
            trigger['repeat'] = trigger_data.get('repeat', trigger_data.get('repeat_interval', ''))

        return trigger

    def _parse_operation(self, op: Dict[str, Any], index: int) -> Optional[ParsedStep]:
        """Parse a single ServiceNow Flow Designer operation."""
        op_sys_id = str(op.get('sys_id', op.get('id', f'op_{index}')))
        op_name = op.get('name', op.get('display_name', f'Operation {index + 1}'))
        type_id = op.get('type_id', 'action').lower()
        action_type = op.get('action_type', op.get('action', '')).lower()
        order = op.get('order', index)

        # Determine the step type string for mapping
        if type_id == 'flow_logic':
            # Flow logic operations: if, for_each, do_until, parallel, try_catch
            logic_type = op.get('flow_logic_type', op.get('logic_type', '')).lower()
            if not logic_type:
                # Infer from action_type or name
                logic_type = self._infer_logic_type(action_type, op_name)
            step_type = f'flow_logic.{logic_type}' if logic_type else 'flow_logic'
        elif type_id == 'subflow':
            step_type = 'subflow'
        else:
            # Regular action — use the full action_type (e.g., sn_si.create_security_incident)
            step_type = action_type or 'action'

        step = ParsedStep(
            id=op_sys_id,
            name=op_name,
            step_type=step_type,
            raw=op,
        )

        # Extract inputs
        inputs = op.get('inputs', {})
        if isinstance(inputs, list):
            # Convert list-of-dicts to dict
            input_dict = {}
            for inp in inputs:
                if isinstance(inp, dict):
                    inp_name = inp.get('name', inp.get('sys_name', ''))
                    inp_value = inp.get('value', inp.get('default_value', ''))
                    if inp_name:
                        input_dict[inp_name] = inp_value
            step.inputs = input_dict
        elif isinstance(inputs, dict):
            step.inputs = inputs

        # Extract outputs
        outputs = op.get('outputs', {})
        if isinstance(outputs, list):
            output_dict = {}
            for out in outputs:
                if isinstance(out, dict):
                    out_name = out.get('name', out.get('sys_name', ''))
                    out_type = out.get('type', 'string')
                    if out_name:
                        output_dict[out_name] = out_type
            step.outputs = output_dict
        elif isinstance(outputs, dict):
            step.outputs = outputs

        # Extract config based on type
        step.config = self._extract_operation_config(step_type, type_id, op)

        # Position based on order (y increases with order)
        step.position = {'x': 250, 'y': order * 100}

        return step

    def _extract_operation_config(
        self,
        step_type: str,
        type_id: str,
        op: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract operation configuration based on type."""
        config: Dict[str, Any] = {}
        action_type = op.get('action_type', op.get('action', '')).lower()

        if type_id == 'flow_logic':
            logic_type = op.get('flow_logic_type', op.get('logic_type', '')).lower()
            if not logic_type:
                logic_type = self._infer_logic_type(action_type, op.get('name', ''))

            if logic_type in ('if_then', 'else_if', 'else'):
                config = {
                    'logic_type': logic_type,
                    'conditions': op.get('conditions', op.get('condition', [])),
                    'operator': op.get('operator', 'and'),
                }
            elif logic_type == 'for_each':
                config = {
                    'logic_type': 'for_each',
                    'transform_type': 'loop',
                    'data_source': op.get('data_source', op.get('items', '')),
                    'batch_size': op.get('batch_size', 1),
                }
            elif logic_type == 'do_until':
                config = {
                    'logic_type': 'do_until',
                    'transform_type': 'loop',
                    'condition': op.get('condition', ''),
                    'max_iterations': op.get('max_iterations', op.get('max_count', 100)),
                }
            elif logic_type == 'parallel':
                config = {
                    'logic_type': 'parallel',
                    'transform_type': 'parallel',
                    'branches': op.get('branches', []),
                }
            elif logic_type in ('try_catch', 'try', 'catch', 'finally'):
                config = {
                    'logic_type': logic_type,
                    'error_handling': True,
                }
            else:
                config = {'logic_type': logic_type}

        elif type_id == 'subflow':
            config = {
                'action_type': 'run_playbook',
                'subflow_id': op.get('subflow_id', op.get('sys_id', '')),
                'subflow_name': op.get('subflow_name', op.get('name', '')),
                'inputs': op.get('inputs', {}),
            }

        else:
            # Regular action
            config = {
                'action_type': action_type,
                'inputs': op.get('inputs', {}),
            }

            # Parse the namespace to identify integration
            if '.' in action_type:
                namespace, action_name = action_type.rsplit('.', 1)
                config['namespace'] = namespace
                config['action_name'] = action_name

                # Map common ServiceNow namespaces
                if namespace == 'sn_si':
                    config['integration'] = 'servicenow_sir'
                elif namespace == 'sn_vul':
                    config['integration'] = 'servicenow_vr'
                elif namespace == 'sn_ti':
                    config['integration'] = 'servicenow_ti'
                elif namespace == 'global':
                    config['integration'] = 'servicenow'
                elif namespace == 'sn_orchestration':
                    config['integration'] = 'servicenow_orchestration'
                else:
                    config['integration'] = namespace

            # Extract script content for run_script actions
            if action_type in ('global.run_script', 'global.script'):
                script = op.get('script', op.get('inputs', {}).get('script', ''))
                if isinstance(script, dict):
                    script = script.get('value', '')
                config['script'] = script

            # Extract HTTP config for global.http
            if action_type == 'global.http':
                inputs = op.get('inputs', {})
                if isinstance(inputs, dict):
                    config['url'] = self._resolve_input_value(inputs.get('url', ''))
                    config['method'] = self._resolve_input_value(inputs.get('method', 'GET'))
                    config['headers'] = self._resolve_input_value(inputs.get('headers', {}))
                    config['body'] = self._resolve_input_value(inputs.get('body', ''))

        return config

    def _infer_logic_type(self, action_type: str, name: str) -> str:
        """Infer flow logic type from action_type or name."""
        combined = f'{action_type} {name}'.lower()

        if 'if' in combined and ('then' in combined or 'else' not in combined):
            return 'if_then'
        if 'else_if' in combined or 'elseif' in combined:
            return 'else_if'
        if 'else' in combined:
            return 'else'
        if 'for_each' in combined or 'foreach' in combined or 'for each' in combined:
            return 'for_each'
        if 'do_until' in combined or 'dountil' in combined or 'do until' in combined:
            return 'do_until'
        if 'parallel' in combined:
            return 'parallel'
        if 'try' in combined and 'catch' in combined:
            return 'try_catch'
        if 'try' in combined:
            return 'try'
        if 'catch' in combined:
            return 'catch'

        return ''

    def _resolve_input_value(self, value: Any) -> Any:
        """
        Resolve a ServiceNow input value.

        ServiceNow inputs can be:
        - Simple strings/values
        - Dict with 'value' key: {"value": "...", "type": "..."}
        - Data pillar references: "{{trigger.current.field}}"
        """
        if isinstance(value, dict):
            return value.get('value', value.get('default_value', str(value)))
        return value

    def _build_edges(
        self,
        steps: List[ParsedStep],
        operations: List[Dict[str, Any]],
        step_map: Dict[str, ParsedStep]
    ) -> None:
        """
        Build step connections from ServiceNow operation order and flow logic.

        ServiceNow Flow Designer operations are ordered sequentially, but flow
        logic operations (if/then, for_each, etc.) create branching. We connect
        steps sequentially by default, then handle flow logic branches.
        """
        if not steps:
            return

        # Sort steps by their operation order
        order_map: Dict[str, int] = {}
        for op in operations:
            op_id = str(op.get('sys_id', op.get('id', '')))
            order_map[op_id] = op.get('order', 0)

        sorted_steps = sorted(steps, key=lambda s: order_map.get(s.id, 0))

        # Build sequential connections
        for i in range(len(sorted_steps) - 1):
            current = sorted_steps[i]
            next_step = sorted_steps[i + 1]

            # Skip connecting flow logic end markers back to main flow
            # (handled by the nesting logic)
            if current.step_type.startswith('flow_logic.'):
                logic_type = current.config.get('logic_type', '')
                if logic_type in ('else', 'catch', 'finally'):
                    # These connect to the next step after the block
                    continue

            if next_step.id not in current.next_steps:
                current.next_steps.append(next_step.id)

        # Process explicit connections from operations
        for op in operations:
            op_id = str(op.get('sys_id', op.get('id', '')))
            if op_id not in step_map:
                continue

            step = step_map[op_id]

            # Explicit next_operation or on_success
            next_op = op.get('next_operation', op.get('on_success', op.get('next', '')))
            if next_op and str(next_op) in step_map:
                next_id = str(next_op)
                if next_id not in step.next_steps:
                    step.next_steps.append(next_id)

            # on_failure / error handling
            on_failure = op.get('on_failure', op.get('on_error', ''))
            if on_failure and str(on_failure) in step_map:
                fail_id = str(on_failure)
                if fail_id not in step.next_steps:
                    step.next_steps.append(fail_id)
                    # Mark the condition for the edge
                    if not step.condition:
                        step.condition = 'on_failure'

            # Flow logic branches (if_then true/false paths)
            true_branch = op.get('true_branch', op.get('then', ''))
            if true_branch and str(true_branch) in step_map:
                branch_id = str(true_branch)
                if branch_id not in step.next_steps:
                    step.next_steps.append(branch_id)

            false_branch = op.get('false_branch', op.get('else', ''))
            if false_branch and str(false_branch) in step_map:
                branch_id = str(false_branch)
                if branch_id not in step.next_steps:
                    step.next_steps.append(branch_id)

            # Nested operations (children of flow logic blocks)
            children = op.get('children', op.get('nested_operations', []))
            if isinstance(children, list) and children:
                first_child_id = str(children[0].get('sys_id', children[0].get('id', ''))) if isinstance(children[0], dict) else str(children[0])
                if first_child_id in step_map and first_child_id not in step.next_steps:
                    step.next_steps.append(first_child_id)

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map a ServiceNow operation to a native T1 node type.

        Mapping priority:
        1. Flow logic type (if_then, for_each, do_until, parallel, etc.)
        2. Subflow invocation
        3. Action type lookup in SERVICENOW_SECOPS_ACTIONS
        4. Fuzzy matching via find_best_mapping()
        5. Namespace-based heuristics
        6. Default to 'action'
        """
        step_type = step.step_type
        config = step.config or {}

        # ------------------------------------------------------------------
        # 1. Flow logic operations
        # ------------------------------------------------------------------
        if step_type.startswith('flow_logic'):
            logic_type = config.get('logic_type', '')

            if logic_type in ('if_then', 'else_if', 'else'):
                return 'condition', {
                    'conditions': config.get('conditions', []),
                    'operator': config.get('operator', 'and'),
                    'logic_type': logic_type,
                }
            elif logic_type in ('for_each', 'do_until'):
                return 'transform', {
                    'transform_type': 'loop',
                    'loop_type': logic_type,
                    'data_source': config.get('data_source', ''),
                    'max_iterations': config.get('max_iterations', 100),
                }
            elif logic_type == 'parallel':
                return 'transform', {
                    'transform_type': 'parallel',
                    'branches': config.get('branches', []),
                }
            elif logic_type in ('try_catch', 'try'):
                return 'transform', {
                    'transform_type': 'error_handling',
                    'error_handling': True,
                }
            elif logic_type in ('catch', 'finally'):
                return 'action', {
                    'action_type': 'error_handler',
                    'error_handling': True,
                }
            elif logic_type == 'return':
                return 'end', {'disposition': 'completed'}

            # Unknown flow logic — default to condition
            return 'condition', {'logic_type': logic_type}

        # ------------------------------------------------------------------
        # 2. Subflow invocation
        # ------------------------------------------------------------------
        if step_type == 'subflow':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('subflow_name', step.name),
                'subflow_id': config.get('subflow_id', ''),
            }

        # ------------------------------------------------------------------
        # 3. Direct action type lookup
        # ------------------------------------------------------------------
        action_type = config.get('action_type', step_type)
        normalized_action = action_type.lower().replace('-', '_').replace(' ', '_')

        if normalized_action in self.action_maps:
            node_type, base_config = self.action_maps[normalized_action]
            merged = {**base_config}
            # Carry over useful config fields
            for key in ('inputs', 'script', 'url', 'method'):
                if key in config:
                    merged[key] = config[key]
            return node_type, merged

        # ------------------------------------------------------------------
        # 4. Fuzzy matching via find_best_mapping
        # ------------------------------------------------------------------
        best = find_best_mapping(normalized_action, 'servicenow_secops')
        if best[0] != 'unmapped':
            node_type, base_config = best
            merged = {**base_config}
            for key in ('inputs', 'script', 'url', 'method'):
                if key in config:
                    merged[key] = config[key]
            return node_type, merged

        # ------------------------------------------------------------------
        # 5. Namespace-based heuristics
        # ------------------------------------------------------------------
        namespace = config.get('namespace', '')
        action_name = config.get('action_name', '')

        if namespace:
            # Security Incident actions
            if namespace == 'sn_si':
                return self._map_sn_si_action(action_name, config)

            # Vulnerability Response actions
            if namespace == 'sn_vul':
                return self._map_sn_vul_action(action_name, config)

            # Threat Intelligence actions
            if namespace == 'sn_ti':
                return 'enrich', {
                    'integration': 'servicenow_ti',
                    'action': action_name,
                    'observable_type': self._guess_observable(action_name),
                }

            # Global built-in actions
            if namespace == 'global':
                return self._map_global_action(action_name, config)

            # Integration Hub spokes
            return self._map_spoke_action(namespace, action_name, config)

        # ------------------------------------------------------------------
        # 6. Action name keyword heuristics
        # ------------------------------------------------------------------
        combined = f'{action_type} {step.name}'.lower()

        if any(kw in combined for kw in ['scan', 'lookup', 'search', 'query', 'enrich', 'reputation', 'check', 'get']):
            return 'enrich', {'action': action_type, 'auto_mapped': True}
        if any(kw in combined for kw in ['block', 'isolate', 'contain', 'quarantine', 'disable', 'terminate']):
            return 'action', {'action_type': action_type, 'requires_approval': True, 'auto_mapped': True}
        if any(kw in combined for kw in ['notify', 'send', 'email', 'slack', 'teams', 'message']):
            return 'notify', {'action': action_type, 'auto_mapped': True}
        if any(kw in combined for kw in ['ticket', 'incident', 'case', 'create']):
            return 'create_ticket', {'action': action_type, 'auto_mapped': True}
        if any(kw in combined for kw in ['close', 'resolve', 'complete']):
            return 'end', {'disposition': 'completed', 'auto_mapped': True}
        if any(kw in combined for kw in ['approve', 'approval', 'wait_for']):
            return 'approval_gate', {'action': action_type, 'auto_mapped': True}
        if any(kw in combined for kw in ['script', 'run_script', 'code']):
            return 'python_code', {'action': action_type, 'auto_mapped': True}

        # ------------------------------------------------------------------
        # 7. Default: generic action
        # ------------------------------------------------------------------
        return 'action', {
            'action_type': action_type,
            'integration': config.get('integration', 'servicenow'),
            'unmapped': True,
        }

    # ========================================================================
    # Namespace-specific mapping helpers
    # ========================================================================

    def _map_sn_si_action(
        self, action_name: str, config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map a ServiceNow Security Incident Response (sn_si) action."""
        action_lower = action_name.lower()

        if 'create' in action_lower and 'incident' in action_lower:
            return 'create_ticket', {'integration': 'servicenow', 'ticket_type': 'security_incident'}
        if 'update' in action_lower and 'incident' in action_lower:
            return 'action', {'action_type': 'update_ticket', 'integration': 'servicenow'}
        if 'close' in action_lower:
            return 'action', {'action_type': 'close_ticket', 'integration': 'servicenow'}
        if 'observable' in action_lower:
            if 'add' in action_lower:
                return 'action', {'action_type': 'add_observable', 'integration': 'servicenow'}
            return 'enrich', {'integration': 'servicenow', 'observable_type': 'indicator'}
        if 'playbook' in action_lower or 'run' in action_lower:
            return 'action', {'action_type': 'run_playbook', 'integration': 'servicenow'}
        if 'approval' in action_lower or 'request' in action_lower:
            return 'approval_gate', {'integration': 'servicenow'}
        if 'threat' in action_lower or 'score' in action_lower:
            return 'enrich', {'integration': 'servicenow', 'observable_type': 'threat_score'}
        if 'affected' in action_lower or 'ci' in action_lower:
            return 'action', {'action_type': 'add_affected_ci', 'integration': 'servicenow'}

        # Default for sn_si namespace
        return 'action', {
            'action_type': f'sn_si.{action_name}',
            'integration': 'servicenow_sir',
        }

    def _map_sn_vul_action(
        self, action_name: str, config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map a ServiceNow Vulnerability Response (sn_vul) action."""
        action_lower = action_name.lower()

        if 'create' in action_lower:
            return 'create_ticket', {'integration': 'servicenow', 'ticket_type': 'vulnerability'}
        if 'update' in action_lower:
            return 'action', {'action_type': 'update_ticket', 'integration': 'servicenow'}
        if 'assign' in action_lower:
            return 'action', {'action_type': 'assign_ticket', 'integration': 'servicenow'}
        if 'scan' in action_lower or 'lookup' in action_lower:
            return 'enrich', {'integration': 'servicenow_vr', 'observable_type': 'vulnerability'}

        return 'action', {
            'action_type': f'sn_vul.{action_name}',
            'integration': 'servicenow_vr',
        }

    def _map_global_action(
        self, action_name: str, config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map a ServiceNow global (built-in) action."""
        action_lower = action_name.lower()

        if action_lower in ('run_script', 'script'):
            return 'python_code', {
                'script': config.get('script', ''),
                'integration': 'servicenow',
            }
        if action_lower == 'http':
            return 'webhook_call', {
                'url': config.get('url', ''),
                'method': config.get('method', 'GET'),
                'headers': config.get('headers', {}),
                'body': config.get('body', ''),
            }
        if action_lower in ('send_email', 'email'):
            return 'notify', {'channel': 'email'}
        if action_lower in ('send_notification', 'notification'):
            return 'notify', {'channel': 'servicenow'}
        if action_lower in ('slack_post', 'slack'):
            return 'notify', {'channel': 'slack'}
        if action_lower in ('teams_post', 'teams'):
            return 'notify', {'channel': 'teams'}
        if action_lower in ('approval', 'request_approval'):
            return 'approval_gate', {}
        if action_lower in ('wait_for', 'wait', 'timer'):
            return 'delay', {'duration_seconds': 60}
        if action_lower in ('create_record', 'insert_record'):
            return 'create_ticket', {'integration': 'servicenow'}
        if action_lower in ('update_record',):
            return 'action', {'action_type': 'update_record', 'integration': 'servicenow'}
        if action_lower in ('lookup_record', 'get_record'):
            return 'enrich', {'integration': 'servicenow', 'observable_type': 'record'}
        if action_lower in ('delete_record',):
            return 'action', {'action_type': 'delete_record', 'integration': 'servicenow', 'requires_approval': True}
        if action_lower in ('transform_data', 'transform'):
            return 'transform', {}
        if action_lower in ('log_message', 'log'):
            return 'action', {'action_type': 'log_message'}

        return 'action', {
            'action_type': f'global.{action_name}',
            'integration': 'servicenow',
        }

    def _map_spoke_action(
        self, namespace: str, action_name: str, config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map Integration Hub spoke actions (third-party integrations)."""
        ns_lower = namespace.lower()
        action_lower = action_name.lower()
        combined = f'{ns_lower}.{action_lower}'

        # Try direct lookup
        if combined in self.action_maps:
            return self.action_maps[combined]

        # Enrichment spokes
        enrich_spokes = [
            'virustotal', 'shodan', 'abuseipdb', 'greynoise', 'hybrid_analysis',
            'urlscan', 'whois', 'dns', 'maxmind', 'ipinfo', 'censys',
            'recorded_future', 'misp', 'alienvault', 'otx', 'threatconnect',
        ]
        if any(s in ns_lower for s in enrich_spokes):
            return 'enrich', {
                'integration': namespace,
                'action': action_name,
                'observable_type': self._guess_observable(action_name),
            }

        # EDR / containment spokes
        edr_spokes = [
            'crowdstrike', 'sentinelone', 'carbon_black', 'cybereason',
            'microsoft_defender', 'cortex_xdr',
        ]
        if any(s in ns_lower for s in edr_spokes):
            requires_approval = any(
                kw in action_lower
                for kw in ['contain', 'isolate', 'block', 'quarantine', 'disable', 'kill']
            )
            return 'action', {
                'integration': namespace,
                'action': action_name,
                'requires_approval': requires_approval,
            }

        # Identity spokes
        identity_spokes = ['active_directory', 'okta', 'azure_ad', 'ldap', 'ping']
        if any(s in ns_lower for s in identity_spokes):
            if any(kw in action_lower for kw in ['get', 'lookup', 'search', 'find']):
                return 'enrich', {
                    'integration': namespace,
                    'action': action_name,
                    'observable_type': 'user',
                }
            return 'action', {
                'integration': namespace,
                'action': action_name,
                'requires_approval': True,
            }

        # Ticketing spokes
        ticket_spokes = ['servicenow', 'jira', 'pagerduty', 'opsgenie']
        if any(s in ns_lower for s in ticket_spokes):
            if 'create' in action_lower:
                return 'create_ticket', {'integration': namespace, 'action': action_name}
            return 'action', {'integration': namespace, 'action': action_name}

        # Notification spokes
        notify_spokes = ['slack', 'teams', 'email', 'smtp', 'webhook']
        if any(s in ns_lower for s in notify_spokes):
            return 'notify', {'integration': namespace, 'action': action_name}

        # Firewall spokes
        firewall_spokes = ['palo_alto', 'fortinet', 'fortigate', 'cisco', 'checkpoint']
        if any(s in ns_lower for s in firewall_spokes):
            return 'action', {
                'integration': namespace,
                'action': action_name,
                'requires_approval': True,
            }

        # Default spoke action
        return 'action', {
            'integration': namespace,
            'action': action_name,
            'auto_mapped': True,
        }

    @staticmethod
    def _guess_observable(action: str) -> str:
        """Guess the observable type from an action name."""
        action_lower = action.lower()
        if any(kw in action_lower for kw in ['ip', 'address']):
            return 'ip'
        if any(kw in action_lower for kw in ['domain', 'dns', 'fqdn']):
            return 'domain'
        if any(kw in action_lower for kw in ['hash', 'file', 'md5', 'sha']):
            return 'hash'
        if any(kw in action_lower for kw in ['url', 'link']):
            return 'url'
        if any(kw in action_lower for kw in ['email', 'mail']):
            return 'email'
        if any(kw in action_lower for kw in ['user', 'account', 'identity']):
            return 'user'
        if any(kw in action_lower for kw in ['host', 'device', 'endpoint', 'machine']):
            return 'host'
        return 'unknown'
