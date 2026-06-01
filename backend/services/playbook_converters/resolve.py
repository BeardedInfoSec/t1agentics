# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Resolve (Resolve Systems) Runbook Converter

Converts Resolve runbooks to T1 Agentics native format.

Resolve runbook structure:
- Top-level: { runbook_name, runbook_id, description, category, steps, transitions, variables }
- Steps array: [{ step_id, name, type, action_type, module, function, parameters, position }]
- Step types: action, decision, approval, wait, script, parallel, email, rest_call, sub_runbook, start, end
- Module references: module = integration category (network, endpoint, identity, ticketing, cloud, email)
- Function references: function = specific action (block_ip, isolate_host, disable_account, etc.)
- Transitions: [{ from_step, to_step, condition, condition_expression }]
- Decision steps: conditions with variable/operator/value and true_step/false_step routing
- Wait steps: duration_seconds for timed delays
- Approval steps: approvers list, message, timeout_hours
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import RESOLVE_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Module normalization
# ============================================================================

_MODULE_INTEGRATION_MAP = {
    'network': 'firewall',
    'firewall': 'firewall',
    'endpoint': 'edr',
    'edr': 'edr',
    'identity': 'identity',
    'iam': 'identity',
    'active_directory': 'active_directory',
    'ad': 'active_directory',
    'ldap': 'active_directory',
    'okta': 'okta',
    'azure_ad': 'azure_ad',
    'ticketing': 'ticketing',
    'itsm': 'ticketing',
    'servicenow': 'servicenow',
    'jira': 'jira',
    'cloud': 'cloud',
    'aws': 'aws',
    'azure': 'azure',
    'gcp': 'gcp',
    'email': 'email',
    'smtp': 'email',
    'exchange': 'exchange',
    'siem': 'siem',
    'splunk': 'splunk',
    'qradar': 'qradar',
    'database': 'database',
    'storage': 'storage',
    'monitoring': 'monitoring',
    'dns': 'dns',
}


def _normalize_module(module_name: str) -> str:
    """Normalize a Resolve module name to a canonical integration category."""
    if not module_name:
        return ''
    normalized = module_name.lower().strip().replace('-', '_').replace(' ', '_')
    return _MODULE_INTEGRATION_MAP.get(normalized, normalized)


class ResolveConverter(PlaybookConverter):
    """
    Converter for Resolve (Resolve Systems) runbooks.

    Step Types:
    - action: Execute an integration function (module + function)
    - decision: Conditional branching with variable/operator/value
    - approval: Human approval gate with approvers, message, timeout
    - wait: Timed delay (duration_seconds)
    - script: Custom script execution
    - parallel: Execute multiple branches concurrently
    - email: Send email notification
    - rest_call: Make an HTTP/REST API call
    - sub_runbook: Invoke another runbook as a sub-process
    - start: Runbook entry point
    - end: Runbook exit point

    Transition Conditions:
    - success: Execute when previous step succeeds
    - failure: Execute when previous step fails
    - always: Execute regardless of outcome
    - custom: Execute when condition_expression evaluates to true
    """

    PLATFORM = SourcePlatform.RESOLVE

    def __init__(self):
        super().__init__(RESOLVE_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from Resolve."""
        try:
            data = json.loads(content)

            indicators = [
                'runbook_name' in data,
                'runbook_id' in data,
                isinstance(data.get('steps'), list),
                isinstance(data.get('transitions'), list),
                isinstance(data.get('variables'), dict),
                'category' in data,
                'resolve' in str(data).lower()[:2000],
            ]

            # Check step structure for Resolve-specific patterns
            steps = data.get('steps', [])
            if isinstance(steps, list) and steps:
                # Resolve steps have module + function structure
                has_module_function = any(
                    isinstance(s, dict) and ('module' in s or 'function' in s)
                    for s in steps[:10]
                )
                if has_module_function:
                    indicators.append(True)

                # Resolve step types include 'rest_call', 'sub_runbook', 'approval'
                step_types = {s.get('type', '') for s in steps[:20] if isinstance(s, dict)}
                resolve_types = {'rest_call', 'sub_runbook', 'approval', 'wait', 'parallel'}
                if step_types & resolve_types:
                    indicators.append(True)

                # Steps use step_id field
                has_step_id = any(
                    isinstance(s, dict) and 'step_id' in s
                    for s in steps[:10]
                )
                if has_step_id:
                    indicators.append(True)

            # Check transitions for Resolve-specific patterns
            transitions = data.get('transitions', [])
            if isinstance(transitions, list) and transitions:
                has_from_to = any(
                    isinstance(t, dict) and 'from_step' in t and 'to_step' in t
                    for t in transitions[:10]
                )
                if has_from_to:
                    indicators.append(True)

            return sum(indicators) >= 3

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Resolve runbook JSON."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('runbook_name', 'Imported Resolve Runbook'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Parse variables
        variables = data.get('variables', {})
        if isinstance(variables, dict):
            parsed.variables = variables.copy()

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

        # Parse transitions and wire up next_steps
        transitions = data.get('transitions', [])
        for transition in transitions:
            if not isinstance(transition, dict):
                continue

            from_step_id = str(transition.get('from_step', ''))
            to_step_id = str(transition.get('to_step', ''))
            condition = transition.get('condition', 'always')
            condition_expression = transition.get('condition_expression', '')

            source_step = step_map.get(from_step_id)
            if source_step and to_step_id:
                if to_step_id not in source_step.next_steps:
                    source_step.next_steps.append(to_step_id)

                # For failure transitions, tag so edges can be annotated
                if condition == 'failure':
                    source_step.condition = 'failure'
                elif condition == 'custom' and condition_expression:
                    source_step.condition = condition_expression

        # Wire up decision step true/false outputs
        for step in parsed.steps:
            if step.step_type == 'decision':
                true_step = step.config.get('true_step', '')
                false_step = step.config.get('false_step', '')
                if true_step and true_step not in step.next_steps:
                    step.next_steps.append(true_step)
                if false_step and false_step not in step.next_steps:
                    step.next_steps.append(false_step)

        # Detect triggers (start nodes serve as triggers)
        for step in parsed.steps:
            if step.step_type == 'start':
                parsed.triggers.append({
                    'step_id': step.id,
                    'type': 'start',
                    'name': step.name
                })

        return parsed

    def _parse_step(self, step_data: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Resolve step into a ParsedStep."""
        step_id = str(step_data.get('step_id', ''))
        if not step_id:
            return None

        step_name = step_data.get('name', f'Step {step_id[:8]}')
        step_type = step_data.get('type', 'unknown')

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

        # Extract config based on step type
        parameters = step_data.get('parameters', {})
        if not isinstance(parameters, dict):
            parameters = {}

        module = step_data.get('module', '')
        function = step_data.get('function', '')
        action_type = step_data.get('action_type', '')

        step.config = self._extract_step_config(
            step_type, parameters, module, function, action_type, step_data
        )

        return step

    def _extract_step_config(
        self,
        step_type: str,
        parameters: Dict[str, Any],
        module: str,
        function: str,
        action_type: str,
        step_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a Resolve step."""
        result: Dict[str, Any] = {}

        if step_type == 'action':
            result = {
                'module': module,
                'module_normalized': _normalize_module(module),
                'function': function,
                'action_type': action_type,
                'parameters': parameters,
            }

        elif step_type == 'decision':
            conditions = step_data.get('conditions', [])
            if not isinstance(conditions, list):
                conditions = []
            result = {
                'conditions': conditions,
                'true_step': str(step_data.get('true_step', '')),
                'false_step': str(step_data.get('false_step', '')),
            }

        elif step_type == 'approval':
            result = {
                'approvers': step_data.get('approvers', []),
                'message': step_data.get('message', ''),
                'timeout_hours': step_data.get('timeout_hours', 24),
            }

        elif step_type == 'wait':
            result = {
                'duration_seconds': step_data.get('duration_seconds',
                                                   parameters.get('duration_seconds', 60)),
            }

        elif step_type == 'script':
            result = {
                'language': parameters.get('language', step_data.get('language', 'python')),
                'code': parameters.get('code', step_data.get('code', '')),
            }

        elif step_type == 'parallel':
            result = {
                'branches': step_data.get('branches', parameters.get('branches', [])),
                'join_type': step_data.get('join_type', parameters.get('join_type', 'all')),
            }

        elif step_type == 'email':
            result = {
                'to': parameters.get('to', parameters.get('recipients', '')),
                'subject': parameters.get('subject', ''),
                'body': parameters.get('body', parameters.get('message', '')),
                'cc': parameters.get('cc', ''),
                'bcc': parameters.get('bcc', ''),
            }

        elif step_type == 'rest_call':
            result = {
                'url': parameters.get('url', parameters.get('endpoint', '')),
                'method': parameters.get('method', 'GET'),
                'headers': parameters.get('headers', {}),
                'body': parameters.get('body', parameters.get('payload', '')),
                'auth_type': parameters.get('auth_type', ''),
                'timeout_seconds': parameters.get('timeout_seconds', 30),
            }

        elif step_type == 'sub_runbook':
            result = {
                'runbook_name': parameters.get('runbook_name',
                                               step_data.get('runbook_name', '')),
                'runbook_id': parameters.get('runbook_id',
                                             step_data.get('runbook_id', '')),
                'input_parameters': parameters.get('input_parameters', {}),
                'wait_for_completion': parameters.get('wait_for_completion', True),
            }

        elif step_type == 'start':
            result = {
                'trigger_type': 'start',
                'input_parameters': parameters,
            }

        elif step_type == 'end':
            result = {
                'disposition': parameters.get('disposition', 'completed'),
                'output_parameters': parameters.get('output_parameters', {}),
            }

        else:
            # Unknown type -- preserve all parameters and metadata
            result = parameters.copy() if isinstance(parameters, dict) else {}
            if module:
                result['module'] = module
            if function:
                result['function'] = function

        return result

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map Resolve step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # Start → trigger
        if step_type == 'start':
            return 'trigger', {
                'trigger_type': 'alert',
                'input_parameters': config.get('input_parameters', {}),
            }

        # End → end
        if step_type == 'end':
            return 'end', {
                'disposition': config.get('disposition', 'completed'),
            }

        # Decision → condition
        if step_type == 'decision':
            conditions = config.get('conditions', [])
            if conditions and isinstance(conditions, list):
                first_condition = conditions[0] if isinstance(conditions[0], dict) else {}
                return 'condition', {
                    'field': first_condition.get('variable', ''),
                    'operator': self._map_operator(first_condition.get('operator', 'equals')),
                    'value': first_condition.get('value', ''),
                    'all_conditions': conditions,
                }
            return 'condition', {}

        # Approval → approval_gate
        if step_type == 'approval':
            timeout_hours = config.get('timeout_hours', 24)
            return 'approval_gate', {
                'message': config.get('message', ''),
                'approvers': config.get('approvers', []),
                'timeout_minutes': timeout_hours * 60 if isinstance(timeout_hours, (int, float)) else 1440,
            }

        # Wait → delay
        if step_type == 'wait':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        # Script → python_code
        if step_type == 'script':
            language = config.get('language', 'python').lower()
            result_config = {
                'code': config.get('code', ''),
            }
            if language not in ('python', 'python3', 'py'):
                result_config['original_language'] = language
                result_config['requires_review'] = True
            return 'python_code', result_config

        # Parallel → transform (parallel)
        if step_type == 'parallel':
            return 'transform', {
                'transform_type': 'parallel',
                'branches': config.get('branches', []),
                'join_type': config.get('join_type', 'all'),
            }

        # Email → notify
        if step_type == 'email':
            return 'notify', {
                'channel': 'email',
                'recipients': config.get('to', ''),
                'subject': config.get('subject', ''),
                'message': config.get('body', ''),
                'cc': config.get('cc', ''),
            }

        # REST call → webhook_call
        if step_type == 'rest_call':
            return 'webhook_call', {
                'url': config.get('url', ''),
                'method': config.get('method', 'GET'),
                'headers': config.get('headers', {}),
                'body': config.get('body', ''),
            }

        # Sub-runbook → action (run_playbook)
        if step_type == 'sub_runbook':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('runbook_name', ''),
                'playbook_id': config.get('runbook_id', ''),
                'input_parameters': config.get('input_parameters', {}),
            }

        # Action → map by module.function
        if step_type == 'action':
            return self._map_action_step(config)

        # Fallback: try action maps
        return find_best_mapping(step_type, 'resolve')

    def _map_action_step(self, config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Map a Resolve action step to a native node type.

        Uses module + function to look up the most specific mapping,
        falling back to function-only, then module-only, then heuristics.
        """
        module = config.get('module', '')
        module_normalized = config.get('module_normalized', _normalize_module(module))
        function = config.get('function', '')
        action_type = config.get('action_type', '')
        parameters = config.get('parameters', {})

        # Build composite key: "module.function"
        composite_key = ''
        if module_normalized and function:
            normalized_function = function.lower().replace('-', '_').replace(' ', '_')
            composite_key = f"{module_normalized}.{normalized_function}"

        # Try composite key first (e.g., "endpoint.isolate_host")
        if composite_key:
            node_type, base_config = self._map_action_from_table(composite_key, parameters)
            if node_type != 'unmapped':
                return node_type, base_config

        # Try module_normalized.function with original module
        if module and function:
            alt_key = f"{module.lower().replace('-', '_').replace(' ', '_')}.{function.lower().replace('-', '_').replace(' ', '_')}"
            if alt_key != composite_key:
                node_type, base_config = self._map_action_from_table(alt_key, parameters)
                if node_type != 'unmapped':
                    return node_type, base_config

        # Try function alone
        if function:
            normalized_function = function.lower().replace('-', '_').replace(' ', '_')
            node_type, base_config = self._map_action_from_table(normalized_function, parameters)
            if node_type != 'unmapped':
                if module_normalized:
                    base_config.setdefault('integration', module_normalized)
                return node_type, base_config

        # Try action_type
        if action_type:
            normalized_action_type = action_type.lower().replace('-', '_').replace(' ', '_')
            node_type, base_config = self._map_action_from_table(normalized_action_type, parameters)
            if node_type != 'unmapped':
                if module_normalized:
                    base_config.setdefault('integration', module_normalized)
                return node_type, base_config

        # Try module alone
        if module_normalized:
            node_type, base_config = self._map_action_from_table(module_normalized, parameters)
            if node_type != 'unmapped':
                return node_type, base_config

        # Heuristic: infer from function name keywords
        target_name = function or action_type or ''
        if target_name:
            target_lower = target_name.lower()

            # Enrichment-like functions
            if any(kw in target_lower for kw in ('get', 'lookup', 'search', 'scan', 'check', 'query', 'list', 'collect', 'retrieve', 'ping', 'traceroute', 'resolve')):
                return 'enrich', {
                    'integration': module_normalized or module or 'unknown',
                    'auto_mapped': True,
                }

            # Containment-like functions
            if any(kw in target_lower for kw in ('block', 'isolate', 'contain', 'disable', 'quarantine', 'kill', 'terminate', 'revoke', 'lock', 'suspend', 'restrict')):
                return 'action', {
                    'action_type': target_lower.replace(' ', '_').replace('-', '_'),
                    'integration': module_normalized or module or 'unknown',
                    'requires_approval': True,
                    'auto_mapped': True,
                }

            # Remediation-like functions (non-destructive)
            if any(kw in target_lower for kw in ('enable', 'unblock', 'unisolate', 'uncontain', 'unlock', 'activate', 'reconnect', 'restore', 'restart')):
                return 'action', {
                    'action_type': target_lower.replace(' ', '_').replace('-', '_'),
                    'integration': module_normalized or module or 'unknown',
                    'requires_approval': True,
                    'auto_mapped': True,
                }

            # Ticket-like functions
            if any(kw in target_lower for kw in ('create_ticket', 'create_incident', 'create_case', 'open_ticket', 'create_record')):
                return 'create_ticket', {
                    'integration': module_normalized or module or 'unknown',
                    'auto_mapped': True,
                }

            # Update-like functions
            if any(kw in target_lower for kw in ('update', 'modify', 'set', 'assign', 'escalate', 'add_comment')):
                return 'action', {
                    'action_type': target_lower.replace(' ', '_').replace('-', '_'),
                    'integration': module_normalized or module or 'unknown',
                    'auto_mapped': True,
                }

            # Notification-like functions
            if any(kw in target_lower for kw in ('send', 'notify', 'email', 'alert', 'message', 'post', 'page')):
                return 'notify', {
                    'integration': module_normalized or module or 'unknown',
                    'auto_mapped': True,
                }

            # Close/resolve functions
            if any(kw in target_lower for kw in ('close', 'resolve', 'complete', 'archive', 'finish')):
                return 'action', {
                    'action_type': target_lower.replace(' ', '_').replace('-', '_'),
                    'integration': module_normalized or module or 'unknown',
                    'auto_mapped': True,
                }

        # Generic unmapped action
        logger.warning(
            f"No mapping for Resolve action: module={module}, function={function}, "
            f"action_type={action_type}"
        )
        return 'action', {
            'integration': module_normalized or module or 'unknown',
            'function': function,
            'action_type': action_type,
            'auto_mapped': True,
            'requires_review': True,
        }

    def _map_operator(self, operator: str) -> str:
        """Map Resolve condition operator to native operator."""
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
