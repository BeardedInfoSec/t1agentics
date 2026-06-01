# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Splunk SOAR (Phantom) Playbook Converter

Converts Splunk SOAR playbooks to T1 Agentics native format.

Splunk SOAR playbook structure:
- Blocks with actions, decisions, filters, custom code
- CEF field mappings
- Playbook type (automation, investigative, etc.)
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import SPLUNK_SOAR_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


class SplunkSOARConverter(PlaybookConverter):
    """
    Converter for Splunk SOAR (Phantom) playbooks.

    Splunk SOAR uses a dual-file format:
    - Python file (.py): Contains actual code with descriptive function names
    - JSON file (.json): Contains visual layout and VPE configuration

    Block Types:
    - action: Execute an app action
    - decision: Conditional branching
    - filter: Filter data
    - playbook: Run sub-playbook
    - code: Custom Python code
    - prompt: Wait for user input
    - format: Format data
    - join: Join multiple branches
    """

    PLATFORM = SourcePlatform.SPLUNK_SOAR

    def __init__(self):
        super().__init__(SPLUNK_SOAR_ACTIONS)
        self.python_code = None
        self.function_metadata = {}  # Maps function names to their metadata

    def set_python_code(self, python_code: str):
        """
        Set the Python code from the .py file.

        Splunk SOAR exports have two files:
        - .json file with visual layout
        - .py file with actual code and function names

        This method parses the Python code to extract function metadata.
        """
        self.python_code = python_code
        self._parse_python_code()

    def _parse_python_code(self):
        """
        Parse the Python code to extract function names and metadata.

        Extracts functions decorated with @phantom.playbook_block()
        """
        if not self.python_code:
            return

        # Pattern to find function definitions
        # Matches: def function_name(action=None, ...):
        function_pattern = r'def\s+(\w+)\s*\([^)]*\):'

        # Find all function definitions
        for match in re.finditer(function_pattern, self.python_code):
            function_name = match.group(1)

            # Skip internal functions (on_start, on_finish, etc.)
            if function_name in ['on_start', 'on_finish']:
                continue

            # Extract the function's docstring if present
            function_start = match.end()
            # Look for docstring after function definition
            docstring_match = re.search(r'"""(.*?)"""', self.python_code[function_start:function_start+500], re.DOTALL)
            description = docstring_match.group(1).strip() if docstring_match else ''

            # Store metadata
            self.function_metadata[function_name] = {
                'name': function_name,
                'description': description,
                'display_name': self._format_function_name(function_name)
            }

        logger.info(f"Parsed {len(self.function_metadata)} functions from Python code")

    def _format_function_name(self, function_name: str) -> str:
        """
        Convert snake_case function name to Title Case display name.

        Examples:
        - list_external_dynamic_acl -> List External Dynamic ACL
        - get_external_dynamic_acl -> Get External Dynamic ACL
        - filter_1 -> Filter 1
        """
        # Replace underscores with spaces and capitalize each word
        words = function_name.replace('_', ' ').split()
        return ' '.join(word.capitalize() for word in words)

    def detect(self, content: str) -> bool:
        """Detect if content is from Splunk SOAR."""
        try:
            data = json.loads(content)

            # Check for Splunk SOAR indicators
            indicators = [
                'playbook_type' in data,
                'cef' in str(data).lower(),
                'phantom' in str(data).lower(),
                'splunk soar' in str(data).lower(),
                'blocks' in data and isinstance(data.get('blocks'), list),
                'block_type' in str(data),
            ]

            return sum(indicators) >= 2

        except:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Splunk SOAR playbook JSON."""
        data = json.loads(content)

        # Extract name - could be at top level or in coa.data.origin
        name = data.get('name', 'Imported Splunk SOAR Playbook')
        if 'coa' in data and 'data' in data['coa']:
            coa_data = data['coa']['data']
            if 'origin' in coa_data and 'playbook_name' in coa_data['origin']:
                name = coa_data['origin']['playbook_name']

        parsed = ParsedPlaybook(
            name=name,
            description=data.get('description', coa_data.get('description', '') if 'coa' in data else ''),
            platform=self.PLATFORM,
            version=data.get('version', '1.0'),
            raw=data
        )

        # Handle both formats: blocks array or coa.data.nodes dictionary
        blocks = []
        edges = []

        if 'blocks' in data:
            # Simple format: blocks array
            blocks = data.get('blocks', [])
        elif 'coa' in data and 'data' in data['coa']:
            # Full export format: coa.data.nodes dictionary
            coa_data = data['coa']['data']
            nodes_dict = coa_data.get('nodes', {})
            edges = coa_data.get('edges', [])

            # Convert dictionary of nodes to list of blocks
            for node_id, node_data in nodes_dict.items():
                # Merge node metadata with node data
                block = {
                    'id': node_id,
                    'block_type': node_data.get('type', 'unknown'),
                    'x': node_data.get('x', 0),
                    'y': node_data.get('y', 0)
                }
                # Add all data fields
                if 'data' in node_data:
                    block.update(node_data['data'])
                blocks.append(block)

        block_map = {}  # id -> block
        join_blocks = set()  # Track join block IDs

        # Parse all blocks into steps
        for block in blocks:
            block_id = str(block.get('id', ''))
            block_map[block_id] = block

            # Track join blocks
            if block.get('block_type') == 'join' or block.get('type') == 'join':
                join_blocks.add(block_id)
                logger.debug(f"Found join block: {block_id}")

            step = self._parse_block(block)
            if step:
                parsed.steps.append(step)

        # Helper function to resolve join blocks to their targets
        def resolve_target(target_id: str) -> list:
            """If target is a join block, return its outgoing targets. Otherwise return [target_id]."""
            if target_id not in join_blocks:
                return [target_id]

            # Find outgoing edges from this join block
            join_targets = []
            for edge in edges:
                if str(edge.get('sourceNode', '')) == target_id:
                    next_target = str(edge.get('targetNode', ''))
                    # Recursively resolve in case of chained joins
                    join_targets.extend(resolve_target(next_target))
            return join_targets if join_targets else [target_id]

        # Build connections from edges (coa format) or outputs (blocks format)
        if edges:
            # Use edges from coa.data.edges
            logger.info(f"Processing {len(edges)} edges from Splunk SOAR playbook ({len(join_blocks)} join blocks)")
            for edge in edges:
                source_id = str(edge.get('sourceNode', ''))
                target_id = str(edge.get('targetNode', ''))

                # Skip edges FROM join blocks (they're handled by resolve_target)
                if source_id in join_blocks:
                    continue

                step = next((s for s in parsed.steps if s.id == source_id), None)
                if step and target_id:
                    # Resolve target through join blocks
                    resolved_targets = resolve_target(target_id)

                    for resolved_target in resolved_targets:
                        # Check if resolved target exists in parsed steps
                        target_exists = any(s.id == resolved_target for s in parsed.steps)
                        if target_exists:
                            if resolved_target not in step.next_steps:  # Avoid duplicates
                                step.next_steps.append(resolved_target)
                                logger.debug(f"Added edge: {source_id} ({step.name}) -> {resolved_target}")
                        else:
                            logger.warning(f"Resolved target node {resolved_target} not found in parsed steps (from {source_id} via {target_id})")
                elif not step:
                    # This is expected for join blocks
                    if source_id not in join_blocks:
                        logger.warning(f"Source node {source_id} not found in parsed steps")
                else:
                    logger.warning(f"Edge has no target: {source_id} -> {target_id}")
        else:
            # Use outputs from blocks
            for block in blocks:
                block_id = str(block.get('id', ''))
                step = next((s for s in parsed.steps if s.id == block_id), None)
                if not step:
                    continue

                # Get outgoing connections
                outputs = block.get('outputs', [])
                for output in outputs:
                    target_id = str(output.get('target', ''))
                    if target_id:
                        step.next_steps.append(target_id)

                # Handle decision branches
                if block.get('block_type') == 'decision':
                    conditions = block.get('conditions', [])
                    for i, cond in enumerate(conditions):
                        target_id = str(cond.get('target', ''))
                        if target_id and target_id not in step.next_steps:
                            step.next_steps.append(target_id)

        # Extract triggers/start block
        start_block = data.get('start_block', data.get('entry_block'))
        if start_block:
            parsed.triggers.append({'start_block': start_block})
        elif 'coa' in data and 'playbook_trigger' in data['coa']:
            parsed.triggers.append({'trigger': data['coa']['playbook_trigger']})

        return parsed

    def _parse_block(self, block: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Splunk SOAR block."""
        block_type = block.get('block_type', block.get('type', 'unknown'))
        block_id = str(block.get('id', ''))

        # Try to get function name from JSON
        function_name = block.get('functionName') or block.get('custom_function_name')

        # Try to get custom name from advanced settings
        advanced = block.get('advanced', {})
        custom_name = advanced.get('customName') if isinstance(advanced, dict) else None

        # If we have Python code metadata, use the display name from there
        if function_name and function_name in self.function_metadata:
            block_name = self.function_metadata[function_name]['display_name']
            block_description = self.function_metadata[function_name].get('description', '')
        elif custom_name:
            # Use custom name if set in advanced settings
            block_name = custom_name
            block_description = block.get('description', '')
        else:
            # Fallback: try multiple fields for the block name
            block_name = (
                block.get('name') or
                block.get('label') or
                (self._format_function_name(function_name) if function_name else None) or
                f'Block {block_id}'
            )
            block_description = block.get('description', '')

        step = ParsedStep(
            id=block_id,
            name=block_name,
            step_type=block_type,
            raw=block
        )

        # Add description if available
        if block_description:
            step.config['description'] = block_description

        # Extract configuration based on block type
        if block_type == 'action':
            step.config = self._extract_action_config(block)
        elif block_type == 'decision':
            step.config = self._extract_decision_config(block)
        elif block_type == 'filter':
            step.config = self._extract_filter_config(block)
        elif block_type == 'code':
            step.config = self._extract_code_config(block)
        elif block_type == 'prompt':
            step.config = self._extract_prompt_config(block)
        elif block_type == 'format':
            step.config = self._extract_format_config(block)
        elif block_type == 'playbook':
            step.config = self._extract_playbook_config(block)

        # Extract position
        if 'x' in block and 'y' in block:
            step.position = {'x': int(block['x']), 'y': int(block['y'])}

        return step

    def _extract_action_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from an action block."""
        config = {}

        # Get action name
        action = block.get('action', block.get('action_id', ''))
        config['action_name'] = action

        # Get app/integration
        app = block.get('app', block.get('app_id', ''))
        config['app'] = app

        # Get parameters
        parameters = block.get('parameters', {})
        config['parameters'] = parameters

        # Get CEF field mappings
        cef = block.get('cef', block.get('cef_field', ''))
        if cef:
            config['cef_field'] = cef

        # Get asset
        asset = block.get('asset', block.get('assets', []))
        if asset:
            config['asset'] = asset

        return config

    def _extract_decision_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a decision block."""
        config = {}

        conditions = block.get('conditions', [])
        config['conditions'] = []

        for cond in conditions:
            config['conditions'].append({
                'field': cond.get('field', ''),
                'operator': cond.get('operator', cond.get('comparator', 'equals')),
                'value': cond.get('value', ''),
                'target': cond.get('target', '')
            })

        # Default/else branch
        default = block.get('default', block.get('else', ''))
        if default:
            config['default_target'] = default

        return config

    def _extract_filter_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a filter block."""
        config = {}

        conditions = block.get('conditions', block.get('filters', []))
        config['conditions'] = []

        for cond in conditions:
            config['conditions'].append({
                'field': cond.get('field', ''),
                'operator': cond.get('operator', 'equals'),
                'value': cond.get('value', '')
            })

        config['filter_mode'] = block.get('mode', 'all')  # all or any

        return config

    def _extract_code_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a code block."""
        return {
            'code': block.get('code', block.get('script', '')),
            'inputs': block.get('inputs', {}),
            'outputs': block.get('outputs', [])
        }

    def _extract_prompt_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a prompt block."""
        return {
            'message': block.get('message', block.get('prompt_message', '')),
            'options': block.get('options', block.get('responses', [])),
            'timeout_minutes': block.get('timeout', 60),
            'notify_users': block.get('notify', block.get('users', []))
        }

    def _extract_format_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a format block."""
        return {
            'template': block.get('template', block.get('format_string', '')),
            'parameters': block.get('parameters', {}),
            'output_variable': block.get('output', block.get('output_name', 'formatted_data'))
        }

    def _extract_playbook_config(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a playbook (sub-playbook) block."""
        return {
            'playbook_name': block.get('playbook', block.get('playbook_name', '')),
            'playbook_id': block.get('playbook_id', ''),
            'inputs': block.get('inputs', {}),
            'scope': block.get('scope', 'new')  # new or current
        }

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map Splunk SOAR block type to native node type."""
        block_type = step.step_type.lower()
        config = step.config.copy()

        # Direct type mappings
        if block_type == 'start':
            return 'trigger', {
                'trigger_type': 'alert',
                'imported': True
            }

        if block_type == 'end':
            return 'end', {
                'disposition': 'completed',
                'imported': True
            }

        if block_type == 'utility':
            return 'action', {
                'action_type': 'utility',
                'auto_mapped': True
            }

        if block_type == 'decision':
            # Convert decision conditions to our condition format
            conditions = config.get('conditions', [])
            if conditions:
                first_cond = conditions[0]
                return 'condition', {
                    'field': first_cond.get('field', ''),
                    'operator': self._map_operator(first_cond.get('operator', 'equals')),
                    'value': first_cond.get('value', '')
                }
            return 'condition', {}

        elif block_type == 'filter':
            # Convert filter to condition
            conditions = config.get('conditions', [])
            if conditions:
                first_cond = conditions[0]
                return 'condition', {
                    'field': first_cond.get('field', ''),
                    'operator': self._map_operator(first_cond.get('operator', 'equals')),
                    'value': first_cond.get('value', '')
                }
            return 'condition', {}

        elif block_type == 'code':
            return 'python_code', {
                'code': config.get('code', ''),
                'inputs': config.get('inputs', {})
            }

        elif block_type == 'prompt':
            return 'approval_gate', {
                'message': config.get('message', 'Approval required'),
                'timeout_minutes': config.get('timeout_minutes', 60)
            }

        elif block_type == 'format':
            return 'transform', {
                'transform_type': 'format',
                'template': config.get('template', '')
            }

        elif block_type == 'playbook':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', ''),
                'requires_approval': False
            }

        elif block_type == 'join':
            # Join blocks are just synchronization points in Splunk SOAR
            # In React Flow, multiple edges can converge to the same node without an explicit join
            # Mark as unmapped so the base converter skips creating a node for it
            return 'unmapped', {'original_type': 'join', 'reason': 'Join blocks are not needed in React Flow'}

        elif block_type == 'action':
            # Map action based on action name
            action_name = config.get('action_name', '')
            node_type, node_config = find_best_mapping(action_name, 'splunk_soar')
            if node_type == 'unmapped':
                return 'action', {
                    'action_type': action_name or 'custom_action',
                    'original_action': action_name or step.name or '',
                    'auto_mapped': True
                }
            return node_type, node_config

        # Unknown block type
        return 'unmapped', {'original_type': block_type, 'config': config}

    def _map_operator(self, operator: str) -> str:
        """Map Splunk SOAR operator to native operator."""
        operator_map = {
            '==': 'equals',
            '!=': 'not_equals',
            '>=': 'greater_or_equal',
            '<=': 'less_or_equal',
            '>': 'greater_than',
            '<': 'less_than',
            'in': 'in',
            'not in': 'not_in',
            'contains': 'contains',
            'does not contain': 'not_contains',
            'is empty': 'is_empty',
            'is not empty': 'is_not_empty',
            'matches': 'matches',
        }
        return operator_map.get(operator.lower(), 'equals')
