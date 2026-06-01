# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Palo Alto XSOAR (Demisto) Playbook Converter

Converts XSOAR playbooks to T1 Agentics native format.

XSOAR playbook structure (YAML):
- tasks: Dictionary of task definitions
- inputs: Input parameters
- outputs: Output parameters
- starttaskid: Entry point
- conditions: Conditional logic within tasks
"""

import json
import yaml
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import XSOAR_COMMANDS, find_best_mapping

logger = logging.getLogger(__name__)


class XSOARConverter(PlaybookConverter):
    """
    Converter for Palo Alto XSOAR (Demisto) playbooks.

    Task Types:
    - regular: Command execution
    - condition: Conditional branching
    - playbook: Sub-playbook call
    - title: Section title/comment
    - start: Start point
    - collection: Data collection
    """

    PLATFORM = SourcePlatform.XSOAR

    def __init__(self):
        super().__init__(XSOAR_COMMANDS)

    def detect(self, content: str) -> bool:
        """Detect if content is from XSOAR."""
        try:
            # Try YAML first (XSOAR typically uses YAML)
            try:
                data = yaml.safe_load(content)
            except:
                data = json.loads(content)

            if not isinstance(data, dict):
                return False

            # Check for XSOAR indicators
            indicators = [
                'tasks' in data,
                'starttaskid' in data,
                'fromversion' in data,
                'version' in data and 'inputs' in data,
                'contentitemexportablefields' in str(data).lower(),
                'demisto' in str(data).lower(),
                'xsoar' in str(data).lower(),
            ]

            return sum(indicators) >= 2

        except:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse XSOAR playbook YAML/JSON."""
        try:
            data = yaml.safe_load(content)
        except:
            data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported XSOAR Playbook'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', data.get('fromversion', '1.0'))),
            raw=data
        )

        # Parse tasks
        tasks = data.get('tasks', {})
        task_map = {}

        # First pass: create steps
        for task_id, task in tasks.items():
            step = self._parse_task(task_id, task)
            if step:
                parsed.steps.append(step)
                task_map[task_id] = step

        # Second pass: build connections
        for task_id, task in tasks.items():
            step = task_map.get(task_id)
            if not step:
                continue

            # Get next tasks
            nexttasks = task.get('nexttasks', {})

            # Handle simple next (single path)
            if '#none#' in nexttasks:
                for next_id in nexttasks['#none#']:
                    step.next_steps.append(str(next_id))

            # Handle conditional branches
            for condition, next_ids in nexttasks.items():
                if condition == '#none#':
                    continue
                for next_id in next_ids:
                    if str(next_id) not in step.next_steps:
                        step.next_steps.append(str(next_id))
                        # Store condition for edge labeling
                        step.condition = condition

            # Handle yes/no conditions
            if 'yes' in nexttasks:
                for next_id in nexttasks['yes']:
                    if str(next_id) not in step.next_steps:
                        step.next_steps.append(str(next_id))
            if 'no' in nexttasks:
                for next_id in nexttasks['no']:
                    if str(next_id) not in step.next_steps:
                        step.next_steps.append(str(next_id))

        # Extract start task
        start_task = data.get('starttaskid', data.get('startTaskId', ''))
        if start_task:
            parsed.triggers.append({'start_task': start_task})

        # Extract inputs/outputs
        parsed.variables = {
            'inputs': data.get('inputs', []),
            'outputs': data.get('outputs', [])
        }

        return parsed

    def _parse_task(self, task_id: str, task: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single XSOAR task."""
        task_type = task.get('type', 'regular')
        task_name = task.get('task', {}).get('name', task.get('name', f'Task {task_id}'))

        # Skip title tasks (they're just labels)
        if task_type == 'title':
            return None

        step = ParsedStep(
            id=str(task_id),
            name=task_name,
            step_type=task_type,
            raw=task
        )

        # Extract configuration based on task type
        task_info = task.get('task', {})

        if task_type == 'regular':
            step.config = self._extract_regular_config(task, task_info)
        elif task_type == 'condition':
            step.config = self._extract_condition_config(task)
        elif task_type == 'playbook':
            step.config = self._extract_playbook_config(task, task_info)
        elif task_type == 'collection':
            step.config = self._extract_collection_config(task)
        elif task_type == 'start':
            step.step_type = 'trigger'

        # Extract position from view. XSOAR commonly serializes `view` as a
        # YAML literal block containing JSON, so it round-trips as a STRING
        # rather than a dict. Parse the inner JSON when that's the case.
        view = task.get('view', {})
        if isinstance(view, str):
            try:
                view = json.loads(view)
            except (json.JSONDecodeError, ValueError, TypeError):
                view = {}
        if isinstance(view, dict) and 'position' in view:
            pos = view['position']
            if isinstance(pos, dict):
                step.position = {'x': int(pos.get('x', 0)), 'y': int(pos.get('y', 0))}

        # Extract inputs
        if 'scriptarguments' in task:
            step.inputs = task['scriptarguments']

        return step

    def _extract_regular_config(self, task: Dict[str, Any], task_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a regular (command) task."""
        config = {}

        # Get script/command
        script = task_info.get('script', task_info.get('scriptId', ''))
        config['script'] = script

        # Get command (often prefixed with !)
        command = task_info.get('command', '')
        if not command and script:
            # Extract command from script reference
            if '|||' in script:
                command = script.split('|||')[0]
            else:
                command = script
        config['command'] = command

        # Get brand/integration
        brand = task_info.get('brand', task.get('brand', ''))
        config['brand'] = brand

        # Get arguments
        args = task.get('scriptarguments', {})
        config['arguments'] = args

        # Get description
        config['description'] = task_info.get('description', '')

        return config

    def _extract_condition_config(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a condition task."""
        config = {'conditions': []}

        conditions = task.get('conditions', [])
        for cond in conditions:
            config['conditions'].append({
                'label': cond.get('label', ''),
                'condition': cond.get('condition', [])
            })

        # Get default path
        default_path = task.get('defaultassigneecomplex', task.get('defaultroute', ''))
        config['default'] = default_path

        return config

    def _extract_playbook_config(self, task: Dict[str, Any], task_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a playbook (sub-playbook) task."""
        return {
            'playbook_name': task_info.get('playbookName', task_info.get('name', '')),
            'playbook_id': task_info.get('playbookId', ''),
            'inputs': task.get('scriptarguments', {}),
            'loop': task.get('loop', {})
        }

    def _extract_collection_config(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration from a data collection task."""
        return {
            'message': task.get('message', {}),
            'form': task.get('form', {}),
            'results': task.get('results', {})
        }

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map XSOAR task type to native node type."""
        task_type = step.step_type.lower()
        config = step.config.copy()

        # Direct type mappings
        if task_type == 'start' or task_type == 'trigger':
            return 'trigger', {'trigger_type': 'alert'}

        elif task_type == 'condition':
            # Convert XSOAR conditions to our format
            conditions = config.get('conditions', [])
            if conditions:
                first_cond = conditions[0]
                cond_list = first_cond.get('condition', [])
                if cond_list and len(cond_list) > 0:
                    # XSOAR conditions are nested arrays
                    first_clause = cond_list[0] if isinstance(cond_list[0], list) else cond_list
                    if first_clause and len(first_clause) > 0:
                        clause = first_clause[0] if isinstance(first_clause[0], dict) else {}
                        return 'condition', {
                            'field': clause.get('left', {}).get('value', ''),
                            'operator': self._map_operator(clause.get('operator', 'isEqualString')),
                            'value': clause.get('right', {}).get('value', '')
                        }
            return 'condition', {}

        elif task_type == 'playbook':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', ''),
                'requires_approval': False
            }

        elif task_type == 'collection':
            return 'webform', {
                'message': config.get('message', {}).get('body', ''),
                'fields': self._convert_form_fields(config.get('form', {}))
            }

        elif task_type == 'regular':
            # Map based on command
            command = config.get('command', config.get('script', ''))

            # Check for special commands
            if command == 'setIncident' or command == '!setIncident':
                return 'action', {'action_type': 'update_incident'}
            elif command == 'closeInvestigation' or command == '!closeInvestigation':
                return 'end', {'disposition': 'completed'}
            elif command == 'send-mail' or command == '!send-mail':
                return 'notify', {'channel': 'email'}
            elif command == 'slack-send' or command == '!slack-send':
                return 'notify', {'channel': 'slack'}

            # Use action mapping
            return find_best_mapping(command, 'xsoar')

        # Unknown task type
        return 'unmapped', {'original_type': task_type, 'config': config}

    def _map_operator(self, operator: str) -> str:
        """Map XSOAR operator to native operator."""
        operator_map = {
            'isEqualString': 'equals',
            'isNotEqualString': 'not_equals',
            'isExists': 'is_not_empty',
            'isNotExists': 'is_empty',
            'containsString': 'contains',
            'notContainsString': 'not_contains',
            'containsGeneral': 'contains',
            'isEqualNumber': 'equals',
            'isNotEqualNumber': 'not_equals',
            'greaterThan': 'greater_than',
            'lessThan': 'less_than',
            'greaterThanOrEqual': 'greater_or_equal',
            'lessThanOrEqual': 'less_or_equal',
            'inList': 'in',
            'notInList': 'not_in',
            'startWith': 'matches',
            'endWith': 'matches',
            'match': 'matches',
        }
        return operator_map.get(operator, 'equals')

    def _convert_form_fields(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert XSOAR form definition to our field format."""
        fields = []

        questions = form.get('questions', [])
        for q in questions:
            field = {
                'name': q.get('id', q.get('fieldAssociated', '')),
                'label': q.get('label', ''),
                'type': self._map_field_type(q.get('type', 'shortText')),
                'required': q.get('required', False)
            }

            # Add options for select fields
            if 'options' in q:
                field['options'] = [
                    {'label': opt, 'value': opt}
                    for opt in q['options']
                ]

            fields.append(field)

        return fields

    def _map_field_type(self, xsoar_type: str) -> str:
        """Map XSOAR field type to our field type."""
        type_map = {
            'shortText': 'text',
            'longText': 'textarea',
            'number': 'number',
            'singleSelect': 'select',
            'multiSelect': 'multiselect',
            'date': 'date',
            'dateTime': 'datetime',
            'boolean': 'checkbox',
            'file': 'file',
        }
        return type_map.get(xsoar_type, 'text')
