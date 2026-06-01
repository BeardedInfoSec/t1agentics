# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Exabeam (New-Scale SOAR) Playbook Converter

Converts Exabeam SOAR playbooks to T1 Agentics native format.

Exabeam SOAR (formerly Exabeam Incident Responder) playbooks are structured
as phases containing ordered tasks. Each task can be an action, decision,
manual approval, script, notification, or enrichment step.

Playbook export structure:
{
  "playbook_id": "...",
  "name": "...",
  "description": "...",
  "type": "automation|investigation|response",
  "phases": [
    {
      "name": "...",
      "phase_id": "...",
      "tasks": [
        {
          "task_id": "...",
          "name": "...",
          "type": "action|decision|manual|script|notification|enrichment",
          "action": { "integration": "...", "command": "..." },
          "inputs": { ... },
          "outputs": { ... },
          "next_task": "task_id",
          "on_failure": "task_id"
        }
      ],
      "order": N
    }
  ],
  "trigger": { "type": "alert|incident|scheduled|manual", "conditions": { ... } }
}

Task types:
- action: Execute an integration command (action.integration + action.command)
- decision: Conditional branching (conditions array with true_path/false_path)
- manual: Human approval / manual step
- script: Custom script execution
- notification: Send alerts/messages
- enrichment: Data gathering / lookup
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import EXABEAM_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Exabeam task type -> native node type (fallback mapping)
# ============================================================================

TASK_TYPE_MAP: Dict[str, str] = {
    'action': 'action',
    'decision': 'condition',
    'manual': 'approval_gate',
    'script': 'python_code',
    'notification': 'notify',
    'enrichment': 'enrich',
    'approval': 'approval_gate',
    'wait': 'delay',
    'timer': 'delay',
    'subplaybook': 'action',
    'sub_playbook': 'action',
    'parallel': 'transform',
    'loop': 'transform',
    'end': 'end',
    'close': 'end',
}


# ============================================================================
# Trigger type normalization
# ============================================================================

TRIGGER_TYPE_MAP: Dict[str, str] = {
    'alert': 'alert',
    'incident': 'alert',
    'scheduled': 'schedule',
    'manual': 'manual',
    'webhook': 'webhook',
    'api': 'webhook',
    'email': 'email',
    'siem_alert': 'alert',
    'correlation_rule': 'alert',
    'notable_event': 'alert',
}


class ExabeamConverter(PlaybookConverter):
    """
    Converter for Exabeam (New-Scale SOAR) playbooks.

    Exabeam SOAR playbooks are organized as an ordered sequence of phases,
    each containing tasks. Tasks reference integrations and commands (e.g.,
    integration="CrowdStrike", command="contain_host").

    Task types:
    - action: Calls an integration action (integration + command)
    - decision: Conditional branch (true_path / false_path)
    - manual: Requires human input or approval
    - script: Runs custom Python/PowerShell
    - notification: Sends alerts via email, Slack, Teams, etc.
    - enrichment: Gathers data from threat intel / SIEM sources

    The converter flattens the phase/task hierarchy into a sequential node
    graph, preserving the original phase groupings as labels and maintaining
    explicit task-to-task connections where defined (next_task, on_failure,
    true_path, false_path).
    """

    PLATFORM = SourcePlatform.EXABEAM

    def __init__(self):
        super().__init__(EXABEAM_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is from Exabeam SOAR."""
        try:
            data = json.loads(content)

            if not isinstance(data, dict):
                return False

            content_lower = str(data).lower()[:3000]

            indicators = [
                # Primary: playbook_id + phases array
                'playbook_id' in data and isinstance(data.get('phases'), list),
                # Phases with phase_id
                isinstance(data.get('phases'), list) and any(
                    isinstance(p, dict) and 'phase_id' in p
                    for p in data.get('phases', [])[:10]
                ),
                # Tasks within phases with action.integration + action.command
                self._has_exabeam_tasks(data),
                # Exabeam-specific type values
                data.get('type') in ('automation', 'investigation', 'response'),
                # Exabeam branding
                'exabeam' in content_lower,
                # Task types matching Exabeam conventions
                isinstance(data.get('phases'), list) and any(
                    isinstance(p, dict) and isinstance(p.get('tasks'), list) and any(
                        isinstance(t, dict) and t.get('type') in (
                            'action', 'decision', 'manual', 'script',
                            'notification', 'enrichment'
                        )
                        for t in p.get('tasks', [])[:10]
                    )
                    for p in data.get('phases', [])[:5]
                ),
                # Trigger with Exabeam-specific types
                isinstance(data.get('trigger'), dict) and data.get('trigger', {}).get('type') in (
                    'alert', 'incident', 'scheduled', 'manual',
                    'siem_alert', 'correlation_rule', 'notable_event'
                ),
                # playbook_id format (UUID-like)
                isinstance(data.get('playbook_id'), str) and len(data.get('playbook_id', '')) >= 8,
                # Phases with order field
                isinstance(data.get('phases'), list) and any(
                    isinstance(p, dict) and 'order' in p
                    for p in data.get('phases', [])[:10]
                ),
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    def _has_exabeam_tasks(self, data: Dict[str, Any]) -> bool:
        """Check if data has Exabeam-style tasks with action.integration + action.command."""
        phases = data.get('phases', [])
        if not isinstance(phases, list):
            return False

        for phase in phases[:5]:
            if not isinstance(phase, dict):
                continue
            tasks = phase.get('tasks', [])
            if not isinstance(tasks, list):
                continue
            for task in tasks[:10]:
                if not isinstance(task, dict):
                    continue
                action = task.get('action', {})
                if isinstance(action, dict) and ('integration' in action or 'command' in action):
                    return True
        return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Exabeam SOAR playbook export."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('name', data.get('title', 'Exabeam Playbook')),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data,
        )

        # Parse trigger
        trigger_data = data.get('trigger', {})
        if isinstance(trigger_data, dict) and trigger_data:
            parsed.triggers.append(self._parse_trigger(trigger_data))

        # Parse phases and tasks
        phases = data.get('phases', [])
        if not isinstance(phases, list):
            phases = []

        # Sort phases by order
        sorted_phases = sorted(
            [p for p in phases if isinstance(p, dict)],
            key=lambda p: p.get('order', 0)
        )

        step_map: Dict[str, ParsedStep] = {}
        all_tasks_ordered: List[ParsedStep] = []
        phase_last_tasks: List[str] = []  # Last task ID of each phase (for inter-phase edges)

        y_offset = 0
        for phase_idx, phase in enumerate(sorted_phases):
            phase_name = phase.get('name', f'Phase {phase_idx + 1}')
            phase_id = str(phase.get('phase_id', f'phase_{phase_idx}'))
            tasks = phase.get('tasks', [])

            if not isinstance(tasks, list):
                continue

            # Sort tasks by order if present, otherwise preserve array order
            sorted_tasks = sorted(
                [t for t in tasks if isinstance(t, dict)],
                key=lambda t: t.get('order', t.get('position', 0))
            )

            phase_steps: List[ParsedStep] = []
            for task_idx, task in enumerate(sorted_tasks):
                step = self._parse_task(task, phase_name, phase_id, task_idx, y_offset)
                if step:
                    parsed.steps.append(step)
                    step_map[step.id] = step
                    phase_steps.append(step)
                    all_tasks_ordered.append(step)
                    y_offset += 100

            # Track last task of this phase for inter-phase connections
            if phase_steps:
                phase_last_tasks.append(phase_steps[-1].id)

        # Build edges
        self._build_edges(parsed.steps, step_map, sorted_phases, phase_last_tasks)

        # Extract variables from playbook-level inputs/outputs
        playbook_inputs = data.get('inputs', data.get('input_spec', {}))
        if isinstance(playbook_inputs, dict):
            for var_name, var_def in playbook_inputs.items():
                parsed.variables[var_name] = {
                    'type': var_def.get('type', 'string') if isinstance(var_def, dict) else 'string',
                    'default': var_def.get('default', '') if isinstance(var_def, dict) else var_def,
                }

        return parsed

    def _parse_trigger(self, trigger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an Exabeam playbook trigger definition."""
        trigger_type_raw = trigger_data.get('type', 'alert')
        trigger_type = str(trigger_type_raw).lower()
        native_type = TRIGGER_TYPE_MAP.get(trigger_type, 'alert')

        trigger = {
            'type': native_type,
            'original_type': trigger_type,
        }

        # Extract conditions
        conditions = trigger_data.get('conditions', trigger_data.get('filters', {}))
        if conditions:
            trigger['conditions'] = conditions

        # Extract source context
        source = trigger_data.get('source', trigger_data.get('source_type', ''))
        if source:
            trigger['source'] = source

        # Extract alert/incident filters
        severity = trigger_data.get('severity', trigger_data.get('min_severity', ''))
        if severity:
            trigger['severity'] = severity

        alert_type = trigger_data.get('alert_type', trigger_data.get('rule_name', ''))
        if alert_type:
            trigger['alert_type'] = alert_type

        return trigger

    def _parse_task(
        self,
        task: Dict[str, Any],
        phase_name: str,
        phase_id: str,
        task_index: int,
        y_offset: int
    ) -> Optional[ParsedStep]:
        """Parse a single Exabeam task within a phase."""
        task_id = str(task.get('task_id', task.get('id', f'{phase_id}_task_{task_index}')))
        task_name = task.get('name', task.get('display_name', f'Task {task_index + 1}'))
        task_type = task.get('type', 'action').lower()

        # Build a descriptive step type for mapping
        action_data = task.get('action', {})
        if isinstance(action_data, dict) and action_data:
            integration = action_data.get('integration', '').lower()
            command = action_data.get('command', action_data.get('action', '')).lower()
            if integration and command:
                step_type = f'{integration}.{command}'
            elif integration:
                step_type = integration
            elif command:
                step_type = command
            else:
                step_type = task_type
        else:
            step_type = task_type

        step = ParsedStep(
            id=task_id,
            name=task_name,
            step_type=step_type,
            raw=task,
            position={'x': 250, 'y': y_offset},
        )

        # Extract inputs
        inputs = task.get('inputs', {})
        if isinstance(inputs, dict):
            step.inputs = inputs
        elif isinstance(inputs, list):
            step.inputs = {
                inp.get('name', f'input_{i}'): inp.get('value', '')
                for i, inp in enumerate(inputs)
                if isinstance(inp, dict)
            }

        # Extract outputs
        outputs = task.get('outputs', {})
        if isinstance(outputs, dict):
            step.outputs = outputs
        elif isinstance(outputs, list):
            step.outputs = {
                out.get('name', f'output_{i}'): out.get('type', 'string')
                for i, out in enumerate(outputs)
                if isinstance(out, dict)
            }

        # Extract config based on task type
        step.config = self._extract_task_config(task_type, task, phase_name)

        return step

    def _extract_task_config(
        self,
        task_type: str,
        task: Dict[str, Any],
        phase_name: str
    ) -> Dict[str, Any]:
        """Extract task configuration based on type."""
        config: Dict[str, Any] = {
            'phase': phase_name,
            'original_type': task_type,
        }

        action_data = task.get('action', {})
        if not isinstance(action_data, dict):
            action_data = {}

        if task_type == 'action':
            integration = action_data.get('integration', '')
            command = action_data.get('command', action_data.get('action', ''))
            config.update({
                'integration': integration,
                'command': command,
                'action_identifier': f'{integration.lower()}.{command.lower()}' if integration else command.lower(),
                'parameters': action_data.get('parameters', task.get('inputs', {})),
            })

        elif task_type == 'decision':
            conditions = task.get('conditions', [])
            if isinstance(conditions, list):
                config['conditions'] = conditions
            elif isinstance(conditions, dict):
                config['conditions'] = [conditions]
            else:
                config['conditions'] = []

            config['true_path'] = task.get('true_path', task.get('yes_path', ''))
            config['false_path'] = task.get('false_path', task.get('no_path', ''))
            config['operator'] = task.get('operator', task.get('logic', 'and'))

        elif task_type in ('manual', 'approval'):
            config.update({
                'message': task.get('message', task.get('description', 'Manual action required')),
                'assignee': task.get('assignee', task.get('assigned_to', '')),
                'timeout_minutes': task.get('timeout_minutes', task.get('sla_minutes', 60)),
                'instructions': task.get('instructions', task.get('notes', '')),
            })

        elif task_type == 'script':
            config.update({
                'script': task.get('script', task.get('code', '')),
                'language': task.get('language', task.get('script_type', 'python')),
                'timeout_seconds': task.get('timeout_seconds', task.get('timeout', 300)),
            })

        elif task_type == 'notification':
            config.update({
                'channel': action_data.get('channel', task.get('channel', 'email')),
                'recipients': task.get('recipients', task.get('to', [])),
                'subject': task.get('subject', ''),
                'message': task.get('message', task.get('body', '')),
                'template': task.get('template', ''),
            })

        elif task_type == 'enrichment':
            integration = action_data.get('integration', '')
            command = action_data.get('command', action_data.get('action', ''))
            config.update({
                'integration': integration,
                'command': command,
                'action_identifier': f'{integration.lower()}.{command.lower()}' if integration else command.lower(),
                'observable_type': self._guess_observable_from_task(task),
            })

        elif task_type in ('wait', 'timer'):
            duration = task.get('duration', task.get('wait_seconds', task.get('timeout', 60)))
            if isinstance(duration, dict):
                seconds = int(duration.get('seconds', 0))
                minutes = int(duration.get('minutes', 0))
                hours = int(duration.get('hours', 0))
                config['duration_seconds'] = seconds + minutes * 60 + hours * 3600
            else:
                config['duration_seconds'] = int(duration or 60)

        elif task_type in ('subplaybook', 'sub_playbook'):
            config.update({
                'action_type': 'run_playbook',
                'playbook_name': task.get('playbook_name', task.get('sub_playbook', '')),
                'playbook_id': task.get('playbook_id', task.get('sub_playbook_id', '')),
                'inputs': task.get('inputs', {}),
            })

        else:
            # Unknown type — copy all fields as config
            for key, value in task.items():
                if key not in ('task_id', 'id', 'name', 'type', 'display_name'):
                    config[key] = value

        return config

    def _build_edges(
        self,
        steps: List[ParsedStep],
        step_map: Dict[str, ParsedStep],
        sorted_phases: List[Dict[str, Any]],
        phase_last_tasks: List[str]
    ) -> None:
        """
        Build step connections from Exabeam task references and phase ordering.

        Connection sources:
        1. Explicit next_task / on_success references within tasks
        2. Explicit on_failure / on_error references
        3. Decision task true_path / false_path
        4. Sequential task ordering within phases
        5. Phase-to-phase connections (last task of phase N -> first task of phase N+1)
        """
        if not steps:
            return

        # Build a map of phase_id -> ordered task IDs
        phase_task_ids: Dict[str, List[str]] = {}
        for phase in sorted_phases:
            phase_id = str(phase.get('phase_id', ''))
            tasks = phase.get('tasks', [])
            if not isinstance(tasks, list):
                continue

            sorted_tasks = sorted(
                [t for t in tasks if isinstance(t, dict)],
                key=lambda t: t.get('order', t.get('position', 0))
            )

            task_ids = []
            for task in sorted_tasks:
                tid = str(task.get('task_id', task.get('id', '')))
                if tid in step_map:
                    task_ids.append(tid)
            if task_ids:
                phase_task_ids[phase_id] = task_ids

        # 1 & 2. Apply explicit task-level connections
        for step in steps:
            task_raw = step.raw
            if not isinstance(task_raw, dict):
                continue

            # next_task / on_success
            next_task = task_raw.get('next_task', task_raw.get('on_success', ''))
            if next_task and str(next_task) in step_map:
                next_id = str(next_task)
                if next_id not in step.next_steps:
                    step.next_steps.append(next_id)

            # on_failure / on_error
            on_failure = task_raw.get('on_failure', task_raw.get('on_error', ''))
            if on_failure and str(on_failure) in step_map:
                fail_id = str(on_failure)
                if fail_id not in step.next_steps:
                    step.next_steps.append(fail_id)
                    if not step.condition:
                        step.condition = 'on_failure'

            # 3. Decision true_path / false_path
            config = step.config or {}
            true_path = config.get('true_path', '')
            if true_path and str(true_path) in step_map:
                true_id = str(true_path)
                if true_id not in step.next_steps:
                    step.next_steps.append(true_id)

            false_path = config.get('false_path', '')
            if false_path and str(false_path) in step_map:
                false_id = str(false_path)
                if false_id not in step.next_steps:
                    step.next_steps.append(false_id)

        # 4. Sequential connections within phases (for tasks without explicit next_task)
        for phase_id, task_ids in phase_task_ids.items():
            for i in range(len(task_ids) - 1):
                current_step = step_map.get(task_ids[i])
                next_step = step_map.get(task_ids[i + 1])
                if current_step and next_step:
                    # Only add sequential edge if no explicit edges exist
                    if not current_step.next_steps:
                        current_step.next_steps.append(next_step.id)
                    # For decision nodes with explicit branches, don't add sequential edge
                    elif current_step.config.get('original_type') == 'decision':
                        pass  # Decision nodes use true_path/false_path
                    # If explicit edges point elsewhere, still add sequential as fallback
                    # only if the next task isn't already connected
                    elif next_step.id not in current_step.next_steps:
                        # Check if any explicit edge already goes to the next task
                        has_explicit_next = any(
                            ns in step_map for ns in current_step.next_steps
                        )
                        if not has_explicit_next:
                            current_step.next_steps.append(next_step.id)

        # 5. Phase-to-phase connections
        phase_ids_ordered = list(phase_task_ids.keys())
        for i in range(len(phase_ids_ordered) - 1):
            current_phase_tasks = phase_task_ids.get(phase_ids_ordered[i], [])
            next_phase_tasks = phase_task_ids.get(phase_ids_ordered[i + 1], [])

            if current_phase_tasks and next_phase_tasks:
                last_step = step_map.get(current_phase_tasks[-1])
                first_step = step_map.get(next_phase_tasks[0])

                if last_step and first_step:
                    # Only add inter-phase edge if the last step has no outgoing edges
                    # or its existing edges don't point to the next phase
                    next_phase_ids = set(next_phase_tasks)
                    has_cross_phase = any(ns in next_phase_ids for ns in last_step.next_steps)
                    if not has_cross_phase and first_step.id not in last_step.next_steps:
                        last_step.next_steps.append(first_step.id)

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map an Exabeam task to a native T1 node type.

        Mapping priority:
        1. Task type (decision, manual, script, notification, enrichment, wait)
        2. Integration.command lookup in EXABEAM_ACTIONS
        3. Fuzzy matching via find_best_mapping()
        4. Integration-based heuristics
        5. Command name keyword heuristics
        6. Default to 'action'
        """
        config = step.config or {}
        original_type = config.get('original_type', '')
        integration = config.get('integration', '').lower()
        command = config.get('command', '').lower()
        action_id = config.get('action_identifier', '').lower()

        # ------------------------------------------------------------------
        # 1. Direct task type mappings (non-action types)
        # ------------------------------------------------------------------
        if original_type == 'decision':
            return 'condition', {
                'conditions': config.get('conditions', []),
                'operator': config.get('operator', 'and'),
                'true_path': config.get('true_path', ''),
                'false_path': config.get('false_path', ''),
            }

        if original_type in ('manual', 'approval'):
            return 'approval_gate', {
                'message': config.get('message', step.name),
                'assignee': config.get('assignee', ''),
                'timeout_minutes': config.get('timeout_minutes', 60),
                'instructions': config.get('instructions', ''),
            }

        if original_type == 'script':
            return 'python_code', {
                'script': config.get('script', ''),
                'language': config.get('language', 'python'),
                'timeout_seconds': config.get('timeout_seconds', 300),
            }

        if original_type == 'notification':
            channel = config.get('channel', 'email').lower()
            return 'notify', {
                'channel': channel,
                'recipients': config.get('recipients', []),
                'subject': config.get('subject', ''),
                'message': config.get('message', ''),
                'template': config.get('template', ''),
            }

        if original_type in ('wait', 'timer'):
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60),
            }

        if original_type in ('subplaybook', 'sub_playbook'):
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', step.name),
                'playbook_id': config.get('playbook_id', ''),
            }

        if original_type in ('end', 'close'):
            return 'end', {'disposition': 'completed'}

        # ------------------------------------------------------------------
        # 2. Action identifier lookup (integration.command format)
        # ------------------------------------------------------------------
        if action_id:
            # Exact match
            if action_id in self.action_maps:
                node_type, base_config = self.action_maps[action_id]
                merged = {**base_config}
                self._merge_task_config(merged, config)
                return node_type, merged

            # Try just the command
            if command and command in self.action_maps:
                node_type, base_config = self.action_maps[command]
                merged = {**base_config}
                self._merge_task_config(merged, config)
                return node_type, merged

        # ------------------------------------------------------------------
        # 3. Fuzzy matching via find_best_mapping
        # ------------------------------------------------------------------
        if action_id:
            best = find_best_mapping(action_id, 'exabeam')
            if best[0] != 'unmapped':
                node_type, base_config = best
                merged = {**base_config}
                self._merge_task_config(merged, config)
                return node_type, merged

        if command:
            best = find_best_mapping(command, 'exabeam')
            if best[0] != 'unmapped':
                node_type, base_config = best
                merged = {**base_config}
                self._merge_task_config(merged, config)
                return node_type, merged

        # ------------------------------------------------------------------
        # 4. Integration-based heuristics
        # ------------------------------------------------------------------
        if integration:
            result = self._map_by_integration(integration, command, config)
            if result:
                return result

        # ------------------------------------------------------------------
        # 5. Enrichment type with integration context
        # ------------------------------------------------------------------
        if original_type == 'enrichment':
            return 'enrich', {
                'integration': integration,
                'action': command,
                'observable_type': config.get('observable_type', self._guess_observable_from_command(command)),
            }

        # ------------------------------------------------------------------
        # 6. Command name keyword heuristics
        # ------------------------------------------------------------------
        combined = f'{integration} {command} {step.name}'.lower()

        if any(kw in combined for kw in ['scan', 'lookup', 'search', 'query', 'enrich', 'reputation', 'check', 'get_', 'analyze']):
            return 'enrich', {
                'integration': integration,
                'action': command,
                'auto_mapped': True,
            }
        if any(kw in combined for kw in ['block', 'isolate', 'contain', 'quarantine', 'disable', 'terminate', 'kill', 'revoke']):
            return 'action', {
                'integration': integration,
                'action': command,
                'requires_approval': True,
                'auto_mapped': True,
            }
        if any(kw in combined for kw in ['notify', 'send', 'email', 'slack', 'teams', 'message', 'alert']):
            return 'notify', {
                'integration': integration,
                'action': command,
                'auto_mapped': True,
            }
        if any(kw in combined for kw in ['ticket', 'incident', 'case', 'issue', 'create']):
            return 'create_ticket', {
                'integration': integration,
                'action': command,
                'auto_mapped': True,
            }
        if any(kw in combined for kw in ['close', 'resolve', 'complete']):
            return 'end', {'disposition': 'completed', 'auto_mapped': True}
        if any(kw in combined for kw in ['approve', 'approval', 'review']):
            return 'approval_gate', {
                'action': command,
                'auto_mapped': True,
            }

        # ------------------------------------------------------------------
        # 7. Default: generic action
        # ------------------------------------------------------------------
        return 'action', {
            'integration': integration,
            'action': command,
            'unmapped': True,
        }

    # ========================================================================
    # Mapping helpers
    # ========================================================================

    def _map_by_integration(
        self,
        integration: str,
        command: str,
        config: Dict[str, Any]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Map based on known integration categories."""
        int_lower = integration.lower()

        # Enrichment integrations
        enrich_integrations = [
            'virustotal', 'shodan', 'abuseipdb', 'greynoise', 'hybrid_analysis',
            'urlscan', 'whois', 'dns', 'maxmind', 'ipinfo', 'censys',
            'recorded_future', 'misp', 'alienvault', 'otx', 'threatconnect',
            'passivetotal', 'domaintools', 'pulsedive',
        ]
        if any(ei in int_lower for ei in enrich_integrations):
            return 'enrich', {
                'integration': integration,
                'action': command,
                'observable_type': self._guess_observable_from_command(command),
            }

        # EDR / endpoint integrations
        edr_integrations = [
            'crowdstrike', 'sentinelone', 'carbon_black', 'cybereason',
            'microsoft_defender', 'cortex_xdr', 'tanium', 'cylance',
        ]
        if any(ei in int_lower for ei in edr_integrations):
            requires_approval = any(
                kw in command
                for kw in ['contain', 'isolate', 'block', 'quarantine', 'disable', 'kill']
            )
            if any(kw in command for kw in ['get', 'search', 'list', 'find', 'query']):
                return 'enrich', {
                    'integration': integration,
                    'action': command,
                    'observable_type': 'host',
                }
            return 'action', {
                'integration': integration,
                'action': command,
                'requires_approval': requires_approval,
            }

        # Identity integrations
        identity_integrations = [
            'active_directory', 'okta', 'azure_ad', 'ping_identity',
            'ldap', 'cyberark', 'sailpoint',
        ]
        if any(ii in int_lower for ii in identity_integrations):
            if any(kw in command for kw in ['get', 'search', 'list', 'find', 'lookup']):
                return 'enrich', {
                    'integration': integration,
                    'action': command,
                    'observable_type': 'user',
                }
            return 'action', {
                'integration': integration,
                'action': command,
                'requires_approval': True,
            }

        # Firewall / network integrations
        firewall_integrations = [
            'palo_alto', 'fortinet', 'fortigate', 'cisco', 'checkpoint',
            'zscaler', 'netskope',
        ]
        if any(fi in int_lower for fi in firewall_integrations):
            return 'action', {
                'integration': integration,
                'action': command,
                'requires_approval': True,
            }

        # Ticketing integrations
        ticket_integrations = [
            'servicenow', 'jira', 'pagerduty', 'opsgenie', 'bmc_remedy',
        ]
        if any(ti in int_lower for ti in ticket_integrations):
            if 'create' in command:
                return 'create_ticket', {'integration': integration, 'action': command}
            return 'action', {
                'action_type': 'update_ticket',
                'integration': integration,
                'action': command,
            }

        # Notification integrations
        notify_integrations = ['slack', 'teams', 'email', 'smtp', 'webhook']
        if any(ni in int_lower for ni in notify_integrations):
            channel = int_lower
            if 'email' in int_lower or 'smtp' in int_lower:
                channel = 'email'
            elif 'slack' in int_lower:
                channel = 'slack'
            elif 'teams' in int_lower:
                channel = 'teams'
            return 'notify', {
                'channel': channel,
                'integration': integration,
                'action': command,
            }

        # SIEM / Exabeam native
        siem_integrations = [
            'exabeam', 'splunk', 'qradar', 'elastic', 'chronicle',
            'sentinel', 'sumo_logic', 'logrhythm',
        ]
        if any(si in int_lower for si in siem_integrations):
            return 'enrich', {
                'integration': integration,
                'action': command,
                'observable_type': 'events',
            }

        # Cloud integrations
        cloud_integrations = ['aws', 'azure', 'gcp', 'google_cloud']
        if any(ci in int_lower for ci in cloud_integrations):
            if any(kw in command for kw in ['get', 'list', 'describe', 'search']):
                return 'enrich', {
                    'integration': integration,
                    'action': command,
                    'auto_mapped': True,
                }
            return 'action', {
                'integration': integration,
                'action': command,
                'requires_approval': True,
                'auto_mapped': True,
            }

        return None

    def _merge_task_config(
        self, target: Dict[str, Any], source: Dict[str, Any]
    ) -> None:
        """Merge useful fields from task config into target config."""
        for key in ('parameters', 'inputs', 'script', 'phase'):
            if key in source:
                target[key] = source[key]

    def _guess_observable_from_task(self, task: Dict[str, Any]) -> str:
        """Guess observable type from task context."""
        # Check inputs for observable hints
        inputs = task.get('inputs', {})
        if isinstance(inputs, dict):
            input_keys = ' '.join(str(k) for k in inputs.keys()).lower()
            input_vals = ' '.join(str(v) for v in inputs.values() if isinstance(v, str)).lower()
            combined = f'{input_keys} {input_vals}'

            if any(kw in combined for kw in ['ip', 'address', 'src_ip', 'dst_ip']):
                return 'ip'
            if any(kw in combined for kw in ['domain', 'fqdn', 'hostname']):
                return 'domain'
            if any(kw in combined for kw in ['hash', 'md5', 'sha1', 'sha256']):
                return 'hash'
            if any(kw in combined for kw in ['url', 'link', 'uri']):
                return 'url'
            if any(kw in combined for kw in ['email', 'sender', 'recipient']):
                return 'email'
            if any(kw in combined for kw in ['user', 'account', 'username']):
                return 'user'

        # Check action context
        action = task.get('action', {})
        if isinstance(action, dict):
            command = action.get('command', '').lower()
            return self._guess_observable_from_command(command)

        return 'unknown'

    @staticmethod
    def _guess_observable_from_command(command: str) -> str:
        """Guess the observable type from a command name."""
        command_lower = command.lower()
        if any(kw in command_lower for kw in ['ip', 'address']):
            return 'ip'
        if any(kw in command_lower for kw in ['domain', 'dns', 'fqdn']):
            return 'domain'
        if any(kw in command_lower for kw in ['hash', 'file', 'md5', 'sha']):
            return 'hash'
        if any(kw in command_lower for kw in ['url', 'link']):
            return 'url'
        if any(kw in command_lower for kw in ['email', 'mail']):
            return 'email'
        if any(kw in command_lower for kw in ['user', 'account', 'identity']):
            return 'user'
        if any(kw in command_lower for kw in ['host', 'device', 'endpoint', 'machine', 'agent']):
            return 'host'
        return 'unknown'
