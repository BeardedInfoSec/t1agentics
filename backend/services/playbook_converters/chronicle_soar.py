# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Google Chronicle SOAR (Siemplify) Playbook Converter

Converts Chronicle SOAR playbooks to T1 Agentics native format.

Chronicle SOAR (formerly Siemplify) export format:
- playbook_name, description, version
- steps: dict of step_identifier -> step_definition
- connections: list of {source_step, target_step, condition}
- Step types: Trigger, Action, Condition, Parallel, Placeholder, Wait
- Actions reference integration.action (e.g. "VirusTotal_Scan IP")
- Conditions use expression field with operators
- Playbook trigger types: ALERT, MANUAL, NESTED, SCHEDULED
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import CHRONICLE_SOAR_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Chronicle SOAR step type -> native node type
# ============================================================================

STEP_TYPE_MAP: Dict[str, str] = {
    'trigger': 'trigger',
    'action': 'action',
    'condition': 'condition',
    'parallel': 'transform',
    'placeholder': 'action',
    'wait': 'delay',
    'manual': 'approval_gate',
    'nested_playbook': 'action',
    'visual_link': None,  # skip
    'flow_control': 'condition',
}


class ChronicleSoarConverter(PlaybookConverter):
    """
    Converter for Google Chronicle SOAR (Siemplify) playbooks.

    Chronicle SOAR playbook structure:
    - Steps are stored in a dict keyed by step identifier
    - Each step has: name, type, integration, action, parameters, conditions
    - Connections define the flow between steps
    - Actions are referenced as "Integration_ActionName" or "integration.action"

    Step types:
    - Trigger: Entry point (alert, manual, scheduled, nested)
    - Action: Execute an integration action
    - Condition: Conditional branching (if/else)
    - Parallel: Fork execution
    - Placeholder: Marker/comment node
    - Wait: Timer/delay node
    - Manual: Human approval step
    """

    PLATFORM = SourcePlatform.CHRONICLE_SOAR

    def __init__(self):
        super().__init__(CHRONICLE_SOAR_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is from Google Chronicle SOAR (Siemplify)."""
        try:
            data = json.loads(content)

            if not isinstance(data, dict):
                return False

            content_lower = str(data).lower()[:3000]

            indicators = [
                'playbook_name' in data,
                'steps' in data and isinstance(data.get('steps'), (dict, list)),
                'playbook_trigger_type' in data,
                'siemplify' in content_lower,
                'chronicle' in content_lower and 'soar' in content_lower,
                'identifier' in data and 'steps' in data,
                'environment' in data and 'priority' in data,
                isinstance(data.get('steps'), dict) and any(
                    isinstance(v, dict) and 'type' in v
                    for v in (data.get('steps') or {}).values()
                ),
                'creator' in data and 'modification_time_unix_time_in_ms' in data,
                'category' in data and 'is_enabled' in data,
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Chronicle SOAR playbook export."""
        data = json.loads(content)

        parsed = ParsedPlaybook(
            name=data.get('playbook_name', data.get('name', 'Chronicle SOAR Playbook')),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data,
        )

        # Parse steps (dict or list format)
        steps_data = data.get('steps', {})
        step_map: Dict[str, ParsedStep] = {}

        if isinstance(steps_data, dict):
            for step_id, step_def in steps_data.items():
                step = self._parse_step(step_id, step_def)
                if step:
                    parsed.steps.append(step)
                    step_map[step.id] = step
        elif isinstance(steps_data, list):
            for i, step_def in enumerate(steps_data):
                step_id = str(step_def.get('identifier', step_def.get('id', f'step_{i}')))
                step = self._parse_step(step_id, step_def)
                if step:
                    parsed.steps.append(step)
                    step_map[step.id] = step

        # Parse connections
        connections = data.get('connections', [])
        for conn in connections:
            self._apply_connection(conn, step_map)

        # Also check for inline next_step references in step definitions
        if isinstance(steps_data, dict):
            for step_id, step_def in steps_data.items():
                if step_id in step_map:
                    self._parse_inline_connections(step_map[step_id], step_def, step_map)

        # Identify triggers
        trigger_type = data.get('playbook_trigger_type', '')
        for step in parsed.steps:
            if step.step_type == 'trigger':
                parsed.triggers.append({
                    'node_id': step.id,
                    'type': trigger_type or step.config.get('trigger_type', 'alert'),
                })

        return parsed

    def _parse_step(self, step_id: str, step_def: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Chronicle SOAR step."""
        if not isinstance(step_def, dict):
            return None

        step_type = step_def.get('type', step_def.get('step_type', 'action')).lower()

        # Skip visual-only elements
        if step_type == 'visual_link':
            return None

        step_name = step_def.get('name', step_def.get('display_name', f'Step {step_id}'))

        step = ParsedStep(
            id=step_id,
            name=step_name,
            step_type=step_type,
            raw=step_def,
        )

        # Extract position
        position = step_def.get('position', step_def.get('ui_position', {}))
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0)),
            }

        # Extract config based on step type
        step.config = self._extract_step_config(step_type, step_def)

        return step

    def _extract_step_config(
        self, step_type: str, step_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract step configuration based on type."""
        config: Dict[str, Any] = {}

        if step_type == 'trigger':
            config = {
                'trigger_type': step_def.get('trigger_type', step_def.get('playbook_trigger_type', 'alert')).lower(),
                'filters': step_def.get('filters', []),
                'conditions': step_def.get('conditions', []),
            }

        elif step_type == 'action':
            integration = step_def.get('integration', step_def.get('integration_identifier', ''))
            action = step_def.get('action', step_def.get('action_identifier', ''))

            # Chronicle SOAR often uses "Integration_ActionName" format
            if not integration and '_' in action:
                parts = action.split('_', 1)
                integration = parts[0]

            config = {
                'integration': integration,
                'action': action,
                'action_identifier': f'{integration}.{action}'.lower() if integration else action.lower(),
                'parameters': step_def.get('parameters', step_def.get('properties', {})),
                'script': step_def.get('script', ''),
            }

        elif step_type == 'condition':
            config = {
                'conditions': step_def.get('conditions', []),
                'expression': step_def.get('expression', ''),
                'operator': step_def.get('operator', step_def.get('logical_operator', 'and')),
                'branches': step_def.get('branches', {}),
            }

        elif step_type == 'parallel':
            config = {
                'branches': step_def.get('branches', []),
                'wait_for_all': step_def.get('wait_for_all', True),
            }

        elif step_type == 'wait':
            duration = step_def.get('duration', step_def.get('timeout', {}))
            if isinstance(duration, dict):
                seconds = int(duration.get('seconds', 0))
                minutes = int(duration.get('minutes', 0))
                hours = int(duration.get('hours', 0))
                config = {'duration_seconds': seconds + minutes * 60 + hours * 3600}
            else:
                config = {'duration_seconds': int(duration or 60)}

        elif step_type == 'manual':
            config = {
                'message': step_def.get('message', step_def.get('description', 'Manual approval required')),
                'assignee': step_def.get('assignee', ''),
                'timeout_minutes': step_def.get('timeout_minutes', 60),
            }

        elif step_type == 'nested_playbook':
            config = {
                'playbook_name': step_def.get('playbook_identifier', step_def.get('nested_playbook_name', '')),
                'action_type': 'run_playbook',
                'inputs': step_def.get('inputs', step_def.get('parameters', {})),
            }

        elif step_type == 'placeholder':
            config = {
                'note': step_def.get('description', step_def.get('note', '')),
                'placeholder_type': step_def.get('placeholder_type', 'comment'),
            }

        else:
            config = {k: v for k, v in step_def.items() if k not in ('name', 'type', 'position', 'id', 'identifier')}

        return config

    def _apply_connection(
        self, conn: Dict[str, Any], step_map: Dict[str, ParsedStep]
    ) -> None:
        """Apply a connection between two steps."""
        source_id = str(conn.get('source_step', conn.get('source', conn.get('from', ''))))
        target_id = str(conn.get('target_step', conn.get('target', conn.get('to', ''))))
        condition_label = conn.get('condition', conn.get('label', conn.get('name', '')))

        source = step_map.get(source_id)
        if source and target_id in step_map:
            if target_id not in source.next_steps:
                source.next_steps.append(target_id)
            if condition_label and not source.condition:
                source.condition = str(condition_label)

    def _parse_inline_connections(
        self, step: ParsedStep, step_def: Dict[str, Any], step_map: Dict[str, ParsedStep]
    ) -> None:
        """Parse connections defined inline within step definitions."""
        next_step = step_def.get('next_step', step_def.get('on_success', ''))
        if next_step and str(next_step) in step_map:
            if str(next_step) not in step.next_steps:
                step.next_steps.append(str(next_step))

        on_failure = step_def.get('on_failure', '')
        if on_failure and str(on_failure) in step_map:
            if str(on_failure) not in step.next_steps:
                step.next_steps.append(str(on_failure))

        branches = step_def.get('branches', {})
        if isinstance(branches, dict):
            for branch_label, branch_target in branches.items():
                target_id = str(branch_target) if not isinstance(branch_target, dict) else str(branch_target.get('target', ''))
                if target_id in step_map and target_id not in step.next_steps:
                    step.next_steps.append(target_id)

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map a Chronicle SOAR step to a native T1 node type.

        Mapping priority:
        1. Step type (Trigger, Condition, Wait, Manual, etc.)
        2. integration.action lookup in CHRONICLE_SOAR_ACTIONS
        3. Fuzzy matching via find_best_mapping()
        4. Integration name heuristics
        5. Default to 'action'
        """
        step_type = step.step_type.lower()
        config = step.config or {}
        integration = config.get('integration', '').lower()
        action = config.get('action', '').lower()
        action_id = config.get('action_identifier', '').lower()

        # ------------------------------------------------------------------
        # 1. Direct step type mapping
        # ------------------------------------------------------------------
        if step_type in STEP_TYPE_MAP:
            native_type = STEP_TYPE_MAP[step_type]

            if native_type is None:
                return 'action', {'unmapped': True, 'note': f'Skipped visual element: {step.name}'}

            if native_type == 'trigger':
                return 'trigger', {
                    'trigger_type': config.get('trigger_type', 'alert'),
                    'filters': config.get('filters', []),
                }

            elif native_type == 'condition':
                return 'condition', {
                    'expression': config.get('expression', ''),
                    'conditions': config.get('conditions', []),
                    'operator': config.get('operator', 'and'),
                }

            elif native_type == 'delay':
                return 'delay', {
                    'duration_seconds': config.get('duration_seconds', 60),
                }

            elif native_type == 'approval_gate':
                return 'approval_gate', {
                    'message': config.get('message', step.name),
                    'assignee': config.get('assignee', ''),
                    'timeout_minutes': config.get('timeout_minutes', 60),
                }

            elif native_type == 'transform':
                return 'transform', {
                    'transform_type': 'parallel',
                    'branches': config.get('branches', []),
                }

            # For 'action' type (from Action, Placeholder, nested_playbook),
            # fall through to action resolution below

        # ------------------------------------------------------------------
        # 2. Action identifier lookup (integration.action format)
        # ------------------------------------------------------------------
        if action_id:
            if action_id in self.action_maps:
                return self.action_maps[action_id]

            if action and action in self.action_maps:
                return self.action_maps[action]

            best = find_best_mapping(action_id, 'chronicle_soar')
            if best:
                return best

        # ------------------------------------------------------------------
        # 3. Integration-based heuristics
        # ------------------------------------------------------------------
        if integration:
            enrich_integrations = [
                'virustotal', 'shodan', 'abuseipdb', 'greynoise', 'hybrid_analysis',
                'urlscan', 'whois', 'dns', 'maxmind', 'ipinfo', 'censys',
                'alienvault', 'otx', 'threatcrowd', 'recordedfuture', 'misp',
            ]
            action_integrations = [
                'crowdstrike', 'carbonblack', 'sentinelone', 'cybereason',
                'activedirectory', 'ad', 'ldap',
            ]
            ticket_integrations = [
                'servicenow', 'jira', 'thehive', 'pagerduty', 'opsgenie',
            ]
            notify_integrations = [
                'slack', 'teams', 'email', 'smtp', 'webhook',
            ]

            if any(ei in integration for ei in enrich_integrations):
                return 'enrich', {'integration': integration, 'action': action, 'observable_type': self._guess_observable(action)}
            if any(ai in integration for ai in action_integrations):
                return 'action', {'integration': integration, 'action': action}
            if any(ti in integration for ti in ticket_integrations):
                return 'create_ticket', {'integration': integration, 'action': action}
            if any(ni in integration for ni in notify_integrations):
                return 'notify', {'integration': integration, 'action': action}

        # ------------------------------------------------------------------
        # 4. Action name heuristics
        # ------------------------------------------------------------------
        if action:
            combined = f'{integration}_{action}'.lower()
            if any(kw in combined for kw in ['scan', 'lookup', 'search', 'query', 'enrich', 'reputation', 'check']):
                return 'enrich', {'integration': integration, 'action': action}
            if any(kw in combined for kw in ['block', 'isolate', 'contain', 'quarantine', 'disable']):
                return 'action', {'integration': integration, 'action': action, 'requires_approval': True}
            if any(kw in combined for kw in ['notify', 'send', 'email', 'message']):
                return 'notify', {'integration': integration, 'action': action}
            if any(kw in combined for kw in ['ticket', 'incident', 'case', 'create']):
                return 'create_ticket', {'integration': integration, 'action': action}

        # ------------------------------------------------------------------
        # 5. Nested playbook
        # ------------------------------------------------------------------
        if step_type == 'nested_playbook' or config.get('action_type') == 'run_playbook':
            return 'action', {
                'action_type': 'run_playbook',
                'playbook_name': config.get('playbook_name', step.name),
            }

        # ------------------------------------------------------------------
        # 6. Default: generic action
        # ------------------------------------------------------------------
        return 'action', {
            'integration': integration,
            'action': action,
            'unmapped': True,
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
        return 'unknown'
