# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Swimlane SOAR Playbook Converter

Converts Swimlane Turbine workflows and SSP action packages to T1 Agentics
native format.

Swimlane export formats:

1. Turbine Workflow (newer Swimlane Turbine platform):
   - playbook.nodes: Array of node definitions (trigger, action, condition, etc.)
   - playbook.connections: Array of edges between nodes
   - Top-level name and description

2. SSP Action Package (older, integration-level):
   - actionType: The action class name (e.g. "GreyNoiseIPLookup")
   - family: Action category (Investigation, Containment, Notification, etc.)
   - assetDependencyType: Integration name (e.g. "GreyNoise")
   - inputParameters / availableOutputVariables
   - scriptFile: Python script backing the action

3. SSP Package Wrapper (metadata-only manifest):
   - supported_swimlane_version: Version constraint
   - packages: List of package names
   - vendor: Vendor name

Formats 2 and 3 are converted to single-node playbooks.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import SWIMLANE_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# Swimlane action family -> native node type
# ============================================================================

FAMILY_TYPE_MAP: Dict[str, str] = {
    'investigation': 'enrich',
    'containment': 'action',
    'notification': 'notify',
    'remediation': 'action',
    'utility': 'transform',
    'enrichment': 'enrich',
    'response': 'action',
    'triage': 'enrich',
    'communication': 'notify',
}

# Swimlane Turbine node type -> native node type
NODE_TYPE_MAP: Dict[str, str] = {
    'trigger': 'trigger',
    'action': 'action',
    'condition': 'condition',
    'decision': 'condition',
    'parallel': 'transform',
    'loop': 'transform',
    'delay': 'delay',
    'approval': 'approval_gate',
    'notification': 'notify',
    'end': 'end',
    'script': 'python_code',
    'subworkflow': 'action',
    'transform': 'transform',
    'webhook': 'webhook_call',
    'email': 'notify',
    'integration': 'action',
}

class SwimlaneConverter(PlaybookConverter):
    """
    Converter for Swimlane Turbine workflows and SSP action packages.

    Handles three Swimlane export formats:
    - Turbine Workflow JSON (full playbook with nodes and connections)
    - SSP Action Package JSON (single integration action definition)
    - SSP Package Wrapper JSON (metadata manifest referencing packages)

    Turbine node types:
    - trigger: Entry point (alert, schedule, webhook)
    - action: Execute an integration action
    - condition/decision: Conditional branching
    - parallel: Fork execution
    - loop: Iterate over a collection
    - delay: Wait/pause
    - approval: Human-in-the-loop gate
    - notification: Send notification
    - script: Custom Python/PowerShell
    - subworkflow: Run another workflow
    - end: Terminal node

    SSP action families:
    - Investigation: Enrichment lookups -> enrich
    - Containment: Isolate/block actions -> action
    - Notification: Alert/message sending -> notify
    - Remediation: Fix/restore actions -> action
    - Utility: Data transforms -> transform
    """

    PLATFORM = SourcePlatform.SWIMLANE

    def __init__(self):
        super().__init__(SWIMLANE_ACTIONS)

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """
        Detect if content is from Swimlane.

        Checks for:
        - supported_swimlane_version (SSP package wrapper)
        - actionType + assetDependencyType (SSP action package)
        - playbook.nodes (Turbine workflow)
        - 'swimlane' keyword anywhere in content
        """
        try:
            data = json.loads(content)

            if not isinstance(data, dict):
                return False

            content_str = str(data).lower()

            indicators = [
                # SSP package wrapper
                'supported_swimlane_version' in data,
                # SSP action package
                'actionType' in data and (
                    'assetDependencyType' in data or 'inputParameters' in data
                ),
                # Turbine workflow -- nodes inside playbook key
                isinstance(data.get('playbook'), dict) and 'nodes' in data.get('playbook', {}),
                # Generic keyword match
                'swimlane' in content_str,
                # Package list (SSP wrapper)
                'packages' in data and 'vendor' in data,
                # Turbine-specific keys
                'workflowId' in data or 'workflow_id' in data,
                # Family field from SSP actions
                'family' in data and 'scriptFile' in data,
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """
        Parse Swimlane playbook/action content.

        Routes to the correct parser based on detected format:
        - Turbine Workflow: playbook.nodes present
        - SSP Action Package: actionType present
        - SSP Package Wrapper: supported_swimlane_version or packages present
        """
        data = json.loads(content)

        # Determine format and dispatch
        if isinstance(data.get('playbook'), dict) and 'nodes' in data.get('playbook', {}):
            return self._parse_turbine_workflow(data)
        elif 'actionType' in data:
            return self._parse_ssp_action(data)
        elif 'supported_swimlane_version' in data or ('packages' in data and 'vendor' in data):
            return self._parse_ssp_package_wrapper(data)
        else:
            # Best-effort: try Turbine first, fall back to single-node
            if 'nodes' in data and isinstance(data.get('nodes'), list):
                # Nodes at top level instead of under playbook key
                wrapper = {
                    'name': data.get('name', 'Imported Swimlane Workflow'),
                    'description': data.get('description', ''),
                    'playbook': {
                        'nodes': data['nodes'],
                        'connections': data.get('connections', data.get('edges', []))
                    }
                }
                wrapper.update({k: v for k, v in data.items() if k not in ('nodes', 'connections', 'edges')})
                return self._parse_turbine_workflow(wrapper)

            # Fallback: create a minimal single-node playbook
            return self._parse_generic_swimlane(data)
    def _parse_turbine_workflow(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """
        Parse a Swimlane Turbine workflow export.

        Expected structure:
        {
            "name": "...",
            "description": "...",
            "playbook": {
                "nodes": [...],
                "connections": [...]
            }
        }
        """
        playbook_data = data.get('playbook', {})
        nodes = playbook_data.get('nodes', [])
        connections = playbook_data.get('connections', playbook_data.get('edges', []))

        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported Swimlane Workflow'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', data.get('workflowVersion', '1.0'))),
            raw=data
        )

        # Parse variables / global config
        if 'variables' in data:
            parsed.variables = data['variables']
        elif 'variables' in playbook_data:
            parsed.variables = playbook_data['variables']

        # Build node map for connection resolution
        node_map: Dict[str, ParsedStep] = {}

        for node in nodes:
            step = self._parse_turbine_node(node)
            if step:
                parsed.steps.append(step)
                node_map[step.id] = step

        # Parse connections
        for conn in connections:
            source_id = str(conn.get('source', conn.get('sourceId', conn.get('from', ''))))
            target_id = str(conn.get('target', conn.get('targetId', conn.get('to', ''))))
            condition_label = conn.get('label', conn.get('condition', None))

            source_step = node_map.get(source_id)
            if source_step and target_id:
                if target_id not in source_step.next_steps:
                    source_step.next_steps.append(target_id)
                # Preserve condition label on the edge
                if condition_label and not source_step.condition:
                    source_step.condition = str(condition_label)

        # Identify triggers
        trigger_types = {'trigger', 'webhook', 'schedule'}
        for step in parsed.steps:
            if step.step_type in trigger_types:
                parsed.triggers.append({
                    'node_id': step.id,
                    'type': step.step_type
                })

        return parsed

    def _parse_turbine_node(self, node: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Turbine workflow node."""
        node_id = str(node.get('id', ''))
        node_type = node.get('type', 'action').lower()
        node_name = node.get('name', node.get('label', f'Node {node_id}'))
        config_data = node.get('config', {})

        step = ParsedStep(
            id=node_id,
            name=node_name,
            step_type=node_type,
            raw=node
        )

        # Extract position
        position = node.get('position', {})
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        # Extract configuration based on node type
        step.config = self._extract_turbine_node_config(node_type, config_data, node)

        # Extract inputs/outputs if present
        if 'inputs' in node:
            step.inputs = node['inputs']
        elif 'inputParameters' in config_data:
            step.inputs = config_data['inputParameters']

        if 'outputs' in node:
            step.outputs = node['outputs']
        elif 'outputVariables' in config_data:
            step.outputs = config_data['outputVariables']

        return step
    def _extract_turbine_node_config(
        self,
        node_type: str,
        config: Dict[str, Any],
        node: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a Turbine workflow node."""
        result: Dict[str, Any] = {}

        if node_type == 'trigger':
            result = {
                'trigger_type': config.get('triggerType', config.get('type', 'alert')),
                'filters': config.get('filters', []),
            }

        elif node_type == 'action':
            result = {
                'action_name': node.get('action', config.get('action', config.get('actionType', ''))),
                'integration': config.get('integration', config.get('asset', config.get('assetDependencyType', ''))),
                'parameters': config.get('parameters', config.get('inputs', {})),
            }

        elif node_type in ('condition', 'decision'):
            result = {
                'conditions': config.get('conditions', config.get('rules', [])),
                'operator': config.get('operator', 'and'),
            }

        elif node_type == 'parallel':
            result = {
                'branches': config.get('branches', []),
                'wait_for_all': config.get('waitForAll', True),
            }

        elif node_type == 'loop':
            result = {
                'collection': config.get('collection', config.get('items', '')),
                'variable': config.get('variable', config.get('itemVariable', 'item')),
                'max_iterations': config.get('maxIterations', 1000),
            }

        elif node_type == 'delay':
            result = {
                'duration_seconds': self._parse_delay(config),
            }

        elif node_type == 'approval':
            result = {
                'message': config.get('message', config.get('body', '')),
                'approvers': config.get('approvers', config.get('assignees', [])),
                'timeout_minutes': config.get('timeoutMinutes', config.get('timeout', 60)),
            }

        elif node_type in ('notification', 'email'):
            result = {
                'channel': config.get('channel', config.get('type', 'email')),
                'recipients': config.get('recipients', config.get('to', [])),
                'subject': config.get('subject', ''),
                'body': config.get('body', config.get('message', '')),
            }

        elif node_type == 'script':
            result = {
                'code': config.get('code', config.get('script', '')),
                'language': config.get('language', 'python'),
                'inputs': config.get('inputs', {}),
            }

        elif node_type == 'subworkflow':
            result = {
                'workflow_name': config.get('workflowName', config.get('playbookName', '')),
                'workflow_id': config.get('workflowId', config.get('playbookId', '')),
                'inputs': config.get('inputs', {}),
            }

        elif node_type == 'transform':
            result = {
                'transform_type': config.get('transformType', 'template'),
                'template': config.get('template', config.get('expression', '')),
            }

        elif node_type == 'webhook':
            result = {
                'url': config.get('url', ''),
                'method': config.get('method', 'POST'),
                'headers': config.get('headers', {}),
                'body': config.get('body', ''),
            }

        elif node_type == 'end':
            result = {
                'disposition': config.get('disposition', config.get('status', 'completed')),
            }

        else:
            # Generic: copy all config keys
            result = dict(config) if isinstance(config, dict) else {}

        return result
    def _parse_ssp_action(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """
        Parse a Swimlane SSP action package into a single-node playbook.

        Expected structure:
        {
            "name": "IP Lookup",
            "actionType": "GreyNoiseIPLookup",
            "family": "Investigation",
            "assetDependencyType": "GreyNoise",
            "inputParameters": {...},
            "availableOutputVariables": {...},
            "scriptFile": "greynoise_ip_lookup.py"
        }
        """
        action_type = data.get('actionType', '')
        family = data.get('family', '')
        asset = data.get('assetDependencyType', '')
        action_name = data.get('name', action_type)

        parsed = ParsedPlaybook(
            name=action_name,
            description=data.get('description', f'{family} action via {asset}'),
            platform=self.PLATFORM,
            version=data.get('version', '1.0'),
            raw=data
        )

        # Build a single action step
        step = ParsedStep(
            id='ssp_action_1',
            name=action_name,
            step_type='action',
            config={
                'action_name': action_type,
                'family': family.lower() if family else '',
                'integration': asset,
                'script_file': data.get('scriptFile', ''),
            },
            raw=data
        )

        # Map input parameters
        input_params = data.get('inputParameters', {})
        if isinstance(input_params, dict):
            step.inputs = {
                key: {
                    'name': val.get('name', key) if isinstance(val, dict) else key,
                    'required': val.get('required', False) if isinstance(val, dict) else False,
                    'type': val.get('type', '') if isinstance(val, dict) else '',
                }
                for key, val in input_params.items()
            }

        # Map output variables
        output_vars = data.get('availableOutputVariables', {})
        if isinstance(output_vars, dict):
            step.outputs = output_vars

        parsed.steps.append(step)
        return parsed

    def _parse_ssp_package_wrapper(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """
        Parse an SSP package wrapper manifest.

        Expected structure:
        {
            "name": "sw_greynoise",
            "version": "1.3.0",
            "supported_swimlane_version": "<10.5.0",
            "packages": ["sw_greynoise"],
            "vendor": "GreyNoise"
        }

        Since this is metadata-only, create a minimal placeholder playbook.
        """
        package_name = data.get('name', 'Unknown Package')
        vendor = data.get('vendor', '')

        parsed = ParsedPlaybook(
            name=f'{vendor} Integration' if vendor else package_name,
            description=(
                f'Swimlane SSP package: {package_name} '
                f'(vendor: {vendor}, version: {data.get("version", "unknown")})'
            ),
            platform=self.PLATFORM,
            version=data.get('version', '1.0'),
            raw=data
        )

        # Create a placeholder action step representing the package
        step = ParsedStep(
            id='ssp_package_1',
            name=f'{vendor} Action' if vendor else package_name,
            step_type='action',
            config={
                'action_name': package_name,
                'integration': vendor.lower().replace(' ', '_') if vendor else package_name,
                'family': '',
                'ssp_package': True,
                'packages': data.get('packages', []),
                'supported_swimlane_version': data.get('supported_swimlane_version', ''),
            },
            raw=data
        )

        parsed.steps.append(step)
        return parsed

    def _parse_generic_swimlane(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Fallback parser for unrecognized Swimlane content."""
        parsed = ParsedPlaybook(
            name=data.get('name', 'Imported Swimlane Playbook'),
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('version', '1.0')),
            raw=data
        )

        # Create a single placeholder step
        step = ParsedStep(
            id='swimlane_generic_1',
            name=data.get('name', 'Swimlane Action'),
            step_type='action',
            config={
                'action_name': data.get('name', 'unknown'),
                'auto_mapped': True,
            },
            raw=data
        )
        parsed.steps.append(step)
        return parsed

    # ========================================================================
    # Delay Parsing Helper
    # ========================================================================

    def _parse_delay(self, config: Dict[str, Any]) -> int:
        """Parse delay duration from config into seconds."""
        seconds = config.get('seconds', config.get('duration', 0))
        minutes = config.get('minutes', 0)
        hours = config.get('hours', 0)
        if not any([seconds, minutes, hours]):
            seconds = config.get('delay', config.get('wait', 60))
        return int(seconds) + int(minutes) * 60 + int(hours) * 3600

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map a Swimlane step to a native T1 node type and config.

        Mapping priority:
        1. Turbine node type (trigger, condition, script, etc.)
        2. Action name lookup in SWIMLANE_ACTIONS
        3. SSP action family (Investigation -> enrich, Containment -> action)
        4. Fuzzy matching via find_best_mapping()
        5. Default to 'action'
        """
        step_type = step.step_type.lower()
        config = step.config or {}
        action_name = config.get('action_name', '').lower()
        family = config.get('family', '').lower()
        integration = config.get('integration', '').lower()

        # ------------------------------------------------------------------
        # 1. Direct Turbine node type mapping
        # ------------------------------------------------------------------
        if step_type in NODE_TYPE_MAP:
            native_type = NODE_TYPE_MAP[step_type]

            if native_type == 'trigger':
                return 'trigger', {
                    'trigger_type': config.get('trigger_type', 'alert'),
                    'filters': config.get('filters', []),
                }
            elif native_type == 'condition':
                return 'condition', {
                    'conditions': config.get('conditions', []),
                    'operator': config.get('operator', 'and'),
                }
            elif native_type == 'delay':
                return 'delay', {
                    'duration_seconds': config.get('duration_seconds', 60),
                }
            elif native_type == 'approval_gate':
                return 'approval_gate', {
                    'message': config.get('message', 'Approval required'),
                    'approvers': config.get('approvers', []),
                    'timeout_minutes': config.get('timeout_minutes', 60),
                }
            elif native_type == 'notify':
                return 'notify', {
                    'channel': config.get('channel', 'email'),
                    'recipients': config.get('recipients', []),
                    'subject': config.get('subject', ''),
                    'body': config.get('body', ''),
                }
            elif native_type == 'python_code':
                return 'python_code', {
                    'code': config.get('code', ''),
                    'language': config.get('language', 'python'),
                }
            elif native_type == 'webhook_call':
                return 'webhook_call', {
                    'url': config.get('url', ''),
                    'method': config.get('method', 'POST'),
                    'headers': config.get('headers', {}),
                }
            elif native_type == 'end':
                return 'end', {
                    'disposition': config.get('disposition', 'completed'),
                }
            elif native_type == 'transform':
                return 'transform', {
                    'transform_type': config.get('transform_type', 'template'),
                    'template': config.get('template', ''),
                }
            # For 'action' mapped from Turbine node type, fall through
            # to action-name or family resolution below.

        # ------------------------------------------------------------------
        # 2. Lookup by action name in the action map
        # ------------------------------------------------------------------
        if action_name:
            if action_name in self.action_maps:
                return self.action_maps[action_name]

            best = find_best_mapping(action_name, 'swimlane')
            if best:
                return best

        # ------------------------------------------------------------------
        # 3. SSP family-based mapping
        # ------------------------------------------------------------------
        if family and family in FAMILY_TYPE_MAP:
            native_type = FAMILY_TYPE_MAP[family]
            return native_type, {
                'action_name': action_name or step.name,
                'integration': integration,
                'family': family,
            }

        # ------------------------------------------------------------------
        # 4. Integration name heuristics
        # ------------------------------------------------------------------
        if integration:
            enrichment_kw = ['lookup', 'search', 'query', 'scan', 'check', 'reputation', 'whois']
            action_kw = ['block', 'isolate', 'contain', 'quarantine', 'disable', 'terminate']
            notify_kw = ['notify', 'email', 'message', 'slack', 'teams', 'send']
            ticket_kw = ['ticket', 'incident', 'case', 'jira', 'servicenow', 'create_record']

            combined = f'{action_name} {integration}'.lower()

            if any(kw in combined for kw in enrichment_kw):
                return 'enrich', {'action_name': action_name, 'integration': integration}
            if any(kw in combined for kw in action_kw):
                return 'action', {'action_name': action_name, 'integration': integration, 'requires_approval': True}
            if any(kw in combined for kw in notify_kw):
                return 'notify', {'action_name': action_name, 'integration': integration}
            if any(kw in combined for kw in ticket_kw):
                return 'create_ticket', {'action_name': action_name, 'integration': integration}

        # ------------------------------------------------------------------
        # 5. Default: generic action node
        # ------------------------------------------------------------------
        return 'action', {
            'action_name': action_name or step.name,
            'integration': integration,
            'unmapped': True,
        }
