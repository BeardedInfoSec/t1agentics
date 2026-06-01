# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
TheHive (StrangeBee) / Cortex Playbook Converter

Converts TheHive case templates and Cortex analyzer/responder definitions
to T1 Agentics native format.

TheHive supports several export formats:

1. Case Template with Tasks:
   { "name": "...", "titlePrefix": "...", "description": "...",
     "tasks": [{ "title": "...", "group": "...", "order": N, "description": "..." }],
     "customFields": { ... } }

2. Cortex Analyzer Definition:
   { "analyzers": [{ "name": "VirusTotal_Scan", "id": "...",
     "dataTypeList": ["ip", "domain", "hash"] }] }

3. Cortex Responder Execution (operation log):
   { "workerName": "...", "workerDefinitionId": "...", "cortexId": "...",
     "operations": [{ "type": "AddTagToCase", "status": "Success" }] }

4. TheHive Workflow (newer versions):
   { "name": "...", "description": "...", "tasks": [...],
     "customFields": { ... }, "metrics": { ... } }

Tasks are linear sequences ordered by the "order" field.
Each task can reference Cortex analyzers via description keywords.
Groups/categories map to IR phases (identification, containment, etc.).
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import THEHIVE_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# Known Cortex analyzer name patterns mapped to integration names
ANALYZER_INTEGRATION_MAP = {
    'virustotal': 'virustotal',
    'abuseipdb': 'abuseipdb',
    'shodan': 'shodan',
    'urlscan': 'urlscan',
    'whois': 'whois',
    'dns': 'dns',
    'greynoise': 'greynoise',
    'maxmind': 'maxmind',
    'misp': 'misp',
    'otx': 'otx',
    'censys': 'censys',
    'hybridanalysis': 'hybrid_analysis',
    'hybrid_analysis': 'hybrid_analysis',
    'joe_sandbox': 'joe_sandbox',
    'joesandbox': 'joe_sandbox',
    'cuckoo': 'cuckoo',
    'yara': 'yara',
    'hippocampe': 'hippocampe',
    'dnsdb': 'dnsdb',
    'passivetotal': 'passivetotal',
    'threatcrowd': 'threatcrowd',
    'robtex': 'robtex',
    'isc': 'isc',
    'fortiguard': 'fortiguard',
    'cymon': 'cymon',
    'mailer': 'email',
}


class TheHiveConverter(PlaybookConverter):
    """
    Converter for TheHive case templates and Cortex analyzer/responder definitions.

    TheHive orchestration is task-based rather than node-graph based.
    Tasks are executed in order (sequential), grouped by IR phase.

    Supported input formats:
    - Case templates with tasks (main playbook format)
    - Cortex analyzer lists
    - Cortex responder execution logs with operations
    - Combined analyzer + task definitions
    """

    PLATFORM = SourcePlatform.THEHIVE

    def __init__(self):
        super().__init__(THEHIVE_ACTIONS)

    def detect(self, content: str) -> bool:
        """Detect if content is from TheHive or Cortex."""
        try:
            data = json.loads(content)

            indicators = [
                # Cortex-specific fields
                'cortexId' in data,
                'workerName' in data,
                'workerDefinitionId' in data,
                # Cortex analyzers list
                isinstance(data.get('analyzers'), list),
                # Cortex responder operations
                isinstance(data.get('operations'), list) and self._has_thehive_operations(data),
                # TheHive case template fields
                'titlePrefix' in data,
                # Task list with order field
                self._has_ordered_tasks(data),
                # dataTypeList (Cortex analyzer indicator)
                'dataTypeList' in str(data)[:2000],
                # Platform keywords
                'thehive' in str(data).lower()[:2000],
                'cortex' in str(data).lower()[:2000],
                'strangebee' in str(data).lower()[:2000],
                # customFields (TheHive-specific)
                isinstance(data.get('customFields'), dict),
                # metrics (TheHive case template)
                isinstance(data.get('metrics'), dict),
                # severity / tlp / pap (TheHive metadata)
                'severity' in data and 'tlp' in data,
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    def _has_ordered_tasks(self, data: Dict[str, Any]) -> bool:
        """Check if data has tasks with order fields (TheHive pattern)."""
        tasks = data.get('tasks', [])
        if not isinstance(tasks, list) or not tasks:
            return False
        # Check first few tasks for order field
        return any(
            isinstance(t, dict) and 'order' in t
            for t in tasks[:5]
        )

    def _has_thehive_operations(self, data: Dict[str, Any]) -> bool:
        """Check if operations list contains TheHive-style operations."""
        ops = data.get('operations', [])
        if not isinstance(ops, list) or not ops:
            return False
        thehive_ops = {
            'AddTagToCase', 'AddTagToAlert', 'CloseCase', 'AssignCase',
            'AddCustomField', 'CreateTask', 'CreateAlert', 'UpdateCase',
            'AddArtifact', 'AddLog',
        }
        for op in ops[:10]:
            if isinstance(op, dict) and op.get('type', '') in thehive_ops:
                return True
        return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse TheHive/Cortex content into intermediate format."""
        data = json.loads(content)

        # Detect which format we have and delegate
        if 'analyzers' in data and isinstance(data['analyzers'], list):
            return self._parse_analyzer_list(data)
        elif 'workerName' in data or 'workerDefinitionId' in data:
            return self._parse_responder(data)
        elif isinstance(data.get('operations'), list) and self._has_thehive_operations(data):
            return self._parse_operations(data)
        else:
            # Default: case template with tasks
            return self._parse_case_template(data)

    # ========================================================================
    # Format 1: Case Template with Tasks
    # ========================================================================

    def _parse_case_template(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Parse a TheHive case template with tasks."""
        name = data.get('name', data.get('title', 'Imported TheHive Template'))
        prefix = data.get('titlePrefix', '')
        if prefix and not name.startswith(prefix):
            name = f"{prefix} - {name}"

        parsed = ParsedPlaybook(
            name=name,
            description=data.get('description', ''),
            platform=self.PLATFORM,
            version='1.0',
            raw=data
        )

        # Extract custom fields as variables
        custom_fields = data.get('customFields', {})
        if isinstance(custom_fields, dict):
            parsed.variables = custom_fields

        # Parse tasks in order
        tasks = data.get('tasks', [])
        if isinstance(tasks, list):
            # Sort by order field if present
            sorted_tasks = sorted(
                [t for t in tasks if isinstance(t, dict)],
                key=lambda t: t.get('order', 0)
            )

            previous_step_id = None
            for i, task in enumerate(sorted_tasks):
                step = self._parse_task(task, i)
                if step:
                    # Link sequentially
                    if previous_step_id:
                        # Find previous step and add this as next
                        for prev_step in parsed.steps:
                            if prev_step.id == previous_step_id:
                                prev_step.next_steps.append(step.id)
                                break
                    parsed.steps.append(step)
                    previous_step_id = step.id

        # Extract severity/TLP as trigger metadata
        if 'severity' in data or 'tlp' in data:
            parsed.triggers.append({
                'type': 'case_creation',
                'severity': data.get('severity', 2),
                'tlp': data.get('tlp', 2),
                'pap': data.get('pap', 2),
            })

        return parsed

    def _parse_task(
        self,
        task: Dict[str, Any],
        index: int
    ) -> Optional[ParsedStep]:
        """Parse a single TheHive task into a ParsedStep."""
        task_title = task.get('title', task.get('name', f'Task {index + 1}'))
        task_id = str(task.get('id', f'task_{index}'))
        task_group = task.get('group', task.get('category', '')).lower().strip()
        task_description = task.get('description', '')
        task_order = task.get('order', index)

        step = ParsedStep(
            id=task_id,
            name=task_title,
            step_type='task',
            raw=task
        )

        step.config = {
            'group': task_group,
            'order': task_order,
            'description': task_description,
            'flag': task.get('flag', False),
        }

        # Try to detect analyzer references in the task description
        analyzer_refs = self._detect_analyzers_in_text(task_description)
        if analyzer_refs:
            step.config['detected_analyzers'] = analyzer_refs

        # Assign owner if present
        owner = task.get('owner', task.get('assignee', ''))
        if owner:
            step.config['owner'] = owner

        return step

    def _detect_analyzers_in_text(self, text: str) -> List[str]:
        """Detect Cortex analyzer references in task description text."""
        if not text:
            return []

        text_lower = text.lower()
        detected = []

        for pattern, integration in ANALYZER_INTEGRATION_MAP.items():
            if pattern in text_lower:
                if integration not in detected:
                    detected.append(integration)

        # Also look for explicit analyzer references like "Run VirusTotal_Scan_3_1"
        analyzer_pattern = re.compile(r'\b([A-Za-z]+(?:_[A-Za-z0-9]+)+)\b')
        for match in analyzer_pattern.finditer(text):
            candidate = match.group(1).lower()
            for pattern, integration in ANALYZER_INTEGRATION_MAP.items():
                if pattern in candidate and integration not in detected:
                    detected.append(integration)

        return detected

    # ========================================================================
    # Format 2: Cortex Analyzer List
    # ========================================================================

    def _parse_analyzer_list(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Parse a Cortex analyzer list export."""
        parsed = ParsedPlaybook(
            name=data.get('name', 'Cortex Analyzer Workflow'),
            description=data.get('description', 'Imported from Cortex analyzer definitions'),
            platform=self.PLATFORM,
            version='1.0',
            raw=data
        )

        analyzers = data.get('analyzers', [])
        previous_step_id = None

        for i, analyzer in enumerate(analyzers):
            if not isinstance(analyzer, dict):
                continue

            step = self._parse_analyzer(analyzer, i)
            if step:
                # Link sequentially
                if previous_step_id:
                    for prev_step in parsed.steps:
                        if prev_step.id == previous_step_id:
                            prev_step.next_steps.append(step.id)
                            break
                parsed.steps.append(step)
                previous_step_id = step.id

        return parsed

    def _parse_analyzer(
        self,
        analyzer: Dict[str, Any],
        index: int
    ) -> Optional[ParsedStep]:
        """Parse a single Cortex analyzer definition."""
        analyzer_name = analyzer.get('name', analyzer.get('id', f'Analyzer_{index}'))
        analyzer_id = str(analyzer.get('id', f'analyzer_{index}'))

        step = ParsedStep(
            id=analyzer_id,
            name=analyzer_name,
            step_type='analyzer',
            raw=analyzer
        )

        # Extract data types this analyzer supports
        data_types = analyzer.get('dataTypeList', analyzer.get('dataTypes', []))
        if isinstance(data_types, list):
            step.config['data_types'] = data_types

        # Extract analyzer metadata
        step.config['analyzer_name'] = analyzer_name
        step.config['description'] = analyzer.get('description', '')
        step.config['max_tlp'] = analyzer.get('maxTlp', 3)
        step.config['max_pap'] = analyzer.get('maxPap', 3)
        step.config['cortex_id'] = analyzer.get('cortexId', '')

        # Rate limiting
        rate = analyzer.get('rate', analyzer.get('rateLimit', None))
        if rate is not None:
            step.config['rate_limit'] = rate

        return step

    # ========================================================================
    # Format 3: Cortex Responder Execution Log
    # ========================================================================

    def _parse_responder(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Parse a Cortex responder execution log."""
        worker_name = data.get('workerName', data.get('workerDefinitionId', 'Unknown Responder'))

        parsed = ParsedPlaybook(
            name=f"Responder: {worker_name}",
            description=data.get('description', f"Imported from Cortex responder: {worker_name}"),
            platform=self.PLATFORM,
            version='1.0',
            raw=data
        )

        # Parse operations as sequential steps
        operations = data.get('operations', [])
        previous_step_id = None

        for i, operation in enumerate(operations):
            if not isinstance(operation, dict):
                continue

            step = self._parse_operation(operation, i)
            if step:
                if previous_step_id:
                    for prev_step in parsed.steps:
                        if prev_step.id == previous_step_id:
                            prev_step.next_steps.append(step.id)
                            break
                parsed.steps.append(step)
                previous_step_id = step.id

        # If no operations, create a single step for the responder itself
        if not parsed.steps:
            step = ParsedStep(
                id='responder_0',
                name=worker_name,
                step_type='responder',
                config={
                    'worker_name': worker_name,
                    'worker_definition_id': data.get('workerDefinitionId', ''),
                    'cortex_id': data.get('cortexId', ''),
                },
                raw=data
            )
            parsed.steps.append(step)

        return parsed

    def _parse_operation(
        self,
        operation: Dict[str, Any],
        index: int
    ) -> Optional[ParsedStep]:
        """Parse a single Cortex responder operation."""
        op_type = operation.get('type', f'Operation_{index}')
        op_status = operation.get('status', 'Unknown')

        step = ParsedStep(
            id=f'op_{index}',
            name=f"{op_type} ({op_status})",
            step_type='operation',
            raw=operation
        )

        step.config = {
            'operation_type': op_type,
            'status': op_status,
        }

        # Extract operation-specific data
        if 'tag' in operation:
            step.config['tag'] = operation['tag']
        if 'value' in operation:
            step.config['value'] = operation['value']
        if 'message' in operation:
            step.config['message'] = operation['message']

        return step

    # ========================================================================
    # Format 4: Operations-only (without workerName)
    # ========================================================================

    def _parse_operations(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Parse a TheHive operations log (operations without responder context)."""
        parsed = ParsedPlaybook(
            name=data.get('name', 'TheHive Operations Workflow'),
            description=data.get('description', 'Imported from TheHive operations'),
            platform=self.PLATFORM,
            version='1.0',
            raw=data
        )

        operations = data.get('operations', [])
        previous_step_id = None

        for i, operation in enumerate(operations):
            if not isinstance(operation, dict):
                continue

            step = self._parse_operation(operation, i)
            if step:
                if previous_step_id:
                    for prev_step in parsed.steps:
                        if prev_step.id == previous_step_id:
                            prev_step.next_steps.append(step.id)
                            break
                parsed.steps.append(step)
                previous_step_id = step.id

        return parsed

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map TheHive/Cortex step type to native node type."""
        step_type = step.step_type
        config = step.config.copy()

        # ---- Task (from case template) ----
        if step_type == 'task':
            return self._map_task(step)

        # ---- Analyzer (from Cortex) ----
        if step_type == 'analyzer':
            return self._map_analyzer(step)

        # ---- Responder ----
        if step_type == 'responder':
            worker_name = config.get('worker_name', '').lower()
            return self._map_responder_name(worker_name, config)

        # ---- Operation (from responder log) ----
        if step_type == 'operation':
            return self._map_operation(step)

        # Fallback
        return find_best_mapping(step_type, 'thehive')

    def _map_task(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a TheHive task to a native node type based on group and content."""
        config = step.config
        group = config.get('group', '').lower().strip()
        title_lower = step.name.lower()
        description = config.get('description', '').lower()
        detected_analyzers = config.get('detected_analyzers', [])

        # First: try mapping by group/category (IR phases)
        group_result = find_best_mapping(group, 'thehive') if group else None
        if group_result and group_result[0] != 'unmapped':
            node_type, node_config = group_result
            node_config = {**node_config}
            node_config['task_title'] = step.name
            node_config['task_group'] = group

            # If analyzers were detected in the description, prefer enrich
            if detected_analyzers and node_type in ('action', 'enrich'):
                node_config['integrations'] = detected_analyzers
                return 'enrich', node_config

            return node_type, node_config

        # Second: try mapping by task title keywords
        title_mapping = self._infer_from_title(title_lower, description)
        if title_mapping:
            node_type, node_config = title_mapping
            node_config['task_title'] = step.name
            if detected_analyzers:
                node_config['integrations'] = detected_analyzers
            return node_type, node_config

        # Third: if analyzers detected, this is enrichment
        if detected_analyzers:
            return 'enrich', {
                'integrations': detected_analyzers,
                'task_title': step.name,
                'auto_mapped': True,
            }

        # Fourth: try the full task name as a mapping key
        result = find_best_mapping(step.name, 'thehive')
        if result[0] != 'unmapped':
            return result

        # Default: treat as generic action
        return 'action', {
            'task_title': step.name,
            'task_group': group,
            'auto_mapped': True,
        }

    def _map_analyzer(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a Cortex analyzer to a native enrich node."""
        config = step.config
        analyzer_name = config.get('analyzer_name', step.name)
        data_types = config.get('data_types', [])
        analyzer_lower = analyzer_name.lower().replace('-', '_').replace(' ', '_')

        # Try direct mapping by analyzer name
        result = find_best_mapping(analyzer_lower, 'thehive')
        if result[0] != 'unmapped':
            node_type, node_config = result
            node_config = {**node_config}
            node_config['analyzer'] = analyzer_name
            if data_types:
                node_config['data_types'] = data_types
            return node_type, node_config

        # Try to infer from analyzer name
        for pattern, integration in ANALYZER_INTEGRATION_MAP.items():
            if pattern in analyzer_lower:
                # Determine observable type from data_types
                observable_type = self._infer_observable_type(data_types)
                return 'enrich', {
                    'integration': integration,
                    'observable_type': observable_type,
                    'analyzer': analyzer_name,
                    'data_types': data_types,
                }

        # Fallback: generic enrichment
        observable_type = self._infer_observable_type(data_types)
        return 'enrich', {
            'analyzer': analyzer_name,
            'observable_type': observable_type,
            'data_types': data_types,
            'auto_mapped': True,
        }

    def _map_operation(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map a Cortex responder operation to a native node type."""
        config = step.config
        op_type = config.get('operation_type', '')
        op_type_lower = op_type.lower().replace(' ', '')

        # Try direct mapping
        result = find_best_mapping(op_type_lower, 'thehive')
        if result[0] != 'unmapped':
            return result

        # Fallback by operation name pattern
        if 'close' in op_type_lower:
            return 'end', {'disposition': 'completed', 'operation': op_type}
        elif 'tag' in op_type_lower:
            return 'action', {'action_type': 'add_tag', 'operation': op_type}
        elif 'create' in op_type_lower:
            return 'create_ticket', {'operation': op_type}
        elif 'assign' in op_type_lower:
            return 'action', {'action_type': 'assign', 'operation': op_type}
        elif 'update' in op_type_lower:
            return 'action', {'action_type': 'update_case', 'operation': op_type}
        elif 'log' in op_type_lower or 'comment' in op_type_lower:
            return 'action', {'action_type': 'add_comment', 'operation': op_type}
        elif 'artifact' in op_type_lower:
            return 'action', {'action_type': 'add_artifact', 'operation': op_type}
        elif 'mail' in op_type_lower or 'email' in op_type_lower or 'notify' in op_type_lower:
            return 'notify', {'channel': 'email', 'operation': op_type}

        return 'action', {'operation': op_type, 'auto_mapped': True}

    def _map_responder_name(
        self,
        worker_name: str,
        config: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Map a Cortex responder by its worker name."""
        worker_lower = worker_name.lower().replace('-', '_').replace(' ', '_')

        # Try direct mapping
        result = find_best_mapping(worker_lower, 'thehive')
        if result[0] != 'unmapped':
            return result

        # Pattern-based inference
        if 'mailer' in worker_lower or 'email' in worker_lower:
            return 'notify', {'channel': 'email', 'responder': worker_name}
        elif 'case_close' in worker_lower or 'closecase' in worker_lower:
            return 'end', {'disposition': 'completed', 'responder': worker_name}
        elif any(p in worker_lower for p in ['crowdstrike', 'sentinelone', 'carbon_black', 'velociraptor']):
            return 'action', {
                'integration': worker_lower.split('_')[0],
                'requires_approval': True,
                'responder': worker_name,
            }
        elif 'wazuh' in worker_lower:
            return 'action', {'integration': 'wazuh', 'responder': worker_name}

        return 'action', {'responder': worker_name, 'auto_mapped': True}

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _infer_from_title(
        self,
        title_lower: str,
        description_lower: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Infer node type from task title and description keywords."""
        combined = f"{title_lower} {description_lower}"

        # Enrichment keywords
        enrichment_words = [
            'analyze', 'scan', 'lookup', 'check', 'search', 'investigate',
            'reputation', 'enrich', 'query', 'collect', 'gather', 'identify',
            'review', 'examine', 'inspect', 'detect', 'monitor',
        ]
        if any(w in combined for w in enrichment_words):
            # Refine: if containment words also present, prefer action
            if not any(w in combined for w in [
                'contain', 'isolate', 'block', 'disable', 'quarantine',
                'remove', 'delete', 'revoke', 'terminate'
            ]):
                return 'enrich', {}

        # Containment / action keywords
        containment_words = [
            'contain', 'isolate', 'block', 'disable', 'quarantine',
            'remove', 'delete', 'revoke', 'terminate', 'kill', 'stop',
            'eradicate', 'patch', 'remediate', 'fix', 'mitigate',
            'recover', 'restore', 'reset', 'rebuild',
        ]
        if any(w in combined for w in containment_words):
            return 'action', {'requires_approval': True}

        # Notification keywords
        notification_words = [
            'notify', 'email', 'alert', 'communicate', 'inform', 'report',
            'escalate', 'page', 'message', 'brief', 'update stakeholder',
        ]
        if any(w in combined for w in notification_words):
            return 'notify', {}

        # Ticketing keywords
        ticketing_words = [
            'create ticket', 'create incident', 'create case', 'open ticket',
            'file report', 'document', 'log incident',
        ]
        if any(w in combined for w in ticketing_words):
            return 'create_ticket', {}

        # Approval keywords
        approval_words = [
            'approve', 'approval', 'authorize', 'confirm', 'sign off',
            'get permission', 'manager review',
        ]
        if any(w in combined for w in approval_words):
            return 'approval_gate', {}

        # Closure keywords
        closure_words = [
            'close case', 'close incident', 'resolve', 'complete',
            'lessons learned', 'post-incident', 'post incident',
        ]
        if any(w in combined for w in closure_words):
            if 'lessons' in combined or 'post' in combined:
                return 'notify', {'phase': 'lessons_learned'}
            return 'end', {'disposition': 'completed'}

        return None

    def _infer_observable_type(self, data_types: List[str]) -> str:
        """Infer the primary observable type from Cortex data type list."""
        if not data_types:
            return 'indicator'

        type_priority = ['hash', 'ip', 'domain', 'url', 'mail', 'filename', 'fqdn', 'other']

        for ptype in type_priority:
            if ptype in data_types:
                # Normalize to our type names
                type_map = {
                    'hash': 'hash',
                    'ip': 'ip',
                    'domain': 'domain',
                    'url': 'url',
                    'mail': 'email',
                    'filename': 'file',
                    'fqdn': 'domain',
                    'other': 'indicator',
                }
                return type_map.get(ptype, 'indicator')

        return 'indicator'

    def _extract_tags(self, parsed: ParsedPlaybook) -> List[str]:
        """Override to extract TheHive-specific tags."""
        tags = super()._extract_tags(parsed)

        # Add tags from raw data
        raw_tags = parsed.raw.get('tags', [])
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                if isinstance(tag, str) and tag not in tags:
                    tags.append(tag)

        # Add tags based on task groups
        for step in parsed.steps:
            group = step.config.get('group', '')
            if group and group not in tags:
                tags.append(group)

        return tags

    def _extract_alert_types(self, parsed: ParsedPlaybook) -> List[str]:
        """Override to extract TheHive-specific alert types."""
        alert_types = super()._extract_alert_types(parsed)

        # Check for TheHive case template metadata
        raw = parsed.raw
        if 'caseTemplate' in raw:
            template = raw['caseTemplate']
            if isinstance(template, str) and template not in alert_types:
                alert_types.append(template)

        return alert_types
