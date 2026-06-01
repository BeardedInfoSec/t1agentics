# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IBM QRadar SOAR (Resilient) Playbook Converter

Converts QRadar SOAR playbooks and workflows to T1 Agentics native format.

QRadar SOAR has two export formats:

Format 1 - Newer JSON Playbook format:
  Top-level keys include export_format_version, playbooks, functions, scripts.
  Each playbook has activation_type, name, display_name, description, object_type,
  status, local_scripts, and a content block with embedded XML (BPMN).

Format 2 - Legacy XML Workflow format:
  The XML uses BPMN-like elements: startEvent, endEvent, serviceTask,
  exclusiveGateway, scriptTask, and sequenceFlow to describe the flow.
  Each serviceTask references a function by uuid and carries pre/post
  processing scripts.

Both formats are handled with graceful fallback.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import QRADAR_SOAR_ACTIONS, find_best_mapping

logger = logging.getLogger(__name__)


# ============================================================================
# BPMN XML Namespace - QRadar SOAR embeds BPMN 2.0 definitions
# ============================================================================

BPMN_NS = {
    'bpmn2': 'http://www.omg.org/spec/BPMN/20100524/MODEL',
    'bpmndi': 'http://www.omg.org/spec/BPMN/20100524/DI',
    'dc': 'http://www.omg.org/spec/DD/20100524/DC',
    'resilient': 'http://resilient.ibm.com/bpmn',
}

# BPMN element -> native node type
BPMN_TYPE_MAP = {
    'startevent': 'trigger',
    'endevent': 'end',
    'servicetask': 'action',
    'exclusivegateway': 'condition',
    'scripttask': 'python_code',
    'usertask': 'approval_gate',
    'manualtask': 'approval_gate',
    'intermediatecatchevent': 'delay',
    'callactivity': 'action',
    'subprocess': 'action',
    'parallelgateway': 'transform',
}


class QRadarSOARConverter(PlaybookConverter):
    """
    Converter for IBM QRadar SOAR (Resilient) playbooks and workflows.

    Handles two export formats:
    - Newer JSON playbook format (export_format_version >= 2)
    - Legacy XML workflow format with BPMN elements

    BPMN Element Mapping:
    - startEvent       -> trigger
    - endEvent         -> end
    - serviceTask      -> action/enrich (resolved via function name)
    - exclusiveGateway -> condition
    - scriptTask       -> python_code
    - sequenceFlow     -> edges (with optional conditionExpression)
    """

    PLATFORM = SourcePlatform.QRADAR_SOAR

    def __init__(self):
        super().__init__(QRADAR_SOAR_ACTIONS)
        self.functions_by_uuid: Dict[str, Dict[str, Any]] = {}
        self.functions_by_name: Dict[str, Dict[str, Any]] = {}
        self.scripts_by_uuid: Dict[str, Dict[str, Any]] = {}

    # ========================================================================
    # Detection
    # ========================================================================

    def detect(self, content: str) -> bool:
        """Detect if content is from IBM QRadar SOAR (Resilient)."""
        try:
            data = json.loads(content)

            if not isinstance(data, dict):
                return False

            content_sample = str(data).lower()[:3000]

            indicators = [
                'export_format_version' in data,
                'workflows' in data and isinstance(data.get('workflows'), list),
                'playbooks' in data and isinstance(data.get('playbooks'), list),
                'functions' in data and isinstance(data.get('functions'), list),
                'resilient' in content_sample,
                'qradar' in content_sample,
                'ibm' in content_sample and 'soar' in content_sample,
                'export_date' in data,
                'incident_types' in data,
                'message_destinations' in data,
                any(
                    'destination_handle' in str(f)
                    for f in data.get('functions', [])[:5]
                ),
            ]

            return sum(indicators) >= 2

        except (json.JSONDecodeError, TypeError):
            return False

    # ========================================================================
    # Parsing
    # ========================================================================

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse QRadar SOAR export JSON."""
        data = json.loads(content)

        # Build function/script lookup tables
        self._index_functions(data.get('functions', []))
        self._index_scripts(data.get('scripts', []))

        # Determine primary playbook/workflow to convert
        playbooks = data.get('playbooks', [])
        workflows = data.get('workflows', [])

        if playbooks:
            return self._parse_playbook_format(data, playbooks)
        elif workflows:
            return self._parse_workflow_format(data, workflows)
        else:
            return self._parse_minimal(data)

    def _index_functions(self, functions: List[Dict[str, Any]]) -> None:
        """Build lookup dictionaries for functions by uuid and name."""
        self.functions_by_uuid.clear()
        self.functions_by_name.clear()
        for fn in functions:
            fn_uuid = fn.get('uuid', '')
            fn_name = fn.get('name', '')
            if fn_uuid:
                self.functions_by_uuid[fn_uuid] = fn
            if fn_name:
                self.functions_by_name[fn_name] = fn

    def _index_scripts(self, scripts: List[Dict[str, Any]]) -> None:
        """Build lookup dictionary for scripts by uuid."""
        self.scripts_by_uuid.clear()
        for script in scripts:
            script_uuid = script.get('uuid', '')
            if script_uuid:
                self.scripts_by_uuid[script_uuid] = script

    # ========================================================================
    # Playbook Format (newer JSON)
    # ========================================================================

    def _parse_playbook_format(
        self, data: Dict[str, Any], playbooks: List[Dict[str, Any]]
    ) -> ParsedPlaybook:
        """Parse the newer JSON playbook format with embedded BPMN XML."""
        # Pick the first active playbook, or just the first one
        pb = None
        for p in playbooks:
            if p.get('status', '').lower() in ('enabled', 'active', ''):
                pb = p
                break
        if pb is None:
            pb = playbooks[0]

        parsed = ParsedPlaybook(
            name=pb.get('display_name', pb.get('name', 'QRadar SOAR Playbook')),
            description=pb.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('export_format_version', '2')),
            raw=data,
        )

        # The playbook content contains embedded BPMN XML
        content_block = pb.get('content', {})
        xml_str = content_block.get('xml', '')

        if xml_str:
            self._parse_bpmn_xml(xml_str, parsed, pb)
        else:
            self._parse_playbook_actions(pb, parsed)

        return parsed

    def _parse_bpmn_xml(
        self, xml_str: str, parsed: ParsedPlaybook, pb: Dict[str, Any]
    ) -> None:
        """Parse BPMN 2.0 XML embedded in a QRadar SOAR playbook."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.warning(f"Failed to parse BPMN XML: {e}")
            return

        # Find the process element
        process = root.find('.//bpmn2:process', BPMN_NS)
        if process is None:
            process = root.find('.//process')
        if process is None:
            process = root

        node_map: Dict[str, ParsedStep] = {}
        sequence_flows: List[Dict[str, str]] = []

        for elem in process:
            tag = self._strip_ns(elem.tag).lower()

            if tag == 'sequenceflow':
                sequence_flows.append({
                    'source': elem.get('sourceRef', ''),
                    'target': elem.get('targetRef', ''),
                    'name': elem.get('name', ''),
                    'id': elem.get('id', ''),
                })
                continue

            # Skip non-node elements
            if tag not in BPMN_TYPE_MAP:
                continue

            step = self._parse_bpmn_element(elem, tag, pb)
            if step:
                parsed.steps.append(step)
                node_map[step.id] = step

        # Resolve sequence flows into next_steps
        for flow in sequence_flows:
            source = node_map.get(flow['source'])
            target_id = flow['target']
            if source and target_id in node_map:
                if target_id not in source.next_steps:
                    source.next_steps.append(target_id)
                if flow['name'] and not source.condition:
                    source.condition = flow['name']

        # Extract positions from BPMN diagram info
        self._extract_bpmn_positions(root, node_map)

    def _parse_bpmn_element(
        self, elem: ET.Element, tag: str, pb: Dict[str, Any]
    ) -> Optional[ParsedStep]:
        """Parse a single BPMN element into a ParsedStep."""
        elem_id = elem.get('id', '')
        elem_name = elem.get('name', '')

        step = ParsedStep(
            id=elem_id,
            name=elem_name or tag.replace('event', '').replace('task', '').title(),
            step_type=tag,
            raw={'tag': tag, 'id': elem_id, 'name': elem_name},
        )

        if tag == 'startevent':
            step.config = {
                'trigger_type': pb.get('activation_type', 'manual'),
                'object_type': pb.get('object_type', 'incident'),
            }

        elif tag == 'endevent':
            step.config = {'disposition': 'completed'}

        elif tag == 'servicetask':
            fn_uuid = self._extract_function_uuid(elem)
            fn_data = self.functions_by_uuid.get(fn_uuid, {})
            fn_name = fn_data.get('name', elem_name)

            step.config = {
                'function_name': fn_name,
                'function_uuid': fn_uuid,
                'destination_handle': fn_data.get('destination_handle', ''),
                'inputs': self._extract_function_inputs(fn_data),
            }
            step.name = elem_name or fn_name

            pre_script = self._find_script_ref(elem, 'pre')
            post_script = self._find_script_ref(elem, 'post')
            if pre_script:
                step.config['pre_processing_script'] = pre_script
            if post_script:
                step.config['post_processing_script'] = post_script

        elif tag == 'exclusivegateway':
            step.config = {
                'gateway_type': 'exclusive',
                'conditions': [],
            }

        elif tag == 'scripttask':
            script_uuid = self._extract_script_uuid(elem)
            script_data = self.scripts_by_uuid.get(script_uuid, {})
            step.config = {
                'code': script_data.get('script_text', ''),
                'language': script_data.get('language', 'python3'),
                'script_name': script_data.get('name', elem_name),
            }

        elif tag in ('usertask', 'manualtask'):
            step.config = {
                'message': elem_name or 'Manual approval required',
                'task_type': 'approval',
            }

        elif tag == 'intermediatecatchevent':
            step.config = {
                'duration_seconds': 60,
                'event_type': 'timer',
            }

        elif tag in ('callactivity', 'subprocess'):
            step.config = {
                'sub_process': elem.get('calledElement', ''),
                'action_type': 'run_playbook',
            }

        return step

    def _extract_function_uuid(self, elem: ET.Element) -> str:
        """Extract function UUID from a serviceTask BPMN element."""
        # Try resilient namespace attribute
        fn_uuid = elem.get('{http://resilient.ibm.com/bpmn}function_uuid', '')
        if fn_uuid:
            return fn_uuid

        # Try extension elements
        for ext in elem.findall('.//bpmn2:extensionElements', BPMN_NS):
            for prop in ext:
                prop_tag = self._strip_ns(prop.tag).lower()
                if 'resilientservicetask' in prop_tag or 'function' in prop_tag:
                    uuid_val = prop.get('uuid', prop.get('function_uuid', ''))
                    if uuid_val:
                        return uuid_val
                    if prop.text:
                        return prop.text

        # Try without namespace
        for ext in elem.findall('.//extensionElements'):
            for prop in ext:
                prop_tag = self._strip_ns(prop.tag).lower()
                if 'function' in prop_tag or 'resilient' in prop_tag:
                    uuid_val = prop.get('uuid', '')
                    if uuid_val:
                        return uuid_val

        return ''

    def _extract_script_uuid(self, elem: ET.Element) -> str:
        """Extract script UUID from a scriptTask BPMN element."""
        for ext in elem.findall('.//bpmn2:extensionElements', BPMN_NS):
            for prop in ext:
                if 'script' in self._strip_ns(prop.tag).lower():
                    return prop.get('uuid', prop.text or '')

        for ext in elem.findall('.//extensionElements'):
            for prop in ext:
                if 'script' in self._strip_ns(prop.tag).lower():
                    return prop.get('uuid', prop.text or '')

        return ''

    def _find_script_ref(self, elem: ET.Element, phase: str) -> str:
        """Find pre/post processing script reference from BPMN element."""
        for ext in elem.findall('.//bpmn2:extensionElements', BPMN_NS):
            for prop in ext:
                tag_lower = self._strip_ns(prop.tag).lower()
                if phase in tag_lower and 'script' in tag_lower:
                    uuid_ref = prop.get('uuid', prop.text or '')
                    script = self.scripts_by_uuid.get(uuid_ref, {})
                    return script.get('script_text', uuid_ref)
        return ''

    def _extract_function_inputs(self, fn_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract function input schema."""
        inputs = {}
        for inp in fn_data.get('inputs', []):
            if isinstance(inp, dict):
                name = inp.get('name', inp.get('programmatic_name', ''))
                if name:
                    inputs[name] = {
                        'type': inp.get('input_type', ''),
                        'required': inp.get('required', False),
                    }
        return inputs

    def _extract_bpmn_positions(
        self, root: ET.Element, node_map: Dict[str, ParsedStep]
    ) -> None:
        """Extract node positions from BPMN diagram elements."""
        for shape in root.iter():
            tag = self._strip_ns(shape.tag).lower()
            if tag == 'bpmnshape':
                elem_ref = shape.get('bpmnElement', '')
                if elem_ref in node_map:
                    bounds = shape.find('dc:Bounds', BPMN_NS)
                    if bounds is None:
                        for child in shape:
                            if 'bounds' in self._strip_ns(child.tag).lower():
                                bounds = child
                                break
                    if bounds is not None:
                        try:
                            node_map[elem_ref].position = {
                                'x': int(float(bounds.get('x', 0))),
                                'y': int(float(bounds.get('y', 0))),
                            }
                        except (ValueError, TypeError):
                            pass

    @staticmethod
    def _strip_ns(tag: str) -> str:
        """Strip XML namespace prefix from a tag."""
        if '}' in tag:
            return tag.split('}', 1)[1]
        return tag

    # ========================================================================
    # Workflow Format (legacy)
    # ========================================================================

    def _parse_workflow_format(
        self, data: Dict[str, Any], workflows: List[Dict[str, Any]]
    ) -> ParsedPlaybook:
        """Parse legacy workflow format (XML-based)."""
        wf = workflows[0]

        parsed = ParsedPlaybook(
            name=wf.get('name', 'QRadar SOAR Workflow'),
            description=wf.get('description', ''),
            platform=self.PLATFORM,
            version=str(data.get('export_format_version', '1')),
            raw=data,
        )

        wf_content = wf.get('content', {})
        xml_str = wf_content.get('xml', '')

        if xml_str:
            self._parse_bpmn_xml(xml_str, parsed, wf)
        else:
            actions = wf.get('actions', [])
            for i, action in enumerate(actions):
                step = ParsedStep(
                    id=str(action.get('id', f'wf_action_{i}')),
                    name=action.get('name', f'Action {i}'),
                    step_type='servicetask',
                    config={
                        'function_name': action.get('function_name', ''),
                    },
                    raw=action,
                )
                parsed.steps.append(step)
                if i > 0:
                    parsed.steps[i - 1].next_steps.append(step.id)

        return parsed

    def _parse_playbook_actions(
        self, pb: Dict[str, Any], parsed: ParsedPlaybook
    ) -> None:
        """Fallback: parse playbook actions when no BPMN XML is available."""
        local_scripts = pb.get('local_scripts', [])
        for i, script in enumerate(local_scripts):
            step = ParsedStep(
                id=str(script.get('uuid', f'script_{i}')),
                name=script.get('name', f'Script {i}'),
                step_type='scripttask',
                config={
                    'code': script.get('script_text', ''),
                    'language': script.get('language', 'python3'),
                },
                raw=script,
            )
            parsed.steps.append(step)

    # ========================================================================
    # Minimal / fallback
    # ========================================================================

    def _parse_minimal(self, data: Dict[str, Any]) -> ParsedPlaybook:
        """Parse minimal export with just functions or scripts."""
        parsed = ParsedPlaybook(
            name=data.get('name', 'QRadar SOAR Import'),
            description='Imported from QRadar SOAR export',
            platform=self.PLATFORM,
            version=str(data.get('export_format_version', '1')),
            raw=data,
        )

        for i, fn in enumerate(data.get('functions', [])):
            step = ParsedStep(
                id=str(fn.get('uuid', f'fn_{i}')),
                name=fn.get('display_name', fn.get('name', f'Function {i}')),
                step_type='servicetask',
                config={
                    'function_name': fn.get('name', ''),
                    'destination_handle': fn.get('destination_handle', ''),
                    'inputs': self._extract_function_inputs(fn),
                },
                raw=fn,
            )
            parsed.steps.append(step)

        return parsed

    # ========================================================================
    # Step Type Mapping
    # ========================================================================

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map a QRadar SOAR step to a native T1 node type.

        Mapping priority:
        1. BPMN element type (startEvent, endEvent, etc.)
        2. Function name lookup in QRADAR_SOAR_ACTIONS
        3. Fuzzy matching via find_best_mapping()
        4. Default to 'action'
        """
        bpmn_type = step.step_type.lower()
        config = step.config or {}
        fn_name = config.get('function_name', '').lower()

        # ------------------------------------------------------------------
        # 1. BPMN element type mapping
        # ------------------------------------------------------------------
        if bpmn_type in BPMN_TYPE_MAP:
            native_type = BPMN_TYPE_MAP[bpmn_type]

            if native_type == 'trigger':
                return 'trigger', {
                    'trigger_type': config.get('trigger_type', 'manual'),
                    'object_type': config.get('object_type', 'incident'),
                }

            elif native_type == 'end':
                return 'end', {
                    'disposition': config.get('disposition', 'completed'),
                }

            elif native_type == 'condition':
                return 'condition', {
                    'gateway_type': config.get('gateway_type', 'exclusive'),
                    'conditions': config.get('conditions', []),
                }

            elif native_type == 'python_code':
                return 'python_code', {
                    'code': config.get('code', ''),
                    'language': config.get('language', 'python3'),
                    'script_name': config.get('script_name', step.name),
                }

            elif native_type == 'approval_gate':
                return 'approval_gate', {
                    'message': config.get('message', step.name),
                    'task_type': config.get('task_type', 'approval'),
                }

            elif native_type == 'delay':
                return 'delay', {
                    'duration_seconds': config.get('duration_seconds', 60),
                }

            elif native_type == 'transform':
                return 'transform', {
                    'transform_type': 'parallel_gateway',
                }

            # For 'action' (serviceTask, callActivity, subprocess),
            # fall through to function name resolution below

        # ------------------------------------------------------------------
        # 2. Function name lookup
        # ------------------------------------------------------------------
        if fn_name:
            if fn_name in self.action_maps:
                mapped_type, mapped_config = self.action_maps[fn_name]
                merged = {**mapped_config, **{k: v for k, v in config.items() if k not in mapped_config}}
                return mapped_type, merged

            stripped = fn_name.lstrip('fn_')
            if stripped and stripped in self.action_maps:
                mapped_type, mapped_config = self.action_maps[stripped]
                return mapped_type, {**mapped_config, 'function_name': fn_name}

            best = find_best_mapping(fn_name, 'qradar_soar')
            if best:
                return best

        # ------------------------------------------------------------------
        # 3. Heuristics on function name
        # ------------------------------------------------------------------
        if fn_name:
            enrich_kw = ['lookup', 'search', 'query', 'scan', 'get', 'check', 'enrich', 'intel']
            action_kw = ['block', 'isolate', 'contain', 'quarantine', 'disable', 'close', 'update']
            notify_kw = ['notify', 'email', 'message', 'send', 'slack']
            ticket_kw = ['ticket', 'incident', 'case', 'create_incident', 'create_task']

            if any(kw in fn_name for kw in enrich_kw):
                return 'enrich', {'function_name': fn_name, 'integration': config.get('destination_handle', '')}
            if any(kw in fn_name for kw in action_kw):
                return 'action', {'function_name': fn_name, 'requires_approval': True}
            if any(kw in fn_name for kw in notify_kw):
                return 'notify', {'function_name': fn_name}
            if any(kw in fn_name for kw in ticket_kw):
                return 'create_ticket', {'function_name': fn_name}

        # ------------------------------------------------------------------
        # 4. Default: generic action
        # ------------------------------------------------------------------
        return 'action', {
            'function_name': fn_name or step.name,
            'bpmn_type': bpmn_type,
            'unmapped': True,
        }
