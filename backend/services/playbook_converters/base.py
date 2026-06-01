# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Base Playbook Converter

Abstract base class for SOAR playbook converters.
Provides common functionality and defines the conversion interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
import json
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================

class SourcePlatform(str, Enum):
    """Supported source SOAR platforms."""
    XSOAR = "xsoar"
    TINES = "tines"
    SWIMLANE = "swimlane"
    CHRONICLE_SOAR = "chronicle_soar"
    QRADAR_SOAR = "qradar_soar"
    INSIGHT_CONNECT = "insight_connect"
    THEHIVE = "thehive"
    SENTINEL = "sentinel"
    FORTISOAR = "fortisoar"
    SHUFFLE = "shuffle"
    TORQ = "torq"
    SERVICENOW_SECOPS = "servicenow_secops"
    EXABEAM = "exabeam"
    BLINKOPS = "blinkops"
    D3_SECURITY = "d3_security"
    LOGICHUB = "logichub"
    RESOLVE = "resolve"
    UNKNOWN = "unknown"


@dataclass
class ParsedStep:
    """A parsed step from the source playbook."""
    id: str
    name: str
    step_type: str  # Source platform step type
    config: Dict[str, Any] = field(default_factory=dict)
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    position: Dict[str, int] = field(default_factory=dict)
    next_steps: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedPlaybook:
    """Intermediate representation of a parsed playbook."""
    name: str
    description: str = ""
    platform: SourcePlatform = SourcePlatform.UNKNOWN
    version: str = "1.0"
    steps: List[ParsedStep] = field(default_factory=list)
    triggers: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SkippedStep:
    """Record of a step that couldn't be converted."""
    original_id: str
    original_name: str
    original_type: str
    reason: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversionReport:
    """Report of a playbook conversion."""
    success: bool = False
    playbook_id: Optional[str] = None
    total_steps: int = 0
    converted_steps: int = 0
    skipped_steps: List[SkippedStep] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    unmapped_actions: List[str] = field(default_factory=list)
    requires_review: bool = True
    conversion_time_ms: float = 0


@dataclass
class NativePlaybook:
    """T1 Agentics native playbook format."""
    name: str
    description: str = ""
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    canvas_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    alert_types: List[str] = field(default_factory=list)
    imported_from: str = ""
    import_metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Base Converter
# ============================================================================

class PlaybookConverter(ABC):
    """
    Abstract base class for playbook converters.

    Subclasses implement platform-specific parsing and action mapping.
    """

    # Platform identifier
    PLATFORM: SourcePlatform = SourcePlatform.UNKNOWN

    def __init__(self, action_maps: Dict[str, Tuple[str, Dict[str, Any]]] = None):
        """
        Initialize converter.

        Args:
            action_maps: Dictionary mapping source action names to (node_type, config)
        """
        self.action_maps = action_maps or {}

    # ========================================================================
    # Abstract Methods (Must be implemented by subclasses)
    # ========================================================================

    @abstractmethod
    def detect(self, content: str) -> bool:
        """
        Detect if the content is from this platform.

        Args:
            content: Raw playbook content (JSON/YAML string)

        Returns:
            True if content appears to be from this platform
        """
        pass

    @abstractmethod
    def parse(self, content: str) -> ParsedPlaybook:
        """
        Parse source format into intermediate representation.

        Args:
            content: Raw playbook content (JSON/YAML string)

        Returns:
            ParsedPlaybook intermediate representation
        """
        pass

    @abstractmethod
    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """
        Map a source step type to native node type and config.

        Args:
            step: Parsed step from source playbook

        Returns:
            Tuple of (node_type, node_config)
        """
        pass

    # ========================================================================
    # Core Conversion Logic
    # ========================================================================

    def convert(self, content: str, name_override: str = None) -> Tuple[NativePlaybook, ConversionReport]:
        """
        Convert source playbook to T1 Agentics native format.

        Args:
            content: Raw playbook content
            name_override: Optional name to use instead of source name

        Returns:
            Tuple of (NativePlaybook, ConversionReport)
        """
        start_time = datetime.utcnow()
        report = ConversionReport()

        try:
            # Parse source format
            parsed = self.parse(content)
            report.total_steps = len(parsed.steps)

            # Convert to native format
            nodes = []
            edges = []
            step_to_node_id: Dict[str, str] = {}

            # Calculate positions based on step order
            y_offset = 0
            x_center = 250

            for i, step in enumerate(parsed.steps):
                # Map step type
                try:
                    node_type, node_config = self.map_step_type(step)

                    if node_type == "unmapped":
                        report.unmapped_actions.append(f"{step.step_type}: {step.name}")
                        report.skipped_steps.append(SkippedStep(
                            original_id=step.id,
                            original_name=step.name,
                            original_type=step.step_type,
                            reason="No mapping for this action type",
                            raw=step.raw
                        ))
                        continue

                    # Generate node ID
                    node_id = f"{node_type}_{uuid.uuid4().hex[:6]}"
                    step_to_node_id[step.id] = node_id

                    # Calculate position
                    position = step.position if step.position else {"x": x_center, "y": y_offset}
                    y_offset += 100

                    # Create node
                    node = {
                        "id": node_id,
                        "type": node_type,
                        "position": position,
                        "data": {
                            "label": step.name or node_type.replace('_', ' ').title(),
                            "config": node_config,
                            "imported_from": {
                                "platform": self.PLATFORM.value,
                                "original_id": step.id,
                                "original_type": step.step_type
                            }
                        }
                    }
                    nodes.append(node)
                    report.converted_steps += 1

                except Exception as e:
                    logger.warning(f"Failed to convert step {step.id}: {e}")
                    report.skipped_steps.append(SkippedStep(
                        original_id=step.id,
                        original_name=step.name,
                        original_type=step.step_type,
                        reason=str(e),
                        raw=step.raw
                    ))

            # Create edges based on step connections
            for step in parsed.steps:
                if step.id not in step_to_node_id:
                    continue

                source_node_id = step_to_node_id[step.id]

                for next_step_id in step.next_steps:
                    if next_step_id in step_to_node_id:
                        target_node_id = step_to_node_id[next_step_id]
                        edge_id = f"e_{source_node_id}_{target_node_id}"
                        edge = {
                            "id": edge_id,
                            "source": source_node_id,
                            "target": target_node_id
                        }

                        # Add condition handle if applicable
                        if step.condition:
                            edge["sourceHandle"] = step.condition

                        edges.append(edge)

            # Add trigger node if not present
            has_trigger = any(n['type'] == 'trigger' for n in nodes)
            if not has_trigger and nodes:
                trigger_id = f"trigger_{uuid.uuid4().hex[:6]}"
                trigger_node = {
                    "id": trigger_id,
                    "type": "trigger",
                    "position": {"x": x_center, "y": -100},
                    "data": {
                        "label": "Alert Trigger",
                        "config": {
                            "trigger_type": "alert",
                            "imported": True
                        }
                    }
                }
                nodes.insert(0, trigger_node)

                # Connect to first node
                if nodes:
                    first_node = nodes[1] if len(nodes) > 1 else None
                    if first_node:
                        edges.insert(0, {
                            "id": f"e_{trigger_id}_{first_node['id']}",
                            "source": trigger_id,
                            "target": first_node['id']
                        })

            # Add end node if not present
            has_end = any(n['type'] == 'end' for n in nodes)
            if not has_end and nodes:
                # Find terminal nodes (nodes with no outgoing edges)
                outgoing_sources = {e['source'] for e in edges}
                terminal_nodes = [n for n in nodes if n['id'] not in outgoing_sources and n['type'] != 'trigger']

                if terminal_nodes:
                    end_id = f"end_{uuid.uuid4().hex[:6]}"
                    max_y = max(n['position']['y'] for n in nodes)
                    end_node = {
                        "id": end_id,
                        "type": "end",
                        "position": {"x": x_center, "y": max_y + 100},
                        "data": {
                            "label": "End",
                            "config": {"disposition": "completed"}
                        }
                    }
                    nodes.append(end_node)

                    for terminal in terminal_nodes:
                        edges.append({
                            "id": f"e_{terminal['id']}_{end_id}",
                            "source": terminal['id'],
                            "target": end_id
                        })

            # Build native playbook
            playbook = NativePlaybook(
                name=name_override or parsed.name,
                description=parsed.description,
                trigger_conditions=self._extract_triggers(parsed),
                canvas_data={"nodes": nodes, "edges": edges},
                tags=self._extract_tags(parsed),
                alert_types=self._extract_alert_types(parsed),
                imported_from=self.PLATFORM.value,
                import_metadata={
                    "source_version": parsed.version,
                    "import_time": datetime.utcnow().isoformat(),
                    "original_step_count": len(parsed.steps)
                }
            )

            # Finalize report
            report.success = report.converted_steps > 0
            if not report.success and report.total_steps == 0:
                # Most common cause: user uploaded the wrong file (e.g. an
                # OpenAPI/Swagger spec instead of a workflow export).
                report.warnings.append(
                    f"No workflow steps found in this file. Verify it is a "
                    f"{self.PLATFORM.value} playbook export rather than an "
                    f"API spec, README, or asset definition."
                )
            report.requires_review = len(report.unmapped_actions) > 0 or len(report.warnings) > 0

            end_time = datetime.utcnow()
            report.conversion_time_ms = (end_time - start_time).total_seconds() * 1000

            return playbook, report

        except Exception as e:
            logger.error(f"Conversion failed: {e}")
            report.warnings.append(f"Conversion failed: {str(e)}")
            return NativePlaybook(name=name_override or "Failed Import"), report

    def validate(self, playbook: NativePlaybook) -> List[str]:
        """
        Validate a converted playbook.

        Args:
            playbook: Converted native playbook

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        canvas = playbook.canvas_data
        nodes = canvas.get('nodes', [])
        edges = canvas.get('edges', [])

        if len(nodes) == 0:
            errors.append("Playbook has no nodes")

        # Check for orphan nodes (except trigger)
        node_ids = {n['id'] for n in nodes}
        connected_targets = {e['target'] for e in edges}
        connected_sources = {e['source'] for e in edges}

        for node in nodes:
            if node['type'] != 'trigger' and node['id'] not in connected_targets:
                if node['type'] != 'end':  # End nodes don't need incoming
                    errors.append(f"Node '{node['data'].get('label', node['id'])}' has no incoming connections")

        # Check for missing edge targets
        for edge in edges:
            if edge['source'] not in node_ids:
                errors.append(f"Edge references missing source node: {edge['source']}")
            if edge['target'] not in node_ids:
                errors.append(f"Edge references missing target node: {edge['target']}")

        return errors

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _extract_triggers(self, parsed: ParsedPlaybook) -> Dict[str, Any]:
        """Extract trigger conditions from parsed playbook."""
        if parsed.triggers:
            return {"triggers": parsed.triggers}
        return {}

    def _extract_tags(self, parsed: ParsedPlaybook) -> List[str]:
        """Extract tags from parsed playbook."""
        tags = []

        # Extract from name
        name_lower = parsed.name.lower()
        for tag in ['phishing', 'malware', 'ransomware', 'incident', 'alert', 'response']:
            if tag in name_lower:
                tags.append(tag)

        # Extract from description
        if parsed.description:
            desc_lower = parsed.description.lower()
            for tag in ['phishing', 'malware', 'ransomware', 'endpoint', 'email', 'network']:
                if tag in desc_lower and tag not in tags:
                    tags.append(tag)

        return tags

    def _extract_alert_types(self, parsed: ParsedPlaybook) -> List[str]:
        """Extract alert types from parsed playbook."""
        alert_types = []

        name_lower = parsed.name.lower()
        desc_lower = (parsed.description or '').lower()
        combined = f"{name_lower} {desc_lower}"

        if 'phishing' in combined:
            alert_types.append('phishing')
        if 'malware' in combined:
            alert_types.append('malware')
        if 'ransomware' in combined:
            alert_types.append('ransomware')
        if 'suspicious' in combined:
            alert_types.append('suspicious_activity')

        return alert_types

    def _map_action_from_table(
        self,
        action_name: str,
        action_config: Dict[str, Any] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Map an action using the action mapping table.

        Args:
            action_name: Source action name
            action_config: Additional configuration from source

        Returns:
            Tuple of (node_type, node_config)
        """
        # Normalize action name
        normalized = action_name.lower().replace('-', '_').replace(' ', '_')

        # Check direct mapping
        if normalized in self.action_maps:
            node_type, base_config = self.action_maps[normalized]
            config = {**base_config}
            if action_config:
                config.update(action_config)
            return node_type, config

        # Check partial matches
        for key, (node_type, base_config) in self.action_maps.items():
            if key in normalized or normalized in key:
                config = {**base_config}
                if action_config:
                    config.update(action_config)
                return node_type, config

        # No mapping found
        return "unmapped", {"original_action": action_name}


# ============================================================================
# Auto-Detection Utility
# ============================================================================

def detect_platform(content: str) -> SourcePlatform:
    """
    Auto-detect the source platform from playbook content.

    Args:
        content: Raw playbook content

    Returns:
        Detected platform
    """
    try:
        # Try JSON
        data = json.loads(content)
        content_lower = str(data).lower()[:2000]

        # Tines indicators (check before generic 'agents' key)
        story = data.get('story', data)
        if 'agents' in story and 'links' in story:
            agents = story.get('agents', [])
            if agents and any('Agent' in str(a.get('type', '')) for a in agents[:5]):
                return SourcePlatform.TINES

        # XSOAR indicators
        if 'tasks' in data and ('starttaskid' in data or 'startTaskId' in data):
            return SourcePlatform.XSOAR

        # Chronicle SOAR (Siemplify) indicators
        if 'playbook_name' in data and 'playbook_trigger_type' in data:
            return SourcePlatform.CHRONICLE_SOAR
        if 'playbook_name' in data or ('steps' in data and 'identifier' in str(data)[:500]):
            if 'siemplify' in content_lower or 'chronicle' in content_lower:
                return SourcePlatform.CHRONICLE_SOAR
        if 'creator' in data and 'playbook_trigger_type' in data:
            return SourcePlatform.CHRONICLE_SOAR
        if isinstance(data.get('steps'), dict) and 'playbook_name' in data:
            return SourcePlatform.CHRONICLE_SOAR

        # QRadar SOAR (Resilient) indicators
        if 'export_format_version' in data:
            return SourcePlatform.QRADAR_SOAR
        if 'workflows' in data and 'functions' in data:
            return SourcePlatform.QRADAR_SOAR
        if 'resilient' in content_lower or 'qradar' in content_lower:
            if 'playbooks' in data or 'workflows' in data:
                return SourcePlatform.QRADAR_SOAR

        # Rapid7 InsightConnect (Komand) indicators
        if 'kom' in data and isinstance(data.get('kom'), dict):
            return SourcePlatform.INSIGHT_CONNECT
        if isinstance(data.get('steps'), dict) and 'komandVersion' in str(data)[:2000]:
            return SourcePlatform.INSIGHT_CONNECT
        if isinstance(data.get('steps'), dict):
            steps_sample = str(list(data['steps'].values())[:3])[:1000]
            if 'plugin' in steps_sample and 'action' in steps_sample and 'slugVendor' in steps_sample:
                return SourcePlatform.INSIGHT_CONNECT
        if 'komand' in content_lower or 'insightconnect' in content_lower or 'insight_connect' in content_lower:
            if 'steps' in data or 'triggers' in data:
                return SourcePlatform.INSIGHT_CONNECT

        # TheHive / Cortex indicators
        if 'cortexId' in data or 'workerName' in data or 'workerDefinitionId' in data:
            return SourcePlatform.THEHIVE
        if isinstance(data.get('analyzers'), list):
            analyzers = data['analyzers']
            if analyzers and 'dataTypeList' in str(analyzers[:3])[:500]:
                return SourcePlatform.THEHIVE
        if isinstance(data.get('tasks'), list) and 'titlePrefix' in data:
            return SourcePlatform.THEHIVE
        if isinstance(data.get('tasks'), list):
            tasks = data['tasks']
            if tasks and all(isinstance(t, dict) and 'order' in t for t in tasks[:5]):
                if 'thehive' in content_lower or 'cortex' in content_lower or 'strangebee' in content_lower:
                    return SourcePlatform.THEHIVE
        if 'operations' in data and isinstance(data.get('operations'), list):
            ops_sample = str(data['operations'][:5])[:500]
            if any(op in ops_sample for op in ['AddTagToCase', 'CloseCase', 'AddTagToAlert']):
                return SourcePlatform.THEHIVE

        # Swimlane indicators
        if 'supported_swimlane_version' in str(data):
            return SourcePlatform.SWIMLANE
        if 'actionType' in data and ('assetDependencyType' in data or 'inputParameters' in data):
            return SourcePlatform.SWIMLANE
        if 'swimlane' in content_lower:
            return SourcePlatform.SWIMLANE

        # Microsoft Sentinel (Azure Logic Apps) indicators
        if 'microsoft.logic/workflows' in content_lower:
            return SourcePlatform.SENTINEL
        if '$schema' in data and 'resources' in data:
            resources = data.get('resources', [])
            if any('Microsoft.Logic/workflows' in str(r.get('type', '')) for r in resources if isinstance(r, dict)):
                return SourcePlatform.SENTINEL
        if 'properties' in data and 'definition' in data.get('properties', {}):
            defn = data['properties']['definition']
            if isinstance(defn, dict) and ('triggers' in defn or 'actions' in defn):
                return SourcePlatform.SENTINEL
        if '$connections' in content_lower and ('azuresentinel' in content_lower or 'managedapis' in content_lower):
            return SourcePlatform.SENTINEL

        # FortiSOAR indicators
        if data.get('type') == 'workflow' and 'steps' in data and 'routes' in data:
            return SourcePlatform.FORTISOAR
        if isinstance(data.get('steps'), list) and isinstance(data.get('routes'), list):
            steps = data['steps']
            routes = data['routes']
            if steps and routes:
                if any('sourceStep' in str(r) for r in routes[:5] if isinstance(r, dict)):
                    return SourcePlatform.FORTISOAR
        if 'fortisoar' in content_lower or 'fortinet' in content_lower:
            if 'steps' in data and 'routes' in data:
                return SourcePlatform.FORTISOAR

        # Shuffle indicators
        if isinstance(data.get('actions'), list) and isinstance(data.get('branches'), list):
            actions = data['actions']
            if actions and any(isinstance(a, dict) and 'app_name' in a for a in actions[:5]):
                return SourcePlatform.SHUFFLE
        if isinstance(data.get('actions'), list) and isinstance(data.get('triggers'), list):
            actions = data['actions']
            if actions and any(isinstance(a, dict) and 'app_id' in a for a in actions[:5]):
                return SourcePlatform.SHUFFLE
        if 'shuffle' in content_lower:
            if 'actions' in data and ('branches' in data or 'triggers' in data):
                return SourcePlatform.SHUFFLE

        # Torq indicators
        if 'workflow_id' in data and isinstance(data.get('steps'), list):
            steps = data['steps']
            if steps and any(isinstance(s, dict) and 'integration' in s for s in steps[:5]):
                return SourcePlatform.TORQ
        if isinstance(data.get('steps'), list) and isinstance(data.get('trigger'), dict):
            steps = data['steps']
            if steps and any(isinstance(s, dict) and 'on_error' in s for s in steps[:5]):
                return SourcePlatform.TORQ
        if 'torq' in content_lower:
            if 'steps' in data and ('trigger' in data or 'workflow_id' in data):
                return SourcePlatform.TORQ

        # LogicHub indicators
        if 'playbook_id' in data and isinstance(data.get('nodes'), list) and isinstance(data.get('edges'), list):
            nodes = data['nodes']
            if nodes and any(isinstance(n, dict) and n.get('type') in ('integration', 'batch', 'transform', 'decision', 'script') for n in nodes[:10]):
                return SourcePlatform.LOGICHUB
        if isinstance(data.get('nodes'), list) and isinstance(data.get('edges'), list):
            nodes = data['nodes']
            if nodes and any(isinstance(n, dict) and 'integration' in n and isinstance(n.get('integration'), dict) for n in nodes[:10]):
                return SourcePlatform.LOGICHUB
        if 'logichub' in content_lower:
            if 'nodes' in data and 'edges' in data:
                return SourcePlatform.LOGICHUB

        # Resolve (Resolve Systems) indicators
        if 'runbook_name' in data and 'runbook_id' in data:
            return SourcePlatform.RESOLVE
        if isinstance(data.get('steps'), list) and isinstance(data.get('transitions'), list):
            steps = data['steps']
            transitions = data['transitions']
            if steps and any(isinstance(s, dict) and ('module' in s or 'function' in s) for s in steps[:10]):
                return SourcePlatform.RESOLVE
            if transitions and any(isinstance(t, dict) and 'from_step' in t and 'to_step' in t for t in transitions[:10]):
                return SourcePlatform.RESOLVE
        if 'resolve' in content_lower or 'resolve_systems' in content_lower:
            if 'steps' in data and 'transitions' in data:
                return SourcePlatform.RESOLVE

        # ServiceNow Security Operations (Flow Designer) indicators
        if 'sys_id' in data and isinstance(data.get('operations'), list):
            ops = data['operations']
            if ops and any(isinstance(o, dict) and 'type_id' in o for o in ops[:10]):
                return SourcePlatform.SERVICENOW_SECOPS
        if data.get('sys_class_name') in ('sys_hub_flow', 'sys_hub_action_type_definition', 'sys_hub_sub_flow'):
            return SourcePlatform.SERVICENOW_SECOPS
        if 'flow_type' in data and isinstance(data.get('operations'), list):
            if data.get('flow_type') in ('flow', 'subflow', 'action'):
                return SourcePlatform.SERVICENOW_SECOPS
        if isinstance(data.get('operations'), list):
            ops_sample = str(data['operations'][:5])[:1000]
            if 'sn_si.' in ops_sample or 'sn_vul.' in ops_sample or 'sn_ti.' in ops_sample:
                return SourcePlatform.SERVICENOW_SECOPS
        if 'servicenow' in content_lower or 'service_now' in content_lower or 'service-now' in content_lower:
            if 'operations' in data and ('sys_id' in data or 'flow_type' in data):
                return SourcePlatform.SERVICENOW_SECOPS

        # Exabeam (New-Scale SOAR) indicators
        if 'playbook_id' in data and isinstance(data.get('phases'), list):
            phases = data['phases']
            if phases and any(isinstance(p, dict) and 'phase_id' in p for p in phases[:10]):
                return SourcePlatform.EXABEAM
            if phases and any(isinstance(p, dict) and 'tasks' in p for p in phases[:10]):
                return SourcePlatform.EXABEAM
        if isinstance(data.get('phases'), list):
            phases = data['phases']
            if phases:
                for p in phases[:5]:
                    if isinstance(p, dict) and isinstance(p.get('tasks'), list):
                        tasks = p['tasks']
                        if tasks and any(isinstance(t, dict) and 'action' in t and isinstance(t.get('action'), dict) for t in tasks[:10]):
                            action = tasks[0].get('action', {})
                            if isinstance(action, dict) and ('integration' in action or 'command' in action):
                                return SourcePlatform.EXABEAM
        if 'exabeam' in content_lower:
            if 'phases' in data or 'playbook_id' in data:
                return SourcePlatform.EXABEAM

        # BlinkOps indicators
        if 'automation_id' in data and isinstance(data.get('steps'), list):
            steps = data['steps']
            if steps and any(isinstance(s, dict) and 'plugin' in s for s in steps[:5]):
                return SourcePlatform.BLINKOPS
        if isinstance(data.get('steps'), list) and isinstance(data.get('connections'), list):
            steps = data['steps']
            connections = data['connections']
            if steps and any(isinstance(s, dict) and isinstance(s.get('plugin'), dict) for s in steps[:5]):
                return SourcePlatform.BLINKOPS
            if connections and any(isinstance(c, dict) and 'from' in c and 'to' in c for c in connections[:5]):
                if steps and any(isinstance(s, dict) and 'plugin' in s for s in steps[:5]):
                    return SourcePlatform.BLINKOPS
        if 'blinkops' in content_lower or 'blink' in content_lower:
            if isinstance(data.get('steps'), list) and ('automation_id' in data or 'connections' in data):
                return SourcePlatform.BLINKOPS

        # D3 Security (Smart SOAR) indicators
        if 'playbook_name' in data and isinstance(data.get('commands'), list):
            commands = data['commands']
            if commands and any(isinstance(c, dict) and 'command_id' in c for c in commands[:5]):
                return SourcePlatform.D3_SECURITY
        if isinstance(data.get('commands'), list) and isinstance(data.get('connections'), list):
            commands = data['commands']
            connections = data['connections']
            if commands and any(isinstance(c, dict) and 'integration_name' in c for c in commands[:5]):
                return SourcePlatform.D3_SECURITY
            if connections and any(isinstance(c, dict) and 'source_command_id' in c for c in connections[:5]):
                return SourcePlatform.D3_SECURITY
        if 'd3' in content_lower or 'smart soar' in content_lower or 'd3_security' in content_lower:
            if isinstance(data.get('commands'), list):
                return SourcePlatform.D3_SECURITY

    except json.JSONDecodeError:
        pass

    try:
        # Try YAML (XSOAR often uses YAML, Torq can also use YAML)
        import yaml
        data = yaml.safe_load(content)

        if isinstance(data, dict):
            if 'tasks' in data and ('starttaskid' in data or 'fromversion' in data):
                return SourcePlatform.XSOAR

            # Torq YAML detection
            if 'workflow_id' in data and isinstance(data.get('steps'), list):
                steps = data['steps']
                if steps and any(isinstance(s, dict) and 'integration' in s for s in steps[:5]):
                    return SourcePlatform.TORQ
            if isinstance(data.get('steps'), list) and isinstance(data.get('trigger'), dict):
                steps = data['steps']
                if steps and any(isinstance(s, dict) and 'on_error' in s for s in steps[:5]):
                    return SourcePlatform.TORQ

    except Exception:
        pass

    return SourcePlatform.UNKNOWN
