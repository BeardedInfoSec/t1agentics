# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tines Playbook (Story) Converter

Converts Tines stories to T1 Agentics native format.

Tines story structure:
- agents: Array of agent definitions
- links: Connections between agents (edges)
- diagram_layout: JSON string mapping agent GUIDs to [x, y] positions
- story metadata

Tines agent types use namespaced format: "Agents::WebhookAgent", "Agents::HTTPRequestAgent", etc.
Links use array indices (integers) into the agents array, not agent IDs.
"""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from .base import (
    PlaybookConverter, ParsedPlaybook, ParsedStep,
    SourcePlatform, NativePlaybook, ConversionReport
)
from .action_maps import TINES_AGENTS, find_best_mapping

logger = logging.getLogger(__name__)


def _normalize_agent_type(raw_type: str) -> str:
    """
    Normalize Tines agent type from namespaced format to camelCase.

    Real exports use "Agents::WebhookAgent", "Agents::HTTPRequestAgent", etc.
    Our action maps and type checks use camelCase: "webhookAgent", "httpRequestAgent".

    Also handles already-normalized camelCase input for backward compatibility.
    """
    if '::' in raw_type:
        # "Agents::WebhookAgent" → "WebhookAgent" → "webhookAgent"
        class_name = raw_type.split('::')[-1]
        if class_name:
            return class_name[0].lower() + class_name[1:]
    return raw_type


class TinesConverter(PlaybookConverter):
    """
    Converter for Tines stories.

    Agent Types (namespaced → normalized):
    - Agents::HTTPRequestAgent → httpRequestAgent: Make HTTP requests
    - Agents::WebhookAgent → webhookAgent: Receive webhooks
    - Agents::ScheduleAgent → scheduleAgent: Scheduled triggers
    - Agents::EventTransformationAgent → eventTransformationAgent: Transform data / delay
    - Agents::TriggerAgent → triggerAgent: Conditional triggers
    - Agents::HumanInTheLoopAgent → humanInTheLoopAgent: Manual approval
    - Agents::SendEmailAgent → sendEmailAgent: Send emails
    - Agents::SlackAgent → slackAgent: Slack integration
    - Agents::DelayAgent → delayAgent: Wait/pause
    - Agents::DataLookupAgent → dataLookupAgent: Data lookups
    - Agents::StoreAgent → storeAgent: Store data
    - Agents::ReadAgent → readAgent: Read stored data
    - Agents::DedupeAgent → dedupeAgent: Deduplication
    """

    PLATFORM = SourcePlatform.TINES

    def __init__(self):
        super().__init__(TINES_AGENTS)

    def detect(self, content: str) -> bool:
        """Detect if content is from Tines."""
        try:
            data = json.loads(content)

            # Handle wrapped story format
            story = data.get('story', data)

            # Check for Tines indicators
            indicators = [
                'agents' in story,
                'links' in story,
                'story' in data or 'name' in story,
                'tines' in str(data).lower(),
                any('Agent' in str(agent.get('type', '')) for agent in story.get('agents', [])),
                'diagram_layout' in story,
                'schema_version' in story,
                'guid' in str(data)[:500],
            ]

            return sum(indicators) >= 2

        except Exception:
            return False

    def parse(self, content: str) -> ParsedPlaybook:
        """Parse Tines story JSON."""
        data = json.loads(content)

        # Handle both direct story format and wrapped format
        story = data.get('story', data)

        parsed = ParsedPlaybook(
            name=story.get('name', story.get('title', 'Imported Tines Story')),
            description=story.get('description', ''),
            platform=self.PLATFORM,
            version=str(story.get('schema_version', '1.0')),
            raw=data
        )

        # Parse agents — build both ID-based and index-based mappings
        agents = story.get('agents', [])
        agent_map = {}       # agent_id (str) → ParsedStep
        index_to_step = {}   # array_index (int) → ParsedStep

        for i, agent in enumerate(agents):
            step = self._parse_agent(agent)
            if step:
                parsed.steps.append(step)
                agent_map[step.id] = step
                index_to_step[i] = step

        # Parse diagram_layout for positions (GUID → [x, y])
        layout_raw = story.get('diagram_layout', '{}')
        try:
            layout = json.loads(layout_raw) if isinstance(layout_raw, str) else (layout_raw or {})
        except (json.JSONDecodeError, TypeError):
            layout = {}

        if layout:
            for step in parsed.steps:
                guid = step.raw.get('guid', '')
                if guid and guid in layout:
                    pos = layout[guid]
                    if isinstance(pos, (list, tuple)) and len(pos) >= 2:
                        step.position = {'x': int(pos[0]), 'y': int(pos[1])}

        # Parse links (connections)
        # Links can use either:
        #   - Integer indices into agents array: {"source": 0, "receiver": 5}
        #   - String IDs/GUIDs: {"source": "abc123", "receiver": "def456"}
        links = story.get('links', [])
        for link in links:
            source_ref = link.get('source', link.get('source_id', ''))
            target_ref = link.get('receiver', link.get('target_id', ''))

            # Resolve source step
            if isinstance(source_ref, int):
                source_step = index_to_step.get(source_ref)
            else:
                source_step = agent_map.get(str(source_ref))

            # Resolve target step
            if isinstance(target_ref, int):
                target_step = index_to_step.get(target_ref)
            else:
                target_step = agent_map.get(str(target_ref))

            if source_step and target_step:
                if target_step.id not in source_step.next_steps:
                    source_step.next_steps.append(target_step.id)

        # Find trigger agents (webhook, schedule, receiveEvents)
        trigger_types = {'webhookAgent', 'scheduleAgent', 'receiveEventsAgent'}
        for step in parsed.steps:
            if step.step_type in trigger_types:
                parsed.triggers.append({
                    'agent_id': step.id,
                    'type': step.step_type
                })

        return parsed

    def _parse_agent(self, agent: Dict[str, Any]) -> Optional[ParsedStep]:
        """Parse a single Tines agent."""
        raw_type = agent.get('type', 'unknown')
        agent_type = _normalize_agent_type(raw_type)

        # Prefer guid over id (real exports use guid)
        agent_id = str(agent.get('guid', agent.get('id', '')))
        agent_name = agent.get('name', f'Agent {agent_id[:8]}')

        step = ParsedStep(
            id=agent_id,
            name=agent_name,
            step_type=agent_type,
            raw=agent
        )

        # Extract configuration based on normalized agent type
        options = agent.get('options', {})
        step.config = self._extract_agent_config(agent_type, options, agent)

        # Position from agent-level position field (fallback; diagram_layout is preferred)
        position = agent.get('position', agent.get('diagram_position', {}))
        if isinstance(position, dict) and position:
            step.position = {
                'x': int(position.get('x', 0)),
                'y': int(position.get('y', 0))
            }

        return step

    def _extract_agent_config(
        self,
        agent_type: str,
        options: Dict[str, Any],
        agent: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract configuration from a Tines agent."""
        config = {}

        if agent_type == 'httpRequestAgent' or agent_type == 'hTTPRequestAgent':
            config = {
                'url': options.get('url', ''),
                'method': options.get('method', 'GET'),
                'headers': options.get('headers', {}),
                'body': options.get('content', options.get('payload', '')),
                'content_type': options.get('content_type', 'application/json')
            }

        elif agent_type == 'webhookAgent':
            config = {
                'trigger_type': 'webhook',
                'path': options.get('path', ''),
                'secret': options.get('secret', ''),
                'verbs': options.get('verbs', 'get,post')
            }

        elif agent_type == 'scheduleAgent':
            config = {
                'trigger_type': 'schedule',
                'schedule': options.get('schedule', options.get('cron', '')),
                'timezone': options.get('timezone', 'UTC')
            }

        elif agent_type == 'eventTransformationAgent':
            # EventTransformationAgent can be a transform OR a delay depending on mode
            mode = options.get('mode', 'message_only')
            if mode == 'delay':
                config = {
                    'mode': 'delay',
                    'seconds': options.get('seconds', '60'),
                    'duration_seconds': self._parse_delay(options.get('seconds', '60'))
                }
            else:
                config = {
                    'mode': mode,
                    'template': options.get('payload', options.get('template', '')),
                    'loop': options.get('loop', False)
                }

        elif agent_type == 'triggerAgent':
            config = {
                'rules': options.get('rules', []),
                'emit_mode': options.get('emit', 'when_true'),
                'must_match': options.get('must_match', 1)
            }

        elif agent_type == 'humanInTheLoopAgent':
            keep_alive = options.get('keep_alive')
            config = {
                'message': options.get('message', options.get('body', '')),
                'subject': options.get('subject', ''),
                'recipients': options.get('recipients', options.get('email_addresses', [])),
                'timeout_hours': keep_alive // 3600 if isinstance(keep_alive, int) and keep_alive else 168
            }

        elif agent_type == 'formAgent':
            config = {
                'title': options.get('title', agent.get('name', '')),
                'description': options.get('description', ''),
                'fields': self._extract_form_fields(options)
            }

        elif agent_type == 'sendEmailAgent':
            config = {
                'channel': 'email',
                'to': options.get('recipients', ''),
                'subject': options.get('subject', ''),
                'body': options.get('body', '')
            }

        elif agent_type == 'slackAgent':
            config = {
                'channel': 'slack',
                'slack_channel': options.get('channel', ''),
                'message': options.get('message', '')
            }

        elif agent_type == 'delayAgent':
            config = {
                'duration_seconds': self._parse_delay(options.get('delay', '60'))
            }

        elif agent_type == 'dataLookupAgent':
            config = {
                'list_name': options.get('data_source', ''),
                'lookup_key': options.get('key', '')
            }

        elif agent_type == 'storeAgent':
            config = {
                'variable_name': options.get('key', options.get('name', '')),
                'value': options.get('value', '')
            }

        elif agent_type == 'readAgent':
            config = {
                'variable_name': options.get('key', options.get('name', ''))
            }

        elif agent_type == 'dedupeAgent':
            config = {
                'dedupe_key': options.get('property', ''),
                'window_seconds': options.get('period', 3600)
            }

        else:
            # Generic extraction — copy all options
            config = options.copy() if isinstance(options, dict) else {}

        return config

    def _extract_form_fields(self, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract form fields from Tines form agent options."""
        fields = []

        form_fields = options.get('fields', options.get('questions', []))
        for f in form_fields:
            field = {
                'name': f.get('name', f.get('id', '')),
                'label': f.get('label', f.get('name', '')),
                'type': self._map_field_type(f.get('type', 'text')),
                'required': f.get('required', False)
            }

            if 'options' in f:
                field['options'] = [
                    {'label': opt, 'value': opt}
                    for opt in f['options']
                ]

            fields.append(field)

        return fields

    def _map_field_type(self, tines_type: str) -> str:
        """Map Tines field type to our field type."""
        type_map = {
            'text': 'text',
            'string': 'text',
            'textarea': 'textarea',
            'number': 'number',
            'email': 'email',
            'select': 'select',
            'dropdown': 'select',
            'multi_select': 'multiselect',
            'checkbox': 'checkbox',
            'boolean': 'checkbox',
            'date': 'date',
            'datetime': 'datetime',
            'file': 'file',
        }
        return type_map.get(tines_type.lower(), 'text')

    def _parse_delay(self, delay_str) -> int:
        """Parse Tines delay string to seconds."""
        if isinstance(delay_str, (int, float)):
            return int(delay_str)

        try:
            delay_str = str(delay_str).lower().strip()

            if delay_str.endswith('d'):
                return int(delay_str[:-1]) * 86400
            elif delay_str.endswith('h'):
                return int(delay_str[:-1]) * 3600
            elif delay_str.endswith('m'):
                return int(delay_str[:-1]) * 60
            elif delay_str.endswith('s'):
                return int(delay_str[:-1])
            else:
                return int(delay_str)
        except (ValueError, TypeError):
            return 60

    def map_step_type(self, step: ParsedStep) -> Tuple[str, Dict[str, Any]]:
        """Map Tines agent type to native node type."""
        agent_type = step.step_type
        config = step.config.copy()

        # Direct type mappings
        if agent_type == 'webhookAgent':
            return 'trigger', {'trigger_type': 'webhook'}

        elif agent_type == 'scheduleAgent':
            return 'trigger', {
                'trigger_type': 'schedule',
                'schedule': config.get('schedule', '')
            }

        elif agent_type == 'receiveEventsAgent':
            return 'trigger', {'trigger_type': 'event'}

        elif agent_type == 'httpRequestAgent' or agent_type == 'hTTPRequestAgent':
            # Try to infer purpose from URL
            url = config.get('url', '').lower()

            # Check for known enrichment APIs
            if 'virustotal' in url:
                return 'enrich', {'integration': 'virustotal'}
            elif 'urlscan' in url:
                return 'enrich', {'integration': 'urlscan'}
            elif 'shodan' in url:
                return 'enrich', {'integration': 'shodan'}
            elif 'abuseipdb' in url:
                return 'enrich', {'integration': 'abuseipdb'}
            elif 'greynoise' in url:
                return 'enrich', {'integration': 'greynoise'}
            elif 'hybrid-analysis' in url or 'hybridanalysis' in url:
                return 'enrich', {'integration': 'hybrid_analysis'}
            elif 'pulsedive' in url:
                return 'enrich', {'integration': 'pulsedive'}

            # Check for action APIs
            elif 'crowdstrike' in url:
                return 'action', {'integration': 'crowdstrike', 'requires_approval': True}
            elif 'okta' in url:
                return 'action', {'integration': 'okta', 'requires_approval': True}
            elif 'servicenow' in url or 'service-now' in url:
                return 'action', {'integration': 'servicenow'}
            elif 'jira' in url or 'atlassian' in url:
                return 'create_ticket', {'integration': 'jira'}
            elif 'pagerduty' in url:
                return 'notify', {'integration': 'pagerduty'}
            elif 'slack' in url:
                return 'notify', {'channel': 'slack'}
            elif 'teams' in url or 'microsoft.com/webhook' in url:
                return 'notify', {'channel': 'teams'}

            # Check for cloud provider APIs (likely actions)
            elif 'amazonaws.com' in url or 'aws.' in url:
                return 'action', {'integration': 'aws', 'auto_mapped': True}
            elif 'azure' in url or 'microsoft.com/v1' in url:
                return 'action', {'integration': 'azure', 'auto_mapped': True}
            elif 'googleapis.com' in url:
                return 'action', {'integration': 'gcp', 'auto_mapped': True}

            # Generic webhook call
            return 'webhook_call', {
                'url': config.get('url', ''),
                'method': config.get('method', 'POST'),
                'headers': config.get('headers', {}),
                'body': config.get('body', '')
            }

        elif agent_type == 'eventTransformationAgent':
            # Check if this is a delay (mode=delay) or a transform
            if config.get('mode') == 'delay':
                return 'delay', {
                    'duration_seconds': config.get('duration_seconds', 60)
                }
            return 'transform', {
                'transform_type': 'template',
                'template': config.get('template', '')
            }

        elif agent_type == 'triggerAgent':
            # Convert Tines trigger rules to condition
            rules = config.get('rules', [])
            if rules:
                rule = rules[0] if isinstance(rules, list) else rules
                return 'condition', {
                    'field': rule.get('path', rule.get('property', '')),
                    'operator': self._map_operator(rule.get('type', 'equals')),
                    'value': rule.get('value', '')
                }
            return 'condition', {}

        elif agent_type == 'humanInTheLoopAgent':
            return 'approval_gate', {
                'message': config.get('message', ''),
                'timeout_minutes': config.get('timeout_hours', 168) * 60
            }

        elif agent_type == 'formAgent':
            return 'webform', {
                'fields': config.get('fields', [])
            }

        elif agent_type == 'sendEmailAgent':
            return 'notify', {
                'channel': 'email',
                'recipients': config.get('to', ''),
                'subject': config.get('subject', ''),
                'message': config.get('body', '')
            }

        elif agent_type == 'slackAgent':
            return 'notify', {
                'channel': 'slack',
                'slack_channel': config.get('slack_channel', ''),
                'message': config.get('message', '')
            }

        elif agent_type == 'delayAgent':
            return 'delay', {
                'duration_seconds': config.get('duration_seconds', 60)
            }

        elif agent_type == 'dataLookupAgent':
            return 'list_lookup', {
                'list_name': config.get('list_name', ''),
                'value_path': config.get('lookup_key', '')
            }

        elif agent_type == 'storeAgent':
            return 'variable_set', {
                'name': config.get('variable_name', ''),
                'static_value': config.get('value', '')
            }

        elif agent_type == 'readAgent':
            return 'variable_get', {
                'name': config.get('variable_name', '')
            }

        elif agent_type == 'dedupeAgent':
            return 'transform', {
                'transform_type': 'dedupe',
                'dedupe_key': config.get('dedupe_key', '')
            }

        elif agent_type == 'emitEventsAgent':
            return 'notify', {'auto_mapped': True}

        # Try action mapping as fallback
        return find_best_mapping(agent_type, 'tines')

    def _map_operator(self, operator: str) -> str:
        """Map Tines operator to native operator."""
        operator_map = {
            'equals': 'equals',
            'does_not_equal': 'not_equals',
            'contains': 'contains',
            'does_not_contain': 'not_contains',
            'is_present': 'is_not_empty',
            'is_not_present': 'is_empty',
            'greater_than': 'greater_than',
            'less_than': 'less_than',
            'regex': 'matches',
            'field_equals': 'equals',
            'field_contains': 'contains',
            # Real Tines exports use field==value format
            'field==value': 'equals',
            'field!=value': 'not_equals',
            'field>value': 'greater_than',
            'field<value': 'less_than',
            'field>=value': 'greater_or_equal',
            'field<=value': 'less_or_equal',
            'field=~value': 'matches',
        }
        return operator_map.get(operator.lower() if isinstance(operator, str) else 'equals', 'equals')
