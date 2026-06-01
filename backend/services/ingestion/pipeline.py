# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Ingestion Pipeline
Unified pipeline for extracting, transforming, and normalizing security events
"""

import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import hashlib

from .field_extractor import FieldExtractor, ExtractionRule, ExtractionMethod, FieldType, field_extractor
from .transform_engine import TransformEngine, TransformRule, Condition, Action, TransformAction, ConditionOperator, transform_engine

logger = logging.getLogger(__name__)


@dataclass
class ProcessingResult:
    """Result of processing an event through the pipeline"""
    success: bool
    event_id: str
    original_event: Dict[str, Any]
    processed_event: Optional[Dict[str, Any]]
    extracted_fields: Dict[str, Any]
    applied_rules: List[str]
    dropped: bool = False
    drop_reason: Optional[str] = None
    processing_time_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'event_id': self.event_id,
            'processed_event': self.processed_event,
            'extracted_fields': self.extracted_fields,
            'applied_rules': self.applied_rules,
            'dropped': self.dropped,
            'drop_reason': self.drop_reason,
            'processing_time_ms': self.processing_time_ms,
            'errors': self.errors
        }


class IngestionPipeline:
    """
    Main ingestion pipeline that orchestrates field extraction and transformation
    """
    
    def __init__(self):
        self.extractor = field_extractor
        self.transformer = transform_engine
        self.metrics = {
            'events_processed': 0,
            'events_dropped': 0,
            'events_errored': 0,
            'total_processing_time_ms': 0.0
        }
    
    def process(self, event: Dict[str, Any], vendor: Optional[str] = None) -> ProcessingResult:
        """
        Process a single event through the full pipeline
        
        1. Extract fields (regex, JSON path, heuristics)
        2. Apply transforms (normalize, filter, enrich)
        3. Validate and return
        """
        start_time = datetime.utcnow()
        event_id = self._generate_event_id(event)
        applied_rules = []
        errors = []
        
        try:
            # Step 1: Detect vendor if not provided
            if not vendor:
                vendor = self._detect_vendor(event)
            
            # Step 2: Extract fields
            extracted = self.extractor.extract_all(event, vendor)
            
            # Step 3: Merge extracted fields into event
            processed = self._merge_extracted(event, extracted)
            
            # Step 4: Apply transforms
            for rule in self.transformer.rules:
                if rule.enabled:
                    preview = self.transformer.preview_transform(processed, rule)
                    if preview['matched']:
                        applied_rules.append(rule.id)
                        if preview['dropped']:
                            self.metrics['events_dropped'] += 1
                            return ProcessingResult(
                                success=True,
                                event_id=event_id,
                                original_event=event,
                                processed_event=None,
                                extracted_fields=extracted,
                                applied_rules=applied_rules,
                                dropped=True,
                                drop_reason=f"Dropped by rule: {rule.name}",
                                processing_time_ms=self._calc_time(start_time)
                            )
                        processed = preview['result']
            
            # Step 5: Final normalization
            processed = self._final_normalize(processed, event_id, vendor)
            
            self.metrics['events_processed'] += 1
            processing_time = self._calc_time(start_time)
            self.metrics['total_processing_time_ms'] += processing_time
            
            return ProcessingResult(
                success=True,
                event_id=event_id,
                original_event=event,
                processed_event=processed,
                extracted_fields=extracted,
                applied_rules=applied_rules,
                processing_time_ms=processing_time
            )
        
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            self.metrics['events_errored'] += 1
            errors.append(str(e))
            
            return ProcessingResult(
                success=False,
                event_id=event_id,
                original_event=event,
                processed_event=None,
                extracted_fields={},
                applied_rules=applied_rules,
                processing_time_ms=self._calc_time(start_time),
                errors=errors
            )
    
    def process_batch(self, events: List[Dict[str, Any]], vendor: Optional[str] = None) -> List[ProcessingResult]:
        """Process a batch of events"""
        return [self.process(event, vendor) for event in events]
    
    def _generate_event_id(self, event: Dict) -> str:
        """Generate a unique event ID"""
        # Use existing ID if present
        for id_field in ['event_id', 'id', 'uuid', 'eventId', 'alert_id']:
            if id_field in event and event[id_field]:
                return str(event[id_field])
        
        # Generate from content hash
        content = json.dumps(event, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _detect_vendor(self, event: Dict) -> Optional[str]:
        """Detect the vendor from event content"""
        # Check explicit vendor field
        vendor_fields = ['vendor', 'source.vendor', 'vendor.name', 'sourcetype', 'source_type']
        for field in vendor_fields:
            value = self._get_nested(event, field)
            if value:
                return str(value).lower()
        
        # Heuristic detection based on field presence
        vendor_signatures = {
            'crowdstrike': ['aid', 'cid', 'ExternalApiType'],
            'sentinelone': ['agentId', 'siteId', 'threatInfo'],
            'defender': ['ExtendedProperties', 'AlertId', 'ProviderAlertId'],
            'okta': ['actor', 'authenticationContext', 'displayMessage'],
            'aws': ['awsRegion', 'recipientAccountId', 'eventSource'],
            'azure': ['tenantId', 'operationName', 'resourceId'],
            'paloalto': ['pan_log_subtype', 'pan_log_action'],
            'splunk': ['_raw', '_time', '_indextime'],
        }
        
        for vendor, signatures in vendor_signatures.items():
            for sig in signatures:
                if self._get_nested(event, sig) is not None:
                    return vendor
        
        return None
    
    def _merge_extracted(self, event: Dict, extracted: Dict) -> Dict:
        """Merge extracted fields into the event, preserving original structure"""
        result = dict(event)
        
        # Add extracted fields under 'extracted' namespace to avoid conflicts
        result['_extracted'] = extracted
        
        # Also set canonical fields at top level if not present
        for key, value in extracted.items():
            if '.' in key:
                # Nested field - create structure
                parts = key.split('.')
                current = result
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    elif not isinstance(current[part], dict):
                        break
                    current = current[part]
                if isinstance(current, dict):
                    current[parts[-1]] = current.get(parts[-1], value)
            else:
                result[key] = result.get(key, value)
        
        return result
    
    def _final_normalize(self, event: Dict, event_id: str, vendor: Optional[str]) -> Dict:
        """Apply final normalization to the processed event"""
        # Ensure required fields exist
        if 'event' not in event:
            event['event'] = {}
        
        event['event']['id'] = event_id
        event['event']['ingested'] = datetime.utcnow().isoformat() + 'Z'
        
        if vendor:
            if 'vendor' not in event:
                event['vendor'] = {}
            event['vendor']['name'] = vendor
        
        # Ensure time field exists
        if 'event' in event and 'time' not in event['event']:
            # Try to find a timestamp
            for time_field in ['timestamp', '@timestamp', 'time', 'datetime', 'created_at']:
                if time_field in event:
                    event['event']['time'] = event[time_field]
                    break
            else:
                event['event']['time'] = event['event']['ingested']
        
        return event
    
    def _get_nested(self, obj: Dict, path: str) -> Any:
        """Get a nested value using dot notation"""
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def _calc_time(self, start: datetime) -> float:
        """Calculate processing time in milliseconds"""
        return (datetime.utcnow() - start).total_seconds() * 1000
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline processing metrics"""
        return {
            **self.metrics,
            'avg_processing_time_ms': (
                self.metrics['total_processing_time_ms'] / self.metrics['events_processed']
                if self.metrics['events_processed'] > 0 else 0
            )
        }
    
    def reset_metrics(self) -> None:
        """Reset processing metrics"""
        self.metrics = {
            'events_processed': 0,
            'events_dropped': 0,
            'events_errored': 0,
            'total_processing_time_ms': 0.0
        }


class RuleParser:
    """
    Parser for different rule formats (JSON, YAML, Splunk-style)
    """
    
    @staticmethod
    def parse_yaml(yaml_content: str) -> List[Dict]:
        """Parse YAML rule definitions"""
        try:
            rules = yaml.safe_load(yaml_content)
            if isinstance(rules, dict):
                return [rules]
            elif isinstance(rules, list):
                return rules
            return []
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML: {e}")
            return []
    
    @staticmethod
    def parse_splunk_extract(splunk_line: str) -> Optional[ExtractionRule]:
        """
        Parse Splunk-style field extraction
        Example: EXTRACT-user = user=(?<user.username>[^\s]+)
        """
        match = re.match(r'EXTRACT-(\w+)\s*=\s*(.+)', splunk_line.strip())
        if not match:
            return None
        
        name = match.group(1)
        pattern = match.group(2)
        
        # Extract named groups as target fields
        named_groups = re.findall(r'\?<([^>]+)>', pattern)
        
        if named_groups:
            return ExtractionRule(
                id=f'splunk_extract_{name}',
                name=f'Splunk Extract: {name}',
                description=f'Converted from Splunk: EXTRACT-{name}',
                source_field='raw_message',
                method=ExtractionMethod.REGEX,
                pattern=pattern,
                target_field=named_groups[0],  # First named group
                field_type=FieldType.STRING
            )
        
        return None
    
    @staticmethod
    def parse_splunk_transform(splunk_config: str) -> Optional[TransformRule]:
        """
        Parse Splunk-style transform configuration
        Example:
        [drop_internal_ips]
        REGEX = ^(10\.|192\.168\.)
        DEST_KEY = queue
        FORMAT = nullQueue
        """
        lines = splunk_config.strip().split('\n')
        if not lines:
            return None
        
        # Parse stanza name
        stanza_match = re.match(r'\[([^\]]+)\]', lines[0])
        if not stanza_match:
            return None
        
        name = stanza_match.group(1)
        config = {}
        
        for line in lines[1:]:
            if '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
        
        # Convert to transform rule
        if config.get('DEST_KEY') == 'queue' and config.get('FORMAT') == 'nullQueue':
            # This is a drop rule
            return TransformRule(
                id=f'splunk_transform_{name}',
                name=f'Splunk Transform: {name}',
                description=f'Converted from Splunk transform',
                conditions=[Condition(
                    field='_raw',
                    operator=ConditionOperator.MATCHES,
                    value=config.get('REGEX', '.*')
                )],
                actions=[Action(action_type=TransformAction.DROP_EVENT)]
            )
        
        return None
    
    @staticmethod
    def to_yaml(rules: List[Dict]) -> str:
        """Convert rules to YAML format"""
        return yaml.dump(rules, default_flow_style=False, sort_keys=False)
    
    @staticmethod
    def to_splunk_extract(rule: ExtractionRule) -> str:
        """Convert extraction rule to Splunk format"""
        if rule.method == ExtractionMethod.REGEX and rule.pattern:
            # Add named group if not present
            pattern = rule.pattern
            if '?<' not in pattern:
                pattern = f'(?<{rule.target_field}>{pattern})'
            return f'EXTRACT-{rule.name.replace(" ", "_")} = {pattern}'
        return ''


# Global pipeline instance
ingestion_pipeline = IngestionPipeline()
rule_parser = RuleParser()


# Convenience function for processing events
def process_event(event: Dict[str, Any], vendor: Optional[str] = None) -> ProcessingResult:
    """Process a single event through the ingestion pipeline"""
    return ingestion_pipeline.process(event, vendor)
