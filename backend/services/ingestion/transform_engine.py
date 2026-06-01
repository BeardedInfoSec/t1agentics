# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Transform Engine
Transforms, filters, and normalizes security events at ingestion time
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import copy

logger = logging.getLogger(__name__)


class TransformAction(Enum):
    """Types of transform actions"""
    DROP_EVENT = "drop_event"
    DROP_FIELD = "drop_field"
    RENAME_FIELD = "rename_field"
    SET_FIELD = "set_field"
    COPY_FIELD = "copy_field"
    SWAP_FIELDS = "swap_fields"
    MASK_FIELD = "mask_field"
    HASH_FIELD = "hash_field"
    MAP_VALUE = "map_value"
    CONVERT_TYPE = "convert_type"
    LOWERCASE = "lowercase"
    UPPERCASE = "uppercase"
    TRIM = "trim"
    SPLIT = "split"
    JOIN = "join"
    REGEX_REPLACE = "regex_replace"
    ADD_TAG = "add_tag"
    REMOVE_TAG = "remove_tag"
    ENRICH = "enrich"


class ConditionOperator(Enum):
    """Condition operators for rule matching"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"  # Regex match
    NOT_MATCHES = "not_matches"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IS_PRIVATE_IP = "is_private_ip"
    IS_PUBLIC_IP = "is_public_ip"


@dataclass
class Condition:
    """A condition that must be met for a transform to apply"""
    field: str
    operator: ConditionOperator
    value: Any = None
    
    def to_dict(self) -> Dict:
        return {
            'field': self.field,
            'operator': self.operator.value,
            'value': self.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Condition':
        return cls(
            field=data['field'],
            operator=ConditionOperator(data['operator']),
            value=data.get('value')
        )


@dataclass
class Action:
    """An action to perform when conditions are met"""
    action_type: TransformAction
    params: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'action_type': self.action_type.value,
            'params': self.params
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Action':
        return cls(
            action_type=TransformAction(data['action_type']),
            params=data.get('params', {})
        )


@dataclass 
class TransformRule:
    """Definition of a transform rule"""
    id: str
    name: str
    description: str
    conditions: List[Condition]
    condition_logic: str = "all"  # "all" (AND) or "any" (OR)
    actions: List[Action] = field(default_factory=list)
    enabled: bool = True
    priority: int = 100
    vendor_scope: Optional[List[str]] = None
    source_type_scope: Optional[List[str]] = None
    stop_processing: bool = False  # Stop processing more rules after this one
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'conditions': [c.to_dict() for c in self.conditions],
            'condition_logic': self.condition_logic,
            'actions': [a.to_dict() for a in self.actions],
            'enabled': self.enabled,
            'priority': self.priority,
            'vendor_scope': self.vendor_scope,
            'source_type_scope': self.source_type_scope,
            'stop_processing': self.stop_processing
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TransformRule':
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            conditions=[Condition.from_dict(c) for c in data.get('conditions', [])],
            condition_logic=data.get('condition_logic', 'all'),
            actions=[Action.from_dict(a) for a in data.get('actions', [])],
            enabled=data.get('enabled', True),
            priority=data.get('priority', 100),
            vendor_scope=data.get('vendor_scope'),
            source_type_scope=data.get('source_type_scope'),
            stop_processing=data.get('stop_processing', False)
        )


class TransformEngine:
    """
    Core transform engine for security event processing
    Applies transforms at ingestion time before storage
    """
    
    # Built-in value mappings for normalization
    BUILTIN_MAPPINGS = {
        'severity': {
            'info': 'low', 'informational': 'low', '1': 'low', 'notice': 'low',
            'warning': 'medium', 'warn': 'medium', '2': 'medium', '3': 'medium',
            'error': 'high', 'err': 'high', '4': 'high',
            'critical': 'critical', 'crit': 'critical', 'fatal': 'critical', '5': 'critical',
            'emergency': 'critical', 'alert': 'high'
        },
        'outcome': {
            'success': 'success', 'succeeded': 'success', 'ok': 'success', 'allowed': 'success',
            'failure': 'failure', 'failed': 'failure', 'error': 'failure', 'denied': 'failure',
            'blocked': 'failure', 'rejected': 'failure',
            'unknown': 'unknown', 'pending': 'unknown'
        },
        'direction': {
            'in': 'inbound', 'inbound': 'inbound', 'ingress': 'inbound', 'incoming': 'inbound',
            'out': 'outbound', 'outbound': 'outbound', 'egress': 'outbound', 'outgoing': 'outbound',
            'internal': 'internal', 'lateral': 'internal'
        }
    }
    
    # Private IP ranges for detection
    PRIVATE_IP_PATTERNS = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^169\.254\.'),
    ]
    
    def __init__(self):
        self.rules: List[TransformRule] = []
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """Load built-in transform rules"""
        # Rule: Normalize severity values
        self.rules.append(TransformRule(
            id='builtin_normalize_severity',
            name='Normalize Severity',
            description='Normalize severity values to standard format',
            conditions=[Condition(field='event.severity', operator=ConditionOperator.EXISTS)],
            actions=[Action(
                action_type=TransformAction.MAP_VALUE,
                params={'field': 'event.severity', 'mapping': 'severity'}
            )],
            priority=10
        ))
        
        # Rule: Add timestamp if missing
        self.rules.append(TransformRule(
            id='builtin_add_timestamp',
            name='Add Timestamp',
            description='Add ingestion timestamp if event.time is missing',
            conditions=[Condition(field='event.time', operator=ConditionOperator.NOT_EXISTS)],
            actions=[Action(
                action_type=TransformAction.SET_FIELD,
                params={'field': 'event.time', 'value': '${NOW}'}
            )],
            priority=5
        ))
    
    def add_rule(self, rule: TransformRule) -> None:
        """Add a transform rule"""
        self.rules.append(rule)
        # Re-sort by priority
        self.rules.sort(key=lambda r: r.priority)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a transform rule"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False
    
    def update_rule(self, rule_id: str, updates: Dict) -> bool:
        """Update an existing rule"""
        for rule in self.rules:
            if rule.id == rule_id:
                for key, value in updates.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                return True
        return False
    
    def transform(self, event: Dict[str, Any], vendor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Apply all transform rules to an event
        Returns None if the event should be dropped
        """
        # Work on a copy to avoid modifying the original
        transformed = copy.deepcopy(event)
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check vendor scope
            if rule.vendor_scope and vendor and vendor not in rule.vendor_scope:
                continue
            
            # Evaluate conditions
            if self._evaluate_conditions(transformed, rule.conditions, rule.condition_logic):
                # Apply actions
                result = self._apply_actions(transformed, rule.actions)
                
                if result is None:
                    # Event was dropped
                    logger.debug(f"Event dropped by rule {rule.id}")
                    return None
                
                transformed = result
                
                if rule.stop_processing:
                    break
        
        return transformed
    
    def _evaluate_conditions(self, event: Dict, conditions: List[Condition], logic: str) -> bool:
        """Evaluate rule conditions"""
        if not conditions:
            return True
        
        results = [self._evaluate_condition(event, cond) for cond in conditions]
        
        if logic == 'any':
            return any(results)
        else:  # 'all'
            return all(results)
    
    def _evaluate_condition(self, event: Dict, condition: Condition) -> bool:
        """Evaluate a single condition"""
        value = self._get_field_value(event, condition.field)
        
        try:
            if condition.operator == ConditionOperator.EXISTS:
                return value is not None
            
            elif condition.operator == ConditionOperator.NOT_EXISTS:
                return value is None
            
            elif condition.operator == ConditionOperator.EQUALS:
                return str(value).lower() == str(condition.value).lower() if value else False
            
            elif condition.operator == ConditionOperator.NOT_EQUALS:
                return str(value).lower() != str(condition.value).lower() if value else True
            
            elif condition.operator == ConditionOperator.CONTAINS:
                return str(condition.value).lower() in str(value).lower() if value else False
            
            elif condition.operator == ConditionOperator.NOT_CONTAINS:
                return str(condition.value).lower() not in str(value).lower() if value else True
            
            elif condition.operator == ConditionOperator.STARTS_WITH:
                return str(value).lower().startswith(str(condition.value).lower()) if value else False
            
            elif condition.operator == ConditionOperator.ENDS_WITH:
                return str(value).lower().endswith(str(condition.value).lower()) if value else False
            
            elif condition.operator == ConditionOperator.MATCHES:
                if not value:
                    return False
                return bool(re.search(condition.value, str(value), re.IGNORECASE))
            
            elif condition.operator == ConditionOperator.NOT_MATCHES:
                if not value:
                    return True
                return not bool(re.search(condition.value, str(value), re.IGNORECASE))
            
            elif condition.operator == ConditionOperator.GREATER_THAN:
                return float(value) > float(condition.value) if value else False
            
            elif condition.operator == ConditionOperator.LESS_THAN:
                return float(value) < float(condition.value) if value else False
            
            elif condition.operator == ConditionOperator.IN:
                return value in condition.value if value else False
            
            elif condition.operator == ConditionOperator.NOT_IN:
                return value not in condition.value if value else True
            
            elif condition.operator == ConditionOperator.IS_PRIVATE_IP:
                return self._is_private_ip(str(value)) if value else False
            
            elif condition.operator == ConditionOperator.IS_PUBLIC_IP:
                return not self._is_private_ip(str(value)) if value else False
        
        except Exception as e:
            logger.warning(f"Error evaluating condition: {e}")
            return False
        
        return False
    
    def _apply_actions(self, event: Dict, actions: List[Action]) -> Optional[Dict]:
        """Apply a list of actions to an event"""
        for action in actions:
            result = self._apply_action(event, action)
            if result is None:
                return None
            event = result
        return event
    
    def _apply_action(self, event: Dict, action: Action) -> Optional[Dict]:
        """Apply a single action to an event"""
        params = action.params
        
        try:
            if action.action_type == TransformAction.DROP_EVENT:
                return None
            
            elif action.action_type == TransformAction.DROP_FIELD:
                field = params.get('field')
                if field:
                    self._delete_field(event, field)
            
            elif action.action_type == TransformAction.RENAME_FIELD:
                from_field = params.get('from')
                to_field = params.get('to')
                if from_field and to_field:
                    value = self._get_field_value(event, from_field)
                    if value is not None:
                        self._set_field_value(event, to_field, value)
                        self._delete_field(event, from_field)
            
            elif action.action_type == TransformAction.SET_FIELD:
                field = params.get('field')
                value = params.get('value')
                if field and value is not None:
                    # Handle special values
                    if value == '${NOW}':
                        value = datetime.utcnow().isoformat() + 'Z'
                    elif value.startswith('${') and value.endswith('}'):
                        # Reference another field
                        ref_field = value[2:-1]
                        value = self._get_field_value(event, ref_field)
                    self._set_field_value(event, field, value)
            
            elif action.action_type == TransformAction.COPY_FIELD:
                from_field = params.get('from')
                to_field = params.get('to')
                if from_field and to_field:
                    value = self._get_field_value(event, from_field)
                    if value is not None:
                        self._set_field_value(event, to_field, value)
            
            elif action.action_type == TransformAction.SWAP_FIELDS:
                field_a = params.get('field_a')
                field_b = params.get('field_b')
                if field_a and field_b:
                    value_a = self._get_field_value(event, field_a)
                    value_b = self._get_field_value(event, field_b)
                    if value_a is not None:
                        self._set_field_value(event, field_b, value_a)
                    if value_b is not None:
                        self._set_field_value(event, field_a, value_b)
            
            elif action.action_type == TransformAction.MASK_FIELD:
                field = params.get('field')
                pattern = params.get('pattern', r'.')
                replacement = params.get('replacement', '*')
                if field:
                    value = self._get_field_value(event, field)
                    if value:
                        masked = re.sub(pattern, replacement, str(value))
                        self._set_field_value(event, field, masked)
            
            elif action.action_type == TransformAction.MAP_VALUE:
                field = params.get('field')
                mapping_name = params.get('mapping')
                custom_mapping = params.get('custom_mapping', {})
                if field:
                    value = self._get_field_value(event, field)
                    if value:
                        # Use built-in mapping or custom
                        mapping = self.BUILTIN_MAPPINGS.get(mapping_name, custom_mapping)
                        mapped = mapping.get(str(value).lower(), value)
                        self._set_field_value(event, field, mapped)
            
            elif action.action_type == TransformAction.CONVERT_TYPE:
                field = params.get('field')
                target_type = params.get('type')
                if field and target_type:
                    value = self._get_field_value(event, field)
                    if value is not None:
                        converted = self._convert_type(value, target_type)
                        self._set_field_value(event, field, converted)
            
            elif action.action_type == TransformAction.LOWERCASE:
                field = params.get('field')
                if field:
                    value = self._get_field_value(event, field)
                    if value and isinstance(value, str):
                        self._set_field_value(event, field, value.lower())
            
            elif action.action_type == TransformAction.UPPERCASE:
                field = params.get('field')
                if field:
                    value = self._get_field_value(event, field)
                    if value and isinstance(value, str):
                        self._set_field_value(event, field, value.upper())
            
            elif action.action_type == TransformAction.REGEX_REPLACE:
                field = params.get('field')
                pattern = params.get('pattern')
                replacement = params.get('replacement', '')
                if field and pattern:
                    value = self._get_field_value(event, field)
                    if value:
                        replaced = re.sub(pattern, replacement, str(value))
                        self._set_field_value(event, field, replaced)
            
            elif action.action_type == TransformAction.ADD_TAG:
                tag = params.get('tag')
                if tag:
                    tags = event.get('tags', [])
                    if tag not in tags:
                        tags.append(tag)
                    event['tags'] = tags
            
            elif action.action_type == TransformAction.REMOVE_TAG:
                tag = params.get('tag')
                if tag:
                    tags = event.get('tags', [])
                    if tag in tags:
                        tags.remove(tag)
                    event['tags'] = tags
        
        except Exception as e:
            logger.error(f"Error applying action {action.action_type}: {e}")
        
        return event
    
    def _get_field_value(self, event: Dict, field_path: str) -> Any:
        """Get a value from nested dict using dot notation"""
        keys = field_path.split('.')
        value = event
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def _set_field_value(self, event: Dict, field_path: str, value: Any) -> None:
        """Set a value in nested dict using dot notation"""
        keys = field_path.split('.')
        current = event
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
    
    def _delete_field(self, event: Dict, field_path: str) -> None:
        """Delete a field from nested dict using dot notation"""
        keys = field_path.split('.')
        current = event
        for key in keys[:-1]:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return
        if isinstance(current, dict) and keys[-1] in current:
            del current[keys[-1]]
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private"""
        for pattern in self.PRIVATE_IP_PATTERNS:
            if pattern.match(ip):
                return True
        return False
    
    def _convert_type(self, value: Any, target_type: str) -> Any:
        """Convert a value to a target type"""
        try:
            if target_type == 'string':
                return str(value)
            elif target_type == 'integer':
                return int(float(value))
            elif target_type == 'float':
                return float(value)
            elif target_type == 'boolean':
                if isinstance(value, bool):
                    return value
                return str(value).lower() in ('true', 'yes', '1')
            elif target_type == 'list':
                if isinstance(value, list):
                    return value
                return [value]
        except (ValueError, TypeError):
            return value
        return value
    
    def preview_transform(self, event: Dict[str, Any], rule: TransformRule) -> Dict[str, Any]:
        """Preview the result of applying a single rule to an event"""
        test_event = copy.deepcopy(event)
        
        if self._evaluate_conditions(test_event, rule.conditions, rule.condition_logic):
            result = self._apply_actions(test_event, rule.actions)
            return {
                'matched': True,
                'dropped': result is None,
                'result': result,
                'original': event
            }
        
        return {
            'matched': False,
            'dropped': False,
            'result': test_event,
            'original': event
        }
    
    def get_rules(self) -> List[Dict]:
        """Return all rules"""
        return [rule.to_dict() for rule in self.rules]
    
    def import_rules(self, rules_data: List[Dict]) -> int:
        """Import rules from a list of dicts"""
        count = 0
        for rule_data in rules_data:
            try:
                rule = TransformRule.from_dict(rule_data)
                self.add_rule(rule)
                count += 1
            except Exception as e:
                logger.error(f"Failed to import rule: {e}")
        return count
    
    def export_rules(self) -> List[Dict]:
        """Export all rules as a list of dicts"""
        return [rule.to_dict() for rule in self.rules]


# Global transform engine instance
transform_engine = TransformEngine()
