# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Guardrail Rule Engine

A robust rule engine for evaluating agent guardrails. Replaces simple keyword matching
with pattern-based rule evaluation supporting:

- Never rules: Actions that are always blocked
- Escalation triggers: Conditions that require human review
- Target restrictions: Patterns for allowed/denied targets
- Rate limits: Enforced action counts
- Operating hours: Time-based restrictions

Rule Format (in guardrails.never_rules):
    - Simple string: "Never isolate domain controllers"
    - Pattern object: {"pattern": "domain-controller|dc-|pdc-", "action": "isolate*", "type": "regex"}

Escalation Trigger Format (in guardrails.escalation_triggers):
    - Simple string: "VIP user involved"
    - Condition object: {"condition": "affected_hosts > 3", "description": "Multiple hosts affected"}
"""

import re
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, time

logger = logging.getLogger(__name__)


class RuleType(str, Enum):
    """Types of guardrail rules"""
    KEYWORD = "keyword"      # Simple keyword matching
    REGEX = "regex"          # Regular expression
    PATTERN = "pattern"      # Glob-like patterns (*, ?)
    CONDITION = "condition"  # Logical conditions (>, <, ==)
    COMPOSITE = "composite"  # AND/OR of multiple rules


@dataclass
class RuleViolation:
    """Result of a rule violation"""
    rule: str
    reason: str
    severity: str = "high"  # low, medium, high, critical
    blocked: bool = True    # If False, just warns
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailResult:
    """Complete result of guardrail evaluation"""
    passed: bool
    violations: List[RuleViolation] = field(default_factory=list)
    escalation_required: bool = False
    escalation_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [
                {"rule": v.rule, "reason": v.reason, "severity": v.severity, "blocked": v.blocked}
                for v in self.violations
            ],
            "escalation_required": self.escalation_required,
            "escalation_reasons": self.escalation_reasons,
            "warnings": self.warnings
        }


class GuardrailEngine:
    """
    Rule engine for evaluating agent guardrails.

    Supports sophisticated pattern matching and condition evaluation
    beyond simple keyword matching.
    """

    # Common patterns for high-value/sensitive targets
    SENSITIVE_TARGET_PATTERNS = {
        "domain_controller": [
            r"domain[-_]?controller",
            r"\bdc[-_]?\d*\b",
            r"\bpdc\b",
            r"\bbdc\b",
            r"ad[-_]?server",
            r"active[-_]?directory"
        ],
        "privileged_account": [
            r"\badmin\b",
            r"\broot\b",
            r"service[-_]?account",
            r"svc[-_]",
            r"sys[-_]?admin",
            r"\bda[-_]",  # Domain Admin
            r"enterprise[-_]?admin"
        ],
        "critical_infrastructure": [
            r"\bpdc\b",
            r"certificate[-_]?authority",
            r"\bca[-_]?\d*\b",
            r"key[-_]?vault",
            r"secrets?[-_]?manager",
            r"backup[-_]?server",
            r"sql[-_]?server",
            r"database[-_]?server"
        ],
        "executive": [
            r"\bceo\b",
            r"\bcfo\b",
            r"\bcto\b",
            r"\bciso\b",
            r"\bcoo\b",
            r"c[-_]?suite",
            r"executive",
            r"\bvp[-_]",
            r"vice[-_]?president",
            r"director[-_]?of"
        ]
    }

    # Threat indicators for escalation
    THREAT_INDICATORS = {
        "ransomware": [
            r"\.encrypted$",
            r"ransom",
            r"decrypt",
            r"bitcoin",
            r"monero",
            r"tor[-_]?browser",
            r"shadow[-_]?copy",
            r"vssadmin",
            r"bcdedit.*recoveryenabled"
        ],
        "lateral_movement": [
            r"psexec",
            r"wmic.*process.*call",
            r"pass[-_]?the[-_]?hash",
            r"mimikatz",
            r"rubeus",
            r"bloodhound",
            r"sharphound",
            r"invoke[-_]?mimikatz"
        ],
        "data_exfiltration": [
            r"rclone",
            r"mega\.nz",
            r"anonfiles",
            r"transfer\.sh",
            r"base64.*\|.*curl",
            r"certutil.*decode"
        ],
        "persistence": [
            r"schtasks.*/create",
            r"reg.*add.*run",
            r"startup[-_]?folder",
            r"wmi[-_]?subscription",
            r"golden[-_]?ticket"
        ]
    }

    def __init__(self):
        # Pre-compile common patterns for performance
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for category, patterns in self.SENSITIVE_TARGET_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
        for category, patterns in self.THREAT_INDICATORS.items():
            self._compiled_patterns[f"threat_{category}"] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def check_guardrails(
        self,
        agent: Dict[str, Any],
        action_context: Dict[str, Any]
    ) -> GuardrailResult:
        """
        Comprehensive guardrail evaluation.

        Args:
            agent: Agent definition with guardrails
            action_context: Context about the action being taken
                - action: The action name (e.g., "isolate_host")
                - target: Target identifier
                - target_type: Type of target (host, user, ip, etc.)
                - confidence: Agent's confidence in the action
                - description: Text description of what's being done
                - raw_data: Any raw data being analyzed
                - affected_hosts: Number of hosts affected
                - involves_vip: Whether VIPs are involved
                - actions_this_run: Actions taken so far

        Returns:
            GuardrailResult with pass/fail, violations, and escalation info
        """
        guardrails = agent.get('guardrails', {})
        tier = agent.get('tier', 1)

        violations: List[RuleViolation] = []
        escalation_reasons: List[str] = []
        warnings: List[str] = []

        # 1. Check confidence threshold
        confidence = action_context.get('confidence', 0)
        threshold = guardrails.get('confidence_threshold', self._default_threshold(tier))
        if confidence < threshold:
            escalation_reasons.append(
                f"Confidence {confidence:.0%} below threshold {threshold:.0%}"
            )

        # 2. Check never rules with proper pattern matching
        never_rules = guardrails.get('never_rules', [])
        for rule in never_rules:
            violation = self._evaluate_never_rule(rule, action_context)
            if violation:
                violations.append(violation)

        # 3. Check for sensitive targets
        target_violations = self._check_sensitive_targets(action_context, tier)
        violations.extend(target_violations)

        # 4. Check escalation triggers with real detection
        escalation_triggers = guardrails.get('escalation_triggers', [])
        for trigger in escalation_triggers:
            triggered, reason = self._evaluate_escalation_trigger(trigger, action_context)
            if triggered:
                escalation_reasons.append(reason)

        # 5. Check for threat indicators in data
        threat_escalations = self._check_threat_indicators(action_context)
        escalation_reasons.extend(threat_escalations)

        # 6. Check rate limits
        rate_limits = guardrails.get('rate_limits', {})
        rate_violation = self._check_rate_limits(rate_limits, action_context)
        if rate_violation:
            violations.append(rate_violation)

        # 7. Check operating hours
        allowed_hours = guardrails.get('allowed_hours', {})
        if allowed_hours:
            hours_violation = self._check_operating_hours(allowed_hours)
            if hours_violation:
                violations.append(hours_violation)

        # 8. Tier-specific restrictions
        tier_violations = self._check_tier_restrictions(tier, action_context)
        violations.extend(tier_violations)

        # Build result
        blocking_violations = [v for v in violations if v.blocked]

        return GuardrailResult(
            passed=len(blocking_violations) == 0,
            violations=violations,
            escalation_required=len(escalation_reasons) > 0,
            escalation_reasons=escalation_reasons,
            warnings=warnings
        )

    def _default_threshold(self, tier: int) -> float:
        """Default confidence thresholds by tier"""
        thresholds = {1: 0.3, 2: 0.6, 3: 0.85}
        return thresholds.get(tier, 0.5)

    def _evaluate_never_rule(
        self,
        rule: Union[str, Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Optional[RuleViolation]:
        """
        Evaluate a never rule against action context.

        Supports:
        - Simple string: "Never isolate domain controllers"
        - Pattern object: {"pattern": "dc-*", "action": "isolate", "type": "pattern"}
        """
        if isinstance(rule, str):
            return self._evaluate_string_rule(rule, context)
        elif isinstance(rule, dict):
            return self._evaluate_pattern_rule(rule, context)
        return None

    def _evaluate_string_rule(
        self,
        rule: str,
        context: Dict[str, Any]
    ) -> Optional[RuleViolation]:
        """Evaluate a string-based never rule with semantic understanding"""
        rule_lower = rule.lower()
        action = context.get('action', '').lower()
        target = str(context.get('target', '')).lower()
        target_type = context.get('target_type', '').lower()
        description = context.get('description', '').lower()

        # Extract key concepts from the rule
        concepts = self._extract_rule_concepts(rule_lower)

        # Check each concept
        for concept, patterns in concepts.items():
            for pattern in patterns:
                # Check action match
                if concept == 'action' and not self._matches_pattern(pattern, action):
                    continue

                # Check target match
                if concept == 'target':
                    target_matches = (
                        self._matches_pattern(pattern, target) or
                        self._matches_pattern(pattern, target_type) or
                        self._matches_category(pattern, target)
                    )
                    if target_matches:
                        return RuleViolation(
                            rule=rule,
                            reason=f"Action '{action}' on target '{target}' violates rule: {rule}",
                            severity="critical",
                            blocked=True,
                            details={"matched_pattern": pattern, "target": target}
                        )

        # Check for private IP rules
        if 'private' in rule_lower and ('ip' in rule_lower or 'rfc1918' in rule_lower):
            target_ip = context.get('target_ip', '') or context.get('target', '')
            if self._is_private_ip(target_ip):
                return RuleViolation(
                    rule=rule,
                    reason=f"Cannot perform action on private IP: {target_ip}",
                    severity="high",
                    blocked=True,
                    details={"ip": target_ip}
                )

        # Check for domain controller patterns
        if 'domain controller' in rule_lower or 'domain-controller' in rule_lower:
            if self._is_domain_controller(target):
                action_blocked = self._get_blocked_action(rule_lower)
                if not action_blocked or action_blocked in action:
                    return RuleViolation(
                        rule=rule,
                        reason=f"Cannot {action} domain controller: {target}",
                        severity="critical",
                        blocked=True,
                        details={"target": target, "category": "domain_controller"}
                    )

        # Check for privileged account patterns
        if 'privileged' in rule_lower or 'admin' in rule_lower or 'service account' in rule_lower:
            if self._is_privileged_account(target):
                return RuleViolation(
                    rule=rule,
                    reason=f"Cannot {action} privileged account: {target}",
                    severity="critical",
                    blocked=True,
                    details={"target": target, "category": "privileged_account"}
                )

        return None

    def _evaluate_pattern_rule(
        self,
        rule: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[RuleViolation]:
        """Evaluate a pattern-based rule"""
        pattern = rule.get('pattern', '')
        rule_type = rule.get('type', 'pattern')
        action_pattern = rule.get('action', '*')
        description = rule.get('description', f"Pattern rule: {pattern}")

        target = str(context.get('target', ''))
        action = context.get('action', '')

        # Check if action matches
        if action_pattern != '*':
            if rule_type == 'regex':
                if not re.match(action_pattern, action, re.IGNORECASE):
                    return None
            elif not self._glob_match(action_pattern, action):
                return None

        # Check if target matches pattern
        matched = False
        if rule_type == 'regex':
            matched = bool(re.search(pattern, target, re.IGNORECASE))
        elif rule_type == 'pattern':
            matched = self._glob_match(pattern, target)
        else:
            matched = pattern.lower() in target.lower()

        if matched:
            return RuleViolation(
                rule=description,
                reason=f"Target '{target}' matches blocked pattern: {pattern}",
                severity=rule.get('severity', 'high'),
                blocked=True,
                details={"pattern": pattern, "target": target, "action": action}
            )

        return None

    def _extract_rule_concepts(self, rule: str) -> Dict[str, List[str]]:
        """Extract action and target concepts from a rule string"""
        concepts = {'action': [], 'target': []}

        # Common action words
        action_words = ['isolate', 'disable', 'delete', 'remove', 'kill', 'block',
                       'modify', 'change', 'update', 'close', 'terminate', 'quarantine']
        for word in action_words:
            if word in rule:
                concepts['action'].append(word)

        # Extract "never X" patterns
        if 'never ' in rule:
            after_never = rule.split('never ', 1)[1]
            for word in action_words:
                if after_never.startswith(word):
                    concepts['action'].append(word)

        return concepts

    def _matches_pattern(self, pattern: str, text: str) -> bool:
        """Check if text matches a pattern (supports * wildcard)"""
        if '*' in pattern:
            return self._glob_match(pattern, text)
        return pattern in text.lower()

    def _matches_category(self, category: str, target: str) -> bool:
        """Check if target matches a sensitive category"""
        patterns = self._compiled_patterns.get(category, [])
        for pattern in patterns:
            if pattern.search(target):
                return True
        return False

    def _glob_match(self, pattern: str, text: str) -> bool:
        """Simple glob-style matching (* and ?)"""
        regex = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f'^{regex}$', text, re.IGNORECASE))

    def _get_blocked_action(self, rule: str) -> Optional[str]:
        """Extract the blocked action from a rule string"""
        action_words = ['isolate', 'disable', 'delete', 'remove', 'kill',
                       'block', 'modify', 'terminate', 'quarantine']
        for word in action_words:
            if word in rule:
                return word
        return None

    def _is_domain_controller(self, target: str) -> bool:
        """Check if target appears to be a domain controller"""
        for pattern in self._compiled_patterns.get('domain_controller', []):
            if pattern.search(target):
                return True
        return False

    def _is_privileged_account(self, target: str) -> bool:
        """Check if target appears to be a privileged account"""
        for pattern in self._compiled_patterns.get('privileged_account', []):
            if pattern.search(target):
                return True
        return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC1918) or reserved"""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_reserved or addr.is_loopback
        except ValueError:
            return False

    def _check_sensitive_targets(
        self,
        context: Dict[str, Any],
        tier: int
    ) -> List[RuleViolation]:
        """Check if action targets sensitive infrastructure"""
        violations = []
        target = str(context.get('target', ''))
        action = context.get('action', '').lower()

        # Destructive actions on sensitive targets
        destructive_actions = ['isolate', 'disable', 'terminate', 'kill', 'delete', 'remove', 'quarantine']
        is_destructive = any(a in action for a in destructive_actions)

        if not is_destructive:
            return violations

        # Check domain controllers
        if self._is_domain_controller(target):
            violations.append(RuleViolation(
                rule="No destructive actions on domain controllers",
                reason=f"Target '{target}' identified as domain controller",
                severity="critical",
                blocked=True,
                details={"category": "domain_controller", "target": target}
            ))

        # Check critical infrastructure
        for pattern in self._compiled_patterns.get('critical_infrastructure', []):
            if pattern.search(target):
                violations.append(RuleViolation(
                    rule="No destructive actions on critical infrastructure",
                    reason=f"Target '{target}' identified as critical infrastructure",
                    severity="critical",
                    blocked=True,
                    details={"category": "critical_infrastructure", "target": target}
                ))
                break

        return violations

    def _evaluate_escalation_trigger(
        self,
        trigger: Union[str, Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Evaluate an escalation trigger with real detection logic"""

        if isinstance(trigger, dict):
            condition = trigger.get('condition', '')
            description = trigger.get('description', condition)
            return self._evaluate_condition(condition, context), description

        # String-based trigger with semantic understanding
        trigger_lower = trigger.lower()

        # VIP/Executive detection
        if 'vip' in trigger_lower or 'executive' in trigger_lower:
            target = str(context.get('target', ''))
            user = context.get('user', '')

            # Check context flag
            if context.get('involves_vip', False):
                return True, f"VIP user involved: {user or target}"

            # Check target against executive patterns
            for pattern in self._compiled_patterns.get('executive', []):
                if pattern.search(target) or pattern.search(str(user)):
                    return True, f"Executive/VIP detected: {target or user}"

        # Multiple hosts affected
        if 'multiple' in trigger_lower and 'host' in trigger_lower:
            affected = context.get('affected_hosts', 0)
            if affected > 3:
                return True, f"Multiple hosts affected: {affected}"

        # Ransomware indicators
        if 'ransomware' in trigger_lower:
            if context.get('ransomware_indicators', False):
                return True, "Ransomware indicators detected in alert"

            # Check raw data for ransomware patterns
            raw_data = str(context.get('raw_data', '')) + str(context.get('description', ''))
            for pattern in self._compiled_patterns.get('threat_ransomware', []):
                if pattern.search(raw_data):
                    return True, f"Ransomware indicator detected: {pattern.pattern}"

        # Lateral movement
        if 'lateral' in trigger_lower or 'movement' in trigger_lower:
            raw_data = str(context.get('raw_data', '')) + str(context.get('description', ''))
            for pattern in self._compiled_patterns.get('threat_lateral_movement', []):
                if pattern.search(raw_data):
                    return True, f"Lateral movement indicator: {pattern.pattern}"

        # Data exfiltration
        if 'exfiltration' in trigger_lower or 'data loss' in trigger_lower:
            raw_data = str(context.get('raw_data', '')) + str(context.get('description', ''))
            for pattern in self._compiled_patterns.get('threat_data_exfiltration', []):
                if pattern.search(raw_data):
                    return True, f"Data exfiltration indicator: {pattern.pattern}"

        # Impossible travel (requires geo data)
        if 'impossible travel' in trigger_lower:
            if context.get('impossible_travel', False):
                return True, "Impossible travel detected"

        return False, ""

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a condition expression like 'affected_hosts > 3'"""
        # Parse simple conditions: field operator value
        operators = ['>=', '<=', '!=', '==', '>', '<', ' in ', ' not in ']

        for op in operators:
            if op in condition:
                parts = condition.split(op)
                if len(parts) != 2:
                    continue

                field = parts[0].strip()
                value_str = parts[1].strip()

                actual = context.get(field)
                if actual is None:
                    return False

                try:
                    # Try numeric comparison
                    if op in ['>', '<', '>=', '<=']:
                        expected = float(value_str)
                        actual = float(actual)
                        if op == '>': return actual > expected
                        if op == '<': return actual < expected
                        if op == '>=': return actual >= expected
                        if op == '<=': return actual <= expected
                    elif op == '==':
                        return str(actual).lower() == value_str.lower().strip('"\'')
                    elif op == '!=':
                        return str(actual).lower() != value_str.lower().strip('"\'')
                    elif op == ' in ':
                        return value_str.lower() in str(actual).lower()
                    elif op == ' not in ':
                        return value_str.lower() not in str(actual).lower()
                except (ValueError, TypeError):
                    continue

        return False

    def _check_threat_indicators(self, context: Dict[str, Any]) -> List[str]:
        """Check for threat indicators that require escalation"""
        escalations = []

        # Combine all text data for analysis
        text_data = ' '.join([
            str(context.get('description', '')),
            str(context.get('raw_data', '')),
            str(context.get('command_line', '')),
            str(context.get('file_path', '')),
            str(context.get('process_name', ''))
        ])

        if not text_data.strip():
            return escalations

        # Check each threat category
        threat_categories = ['ransomware', 'lateral_movement', 'data_exfiltration', 'persistence']

        for category in threat_categories:
            patterns = self._compiled_patterns.get(f'threat_{category}', [])
            for pattern in patterns:
                match = pattern.search(text_data)
                if match:
                    escalations.append(
                        f"{category.replace('_', ' ').title()} indicator detected: {match.group()}"
                    )
                    break  # One match per category is enough

        return escalations

    def _check_rate_limits(
        self,
        rate_limits: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[RuleViolation]:
        """Check rate limit violations"""
        actions_this_run = context.get('actions_this_run', 0)
        max_actions = rate_limits.get('max_actions_per_investigation', 50)

        if actions_this_run >= max_actions:
            return RuleViolation(
                rule="Rate limit: max_actions_per_investigation",
                reason=f"Action limit reached: {actions_this_run}/{max_actions}",
                severity="high",
                blocked=True,
                details={"current": actions_this_run, "limit": max_actions}
            )

        enrichments = context.get('enrichments_this_run', 0)
        max_enrichments = rate_limits.get('max_enrichments_per_minute', 30)

        if enrichments >= max_enrichments:
            return RuleViolation(
                rule="Rate limit: max_enrichments_per_minute",
                reason=f"Enrichment limit reached: {enrichments}/{max_enrichments}",
                severity="medium",
                blocked=True,
                details={"current": enrichments, "limit": max_enrichments}
            )

        return None

    def _check_operating_hours(
        self,
        allowed_hours: Dict[str, Any]
    ) -> Optional[RuleViolation]:
        """Check if current time is within allowed operating hours"""
        start = allowed_hours.get('start')  # Format: "09:00"
        end = allowed_hours.get('end')      # Format: "17:00"
        timezone = allowed_hours.get('timezone', 'UTC')

        if not start or not end:
            return None

        try:
            now = datetime.utcnow().time()
            start_time = time.fromisoformat(start)
            end_time = time.fromisoformat(end)

            # Handle overnight ranges (e.g., 22:00 - 06:00)
            if start_time <= end_time:
                is_allowed = start_time <= now <= end_time
            else:
                is_allowed = now >= start_time or now <= end_time

            if not is_allowed:
                return RuleViolation(
                    rule="Operating hours restriction",
                    reason=f"Current time {now.strftime('%H:%M')} outside allowed hours ({start}-{end})",
                    severity="medium",
                    blocked=True,
                    details={"current_time": now.strftime('%H:%M'), "allowed": f"{start}-{end}"}
                )
        except Exception as e:
            logger.warning(f"Failed to parse operating hours: {e}")

        return None

    def _check_tier_restrictions(
        self,
        tier: int,
        context: Dict[str, Any]
    ) -> List[RuleViolation]:
        """Enforce tier-based action restrictions"""
        violations = []
        action = context.get('action', '').lower()
        action_type = context.get('action_type', 'read')

        # Tier 1: Read-only + enrichment
        if tier == 1:
            destructive_actions = ['isolate', 'disable', 'terminate', 'kill',
                                  'delete', 'remove', 'quarantine', 'block']
            write_actions = ['update', 'modify', 'create', 'close']

            if any(a in action for a in destructive_actions):
                violations.append(RuleViolation(
                    rule="Tier 1 restriction: No destructive actions",
                    reason=f"Tier 1 agents cannot perform destructive action: {action}",
                    severity="critical",
                    blocked=True,
                    details={"tier": 1, "action": action}
                ))

            # Allow specific writes for T1
            allowed_writes = ['add_comment', 'add_note', 'add_reasoning', 'add_ioc']
            if action_type == 'write' and action not in allowed_writes:
                if any(a in action for a in write_actions):
                    violations.append(RuleViolation(
                        rule="Tier 1 restriction: Limited write access",
                        reason=f"Tier 1 agents cannot perform write action: {action}",
                        severity="high",
                        blocked=True,
                        details={"tier": 1, "action": action, "allowed": allowed_writes}
                    ))

        # Tier 2: No destructive actions
        elif tier == 2:
            destructive_actions = ['isolate', 'disable', 'terminate', 'kill',
                                  'delete', 'remove', 'quarantine']

            if any(a in action for a in destructive_actions):
                violations.append(RuleViolation(
                    rule="Tier 2 restriction: No destructive actions without escalation",
                    reason=f"Tier 2 agents cannot perform destructive action: {action}. Escalate to Tier 3 or human.",
                    severity="high",
                    blocked=True,
                    details={"tier": 2, "action": action}
                ))

        # Tier 3: Can do destructive with approval
        # No automatic blocking, but approval should be required

        return violations


# Singleton instance
_guardrail_engine: Optional[GuardrailEngine] = None


def get_guardrail_engine() -> GuardrailEngine:
    """Get the singleton guardrail engine instance"""
    global _guardrail_engine
    if _guardrail_engine is None:
        _guardrail_engine = GuardrailEngine()
    return _guardrail_engine


def check_guardrails(
    agent: Dict[str, Any],
    action_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function to check guardrails.

    Returns dict compatible with the original agent_service implementation.
    """
    engine = get_guardrail_engine()
    result = engine.check_guardrails(agent, action_context)
    return result.to_dict()
