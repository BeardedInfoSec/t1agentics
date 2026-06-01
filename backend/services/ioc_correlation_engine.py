# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IOC Correlation Engine

Advanced correlation service that:
- Links IOCs to alerts and investigations
- Detects patterns across multiple alerts
- Auto-creates campaigns when correlation rules trigger
- Supports temporal clustering and MITRE technique matching
"""

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CorrelationType(str, Enum):
    """Types of correlations"""
    IOC_MATCH = "ioc_match"
    TIME_WINDOW = "time_window"
    HOST_PATTERN = "host_pattern"
    USER_PATTERN = "user_pattern"
    TECHNIQUE_MATCH = "technique_match"
    SEVERITY_CHAIN = "severity_chain"
    CUSTOM = "custom"


class CampaignType(str, Enum):
    """Campaign classification types"""
    APT = "apt"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    MALWARE = "malware"
    BOTNET = "botnet"
    DATA_EXFIL = "data_exfil"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_THEFT = "credential_theft"
    UNKNOWN = "unknown"


@dataclass
class CorrelationResult:
    """Result of a correlation check"""
    triggered: bool = False
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    correlation_type: Optional[str] = None
    correlation_score: float = 0.0
    matched_alerts: List[str] = field(default_factory=list)
    matched_investigations: List[str] = field(default_factory=list)
    matched_iocs: List[str] = field(default_factory=list)
    campaign_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Campaign:
    """Campaign data structure"""
    campaign_id: str
    name: str
    campaign_type: str = "unknown"
    severity: str = "medium"
    confidence: float = 70.0
    alert_ids: List[str] = field(default_factory=list)
    investigation_ids: List[str] = field(default_factory=list)
    ioc_values: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


class IOCCorrelationEngine:
    """
    Enhanced IOC Correlation Engine

    Provides:
    - Real-time correlation as alerts are ingested
    - Rule-based pattern detection
    - Automatic campaign creation
    - Cross-alert IOC tracking
    """

    # IOC extraction patterns
    IOC_PATTERNS = {
        'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'cve': re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    }

    # Private/internal patterns to filter out
    PRIVATE_IP_RANGES = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^0\.'),
        re.compile(r'^169\.254\.'),
    ]

    INTERNAL_DOMAINS = [
        '.local', '.internal', '.corp', '.lan', '.home', '.localdomain',
        'localhost', 'example.com', 'example.org', 'example.net'
    ]

    def __init__(self):
        self._running = False
        self._correlation_task: Optional[asyncio.Task] = None
        self._rules_cache: List[Dict] = []
        self._rules_cache_time: Optional[datetime] = None

    def _get_db(self):
        """Get database connection"""
        try:
            from services.postgres_db import postgres_db
            return postgres_db
        except Exception:
            return None

    # ========================================================================
    # IOC EXTRACTION
    # ========================================================================

    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text content"""
        if not text:
            return {}

        iocs = {}

        for ioc_type, pattern in self.IOC_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                # Filter and deduplicate
                filtered = []
                for match in set(matches):
                    if self._is_valid_ioc(match, ioc_type):
                        filtered.append(match)
                if filtered:
                    iocs[ioc_type] = filtered

        return iocs

    def extract_iocs_from_alert(self, alert: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from alert structure"""
        iocs = {}

        # Ensure alert is a dict
        if isinstance(alert, str):
            try:
                alert = json.loads(alert)
            except:
                alert = {}

        if not isinstance(alert, dict):
            return iocs

        # Extract from title and description
        text_fields = [
            alert.get('title', '') or '',
            alert.get('description', '') or '',
        ]

        # Extract from raw_event JSONB
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        if not isinstance(raw_event, dict):
            raw_event = {}

        # Flatten raw_event to text
        text_fields.append(json.dumps(raw_event))

        # Extract structured IOCs from common fields
        structured_iocs = self._extract_structured_iocs(raw_event)

        # Combine text extraction
        combined_text = ' '.join(text_fields)
        text_iocs = self.extract_iocs_from_text(combined_text)

        # Merge results
        for ioc_type, values in structured_iocs.items():
            if ioc_type not in iocs:
                iocs[ioc_type] = []
            iocs[ioc_type].extend(values)

        for ioc_type, values in text_iocs.items():
            if ioc_type not in iocs:
                iocs[ioc_type] = []
            iocs[ioc_type].extend(values)

        # Deduplicate
        for ioc_type in iocs:
            iocs[ioc_type] = list(set(iocs[ioc_type]))

        return iocs

    def _extract_structured_iocs(self, raw_event: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from structured fields (ECS format)"""
        iocs = {}

        # Common ECS paths for IOCs
        ecs_paths = {
            'ip': [
                'source.ip', 'destination.ip', 'client.ip', 'server.ip',
                'host.ip', 'network.remote_ip', 'network.local_ip',
                'source.nat.ip', 'destination.nat.ip'
            ],
            'domain': [
                'dns.question.name', 'url.domain', 'destination.domain',
                'source.domain', 'host.hostname', 'server.domain'
            ],
            'hash_sha256': [
                'file.hash.sha256', 'process.hash.sha256', 'dll.hash.sha256'
            ],
            'hash_sha1': [
                'file.hash.sha1', 'process.hash.sha1', 'dll.hash.sha1'
            ],
            'hash_md5': [
                'file.hash.md5', 'process.hash.md5', 'dll.hash.md5'
            ],
            'url': [
                'url.full', 'url.original', 'http.request.referrer'
            ],
            'email': [
                'user.email', 'source.user.email', 'destination.user.email'
            ]
        }

        for ioc_type, paths in ecs_paths.items():
            for path in paths:
                value = self._get_nested_value(raw_event, path)
                if value:
                    if ioc_type not in iocs:
                        iocs[ioc_type] = []
                    if isinstance(value, list):
                        iocs[ioc_type].extend([v for v in value if self._is_valid_ioc(v, ioc_type)])
                    elif self._is_valid_ioc(value, ioc_type):
                        iocs[ioc_type].append(value)

        return iocs

    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get value from nested dict using dot notation"""
        keys = path.split('.')
        current = obj
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _is_valid_ioc(self, value: str, ioc_type: str) -> bool:
        """Check if IOC value is valid (not private/internal)"""
        if not value:
            return False

        value = str(value).strip()

        # Filter private IPs
        if ioc_type == 'ip':
            for pattern in self.PRIVATE_IP_RANGES:
                if pattern.match(value):
                    return False

        # Filter internal domains
        if ioc_type == 'domain':
            value_lower = value.lower()
            for internal in self.INTERNAL_DOMAINS:
                if value_lower.endswith(internal) or value_lower == internal.lstrip('.'):
                    return False

        return True

    # ========================================================================
    # ALERT-IOC LINKING
    # ========================================================================

    async def link_alert_iocs(self, alert_id: str, alert: Dict) -> int:
        """Extract IOCs from alert and create links"""
        db = self._get_db()
        if not db or not db.pool:
            return 0

        iocs = self.extract_iocs_from_alert(alert)
        if not iocs:
            logger.debug(f"No IOCs extracted from alert {alert_id}")
            return 0

        linked_count = 0

        try:
            async with db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = alert.get('tenant_id') or get_optional_tenant_id()

                for ioc_type, values in iocs.items():
                    for ioc_value in values:
                        try:
                            # alert_id is a string like "ALT-XXXXXX", not UUID
                            await conn.execute(
                                """
                                INSERT INTO alert_ioc_links (alert_id, ioc_value, ioc_type, extraction_method, tenant_id)
                                VALUES ($1, $2, $3, 'regex', $4)
                                ON CONFLICT (alert_id, ioc_value, ioc_type) DO NOTHING
                                """,
                                alert_id, ioc_value, ioc_type,
                                uuid.UUID(str(_tenant_id)) if _tenant_id else None
                            )
                            linked_count += 1
                        except Exception as e:
                            logger.debug(f"Failed to link IOC {ioc_value}: {e}")

            if linked_count > 0:
                logger.info(f"[CORRELATION] Linked {linked_count} IOCs from alert {alert_id}")

        except Exception as e:
            logger.error(f"Failed to link alert IOCs: {e}")

        return linked_count

    # ========================================================================
    # CORRELATION DETECTION
    # ========================================================================

    async def check_correlations(self, alert_id: str, alert: Dict) -> List[CorrelationResult]:
        """Check all correlation rules against new alert"""
        logger.info(f"[CORRELATION] Starting correlation check for alert {alert_id}")
        results = []

        # Get active rules
        rules = await self._get_active_rules()
        logger.info(f"[CORRELATION] Found {len(rules)} active rules to check")

        for rule in rules:
            try:
                logger.debug(f"[CORRELATION] Checking rule {rule.get('rule_id', 'unknown')} for alert {alert_id}")
                result = await self._check_rule(rule, alert_id, alert)
                if result.triggered:
                    results.append(result)

                    # Log correlation event
                    await self._log_correlation_event(result)

                    # Auto-create campaign if configured
                    if rule.get('auto_create_campaign') and not result.campaign_id:
                        campaign = await self._create_campaign_from_correlation(result)
                        if campaign:
                            result.campaign_id = campaign.campaign_id

            except Exception as e:
                import traceback
                logger.warning(f"Error checking rule {rule.get('rule_id')}: {e}")
                logger.debug(traceback.format_exc())

        return results

    async def _get_active_rules(self) -> List[Dict]:
        """Get active correlation rules (with caching)"""
        # Check cache
        if self._rules_cache_time and (datetime.utcnow() - self._rules_cache_time).seconds < 300:
            return self._rules_cache

        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT * FROM correlation_rules
                    WHERE enabled = true
                    ORDER BY priority ASC
                    """
                )
                self._rules_cache = [dict(row) for row in rows]
                self._rules_cache_time = datetime.utcnow()
                return self._rules_cache

        except Exception as e:
            logger.error(f"Failed to get correlation rules: {e}")
            return []

    async def _check_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """Check a single correlation rule"""
        # Ensure alert is a dict, not a string
        if isinstance(alert, str):
            try:
                alert = json.loads(alert)
            except:
                logger.warning(f"Alert data is a string and not valid JSON: {alert[:100]}")
                return CorrelationResult()

        rule_type = rule.get('rule_type')

        if rule_type == 'ioc_match':
            return await self._check_ioc_match_rule(rule, alert_id, alert)
        elif rule_type == 'time_window':
            return await self._check_time_window_rule(rule, alert_id, alert)
        elif rule_type == 'host_pattern':
            return await self._check_host_pattern_rule(rule, alert_id, alert)
        elif rule_type == 'technique_match':
            return await self._check_technique_match_rule(rule, alert_id, alert)
        elif rule_type == 'severity_chain':
            return await self._check_severity_chain_rule(rule, alert_id, alert)

        return CorrelationResult()

    def _get_rule_params(self, rule: Dict) -> Dict:
        """Safely get parameters from a rule (handles JSON string)"""
        params = rule.get('parameters', {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except:
                params = {}
        return params if isinstance(params, dict) else {}

    async def _check_ioc_match_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """Check if IOCs in this alert match other alerts"""
        db = self._get_db()
        if not db or not db.pool:
            return CorrelationResult()

        params = self._get_rule_params(rule)
        min_occurrences = params.get('min_occurrences', 3)
        ioc_types = params.get('ioc_types', ['ip', 'domain', 'hash_sha256'])
        time_window_hours = params.get('time_window_hours', 24)

        # Get IOCs from this alert
        iocs = self.extract_iocs_from_alert(alert)
        if not iocs:
            return CorrelationResult()

        try:
            async with db.tenant_acquire() as conn:
                # Check each IOC for matches in other alerts
                for ioc_type, values in iocs.items():
                    if ioc_type not in ioc_types:
                        continue

                    for ioc_value in values:
                        # Count occurrences across alerts
                        row = await conn.fetchrow(
                            """
                            SELECT
                                COUNT(DISTINCT alert_id) as alert_count,
                                array_agg(DISTINCT alert_id::text) as alert_ids
                            FROM alert_ioc_links
                            WHERE ioc_value = $1
                              AND ioc_type = $2
                              AND created_at > NOW() - $3 * INTERVAL '1 hour'
                            """,
                            ioc_value, ioc_type, time_window_hours
                        )

                        logger.info(f"[CORRELATION] IOC {ioc_value} ({ioc_type}) found in {row['alert_count'] if row else 0} alerts (need {min_occurrences})")
                        if row and row['alert_count'] >= min_occurrences:
                            # Correlation found!
                            logger.info(f"[CORRELATION] IOC MATCH TRIGGERED! {ioc_value} in {row['alert_count']} alerts")
                            return CorrelationResult(
                                triggered=True,
                                rule_id=rule.get('rule_id'),
                                rule_name=rule.get('name'),
                                correlation_type='ioc_match',
                                correlation_score=min(100, row['alert_count'] * 20),
                                matched_alerts=row['alert_ids'] or [],
                                matched_iocs=[ioc_value],
                                details={
                                    'ioc_value': ioc_value,
                                    'ioc_type': ioc_type,
                                    'occurrence_count': row['alert_count']
                                }
                            )

        except Exception as e:
            logger.error(f"IOC match rule check failed: {e}")

        return CorrelationResult()

    async def _check_time_window_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """Check for event clustering within time window"""
        db = self._get_db()
        if not db or not db.pool:
            return CorrelationResult()

        params = self._get_rule_params(rule)
        window_minutes = params.get('window_minutes', 5)
        min_events = params.get('min_events', 5)
        group_by = params.get('group_by', ['source_ip'])

        # Get grouping values from alert
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        # Extract grouping key
        group_values = []
        for field in group_by:
            value = self._get_nested_value(raw_event, field) or self._get_nested_value(raw_event, f'source.{field}')
            if value:
                group_values.append(str(value))

        if not group_values:
            return CorrelationResult()

        group_key = '|'.join(group_values)

        try:
            async with db.tenant_acquire() as conn:
                # Count recent alerts with similar grouping
                row = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) as event_count,
                        array_agg(alert_id::text) as alert_ids
                    FROM alerts
                    WHERE created_at > NOW() - $1 * INTERVAL '1 minute'
                      AND raw_event::text LIKE $2
                    """,
                    window_minutes, f'%{group_values[0]}%'
                )

                if row and row['event_count'] >= min_events:
                    return CorrelationResult(
                        triggered=True,
                        rule_id=rule.get('rule_id'),
                        rule_name=rule.get('name'),
                        correlation_type='time_window',
                        correlation_score=min(100, row['event_count'] * 15),
                        matched_alerts=row['alert_ids'][:20] if row['alert_ids'] else [],
                        details={
                            'group_key': group_key,
                            'event_count': row['event_count'],
                            'window_minutes': window_minutes
                        }
                    )

        except Exception as e:
            logger.error(f"Time window rule check failed: {e}")

        return CorrelationResult()

    async def _check_host_pattern_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """Check for multiple alert types on same host"""
        db = self._get_db()
        if not db or not db.pool:
            return CorrelationResult()

        params = self._get_rule_params(rule)
        min_alert_types = params.get('min_alert_types', 3)
        time_window_hours = params.get('time_window_hours', 24)

        # Get hostname from alert
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        hostname = (
            self._get_nested_value(raw_event, 'host.hostname') or
            self._get_nested_value(raw_event, 'host.name') or
            self._get_nested_value(raw_event, 'agent.hostname')
        )

        if not hostname:
            return CorrelationResult()

        try:
            async with db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(DISTINCT category) as type_count,
                        array_agg(DISTINCT alert_id::text) as alert_ids,
                        array_agg(DISTINCT category) as categories
                    FROM alerts
                    WHERE created_at > NOW() - $1 * INTERVAL '1 hour'
                      AND raw_event::text ILIKE $2
                    """,
                    time_window_hours, f'%{hostname}%'
                )

                if row and row['type_count'] >= min_alert_types:
                    return CorrelationResult(
                        triggered=True,
                        rule_id=rule.get('rule_id'),
                        rule_name=rule.get('name'),
                        correlation_type='host_pattern',
                        correlation_score=min(100, row['type_count'] * 25),
                        matched_alerts=row['alert_ids'][:20] if row['alert_ids'] else [],
                        details={
                            'hostname': hostname,
                            'alert_types': row['categories'],
                            'type_count': row['type_count']
                        }
                    )

        except Exception as e:
            logger.error(f"Host pattern rule check failed: {e}")

        return CorrelationResult()

    async def _check_technique_match_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """
        Check for MITRE ATT&CK technique matches across alerts.

        Detects when multiple alerts share the same MITRE technique or
        when a sequence of related techniques appears (attack chain).

        Parameters:
            - min_occurrences: Minimum alerts with same technique (default: 2)
            - time_window_hours: Lookback window (default: 48)
            - technique_groups: Optional list of technique IDs to watch for
        """
        db = self._get_db()
        if not db or not db.pool:
            return CorrelationResult()

        params = self._get_rule_params(rule)
        min_occurrences = params.get('min_occurrences', 2)
        time_window_hours = params.get('time_window_hours', 48)
        technique_groups = params.get('technique_groups', [])

        # Extract MITRE techniques from current alert
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                import json
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        alert_techniques = self._extract_mitre_techniques(alert, raw_event)

        if not alert_techniques:
            return CorrelationResult()

        try:
            async with db.tenant_acquire() as conn:
                # Find other alerts with matching techniques
                matching_alerts = await conn.fetch(
                    """
                    SELECT
                        a.alert_id,
                        a.title,
                        a.category,
                        a.raw_event
                    FROM alerts a
                    WHERE a.created_at > NOW() - $1 * INTERVAL '1 hour'
                      AND a.alert_id != $2
                      AND (
                          -- Check in raw_event for technique IDs
                          a.raw_event::text ~* $3
                          OR a.category ~* $3
                      )
                    ORDER BY a.created_at DESC
                    LIMIT 50
                    """,
                    time_window_hours,
                    alert.get('alert_id', ''),
                    '|'.join(alert_techniques)  # Regex OR pattern for all techniques
                )

                # Filter to alerts that actually have matching techniques
                matched_alert_ids = []
                matched_techniques = set(alert_techniques)

                for row in matching_alerts:
                    row_raw = row['raw_event'] or {}
                    if isinstance(row_raw, str):
                        try:
                            import json
                            row_raw = json.loads(row_raw)
                        except:
                            row_raw = {}

                    row_techniques = self._extract_mitre_techniques(
                        {'category': row['category']}, row_raw
                    )

                    # Check for technique overlap
                    overlap = set(row_techniques) & set(alert_techniques)
                    if overlap:
                        matched_alert_ids.append(row['alert_id'])
                        matched_techniques.update(row_techniques)

                # Include current alert
                total_matches = len(matched_alert_ids) + 1

                if total_matches >= min_occurrences:
                    # Determine campaign type from techniques
                    campaign_type = self._infer_campaign_type_from_techniques(list(matched_techniques))

                    return CorrelationResult(
                        triggered=True,
                        rule_id=rule.get('rule_id'),
                        rule_name=rule.get('name'),
                        correlation_type='technique_match',
                        correlation_score=min(100, total_matches * 20 + len(matched_techniques) * 10),
                        matched_alerts=[alert.get('alert_id')] + matched_alert_ids[:19],
                        matched_iocs=list(matched_techniques),
                        details={
                            'techniques': list(matched_techniques),
                            'technique_count': len(matched_techniques),
                            'alert_count': total_matches,
                            'campaign_type': campaign_type
                        }
                    )

        except Exception as e:
            logger.error(f"Technique match rule check failed: {e}")

        return CorrelationResult()

    def _extract_mitre_techniques(self, alert: Dict, raw_event: Dict) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from alert data."""
        techniques = []

        # Pattern for MITRE technique IDs (T1234, T1234.001, etc.)
        import re
        technique_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)

        # Check various locations where techniques might be stored
        sources_to_check = [
            alert.get('category', ''),
            alert.get('subcategory', ''),
            str(raw_event.get('threat', {}).get('technique', {}).get('id', '')),
            str(raw_event.get('threat', {}).get('technique', {}).get('name', '')),
            str(raw_event.get('rule', {}).get('mitre', '')),
            str(raw_event.get('signal', {}).get('rule', {}).get('threat', '')),
            str(raw_event.get('_extracted', {}).get('mitre_techniques', [])),
            str(raw_event.get('kibana.alert.rule.threat', '')),
        ]

        # Also check ECS threat.technique array
        threat_techniques = raw_event.get('threat', {}).get('technique', [])
        if isinstance(threat_techniques, list):
            for t in threat_techniques:
                if isinstance(t, dict) and t.get('id'):
                    techniques.append(t['id'].upper())

        # Extract from all text sources
        for source in sources_to_check:
            if source:
                matches = technique_pattern.findall(str(source))
                techniques.extend([m.upper() for m in matches])

        # Deduplicate
        return list(set(techniques))

    def _infer_campaign_type_from_techniques(self, techniques: List[str]) -> str:
        """Infer campaign type from MITRE technique patterns."""
        # Common technique to campaign type mappings
        technique_mappings = {
            # Phishing / Initial Access
            'T1566': 'phishing', 'T1566.001': 'phishing', 'T1566.002': 'phishing',
            'T1598': 'phishing',

            # Credential theft
            'T1003': 'credential_theft', 'T1003.001': 'credential_theft',
            'T1110': 'credential_theft', 'T1555': 'credential_theft',
            'T1552': 'credential_theft', 'T1558': 'credential_theft',

            # Lateral movement
            'T1021': 'lateral_movement', 'T1021.001': 'lateral_movement',
            'T1021.002': 'lateral_movement', 'T1021.003': 'lateral_movement',
            'T1080': 'lateral_movement', 'T1570': 'lateral_movement',

            # Data exfiltration
            'T1041': 'data_exfil', 'T1048': 'data_exfil', 'T1567': 'data_exfil',
            'T1029': 'data_exfil', 'T1030': 'data_exfil',

            # Ransomware indicators
            'T1486': 'ransomware', 'T1490': 'ransomware', 'T1489': 'ransomware',

            # C2 / Botnet
            'T1071': 'botnet', 'T1095': 'botnet', 'T1102': 'botnet',
            'T1105': 'botnet', 'T1571': 'botnet',

            # Malware execution
            'T1059': 'malware', 'T1059.001': 'malware', 'T1059.003': 'malware',
            'T1204': 'malware', 'T1106': 'malware',
        }

        for tech in techniques:
            tech_upper = tech.upper()
            if tech_upper in technique_mappings:
                return technique_mappings[tech_upper]

        return 'unknown'

    async def _check_severity_chain_rule(self, rule: Dict, alert_id: str, alert: Dict) -> CorrelationResult:
        """
        Check for severity escalation patterns.

        Detects when alerts from the same source show severity escalation
        (e.g., low -> medium -> high -> critical) within a time window.

        Parameters:
            - time_window_hours: Lookback window (default: 24)
            - min_escalations: Minimum severity jumps to trigger (default: 2)
            - group_by: Field to group alerts (default: source_ip)
        """
        db = self._get_db()
        if not db or not db.pool:
            return CorrelationResult()

        params = self._get_rule_params(rule)
        time_window_hours = params.get('time_window_hours', 24)
        min_escalations = params.get('min_escalations', 2)
        group_by = params.get('group_by', 'source_ip')

        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                import json
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        # Get grouping value (source IP, hostname, user, etc.)
        group_value = None
        if group_by == 'source_ip':
            group_value = (
                self._get_nested_value(raw_event, 'source.ip') or
                self._get_nested_value(raw_event, 'client.ip')
            )
        elif group_by == 'hostname':
            group_value = (
                self._get_nested_value(raw_event, 'host.hostname') or
                self._get_nested_value(raw_event, 'host.name')
            )
        elif group_by == 'user':
            group_value = (
                self._get_nested_value(raw_event, 'user.name') or
                self._get_nested_value(raw_event, 'user.id')
            )

        if not group_value:
            return CorrelationResult()

        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        current_severity = alert.get('severity', 'medium').lower()
        current_score = severity_order.get(current_severity, 2)

        try:
            async with db.tenant_acquire() as conn:
                # Get recent alerts from same source with escalating severity
                rows = await conn.fetch(
                    """
                    SELECT alert_id, severity, created_at, title
                    FROM alerts
                    WHERE created_at > NOW() - $1 * INTERVAL '1 hour'
                      AND raw_event::text ILIKE $2
                    ORDER BY created_at ASC
                    """,
                    time_window_hours, f'%{group_value}%'
                )

                if len(rows) < 2:
                    return CorrelationResult()

                # Count severity escalations
                escalations = 0
                prev_score = 0
                alert_ids = []
                severity_sequence = []

                for row in rows:
                    row_severity = (row['severity'] or 'medium').lower()
                    row_score = severity_order.get(row_severity, 2)

                    if row_score > prev_score and prev_score > 0:
                        escalations += 1

                    alert_ids.append(row['alert_id'])
                    severity_sequence.append(row_severity)
                    prev_score = row_score

                if escalations >= min_escalations:
                    return CorrelationResult(
                        triggered=True,
                        rule_id=rule.get('rule_id'),
                        rule_name=rule.get('name'),
                        correlation_type='severity_chain',
                        correlation_score=min(100, escalations * 30 + len(alert_ids) * 5),
                        matched_alerts=alert_ids[:20],
                        details={
                            'group_by': group_by,
                            'group_value': group_value,
                            'escalations': escalations,
                            'severity_sequence': severity_sequence,
                            'alert_count': len(alert_ids)
                        }
                    )

        except Exception as e:
            logger.error(f"Severity chain rule check failed: {e}")

        return CorrelationResult()

    # ========================================================================
    # CAMPAIGN MANAGEMENT
    # ========================================================================

    async def _create_campaign_from_correlation(self, result: CorrelationResult) -> Optional[Campaign]:
        """Auto-create campaign from correlation result"""
        db = self._get_db()
        if not db or not db.pool:
            return None

        campaign_id = f"CAMP-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

        # Determine campaign type from correlation
        campaign_type = self._infer_campaign_type(result)

        # Generate name
        name = f"Auto-Correlated Campaign ({result.correlation_type})"
        if result.matched_iocs:
            name = f"Campaign: {result.matched_iocs[0][:30]}..."

        try:
            async with db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()
                _tenant_uuid = uuid.UUID(str(_tenant_id)) if _tenant_id else None

                # Create campaign
                await conn.execute(
                    """
                    INSERT INTO campaigns (
                        campaign_id, name, campaign_type, severity, confidence,
                        alert_count, ioc_count, created_by,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'auto_correlation', $8)
                    """,
                    campaign_id,
                    name,
                    campaign_type,
                    'high' if result.correlation_score > 70 else 'medium',
                    result.correlation_score,
                    len(result.matched_alerts),
                    len(result.matched_iocs),
                    _tenant_uuid
                )

                # Add alert members and their investigations
                for alert_id in result.matched_alerts:
                    try:
                        # Link alert to campaign
                        await conn.execute(
                            """
                            INSERT INTO campaign_members (campaign_id, member_type, alert_id, added_by, correlation_reason, correlation_score, tenant_id)
                            SELECT id, 'alert', $2::uuid, 'auto', $3, $4, $5
                            FROM campaigns WHERE campaign_id = $1
                            ON CONFLICT DO NOTHING
                            """,
                            campaign_id, alert_id, result.rule_name, result.correlation_score,
                            _tenant_uuid
                        )

                        # Also link any investigation associated with this alert
                        inv_row = await conn.fetchrow(
                            """
                            SELECT i.id as inv_uuid, i.investigation_id
                            FROM investigations i
                            JOIN alerts a ON a.investigation_id = i.id
                            WHERE a.id = $1::uuid
                            """,
                            alert_id
                        )
                        if inv_row:
                            await conn.execute(
                                """
                                INSERT INTO campaign_members (campaign_id, member_type, investigation_id, added_by, correlation_reason, correlation_score, tenant_id)
                                SELECT id, 'investigation', $2::uuid, 'auto_correlation', $3, $4, $5
                                FROM campaigns WHERE campaign_id = $1
                                ON CONFLICT DO NOTHING
                                """,
                                campaign_id, inv_row['inv_uuid'], result.rule_name, result.correlation_score,
                                _tenant_uuid
                            )
                            result.matched_investigations.append(inv_row['investigation_id'])
                    except Exception as e:
                        logger.debug(f"Error linking alert/investigation to campaign: {e}")

                # Add IOCs
                for ioc_value in result.matched_iocs:
                    try:
                        # Detect IOC type
                        ioc_type = 'unknown'
                        for t, pattern in self.IOC_PATTERNS.items():
                            if pattern.match(ioc_value):
                                ioc_type = t
                                break

                        await conn.execute(
                            """
                            INSERT INTO campaign_iocs (campaign_id, ioc_value, ioc_type, confidence, tenant_id)
                            SELECT id, $2, $3, $4, $5
                            FROM campaigns WHERE campaign_id = $1
                            ON CONFLICT DO NOTHING
                            """,
                            campaign_id, ioc_value, ioc_type, result.correlation_score,
                            _tenant_uuid
                        )
                    except Exception:
                        pass

                # Update rule trigger count
                if result.rule_id:
                    await conn.execute(
                        """
                        UPDATE correlation_rules
                        SET trigger_count = trigger_count + 1, last_triggered_at = NOW()
                        WHERE rule_id = $1
                        """,
                        result.rule_id
                    )

                logger.info(f"Auto-created campaign {campaign_id} from {result.rule_name}")

                return Campaign(
                    campaign_id=campaign_id,
                    name=name,
                    campaign_type=campaign_type,
                    alert_ids=result.matched_alerts,
                    ioc_values=result.matched_iocs
                )

        except Exception as e:
            logger.error(f"Failed to create campaign: {e}")
            return None

    def _infer_campaign_type(self, result: CorrelationResult) -> str:
        """Infer campaign type from correlation details"""
        if result.correlation_type == 'technique_match':
            techniques = result.details.get('techniques', [])
            if any(t.startswith('T102') for t in techniques):  # Lateral movement
                return 'lateral_movement'
            if any(t.startswith('T1566') for t in techniques):  # Phishing
                return 'phishing'

        if result.correlation_type == 'ioc_match':
            ioc_type = result.details.get('ioc_type', '')
            if ioc_type == 'domain':
                return 'phishing'
            if ioc_type == 'hash_sha256':
                return 'malware'

        return 'unknown'

    async def _log_correlation_event(self, result: CorrelationResult):
        """Log correlation event to database"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO correlation_events (
                        rule_id, rule_name, correlation_type, correlation_score,
                        alert_ids, ioc_values, campaign_id, action_taken, details
                    )
                    SELECT id, $2, $3, $4, $5::uuid[], $6::text[],
                           (SELECT id FROM campaigns WHERE campaign_id = $7),
                           $8, $9::jsonb
                    FROM correlation_rules WHERE rule_id = $1
                    """,
                    result.rule_id,
                    result.rule_name,
                    result.correlation_type,
                    result.correlation_score,
                    result.matched_alerts if result.matched_alerts else None,
                    result.matched_iocs if result.matched_iocs else None,
                    result.campaign_id,
                    'campaign_created' if result.campaign_id else 'correlation_detected',
                    json.dumps(result.details)
                )
        except Exception as e:
            logger.debug(f"Failed to log correlation event: {e}")

    # ========================================================================
    # QUERY METHODS
    # ========================================================================

    async def get_campaigns(
        self,
        status: Optional[str] = None,
        campaign_type: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Get campaigns with optional filtering"""
        db = self._get_db()
        if not db or not db.pool:
            return []

        try:
            async with db.tenant_acquire() as conn:
                query = """
                    SELECT * FROM campaigns
                    WHERE ($1::text IS NULL OR status = $1)
                      AND ($2::text IS NULL OR campaign_type = $2)
                    ORDER BY last_activity DESC
                    LIMIT $3
                """
                rows = await conn.fetch(query, status, campaign_type, limit)
                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get campaigns: {e}")
            return []

    async def get_campaign_details(self, campaign_id: str) -> Optional[Dict]:
        """Get full campaign details including members and IOCs"""
        db = self._get_db()
        if not db or not db.pool:
            return None

        try:
            async with db.tenant_acquire() as conn:
                # Get campaign
                campaign = await conn.fetchrow(
                    "SELECT * FROM campaigns WHERE campaign_id = $1",
                    campaign_id
                )

                if not campaign:
                    return None

                result = dict(campaign)

                # Get members
                members = await conn.fetch(
                    """
                    SELECT cm.*, a.title as alert_title, a.severity as alert_severity
                    FROM campaign_members cm
                    LEFT JOIN alerts a ON cm.alert_id = a.id
                    WHERE cm.campaign_id = (SELECT id FROM campaigns WHERE campaign_id = $1)
                    ORDER BY cm.added_at DESC
                    """,
                    campaign_id
                )
                result['members'] = [dict(m) for m in members]

                # Get IOCs
                iocs = await conn.fetch(
                    """
                    SELECT * FROM campaign_iocs
                    WHERE campaign_id = (SELECT id FROM campaigns WHERE campaign_id = $1)
                    ORDER BY occurrence_count DESC
                    """,
                    campaign_id
                )
                result['iocs'] = [dict(i) for i in iocs]

                return result

        except Exception as e:
            logger.error(f"Failed to get campaign details: {e}")
            return None

    async def get_ioc_correlations(self, ioc_value: str, ioc_type: str) -> Dict:
        """Get all correlations for a specific IOC"""
        db = self._get_db()
        if not db or not db.pool:
            return {}

        try:
            async with db.tenant_acquire() as conn:
                # Get alert links
                alert_links = await conn.fetch(
                    """
                    SELECT ail.*, a.title, a.severity, a.created_at as alert_created
                    FROM alert_ioc_links ail
                    JOIN alerts a ON ail.alert_id = a.id
                    WHERE ail.ioc_value = $1 AND ail.ioc_type = $2
                    ORDER BY a.created_at DESC
                    LIMIT 50
                    """,
                    ioc_value, ioc_type
                )

                # Get campaigns containing this IOC
                campaigns = await conn.fetch(
                    """
                    SELECT c.* FROM campaigns c
                    JOIN campaign_iocs ci ON c.id = ci.campaign_id
                    WHERE ci.ioc_value = $1 AND ci.ioc_type = $2
                    """,
                    ioc_value, ioc_type
                )

                # Get feed appearances
                feed_appearances = await conn.fetch(
                    """
                    SELECT * FROM ioc_feed_appearances
                    WHERE ioc_value = $1 AND ioc_type = $2
                    ORDER BY last_seen_in_feed DESC
                    """,
                    ioc_value, ioc_type
                )

                return {
                    'ioc_value': ioc_value,
                    'ioc_type': ioc_type,
                    'alert_count': len(alert_links),
                    'campaign_count': len(campaigns),
                    'feed_count': len(feed_appearances),
                    'alerts': [dict(a) for a in alert_links],
                    'campaigns': [dict(c) for c in campaigns],
                    'feed_appearances': [dict(f) for f in feed_appearances]
                }

        except Exception as e:
            logger.error(f"Failed to get IOC correlations: {e}")
            return {}

    async def get_correlation_stats(self) -> Dict:
        """Get correlation statistics"""
        db = self._get_db()
        if not db or not db.pool:
            return {}

        try:
            async with db.tenant_acquire() as conn:
                stats = {}

                # Campaign stats
                campaign_stats = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE status = 'active') as active,
                        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h
                    FROM campaigns
                    """
                )
                stats['campaigns'] = dict(campaign_stats) if campaign_stats else {}

                # Rule stats
                rule_stats = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE enabled = true) as enabled,
                        SUM(trigger_count) as total_triggers
                    FROM correlation_rules
                    """
                )
                stats['rules'] = dict(rule_stats) if rule_stats else {}

                # IOC link stats
                link_stats = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) as total_links,
                        COUNT(DISTINCT alert_id) as alerts_with_iocs,
                        COUNT(DISTINCT ioc_value) as unique_iocs
                    FROM alert_ioc_links
                    """
                )
                stats['ioc_links'] = dict(link_stats) if link_stats else {}

                # Recent correlations
                recent_events = await conn.fetch(
                    """
                    SELECT correlation_type, COUNT(*) as count
                    FROM correlation_events
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                    GROUP BY correlation_type
                    """
                )
                stats['recent_correlations'] = {r['correlation_type']: r['count'] for r in recent_events}

                return stats

        except Exception as e:
            logger.error(f"Failed to get correlation stats: {e}")
            return {}


# ============================================================================
# SINGLETON
# ============================================================================

_correlation_engine: Optional[IOCCorrelationEngine] = None


def get_correlation_engine() -> IOCCorrelationEngine:
    """Get the global correlation engine instance"""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = IOCCorrelationEngine()
    return _correlation_engine
