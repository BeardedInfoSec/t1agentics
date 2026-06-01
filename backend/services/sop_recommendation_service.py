# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
SOP Recommendation Service

Automatically recommends relevant SOPs and playbooks based on:
- Alert characteristics (type, severity, source)
- IOC types present
- MITRE ATT&CK techniques
- Historical investigation patterns
- Text similarity matching

This service provides proactive SOP suggestions to analysts
during investigation, improving response consistency and speed.
"""

import logging
import re
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class SOPRecommendation:
    """A single SOP recommendation with relevance score."""
    kb_id: str
    title: str
    content_type: str
    category: Optional[str]
    relevance_score: float  # 0.0 to 1.0
    match_reasons: List[str]
    summary: Optional[str] = None
    key_steps: List[str] = field(default_factory=list)
    priority: int = 100


@dataclass
class RecommendationResult:
    """Result of SOP recommendation query."""
    recommendations: List[SOPRecommendation]
    alert_context: Dict[str, Any]
    query_time_ms: float
    source: str  # 'investigation', 'alert', 'manual'


# Alert type keywords for classification
ALERT_TYPE_KEYWORDS = {
    'phishing': ['phishing', 'phish', 'spear', 'bec', 'email', 'sender', 'recipient',
                 'attachment', 'link', 'credential harvest', 'impersonation'],
    'malware': ['malware', 'virus', 'trojan', 'ransomware', 'worm', 'backdoor',
                'exploit', 'dropper', 'payload', 'execution', 'process'],
    'endpoint': ['endpoint', 'edr', 'process', 'registry', 'file', 'persistence',
                 'service', 'driver', 'dll', 'executable'],
    'network': ['network', 'traffic', 'connection', 'dns', 'firewall', 'proxy',
                'c2', 'beacon', 'exfiltration', 'lateral'],
    'identity': ['login', 'authentication', 'credential', 'password', 'mfa',
                 'brute force', 'account', 'privilege', 'access'],
    'data_loss': ['data loss', 'dlp', 'exfiltration', 'upload', 'transfer',
                  'sensitive', 'pii', 'confidential'],
    'cloud': ['cloud', 'aws', 'azure', 'gcp', 's3', 'iam', 'api', 'saas'],
    'insider': ['insider', 'employee', 'terminated', 'unusual access', 'policy violation']
}

# MITRE technique to category mapping
MITRE_CATEGORY_MAP = {
    'T1566': 'phishing',      # Phishing
    'T1059': 'malware',       # Command and Scripting Interpreter
    'T1055': 'malware',       # Process Injection
    'T1547': 'endpoint',      # Boot or Logon Autostart Execution
    'T1053': 'endpoint',      # Scheduled Task/Job
    'T1071': 'network',       # Application Layer Protocol
    'T1021': 'network',       # Remote Services
    'T1078': 'identity',      # Valid Accounts
    'T1110': 'identity',      # Brute Force
    'T1567': 'data_loss',     # Exfiltration Over Web Service
    'T1048': 'data_loss',     # Exfiltration Over Alternative Protocol
}


class SOPRecommendationService:
    """
    Service for recommending relevant SOPs based on alert/investigation context.

    Features:
    - Multi-factor relevance scoring
    - Alert type classification
    - MITRE technique matching
    - Historical effectiveness tracking
    - Real-time recommendations
    """

    def __init__(self):
        self.enabled = True
        self._usage_cache: Dict[str, int] = {}  # kb_id -> usage count
        self._effectiveness_cache: Dict[str, float] = {}  # kb_id -> effectiveness score

    async def recommend_for_alert(
        self,
        alert_data: Dict[str, Any],
        limit: int = 5,
        min_score: float = 0.2
    ) -> RecommendationResult:
        """
        Get SOP recommendations for an alert.

        Args:
            alert_data: Alert data including title, description, severity, IOCs
            limit: Maximum number of recommendations
            min_score: Minimum relevance score (0-1)

        Returns:
            RecommendationResult with ranked recommendations
        """
        import time
        start_time = time.time()

        # Extract alert context
        context = self._extract_alert_context(alert_data)

        # Query knowledge base for matching SOPs
        from services.knowledge_base_service import knowledge_base_service

        # Build search parameters
        keywords = context.get('keywords', [])
        severity = context.get('severity')
        ioc_types = context.get('ioc_types', [])
        mitre_techniques = context.get('mitre_techniques', [])
        alert_type = context.get('alert_type')

        # Query with extracted context
        kb_results = await knowledge_base_service.query_for_context(
            alert_data=alert_data,
            severity=severity,
            ioc_types=ioc_types,
            mitre_techniques=mitre_techniques,
            keywords=keywords,
            limit=limit * 3,  # Get more to filter by score
            alert_type=alert_type
        )

        # Score and rank results
        recommendations = []
        for entry in kb_results:
            score, reasons = self._calculate_relevance_score(entry, context)

            if score >= min_score:
                # Extract key steps from content
                key_steps = self._extract_key_steps(entry.get('content', ''))

                recommendations.append(SOPRecommendation(
                    kb_id=entry['kb_id'],
                    title=entry['title'],
                    content_type=entry['content_type'],
                    category=entry.get('category'),
                    relevance_score=score,
                    match_reasons=reasons,
                    summary=entry.get('ai_summary'),
                    key_steps=key_steps[:5],
                    priority=entry.get('priority', 100)
                ))

        # Sort by relevance score (descending)
        recommendations.sort(key=lambda x: (-x.relevance_score, x.priority))

        query_time = (time.time() - start_time) * 1000

        return RecommendationResult(
            recommendations=recommendations[:limit],
            alert_context=context,
            query_time_ms=query_time,
            source='alert'
        )

    async def recommend_for_investigation(
        self,
        investigation_id: str,
        limit: int = 5,
        min_score: float = 0.2
    ) -> RecommendationResult:
        """
        Get SOP recommendations for an ongoing investigation.

        Considers all linked alerts and investigation history.

        Args:
            investigation_id: Investigation ID
            limit: Maximum number of recommendations
            min_score: Minimum relevance score

        Returns:
            RecommendationResult with ranked recommendations
        """
        import time
        start_time = time.time()

        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return RecommendationResult(
                recommendations=[],
                alert_context={},
                query_time_ms=0,
                source='investigation'
            )

        # Get investigation details
        async with postgres_db.tenant_acquire() as conn:
            inv_row = await conn.fetchrow('''
                SELECT * FROM investigations WHERE investigation_id = $1
            ''', investigation_id)

            if not inv_row:
                return RecommendationResult(
                    recommendations=[],
                    alert_context={'error': 'Investigation not found'},
                    query_time_ms=0,
                    source='investigation'
                )

            # Get linked alerts
            alert_rows = await conn.fetch('''
                SELECT a.* FROM alerts a
                JOIN investigation_alerts ia ON a.alert_id = ia.alert_id
                WHERE ia.investigation_id = $1
            ''', investigation_id)

        # Aggregate context from all alerts
        aggregated_context = {
            'severity': inv_row.get('priority') or 'medium',
            'keywords': [],
            'ioc_types': set(),
            'mitre_techniques': set(),
            'alert_types': set(),
        }

        for alert_row in alert_rows:
            alert_data = dict(alert_row)
            context = self._extract_alert_context(alert_data)

            aggregated_context['keywords'].extend(context.get('keywords', []))
            aggregated_context['ioc_types'].update(context.get('ioc_types', []))
            aggregated_context['mitre_techniques'].update(context.get('mitre_techniques', []))
            if context.get('alert_type'):
                aggregated_context['alert_types'].add(context['alert_type'])

        # Convert sets to lists
        aggregated_context['ioc_types'] = list(aggregated_context['ioc_types'])
        aggregated_context['mitre_techniques'] = list(aggregated_context['mitre_techniques'])
        aggregated_context['alert_types'] = list(aggregated_context['alert_types'])

        # Dedupe keywords, keep most frequent
        keyword_counts = defaultdict(int)
        for kw in aggregated_context['keywords']:
            keyword_counts[kw.lower()] += 1
        aggregated_context['keywords'] = sorted(
            keyword_counts.keys(),
            key=lambda x: keyword_counts[x],
            reverse=True
        )[:10]

        # Determine primary alert type
        if aggregated_context['alert_types']:
            aggregated_context['alert_type'] = list(aggregated_context['alert_types'])[0]

        # Query knowledge base
        from services.knowledge_base_service import knowledge_base_service

        kb_results = await knowledge_base_service.query_for_context(
            severity=aggregated_context['severity'],
            ioc_types=aggregated_context['ioc_types'],
            mitre_techniques=aggregated_context['mitre_techniques'],
            keywords=aggregated_context['keywords'],
            limit=limit * 3,
            alert_type=aggregated_context.get('alert_type')
        )

        # Score and rank
        recommendations = []
        for entry in kb_results:
            score, reasons = self._calculate_relevance_score(entry, aggregated_context)

            if score >= min_score:
                key_steps = self._extract_key_steps(entry.get('content', ''))

                recommendations.append(SOPRecommendation(
                    kb_id=entry['kb_id'],
                    title=entry['title'],
                    content_type=entry['content_type'],
                    category=entry.get('category'),
                    relevance_score=score,
                    match_reasons=reasons,
                    summary=entry.get('ai_summary'),
                    key_steps=key_steps[:5],
                    priority=entry.get('priority', 100)
                ))

        recommendations.sort(key=lambda x: (-x.relevance_score, x.priority))

        query_time = (time.time() - start_time) * 1000

        return RecommendationResult(
            recommendations=recommendations[:limit],
            alert_context=aggregated_context,
            query_time_ms=query_time,
            source='investigation'
        )

    async def recommend_by_text(
        self,
        query_text: str,
        limit: int = 5,
        content_types: Optional[List[str]] = None
    ) -> RecommendationResult:
        """
        Get SOP recommendations based on free-text search.

        Args:
            query_text: Search text
            limit: Maximum recommendations
            content_types: Filter by content types

        Returns:
            RecommendationResult with ranked recommendations
        """
        import time
        start_time = time.time()

        from services.knowledge_base_service import knowledge_base_service

        # Try semantic search first, fall back to text search
        results = await knowledge_base_service.semantic_search(
            query=query_text,
            limit=limit,
            content_types=content_types or ['sop', 'playbook', 'procedure', 'runbook']
        )

        recommendations = []
        for result in results:
            recommendations.append(SOPRecommendation(
                kb_id=result.kb_id,
                title=result.title,
                content_type=result.content_type,
                category=result.category,
                relevance_score=result.similarity_score,
                match_reasons=[f"Text match: {query_text[:50]}..."],
                summary=result.content_snippet
            ))

        query_time = (time.time() - start_time) * 1000

        return RecommendationResult(
            recommendations=recommendations,
            alert_context={'query': query_text},
            query_time_ms=query_time,
            source='manual'
        )

    def _extract_alert_context(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract searchable context from alert data."""
        context = {
            'severity': alert_data.get('severity', 'medium'),
            'keywords': [],
            'ioc_types': [],
            'mitre_techniques': [],
            'alert_type': None
        }

        # Extract from title
        title = alert_data.get('title', '')
        if title:
            words = re.findall(r'\b[a-zA-Z]{3,}\b', title.lower())
            context['keywords'].extend(words[:10])

        # Extract from description
        description = alert_data.get('description', '')
        if description:
            words = re.findall(r'\b[a-zA-Z]{4,}\b', description.lower())
            context['keywords'].extend(words[:10])

        # Get raw event data
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        # Extract IOC types
        extracted = raw_event.get('_extracted', {})
        if extracted:
            iocs = extracted.get('iocs', {})
            context['ioc_types'] = list(iocs.keys())

        # Extract MITRE techniques
        mitre = raw_event.get('mitre_techniques', [])
        if isinstance(mitre, str):
            mitre = [mitre]
        context['mitre_techniques'] = mitre

        # Classify alert type
        context['alert_type'] = self._classify_alert_type(title, description, raw_event)

        # Add type-specific keywords
        if context['alert_type']:
            type_keywords = ALERT_TYPE_KEYWORDS.get(context['alert_type'], [])
            context['keywords'].extend(type_keywords[:3])

        # Dedupe keywords
        seen = set()
        unique_keywords = []
        for kw in context['keywords']:
            if kw not in seen and len(kw) > 2:
                seen.add(kw)
                unique_keywords.append(kw)
        context['keywords'] = unique_keywords[:15]

        return context

    def _classify_alert_type(
        self,
        title: str,
        description: str,
        raw_event: Dict[str, Any]
    ) -> Optional[str]:
        """Classify alert into a type based on keywords."""
        text = f"{title} {description}".lower()

        # Check explicit category
        category = raw_event.get('category', '') or raw_event.get('alert_type', '')
        if category:
            category_lower = category.lower()
            for alert_type, keywords in ALERT_TYPE_KEYWORDS.items():
                if any(kw in category_lower for kw in keywords[:3]):
                    return alert_type

        # Score each type by keyword matches
        type_scores = defaultdict(int)
        for alert_type, keywords in ALERT_TYPE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    type_scores[alert_type] += 1

        # Check MITRE techniques
        mitre = raw_event.get('mitre_techniques', [])
        if isinstance(mitre, str):
            mitre = [mitre]
        for technique in mitre:
            # Get parent technique (e.g., T1566.001 -> T1566)
            parent = technique.split('.')[0] if '.' in technique else technique
            if parent in MITRE_CATEGORY_MAP:
                type_scores[MITRE_CATEGORY_MAP[parent]] += 2

        # Return highest scoring type
        if type_scores:
            return max(type_scores.keys(), key=lambda x: type_scores[x])

        return None

    def _calculate_relevance_score(
        self,
        kb_entry: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Calculate relevance score for a KB entry against alert context.

        Returns tuple of (score, match_reasons).
        """
        score = 0.0
        reasons = []

        entry_title = (kb_entry.get('title') or '').lower()
        entry_category = (kb_entry.get('category') or '').lower()
        entry_content = (kb_entry.get('content') or '')[:500].lower()
        entry_tags = [t.lower() for t in kb_entry.get('tags', [])]
        entry_severity = kb_entry.get('severity_filter', [])
        entry_incident_types = [t.lower() for t in kb_entry.get('incident_types', [])]

        # 1. Severity match (0.15 max)
        severity = context.get('severity', '').lower()
        if severity and severity in [s.lower() for s in entry_severity]:
            score += 0.15
            reasons.append(f"Severity match: {severity}")

        # 2. Alert type match (0.25 max)
        alert_type = context.get('alert_type')
        if alert_type:
            if alert_type in entry_category:
                score += 0.25
                reasons.append(f"Category match: {alert_type}")
            elif alert_type in entry_title:
                score += 0.20
                reasons.append(f"Title match: {alert_type}")
            elif any(alert_type in t for t in entry_tags):
                score += 0.15
                reasons.append(f"Tag match: {alert_type}")
            elif alert_type in entry_incident_types:
                score += 0.25
                reasons.append(f"Incident type match: {alert_type}")

        # 3. Keyword matches (0.30 max)
        keywords = context.get('keywords', [])
        keyword_matches = 0
        matched_keywords = []
        for keyword in keywords[:10]:
            if keyword in entry_title:
                keyword_matches += 2
                matched_keywords.append(keyword)
            elif keyword in entry_content:
                keyword_matches += 1
            elif keyword in entry_tags:
                keyword_matches += 1
                matched_keywords.append(keyword)

        keyword_score = min(0.30, keyword_matches * 0.03)
        if keyword_score > 0:
            score += keyword_score
            if matched_keywords:
                reasons.append(f"Keywords: {', '.join(matched_keywords[:3])}")

        # 4. IOC type match (0.15 max)
        ioc_types = context.get('ioc_types', [])
        entry_ioc_types = kb_entry.get('ioc_types', [])
        ioc_matches = set(ioc_types) & set(entry_ioc_types)
        if ioc_matches:
            score += min(0.15, len(ioc_matches) * 0.05)
            reasons.append(f"IOC types: {', '.join(list(ioc_matches)[:3])}")

        # 5. MITRE technique match (0.15 max)
        mitre_techniques = context.get('mitre_techniques', [])
        entry_mitre = kb_entry.get('mitre_techniques', []) or []
        mitre_matches = set(mitre_techniques) & set(entry_mitre)
        if mitre_matches:
            score += min(0.15, len(mitre_matches) * 0.075)
            reasons.append(f"MITRE: {', '.join(list(mitre_matches)[:2])}")

        # 6. Content type bonus (playbooks/SOPs prioritized)
        content_type = kb_entry.get('content_type', '')
        if content_type in ['sop', 'playbook', 'runbook']:
            score += 0.05

        # 7. Priority bonus
        priority = kb_entry.get('priority', 100)
        if priority < 50:
            score += 0.05
        elif priority < 25:
            score += 0.10

        # Cap at 1.0
        score = min(1.0, score)

        return score, reasons

    def _extract_key_steps(self, content: str) -> List[str]:
        """Extract key steps/procedures from SOP content."""
        steps = []

        # Look for numbered steps
        numbered = re.findall(r'^\s*\d+[\.\)]\s*(.+)$', content, re.MULTILINE)
        steps.extend(numbered[:5])

        # Look for bullet points
        if len(steps) < 3:
            bullets = re.findall(r'^\s*[-•*]\s*(.+)$', content, re.MULTILINE)
            steps.extend(bullets[:5 - len(steps)])

        # Look for action verbs (imperative sentences)
        if len(steps) < 3:
            action_pattern = r'^(Verify|Check|Confirm|Review|Analyze|Escalate|Notify|Block|Isolate|Contain|Document|Report)\b.+$'
            actions = re.findall(action_pattern, content, re.MULTILINE | re.IGNORECASE)
            steps.extend(actions[:5 - len(steps)])

        # Clean up steps
        cleaned = []
        for step in steps:
            step = step.strip()
            if len(step) > 10 and len(step) < 200:
                cleaned.append(step)

        return cleaned

    async def track_sop_effectiveness(
        self,
        kb_id: str,
        investigation_id: str,
        was_helpful: bool,
        resolution_time_minutes: Optional[int] = None
    ) -> None:
        """
        Track whether a recommended SOP was helpful.
        Used to improve future recommendations.

        Args:
            kb_id: Knowledge base entry ID
            investigation_id: Investigation ID
            was_helpful: Whether analyst found it helpful
            resolution_time_minutes: Time to resolution if applicable
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return

            async with postgres_db.tenant_acquire() as conn:
                # Record feedback
                await conn.execute('''
                    INSERT INTO sop_effectiveness_tracking (
                        kb_id, investigation_id, was_helpful,
                        resolution_time_minutes, tracked_at
                    ) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                    ON CONFLICT (kb_id, investigation_id)
                    DO UPDATE SET was_helpful = $3, resolution_time_minutes = $4
                ''', kb_id, investigation_id, was_helpful, resolution_time_minutes)

                # Update KB entry effectiveness score
                stats = await conn.fetchrow('''
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN was_helpful THEN 1 ELSE 0 END) as helpful_count,
                        AVG(resolution_time_minutes) FILTER (WHERE resolution_time_minutes IS NOT NULL) as avg_resolution
                    FROM sop_effectiveness_tracking
                    WHERE kb_id = $1
                ''', kb_id)

                if stats and stats['total'] > 0:
                    effectiveness = stats['helpful_count'] / stats['total']
                    self._effectiveness_cache[kb_id] = effectiveness

                    # Could update KB entry metadata here if needed
                    logger.info(f"SOP {kb_id} effectiveness: {effectiveness:.2%} ({stats['total']} samples)")

        except Exception as e:
            logger.error(f"Failed to track SOP effectiveness: {e}")


# Singleton instance
sop_recommendation_service = SOPRecommendationService()


def get_sop_recommendation_service() -> SOPRecommendationService:
    """Get the singleton SOP recommendation service instance."""
    return sop_recommendation_service
