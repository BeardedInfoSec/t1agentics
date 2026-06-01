# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tool Broker (PMC-style) - Token Optimization Phase 2

This module implements a tool broker that:
1. Executes tools OUTSIDE the LLM context
2. Compresses results to ≤100 tokens
3. Caches IOC enrichment results across alerts
4. Enforces tool gating based on data availability

TOKEN SAVINGS:
- Tool results: 500+ tokens → ≤100 tokens (80% reduction)
- IOC cache hits: 100% token savings on repeated IOCs
- Gated tools: 0 tokens for unavailable data

CRITICAL INVARIANTS:
- LLM only receives compressed results
- Raw results stored for audit only
- Cache shared across all executions
"""

import json
import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Entry in the IOC enrichment cache."""
    compressed: str
    raw: Dict[str, Any]
    cached_at: datetime
    hit_count: int = 0
    indicator_type: str = ""
    indicator_value: str = ""


@dataclass
class ToolResult:
    """Result from tool broker execution."""
    success: bool
    compressed_result: str  # ≤100 tokens for LLM
    raw_result: Dict[str, Any]  # Full result for audit
    cached: bool = False
    gated: bool = False
    error: Optional[str] = None


class IOCCache:
    """
    Cross-alert IOC enrichment cache.

    Enables reuse when:
    - Same IOC appears in multiple alerts
    - Same IOC enriched multiple times in one investigation
    - Batch processing of similar alerts

    Expected hit rate: 30-40% for typical alert batches
    """

    def __init__(self, ttl_hours: int = 24, max_size: int = 10000):
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0
        }

    def get_cache_key(self, indicator_type: str, indicator_value: str) -> str:
        """Generate cache key for IOC."""
        normalized = indicator_value.lower().strip()
        return f"{indicator_type}:{normalized}"

    def get(self, indicator_type: str, indicator_value: str) -> Optional[CacheEntry]:
        """Get cached enrichment result if valid."""
        key = self.get_cache_key(indicator_type, indicator_value)
        entry = self.cache.get(key)

        if entry and datetime.utcnow() - entry.cached_at < self.ttl:
            entry.hit_count += 1
            self.stats['hits'] += 1
            logger.info(f"[IOC_CACHE] hit=true key={key} hits={entry.hit_count}")
            return entry

        self.stats['misses'] += 1
        if entry:
            # Expired entry
            del self.cache[key]

        return None

    def set(
        self,
        indicator_type: str,
        indicator_value: str,
        compressed: str,
        raw: Dict[str, Any]
    ):
        """Cache enrichment result."""
        # Evict oldest entries if at capacity
        if len(self.cache) >= self.max_size:
            self._evict_oldest(self.max_size // 10)

        key = self.get_cache_key(indicator_type, indicator_value)
        self.cache[key] = CacheEntry(
            compressed=compressed,
            raw=raw,
            cached_at=datetime.utcnow(),
            hit_count=0,
            indicator_type=indicator_type,
            indicator_value=indicator_value
        )
        logger.info(f"[IOC_CACHE] stored key={key} size={len(self.cache)}")

    def _evict_oldest(self, count: int):
        """Evict oldest entries from cache."""
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: x[1].cached_at
        )
        for key, _ in sorted_entries[:count]:
            del self.cache[key]
            self.stats['evictions'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = self.stats['hits'] / total if total > 0 else 0
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'hit_rate': round(hit_rate, 3),
            'evictions': self.stats['evictions']
        }


# Global IOC cache instance (shared across all executions)
_ioc_cache = IOCCache(ttl_hours=24, max_size=10000)


def get_ioc_cache() -> IOCCache:
    """Get the global IOC cache instance."""
    return _ioc_cache


class ToolBroker:
    """
    PMC-style tool broker that handles all tool execution outside the LLM.

    Responsibilities:
    1. Validate tool calls against frozen registry
    2. Execute tools with proper error handling
    3. Compress results to ≤100 tokens
    4. Cache IOC enrichment results
    5. Gate tools based on data availability
    """

    # Maximum tokens for compressed result
    MAX_RESULT_TOKENS = 100
    MAX_RESULT_CHARS = 400  # ~100 tokens at 4 chars/token

    def __init__(self, frozen_registry=None, execution_context=None):
        self.registry = frozen_registry
        self.context = execution_context
        self.ioc_cache = get_ioc_cache()

    async def execute_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_executor  # The actual tool execution function
    ) -> ToolResult:
        """
        Execute a tool and return compressed result.

        Args:
            tool_name: Name of tool to execute
            tool_args: Arguments for the tool
            tool_executor: Async function that actually executes the tool

        Returns:
            ToolResult with compressed result for LLM consumption
        """
        # 1. Validate against frozen registry (if available)
        if self.registry and not self.registry.validate_tool_call(tool_name):
            logger.warning(f"[TOOL_BROKER] blocked tool={tool_name} reason=not_in_registry")
            return ToolResult(
                success=False,
                compressed_result=f"Tool '{tool_name}' not available",
                raw_result={"error": "blocked", "reason": "not_in_registry"},
                gated=True
            )

        # 2. Check cache for IOC enrichment
        if tool_name == "enrich_indicator":
            indicator_type = tool_args.get('indicator_type', '')
            indicator_value = tool_args.get('indicator_value', '')

            cached = self.ioc_cache.get(indicator_type, indicator_value)
            if cached:
                return ToolResult(
                    success=True,
                    compressed_result=cached.compressed,
                    raw_result=cached.raw,
                    cached=True
                )

        # 3. Execute the actual tool
        try:
            raw_result = await tool_executor(tool_name, tool_args)

            if not raw_result.get('success', True):
                error_msg = raw_result.get('error', 'Unknown error')
                compressed = self._compress_error(tool_name, error_msg)
                return ToolResult(
                    success=False,
                    compressed_result=compressed,
                    raw_result=raw_result,
                    error=error_msg
                )

        except Exception as e:
            logger.error(f"[TOOL_BROKER] execution_error tool={tool_name} error={e}")
            return ToolResult(
                success=False,
                compressed_result=f"Tool error: {str(e)[:100]}",
                raw_result={"error": str(e)},
                error=str(e)
            )

        # 4. Compress result
        compressed = self._compress_result(tool_name, raw_result)

        # 5. Cache if applicable
        if tool_name == "enrich_indicator" and raw_result.get('success', True):
            indicator_type = tool_args.get('indicator_type', '')
            indicator_value = tool_args.get('indicator_value', '')
            self.ioc_cache.set(indicator_type, indicator_value, compressed, raw_result)

        # 6. Log token savings
        raw_tokens = len(json.dumps(raw_result)) // 4
        compressed_tokens = len(compressed) // 4
        savings = ((raw_tokens - compressed_tokens) / raw_tokens * 100) if raw_tokens > 0 else 0
        logger.info(
            f"[TOOL_BROKER] tool={tool_name} raw_tokens={raw_tokens} "
            f"compressed_tokens={compressed_tokens} savings={savings:.0f}%"
        )

        return ToolResult(
            success=True,
            compressed_result=compressed,
            raw_result=raw_result,
            cached=False
        )

    def _compress_result(self, tool_name: str, result: Dict[str, Any]) -> str:
        """
        Compress tool result to ≤100 tokens.

        Each tool has a custom compression strategy that extracts
        only the decision-relevant information.
        """
        try:
            if tool_name == "enrich_indicator":
                return self._compress_enrichment(result)
            elif tool_name == "list_alert_attachments":
                return self._compress_attachments(result)
            elif tool_name == "query_knowledge_base":
                return self._compress_kb(result)
            elif tool_name == "extract_indicators":
                return self._compress_indicators(result)
            elif tool_name == "check_sender_trust":
                return self._compress_sender_trust(result)
            elif tool_name == "inspect_raw_event_data":
                return self._compress_raw_event(result)
            elif tool_name == "search_ioc_database":
                return self._compress_ioc_search(result)
            elif tool_name == "complete_analysis":
                # This is the final verdict - pass through
                return json.dumps(result, separators=(',', ':'))[:self.MAX_RESULT_CHARS]
            else:
                # Generic compression
                return self._compress_generic(result)
        except Exception as e:
            logger.error(f"[TOOL_BROKER] compression_error tool={tool_name} error={e}")
            return f"Result: {str(result)[:300]}"

    def _compress_enrichment(self, result: Dict[str, Any]) -> str:
        """
        Compress IOC enrichment to one line.

        Example output:
        "185.220.101.45: malicious (VT 15/90, AbuseIPDB 85%)"
        """
        indicator = result.get('indicator', result.get('indicator_value', 'unknown'))
        verdict = result.get('verdict', result.get('overall_verdict', 'unknown'))

        # Collect source summaries
        sources = []
        source_data = result.get('sources', result.get('enrichment_results', {}))

        if isinstance(source_data, dict):
            for source, data in source_data.items():
                if isinstance(data, dict):
                    if data.get('is_malicious'):
                        detected = data.get('detected', data.get('positives', '?'))
                        total = data.get('total', '?')
                        sources.append(f"{source[:3].upper()}:{detected}/{total}")
                    elif data.get('abuse_confidence_score'):
                        score = data.get('abuse_confidence_score')
                        sources.append(f"Abuse:{score}%")
                    elif data.get('threat_score', 0) > 0:
                        sources.append(f"{source[:3]}:{data['threat_score']}%")
                    elif data.get('pulse_count', 0) > 0:
                        sources.append(f"OTX:{data['pulse_count']}p")

        source_str = ', '.join(sources[:4]) if sources else 'no hits'
        return f"{indicator}: {verdict} ({source_str})"

    def _compress_attachments(self, result: Dict[str, Any]) -> str:
        """
        Compress attachment list.

        Example output:
        "2 files: invoice.pdf (clean), payload.exe (suspicious)"
        """
        attachments = result.get('attachments', [])
        if not attachments:
            return "No attachments"

        count = len(attachments)
        summaries = []

        for att in attachments[:3]:  # Max 3 attachments in summary
            name = att.get('filename', att.get('name', 'unknown'))[:20]
            status = att.get('status', att.get('verdict', 'unknown'))
            summaries.append(f"{name} ({status})")

        more = f", +{count-3} more" if count > 3 else ""
        return f"{count} files: {', '.join(summaries)}{more}"

    def _compress_kb(self, result: Dict[str, Any]) -> str:
        """
        Compress KB/SOP query result.

        Example output:
        "SOP-EMAIL-001: Trusted sender + clean links = benign | SOP-PHISH-002: Check URLs"
        """
        entries = result.get('entries', result.get('results', []))
        if not entries:
            return "No relevant SOPs found"

        summaries = []
        for entry in entries[:2]:  # Max 2 SOPs in summary
            sop_id = entry.get('sop_id', entry.get('kb_id', 'SOP'))
            title = entry.get('title', '')[:30]
            # Get first rule if available
            rules = entry.get('rules', entry.get('ai_extracted_rules', []))
            if isinstance(rules, list) and rules:
                rule = str(rules[0])[:40]
                summaries.append(f"{sop_id}: {rule}")
            else:
                summaries.append(f"{sop_id}: {title}")

        return " | ".join(summaries)

    def _compress_indicators(self, result: Dict[str, Any]) -> str:
        """
        Compress extracted indicators.

        Example output:
        "Found: 2 IPs (1.2.3.4, 5.6.7.8), 1 domain (evil.com), 1 URL"
        """
        indicators = result.get('indicators', result.get('iocs', {}))
        if not indicators:
            return "No indicators found"

        parts = []
        for ioc_type, values in indicators.items():
            if not values:
                continue
            if isinstance(values, list):
                count = len(values)
                sample = ', '.join(str(v)[:30] for v in values[:2])
                if count > 2:
                    sample += f", +{count-2}"
                parts.append(f"{count} {ioc_type}s ({sample})")
            else:
                parts.append(f"1 {ioc_type} ({str(values)[:30]})")

        return "Found: " + ", ".join(parts[:4]) if parts else "No indicators"

    def _compress_sender_trust(self, result: Dict[str, Any]) -> str:
        """
        Compress sender trust check.

        Example output:
        "sender@example.com: TRUSTED (allowlist match)"
        """
        sender = result.get('sender', result.get('email', 'unknown'))
        is_trusted = result.get('is_trusted', False)
        reason = result.get('reason', result.get('match_type', ''))

        status = "TRUSTED" if is_trusted else "NOT TRUSTED"
        return f"{sender}: {status}" + (f" ({reason})" if reason else "")

    def _compress_raw_event(self, result: Dict[str, Any]) -> str:
        """
        Compress raw event inspection.

        Example output:
        "Email from sender@domain.com, subject: 'Urgent...', 2 URLs, 1 attachment"
        """
        raw = result.get('raw_event', result)
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except:
                return f"Raw event: {raw[:200]}"

        parts = []

        # Sender
        sender = raw.get('original_sender', raw.get('sender', ''))
        if sender:
            parts.append(f"from {sender}")

        # Subject
        subject = raw.get('subject', '')
        if subject:
            parts.append(f"subj: '{subject[:30]}...'")

        # IOC counts
        extracted = raw.get('_extracted', {})
        if extracted.get('urls'):
            parts.append(f"{len(extracted['urls'])} URLs")
        if extracted.get('domains'):
            parts.append(f"{len(extracted['domains'])} domains")

        # Attachments
        if raw.get('has_attachments') or raw.get('attachment_count', 0) > 0:
            count = raw.get('attachment_count', 1)
            parts.append(f"{count} attachment(s)")

        return "Email " + ", ".join(parts) if parts else "Event data available"

    def _compress_ioc_search(self, result: Dict[str, Any]) -> str:
        """
        Compress IOC database search result.

        Example output:
        "Found 3 matches: 1.2.3.4 (malicious, seen 5x), evil.com (suspicious)"
        """
        matches = result.get('matches', result.get('results', []))
        if not matches:
            return "No IOC matches in database"

        parts = []
        for m in matches[:3]:
            indicator = m.get('indicator', m.get('value', '?'))[:25]
            verdict = m.get('verdict', m.get('status', '?'))
            sightings = m.get('sighting_count', m.get('seen_count', 0))
            part = f"{indicator} ({verdict}"
            if sightings:
                part += f", seen {sightings}x"
            part += ")"
            parts.append(part)

        count = len(matches)
        more = f" +{count-3} more" if count > 3 else ""
        return f"Found {count} matches: {', '.join(parts)}{more}"

    def _compress_error(self, tool_name: str, error: str) -> str:
        """Compress error message."""
        return f"{tool_name} error: {error[:80]}"

    def _compress_generic(self, result: Dict[str, Any]) -> str:
        """Generic compression for unknown tools."""
        # Extract key fields
        important_keys = ['success', 'result', 'status', 'verdict', 'message', 'data']

        parts = []
        for key in important_keys:
            if key in result:
                value = result[key]
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, separators=(',', ':'))[:50]
                parts.append(f"{key}={value}")

        compressed = ", ".join(parts)
        if len(compressed) > self.MAX_RESULT_CHARS:
            compressed = compressed[:self.MAX_RESULT_CHARS - 3] + "..."

        return compressed or json.dumps(result, separators=(',', ':'))[:self.MAX_RESULT_CHARS]


def create_tool_broker(frozen_registry=None, context=None) -> ToolBroker:
    """Factory function to create a tool broker."""
    return ToolBroker(frozen_registry=frozen_registry, execution_context=context)
