# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Fast Alert Triage Service

Lightweight LLM-based triage for immediate alert classification.
Extracts IOCs, assigns severity, decides if Riggs escalation needed.

Flow: Alert -> IOC Extraction -> Fast LLM Review -> [Escalate to Riggs?]
Target: <5 seconds total
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)


# Map extractor IOC types to DB CHECK constraint values
_IOC_TYPE_MAP = {
    "md5": "hash_md5",
    "sha1": "hash_sha1",
    "sha256": "hash_sha256",
    "filename": "file_path",
}


def _normalize_ioc_type(raw_type: str) -> str:
    """Normalize IOC type from extractor format to DB schema format."""
    return _IOC_TYPE_MAP.get(raw_type, raw_type)


class FastTriageService:
    """
    Fast triage using lightweight LLM review

    Responsibilities:
    1. Extract IOCs from alert (IPs, domains, hashes, emails)
    2. Quick severity classification
    3. Decide if deep Riggs investigation needed
    4. Update alert with triage results

    NOT responsible for:
    - Deep investigation (that's Riggs)
    - Response actions (that's Tier-3)
    - Enrichment (separate service)
    """

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    async def triage_alert(self, alert_id: int) -> Dict[str, Any]:
        """
        Fast triage of alert

        Args:
            alert_id: Alert database ID

        Returns:
            {
                "alert_id": int,
                "severity": str,  # low, medium, high, critical
                "iocs_extracted": List[Dict],
                "needs_riggs": bool,
                "confidence": float,
                "reasoning": str,
                "triage_time_ms": int
            }
        """
        start_time = datetime.utcnow()

        # 1. Fetch alert from database
        alert = await self._fetch_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        # 2. Extract IOCs (fast regex, no external calls)
        iocs = self._extract_iocs(alert)

        # 3. Fast LLM classification (3-5 seconds)
        llm_result = await self._llm_quick_classify(alert, iocs)

        # 4. Update alert in database
        await self._update_alert_triage(alert_id, llm_result, iocs)

        # 5. Create investigation if Riggs escalation needed
        investigation_id = None
        if llm_result["needs_riggs"]:
            investigation_id = await self._create_investigation(alert_id, llm_result)

        triage_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return {
            "alert_id": alert_id,
            "severity": llm_result["severity"],
            "iocs_extracted": iocs,
            "needs_riggs": llm_result["needs_riggs"],
            "confidence": llm_result["confidence"],
            "reasoning": llm_result["reasoning"],
            "investigation_id": investigation_id,
            "triage_time_ms": triage_time
        }

    def _extract_iocs(self, alert: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Fast IOC extraction using regex patterns

        Returns: [{"type": "ip", "value": "1.2.3.4"}, ...]
        """
        iocs = []

        # Combine all text fields
        text = ""
        if alert.get("title"):
            text += alert["title"] + " "
        if alert.get("description"):
            text += alert["description"] + " "
        if alert.get("raw_event"):
            # JSONB to string
            text += json.dumps(alert["raw_event"])

        # IP addresses (IPv4)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for ip in re.findall(ip_pattern, text):
            # Skip IPs with leading zeros (e.g., 01.24.04.57)
            parts = ip.split('.')
            if any(len(p) > 1 and p.startswith('0') for p in parts):
                continue
            # Filter private IPs
            if not self._is_private_ip(ip):
                iocs.append({"type": "ip", "value": ip})

        # Domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        for domain in re.findall(domain_pattern, text.lower()):
            if not domain.endswith(('.local', '.localdomain', '.internal')):
                iocs.append({"type": "domain", "value": domain})

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for email in re.findall(email_pattern, text):
            iocs.append({"type": "email", "value": email.lower()})

        # SHA256 hashes
        sha256_pattern = r'\b[a-f0-9]{64}\b'
        for hash_val in re.findall(sha256_pattern, text.lower()):
            iocs.append({"type": "sha256", "value": hash_val})

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for url in re.findall(url_pattern, text):
            iocs.append({"type": "url", "value": url})

        # Deduplicate
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        octets = ip.split('.')
        if len(octets) != 4:
            return True

        try:
            first = int(octets[0])
            second = int(octets[1])

            # RFC 1918 private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Loopback
                return True
            if first == 169 and second == 254:  # Link-local
                return True

            return False
        except (ValueError, IndexError):
            return True

    async def _llm_quick_classify(
        self, alert: Dict[str, Any], iocs: List[Dict], tenant_id=None
    ) -> Dict[str, Any]:
        """
        Fast LLM classification (3-5 seconds max)

        Prompt optimized for speed:
        - No enrichment data (that's for Riggs)
        - No investigation (that's for Riggs)
        - Just: severity + escalation decision

        Uses Claude when AI_PROVIDER=claude, otherwise legacy llm_client.
        """
        import os

        prompt = f"""You are a SOC analyst doing FAST TRIAGE. Provide immediate classification only.

ALERT:
Title: {alert.get('title', 'N/A')}
Source: {alert.get('source', 'N/A')}
Description: {alert.get('description', 'N/A')}

IOCs FOUND: {len(iocs)}
{json.dumps(iocs[:10], indent=2) if iocs else 'None'}

TASK: Provide JSON response with:
1. severity: low/medium/high/critical
2. needs_riggs: true if needs deep investigation, false if can auto-close
3. confidence: 0.0-1.0
4. reasoning: 1-2 sentence explanation

ESCALATE TO RIGGS IF:
- Critical severity
- Complex attack pattern
- Multiple IOCs
- Unclear threat actor
- Potential data breach

AUTO-CLOSE IF:
- Known false positive
- Low severity + no IOCs
- Informational only

OUTPUT JSON ONLY:"""

        response_text = None
        ai_provider = os.getenv('AI_PROVIDER', '').lower()

        # Try Claude first when configured
        if ai_provider in ('claude', 'anthropic'):
            try:
                from services.claude_service import get_claude_service
                import uuid as _uuid

                service = await get_claude_service()
                if service.is_configured:
                    resolved_tid = tenant_id
                    if not resolved_tid:
                        from config.constants import PLATFORM_OWNER_TENANT_ID
                        resolved_tid = PLATFORM_OWNER_TENANT_ID
                    if isinstance(resolved_tid, str):
                        resolved_tid = _uuid.UUID(resolved_tid)

                    result = await service.complete(
                        tenant_id=resolved_tid,
                        prompt=prompt,
                        max_tokens=200,
                        temperature=0.3,
                        request_type="fast_triage",
                    )
                    response_text = result.text
            except Exception:
                pass  # Fall through to legacy client or heuristics

        # Legacy LLM client fallback
        if response_text is None and self.llm_client:
            response_text = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=200,
                temperature=0.3,
                timeout=5
            )

        # Parse JSON response
        if response_text:
            try:
                result = json.loads(response_text)
                return {
                    "severity": result.get("severity", "medium"),
                    "needs_riggs": result.get("needs_riggs", True),
                    "confidence": result.get("confidence", 0.7),
                    "reasoning": result.get("reasoning", "Fast triage classification")
                }
            except json.JSONDecodeError:
                pass

        # Fallback: heuristic-based classification
        return self._heuristic_classify(alert, iocs)

    def _heuristic_classify(self, alert: Dict[str, Any], iocs: List[Dict]) -> Dict[str, Any]:
        """
        Fallback heuristic classification if LLM fails
        """
        severity = "medium"
        needs_riggs = False
        confidence = 0.6
        reasoning = "Heuristic classification (LLM unavailable)"

        # Keyword-based severity
        text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()

        critical_keywords = ['ransomware', 'data breach', 'exfiltration', 'privilege escalation', 'backdoor']
        high_keywords = ['malware', 'exploit', 'command and control', 'c2', 'suspicious process']

        if any(kw in text for kw in critical_keywords):
            severity = "critical"
            needs_riggs = True
            confidence = 0.8
        elif any(kw in text for kw in high_keywords):
            severity = "high"
            needs_riggs = True
            confidence = 0.7
        elif len(iocs) >= 3:
            severity = "medium"
            needs_riggs = True
            confidence = 0.6
        else:
            severity = "low"
            needs_riggs = False
            confidence = 0.5

        return {
            "severity": severity,
            "needs_riggs": needs_riggs,
            "confidence": confidence,
            "reasoning": reasoning
        }

    async def _fetch_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Fetch alert from database"""
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1",
                alert_id
            )
            if row:
                return dict(row)
        return None

    async def _update_alert_triage(self, alert_id: int, llm_result: Dict, iocs: List[Dict]):
        """Update alert with triage results"""
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                UPDATE alerts
                SET
                    severity = $1,
                    status = CASE
                        WHEN $2 = true THEN 'investigating'
                        ELSE 'closed'
                    END,
                    updated_at = NOW()
                WHERE id = $3
            """, llm_result["severity"], llm_result["needs_riggs"], alert_id)

            # Store IOCs in database
            from config.constants import PLATFORM_OWNER_TENANT_ID
            import uuid as uuid_mod
            try:
                from middleware.tenant_middleware import get_current_tenant_id
                tid = uuid_mod.UUID(get_current_tenant_id())
            except Exception:
                tid = uuid_mod.UUID(PLATFORM_OWNER_TENANT_ID)

            for ioc in iocs:
                # Normalize IOC type to match DB CHECK constraint
                ioc_type = _normalize_ioc_type(ioc["type"])
                await conn.execute("""
                    INSERT INTO iocs (ioc_type, ioc_value, source, source_type, source_id,
                                      first_seen, last_seen, severity, tenant_id)
                    VALUES ($1, $2, $3, 'event', $4, NOW(), NOW(), 'unknown', $5)
                    ON CONFLICT (ioc_value, ioc_type) DO UPDATE
                    SET last_seen = NOW(), occurrences = iocs.occurrences + 1
                """, ioc_type, ioc["value"], f"alert:{alert_id}",
                    str(alert_id), tid)

    async def _create_investigation(self, alert_id: int, llm_result: Dict) -> int:
        """Create investigation for Riggs escalation"""
        import uuid as uuid_mod
        from config.constants import PLATFORM_OWNER_TENANT_ID

        # Get tenant_id for auto-trigger
        try:
            from middleware.tenant_middleware import get_current_tenant_id
            tenant_id = get_current_tenant_id()
        except Exception:
            tenant_id = PLATFORM_OWNER_TENANT_ID

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO investigations (
                    title, description, severity, priority, status,
                    assigned_to, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
                RETURNING id
            """,
                f"Escalated: Alert requiring Riggs investigation",
                llm_result["reasoning"],
                llm_result["severity"],
                "P2" if llm_result["severity"] == "critical" else "P3",
                "NEW",
                "riggs"  # Assigned to Riggs reasoning engine
            )

            investigation_id = row["id"]

            # Link alert to investigation
            await conn.execute("""
                UPDATE alerts
                SET investigation_id = $1
                WHERE id = $2
            """, investigation_id, alert_id)

        # Auto-trigger Riggs analysis for all premium customers
        try:
            from services.auto_analysis_trigger import auto_trigger_analysis_for_investigation
            await auto_trigger_analysis_for_investigation(
                investigation_id=str(investigation_id),
                tenant_id=str(tenant_id),
                priority=2  # High priority for new escalations
            )
        except Exception as e:
            logger.error(f"Failed to auto-trigger Riggs analysis for investigation {investigation_id}: {e}")
            # Don't fail investigation creation if auto-trigger fails

        # Auto-trigger Deep Dive for premium customers
        try:
            import asyncio
            from dependencies.license_checks import _get_tenant_tier
            from services.licensing.default_plans import get_default_entitlements

            tier = await _get_tenant_tier(str(tenant_id))
            entitlements = get_default_entitlements(tier)
            features = entitlements.features or {}

            if features.get('deep_dive'):
                monthly_limit = features.get('deep_dive_monthly_limit', 0)
                # 0 means unlimited; positive number means capped
                if monthly_limit == 0:
                    # Unlimited deep dives - trigger deep dive analysis in background
                    logger.info(f"Auto-triggering Deep Dive for investigation {investigation_id} (tier={tier.value}, unlimited)")

                    # Import the ai_triage_service to access deep_dive_investigation method
                    from services.ai_triage_service import get_ai_triage_service
                    ai_triage = get_ai_triage_service()

                    # Run deep dive asynchronously in background (don't await)
                    asyncio.create_task(
                        ai_triage.deep_dive_investigation(str(investigation_id), str(tenant_id))
                    )
        except Exception as e:
            logger.warning(f"Failed to auto-trigger Deep Dive for investigation {investigation_id}: {e}")
            # Don't fail investigation creation if deep dive trigger fails

        return investigation_id


# Global instance
_triage_service = None

def get_triage_service() -> FastTriageService:
    """Get or create triage service singleton"""
    global _triage_service
    if _triage_service is None:
        # TODO: Initialize with actual LLM client
        _triage_service = FastTriageService()
    return _triage_service
