# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation Timeline Generator
Creates chronological timeline of investigation events
"""

from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class TimelineGenerator:
    def __init__(self, db):
        self.db = db
    
    def create_event(
        self,
        event_type: str,
        description: str,
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create a timeline event
        
        Event types:
        - alert_linked
        - ioc_detected
        - enrichment_complete
        - status_change
        - framework_match
        - script_run
        - analyst_action
        - severity_change
        - correlation_found
        """
        return {
            "timestamp": datetime.utcnow(),
            "type": event_type,
            "description": description,
            "metadata": metadata or {},
            "icon": self._get_event_icon(event_type),
            "color": self._get_event_color(event_type)
        }
    
    def _get_event_icon(self, event_type: str) -> str:
        """Get icon for event type"""
        icons = {
            "alert_linked": "[ALERT]",
            "ioc_detected": "[IOC]",
            "enrichment_complete": "[ENRICH]",
            "status_change": "[STATUS]",
            "framework_match": "[FRAMEWORK]",
            "script_run": "[SCRIPT]",
            "analyst_action": "[ANALYST]",
            "severity_change": "[SEVERITY]",
            "correlation_found": "[CORR]",
            "investigation_created": "[NEW]",
            "verdict_assigned": "[VERDICT]"
        }
        return icons.get(event_type, "[EVENT]")
    
    def _get_event_color(self, event_type: str) -> str:
        """Get color for event type"""
        colors = {
            "alert_linked": "#3b82f6",
            "ioc_detected": "#eab308",
            "enrichment_complete": "#22c55e",
            "status_change": "#6366f1",
            "framework_match": "#8b5cf6",
            "script_run": "#06b6d4",
            "analyst_action": "#ec4899",
            "severity_change": "#f59e0b",
            "correlation_found": "#10b981",
            "investigation_created": "#667eea",
            "verdict_assigned": "#dc2626"
        }
        return colors.get(event_type, "#6b7280")
    
    async def generate_timeline(self, investigation_id: str) -> List[Dict[str, Any]]:
        """
        Generate complete timeline for an investigation
        
        Args:
            investigation_id: Investigation ID
            
        Returns:
            List of timeline events in chronological order
        """
        try:
            # Get investigation
            investigation = await self.db.get_investigation(investigation_id)
            if not investigation:
                return []
            
            timeline = []
            
            # Event 1: Investigation created
            timeline.append(self.create_event(
                "investigation_created",
                f"Investigation created: {investigation.get('summary', 'Unknown')[:50]}...",
                {
                    "investigation_id": investigation_id,
                    "severity": investigation.get("severity"),
                    "created_at": investigation.get("created_at")
                }
            ))
            
            # Event 2: Alert linked (if applicable)
            if investigation.get("alert_id"):
                alert = await self._get_alert(investigation["alert_id"])
                if alert:
                    timeline.append(self.create_event(
                        "alert_linked",
                        f"Alert linked: {alert.get('title', 'Unknown')}",
                        {
                            "alert_id": alert.get("alert_id"),
                            "alert_source": alert.get("source"),
                            "alert_severity": alert.get("severity")
                        }
                    ))
            
            # Event 3: IOCs detected
            indicators = investigation.get("indicators", [])
            if indicators:
                for ioc in indicators:
                    timeline.append(self.create_event(
                        "ioc_detected",
                        f"IOC detected: {ioc.get('type', 'unknown')} - {ioc.get('value', 'N/A')[:50]}",
                        {
                            "ioc_type": ioc.get("type"),
                            "ioc_value": ioc.get("value"),
                            "confidence": ioc.get("confidence")
                        }
                    ))
            
            # Event 4: Enrichment complete
            enrichment_data = investigation.get("enrichment_data", {})
            if enrichment_data:
                timeline.append(self.create_event(
                    "enrichment_complete",
                    f"Enrichment completed with {len(enrichment_data)} data points",
                    {"enrichment_sources": list(enrichment_data.keys())}
                ))
            
            # Event 5: Framework mappings
            framework_matches = investigation.get("framework_matches", {})
            if framework_matches:
                for framework, controls in framework_matches.items():
                    if controls:
                        timeline.append(self.create_event(
                            "framework_match",
                            f"{framework.replace('_', ' ').title()}: {len(controls)} controls matched",
                            {
                                "framework": framework,
                                "controls": controls[:5]  # First 5
                            }
                        ))
            
            # Event 6: Correlation found
            correlations = investigation.get("correlations", {})
            if correlations:
                related_count = (
                    len(correlations.get("related_alerts", [])) +
                    len(correlations.get("related_investigations", []))
                )
                if related_count > 0:
                    timeline.append(self.create_event(
                        "correlation_found",
                        f"Found {related_count} related items",
                        {
                            "related_alerts": len(correlations.get("related_alerts", [])),
                            "related_investigations": len(correlations.get("related_investigations", [])),
                            "correlation_score": correlations.get("correlation_score", 0)
                        }
                    ))
            
            # Event 7: Verdict assigned
            if investigation.get("verdict"):
                timeline.append(self.create_event(
                    "verdict_assigned",
                    f"Verdict: {investigation.get('verdict')} (Confidence: {investigation.get('confidence', 'Unknown')})",
                    {
                        "verdict": investigation.get("verdict"),
                        "confidence": investigation.get("confidence"),
                        "severity": investigation.get("severity")
                    }
                ))
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x["timestamp"])
            
            # Add sequential order
            for i, event in enumerate(timeline):
                event["order"] = i + 1
            
            return timeline
            
        except Exception as e:
            logger.error(f"Timeline generation failed for {investigation_id}: {e}")
            return []
    
    async def _get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Get alert by ID"""
        if not self.db.connected:
            return {}

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM alerts WHERE alert_id = $1", alert_id
                )
                if row:
                    result = dict(row)
                    for k, v in result.items():
                        if hasattr(v, 'isoformat'):
                            result[k] = v.isoformat()
                        elif hasattr(v, 'hex'):
                            result[k] = str(v)
                    return result
            return {}
        except Exception as e:
            logger.error(f"Error fetching alert {alert_id}: {e}")
            return {}
    
    async def add_timeline_event(
        self,
        investigation_id: str,
        event_type: str,
        description: str,
        metadata: Dict[str, Any] = None
    ) -> bool:
        """
        Add a new event to investigation timeline
        
        Args:
            investigation_id: Investigation ID
            event_type: Type of event
            description: Event description
            metadata: Additional event data
            
        Returns:
            True if successful
        """
        if not self.db.connected:
            return False

        try:
            import json
            event = self.create_event(event_type, description, metadata)
            # Serialize datetime for JSONB storage
            event_json = json.loads(json.dumps(event, default=str))

            async with self.db.tenant_acquire() as conn:
                result = await conn.execute(
                    """UPDATE investigations
                       SET timeline = COALESCE(timeline, '[]'::jsonb) || $1::jsonb
                       WHERE investigation_id = $2""",
                    json.dumps([event_json]), investigation_id
                )
                return 'UPDATE 1' in result

        except Exception as e:
            logger.error(f"Failed to add timeline event: {e}")
            return False
