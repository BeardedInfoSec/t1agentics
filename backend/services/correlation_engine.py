# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Correlation Engine
Links alerts, investigations, and IOCs based on common indicators
"""

from typing import List, Dict, Any, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self, db):
        self.db = db
    
    async def correlate_investigation(self, investigation_id: str) -> Dict[str, Any]:
        """
        Find all related alerts, investigations, and IOCs for an investigation
        
        Args:
            investigation_id: Investigation ID
            
        Returns:
            Dict with related_alerts, related_investigations, shared_iocs
        """
        try:
            # Get investigation
            investigation = await self.db.get_investigation(investigation_id)
            if not investigation:
                return self._empty_correlation()
            
            # Extract IOCs from investigation
            iocs = investigation.get("indicators", [])
            ioc_values = {ioc.get("value") for ioc in iocs if ioc.get("value")}
            
            # Get alert_id if linked
            alert_id = investigation.get("alert_id")
            
            # Find related alerts (share IOCs or same investigation)
            related_alerts = await self._find_related_alerts(ioc_values, alert_id)
            
            # Find related investigations (share IOCs)
            related_investigations = await self._find_related_investigations(
                ioc_values,
                investigation_id
            )
            
            # Get shared IOC details
            shared_iocs = await self._get_shared_ioc_details(ioc_values)
            
            return {
                "related_alerts": related_alerts,
                "related_investigations": related_investigations,
                "shared_iocs": shared_iocs,
                "correlation_score": self._calculate_correlation_score(
                    len(related_alerts),
                    len(related_investigations),
                    len(shared_iocs)
                )
            }
            
        except Exception as e:
            logger.error(f"Correlation failed for {investigation_id}: {e}")
            return self._empty_correlation()
    
    async def _find_related_alerts(
        self,
        ioc_values: Set[str],
        current_alert_id: str = None
    ) -> List[Dict[str, Any]]:
        """Find alerts that share IOCs or have common characteristics"""
        if not self.db.connected or not ioc_values:
            return []
        
        try:
            related = []
            
            # Search in alert descriptions and raw_data for IOC matches
            alerts = []
            cursor = self.db.db.alerts.find().limit(1000)
            async for alert in cursor:
                alert["_id"] = str(alert["_id"])
                
                # Skip current alert
                if alert.get("alert_id") == current_alert_id:
                    continue
                
                # Check if any IOCs appear in alert
                alert_text = f"{alert.get('title', '')} {alert.get('description', '')}"
                alert_text_lower = alert_text.lower()
                
                matching_iocs = []
                for ioc_value in ioc_values:
                    if ioc_value.lower() in alert_text_lower:
                        matching_iocs.append(ioc_value)
                
                if matching_iocs:
                    related.append({
                        "alert_id": alert.get("alert_id"),
                        "title": alert.get("title"),
                        "severity": alert.get("severity"),
                        "source": alert.get("source"),
                        "created_at": alert.get("created_at"),
                        "matching_iocs": matching_iocs,
                        "match_count": len(matching_iocs)
                    })
            
            # Sort by match count
            related.sort(key=lambda x: x["match_count"], reverse=True)
            
            return related[:10]  # Top 10
            
        except Exception as e:
            logger.error(f"Error finding related alerts: {e}")
            return []
    
    async def _find_related_investigations(
        self,
        ioc_values: Set[str],
        current_investigation_id: str
    ) -> List[Dict[str, Any]]:
        """Find investigations that share IOCs"""
        if not self.db.connected or not ioc_values:
            return []
        
        try:
            related = []
            
            # Get all investigations
            investigations = await self.db.get_all_investigations()
            
            for inv in investigations:
                # Skip current investigation
                if inv.get("investigation_id") == current_investigation_id:
                    continue
                
                # Get IOCs from investigation
                inv_iocs = inv.get("indicators", [])
                inv_ioc_values = {ioc.get("value") for ioc in inv_iocs if ioc.get("value")}
                
                # Find shared IOCs
                shared = ioc_values.intersection(inv_ioc_values)
                
                if shared:
                    related.append({
                        "investigation_id": inv.get("investigation_id"),
                        "summary": inv.get("summary", "")[:100],
                        "verdict": inv.get("verdict"),
                        "severity": inv.get("severity"),
                        "created_at": inv.get("created_at"),
                        "shared_iocs": list(shared),
                        "match_count": len(shared)
                    })
            
            # Sort by match count
            related.sort(key=lambda x: x["match_count"], reverse=True)
            
            return related[:10]  # Top 10
            
        except Exception as e:
            logger.error(f"Error finding related investigations: {e}")
            return []
    
    async def _get_shared_ioc_details(self, ioc_values: Set[str]) -> List[Dict[str, Any]]:
        """Get details about IOCs that appear in multiple places"""
        if not ioc_values:
            return []
        
        shared = []
        
        for ioc_value in ioc_values:
            # Count occurrences in alerts
            alert_count = 0
            if self.db.connected:
                try:
                    alert_count = await self.db.db.alerts.count_documents({
                        "$or": [
                            {"title": {"$regex": ioc_value, "$options": "i"}},
                            {"description": {"$regex": ioc_value, "$options": "i"}}
                        ]
                    })
                except:
                    pass
            
            # Count occurrences in investigations (via IOC tracking)
            investigation_count = 0
            if self.db.connected:
                try:
                    investigation_count = await self.db.db.ioc_tracking.count_documents({
                        "value": ioc_value
                    })
                except:
                    pass
            
            total = alert_count + investigation_count
            
            if total > 1:  # Appears in multiple places
                shared.append({
                    "value": ioc_value,
                    "alert_count": alert_count,
                    "investigation_count": investigation_count,
                    "total_occurrences": total,
                    "risk_score": min(total * 10, 100)  # Simple scoring
                })
        
        # Sort by total occurrences
        shared.sort(key=lambda x: x["total_occurrences"], reverse=True)
        
        return shared
    
    def _calculate_correlation_score(
        self,
        alert_count: int,
        investigation_count: int,
        ioc_count: int
    ) -> int:
        """Calculate overall correlation score (0-100)"""
        score = 0
        
        # Alerts contribute 30 points max
        score += min(alert_count * 10, 30)
        
        # Investigations contribute 40 points max
        score += min(investigation_count * 15, 40)
        
        # Shared IOCs contribute 30 points max
        score += min(ioc_count * 5, 30)
        
        return min(score, 100)
    
    def _empty_correlation(self) -> Dict[str, Any]:
        """Return empty correlation result"""
        return {
            "related_alerts": [],
            "related_investigations": [],
            "shared_iocs": [],
            "correlation_score": 0
        }
    
    async def create_correlation_on_new_alert(self, alert_id: str):
        """
        Check for correlations when a new alert is created
        and create timeline events
        """
        try:
            if not self.db.connected:
                return
            
            # Get alert
            alert = await self.db.db.alerts.find_one({"alert_id": alert_id})
            if not alert:
                return
            
            # Extract potential IOCs from alert
            alert_text = f"{alert.get('title', '')} {alert.get('description', '')}"
            
            # Simple IOC extraction (IPs, domains, hashes)
            import re
            
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert_text)
            domains = re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', alert_text.lower())
            hashes = re.findall(r'\b[a-f0-9]{32,64}\b', alert_text.lower())
            
            potential_iocs = set(ips + domains + hashes)
            
            if potential_iocs:
                # Check if these IOCs exist in other alerts/investigations
                correlation = await self.correlate_investigation(alert_id)
                
                # If correlations found, log them
                if correlation["correlation_score"] > 0:
                    logger.info(
                        f"Alert {alert_id} correlates with "
                        f"{len(correlation['related_alerts'])} alerts, "
                        f"{len(correlation['related_investigations'])} investigations"
                    )
                    
        except Exception as e:
            logger.error(f"Error creating alert correlation: {e}")
