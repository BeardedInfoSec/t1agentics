# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agentic Planner - Core reasoning engine for autonomous investigation.
Determines investigation steps, orchestrates tool calls, and makes decisions.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from models import (
    Alert, Indicator, InvestigationPlan, InvestigationResult,
    EnrichmentResult, TimelineEvent, TechnicalFinding, 
    RecommendedAction, IOCSummary, SeverityLevel, 
    ConfidenceLevel, DispositionType, AgentState, IndicatorType
)
from tools import get_tool
import asyncio


class AgentPlanner:
    """
    Autonomous planner that orchestrates investigation workflow.
    Implements the core reasoning loop for cybersecurity analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.state: Optional[AgentState] = None
        self.enrichment_results: List[EnrichmentResult] = []
        self.reasoning_trace: List[str] = []
        self.indicators: List[Indicator] = []
    
    async def investigate(self, alert: Alert, indicators: List[Indicator]) -> InvestigationResult:
        """
        Main investigation entry point.
        Orchestrates the complete investigation workflow.
        """
        investigation_id = f"inv-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        self.indicators = indicators
        self.reasoning_trace.append(f"Starting investigation {investigation_id} for alert: {alert.title}")
        
        # Phase 1: Planning
        self.state = AgentState(
            phase="planning",
            current_step="Creating investigation plan",
            completed_steps=[],
            pending_steps=[],
            findings={}
        )
        
        plan = await self._create_investigation_plan(alert, indicators)
        self.reasoning_trace.append(f"Investigation plan created: {plan.reasoning}")
        
        # Phase 2: Enrichment
        self.state.phase = "enrichment"
        await self._execute_enrichment(indicators, plan)
        
        # Phase 3: Analysis
        self.state.phase = "analysis"
        analysis_results = await self._analyze_findings(alert, indicators)
        
        # Phase 4: Reporting
        self.state.phase = "reporting"
        result = await self._generate_report(
            investigation_id=investigation_id,
            alert=alert,
            indicators=indicators,
            analysis=analysis_results
        )
        
        self.reasoning_trace.append(f"Investigation complete. Verdict: {result.verdict}")
        
        return result
    
    async def _create_investigation_plan(
        self, 
        alert: Alert, 
        indicators: List[Indicator]
    ) -> InvestigationPlan:
        """
        Create investigation plan based on alert and indicators.
        Determines which enrichment tools to use and in what order.
        """
        steps = []
        reasoning_parts = []
        
        # Group indicators by type
        indicator_types = set(ind.type for ind in indicators)
        
        reasoning_parts.append(f"Alert involves {len(indicators)} indicators of types: {indicator_types}")
        
        # Plan enrichment based on indicator types
        if IndicatorType.IP in indicator_types:
            steps.extend([
                "Check IP reputation",
                "Perform GeoIP lookup",
                "Analyze IP for VPN/Tor/Proxy"
            ])
            reasoning_parts.append("IP indicators require reputation and geolocation analysis")
        
        if IndicatorType.DOMAIN in indicator_types:
            steps.extend([
                "Check domain reputation",
                "Perform WHOIS lookup",
                "Analyze domain age and registration"
            ])
            reasoning_parts.append("Domain indicators require reputation and WHOIS analysis")
        
        if IndicatorType.URL in indicator_types:
            steps.extend([
                "Analyze URL for malicious patterns",
                "Check URL reputation"
            ])
            reasoning_parts.append("URL indicators require content and reputation analysis")
        
        if IndicatorType.HASH in indicator_types:
            steps.extend([
                "Analyze file hash against malware databases",
                "Check hash reputation"
            ])
            reasoning_parts.append("Hash indicators require malware database lookup")
        
        if IndicatorType.EMAIL in indicator_types:
            steps.append("Analyze email sender reputation")
            reasoning_parts.append("Email indicators require sender reputation check")
        
        # Add correlation and timeline steps
        steps.extend([
            "Correlate findings across indicators",
            "Build attack timeline",
            "Assess threat severity",
            "Determine verdict and confidence"
        ])
        
        reasoning = " | ".join(reasoning_parts)
        
        return InvestigationPlan(
            steps=steps,
            reasoning=reasoning,
            estimated_duration=len(steps) * 2  # 2 seconds per step estimate
        )
    
    async def _execute_enrichment(
        self, 
        indicators: List[Indicator], 
        plan: InvestigationPlan
    ) -> None:
        """Execute enrichment tools for all indicators"""
        
        enrichment_tasks = []
        
        for indicator in indicators:
            # Determine which tools to use for this indicator type
            tools_to_use = self._get_tools_for_indicator(indicator.type)
            
            for tool_name in tools_to_use:
                enrichment_tasks.append(
                    self._enrich_indicator(indicator, tool_name)
                )
        
        # Execute all enrichment tasks concurrently
        results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, EnrichmentResult):
                self.enrichment_results.append(result)
                self.reasoning_trace.append(
                    f"Enrichment completed: {result.tool_name} - Success: {result.success}"
                )
    
    def _get_tools_for_indicator(self, indicator_type: IndicatorType) -> List[str]:
        """Determine which tools to use for a given indicator type"""
        tool_mapping = {
            IndicatorType.IP: ['ip_reputation', 'geoip_lookup'],
            IndicatorType.DOMAIN: ['domain_reputation', 'whois_lookup'],
            IndicatorType.URL: ['url_analysis'],
            IndicatorType.HASH: ['hash_analysis'],
            IndicatorType.EMAIL: ['domain_reputation'],  # Check email domain
            IndicatorType.USERNAME: [],
            IndicatorType.HOSTNAME: []
        }
        return tool_mapping.get(indicator_type, [])
    
    async def _enrich_indicator(
        self, 
        indicator: Indicator, 
        tool_name: str
    ) -> EnrichmentResult:
        """Execute a single enrichment tool for an indicator"""
        try:
            tool = get_tool(tool_name)
            
            # Prepare input
            input_data = {
                'value': indicator.value,
                'type': indicator.type,
                'context': indicator.context
            }
            
            # Execute tool
            result = await tool.execute(input_data)
            
            return EnrichmentResult(
                tool_name=tool_name,
                success=result.success,
                result=result.result,
                raw=result.raw,
                error=None
            )
        
        except Exception as e:
            return EnrichmentResult(
                tool_name=tool_name,
                success=False,
                result={},
                raw=None,
                error=str(e)
            )
    
    async def _analyze_findings(
        self, 
        alert: Alert, 
        indicators: List[Indicator]
    ) -> Dict[str, Any]:
        """
        Analyze enrichment results to determine severity, confidence, and verdict.
        This is the core analytical reasoning step.
        """
        analysis = {
            'malicious_count': 0,
            'suspicious_count': 0,
            'benign_count': 0,
            'high_risk_indicators': [],
            'technical_findings': [],
            'timeline_events': [],
            'threat_score': 0
        }
        
        # Analyze each enrichment result
        for enrichment in self.enrichment_results:
            if not enrichment.success:
                continue
            
            result = enrichment.result
            
            # IP reputation analysis
            if enrichment.tool_name == 'ip_reputation':
                if result.get('is_malicious'):
                    analysis['malicious_count'] += 1
                    analysis['high_risk_indicators'].append(result.get('ip'))
                    analysis['threat_score'] += 30
                    
                    analysis['technical_findings'].append({
                        'title': 'Malicious IP Detected',
                        'description': f"IP {result.get('ip')} flagged as malicious with reputation score {result.get('reputation_score')}",
                        'severity': 'High',
                        'indicators': [result.get('ip')],
                        'categories': result.get('threat_categories', [])
                    })
                elif result.get('reputation_score', 100) < 50:
                    analysis['suspicious_count'] += 1
                    analysis['threat_score'] += 15
            
            # Domain reputation analysis
            elif enrichment.tool_name == 'domain_reputation':
                if result.get('is_malicious'):
                    analysis['malicious_count'] += 1
                    analysis['high_risk_indicators'].append(result.get('domain'))
                    analysis['threat_score'] += 30
                    
                    analysis['technical_findings'].append({
                        'title': 'Malicious Domain Detected',
                        'description': f"Domain {result.get('domain')} associated with {', '.join(result.get('threat_categories', []))}",
                        'severity': 'High',
                        'indicators': [result.get('domain')],
                        'categories': result.get('threat_categories', [])
                    })
            
            # Hash analysis
            elif enrichment.tool_name == 'hash_analysis':
                if result.get('is_malicious'):
                    analysis['malicious_count'] += 1
                    analysis['high_risk_indicators'].append(result.get('hash'))
                    analysis['threat_score'] += 40
                    
                    analysis['technical_findings'].append({
                        'title': 'Malware Detected',
                        'description': f"File hash {result.get('hash')} identified as {result.get('malware_family')}",
                        'severity': 'Critical',
                        'indicators': [result.get('hash')],
                        'categories': ['malware']
                    })
        
        # Build timeline
        analysis['timeline_events'].append({
            'timestamp': alert.timestamp,
            'event_type': 'alert_received',
            'description': alert.title,
            'indicators': [ind.value for ind in indicators[:3]]
        })
        
        self.reasoning_trace.append(
            f"Analysis complete: {analysis['malicious_count']} malicious, "
            f"{analysis['suspicious_count']} suspicious, threat score: {analysis['threat_score']}"
        )
        
        return analysis
    
    async def _generate_report(
        self,
        investigation_id: str,
        alert: Alert,
        indicators: List[Indicator],
        analysis: Dict[str, Any]
    ) -> InvestigationResult:
        """Generate final investigation report with verdict and recommendations"""
        
        # Determine severity based on threat score and findings
        threat_score = analysis['threat_score']
        if threat_score >= 60:
            severity = SeverityLevel.CRITICAL
        elif threat_score >= 40:
            severity = SeverityLevel.HIGH
        elif threat_score >= 20:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW
        
        # Determine verdict
        if analysis['malicious_count'] > 0:
            verdict = DispositionType.MALICIOUS
            confidence = ConfidenceLevel.HIGH
        elif analysis['suspicious_count'] > 0:
            verdict = DispositionType.SUSPICIOUS
            confidence = ConfidenceLevel.MEDIUM
        elif len(self.enrichment_results) < len(indicators):
            verdict = DispositionType.INCONCLUSIVE
            confidence = ConfidenceLevel.LOW
        else:
            verdict = DispositionType.BENIGN
            confidence = ConfidenceLevel.HIGH
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            alert, analysis, verdict, severity
        )
        
        # Convert technical findings
        technical_findings = [
            TechnicalFinding(**finding) for finding in analysis['technical_findings']
        ]
        
        # Build timeline
        timeline = [
            TimelineEvent(**event) for event in analysis['timeline_events']
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(verdict, severity, analysis)
        
        # Build IOC summary
        ioc_summary = IOCSummary(
            ips=[ind.value for ind in indicators if ind.type == IndicatorType.IP],
            domains=[ind.value for ind in indicators if ind.type == IndicatorType.DOMAIN],
            hashes=[ind.value for ind in indicators if ind.type == IndicatorType.HASH],
            urls=[ind.value for ind in indicators if ind.type == IndicatorType.URL],
            emails=[ind.value for ind in indicators if ind.type == IndicatorType.EMAIL],
            users=[ind.value for ind in indicators if ind.type == IndicatorType.USERNAME],
            hosts=[ind.value for ind in indicators if ind.type == IndicatorType.HOSTNAME]
        )
        
        return InvestigationResult(
            investigation_id=investigation_id,
            alert_id=alert.id,
            executive_summary=executive_summary,
            technical_findings=technical_findings,
            timeline=timeline,
            severity=severity,
            confidence=confidence,
            verdict=verdict,
            recommended_actions=recommendations,
            ioc_summary=ioc_summary,
            enrichment_results=self.enrichment_results,
            reasoning_trace=self.reasoning_trace,
            completed_at=datetime.utcnow()
        )
    
    def _generate_executive_summary(
        self,
        alert: Alert,
        analysis: Dict[str, Any],
        verdict: DispositionType,
        severity: SeverityLevel
    ) -> str:
        """Generate executive summary of investigation"""
        
        malicious = analysis['malicious_count']
        suspicious = analysis['suspicious_count']
        
        if verdict == DispositionType.MALICIOUS:
            summary = f"Investigation of '{alert.title}' revealed {malicious} confirmed malicious indicator(s). "
            summary += f"High-risk indicators include: {', '.join(analysis['high_risk_indicators'][:3])}. "
            summary += f"This incident is classified as {severity} severity and requires immediate attention."
        
        elif verdict == DispositionType.SUSPICIOUS:
            summary = f"Investigation of '{alert.title}' identified {suspicious} suspicious indicator(s). "
            summary += f"While not definitively malicious, these indicators warrant further monitoring and investigation. "
            summary += f"Classified as {severity} severity."
        
        elif verdict == DispositionType.INCONCLUSIVE:
            summary = f"Investigation of '{alert.title}' completed with inconclusive results. "
            summary += f"Insufficient data available to make a definitive determination. "
            summary += f"Additional enrichment or manual review recommended."
        
        else:  # BENIGN
            summary = f"Investigation of '{alert.title}' found no indicators of malicious activity. "
            summary += f"All analyzed indicators appear benign. "
            summary += f"This alert can likely be closed as a false positive."
        
        return summary
    
    def _generate_recommendations(
        self,
        verdict: DispositionType,
        severity: SeverityLevel,
        analysis: Dict[str, Any]
    ) -> List[RecommendedAction]:
        """Generate recommended response actions"""
        
        recommendations = []
        
        if verdict == DispositionType.MALICIOUS:
            if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                recommendations.extend([
                    RecommendedAction(
                        action="Isolate affected systems immediately",
                        priority="Critical",
                        rationale="Prevent lateral movement and data exfiltration",
                        automation_possible=True
                    ),
                    RecommendedAction(
                        action="Block identified malicious indicators at network perimeter",
                        priority="Critical",
                        rationale="Prevent further compromise",
                        automation_possible=True
                    ),
                    RecommendedAction(
                        action="Initiate incident response procedure",
                        priority="High",
                        rationale="Coordinate comprehensive response",
                        automation_possible=False
                    )
                ])
            else:
                recommendations.append(
                    RecommendedAction(
                        action="Monitor affected systems for 24-48 hours",
                        priority="Medium",
                        rationale="Ensure no additional malicious activity",
                        automation_possible=True
                    )
                )
        
        elif verdict == DispositionType.SUSPICIOUS:
            recommendations.extend([
                RecommendedAction(
                    action="Enable enhanced logging on affected systems",
                    priority="Medium",
                    rationale="Gather additional forensic data",
                    automation_possible=True
                ),
                RecommendedAction(
                    action="Add indicators to watchlist",
                    priority="Medium",
                    rationale="Monitor for future occurrences",
                    automation_possible=True
                )
            ])
        
        elif verdict == DispositionType.INCONCLUSIVE:
            recommendations.append(
                RecommendedAction(
                    action="Escalate to Tier 2 analyst for manual review",
                    priority="Low",
                    rationale="Human analysis required for conclusive determination",
                    automation_possible=False
                )
            )
        
        else:  # BENIGN
            recommendations.append(
                RecommendedAction(
                    action="Close alert as false positive",
                    priority="Low",
                    rationale="No threat detected",
                    automation_possible=True
                )
            )
        
        # Always add documentation recommendation
        recommendations.append(
            RecommendedAction(
                action="Document findings in case management system",
                priority="Low",
                rationale="Maintain audit trail and knowledge base",
                automation_possible=False
            )
        )
        
        return recommendations
