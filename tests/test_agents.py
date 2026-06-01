"""
Tests for AgentCore agents and investigation workflow.
"""

import pytest
import asyncio
from datetime import datetime
from models import Alert, Indicator, IndicatorType, SeverityLevel, VerdictType
from agents.planner import AgentPlanner
from agents.l1_agent import L1Agent
from agents.l2_agent import L2Agent


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing"""
    return Alert(
        id="test-alert-001",
        title="Suspicious Login Attempt",
        description="Multiple failed login attempts from 192.168.1.100 targeting user admin",
        source="test_logs",
        metadata={
            "user": "admin",
            "ip": "192.168.1.100",
            "attempts": 15
        }
    )


@pytest.fixture
def sample_indicators():
    """Create sample indicators for testing"""
    return [
        Indicator(
            type=IndicatorType.IP,
            value="192.168.1.100",
            context="source_ip"
        ),
        Indicator(
            type=IndicatorType.USERNAME,
            value="admin",
            context="target_user"
        )
    ]


@pytest.fixture
def malicious_alert():
    """Create an alert with known malicious indicators"""
    return Alert(
        id="test-alert-002",
        title="Malware Detected",
        description="File with hash 44d88612fea8a8f36de82e1278abb02f detected on host WORKSTATION-01",
        source="endpoint_protection",
        metadata={
            "host": "WORKSTATION-01",
            "hash": "44d88612fea8a8f36de82e1278abb02f",
            "file_path": "C:\\suspicious.exe"
        }
    )


@pytest.fixture
def malicious_indicators():
    """Create malicious indicators for testing"""
    return [
        Indicator(
            type=IndicatorType.HASH,
            value="44d88612fea8a8f36de82e1278abb02f",
            context="file_hash"
        ),
        Indicator(
            type=IndicatorType.HOSTNAME,
            value="WORKSTATION-01",
            context="affected_host"
        )
    ]


class TestL1Agent:
    """Test Tier 1 agent functionality"""
    
    @pytest.mark.asyncio
    async def test_triage_alert(self, sample_alert):
        """Test alert triage"""
        agent = L1Agent()
        result = await agent.triage_alert(sample_alert)
        
        assert "should_investigate" in result
        assert "priority" in result
        assert "reasoning" in result
        assert isinstance(result["should_investigate"], bool)
    
    @pytest.mark.asyncio
    async def test_extract_indicators(self, sample_alert):
        """Test indicator extraction"""
        agent = L1Agent()
        result = await agent.extract_and_classify_indicators(sample_alert)
        
        assert "total_indicators" in result
        assert "by_type" in result
        assert result["total_indicators"] > 0
    
    @pytest.mark.asyncio
    async def test_generate_hypothesis(self, sample_alert, sample_indicators):
        """Test hypothesis generation"""
        agent = L1Agent()
        triage = await agent.triage_alert(sample_alert)
        hypothesis = await agent.generate_initial_hypothesis(sample_alert, sample_indicators, triage)
        
        assert "likely_attack_types" in hypothesis
        assert "confidence" in hypothesis
        assert "needs_escalation" in hypothesis


class TestL2Agent:
    """Test Tier 2 agent functionality"""
    
    @pytest.mark.asyncio
    async def test_correlate_indicators(self, malicious_indicators):
        """Test indicator correlation"""
        agent = L2Agent()
        enrichment_results = []
        
        correlation = await agent.correlate_indicators(malicious_indicators, enrichment_results)
        
        assert "relationships" in correlation
        assert "clusters" in correlation
        assert "confidence" in correlation
    
    @pytest.mark.asyncio
    async def test_build_timeline(self, malicious_alert, malicious_indicators):
        """Test timeline construction"""
        agent = L2Agent()
        timeline = await agent.build_attack_timeline(malicious_alert, malicious_indicators, [])
        
        assert len(timeline) > 0
        assert all(hasattr(event, 'timestamp') for event in timeline)
    
    @pytest.mark.asyncio
    async def test_identify_attack_path(self, malicious_indicators):
        """Test attack path identification"""
        agent = L2Agent()
        correlation = {"relationships": [], "insights": []}
        attack_path = await agent.identify_attack_path(malicious_indicators, correlation, [])
        
        assert "phases" in attack_path
        assert "techniques" in attack_path
        assert "mitre_tactics" in attack_path


class TestAgentPlanner:
    """Test agent planner and investigation workflow"""
    
    @pytest.mark.asyncio
    async def test_create_investigation_plan(self, sample_alert, sample_indicators):
        """Test investigation plan creation"""
        planner = AgentPlanner()
        plan = await planner._create_investigation_plan(sample_alert, sample_indicators)
        
        assert len(plan.steps) > 0
        assert plan.reasoning is not None
        assert plan.estimated_duration > 0
    
    @pytest.mark.asyncio
    async def test_full_investigation_benign(self, sample_alert, sample_indicators):
        """Test full investigation of benign alert"""
        planner = AgentPlanner()
        result = await planner.investigate(sample_alert, sample_indicators)
        
        assert result.investigation_id is not None
        assert result.verdict in [VerdictType.BENIGN, VerdictType.SUSPICIOUS, VerdictType.MALICIOUS, VerdictType.INCONCLUSIVE]
        assert result.severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert len(result.reasoning_trace) > 0
    
    @pytest.mark.asyncio
    async def test_full_investigation_malicious(self, malicious_alert, malicious_indicators):
        """Test full investigation of malicious alert"""
        planner = AgentPlanner()
        result = await planner.investigate(malicious_alert, malicious_indicators)
        
        assert result.verdict == VerdictType.MALICIOUS
        assert result.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert len(result.recommended_actions) > 0
        assert len(result.technical_findings) > 0
    
    @pytest.mark.asyncio
    async def test_executive_summary_generation(self, malicious_alert, malicious_indicators):
        """Test executive summary generation"""
        planner = AgentPlanner()
        result = await planner.investigate(malicious_alert, malicious_indicators)
        
        assert result.executive_summary is not None
        assert len(result.executive_summary) > 50  # Should be substantial
        assert "malicious" in result.executive_summary.lower()


def test_investigation_result_structure(sample_alert, sample_indicators):
    """Test investigation result structure"""
    # This would normally be async, but we're just testing structure
    from models import InvestigationResult, IOCSummary
    
    result = InvestigationResult(
        investigation_id="test-inv-001",
        alert_id=sample_alert.id,
        executive_summary="Test summary",
        technical_findings=[],
        timeline=[],
        severity=SeverityLevel.MEDIUM,
        confidence="Medium",
        verdict=VerdictType.SUSPICIOUS,
        recommended_actions=[],
        ioc_summary=IOCSummary()
    )
    
    assert result.investigation_id == "test-inv-001"
    assert result.severity == SeverityLevel.MEDIUM


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
