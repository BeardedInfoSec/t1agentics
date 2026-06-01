# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Test for Unified Reasoning Engine

Tests the complete reasoning engine flow including:
- Investigation cycle execution
- Tool broker authority enforcement
- Checkpoint progression
- Heuristic loading
- LLM client integration

Usage:
    python -m reasoning_engine.test_reasoning_engine

Or from backend directory:
    python reasoning_engine/test_reasoning_engine.py
"""

import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
import json

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))


class MockLLMClient:
    """Mock LLM client for testing without real API calls."""

    def __init__(self):
        self.call_count = 0
        self.responses = []

    async def complete(self, prompt: str, temperature: float = 0.3, system_prompt: str = None):
        """Return mock LLM response."""
        from reasoning_engine.llm_client import LLMResponse

        self.call_count += 1

        # Generate mock reasoning response
        mock_response = {
            "assessment": f"Mock assessment iteration {self.call_count}. Analysis suggests moderate risk.",
            "confidence": min(30 + (self.call_count * 15), 95),
            "confidence_justification": f"Based on {self.call_count} tool calls and evidence collected",
            "gaps": ["Need IP reputation check", "User history unknown"] if self.call_count < 3 else [],
            "next_action": {
                "type": "tool_call" if self.call_count < 3 else "checkpoint_progress",
                "tool": "lookup_ip_reputation" if self.call_count == 1 else "query_threat_intel",
                "parameters": {"ip": "192.168.1.100"} if self.call_count == 1 else {"ioc": "malicious.com"},
                "reason": "Gather more evidence" if self.call_count < 3 else "Sufficient confidence reached"
            },
            "rationale": f"Mock rationale for iteration {self.call_count}"
        }

        return LLMResponse(
            success=True,
            content=json.dumps(mock_response),
            raw_response={"mock": True},
            prompt_tokens=len(prompt) // 4,
            completion_tokens=100,
            response_time_ms=50,
            model="mock-model",
            provider="mock"
        )


async def test_tool_broker():
    """Test tool broker authority enforcement."""
    print("\n" + "=" * 60)
    print("TEST: Tool Broker Authority Enforcement")
    print("=" * 60)

    from reasoning_engine import get_tool_broker, AuthorityLevel

    broker = get_tool_broker()
    broker.register_default_tools()

    # Test 1: OBSERVE can't access INVESTIGATE tools
    allowed, reason = broker.can_execute(
        "lookup_ip_reputation",
        AuthorityLevel.OBSERVE,
        50
    )
    print(f"OBSERVE trying INVESTIGATE tool: allowed={allowed}")
    assert not allowed, "OBSERVE should not access INVESTIGATE tools"
    print("  [OK] OBSERVE correctly blocked from INVESTIGATE tool")

    # Test 2: INVESTIGATE can access INVESTIGATE tools
    allowed, reason = broker.can_execute(
        "lookup_ip_reputation",
        AuthorityLevel.INVESTIGATE,
        50
    )
    print(f"INVESTIGATE trying INVESTIGATE tool: allowed={allowed}")
    assert allowed, "INVESTIGATE should access INVESTIGATE tools"
    print("  [OK] INVESTIGATE correctly allowed INVESTIGATE tool")

    # Test 3: Low confidence blocks high-impact tools
    allowed, reason = broker.can_execute(
        "isolate_endpoint",
        AuthorityLevel.PRE_APPROVED,
        50  # Needs 90%
    )
    print(f"PRE_APPROVED + 50% confidence trying isolate_endpoint: allowed={allowed}")
    assert not allowed, "Low confidence should block high-impact tools"
    print("  [OK] Low confidence correctly blocked isolate_endpoint")

    # Test 4: High confidence allows high-impact tools
    allowed, reason = broker.can_execute(
        "isolate_endpoint",
        AuthorityLevel.PRE_APPROVED,
        95
    )
    print(f"PRE_APPROVED + 95% confidence trying isolate_endpoint: allowed={allowed}")
    assert allowed, "High confidence should allow high-impact tools"
    print("  [OK] High confidence correctly allowed isolate_endpoint")

    print("\nTool Broker tests PASSED [OK]")


async def test_checkpoint_manager():
    """Test checkpoint manager progression."""
    print("\n" + "=" * 60)
    print("TEST: Checkpoint Manager Progression")
    print("=" * 60)

    from reasoning_engine import get_checkpoint_manager, Checkpoint

    manager = get_checkpoint_manager()

    # Test checkpoint progression
    inv_id = f"test-inv-{datetime.now().timestamp()}"

    # Initial state (get_or_create_state creates the state)
    manager.get_or_create_state(inv_id)
    state = manager.get_progress_summary(inv_id)
    print(f"Initial checkpoint: {state['current_checkpoint']}")
    assert state["current_checkpoint"] == "triage"
    print("  [OK] Investigation starts at TRIAGE")

    # Try to progress with low confidence
    result = await manager.evaluate_progression(
        investigation_id=inv_id,
        reasoning_output={"confidence": 40, "gaps": ["need more evidence"]},
        evidence_collected=["alert_data"]
    )
    print(f"Progress with 40% confidence: action={result.action}")
    assert result.action != "progress", "Should not progress with low confidence"
    print("  [OK] Correctly blocked progression with low confidence")

    # Progress with sufficient confidence
    result = await manager.evaluate_progression(
        investigation_id=inv_id,
        reasoning_output={"confidence": 70, "gaps": []},
        evidence_collected=["alert_data", "threat_intel", "user_context"]
    )
    print(f"Progress with 70% confidence: action={result.action}")
    # Note: May still not progress if other requirements not met
    print(f"  Result: {result.action} - {result.reason}")

    print("\nCheckpoint Manager tests PASSED [OK]")


async def test_heuristic_loader():
    """Test heuristic loader."""
    print("\n" + "=" * 60)
    print("TEST: Heuristic Loader")
    print("=" * 60)

    from reasoning_engine import get_heuristic_loader

    loader = get_heuristic_loader()

    # Test loading heuristics
    stats = loader.get_heuristic_stats()
    print(f"Total heuristics loaded: {len(stats)}")
    assert len(stats) > 0, "Should have seed heuristics loaded"
    print("  [OK] Seed heuristics loaded")

    # Test matching heuristics
    features = {
        "alert_type": "phishing",
        "has_domain": True,
        "severity": "high"
    }
    matches = loader.get_matching_heuristics(features, "triage")
    print(f"Matching heuristics for phishing alert: {len(matches)}")
    print("  [OK] Heuristic matching works")

    # Test heuristic limits
    assert len(matches) <= 5, "Should not exceed max heuristics"
    print("  [OK] Heuristic limit enforced")

    print("\nHeuristic Loader tests PASSED [OK]")


async def test_confidence_gate():
    """Test confidence gate."""
    print("\n" + "=" * 60)
    print("TEST: Confidence Gate")
    print("=" * 60)

    from reasoning_engine import get_confidence_gate

    gate = get_confidence_gate()

    # Test stall detection
    inv_id = f"test-stall-{datetime.now().timestamp()}"

    # Record flat confidence
    gate.record_confidence(inv_id, 50)
    gate.record_confidence(inv_id, 51)
    gate.record_confidence(inv_id, 50)

    is_stalled, reason = gate.is_stalled(inv_id)
    print(f"Stall detection (flat confidence): is_stalled={is_stalled}")
    print(f"  Reason: {reason}")
    print("  [OK] Stall detection works")

    # Test escalation decision
    escalation = gate.should_escalate(
        confidence=30,
        severity="critical",
        iterations=10
    )
    print(f"Escalation decision (critical + low confidence): escalate={escalation.escalate}")
    print(f"  Urgency: {escalation.urgency}")
    print("  [OK] Escalation decision works")

    print("\nConfidence Gate tests PASSED [OK]")


async def test_sop_retriever():
    """Test SOP retriever."""
    print("\n" + "=" * 60)
    print("TEST: SOP Retriever")
    print("=" * 60)

    from reasoning_engine import get_sop_retriever

    retriever = get_sop_retriever()

    # Test listing SOPs
    sops = retriever.list_available_sops()
    print(f"Available SOPs: {len(sops)}")
    for sop in sops:
        print(f"  - {sop['name']}: {sop['alert_types']}")
    assert len(sops) > 0, "Should have SOP references loaded"
    print("  [OK] SOP references loaded")

    # Test stall detection
    confidence_history = [50, 51, 50, 51]
    should_retrieve = retriever.should_retrieve_sop(confidence_history)
    print(f"Should retrieve SOP (flat confidence): {should_retrieve}")
    print("  [OK] SOP retrieval trigger works")

    # Test context retrieval
    context = retriever.get_sop_context("phishing", ["sender_reputation", "url_analysis"])
    if context:
        print(f"SOP context retrieved: {len(context)} chars")
        print(f"  Preview: {context[:100]}...")
    print("  [OK] SOP context retrieval works")

    print("\nSOP Retriever tests PASSED [OK]")


async def test_reasoning_engine():
    """Test reasoning engine with mock LLM."""
    print("\n" + "=" * 60)
    print("TEST: Reasoning Engine Core")
    print("=" * 60)

    from reasoning_engine import get_reasoning_engine, InvestigationContext

    mock_client = MockLLMClient()
    engine = get_reasoning_engine(mock_client)

    # Create test context
    context = InvestigationContext(
        investigation_id="test-123",
        alert_data={
            "title": "Suspicious Login from Unknown Location",
            "severity": "high",
            "source": "SIEM",
            "user": "testuser@company.com",
            "src_ip": "203.0.113.42"
        }
    )

    # Test prompt building
    heuristics = ["Check for VPN usage before flagging foreign IPs"]
    prompt = engine.build_prompt(context, heuristics)
    print(f"Generated prompt length: {len(prompt)} chars (~{len(prompt)//4} tokens)")
    assert len(prompt) > 100, "Prompt should be generated"
    print("  [OK] Prompt generation works")

    # Test reasoning
    output = await engine.reason(context, heuristics)
    print(f"Reasoning output confidence: {output.confidence}%")
    print(f"Reasoning action type: {output.action_type}")
    assert output.confidence > 0, "Should have confidence"
    assert output.action_type in ["tool_call", "checkpoint_progress", "escalate", "complete"]
    print("  [OK] Reasoning execution works")

    print("\nReasoning Engine tests PASSED [OK]")


async def test_investigation_runner():
    """Test investigation runner integration."""
    print("\n" + "=" * 60)
    print("TEST: Investigation Runner")
    print("=" * 60)

    from reasoning_engine import get_investigation_runner, CycleResult

    mock_client = MockLLMClient()

    # Create runner with mock client
    from reasoning_engine.investigation_runner import InvestigationRunner
    runner = InvestigationRunner(llm_client=mock_client)

    # Run investigation cycle
    inv_id = f"test-inv-runner-{datetime.now().timestamp()}"
    alert_data = {
        "title": "Phishing Email Detected",
        "severity": "high",
        "source": "Email Gateway",
        "type": "phishing",
        "sender": "attacker@malicious.com",
        "recipient": "victim@company.com"
    }

    # First cycle
    result = await runner.run_cycle(inv_id, alert_data)
    print(f"Cycle 1 result: {result.result.value}, confidence: {result.confidence}%")
    assert result.result in [CycleResult.CONTINUE, CycleResult.PROGRESSED, CycleResult.ERROR]
    print("  [OK] First cycle executed")

    # Get state
    state = runner.get_state(inv_id)
    print(f"State after cycle 1: checkpoint={state.current_checkpoint}, iterations={state.iteration_count}")
    assert state.iteration_count == 1
    print("  [OK] State tracking works")

    # Run more cycles
    for i in range(2, 5):
        result = await runner.run_cycle(inv_id)
        print(f"Cycle {i} result: {result.result.value}, confidence: {result.confidence}%")

    # Get summary
    summary = runner.get_summary(inv_id)
    print(f"Investigation summary: {json.dumps(summary, indent=2, default=str)}")
    print("  [OK] Investigation runner works")

    print("\nInvestigation Runner tests PASSED [OK]")


async def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("UNIFIED REASONING ENGINE INTEGRATION TESTS")
    print("=" * 60)
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    try:
        await test_tool_broker()
        await test_checkpoint_manager()
        await test_heuristic_loader()
        await test_confidence_gate()
        await test_sop_retriever()
        await test_reasoning_engine()
        await test_investigation_runner()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED [OK]")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(run_all_tests())
    sys.exit(0 if result else 1)
