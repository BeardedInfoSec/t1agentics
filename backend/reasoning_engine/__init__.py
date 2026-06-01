# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Unified Reasoning Engine

A judgment-preserving automation system for security investigations.

DOCTRINE: The reasoning engine is never responsible for enforcing policy,
permissions, or safety. It only reasons. The system decides.

LOCKED INVARIANTS:
- ONE reasoning engine, ONE prompt
- "Tiers" = authority boundaries only, not agents
- Reasoning context persists across checkpoints
- SOPs never encoded as steps or rules
- Tool restrictions enforced by system, not prompt

Key Components:
- ReasoningEngine: Single prompt, unified reasoning
- ToolBroker: Authority enforcement at system level
- CheckpointManager: Investigation progression
- ConfidenceGate: Threshold-based decisions
- HeuristicLoader: Dynamic guidance loading
- SOPRetriever: Reference-only supplemental context
- InvestigationRunner: Main orchestrator
"""

from .core import (
    ReasoningEngine,
    ReasoningOutput,
    InvestigationContext,
    get_reasoning_engine,
    UNIFIED_REASONING_PROMPT
)

from .tool_broker import (
    ToolBroker,
    AuthorityLevel,
    ToolDefinition,
    ToolExecutionResult,
    get_tool_broker,
    AUTHORITY_HIERARCHY
)

from .checkpoint_manager import (
    CheckpointManager,
    Checkpoint,
    CheckpointConfig,
    CheckpointState,
    ProgressionResult,
    get_checkpoint_manager,
    CHECKPOINT_TRANSITIONS
)

from .confidence_gate import (
    ConfidenceGate,
    EscalationDecision,
    ToolAccessDecision,
    get_confidence_gate
)

from .heuristic_loader import (
    HeuristicLoader,
    Heuristic,
    HeuristicCategory,
    HeuristicOutcome,
    get_heuristic_loader,
    HEURISTIC_LIFECYCLE,
    SEED_HEURISTICS
)

from .sop_retriever import (
    SOPRetriever,
    SOPReference,
    get_sop_retriever,
    SOP_REFERENCES
)

from .investigation_runner import (
    InvestigationRunner,
    InvestigationState,
    InvestigationCycleResult,
    CycleResult,
    get_investigation_runner
)

from .llm_client import (
    ReasoningLLMClient,
    LLMResponse,
    get_reasoning_llm_client
)

from .tool_handlers import (
    register_tool_handlers,
    initialize_tool_handlers
)

__all__ = [
    # Core
    'ReasoningEngine',
    'ReasoningOutput',
    'InvestigationContext',
    'get_reasoning_engine',
    'UNIFIED_REASONING_PROMPT',

    # Tool Broker
    'ToolBroker',
    'AuthorityLevel',
    'ToolDefinition',
    'ToolExecutionResult',
    'get_tool_broker',
    'AUTHORITY_HIERARCHY',

    # Checkpoint Manager
    'CheckpointManager',
    'Checkpoint',
    'CheckpointConfig',
    'CheckpointState',
    'ProgressionResult',
    'get_checkpoint_manager',
    'CHECKPOINT_TRANSITIONS',

    # Confidence Gate
    'ConfidenceGate',
    'EscalationDecision',
    'ToolAccessDecision',
    'get_confidence_gate',

    # Heuristic Loader
    'HeuristicLoader',
    'Heuristic',
    'HeuristicCategory',
    'HeuristicOutcome',
    'get_heuristic_loader',
    'HEURISTIC_LIFECYCLE',
    'SEED_HEURISTICS',

    # SOP Retriever
    'SOPRetriever',
    'SOPReference',
    'get_sop_retriever',
    'SOP_REFERENCES',

    # Investigation Runner
    'InvestigationRunner',
    'InvestigationState',
    'InvestigationCycleResult',
    'CycleResult',
    'get_investigation_runner',

    # LLM Client
    'ReasoningLLMClient',
    'LLMResponse',
    'get_reasoning_llm_client',

    # Tool Handlers
    'register_tool_handlers',
    'initialize_tool_handlers',
]

# Version info
__version__ = '1.0.0'
__doc_status__ = 'FROZEN'
