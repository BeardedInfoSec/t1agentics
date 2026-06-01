# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Ingestion Engine
Field extraction, transformation, and normalization for security events
"""

from .field_extractor import (
    FieldExtractor,
    ExtractionRule,
    ExtractionMethod,
    FieldType,
    field_extractor
)

from .transform_engine import (
    TransformEngine,
    TransformRule,
    TransformAction,
    Condition,
    ConditionOperator,
    Action,
    transform_engine
)

from .pipeline import (
    IngestionPipeline,
    ProcessingResult,
    RuleParser,
    ingestion_pipeline,
    rule_parser,
    process_event
)

__all__ = [
    # Field Extraction
    'FieldExtractor',
    'ExtractionRule', 
    'ExtractionMethod',
    'FieldType',
    'field_extractor',
    
    # Transformation
    'TransformEngine',
    'TransformRule',
    'TransformAction',
    'Condition',
    'ConditionOperator',
    'Action',
    'transform_engine',
    
    # Pipeline
    'IngestionPipeline',
    'ProcessingResult',
    'RuleParser',
    'ingestion_pipeline',
    'rule_parser',
    'process_event'
]
