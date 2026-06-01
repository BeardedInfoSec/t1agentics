# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Canonical Verdict Definitions

This module is the SINGLE SOURCE OF TRUTH for all verdict values in the T1 Agentics system.
All other modules MUST import from here - do not define verdict values elsewhere.

Verdict Categories:
- Security verdicts: MALICIOUS, SUSPICIOUS, BENIGN
- Disposition verdicts: TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_POSITIVE
- Process verdicts: NEEDS_INVESTIGATION, INCONCLUSIVE, UNKNOWN
"""

from enum import Enum
from typing import Optional, Set, List


class Verdict(str, Enum):
    """
    Canonical verdict enum - the single source of truth.

    All verdict values MUST be defined here. This enum inherits from str
    to allow direct string comparison and JSON serialization.
    """

    # === Security Verdicts (core triage outcomes) ===
    MALICIOUS = "MALICIOUS"          # Confirmed threat requiring action
    SUSPICIOUS = "SUSPICIOUS"        # Potential threat requiring investigation
    BENIGN = "BENIGN"               # Confirmed safe, no threat

    # === Disposition Verdicts (analyst classifications) ===
    TRUE_POSITIVE = "TRUE_POSITIVE"       # Alert correctly identified a real threat
    FALSE_POSITIVE = "FALSE_POSITIVE"     # Alert incorrectly flagged benign activity
    BENIGN_POSITIVE = "BENIGN_POSITIVE"   # Alert correct but activity is authorized

    # === Process Verdicts (triage workflow states) ===
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"  # Requires human review
    INCONCLUSIVE = "INCONCLUSIVE"                # Cannot determine, needs more data
    UNKNOWN = "UNKNOWN"                          # Initial state, not yet triaged

    def __str__(self) -> str:
        return self.value

    @classmethod
    def security_verdicts(cls) -> Set['Verdict']:
        """Return the core security verdict set."""
        return {cls.MALICIOUS, cls.SUSPICIOUS, cls.BENIGN}

    @classmethod
    def disposition_verdicts(cls) -> Set['Verdict']:
        """Return disposition verdicts for analyst classification."""
        return {cls.TRUE_POSITIVE, cls.FALSE_POSITIVE, cls.BENIGN_POSITIVE}

    @classmethod
    def process_verdicts(cls) -> Set['Verdict']:
        """Return process/workflow verdicts."""
        return {cls.NEEDS_INVESTIGATION, cls.INCONCLUSIVE, cls.UNKNOWN}

    @classmethod
    def actionable_verdicts(cls) -> Set['Verdict']:
        """Return verdicts that require analyst action."""
        return {cls.MALICIOUS, cls.SUSPICIOUS, cls.NEEDS_INVESTIGATION}

    @classmethod
    def all_values(cls) -> List[str]:
        """Return all verdict values as strings (for DB constraints)."""
        return [v.value for v in cls]


# === Verdict Sets for Quick Lookup ===
SECURITY_VERDICTS = Verdict.security_verdicts()
DISPOSITION_VERDICTS = Verdict.disposition_verdicts()
PROCESS_VERDICTS = Verdict.process_verdicts()
ACTIONABLE_VERDICTS = Verdict.actionable_verdicts()
ALL_VERDICTS = set(Verdict)


# === Case Normalization Mapping ===
# Maps lowercase/mixed-case variants to canonical uppercase values
_VERDICT_NORMALIZATION_MAP = {
    # Lowercase variants
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "benign": Verdict.BENIGN,
    "true_positive": Verdict.TRUE_POSITIVE,
    "false_positive": Verdict.FALSE_POSITIVE,
    "benign_positive": Verdict.BENIGN_POSITIVE,
    "needs_investigation": Verdict.NEEDS_INVESTIGATION,
    "inconclusive": Verdict.INCONCLUSIVE,
    "unknown": Verdict.UNKNOWN,

    # Uppercase variants (canonical)
    "MALICIOUS": Verdict.MALICIOUS,
    "SUSPICIOUS": Verdict.SUSPICIOUS,
    "BENIGN": Verdict.BENIGN,
    "TRUE_POSITIVE": Verdict.TRUE_POSITIVE,
    "FALSE_POSITIVE": Verdict.FALSE_POSITIVE,
    "BENIGN_POSITIVE": Verdict.BENIGN_POSITIVE,
    "NEEDS_INVESTIGATION": Verdict.NEEDS_INVESTIGATION,
    "INCONCLUSIVE": Verdict.INCONCLUSIVE,
    "UNKNOWN": Verdict.UNKNOWN,

    # Common variants/aliases
    "tp": Verdict.TRUE_POSITIVE,
    "fp": Verdict.FALSE_POSITIVE,
    "bp": Verdict.BENIGN_POSITIVE,
    "mal": Verdict.MALICIOUS,
    "sus": Verdict.SUSPICIOUS,
    "ben": Verdict.BENIGN,
    "needs_review": Verdict.NEEDS_INVESTIGATION,
    "review": Verdict.NEEDS_INVESTIGATION,
}


def normalize_verdict(value: Optional[str]) -> Optional[Verdict]:
    """
    Normalize a verdict string to the canonical Verdict enum.

    Handles:
    - Case differences (malicious -> MALICIOUS)
    - Common aliases (tp -> TRUE_POSITIVE)
    - None/empty values

    Args:
        value: Raw verdict string from any source

    Returns:
        Canonical Verdict enum value, or None if input is None/empty

    Raises:
        ValueError: If value is not a recognized verdict

    Example:
        >>> normalize_verdict("malicious")
        Verdict.MALICIOUS
        >>> normalize_verdict("tp")
        Verdict.TRUE_POSITIVE
        >>> normalize_verdict(None)
        None
    """
    if value is None or value == "":
        return None

    # Clean the input
    cleaned = str(value).strip()

    # Try direct lookup first (handles both cases)
    if cleaned in _VERDICT_NORMALIZATION_MAP:
        return _VERDICT_NORMALIZATION_MAP[cleaned]

    # Try lowercase lookup
    lower = cleaned.lower()
    if lower in _VERDICT_NORMALIZATION_MAP:
        return _VERDICT_NORMALIZATION_MAP[lower]

    # Try as enum member
    try:
        return Verdict(cleaned.upper())
    except ValueError:
        pass

    raise ValueError(f"Unknown verdict: '{value}'. Valid verdicts: {Verdict.all_values()}")


def normalize_verdict_safe(value: Optional[str], default: Verdict = Verdict.UNKNOWN) -> Verdict:
    """
    Safely normalize a verdict string, returning a default on failure.

    Use this when you want to avoid exceptions for invalid verdicts.

    Args:
        value: Raw verdict string
        default: Verdict to return if normalization fails

    Returns:
        Normalized Verdict or default

    Example:
        >>> normalize_verdict_safe("garbage", Verdict.UNKNOWN)
        Verdict.UNKNOWN
    """
    try:
        result = normalize_verdict(value)
        return result if result is not None else default
    except ValueError:
        return default


def is_valid_verdict(value: Optional[str]) -> bool:
    """
    Check if a string is a valid verdict value.

    Args:
        value: String to check

    Returns:
        True if value can be normalized to a valid Verdict

    Example:
        >>> is_valid_verdict("MALICIOUS")
        True
        >>> is_valid_verdict("garbage")
        False
    """
    try:
        normalize_verdict(value)
        return True
    except (ValueError, TypeError):
        return False


def validate_verdict(value: str, context: str = "verdict") -> Verdict:
    """
    Validate and normalize a verdict, raising a descriptive error on failure.

    Use this for validation at system boundaries (API inputs, Riggs outputs, etc.)

    Args:
        value: Verdict string to validate
        context: Description of where the verdict came from (for error messages)

    Returns:
        Normalized Verdict

    Raises:
        ValueError: With descriptive message including context

    Example:
        >>> validate_verdict("malicious", "Riggs output")
        Verdict.MALICIOUS
        >>> validate_verdict("garbage", "Riggs output")
        ValueError: Invalid Riggs output verdict: 'garbage'. Must be one of: [...]
    """
    if value is None or value == "":
        raise ValueError(f"Missing {context}: verdict cannot be empty")

    try:
        return normalize_verdict(value)
    except ValueError:
        valid_list = ", ".join(Verdict.all_values())
        raise ValueError(f"Invalid {context} verdict: '{value}'. Must be one of: [{valid_list}]")


def get_verdict_severity(verdict: Verdict) -> int:
    """
    Get numeric severity for verdict ordering/comparison.

    Higher values = more severe/actionable.

    Args:
        verdict: Verdict to get severity for

    Returns:
        Integer severity (0-100)
    """
    severity_map = {
        Verdict.MALICIOUS: 100,
        Verdict.TRUE_POSITIVE: 85,
        Verdict.SUSPICIOUS: 70,
        Verdict.NEEDS_INVESTIGATION: 60,
        Verdict.INCONCLUSIVE: 40,
        Verdict.BENIGN_POSITIVE: 30,
        Verdict.BENIGN: 20,
        Verdict.FALSE_POSITIVE: 10,
        Verdict.UNKNOWN: 0,
    }
    return severity_map.get(verdict, 0)


def is_threat_verdict(verdict: Verdict) -> bool:
    """Check if verdict indicates a confirmed or potential threat."""
    return verdict in {
        Verdict.MALICIOUS,
        Verdict.SUSPICIOUS,
        Verdict.TRUE_POSITIVE,
    }


def is_safe_verdict(verdict: Verdict) -> bool:
    """Check if verdict indicates the alert is safe/benign."""
    return verdict in {
        Verdict.BENIGN,
        Verdict.FALSE_POSITIVE,
        Verdict.BENIGN_POSITIVE,
    }


def is_actionable_verdict(verdict: Verdict) -> bool:
    """Check if verdict requires analyst action."""
    return verdict in ACTIONABLE_VERDICTS


# === SQL Constraint Helper ===
def get_verdict_sql_constraint() -> str:
    """
    Get SQL CHECK constraint for verdict columns.

    Returns:
        SQL constraint string for use in migrations

    Example:
        >>> get_verdict_sql_constraint()
        "verdict IN ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', ...)"
    """
    values = ", ".join(f"'{v.value}'" for v in Verdict)
    return f"verdict IN ({values})"


def get_verdict_enum_sql() -> str:
    """
    Get SQL to create a PostgreSQL enum type for verdicts.

    Returns:
        SQL CREATE TYPE statement
    """
    values = ", ".join(f"'{v.value}'" for v in Verdict)
    return f"CREATE TYPE verdict_type AS ENUM ({values})"
