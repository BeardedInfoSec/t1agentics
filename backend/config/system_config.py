# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics System Configuration
Customizable settings for dispositions, severities, and display preferences
"""
import os

# ==========================================================================
# Feature Flags for T1 Triage Optimization
# ==========================================================================
# These flags control the gradual rollout of the optimized triage system
#
# ENABLE_FLAG_BASED_TRIAGE: Use specialized prompts based on alert classification
#   - Enables AlertClassifier to tag alerts during IOC extraction
#   - Uses flag-specific prompts for better accuracy and fewer tokens
#
# T1_ENRICHMENT_GATING: [MANDATORY - NOT CONFIGURABLE]
#   - T1 triage MUST wait for IOC enrichment to complete before execution
#   - This eliminates the race condition where triage runs before enrichment
#   - Per directive: No partial enrichment, no FAST mode before enrichment
#   - Accuracy and determinism take precedence over latency
#
# ENABLE_RIGGS_STREAMLINED: Simplified Riggs analysis without redundancy
#   - Reuses T1 extraction results instead of re-extracting
# ==========================================================================

ENABLE_FLAG_BASED_TRIAGE = os.getenv("ENABLE_FLAG_BASED_TRIAGE", "false").lower() == "true"
# REMOVED: ENABLE_ENRICHMENT_WAIT - T1 gating is now MANDATORY (not configurable)
# T1 triage MUST NOT execute until IOC enrichment is COMPLETE
# This is enforced in auto_enrichment.py via is_enrichment_complete() check
ENABLE_RIGGS_STREAMLINED = os.getenv("ENABLE_RIGGS_STREAMLINED", "false").lower() == "true"

# ENABLE_TIERED_ROUTING: Route T1 triage and Riggs investigations to dedicated AI providers
#   - When disabled, all requests use the default AI provider
ENABLE_TIERED_ROUTING = os.getenv("ENABLE_TIERED_ROUTING", "false").lower() == "true"

# Enrichment wait timeout for high-risk alerts (seconds)
ENRICHMENT_WAIT_TIMEOUT = float(os.getenv("ENRICHMENT_WAIT_TIMEOUT", "10.0"))

# ==========================================================================
# Hypothesis-Driven Correlation (v3.0)
# ==========================================================================
# This replaces entity-based correlation with evidence-based correlation.
# Guiding principle: "It is better to miss a correlation than to create a false one."
#
# ENABLE_HYPOTHESIS_CORRELATION: Use hypothesis-driven correlation (v3.0)
#   - Entities (user, host) are used for VALIDATION only, not scoring
#   - Scoring is based on evidence: malicious IOCs, MITRE chains, causal sequences
#   - Cross-domain correlation is BLOCKED by default
#   - Soft-join by default; hard-join requires strong evidence or analyst confirmation
# ==========================================================================

ENABLE_HYPOTHESIS_CORRELATION = os.getenv("ENABLE_HYPOTHESIS_CORRELATION", "true").lower() == "true"

# Evidence-based scoring weights (replaces entity-based scoring)
CORRELATION_SCORE_MALICIOUS_IOC = int(os.getenv("CORRELATION_SCORE_MALICIOUS_IOC", "50"))
CORRELATION_SCORE_SUSPICIOUS_IOC = int(os.getenv("CORRELATION_SCORE_SUSPICIOUS_IOC", "20"))
CORRELATION_SCORE_MITRE_CHAIN = int(os.getenv("CORRELATION_SCORE_MITRE_CHAIN", "40"))
CORRELATION_SCORE_CAUSAL_SEQUENCE = int(os.getenv("CORRELATION_SCORE_CAUSAL_SEQUENCE", "60"))
CORRELATION_SCORE_THREAT_FINGERPRINT = int(os.getenv("CORRELATION_SCORE_THREAT_FINGERPRINT", "70"))
CORRELATION_SCORE_MALWARE_FAMILY = int(os.getenv("CORRELATION_SCORE_MALWARE_FAMILY", "80"))

# Correlation thresholds
CORRELATION_MINIMUM_EVIDENCE = int(os.getenv("CORRELATION_MINIMUM_EVIDENCE", "40"))
CORRELATION_AUTO_CONFIRM_THRESHOLD = int(os.getenv("CORRELATION_AUTO_CONFIRM_THRESHOLD", "100"))

# Time window and capacity limits
CORRELATION_MAX_TIME_WINDOW_HOURS = int(os.getenv("CORRELATION_MAX_TIME_WINDOW_HOURS", "24"))
CORRELATION_MAX_ALERTS = int(os.getenv("CORRELATION_MAX_ALERTS", "25"))
CORRELATION_MAX_USERS = int(os.getenv("CORRELATION_MAX_USERS", "5"))
CORRELATION_MAX_HOSTS = int(os.getenv("CORRELATION_MAX_HOSTS", "10"))

# Cross-domain correlation (BLOCKED by default)
CORRELATION_ALLOW_CROSS_DOMAIN = os.getenv("CORRELATION_ALLOW_CROSS_DOMAIN", "false").lower() == "true"

# Soft-join timeout (hours before escalation)
CORRELATION_SUGGESTED_TIMEOUT_HOURS = int(os.getenv("CORRELATION_SUGGESTED_TIMEOUT_HOURS", "48"))


# ==========================================================================
# Investigation Auto-Close Configuration
# ==========================================================================
# Controls when investigations are automatically closed after Riggs analysis.
# Auto-close is only applied to BENIGN/FALSE_POSITIVE verdicts with high confidence.
#
# RIGGS_AUTO_CLOSE_ENABLED: Master switch for auto-close functionality
#   - When false, all investigations go to NEEDS_REVIEW regardless of verdict
#
# RIGGS_AUTO_CLOSE_THRESHOLD: Minimum confidence % required to auto-close
#   - Default: 90 (only auto-close if >= 90% confidence)
#   - Set higher for more conservative behavior (e.g., 95)
#   - Set lower for more aggressive auto-closing (e.g., 80)
#
# RIGGS_AUTO_CLOSE_VERDICTS: Which verdicts can trigger auto-close
#   - Default: BENIGN, FALSE_POSITIVE
#   - Never include MALICIOUS, SUSPICIOUS, or actionable verdicts
# ==========================================================================

RIGGS_AUTO_CLOSE_ENABLED = os.getenv("RIGGS_AUTO_CLOSE_ENABLED", "true").lower() == "true"
RIGGS_AUTO_CLOSE_THRESHOLD = int(os.getenv("RIGGS_AUTO_CLOSE_THRESHOLD", "90"))
RIGGS_AUTO_CLOSE_VERDICTS = os.getenv("RIGGS_AUTO_CLOSE_VERDICTS", "BENIGN,FALSE_POSITIVE").upper().split(",")


# Default Configuration
DEFAULT_CONFIG = {
    "dispositions": {
        "enabled": [
            {"value": "MALICIOUS", "label": "Malicious", "color": "#dc2626", "description": "Confirmed malicious activity"},
            {"value": "TRUE_POSITIVE", "label": "True Positive", "color": "#dc2626", "description": "Alert correctly identified a real threat"},
            {"value": "SUSPICIOUS", "label": "Suspicious", "color": "#f97316", "description": "Potentially malicious, needs investigation"},
            {"value": "BENIGN", "label": "Benign", "color": "#22c55e", "description": "Confirmed safe activity"},
            {"value": "FALSE_POSITIVE", "label": "False Positive", "color": "#22c55e", "description": "Alert incorrectly flagged safe activity"},
            {"value": "BENIGN_POSITIVE", "label": "Benign Positive", "color": "#eab308", "description": "Alert is accurate but activity is safe"},
            {"value": "INCONCLUSIVE", "label": "Inconclusive", "color": "#6b7280", "description": "Unable to determine"},
            {"value": "UNKNOWN", "label": "Unknown", "color": "#6b7280", "description": "Not yet analyzed"}
        ],
        "custom": []  # User-defined dispositions
    },
    
    "severity_levels": {
        "enabled": [
            {"value": "critical", "label": "Critical", "color": "#dc2626", "threshold": 90},
            {"value": "high", "label": "High", "color": "#ea580c", "threshold": 70},
            {"value": "medium", "label": "Medium", "color": "#eab308", "threshold": 40},
            {"value": "low", "label": "Low", "color": "#22c55e", "threshold": 0}
        ],
        "custom": []  # User-defined severity levels
    },
    
    "confidence": {
        "display_mode": "label",  # "label" (HIGH/MEDIUM/LOW) or "numeric" (0-100)
        "thresholds": {
            "high": 75,     # >= 75% shows as HIGH
            "medium": 40,   # >= 40% shows as MEDIUM
            "low": 0        # < 40% shows as LOW
        },
        "labels": {
            "high": "High Confidence",
            "medium": "Medium Confidence", 
            "low": "Low Confidence"
        }
    },
    
    "priorities": {
        "enabled": [
            {"value": "P1", "label": "P1 - Critical", "sla_hours": 4, "color": "#dc2626"},
            {"value": "P2", "label": "P2 - High", "sla_hours": 24, "color": "#ea580c"},
            {"value": "P3", "label": "P3 - Medium", "sla_hours": 72, "color": "#eab308"},
            {"value": "P4", "label": "P4 - Low", "sla_hours": 168, "color": "#22c55e"}
        ],
        "custom": []
    },

    # ==========================================================================
    # GPU Capacity Planning
    # ==========================================================================
    # Key metric: Escalation Rate = T2 Investigations Created / T1 Events Triaged
    # Target: Keep escalation rate ≤ 5.5% for steady-state with one 5090 Ti
    #
    # Capacity:
    #   - T1 (3090 Ti): 64,000 events/day @ 1.34s each
    #   - T2 (5090 Ti): 3,600 investigations/day @ 24s each
    #   - Max sustainable escalation: 3,600 / 64,000 = 5.6%
    #
    # If escalation rate exceeds threshold:
    #   - T2 queue will back up
    #   - Consider: tuning T1 thresholds, adding GPU capacity, or ML pre-filter
    # ==========================================================================
    "capacity_planning": {
        "t1_events_per_day": 64000,
        "t2_investigations_per_day": 3600,
        "max_escalation_rate": 0.055,  # 5.5% - keep below this for steady-state
        "warning_escalation_rate": 0.045,  # 4.5% - alert when approaching limit
        "alert_on_breach": True
    }
}

# Configuration storage (in production, this would be in database)
_config = DEFAULT_CONFIG.copy()

def get_config():
    """Get current system configuration"""
    return _config

def update_config(section, updates):
    """Update a configuration section"""
    if section in _config:
        _config[section].update(updates)
        return True
    return False

def add_custom_disposition(value, label, color="#6b7280", description=""):
    """Add a custom disposition"""
    custom = {
        "value": value.upper(),
        "label": label,
        "color": color,
        "description": description
    }
    _config["dispositions"]["custom"].append(custom)
    return custom

def add_custom_severity(value, label, color="#6b7280", threshold=50):
    """Add a custom severity level"""
    custom = {
        "value": value.lower(),
        "label": label,
        "color": color,
        "threshold": threshold
    }
    _config["severity_levels"]["custom"].append(custom)
    return custom

def get_all_dispositions():
    """Get all enabled + custom dispositions"""
    return _config["dispositions"]["enabled"] + _config["dispositions"]["custom"]

def get_all_severities():
    """Get all enabled + custom severity levels"""
    return _config["severity_levels"]["enabled"] + _config["severity_levels"]["custom"]

def get_confidence_display_mode():
    """Get how to display confidence (label or numeric)"""
    return _config["confidence"]["display_mode"]

def set_confidence_display_mode(mode):
    """Set confidence display mode"""
    if mode in ["label", "numeric"]:
        _config["confidence"]["display_mode"] = mode
        return True
    return False

def format_confidence(value):
    """
    Format confidence value based on display mode
    
    Args:
        value: Numeric confidence (0-100) or ConfidenceLevel enum
    
    Returns:
        Formatted string based on display mode
    """
    # Convert to numeric if it's an enum
    if isinstance(value, str):
        if 'HIGH' in value.upper():
            numeric_value = 90
        elif 'MEDIUM' in value.upper():
            numeric_value = 66
        elif 'LOW' in value.upper():
            numeric_value = 33
        else:
            numeric_value = 50
    else:
        numeric_value = float(value) if value else 50
    
    mode = get_confidence_display_mode()
    
    if mode == "numeric":
        return f"{numeric_value:.1f}%"
    else:  # label
        thresholds = _config["confidence"]["thresholds"]
        labels = _config["confidence"]["labels"]
        
        if numeric_value >= thresholds["high"]:
            return labels["high"]
        elif numeric_value >= thresholds["medium"]:
            return labels["medium"]
        else:
            return labels["low"]
