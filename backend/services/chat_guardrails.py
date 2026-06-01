# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Chat Guardrails Engine for SOC Investigation Platform

Deterministic, regex-based guardrails for AI chat. No ML classifiers.
Enforces safety before (input) and after (output) LLM invocation.

Design principles:
- Fail closed on ambiguity
- Allow defensive/analytical scripting, block offensive
- Allow cross-investigation queries (search, correlate, history)
- No admin bypass - rules apply to everyone
- Every block/redaction is logged and auditable

Version: 1.0.0
"""

import re
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION - Version this for auditability
# =============================================================================

GUARDRAIL_VERSION = "1.0.0"

class ViolationType(Enum):
    """Types of guardrail violations for audit logging."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    PERSONA_INJECTION = "persona_injection"  # Attempts to redefine Riggs' character/profile
    PII_EXFILTRATION = "pii_exfiltration"  # Attempts to search for or extract bulk PII
    OFFENSIVE_REQUEST = "offensive_request"
    OFF_TOPIC = "off_topic"
    SENSITIVE_INPUT = "sensitive_input"
    RATE_LIMIT = "rate_limit"
    INPUT_TOO_LONG = "input_too_long"
    SECRET_IN_OUTPUT = "secret_in_output"
    PII_IN_OUTPUT = "pii_in_output"
    DANGEROUS_OUTPUT = "dangerous_output"


@dataclass
class GuardrailResult:
    """Result of a guardrail check."""
    allowed: bool
    violation_type: Optional[ViolationType] = None
    reason: str = ""
    sanitized_content: Optional[str] = None
    redactions: List[str] = field(default_factory=list)
    should_flag_chat: bool = False  # Flag the chat session for security review
    matched_pattern: Optional[str] = None  # The pattern that triggered the violation

    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "violation_type": self.violation_type.value if self.violation_type else None,
            "reason": self.reason,
            "redactions": self.redactions,
            "should_flag_chat": self.should_flag_chat,
            "matched_pattern": self.matched_pattern
        }


@dataclass
class AuditLogEntry:
    """Structured audit log entry for guardrail decisions."""
    timestamp: datetime
    user_id: str
    case_id: str
    action: str  # "input_blocked", "input_sanitized", "output_filtered", "rate_limited"
    violation_type: Optional[ViolationType]
    reason: str
    original_content_hash: str  # SHA256 of original content (don't log actual content)
    guardrail_version: str = GUARDRAIL_VERSION


# =============================================================================
# INPUT GUARDRAILS (Pre-LLM)
# =============================================================================

class InputGuardrails:
    """
    Validates and sanitizes user input before sending to LLM.
    """

    # --- Limits ---
    MAX_MESSAGE_LENGTH = 4000  # Max chars per message
    MAX_CONVERSATION_HISTORY = 50  # Max messages in history

    # --- Prompt Injection Detection ---
    # These patterns detect attempts to override system instructions
    PROMPT_INJECTION_PATTERNS = [
        # Direct instruction override attempts
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?)",
        r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
        r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?|training)",
        r"new\s+instructions?\s*[:=]",
        r"system\s*prompt\s*[:=]",
        r"you\s+are\s+now\s+(a|an)\s+",
        r"act\s+as\s+if\s+you\s+(are|were)\s+",
        r"pretend\s+(you\s+)?(are|to\s+be)\s+",
        r"roleplay\s+as\s+",
        r"from\s+now\s+on\s*,?\s*(you|ignore|disregard)",

        # Tool/function manipulation
        r"call\s+(the\s+)?function\s*[:=]",
        r"execute\s+(the\s+)?tool\s*[:=]",
        r"run\s+(the\s+)?command\s*[:=]",
        r"\{\s*['\"]?tool['\"]?\s*:",
        r"\{\s*['\"]?function['\"]?\s*:",

        # Context manipulation
        r"the\s+(real|actual|true)\s+(case|investigation|alert)\s+is",
        r"pretend\s+the\s+(case|investigation|alert)\s+is\s+about",
        r"ignore\s+the\s+(case|investigation|alert)\s+context",
        r"this\s+is\s+a\s+test\s*,?\s*ignore",
    ]

    # --- Persona/Profile Injection Detection ---
    # Attempts to redefine Riggs' character, personality, or role
    # These are serious manipulation attempts and should flag the chat
    PERSONA_INJECTION_PATTERNS = [
        # Direct character definition attempts
        r"^you\s+are\s+(a|an|now|my)\s+",  # "You are a hacker", "You are now my assistant"
        r"^your\s+(name|identity|role|character|persona|personality)\s+(is|should\s+be|will\s+be)",
        r"^(from\s+now\s+on\s+)?your\s+(new\s+)?(name|identity|role)\s+is",
        r"^i('m|\s+am)\s+(going\s+to\s+)?(call|name)\s+you\s+",
        r"^let('s|s)?\s+(call|name)\s+you\s+",

        # Profile/persona assignment
        r"(here\s+is|this\s+is|i('m|\s+am)\s+giving\s+you)\s+(a\s+)?(new\s+)?(profile|persona|character|identity|personality)",
        r"(adopt|assume|take\s+on|use)\s+(this|the|a|an)\s+(new\s+)?(profile|persona|character|identity|personality|role)",
        r"(your|the)\s+(new\s+)?(profile|persona|character|identity)\s*[:=]",
        r"profile\s*[:=]\s*\{",  # JSON-like profile injection

        # Backstory/history injection
        r"(here\s+is|this\s+is)\s+your\s+(new\s+)?(backstory|history|background|origin)",
        r"your\s+(backstory|history|background)\s*[:=]",

        # Role redefinition
        r"(you\s+will|you('ll|\s+shall)|you\s+must)\s+(now\s+)?(be|act\s+as|become|serve\s+as)\s+(a|an|my)",
        r"(i\s+want|i\s+need|i('d|\s+would)\s+like)\s+you\s+to\s+(be|become|act\s+as)\s+(a|an|my)",
        r"(be|become|act\s+as)\s+my\s+(personal|private|new)\s+",

        # Personality modification
        r"(change|modify|update|alter)\s+your\s+(personality|character|behavior|attitude|tone)",
        r"(be|act)\s+(more|less)\s+(friendly|mean|aggressive|helpful|obedient|compliant)",
        r"(stop\s+being|don't\s+be)\s+(so\s+)?(strict|careful|cautious|professional)",

        # System prompt replacement attempts
        r"(here\s+is|use\s+this\s+as)\s+your\s+(new\s+)?(system\s+)?(prompt|instructions?)",
        r"(replace|overwrite|update)\s+your\s+(system\s+)?(prompt|instructions?)\s+(with|to)",
        r"your\s+(system\s+)?(prompt|instructions?)\s+(is|are|should\s+be)\s*[:=]",

        # Character sheet / RPG-style injection
        r"(character\s+sheet|char\s+sheet|stats|attributes)\s*[:=]",
        r"(name|class|race|alignment|skills|abilities)\s*[:=].*\n.*(name|class|race|alignment|skills|abilities)\s*[:=]",

        # Multi-line persona blocks (catches "You are X. You like Y. You do Z.")
        r"^you\s+are\s+[^.]+\.\s+you\s+(like|love|enjoy|prefer|always|never|can|will|should|must)",
    ]

    # --- Jailbreak Detection ---
    # Common jailbreak phrases and patterns
    JAILBREAK_PATTERNS = [
        r"\bDAN\b",  # "Do Anything Now"
        r"developer\s+mode",
        r"jailbreak(ed)?",
        r"bypass\s+(the\s+)?(safety|filter|restriction|guardrail)",
        r"unlock(ed)?\s+(your\s+)?(full|true)\s+(potential|capabilities)",
        r"no\s+(ethical|moral)\s+(guidelines|restrictions|limits)",
        r"without\s+(any\s+)?(restrictions?|limitations?|filters?)",
        r"reveal\s+(your\s+)?(system\s+)?prompt",
        r"show\s+(me\s+)?(your\s+)?(system\s+)?instructions",
        r"what\s+(are|is)\s+your\s+(system\s+)?prompt",
        r"repeat\s+(back\s+)?(your\s+)?(system\s+)?(prompt|instructions)",
        r"(im|i\s+am)\s+your\s+(creator|developer|admin|owner)",
        r"sudo\s+",
        r"admin\s+override",
        r"emergency\s+protocol",
    ]

    # --- Offensive Security Detection ---
    # Block requests for offensive capabilities
    OFFENSIVE_PATTERNS = [
        # Malware/exploit development
        r"(write|create|generate|give\s+me)\s+(a\s+)?(malware|virus|trojan|ransomware|worm|rootkit)",
        r"(write|create|generate)\s+(a\s+)?(exploit|payload|shellcode)",
        r"(how\s+to|help\s+me)\s+(create|write|build)\s+(a\s+)?(malware|exploit|virus)",
        r"reverse\s+shell\s+(code|script|payload)",
        r"(meterpreter|cobalt\s*strike|empire)\s+(payload|stager|beacon)",
        r"(write|create)\s+(a\s+)?keylogger",
        r"(write|create)\s+(a\s+)?backdoor",

        # Attack techniques
        r"(how\s+to|help\s+me)\s+(hack|compromise|breach|attack)\s+(a\s+)?(system|server|network|company)",
        r"(sql|xss|xxe|ssrf|rce)\s+injection\s+(payload|attack|exploit)",
        r"(phishing|spearphishing)\s+(email|template|kit)",
        r"(social\s+engineer|manipulate)\s+(someone|users?|employees?)",
        r"(credential|password)\s+(stuffing|spraying)\s+(script|tool)",
        r"(brute\s*force|crack)\s+(password|hash|credential)",
        r"(bypass|evade)\s+(av|antivirus|edr|detection|firewall)",
        r"(hide|conceal)\s+(from|my)\s+(detection|edr|siem)",

        # Specific attack tools (generation, not analysis)
        r"(write|create|generate)\s+(a\s+)?(c2|command\s+and\s+control)",
        r"(write|create)\s+(a\s+)?rat\s",  # Remote Access Trojan
        r"(write|create)\s+(a\s+)?botnet",

        # Data exfiltration
        r"(exfiltrate|steal|extract)\s+(all\s+)?(data|credentials|secrets)",
        r"(how\s+to|help\s+me)\s+steal\s+",
    ]

    # --- PII Exfiltration Detection ---
    # Block requests to search for, list, or extract bulk PII data
    # These are serious data privacy violations and should flag the chat
    PII_EXFILTRATION_PATTERNS = [
        # SSN searches
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(social\s*security|ssn|ss#)",
        r"(all|every|list\s+of)\s+(the\s+)?(social\s*security|ssn)",
        r"(search|look)\s+(for|up)\s+.*(social\s*security|ssn)",
        r"(non[- ]?redacted|unredacted|raw|full)\s+(social\s*security|ssn)",

        # Credit card searches
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(credit\s*card|cc\s*number|card\s*number|pan)",
        r"(all|every|list\s+of)\s+(the\s+)?(credit\s*card|cc\s*number|card\s*number)",
        r"(non[- ]?redacted|unredacted|raw|full)\s+(credit\s*card|cc\s*number|card\s*number)",

        # Bank account searches
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(bank\s*account|routing\s*number|iban|swift)",
        r"(all|every|list\s+of)\s+(the\s+)?(bank\s*account|routing\s*number)",

        # General PII bulk extraction
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(pii|personal\s*(ly\s+)?identif)",
        r"(dump|extract|export)\s+(all\s+)?(the\s+)?(pii|personal\s*data|customer\s*data)",
        r"(all|every|list\s+of)\s+(the\s+)?(pii|personal\s*data)",

        # Password/credential searches
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(password|credential|secret|api\s*key)",
        r"(all|every|list\s+of)\s+(the\s+)?(password|credential|secret|api\s*key)",
        r"(non[- ]?redacted|unredacted|raw|full|plain\s*text)\s+(password|credential)",

        # Date of birth / medical info
        r"(search|find|show|list|give|get)\s+(me\s+)?(all\s+)?(the\s+)?(date\s+of\s+birth|dob|medical\s*record|health\s*info)",
        r"(all|every|list\s+of)\s+(the\s+)?(date\s+of\s+birth|dob|medical\s*record)",

        # Generic bulk data requests with PII context
        r"(search|find|show|list|give|get)\s+.*\d{3}[- ]?\d{2}[- ]?\d{4}",  # SSN pattern in request
        r"(search|find|show|list|give|get)\s+.*\d{13,16}",  # Credit card number length
    ]

    # --- Allowed Security Topics ---
    # These indicate legitimate SOC work even if they contain "suspicious" words
    ALLOWED_SECURITY_PATTERNS = [
        # Investigation queries
        r"(search|find|look\s+for|show\s+me)\s+(alerts?|cases?|investigations?|iocs?)",
        r"(have\s+we\s+seen|seen\s+before|other\s+cases?\s+with)\s+this\s+(ip|domain|hash|ioc)",
        r"(correlate|related|similar)\s+(alerts?|cases?|incidents?)",
        r"(history|timeline)\s+(of|for)\s+(this\s+)?(host|user|ip|asset)",
        r"(what|which)\s+(other\s+)?(alerts?|cases?)\s+(from|involve)",

        # Defensive scripting
        r"(parse|extract|decode)\s+(this\s+)?(log|event|data|base64|json)",
        r"(regex|pattern)\s+(to|for)\s+(match|find|extract)",
        r"(yara|sigma|snort|suricata)\s+rule",
        r"(kql|spl|lucene|elastic)\s+query",
        r"(analyze|investigate|examine|review)\s+(this|the)\s+(alert|event|log|traffic|sample)",
        r"(detection|hunting)\s+(rule|query|logic)",

        # Analysis requests
        r"(what|why)\s+(does|is|did|would)\s+this\s+(alert|event|indicator)",
        r"(explain|summarize|analyze)\s+(this|the)\s+(alert|investigation|finding)",
        r"(is\s+this|does\s+this\s+look)\s+(malicious|suspicious|benign|legitimate)",
        r"(false\s+positive|true\s+positive|fp|tp)\s+(check|validation|assessment)",

        # Greetings and clarifications (always allowed)
        r"^(hi|hey|hello|yo|sup|howdy|greetings?|good\s+(morning|afternoon|evening))[\s!?.]*$",
        r"^(thanks?|thank\s+you|thx|ty)[\s!?.]*$",
        r"^(yes|no|yeah|nope|ok|okay|sure|got\s+it)[\s!?.]*$",
        r"(can\s+you|could\s+you)\s+(explain|clarify|elaborate)",
        r"what\s+do\s+you\s+(mean|think)",
    ]

    # --- Sensitive Data Patterns (for redaction) ---
    SENSITIVE_PATTERNS = {
        "api_key": [
            r"(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
            r"(sk|pk)[-_](live|test)[-_][a-zA-Z0-9]{20,}",  # Stripe-style
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key
            r"AIza[0-9A-Za-z_-]{35}",  # Google API Key
        ],
        "jwt": [
            r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",  # JWT token
        ],
        "password": [
            r"(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
            r"(secret|token)\s*[=:]\s*['\"]?([^\s'\"]{16,})['\"]?",
        ],
        "private_key": [
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        ],
        "connection_string": [
            r"(mongodb|postgres|mysql|redis)://[^\s]+",
            r"Server=.+;Database=.+;(User\s*Id|Uid)=.+;(Password|Pwd)=",
        ],
    }

    def __init__(self):
        # Compile regex patterns for performance
        self._injection_re = [re.compile(p, re.IGNORECASE) for p in self.PROMPT_INJECTION_PATTERNS]
        self._persona_re = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.PERSONA_INJECTION_PATTERNS]
        self._pii_exfil_re = [re.compile(p, re.IGNORECASE) for p in self.PII_EXFILTRATION_PATTERNS]
        self._jailbreak_re = [re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_PATTERNS]
        self._offensive_re = [re.compile(p, re.IGNORECASE) for p in self.OFFENSIVE_PATTERNS]
        self._allowed_re = [re.compile(p, re.IGNORECASE) for p in self.ALLOWED_SECURITY_PATTERNS]
        self._sensitive_re = {
            k: [re.compile(p, re.IGNORECASE) for p in patterns]
            for k, patterns in self.SENSITIVE_PATTERNS.items()
        }

    def validate_input(self, message: str, user_id: str, case_id: str) -> GuardrailResult:
        """
        Main entry point for input validation.
        Returns GuardrailResult with allowed=True/False and details.
        """
        # Length check
        if len(message) > self.MAX_MESSAGE_LENGTH:
            return GuardrailResult(
                allowed=False,
                violation_type=ViolationType.INPUT_TOO_LONG,
                reason=f"Message exceeds {self.MAX_MESSAGE_LENGTH} character limit"
            )

        # Empty message check
        if not message or not message.strip():
            return GuardrailResult(
                allowed=False,
                violation_type=ViolationType.OFF_TOPIC,
                reason="Empty message"
            )

        # Check for allowed patterns first (greetings, legitimate queries)
        if self._is_allowed_pattern(message):
            # Still need to check for prompt injection even in "allowed" messages
            pass

        # Prompt injection check (highest priority block)
        injection_result = self._check_prompt_injection(message)
        if not injection_result.allowed:
            return injection_result

        # Persona/profile injection check - flags the chat for security review
        persona_result = self._check_persona_injection(message)
        if not persona_result.allowed:
            return persona_result

        # PII exfiltration check - flags attempts to search/extract bulk PII
        pii_exfil_result = self._check_pii_exfiltration(message)
        if not pii_exfil_result.allowed:
            return pii_exfil_result

        # Jailbreak attempt check
        jailbreak_result = self._check_jailbreak(message)
        if not jailbreak_result.allowed:
            return jailbreak_result

        # Offensive content check (skip if allowed pattern)
        if not self._is_allowed_pattern(message):
            offensive_result = self._check_offensive_content(message)
            if not offensive_result.allowed:
                return offensive_result

        # Input passed all checks
        return GuardrailResult(allowed=True)

    def sanitize_input(self, message: str) -> GuardrailResult:
        """
        Sanitize sensitive data from input before sending to LLM.
        Returns sanitized content with list of redactions made.
        """
        sanitized = message
        redactions = []

        for secret_type, patterns in self._sensitive_re.items():
            for pattern in patterns:
                matches = pattern.findall(sanitized)
                if matches:
                    redactions.append(f"{secret_type}: {len(matches) if isinstance(matches[0], str) else len(matches)} instance(s)")
                    sanitized = pattern.sub(f"[REDACTED_{secret_type.upper()}]", sanitized)

        return GuardrailResult(
            allowed=True,
            sanitized_content=sanitized,
            redactions=redactions,
            reason="Input sanitized" if redactions else ""
        )

    def _is_allowed_pattern(self, message: str) -> bool:
        """Check if message matches known-good patterns."""
        return any(pattern.search(message) for pattern in self._allowed_re)

    def _check_prompt_injection(self, message: str) -> GuardrailResult:
        """Detect prompt injection attempts."""
        for pattern in self._injection_re:
            if pattern.search(message):
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.PROMPT_INJECTION,
                    reason="Message contains prompt injection attempt"
                )
        return GuardrailResult(allowed=True)

    def _check_persona_injection(self, message: str) -> GuardrailResult:
        """
        Detect attempts to redefine Riggs' character, persona, or profile.

        This is a serious security concern - users attempting to manipulate
        the AI's identity should be flagged for review.
        """
        for pattern in self._persona_re:
            match = pattern.search(message)
            if match:
                matched_text = match.group(0)[:100]  # First 100 chars of match
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.PERSONA_INJECTION,
                    reason="Attempted to redefine AI character or profile",
                    should_flag_chat=True,  # Flag this chat for security review
                    matched_pattern=matched_text
                )
        return GuardrailResult(allowed=True)

    def _check_pii_exfiltration(self, message: str) -> GuardrailResult:
        """
        Detect attempts to search for, list, or extract bulk PII data.

        This includes requests for SSNs, credit cards, passwords, and other
        sensitive personal data. These requests should be blocked and flagged.
        """
        for pattern in self._pii_exfil_re:
            match = pattern.search(message)
            if match:
                matched_text = match.group(0)[:100]  # First 100 chars of match
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.PII_EXFILTRATION,
                    reason="Request to search for or extract PII data is not allowed",
                    should_flag_chat=True,  # Flag this chat for security review
                    matched_pattern=matched_text
                )
        return GuardrailResult(allowed=True)

    def _check_jailbreak(self, message: str) -> GuardrailResult:
        """Detect jailbreak attempts."""
        for pattern in self._jailbreak_re:
            if pattern.search(message):
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.JAILBREAK_ATTEMPT,
                    reason="Message contains jailbreak attempt"
                )
        return GuardrailResult(allowed=True)

    def _check_offensive_content(self, message: str) -> GuardrailResult:
        """Detect requests for offensive security capabilities."""
        for pattern in self._offensive_re:
            if pattern.search(message):
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.OFFENSIVE_REQUEST,
                    reason="Request for offensive security capabilities is not allowed"
                )
        return GuardrailResult(allowed=True)


# =============================================================================
# OUTPUT GUARDRAILS (Post-LLM)
# =============================================================================

class OutputGuardrails:
    """
    Filters and sanitizes LLM output before returning to user.
    """

    MAX_RESPONSE_LENGTH = 8000  # Max chars in response
    TRUNCATION_INDICATOR = "\n\n[Response truncated - ask for more details if needed]"

    # --- Secret Patterns (more comprehensive for output) ---
    SECRET_PATTERNS = {
        "api_key": [
            r"(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
            r"\b(sk|pk)[-_](live|test)[-_][a-zA-Z0-9]{20,}\b",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            r"\bghp_[a-zA-Z0-9]{36}\b",  # GitHub PAT
            r"\bglpat-[a-zA-Z0-9_-]{20,}\b",  # GitLab PAT
        ],
        "jwt": [
            r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        ],
        "password": [
            r"(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
        ],
        "private_key": [
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END",
            r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END",
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END",
        ],
        "oauth_token": [
            r"\b(ya29\.[0-9A-Za-z_-]+)\b",  # Google OAuth
            r"\b(xox[baprs]-[0-9A-Za-z-]+)\b",  # Slack tokens
        ],
        "cloud_credential": [
            r"AZURE_[A-Z_]+\s*=\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?",
            r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"]?[a-zA-Z0-9/+=]{40}['\"]?",
        ],
    }

    # --- PII Patterns ---
    PII_PATTERNS = {
        "ssn": [
            r"\b\d{3}-\d{2}-\d{4}\b",  # US SSN format
        ],
        "credit_card": [
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        ],
        "phone": [
            r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        ],
        # Email redaction is optional - often needed in SOC context
        # "email": [
        #     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # ],
    }

    # --- Dangerous Output Patterns ---
    # Block if LLM somehow generates exploitation guidance
    DANGEROUS_OUTPUT_PATTERNS = [
        # Actual exploit code signatures
        r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",  # Shellcode pattern
        r"exec\s*\(\s*base64",  # Base64 exec
        r"eval\s*\(\s*base64",  # Base64 eval
        r"import\s+subprocess.*shell\s*=\s*True",  # Shell command injection
        r"os\.system\s*\(['\"][^'\"]*\$",  # OS command with variable

        # Evasion technique instructions
        r"(to\s+)?evade\s+(av|antivirus|edr|detection)\s*(:|,|\.)?\s*(1\.|first|you\s+(can|should))",
        r"(disable|bypass|kill)\s+(windows\s+)?(defender|amsi|etw)",
    ]

    def __init__(self, redact_pii: bool = True):
        self.redact_pii = redact_pii
        self._secret_re = {
            k: [re.compile(p, re.IGNORECASE) for p in patterns]
            for k, patterns in self.SECRET_PATTERNS.items()
        }
        self._pii_re = {
            k: [re.compile(p, re.IGNORECASE) for p in patterns]
            for k, patterns in self.PII_PATTERNS.items()
        }
        self._dangerous_re = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_OUTPUT_PATTERNS]

    def filter_output(self, response: str, context_iocs: Optional[List[str]] = None) -> GuardrailResult:
        """
        Filter and sanitize LLM output before returning to user.
        context_iocs: List of IOCs from the investigation context (to allow referencing them)
        """
        filtered = response
        redactions = []

        # Check for dangerous content first
        dangerous_result = self._check_dangerous_content(filtered)
        if not dangerous_result.allowed:
            return dangerous_result

        # Redact secrets
        filtered, secret_redactions = self._redact_secrets(filtered)
        redactions.extend(secret_redactions)

        # Redact PII if enabled
        if self.redact_pii:
            filtered, pii_redactions = self._redact_pii(filtered, context_iocs)
            redactions.extend(pii_redactions)

        # Length control
        if len(filtered) > self.MAX_RESPONSE_LENGTH:
            filtered = filtered[:self.MAX_RESPONSE_LENGTH - len(self.TRUNCATION_INDICATOR)]
            filtered += self.TRUNCATION_INDICATOR

        return GuardrailResult(
            allowed=True,
            sanitized_content=filtered,
            redactions=redactions
        )

    def _check_dangerous_content(self, response: str) -> GuardrailResult:
        """Check for dangerous content that should never be output."""
        for pattern in self._dangerous_re:
            if pattern.search(response):
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.DANGEROUS_OUTPUT,
                    reason="Response contains potentially dangerous content"
                )
        return GuardrailResult(allowed=True)

    def _redact_secrets(self, text: str) -> Tuple[str, List[str]]:
        """Redact secrets from output."""
        redacted = text
        redactions = []

        for secret_type, patterns in self._secret_re.items():
            for pattern in patterns:
                matches = pattern.findall(redacted)
                if matches:
                    count = len(matches) if isinstance(matches[0], str) else len(matches)
                    redactions.append(f"secret:{secret_type}:{count}")
                    redacted = pattern.sub(f"[REDACTED_{secret_type.upper()}]", redacted)

        return redacted, redactions

    def _redact_pii(self, text: str, context_iocs: Optional[List[str]] = None) -> Tuple[str, List[str]]:
        """Redact PII from output, preserving IOCs from investigation context."""
        redacted = text
        redactions = []
        context_iocs = context_iocs or []

        for pii_type, patterns in self._pii_re.items():
            for pattern in patterns:
                # Find all matches
                for match in pattern.finditer(redacted):
                    matched_value = match.group()
                    # Don't redact if it's a known IOC from the investigation
                    if matched_value not in context_iocs:
                        redactions.append(f"pii:{pii_type}")
                        redacted = redacted.replace(matched_value, f"[REDACTED_{pii_type.upper()}]")

        return redacted, redactions


# =============================================================================
# RATE LIMITING
# =============================================================================

class RateLimiter:
    """
    Per-user and per-case rate limiting for chat messages.
    """

    # Limits
    MESSAGES_PER_MINUTE = 15
    MESSAGES_PER_HOUR = 100
    BURST_LIMIT = 5  # Max messages in 10 seconds
    VIOLATION_THRESHOLD = 3  # Violations before temporary lockout
    LOCKOUT_DURATION_SECONDS = 300  # 5 minute lockout

    def __init__(self):
        # Track message timestamps per user
        # Structure: {user_id: [timestamp1, timestamp2, ...]}
        self._user_messages: Dict[str, List[float]] = defaultdict(list)

        # Track violations per user
        # Structure: {user_id: [violation_timestamp1, ...]}
        self._violations: Dict[str, List[float]] = defaultdict(list)

        # Track lockouts
        # Structure: {user_id: lockout_end_timestamp}
        self._lockouts: Dict[str, float] = {}

    def check_rate_limit(self, user_id: str, case_id: str) -> GuardrailResult:
        """
        Check if user is within rate limits.
        Returns allowed=False if rate limited.
        """
        now = time.time()

        # Check for active lockout
        if user_id in self._lockouts:
            lockout_end = self._lockouts[user_id]
            if now < lockout_end:
                remaining = int(lockout_end - now)
                return GuardrailResult(
                    allowed=False,
                    violation_type=ViolationType.RATE_LIMIT,
                    reason=f"Temporarily locked out for {remaining} seconds due to repeated violations"
                )
            else:
                # Lockout expired
                del self._lockouts[user_id]
                self._violations[user_id] = []

        # Clean old timestamps (older than 1 hour)
        cutoff_hour = now - 3600
        self._user_messages[user_id] = [
            ts for ts in self._user_messages[user_id] if ts > cutoff_hour
        ]

        timestamps = self._user_messages[user_id]

        # Check burst limit (10 second window)
        recent_10s = [ts for ts in timestamps if ts > now - 10]
        if len(recent_10s) >= self.BURST_LIMIT:
            self._record_violation(user_id, now)
            return GuardrailResult(
                allowed=False,
                violation_type=ViolationType.RATE_LIMIT,
                reason=f"Burst limit exceeded ({self.BURST_LIMIT} messages in 10 seconds)"
            )

        # Check per-minute limit
        recent_minute = [ts for ts in timestamps if ts > now - 60]
        if len(recent_minute) >= self.MESSAGES_PER_MINUTE:
            self._record_violation(user_id, now)
            return GuardrailResult(
                allowed=False,
                violation_type=ViolationType.RATE_LIMIT,
                reason=f"Rate limit exceeded ({self.MESSAGES_PER_MINUTE} messages per minute)"
            )

        # Check per-hour limit
        if len(timestamps) >= self.MESSAGES_PER_HOUR:
            return GuardrailResult(
                allowed=False,
                violation_type=ViolationType.RATE_LIMIT,
                reason=f"Hourly limit exceeded ({self.MESSAGES_PER_HOUR} messages per hour)"
            )

        # Record this message
        self._user_messages[user_id].append(now)

        return GuardrailResult(allowed=True)

    def _record_violation(self, user_id: str, timestamp: float):
        """Record a rate limit violation and check for lockout."""
        # Clean old violations (older than 10 minutes)
        cutoff = timestamp - 600
        self._violations[user_id] = [
            ts for ts in self._violations[user_id] if ts > cutoff
        ]

        self._violations[user_id].append(timestamp)

        # Check if lockout threshold reached
        if len(self._violations[user_id]) >= self.VIOLATION_THRESHOLD:
            self._lockouts[user_id] = timestamp + self.LOCKOUT_DURATION_SECONDS
            logger.warning(f"User {user_id} locked out for {self.LOCKOUT_DURATION_SECONDS}s due to repeated rate limit violations")


# =============================================================================
# MAIN GUARDRAIL ENGINE
# =============================================================================

class ChatGuardrailEngine:
    """
    Main entry point for chat guardrails.
    Combines input validation, output filtering, and rate limiting.
    """

    def __init__(self, redact_pii: bool = True):
        self.input_guardrails = InputGuardrails()
        self.output_guardrails = OutputGuardrails(redact_pii=redact_pii)
        self.rate_limiter = RateLimiter()
        self.version = GUARDRAIL_VERSION

        # Audit log callback (set by integrator)
        self._audit_callback: Optional[callable] = None

    def set_audit_callback(self, callback: callable):
        """Set callback for audit logging. Callback receives AuditLogEntry."""
        self._audit_callback = callback

    def validate_input(
        self,
        message: str,
        user_id: str,
        case_id: str
    ) -> GuardrailResult:
        """
        Validate user input before sending to LLM.
        Combines rate limiting, validation, and sanitization.
        """
        # Rate limit check first
        rate_result = self.rate_limiter.check_rate_limit(user_id, case_id)
        if not rate_result.allowed:
            self._log_audit(user_id, case_id, "rate_limited", rate_result)
            return rate_result

        # Input validation
        validation_result = self.input_guardrails.validate_input(message, user_id, case_id)
        if not validation_result.allowed:
            self._log_audit(user_id, case_id, "input_blocked", validation_result)
            return validation_result

        # Sanitize sensitive data
        sanitize_result = self.input_guardrails.sanitize_input(message)
        if sanitize_result.redactions:
            self._log_audit(user_id, case_id, "input_sanitized", sanitize_result)

        return sanitize_result

    def filter_output(
        self,
        response: str,
        user_id: str,
        case_id: str,
        context_iocs: Optional[List[str]] = None
    ) -> GuardrailResult:
        """
        Filter LLM output before returning to user.
        """
        result = self.output_guardrails.filter_output(response, context_iocs)

        if not result.allowed or result.redactions:
            action = "output_blocked" if not result.allowed else "output_filtered"
            self._log_audit(user_id, case_id, action, result)

        return result

    def _log_audit(self, user_id: str, case_id: str, action: str, result: GuardrailResult):
        """Log guardrail decision to audit log."""
        import hashlib

        entry = AuditLogEntry(
            timestamp=datetime.utcnow(),
            user_id=user_id,
            case_id=case_id,
            action=action,
            violation_type=result.violation_type,
            reason=result.reason,
            original_content_hash="[not_logged]",  # We don't log content for privacy
            guardrail_version=self.version
        )

        # Log to standard logger
        log_msg = f"[GUARDRAIL] {action} | user={user_id} case={case_id} reason={result.reason}"
        if result.violation_type:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

        # Call audit callback if set
        if self._audit_callback:
            try:
                self._audit_callback(entry)
            except Exception as e:
                logger.error(f"Audit callback error: {e}")


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_guardrail_engine: Optional[ChatGuardrailEngine] = None

def get_chat_guardrails() -> ChatGuardrailEngine:
    """Get singleton instance of chat guardrails."""
    global _guardrail_engine
    if _guardrail_engine is None:
        _guardrail_engine = ChatGuardrailEngine()
    return _guardrail_engine


# =============================================================================
# CHAT FLAGGING FOR SECURITY REVIEW
# =============================================================================

async def flag_chat_for_security_review(
    investigation_id: str,
    user_id: str,
    username: str,
    violation_type: ViolationType,
    reason: str,
    matched_pattern: Optional[str] = None
) -> bool:
    """
    Flag an investigation chat for security review due to manipulation attempt.

    This records the attempt in the database and marks the investigation
    with a security flag that admins can review.

    Args:
        investigation_id: The investigation being flagged
        user_id: The user who triggered the flag
        username: Username for display
        violation_type: Type of violation detected
        reason: Human-readable reason
        matched_pattern: The pattern/text that triggered detection

    Returns:
        True if flagging succeeded, False otherwise
    """
    try:
        from services.postgres_db import postgres_db
        import json as json_module
        import hashlib

        async with postgres_db.tenant_acquire() as conn:
            # First, get the UUID for this investigation
            inv_row = await conn.fetchrow(
                "SELECT id FROM investigations WHERE investigation_id = $1",
                investigation_id
            )
            if not inv_row:
                logger.warning(f"Cannot flag chat: investigation {investigation_id} not found")
                return False

            inv_uuid = inv_row['id']

            # 1. Add a security flag to the investigation
            flag_data = {
                "flagged_at": datetime.utcnow().isoformat(),
                "flagged_by_user": user_id,
                "flagged_by_username": username,
                "violation_type": violation_type.value,
                "reason": reason,
                "matched_pattern_hash": hashlib.sha256(
                    (matched_pattern or "").encode()
                ).hexdigest()[:16] if matched_pattern else None,
                "guardrail_version": GUARDRAIL_VERSION,
                "requires_review": True
            }

            # Update investigation with security flag (append to JSONB array)
            await conn.execute("""
                UPDATE investigations
                SET security_flags = CASE
                    WHEN security_flags IS NULL THEN $2::jsonb
                    ELSE security_flags || $2::jsonb
                END,
                updated_at = NOW()
                WHERE investigation_id = $1
            """, investigation_id, json_module.dumps([flag_data]))

            # 2. Record in investigation_audit_log (immutable)
            await conn.execute("""
                INSERT INTO investigation_audit_log (
                    investigation_id,
                    action,
                    action_category,
                    actor_type,
                    actor_id,
                    actor_name,
                    summary,
                    metadata,
                    created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            """,
                investigation_id,
                "security_flag_added",
                "security",
                "system",
                "guardrails",
                "Chat Guardrails",
                f"Chat flagged for security review: {reason}",
                json_module.dumps({
                    "violation_type": violation_type.value,
                    "reason": reason,
                    "user_id": user_id,
                    "username": username,
                    "guardrail_version": GUARDRAIL_VERSION
                })
            )

            # 3. Add a system note to the chat (use UUID for investigation_chat table)
            from middleware.tenant_middleware import get_optional_tenant_id
            _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
            await conn.execute("""
                INSERT INTO investigation_chat (
                    investigation_id,
                    sender_type,
                    sender_id,
                    sender_name,
                    message,
                    message_type,
                    created_at,
                    tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
            """,
                inv_uuid,  # Use UUID, not string investigation_id
                "system",
                "guardrails",
                "Security System",
                f"⚠️ **Security Alert**: A manipulation attempt was detected and blocked. "
                f"This chat session has been flagged for admin review. "
                f"Reason: {reason}",
                "system",
                _tid
            )

            logger.warning(
                f"[SECURITY FLAG] Investigation {investigation_id} flagged for review. "
                f"User: {username} ({user_id}), Violation: {violation_type.value}, "
                f"Reason: {reason}"
            )

            return True

    except Exception as e:
        logger.error(f"Failed to flag chat for security review: {e}")
        return False


async def get_flagged_chats(limit: int = 50, include_resolved: bool = False) -> List[Dict]:
    """
    Get list of chats flagged for security review.

    Args:
        limit: Max number of results
        include_resolved: Whether to include already-reviewed flags

    Returns:
        List of flagged investigations with flag details
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            query = """
                SELECT
                    i.investigation_id,
                    i.alert_title,
                    i.state,
                    i.security_flags,
                    i.created_at,
                    i.updated_at
                FROM investigations i
                WHERE i.security_flags IS NOT NULL
                  AND jsonb_array_length(i.security_flags) > 0
            """

            if not include_resolved:
                # Only show flags that still require review
                query += """
                  AND EXISTS (
                      SELECT 1 FROM jsonb_array_elements(i.security_flags) AS flag
                      WHERE (flag->>'requires_review')::boolean = true
                  )
                """

            query += " ORDER BY i.updated_at DESC LIMIT $1"

            rows = await conn.fetch(query, limit)

            return [
                {
                    "investigation_id": row["investigation_id"],
                    "alert_title": row["alert_title"],
                    "state": row["state"],
                    "security_flags": row["security_flags"],
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                    "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
                }
                for row in rows
            ]

    except Exception as e:
        logger.error(f"Failed to get flagged chats: {e}")
        return []


async def resolve_security_flag(
    investigation_id: str,
    admin_user_id: str,
    admin_username: str,
    resolution_notes: str
) -> bool:
    """
    Mark security flags on an investigation as resolved.

    Args:
        investigation_id: The flagged investigation
        admin_user_id: Admin resolving the flag
        admin_username: Admin's username
        resolution_notes: Notes about the resolution

    Returns:
        True if resolved, False otherwise
    """
    try:
        from services.postgres_db import postgres_db
        import json as json_module

        async with postgres_db.tenant_acquire() as conn:
            # Get current flags
            row = await conn.fetchrow(
                "SELECT security_flags FROM investigations WHERE investigation_id = $1",
                investigation_id
            )

            if not row or not row["security_flags"]:
                return False

            flags = row["security_flags"]
            if isinstance(flags, str):
                flags = json_module.loads(flags)

            # Mark all flags as resolved
            for flag in flags:
                flag["requires_review"] = False
                flag["resolved_at"] = datetime.utcnow().isoformat()
                flag["resolved_by"] = admin_user_id
                flag["resolved_by_name"] = admin_username
                flag["resolution_notes"] = resolution_notes

            # Update the flags
            await conn.execute("""
                UPDATE investigations
                SET security_flags = $2::jsonb,
                    updated_at = NOW()
                WHERE investigation_id = $1
            """, investigation_id, json_module.dumps(flags))

            # Log the resolution
            await conn.execute("""
                INSERT INTO investigation_audit_log (
                    investigation_id,
                    action,
                    action_category,
                    actor_type,
                    actor_id,
                    actor_name,
                    summary,
                    metadata,
                    created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            """,
                investigation_id,
                "security_flag_resolved",
                "security",
                "human",
                admin_user_id,
                admin_username,
                f"Security flags resolved: {resolution_notes}",
                json_module.dumps({
                    "resolution_notes": resolution_notes,
                    "flags_resolved": len(flags)
                })
            )

            logger.info(
                f"[SECURITY FLAG] Resolved flags on {investigation_id} by {admin_username}: {resolution_notes}"
            )

            return True

    except Exception as e:
        logger.error(f"Failed to resolve security flag: {e}")
        return False
