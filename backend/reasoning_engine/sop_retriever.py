# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
SOP Retriever - Reference-Only Supplemental Context

SOPs exist but are NEVER authoritative.
They are retrieved ONLY when reasoning stalls.
They provide context, not procedures.

BLOCKED:
- Step-by-step procedures
- Decision trees
- Required actions
- SOP citations as authority ("According to SOP-PHISH-001...")

ALLOWED:
- Common pitfalls
- Known edge cases
- Environmental considerations
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class SOPReference:
    """SOP reference material (NOT procedures)."""
    id: str
    name: str
    alert_types: List[str]  # Alert types this SOP relates to

    # ALLOWED fields
    common_pitfalls: str = ""
    environmental_notes: str = ""
    edge_cases: str = ""
    context_hints: Dict[str, str] = field(default_factory=dict)  # gap -> hint

    # Metadata
    version: int = 1
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# SOP REFERENCE CONTENT
# =============================================================================
# These are extracted from SOPs but contain ONLY contextual knowledge,
# NOT procedures. They are for reference when reasoning stalls.

SOP_REFERENCES = [
    SOPReference(
        id="sop_phishing",
        name="Phishing Investigation Context",
        alert_types=["phishing", "suspicious_email", "credential_phishing"],
        common_pitfalls=(
            "Don't trust clean VirusTotal scores for new URLs - many phishing sites are too new to be flagged. "
            "Check if the sender domain is lookalike (typosquatting) before dismissing. "
            "Some legitimate services send emails that look suspicious - check marketing platforms, surveys."
        ),
        environmental_notes=(
            "Finance and HR users are frequent phishing targets. "
            "Executive assistants often receive legitimate but unusual requests. "
            "Password reset emails from internal systems may be legitimate."
        ),
        edge_cases=(
            "Legitimate CDN-hosted content can be used for phishing. "
            "URL shorteners may hide malicious destinations. "
            "Compromised legitimate accounts may send real phishing."
        ),
        context_hints={
            "sender_reputation": "Check if sender domain age < 30 days or uses free email service",
            "url_analysis": "Defanged URLs may miss redirect chains - check final destination",
            "user_action": "Did user click? Did they enter credentials? Check proxy logs."
        }
    ),
    SOPReference(
        id="sop_malware",
        name="Malware Investigation Context",
        alert_types=["malware", "suspicious_file", "ransomware", "trojan"],
        common_pitfalls=(
            "Don't assume single hash detection means limited scope - check for variants. "
            "File names can be deceiving - focus on hash and behavior. "
            "Cleanup without understanding persistence may result in re-infection."
        ),
        environmental_notes=(
            "Developer workstations may have unusual executables (compilers, debug tools). "
            "Security tools may trigger false positives on red team tools. "
            "IT admin machines may have legitimate remote access tools."
        ),
        edge_cases=(
            "Packed/encrypted malware may have low detection rates. "
            "Living-off-the-land techniques use legitimate system tools. "
            "File-less malware won't have hash-based IOCs."
        ),
        context_hints={
            "file_origin": "How did the file arrive? Email, download, USB, network share?",
            "execution_context": "Was it user-initiated or automatic? Check parent process.",
            "persistence": "Check scheduled tasks, services, registry run keys, startup folders."
        }
    ),
    SOPReference(
        id="sop_lateral_movement",
        name="Lateral Movement Context",
        alert_types=["lateral_movement", "suspicious_login", "pass_the_hash"],
        common_pitfalls=(
            "Multiple hosts doesn't always mean attack - could be IT maintenance. "
            "Service accounts legitimately access many systems. "
            "Check timing - batch jobs vs interactive sessions."
        ),
        environmental_notes=(
            "Domain controllers naturally receive many authentication requests. "
            "Jump servers/bastion hosts have unusual login patterns. "
            "Backup systems access many endpoints legitimately."
        ),
        edge_cases=(
            "Kerberos ticket reuse may not generate new login events. "
            "RDP with Network Level Auth may obscure source. "
            "Legitimate admin tools (SCCM, SCOM) can look like lateral movement."
        ),
        context_hints={
            "authentication_chain": "Map source -> destination -> actions taken",
            "account_type": "Is this a user account, service account, or admin account?",
            "time_context": "Does this match normal business hours for this user/system?"
        }
    ),
    SOPReference(
        id="sop_data_exfil",
        name="Data Exfiltration Context",
        alert_types=["data_exfiltration", "dlp_violation", "large_transfer"],
        common_pitfalls=(
            "Large transfers aren't always exfil - check for legitimate cloud sync. "
            "Encrypted traffic to unknown destinations needs more scrutiny. "
            "DLP alerts may miss exfil via approved channels."
        ),
        environmental_notes=(
            "Sales teams legitimately share large files with external parties. "
            "Development teams may upload to cloud repositories. "
            "Marketing often uses third-party file sharing."
        ),
        edge_cases=(
            "Steganography can hide data in images. "
            "DNS tunneling can exfil data slowly but steadily. "
            "Approved cloud storage can be used for exfil."
        ),
        context_hints={
            "destination_analysis": "Is the destination a known service or unknown IP?",
            "data_classification": "What type of data was involved? PII, IP, financial?",
            "user_context": "Does this user normally handle this type of data?"
        }
    ),
    SOPReference(
        id="sop_credential_compromise",
        name="Credential Compromise Context",
        alert_types=["credential_theft", "brute_force", "password_spray"],
        common_pitfalls=(
            "Single failed login isn't attack - users mistype passwords. "
            "Successful login after failures may be user remembering correct password. "
            "Password sprays are slow and may not trigger lockouts."
        ),
        environmental_notes=(
            "Mobile devices with cached credentials cause repeated auth attempts. "
            "Application service accounts may have retry logic. "
            "VPN disconnects cause re-authentication storms."
        ),
        edge_cases=(
            "Pass-the-hash attacks don't involve the actual password. "
            "Kerberoasting targets service account hashes. "
            "Credential stuffing uses previously leaked passwords."
        ),
        context_hints={
            "attack_pattern": "Is this targeted (one account) or broad (many accounts)?",
            "source_analysis": "Single source or distributed? Tor exit nodes?",
            "account_value": "What access does this account have if compromised?"
        }
    ),
]


class SOPRetriever:
    """
    Retrieves SOP reference context when reasoning stalls.

    SOPs are reference material ONLY. Never authoritative.
    Never cite SOPs as authority in reasoning.
    """

    # Hard limits - LOCKED
    MAX_SOP_TOKENS = 200
    STALL_THRESHOLD = 2  # Iterations without confidence increase

    def __init__(self):
        self._sop_references: Dict[str, SOPReference] = {}
        self._load_references()

    def _load_references(self) -> None:
        """Load SOP references."""
        for sop in SOP_REFERENCES:
            self._sop_references[sop.id] = sop
            # Also index by alert type
            for alert_type in sop.alert_types:
                self._sop_references[f"alert:{alert_type}"] = sop
        logger.info(f"[SOP] Loaded {len(SOP_REFERENCES)} SOP references")

    def should_retrieve_sop(self, confidence_history: List[int]) -> bool:
        """
        Check if SOP reference should be retrieved.

        Only retrieve if reasoning is STALLED (confidence not improving).
        """
        if len(confidence_history) < self.STALL_THRESHOLD:
            return False

        recent = confidence_history[-self.STALL_THRESHOLD:]
        improvement = recent[-1] - recent[0]

        # Stalled = less than 5% improvement over threshold iterations
        return improvement < 5

    def get_sop_context(
        self,
        alert_type: str,
        current_gaps: List[str]
    ) -> Optional[str]:
        """
        Get SOP reference context for an alert type.

        Returns summarized context, NOT procedures.
        Never returns step-by-step instructions.

        Args:
            alert_type: Type of alert
            current_gaps: Current evidence gaps

        Returns:
            Summarized context string, or None if no relevant SOP
        """
        # Find relevant SOP
        sop = self._sop_references.get(f"alert:{alert_type}")
        if not sop:
            # Try partial match
            for ref in SOP_REFERENCES:
                if any(at in alert_type.lower() for at in ref.alert_types):
                    sop = ref
                    break

        if not sop:
            return None

        # Build context (NOT procedures)
        context_parts = []

        if sop.common_pitfalls:
            context_parts.append(f"Known pitfalls: {sop.common_pitfalls}")

        if sop.edge_cases:
            context_parts.append(f"Edge cases: {sop.edge_cases}")

        # Add relevant hints for current gaps
        if sop.context_hints and current_gaps:
            relevant_hints = []
            for gap in current_gaps:
                for hint_key, hint_text in sop.context_hints.items():
                    if hint_key in gap.lower() or gap.lower() in hint_key:
                        relevant_hints.append(hint_text)
            if relevant_hints:
                context_parts.append(f"Relevant context: {'; '.join(relevant_hints[:3])}")

        if not context_parts:
            return None

        # Combine and truncate
        full_context = " ".join(context_parts)
        return self._truncate(full_context)

    def _truncate(self, text: str) -> str:
        """Truncate to token limit."""
        max_chars = self.MAX_SOP_TOKENS * 4  # Rough estimate
        if len(text) > max_chars:
            return text[:max_chars] + "..."
        return text

    def format_for_prompt(self, sop_context: str) -> str:
        """
        Format SOP context for prompt injection.

        Includes explicit disclaimer that this is NOT authoritative.
        """
        if not sop_context:
            return ""

        return (
            f"SUPPLEMENTAL CONTEXT (reference only, not authoritative):\n"
            f"{sop_context}\n\n"
            f"Note: This context may inform your analysis but does not override "
            f"evidence-based reasoning or confidence assessments."
        )

    def list_available_sops(self) -> List[Dict[str, Any]]:
        """List available SOP references."""
        return [
            {
                "id": sop.id,
                "name": sop.name,
                "alert_types": sop.alert_types,
                "version": sop.version
            }
            for sop in SOP_REFERENCES
        ]


# =============================================================================
# SINGLETON
# =============================================================================

_sop_retriever: Optional[SOPRetriever] = None


def get_sop_retriever() -> SOPRetriever:
    """Get the global SOP retriever instance."""
    global _sop_retriever
    if _sop_retriever is None:
        _sop_retriever = SOPRetriever()
    return _sop_retriever
