# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Enhanced IOC Extraction with Auto-Linking
"""

import re
from typing import Dict, List, Any
from datetime import datetime


class EnhancedIOCExtractor:
    """
    Extract IOCs from text and automatically link to alerts/investigations
    """

    def __init__(self):
        self.patterns = {
            "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "filename": r'\b[\w\-]+\.(exe|dll|bat|ps1|sh|py|jar|doc|docx|xls|xlsx|pdf|zip|rar|7z)\b',
            "cve": r'CVE-\d{4}-\d{4,7}',
        }

        # Hash context indicators - words that suggest a hex string is actually a hash
        self.hash_context_keywords = [
            'hash', 'md5', 'sha1', 'sha256', 'sha512', 'checksum', 'fingerprint',
            'file_hash', 'filehash', 'malware', 'sample', 'ioc', 'indicator'
        ]
    
    def extract_all(self, text: str, metadata: Dict[str, Any] = None) -> Dict[str, List[str]]:
        """
        Extract all IOC types from text.

        Args:
            text: Text to extract IOCs from
            metadata: Optional metadata dict (may contain pre-extracted IOCs)

        Returns:
            Dict mapping IOC type to list of unique values
        """
        indicators = {}

        if not text:
            text = ""

        # First pass: Extract URLs to identify embedded hex strings
        urls = re.findall(self.patterns["url"], text, re.IGNORECASE)
        embedded_hex_strings = set()
        for url in urls:
            # Find all hex strings embedded in URLs (these are NOT hashes)
            for hex_match in re.findall(r'[a-fA-F0-9]{32,64}', url):
                embedded_hex_strings.add(hex_match.lower())

        # Extract from text
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Deduplicate and filter
                unique_matches = list(set(matches))
                # Filter out common false positives (pass embedded hex strings for hash filtering)
                filtered = self._filter_false_positives(ioc_type, unique_matches, text, embedded_hex_strings)
                if filtered:
                    indicators[ioc_type] = filtered
        
        # Add IOCs from metadata if provided
        if metadata:
            for key in ["ip", "domain", "hash", "email", "url", "file"]:
                if key in metadata:
                    value = metadata[key]
                    if isinstance(value, list):
                        if key not in indicators:
                            indicators[key] = []
                        indicators[key].extend(value)
                    elif isinstance(value, str):
                        if key not in indicators:
                            indicators[key] = []
                        indicators[key].append(value)
        
        # Deduplicate final results
        for ioc_type in indicators:
            indicators[ioc_type] = list(set(indicators[ioc_type]))
        
        return indicators
    
    def _filter_false_positives(self, ioc_type: str, values: List[str], text: str = "", embedded_hex: set = None) -> List[str]:
        """Filter out common false positives"""
        filtered = []
        embedded_hex = embedded_hex or set()
        text_lower = text.lower()

        for value in values:
            # Skip obvious false positives
            if ioc_type == "ip":
                # Skip localhost, private ranges for now (could be legit but noisy)
                if value.startswith("127.") or value.startswith("0."):
                    continue

            elif ioc_type == "domain":
                # Skip very common domains and localhost
                common = ["localhost", "example.com", "example.org", "test.com"]
                if value.lower() in common:
                    continue
                # Skip if it looks like a filename
                if value.endswith(".exe") or value.endswith(".dll"):
                    continue

            elif ioc_type == "email":
                # Skip example emails
                if "example.com" in value.lower() or "test.com" in value.lower():
                    continue

            elif ioc_type in ("md5", "sha1", "sha256"):
                # Skip hex strings that are embedded in URLs (these are identifiers, not hashes)
                if value.lower() in embedded_hex:
                    continue

                # Skip if it appears as part of a filename (e.g., "abc123def456.png")
                # Check if the hex string is followed by a file extension
                hex_with_ext_pattern = re.compile(
                    re.escape(value) + r'\.(png|jpg|jpeg|gif|bmp|pdf|html|htm|php|asp|aspx|js|css|json|xml|txt)',
                    re.IGNORECASE
                )
                if hex_with_ext_pattern.search(text):
                    continue

                # Skip if it appears in a URL path context (after / or before /)
                # This catches cases like "/office/abc123def456/" or "path/abc123def456.png"
                in_path_pattern = re.compile(r'[/\\]' + re.escape(value) + r'[/\\.]', re.IGNORECASE)
                if in_path_pattern.search(text):
                    continue

                # For extra safety with MD5 (most false positives), require hash context
                # unless the hash appears standalone (not in URL-like context)
                if ioc_type == "md5":
                    # Check if there's hash-related context nearby
                    has_hash_context = any(kw in text_lower for kw in self.hash_context_keywords)
                    # Check if it looks like it's in a URL or path
                    url_context_pattern = re.compile(r'https?://[^\s]*' + re.escape(value), re.IGNORECASE)
                    in_url_context = url_context_pattern.search(text)

                    # Skip MD5 if it's in URL context and there's no hash keyword
                    if in_url_context and not has_hash_context:
                        continue

            filtered.append(value)

        return filtered
    
    async def extract_and_track(
        self,
        text: str,
        metadata: Dict[str, Any],
        db_service,
        alert_id: str = None,
        investigation_id: str = None,
        severity: str = "medium"
    ) -> Dict[str, List[str]]:
        """
        Extract IOCs and automatically track them in database.
        
        Args:
            text: Text to extract from
            metadata: Alert/investigation metadata
            db_service: Database service instance
            alert_id: Optional alert ID to link
            investigation_id: Optional investigation ID to link
            severity: Severity level for new IOCs
        
        Returns:
            Dict of extracted IOCs
        """
        # Extract IOCs
        indicators = self.extract_all(text, metadata)
        
        # Map extractor type names to DB CHECK constraint values
        type_map = {"md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256", "filename": "file_path"}

        # Track each IOC
        for ioc_type, ioc_values in indicators.items():
            db_type = type_map.get(ioc_type, ioc_type)
            for ioc_value in ioc_values:
                try:
                    ioc_data = {
                        "ioc_value": ioc_value,
                        "ioc_type": db_type,
                        "severity": severity,
                        "source": "auto_extraction",
                        "source_type": "event",
                        "source_id": str(alert_id) if alert_id else None,
                    }

                    if alert_id:
                        ioc_data["alert_id"] = alert_id

                    if investigation_id:
                        ioc_data["investigation_id"] = investigation_id

                    await db_service.track_or_update_ioc(ioc_data)

                except Exception as e:
                    print(f"[WARN] Failed to track IOC {ioc_value}: {e}")
        
        return indicators
    
    def determine_severity(self, verdict: str) -> str:
        """
        Determine IOC severity based on investigation verdict.
        
        Args:
            verdict: Investigation verdict (Malicious, Suspicious, Benign, Inconclusive)
        
        Returns:
            Severity level (critical, high, medium, low)
        """
        verdict_to_severity = {
            "Malicious": "critical",
            "Suspicious": "high",
            "Inconclusive": "medium",
            "Benign": "low"
        }
        
        return verdict_to_severity.get(verdict, "medium")


# Global extractor instance
ioc_extractor = EnhancedIOCExtractor()
