# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Log Parser Service
Detects and parses multiple log formats including JSON, XML, CSV, Syslog, CEF, LEEF, etc.
"""

import json
import re
import logging
from enum import Enum
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class LogFormat(Enum):
    """Supported log formats"""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_RFC5424 = "syslog_rfc5424"
    CEF = "cef"
    LEEF = "leef"
    WINDOWS_EVENT = "windows_event"
    KEY_VALUE = "key_value"
    PLAIN_TEXT = "plain_text"


class LogParser:
    """
    Multi-format log parser that auto-detects and parses various log formats.
    """

    # CEF pattern: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    CEF_PATTERN = re.compile(r'^CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|')

    # LEEF pattern: LEEF:Version|Vendor|Product|Version|EventID|
    LEEF_PATTERN = re.compile(r'^LEEF:\d+\.\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|')

    # Syslog RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    SYSLOG_RFC3164_PATTERN = re.compile(r'^<\d{1,3}>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')

    # Syslog RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
    SYSLOG_RFC5424_PATTERN = re.compile(r'^<\d{1,3}>\d\s+\d{4}-\d{2}-\d{2}T')

    # Key-value pattern
    KV_PATTERN = re.compile(r'^\s*\w+\s*[=:]\s*[^\s]+')

    async def parse(
        self,
        content: str,
        content_type: Optional[str] = None,
        source_hint: Optional[str] = None
    ) -> Tuple[Dict[str, Any], LogFormat, Dict[str, Any]]:
        """
        Parse log content, auto-detecting format.

        Args:
            content: Raw log content
            content_type: HTTP Content-Type header hint
            source_hint: Optional hint about the log source

        Returns:
            Tuple of (parsed_payload, detected_format, parse_metadata)
        """
        content = content.strip()
        metadata = {
            'original_length': len(content),
            'content_type_hint': content_type,
            'source_hint': source_hint,
            'parsed_at': datetime.utcnow().isoformat()
        }

        # Detect format
        detected_format = self._detect_format(content, content_type)
        metadata['detected_format'] = detected_format.value

        # Parse based on detected format
        try:
            if detected_format == LogFormat.JSON:
                payload = self._parse_json(content)
            elif detected_format == LogFormat.XML:
                payload = self._parse_xml(content)
            elif detected_format == LogFormat.CEF:
                payload = self._parse_cef(content)
            elif detected_format == LogFormat.LEEF:
                payload = self._parse_leef(content)
            elif detected_format == LogFormat.SYSLOG_RFC3164:
                payload = self._parse_syslog_rfc3164(content)
            elif detected_format == LogFormat.SYSLOG_RFC5424:
                payload = self._parse_syslog_rfc5424(content)
            elif detected_format == LogFormat.KEY_VALUE:
                payload = self._parse_key_value(content)
            elif detected_format == LogFormat.CSV:
                payload = self._parse_csv(content)
            elif detected_format == LogFormat.WINDOWS_EVENT:
                payload = self._parse_windows_event(content)
            else:
                payload = self._parse_plain_text(content)

            metadata['parse_success'] = True

        except Exception as e:
            logger.warning(f"Failed to parse as {detected_format.value}, falling back to plain text: {e}")
            payload = self._parse_plain_text(content)
            metadata['parse_success'] = False
            metadata['parse_error'] = str(e)
            detected_format = LogFormat.PLAIN_TEXT

        return payload, detected_format, metadata

    def _detect_format(self, content: str, content_type: Optional[str] = None) -> LogFormat:
        """Detect the log format based on content and hints."""

        # Content-type hints
        if content_type:
            ct_lower = content_type.lower()
            if 'json' in ct_lower:
                return LogFormat.JSON
            elif 'xml' in ct_lower:
                return LogFormat.XML
            elif 'csv' in ct_lower:
                return LogFormat.CSV

        # Try JSON first (most common)
        if content.startswith('{') or content.startswith('['):
            try:
                json.loads(content)
                return LogFormat.JSON
            except json.JSONDecodeError:
                pass

        # XML detection
        if content.startswith('<?xml') or content.startswith('<'):
            if '<Event' in content and '</Event>' in content:
                return LogFormat.WINDOWS_EVENT
            return LogFormat.XML

        # CEF detection
        if self.CEF_PATTERN.match(content):
            return LogFormat.CEF

        # LEEF detection
        if self.LEEF_PATTERN.match(content):
            return LogFormat.LEEF

        # Syslog detection
        if self.SYSLOG_RFC5424_PATTERN.match(content):
            return LogFormat.SYSLOG_RFC5424
        if self.SYSLOG_RFC3164_PATTERN.match(content):
            return LogFormat.SYSLOG_RFC3164

        # Key-value detection (multiple key=value pairs)
        kv_matches = re.findall(r'\w+\s*[=:]\s*(?:"[^"]*"|\'[^\']*\'|[^\s,;]+)', content)
        if len(kv_matches) >= 3:
            return LogFormat.KEY_VALUE

        # CSV detection (comma-separated with consistent columns)
        lines = content.split('\n')
        if len(lines) >= 2:
            first_commas = lines[0].count(',')
            if first_commas >= 2 and all(line.count(',') == first_commas for line in lines[:5] if line.strip()):
                return LogFormat.CSV

        return LogFormat.PLAIN_TEXT

    def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON content."""
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return {'events': parsed, '_is_batch': True}
        return parsed

    def _parse_xml(self, content: str) -> Dict[str, Any]:
        """Parse XML content to dict."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            return self._xml_to_dict(root)
        except Exception as e:
            return {'raw_xml': content, '_parse_error': str(e)}

    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}

        # Add attributes
        if element.attrib:
            result['@attributes'] = dict(element.attrib)

        # Add children
        for child in element:
            child_data = self._xml_to_dict(child)
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag

            if tag in result:
                if isinstance(result[tag], list):
                    result[tag].append(child_data)
                else:
                    result[tag] = [result[tag], child_data]
            else:
                result[tag] = child_data

        # Add text content
        if element.text and element.text.strip():
            if result:
                result['#text'] = element.text.strip()
            else:
                return element.text.strip()

        return result or (element.text.strip() if element.text else '')

    def _parse_cef(self, content: str) -> Dict[str, Any]:
        """Parse CEF (Common Event Format)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        parts = content.split('|', 7)

        result = {
            'cef_version': parts[0].replace('CEF:', '') if len(parts) > 0 else '',
            'device_vendor': parts[1] if len(parts) > 1 else '',
            'device_product': parts[2] if len(parts) > 2 else '',
            'device_version': parts[3] if len(parts) > 3 else '',
            'signature_id': parts[4] if len(parts) > 4 else '',
            'name': parts[5] if len(parts) > 5 else '',
            'severity': parts[6] if len(parts) > 6 else '',
        }

        # Parse extension (key=value pairs)
        if len(parts) > 7:
            extension = parts[7]
            result['extension'] = self._parse_cef_extension(extension)

        return result

    def _parse_cef_extension(self, extension: str) -> Dict[str, str]:
        """Parse CEF extension key=value pairs."""
        result = {}
        # Handle both space-separated and custom delimiters
        pairs = re.findall(r'(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)', extension)
        for key, value in pairs:
            result[key] = value.strip()
        return result

    def _parse_leef(self, content: str) -> Dict[str, Any]:
        """Parse LEEF (Log Event Extended Format)."""
        # LEEF:Version|Vendor|Product|Version|EventID|key=value pairs
        parts = content.split('|', 5)

        result = {
            'leef_version': parts[0].replace('LEEF:', '') if len(parts) > 0 else '',
            'vendor': parts[1] if len(parts) > 1 else '',
            'product': parts[2] if len(parts) > 2 else '',
            'version': parts[3] if len(parts) > 3 else '',
            'event_id': parts[4] if len(parts) > 4 else '',
        }

        # Parse attributes
        if len(parts) > 5:
            result['attributes'] = self._parse_key_value(parts[5])

        return result

    def _parse_syslog_rfc3164(self, content: str) -> Dict[str, Any]:
        """Parse Syslog RFC 3164 format."""
        # <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        match = re.match(
            r'^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)$',
            content,
            re.DOTALL
        )

        if match:
            pri = int(match.group(1))
            return {
                'facility': pri >> 3,
                'severity': pri & 7,
                'timestamp': match.group(2),
                'hostname': match.group(3),
                'tag': match.group(4),
                'message': match.group(5),
                '_format': 'syslog_rfc3164'
            }

        return {'raw_message': content, '_format': 'syslog_rfc3164'}

    def _parse_syslog_rfc5424(self, content: str) -> Dict[str, Any]:
        """Parse Syslog RFC 5424 format."""
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        match = re.match(
            r'^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\[.*?\])?\s*(.*)$',
            content,
            re.DOTALL
        )

        if match:
            pri = int(match.group(1))
            return {
                'facility': pri >> 3,
                'severity': pri & 7,
                'version': match.group(2),
                'timestamp': match.group(3),
                'hostname': match.group(4),
                'app_name': match.group(5),
                'proc_id': match.group(6),
                'msg_id': match.group(7),
                'structured_data': match.group(8) or '-',
                'message': match.group(9),
                '_format': 'syslog_rfc5424'
            }

        return {'raw_message': content, '_format': 'syslog_rfc5424'}

    def _parse_key_value(self, content: str) -> Dict[str, Any]:
        """Parse key=value or key:value pairs."""
        result = {}

        # Match key=value or key:"value" or key:'value'
        pairs = re.findall(
            r'(\w+)\s*[=:]\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s,;]+))',
            content
        )

        for match in pairs:
            key = match[0]
            value = match[1] or match[2] or match[3]
            result[key] = value

        return result

    def _parse_csv(self, content: str) -> Dict[str, Any]:
        """Parse CSV content."""
        lines = content.strip().split('\n')
        if len(lines) < 2:
            return {'raw_csv': content}

        # First line as headers
        headers = [h.strip().strip('"') for h in lines[0].split(',')]

        events = []
        for line in lines[1:]:
            if not line.strip():
                continue
            values = [v.strip().strip('"') for v in line.split(',')]
            event = dict(zip(headers, values))
            events.append(event)

        if len(events) == 1:
            return events[0]
        return {'events': events, '_is_batch': True}

    def _parse_windows_event(self, content: str) -> Dict[str, Any]:
        """Parse Windows Event Log XML."""
        result = self._parse_xml(content)
        result['_format'] = 'windows_event'
        return result

    def _parse_plain_text(self, content: str) -> Dict[str, Any]:
        """Parse plain text as raw message."""
        return {
            'raw_message': content,
            'message': content,
            '_format': 'plain_text'
        }


# Singleton instance
_log_parser: Optional[LogParser] = None


def get_log_parser() -> LogParser:
    """Get the log parser singleton."""
    global _log_parser
    if _log_parser is None:
        _log_parser = LogParser()
    return _log_parser
