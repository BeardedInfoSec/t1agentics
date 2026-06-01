# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
File Metadata Extraction Service

Extracts metadata from various file types:
- PE files (EXE, DLL): imports, exports, sections, timestamps
- Documents (PDF, Office): author, creation date, embedded content
- Images: EXIF data, dimensions
- Archives: contents listing
- Scripts: extracted strings, potential IOCs
"""

import os
import re
import struct
import logging
import mimetypes
import hashlib
import email
from email import policy
from email.parser import BytesParser
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class FileMetadata:
    """Extracted file metadata"""
    file_type: str
    mime_type: str
    file_size: int
    magic_bytes: str

    # Common metadata
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    author: Optional[str] = None

    # PE specific
    pe_info: Optional[Dict[str, Any]] = None

    # Document specific
    doc_info: Optional[Dict[str, Any]] = None

    # Archive specific
    archive_info: Optional[Dict[str, Any]] = None

    # Image specific
    image_info: Optional[Dict[str, Any]] = None

    # Email specific
    email_info: Optional[Dict[str, Any]] = None

    # Extracted IOCs
    extracted_strings: Optional[List[str]] = None
    potential_iocs: Optional[Dict[str, List[str]]] = None

    # Warnings/alerts
    warnings: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class FileMetadataExtractor:
    """
    Extracts metadata from files.

    Uses pure Python implementations where possible to avoid
    dependencies on external tools.
    """

    # IOC patterns
    IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    DOMAIN_PATTERN = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b')
    URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    # PE file magic
    PE_MAGIC = b'MZ'
    PE_SIGNATURE = b'PE\x00\x00'

    # Common file magics
    FILE_MAGICS = {
        b'PK\x03\x04': 'zip',
        b'%PDF': 'pdf',
        b'\x1f\x8b': 'gzip',
        b'BZ': 'bzip2',
        b'\x89PNG': 'png',
        b'\xff\xd8\xff': 'jpeg',
        b'GIF8': 'gif',
        b'Rar!\x1a\x07': 'rar',
        b'7z\xbc\xaf': '7z',
    }

    async def extract(
        self,
        file_data: bytes,
        filename: str,
        mime_type: str = None
    ) -> Dict[str, Any]:
        """
        Extract metadata from file data.

        Args:
            file_data: Raw file bytes
            filename: Original filename
            mime_type: MIME type if known

        Returns:
            Dict with extracted metadata
        """
        warnings = []

        # Detect file type
        detected_type = self._detect_file_type(file_data)
        if not mime_type:
            mime_type, _ = mimetypes.guess_type(filename)
            mime_type = mime_type or 'application/octet-stream'

        # Get magic bytes
        magic_bytes = file_data[:8].hex() if len(file_data) >= 8 else file_data.hex()

        metadata = FileMetadata(
            file_type=detected_type or Path(filename).suffix.lower(),
            mime_type=mime_type,
            file_size=len(file_data),
            magic_bytes=magic_bytes,
            warnings=warnings
        )

        # Extract type-specific metadata
        ext = Path(filename).suffix.lower()

        if self._is_pe_file(file_data):
            metadata.pe_info = self._extract_pe_metadata(file_data)
            if metadata.pe_info.get('is_suspicious'):
                warnings.append("PE file has suspicious characteristics")

        elif ext in ['.pdf']:
            metadata.doc_info = self._extract_pdf_metadata(file_data)

        elif ext in ['.zip', '.docx', '.xlsx', '.pptx']:
            metadata.archive_info = self._extract_archive_metadata(file_data)

        elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            metadata.image_info = self._extract_image_metadata(file_data)

        elif ext in ['.eml', '.msg']:
            metadata.email_info = self._extract_email_metadata(file_data, ext)
            # Extract IOCs from email content
            if metadata.email_info:
                email_text = metadata.email_info.get('body_text', '') or ''
                email_text += ' ' + metadata.email_info.get('subject', '') or ''
                metadata.potential_iocs = self._extract_iocs(email_text)
                # Check for suspicious indicators
                if metadata.email_info.get('has_attachments'):
                    warnings.append("Email contains attachments")
                if metadata.email_info.get('has_html_body'):
                    warnings.append("Email contains HTML content")
                if metadata.email_info.get('suspicious_headers'):
                    warnings.append("Email has suspicious headers")

        # Extract strings and IOCs from text-based files
        if ext in ['.txt', '.log', '.csv', '.json', '.xml', '.ps1', '.bat', '.sh', '.py', '.js', '.vbs', '.html']:
            try:
                text_content = file_data.decode('utf-8', errors='ignore')
                metadata.extracted_strings = self._extract_interesting_strings(text_content)
                metadata.potential_iocs = self._extract_iocs(text_content)
            except Exception as e:
                logger.debug(f"Failed to extract strings: {e}")

        # For binary files, extract printable strings
        elif detected_type in ['pe', 'unknown'] or ext in ['.exe', '.dll', '.bin']:
            metadata.extracted_strings = self._extract_binary_strings(file_data)
            text_content = ' '.join(metadata.extracted_strings)
            metadata.potential_iocs = self._extract_iocs(text_content)

        metadata.warnings = warnings if warnings else None

        return metadata.to_dict()

    def _detect_file_type(self, data: bytes) -> Optional[str]:
        """Detect file type from magic bytes"""
        if len(data) < 4:
            return None

        # Check PE
        if data[:2] == self.PE_MAGIC:
            return 'pe'

        # Check other magics
        for magic, ftype in self.FILE_MAGICS.items():
            if data[:len(magic)] == magic:
                return ftype

        return None

    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is a PE (Windows executable)"""
        if len(data) < 64:
            return False
        if data[:2] != self.PE_MAGIC:
            return False

        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            if pe_offset + 4 > len(data):
                return False
            return data[pe_offset:pe_offset+4] == self.PE_SIGNATURE
        except:
            return False

    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract metadata from PE file"""
        info = {
            'is_pe': True,
            'is_suspicious': False,
            'sections': [],
            'imports': [],
            'characteristics': []
        }

        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]

            # Parse COFF header (starts at pe_offset + 4)
            coff_start = pe_offset + 4
            machine = struct.unpack('<H', data[coff_start:coff_start+2])[0]
            num_sections = struct.unpack('<H', data[coff_start+2:coff_start+4])[0]
            timestamp = struct.unpack('<I', data[coff_start+4:coff_start+8])[0]

            # Machine type
            machine_types = {
                0x14c: 'i386',
                0x8664: 'AMD64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64'
            }
            info['machine'] = machine_types.get(machine, f'Unknown (0x{machine:x})')

            # Compilation timestamp
            if timestamp > 0:
                info['compile_time'] = datetime.utcfromtimestamp(timestamp).isoformat()
                # Check for suspicious timestamps
                if timestamp < 946684800:  # Before year 2000
                    info['is_suspicious'] = True
                    info['characteristics'].append('suspicious_timestamp_old')
                elif timestamp > datetime.utcnow().timestamp():
                    info['is_suspicious'] = True
                    info['characteristics'].append('suspicious_timestamp_future')

            info['num_sections'] = num_sections

            # Get characteristics
            characteristics = struct.unpack('<H', data[coff_start+18:coff_start+20])[0]
            if characteristics & 0x0002:
                info['characteristics'].append('executable')
            if characteristics & 0x0020:
                info['characteristics'].append('large_address_aware')
            if characteristics & 0x2000:
                info['characteristics'].append('dll')

            # Check optional header for subsystem
            optional_start = coff_start + 20
            if len(data) > optional_start + 2:
                magic = struct.unpack('<H', data[optional_start:optional_start+2])[0]
                if magic == 0x10b:
                    info['pe_type'] = 'PE32'
                elif magic == 0x20b:
                    info['pe_type'] = 'PE32+'

        except Exception as e:
            logger.debug(f"PE parsing error: {e}")
            info['parse_error'] = str(e)

        return info

    def _extract_pdf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract metadata from PDF file"""
        info = {
            'is_pdf': True,
            'has_javascript': False,
            'has_embedded_files': False,
            'has_launch_action': False,
            'page_count': None
        }

        try:
            text = data.decode('latin-1', errors='ignore')

            # Check for JavaScript
            if '/JavaScript' in text or '/JS ' in text:
                info['has_javascript'] = True

            # Check for embedded files
            if '/EmbeddedFile' in text:
                info['has_embedded_files'] = True

            # Check for launch actions (suspicious)
            if '/Launch' in text:
                info['has_launch_action'] = True

            # Count pages
            page_count = text.count('/Type /Page')
            if page_count > 0:
                info['page_count'] = page_count

            # Extract metadata
            if '/Author' in text:
                match = re.search(r'/Author\s*\((.*?)\)', text)
                if match:
                    info['author'] = match.group(1)[:100]

            if '/Creator' in text:
                match = re.search(r'/Creator\s*\((.*?)\)', text)
                if match:
                    info['creator'] = match.group(1)[:100]

        except Exception as e:
            logger.debug(f"PDF parsing error: {e}")

        return info

    def _extract_archive_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract metadata from archive file with content hashing"""
        info = {
            'is_archive': True,
            'file_count': None,
            'contains_executables': False,
            'contents': []  # Detailed file info with hashes
        }

        # For ZIP files
        if data[:4] == b'PK\x03\x04':
            try:
                import zipfile
                import io

                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    names = zf.namelist()
                    info['file_count'] = len(names)
                    info['files'] = names[:20]  # First 20 files (for backwards compat)

                    # Check for executables and extract file details
                    exe_extensions = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.wsf'}
                    dangerous_files = []

                    for name in names[:50]:  # Process up to 50 files
                        try:
                            # Skip directories
                            if name.endswith('/'):
                                continue

                            file_info = zf.getinfo(name)
                            ext = Path(name).suffix.lower()

                            file_entry = {
                                'name': name,
                                'size': file_info.file_size,
                                'compressed_size': file_info.compress_size,
                                'is_encrypted': file_info.flag_bits & 0x1,  # Check encryption flag
                            }

                            # Check if dangerous
                            if ext in exe_extensions:
                                info['contains_executables'] = True
                                file_entry['is_dangerous'] = True
                                dangerous_files.append(name)

                            # Try to extract and hash the file (skip if encrypted or too large)
                            if file_info.file_size < 10 * 1024 * 1024 and not file_entry.get('is_encrypted'):  # 10MB limit
                                try:
                                    file_data = zf.read(name)
                                    file_entry['md5'] = hashlib.md5(file_data).hexdigest()
                                    file_entry['sha256'] = hashlib.sha256(file_data).hexdigest()

                                    # Detect file type from magic bytes
                                    detected_type = self._detect_file_type(file_data)
                                    if detected_type:
                                        file_entry['detected_type'] = detected_type
                                        # Flag if extension doesn't match detected type
                                        if detected_type == 'pe' and ext not in ['.exe', '.dll', '.scr', '.sys']:
                                            file_entry['type_mismatch'] = True
                                            file_entry['warning'] = f"File detected as PE executable but has {ext} extension"

                                except (RuntimeError, zipfile.BadZipFile) as e:
                                    file_entry['extraction_error'] = str(e)
                                    if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                                        file_entry['is_encrypted'] = True

                            info['contents'].append(file_entry)

                        except Exception as e:
                            logger.debug(f"Error processing archive entry {name}: {e}")

                    info['dangerous_files'] = dangerous_files if dangerous_files else None
                    info['is_password_protected'] = any(c.get('is_encrypted') for c in info['contents'])

            except zipfile.BadZipFile as e:
                info['error'] = f"Invalid ZIP file: {e}"
            except Exception as e:
                logger.debug(f"ZIP parsing error: {e}")
                info['error'] = str(e)

        # For GZIP files
        elif data[:2] == b'\x1f\x8b':
            try:
                import gzip
                import io

                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    decompressed = gz.read(10 * 1024 * 1024)  # 10MB limit
                    info['decompressed_size'] = len(decompressed)
                    info['contents'].append({
                        'name': 'decompressed_content',
                        'size': len(decompressed),
                        'md5': hashlib.md5(decompressed).hexdigest(),
                        'sha256': hashlib.sha256(decompressed).hexdigest(),
                        'detected_type': self._detect_file_type(decompressed)
                    })
            except Exception as e:
                logger.debug(f"GZIP parsing error: {e}")
                info['error'] = str(e)

        return info

    def _extract_image_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract metadata from image file"""
        info = {
            'is_image': True
        }

        # Get image dimensions for common formats
        try:
            # PNG
            if data[:8] == b'\x89PNG\r\n\x1a\n':
                width = struct.unpack('>I', data[16:20])[0]
                height = struct.unpack('>I', data[20:24])[0]
                info['width'] = width
                info['height'] = height
                info['format'] = 'PNG'

            # JPEG
            elif data[:2] == b'\xff\xd8':
                info['format'] = 'JPEG'
                # JPEG dimensions require parsing segments, skip for now

            # GIF
            elif data[:4] == b'GIF8':
                width = struct.unpack('<H', data[6:8])[0]
                height = struct.unpack('<H', data[8:10])[0]
                info['width'] = width
                info['height'] = height
                info['format'] = 'GIF'

        except Exception as e:
            logger.debug(f"Image parsing error: {e}")

        return info

    def _extract_email_metadata(self, data: bytes, ext: str) -> Dict[str, Any]:
        """
        Extract metadata from email files (.eml, .msg).

        Extracts:
        - Headers (From, To, Subject, Date, etc.)
        - Body content (text and HTML)
        - Attachments with hashes
        - Suspicious indicators
        """
        info = {
            'is_email': True,
            'format': ext.lstrip('.').upper(),
            'headers': {},
            'attachments': [],
            'has_attachments': False,
            'has_html_body': False,
            'suspicious_headers': False
        }

        if ext == '.eml':
            info = self._parse_eml(data, info)
        elif ext == '.msg':
            info = self._parse_msg(data, info)

        return info

    def _parse_eml(self, data: bytes, info: Dict[str, Any]) -> Dict[str, Any]:
        """Parse .eml (RFC 822) email format"""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(data)

            # Extract key headers
            header_fields = ['from', 'to', 'cc', 'bcc', 'subject', 'date',
                           'message-id', 'reply-to', 'return-path', 'received',
                           'x-originating-ip', 'x-mailer', 'user-agent']

            for field in header_fields:
                value = msg.get(field)
                if value:
                    # For 'received' headers, collect all of them
                    if field == 'received':
                        info['headers']['received'] = msg.get_all('received', [])[:10]
                    else:
                        info['headers'][field] = str(value)[:500]  # Limit length

            # Extract sender/recipient info
            info['from'] = info['headers'].get('from', '')
            info['to'] = info['headers'].get('to', '')
            info['subject'] = info['headers'].get('subject', '')
            info['date'] = info['headers'].get('date', '')

            # Check for suspicious headers
            suspicious_indicators = []

            # X-Originating-IP can indicate external origin
            if 'x-originating-ip' in info['headers']:
                suspicious_indicators.append('has_x_originating_ip')

            # Multiple received headers from unusual sources
            received_headers = info['headers'].get('received', [])
            if len(received_headers) > 5:
                suspicious_indicators.append('many_hops')

            # Check for header spoofing indicators
            from_header = info['headers'].get('from', '').lower()
            return_path = info['headers'].get('return-path', '').lower()
            if from_header and return_path and from_header != return_path:
                # Extract domains
                from_domain = self._extract_domain_from_email(from_header)
                return_domain = self._extract_domain_from_email(return_path)
                if from_domain and return_domain and from_domain != return_domain:
                    suspicious_indicators.append('from_return_path_mismatch')

            if suspicious_indicators:
                info['suspicious_headers'] = True
                info['suspicious_indicators'] = suspicious_indicators

            # Extract body
            body_text = ''
            body_html = ''

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))

                    # Skip attachments for body extraction
                    if 'attachment' in content_disposition:
                        continue

                    if content_type == 'text/plain':
                        try:
                            body_text = part.get_content()
                            if isinstance(body_text, bytes):
                                body_text = body_text.decode('utf-8', errors='ignore')
                        except:
                            pass
                    elif content_type == 'text/html':
                        info['has_html_body'] = True
                        try:
                            body_html = part.get_content()
                            if isinstance(body_html, bytes):
                                body_html = body_html.decode('utf-8', errors='ignore')
                        except:
                            pass
            else:
                content_type = msg.get_content_type()
                try:
                    content = msg.get_content()
                    if isinstance(content, bytes):
                        content = content.decode('utf-8', errors='ignore')
                    if content_type == 'text/html':
                        info['has_html_body'] = True
                        body_html = content
                    else:
                        body_text = content
                except:
                    pass

            info['body_text'] = body_text[:5000] if body_text else None  # Limit size
            info['body_html_preview'] = body_html[:2000] if body_html else None

            # Extract attachments
            attachments = []
            for part in msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                if 'attachment' in content_disposition or part.get_filename():
                    filename = part.get_filename() or 'unknown'
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachment_info = {
                                'filename': filename,
                                'size': len(payload),
                                'content_type': part.get_content_type(),
                                'md5': hashlib.md5(payload).hexdigest(),
                                'sha256': hashlib.sha256(payload).hexdigest()
                            }

                            # Detect file type
                            detected_type = self._detect_file_type(payload)
                            if detected_type:
                                attachment_info['detected_type'] = detected_type

                            # Check for dangerous extensions
                            ext = Path(filename).suffix.lower()
                            dangerous_ext = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.wsf', '.msi'}
                            if ext in dangerous_ext:
                                attachment_info['is_dangerous'] = True

                            # Check for extension mismatch
                            if detected_type == 'pe' and ext not in ['.exe', '.dll', '.scr', '.sys']:
                                attachment_info['type_mismatch'] = True
                                attachment_info['warning'] = f"Detected as PE executable but has {ext} extension"

                            attachments.append(attachment_info)
                    except Exception as e:
                        attachments.append({
                            'filename': filename,
                            'error': str(e)
                        })

            if attachments:
                info['has_attachments'] = True
                info['attachments'] = attachments
                info['attachment_count'] = len(attachments)

            # Extract links from HTML body
            if body_html:
                links = re.findall(r'href=["\']([^"\']+)["\']', body_html, re.IGNORECASE)
                info['links'] = list(set(links))[:50]  # Unique links, max 50

                # Check for suspicious link patterns
                suspicious_links = []
                for link in links:
                    link_lower = link.lower()
                    # Check for IP-based URLs (but exclude internal/private IPs)
                    ip_match = re.match(r'https?://(\d+)\.(\d+)\.(\d+)\.(\d+)', link_lower)
                    if ip_match:
                        first, second = int(ip_match.group(1)), int(ip_match.group(2))
                        # Skip internal IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
                        is_private = (
                            first == 10 or
                            first == 127 or
                            (first == 172 and 16 <= second <= 31) or
                            (first == 192 and second == 168)
                        )
                        if not is_private:
                            suspicious_links.append({'url': link, 'reason': 'ip_based_url'})
                    # Check for data URIs
                    elif link_lower.startswith('data:'):
                        suspicious_links.append({'url': link[:100], 'reason': 'data_uri'})
                    # Check for javascript URIs
                    elif link_lower.startswith('javascript:'):
                        suspicious_links.append({'url': link[:100], 'reason': 'javascript_uri'})

                if suspicious_links:
                    info['suspicious_links'] = suspicious_links[:10]

        except Exception as e:
            logger.error(f"EML parsing error: {e}")
            info['parse_error'] = str(e)

        return info

    def _parse_msg(self, data: bytes, info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse .msg (Outlook) email format.

        Note: Full MSG parsing requires the 'extract-msg' or 'olefile' library.
        This is a basic implementation that extracts what we can without dependencies.
        """
        try:
            # MSG files are OLE compound documents
            # Check for OLE magic bytes
            if data[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                info['error'] = 'Not a valid MSG/OLE file'
                return info

            info['format'] = 'MSG (Outlook)'

            # Try to extract readable strings for basic analysis
            text_content = data.decode('utf-16-le', errors='ignore')

            # Look for subject pattern
            subject_match = re.search(r'Subject[:\s]+([^\x00]+)', text_content)
            if subject_match:
                info['subject'] = subject_match.group(1)[:200].strip()

            # Look for From pattern
            from_match = re.search(r'From[:\s]+([^\x00]+)', text_content)
            if from_match:
                info['from'] = from_match.group(1)[:200].strip()

            # Extract potential IOCs from content
            ascii_strings = self._extract_binary_strings(data, min_length=8)

            # Look for email addresses
            emails = []
            for s in ascii_strings:
                found = self.EMAIL_PATTERN.findall(s)
                emails.extend(found)
            if emails:
                info['found_emails'] = list(set(emails))[:20]

            # Look for URLs
            urls = []
            for s in ascii_strings:
                found = self.URL_PATTERN.findall(s)
                urls.extend(found)
            if urls:
                info['found_urls'] = list(set(urls))[:20]

            info['note'] = 'Full MSG parsing requires additional libraries. Basic string extraction performed.'

        except Exception as e:
            logger.error(f"MSG parsing error: {e}")
            info['parse_error'] = str(e)

        return info

    def _extract_domain_from_email(self, email_str: str) -> Optional[str]:
        """Extract domain from email address string"""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_str)
        if match:
            return match.group(1).lower()
        return None

    def _extract_binary_strings(self, data: bytes, min_length: int = 6) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []

        # ASCII strings
        ascii_pattern = re.compile(b'[\x20-\x7e]{%d,}' % min_length)
        for match in ascii_pattern.finditer(data):
            try:
                s = match.group().decode('ascii')
                if self._is_interesting_string(s):
                    strings.append(s)
            except:
                pass

        # Unicode strings (UTF-16LE common in Windows)
        unicode_pattern = re.compile(b'(?:[\x20-\x7e]\x00){%d,}' % min_length)
        for match in unicode_pattern.finditer(data):
            try:
                s = match.group().decode('utf-16le')
                if self._is_interesting_string(s):
                    strings.append(s)
            except:
                pass

        return list(set(strings))[:100]  # Dedupe and limit

    def _is_interesting_string(self, s: str) -> bool:
        """Check if a string is potentially interesting"""
        # Skip very short or very long
        if len(s) < 6 or len(s) > 500:
            return False

        # Skip strings that are just repeated characters
        if len(set(s)) < 4:
            return False

        # Interesting patterns
        interesting_patterns = [
            r'https?://',
            r'\.[a-z]{2,4}$',
            r'password',
            r'user',
            r'admin',
            r'login',
            r'token',
            r'api',
            r'key',
            r'secret',
            r'\.exe',
            r'\.dll',
            r'\\\\',
            r'cmd\.exe',
            r'powershell',
            r'HKEY_',
            r'SOFTWARE\\',
            r'@.*\.com'
        ]

        for pattern in interesting_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                return True

        return False

    def _extract_interesting_strings(self, text: str) -> List[str]:
        """Extract interesting strings from text content"""
        strings = []

        # Look for paths
        paths = re.findall(r'[A-Za-z]:\\[^\s"\'<>|]+', text)
        strings.extend(paths[:20])

        # Look for URLs
        urls = self.URL_PATTERN.findall(text)
        strings.extend(urls[:20])

        # Look for registry keys
        reg_keys = re.findall(r'HKEY_[A-Z_]+\\[^\s"\']+', text)
        strings.extend(reg_keys[:10])

        return list(set(strings))[:50]

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract potential IOCs from text"""
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': []
        }

        # Extract IPs
        ips = self.IP_PATTERN.findall(text)
        # Filter out private/local IPs
        public_ips = [ip for ip in ips if not self._is_private_ip(ip)]
        iocs['ips'] = list(set(public_ips))[:20]

        # Extract domains
        domains = self.DOMAIN_PATTERN.findall(text)
        # Filter out common non-IOC domains
        filtered_domains = [d for d in domains if not self._is_common_domain(d)]
        iocs['domains'] = list(set(filtered_domains))[:20]

        # Extract URLs
        urls = self.URL_PATTERN.findall(text)
        iocs['urls'] = list(set(urls))[:20]

        # Extract emails
        emails = self.EMAIL_PATTERN.findall(text)
        iocs['emails'] = list(set(emails))[:10]

        # Remove empty lists
        return {k: v for k, v in iocs.items() if v}

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 0 or first >= 224:
                return True
        except:
            return True
        return False

    def _is_common_domain(self, domain: str) -> bool:
        """Check if domain is a common non-IOC domain"""
        common = {
            'microsoft.com', 'google.com', 'windows.com', 'apple.com',
            'mozilla.org', 'adobe.com', 'github.com', 'github.io',
            'localhost', 'example.com', 'test.com'
        }
        domain_lower = domain.lower()
        for c in common:
            if domain_lower == c or domain_lower.endswith('.' + c):
                return True
        return False


# Singleton instance
_metadata_extractor: Optional[FileMetadataExtractor] = None


def get_metadata_extractor() -> FileMetadataExtractor:
    """Get metadata extractor singleton"""
    global _metadata_extractor
    if _metadata_extractor is None:
        _metadata_extractor = FileMetadataExtractor()
    return _metadata_extractor
