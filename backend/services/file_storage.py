# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
File Storage Service

Handles file upload, storage, and retrieval for alert attachments.
Supports:
- Local file storage
- Automatic hash calculation (MD5, SHA1, SHA256)
- File metadata extraction
- Secure storage with path validation
"""

import os
import hashlib
import logging
import secrets
import mimetypes
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, BinaryIO, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class StoredFile:
    """Represents a stored file"""
    attachment_id: str
    filename: str
    original_filename: str
    file_size: int
    mime_type: str
    storage_path: str
    md5_hash: str
    sha1_hash: str
    sha256_hash: str


class FileStorageService:
    """
    File storage service for alert attachments.

    Stores files in a secure location with hash verification.
    """

    # Maximum file size (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    # Allowed file types (empty = all allowed)
    ALLOWED_EXTENSIONS = {
        '.txt', '.log', '.csv', '.json', '.xml',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp',
        '.pcap', '.pcapng', '.evtx', '.eml', '.msg',
        '.zip', '.gz', '.tar', '.7z',
        '.py', '.html', '.htm', '.css'
    }

    # Dangerous file types that require extra handling
    DANGEROUS_EXTENSIONS = {
        '.exe', '.dll', '.msi', '.ps1', '.bat', '.sh',
        '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        '.hta', '.scr', '.pif', '.cmd', '.com'
    }

    def __init__(self, storage_path: str = None):
        """Initialize file storage service"""
        # Default to data/attachments in the backend directory
        if storage_path is None:
            base_path = Path(__file__).parent.parent
            storage_path = base_path / "data" / "attachments"

        self.storage_path = Path(storage_path)
        self._ensure_storage_directory()
        logger.info(f"[FILE_STORAGE] Initialized with path: {self.storage_path}")

    def _ensure_storage_directory(self):
        """Create storage directory if it doesn't exist"""
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Create subdirectories for organization
        (self.storage_path / "samples").mkdir(exist_ok=True)
        (self.storage_path / "evidence").mkdir(exist_ok=True)
        (self.storage_path / "quarantine").mkdir(exist_ok=True)

    def _generate_attachment_id(self) -> str:
        """Generate unique attachment ID"""
        return f"ATT-{secrets.token_hex(8).upper()}"

    def _calculate_hashes(self, file_data: bytes) -> Tuple[str, str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes"""
        md5 = hashlib.md5(file_data).hexdigest()
        sha1 = hashlib.sha1(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()
        return md5, sha1, sha256

    def _get_safe_filename(self, original_filename: str, sha256: str) -> str:
        """Generate safe storage filename"""
        # Extract extension
        ext = Path(original_filename).suffix.lower()
        if not ext:
            ext = '.bin'

        # Use hash-based naming for safety
        # Format: SHA256_timestamp_original-name-truncated.ext
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        safe_name = original_filename[:50].replace('/', '_').replace('\\', '_')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in '._-')

        return f"{sha256[:16]}_{timestamp}_{safe_name}"

    def _is_dangerous(self, filename: str) -> bool:
        """Check if file type is potentially dangerous"""
        ext = Path(filename).suffix.lower()
        return ext in self.DANGEROUS_EXTENSIONS

    def _get_storage_subdir(self, is_dangerous: bool) -> Path:
        """Get appropriate storage subdirectory"""
        if is_dangerous:
            return self.storage_path / "quarantine"
        return self.storage_path / "evidence"

    async def store_file(
        self,
        file_data: bytes,
        original_filename: str,
        alert_id: str,
        uploaded_by: str = None,
        description: str = None
    ) -> StoredFile:
        """
        Store a file and return storage metadata.

        Args:
            file_data: Raw file bytes
            original_filename: Original filename
            alert_id: Associated alert ID
            uploaded_by: Username of uploader
            description: Optional file description

        Returns:
            StoredFile with storage details
        """
        # Validate file size
        file_size = len(file_data)
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} bytes (max {self.MAX_FILE_SIZE})")

        if file_size == 0:
            raise ValueError("Empty file not allowed")

        # Reject dangerous file extensions outright
        ext = Path(original_filename).suffix.lower()
        if ext in self.DANGEROUS_EXTENSIONS:
            raise ValueError(
                f"File type '{ext}' is not allowed. "
                f"Executable and script files cannot be uploaded."
            )

        # Validate extension against allowlist
        if ext and ext not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"File type '{ext}' is not in the list of allowed extensions")

        # Calculate hashes
        md5, sha1, sha256 = self._calculate_hashes(file_data)

        # Generate attachment ID and safe filename
        attachment_id = self._generate_attachment_id()
        safe_filename = self._get_safe_filename(original_filename, sha256)

        # Determine storage location
        is_dangerous = self._is_dangerous(original_filename)
        storage_subdir = self._get_storage_subdir(is_dangerous)

        # Create alert-specific subdirectory
        alert_dir = storage_subdir / alert_id
        alert_dir.mkdir(parents=True, exist_ok=True)

        # Full storage path
        storage_file_path = alert_dir / safe_filename

        # Write file
        try:
            with open(storage_file_path, 'wb') as f:
                f.write(file_data)
            logger.info(f"[FILE_STORAGE] Stored file: {storage_file_path}")
        except Exception as e:
            logger.error(f"[FILE_STORAGE] Failed to store file: {e}")
            raise

        # Detect MIME type
        mime_type, _ = mimetypes.guess_type(original_filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        # Log dangerous files
        if is_dangerous:
            logger.warning(f"[FILE_STORAGE] Stored potentially dangerous file in quarantine: {original_filename} ({sha256})")

        return StoredFile(
            attachment_id=attachment_id,
            filename=safe_filename,
            original_filename=original_filename,
            file_size=file_size,
            mime_type=mime_type,
            storage_path=str(storage_file_path.relative_to(self.storage_path)),
            md5_hash=md5,
            sha1_hash=sha1,
            sha256_hash=sha256
        )

    async def get_file(self, storage_path: str) -> Optional[bytes]:
        """
        Retrieve file data by storage path.

        Args:
            storage_path: Relative storage path

        Returns:
            File bytes or None if not found
        """
        full_path = self.storage_path / storage_path

        # Security: ensure path is within storage directory
        try:
            full_path.resolve().relative_to(self.storage_path.resolve())
        except ValueError:
            logger.warning(f"[FILE_STORAGE] Path traversal attempt: {storage_path}")
            return None

        if not full_path.exists():
            logger.warning(f"[FILE_STORAGE] File not found: {storage_path}")
            return None

        try:
            with open(full_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"[FILE_STORAGE] Failed to read file: {e}")
            return None

    async def delete_file(self, storage_path: str) -> bool:
        """
        Delete a file from storage.

        Args:
            storage_path: Relative storage path

        Returns:
            True if deleted, False otherwise
        """
        full_path = self.storage_path / storage_path

        # Security check
        try:
            full_path.resolve().relative_to(self.storage_path.resolve())
        except ValueError:
            logger.warning(f"[FILE_STORAGE] Path traversal attempt on delete: {storage_path}")
            return False

        if not full_path.exists():
            return False

        try:
            full_path.unlink()
            logger.info(f"[FILE_STORAGE] Deleted file: {storage_path}")
            return True
        except Exception as e:
            logger.error(f"[FILE_STORAGE] Failed to delete file: {e}")
            return False

    async def verify_file(self, storage_path: str, expected_sha256: str) -> bool:
        """
        Verify file integrity using SHA256 hash.

        Args:
            storage_path: Relative storage path
            expected_sha256: Expected SHA256 hash

        Returns:
            True if hash matches, False otherwise
        """
        file_data = await self.get_file(storage_path)
        if not file_data:
            return False

        actual_sha256 = hashlib.sha256(file_data).hexdigest()
        return actual_sha256.lower() == expected_sha256.lower()

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        stats = {
            'storage_path': str(self.storage_path),
            'total_files': 0,
            'total_size_bytes': 0,
            'by_directory': {}
        }

        for subdir in ['evidence', 'quarantine', 'samples']:
            subdir_path = self.storage_path / subdir
            if subdir_path.exists():
                files = list(subdir_path.rglob('*'))
                file_count = sum(1 for f in files if f.is_file())
                total_size = sum(f.stat().st_size for f in files if f.is_file())

                stats['by_directory'][subdir] = {
                    'file_count': file_count,
                    'size_bytes': total_size
                }
                stats['total_files'] += file_count
                stats['total_size_bytes'] += total_size

        return stats


# Singleton instance
_file_storage: Optional[FileStorageService] = None


def get_file_storage() -> FileStorageService:
    """Get file storage service singleton"""
    global _file_storage
    if _file_storage is None:
        _file_storage = FileStorageService()
    return _file_storage
