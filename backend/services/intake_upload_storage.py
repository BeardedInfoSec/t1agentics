# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Intake-form attachment storage.

Files uploaded against intake-form file fields are stored on local disk
under INTAKE_UPLOAD_DIR (default /var/lib/t1agentics-uploads), indexed by a
UUID attachment id. Metadata lives in the intake_form_attachments table —
this module owns the disk side only.

Lifecycle:
  - Upload  -> store_upload() writes the stream chunk-by-chunk, enforces the
              size cap mid-stream, returns bytes written.
  - Serve   -> get_upload_path() returns a Path the route can stream from.
  - Expire  -> delete_upload() removes the file. The DB row is marked
              deleted_at separately so the lifecycle is auditable.

Size limit and root are env-tunable so deployments can dial in based on
disk budget. Conservative default: 25 MB.
"""

import logging
import os
import re
from pathlib import Path
from typing import BinaryIO, Optional

logger = logging.getLogger(__name__)


# Configurable via env. Set INTAKE_UPLOAD_DIR to a bind-mounted volume in
# the prod compose so files survive container rebuilds; set
# INTAKE_UPLOAD_MAX_BYTES to a different cap if you need bigger uploads.
UPLOAD_ROOT: Path = Path(os.environ.get("INTAKE_UPLOAD_DIR", "/var/lib/t1agentics-uploads"))
MAX_UPLOAD_SIZE_BYTES: int = int(
    os.environ.get("INTAKE_UPLOAD_MAX_BYTES", str(25 * 1024 * 1024))
)


# Executable / installer types — refused at the upload boundary. End users
# never have a legitimate reason to upload these to a security intake form.
# Everything else (eml, msg, pdf, png, txt, log, json, csv, etc.) passes.
DENIED_CONTENT_TYPES = frozenset({
    "application/x-msdownload",        # .exe
    "application/x-msdos-program",      # .com / .bat
    "application/x-ms-installer",       # .msi (variant)
    "application/x-msi",                # .msi
    "application/x-sh",                 # shell script
    "application/x-shellscript",        # shell script (variant)
    "application/x-mach-binary",        # macOS Mach-O
    "application/x-elf",                # Linux ELF
    "application/x-dosexec",            # generic DOS exec
})

# Same idea but by extension, for cases where content-type is generic
# application/octet-stream. Lowercase. Includes the dot.
DENIED_EXTENSIONS = frozenset({
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".cpl", ".msi",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
    ".jar", ".sh", ".bash",
})

_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_filename(name: str) -> str:
    """
    Make a user-supplied filename safe to store and display.

    - Strip any path components (os.path.basename)
    - Replace unsafe characters with underscore
    - Cap the total length so we don't have giant filenames in headers
    Returns at least "upload" if everything got stripped.
    """
    name = os.path.basename(name or "")
    name = _SAFE_FILENAME.sub("_", name)
    if len(name) > 200:
        # Preserve the extension if there is one
        stem, dot, ext = name.rpartition(".")
        if dot:
            ext = ext[:20]
            stem = stem[: 200 - len(ext) - 1]
            name = f"{stem}.{ext}"
        else:
            name = name[:200]
    return name or "upload"


def is_denied(filename: str, content_type: str) -> bool:
    """True if either the content_type or the file extension is on the deny list."""
    ct = (content_type or "").lower().split(";")[0].strip()
    if ct in DENIED_CONTENT_TYPES:
        return True
    ext = os.path.splitext(filename or "")[1].lower()
    if ext in DENIED_EXTENSIONS:
        return True
    return False


def attachment_storage_path(attachment_id: str) -> Path:
    """
    Path on disk for a given attachment id.

    Flat layout — no nesting — because cleanup-by-id is the access pattern.
    The attachment id is a UUID so collisions are not a concern.
    """
    return UPLOAD_ROOT / attachment_id


def ensure_root() -> None:
    """Make sure the upload directory exists. Idempotent."""
    try:
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create upload root {UPLOAD_ROOT}: {e}")
        raise


def store_upload(attachment_id: str, stream: BinaryIO) -> int:
    """
    Stream `stream` to disk under `attachment_id`.

    Returns total bytes written. Raises ValueError if the stream exceeds
    MAX_UPLOAD_SIZE_BYTES (the file is removed in that case so we never
    leave partial uploads behind).
    """
    ensure_root()
    path = attachment_storage_path(attachment_id)
    bytes_written = 0
    try:
        with open(path, "wb") as out:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_SIZE_BYTES:
                    out.close()
                    path.unlink(missing_ok=True)
                    raise ValueError(
                        f"File exceeds {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB limit"
                    )
                out.write(chunk)
    except ValueError:
        raise
    except Exception as e:
        # Clean up partial file on any error so we don't accrete junk.
        path.unlink(missing_ok=True)
        logger.error(f"store_upload failed for {attachment_id}: {e}")
        raise
    return bytes_written


def get_upload_path(attachment_id: str) -> Optional[Path]:
    """Return the on-disk path if the file exists, else None."""
    path = attachment_storage_path(attachment_id)
    return path if path.exists() else None


def delete_upload(attachment_id: str) -> bool:
    """
    Remove the file from disk. Idempotent — already-missing files are
    treated as a successful delete. Returns True if a file actually went
    away, False if nothing to do.
    """
    path = attachment_storage_path(attachment_id)
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except Exception as e:
        logger.warning(f"Failed to delete upload {attachment_id}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# TTL cleanup — sweeps expired attachments. Wired into app lifespan.
# ─────────────────────────────────────────────────────────────────────────────


async def cleanup_expired_attachments_once() -> int:
    """
    Sweep attachments past expires_at, delete the disk file, mark
    deleted_at. Returns the number of attachments swept.

    Runs under platform-admin mode so it sees every tenant's rows. Used
    by both the manual-trigger admin route and the lifespan loop below.
    """
    from services.postgres_db import postgres_db, set_platform_admin_mode

    if not postgres_db.connected or not postgres_db.pool:
        return 0

    deleted = 0
    set_platform_admin_mode(True)
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id FROM intake_form_attachments
                WHERE expires_at < NOW() AND deleted_at IS NULL
                LIMIT 1000
                """
            )
            for row in rows:
                delete_upload(str(row["id"]))
                await conn.execute(
                    "UPDATE intake_form_attachments SET deleted_at = NOW() WHERE id = $1::uuid",
                    row["id"],
                )
                deleted += 1
    except Exception as e:
        logger.error(f"intake-form attachment TTL sweep failed: {e}")
    finally:
        set_platform_admin_mode(False)

    if deleted:
        logger.info(f"[INTAKE_UPLOADS] TTL swept {deleted} expired attachment(s)")
    return deleted


async def cleanup_loop(interval_seconds: int = 3600) -> None:
    """
    Long-running task: sweep expired attachments every `interval_seconds`.
    Default hourly is plenty — TTL is 14 days, so per-hour granularity is
    overkill but cheap. Started from app.py:lifespan.
    """
    import asyncio
    # Stagger the first run a bit so app startup isn't blocked on DB I/O
    await asyncio.sleep(60)
    while True:
        try:
            await cleanup_expired_attachments_once()
        except Exception as e:
            logger.error(f"intake upload cleanup_loop tick failed: {e}")
        await asyncio.sleep(interval_seconds)
