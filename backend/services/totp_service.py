# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
TOTP (Time-based One-Time Password) Service for MFA.

Supports Google Authenticator, Authy, and other TOTP apps.
Uses HMAC-SHA1 with 30-second time steps and 6-digit codes.
"""
import base64
import hashlib
import hmac
import logging
import os
import struct
import time
import uuid as uuid_mod
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# TOTP parameters
TOTP_DIGITS = 6
TOTP_PERIOD = 30  # seconds
TOTP_ALGORITHM = 'sha1'
TOTP_ISSUER = 'T1 Agentics'
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 8


def generate_secret(length: int = 20) -> str:
    """Generate a random base32-encoded secret key."""
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list:
    """Generate one-time recovery codes."""
    codes = []
    for _ in range(count):
        code = os.urandom(RECOVERY_CODE_LENGTH // 2).hex()[:RECOVERY_CODE_LENGTH]
        codes.append(code)
    return codes


def get_totp_uri(secret: str, username: str, issuer: str = TOTP_ISSUER) -> str:
    """Generate otpauth:// URI for QR code scanning."""
    # Pad secret to valid base32
    padded = secret + '=' * (-len(secret) % 8)
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"


def _dynamic_truncate(hmac_result: bytes) -> int:
    """Extract a 4-byte dynamic binary code from HMAC result."""
    offset = hmac_result[-1] & 0x0F
    code = struct.unpack('>I', hmac_result[offset:offset + 4])[0]
    code &= 0x7FFFFFFF
    return code % (10 ** TOTP_DIGITS)


def generate_totp(secret: str, time_step: Optional[int] = None) -> str:
    """Generate a TOTP code for the given secret and time."""
    if time_step is None:
        time_step = int(time.time()) // TOTP_PERIOD

    # Decode base32 secret
    padded = secret + '=' * (-len(secret) % 8)
    key = base64.b32decode(padded.upper())

    # Create HMAC
    msg = struct.pack('>Q', time_step)
    hmac_result = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic truncation
    code = _dynamic_truncate(hmac_result)
    return str(code).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code with a time window tolerance.

    Args:
        secret: Base32-encoded secret
        code: 6-digit code from user
        window: Number of time steps to check before/after current

    Returns:
        True if code is valid
    """
    if not code or len(code) != TOTP_DIGITS:
        return False

    current_step = int(time.time()) // TOTP_PERIOD

    for offset in range(-window, window + 1):
        expected = generate_totp(secret, current_step + offset)
        if hmac.compare_digest(expected, code):
            return True

    return False


class TOTPManager:
    """Manages TOTP enrollment and verification with database persistence."""

    def __init__(self, db):
        self.db = db

    @staticmethod
    def _ensure_uuid(user_id):
        """Convert user_id to UUID object if it's a string (required by asyncpg)."""
        if isinstance(user_id, str):
            return uuid_mod.UUID(user_id)
        return user_id

    async def setup_totp(self, user_id) -> dict:
        """
        Begin TOTP setup for a user. Returns secret and URI for QR code.
        Does NOT enable MFA yet - user must verify a code first.
        """
        user_id = self._ensure_uuid(user_id)
        secret = generate_secret()
        recovery_codes = generate_recovery_codes()

        # Get username for URI
        async with self.db.tenant_acquire() as conn:
            user = await conn.fetchrow(
                "SELECT username, email FROM users WHERE id = $1",
                user_id
            )
            if not user:
                raise ValueError("User not found")

            username = user['username']

            # Store pending TOTP setup (not yet verified)
            import json
            import hashlib as hl
            hashed_codes = [hl.sha256(c.encode()).hexdigest() for c in recovery_codes]

            await conn.execute("""
                UPDATE users SET
                    totp_secret = $1,
                    totp_verified = false,
                    totp_recovery_codes = $2
                WHERE id = $3
            """, secret, json.dumps(hashed_codes), user_id)

        uri = get_totp_uri(secret, username)

        return {
            "secret": secret,
            "uri": uri,
            "recovery_codes": recovery_codes,
            "message": "Scan the QR code with your authenticator app, then verify with a code."
        }

    async def verify_setup(self, user_id, code: str) -> dict:
        """Verify TOTP setup by checking the first code. Enables MFA on success."""
        user_id = self._ensure_uuid(user_id)
        async with self.db.tenant_acquire() as conn:
            user = await conn.fetchrow(
                "SELECT totp_secret, totp_verified FROM users WHERE id = $1",
                user_id
            )

            if not user or not user['totp_secret']:
                raise ValueError("TOTP not set up for this user")

            if user['totp_verified']:
                raise ValueError("TOTP is already verified and active")

            if not verify_totp(user['totp_secret'], code):
                return {"success": False, "message": "Invalid code. Please try again."}

            # Enable MFA
            await conn.execute("""
                UPDATE users SET
                    totp_verified = true,
                    mfa_enabled = true
                WHERE id = $1
            """, user_id)

        return {"success": True, "message": "MFA enabled successfully."}

    async def verify_code(self, user_id, code: str) -> bool:
        """Verify a TOTP code during login."""
        user_id = self._ensure_uuid(user_id)
        async with self.db.tenant_acquire() as conn:
            user = await conn.fetchrow(
                "SELECT totp_secret, totp_verified, totp_recovery_codes FROM users WHERE id = $1",
                user_id
            )

            if not user or not user['totp_secret'] or not user['totp_verified']:
                return False

            # Try TOTP code first
            if verify_totp(user['totp_secret'], code):
                return True

            # Try recovery code
            import json
            import hashlib as hl
            recovery_codes = json.loads(user['totp_recovery_codes'] or '[]')
            code_hash = hl.sha256(code.encode()).hexdigest()

            if code_hash in recovery_codes:
                recovery_codes.remove(code_hash)
                await conn.execute(
                    "UPDATE users SET totp_recovery_codes = $1 WHERE id = $2",
                    json.dumps(recovery_codes), user_id
                )
                logger.warning(f"Recovery code used for user {user_id}. {len(recovery_codes)} remaining.")
                return True

            return False

    async def disable_totp(self, user_id) -> dict:
        """Disable TOTP MFA for a user."""
        user_id = self._ensure_uuid(user_id)
        async with self.db.tenant_acquire() as conn:
            await conn.execute("""
                UPDATE users SET
                    totp_secret = NULL,
                    totp_verified = false,
                    totp_recovery_codes = NULL,
                    mfa_enabled = false
                WHERE id = $1
            """, user_id)

        return {"success": True, "message": "MFA has been disabled."}


def get_totp_manager(db=None):
    """Get TOTP manager instance."""
    if db is None:
        from services.postgres_db import postgres_db
        db = postgres_db
    return TOTPManager(db)
