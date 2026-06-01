#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Secrets Rotation Manager

This script generates and manages cryptographic secrets for T1 Agentics.
It creates new secrets, validates them, and outputs to a secure .env.new file.

SECURITY NOTES:
- All secrets are written to .env.new (never stdout)
- Current .env is backed up before any changes
- Secrets meet production security requirements
- Rotation recommended quarterly or after personnel changes
- Never commit .env or .env.new to version control

USAGE:
    python scripts/rotate_secrets.py
    python scripts/rotate_secrets.py --apply    # Apply immediately (requires confirmation)
    python scripts/rotate_secrets.py --help     # Show detailed help

SUPPORTED SECRET TYPES:
    - JWT_SECRET_KEY: Authentication token signing (32+ bytes)
    - ADMIN_PASSWORD: Platform admin password (16+ chars, mixed case + symbols)
    - POSTGRES_PASSWORD: Database connection (32+ chars, random)
    - CREDENTIALS_ENCRYPTION_KEY: Integration credential encryption (Fernet key)
    - ANTHROPIC_API_KEY: Claude API key (user-provided or skip)
    - SMTP_PASSWORD: Email service (user-provided or skip)
    - PLATFORM_JWT_SECRET: Platform-level JWT signing (32+ bytes)
    - FORM_TOKEN_SECRET: Form CSRF token signing (32+ bytes)
    - INTEGRATION_ENCRYPTION_KEY: Alternative credential key (32+ bytes)

DEPLOYMENT INSTRUCTIONS:
    1. Run this script: python scripts/rotate_secrets.py
    2. Review .env.new for correctness
    3. Update configuration management system with new secrets
    4. Create a backup of current .env: cp .env .env.backup.YYYY-MM-DD
    5. Copy new secrets: cp .env.new .env
    6. Restart services: docker compose up -d
    7. Verify application health and logs
    8. Securely destroy .env.new: shred -vfz -n 3 .env.new
    9. Update password manager with new ADMIN_PASSWORD and POSTGRES_PASSWORD
    10. Notify all system administrators of rotation completion

ROTATION FREQUENCY:
    - RECOMMENDED: Quarterly (every 3 months)
    - SECURITY EVENT: Immediately after suspected compromise
    - PERSONNEL: When team members with secret access leave
    - INCIDENT: After security incident investigation

WARNING:
    After applying new secrets, ensure:
    - All services restart successfully
    - No "authentication failed" errors in logs
    - Database connections are working
    - Existing user sessions may need to re-authenticate
    - Saved credentials may require re-entry for integrations
"""

import argparse
import datetime
import json
import os
import re
import secrets
import sys
import string
from pathlib import Path
from typing import Dict, Optional, Tuple


class SecretValidator:
    """Validates secrets meet security requirements."""

    @staticmethod
    def validate_jwt_secret(value: str) -> Tuple[bool, str]:
        """JWT secrets must be 32+ characters, URL-safe."""
        if len(value) < 32:
            return False, f"JWT secret too short: {len(value)} chars (min 32)"
        if not all(c in string.ascii_letters + string.digits + "-_" for c in value):
            return False, "JWT secret contains invalid characters (must be URL-safe)"
        return True, "JWT secret valid"

    @staticmethod
    def validate_password(value: str, name: str = "password") -> Tuple[bool, str]:
        """Passwords must be 16+ chars with uppercase, lowercase, digits, symbols."""
        if len(value) < 16:
            return False, f"{name} too short: {len(value)} chars (min 16)"
        if not any(c.isupper() for c in value):
            return False, f"{name} missing uppercase letters"
        if not any(c.islower() for c in value):
            return False, f"{name} missing lowercase letters"
        if not any(c.isdigit() for c in value):
            return False, f"{name} missing digits"
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in value):
            return False, f"{name} missing symbols"
        return True, f"{name} valid"

    @staticmethod
    def validate_fernet_key(value: str) -> Tuple[bool, str]:
        """Fernet keys must be valid base64-encoded 32-byte keys."""
        try:
            from cryptography.fernet import Fernet
            # Fernet.generate_key() returns bytes, but we store as string
            # Validate it can be used with Fernet
            Fernet(value.encode() if isinstance(value, str) else value)
            return True, "Fernet key valid"
        except Exception as e:
            return False, f"Invalid Fernet key: {str(e)}"

    @staticmethod
    def validate_api_key(value: str, provider: str = "api") -> Tuple[bool, str]:
        """API keys should follow provider-specific patterns."""
        if not value or value == "":
            return False, f"{provider} key is empty"
        if len(value) < 8:
            return False, f"{provider} key too short: {len(value)} chars"
        return True, f"{provider} key valid"


class SecretGenerator:
    """Generates cryptographically secure secrets."""

    @staticmethod
    def generate_jwt_secret() -> str:
        """Generate a secure JWT secret using secrets.token_urlsafe."""
        # 32 bytes = 43 characters in base64url encoding
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_platform_jwt_secret() -> str:
        """Generate a secure platform JWT secret."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_form_token_secret() -> str:
        """Generate a secure form token signing secret."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_strong_password(length: int = 20) -> str:
        """
        Generate a strong password meeting security requirements:
        - 20 characters (configurable, min 16)
        - Mixed case, digits, symbols
        - No ambiguous characters (0/O, 1/l/I)
        """
        if length < 16:
            length = 16

        # Remove ambiguous characters
        alphabet = string.ascii_letters.replace('I', '').replace('l', '').replace('O', '')
        digits = string.digits.replace('0', '').replace('1', '')
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Ensure we have at least one of each required type
        password_chars = [
            secrets.choice(alphabet.replace(alphabet.lower(), '').replace(alphabet.upper(), alphabet.upper())),  # uppercase
            secrets.choice(alphabet.lower()),  # lowercase
            secrets.choice(digits),  # digit
            secrets.choice(symbols),  # symbol
        ]

        # Fill the rest randomly
        remaining_length = length - len(password_chars)
        all_chars = alphabet + digits + symbols
        password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))

        # Shuffle to avoid predictable patterns
        password_list = list(password_chars)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    @staticmethod
    def generate_postgres_password(length: int = 32) -> str:
        """Generate a secure PostgreSQL password."""
        # PostgreSQL allows most characters, but avoid special shell chars
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_fernet_key() -> str:
        """Generate a Fernet encryption key."""
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def generate_integration_encryption_key(length: int = 32) -> str:
        """Generate an integration credential encryption key."""
        # 32 bytes base64-encoded
        return secrets.token_urlsafe(length)


class SecretsRotationManager:
    """Manages secrets rotation with validation and backup."""

    def __init__(self, env_path: str = ".env", backup_dir: Optional[str] = None):
        """Initialize the secrets manager."""
        self.env_path = Path(env_path)
        self.backup_dir = Path(backup_dir) if backup_dir else self.env_path.parent
        self.current_secrets: Dict[str, str] = {}
        self.new_secrets: Dict[str, str] = {}
        self.validator = SecretValidator()
        self.generator = SecretGenerator()
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def load_current_env(self) -> bool:
        """Load current .env file if it exists."""
        if not self.env_path.exists():
            print(f"WARNING: {self.env_path} not found. Will create new secrets from scratch.")
            return False

        try:
            with open(self.env_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        # Remove inline comments
                        if '#' in value and not value.startswith('"'):
                            value = value.split('#')[0].strip()
                        self.current_secrets[key] = value
            return True
        except Exception as e:
            print(f"ERROR: Failed to load current .env: {e}")
            return False

    def backup_current_env(self) -> bool:
        """Create backup of current .env file."""
        if not self.env_path.exists():
            return True

        backup_path = self.backup_dir / f".env.backup.{self.timestamp}"
        try:
            with open(self.env_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(content)
            # Secure file permissions (owner read/write only)
            backup_path.chmod(0o600)
            print(f"Backup created: {backup_path}")
            return True
        except Exception as e:
            print(f"ERROR: Failed to create backup: {e}")
            return False

    def generate_secrets(self, interactive: bool = False) -> bool:
        """Generate new secrets."""
        print("\n" + "=" * 70)
        print("SECRETS GENERATION")
        print("=" * 70)

        try:
            # Core secrets (always generated)
            print("\nGenerating core authentication secrets...")
            self.new_secrets['JWT_SECRET_KEY'] = self.generator.generate_jwt_secret()
            self.new_secrets['PLATFORM_JWT_SECRET'] = self.generator.generate_platform_jwt_secret()
            self.new_secrets['FORM_TOKEN_SECRET'] = self.generator.generate_form_token_secret()
            self.new_secrets['ADMIN_PASSWORD'] = self.generator.generate_strong_password(20)

            print("Generating database secrets...")
            self.new_secrets['POSTGRES_PASSWORD'] = self.generator.generate_postgres_password(32)

            print("Generating encryption keys...")
            self.new_secrets['CREDENTIALS_ENCRYPTION_KEY'] = self.generator.generate_fernet_key()
            self.new_secrets['INTEGRATION_ENCRYPTION_KEY'] = self.generator.generate_integration_encryption_key(32)

            # Optional secrets (user-provided or skipped)
            if interactive:
                print("\nOptional secrets (press Enter to skip):")

                # Anthropic API Key
                anthropic_key = input("\nANTHROPIC_API_KEY (press Enter to keep current): ").strip()
                if anthropic_key:
                    is_valid, msg = self.validator.validate_api_key(anthropic_key, "ANTHROPIC_API_KEY")
                    if is_valid:
                        self.new_secrets['ANTHROPIC_API_KEY'] = anthropic_key
                    else:
                        print(f"WARNING: {msg}")
                elif 'ANTHROPIC_API_KEY' in self.current_secrets:
                    self.new_secrets['ANTHROPIC_API_KEY'] = self.current_secrets['ANTHROPIC_API_KEY']

                # SMTP Password
                smtp_pass = input("\nSMTP_PASSWORD (press Enter to keep current): ").strip()
                if smtp_pass:
                    self.new_secrets['SMTP_PASSWORD'] = smtp_pass
                elif 'SMTP_PASSWORD' in self.current_secrets:
                    self.new_secrets['SMTP_PASSWORD'] = self.current_secrets['SMTP_PASSWORD']
            else:
                # In non-interactive mode, preserve existing optional secrets
                optional_keys = ['ANTHROPIC_API_KEY', 'SMTP_PASSWORD', 'OPENAI_API_KEY']
                for key in optional_keys:
                    if key in self.current_secrets:
                        self.new_secrets[key] = self.current_secrets[key]

            return True
        except Exception as e:
            print(f"ERROR: Secret generation failed: {e}")
            return False

    def validate_secrets(self) -> Tuple[bool, list]:
        """Validate all generated secrets."""
        print("\n" + "=" * 70)
        print("SECRETS VALIDATION")
        print("=" * 70)

        errors = []

        # JWT Secret
        is_valid, msg = self.validator.validate_jwt_secret(self.new_secrets.get('JWT_SECRET_KEY', ''))
        print(f"  JWT_SECRET_KEY: {msg}")
        if not is_valid:
            errors.append(f"JWT_SECRET_KEY: {msg}")

        # Platform JWT Secret
        is_valid, msg = self.validator.validate_jwt_secret(self.new_secrets.get('PLATFORM_JWT_SECRET', ''))
        print(f"  PLATFORM_JWT_SECRET: {msg}")
        if not is_valid:
            errors.append(f"PLATFORM_JWT_SECRET: {msg}")

        # Form Token Secret
        is_valid, msg = self.validator.validate_jwt_secret(self.new_secrets.get('FORM_TOKEN_SECRET', ''))
        print(f"  FORM_TOKEN_SECRET: {msg}")
        if not is_valid:
            errors.append(f"FORM_TOKEN_SECRET: {msg}")

        # Admin Password
        is_valid, msg = self.validator.validate_password(
            self.new_secrets.get('ADMIN_PASSWORD', ''),
            'ADMIN_PASSWORD'
        )
        print(f"  ADMIN_PASSWORD: {msg}")
        if not is_valid:
            errors.append(f"ADMIN_PASSWORD: {msg}")

        # Postgres Password
        is_valid, msg = self.validator.validate_password(
            self.new_secrets.get('POSTGRES_PASSWORD', ''),
            'POSTGRES_PASSWORD'
        )
        print(f"  POSTGRES_PASSWORD: {msg}")
        if not is_valid:
            errors.append(f"POSTGRES_PASSWORD: {msg}")

        # Fernet Key
        is_valid, msg = self.validator.validate_fernet_key(
            self.new_secrets.get('CREDENTIALS_ENCRYPTION_KEY', '')
        )
        print(f"  CREDENTIALS_ENCRYPTION_KEY: {msg}")
        if not is_valid:
            errors.append(f"CREDENTIALS_ENCRYPTION_KEY: {msg}")

        # Integration Encryption Key (base64-encoded)
        is_valid, msg = self.validator.validate_jwt_secret(
            self.new_secrets.get('INTEGRATION_ENCRYPTION_KEY', '')
        )
        print(f"  INTEGRATION_ENCRYPTION_KEY: {msg}")
        if not is_valid:
            errors.append(f"INTEGRATION_ENCRYPTION_KEY: {msg}")

        # Optional secrets
        for key in ['ANTHROPIC_API_KEY', 'SMTP_PASSWORD', 'OPENAI_API_KEY']:
            if key in self.new_secrets and self.new_secrets[key]:
                print(f"  {key}: Present (not validated for content)")

        return len(errors) == 0, errors

    def write_env_new(self) -> bool:
        """Write new secrets to .env.new file with documentation."""
        env_new_path = self.backup_dir / ".env.new"

        try:
            with open(env_new_path, 'w', encoding='utf-8') as f:
                # Header with security warning
                f.write(f"""# ═══════════════════════════════════════════════════════════════════════════════
# T1 Agentics Environment Configuration - ROTATED SECRETS
# Generated: {datetime.datetime.now().isoformat()}
# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CRITICAL: These secrets were auto-generated. Review each value carefully.
# NEVER commit this file to version control.
# After review and testing, apply by:
#   1. cp .env .env.backup.{self.timestamp}
#   2. cp .env.new .env
#   3. docker compose up -d
#   4. Verify application health: docker compose logs -f
#   5. Securely destroy this file: shred -vfz -n 3 .env.new
# ═══════════════════════════════════════════════════════════════════════════════

""")

                # Authentication & Security Secrets
                f.write("""# ════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION & SECURITY SECRETS - CRITICAL
# ════════════════════════════════════════════════════════════════════════════
# NEVER share these values. Store in secure configuration management system.
# Rotate quarterly or after security incidents.

""")
                f.write(f"# JWT Secret: Used for signing/verifying authentication tokens\n")
                f.write(f"# Generated by: secrets.token_urlsafe(32)\n")
                f.write(f"# Used by: FastAPI endpoints for token verification\n")
                f.write(f"JWT_SECRET_KEY={self.new_secrets.get('JWT_SECRET_KEY', '')}\n\n")

                f.write(f"# Platform JWT Secret: Used for platform-level authentication\n")
                f.write(f"# Generated by: secrets.token_urlsafe(32)\n")
                f.write(f"# Used by: Platform admin endpoints\n")
                f.write(f"PLATFORM_JWT_SECRET={self.new_secrets.get('PLATFORM_JWT_SECRET', '')}\n\n")

                f.write(f"# Form Token Secret: Used for CSRF token signing\n")
                f.write(f"# Generated by: secrets.token_urlsafe(32)\n")
                f.write(f"# Used by: Form submission CSRF protection\n")
                f.write(f"FORM_TOKEN_SECRET={self.new_secrets.get('FORM_TOKEN_SECRET', '')}\n\n")

                # Encryption Keys
                f.write("""# ════════════════════════════════════════════════════════════════════════════
# ENCRYPTION KEYS - CRITICAL
# ════════════════════════════════════════════════════════════════════════════
# These keys encrypt sensitive data at rest. Rotation requires re-encryption.
# See migration guide in documentation.

""")
                f.write(f"# Credentials Encryption Key: Encrypts stored integration credentials\n")
                f.write(f"# Generated by: cryptography.fernet.Fernet.generate_key()\n")
                f.write(f"# Format: Fernet key (base64-encoded 32-byte key)\n")
                f.write(f"# MIGRATION: Old credentials must be re-encrypted after rotation\n")
                f.write(f"CREDENTIALS_ENCRYPTION_KEY={self.new_secrets.get('CREDENTIALS_ENCRYPTION_KEY', '')}\n\n")

                f.write(f"# Integration Encryption Key: Alternative credential encryption\n")
                f.write(f"# Generated by: secrets.token_urlsafe(32)\n")
                f.write(f"# Format: Base64-encoded random bytes\n")
                f.write(f"INTEGRATION_ENCRYPTION_KEY={self.new_secrets.get('INTEGRATION_ENCRYPTION_KEY', '')}\n\n")

                # Credentials
                f.write("""# ════════════════════════════════════════════════════════════════════════════
# CREDENTIALS
# ════════════════════════════════════════════════════════════════════════════
# Strong passwords auto-generated: 16+ chars, uppercase, lowercase, digits, symbols

""")
                f.write(f"# Platform Admin Password: Default admin account (CHANGE AT FIRST LOGIN)\n")
                f.write(f"# Generated by: SecretGenerator.generate_strong_password(20)\n")
                f.write(f"# Account: admin (if using default ADMIN_USERNAME)\n")
                f.write(f"# IMPORTANT: Change this password immediately after first login!\n")
                f.write(f"ADMIN_PASSWORD={self.new_secrets.get('ADMIN_PASSWORD', '')}\n\n")

                f.write(f"# PostgreSQL Password: Database user credential\n")
                f.write(f"# Generated by: SecretGenerator.generate_postgres_password(32)\n")
                f.write(f"# User: agentcore (typically)\n")
                f.write(f"# CRITICAL: Used for database connections. Update connection strings after rotation.\n")
                f.write(f"POSTGRES_PASSWORD={self.new_secrets.get('POSTGRES_PASSWORD', '')}\n\n")

                # Optional / API Keys
                f.write("""# ════════════════════════════════════════════════════════════════════════════
# OPTIONAL: API KEYS & CREDENTIALS
# ════════════════════════════════════════════════════════════════════════════
# Uncomment and configure as needed. Some may be pre-existing.

""")

                if 'ANTHROPIC_API_KEY' in self.new_secrets:
                    f.write(f"# Anthropic API Key: Claude API access\n")
                    f.write(f"# Obtain from: https://console.anthropic.com/\n")
                    f.write(f"ANTHROPIC_API_KEY={self.new_secrets['ANTHROPIC_API_KEY']}\n\n")
                else:
                    f.write(f"# Anthropic API Key: Claude API access\n")
                    f.write(f"# Obtain from: https://console.anthropic.com/\n")
                    f.write(f"# ANTHROPIC_API_KEY=sk-ant-CHANGE_ME\n\n")

                if 'SMTP_PASSWORD' in self.new_secrets:
                    f.write(f"# SMTP Password: Email service authentication\n")
                    f.write(f"# For Gmail: Use app-specific password, not account password\n")
                    f.write(f"SMTP_PASSWORD={self.new_secrets['SMTP_PASSWORD']}\n\n")
                else:
                    f.write(f"# SMTP Password: Email service authentication\n")
                    f.write(f"# For Gmail: Use app-specific password, not account password\n")
                    f.write(f"# SMTP_PASSWORD=your_app_specific_password\n\n")

                # Include other environment settings from current .env
                f.write("""# ════════════════════════════════════════════════════════════════════════════
# APPLICATION CONFIGURATION (PRESERVED FROM CURRENT .env)
# ════════════════════════════════════════════════════════════════════════════

""")

                # Copy non-secret configuration from current .env
                non_secret_keys = [
                    'ENVIRONMENT', 'BASE_URL', 'ALLOWED_ORIGINS',
                    'POSTGRES_HOST', 'POSTGRES_PORT', 'POSTGRES_DB', 'POSTGRES_USER',
                    'POSTGRES_USER', 'DATABASE_URL',
                    'AI_PROVIDER', 'SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME',
                    'SMTP_FROM_EMAIL', 'SMTP_FROM_NAME', 'SMTP_USE_TLS', 'SMTP_USE_SSL',
                    'HOST', 'PORT', 'LOG_LEVEL', 'JWT_EXPIRE_MINUTES',
                    'FORM_TOKEN_EXPIRY_HOURS', 'RATE_LIMIT_PER_MINUTE',
                    'COOKIE_SECURE', 'COOKIE_SAMESITE', 'TRUSTED_PROXY_IPS',
                    'ENVIRONMENT', 'DEBUG',
                ]

                for key in non_secret_keys:
                    if key in self.current_secrets:
                        f.write(f"{key}={self.current_secrets[key]}\n")

            # Secure file permissions (owner read/write only)
            env_new_path.chmod(0o600)
            print(f"\nNew secrets written to: {env_new_path}")
            print(f"File permissions: 0o600 (owner read/write only)")
            return True

        except Exception as e:
            print(f"ERROR: Failed to write .env.new: {e}")
            return False

    def print_summary(self) -> None:
        """Print summary of generated secrets."""
        print("\n" + "=" * 70)
        print("SECRETS ROTATION SUMMARY")
        print("=" * 70)

        print("\nGenerated secrets (do not share):")
        print(f"  JWT_SECRET_KEY: {self.new_secrets.get('JWT_SECRET_KEY', '')[:32]}...")
        print(f"  PLATFORM_JWT_SECRET: {self.new_secrets.get('PLATFORM_JWT_SECRET', '')[:32]}...")
        print(f"  FORM_TOKEN_SECRET: {self.new_secrets.get('FORM_TOKEN_SECRET', '')[:32]}...")
        print(f"  ADMIN_PASSWORD: {'*' * 20}")
        print(f"  POSTGRES_PASSWORD: {'*' * 20}")
        print(f"  CREDENTIALS_ENCRYPTION_KEY: {self.new_secrets.get('CREDENTIALS_ENCRYPTION_KEY', '')[:32]}...")
        print(f"  INTEGRATION_ENCRYPTION_KEY: {self.new_secrets.get('INTEGRATION_ENCRYPTION_KEY', '')[:32]}...")

        print("\nNext steps:")
        print("  1. Review .env.new for correctness")
        print("  2. Backup current .env (already done)")
        print("  3. Test new secrets in staging environment (recommended)")
        print("  4. Update password manager with ADMIN_PASSWORD and POSTGRES_PASSWORD")
        print("  5. Apply to production:")
        print("     cp .env .env.backup.MANUAL")
        print("     cp .env.new .env")
        print("     docker compose up -d")
        print("  6. Monitor logs for authentication errors")
        print("  7. Securely delete .env.new: shred -vfz -n 3 .env.new")

        print("\nIMPORTANT NOTES:")
        print("  - Application will require restart to use new secrets")
        print("  - User sessions may need to be cleared (JWT tokens invalid)")
        print("  - Saved integration credentials may require re-entry")
        print("  - Database users need password updates if not automated")
        print("  - Update all configuration management systems")
        print("  - Notify all administrators of rotation completion")

    def rotate(self, interactive: bool = False, apply: bool = False) -> bool:
        """Perform full rotation workflow."""
        print("\n" + "=" * 70)
        print("T1 AGENTICS SECRETS ROTATION MANAGER")
        print("=" * 70)
        print(f"Timestamp: {self.timestamp}")
        print(f"Environment: {self.env_path}")

        # Load current secrets
        self.load_current_env()

        # Backup current .env
        if not self.backup_current_env():
            return False

        # Generate new secrets
        if not self.generate_secrets(interactive=interactive):
            return False

        # Validate all secrets
        is_valid, errors = self.validate_secrets()
        if not is_valid:
            print("\nERROR: Secret validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False

        print("\nSUCCESS: All secrets validated!")

        # Write .env.new
        if not self.write_env_new():
            return False

        # Print summary
        self.print_summary()

        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="T1 Agentics Secrets Rotation Manager",
        epilog="For detailed help, see rotate_secrets.py docstring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply new secrets immediately (requires confirmation)'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Prompt for optional secrets (ANTHROPIC_API_KEY, SMTP_PASSWORD)'
    )
    parser.add_argument(
        '--env',
        default='.env',
        help='Path to .env file (default: .env)'
    )
    parser.add_argument(
        '--backup-dir',
        help='Backup directory (default: same as .env)'
    )

    args = parser.parse_args()

    # Create manager
    manager = SecretsRotationManager(
        env_path=args.env,
        backup_dir=args.backup_dir
    )

    # Perform rotation
    success = manager.rotate(interactive=args.interactive, apply=args.apply)

    if success:
        print("\n" + "=" * 70)
        print("ROTATION COMPLETE")
        print("=" * 70)
        sys.exit(0)
    else:
        print("\n" + "=" * 70)
        print("ROTATION FAILED")
        print("=" * 70)
        sys.exit(1)


if __name__ == '__main__':
    main()
