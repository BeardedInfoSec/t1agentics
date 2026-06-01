# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Create Initial Platform Admin Account

Run this script to create the first platform admin for T1 Agentics.

Usage:
    python scripts/create_platform_admin.py
"""

import asyncio
import bcrypt
import json
import uuid
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def create_platform_admin():
    """Create the initial platform admin account."""
    from services.postgres_db import postgres_db

    # Default admin credentials - CHANGE IN PRODUCTION
    email = os.environ.get('PLATFORM_ADMIN_EMAIL', 'admin@t1agentics.ai')
    password = os.environ.get('PLATFORM_ADMIN_PASSWORD', 'T1Agentics2024!')
    name = os.environ.get('PLATFORM_ADMIN_NAME', 'T1 Platform Admin')

    print("=" * 60)
    print("T1 Agentics Platform Admin Setup")
    print("=" * 60)

    # Connect to database
    print("\nConnecting to database...")
    try:
        await postgres_db.connect()
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        print("\nMake sure the database is running and POSTGRES_* environment variables are set.")
        return False

    if not postgres_db.connected or postgres_db.pool is None:
        print("Database connection failed")
        return False

    print("Connected!")

    async with postgres_db.pool.acquire() as conn:
        # Check if admin already exists
        existing = await conn.fetchval(
            "SELECT id FROM platform_admins WHERE email = $1",
            email.lower()
        )

        if existing:
            print(f"\nPlatform admin with email '{email}' already exists!")
            print("If you need to reset the password, delete the admin and run again.")
            return True

        # Create admin
        admin_id = uuid.uuid4()
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        permissions = json.dumps(["read", "write", "manage_tenants", "manage_licenses"])
        await conn.execute("""
            INSERT INTO platform_admins (id, user_id, email, name, password_hash, permissions)
            VALUES ($1, $1, $2, $3, $4, $5::jsonb)
        """, admin_id, email.lower(), name, password_hash, permissions)

        # Log creation
        audit_details = json.dumps({"email": email, "name": name, "initial_setup": True})
        await conn.execute("""
            INSERT INTO platform_audit_log (admin_id, action, details)
            VALUES ($1, 'admin_created', $2::jsonb)
        """, admin_id, audit_details)

        print(f"\nPlatform admin created successfully!")
        print("-" * 40)
        print(f"Email:    {email}")
        print(f"Password: {password}")
        print("-" * 40)
        print("\n[!] IMPORTANT: Change the default password after first login!")
        print("\nAccess the Platform Admin dashboard at:")
        print("  http://localhost:3000/platform-admin")

    await postgres_db.disconnect()
    return True


if __name__ == "__main__":
    success = asyncio.run(create_platform_admin())
    sys.exit(0 if success else 1)
