#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Database Reset Script for AgentCore
Clears alerts, investigations, agent executions, token metrics, AI/ML data, and ingested emails.

Usage:
    python reset_database.py              # Reset all data
    python reset_database.py --confirm    # Skip confirmation prompt
    python reset_database.py --tokens     # Reset only token/AI usage data
    python reset_database.py --emails     # Reset only ingested emails
"""

import asyncio
import sys
import asyncpg

DB_URL = 'postgresql://agentcore:agentcore_dev_password@localhost:5432/agentcore'


async def get_counts(conn):
    """Get current record counts."""
    alerts = await conn.fetchval('SELECT COUNT(*) FROM alerts')
    investigations = await conn.fetchval('SELECT COUNT(*) FROM investigations')
    executions = await conn.fetchval('SELECT COUNT(*) FROM agent_executions')
    return alerts, investigations, executions


async def get_email_counts(conn):
    """Get ingested email counts."""
    counts = {}

    # Check each email table
    email_tables = [
        ('inbound_email_queue', 'Ingested emails'),
        ('email_log', 'Email log entries'),
        ('email_digest_queue', 'Email digest queue'),
    ]

    for table_name, desc in email_tables:
        try:
            count = await conn.fetchval(f'SELECT COUNT(*) FROM {table_name}')
            counts[table_name] = (count, desc)
        except:
            pass  # Table doesn't exist

    # Get total processed from mailboxes
    try:
        total_processed = await conn.fetchval(
            'SELECT COALESCE(SUM(emails_processed_total), 0) FROM inbound_mailboxes'
        )
        counts['mailbox_counters'] = (total_processed, 'Total emails processed (mailbox counters)')
    except:
        pass

    return counts


async def reset_emails_only(conn):
    """Reset only ingested email data."""
    print("\nResetting ingested email data...")

    # Tables to clear
    email_tables = [
        'inbound_email_queue',
        'email_log',
        'email_digest_queue',
    ]

    for table_name in email_tables:
        try:
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = $1
                )
            """, table_name)

            if exists:
                await conn.execute(f'TRUNCATE {table_name} CASCADE')
                print(f"  - Cleared {table_name}")
        except Exception as e:
            print(f"  - Skipped {table_name} ({e})")

    # Reset mailbox counters
    try:
        await conn.execute('''
            UPDATE inbound_mailboxes
            SET emails_processed_total = 0,
                last_poll_status = 'reset'
        ''')
        print("  - Reset mailbox counters to 0")
    except Exception as e:
        print(f"  - Skipped mailbox counters reset ({e})")

    print("\nEmail data reset complete!")


async def get_token_counts(conn):
    """Get token/AI usage counts."""
    counts = {}

    # Check each table exists before counting
    tables_to_check = [
        ('ai_token_usage', 'AI token usage records'),
        ('ml_predictions', 'ML predictions'),
        ('ml_training_runs', 'ML training runs'),
        ('model_performance_daily', 'Model performance metrics'),
    ]

    for table_name, desc in tables_to_check:
        try:
            count = await conn.fetchval(f'SELECT COUNT(*) FROM {table_name}')
            counts[table_name] = (count, desc)
        except:
            pass  # Table doesn't exist

    return counts


async def reset_tokens_only(conn):
    """Reset only token and AI-related data."""
    print("\nResetting token and AI usage data...")

    # Tables to reset (in order to handle dependencies)
    token_tables = [
        'ai_token_usage',
        'ml_predictions',
        'ml_training_runs',
        'model_performance_daily',
        'daily_aggregates',
        'token_usage',
    ]

    for table_name in token_tables:
        try:
            # Check if table exists
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = $1
                )
            """, table_name)

            if exists:
                await conn.execute(f'TRUNCATE {table_name} CASCADE')
                print(f"  - Cleared {table_name}")
        except Exception as e:
            print(f"  - Skipped {table_name} ({e})")

    # Also clear ML model files if they exist
    import os
    ml_model_dir = os.path.join(os.path.dirname(__file__), 'backend', 'ml_models')
    if os.path.exists(ml_model_dir):
        for f in os.listdir(ml_model_dir):
            if f.endswith(('.pkl', '.json')):
                try:
                    os.remove(os.path.join(ml_model_dir, f))
                    print(f"  - Deleted ML model file: {f}")
                except:
                    pass

    print("\nToken/AI data reset complete!")


async def reset_database(skip_confirm=False, tokens_only=False, emails_only=False):
    """Reset all operational data in the database."""
    try:
        conn = await asyncpg.connect(DB_URL)
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        print(f"Connection URL: {DB_URL}")
        return False

    try:
        # Handle emails-only reset
        if emails_only:
            email_counts = await get_email_counts(conn)
            print("\nCurrent email data:")
            total = 0
            for table_name, (count, desc) in email_counts.items():
                print(f"  - {desc}: {count}")
                total += count

            if total == 0:
                print("\nNo email data to reset.")
                await conn.close()
                return True

            if not skip_confirm:
                response = input("\nReset all ingested email data? (yes/no): ")
                if response.lower() not in ('yes', 'y'):
                    print("Aborted.")
                    await conn.close()
                    return False

            await reset_emails_only(conn)
            await conn.close()
            return True

        if tokens_only:
            # Just reset token data
            token_counts = await get_token_counts(conn)
            print("\nCurrent token/AI data:")
            total = 0
            for table_name, (count, desc) in token_counts.items():
                print(f"  - {desc}: {count}")
                total += count

            if total == 0:
                print("\nNo token/AI data to reset.")
                await conn.close()
                return True

            if not skip_confirm:
                response = input("\nReset all token and AI usage data? (yes/no): ")
                if response.lower() not in ('yes', 'y'):
                    print("Aborted.")
                    await conn.close()
                    return False

            await reset_tokens_only(conn)
            await conn.close()
            return True

        # Full reset
        alerts, investigations, executions = await get_counts(conn)
        token_counts = await get_token_counts(conn)
        email_counts = await get_email_counts(conn)

        print(f"\nCurrent data:")
        print(f"  - Alerts:         {alerts}")
        print(f"  - Investigations: {investigations}")
        print(f"  - Executions:     {executions}")

        if email_counts:
            print("\nEmail data:")
            for table_name, (count, desc) in email_counts.items():
                print(f"  - {desc}: {count}")

        if token_counts:
            print("\nToken/AI data:")
            for table_name, (count, desc) in token_counts.items():
                print(f"  - {desc}: {count}")

        total = alerts + investigations + executions + sum(c for c, _ in token_counts.values()) + sum(c for c, _ in email_counts.values())
        if total == 0:
            print("\nDatabase is already empty. Nothing to reset.")
            await conn.close()
            return True

        # Confirm unless --confirm flag passed
        if not skip_confirm:
            response = input("\nAre you sure you want to delete all this data? (yes/no): ")
            if response.lower() not in ('yes', 'y'):
                print("Aborted.")
                await conn.close()
                return False

        print("\nResetting database...")

        # Use TRUNCATE with CASCADE to handle all foreign keys
        await conn.execute('''
            TRUNCATE
                alerts,
                investigations,
                agent_executions,
                agent_action_log
            CASCADE
        ''')
        print("  - Cleared alerts, investigations, executions")

        # Clear ingested emails
        email_tables = ['inbound_email_queue', 'email_log', 'email_digest_queue']
        for table_name in email_tables:
            try:
                exists = await conn.fetchval("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = $1
                    )
                """, table_name)
                if exists:
                    await conn.execute(f'TRUNCATE {table_name} CASCADE')
                    print(f"  - Cleared {table_name}")
            except Exception as e:
                print(f"  - Skipped {table_name} ({e})")

        # Reset mailbox counters
        try:
            await conn.execute('''
                UPDATE inbound_mailboxes
                SET emails_processed_total = 0,
                    last_poll_status = 'reset'
            ''')
            print("  - Reset mailbox counters to 0")
        except Exception as e:
            print(f"  - Skipped mailbox counters ({e})")

        # Reset token/metrics tables (check which exist)
        tables = await conn.fetch("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name IN (
                'token_usage',
                'model_performance_daily',
                'daily_aggregates',
                'action_approvals',
                'ai_token_usage',
                'ml_predictions',
                'ml_training_runs',
                'investigation_audit_log',
                'chat_messages',
                'investigation_notes'
            )
        """)

        for t in tables:
            table_name = t['table_name']
            try:
                await conn.execute(f'TRUNCATE {table_name} CASCADE')
                print(f"  - Cleared {table_name}")
            except Exception as e:
                print(f"  - Skipped {table_name} ({e})")

        # Clear ML model files
        import os
        ml_model_dir = os.path.join(os.path.dirname(__file__), 'backend', 'ml_models')
        if os.path.exists(ml_model_dir):
            for f in os.listdir(ml_model_dir):
                if f.endswith(('.pkl', '.json')):
                    try:
                        os.remove(os.path.join(ml_model_dir, f))
                        print(f"  - Deleted ML model file: {f}")
                    except:
                        pass

        # Verify
        alerts_after, inv_after, exec_after = await get_counts(conn)
        print(f"\nAfter reset:")
        print(f"  - Alerts:         {alerts_after}")
        print(f"  - Investigations: {inv_after}")
        print(f"  - Executions:     {exec_after}")
        print("\nReset complete!")

        await conn.close()
        return True

    except Exception as e:
        print(f"\nError during reset: {e}")
        await conn.close()
        return False


def main():
    skip_confirm = '--confirm' in sys.argv or '-y' in sys.argv
    tokens_only = '--tokens' in sys.argv
    emails_only = '--emails' in sys.argv

    if '--help' in sys.argv or '-h' in sys.argv:
        print(__doc__)
        return

    success = asyncio.run(reset_database(skip_confirm, tokens_only, emails_only))
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
