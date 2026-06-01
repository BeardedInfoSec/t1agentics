# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Startup helpers for T1 Agentics.
"""

import logging

logger = logging.getLogger(__name__)


async def init_postgres_dependent_services(app, postgres_db):
    """
    Initialize services that require PostgreSQL.
    """
    # Initialize credentials service with database
    try:
        from services.credentials_service import get_credentials_service
        if postgres_db.connected:
            creds_service = get_credentials_service()
            creds_service.set_db(postgres_db)
            logger.info("[OK] Credentials service connected to database")
    except Exception as e:
        logger.warning(f"Credentials service init error: {e}")

    # Initialize token tracking service with database
    try:
        from services.token_tracking import get_token_tracker
        if postgres_db.connected:
            token_tracker = get_token_tracker()
            token_tracker.set_db(postgres_db)
            logger.info("[OK] Token tracking service connected to database")
    except Exception as e:
        logger.warning(f"Token tracking init error: {e}")

    # Initialize email notification service with database
    try:
        from services.email_service import get_email_service
        if postgres_db.connected:
            email_service = get_email_service()
            email_service.set_db(postgres_db)
            await email_service.initialize()
            logger.info("[OK] Email notification service connected to database")
    except Exception as e:
        logger.warning(f"Email service init error: {e}")

    # Connect the db wrapper service (uses PostgreSQL under the hood)
    try:
        from services.database import db
        await db.connect()
        logger.info("[OK] Database wrapper service connected")
    except Exception as e:
        logger.warning(f"Database wrapper connection error: {e}")
