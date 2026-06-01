# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ClickHouse Client

Manages ClickHouse connection for telemetry and analytics.
Uses clickhouse-driver for native protocol (port 9000).
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_client = None
_available = False


def get_clickhouse_client():
    """Get or create a ClickHouse client singleton. Returns None if unavailable."""
    global _client, _available

    if _client is not None:
        return _client if _available else None

    host = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
    port = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
    user = os.environ.get("CLICKHOUSE_USER", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")

    try:
        from clickhouse_driver import Client
        _client = Client(
            host=host,
            port=port,
            user=user,
            password=password,
            connect_timeout=5,
            send_receive_timeout=10,
        )
        # Health check
        result = _client.execute("SELECT 1")
        if result and result[0][0] == 1:
            _available = True
            logger.info(f"ClickHouse connected: {host}:{port}")
            return _client
        else:
            _available = False
            logger.warning("ClickHouse health check failed")
            return None
    except ImportError:
        logger.warning("clickhouse-driver not installed")
        _available = False
        return None
    except Exception as e:
        logger.warning(f"ClickHouse unavailable: {e}")
        _available = False
        return None


def is_clickhouse_available() -> bool:
    """Check if ClickHouse is available without creating a connection."""
    return _available
