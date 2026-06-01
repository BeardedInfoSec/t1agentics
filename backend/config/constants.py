# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform-wide constants for T1 Agentics.
"""
import os

# The UUID for the T1 Agentics platform owner tenant.
# Can be overridden via DEFAULT_TENANT_ID env var for custom deployments.
PLATFORM_OWNER_TENANT_ID = os.getenv(
    "DEFAULT_TENANT_ID", "00000000-0000-0000-0000-000000000001"
)
