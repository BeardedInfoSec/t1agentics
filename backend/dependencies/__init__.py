# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Dependencies package for T1 Agentics
Shared FastAPI dependencies for routes.
"""

from .auth import (
    get_current_user,
    get_current_username,
    require_admin,
    require_role,
    optional_auth,
    decode_jwt_token,
    RequireAuth,
    RequireAdmin,
    GetUsername,
    OptionalAuth
)

__all__ = [
    "get_current_user",
    "get_current_username",
    "require_admin",
    "require_role",
    "optional_auth",
    "decode_jwt_token",
    "RequireAuth",
    "RequireAdmin",
    "GetUsername",
    "OptionalAuth"
]
