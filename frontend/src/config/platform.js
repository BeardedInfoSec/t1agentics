/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Platform configuration — single source of truth for platform-level constants.
 */

// UUID of the platform-owner tenant. This MUST match the tenant created by the
// backend bootstrap (PLATFORM_OWNER_TENANT_ID, overridable via DEFAULT_TENANT_ID).
// The default below is the OSS bootstrap default; override at build time with
// REACT_APP_PLATFORM_OWNER_TENANT_ID if the backend uses a different value.
export const PLATFORM_OWNER_TENANT_ID =
  process.env.REACT_APP_PLATFORM_OWNER_TENANT_ID ||
  '00000000-0000-0000-0000-000000000001';
