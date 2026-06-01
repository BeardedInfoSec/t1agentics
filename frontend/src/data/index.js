/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Data Layer Index
 *
 * Centralized exports for the data abstraction layer.
 * Import from '@/data' for all data-related functionality.
 */

// API Client
export { apiClient, ApiClientError } from './apiClient';

// Adapters
export * from './adapters';

// Services
export * from './services';

// Types are imported via JSDoc, no runtime export needed
