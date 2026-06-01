/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * License Cache Utility
 *
 * Fetches license tier + feature flags ONCE per session from /api/v1/users/me,
 * caches in sessionStorage with a 5-minute TTL. All components read from cache
 * to avoid redundant API calls.
 *
 * Cache includes:
 * - tier: string (free, pro, enterprise, dev, unlimited)
 * - features: object (feature flags)
 * - riggs_limits: object (per-feature monthly limits)
 * - riggs_usage: object (current month usage counts)
 * - cached_at: timestamp
 */

import { API_BASE_URL } from './api';

const CACHE_KEY = 't1_license_tier';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Get the current tenant's license tier and feature entitlements.
 * Returns cached data if valid, otherwise fetches from /api/v1/users/me.
 *
 * @returns {Promise<{tier: string, features: object, riggs_limits: object, riggs_usage: object}>}
 */
export async function getLicenseTier() {
  // Check cache first
  try {
    const cached = sessionStorage.getItem(CACHE_KEY);
    if (cached) {
      const data = JSON.parse(cached);
      if (Date.now() - data.cached_at < CACHE_TTL_MS) {
        return data;
      }
    }
  } catch {
    // Corrupted cache — ignore and refetch
  }

  // Fetch from API
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/users/me`, {
      credentials: 'include',
    });

    if (!res.ok) {
      // Return safe defaults on failure
      return _defaults();
    }

    const user = await res.json();

    const data = {
      tier: user.license_tier || 'free',
      features: user.features || {},
      riggs_limits: user.riggs_limits || {},
      riggs_usage: user.riggs_usage || {},
      deep_dive_usage: user.deep_dive_usage || {},
      cached_at: Date.now(),
    };

    sessionStorage.setItem(CACHE_KEY, JSON.stringify(data));
    return data;
  } catch {
    return _defaults();
  }
}

/**
 * Check if a specific feature is enabled for the current tenant.
 * @param {string} feature - Feature name (e.g. "deep_dive", "riggs_chat")
 * @returns {Promise<boolean>}
 */
export async function hasFeature(feature) {
  const license = await getLicenseTier();
  return !!license.features[feature];
}

/**
 * Check if the current tenant is on a Pro or higher tier.
 * @returns {Promise<boolean>}
 */
export async function isProOrAbove() {
  const license = await getLicenseTier();
  return ['pro', 'professional', 'enterprise', 'unlimited', 'dev'].includes(license.tier);
}

/**
 * Get remaining Riggs usage for a feature.
 * @param {"chat"|"playbook_create"} feature
 * @returns {Promise<{used: number, limit: number, remaining: number, unlimited: boolean}>}
 */
export async function getRiggsUsage(feature) {
  const license = await getLicenseTier();
  const usage = license.riggs_usage?.[feature];
  if (!usage) {
    return { used: 0, limit: 0, remaining: 0, unlimited: true };
  }
  return usage;
}

/**
 * Invalidate the license cache. Call on login/logout.
 */
export function clearLicenseCache() {
  sessionStorage.removeItem(CACHE_KEY);
}

/**
 * Force refresh the license cache (ignoring TTL).
 * Useful after an action that changes usage counts.
 */
export async function refreshLicenseCache() {
  sessionStorage.removeItem(CACHE_KEY);
  return getLicenseTier();
}

function _defaults() {
  return {
    tier: 'free',
    features: {},
    riggs_limits: {},
    riggs_usage: {},
    deep_dive_usage: {},
    cached_at: 0,
  };
}
