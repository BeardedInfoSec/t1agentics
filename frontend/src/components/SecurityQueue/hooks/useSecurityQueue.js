/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * useSecurityQueue Hook
 *
 * Fetches alerts and investigations, transforms them into unified SecurityQueueItems.
 * Handles auto-refresh and loading states.
 *
 * This is the ONLY place where raw API data is transformed - all consumers
 * work with the normalized SecurityQueueItem type.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { getAuthHeaders, API_BASE_URL } from '../../../utils/api';
import { buildSecurityQueue, computeMetrics } from '../transforms';
import { AUTO_REFRESH_INTERVAL } from '../constants';

/**
 * @typedef {Object} UseSecurityQueueResult
 * @property {import('../types').SecurityQueueItem[]} items - Transformed queue items
 * @property {import('../types').QueueMetrics} metrics - Computed metrics
 * @property {boolean} loading - Initial load in progress
 * @property {boolean} isRefreshing - Background refresh in progress
 * @property {string|null} error - Error message if fetch failed
 * @property {Object} systemConfig - System configuration for display settings
 * @property {Function} refetch - Manual refetch function
 */

/**
 * Hook for fetching and transforming security queue data
 * @param {Object} options
 * @param {boolean} [options.autoRefresh=true] - Enable auto-refresh
 * @param {number} [options.refreshInterval] - Custom refresh interval in ms
 * @returns {UseSecurityQueueResult}
 */
export function useSecurityQueue(options = {}) {
  const {
    autoRefresh = true,
    refreshInterval = AUTO_REFRESH_INTERVAL,
  } = options;

  // Cap values must match the server-side limits used in fetchData below.
  // If the response length equals the cap, we assume the server truncated
  // and surface a warning to the analyst instead of silently hiding rows.
  const ALERT_FETCH_LIMIT = 500;
  const INVESTIGATION_FETCH_LIMIT = 1000;

  // Raw data from API
  const [alerts, setAlerts] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [systemConfig, setSystemConfig] = useState({});

  // Loading states
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Truncation flags — true when the server returned exactly the cap value.
  const [truncated, setTruncated] = useState({ alerts: false, investigations: false });

  // Track if component is mounted to avoid state updates after unmount
  const mountedRef = useRef(true);

  /**
   * Fetch all data from API
   * @param {boolean} showFullLoading - Show loading spinner (true for initial, false for background)
   */
  const fetchData = useCallback(async (showFullLoading = false) => {
    if (showFullLoading) {
      setLoading(true);
      setError(null);
    } else {
      setIsRefreshing(true);
    }

    try {
      // Fetch alerts, investigations, and config in parallel
      // include_investigated=true: the queue dedups alert↔investigation pairs itself
      // and needs the alert row to preserve source/source_type on the merged item.
      const alertUrl = `${API_BASE_URL}/api/v1/alerts?limit=${ALERT_FETCH_LIMIT}&include_investigated=true`;
      const invUrl = `${API_BASE_URL}/api/v1/investigations?limit=${INVESTIGATION_FETCH_LIMIT}`;
      const configUrl = `${API_BASE_URL}/api/v1/config/`;

      const [alertsRes, investigationsRes, configRes] = await Promise.all([
        fetch(alertUrl, { headers: getAuthHeaders() }),
        fetch(invUrl, { headers: getAuthHeaders() }),
        fetch(configUrl, { headers: getAuthHeaders() }),
      ]);

      // Check for auth errors - redirect to login if session expired
      if (alertsRes.status === 401 || investigationsRes.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('role');
        window.location.href = '/login';
        return;
      }

      // Only update state if still mounted
      if (!mountedRef.current) return;

      const alertsData = alertsRes.ok ? await alertsRes.json() : [];
      const investigationsData = investigationsRes.ok ? await investigationsRes.json() : [];
      const configData = configRes.ok ? await configRes.json() : {};

      const alertList = Array.isArray(alertsData) ? alertsData : [];
      const invList = Array.isArray(investigationsData) ? investigationsData : [];
      setAlerts(alertList);
      setInvestigations(invList);
      setSystemConfig(configData);
      setTruncated({
        alerts: alertList.length >= ALERT_FETCH_LIMIT,
        investigations: invList.length >= INVESTIGATION_FETCH_LIMIT,
      });
      setError(null);
    } catch (err) {
      if (mountedRef.current) {
        setError(err.message || 'Failed to fetch data');
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
        setIsRefreshing(false);
      }
    }
  }, []);

  // Initial fetch and auto-refresh setup
  useEffect(() => {
    mountedRef.current = true;

    // Initial load with full loading state
    fetchData(true);

    // Set up auto-refresh interval
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => fetchData(false), refreshInterval);
    }

    return () => {
      mountedRef.current = false;
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, refreshInterval, fetchData]);

  // Transform raw data into unified queue items
  // This runs on every render but is cheap - just array mapping
  const items = buildSecurityQueue(alerts, investigations);

  // Compute metrics from transformed items
  const metrics = computeMetrics(items);

  // Manual refetch function for pull-to-refresh or manual refresh button
  const refetch = useCallback((showLoading = true) => {
    return fetchData(showLoading);
  }, [fetchData]);

  /**
   * Patch a single item in-place without a full refetch.
   * Field names are queue-item level (e.g. "status") and get mapped to the
   * raw API field names where they differ (e.g. investigation "state").
   * @param {string} id - alert_id or investigation_id
   * @param {'alert'|'investigation'} itemType
   * @param {Object} patch - fields to merge (e.g. { severity: 'high', status: 'closed' })
   */
  const updateItem = useCallback((id, itemType, patch) => {
    if (itemType === 'alert') {
      setAlerts(prev => prev.map(a =>
        (a.id === id || a.alert_id === id) ? { ...a, ...patch } : a
      ));
    } else {
      // Map queue-item field names to raw investigation field names
      const rawPatch = { ...patch };
      if ('status' in rawPatch) {
        rawPatch.state = rawPatch.status;
        delete rawPatch.status;
      }
      setInvestigations(prev => prev.map(inv =>
        (inv.id === id || inv.investigation_id === id) ? { ...inv, ...rawPatch } : inv
      ));
    }
  }, []);

  return {
    items,
    metrics,
    loading,
    isRefreshing,
    error,
    systemConfig,
    refetch,
    updateItem,
    truncated,
    fetchLimits: { alerts: ALERT_FETCH_LIMIT, investigations: INVESTIGATION_FETCH_LIMIT },
  };
}

export default useSecurityQueue;
