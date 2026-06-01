/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * useDashboardStats Hook
 *
 * Centralized hook for fetching and managing dashboard statistics.
 * Provides consistent error handling, loading states, and data transformation.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { API_BASE_URL, getAuthHeaders } from '../../utils/api';
import { generateAutomationData, getRecentAlerts } from './dashboardUtils';
import {
  TIME_RANGES,
  REFRESH_INTERVALS,
  PAGINATION_CONFIG,
  ERROR_MESSAGES
} from './DashboardConfig';

/**
 * Dashboard Stats Hook
 * @param {string} initialRange - Initial time range ('24h', '7d', '30d', '90d')
 * @param {object} options - Optional configuration
 * @param {boolean} options.autoRefresh - Whether to auto-refresh (default: true)
 * @param {number} options.refreshInterval - Refresh interval in ms (default: 30000)
 * @returns {object} Dashboard stats and controls
 */
export function useDashboardStats(initialRange = '7d', options = {}) {
  const {
    autoRefresh = true,
    refreshInterval = REFRESH_INTERVALS.stats
  } = options;

  // State
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState(initialRange);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Ref to track mounted state
  const mountedRef = useRef(true);
  const abortControllerRef = useRef(null);
  const hasDataRef = useRef(false);

  /**
   * Fetch dashboard data from API
   */
  const fetchDashboardData = useCallback(async (showLoadingState = false) => {
    // Cancel any pending request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    // Create new abort controller
    abortControllerRef.current = new AbortController();

    // Only show loading state on initial load or explicit refresh
    if (showLoadingState || !hasDataRef.current) {
      setLoading(true);
    }
    setError(null);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/stats?time_range=${timeRange}`,
        {
          headers: getAuthHeaders(),
          credentials: 'include',
          signal: abortControllerRef.current.signal
        }
      );

      // Check if component is still mounted
      if (!mountedRef.current) return;

      if (!response.ok) {
        const errorData = {
          status: response.status,
          message: response.statusText
        };

        // Try to get error detail from response
        try {
          const errorJson = await response.json();
          errorData.message = errorJson.detail || errorJson.message || response.statusText;
        } catch {
          // Use default statusText
        }

        throw errorData;
      }

      const data = await response.json();

      if (!mountedRef.current) return;

      hasDataRef.current = true;
      setStats(data);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      // Ignore abort errors
      if (err.name === 'AbortError') return;

      if (!mountedRef.current) return;

      // Set appropriate error message
      if (err.status) {
        setError(err);
      } else if (err.message?.includes('fetch') || err.message?.includes('network')) {
        setError({ message: ERROR_MESSAGES.network });
      } else {
        setError({ message: err.message || ERROR_MESSAGES.default });
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [timeRange]);

  /**
   * Manual refresh function
   */
  const refresh = useCallback(() => {
    return fetchDashboardData(true);
  }, [fetchDashboardData]);

  // Initial fetch and auto-refresh setup
  useEffect(() => {
    mountedRef.current = true;

    fetchDashboardData(true);

    // Setup auto-refresh interval
    let intervalId = null;
    if (autoRefresh) {
      intervalId = setInterval(() => {
        if (mountedRef.current) {
          fetchDashboardData(false);
        }
      }, refreshInterval);
    }

    // Cleanup
    return () => {
      mountedRef.current = false;
      if (intervalId) {
        clearInterval(intervalId);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchDashboardData, autoRefresh, refreshInterval]);

  /**
   * Get time range label
   */
  const getTimeRangeLabel = useCallback(() => {
    return TIME_RANGES[timeRange]?.label || 'Last 7 Days';
  }, [timeRange]);

  /**
   * Memoized computed values
   */
  const alertTrendData = useMemo(() => {
    if (!stats?.alert_trend) return [];
    return stats.alert_trend.map((d) => ({
      time: d.date,
      count: d.count
    }));
  }, [stats?.alert_trend]);

  const automationTrendData = useMemo(() => {
    if (stats?.automation_trend?.length > 0) {
      return stats.automation_trend;
    }
    return generateAutomationData();
  }, [stats?.automation_trend]);

  const severityDistribution = useMemo(() => {
    return stats?.severity_distribution || {};
  }, [stats?.severity_distribution]);

  const severityTotal = useMemo(() => {
    const total = Object.values(severityDistribution).reduce(
      (sum, val) => sum + (val || 0),
      0
    );
    return total || 1; // Prevent division by zero
  }, [severityDistribution]);

  const criticalCount = useMemo(() => {
    return severityDistribution.critical || 0;
  }, [severityDistribution]);

  const autoClosed = useMemo(() => {
    return stats?.ai_impact?.alerts_auto_closed || 0;
  }, [stats?.ai_impact?.alerts_auto_closed]);

  const totalAlerts = useMemo(() => {
    return stats?.total_alerts || 0;
  }, [stats?.total_alerts]);

  const automationRate = useMemo(() => {
    if (!totalAlerts) return 0;
    return Math.min(
      Math.round((autoClosed / Math.max(totalAlerts, 1)) * 100),
      100
    );
  }, [autoClosed, totalAlerts]);

  const automationManualSplit = useMemo(() => {
    return {
      automated: autoClosed,
      manual: Math.max(totalAlerts - autoClosed, 0)
    };
  }, [autoClosed, totalAlerts]);

  const analystLoad = useMemo(() => {
    return stats?.investigation_status_distribution || {};
  }, [stats?.investigation_status_distribution]);

  const recentAlerts = useMemo(() => {
    return getRecentAlerts(stats).slice(0, PAGINATION_CONFIG.maxRecentAlerts);
  }, [stats]);

  // Return all values
  return {
    // Data
    stats,
    loading,
    error,
    lastUpdated,

    // Time range controls
    timeRange,
    setTimeRange,
    getTimeRangeLabel,

    // Actions
    refresh,

    // Computed values
    alertTrendData,
    automationTrendData,
    severityDistribution,
    severityTotal,
    criticalCount,
    autoClosed,
    totalAlerts,
    automationRate,
    automationManualSplit,
    analystLoad,
    recentAlerts,

    // Config
    timeRanges: TIME_RANGES
  };
}

/**
 * Generic data fetching hook for dashboards
 * @param {string} endpoint - API endpoint to fetch
 * @param {object} options - Fetch options
 * @returns {object} Data, loading, error, and refresh function
 */
export function useDashboardData(endpoint, options = {}) {
  const {
    autoRefresh = false,
    refreshInterval = REFRESH_INTERVALS.stats,
    transform = (data) => data,
    initialData = null
  } = options;

  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const mountedRef = useRef(true);
  const abortControllerRef = useRef(null);

  const fetchData = useCallback(async (showLoading = true) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    abortControllerRef.current = new AbortController();

    if (showLoading) {
      setLoading(true);
    }
    setError(null);

    try {
      const url = endpoint.startsWith('http')
        ? endpoint
        : `${API_BASE_URL}${endpoint}`;

      const response = await fetch(url, {
        headers: getAuthHeaders(),
        credentials: 'include',
        signal: abortControllerRef.current.signal
      });

      if (!mountedRef.current) return;

      if (!response.ok) {
        throw {
          status: response.status,
          message: response.statusText
        };
      }

      const result = await response.json();

      if (!mountedRef.current) return;

      setData(transform(result));
      setError(null);
    } catch (err) {
      if (err.name === 'AbortError') return;
      if (!mountedRef.current) return;

      setError(err);
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [endpoint, transform]);

  const refresh = useCallback(() => {
    return fetchData(true);
  }, [fetchData]);

  useEffect(() => {
    mountedRef.current = true;

    fetchData(true);

    let intervalId = null;
    if (autoRefresh) {
      intervalId = setInterval(() => {
        if (mountedRef.current) {
          fetchData(false);
        }
      }, refreshInterval);
    }

    return () => {
      mountedRef.current = false;
      if (intervalId) clearInterval(intervalId);
      if (abortControllerRef.current) abortControllerRef.current.abort();
    };
  }, [fetchData, autoRefresh, refreshInterval]);

  return { data, loading, error, refresh };
}

export default useDashboardStats;
