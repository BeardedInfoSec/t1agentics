/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * useApi Hook
 *
 * Generic hook for making API calls with loading, error, and data state.
 * Supports automatic refresh, caching, and abort handling.
 */

import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * @typedef {Object} UseApiOptions
 * @property {boolean} [immediate=true] - Fetch immediately on mount
 * @property {number} [refreshInterval] - Auto-refresh interval in ms
 * @property {boolean} [keepPreviousData=false] - Keep previous data while refetching
 * @property {function} [onSuccess] - Callback on successful fetch
 * @property {function} [onError] - Callback on error
 */

/**
 * @typedef {Object} UseApiResult
 * @template T
 * @property {T|null} data - The fetched data
 * @property {boolean} loading - Initial loading state
 * @property {boolean} isRefreshing - Refresh loading state
 * @property {Error|null} error - Error if request failed
 * @property {function} refetch - Manually trigger refetch
 * @property {function} mutate - Manually set data
 * @property {number|null} lastUpdated - Timestamp of last successful fetch
 */

/**
 * Generic API hook
 *
 * @template T
 * @param {function(): Promise<T>} fetcher - Async function that returns data
 * @param {any[]} deps - Dependencies that trigger refetch
 * @param {UseApiOptions} [options] - Configuration options
 * @returns {UseApiResult<T>}
 */
export function useApi(fetcher, deps = [], options = {}) {
  const {
    immediate = true,
    refreshInterval,
    keepPreviousData = false,
    onSuccess,
    onError
  } = options;

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(immediate);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const mountedRef = useRef(true);
  const abortControllerRef = useRef(null);
  const intervalRef = useRef(null);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  // Main fetch function
  const fetchData = useCallback(async (isRefresh = false) => {
    // Abort previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    // Create new abort controller
    abortControllerRef.current = new AbortController();

    if (isRefresh) {
      setIsRefreshing(true);
    } else {
      if (!keepPreviousData) {
        setData(null);
      }
      setLoading(true);
    }

    setError(null);

    try {
      const result = await fetcher(abortControllerRef.current.signal);

      if (!mountedRef.current) return;

      setData(result);
      setLastUpdated(Date.now());
      setError(null);

      if (onSuccess) {
        onSuccess(result);
      }
    } catch (err) {
      if (!mountedRef.current) return;

      // Ignore abort errors
      if (err.name === 'AbortError') return;

      setError(err);

      if (onError) {
        onError(err);
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
        setIsRefreshing(false);
      }
    }
  }, [fetcher, keepPreviousData, onSuccess, onError]);

  // Refetch function
  const refetch = useCallback((force = false) => {
    return fetchData(data !== null && !force);
  }, [fetchData, data]);

  // Mutate function (manually set data)
  const mutate = useCallback((newData) => {
    if (typeof newData === 'function') {
      setData(prev => newData(prev));
    } else {
      setData(newData);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    if (immediate) {
      fetchData(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  // Auto-refresh interval
  useEffect(() => {
    if (refreshInterval && refreshInterval > 0) {
      intervalRef.current = setInterval(() => {
        if (mountedRef.current) {
          fetchData(true);
        }
      }, refreshInterval);

      return () => {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
        }
      };
    }
  }, [refreshInterval, fetchData]);

  return {
    data,
    loading,
    isRefreshing,
    error,
    refetch,
    mutate,
    lastUpdated
  };
}

/**
 * Hook for paginated API calls
 *
 * @template T
 * @param {function(Object): Promise<{items: T[], total: number}>} fetcher
 * @param {Object} [initialFilters]
 * @param {UseApiOptions} [options]
 */
export function usePaginatedApi(fetcher, initialFilters = {}, options = {}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(options.pageSize || 25);
  const [filters, setFilters] = useState(initialFilters);
  const [total, setTotal] = useState(0);

  const paginatedFetcher = useCallback(async (signal) => {
    const result = await fetcher({ page, pageSize, ...filters }, signal);
    setTotal(result.total || 0);
    return result.items;
  }, [fetcher, page, pageSize, filters]);

  const api = useApi(paginatedFetcher, [page, pageSize, JSON.stringify(filters)], {
    ...options,
    immediate: true
  });

  const updateFilters = useCallback((newFilters) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
    setPage(1); // Reset to first page on filter change
  }, []);

  const resetFilters = useCallback(() => {
    setFilters(initialFilters);
    setPage(1);
  }, [initialFilters]);

  return {
    ...api,
    page,
    setPage,
    pageSize,
    setPageSize,
    filters,
    setFilters: updateFilters,
    resetFilters,
    total,
    totalPages: Math.ceil(total / pageSize),
    hasNextPage: page * pageSize < total,
    hasPrevPage: page > 1
  };
}

export default useApi;
