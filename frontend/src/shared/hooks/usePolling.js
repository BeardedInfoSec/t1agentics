/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * usePolling Hook
 *
 * Polls an async function at a specified interval with
 * proper cleanup and error handling.
 */

import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * @typedef {Object} UsePollingOptions
 * @property {number} interval - Polling interval in milliseconds
 * @property {boolean} [immediate=true] - Execute immediately on mount
 * @property {boolean} [enabled=true] - Whether polling is enabled
 * @property {number} [maxErrors=3] - Max consecutive errors before stopping
 * @property {function} [onError] - Error callback
 * @property {function} [onSuccess] - Success callback
 */

/**
 * @typedef {Object} UsePollingResult
 * @template T
 * @property {T|null} data - Latest polled data
 * @property {boolean} loading - Initial loading state
 * @property {Error|null} error - Latest error
 * @property {boolean} isPolling - Whether currently polling
 * @property {function} start - Start polling
 * @property {function} stop - Stop polling
 * @property {function} poll - Manual poll trigger
 * @property {number} pollCount - Number of successful polls
 */

/**
 * Polling hook with error handling and auto-stop on errors
 *
 * @template T
 * @param {function(): Promise<T>} fetcher - Async function to poll
 * @param {UsePollingOptions} options - Polling configuration
 * @returns {UsePollingResult<T>}
 */
export function usePolling(fetcher, options) {
  const {
    interval,
    immediate = true,
    enabled = true,
    maxErrors = 3,
    onError,
    onSuccess
  } = options;

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(immediate);
  const [error, setError] = useState(null);
  const [isPolling, setIsPolling] = useState(enabled);
  const [pollCount, setPollCount] = useState(0);

  const mountedRef = useRef(true);
  const intervalRef = useRef(null);
  const errorCountRef = useRef(0);
  const abortControllerRef = useRef(null);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  // Execute poll
  const executePoll = useCallback(async () => {
    if (!mountedRef.current) return;

    // Abort previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    try {
      const result = await fetcher(abortControllerRef.current.signal);

      if (!mountedRef.current) return;

      setData(result);
      setError(null);
      setLoading(false);
      setPollCount(prev => prev + 1);
      errorCountRef.current = 0;

      if (onSuccess) {
        onSuccess(result);
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (err.name === 'AbortError') return;

      setError(err);
      setLoading(false);
      errorCountRef.current += 1;

      if (onError) {
        onError(err);
      }

      // Stop polling after max consecutive errors
      if (errorCountRef.current >= maxErrors) {
        setIsPolling(false);
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }
    }
  }, [fetcher, maxErrors, onError, onSuccess]);

  // Start polling
  const start = useCallback(() => {
    if (intervalRef.current) return; // Already polling

    setIsPolling(true);
    errorCountRef.current = 0;

    if (immediate) {
      executePoll();
    }

    intervalRef.current = setInterval(executePoll, interval);
  }, [executePoll, immediate, interval]);

  // Stop polling
  const stop = useCallback(() => {
    setIsPolling(false);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  }, []);

  // Manual poll trigger
  const poll = useCallback(() => {
    return executePoll();
  }, [executePoll]);

  // Start/stop based on enabled prop
  useEffect(() => {
    if (enabled && !intervalRef.current) {
      start();
    } else if (!enabled && intervalRef.current) {
      stop();
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [enabled, start, stop]);

  return {
    data,
    loading,
    error,
    isPolling,
    start,
    stop,
    poll,
    pollCount
  };
}

export default usePolling;
