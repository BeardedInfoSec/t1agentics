/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * useQueueFilters Hook
 *
 * Manages filter state for the security queue.
 * Handles localStorage persistence and URL sync.
 */

import { useState, useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  VIEW_MODES,
  FILTER_CONFIG,
  STORAGE_KEYS,
  DEFAULT_COLUMNS,
  ROWS_PER_PAGE_OPTIONS,
  DEFAULT_ROWS_PER_PAGE,
} from '../constants';
import { filterQueueItems } from '../transforms';

/**
 * @typedef {Object} UseQueueFiltersResult
 * @property {import('../types').QueueFilters} filters - Current filter state
 * @property {Function} setFilters - Update filters (partial update)
 * @property {Function} resetFilters - Reset all filters to defaults
 * @property {string} viewMode - Current view mode
 * @property {Function} setViewMode - Update view mode
 * @property {string[]} visibleColumns - Currently visible column keys
 * @property {Function} setVisibleColumns - Update visible columns
 * @property {number} rowsPerPage - Rows per page
 * @property {Function} setRowsPerPage - Update rows per page
 * @property {number} currentPage - Current page number
 * @property {Function} setCurrentPage - Update current page
 * @property {Function} filterItems - Apply filters to items array
 */

/**
 * Hook for managing queue filter state
 * @param {Object} options
 * @param {string} [options.defaultViewMode='all'] - Default view mode
 * @returns {UseQueueFiltersResult}
 */
// Map of filter state keys → URL param name + the FILTER_CONFIG key that
// supplies the default and (if present) `options` list for validation.
// Keeping this table-driven lets reads, writes, and resets all share one
// source of truth — adding a new filter is a single-line change.
const URL_FILTER_MAP = [
  { stateKey: 'statusFilter',      urlKey: 'status',      cfgKey: 'status' },
  { stateKey: 'severityFilter',    urlKey: 'severity',    cfgKey: 'severity' },
  { stateKey: 'dispositionFilter', urlKey: 'disposition', cfgKey: 'disposition' },
  { stateKey: 'priorityFilter',    urlKey: 'priority',    cfgKey: 'priority' },
  { stateKey: 'slaFilter',         urlKey: 'sla',         cfgKey: 'slaStatus' },
  { stateKey: 'sourceFilter',      urlKey: 'source',      cfgKey: 'source' },
  { stateKey: 'sensitivityFilter', urlKey: 'sensitivity', cfgKey: 'sensitivity' },
  { stateKey: 'timeRange',         urlKey: 'timeRange',   cfgKey: 'timeRange' },
];

function readFilterFromUrl(searchParams, { urlKey, cfgKey }, fallback) {
  const raw = searchParams.get(urlKey);
  if (raw == null || raw === '') return fallback;
  const cfg = FILTER_CONFIG[cfgKey];
  // 'all' is always permitted. If the config has a fixed option list,
  // validate; otherwise (e.g. source which is data-driven) accept as-is.
  if (raw === 'all' || raw === cfg?.default) return raw;
  if (Array.isArray(cfg?.options) && cfg.options.length > 0) {
    const allowed = cfg.options.map((o) => (typeof o === 'string' ? o : o.value));
    if (!allowed.includes(raw)) return fallback;
  }
  return raw;
}

export function useQueueFilters(options = {}) {
  const { defaultViewMode = VIEW_MODES.ALL } = options;
  const [searchParams, setSearchParams] = useSearchParams();

  // View mode from URL or default
  const [viewMode, setViewModeState] = useState(() => {
    const urlView = searchParams.get('view');
    if (urlView && Object.values(VIEW_MODES).includes(urlView)) {
      return urlView;
    }
    return defaultViewMode;
  });

  // Filter state — seed every filter from the URL, falling back to its
  // configured default (or localStorage for timeRange).
  const [filters, setFiltersState] = useState(() => {
    const initial = {
      viewMode,
      searchQuery: searchParams.get('search') || '',
    };
    for (const entry of URL_FILTER_MAP) {
      let fallback = FILTER_CONFIG[entry.cfgKey].default;
      if (entry.stateKey === 'timeRange') {
        fallback = localStorage.getItem(STORAGE_KEYS.TIME_RANGE) || fallback;
      }
      initial[entry.stateKey] = readFilterFromUrl(searchParams, entry, fallback);
    }
    return initial;
  });

  // Visible columns from localStorage or defaults
  const [visibleColumns, setVisibleColumnsState] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEYS.COLUMNS);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        return parsed[viewMode] || DEFAULT_COLUMNS[viewMode];
      } catch {
        return DEFAULT_COLUMNS[viewMode];
      }
    }
    return DEFAULT_COLUMNS[viewMode];
  });

  // Pagination state
  const [rowsPerPage, setRowsPerPageState] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEYS.ROWS_PER_PAGE);
    const parsed = parseInt(stored, 10);
    return ROWS_PER_PAGE_OPTIONS.includes(parsed) ? parsed : DEFAULT_ROWS_PER_PAGE;
  });

  const [currentPage, setCurrentPage] = useState(1);

  // Sync viewMode to URL
  const setViewMode = useCallback((newMode) => {
    if (!Object.values(VIEW_MODES).includes(newMode)) return;

    setViewModeState(newMode);
    setFiltersState(prev => ({ ...prev, viewMode: newMode }));

    // Update URL
    const newParams = new URLSearchParams(searchParams);
    if (newMode === defaultViewMode) {
      newParams.delete('view');
    } else {
      newParams.set('view', newMode);
    }
    setSearchParams(newParams, { replace: true });

    // Update visible columns for new view mode
    const storedColumns = localStorage.getItem(STORAGE_KEYS.COLUMNS);
    if (storedColumns) {
      try {
        const parsed = JSON.parse(storedColumns);
        setVisibleColumnsState(parsed[newMode] || DEFAULT_COLUMNS[newMode]);
      } catch {
        setVisibleColumnsState(DEFAULT_COLUMNS[newMode]);
      }
    } else {
      setVisibleColumnsState(DEFAULT_COLUMNS[newMode]);
    }

    // Reset to first page on view mode change
    setCurrentPage(1);
  }, [searchParams, setSearchParams, defaultViewMode]);

  // Update filters (partial update). Every filter that's part of
  // URL_FILTER_MAP is mirrored to the query string so the view is shareable
  // and the browser back/forward button restores state correctly.
  const setFilters = useCallback((updater) => {
    setFiltersState(prev => {
      const next = typeof updater === 'function' ? updater(prev) : { ...prev, ...updater };

      // Persist time range to localStorage as before.
      if (next.timeRange !== prev.timeRange) {
        localStorage.setItem(STORAGE_KEYS.TIME_RANGE, next.timeRange);
      }

      // Single URL update for everything that changed in this call —
      // batching avoids a flicker of intermediate URLs.
      const newParams = new URLSearchParams(searchParams);
      let dirty = false;

      if (next.searchQuery !== prev.searchQuery) {
        if (next.searchQuery) newParams.set('search', next.searchQuery);
        else newParams.delete('search');
        dirty = true;
      }

      for (const entry of URL_FILTER_MAP) {
        if (next[entry.stateKey] === prev[entry.stateKey]) continue;
        const cfgDefault = FILTER_CONFIG[entry.cfgKey].default;
        // Don't pollute the URL with default values — keeps clean URLs.
        if (!next[entry.stateKey] || next[entry.stateKey] === cfgDefault) {
          newParams.delete(entry.urlKey);
        } else {
          newParams.set(entry.urlKey, next[entry.stateKey]);
        }
        dirty = true;
      }

      if (dirty) setSearchParams(newParams, { replace: true });

      return next;
    });

    // Reset to first page on filter change
    setCurrentPage(1);
  }, [searchParams, setSearchParams]);

  // Reset all filters to defaults
  const resetFilters = useCallback(() => {
    const cleared = {
      viewMode,
      searchQuery: '',
    };
    for (const entry of URL_FILTER_MAP) {
      cleared[entry.stateKey] = FILTER_CONFIG[entry.cfgKey].default;
    }
    setFiltersState(cleared);

    // Wipe every filter param from URL too (keep ?view= if it was set).
    const newParams = new URLSearchParams(searchParams);
    newParams.delete('search');
    for (const entry of URL_FILTER_MAP) {
      newParams.delete(entry.urlKey);
    }
    setSearchParams(newParams, { replace: true });

    setCurrentPage(1);
  }, [viewMode, searchParams, setSearchParams]);

  // Update visible columns and persist
  const setVisibleColumns = useCallback((columns) => {
    setVisibleColumnsState(columns);

    // Persist to localStorage with view mode key
    const stored = localStorage.getItem(STORAGE_KEYS.COLUMNS);
    let allColumns = {};
    try {
      allColumns = stored ? JSON.parse(stored) : {};
    } catch {
      allColumns = {};
    }
    allColumns[viewMode] = columns;
    localStorage.setItem(STORAGE_KEYS.COLUMNS, JSON.stringify(allColumns));
  }, [viewMode]);

  // Update rows per page and persist
  const setRowsPerPage = useCallback((count) => {
    if (!ROWS_PER_PAGE_OPTIONS.includes(count)) return;
    setRowsPerPageState(count);
    localStorage.setItem(STORAGE_KEYS.ROWS_PER_PAGE, String(count));
    setCurrentPage(1);
  }, []);

  // Sync filter state from URL changes (back/forward, deep-link arrivals).
  // We diff every URL-mirrored filter; if any drift from current state we
  // pull them in. Without this the browser's back button doesn't actually
  // restore the view.
  useEffect(() => {
    setFiltersState(prev => {
      let changed = false;
      const next = { ...prev };

      const urlSearch = searchParams.get('search') || '';
      if (urlSearch !== prev.searchQuery) {
        next.searchQuery = urlSearch;
        changed = true;
      }

      for (const entry of URL_FILTER_MAP) {
        const fallback = entry.stateKey === 'timeRange'
          ? (localStorage.getItem(STORAGE_KEYS.TIME_RANGE) || FILTER_CONFIG[entry.cfgKey].default)
          : FILTER_CONFIG[entry.cfgKey].default;
        const fromUrl = readFilterFromUrl(searchParams, entry, fallback);
        if (fromUrl !== prev[entry.stateKey]) {
          next[entry.stateKey] = fromUrl;
          changed = true;
        }
      }

      return changed ? next : prev;
    });
  }, [searchParams]);

  // Apply filters to items array
  const filterItems = useCallback((items) => {
    return filterQueueItems(items, filters);
  }, [filters]);

  // Memoize the filters object to prevent unnecessary re-renders
  const memoizedFilters = useMemo(() => ({
    ...filters,
    viewMode,
  }), [filters, viewMode]);

  return {
    filters: memoizedFilters,
    setFilters,
    resetFilters,
    viewMode,
    setViewMode,
    visibleColumns,
    setVisibleColumns,
    rowsPerPage,
    setRowsPerPage,
    currentPage,
    setCurrentPage,
    filterItems,
  };
}

export default useQueueFilters;
