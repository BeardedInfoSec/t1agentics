/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * QueueFilters Component
 *
 * Filter bar with view mode toggle, search, and filter dropdowns.
 * Config-driven - filters appear based on appliesTo in FILTER_CONFIG.
 */

import React, { useCallback, useMemo } from 'react';
import { Search } from 'lucide-react';
import {
  VIEW_MODES,
  FILTER_CONFIG,
  filterAppliesTo,
} from '../constants';
import styles from '../SecurityQueue.module.css';

/**
 * QueueFilters Component
 * @param {Object} props
 * @param {string} props.viewMode - Current view mode
 * @param {Function} props.setViewMode - View mode setter
 * @param {import('../types').QueueFilters} props.filters - Current filter state
 * @param {Function} props.setFilters - Filter update function
 * @param {Function} props.resetFilters - Reset filters to defaults
 * @param {string[]} props.availableSources - Dynamic source options from data
 * @param {boolean} props.isRefreshing - Whether data is refreshing
 * @param {Function} props.onRefresh - Manual refresh handler
 * @param {boolean} props.autoRefresh - Auto-refresh enabled
 * @param {Function} props.setAutoRefresh - Auto-refresh toggle
 */
function QueueFilters({
  viewMode,
  setViewMode,
  filters,
  setFilters,
  resetFilters,
  availableSources = [],
  isRefreshing,
  onRefresh,
  autoRefresh,
  setAutoRefresh,
}) {
  // Get status options based on view mode
  const statusOptions = useMemo(() => {
    if (viewMode === VIEW_MODES.INVESTIGATIONS) {
      return FILTER_CONFIG.status.investigationOptions;
    }
    if (viewMode === VIEW_MODES.ALERTS) {
      return FILTER_CONFIG.status.alertOptions;
    }
    // Combined view - merge both with deduplication
    const combined = [
      { value: 'all', label: 'All' },
      ...FILTER_CONFIG.status.alertOptions.filter(o => o.value !== 'all'),
      ...FILTER_CONFIG.status.investigationOptions.filter(o =>
        o.value !== 'all' && !FILTER_CONFIG.status.alertOptions.find(a => a.value === o.value)
      ),
    ];
    return combined;
  }, [viewMode]);

  // Handle filter changes
  const handleFilterChange = useCallback((key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  }, [setFilters]);

  // Handle search input
  const handleSearchChange = useCallback((e) => {
    setFilters(prev => ({ ...prev, searchQuery: e.target.value }));
  }, [setFilters]);

  // Handle search clear
  const handleSearchClear = useCallback(() => {
    setFilters(prev => ({ ...prev, searchQuery: '' }));
  }, [setFilters]);

  // Check if any filters are active
  const hasActiveFilters = useMemo(() => {
    return (
      filters.statusFilter !== 'all' ||
      filters.severityFilter !== 'all' ||
      filters.dispositionFilter !== 'all' ||
      filters.priorityFilter !== 'all' ||
      filters.slaFilter !== 'all' ||
      filters.sourceFilter !== 'all' ||
      filters.sensitivityFilter !== 'all' ||
      filters.timeRange !== '24h' ||
      filters.searchQuery !== ''
    );
  }, [filters]);

  return (
    <div className={styles.filtersContainer}>
      {/* View Mode Toggle */}
      <div className={styles.viewModeToggle}>
        <button
          className={`${styles.viewModeButton} ${viewMode === VIEW_MODES.ALL ? styles.active : ''}`}
          onClick={() => setViewMode(VIEW_MODES.ALL)}
        >
          All
        </button>
        <button
          className={`${styles.viewModeButton} ${viewMode === VIEW_MODES.ALERTS ? styles.active : ''}`}
          onClick={() => setViewMode(VIEW_MODES.ALERTS)}
        >
          Alerts
        </button>
        <button
          className={`${styles.viewModeButton} ${viewMode === VIEW_MODES.INVESTIGATIONS ? styles.active : ''}`}
          onClick={() => setViewMode(VIEW_MODES.INVESTIGATIONS)}
        >
          Investigations
        </button>
      </div>

      {/* Search Input */}
      <div className={styles.searchContainer}>
        <Search size={14} className={styles.searchIcon} />
        <input
          type="text"
          placeholder="Search by ID, title, owner..."
          value={filters.searchQuery}
          onChange={handleSearchChange}
          className={styles.searchInput}
        />
        {filters.searchQuery && (
          <button
            className={styles.searchClear}
            onClick={handleSearchClear}
            aria-label="Clear search"
          >
            &#10005;
          </button>
        )}
      </div>

      {/* Filter Dropdowns */}
      <div className={styles.filterDropdowns}>
        {/* Time Range - Always visible */}
        <select
          value={filters.timeRange}
          onChange={(e) => handleFilterChange('timeRange', e.target.value)}
          className={styles.filterSelect}
        >
          {FILTER_CONFIG.timeRange.options.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>

        {/* Severity - Always visible */}
        <select
          value={filters.severityFilter}
          onChange={(e) => handleFilterChange('severityFilter', e.target.value)}
          className={styles.filterSelect}
        >
          {FILTER_CONFIG.severity.options.map(opt => (
            <option key={opt.value} value={opt.value}>
              {opt.value === 'all' ? 'All Severities' : opt.label}
            </option>
          ))}
        </select>

        {/* Status - Always visible */}
        <select
          value={filters.statusFilter}
          onChange={(e) => handleFilterChange('statusFilter', e.target.value)}
          className={styles.filterSelect}
        >
          {statusOptions.map(opt => (
            <option key={opt.value} value={opt.value}>
              {opt.value === 'all' ? 'All Statuses' : opt.label}
            </option>
          ))}
        </select>

        {/* Source - Only for alerts view or all view */}
        {filterAppliesTo('source', viewMode) && availableSources.length > 0 && (
          <select
            value={filters.sourceFilter}
            onChange={(e) => handleFilterChange('sourceFilter', e.target.value)}
            className={styles.filterSelect}
          >
            <option value="all">All Sources</option>
            {availableSources.map(source => (
              <option key={source} value={source}>{source}</option>
            ))}
          </select>
        )}

        {/* Disposition - Only for investigations view or all view */}
        {filterAppliesTo('disposition', viewMode) && (
          <select
            value={filters.dispositionFilter}
            onChange={(e) => handleFilterChange('dispositionFilter', e.target.value)}
            className={styles.filterSelect}
          >
            {FILTER_CONFIG.disposition.options.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.value === 'all' ? 'All Dispositions' : opt.label}
              </option>
            ))}
          </select>
        )}

        {/* Priority - Only for investigations view or all view */}
        {filterAppliesTo('priority', viewMode) && (
          <select
            value={filters.priorityFilter}
            onChange={(e) => handleFilterChange('priorityFilter', e.target.value)}
            className={styles.filterSelect}
          >
            {FILTER_CONFIG.priority.options.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.value === 'all' ? 'All Priorities' : opt.label}
              </option>
            ))}
          </select>
        )}

        {/* SLA Status - Only for investigations view or all view */}
        {filterAppliesTo('slaStatus', viewMode) && (
          <select
            value={filters.slaFilter}
            onChange={(e) => handleFilterChange('slaFilter', e.target.value)}
            className={styles.filterSelect}
          >
            {FILTER_CONFIG.slaStatus.options.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.value === 'all' ? 'All SLA' : opt.label}
              </option>
            ))}
          </select>
        )}

        {/* Sensitivity - Always visible */}
        <select
          value={filters.sensitivityFilter}
          onChange={(e) => handleFilterChange('sensitivityFilter', e.target.value)}
          className={styles.filterSelect}
        >
          {FILTER_CONFIG.sensitivity.options.map(opt => (
            <option key={opt.value} value={opt.value}>
              {opt.value === 'all' ? 'All Sensitivity' : opt.label}
            </option>
          ))}
        </select>
      </div>

      {/* Active Filters Display */}
      {hasActiveFilters && (
        <div className={styles.activeFiltersContainer}>
          {filters.statusFilter !== 'all' && (
            <span className={styles.filterChip}>
              Status: {statusOptions.find(o => o.value === filters.statusFilter)?.label || filters.statusFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('statusFilter', 'all')}
                aria-label="Remove status filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.severityFilter !== 'all' && (
            <span className={styles.filterChip}>
              Severity: {FILTER_CONFIG.severity.options.find(o => o.value === filters.severityFilter)?.label || filters.severityFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('severityFilter', 'all')}
                aria-label="Remove severity filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.timeRange !== '24h' && (
            <span className={styles.filterChip}>
              Time: {FILTER_CONFIG.timeRange.options.find(o => o.value === filters.timeRange)?.label || filters.timeRange}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('timeRange', '24h')}
                aria-label="Remove time range filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.sourceFilter !== 'all' && (
            <span className={styles.filterChip}>
              Source: {filters.sourceFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('sourceFilter', 'all')}
                aria-label="Remove source filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.dispositionFilter !== 'all' && (
            <span className={styles.filterChip}>
              Disposition: {FILTER_CONFIG.disposition.options.find(o => o.value === filters.dispositionFilter)?.label || filters.dispositionFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('dispositionFilter', 'all')}
                aria-label="Remove disposition filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.priorityFilter !== 'all' && (
            <span className={styles.filterChip}>
              Priority: {FILTER_CONFIG.priority.options.find(o => o.value === filters.priorityFilter)?.label || filters.priorityFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('priorityFilter', 'all')}
                aria-label="Remove priority filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.slaFilter !== 'all' && (
            <span className={styles.filterChip}>
              SLA: {FILTER_CONFIG.slaStatus.options.find(o => o.value === filters.slaFilter)?.label || filters.slaFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('slaFilter', 'all')}
                aria-label="Remove SLA filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.sensitivityFilter !== 'all' && (
            <span className={styles.filterChip}>
              Sensitivity: {FILTER_CONFIG.sensitivity.options.find(o => o.value === filters.sensitivityFilter)?.label || filters.sensitivityFilter}
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('sensitivityFilter', 'all')}
                aria-label="Remove sensitivity filter"
              >
                ×
              </button>
            </span>
          )}
          {filters.searchQuery && (
            <span className={styles.filterChip}>
              Search: "{filters.searchQuery}"
              <button
                className={styles.chipClose}
                onClick={() => handleFilterChange('searchQuery', '')}
                aria-label="Remove search filter"
              >
                ×
              </button>
            </span>
          )}
        </div>
      )}

      {/* Actions */}
      <div className={styles.filterActions}>
        {hasActiveFilters && (
          <button
            className={styles.clearFiltersButton}
            onClick={resetFilters}
          >
            Clear Filters
          </button>
        )}

        <label className={styles.autoRefreshToggle}>
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh?.(e.target.checked)}
          />
          <span>Auto-refresh</span>
        </label>

        <button
          className={styles.refreshButton}
          onClick={() => onRefresh?.(true)}
          disabled={isRefreshing}
          aria-label="Refresh data"
        >
          <span className={`${styles.refreshIcon} ${isRefreshing ? styles.spinning : ''}`}>
            &#8635;
          </span>
        </button>
      </div>
    </div>
  );
}

export default React.memo(QueueFilters);
