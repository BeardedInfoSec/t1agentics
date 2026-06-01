/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueue Component
 *
 * Thin orchestration component (~250 lines) that composes hooks and child components.
 * All logic lives in hooks, child components, and config objects.
 *
 * Props:
 * - defaultViewMode: 'all' | 'alerts' | 'investigations' - Initial view mode
 *
 * Routes:
 * - /queue - Combined view (defaultViewMode='all')
 * - /events - Alerts view (defaultViewMode='alerts')
 * - /investigations - Investigations view (defaultViewMode='investigations')
 */

import React, { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSecurityQueue } from './hooks/useSecurityQueue';
import { useQueueFilters } from './hooks/useQueueFilters';
import SecurityQueueTable from './components/SecurityQueueTable';
import QueueFilters from './components/QueueFilters';
import QueueMetrics from './components/QueueMetrics';
import BulkActionsBar from './components/BulkActionsBar';
import QueueSkeleton from './components/QueueSkeleton';
import { VIEW_MODES, AVAILABLE_COLUMNS, COLUMN_CONFIG } from './constants';
import { getAuthHeaders, API_BASE_URL } from '../../utils/api';
import styles from './SecurityQueue.module.css';

/**
 * ColumnCustomizer - Dropdown to toggle visible columns
 */
function ColumnCustomizer({ viewMode, visibleColumns, setVisibleColumns }) {
  const [open, setOpen] = useState(false);
  const availableCols = AVAILABLE_COLUMNS[viewMode] || [];

  const toggleColumn = useCallback((colKey) => {
    const isVisible = visibleColumns.includes(colKey);
    if (isVisible && visibleColumns.length <= 2) return; // Minimum 2 columns
    const next = isVisible
      ? visibleColumns.filter(c => c !== colKey)
      : [...visibleColumns, colKey];
    setVisibleColumns(next);
  }, [visibleColumns, setVisibleColumns]);

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        className={styles.refreshButton}
        title="Customize columns"
        style={{ fontSize: '0.75rem', padding: '0.4rem 0.6rem', display: 'flex', alignItems: 'center', gap: '4px' }}
      >
        <span style={{ fontSize: '0.85rem', lineHeight: 1 }}>{'\u2630'}</span>
        <span>Columns</span>
      </button>
      {open && (
        <>
          <div
            onClick={() => setOpen(false)}
            style={{ position: 'fixed', inset: 0, zIndex: 99 }}
          />
          <div style={{
            position: 'absolute',
            top: 'calc(100% + 4px)',
            right: 0,
            minWidth: '180px',
            background: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
            borderRadius: '6px',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
            zIndex: 100,
            padding: '4px 0',
            animation: 'dropdownFadeIn 0.15s ease',
          }}>
            <div style={{
              padding: '6px 12px',
              fontSize: '0.7rem',
              fontWeight: 600,
              color: 'var(--text-muted, #64748b)',
              textTransform: 'uppercase',
              letterSpacing: '0.03em',
              borderBottom: '1px solid var(--border-color, #334155)',
            }}>
              Toggle Columns
            </div>
            {availableCols.map(colKey => {
              const config = COLUMN_CONFIG[colKey];
              if (!config) return null;
              const checked = visibleColumns.includes(colKey);
              return (
                <label
                  key={colKey}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 12px',
                    fontSize: '0.75rem',
                    color: 'var(--text-primary, #f0f6fc)',
                    cursor: 'pointer',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary, #2d3748)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleColumn(colKey)}
                    disabled={checked && visibleColumns.length <= 2}
                    style={{ accentColor: 'var(--info, #3b82f6)', cursor: 'pointer' }}
                  />
                  {config.label}
                </label>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

/**
 * SecurityQueue Component
 * @param {Object} props
 * @param {'all'|'alerts'|'investigations'} [props.defaultViewMode='all'] - Default view mode
 */
function SecurityQueue({ defaultViewMode = VIEW_MODES.ALL }) {
  const navigate = useNavigate();

  // Auto-refresh state
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Selection state
  const [selectedIds, setSelectedIds] = useState([]);

  // Data fetching hook
  const {
    items,
    metrics,
    loading,
    isRefreshing,
    error,
    systemConfig,
    refetch,
    updateItem,
    truncated,
    fetchLimits,
  } = useSecurityQueue({ autoRefresh });

  // Filter state hook
  const {
    filters,
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
  } = useQueueFilters({ defaultViewMode });

  // Apply filters to items
  const filteredItems = useMemo(() => {
    return filterItems(items);
  }, [items, filterItems]);

  // Compute metrics on filtered items (for display) but show total metrics
  const displayMetrics = useMemo(() => {
    // Show metrics for unfiltered items matching current view mode
    const viewItems = viewMode === VIEW_MODES.ALL
      ? items
      : items.filter(i => viewMode === VIEW_MODES.ALERTS ? i.item_type === 'alert' : i.item_type === 'investigation');

    return {
      total: viewItems.length,
      alerts: items.filter(i => i.item_type === 'alert').length,
      investigations: items.filter(i => i.item_type === 'investigation').length,
      critical: viewItems.filter(i => i.severity === 'critical').length,
      needsReview: viewItems.filter(i =>
        i.item_type === 'investigation' &&
        (i.status === 'NEEDS_REVIEW' || i.status === 'AWAITING_HUMAN' || i.status === 'RIGGS_REVIEW')
      ).length,
      breached: viewItems.filter(i => i.sla?.status === 'breached').length,
      atRisk: viewItems.filter(i => i.sla?.status === 'at_risk').length,
      resolvedToday: (() => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return viewItems.filter(i => {
          if (i.status !== 'CLOSED' && i.status !== 'RESOLVED' && i.status?.toLowerCase() !== 'resolved') return false;
          const updatedDate = new Date(i.updated_at);
          return updatedDate >= today;
        }).length;
      })(),
    };
  }, [items, viewMode]);

  // Extract unique sources from alerts for filter dropdown
  const availableSources = useMemo(() => {
    const sources = new Set();
    items.forEach(item => {
      if (item.item_type === 'alert' && item.source) {
        sources.add(item.source);
      }
    });
    return Array.from(sources).sort();
  }, [items]);

  // Handle item click - navigate to detail page
  const handleItemClick = useCallback((item) => {
    if (item.item_type === 'investigation') {
      navigate(`/investigation/${item.investigation_id}`);
    } else {
      // For alerts, could navigate to alert detail or expand row
      // Currently just expanding is handled by table
    }
  }, [navigate]);

  // Handle bulk action completion (refresh data)
  const handleBulkActionComplete = useCallback(() => {
    refetch(true);
  }, [refetch]);

  // Clear selection when filters change
  const handleSetFilters = useCallback((updater) => {
    setFilters(updater);
    setSelectedIds([]);
  }, [setFilters]);

  // Clear selection when view mode changes
  const handleSetViewMode = useCallback((mode) => {
    setViewMode(mode);
    setSelectedIds([]);
  }, [setViewMode]);

  // Get page title based on view mode
  const getPageTitle = () => {
    switch (viewMode) {
      case VIEW_MODES.ALERTS:
        return 'Security Alerts';
      case VIEW_MODES.INVESTIGATIONS:
        return 'Investigations';
      default:
        return 'Security Queue';
    }
  };

  return (
    <div className={styles.securityQueue}>
      {/* Header */}
      <div className={styles.header}>
        <h1 className={styles.title}>{getPageTitle()}</h1>
        {isRefreshing && (
          <span className={styles.refreshingIndicator}>Refreshing...</span>
        )}
        <div style={{ marginLeft: 'auto' }}>
          <ColumnCustomizer
            viewMode={viewMode}
            visibleColumns={visibleColumns}
            setVisibleColumns={setVisibleColumns}
          />
        </div>
      </div>

      {/* Metrics */}
      <div data-tour="queue-stat-tiles">
        <QueueMetrics
          metrics={displayMetrics}
          viewMode={viewMode}
          setFilters={handleSetFilters}
          setViewMode={handleSetViewMode}
        />
      </div>

      {/* Data truncation warning — only when server returned exactly the cap.
          Without this, large tenants would silently lose rows past the limit. */}
      {(truncated?.alerts || truncated?.investigations) && (
        <div className={styles.truncationBanner} role="status">
          <strong>Showing the most recent results only.</strong>{' '}
          {truncated.alerts && truncated.investigations
            ? `Capped at ${fetchLimits.alerts} alerts and ${fetchLimits.investigations} investigations.`
            : truncated.alerts
              ? `Capped at ${fetchLimits.alerts} alerts.`
              : `Capped at ${fetchLimits.investigations} investigations.`}
          {' '}Narrow your filters (time range, status, severity) to drill into older items.
        </div>
      )}

      {/* Filters */}
      <div data-tour="queue-filters">
      <QueueFilters
        viewMode={viewMode}
        setViewMode={handleSetViewMode}
        filters={filters}
        setFilters={handleSetFilters}
        resetFilters={resetFilters}
        availableSources={availableSources}
        isRefreshing={isRefreshing}
        onRefresh={refetch}
        autoRefresh={autoRefresh}
        setAutoRefresh={setAutoRefresh}
      />
      </div>

      {/* Bulk Actions Bar (when items selected) */}
      <div data-tour="queue-bulk">
      <BulkActionsBar
        selectedIds={selectedIds}
        items={items}
        onClearSelection={() => setSelectedIds([])}
        onActionComplete={handleBulkActionComplete}
      />
      </div>

      {/* Error State */}
      {error && (
        <div className={styles.errorBanner}>
          <span>Error loading data: {error}</span>
          <button onClick={() => refetch(true)}>Retry</button>
        </div>
      )}

      {/* Loading State */}
      {loading ? (
        <QueueSkeleton />
      ) : (
        /* Table */
        <div data-tour="queue-table">
        <SecurityQueueTable
          items={filteredItems}
          visibleColumns={visibleColumns}
          setVisibleColumns={setVisibleColumns}
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          onPageChange={setCurrentPage}
          onRowsPerPageChange={setRowsPerPage}
          onItemClick={handleItemClick}
          selectedIds={selectedIds}
          onSelectionChange={setSelectedIds}
          onRefresh={refetch}
          onUpdateItem={updateItem}
          systemConfig={systemConfig}
        />
        </div>
      )}

      {/* Footer Stats */}
      <div className={styles.footer}>
        <span className={styles.footerStat}>
          Showing {filteredItems.length} of {items.length} items
        </span>
        {viewMode === VIEW_MODES.ALL && (
          <span className={styles.footerStat}>
            ({metrics.alerts} alerts, {metrics.investigations} investigations)
          </span>
        )}
      </div>
    </div>
  );
}

export default SecurityQueue;
