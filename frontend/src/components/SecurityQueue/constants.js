/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueue Constants
 *
 * Configuration for filters, columns, metrics, and view modes.
 * UI components read from these configs - no conditional logic hardcoded.
 */

/**
 * View mode options
 */
export const VIEW_MODES = {
  ALL: 'all',
  ALERTS: 'alerts',
  INVESTIGATIONS: 'investigations',
};

/**
 * Filter configuration
 * appliesTo determines which view modes show each filter
 */
export const FILTER_CONFIG = {
  severity: {
    key: 'severity',
    label: 'Severity',
    appliesTo: ['alert', 'investigation'],
    options: [
      { value: 'all', label: 'All' },
      { value: 'critical', label: 'Critical' },
      { value: 'high', label: 'High' },
      { value: 'medium', label: 'Medium' },
      { value: 'low', label: 'Low' },
    ],
    default: 'all',
  },
  timeRange: {
    key: 'timeRange',
    label: 'Time',
    appliesTo: ['alert', 'investigation'],
    options: [
      { value: '1h', label: '1 hour' },
      { value: '6h', label: '6 hours' },
      { value: '24h', label: '24 hours' },
      { value: '7d', label: '7 days' },
      { value: '30d', label: '30 days' },
      { value: 'all', label: 'All time' },
    ],
    default: '24h',
  },
  status: {
    key: 'status',
    label: 'Status',
    appliesTo: ['alert', 'investigation'],
    alertOptions: [
      { value: 'all', label: 'All Statuses' },
      { value: 'active', label: 'Active (not closed)' },
      { value: 'open', label: 'Open' },
      { value: 'investigating', label: 'Investigating' },
      { value: 'in_progress', label: 'In Progress' },
      { value: 'needs_review', label: 'Needs Review' },
      { value: 'resolved', label: 'Resolved' },
      { value: 'closed', label: 'Closed' },
    ],
    investigationOptions: [
      { value: 'all', label: 'All Statuses' },
      { value: 'active', label: 'Active (not closed)' },
      { value: 'open', label: 'Open' },
      { value: 'investigating', label: 'Investigating' },
      { value: 'in_progress', label: 'In Progress' },
      { value: 'needs_review', label: 'Needs Review' },
      { value: 'resolved', label: 'Resolved' },
      { value: 'closed', label: 'Closed' },
    ],
    default: 'all',
  },
  source: {
    key: 'source',
    label: 'Source',
    appliesTo: ['alert'],  // Only for alerts
    options: [],  // Populated dynamically from data
    default: 'all',
  },
  disposition: {
    key: 'disposition',
    label: 'Disposition',
    appliesTo: ['investigation'],
    options: [
      { value: 'all', label: 'All' },
      { value: 'true_positive', label: 'True Positive' },
      { value: 'malicious', label: 'Malicious' },
      { value: 'suspicious', label: 'Suspicious' },
      { value: 'benign', label: 'Benign' },
      { value: 'false_positive', label: 'False Positive' },
      { value: 'unknown', label: 'Unknown' },
    ],
    default: 'all',
  },
  priority: {
    key: 'priority',
    label: 'Priority',
    appliesTo: ['investigation'],
    options: [
      { value: 'all', label: 'All' },
      { value: 'P1', label: 'P1' },
      { value: 'P2', label: 'P2' },
      { value: 'P3', label: 'P3' },
      { value: 'P4', label: 'P4' },
    ],
    default: 'all',
  },
  sensitivity: {
    key: 'sensitivity',
    label: 'Sensitivity',
    appliesTo: ['alert', 'investigation'],
    options: [
      { value: 'all', label: 'All' },
      { value: 'public', label: 'Public' },
      { value: 'internal', label: 'Internal' },
      { value: 'confidential', label: 'Confidential' },
      { value: 'restricted', label: 'Restricted' },
    ],
    default: 'all',
  },
  slaStatus: {
    key: 'slaStatus',
    label: 'SLA',
    appliesTo: ['alert', 'investigation'],
    options: [
      { value: 'all', label: 'All' },
      { value: 'exceeded', label: 'Exceeded' },
      { value: 'at_risk', label: 'At Risk' },
      { value: 'ok', label: 'On Track' },
      { value: 'met', label: 'Met' },
    ],
    default: 'all',
  },
};

/**
 * Column configuration
 * appliesTo determines which item types render this column
 */
export const COLUMN_CONFIG = {
  id: {
    key: 'id',
    label: 'ID',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 120,
  },
  title: {
    key: 'title',
    label: 'Title',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    minWidth: 200,
  },
  status: {
    key: 'status',
    label: 'Status',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 120,
  },
  severity: {
    key: 'severity',
    label: 'Severity',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 90,
  },
  disposition: {
    key: 'disposition',
    label: 'Disposition',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 110,
  },
  priority: {
    key: 'priority',
    label: 'Priority',
    appliesTo: ['investigation'],
    sortable: true,
    width: 80,
  },
  sla: {
    key: 'sla',
    label: 'SLA',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 100,
  },
  owner: {
    key: 'owner',
    label: 'Owner',
    appliesTo: ['investigation'],
    sortable: true,
    width: 100,
  },
  enrichment: {
    key: 'enrichment',
    label: 'Enrichment',
    appliesTo: ['alert', 'investigation'],
    sortable: false,
    width: 100,
  },
  confidence: {
    key: 'confidence',
    label: 'Confidence',
    appliesTo: ['alert'],
    sortable: true,
    width: 90,
  },
  correlation: {
    key: 'correlation',
    label: 'Correlation',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 100,
  },
  source: {
    key: 'source',
    label: 'Source',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 100,
  },
  created_at: {
    key: 'created_at',
    label: 'Created',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 140,
  },
  updated_at: {
    key: 'updated_at',
    label: 'Updated',
    appliesTo: ['alert', 'investigation'],
    sortable: true,
    width: 140,
  },
};

/**
 * Default columns for each view mode
 */
export const DEFAULT_COLUMNS = {
  all: ['id', 'title', 'status', 'severity', 'sla', 'source', 'created_at'],
  alerts: ['id', 'title', 'status', 'severity', 'sla', 'disposition', 'enrichment', 'source', 'created_at'],
  investigations: ['id', 'title', 'status', 'severity', 'sla', 'disposition', 'enrichment', 'owner', 'created_at'],
};

/**
 * Available columns for each view mode (for column customizer)
 */
export const AVAILABLE_COLUMNS = {
  all: Object.keys(COLUMN_CONFIG),
  alerts: Object.keys(COLUMN_CONFIG).filter(k =>
    COLUMN_CONFIG[k].appliesTo.includes('alert')
  ),
  investigations: Object.keys(COLUMN_CONFIG).filter(k =>
    COLUMN_CONFIG[k].appliesTo.includes('investigation')
  ),
};

/**
 * Metric configuration for the dashboard cards
 */
export const METRIC_CONFIG = [
  {
    key: 'total',
    label: 'Total',
    color: 'var(--text-primary)',
    appliesTo: ['all', 'alerts', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, statusFilter: 'all', severityFilter: 'all' }));
    },
  },
  {
    key: 'alerts',
    label: 'Alerts',
    color: '#3CB371',
    appliesTo: ['all'],
    onClick: (setFilters, setViewMode) => {
      setViewMode('alerts');
    },
  },
  {
    key: 'investigations',
    label: 'Investigations',
    color: '#8b5cf6',
    appliesTo: ['all'],
    onClick: (setFilters, setViewMode) => {
      setViewMode('investigations');
    },
  },
  {
    key: 'critical',
    label: 'Critical',
    color: '#dc2626',
    appliesTo: ['all', 'alerts', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, severityFilter: 'critical' }));
    },
  },
  {
    key: 'needsReview',
    label: 'Needs Review',
    color: '#f97316',
    appliesTo: ['all', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, statusFilter: 'NEEDS_REVIEW' }));
    },
  },
  {
    key: 'breached',
    label: 'SLA Exceeded',
    color: '#dc2626',
    appliesTo: ['all', 'alerts', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, slaFilter: 'exceeded' }));
    },
  },
  {
    key: 'atRisk',
    label: 'At Risk',
    color: '#eab308',
    appliesTo: ['all', 'alerts', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, slaFilter: 'at_risk' }));
    },
  },
  {
    key: 'resolvedToday',
    label: 'Resolved Today',
    color: '#22c55e',
    appliesTo: ['all', 'alerts', 'investigations'],
    onClick: (setFilters) => {
      setFilters(prev => ({ ...prev, statusFilter: 'CLOSED' }));
    },
  },
];

/**
 * LocalStorage keys for persisting preferences
 */
export const STORAGE_KEYS = {
  VIEW_MODE: 'T1_security_queue_view_mode',
  COLUMNS: 'T1_security_queue_columns',
  TIME_RANGE: 'T1_security_queue_time_range',
  ROWS_PER_PAGE: 'T1_security_queue_rows_per_page',
};

/**
 * Pagination options
 */
export const ROWS_PER_PAGE_OPTIONS = [10, 15, 20, 30, 50, 100];
export const DEFAULT_ROWS_PER_PAGE = 20;

/**
 * Auto-refresh interval in milliseconds
 */
export const AUTO_REFRESH_INTERVAL = 30000;

/**
 * Helper: Check if a filter applies to the current view mode
 * @param {string} filterKey - Filter key from FILTER_CONFIG
 * @param {string} viewMode - Current view mode ('all', 'alerts', 'investigations')
 * @returns {boolean}
 */
export function filterAppliesTo(filterKey, viewMode) {
  const config = FILTER_CONFIG[filterKey];
  if (!config) return false;
  if (viewMode === 'all') return true;
  const itemType = viewMode === 'alerts' ? 'alert' : 'investigation';
  return config.appliesTo.includes(itemType);
}

/**
 * Helper: Check if a column applies to an item type
 * @param {string} columnKey - Column key from COLUMN_CONFIG
 * @param {string} itemType - Item type ('alert' or 'investigation')
 * @returns {boolean}
 */
export function columnAppliesTo(columnKey, itemType) {
  const config = COLUMN_CONFIG[columnKey];
  if (!config) return false;
  return config.appliesTo.includes(itemType);
}

export default {
  VIEW_MODES,
  FILTER_CONFIG,
  COLUMN_CONFIG,
  DEFAULT_COLUMNS,
  AVAILABLE_COLUMNS,
  METRIC_CONFIG,
  STORAGE_KEYS,
  ROWS_PER_PAGE_OPTIONS,
  DEFAULT_ROWS_PER_PAGE,
  AUTO_REFRESH_INTERVAL,
  filterAppliesTo,
  columnAppliesTo,
};
