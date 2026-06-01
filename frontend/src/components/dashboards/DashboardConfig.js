/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Dashboard Configuration
 * Centralized configuration for all dashboard components.
 * Eliminates magic numbers, hardcoded values, and provides consistent defaults.
 */

// Time range options for dashboard filters
export const TIME_RANGES = {
  '24h': { label: 'Last 24 Hours', hours: 24 },
  '7d': { label: 'Last 7 Days', hours: 168 },
  '30d': { label: 'Last 30 Days', hours: 720 },
  '90d': { label: 'Last 90 Days', hours: 2160 }
};

// Severity levels with their associated colors
export const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    color: '#ef4444',
    bgColor: 'rgba(239, 68, 68, 0.2)',
    borderColor: '#ef4444'
  },
  high: {
    label: 'High',
    color: '#f59e0b',
    bgColor: 'rgba(245, 158, 11, 0.2)',
    borderColor: '#f59e0b'
  },
  medium: {
    label: 'Medium',
    color: '#38bdf8',
    bgColor: 'rgba(56, 189, 248, 0.2)',
    borderColor: '#38bdf8'
  },
  low: {
    label: 'Low',
    color: '#22c55e',
    bgColor: 'rgba(34, 197, 94, 0.2)',
    borderColor: '#22c55e'
  },
  informational: {
    label: 'Info',
    color: '#94a3b8',
    bgColor: 'rgba(148, 163, 184, 0.2)',
    borderColor: '#94a3b8'
  }
};

// KPI card tone configurations
export const KPI_TONES = {
  critical: { borderColor: '#ef4444' },
  high: { borderColor: '#f59e0b' },
  success: { borderColor: '#22c55e' },
  info: { borderColor: '#38bdf8' },
  neutral: { borderColor: 'rgba(148, 163, 184, 0.6)' },
  warning: { borderColor: '#f97316' }
};

// Role badge configurations
export const ROLE_CONFIG = {
  admin: {
    bg: 'rgba(239, 68, 68, 0.2)',
    color: '#ef4444',
    border: '#ef4444',
    label: 'Administrator'
  },
  analyst: {
    bg: 'rgba(59, 130, 246, 0.2)',
    color: '#3b82f6',
    border: '#3b82f6',
    label: 'Analyst'
  },
  read_only: {
    bg: 'rgba(107, 114, 128, 0.2)',
    color: '#9ca3af',
    border: '#6b7280',
    label: 'Read Only'
  }
};

// Default ROI calculation values
export const DEFAULT_ROI_CONFIG = {
  costPerHour: 120,        // USD per hour of analyst time
  humanActionMins: 12,     // Average minutes for human to handle action
  automationActionMins: 2  // Average minutes for automation to handle action
};

// Dashboard refresh intervals (in milliseconds)
export const REFRESH_INTERVALS = {
  stats: 30000,           // 30 seconds for stats refresh
  alerts: 15000,          // 15 seconds for alert data
  realtime: 5000          // 5 seconds for real-time data
};

// Chart color configurations
export const CHART_COLORS = {
  primary: '#38bdf8',
  secondary: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  muted: 'rgba(148, 163, 184, 0.6)',
  // Trend line colors
  alertTrend: 'var(--accent-amber)',
  automationTrend: 'var(--accent-green)',
  // Gradient colors
  gradient: {
    start: '#3CB371',
    end: '#2e8b57'
  }
};

// Pagination defaults
export const PAGINATION_CONFIG = {
  defaultPageSize: 10,
  pageSizeOptions: [5, 10, 25, 50, 100],
  maxRecentAlerts: 5
};

// API endpoints for dashboards
export const DASHBOARD_ENDPOINTS = {
  stats: '/api/v1/stats',
  alerts: '/api/v1/alerts',
  investigations: '/api/v1/investigations',
  users: '/api/v1/admin/users',
  integrations: '/api/v1/integrations/v2/instances',
  llm: '/api/v1/llm'
};

// Status configurations for investigations
export const INVESTIGATION_STATUS = {
  NEW: { label: 'New', color: '#38bdf8' },
  IN_PROGRESS: { label: 'In Progress', color: '#f59e0b' },
  NEEDS_REVIEW: { label: 'Needs Review', color: '#ef4444' },
  AWAITING_HUMAN: { label: 'Awaiting Human', color: '#f97316' },
  ON_HOLD: { label: 'On Hold', color: '#94a3b8' },
  RESOLVED: { label: 'Resolved', color: '#22c55e' },
  CLOSED: { label: 'Closed', color: '#6b7280' }
};

// Empty state messages
export const EMPTY_MESSAGES = {
  alerts: 'No alerts found',
  investigations: 'No investigations found',
  users: 'No users found',
  integrations: 'No integrations configured',
  data: 'No data available'
};

// Error messages
export const ERROR_MESSAGES = {
  network: 'Unable to connect to the server. Please check your connection.',
  unauthorized: 'You are not authorized to view this data.',
  notFound: 'The requested resource was not found.',
  serverError: 'An unexpected error occurred. Please try again later.',
  timeout: 'The request timed out. Please try again.',
  default: 'Something went wrong. Please try again.'
};

// Accessibility labels
export const ARIA_LABELS = {
  timeRangeSelector: 'Select time range',
  refreshButton: 'Refresh dashboard data',
  loadingSpinner: 'Loading dashboard data',
  kpiCard: (label) => `Key metric: ${label}`,
  severityBar: 'Alert severity distribution',
  dataTable: 'Dashboard data table',
  pagination: 'Table pagination controls'
};

/**
 * Get severity configuration by level
 * @param {string} severity - Severity level
 * @returns {object} Severity configuration
 */
export function getSeverityConfig(severity) {
  return SEVERITY_CONFIG[severity?.toLowerCase()] || SEVERITY_CONFIG.informational;
}

/**
 * Get role configuration
 * @param {string} role - User role
 * @returns {object} Role configuration
 */
export function getRoleConfig(role) {
  return ROLE_CONFIG[role] || ROLE_CONFIG.read_only;
}

/**
 * Format number with locale and abbreviation
 * @param {number} value - Number to format
 * @param {boolean} abbreviate - Whether to abbreviate large numbers
 * @returns {string} Formatted number
 */
export function formatNumber(value, abbreviate = false) {
  if (value === null || value === undefined) return '0';

  if (abbreviate && value >= 1000000) {
    return `${(value / 1000000).toFixed(1)}M`;
  }
  if (abbreviate && value >= 1000) {
    return `${(value / 1000).toFixed(1)}K`;
  }

  return value.toLocaleString();
}

/**
 * Format currency value
 * @param {number} value - Value to format
 * @param {string} currency - Currency code (default: USD)
 * @returns {string} Formatted currency string
 */
export function formatCurrency(value, currency = 'USD') {
  if (value === null || value === undefined) return '$0';

  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(value);
}

/**
 * Format percentage value
 * @param {number} value - Value to format (0-100)
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted percentage string
 */
export function formatPercent(value, decimals = 0) {
  if (value === null || value === undefined) return '0%';
  return `${value.toFixed(decimals)}%`;
}

/**
 * Format duration in hours/minutes
 * @param {number} minutes - Duration in minutes
 * @returns {string} Formatted duration string
 */
export function formatDuration(minutes) {
  if (!minutes || minutes <= 0) return '0m';

  if (minutes < 60) {
    return `${Math.round(minutes)}m`;
  }

  const hours = Math.floor(minutes / 60);
  const mins = Math.round(minutes % 60);

  if (mins === 0) {
    return `${hours}h`;
  }

  return `${hours}h ${mins}m`;
}

export default {
  TIME_RANGES,
  SEVERITY_CONFIG,
  KPI_TONES,
  ROLE_CONFIG,
  DEFAULT_ROI_CONFIG,
  REFRESH_INTERVALS,
  CHART_COLORS,
  PAGINATION_CONFIG,
  DASHBOARD_ENDPOINTS,
  INVESTIGATION_STATUS,
  EMPTY_MESSAGES,
  ERROR_MESSAGES,
  ARIA_LABELS,
  getSeverityConfig,
  getRoleConfig,
  formatNumber,
  formatCurrency,
  formatPercent,
  formatDuration
};
