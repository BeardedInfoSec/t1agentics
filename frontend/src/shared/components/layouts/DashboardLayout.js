/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * DashboardLayout Component
 *
 * Standard layout for dashboard pages with header, metrics area,
 * time range selector, and content sections.
 */

import React from 'react';
import PropTypes from 'prop-types';
import styles from './DashboardLayout.module.css';

/**
 * Time range options
 */
const TIME_RANGES = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: '90d', label: '90d' }
];

/**
 * Time Range Selector Component
 */
function TimeRangeSelector({ value, onChange, options = TIME_RANGES }) {
  return (
    <div className={styles.timeRangeContainer} role="group" aria-label="Time range selector">
      {options.map(option => (
        <button
          key={option.value}
          className={`${styles.timeRangeButton} ${value === option.value ? styles.active : ''}`}
          onClick={() => onChange(option.value)}
          aria-pressed={value === option.value}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Refresh Button Component
 */
function RefreshButton({ onClick, loading, ariaLabel = 'Refresh data' }) {
  return (
    <button
      className={`${styles.refreshButton} ${loading ? styles.loading : ''}`}
      onClick={onClick}
      disabled={loading}
      aria-label={ariaLabel}
      title="Refresh data"
    >
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        className={loading ? styles.spinning : ''}
      >
        <path d="M23 4v6h-6" />
        <path d="M1 20v-6h6" />
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
      </svg>
    </button>
  );
}

/**
 * Error Banner Component
 */
function ErrorBanner({ error, onRetry }) {
  if (!error) return null;

  return (
    <div className={styles.errorBanner} role="alert">
      <span className={styles.errorMessage}>
        {typeof error === 'string' ? error : error.message || 'An error occurred'}
      </span>
      {onRetry && (
        <button className={styles.retryButton} onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

/**
 * Dashboard Section Component
 */
export function DashboardSection({ title, subtitle, children, className }) {
  return (
    <section className={`${styles.section} ${className || ''}`}>
      {(title || subtitle) && (
        <div className={styles.sectionHeader}>
          {title && <h2 className={styles.sectionTitle}>{title}</h2>}
          {subtitle && <p className={styles.sectionSubtitle}>{subtitle}</p>}
        </div>
      )}
      <div className={styles.sectionContent}>
        {children}
      </div>
    </section>
  );
}

DashboardSection.propTypes = {
  title: PropTypes.string,
  subtitle: PropTypes.string,
  children: PropTypes.node,
  className: PropTypes.string
};

/**
 * DashboardLayout Component
 */
export function DashboardLayout({
  title,
  subtitle,
  timeRange,
  onTimeRangeChange,
  timeRangeOptions,
  onRefresh,
  isRefreshing,
  error,
  headerActions,
  children
}) {
  return (
    <div className={styles.container}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerContent}>
          <div className={styles.headerText}>
            <h1 className={styles.title}>{title}</h1>
            {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
          </div>

          <div className={styles.headerActions}>
            {headerActions}

            {timeRange !== undefined && onTimeRangeChange && (
              <TimeRangeSelector
                value={timeRange}
                onChange={onTimeRangeChange}
                options={timeRangeOptions}
              />
            )}

            {onRefresh && (
              <RefreshButton
                onClick={onRefresh}
                loading={isRefreshing}
              />
            )}
          </div>
        </div>
      </header>

      {/* Error Banner */}
      <ErrorBanner error={error} onRetry={onRefresh} />

      {/* Main Content */}
      <main className={styles.main}>
        {children}
      </main>
    </div>
  );
}

DashboardLayout.propTypes = {
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string,
  timeRange: PropTypes.string,
  onTimeRangeChange: PropTypes.func,
  timeRangeOptions: PropTypes.arrayOf(PropTypes.shape({
    value: PropTypes.string.isRequired,
    label: PropTypes.string.isRequired
  })),
  onRefresh: PropTypes.func,
  isRefreshing: PropTypes.bool,
  error: PropTypes.oneOfType([PropTypes.string, PropTypes.object]),
  headerActions: PropTypes.node,
  children: PropTypes.node
};

DashboardLayout.defaultProps = {
  isRefreshing: false,
  timeRangeOptions: TIME_RANGES
};

// Also export sub-components for flexibility
DashboardLayout.Section = DashboardSection;
DashboardLayout.TimeRangeSelector = TimeRangeSelector;
DashboardLayout.RefreshButton = RefreshButton;
DashboardLayout.ErrorBanner = ErrorBanner;

export default DashboardLayout;
