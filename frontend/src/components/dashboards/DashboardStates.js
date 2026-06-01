/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Dashboard State Components
 * Shared components for loading, error, and empty states across all dashboards.
 * Provides consistent UX and accessibility.
 */

import React from 'react';
import { ERROR_MESSAGES, EMPTY_MESSAGES, ARIA_LABELS } from './DashboardConfig';
import styles from './DashboardStates.module.css';

/**
 * Loading State Component
 * Displays a spinner with optional message
 */
export function LoadingState({
  message = 'Loading...',
  size = 'medium',
  fullPage = false,
  className = ''
}) {
  const sizeClass = styles[`spinner${size.charAt(0).toUpperCase() + size.slice(1)}`];

  return (
    <div
      className={`${styles.loadingContainer} ${fullPage ? styles.fullPage : ''} ${className}`}
      role="status"
      aria-label={ARIA_LABELS.loadingSpinner}
      aria-busy="true"
    >
      <div className={`${styles.spinner} ${sizeClass}`} aria-hidden="true" />
      {message && (
        <p className={styles.loadingMessage}>{message}</p>
      )}
    </div>
  );
}

/**
 * Error State Component
 * Displays error message with optional retry action
 */
export function ErrorState({
  error,
  title = 'Error Loading Data',
  onRetry,
  retryLabel = 'Try Again',
  className = ''
}) {
  // Determine error message based on error type
  const getErrorMessage = () => {
    if (typeof error === 'string') return error;

    if (error?.status) {
      switch (error.status) {
        case 401:
        case 403:
          return ERROR_MESSAGES.unauthorized;
        case 404:
          return ERROR_MESSAGES.notFound;
        case 408:
          return ERROR_MESSAGES.timeout;
        case 500:
        case 502:
        case 503:
          return ERROR_MESSAGES.serverError;
        default:
          return error.message || ERROR_MESSAGES.default;
      }
    }

    if (error?.message?.includes('fetch') || error?.message?.includes('network')) {
      return ERROR_MESSAGES.network;
    }

    return error?.message || ERROR_MESSAGES.default;
  };

  return (
    <div
      className={`${styles.errorContainer} ${className}`}
      role="alert"
      aria-live="assertive"
    >
      <div className={styles.errorIcon} aria-hidden="true">
        <svg
          width="48"
          height="48"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      </div>
      <h3 className={styles.errorTitle}>{title}</h3>
      <p className={styles.errorMessage}>{getErrorMessage()}</p>
      {onRetry && (
        <button
          className={styles.retryButton}
          onClick={onRetry}
          type="button"
          aria-label={retryLabel}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M23 4v6h-6" />
            <path d="M1 20v-6h6" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </svg>
          {retryLabel}
        </button>
      )}
    </div>
  );
}

/**
 * Empty State Component
 * Displays when no data is available
 */
export function EmptyState({
  message,
  type = 'data',
  icon,
  action,
  actionLabel,
  className = ''
}) {
  const displayMessage = message || EMPTY_MESSAGES[type] || EMPTY_MESSAGES.data;

  // Default icon based on type
  const renderIcon = () => {
    if (icon) return icon;

    switch (type) {
      case 'alerts':
        return (
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.73 21a2 2 0 0 1-3.46 0" />
          </svg>
        );
      case 'investigations':
        return (
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
        );
      case 'users':
        return (
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
        );
      case 'integrations':
        return (
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
            <line x1="6" y1="6" x2="6.01" y2="6" />
            <line x1="6" y1="18" x2="6.01" y2="18" />
          </svg>
        );
      default:
        return (
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
            <polyline points="13 2 13 9 20 9" />
          </svg>
        );
    }
  };

  return (
    <div className={`${styles.emptyContainer} ${className}`} role="status">
      <div className={styles.emptyIcon} aria-hidden="true">
        {renderIcon()}
      </div>
      <p className={styles.emptyMessage}>{displayMessage}</p>
      {action && actionLabel && (
        <button
          className={styles.actionButton}
          onClick={action}
          type="button"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

/**
 * Inline Error Component
 * Displays a small inline error message
 */
export function InlineError({ message, className = '' }) {
  if (!message) return null;

  return (
    <div
      className={`${styles.inlineError} ${className}`}
      role="alert"
    >
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        aria-hidden="true"
      >
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
      <span>{message}</span>
    </div>
  );
}

/**
 * Success State Component
 * Displays a success message with optional action
 */
export function SuccessState({
  message,
  title = 'Success',
  action,
  actionLabel,
  className = ''
}) {
  return (
    <div
      className={`${styles.successContainer} ${className}`}
      role="status"
      aria-live="polite"
    >
      <div className={styles.successIcon} aria-hidden="true">
        <svg
          width="48"
          height="48"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      </div>
      <h3 className={styles.successTitle}>{title}</h3>
      {message && <p className={styles.successMessage}>{message}</p>}
      {action && actionLabel && (
        <button
          className={styles.actionButton}
          onClick={action}
          type="button"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

/**
 * Skeleton Loader Component
 * Displays a placeholder while content is loading
 */
export function Skeleton({
  width = '100%',
  height = '20px',
  variant = 'text',
  className = ''
}) {
  const variantClass = styles[`skeleton${variant.charAt(0).toUpperCase() + variant.slice(1)}`];

  return (
    <div
      className={`${styles.skeleton} ${variantClass} ${className}`}
      style={{ width, height }}
      aria-hidden="true"
    />
  );
}

/**
 * Dashboard Card Skeleton
 * Displays a placeholder for dashboard cards while loading
 */
export function CardSkeleton({ className = '' }) {
  return (
    <div className={`${styles.cardSkeleton} ${className}`} aria-hidden="true">
      <Skeleton variant="text" width="40%" height="14px" />
      <Skeleton variant="text" width="60%" height="24px" />
      <Skeleton variant="text" width="30%" height="12px" />
    </div>
  );
}

/**
 * Table Skeleton
 * Displays a placeholder for tables while loading
 */
export function TableSkeleton({ rows = 5, columns = 4, className = '' }) {
  return (
    <div className={`${styles.tableSkeleton} ${className}`} aria-hidden="true">
      <div className={styles.tableSkeletonHeader}>
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} width="80px" height="12px" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className={styles.tableSkeletonRow}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} width={colIndex === 1 ? '150px' : '60px'} height="14px" />
          ))}
        </div>
      ))}
    </div>
  );
}

export default {
  LoadingState,
  ErrorState,
  EmptyState,
  InlineError,
  SuccessState,
  Skeleton,
  CardSkeleton,
  TableSkeleton
};
