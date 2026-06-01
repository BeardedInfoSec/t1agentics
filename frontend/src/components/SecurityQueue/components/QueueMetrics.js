/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * QueueMetrics Component
 *
 * Displays clickable metric cards for the security queue.
 * Config-driven - metrics appear based on appliesTo in METRIC_CONFIG.
 */

import React, { useMemo } from 'react';
import { METRIC_CONFIG } from '../constants';
import styles from '../SecurityQueue.module.css';

/**
 * QueueMetrics Component
 * @param {Object} props
 * @param {import('../types').QueueMetrics} props.metrics - Computed metrics
 * @param {string} props.viewMode - Current view mode
 * @param {Function} props.setFilters - Filter update function
 * @param {Function} props.setViewMode - View mode setter
 */
function QueueMetrics({
  metrics,
  viewMode,
  setFilters,
  setViewMode,
}) {
  // Filter metrics that apply to current view mode
  const visibleMetrics = useMemo(() => {
    return METRIC_CONFIG.filter(m => m.appliesTo.includes(viewMode));
  }, [viewMode]);

  return (
    <div className={styles.metricsGrid}>
      {visibleMetrics.map(config => {
        const value = metrics[config.key] || 0;
        const isHighlighted = config.key === 'critical' || config.key === 'breached';
        const isWarning = config.key === 'needsReview' || config.key === 'atRisk';

        return (
          <button
            key={config.key}
            className={`${styles.metricCard} ${isHighlighted && value > 0 ? styles.metricHighlighted : ''} ${isWarning && value > 0 ? styles.metricWarning : ''}`}
            onClick={() => config.onClick?.(setFilters, setViewMode)}
            title={`Click to filter by ${config.label.toLowerCase()}`}
          >
            <span
              className={styles.metricValue}
              style={{ color: value > 0 ? config.color : 'var(--text-muted)' }}
            >
              {value}
            </span>
            <span className={styles.metricLabel}>{config.label}</span>
          </button>
        );
      })}
    </div>
  );
}

export default React.memo(QueueMetrics);
