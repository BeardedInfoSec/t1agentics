/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * UrgencyStrip Component
 *
 * Persistent strip showing top 3 urgent items requiring immediate attention.
 * Provides at-a-glance visibility into critical work.
 */

import React from 'react';
import PropTypes from 'prop-types';
import styles from './UrgencyStrip.module.css';

/**
 * Alert icon
 */
const AlertIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

/**
 * Clock icon for SLA
 */
const ClockIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" />
    <polyline points="12 6 12 12 16 14" />
  </svg>
);

/**
 * Arrow right icon
 */
const ArrowIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="5" y1="12" x2="19" y2="12" />
    <polyline points="12 5 19 12 12 19" />
  </svg>
);

/**
 * Format SLA time remaining
 * @param {number} remainingMs
 * @returns {string}
 */
function formatSLATime(remainingMs) {
  if (remainingMs < 0) {
    const overMs = Math.abs(remainingMs);
    const overMins = Math.floor(overMs / 60000);
    const overHours = Math.floor(overMins / 60);
    if (overHours > 0) return `${overHours}h ${overMins % 60}m overdue`;
    return `${overMins}m overdue`;
  }

  const mins = Math.floor(remainingMs / 60000);
  const hours = Math.floor(mins / 60);
  if (hours > 0) return `${hours}h ${mins % 60}m left`;
  return `${mins}m left`;
}

/**
 * Single urgent item card
 */
function UrgentItem({ item, onClick }) {
  const {
    id,
    title,
    severity,
    type,
    owner,
    sla,
    action
  } = item;

  const slaStatus = sla?.status || 'healthy';
  const isBreached = slaStatus === 'breached';
  const isAtRisk = slaStatus === 'at_risk';

  return (
    <button
      className={`${styles.item} ${styles[`severity-${severity}`]} ${isBreached ? styles.breached : ''}`}
      onClick={() => onClick?.(item)}
    >
      <div className={styles.itemHeader}>
        <span className={styles.itemType}>{type}</span>
        {sla && (
          <span className={`${styles.itemSla} ${isBreached ? styles.slaBreached : isAtRisk ? styles.slaAtRisk : ''}`}>
            <ClockIcon />
            {formatSLATime(sla.remainingMs)}
          </span>
        )}
      </div>

      <div className={styles.itemTitle}>{title}</div>

      <div className={styles.itemFooter}>
        {owner && <span className={styles.itemOwner}>{owner}</span>}
        {action && (
          <span className={styles.itemAction}>
            {action}
            <ArrowIcon />
          </span>
        )}
      </div>
    </button>
  );
}

UrgentItem.propTypes = {
  item: PropTypes.shape({
    id: PropTypes.string.isRequired,
    title: PropTypes.string.isRequired,
    severity: PropTypes.oneOf(['critical', 'high', 'medium', 'low']),
    type: PropTypes.string,
    owner: PropTypes.string,
    sla: PropTypes.shape({
      status: PropTypes.string,
      remainingMs: PropTypes.number
    }),
    action: PropTypes.string
  }).isRequired,
  onClick: PropTypes.func
};

/**
 * UrgencyStrip Component
 */
export function UrgencyStrip({
  items = [],
  maxItems = 3,
  title = 'Requires Attention',
  onItemClick,
  onViewAll,
  className
}) {
  // Only show urgent items (critical/high or breached SLA)
  const urgentItems = items
    .filter(item =>
      item.severity === 'critical' ||
      item.severity === 'high' ||
      item.sla?.status === 'breached' ||
      item.sla?.status === 'at_risk'
    )
    .slice(0, maxItems);

  if (urgentItems.length === 0) {
    return null; // Don't show strip if nothing urgent
  }

  return (
    <div className={`${styles.strip} ${className || ''}`}>
      <div className={styles.header}>
        <div className={styles.headerIcon}>
          <AlertIcon />
        </div>
        <span className={styles.headerTitle}>{title}</span>
        <span className={styles.headerCount}>{urgentItems.length}</span>
        {onViewAll && (
          <button className={styles.viewAllButton} onClick={onViewAll}>
            View all
          </button>
        )}
      </div>

      <div className={styles.items}>
        {urgentItems.map(item => (
          <UrgentItem
            key={item.id}
            item={item}
            onClick={onItemClick}
          />
        ))}
      </div>
    </div>
  );
}

UrgencyStrip.propTypes = {
  items: PropTypes.arrayOf(PropTypes.shape({
    id: PropTypes.string.isRequired,
    title: PropTypes.string.isRequired,
    severity: PropTypes.oneOf(['critical', 'high', 'medium', 'low']),
    type: PropTypes.string,
    owner: PropTypes.string,
    sla: PropTypes.shape({
      status: PropTypes.string,
      remainingMs: PropTypes.number
    }),
    action: PropTypes.string
  })),
  maxItems: PropTypes.number,
  title: PropTypes.string,
  onItemClick: PropTypes.func,
  onViewAll: PropTypes.func,
  className: PropTypes.string
};

export default UrgencyStrip;
