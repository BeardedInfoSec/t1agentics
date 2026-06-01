/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Attribution Component
 *
 * Shows who/what performed an action - human, automation, or AI.
 * Critical for SOC trust and auditability.
 */

import React from 'react';
import PropTypes from 'prop-types';
import styles from './Attribution.module.css';

/**
 * @typedef {import('../../../data/types/common.types').Attribution} Attribution
 */

/**
 * Human icon
 */
const UserIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
    <circle cx="12" cy="7" r="4" />
  </svg>
);

/**
 * Automation/playbook icon
 */
const AutomationIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
  </svg>
);

/**
 * AI/Riggs icon
 */
const AIIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 2L2 7l10 5 10-5-10-5z" />
    <path d="M2 17l10 5 10-5" />
    <path d="M2 12l10 5 10-5" />
  </svg>
);

/**
 * System icon
 */
const SystemIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
    <line x1="8" y1="21" x2="16" y2="21" />
    <line x1="12" y1="17" x2="12" y2="21" />
  </svg>
);

/**
 * Get icon for attribution source
 * @param {string} source
 * @returns {React.ReactNode}
 */
function getSourceIcon(source) {
  switch (source) {
    case 'human':
      return <UserIcon />;
    case 'automation':
      return <AutomationIcon />;
    case 'riggs':
    case 'ai':
      return <AIIcon />;
    case 'system':
    default:
      return <SystemIcon />;
  }
}

/**
 * Get label for attribution source
 * @param {string} source
 * @returns {string}
 */
function getSourceLabel(source) {
  switch (source) {
    case 'human':
      return 'Manual';
    case 'automation':
      return 'Automated';
    case 'riggs':
      return 'Riggs AI';
    case 'ai':
      return 'AI';
    case 'system':
    default:
      return 'System';
  }
}

/**
 * Format confidence as percentage
 * @param {number} confidence - 0 to 1
 * @returns {string}
 */
function formatConfidence(confidence) {
  if (typeof confidence !== 'number') return '';
  return `${Math.round(confidence * 100)}%`;
}

/**
 * Format relative time
 * @param {Date} date
 * @returns {string}
 */
function formatRelativeTime(date) {
  if (!date) return '';

  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * Confidence indicator bar
 */
function ConfidenceBar({ confidence }) {
  if (typeof confidence !== 'number') return null;

  const percentage = Math.round(confidence * 100);
  let color = '#22c55e'; // green
  if (percentage < 70) color = '#f59e0b'; // amber
  if (percentage < 50) color = '#ef4444'; // red

  return (
    <div className={styles.confidenceBar} title={`${percentage}% confidence`}>
      <div
        className={styles.confidenceFill}
        style={{ width: `${percentage}%`, backgroundColor: color }}
      />
    </div>
  );
}

/**
 * Attribution Badge - compact version
 */
export function AttributionBadge({ attribution, showTime = false }) {
  if (!attribution) return null;

  const { source, username, playbookName, confidence, timestamp } = attribution;

  return (
    <div className={`${styles.badge} ${styles[`source-${source}`]}`}>
      <span className={styles.badgeIcon}>{getSourceIcon(source)}</span>
      <span className={styles.badgeLabel}>
        {source === 'human' && username ? username : getSourceLabel(source)}
        {source === 'automation' && playbookName && ` • ${playbookName}`}
        {confidence !== undefined && ` • ${formatConfidence(confidence)}`}
      </span>
      {showTime && timestamp && (
        <span className={styles.badgeTime}>{formatRelativeTime(timestamp)}</span>
      )}
    </div>
  );
}

AttributionBadge.propTypes = {
  attribution: PropTypes.shape({
    source: PropTypes.oneOf(['human', 'automation', 'riggs', 'ai', 'system']).isRequired,
    username: PropTypes.string,
    playbookName: PropTypes.string,
    confidence: PropTypes.number,
    timestamp: PropTypes.instanceOf(Date)
  }),
  showTime: PropTypes.bool
};

/**
 * Attribution Card - detailed version with rationale
 */
export function AttributionCard({
  attribution,
  title = 'Attribution',
  showConfidenceBar = true,
  className
}) {
  if (!attribution) return null;

  const { source, username, userId, playbookId, playbookName, confidence, rationale, timestamp } = attribution;

  return (
    <div className={`${styles.card} ${styles[`source-${source}`]} ${className || ''}`}>
      <div className={styles.cardHeader}>
        <div className={styles.cardIcon}>{getSourceIcon(source)}</div>
        <div className={styles.cardTitle}>
          <span className={styles.cardLabel}>{getSourceLabel(source)}</span>
          {source === 'human' && username && (
            <span className={styles.cardValue}>{username}</span>
          )}
          {source === 'automation' && playbookName && (
            <span className={styles.cardValue}>{playbookName}</span>
          )}
        </div>
        {timestamp && (
          <span className={styles.cardTime}>{formatRelativeTime(timestamp)}</span>
        )}
      </div>

      {(confidence !== undefined || rationale) && (
        <div className={styles.cardBody}>
          {confidence !== undefined && (
            <div className={styles.confidenceRow}>
              <span className={styles.confidenceLabel}>Confidence</span>
              <span className={styles.confidenceValue}>{formatConfidence(confidence)}</span>
              {showConfidenceBar && <ConfidenceBar confidence={confidence} />}
            </div>
          )}

          {rationale && (
            <div className={styles.rationaleRow}>
              <span className={styles.rationaleLabel}>Rationale</span>
              <p className={styles.rationaleText}>{rationale}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

AttributionCard.propTypes = {
  attribution: PropTypes.shape({
    source: PropTypes.oneOf(['human', 'automation', 'riggs', 'ai', 'system']).isRequired,
    username: PropTypes.string,
    userId: PropTypes.string,
    playbookId: PropTypes.string,
    playbookName: PropTypes.string,
    confidence: PropTypes.number,
    rationale: PropTypes.string,
    timestamp: PropTypes.instanceOf(Date)
  }),
  title: PropTypes.string,
  showConfidenceBar: PropTypes.bool,
  className: PropTypes.string
};

/**
 * Inline Attribution - minimal inline display
 */
export function AttributionInline({ attribution }) {
  if (!attribution) return null;

  const { source, username, playbookName, timestamp } = attribution;

  return (
    <span className={styles.inline}>
      {getSourceIcon(source)}
      <span className={styles.inlineText}>
        {source === 'human' && username ? username : getSourceLabel(source)}
        {source === 'automation' && playbookName && ` via ${playbookName}`}
      </span>
      {timestamp && (
        <span className={styles.inlineTime}>{formatRelativeTime(timestamp)}</span>
      )}
    </span>
  );
}

AttributionInline.propTypes = {
  attribution: PropTypes.shape({
    source: PropTypes.oneOf(['human', 'automation', 'riggs', 'ai', 'system']).isRequired,
    username: PropTypes.string,
    playbookName: PropTypes.string,
    timestamp: PropTypes.instanceOf(Date)
  })
};

export default AttributionBadge;
