/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * NextActionCard Component
 *
 * Shows AI-recommended next best action with rationale,
 * confidence, and expected outcome.
 */

import React, { useState } from 'react';
import PropTypes from 'prop-types';
import styles from './NextActionCard.module.css';

/**
 * Sparkles/AI icon
 */
const SparklesIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 3l1.912 5.813a2 2 0 001.275 1.275L21 12l-5.813 1.912a2 2 0 00-1.275 1.275L12 21l-1.912-5.813a2 2 0 00-1.275-1.275L3 12l5.813-1.912a2 2 0 001.275-1.275L12 3z" />
  </svg>
);

/**
 * Check icon
 */
const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

/**
 * X icon
 */
const XIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

/**
 * Chevron icon
 */
const ChevronIcon = ({ expanded }) => (
  <svg
    width="14"
    height="14"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}
  >
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

/**
 * Format confidence percentage
 */
function formatConfidence(confidence) {
  if (typeof confidence !== 'number') return 'N/A';
  return `${Math.round(confidence * 100)}%`;
}

/**
 * Get confidence color
 */
function getConfidenceColor(confidence) {
  if (confidence >= 0.8) return '#22c55e';
  if (confidence >= 0.6) return '#f59e0b';
  return '#ef4444';
}

/**
 * NextActionCard Component
 */
export function NextActionCard({
  recommendation,
  onAccept,
  onDismiss,
  onViewDetails,
  loading = false,
  compact = false,
  className
}) {
  const [expanded, setExpanded] = useState(false);

  if (!recommendation) return null;

  const {
    id,
    title,
    description,
    rationale,
    confidence,
    expectedOutcome,
    priority,
    playbookId,
    playbookName,
    parameters
  } = recommendation;

  const confidenceColor = getConfidenceColor(confidence);

  if (compact) {
    return (
      <div className={`${styles.compactCard} ${className || ''}`}>
        <div className={styles.compactIcon}>
          <SparklesIcon />
        </div>
        <div className={styles.compactContent}>
          <span className={styles.compactTitle}>{title}</span>
          <span className={styles.compactConfidence} style={{ color: confidenceColor }}>
            {formatConfidence(confidence)}
          </span>
        </div>
        <div className={styles.compactActions}>
          <button
            className={styles.acceptButtonCompact}
            onClick={() => onAccept?.(recommendation)}
            disabled={loading}
            aria-label="Accept recommendation"
          >
            <CheckIcon />
          </button>
          <button
            className={styles.dismissButtonCompact}
            onClick={() => onDismiss?.(recommendation)}
            disabled={loading}
            aria-label="Dismiss recommendation"
          >
            <XIcon />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`${styles.card} ${className || ''}`}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerIcon}>
          <SparklesIcon />
        </div>
        <div className={styles.headerText}>
          <span className={styles.headerLabel}>Recommended Action</span>
          {priority && (
            <span className={`${styles.priority} ${styles[`priority-${priority.toLowerCase()}`]}`}>
              {priority}
            </span>
          )}
        </div>
        <div className={styles.confidence} style={{ color: confidenceColor }}>
          <span className={styles.confidenceValue}>{formatConfidence(confidence)}</span>
          <span className={styles.confidenceLabel}>confidence</span>
        </div>
      </div>

      {/* Title & Description */}
      <div className={styles.body}>
        <h3 className={styles.title}>{title}</h3>
        {description && <p className={styles.description}>{description}</p>}

        {/* Rationale */}
        {rationale && (
          <div className={styles.rationale}>
            <span className={styles.rationaleLabel}>Why this action?</span>
            <p className={styles.rationaleText}>{rationale}</p>
          </div>
        )}

        {/* Expected Outcome */}
        {expectedOutcome && (
          <div className={styles.outcome}>
            <span className={styles.outcomeLabel}>Expected outcome</span>
            <p className={styles.outcomeText}>{expectedOutcome}</p>
          </div>
        )}

        {/* Expandable Details */}
        {(playbookName || parameters) && (
          <>
            <button
              className={styles.expandButton}
              onClick={() => setExpanded(!expanded)}
            >
              <span>{expanded ? 'Hide details' : 'Show details'}</span>
              <ChevronIcon expanded={expanded} />
            </button>

            {expanded && (
              <div className={styles.details}>
                {playbookName && (
                  <div className={styles.detailRow}>
                    <span className={styles.detailLabel}>Playbook</span>
                    <span className={styles.detailValue}>{playbookName}</span>
                  </div>
                )}
                {parameters && Object.keys(parameters).length > 0 && (
                  <div className={styles.detailRow}>
                    <span className={styles.detailLabel}>Parameters</span>
                    <div className={styles.parameters}>
                      {Object.entries(parameters).map(([key, value]) => (
                        <div key={key} className={styles.parameter}>
                          <span className={styles.paramKey}>{key}:</span>
                          <span className={styles.paramValue}>{String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Actions */}
      <div className={styles.actions}>
        <button
          className={styles.acceptButton}
          onClick={() => onAccept?.(recommendation)}
          disabled={loading}
        >
          {loading ? 'Executing...' : 'Accept & Execute'}
        </button>
        <button
          className={styles.dismissButton}
          onClick={() => onDismiss?.(recommendation)}
          disabled={loading}
        >
          Dismiss
        </button>
        {onViewDetails && (
          <button
            className={styles.detailsButton}
            onClick={() => onViewDetails?.(recommendation)}
          >
            View Details
          </button>
        )}
      </div>
    </div>
  );
}

NextActionCard.propTypes = {
  recommendation: PropTypes.shape({
    id: PropTypes.string,
    title: PropTypes.string.isRequired,
    description: PropTypes.string,
    rationale: PropTypes.string,
    confidence: PropTypes.number,
    expectedOutcome: PropTypes.string,
    priority: PropTypes.string,
    playbookId: PropTypes.string,
    playbookName: PropTypes.string,
    parameters: PropTypes.object
  }),
  onAccept: PropTypes.func,
  onDismiss: PropTypes.func,
  onViewDetails: PropTypes.func,
  loading: PropTypes.bool,
  compact: PropTypes.bool,
  className: PropTypes.string
};

export default NextActionCard;
