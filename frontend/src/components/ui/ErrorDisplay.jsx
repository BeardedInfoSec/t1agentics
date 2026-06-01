/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ErrorDisplay Component
 *
 * Displays structured errors in a user-friendly format.
 * Shows what happened, why, impact, remediation steps, and Riggs insights.
 */

import React, { useState } from 'react';
import {
  AlertTriangle, XCircle, Clock, WifiOff, KeyRound, Shield,
  AlertCircle, Timer, Bot, ChevronDown, ChevronRight,
  RefreshCw, SkipForward, FileText
} from 'lucide-react';
import styles from './ErrorDisplay.module.css';

const ErrorDisplay = ({
  error,
  onRetry,
  onSkip,
  onViewDetails,
  compact = false
}) => {
  const [expanded, setExpanded] = useState(!compact);
  const [showTechnical, setShowTechnical] = useState(false);

  if (!error) return null;

  // Category icons mapping
  const categoryIcons = {
    authentication: KeyRound,
    authorization: Shield,
    network: WifiOff,
    timeout: Clock,
    rate_limit: Timer,
    validation: AlertCircle,
    not_found: FileText,
    external_service: AlertTriangle,
    configuration: AlertTriangle,
    internal: XCircle,
    unknown: AlertTriangle,
  };

  const CategoryIcon = categoryIcons[error.category] || AlertTriangle;

  // Severity colors
  const severityConfig = {
    low: { color: 'blue', label: 'Low' },
    medium: { color: 'yellow', label: 'Medium' },
    high: { color: 'orange', label: 'High' },
    critical: { color: 'red', label: 'Critical' },
  };

  const severity = severityConfig[error.severity] || severityConfig.medium;

  return (
    <div
      className={`${styles.errorDisplay} ${styles[`severity-${error.severity}`]} ${compact ? styles.compact : ''}`}
      role="alert"
      aria-live="polite"
    >
      {/* Error Header */}
      <div className={styles.errorHeader}>
        <div className={styles.errorIcon}>
          <CategoryIcon size={24} />
        </div>
        <div className={styles.errorTitle}>
          <h4>{error.what_happened}</h4>
          <div className={styles.errorMeta}>
            <span className={`${styles.severityBadge} ${styles[`severity-${error.severity}`]}`}>
              {severity.label}
            </span>
            <span className={styles.categoryBadge}>
              {error.category.replace('_', ' ')}
            </span>
          </div>
        </div>
        {compact && (
          <button
            className={styles.expandButton}
            onClick={() => setExpanded(!expanded)}
            aria-label={expanded ? 'Collapse error details' : 'Expand error details'}
          >
            {expanded ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
          </button>
        )}
      </div>

      {/* Error Body (Collapsible if compact) */}
      {expanded && (
        <div className={styles.errorBody}>
          {/* Why it happened */}
          <section className={styles.errorSection}>
            <h5 className={styles.sectionTitle}>Why it happened:</h5>
            <p className={styles.sectionContent}>{error.why_it_happened}</p>
          </section>

          {/* Impact */}
          <section className={styles.errorSection}>
            <h5 className={styles.sectionTitle}>Impact:</h5>
            <p className={`${styles.sectionContent} ${styles.impact}`}>
              {error.what_it_means}
            </p>
          </section>

          {/* Remediation Steps */}
          {error.remediation_steps && error.remediation_steps.length > 0 && (
            <section className={styles.errorSection}>
              <h5 className={styles.sectionTitle}>What to do next:</h5>
              <ol className={styles.remediationSteps}>
                {error.remediation_steps.map((step, index) => (
                  <li key={index}>{step}</li>
                ))}
              </ol>
            </section>
          )}

          {/* Riggs Insights */}
          {(error.riggs_explanation || (error.riggs_suggestions && error.riggs_suggestions.length > 0)) && (
            <section className={`${styles.errorSection} ${styles.riggsInsights}`}>
              <div className={styles.riggsHeader}>
                <Bot size={18} />
                <h5 className={styles.sectionTitle}>Riggs Analysis</h5>
              </div>
              {error.riggs_explanation && (
                <p className={styles.sectionContent}>{error.riggs_explanation}</p>
              )}
              {error.riggs_suggestions && error.riggs_suggestions.length > 0 && (
                <ul className={styles.riggsSuggestions}>
                  {error.riggs_suggestions.map((suggestion, index) => (
                    <li key={index}>• {suggestion}</li>
                  ))}
                </ul>
              )}
            </section>
          )}

          {/* Technical Details (Collapsible) */}
          {error.technical && (
            <section className={styles.errorSection}>
              <button
                className={styles.technicalToggle}
                onClick={() => setShowTechnical(!showTechnical)}
              >
                {showTechnical ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <span>Technical Details</span>
              </button>
              {showTechnical && (
                <div className={styles.technicalDetails}>
                  <div className={styles.technicalItem}>
                    <strong>Error Type:</strong> <code>{error.error_type}</code>
                  </div>
                  <div className={styles.technicalItem}>
                    <strong>Error Message:</strong> <code>{error.error_message}</code>
                  </div>
                  {error.technical.request && (
                    <details className={styles.technicalDropdown}>
                      <summary>Request Details</summary>
                      <pre>{JSON.stringify(error.technical.request, null, 2)}</pre>
                    </details>
                  )}
                  {error.technical.response && (
                    <details className={styles.technicalDropdown}>
                      <summary>Response Details</summary>
                      <pre>{JSON.stringify(error.technical.response, null, 2)}</pre>
                    </details>
                  )}
                  {error.technical.stack_trace && (
                    <details className={styles.technicalDropdown}>
                      <summary>Stack Trace</summary>
                      <pre>{error.technical.stack_trace}</pre>
                    </details>
                  )}
                </div>
              )}
            </section>
          )}
        </div>
      )}

      {/* Error Actions */}
      {expanded && (onRetry || onSkip || onViewDetails) && (
        <div className={styles.errorActions}>
          {error.can_retry && onRetry && (
            <button
              className={`${styles.actionButton} ${styles.primary}`}
              onClick={onRetry}
            >
              <RefreshCw size={16} />
              <span>Retry Step</span>
            </button>
          )}
          {onSkip && (
            <button
              className={`${styles.actionButton} ${styles.secondary}`}
              onClick={onSkip}
            >
              <SkipForward size={16} />
              <span>Skip Step</span>
            </button>
          )}
          {onViewDetails && (
            <button
              className={`${styles.actionButton} ${styles.ghost}`}
              onClick={onViewDetails}
            >
              <FileText size={16} />
              <span>View Full Details</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default ErrorDisplay;
