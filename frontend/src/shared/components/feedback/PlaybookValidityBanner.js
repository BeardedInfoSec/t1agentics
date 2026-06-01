/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * PlaybookValidityBanner Component
 *
 * Shows playbook deployment readiness status:
 * - valid (deployable)
 * - needs_inputs (missing required configuration)
 * - has_errors (validation errors)
 * - requires_approval (needs approval to deploy)
 */

import React, { useState } from 'react';
import PropTypes from 'prop-types';
import styles from './PlaybookValidityBanner.module.css';

/**
 * Check circle icon
 */
const CheckCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
    <polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

/**
 * Alert triangle icon
 */
const AlertTriangleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

/**
 * X circle icon
 */
const XCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" />
    <line x1="15" y1="9" x2="9" y2="15" />
    <line x1="9" y1="9" x2="15" y2="15" />
  </svg>
);

/**
 * Shield icon
 */
const ShieldIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
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
 * Get status configuration
 */
function getStatusConfig(status) {
  switch (status) {
    case 'valid':
      return {
        icon: <CheckCircleIcon />,
        label: 'Ready to Deploy',
        description: 'All nodes configured, no errors detected',
        variant: 'success'
      };
    case 'needs_inputs':
      return {
        icon: <AlertTriangleIcon />,
        label: 'Needs Configuration',
        description: 'Some nodes require additional input',
        variant: 'warning'
      };
    case 'has_errors':
      return {
        icon: <XCircleIcon />,
        label: 'Has Errors',
        description: 'Fix errors before deployment',
        variant: 'error'
      };
    case 'requires_approval':
      return {
        icon: <ShieldIcon />,
        label: 'Requires Approval',
        description: 'Submit for approval to deploy',
        variant: 'info'
      };
    default:
      return {
        icon: <AlertTriangleIcon />,
        label: 'Unknown Status',
        description: 'Unable to determine playbook status',
        variant: 'neutral'
      };
  }
}

/**
 * PlaybookValidityBanner Component
 */
export function PlaybookValidityBanner({
  validity,
  onDeploy,
  onRequestApproval,
  onFixErrors,
  compact = false,
  className
}) {
  const [expanded, setExpanded] = useState(false);

  if (!validity) return null;

  const { status, errors, warnings, missingInputs, canDeploy } = validity;
  const config = getStatusConfig(status);
  const hasDetails = (errors?.length > 0) || (warnings?.length > 0) || (missingInputs?.length > 0);

  if (compact) {
    return (
      <div className={`${styles.compactBanner} ${styles[config.variant]} ${className || ''}`}>
        <span className={styles.compactIcon}>{config.icon}</span>
        <span className={styles.compactLabel}>{config.label}</span>
        {canDeploy && onDeploy && (
          <button className={styles.compactAction} onClick={onDeploy}>
            Deploy
          </button>
        )}
      </div>
    );
  }

  return (
    <div className={`${styles.banner} ${styles[config.variant]} ${className || ''}`}>
      <div className={styles.header}>
        <div className={styles.status}>
          <span className={styles.statusIcon}>{config.icon}</span>
          <div className={styles.statusText}>
            <span className={styles.statusLabel}>{config.label}</span>
            <span className={styles.statusDescription}>{config.description}</span>
          </div>
        </div>

        <div className={styles.actions}>
          {canDeploy && onDeploy && (
            <button className={styles.deployButton} onClick={onDeploy}>
              Deploy Playbook
            </button>
          )}
          {status === 'requires_approval' && onRequestApproval && (
            <button className={styles.approvalButton} onClick={onRequestApproval}>
              Request Approval
            </button>
          )}
          {(status === 'has_errors' || status === 'needs_inputs') && onFixErrors && (
            <button className={styles.fixButton} onClick={onFixErrors}>
              {status === 'has_errors' ? 'Fix Errors' : 'Configure'}
            </button>
          )}
        </div>
      </div>

      {hasDetails && (
        <>
          <button
            className={styles.expandButton}
            onClick={() => setExpanded(!expanded)}
          >
            <span>
              {expanded ? 'Hide details' : `Show ${(errors?.length || 0) + (warnings?.length || 0) + (missingInputs?.length || 0)} issue${((errors?.length || 0) + (warnings?.length || 0) + (missingInputs?.length || 0)) !== 1 ? 's' : ''}`}
            </span>
            <ChevronIcon expanded={expanded} />
          </button>

          {expanded && (
            <div className={styles.details}>
              {errors?.length > 0 && (
                <div className={styles.detailSection}>
                  <span className={styles.detailLabel}>Errors ({errors.length})</span>
                  <ul className={styles.detailList}>
                    {errors.map((error, i) => (
                      <li key={i} className={styles.errorItem}>{error}</li>
                    ))}
                  </ul>
                </div>
              )}

              {warnings?.length > 0 && (
                <div className={styles.detailSection}>
                  <span className={styles.detailLabel}>Warnings ({warnings.length})</span>
                  <ul className={styles.detailList}>
                    {warnings.map((warning, i) => (
                      <li key={i} className={styles.warningItem}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}

              {missingInputs?.length > 0 && (
                <div className={styles.detailSection}>
                  <span className={styles.detailLabel}>Missing Configuration ({missingInputs.length})</span>
                  <ul className={styles.detailList}>
                    {missingInputs.map((input, i) => (
                      <li key={i} className={styles.inputItem}>{input}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

PlaybookValidityBanner.propTypes = {
  validity: PropTypes.shape({
    status: PropTypes.oneOf(['valid', 'needs_inputs', 'has_errors', 'requires_approval']).isRequired,
    errors: PropTypes.arrayOf(PropTypes.string),
    warnings: PropTypes.arrayOf(PropTypes.string),
    missingInputs: PropTypes.arrayOf(PropTypes.string),
    canDeploy: PropTypes.bool
  }),
  onDeploy: PropTypes.func,
  onRequestApproval: PropTypes.func,
  onFixErrors: PropTypes.func,
  compact: PropTypes.bool,
  className: PropTypes.string
};

export default PlaybookValidityBanner;
