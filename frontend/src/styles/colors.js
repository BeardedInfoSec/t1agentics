/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Centralized Color Tokens - Single Source of Truth
 *
 * Maps semantic color names to CSS variables defined in App.css.
 * Use these functions instead of hardcoding color values in components.
 *
 * CSS Variable References (from App.css):
 *   --critical: #ef4444
 *   --high: #f97316
 *   --medium: #eab308
 *   --low: #22c55e
 *   --danger: #ef4444
 *   --warning: #f59e0b
 *   --success: #01B574
 *   --info: #3b82f6
 */

// =============================================================================
// SEVERITY COLORS - For alert/event severity levels
// =============================================================================
export const SEVERITY_COLORS = {
  CRITICAL: 'var(--critical)',    // #ef4444 - red
  HIGH: 'var(--high)',            // #f97316 - orange
  MEDIUM: 'var(--medium)',        // #eab308 - yellow
  LOW: 'var(--low)',              // #22c55e - green
  INFO: 'var(--info)',            // #3b82f6 - blue
  UNKNOWN: 'var(--text-muted)',   // #6e7681 - gray
};

export const SEVERITY_BG_COLORS = {
  CRITICAL: 'var(--danger-light)',
  HIGH: 'rgba(249, 115, 22, 0.15)',
  MEDIUM: 'rgba(234, 179, 8, 0.15)',
  LOW: 'var(--success-light)',
  INFO: 'var(--info-light)',
  UNKNOWN: 'rgba(110, 118, 129, 0.1)',
};

// =============================================================================
// STATUS COLORS - For investigation/alert workflow states
// =============================================================================
export const STATUS_COLORS = {
  NEW: 'var(--info)',             // #3b82f6 - blue (just arrived)
  ANALYZING: 'var(--success)',    // #01B574 - green (AI working)
  NEEDS_REVIEW: 'var(--warning)', // #f59e0b - amber (needs human attention)
  IN_PROGRESS: '#d97706',         // amber-dark (analyst working)
  CLOSED: 'var(--text-muted)',    // #6e7681 - gray (terminal state)
  OPEN: 'var(--info)',            // #3b82f6 - blue
  PENDING: 'var(--warning)',      // #f59e0b - amber
};

export const STATUS_BG_COLORS = {
  NEW: 'var(--info-light)',
  ANALYZING: 'var(--success-light)',
  NEEDS_REVIEW: 'var(--warning-light)',
  IN_PROGRESS: 'rgba(217, 119, 6, 0.15)',
  CLOSED: 'rgba(110, 118, 129, 0.1)',
  OPEN: 'var(--info-light)',
  PENDING: 'var(--warning-light)',
};

// =============================================================================
// VERDICT COLORS - For AI/analyst verdicts on alerts/investigations
// =============================================================================
export const VERDICT_COLORS = {
  MALICIOUS: 'var(--danger)',     // #ef4444 - red
  TRUE_POSITIVE: 'var(--danger)', // #ef4444 - red
  SUSPICIOUS: 'var(--warning)',   // #f59e0b - amber
  BENIGN: 'var(--success)',       // #01B574 - green
  FALSE_POSITIVE: 'var(--success)', // #01B574 - green
  BENIGN_POSITIVE: 'var(--success)', // #01B574 - green
  INCONCLUSIVE: 'var(--text-muted)', // gray
  UNKNOWN: 'var(--text-muted)',   // gray
  NEEDS_INVESTIGATION: 'var(--info)', // blue
};

export const VERDICT_BG_COLORS = {
  MALICIOUS: 'var(--danger-light)',
  TRUE_POSITIVE: 'var(--danger-light)',
  SUSPICIOUS: 'var(--warning-light)',
  BENIGN: 'var(--success-light)',
  FALSE_POSITIVE: 'var(--success-light)',
  BENIGN_POSITIVE: 'var(--success-light)',
  INCONCLUSIVE: 'rgba(110, 118, 129, 0.1)',
  UNKNOWN: 'rgba(110, 118, 129, 0.1)',
  NEEDS_INVESTIGATION: 'var(--info-light)',
};

// =============================================================================
// PRIORITY COLORS - For alert/investigation priority levels
// =============================================================================
export const PRIORITY_COLORS = {
  P1: 'var(--critical)',          // #ef4444 - critical
  P2: 'var(--high)',              // #f97316 - high
  P3: 'var(--medium)',            // #eab308 - medium
  P4: 'var(--low)',               // #22c55e - low
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
};

export const PRIORITY_BG_COLORS = {
  P1: 'var(--danger-light)',
  P2: 'rgba(249, 115, 22, 0.15)',
  P3: 'rgba(234, 179, 8, 0.15)',
  P4: 'var(--success-light)',
  CRITICAL: 'var(--danger-light)',
  HIGH: 'rgba(249, 115, 22, 0.15)',
  MEDIUM: 'rgba(234, 179, 8, 0.15)',
  LOW: 'var(--success-light)',
};

// =============================================================================
// DISPOSITION COLORS - Alias for verdict colors (used in some components)
// =============================================================================
export const DISPOSITION_COLORS = VERDICT_COLORS;
export const DISPOSITION_BG_COLORS = VERDICT_BG_COLORS;

// =============================================================================
// HELPER FUNCTIONS - Use these in components
// =============================================================================

/**
 * Get color for severity level
 * @param {string} severity - CRITICAL, HIGH, MEDIUM, LOW, INFO
 * @returns {string} CSS variable reference
 */
export const getSeverityColor = (severity) => {
  const key = severity?.toUpperCase()?.trim();
  return SEVERITY_COLORS[key] || SEVERITY_COLORS.UNKNOWN;
};

/**
 * Get background color for severity level
 * @param {string} severity - CRITICAL, HIGH, MEDIUM, LOW, INFO
 * @returns {string} CSS variable or rgba value
 */
export const getSeverityBgColor = (severity) => {
  const key = severity?.toUpperCase()?.trim();
  return SEVERITY_BG_COLORS[key] || SEVERITY_BG_COLORS.UNKNOWN;
};

/**
 * Get color for workflow status
 * @param {string} status - NEW, ANALYZING, NEEDS_REVIEW, IN_PROGRESS, CLOSED
 * @returns {string} CSS variable reference
 */
export const getStatusColor = (status) => {
  const key = status?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  return STATUS_COLORS[key] || STATUS_COLORS.NEW;
};

/**
 * Get background color for workflow status
 * @param {string} status - NEW, ANALYZING, NEEDS_REVIEW, IN_PROGRESS, CLOSED
 * @returns {string} CSS variable or rgba value
 */
export const getStatusBgColor = (status) => {
  const key = status?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  return STATUS_BG_COLORS[key] || STATUS_BG_COLORS.NEW;
};

/**
 * Get color for verdict/disposition
 * @param {string} verdict - MALICIOUS, SUSPICIOUS, BENIGN, TRUE_POSITIVE, etc.
 * @returns {string} CSS variable reference
 */
export const getVerdictColor = (verdict) => {
  const key = verdict?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  return VERDICT_COLORS[key] || VERDICT_COLORS.UNKNOWN;
};

/**
 * Get background color for verdict/disposition
 * @param {string} verdict - MALICIOUS, SUSPICIOUS, BENIGN, TRUE_POSITIVE, etc.
 * @returns {string} CSS variable or rgba value
 */
export const getVerdictBgColor = (verdict) => {
  const key = verdict?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  return VERDICT_BG_COLORS[key] || VERDICT_BG_COLORS.UNKNOWN;
};

/**
 * Alias for getVerdictColor - some components use "disposition" terminology
 */
export const getDispositionColor = getVerdictColor;
export const getDispositionBgColor = getVerdictBgColor;

/**
 * Get color for priority level
 * @param {string} priority - P1, P2, P3, P4 or CRITICAL, HIGH, MEDIUM, LOW
 * @returns {string} CSS variable reference
 */
export const getPriorityColor = (priority) => {
  const key = priority?.toUpperCase()?.trim();
  return PRIORITY_COLORS[key] || PRIORITY_COLORS.P4;
};

/**
 * Get background color for priority level
 * @param {string} priority - P1, P2, P3, P4 or CRITICAL, HIGH, MEDIUM, LOW
 * @returns {string} CSS variable or rgba value
 */
export const getPriorityBgColor = (priority) => {
  const key = priority?.toUpperCase()?.trim();
  return PRIORITY_BG_COLORS[key] || PRIORITY_BG_COLORS.P4;
};

// =============================================================================
// BADGE VARIANT MAPPING - Maps semantic values to Badge component variants
// =============================================================================

/**
 * Map severity to Badge variant
 * @param {string} severity - CRITICAL, HIGH, MEDIUM, LOW
 * @returns {string} Badge variant: danger, warning, info, success, default
 */
export const severityToBadgeVariant = (severity) => {
  const key = severity?.toUpperCase()?.trim();
  const mapping = {
    CRITICAL: 'danger',
    HIGH: 'warning',
    MEDIUM: 'medium',
    LOW: 'success',
    INFO: 'info',
  };
  return mapping[key] || 'default';
};

/**
 * Map verdict to Badge variant
 * @param {string} verdict - MALICIOUS, SUSPICIOUS, BENIGN, etc.
 * @returns {string} Badge variant: danger, warning, success, default
 */
export const verdictToBadgeVariant = (verdict) => {
  const key = verdict?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  const mapping = {
    MALICIOUS: 'danger',
    TRUE_POSITIVE: 'danger',
    SUSPICIOUS: 'warning',
    NEEDS_INVESTIGATION: 'info',
    BENIGN: 'success',
    FALSE_POSITIVE: 'success',
    BENIGN_POSITIVE: 'success',
    INCONCLUSIVE: 'default',
    UNKNOWN: 'default',
  };
  return mapping[key] || 'default';
};

/**
 * Map status to Badge variant
 * @param {string} status - NEW, ANALYZING, NEEDS_REVIEW, etc.
 * @returns {string} Badge variant: info, success, warning, default
 */
export const statusToBadgeVariant = (status) => {
  const key = status?.toUpperCase()?.replace(/[_\s-]/g, '_')?.trim();
  const mapping = {
    NEW: 'info',
    OPEN: 'info',
    ANALYZING: 'success',
    NEEDS_REVIEW: 'warning',
    IN_PROGRESS: 'warning',
    PENDING: 'warning',
    CLOSED: 'default',
  };
  return mapping[key] || 'default';
};

/**
 * Map priority to Badge variant
 * @param {string} priority - P1, P2, P3, P4
 * @returns {string} Badge variant: danger, warning, info, success
 */
export const priorityToBadgeVariant = (priority) => {
  const key = priority?.toUpperCase()?.trim();
  const mapping = {
    P1: 'danger',
    CRITICAL: 'danger',
    P2: 'warning',
    HIGH: 'warning',
    P3: 'info',
    MEDIUM: 'info',
    P4: 'success',
    LOW: 'success',
  };
  return mapping[key] || 'default';
};

export default {
  // Color maps
  SEVERITY_COLORS,
  SEVERITY_BG_COLORS,
  STATUS_COLORS,
  STATUS_BG_COLORS,
  VERDICT_COLORS,
  VERDICT_BG_COLORS,
  PRIORITY_COLORS,
  PRIORITY_BG_COLORS,
  DISPOSITION_COLORS,
  DISPOSITION_BG_COLORS,
  // Helper functions
  getSeverityColor,
  getSeverityBgColor,
  getStatusColor,
  getStatusBgColor,
  getVerdictColor,
  getVerdictBgColor,
  getDispositionColor,
  getDispositionBgColor,
  getPriorityColor,
  getPriorityBgColor,
  // Badge variant mappers
  severityToBadgeVariant,
  verdictToBadgeVariant,
  statusToBadgeVariant,
  priorityToBadgeVariant,
};
