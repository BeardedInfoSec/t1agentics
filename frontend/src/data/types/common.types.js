/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Common Type Definitions
 *
 * Shared types used across the data layer and components.
 * Uses JSDoc for type hints without TypeScript overhead.
 */

/**
 * Severity levels for alerts and findings
 * @typedef {'critical'|'high'|'medium'|'low'} Severity
 */

/**
 * UI tone variants for badges and indicators
 * @typedef {'critical'|'high'|'medium'|'low'|'success'|'warning'|'danger'|'info'|'neutral'} Tone
 */

/**
 * Investigation states
 * @typedef {'NEW'|'ANALYZING'|'NEEDS_REVIEW'|'IN_PROGRESS'|'AWAITING_HUMAN'|'RIGGS_REVIEW'|'CLOSED'|'RESOLVED'} InvestigationStatus
 */

/**
 * Alert states
 * @typedef {'new'|'in_progress'|'resolved'|'closed'|'escalated'} AlertStatus
 */

/**
 * Disposition types for investigations
 * @typedef {'MALICIOUS'|'SUSPICIOUS'|'BENIGN'|'TRUE_POSITIVE'|'FALSE_POSITIVE'|'INCONCLUSIVE'} DispositionType
 */

/**
 * Priority levels
 * @typedef {'P1'|'P2'|'P3'|'P4'} PriorityLevel
 */

/**
 * Confidence levels
 * @typedef {'low'|'medium'|'high'} ConfidenceLevel
 */

/**
 * Attribution source types
 * @typedef {'human'|'automation'|'riggs'|'system'} AttributionSource
 */

/**
 * Attribution information for actions and decisions
 * @typedef {Object} Attribution
 * @property {AttributionSource} source - Who/what performed the action
 * @property {string} [userId] - User ID if human
 * @property {string} [username] - Username if human
 * @property {string} [playbookId] - Playbook ID if automation
 * @property {string} [playbookName] - Playbook name if automation
 * @property {number} [confidence] - Confidence score (0-1) if AI
 * @property {string} [rationale] - Brief explanation if AI
 * @property {Date} timestamp - When the action occurred
 */

/**
 * SLA status information
 * @typedef {Object} SLAInfo
 * @property {'healthy'|'at_risk'|'breached'} status - Current SLA status
 * @property {number} remainingMs - Milliseconds remaining (negative if breached)
 * @property {Date} dueAt - SLA due time
 * @property {string} label - Human-readable label (e.g., "2h 30m remaining")
 */

/**
 * Paginated result wrapper
 * @template T
 * @typedef {Object} PaginatedResult
 * @property {T[]} items - Result items
 * @property {number} total - Total count
 * @property {number} page - Current page (1-indexed)
 * @property {number} pageSize - Items per page
 * @property {boolean} hasMore - Whether more pages exist
 */

/**
 * API error response
 * @typedef {Object} ApiError
 * @property {string} message - Error message
 * @property {string} [code] - Error code
 * @property {Object} [details] - Additional error details
 * @property {number} [status] - HTTP status code
 */

/**
 * Time range for dashboard queries
 * @typedef {'24h'|'7d'|'30d'|'90d'} TimeRange
 */

/**
 * Filter operator types
 * @typedef {'eq'|'ne'|'gt'|'gte'|'lt'|'lte'|'in'|'contains'|'startsWith'} FilterOperator
 */

/**
 * Generic filter definition
 * @typedef {Object} Filter
 * @property {string} field - Field to filter on
 * @property {FilterOperator} operator - Filter operator
 * @property {*} value - Filter value
 */

/**
 * Sort direction
 * @typedef {'asc'|'desc'} SortDirection
 */

/**
 * Sort definition
 * @typedef {Object} Sort
 * @property {string} field - Field to sort by
 * @property {SortDirection} direction - Sort direction
 */

/**
 * Indicator types for IOCs
 * @typedef {'ip'|'domain'|'url'|'hash'|'email'|'username'|'hostname'|'file_path'} IndicatorType
 */

/**
 * Indicator of Compromise
 * @typedef {Object} IOC
 * @property {string} value - The indicator value
 * @property {IndicatorType} type - Type of indicator
 * @property {string} [context] - Additional context
 * @property {Date} [firstSeen] - First seen timestamp
 * @property {Date} [lastSeen] - Last seen timestamp
 * @property {Severity} [severity] - Associated severity
 */

// Export empty object to make this a module
export default {};
