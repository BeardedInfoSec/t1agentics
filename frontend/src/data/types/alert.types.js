/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Alert Type Definitions
 *
 * Types for alert data throughout the application.
 */

/**
 * Alert ViewModel - normalized alert data for UI consumption
 * @typedef {Object} AlertVM
 * @property {string} id - Unique alert identifier
 * @property {string} title - Alert title
 * @property {string} [description] - Alert description
 * @property {import('./common.types').Severity} severity - Alert severity
 * @property {import('./common.types').AlertStatus} status - Current status
 * @property {string} source - Alert source system
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 * @property {import('./common.types').SLAInfo|null} sla - SLA information
 * @property {import('./common.types').IOC[]} iocs - Extracted indicators
 * @property {string|null} investigationId - Linked investigation ID
 * @property {string|null} assignee - Assigned user
 * @property {Object} metadata - Additional metadata
 * @property {Object} rawLog - Original raw log data
 * @property {import('./common.types').Attribution|null} lastAction - Last action attribution
 */

/**
 * Alert list filters
 * @typedef {Object} AlertFilters
 * @property {import('./common.types').Severity[]} [severities] - Filter by severities
 * @property {import('./common.types').AlertStatus[]} [statuses] - Filter by statuses
 * @property {string[]} [sources] - Filter by sources
 * @property {string} [search] - Text search
 * @property {string} [assignee] - Filter by assignee
 * @property {Date} [createdAfter] - Created after date
 * @property {Date} [createdBefore] - Created before date
 * @property {boolean} [hasInvestigation] - Has linked investigation
 * @property {string} [slaStatus] - SLA status filter
 */

/**
 * Alert metrics summary
 * @typedef {Object} AlertMetrics
 * @property {number} total - Total alerts
 * @property {number} critical - Critical severity count
 * @property {number} high - High severity count
 * @property {number} medium - Medium severity count
 * @property {number} low - Low severity count
 * @property {number} new - New status count
 * @property {number} inProgress - In progress count
 * @property {number} resolved - Resolved count
 * @property {number} breached - SLA breached count
 * @property {number} atRisk - SLA at risk count
 */

/**
 * Alert update payload
 * @typedef {Object} AlertUpdate
 * @property {import('./common.types').AlertStatus} [status] - New status
 * @property {import('./common.types').Severity} [severity] - New severity
 * @property {string} [assignee] - New assignee
 * @property {string} [note] - Note to add
 */

/**
 * Bulk alert action result
 * @typedef {Object} BulkAlertResult
 * @property {number} success - Successfully updated count
 * @property {number} failed - Failed update count
 * @property {string[]} errors - Error messages
 */

export default {};
