/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueue Type Definitions
 *
 * JSDoc types for the unified security queue data model.
 * All UI components work with SecurityQueueItem - never raw backend objects.
 */

/**
 * SLA status information for investigations
 * @typedef {Object} SLAInfo
 * @property {'breached'|'at_risk'|'ok'|'met'} status - Current SLA status
 * @property {number} [percent] - Percentage of SLA time used (0-100)
 * @property {number} [remaining] - Minutes remaining before breach
 * @property {number} [threshold] - SLA threshold in minutes
 */

/**
 * Unified Security Queue Item
 *
 * This is the ONE canonical type used throughout the SecurityQueue UI.
 * All alerts and investigations are normalized to this shape.
 *
 * @typedef {Object} SecurityQueueItem
 * @property {string} queue_id - Unique ID for this queue item (e.g., "alert-abc123" or "inv-xyz789")
 * @property {'alert'|'investigation'} item_type - Determines rendering mode
 *
 * @property {string} [alert_id] - Alert ID (present for alerts and investigations with source alert)
 * @property {string} [investigation_id] - Investigation ID (present for investigations only)
 *
 * @property {string} title - Display title
 * @property {'critical'|'high'|'medium'|'low'} severity - Severity level
 * @property {string} status - Unified status (alert status or investigation state)
 * @property {string} created_at - ISO timestamp
 * @property {string} updated_at - ISO timestamp
 * @property {string} source - Alert source (e.g., "webhook", "email")
 *
 * @property {string} [disposition] - Investigation verdict (MALICIOUS, SUSPICIOUS, BENIGN, etc.)
 * @property {'P1'|'P2'|'P3'|'P4'} [priority] - Investigation priority
 * @property {string} [owner] - Assigned analyst
 * @property {SLAInfo} [sla] - SLA tracking info
 * @property {string} [executive_summary] - Investigation summary
 *
 * @property {string} [enrichment_status] - Alert enrichment status
 * @property {number} [ai_confidence] - AI confidence score (0-100)
 * @property {string} [ai_verdict] - AI verdict
 *
 * @property {number} [correlation_count] - Number of correlated alerts/investigations
 * @property {string} [correlation_group] - Correlation group name or ID
 * @property {number} [correlation_score] - Correlation score (0-100)
 *
 * @property {Object} [alert_context] - Full alert object (for expanded view drill-down)
 * @property {Object} [investigation_context] - Full investigation object (for expanded view drill-down)
 */

/**
 * View mode for the security queue
 * @typedef {'all'|'alerts'|'investigations'} ViewMode
 */

/**
 * Filter state for the security queue
 * @typedef {Object} QueueFilters
 * @property {ViewMode} viewMode - Current view mode
 * @property {string} statusFilter - Status/state filter value
 * @property {string} severityFilter - Severity filter value
 * @property {string} dispositionFilter - Disposition filter value (investigations only)
 * @property {string} priorityFilter - Priority filter value (investigations only)
 * @property {string} slaFilter - SLA status filter value (investigations only)
 * @property {string} sourceFilter - Source filter value (alerts only)
 * @property {string} timeRange - Time range filter value
 * @property {string} searchQuery - Search query string
 */

/**
 * Metrics computed from queue items
 * @typedef {Object} QueueMetrics
 * @property {number} total - Total items in queue
 * @property {number} alerts - Total alerts (no investigation)
 * @property {number} investigations - Total investigations
 * @property {number} critical - Critical severity items
 * @property {number} needsReview - Items needing human review
 * @property {number} breached - SLA breached items
 * @property {number} atRisk - SLA at risk items
 * @property {number} resolvedToday - Items resolved/closed today
 */

/**
 * Column configuration for the queue table
 * @typedef {Object} ColumnConfig
 * @property {string} key - Column key (matches SecurityQueueItem property)
 * @property {string} label - Display label
 * @property {('alert'|'investigation')[]} appliesTo - Which item types this column applies to
 * @property {boolean} [sortable] - Whether column is sortable
 * @property {number} [width] - Optional fixed width
 */

/**
 * Filter configuration
 * @typedef {Object} FilterConfig
 * @property {string} key - Filter key
 * @property {string} label - Display label
 * @property {('alert'|'investigation')[]} appliesTo - Which view modes show this filter
 * @property {Array<{value: string, label: string}>} options - Filter options
 */

export default {};
