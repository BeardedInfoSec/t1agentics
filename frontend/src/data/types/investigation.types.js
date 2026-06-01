/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Investigation Type Definitions
 *
 * Types for investigation data throughout the application.
 */

/**
 * Investigation ViewModel - normalized investigation data for UI consumption
 * @typedef {Object} InvestigationVM
 * @property {string} id - Unique investigation identifier
 * @property {string} title - Investigation title
 * @property {string} [description] - Investigation description
 * @property {import('./common.types').InvestigationStatus} status - Current status
 * @property {import('./common.types').PriorityLevel} priority - Priority level
 * @property {import('./common.types').Severity} severity - Overall severity
 * @property {import('./common.types').DispositionType|null} disposition - Final disposition
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 * @property {import('./common.types').SLAInfo|null} sla - SLA information
 * @property {string|null} owner - Assigned owner
 * @property {string[]} alertIds - Linked alert IDs
 * @property {number} alertCount - Number of linked alerts
 * @property {TechnicalFinding[]} findings - Technical findings
 * @property {TimelineEvent[]} timeline - Timeline events
 * @property {RecommendedAction[]} recommendations - Recommended actions
 * @property {import('./common.types').IOC[]} iocs - Extracted IOCs
 * @property {InvestigationNote[]} notes - Investigation notes
 * @property {Object} metadata - Additional metadata
 * @property {import('./common.types').Attribution|null} lastAction - Last action attribution
 */

/**
 * Technical finding from investigation
 * @typedef {Object} TechnicalFinding
 * @property {string} id - Finding identifier
 * @property {string} title - Finding title
 * @property {string} description - Finding description
 * @property {import('./common.types').Severity} severity - Finding severity
 * @property {string[]} mitreTactics - MITRE ATT&CK tactics
 * @property {string[]} mitreTechniques - MITRE ATT&CK techniques
 * @property {Object} evidence - Supporting evidence
 * @property {import('./common.types').ConfidenceLevel} confidence - Confidence level
 * @property {import('./common.types').Attribution} attribution - Who identified this
 */

/**
 * Timeline event
 * @typedef {Object} TimelineEvent
 * @property {string} id - Event identifier
 * @property {Date} timestamp - Event timestamp
 * @property {string} title - Event title
 * @property {string} [description] - Event description
 * @property {'alert'|'action'|'finding'|'note'|'status_change'|'enrichment'} type - Event type
 * @property {import('./common.types').Severity} [severity] - Event severity
 * @property {Object} [data] - Additional event data
 * @property {import('./common.types').Attribution} attribution - Event source
 */

/**
 * Recommended action
 * @typedef {Object} RecommendedAction
 * @property {string} id - Action identifier
 * @property {string} title - Action title
 * @property {string} description - Action description
 * @property {import('./common.types').PriorityLevel} priority - Action priority
 * @property {string} rationale - Why this is recommended
 * @property {'pending'|'accepted'|'rejected'|'completed'} status - Action status
 * @property {import('./common.types').ConfidenceLevel} confidence - AI confidence
 * @property {string} [playbookId] - Associated playbook if applicable
 * @property {Object} [parameters] - Action parameters
 */

/**
 * Investigation note
 * @typedef {Object} InvestigationNote
 * @property {string} id - Note identifier
 * @property {string} content - Note content (supports markdown)
 * @property {'analyst'|'system'|'ai'} type - Note type
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} [updatedAt] - Update timestamp
 * @property {import('./common.types').Attribution} attribution - Note author
 * @property {string|null} parentId - Parent note ID for threading
 * @property {Object[]} [attachments] - File attachments
 */

/**
 * Investigation list filters
 * @typedef {Object} InvestigationFilters
 * @property {import('./common.types').InvestigationStatus[]} [statuses] - Filter by statuses
 * @property {import('./common.types').PriorityLevel[]} [priorities] - Filter by priorities
 * @property {import('./common.types').Severity[]} [severities] - Filter by severities
 * @property {string} [search] - Text search
 * @property {string} [owner] - Filter by owner
 * @property {Date} [createdAfter] - Created after date
 * @property {Date} [createdBefore] - Created before date
 * @property {boolean} [needsReview] - Needs human review
 * @property {string} [slaStatus] - SLA status filter
 */

/**
 * Investigation metrics summary
 * @typedef {Object} InvestigationMetrics
 * @property {number} total - Total investigations
 * @property {number} open - Open investigations
 * @property {number} needsReview - Awaiting review
 * @property {number} inProgress - In progress
 * @property {number} closed - Closed investigations
 * @property {number} breached - SLA breached
 * @property {number} atRisk - SLA at risk
 * @property {number} avgResolutionMs - Average resolution time (ms)
 */

/**
 * Investigation update payload
 * @typedef {Object} InvestigationUpdate
 * @property {import('./common.types').InvestigationStatus} [status] - New status
 * @property {import('./common.types').PriorityLevel} [priority] - New priority
 * @property {import('./common.types').DispositionType} [disposition] - Set disposition
 * @property {string} [owner] - New owner
 * @property {string} [note] - Note to add
 */

export default {};
