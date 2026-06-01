/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Playbook Type Definitions
 *
 * Types for playbook/SOAR data throughout the application.
 */

/**
 * Playbook ViewModel - normalized playbook data for UI consumption
 * @typedef {Object} PlaybookVM
 * @property {string} id - Unique playbook identifier
 * @property {string} name - Playbook name
 * @property {string} [description] - Playbook description
 * @property {'draft'|'active'|'disabled'|'archived'} status - Playbook status
 * @property {string} version - Version string
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 * @property {string} createdBy - Creator username
 * @property {string} [updatedBy] - Last updater username
 * @property {PlaybookTrigger} trigger - Trigger configuration
 * @property {PlaybookNode[]} nodes - Workflow nodes
 * @property {PlaybookEdge[]} edges - Node connections
 * @property {PlaybookStats} stats - Execution statistics
 * @property {PlaybookValidity} validity - Validity status
 * @property {string[]} tags - Playbook tags
 * @property {Object} metadata - Additional metadata
 */

/**
 * Playbook trigger configuration
 * @typedef {Object} PlaybookTrigger
 * @property {'manual'|'alert'|'schedule'|'webhook'|'investigation'} type - Trigger type
 * @property {Object} [conditions] - Trigger conditions (for alert trigger)
 * @property {string} [schedule] - Cron expression (for schedule trigger)
 * @property {string} [webhookId] - Webhook ID (for webhook trigger)
 */

/**
 * Playbook workflow node
 * @typedef {Object} PlaybookNode
 * @property {string} id - Node identifier
 * @property {PlaybookNodeType} type - Node type
 * @property {string} label - Display label
 * @property {Object} position - Canvas position {x, y}
 * @property {Object} config - Node configuration
 * @property {boolean} [isConfigured] - Whether node is fully configured
 * @property {string[]} [errors] - Configuration errors
 */

/**
 * Playbook node types
 * @typedef {'trigger'|'action'|'condition'|'python'|'enrich'|'notify'|'create_ticket'|'case_update'|'approval'|'delay'|'loop'|'parallel'|'merge'|'edl_add'|'edl_remove'|'webhook_call'|'riggs_analyze'} PlaybookNodeType
 */

/**
 * Playbook edge (connection between nodes)
 * @typedef {Object} PlaybookEdge
 * @property {string} id - Edge identifier
 * @property {string} source - Source node ID
 * @property {string} target - Target node ID
 * @property {string} [sourceHandle] - Source handle (for condition nodes)
 * @property {string} [label] - Edge label
 */

/**
 * Playbook execution statistics
 * @typedef {Object} PlaybookStats
 * @property {number} totalExecutions - Total execution count
 * @property {number} successfulExecutions - Successful count
 * @property {number} failedExecutions - Failed count
 * @property {number} avgDurationMs - Average duration in ms
 * @property {Date|null} lastExecutedAt - Last execution timestamp
 * @property {number} activeExecutions - Currently running count
 */

/**
 * Playbook validity status
 * @typedef {Object} PlaybookValidity
 * @property {'valid'|'needs_inputs'|'has_errors'|'requires_approval'} status - Overall status
 * @property {string[]} errors - Validation errors
 * @property {string[]} warnings - Validation warnings
 * @property {string[]} missingInputs - Missing required inputs
 * @property {boolean} canDeploy - Whether playbook can be deployed
 */

/**
 * Playbook execution record
 * @typedef {Object} PlaybookExecution
 * @property {string} id - Execution identifier
 * @property {string} playbookId - Playbook identifier
 * @property {string} playbookName - Playbook name at execution time
 * @property {'queued'|'running'|'completed'|'failed'|'cancelled'|'waiting_approval'|'waiting_delay'} status - Execution status
 * @property {Date} startedAt - Start timestamp
 * @property {Date|null} completedAt - Completion timestamp
 * @property {number|null} durationMs - Execution duration
 * @property {string} triggeredBy - Who/what triggered
 * @property {Object} triggerContext - Trigger context data
 * @property {NodeExecutionResult[]} nodeResults - Per-node results
 * @property {Object} outputs - Final outputs
 * @property {string|null} error - Error message if failed
 */

/**
 * Node execution result
 * @typedef {Object} NodeExecutionResult
 * @property {string} nodeId - Node identifier
 * @property {PlaybookNodeType} nodeType - Node type
 * @property {'pending'|'running'|'completed'|'failed'|'skipped'} status - Node status
 * @property {Date|null} startedAt - Start timestamp
 * @property {Date|null} completedAt - Completion timestamp
 * @property {number|null} durationMs - Node duration
 * @property {Object} inputs - Resolved inputs
 * @property {Object} outputs - Node outputs
 * @property {string|null} error - Error message if failed
 * @property {Object} [meta] - Additional metadata (cached, rate_limited, etc.)
 */

/**
 * Playbook template
 * @typedef {Object} PlaybookTemplate
 * @property {string} id - Template identifier
 * @property {string} name - Template name
 * @property {string} description - Template description
 * @property {string} category - Template category
 * @property {string[]} tags - Template tags
 * @property {Object} thumbnail - Thumbnail/preview
 * @property {PlaybookNode[]} nodes - Template nodes
 * @property {PlaybookEdge[]} edges - Template edges
 */

/**
 * Playbook list filters
 * @typedef {Object} PlaybookFilters
 * @property {string[]} [statuses] - Filter by statuses
 * @property {string} [search] - Text search
 * @property {string[]} [tags] - Filter by tags
 * @property {string} [createdBy] - Filter by creator
 * @property {string} [triggerType] - Filter by trigger type
 */

export default {};
