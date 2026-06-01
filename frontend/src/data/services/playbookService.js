/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Playbook Service
 *
 * API service for playbook/SOAR operations. All methods return normalized ViewModels.
 */

import { apiClient } from '../apiClient';
import {
  toPlaybookVM,
  toPlaybookVMList,
  toPlaybookExecution,
  toPlaybookExecutionList,
  fromPlaybookVM
} from '../adapters/playbookAdapter';

/**
 * @typedef {import('../types/playbook.types').PlaybookVM} PlaybookVM
 * @typedef {import('../types/playbook.types').PlaybookExecution} PlaybookExecution
 * @typedef {import('../types/playbook.types').PlaybookFilters} PlaybookFilters
 * @typedef {import('../types/playbook.types').PlaybookTemplate} PlaybookTemplate
 * @typedef {import('../types/common.types').PaginatedResult} PaginatedResult
 */

const BASE = '/api/v1/playbooks';
const SOAR_BASE = '/api/v1/soar';

export const playbookService = {
  /**
   * Fetch paginated playbooks with filters
   * @param {PlaybookFilters} [filters={}] - Filter criteria
   * @param {Object} [pagination={}] - Pagination options
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PaginatedResult<PlaybookVM>>}
   */
  async list(filters = {}, pagination = {}, signal) {
    const {
      page = 1,
      pageSize = 25,
      sortBy = 'updated_at',
      sortDir = 'desc'
    } = pagination;

    const params = {
      page,
      page_size: pageSize,
      sort_by: sortBy,
      sort_dir: sortDir,
      ...mapFiltersToParams(filters)
    };

    const response = await apiClient.get(BASE, { params, signal });

    return {
      items: toPlaybookVMList(response.items || response.playbooks || response),
      total: response.total || response.count || 0,
      page,
      pageSize,
      hasMore: (response.total || 0) > page * pageSize
    };
  },

  /**
   * Fetch a single playbook by ID
   * @param {string} id - Playbook ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookVM>}
   */
  async get(id, signal) {
    const response = await apiClient.get(`${BASE}/${id}`, { signal });
    return toPlaybookVM(response);
  },

  /**
   * Create a new playbook
   * @param {Object} data - Playbook data
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookVM>}
   */
  async create(data, signal) {
    const response = await apiClient.post(BASE, fromPlaybookVM(data), { signal });
    return toPlaybookVM(response);
  },

  /**
   * Update a playbook
   * @param {string} id - Playbook ID
   * @param {Partial<PlaybookVM>} updates - Update data
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookVM>}
   */
  async update(id, updates, signal) {
    const response = await apiClient.put(`${BASE}/${id}`, fromPlaybookVM(updates), { signal });
    return toPlaybookVM(response);
  },

  /**
   * Delete a playbook
   * @param {string} id - Playbook ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<void>}
   */
  async delete(id, signal) {
    await apiClient.delete(`${BASE}/${id}`, { signal });
  },

  /**
   * Execute a playbook
   * @param {string} id - Playbook ID
   * @param {Object} [context={}] - Execution context
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookExecution>}
   */
  async execute(id, context = {}, signal) {
    const response = await apiClient.post(`${SOAR_BASE}/execute`, {
      playbook_id: id,
      context
    }, { signal });
    return toPlaybookExecution(response);
  },

  /**
   * Get playbook execution status
   * @param {string} executionId - Execution ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookExecution>}
   */
  async getExecution(executionId, signal) {
    const response = await apiClient.get(`${SOAR_BASE}/executions/${executionId}`, { signal });
    return toPlaybookExecution(response);
  },

  /**
   * List executions for a playbook
   * @param {string} playbookId - Playbook ID
   * @param {Object} [pagination={}] - Pagination options
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PaginatedResult<PlaybookExecution>>}
   */
  async listExecutions(playbookId, pagination = {}, signal) {
    const { page = 1, pageSize = 25 } = pagination;

    const response = await apiClient.get(`${BASE}/${playbookId}/executions`, {
      params: { page, page_size: pageSize },
      signal
    });

    return {
      items: toPlaybookExecutionList(response.items || response.executions || response),
      total: response.total || 0,
      page,
      pageSize,
      hasMore: (response.total || 0) > page * pageSize
    };
  },

  /**
   * Cancel a running execution
   * @param {string} executionId - Execution ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookExecution>}
   */
  async cancelExecution(executionId, signal) {
    const response = await apiClient.post(
      `${SOAR_BASE}/executions/${executionId}/cancel`,
      {},
      { signal }
    );
    return toPlaybookExecution(response);
  },

  /**
   * Approve a pending approval in execution
   * @param {string} executionId - Execution ID
   * @param {string} nodeId - Node ID awaiting approval
   * @param {boolean} approved - Approval decision
   * @param {string} [comment] - Optional comment
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookExecution>}
   */
  async approveNode(executionId, nodeId, approved, comment, signal) {
    const response = await apiClient.post(
      `${SOAR_BASE}/executions/${executionId}/approve`,
      { node_id: nodeId, approved, comment },
      { signal }
    );
    return toPlaybookExecution(response);
  },

  /**
   * Get playbook version history
   * @param {string} id - Playbook ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<{versionId: string, versionNumber: number, createdAt: Date, createdBy: string, changeSummary: string}[]>}
   */
  async getVersions(id, signal) {
    const response = await apiClient.get(`${BASE}/${id}/versions`, { signal });
    return (response.versions || response || []).map(v => ({
      versionId: v.version_id || v.id,
      versionNumber: v.version_number || v.version,
      createdAt: new Date(v.created_at),
      createdBy: v.created_by,
      changeSummary: v.change_summary || v.summary
    }));
  },

  /**
   * Restore a playbook version
   * @param {string} playbookId - Playbook ID
   * @param {string} versionId - Version ID to restore
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookVM>}
   */
  async restoreVersion(playbookId, versionId, signal) {
    const response = await apiClient.post(
      `${BASE}/${playbookId}/versions/${versionId}/restore`,
      {},
      { signal }
    );
    return toPlaybookVM(response);
  },

  /**
   * Get playbook templates
   * @param {string} [category] - Filter by category
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookTemplate[]>}
   */
  async getTemplates(category, signal) {
    const params = category ? { category } : {};
    const response = await apiClient.get(`${BASE}/templates`, { params, signal });
    return (response.templates || response || []).map(t => ({
      id: t.id || t.template_id,
      name: t.name,
      description: t.description,
      category: t.category,
      tags: t.tags || [],
      thumbnail: t.thumbnail,
      nodes: t.nodes || t.canvas_data?.nodes || [],
      edges: t.edges || t.canvas_data?.edges || []
    }));
  },

  /**
   * Create playbook from template
   * @param {string} templateId - Template ID
   * @param {string} name - New playbook name
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PlaybookVM>}
   */
  async createFromTemplate(templateId, name, signal) {
    const response = await apiClient.post(`${BASE}/from-template`, {
      template_id: templateId,
      name
    }, { signal });
    return toPlaybookVM(response);
  },

  /**
   * Validate playbook configuration
   * @param {Object} playbookData - Playbook data to validate
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<import('../types/playbook.types').PlaybookValidity>}
   */
  async validate(playbookData, signal) {
    const response = await apiClient.post(`${BASE}/validate`, playbookData, { signal });
    return {
      status: response.status || (response.valid ? 'valid' : 'has_errors'),
      errors: response.errors || [],
      warnings: response.warnings || [],
      missingInputs: response.missing_inputs || [],
      canDeploy: response.can_deploy || response.valid || false
    };
  }
};

/**
 * Map PlaybookFilters to API query parameters
 * @param {PlaybookFilters} filters
 * @returns {Object}
 */
function mapFiltersToParams(filters) {
  const params = {};

  if (filters.statuses?.length) params.statuses = filters.statuses;
  if (filters.search) params.search = filters.search;
  if (filters.tags?.length) params.tags = filters.tags;
  if (filters.createdBy) params.created_by = filters.createdBy;
  if (filters.triggerType) params.trigger_type = filters.triggerType;

  return params;
}

export default playbookService;
