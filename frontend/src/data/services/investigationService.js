/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Investigation Service
 *
 * API service for investigation operations. All methods return normalized ViewModels.
 */

import { apiClient } from '../apiClient';
import {
  toInvestigationVM,
  toInvestigationVMList,
  toInvestigationMetrics,
  fromInvestigationVM
} from '../adapters/investigationAdapter';

/**
 * @typedef {import('../types/investigation.types').InvestigationVM} InvestigationVM
 * @typedef {import('../types/investigation.types').InvestigationFilters} InvestigationFilters
 * @typedef {import('../types/investigation.types').InvestigationMetrics} InvestigationMetrics
 * @typedef {import('../types/investigation.types').InvestigationUpdate} InvestigationUpdate
 * @typedef {import('../types/common.types').PaginatedResult} PaginatedResult
 */

const BASE = '/api/v1/investigations';

export const investigationService = {
  /**
   * Fetch paginated investigations with filters
   * @param {InvestigationFilters} [filters={}] - Filter criteria
   * @param {Object} [pagination={}] - Pagination options
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PaginatedResult<InvestigationVM>>}
   */
  async list(filters = {}, pagination = {}, signal) {
    const {
      page = 1,
      pageSize = 25,
      sortBy = 'created_at',
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
      items: toInvestigationVMList(response.items || response.investigations || response),
      total: response.total || response.count || 0,
      page,
      pageSize,
      hasMore: (response.total || 0) > page * pageSize
    };
  },

  /**
   * Fetch a single investigation by ID
   * @param {string} id - Investigation ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async get(id, signal) {
    const response = await apiClient.get(`${BASE}/${id}`, { signal });
    return toInvestigationVM(response);
  },

  /**
   * Create a new investigation
   * @param {Object} data - Investigation data
   * @param {string} data.title - Investigation title
   * @param {string} [data.description] - Description
   * @param {string[]} [data.alertIds] - Alert IDs to link
   * @param {string} [data.priority] - Priority level
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async create(data, signal) {
    const response = await apiClient.post(BASE, {
      title: data.title,
      description: data.description,
      alert_ids: data.alertIds,
      priority: data.priority
    }, { signal });
    return toInvestigationVM(response);
  },

  /**
   * Update an investigation
   * @param {string} id - Investigation ID
   * @param {InvestigationUpdate} updates - Update data
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async update(id, updates, signal) {
    const response = await apiClient.patch(
      `${BASE}/${id}`,
      fromInvestigationVM(updates),
      { signal }
    );
    return toInvestigationVM(response);
  },

  /**
   * Add note to investigation
   * @param {string} id - Investigation ID
   * @param {string} content - Note content
   * @param {string} [parentId] - Parent note ID for threading
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async addNote(id, content, parentId, signal) {
    const response = await apiClient.post(`${BASE}/${id}/notes`, {
      content,
      parent_id: parentId
    }, { signal });
    return toInvestigationVM(response);
  },

  /**
   * Link alerts to investigation
   * @param {string} id - Investigation ID
   * @param {string[]} alertIds - Alert IDs to link
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async linkAlerts(id, alertIds, signal) {
    const response = await apiClient.post(`${BASE}/${id}/alerts`, {
      alert_ids: alertIds
    }, { signal });
    return toInvestigationVM(response);
  },

  /**
   * Run AI analysis on investigation
   * @param {string} id - Investigation ID
   * @param {Object} [options] - Analysis options
   * @param {boolean} [options.forceRerun] - Force re-analysis
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async analyze(id, options = {}, signal) {
    const response = await apiClient.post(`${BASE}/${id}/analyze`, options, { signal });
    return toInvestigationVM(response);
  },

  /**
   * Get investigation timeline
   * @param {string} id - Investigation ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<import('../types/investigation.types').TimelineEvent[]>}
   */
  async getTimeline(id, signal) {
    const response = await apiClient.get(`${BASE}/${id}/timeline`, { signal });
    const investigation = toInvestigationVM({ timeline: response.events || response });
    return investigation.timeline;
  },

  /**
   * Get investigation metrics
   * @param {Object} [params] - Query parameters
   * @param {string} [params.timeRange] - Time range
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationMetrics>}
   */
  async getMetrics(params = {}, signal) {
    const response = await apiClient.get(`${BASE}/metrics`, { params, signal });
    return toInvestigationMetrics(response);
  },

  /**
   * Accept a recommended action
   * @param {string} investigationId - Investigation ID
   * @param {string} actionId - Recommendation ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async acceptRecommendation(investigationId, actionId, signal) {
    const response = await apiClient.post(
      `${BASE}/${investigationId}/recommendations/${actionId}/accept`,
      {},
      { signal }
    );
    return toInvestigationVM(response);
  },

  /**
   * Reject a recommended action
   * @param {string} investigationId - Investigation ID
   * @param {string} actionId - Recommendation ID
   * @param {string} [reason] - Rejection reason
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<InvestigationVM>}
   */
  async rejectRecommendation(investigationId, actionId, reason, signal) {
    const response = await apiClient.post(
      `${BASE}/${investigationId}/recommendations/${actionId}/reject`,
      { reason },
      { signal }
    );
    return toInvestigationVM(response);
  }
};

/**
 * Map InvestigationFilters to API query parameters
 * @param {InvestigationFilters} filters
 * @returns {Object}
 */
function mapFiltersToParams(filters) {
  const params = {};

  if (filters.statuses?.length) params.statuses = filters.statuses;
  if (filters.priorities?.length) params.priorities = filters.priorities;
  if (filters.severities?.length) params.severities = filters.severities;
  if (filters.search) params.search = filters.search;
  if (filters.owner) params.owner = filters.owner;
  if (filters.createdAfter) params.created_after = filters.createdAfter.toISOString();
  if (filters.createdBefore) params.created_before = filters.createdBefore.toISOString();
  if (filters.needsReview !== undefined) params.needs_review = filters.needsReview;
  if (filters.slaStatus) params.sla_status = filters.slaStatus;

  return params;
}

export default investigationService;
