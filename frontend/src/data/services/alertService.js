/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Alert Service
 *
 * API service for alert operations. All methods return normalized ViewModels.
 */

import { apiClient } from '../apiClient';
import { toAlertVM, toAlertVMList, toAlertMetrics, fromAlertVM } from '../adapters/alertAdapter';

/**
 * @typedef {import('../types/alert.types').AlertVM} AlertVM
 * @typedef {import('../types/alert.types').AlertFilters} AlertFilters
 * @typedef {import('../types/alert.types').AlertMetrics} AlertMetrics
 * @typedef {import('../types/alert.types').AlertUpdate} AlertUpdate
 * @typedef {import('../types/alert.types').BulkAlertResult} BulkAlertResult
 * @typedef {import('../types/common.types').PaginatedResult} PaginatedResult
 */

const BASE = '/api/v1/alerts';

export const alertService = {
  /**
   * Fetch paginated alerts with filters
   * @param {AlertFilters} [filters={}] - Filter criteria
   * @param {Object} [pagination={}] - Pagination options
   * @param {number} [pagination.page=1] - Page number (1-indexed)
   * @param {number} [pagination.pageSize=25] - Items per page
   * @param {string} [pagination.sortBy='created_at'] - Sort field
   * @param {string} [pagination.sortDir='desc'] - Sort direction
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<PaginatedResult<AlertVM>>}
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
      items: toAlertVMList(response.items || response.alerts || response),
      total: response.total || response.count || 0,
      page,
      pageSize,
      hasMore: (response.total || 0) > page * pageSize
    };
  },

  /**
   * Fetch a single alert by ID
   * @param {string} id - Alert ID
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<AlertVM>}
   */
  async get(id, signal) {
    const response = await apiClient.get(`${BASE}/${id}`, { signal });
    return toAlertVM(response);
  },

  /**
   * Update an alert
   * @param {string} id - Alert ID
   * @param {AlertUpdate} updates - Update data
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<AlertVM>}
   */
  async update(id, updates, signal) {
    const response = await apiClient.patch(`${BASE}/${id}`, fromAlertVM(updates), { signal });
    return toAlertVM(response);
  },

  /**
   * Bulk update alerts
   * @param {string[]} ids - Alert IDs
   * @param {AlertUpdate} updates - Update data
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<BulkAlertResult>}
   */
  async bulkUpdate(ids, updates, signal) {
    const response = await apiClient.post(`${BASE}/bulk`, {
      alert_ids: ids,
      updates: fromAlertVM(updates)
    }, { signal });

    return {
      success: response.success || response.updated || 0,
      failed: response.failed || 0,
      errors: response.errors || []
    };
  },

  /**
   * Escalate alert to investigation
   * @param {string} id - Alert ID
   * @param {Object} [options] - Escalation options
   * @param {string} [options.reason] - Escalation reason
   * @param {string} [options.priority] - Investigation priority
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<{alertId: string, investigationId: string}>}
   */
  async escalate(id, options = {}, signal) {
    const response = await apiClient.post(`${BASE}/${id}/escalate`, options, { signal });
    return {
      alertId: id,
      investigationId: response.investigation_id
    };
  },

  /**
   * Add note to alert
   * @param {string} id - Alert ID
   * @param {string} content - Note content
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<AlertVM>}
   */
  async addNote(id, content, signal) {
    const response = await apiClient.post(`${BASE}/${id}/notes`, { content }, { signal });
    return toAlertVM(response);
  },

  /**
   * Get alert metrics/statistics
   * @param {Object} [params] - Query parameters
   * @param {string} [params.timeRange] - Time range (24h, 7d, 30d, 90d)
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<AlertMetrics>}
   */
  async getMetrics(params = {}, signal) {
    const response = await apiClient.get(`${BASE}/metrics`, { params, signal });
    return toAlertMetrics(response);
  },

  /**
   * Get alert trend data
   * @param {Object} [params] - Query parameters
   * @param {string} [params.timeRange] - Time range
   * @param {string} [params.interval] - Data interval (hour, day)
   * @param {AbortSignal} [signal] - Abort signal
   * @returns {Promise<{timestamp: Date, count: number}[]>}
   */
  async getTrends(params = {}, signal) {
    const response = await apiClient.get(`${BASE}/trends`, { params, signal });
    return (response.data || response || []).map(point => ({
      timestamp: new Date(point.timestamp || point.time),
      count: point.count || point.value || 0
    }));
  }
};

/**
 * Map AlertFilters to API query parameters
 * @param {AlertFilters} filters
 * @returns {Object}
 */
function mapFiltersToParams(filters) {
  const params = {};

  if (filters.severities?.length) params.severities = filters.severities;
  if (filters.statuses?.length) params.statuses = filters.statuses;
  if (filters.sources?.length) params.sources = filters.sources;
  if (filters.search) params.search = filters.search;
  if (filters.assignee) params.assignee = filters.assignee;
  if (filters.createdAfter) params.created_after = filters.createdAfter.toISOString();
  if (filters.createdBefore) params.created_before = filters.createdBefore.toISOString();
  if (filters.hasInvestigation !== undefined) params.has_investigation = filters.hasInvestigation;
  if (filters.slaStatus) params.sla_status = filters.slaStatus;

  return params;
}

export default alertService;
