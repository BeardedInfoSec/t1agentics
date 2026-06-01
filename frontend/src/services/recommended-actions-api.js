/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

import { apiClient } from '../utils/api';

const BASE = '/api/v1/recommended-actions';

/**
 * Get all recommended actions for an investigation.
 */
export async function getActions(investigationId, status = null) {
  const params = {};
  if (status) params.status = status;
  const res = await apiClient.get(`${BASE}/investigation/${investigationId}`, { params });
  return res.data;
}

/**
 * Approve a recommended action (triggers execution).
 */
export async function approveAction(actionId) {
  const res = await apiClient.post(`${BASE}/${actionId}/approve`);
  return res.data;
}

/**
 * Dismiss a recommended action.
 */
export async function dismissAction(actionId, reason = null) {
  const res = await apiClient.post(`${BASE}/${actionId}/dismiss`, { reason });
  return res.data;
}

/**
 * Manually trigger recommendation generation for an investigation.
 */
export async function generateActions(investigationId) {
  const res = await apiClient.post(`${BASE}/generate`, { investigation_id: investigationId });
  return res.data;
}

/**
 * Get available one-touch actions for a specific IOC from tenant's connected integrations.
 */
export async function getAvailableActions(iocType, iocValue, investigationId) {
  const res = await apiClient.get(`${BASE}/available`, {
    params: { ioc_type: iocType, ioc_value: iocValue, investigation_id: investigationId },
  });
  return res.data;
}

/**
 * Execute an action instantly (create + approve + execute in one step).
 */
export async function executeInstant({ investigationId, iocType, iocValue, actionType, instanceId }) {
  const res = await apiClient.post(`${BASE}/execute-instant`, {
    investigation_id: investigationId,
    ioc_type: iocType,
    ioc_value: iocValue,
    action_type: actionType,
    instance_id: instanceId,
  });
  return res.data;
}
