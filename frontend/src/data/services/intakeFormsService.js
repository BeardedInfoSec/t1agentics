/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Intake Forms Service
 *
 * API wrapper for tenant-scoped intake forms. Submissions create alerts that
 * flow through the standard Riggs/triage pipeline.
 */

import { apiClient } from '../apiClient';

const BASE = '/api/v1/intake-forms';

export const intakeFormsService = {
  // ── Admin: form CRUD ──────────────────────────────────────────────────────

  async list({ status, limit = 50, offset = 0 } = {}, signal) {
    const params = { limit, offset };
    if (status) params.status = status;
    return apiClient.get(BASE, { params, signal });
  },

  async get(formId, signal) {
    return apiClient.get(`${BASE}/${formId}`, { signal });
  },

  async create(form, signal) {
    return apiClient.post(BASE, form, { signal });
  },

  async update(formId, updates, signal) {
    return apiClient.put(`${BASE}/${formId}`, updates, { signal });
  },

  async remove(formId, signal) {
    return apiClient.delete(`${BASE}/${formId}`, { signal });
  },

  // ── Submitter: render + submit by slug ────────────────────────────────────

  async getBySlug(slug, signal) {
    return apiClient.get(`${BASE}/by-slug/${encodeURIComponent(slug)}`, { signal });
  },

  async submit(slug, payload, signal) {
    return apiClient.post(
      `${BASE}/by-slug/${encodeURIComponent(slug)}/submit`,
      { payload },
      { signal },
    );
  },

  // ── Submitter: file attachment upload ─────────────────────────────────────

  async uploadAttachment(slug, fieldKey, file, onProgress, signal) {
    // Multipart upload for a single file-type field. Returns
    // { attachment_id, filename, content_type, size_bytes }.
    // Caller stores attachment_id in the form payload under fieldKey.
    const fd = new FormData();
    fd.append('field_key', fieldKey);
    fd.append('file', file);
    return apiClient.post(
      `${BASE}/by-slug/${encodeURIComponent(slug)}/upload`,
      fd,
      {
        signal,
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: onProgress,
      },
    );
  },

  // ── Admin: submission browsing ────────────────────────────────────────────

  async listSubmissions(formId, { status, limit = 50, offset = 0 } = {}, signal) {
    const params = { limit, offset };
    if (status) params.status = status;
    return apiClient.get(`${BASE}/${formId}/submissions`, { params, signal });
  },

  async getSubmission(submissionId, signal) {
    return apiClient.get(`${BASE}/submissions/${submissionId}`, { signal });
  },

  // ── Admin: builtin templates ──────────────────────────────────────────────

  async listTemplates(signal) {
    // GET /templates — returns the slim metadata for all builtin
    // templates (template_id, name, category, field_count, etc.) for
    // the picker UI.
    return apiClient.get(`${BASE}/templates`, { signal });
  },

  async createFromTemplate(templateId, signal) {
    // POST /from-template/:id — creates a draft form in the user's
    // tenant pre-populated with the template. Returns the new form
    // (same shape as create()).
    return apiClient.post(
      `${BASE}/from-template/${encodeURIComponent(templateId)}`,
      {},
      { signal },
    );
  },

  // ── Admin: Riggs form generation ──────────────────────────────────────────

  async generateWithRiggs(description, currentForm, signal) {
    // When `currentForm` is provided, Riggs treats the description as a
    // modification request against that form instead of designing from
    // scratch. Frontend passes the current editor state so users can
    // refine an existing draft via natural language.
    const body = { description };
    if (currentForm) body.current_form = currentForm;
    return apiClient.post(`${BASE}/generate`, body, { signal });
  },
};
