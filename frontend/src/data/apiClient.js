/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * API Client
 *
 * Centralized HTTP client with authentication, error handling,
 * and request/response interceptors.
 */

import { API_BASE_URL, getAuthHeaders } from '../utils/api';

/**
 * @typedef {import('./types/common.types').ApiError} ApiError
 */

/**
 * Custom API error class
 */
export class ApiClientError extends Error {
  constructor(message, status, code, details) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
    this.details = details;
  }

  /**
   * Check if error is an authentication error
   * @returns {boolean}
   */
  isAuthError() {
    return this.status === 401 || this.status === 403;
  }

  /**
   * Check if error is a validation error
   * @returns {boolean}
   */
  isValidationError() {
    return this.status === 400 || this.status === 422;
  }

  /**
   * Check if error is a server error
   * @returns {boolean}
   */
  isServerError() {
    return this.status >= 500;
  }

  /**
   * Check if error is a network error
   * @returns {boolean}
   */
  isNetworkError() {
    return this.status === 0 || !this.status;
  }
}

/**
 * Parse error response
 * @param {Response} response
 * @returns {Promise<ApiClientError>}
 */
async function parseErrorResponse(response) {
  let message = 'An error occurred';
  let code = null;
  let details = null;

  try {
    const data = await response.json();
    message = data.detail || data.message || data.error || message;
    code = data.code;
    details = data.details || data.errors;
  } catch {
    message = response.statusText || message;
  }

  return new ApiClientError(message, response.status, code, details);
}

/**
 * API Client with common HTTP methods
 */
export const apiClient = {
  /**
   * Make a GET request
   * @param {string} endpoint - API endpoint
   * @param {Object} [options] - Request options
   * @param {Object} [options.params] - Query parameters
   * @param {AbortSignal} [options.signal] - Abort signal
   * @returns {Promise<any>}
   */
  async get(endpoint, options = {}) {
    const { params, signal } = options;
    let url = `${API_BASE_URL}${endpoint}`;

    if (params) {
      const searchParams = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          if (Array.isArray(value)) {
            value.forEach(v => searchParams.append(key, v));
          } else {
            searchParams.append(key, value);
          }
        }
      });
      const queryString = searchParams.toString();
      if (queryString) {
        url += `?${queryString}`;
      }
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: getAuthHeaders(),
      credentials: 'include',
      signal
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    return response.json();
  },

  /**
   * Make a POST request
   * @param {string} endpoint - API endpoint
   * @param {Object} [data] - Request body
   * @param {Object} [options] - Request options
   * @param {AbortSignal} [options.signal] - Abort signal
   * @returns {Promise<any>}
   */
  async post(endpoint, data = {}, options = {}) {
    const { signal } = options;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        ...getAuthHeaders(),
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(data),
      signal
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return null;
    }

    return response.json();
  },

  /**
   * Make a PUT request
   * @param {string} endpoint - API endpoint
   * @param {Object} [data] - Request body
   * @param {Object} [options] - Request options
   * @param {AbortSignal} [options.signal] - Abort signal
   * @returns {Promise<any>}
   */
  async put(endpoint, data = {}, options = {}) {
    const { signal } = options;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'PUT',
      headers: {
        ...getAuthHeaders(),
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(data),
      signal
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    if (response.status === 204) {
      return null;
    }

    return response.json();
  },

  /**
   * Make a PATCH request
   * @param {string} endpoint - API endpoint
   * @param {Object} [data] - Request body
   * @param {Object} [options] - Request options
   * @param {AbortSignal} [options.signal] - Abort signal
   * @returns {Promise<any>}
   */
  async patch(endpoint, data = {}, options = {}) {
    const { signal } = options;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'PATCH',
      headers: {
        ...getAuthHeaders(),
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(data),
      signal
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    if (response.status === 204) {
      return null;
    }

    return response.json();
  },

  /**
   * Make a DELETE request
   * @param {string} endpoint - API endpoint
   * @param {Object} [options] - Request options
   * @param {AbortSignal} [options.signal] - Abort signal
   * @returns {Promise<any>}
   */
  async delete(endpoint, options = {}) {
    const { signal } = options;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      credentials: 'include',
      signal
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    if (response.status === 204) {
      return null;
    }

    try {
      return await response.json();
    } catch {
      return null;
    }
  }
};

export default apiClient;
