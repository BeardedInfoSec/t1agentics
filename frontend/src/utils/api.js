/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * API utilities for T1 Agentics frontend
 */

import axios from 'axios';

/**
 * Get the API base URL
 * Always use relative URLs so the dev server proxy handles routing
 * This works for both localhost and remote network access
 */
export const getApiBaseUrl = () => {
  // If explicitly configured, use that
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }

  // Always use relative URLs - proxy handles routing to backend
  // This works from any device on the network
  return '';
};

// Export the base URL for easy access
export const API_BASE_URL = getApiBaseUrl();

export const getCookie = (name) => {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
};

export const getCsrfToken = () => getCookie('t1_csrf');

/**
 * Get authentication headers for API requests
 * @returns {Object} Headers object with Content-Type and Authorization
 */
export const getAuthHeaders = (includeContentType = true) => {
  const csrf = getCsrfToken();
  const headers = {
    ...(includeContentType ? { 'Content-Type': 'application/json' } : {})
  };
  if (csrf) {
    headers['X-CSRF-Token'] = csrf;
  }
  return headers;
};

/**
 * Make an authenticated fetch request
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} The fetch response
 */
export const authFetch = async (url, options = {}) => {
  const isFormData = options.body instanceof FormData;
  const includeContentType = !isFormData && !(options.headers && options.headers['Content-Type']);
  const headers = {
    ...getAuthHeaders(includeContentType),
    ...(options.headers || {})
  };

  return fetch(url, {
    ...options,
    headers,
    credentials: 'include'
  });
};

/**
 * Make an authenticated JSON request
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<any>} The parsed JSON response
 */
export const authFetchJson = async (url, options = {}) => {
  const response = await authFetch(url, options);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
};

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true
});

apiClient.interceptors.request.use((config) => {
  const method = (config.method || 'get').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const csrf = getCsrfToken();
    if (csrf) {
      config.headers = config.headers || {};
      config.headers['X-CSRF-Token'] = csrf;
    }
  }
  return config;
});

export default {
  getApiBaseUrl,
  API_BASE_URL,
  getAuthHeaders,
  authFetch,
  authFetchJson,
  getCsrfToken,
  apiClient
};
