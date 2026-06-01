/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import ReactDOM from 'react-dom/client';
import { HelmetProvider } from 'react-helmet-async';
import './index.css';
import App from './App';
import { getCsrfToken } from './utils/api';

// Suppress ResizeObserver loop error - harmless browser warning
const resizeObserverErr = window.onerror;
window.onerror = (message, ...args) => {
  if (message?.includes?.('ResizeObserver loop')) return true;
  return resizeObserverErr?.(message, ...args);
};
window.addEventListener('error', (e) => {
  if (e.message?.includes?.('ResizeObserver loop')) e.stopImmediatePropagation();
});

// Global fetch wrapper to include cookies + CSRF for unsafe requests
// Also intercepts 401 responses to redirect to login on session expiry
const _fetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers || {});
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const csrf = getCsrfToken();
    if (csrf && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', csrf);
    }
  }
  const response = await _fetch(input, {
    ...init,
    headers,
    credentials: init.credentials ?? 'include'
  });

  // On 401, verify session is actually expired before redirecting.
  // A single endpoint 401 (e.g. missing permissions) should NOT redirect —
  // only a genuine session expiry (cookie gone / JWT expired) should.
  if (response.status === 401) {
    const url = typeof input === 'string' ? input : input?.url || '';
    const isAuthEndpoint = url.includes('/login') || url.includes('/users/me') ||
      url.includes('/forgot-password') || url.includes('/reset-password') ||
      url.includes('/register') || url.includes('/platform/elevate');
    if (!isAuthEndpoint && !window.location.pathname.startsWith('/login')) {
      // Verify session is truly expired by probing /users/me with original fetch
      try {
        const probe = await _fetch('/api/v1/users/me', { credentials: 'include' });
        if (probe.status === 401) {
          window.location.href = '/login';
        }
      } catch {
        // Network error — don't redirect
      }
    }
  }

  return response;
};

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <HelmetProvider>
      <App />
    </HelmetProvider>
  </React.StrictMode>
);
