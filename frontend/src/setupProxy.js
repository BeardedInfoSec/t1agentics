/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  // Use environment variable or fallback to localhost
  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://127.0.0.1:8000';

  // Proxy all /api requests to the backend
  app.use(
    '/api',
    createProxyMiddleware({
      target: backendUrl,
      changeOrigin: true,
      onProxyReq: (proxyReq, req, res) => {
        console.log(`[Proxy] ${req.method} ${req.url} -> http://localhost:8000${req.url}`);
      },
      onError: (err, req, res) => {
        console.error('[Proxy Error]', err.message);
        res.status(502).json({
          error: 'Proxy Error',
          message: 'Could not connect to backend API',
          details: err.message
        });
      }
    })
  );

  // Proxy /v1 requests to backend (EDL delivery endpoints for firewalls)
  app.use(
    '/v1',
    createProxyMiddleware({
      target: backendUrl,
      changeOrigin: true,
      onProxyReq: (proxyReq, req, res) => {
        console.log(`[Proxy] ${req.method} ${req.url} -> http://localhost:8000${req.url}`);
      },
      onError: (err, req, res) => {
        console.error('[Proxy Error]', err.message);
        res.status(502).json({
          error: 'Proxy Error',
          message: 'Could not connect to backend API',
          details: err.message
        });
      }
    })
  );
};
