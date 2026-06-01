/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Error Boundary Component
 *
 * Catches JavaScript errors anywhere in the child component tree,
 * logs those errors, and displays a fallback UI instead of a blank screen.
 *
 * Usage:
 *   <ErrorBoundary>
 *     <YourComponent />
 *   </ErrorBoundary>
 *
 * Or with custom fallback:
 *   <ErrorBoundary fallback={<CustomErrorUI />}>
 *     <YourComponent />
 *   </ErrorBoundary>
 */

import React, { Component } from 'react';
import { authFetch, API_BASE_URL } from '../utils/api';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render shows the fallback UI
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.setState({ errorInfo });

    // Send error to backend logging endpoint
    try {
      const errorPayload = {
        error: error.toString(),
        componentStack: errorInfo?.componentStack,
        url: window.location.href,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
      };

      authFetch(`${API_BASE_URL}/api/v1/telemetry/frontend-error`, {
        method: 'POST',
        body: JSON.stringify(errorPayload),
      }).catch(() => {
        // Silent fail - don't error while handling errors
      });
    } catch (e) {
      // Silent fail
    }
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    });
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI provided
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default fallback UI
      return (
        <div style={{
          padding: '40px',
          textAlign: 'center',
          background: 'var(--bg-secondary, #1e293b)',
          borderRadius: '12px',
          margin: '20px',
          border: '1px solid var(--border-color, #334155)'
        }}>
          <img
            src="/riggs_error.png"
            alt="Riggs encountered an error"
            style={{ width: '120px', height: 'auto', marginBottom: '16px', filter: 'drop-shadow(0 4px 16px rgba(239, 68, 68, 0.3))' }}
          />
          <h2 style={{
            color: 'var(--text-primary, #f0f6fc)',
            marginBottom: '12px',
            fontSize: '20px'
          }}>
            Something went wrong
          </h2>
          <p style={{
            color: 'var(--text-secondary, #94a3b8)',
            marginBottom: '24px',
            fontSize: '14px'
          }}>
            {this.props.message || 'An unexpected error occurred. Please try again.'}
          </p>

          {process.env.NODE_ENV === 'development' && this.state.error && (
            <details style={{
              marginBottom: '24px',
              textAlign: 'left',
              background: 'rgba(0,0,0,0.3)',
              padding: '16px',
              borderRadius: '8px',
              maxHeight: '200px',
              overflow: 'auto'
            }}>
              <summary style={{
                color: '#ef4444',
                cursor: 'pointer',
                marginBottom: '8px'
              }}>
                Error Details (Development Only)
              </summary>
              <pre style={{
                color: '#fca5a5',
                fontSize: '12px',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}>
                {this.state.error.toString()}
                {this.state.errorInfo && this.state.errorInfo.componentStack}
              </pre>
            </details>
          )}

          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button
              onClick={this.handleRetry}
              style={{
                padding: '10px 20px',
                background: 'linear-gradient(135deg, var(--t1-blue, #3CB371), var(--t1-blue-dark, #2e8b57))',
                border: 'none',
                borderRadius: '8px',
                color: 'white',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500'
              }}
            >
              Try Again
            </button>
            <button
              onClick={() => window.location.reload()}
              style={{
                padding: '10px 20px',
                background: 'rgba(255,255,255,0.1)',
                border: 'none',
                borderRadius: '8px',
                color: 'white',
                cursor: 'pointer',
                fontSize: '14px'
              }}
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

/**
 * Higher-order component to wrap any component with error boundary
 */
export function withErrorBoundary(WrappedComponent, fallback = null, message = null) {
  return function WithErrorBoundaryWrapper(props) {
    return (
      <ErrorBoundary fallback={fallback} message={message}>
        <WrappedComponent {...props} />
      </ErrorBoundary>
    );
  };
}

export default ErrorBoundary;
