/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { API_BASE_URL, getAuthHeaders as baseGetAuthHeaders, authFetch } from '../../utils/api';

// Helper to get auth headers
export const getAuthHeaders = () => baseGetAuthHeaders();

// Helper to get auth header only (without Content-Type)
export const getAuthHeader = () => baseGetAuthHeaders(false);

// Common input style
export const inputStyle = {
  width: '100%',
  padding: '0.75rem',
  background: 'var(--bg-tertiary)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--text-primary)',
  fontSize: '0.875rem'
};

// Common label style
export const labelStyle = {
  display: 'block',
  marginBottom: '0.5rem',
  fontSize: '0.875rem'
};

// Common modal overlay style
export const modalOverlayStyle = {
  position: 'fixed',
  top: 0, left: 0, right: 0, bottom: 0,
  background: 'rgba(0,0,0,0.8)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 1000
};

// Common modal content style
export const modalContentStyle = {
  background: 'var(--bg-secondary)',
  borderRadius: 'var(--radius-lg)',
  padding: '2rem',
  width: '100%',
  maxWidth: '600px',
  maxHeight: '90vh',
  overflow: 'auto',
  border: '1px solid var(--border-color)'
};

// Common card style
export const cardStyle = {
  padding: '1.5rem',
  background: 'var(--bg-tertiary)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border-color)'
};

// Tab button style generator
export const getTabButtonStyle = (isActive) => ({
  background: isActive ? 'var(--primary-light)' : 'none',
  border: 'none',
  padding: '0.875rem 1.25rem',
  color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
  borderBottom: isActive ? '2px solid var(--primary)' : '2px solid transparent',
  marginBottom: '-2px',
  cursor: 'pointer',
  fontSize: '0.875rem',
  fontWeight: '600',
  transition: 'all 0.2s',
  display: 'flex',
  alignItems: 'center',
  gap: '0.5rem',
  borderRadius: 'var(--radius-md) var(--radius-md) 0 0'
});

// Sub-tab button style generator
export const getSubTabButtonStyle = (isActive) => ({
  background: isActive ? 'var(--primary)' : 'var(--bg-tertiary)',
  border: isActive ? 'none' : '1px solid var(--border-color)',
  padding: '0.5rem 1rem',
  color: isActive ? '#0f172a' : 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: '0.8rem',
  fontWeight: '600',
  borderRadius: 'var(--radius-md)',
  transition: 'all 0.2s'
});

// Action button style generators
export const getActionButtonStyle = (color, isOutline = true) => {
  const colors = {
    primary: { bg: '0, 117, 255', text: '#3CB371' },
    blue: { bg: '59, 130, 246', text: '#3b82f6' },
    green: { bg: '34, 197, 94', text: '#22c55e' },
    yellow: { bg: '234, 179, 8', text: '#eab308' },
    red: { bg: '220, 38, 38', text: '#dc2626' },
    purple: { bg: '168, 85, 247', text: '#a855f7' },
    cyan: { bg: '6, 182, 212', text: '#06b6d4' },
    gray: { bg: '107, 114, 128', text: '#6b7280' }
  };

  const c = colors[color] || colors.gray;

  return {
    padding: '0.5rem 0.75rem',
    background: `rgba(${c.bg}, 0.2)`,
    border: `1px solid rgba(${c.bg}, 0.4)`,
    borderRadius: '6px',
    color: c.text,
    cursor: 'pointer',
    fontSize: '0.8rem',
    fontWeight: isOutline ? '500' : '600'
  };
};

// Badge style generator
export const getBadgeStyle = (color) => {
  const colors = {
    primary: { bg: 'var(--primary)', text: 'white' },
    green: { bg: 'rgba(34, 197, 94, 0.15)', text: '#22c55e', border: 'rgba(34, 197, 94, 0.3)' },
    yellow: { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b', border: 'rgba(245, 158, 11, 0.3)' },
    red: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.3)' },
    cyan: { bg: 'rgba(6, 182, 212, 0.15)', text: '#06b6d4', border: 'rgba(6, 182, 212, 0.3)' },
    gray: { bg: '#6b7280', text: 'white' }
  };

  const c = colors[color] || colors.gray;

  return {
    padding: '0.2rem 0.5rem',
    background: c.bg,
    color: c.text,
    borderRadius: '4px',
    fontSize: '0.7rem',
    fontWeight: '600',
    ...(c.border ? { border: `1px solid ${c.border}` } : {})
  };
};

// Empty state component style
export const emptyStateStyle = {
  textAlign: 'center',
  padding: '3rem',
  background: 'var(--bg-tertiary)',
  borderRadius: 'var(--radius-md)',
  border: '1px dashed var(--border-color)'
};

export { API_BASE_URL, authFetch };


