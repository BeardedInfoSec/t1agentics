/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';

const ToastContext = createContext(null);

const TOAST_TYPES = {
  success: { icon: '\u2713', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.15)' },
  error: { icon: '\u2717', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
  warning: { icon: '!', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  info: { icon: 'i', color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.15)' },
};

function Toast({ id, type = 'info', title, message, duration = 5000, onDismiss }) {
  const [isExiting, setIsExiting] = useState(false);
  const config = TOAST_TYPES[type] || TOAST_TYPES.info;

  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        setIsExiting(true);
        setTimeout(() => onDismiss(id), 300);
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [id, duration, onDismiss]);

  const handleDismiss = () => {
    setIsExiting(true);
    setTimeout(() => onDismiss(id), 300);
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px',
        padding: '12px 16px',
        background: 'var(--bg-secondary, #1e293b)',
        border: `1px solid ${config.color}33`,
        borderLeft: `4px solid ${config.color}`,
        borderRadius: '8px',
        boxShadow: 'var(--shadow-lg, 0 10px 25px rgba(0,0,0,0.3))',
        minWidth: '320px',
        maxWidth: '420px',
        animation: isExiting ? 'toastSlideOut 0.3s ease forwards' : 'toastSlideIn 0.3s ease',
        pointerEvents: 'all',
      }}
    >
      <div style={{
        width: '24px',
        height: '24px',
        borderRadius: '50%',
        background: config.bg,
        color: config.color,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '14px',
        fontWeight: '700',
        flexShrink: 0,
      }}>
        {config.icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        {title && (
          <div style={{ fontSize: '0.875rem', fontWeight: '600', color: 'var(--text-primary, #f0f6fc)', marginBottom: '2px' }}>
            {title}
          </div>
        )}
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary, #94a3b8)', lineHeight: '1.4' }}>
          {message}
        </div>
      </div>
      <button
        onClick={handleDismiss}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--text-muted, #64748b)',
          cursor: 'pointer',
          fontSize: '16px',
          padding: '0',
          lineHeight: '1',
        }}
      >
        {'\u00d7'}
      </button>
    </div>
  );
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback(({ type = 'info', title, message, duration = 5000 }) => {
    const id = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
    setToasts(prev => [...prev, { id, type, title, message, duration }]);
    return id;
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const toastApi = {
    success: (message, title) => addToast({ type: 'success', title, message }),
    error: (message, title) => addToast({ type: 'error', title, message, duration: 8000 }),
    warning: (message, title) => addToast({ type: 'warning', title, message }),
    info: (message, title) => addToast({ type: 'info', title, message }),
    dismiss: dismissToast,
  };

  return (
    <ToastContext.Provider value={toastApi}>
      {children}
      {/* Toast Container */}
      <div style={{
        position: 'fixed',
        top: '16px',
        right: '16px',
        zIndex: 10000,
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        pointerEvents: 'none',
      }}>
        {toasts.map(t => (
          <Toast key={t.id} {...t} onDismiss={dismissToast} />
        ))}
      </div>
      <style>{`
        @keyframes toastSlideIn {
          from { opacity: 0; transform: translateX(100%); }
          to { opacity: 1; transform: translateX(0); }
        }
        @keyframes toastSlideOut {
          from { opacity: 1; transform: translateX(0); }
          to { opacity: 0; transform: translateX(100%); }
        }
      `}</style>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}

export default Toast;
