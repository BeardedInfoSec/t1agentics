/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useEffect } from 'react';
import Button from './ui/Button';

function Toast({ message, type = 'success', onClose, duration = 3000 }) {
  useEffect(() => {
    const timer = setTimeout(() => {
      if (onClose) onClose();
    }, duration);
    
    return () => clearTimeout(timer);
  }, [onClose, duration]);

  const getColors = () => {
    switch (type) {
      case 'success':
        return { bg: '#22c55e', icon: '✓' };
      case 'error':
        return { bg: '#dc2626', icon: '✗' };
      case 'info':
        return { bg: '#3b82f6', icon: 'ℹ' };
      case 'warning':
        return { bg: '#eab308', icon: '⚠' };
      default:
        return { bg: '#6b7280', icon: '•' };
    }
  };

  const { bg, icon } = getColors();

  return (
    <div style={{
      position: 'fixed',
      top: '80px',
      right: '20px',
      padding: '1rem 1.5rem',
      background: bg,
      color: 'white',
      borderRadius: '8px',
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
      zIndex: 10000,
      animation: 'slideInRight 0.3s ease',
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem',
      fontSize: '0.875rem',
      fontWeight: '600',
      minWidth: '250px',
      maxWidth: '400px'
    }}>
      <span style={{ fontSize: '1.25rem' }}>{icon}</span>
      <span style={{ flex: 1 }}>{message}</span>
      {onClose && (
        <Button
          variant="ghost"
          size="xs"
          iconOnly
          onClick={onClose}
          style={{ color: 'white', opacity: 0.8 }}
        >
          ✕
        </Button>
      )}
    </div>
  );
}

export default Toast;
