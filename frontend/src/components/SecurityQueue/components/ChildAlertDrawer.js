/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ChildAlertDrawer
 *
 * Slide-in panel for drilling into a single correlated alert from inside
 * the investigation drawer. Re-uses ExpandedAlertContent so the analyst
 * gets the same context view (analysis, IOCs, raw event, status actions)
 * they'd get from the queue, without leaving the investigation.
 *
 * ESC or backdrop click closes. Uses a portal so it overlays the queue
 * drawer instead of being clipped by it.
 */

import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';
import ExpandedAlertContent from '../ExpandedContent/ExpandedAlertContent';
import { normalizeAlert } from '../transforms';

export default function ChildAlertDrawer({ alert, onClose, onFieldUpdate }) {
  // ESC closes
  useEffect(() => {
    if (!alert) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [alert, onClose]);

  // Lock body scroll while open (prevents queue page from scrolling behind drawer)
  useEffect(() => {
    if (!alert) return undefined;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, [alert]);

  if (!alert) return null;

  const normalized = normalizeAlert(alert);

  const backdropStyle = {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0, 0, 0, 0.55)',
    zIndex: 2000,
    animation: 'fadeIn 0.18s ease-out',
  };

  const panelStyle = {
    position: 'fixed',
    top: 0,
    right: 0,
    bottom: 0,
    width: 'min(720px, 92vw)',
    background: 'var(--bg-secondary, #0f1419)',
    borderLeft: '1px solid var(--border-color, #1f2937)',
    boxShadow: '-8px 0 24px rgba(0, 0, 0, 0.4)',
    zIndex: 2001,
    display: 'flex',
    flexDirection: 'column',
    animation: 'slideInRight 0.22s ease-out',
  };

  const headerStyle = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.85rem 1.1rem',
    borderBottom: '1px solid var(--border-color, #1f2937)',
    flexShrink: 0,
  };

  const titleStyle = {
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--text-primary, #e5e7eb)',
    margin: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  };

  const subStyle = {
    fontSize: '0.7rem',
    color: 'var(--text-muted, #9ca3af)',
    marginTop: '0.15rem',
    fontFamily: "'SF Mono', Monaco, Consolas, monospace",
  };

  const closeBtnStyle = {
    background: 'transparent',
    border: 'none',
    color: 'var(--text-secondary, #cbd5e1)',
    fontSize: '1.4rem',
    lineHeight: 1,
    cursor: 'pointer',
    padding: '0.2rem 0.45rem',
    borderRadius: '4px',
    flexShrink: 0,
    marginLeft: '0.75rem',
  };

  const bodyStyle = {
    flex: 1,
    overflowY: 'auto',
    padding: '0.85rem 1.1rem',
  };

  return createPortal(
    <>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideInRight { from { transform: translateX(100%); } to { transform: translateX(0); } }
      `}</style>
      <div style={backdropStyle} onClick={onClose} aria-hidden="true" />
      <aside style={panelStyle} role="dialog" aria-label={`Alert ${alert.alert_id || alert.id}`}>
        <div style={headerStyle}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <h3 style={titleStyle}>{alert.title || 'Alert detail'}</h3>
            <div style={subStyle}>{alert.alert_id || alert.id}</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={closeBtnStyle}
            aria-label="Close alert detail"
            title="Close (Esc)"
          >
            &times;
          </button>
        </div>
        <div style={bodyStyle}>
          <ExpandedAlertContent
            item={normalized}
            onFieldUpdate={onFieldUpdate}
          />
        </div>
      </aside>
    </>,
    document.body,
  );
}
