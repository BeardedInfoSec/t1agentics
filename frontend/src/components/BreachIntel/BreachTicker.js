/** Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const TYPE_LABELS = {
  data_breach: 'BREACH',
  ransomware: 'RANSOMWARE',
  vulnerability: 'VULNERABILITY',
  apt_campaign: 'APT',
  supply_chain: 'SUPPLY CHAIN',
  ddos: 'DDOS',
  insider_threat: 'INSIDER',
  government_alert: 'ADVISORY',
  other: 'ALERT',
};

export default function BreachTicker() {
  const [items, setItems] = useState([]);
  const [visible, setVisible] = useState(true);
  const navigate = useNavigate();

  const fetchItems = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/breach-intel?limit=20&severity=critical,high', {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        setItems(data.items || []);
      }
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchItems();
    const interval = setInterval(fetchItems, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchItems]);

  // Set CSS variable so nav + main content shift down
  useEffect(() => {
    const show = visible && items.length > 0;
    document.documentElement.style.setProperty('--ticker-height', show ? '32px' : '0px');
    return () => document.documentElement.style.setProperty('--ticker-height', '0px');
  }, [visible, items.length]);

  if (!visible || items.length === 0) return null;

  // Duplicate items for seamless loop
  const tickerContent = [...items, ...items];
  const animDuration = Math.max(items.length * 8, 40);

  return (
    <div style={s.ticker}>
      <div style={s.label}>
        <span style={s.labelDot} />
        BREACH INTEL
      </div>
      <div style={s.trackWrap}>
        <div
          style={{ ...s.track, animationDuration: `${animDuration}s` }}
          className="breach-ticker-track"
        >
          {tickerContent.map((item, i) => (
            <span
              key={`${item.id}-${i}`}
              style={s.item}
              onClick={() => navigate('/breach-intel')}
              role="button"
              tabIndex={0}
            >
              <span style={{
                ...s.badge,
                background: SEVERITY_COLORS[item.severity] || '#6b7280',
              }}>
                {TYPE_LABELS[item.incident_type] || 'ALERT'}
              </span>
              <span style={s.title}>{item.title}</span>
              {item.affected_org && (
                <span style={s.org}>-- {item.affected_org}</span>
              )}
              <span style={s.sep} />
            </span>
          ))}
        </div>
      </div>
      <button
        style={s.close}
        onClick={(e) => { e.stopPropagation(); setVisible(false); }}
        title="Dismiss ticker"
      >
        x
      </button>
      <style>{`
        @keyframes tickerScroll {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .breach-ticker-track {
          animation: tickerScroll linear infinite;
        }
        .breach-ticker-track:hover {
          animation-play-state: paused;
        }
        @keyframes tickerPulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
      `}</style>
    </div>
  );
}

const s = {
  ticker: {
    display: 'flex',
    alignItems: 'center',
    height: '32px',
    background: 'var(--bg-elevated, #0f172a)',
    borderBottom: '1px solid var(--border-color, #1e293b)',
    overflow: 'hidden',
    position: 'fixed',
    top: '48px',
    left: 0,
    right: 0,
    zIndex: 998,
    fontFamily: 'var(--font-sans)',
    fontSize: '0.75rem',
    userSelect: 'none',
  },
  label: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '0 12px',
    fontWeight: 700,
    fontSize: '0.65rem',
    letterSpacing: '0.05em',
    color: '#ef4444',
    whiteSpace: 'nowrap',
    borderRight: '1px solid var(--border-color, #1e293b)',
    height: '100%',
    flexShrink: 0,
    background: 'rgba(239, 68, 68, 0.06)',
  },
  labelDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    background: '#ef4444',
    animation: 'tickerPulse 2s ease-in-out infinite',
  },
  trackWrap: {
    flex: 1,
    overflow: 'hidden',
    height: '100%',
    display: 'flex',
    alignItems: 'center',
  },
  track: {
    display: 'flex',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    gap: '0',
  },
  item: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    cursor: 'pointer',
    padding: '0 4px',
    height: '100%',
  },
  badge: {
    padding: '1px 6px',
    borderRadius: '3px',
    fontSize: '0.6rem',
    fontWeight: 700,
    color: '#fff',
    letterSpacing: '0.03em',
    flexShrink: 0,
  },
  title: {
    color: 'var(--text-primary, #e2e8f0)',
    fontWeight: 500,
  },
  org: {
    color: 'var(--text-muted, #64748b)',
    fontWeight: 400,
  },
  sep: {
    display: 'inline-block',
    width: '4px',
    height: '4px',
    borderRadius: '50%',
    background: 'var(--text-muted, #475569)',
    margin: '0 16px',
    flexShrink: 0,
  },
  close: {
    background: 'none',
    border: 'none',
    color: 'var(--text-muted, #64748b)',
    cursor: 'pointer',
    padding: '0 10px',
    fontSize: '0.8rem',
    height: '100%',
    flexShrink: 0,
    borderLeft: '1px solid var(--border-color, #1e293b)',
  },
};
