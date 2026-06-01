/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';

function ResponsiveTable({ data = [], columns = [], onRowClick, children, mobileBreakpoint = 768 }) {
  const [isMobile, setIsMobile] = useState(window.innerWidth < mobileBreakpoint);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < mobileBreakpoint);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [mobileBreakpoint]);

  if (!isMobile) {
    return children || null;
  }

  // Mobile card view
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '8px' }}>
      {data.map((item, idx) => (
        <div
          key={item.id || idx}
          onClick={() => onRowClick?.(item)}
          style={{
            background: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
            borderRadius: '8px',
            padding: '12px',
            cursor: onRowClick ? 'pointer' : 'default',
            transition: 'border-color 0.15s',
          }}
        >
          {columns.map(col => (
            <div key={col.key} style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '4px 0',
              borderBottom: '1px solid var(--border-color, #334155)22',
            }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #64748b)', fontWeight: '500' }}>
                {col.label}
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-primary, #f0f6fc)', textAlign: 'right' }}>
                {col.render ? col.render(item[col.key], item) : (item[col.key] ?? '-')}
              </span>
            </div>
          ))}
        </div>
      ))}
      {data.length === 0 && (
        <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
          No data to display
        </div>
      )}
    </div>
  );
}

export default ResponsiveTable;
