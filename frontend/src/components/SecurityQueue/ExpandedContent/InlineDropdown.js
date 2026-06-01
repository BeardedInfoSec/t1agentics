/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * InlineDropdown - Single-click dropdown for inline field editing.
 * Click the value to open a dropdown, click an option to select.
 */

import React, { useState, useEffect, useRef } from 'react';

const dropdownStyle = {
  position: 'absolute',
  top: '100%',
  left: 0,
  zIndex: 1000,
  background: 'var(--bg-secondary, #1e293b)',
  border: '1px solid var(--border-color, #334155)',
  borderRadius: '6px',
  minWidth: '140px',
  boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
  padding: '0.25rem 0',
  marginTop: '2px',
};

const itemBase = {
  padding: '0.35rem 0.75rem',
  fontSize: '0.8rem',
  cursor: 'pointer',
  color: 'var(--text-primary, #e2e8f0)',
  fontWeight: 500,
};

const hoverBg = 'var(--bg-tertiary, #334155)';

function InlineDropdown({ value, options, onChange, renderValue, renderOption }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const handleSelect = (val) => {
    setOpen(false);
    if (val !== value) onChange(val);
  };

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <span
        onClick={() => setOpen(!open)}
        style={{
          cursor: 'pointer',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.4rem',
          padding: '0.15rem 0.5rem',
          borderRadius: '4px',
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border-color)',
        }}
      >
        {renderValue ? renderValue(value) : value}
        <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', marginLeft: '0.1rem' }}>{'\u25BC'}</span>
      </span>

      {open && (
        <div style={dropdownStyle}>
          {options.map((opt) => {
            const optValue = typeof opt === 'object' ? opt.value : opt;
            const isSelected = optValue === value;
            return (
              <div
                key={optValue}
                style={{
                  ...itemBase,
                  fontWeight: isSelected ? 700 : 500,
                  background: isSelected ? 'var(--bg-tertiary)' : 'transparent',
                }}
                onClick={() => handleSelect(optValue)}
                onMouseEnter={(e) => e.currentTarget.style.background = hoverBg}
                onMouseLeave={(e) => e.currentTarget.style.background = isSelected ? 'var(--bg-tertiary)' : 'transparent'}
              >
                {renderOption ? renderOption(opt, isSelected) : (typeof opt === 'object' ? opt.label : opt)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default InlineDropdown;
