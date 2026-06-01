/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * InlineOwnerSelect - Compact inline owner picker for SecurityQueue expanded views.
 * Fetches users from /api/v1/admin/users and current user from /api/v1/users/me.
 * Shows a dropdown with "Assign to me" at the top, then all system users.
 */

import React, { useState, useEffect, useRef } from 'react';
import { authFetch, API_BASE_URL } from '../../../utils/api';

const dropdownStyle = {
  position: 'absolute',
  top: '100%',
  left: 0,
  zIndex: 1000,
  background: 'var(--bg-secondary, #1e293b)',
  border: '1px solid var(--border-color, #334155)',
  borderRadius: '6px',
  minWidth: '220px',
  maxHeight: '260px',
  overflowY: 'auto',
  boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
  padding: '0.25rem 0',
};

const itemStyle = {
  padding: '0.4rem 0.75rem',
  fontSize: '0.8rem',
  cursor: 'pointer',
  display: 'flex',
  alignItems: 'center',
  gap: '0.5rem',
  color: 'var(--text-primary, #e2e8f0)',
  whiteSpace: 'nowrap',
};

const itemHoverBg = 'var(--bg-tertiary, #334155)';

const roleColors = {
  admin: '#dc2626',
  platform_owner: '#dc2626',
  analyst: '#3b82f6',
  user: '#3b82f6',
  read_only: '#6b7280',
  readonly: '#6b7280',
};

function InlineOwnerSelect({ value, onChange, disabled }) {
  const [open, setOpen] = useState(false);
  const [users, setUsers] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef(null);
  const searchRef = useRef(null);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false);
        setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  // Focus search when opened
  useEffect(() => {
    if (open && searchRef.current) searchRef.current.focus();
  }, [open]);

  // Fetch users + current user on first open
  useEffect(() => {
    if (!open || users.length > 0) return;
    setLoading(true);

    Promise.all([
      authFetch(`${API_BASE_URL}/api/v1/admin/users`).then(r => r.ok ? r.json() : []).catch(() => []),
      authFetch(`${API_BASE_URL}/api/v1/users/me`).then(r => r.ok ? r.json() : null).catch(() => null),
    ]).then(([userList, me]) => {
      const list = Array.isArray(userList) ? userList : [];
      // Filter out disabled users
      setUsers(list.filter(u => !u.disabled));
      setCurrentUser(me);
      setLoading(false);
    });
  }, [open, users.length]);

  const handleSelect = (username) => {
    setOpen(false);
    setSearch('');
    onChange(username);
  };

  const filtered = users.filter(u => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (u.username || '').toLowerCase().includes(q) ||
           (u.full_name || '').toLowerCase().includes(q) ||
           (u.email || '').toLowerCase().includes(q);
  });

  return (
    <div ref={containerRef} style={{ position: 'relative', display: 'inline-block' }}>
      <span
        style={{
          cursor: disabled ? 'default' : 'pointer',
          fontSize: '0.85rem',
          fontWeight: 500,
          color: value ? 'var(--text-primary)' : 'var(--text-muted)',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.3rem',
          padding: '0.15rem 0.4rem',
          borderRadius: '4px',
          background: disabled ? 'transparent' : 'var(--bg-tertiary)',
          border: disabled ? 'none' : '1px solid var(--border-color)',
        }}
        onClick={() => { if (!disabled) setOpen(!open); }}
        title={disabled ? '' : 'Click to assign owner'}
      >
        {value || 'Unassigned'}
        {!disabled && <span style={{ fontSize: '0.5rem', color: 'var(--text-muted)' }}>{'\u25BC'}</span>}
      </span>

      {open && (
        <div style={dropdownStyle}>
          {/* Search input */}
          <div style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border-color)' }}>
            <input
              ref={searchRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search users..."
              style={{
                width: '100%',
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                padding: '0.25rem 0.5rem',
                fontSize: '0.65rem',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>

          {/* Assign to me */}
          {currentUser && (
            <div
              style={{ ...itemStyle, fontWeight: 600, borderBottom: '1px solid var(--border-color)' }}
              onClick={() => handleSelect(currentUser.username)}
              onMouseEnter={(e) => e.currentTarget.style.background = itemHoverBg}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              Assign to me ({currentUser.username})
            </div>
          )}

          {/* Unassign option */}
          <div
            style={{ ...itemStyle, color: 'var(--text-muted)' }}
            onClick={() => handleSelect('')}
            onMouseEnter={(e) => e.currentTarget.style.background = itemHoverBg}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            Unassigned
          </div>

          {loading && (
            <div style={{ ...itemStyle, color: 'var(--text-muted)' }}>Loading...</div>
          )}

          {/* User list */}
          {filtered.map(u => (
            <div
              key={u.username}
              style={{
                ...itemStyle,
                fontWeight: u.username === value ? 600 : 400,
                background: u.username === value ? 'var(--bg-tertiary)' : 'transparent',
              }}
              onClick={() => handleSelect(u.username)}
              onMouseEnter={(e) => e.currentTarget.style.background = itemHoverBg}
              onMouseLeave={(e) => e.currentTarget.style.background = u.username === value ? 'var(--bg-tertiary)' : 'transparent'}
            >
              <span>{u.full_name || u.username}</span>
              <span style={{
                fontSize: '0.6rem',
                padding: '0.1rem 0.3rem',
                borderRadius: '3px',
                background: roleColors[u.role] || '#6b7280',
                color: '#fff',
                fontWeight: 600,
              }}>
                {u.role}
              </span>
            </div>
          ))}

          {!loading && filtered.length === 0 && (
            <div style={{ ...itemStyle, color: 'var(--text-muted)' }}>No users found</div>
          )}
        </div>
      )}
    </div>
  );
}

export default InlineOwnerSelect;
