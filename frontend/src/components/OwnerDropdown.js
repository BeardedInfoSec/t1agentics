/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../utils/api';

function OwnerDropdown({ value, onChange, currentUser, disabled }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/users`);
      const data = await response.json();
      setUsers(data);
    } catch (error) {
      // Fallback to default users
      setUsers([
        { username: 'admin', role: 'admin', full_name: 'Administrator' },
        { username: 'analyst', role: 'analyst', full_name: 'SOC Analyst' },
        { username: 'readonly', role: 'read_only', full_name: 'Read Only' }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const getRoleBadgeColor = (role) => {
    const colors = {
      'admin': '#dc2626',
      'analyst': '#3b82f6',
      'read_only': '#6b7280'
    };
    return colors[role] || '#6b7280';
  };

  const assignToMe = () => {
    if (currentUser && currentUser.username) {
      onChange(currentUser.username);
    }
  };

  return (
    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', width: '100%' }}>
      <select
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled || loading}
        style={{
          flex: 1,
          padding: '0.5rem 0.75rem',
          background: 'var(--bg-tertiary)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          borderRadius: '6px',
          color: 'var(--text-primary)',
          fontSize: '0.875rem',
          cursor: disabled ? 'not-allowed' : 'pointer'
        }}
      >
        <option value="">Unassigned</option>
        {users.map((user) => (
          <option key={user.username} value={user.username}>
            {user.full_name || user.username} ({user.role})
          </option>
        ))}
      </select>
      
      {!disabled && (
        <button
          onClick={assignToMe}
          className="button button-secondary"
          style={{ 
            padding: '0.5rem 1rem', 
            fontSize: '0.75rem', 
            whiteSpace: 'nowrap',
            fontWeight: '600'
          }}
          title="Assign this investigation to yourself"
        >
          👤 Assign to Me
        </button>
      )}
    </div>
  );
}

export default OwnerDropdown;
