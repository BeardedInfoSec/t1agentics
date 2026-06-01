/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { useState, useEffect } from 'react';
import { API_BASE_URL } from '../utils/api';

/**
 * RBAC Hook for SOC Operations
 * Fetches user permissions and provides helper functions
 */
export function usePermissions() {
  const [permissions, setPermissions] = useState([]);
  const [role, setRole] = useState(null);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    fetchPermissions();
  }, []);

  const fetchPermissions = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/users/me`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        setPermissions(data.permissions || []);
        setRole(data.role);
        setUser(data);
      } else {
        // Fallback to localStorage
        fallbackToLocalStorage();
      }
    } catch (error) {
      fallbackToLocalStorage();
    } finally {
      setLoading(false);
    }
  };

  const fallbackToLocalStorage = () => {
    const userRole = localStorage.getItem('role');
    const username = localStorage.getItem('username');
    
    setRole(userRole);
    setUser({ username, role: userRole });
    
    // Default permissions based on role
    if (userRole === 'platform_owner' || userRole === 'admin') {
      setPermissions([
        'view_alerts', 'filter_alerts', 'create_investigation',
        'update_alert_status', 'view_investigations',
        'update_investigation_state', 'update_disposition',
        'assign_owner', 'add_notes', 'close_investigation',
        'manage_users', 'view_users'
      ]);
    } else if (userRole === 'analyst') {
      setPermissions([
        'view_alerts', 'filter_alerts', 'create_investigation',
        'update_alert_status', 'view_investigations',
        'update_investigation_state', 'update_disposition',
        'assign_owner', 'add_notes', 'close_investigation',
        'view_users'
      ]);
    } else {
      // read_only
      setPermissions([
        'view_alerts', 'filter_alerts',
        'view_investigations', 'view_users'
      ]);
    }
  };

  /**
   * Check if user has a specific permission
   */
  const can = (permission) => {
    return permissions.includes(permission);
  };

  /**
   * Check if user is admin
   */
  const isAdmin = () => role === 'admin' || role === 'platform_owner';

  /**
   * Check if user is analyst
   */
  const isAnalyst = () => role === 'analyst';

  /**
   * Check if user is read-only
   */
  const isReadOnly = () => role === 'read_only';

  /**
   * Check if user can write (admin or analyst)
   */
  const canWrite = () => role === 'platform_owner' || role === 'admin' || role === 'analyst';

  /**
   * Check if user can manage users (admin only)
   */
  const canManageUsers = () => role === 'admin' || role === 'platform_owner';

  return {
    permissions,
    role,
    user,
    loading,
    can,
    isAdmin,
    isAnalyst,
    isReadOnly,
    canWrite,
    canManageUsers
  };
}
