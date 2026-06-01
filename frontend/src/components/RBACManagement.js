/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useMemo } from 'react';
import { API_BASE_URL, getCsrfToken } from '../utils/api';
import { Button, Badge, Modal, Card, Tabs, Input, Textarea, InlineAlert } from './ui';
import {
  Shield, Users, UserCheck, LayoutGrid,
  Plus, Pencil, Trash2, X, Check, Minus,
  Lock, Eye, Settings, FileText, Bell,
  Search, Folder, Zap, Link2, Briefcase, Server, Play,
  ChevronDown, ChevronRight
} from 'lucide-react';

/**
 * RBAC Management Component
 *
 * Allows administrators to:
 * - View and manage roles
 * - Configure permissions per role
 * - Assign roles to users
 * - View permission matrix
 */

// --- Category icon map ---
const CATEGORY_ICONS = {
  Tenant: Briefcase,
  Users: Users,
  Roles: Shield,
  Permissions: Lock,
  Settings: Settings,
  Retention: Folder,
  Audit: Eye,
  Investigations: Search,
  Alerts: Bell,
  Notes: FileText,
  Files: Folder,
  Actions: Zap,
  Integrations: Link2,
  Playbooks: Play,
  System: Server,
};

function RBACManagement() {
  const [activeTab, setActiveTab] = useState('roles');
  const [roles, setRoles] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Modal state
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [editingRole, setEditingRole] = useState(null);
  const [selectedUser, setSelectedUser] = useState(null);

  // Matrix collapsed categories
  const [collapsedCategories, setCollapsedCategories] = useState({});

  // Form state
  const [roleForm, setRoleForm] = useState({
    name: '',
    description: '',
    permissions: []
  });

  const API_BASE = `${API_BASE_URL}/api/v1`;

  // Default permissions structure
  const DEFAULT_PERMISSIONS = [
    { key: 'tenant:read', description: 'View tenant information', category: 'Tenant' },
    { key: 'user:read', description: 'View users', category: 'Users' },
    { key: 'user:create', description: 'Create users', category: 'Users' },
    { key: 'user:update', description: 'Update users', category: 'Users' },
    { key: 'user:disable', description: 'Disable users', category: 'Users' },
    { key: 'role:read', description: 'View roles', category: 'Roles' },
    { key: 'role:create', description: 'Create roles', category: 'Roles' },
    { key: 'role:update', description: 'Update roles', category: 'Roles' },
    { key: 'role:delete', description: 'Delete roles', category: 'Roles' },
    { key: 'permission:read', description: 'View permissions', category: 'Permissions' },
    { key: 'settings:read', description: 'View settings', category: 'Settings' },
    { key: 'settings:update', description: 'Update settings', category: 'Settings' },
    { key: 'retention:read', description: 'View retention policies', category: 'Retention' },
    { key: 'retention:update', description: 'Update retention policies', category: 'Retention' },
    { key: 'audit:read', description: 'View audit logs', category: 'Audit' },
    { key: 'investigation:read', description: 'View investigations', category: 'Investigations' },
    { key: 'investigation:create', description: 'Create investigations', category: 'Investigations' },
    { key: 'investigation:update', description: 'Update investigations', category: 'Investigations' },
    { key: 'investigation:assign', description: 'Assign investigations', category: 'Investigations' },
    { key: 'investigation:close', description: 'Close investigations', category: 'Investigations' },
    { key: 'alert:read', description: 'View alerts', category: 'Alerts' },
    { key: 'alert:update', description: 'Update alerts', category: 'Alerts' },
    { key: 'alert:link', description: 'Link alerts to investigations', category: 'Alerts' },
    { key: 'note:read', description: 'View notes', category: 'Notes' },
    { key: 'note:create', description: 'Create notes', category: 'Notes' },
    { key: 'note:update', description: 'Update notes', category: 'Notes' },
    { key: 'note:delete', description: 'Delete notes', category: 'Notes' },
    { key: 'file:upload', description: 'Upload files', category: 'Files' },
    { key: 'file:read', description: 'View file metadata', category: 'Files' },
    { key: 'file:download', description: 'Download files', category: 'Files' },
    { key: 'file:delete', description: 'Delete files (admin)', category: 'Files' },
    { key: 'action:read', description: 'View action history', category: 'Actions' },
    { key: 'action:execute', description: 'Execute actions', category: 'Actions' },
    { key: 'integration:view', description: 'View integrations and marketplace', category: 'Integrations' },
    { key: 'integration:install', description: 'Install or uninstall integrations', category: 'Integrations' },
    { key: 'integration:configure', description: 'Configure integrations, credentials, and test connections', category: 'Integrations' },
    { key: 'integration:manage', description: 'Full integration management including custom connectors', category: 'Integrations' },
    { key: 'playbook:view', description: 'View playbooks and templates', category: 'Playbooks' },
    { key: 'playbook:create', description: 'Create new playbooks', category: 'Playbooks' },
    { key: 'playbook:edit', description: 'Edit and update playbooks', category: 'Playbooks' },
    { key: 'playbook:execute', description: 'Execute playbooks manually', category: 'Playbooks' },
    { key: 'playbook:delete', description: 'Delete playbooks', category: 'Playbooks' },
    { key: 'job:run', description: 'Run system jobs', category: 'System' },
  ];

  // Default roles
  const DEFAULT_ROLES = [
    {
      name: 'Platform Owner',
      description: 'Highest level of access — full platform control, billing, and tenant management',
      is_system: true,
      permissions: ['*']
    },
    {
      name: 'Admin',
      description: 'Full administrative access to all features',
      is_system: true,
      permissions: ['*']
    },
    {
      name: 'Analyst',
      description: 'Security analyst with investigation capabilities',
      is_system: true,
      permissions: [
        'tenant:read',
        'investigation:read', 'investigation:create', 'investigation:update',
        'investigation:assign', 'investigation:close',
        'alert:read', 'alert:update', 'alert:link',
        'note:read', 'note:create', 'note:update',
        'file:upload', 'file:read', 'file:download',
        'action:read', 'action:execute',
        'integration:view',
        'playbook:view', 'playbook:execute',
      ]
    },
    {
      name: 'ReadOnly',
      description: 'Read-only access to investigations and alerts',
      is_system: true,
      permissions: [
        'tenant:read', 'investigation:read', 'alert:read', 'note:read',
        'file:read', 'action:read', 'integration:view', 'playbook:view'
      ]
    },
    {
      name: 'Automation',
      description: 'Service account for automation and integrations',
      is_system: true,
      permissions: ['action:execute', 'playbook:execute', 'integration:view']
    }
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const rolesRes = await fetch(`${API_BASE}/admin/roles`, { credentials: 'include' });
      if (rolesRes.ok) {
        const rolesData = await rolesRes.json();
        setRoles(rolesData.length > 0 ? rolesData : DEFAULT_ROLES);
      } else {
        setRoles(DEFAULT_ROLES);
      }

      const usersRes = await fetch(`${API_BASE}/admin/users`, { credentials: 'include' });
      if (usersRes.ok) {
        setUsers(await usersRes.json());
      }

      setPermissions(DEFAULT_PERMISSIONS);
    } catch (err) {
      setRoles(DEFAULT_ROLES);
      setPermissions(DEFAULT_PERMISSIONS);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRole = () => {
    setEditingRole(null);
    setRoleForm({ name: '', description: '', permissions: [] });
    setShowRoleModal(true);
  };

  const handleEditRole = (role) => {
    if (role.is_system) {
      setError('System roles cannot be edited');
      setTimeout(() => setError(null), 3000);
      return;
    }
    setEditingRole(role);
    setRoleForm({
      name: role.name,
      description: role.description || '',
      permissions: role.permissions || []
    });
    setShowRoleModal(true);
  };

  const handleSaveRole = async () => {
    if (!roleForm.name.trim()) {
      setError('Role name is required');
      return;
    }

    try {
      const url = editingRole
        ? `${API_BASE}/admin/roles/${editingRole.id || editingRole.name}`
        : `${API_BASE}/admin/roles`;

      const csrf = getCsrfToken();
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRF-Token'] = csrf;

      const response = await fetch(url, {
        method: editingRole ? 'PUT' : 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify(roleForm)
      });

      if (response.ok) {
        setSuccess(editingRole ? 'Role updated successfully' : 'Role created successfully');
        setShowRoleModal(false);
        loadData();
        setTimeout(() => setSuccess(null), 3000);
      } else {
        const err = await response.json().catch(() => ({}));
        setError(err.detail || 'Failed to save role');
        setTimeout(() => setError(null), 5000);
      }
    } catch (err) {
      if (editingRole) {
        setRoles(roles.map(r => r.name === editingRole.name ? { ...r, ...roleForm } : r));
      } else {
        setRoles([...roles, { ...roleForm, is_system: false }]);
      }
      setSuccess(editingRole ? 'Role updated' : 'Role created');
      setShowRoleModal(false);
      setTimeout(() => setSuccess(null), 3000);
    }
  };

  const handleDeleteRole = async (role) => {
    if (role.is_system) {
      setError('System roles cannot be deleted');
      setTimeout(() => setError(null), 3000);
      return;
    }

    if (!window.confirm(`Are you sure you want to delete the role "${role.name}"?`)) {
      return;
    }

    try {
      const csrf = getCsrfToken();
      const headers = {};
      if (csrf) headers['X-CSRF-Token'] = csrf;

      const response = await fetch(`${API_BASE}/admin/roles/${role.id || role.name}`, {
        method: 'DELETE',
        credentials: 'include',
        headers,
      });

      if (response.ok) {
        setSuccess('Role deleted successfully');
        loadData();
        setTimeout(() => setSuccess(null), 3000);
      }
    } catch (err) {
      setRoles(roles.filter(r => r.name !== role.name));
      setSuccess('Role deleted');
      setTimeout(() => setSuccess(null), 3000);
    }
  };

  const handleAssignRole = (user) => {
    setSelectedUser(user);
    setShowAssignModal(true);
  };

  const handleSaveUserRole = async (roleName) => {
    try {
      const csrf = getCsrfToken();
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRF-Token'] = csrf;

      const response = await fetch(`${API_BASE}/admin/users/${selectedUser.username}/role`, {
        method: 'PUT',
        credentials: 'include',
        headers,
        body: JSON.stringify({ role: roleName })
      });

      if (response.ok) {
        setSuccess(`Role updated for ${selectedUser.username}`);
        setShowAssignModal(false);
        loadData();
        setTimeout(() => setSuccess(null), 3000);
      } else {
        const errData = await response.json().catch(() => ({}));
        setError(errData.detail || `Failed to update role for ${selectedUser.username}`);
        setTimeout(() => setError(null), 5000);
      }
    } catch (err) {
      setError(`Network error updating role: ${err.message}`);
      setTimeout(() => setError(null), 5000);
    }
  };

  const togglePermission = (permKey) => {
    const current = roleForm.permissions || [];
    if (current.includes(permKey)) {
      setRoleForm({ ...roleForm, permissions: current.filter(p => p !== permKey) });
    } else {
      setRoleForm({ ...roleForm, permissions: [...current, permKey] });
    }
  };

  const toggleCategoryPermissions = (category) => {
    const categoryPerms = permissions.filter(p => p.category === category).map(p => p.key);
    const current = roleForm.permissions || [];
    const allSelected = categoryPerms.every(p => current.includes(p));

    if (allSelected) {
      setRoleForm({ ...roleForm, permissions: current.filter(p => !categoryPerms.includes(p)) });
    } else {
      const newPerms = [...new Set([...current, ...categoryPerms])];
      setRoleForm({ ...roleForm, permissions: newPerms });
    }
  };

  const toggleMatrixCategory = (category) => {
    setCollapsedCategories(prev => ({ ...prev, [category]: !prev[category] }));
  };

  // Group permissions by category
  const permissionsByCategory = useMemo(() => {
    return permissions.reduce((acc, perm) => {
      if (!acc[perm.category]) acc[perm.category] = [];
      acc[perm.category].push(perm);
      return acc;
    }, {});
  }, [permissions]);

  // Compute per-role per-category stats for the matrix
  const categoryStatsForRole = useMemo(() => {
    const stats = {};
    Object.entries(permissionsByCategory).forEach(([category, perms]) => {
      stats[category] = {};
      roles.forEach(role => {
        const isWildcard = role.permissions?.includes('*');
        const grantedCount = isWildcard
          ? perms.length
          : perms.filter(p => role.permissions?.includes(p.key)).length;
        stats[category][role.name] = { granted: grantedCount, total: perms.length };
      });
    });
    return stats;
  }, [permissionsByCategory, roles]);

  // Tab items for the Tabs component
  const tabItems = [
    { id: 'roles', label: <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-sm)' }}><Shield size={14} /> Roles</span> },
    { id: 'users', label: <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-sm)' }}><UserCheck size={14} /> User Assignments</span> },
    { id: 'matrix', label: <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-sm)' }}><LayoutGrid size={14} /> Permission Matrix</span> },
  ];

  // ─── Loading state ─────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        height: '400px', color: 'var(--text-muted)'
      }}>
        Loading RBAC configuration...
      </div>
    );
  }

  // ─── Render ────────────────────────────────────────────────────────────
  return (
    <div style={{ padding: 'var(--space-xl)', maxWidth: '1400px', margin: '0 auto' }}>

      {/* Page header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 'var(--space-xl)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)' }}>
          <div style={{
            width: 36, height: 36,
            background: 'var(--primary-light)',
            borderRadius: 'var(--radius-md)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Shield size={18} style={{ color: 'var(--primary)' }} />
          </div>
          <h1 style={{
            fontSize: 'var(--text-2xl)', fontWeight: 700,
            color: 'var(--text-primary)', margin: 0
          }}>
            Access Control
          </h1>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div style={{ marginBottom: 'var(--space-lg)' }}>
          <InlineAlert variant="error">{error}</InlineAlert>
        </div>
      )}
      {success && (
        <div style={{ marginBottom: 'var(--space-lg)' }}>
          <InlineAlert variant="success">{success}</InlineAlert>
        </div>
      )}

      {/* Tabs */}
      <div style={{ marginBottom: 'var(--space-xl)' }}>
        <Tabs items={tabItems} active={activeTab} onChange={setActiveTab} />
      </div>

      {/* ═══════════════════ ROLES TAB ═══════════════════ */}
      {activeTab === 'roles' && (
        <div>
          <div style={{
            display: 'flex', justifyContent: 'flex-end',
            marginBottom: 'var(--space-lg)'
          }}>
            <Button
              variant="primary"
              icon={<Plus size={14} />}
              onClick={handleCreateRole}
            >
              Create Role
            </Button>
          </div>

          <div style={{ display: 'grid', gap: 'var(--space-md)' }}>
            {roles.map(role => {
              const permCount = role.permissions?.includes('*')
                ? permissions.length
                : (role.permissions || []).length;
              const totalPerms = permissions.length;

              return (
                <Card key={role.name}>
                  <div style={{
                    display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 'var(--space-sm)'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                      <span style={{
                        fontWeight: 600, fontSize: 'var(--text-lg)',
                        color: 'var(--text-primary)'
                      }}>
                        {role.name}
                      </span>
                      {role.is_system && <Badge variant="info">System</Badge>}
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-sm)' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        icon={<Pencil size={13} />}
                        onClick={() => handleEditRole(role)}
                        disabled={role.is_system}
                      >
                        Edit
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        icon={<Trash2 size={13} />}
                        onClick={() => handleDeleteRole(role)}
                        disabled={role.is_system}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>

                  <p style={{
                    fontSize: 'var(--text-sm)', color: 'var(--text-muted)',
                    margin: '0 0 var(--space-md) 0'
                  }}>
                    {role.description}
                  </p>

                  {/* Permission count bar */}
                  <div style={{
                    display: 'flex', alignItems: 'center',
                    gap: 'var(--space-md)'
                  }}>
                    <div style={{
                      flex: 1, height: 4,
                      background: 'var(--bg-tertiary)',
                      borderRadius: 'var(--radius-full)',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        height: '100%',
                        width: `${(permCount / totalPerms) * 100}%`,
                        background: permCount === totalPerms
                          ? 'var(--primary)'
                          : permCount > 0 ? 'var(--warning)' : 'var(--text-disabled)',
                        borderRadius: 'var(--radius-full)',
                        transition: 'width var(--transition-slow)'
                      }} />
                    </div>
                    <span style={{
                      fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                      whiteSpace: 'nowrap', fontWeight: 500
                    }}>
                      {permCount}/{totalPerms} permissions
                    </span>
                  </div>

                  {/* Permission badges */}
                  <div style={{
                    display: 'flex', flexWrap: 'wrap',
                    gap: 'var(--space-xs)', marginTop: 'var(--space-sm)'
                  }}>
                    {role.permissions?.includes('*') ? (
                      <Badge variant="success">All Permissions</Badge>
                    ) : (
                      <>
                        {(role.permissions || []).slice(0, 6).map(perm => (
                          <span key={perm} style={{
                            fontSize: 'var(--text-xs)',
                            padding: '2px var(--space-sm)',
                            background: 'var(--primary-light)',
                            color: 'var(--primary)',
                            borderRadius: 'var(--radius-sm)',
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 500
                          }}>
                            {perm}
                          </span>
                        ))}
                        {(role.permissions || []).length > 6 && (
                          <span style={{
                            fontSize: 'var(--text-xs)',
                            padding: '2px var(--space-sm)',
                            background: 'var(--bg-tertiary)',
                            color: 'var(--text-muted)',
                            borderRadius: 'var(--radius-sm)',
                            fontWeight: 500
                          }}>
                            +{role.permissions.length - 6} more
                          </span>
                        )}
                      </>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══════════════════ USERS TAB ═══════════════════ */}
      {activeTab === 'users' && (
        <Card>
          <div style={{ overflowX: 'auto' }}>
            <table style={{
              width: '100%', borderCollapse: 'separate', borderSpacing: 0
            }}>
              <thead>
                <tr>
                  {['User', 'Email', 'Current Role', 'Status', 'Actions'].map(h => (
                    <th key={h} style={{
                      textAlign: 'left',
                      padding: 'var(--space-md) var(--space-lg)',
                      fontSize: 'var(--text-xs)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      fontWeight: 600,
                      color: 'var(--text-muted)',
                      borderBottom: '1px solid var(--border-color)',
                      background: 'var(--bg-tertiary)',
                      position: 'sticky', top: 0, zIndex: 2
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{
                      padding: 'var(--space-3xl)',
                      textAlign: 'center',
                      color: 'var(--text-muted)',
                      fontSize: 'var(--text-base)'
                    }}>
                      No users found
                    </td>
                  </tr>
                )}
                {users.map(user => (
                  <tr key={user.username} style={{
                    transition: 'background var(--transition-fast)'
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{
                      padding: 'var(--space-md) var(--space-lg)',
                      borderBottom: '1px solid var(--border-subtle)'
                    }}>
                      <div style={{
                        fontWeight: 500, fontSize: 'var(--text-base)',
                        color: 'var(--text-primary)'
                      }}>
                        {user.full_name || user.username}
                      </div>
                      <div style={{
                        fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)'
                      }}>
                        @{user.username}
                      </div>
                    </td>
                    <td style={{
                      padding: 'var(--space-md) var(--space-lg)',
                      borderBottom: '1px solid var(--border-subtle)',
                      color: 'var(--text-secondary)',
                      fontSize: 'var(--text-base)'
                    }}>
                      {user.email}
                    </td>
                    <td style={{
                      padding: 'var(--space-md) var(--space-lg)',
                      borderBottom: '1px solid var(--border-subtle)'
                    }}>
                      <Badge variant={user.role === 'platform_owner' ? 'error' : user.role === 'admin' ? 'error' : 'info'}>
                        {user.role === 'platform_owner' ? 'Platform Owner' : user.role || 'analyst'}
                      </Badge>
                    </td>
                    <td style={{
                      padding: 'var(--space-md) var(--space-lg)',
                      borderBottom: '1px solid var(--border-subtle)'
                    }}>
                      <Badge
                        variant={user.is_active !== false ? 'success' : 'error'}
                        dot
                      >
                        {user.is_active !== false ? 'Active' : 'Disabled'}
                      </Badge>
                    </td>
                    <td style={{
                      padding: 'var(--space-md) var(--space-lg)',
                      borderBottom: '1px solid var(--border-subtle)'
                    }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        icon={<UserCheck size={13} />}
                        onClick={() => handleAssignRole(user)}
                      >
                        Change Role
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ═══════════════════ PERMISSION MATRIX TAB ═══════════════════ */}
      {activeTab === 'matrix' && (
        <Card>
          <div style={{
            fontSize: 'var(--text-sm)', color: 'var(--text-muted)',
            marginBottom: 'var(--space-lg)'
          }}>
            Click a category row to expand or collapse its permissions.
            <Check size={12} style={{ color: 'var(--success)', marginLeft: 'var(--space-sm)', verticalAlign: 'middle' }} /> = granted
            <Minus size={12} style={{ color: 'var(--text-disabled)', marginLeft: 'var(--space-md)', verticalAlign: 'middle' }} /> = denied
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{
              width: '100%', borderCollapse: 'separate', borderSpacing: 0,
              tableLayout: 'fixed'
            }}>
              {/* Column widths: first col wider, role cols equal */}
              <colgroup>
                <col style={{ width: '240px', minWidth: '200px' }} />
                {roles.map(r => (
                  <col key={r.name} style={{ width: `${Math.max(100, Math.floor(680 / roles.length))}px` }} />
                ))}
              </colgroup>

              {/* Sticky header */}
              <thead>
                <tr>
                  <th style={{
                    textAlign: 'left',
                    padding: 'var(--space-md) var(--space-lg)',
                    fontSize: 'var(--text-xs)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    borderBottom: '2px solid var(--border-accent)',
                    background: 'var(--bg-tertiary)',
                    position: 'sticky', top: 0, left: 0, zIndex: 4
                  }}>
                    Permission
                  </th>
                  {roles.map(role => (
                    <th key={role.name} style={{
                      textAlign: 'center',
                      padding: 'var(--space-md) var(--space-sm)',
                      fontSize: 'var(--text-xs)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                      borderBottom: '2px solid var(--border-accent)',
                      background: 'var(--bg-tertiary)',
                      position: 'sticky', top: 0, zIndex: 3
                    }}>
                      <div style={{
                        display: 'flex', flexDirection: 'column',
                        alignItems: 'center', gap: '2px'
                      }}>
                        <span>{role.name}</span>
                        {role.permissions?.includes('*') && (
                          <span style={{
                            fontSize: '0.6rem',
                            color: 'var(--primary)',
                            fontWeight: 500, textTransform: 'none'
                          }}>
                            Full access
                          </span>
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {Object.entries(permissionsByCategory).map(([category, perms]) => {
                  const isCollapsed = collapsedCategories[category];
                  const CategoryIcon = CATEGORY_ICONS[category] || Shield;

                  return (
                    <React.Fragment key={category}>
                      {/* Category row */}
                      <tr
                        onClick={() => toggleMatrixCategory(category)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{
                          padding: 'var(--space-sm) var(--space-lg)',
                          background: 'var(--bg-elevated)',
                          fontWeight: 600,
                          fontSize: 'var(--text-sm)',
                          color: 'var(--text-primary)',
                          borderBottom: '1px solid var(--border-color)',
                          position: 'sticky', left: 0, zIndex: 2
                        }}>
                          <div style={{
                            display: 'flex', alignItems: 'center',
                            gap: 'var(--space-sm)'
                          }}>
                            {isCollapsed
                              ? <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
                              : <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
                            }
                            <CategoryIcon size={14} style={{ color: 'var(--primary)' }} />
                            <span>{category}</span>
                            <span style={{
                              fontSize: 'var(--text-xs)',
                              color: 'var(--text-muted)', fontWeight: 400,
                              marginLeft: 'var(--space-xs)'
                            }}>
                              ({perms.length})
                            </span>
                          </div>
                        </td>
                        {roles.map(role => {
                          const stat = categoryStatsForRole[category]?.[role.name];
                          if (!stat) return <td key={role.name} />;
                          const ratio = stat.granted / stat.total;
                          let cellBg = 'transparent';
                          let cellColor = 'var(--text-disabled)';
                          let label = `${stat.granted}/${stat.total}`;

                          if (ratio === 1) {
                            cellBg = 'var(--success-light)';
                            cellColor = 'var(--success)';
                          } else if (ratio > 0) {
                            cellBg = 'var(--warning-light)';
                            cellColor = 'var(--warning)';
                          }

                          return (
                            <td key={role.name} style={{
                              textAlign: 'center',
                              padding: 'var(--space-sm)',
                              background: 'var(--bg-elevated)',
                              borderBottom: '1px solid var(--border-color)'
                            }}>
                              <span style={{
                                display: 'inline-block',
                                padding: '2px var(--space-sm)',
                                borderRadius: 'var(--radius-sm)',
                                background: cellBg,
                                color: cellColor,
                                fontSize: 'var(--text-xs)',
                                fontWeight: 600,
                                minWidth: 36
                              }}>
                                {label}
                              </span>
                            </td>
                          );
                        })}
                      </tr>

                      {/* Individual permission rows (collapsible) */}
                      {!isCollapsed && perms.map((perm, idx) => (
                        <tr key={perm.key}>
                          <td style={{
                            padding: 'var(--space-sm) var(--space-lg)',
                            paddingLeft: 'var(--space-3xl)',
                            borderBottom: idx === perms.length - 1
                              ? '1px solid var(--border-color)'
                              : '1px solid var(--border-subtle)',
                            background: 'var(--bg-secondary)',
                            position: 'sticky', left: 0, zIndex: 1
                          }}>
                            <div style={{
                              fontSize: 'var(--text-sm)',
                              color: 'var(--text-primary)',
                              fontFamily: 'var(--font-mono)'
                            }}>
                              {perm.key}
                            </div>
                            <div style={{
                              fontSize: 'var(--text-xs)',
                              color: 'var(--text-muted)'
                            }}>
                              {perm.description}
                            </div>
                          </td>
                          {roles.map(role => {
                            const has = role.permissions?.includes('*') || role.permissions?.includes(perm.key);
                            return (
                              <td key={role.name} style={{
                                textAlign: 'center',
                                padding: 'var(--space-sm)',
                                borderBottom: idx === perms.length - 1
                                  ? '1px solid var(--border-color)'
                                  : '1px solid var(--border-subtle)',
                                background: 'var(--bg-secondary)'
                              }}>
                                {has ? (
                                  <div style={{
                                    display: 'inline-flex',
                                    alignItems: 'center', justifyContent: 'center',
                                    width: 24, height: 24,
                                    borderRadius: 'var(--radius-sm)',
                                    background: 'var(--success-light)'
                                  }}>
                                    <Check size={14} style={{ color: 'var(--success)' }} />
                                  </div>
                                ) : (
                                  <div style={{
                                    display: 'inline-flex',
                                    alignItems: 'center', justifyContent: 'center',
                                    width: 24, height: 24,
                                    borderRadius: 'var(--radius-sm)'
                                  }}>
                                    <Minus size={14} style={{ color: 'var(--text-disabled)' }} />
                                  </div>
                                )}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ═══════════════════ ROLE CREATE/EDIT MODAL ═══════════════════ */}
      <Modal
        open={showRoleModal}
        title={editingRole ? 'Edit Role' : 'Create Role'}
        onClose={() => setShowRoleModal(false)}
        onConfirm={handleSaveRole}
        confirmLabel={editingRole ? 'Save Changes' : 'Create Role'}
      >
        <div style={{ display: 'grid', gap: 'var(--space-lg)' }}>
          <Input
            label="Role Name *"
            value={roleForm.name}
            onChange={e => setRoleForm({ ...roleForm, name: e.target.value })}
            placeholder="e.g., Senior Analyst"
          />
          <Textarea
            label="Description"
            value={roleForm.description}
            onChange={e => setRoleForm({ ...roleForm, description: e.target.value })}
            placeholder="Describe what this role can do..."
            rows={3}
          />

          <div>
            <div style={{
              fontSize: 'var(--text-sm)', fontWeight: 500,
              color: 'var(--text-secondary)',
              marginBottom: 'var(--space-sm)'
            }}>
              Permissions
            </div>
            <div style={{
              maxHeight: '280px', overflowY: 'auto',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--space-sm)'
            }}>
              {Object.entries(permissionsByCategory).map(([category, perms]) => {
                const categoryPerms = perms.map(p => p.key);
                const selectedCount = categoryPerms.filter(p => roleForm.permissions?.includes(p)).length;
                const allSelected = selectedCount === categoryPerms.length;
                const CategoryIcon = CATEGORY_ICONS[category] || Shield;

                return (
                  <div key={category} style={{ marginBottom: 'var(--space-sm)' }}>
                    {/* Category header */}
                    <div
                      style={{
                        display: 'flex', alignItems: 'center',
                        gap: 'var(--space-sm)',
                        padding: 'var(--space-sm) var(--space-md)',
                        background: 'var(--bg-tertiary)',
                        borderRadius: 'var(--radius-md)',
                        cursor: 'pointer', userSelect: 'none'
                      }}
                      onClick={() => toggleCategoryPermissions(category)}
                    >
                      <input
                        type="checkbox"
                        checked={allSelected}
                        readOnly
                        style={{
                          width: 14, height: 14,
                          accentColor: 'var(--primary)',
                          cursor: 'pointer'
                        }}
                      />
                      <CategoryIcon size={13} style={{ color: 'var(--primary)' }} />
                      <span style={{
                        fontWeight: 500,
                        fontSize: 'var(--text-sm)',
                        color: 'var(--text-primary)'
                      }}>
                        {category}
                      </span>
                      <span style={{
                        fontSize: 'var(--text-xs)',
                        color: selectedCount === categoryPerms.length
                          ? 'var(--success)' : selectedCount > 0
                          ? 'var(--warning)' : 'var(--text-muted)',
                        marginLeft: 'auto', fontWeight: 500
                      }}>
                        {selectedCount}/{categoryPerms.length}
                      </span>
                    </div>

                    {/* Permission items */}
                    {perms.map(perm => {
                      const isSelected = roleForm.permissions?.includes(perm.key);
                      return (
                        <div
                          key={perm.key}
                          style={{
                            display: 'flex', alignItems: 'center',
                            gap: 'var(--space-sm)',
                            padding: 'var(--space-xs) var(--space-md)',
                            marginLeft: 'var(--space-xl)',
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                            background: isSelected ? 'var(--primary-light)' : 'transparent',
                            transition: 'background var(--transition-fast)'
                          }}
                          onClick={() => togglePermission(perm.key)}
                        >
                          <input
                            type="checkbox"
                            checked={isSelected}
                            readOnly
                            style={{
                              width: 14, height: 14,
                              accentColor: 'var(--primary)',
                              cursor: 'pointer'
                            }}
                          />
                          <div>
                            <div style={{
                              fontSize: 'var(--text-sm)',
                              color: 'var(--text-primary)',
                              fontFamily: 'var(--font-mono)'
                            }}>
                              {perm.key}
                            </div>
                            <div style={{
                              fontSize: 'var(--text-xs)',
                              color: 'var(--text-muted)'
                            }}>
                              {perm.description}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </Modal>

      {/* ═══════════════════ ASSIGN ROLE MODAL ═══════════════════ */}
      <Modal
        open={showAssignModal && !!selectedUser}
        title="Assign Role"
        onClose={() => setShowAssignModal(false)}
        onConfirm={() => setShowAssignModal(false)}
        confirmLabel="Done"
        cancelLabel="Close"
      >
        {selectedUser && (
          <div>
            <p style={{
              color: 'var(--text-secondary)',
              marginBottom: 'var(--space-lg)',
              fontSize: 'var(--text-base)'
            }}>
              Select a role for <strong style={{ color: 'var(--text-primary)' }}>{selectedUser.full_name || selectedUser.username}</strong>
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
              {roles.map(role => {
                const isCurrent = selectedUser.role === role.name.toLowerCase().replace(/ /g, '_');
                return (
                  <button
                    key={role.name}
                    onClick={() => handleSaveUserRole(role.name.toLowerCase().replace(/ /g, '_'))}
                    style={{
                      display: 'flex', flexDirection: 'column',
                      textAlign: 'left',
                      padding: 'var(--space-md) var(--space-lg)',
                      borderRadius: 'var(--radius-md)',
                      border: isCurrent
                        ? '1px solid var(--border-accent)'
                        : '1px solid var(--border-color)',
                      background: isCurrent
                        ? 'var(--primary-light)'
                        : 'var(--bg-tertiary)',
                      color: 'var(--text-primary)',
                      cursor: 'pointer',
                      transition: 'all var(--transition-fast)',
                      gap: 'var(--space-xs)'
                    }}
                    onMouseEnter={e => {
                      if (!isCurrent) e.currentTarget.style.borderColor = 'var(--border-hover)';
                    }}
                    onMouseLeave={e => {
                      if (!isCurrent) e.currentTarget.style.borderColor = 'var(--border-color)';
                    }}
                  >
                    <div style={{
                      display: 'flex', alignItems: 'center',
                      gap: 'var(--space-sm)'
                    }}>
                      <span style={{ fontWeight: 600, fontSize: 'var(--text-base)' }}>
                        {role.name}
                      </span>
                      {isCurrent && (
                        <Badge variant="success">Current</Badge>
                      )}
                    </div>
                    <div style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-muted)'
                    }}>
                      {role.description}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

export default RBACManagement;
