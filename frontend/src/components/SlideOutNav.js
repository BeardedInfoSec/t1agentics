/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import navStyles from './SlideOutNav.module.css';

// Simple SVG icons for navigation
const NavIcon = ({ name, size = 18 }) => {
  const icons = {
    grid: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" rx="1"/>
        <rect x="14" y="3" width="7" height="7" rx="1"/>
        <rect x="3" y="14" width="7" height="7" rx="1"/>
        <rect x="14" y="14" width="7" height="7" rx="1"/>
      </svg>
    ),
    crown: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M2 17l2-9 4 4 4-8 4 8 4-4 2 9H2z"/>
        <path d="M2 17h20v4H2z"/>
      </svg>
    ),
    bell: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
      </svg>
    ),
    search: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="11" cy="11" r="8"/>
        <path d="M21 21l-4.35-4.35"/>
      </svg>
    ),
    cpu: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="4" y="4" width="16" height="16" rx="2"/>
        <rect x="9" y="9" width="6" height="6"/>
        <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>
      </svg>
    ),
    shield: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
    plug: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22v-5"/>
        <path d="M9 8V2"/>
        <path d="M15 8V2"/>
        <path d="M18 8v5a6 6 0 0 1-12 0V8h12z"/>
      </svg>
    ),
    book: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
        <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
      </svg>
    ),
    settings: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
      </svg>
    ),
    folder: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
      </svg>
    ),
    activity: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
      </svg>
    ),
    workflow: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="5" cy="6" r="3"/>
        <circle cx="19" cy="6" r="3"/>
        <circle cx="12" cy="18" r="3"/>
        <path d="M5 9v3a3 3 0 0 0 3 3h8a3 3 0 0 0 3-3V9"/>
        <path d="M12 15V9"/>
      </svg>
    ),
    sparkles: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 3l1.5 4.5L18 9l-4.5 1.5L12 15l-1.5-4.5L6 9l4.5-1.5L12 3z"/>
        <path d="M5 19l1 3 1-3 3-1-3-1-1-3-1 3-3 1 3 1z"/>
        <path d="M19 13l.5 1.5 1.5.5-1.5.5-.5 1.5-.5-1.5-1.5-.5 1.5-.5.5-1.5z"/>
      </svg>
    ),
    globe: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/>
        <path d="M2 12h20"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
      </svg>
    ),
    clipboard: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="6" y="3" width="12" height="18" rx="2"/>
        <rect x="9" y="2" width="6" height="3" rx="1" fill="currentColor" stroke="none"/>
        <line x1="9" y1="11" x2="15" y2="11"/>
        <line x1="9" y1="15" x2="13" y2="15"/>
      </svg>
    ),
  };

  return icons[name] || <span>{name}</span>;
};

function SlideOutNav({ collapsed, onToggle, mobileOpen, onMobileClose, user }) {
  const location = useLocation();
  const [expandedMenus, setExpandedMenus] = useState({});
  const [pendingApprovals, setPendingApprovals] = useState(0);
  const [isHovered, setIsHovered] = useState(false);
  const [isPlatformOwner, setIsPlatformOwner] = useState(false);

  // Determine if nav should appear expanded (either not collapsed, or hovered while collapsed)
  const isExpanded = !collapsed || isHovered;

  // Close mobile menu on navigation
  useEffect(() => {
    if (mobileOpen && onMobileClose) {
      onMobileClose();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Fetch pending approvals count
  const fetchPendingCount = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/actions/requests/queue`);
      if (res.ok) {
        const data = await res.json();
        setPendingApprovals(data.queue?.length || 0);
      }
    } catch (err) {
      // Silently fail - API might not be available
    }
  }, []);

  useEffect(() => {
    fetchPendingCount();
    // Refresh every 30 seconds
    const interval = setInterval(fetchPendingCount, 30000);
    return () => clearInterval(interval);
  }, [fetchPendingCount]);

  // Check if current tenant is platform owner
  useEffect(() => {
    const checkPlatformOwner = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/admin/me/tenant`, {
          credentials: 'include'
        });
        if (res.ok) {
          const data = await res.json();
          setIsPlatformOwner(data.is_platform_owner === true);
        }
      } catch (err) {
        // Silently fail - endpoint might not be available
      }
    };
    checkPlatformOwner();
  }, []);

  const navItems = [
    {
      path: '/dashboard',
      icon: 'grid',
      label: 'Dashboards',
      description: 'SOC overview and executive views',
      badge: null,
      subItems: [
        { path: '/dashboard/overview', label: 'SOC Overview', description: 'Security operations summary' },
        { path: '/dashboard/management', label: 'Management', description: 'Executive risk posture' },
        { path: '/dashboard/operations', label: 'Operations', description: 'Analyst throughput and workload' },
      ]
    },
    {
      path: '/queue',
      icon: 'activity',
      label: 'Triage',
      description: 'Security alerts and investigations',
      badge: null,
      subItems: null
    },
    {
      path: '/playbooks',
      icon: 'sparkles',
      label: 'Playbooks',
      description: 'Build, import, and run automated response playbooks',
      badge: pendingApprovals > 0 ? pendingApprovals : null,
      // Internal tabs (My Playbooks, Build with Riggs, Marketplace, Import,
      // Intelligence) live inside RiggsStudio — adding subItems here meant
      // clicking the parent expanded the submenu instead of taking the user
      // to the playbooks page where those tabs render.
      subItems: null
    },
    {
      path: '/admin/intake-forms',
      icon: 'clipboard',
      label: 'Intake Forms',
      description: 'Forms whose submissions become alerts',
      badge: null,
      subItems: null
    },
    {
      path: '/threat-intel',
      icon: 'shield',
      label: 'Threat Intel',
      description: 'Search indicators and threat feeds',
      badge: null,
      subItems: null
    },
    {
      path: '/breach-intel',
      icon: 'globe',
      label: 'Breach Intel',
      description: 'Breach disclosures and threat landscape',
      badge: null,
      subItems: null
    },
    {
      path: '/connect',
      icon: 'plug',
      label: 'Connect',
      description: 'Manage integrations and connections',
      badge: null,
      subItems: [
        { path: '/connect?tab=marketplace', label: 'Marketplace' },
        { path: '/integrations/inbound-email', label: 'Email Inbox' },
      ]
    },
    {
      path: '/knowledge-base',
      icon: 'book',
      label: 'Knowledge Base',
      description: 'Documentation and reference materials',
      badge: null,
      subItems: null
    },
    // Admin settings - only visible to admin users
    ...((user?.role === 'admin' || user?.role === 'platform_owner') ? [{
      path: '/admin',
      icon: 'settings',
      label: 'Settings',
      description: 'System configuration and administration',
      badge: null,
      subItems: [
        { path: '/admin', label: 'Users', description: 'Manage user accounts' },
        { path: '/admin/rbac', label: 'Permissions', description: 'Role-based access control' },
        { path: '/settings', label: 'Configuration', description: 'System-wide settings' },
      ]
    }] : []),
    // Platform Admin - only visible for platform owner tenant
    ...(isPlatformOwner ? [{
      path: '/platform-admin',
      icon: 'crown',
      label: 'Platform Admin',
      description: 'Manage tenants, licenses, and platform settings',
      badge: null,
      subItems: null
    }] : []),
  ];

  const isActive = (path) => {
    if (path === '/queue' || path === '/investigations') {
      return location.pathname === path || location.pathname.startsWith(path + '/');
    }
    if (path === '/dashboard') {
      return location.pathname.startsWith('/dashboard');
    }
    // Playbooks: active on all playbook/automation routes
    if (path === '/playbooks') {
      return location.pathname.startsWith('/playbooks')
        || location.pathname.startsWith('/playbook-marketplace')
        || location.pathname.startsWith('/automation-studio');
    }
    // Settings has path '/admin' but Intake Forms lives at '/admin/intake-forms'
    // (own nav item). Whitelist only the routes that genuinely belong to Settings
    // so sibling /admin/* items don't double-highlight Settings.
    if (path === '/admin') {
      return location.pathname === '/admin'
        || location.pathname.startsWith('/admin/rbac')
        || location.pathname.startsWith('/settings');
    }
    return location.pathname.startsWith(path);
  };
  
  const toggleSubmenu = (label) => {
    if (collapsed && !isHovered) return; // Don't expand submenus when nav is collapsed and not hovered
    setExpandedMenus(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };
  
  return (
    <>
    <nav
      aria-label="Main navigation"
      data-tour="nav-sidebar"
      className={`slide-nav sidebar ${collapsed ? 'collapsed' : ''} ${isHovered && collapsed ? 'hover-expanded' : ''} ${mobileOpen ? 'open' : ''}`}
      onMouseEnter={() => !mobileOpen && collapsed && setIsHovered(true)}
      onMouseLeave={() => !mobileOpen && setIsHovered(false)}
      style={{
        width: isExpanded ? '240px' : '64px',
        zIndex: isHovered ? 1000 : 900,
        boxShadow: isHovered && collapsed ? '4px 0 20px rgba(0, 0, 0, 0.4)' : 'none'
      }}
    >
      {/* Collapse Button */}
      <div style={{
        padding: isExpanded ? '0.5rem 0.75rem' : '0.5rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.04)'
      }}>
        <button
          className={`nav-collapse-btn ${navStyles.collapseBtn}`}
          onClick={mobileOpen ? onMobileClose : onToggle}
          title={mobileOpen ? 'Close menu' : (collapsed ? 'Pin sidebar' : 'Collapse')}
          aria-label={mobileOpen ? 'Close navigation menu' : (collapsed ? 'Pin sidebar open' : 'Collapse sidebar')}
          aria-expanded={isExpanded}
        >
          {mobileOpen ? '\u2715' : (collapsed ? (isHovered ? '\u25C9' : '\u25B6') : '\u25C0')}
        </button>
      </div>
      
      {/* Navigation Items */}
      <div style={{ padding: '0.5rem 0' }}>
        {navItems.map((item) => (
          <div key={item.path}>
            {/* Main Nav Item */}
            <div
              className={`slide-nav-item ${isActive(item.path) ? 'active' : ''}`}
              onClick={() => item.subItems && toggleSubmenu(item.label)}
              onKeyDown={(e) => { if (item.subItems && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggleSubmenu(item.label); } }}
              title={!isExpanded ? `${item.label}: ${item.description}` : ''}
              role={item.subItems ? 'button' : undefined}
              tabIndex={item.subItems ? 0 : undefined}
              aria-expanded={item.subItems ? !!expandedMenus[item.label] : undefined}
              aria-label={item.subItems ? `${item.label} - ${item.description}` : undefined}
              style={{
                cursor: item.subItems ? 'pointer' : 'default',
                display: 'flex',
                alignItems: 'center',
                position: 'relative',
                gap: '0'
              }}
            >
              {item.subItems ? (
                // Has submenu - clickable div
                <>
                  <div className="slide-nav-icon"><NavIcon name={item.icon} /></div>
                  {isExpanded && (
                    <span className="slide-nav-text">{item.label}</span>
                  )}
                  {isExpanded && item.badge && <div className="slide-nav-badge">{item.badge}</div>}
                  {isExpanded && item.subItems && (
                    <span style={{
                      marginLeft: 'auto',
                      fontSize: '0.55rem',
                      transform: expandedMenus[item.label] ? 'rotate(90deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s',
                      opacity: 0.4,
                      flexShrink: 0
                    }}>
                      {'\u25B6'}
                    </span>
                  )}
                </>
              ) : (
                // No submenu - link
                <Link
                  to={item.path}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    width: '100%',
                    textDecoration: 'none',
                    color: 'inherit'
                  }}
                >
                  <div className="slide-nav-icon"><NavIcon name={item.icon} /></div>
                  {isExpanded && (
                    <span className="slide-nav-text">{item.label}</span>
                  )}
                  {isExpanded && item.badge && <div className="slide-nav-badge">{item.badge}</div>}
                </Link>
              )}
            </div>
            
            {/* Submenu Items -- always mounted, toggle via max-height for smooth CSS transition */}
            {isExpanded && item.subItems && (
              <div style={{
                paddingLeft: '3.25rem',
                paddingRight: '10px',
                overflow: 'hidden',
                maxHeight: expandedMenus[item.label] ? `${item.subItems.length * 40}px` : '0px',
                opacity: expandedMenus[item.label] ? 1 : 0,
                transition: 'max-height 0.15s ease-out, opacity 0.12s ease-out',
              }}>
                {item.subItems.map((subItem) => {
                  const isSubActive = location.pathname === subItem.path;
                  return (
                    <Link
                      key={subItem.path}
                      to={subItem.path}
                      title={subItem.description}
                      className={`${navStyles.subItem} ${isSubActive ? navStyles.subItemActive : ''}`}
                      style={{
                        color: isSubActive ? '#ffffff' : 'var(--text-secondary)',
                      }}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          background: isSubActive ? '#3CB371' : 'rgba(255, 255, 255, 0.2)',
                          flexShrink: 0,
                          transition: 'all 0.15s',
                          boxShadow: isSubActive ? '0 0 8px rgba(60, 179, 113, 0.5)' : 'none'
                        }} />
                        {subItem.label}
                      </span>
                      {subItem.badge && (
                        <span style={{
                          background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                          color: 'white',
                          fontSize: '0.6rem',
                          fontWeight: '600',
                          padding: '1px 5px',
                          borderRadius: '8px',
                          minWidth: '16px',
                          textAlign: 'center'
                        }}>
                          {subItem.badge > 99 ? '99+' : subItem.badge}
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </div>
    </nav>
    {mobileOpen && (
      <div
        className="mobile-nav-backdrop visible"
        onClick={onMobileClose}
        aria-hidden="true"
      />
    )}
    </>
  );
}

export default SlideOutNav;


