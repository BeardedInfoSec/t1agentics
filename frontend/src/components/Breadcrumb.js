/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import { Link, useLocation } from 'react-router-dom';

// Route configuration with human-readable names and descriptions
const routeConfig = {
  '/dashboard': { name: 'SOC Overview', description: 'Security operations summary' },
  '/dashboard/overview': { name: 'SOC Overview', parent: '/dashboard', description: 'Security operations summary' },
  '/dashboard/management': { name: 'Management', parent: '/dashboard', description: 'Executive risk posture' },
  '/dashboard/operations': { name: 'Operations', parent: '/dashboard', description: 'Analyst throughput and workload' },
  '/': { name: 'Dashboard', description: 'Overview of your security operations' },
  '/queue': { name: 'Triage', description: 'Security alerts awaiting review' },
  '/workbench': { name: 'Riggs', parent: '/', description: 'AI agent status & performance' },
  '/workbench/approvals': { name: 'Approvals', parent: '/workbench', description: 'Actions needing your approval' },
  '/threat-intel': { name: 'Search IOCs', description: 'Look up IPs, domains, hashes' },
  '/threat-intel/feeds': { name: 'Threat Feeds', parent: '/threat-intel', description: 'Manage threat intelligence sources' },
  '/connect': { name: 'Connect', description: 'Integration management' },
  '/connect/webhooks': { name: 'Webhooks', parent: '/connect', description: 'Receive alerts from external systems' },
  '/connect/inbound-email': { name: 'Email Inbox', parent: '/connect', description: 'Process emails and phishing reports' },
  '/knowledge-base': { name: 'Knowledge Base', description: 'Documentation and reference materials' },
  '/admin': { name: 'Users', description: 'Manage user accounts' },
  '/admin/rbac': { name: 'Permissions', parent: '/admin', description: 'Role-based access control' },
  '/admin/audit-logs': { name: 'Audit Log', parent: '/admin', description: 'View all system activity' },
  '/admin/post-resolution': { name: 'Post-Resolution', parent: '/admin', description: 'Automated actions after case closure' },
  '/agents': { name: 'AI Agents', parent: '/admin', description: 'Configure AI agent behavior' },
  '/logs': { name: 'System Logs', parent: '/admin', description: 'Technical system logs' },
  '/settings': { name: 'Configuration', parent: '/admin', description: 'System-wide settings' },
  '/profile': { name: 'Profile', description: 'Your account settings' },
  '/search': { name: 'Search Results', description: 'Global search results' },
  '/investigate': { name: 'New Investigation', description: 'Create a new investigation' },
  '/assets': { name: 'Asset Inventory', description: 'Managed assets and devices' },
  '/behavior': { name: 'Behavior Analytics', description: 'User and entity behavior analysis' },
  '/api-docs/interactive': { name: 'API Explorer', description: 'Interactive API documentation and testing' },
};

// Parent sections for grouping
const sectionNames = {
  '/dashboard': 'Dashboards',
  '/workbench': 'Investigations',
  '/threat-intel': 'Threat Intel',
  '/integrations': 'Integrations',
  '/admin': 'Settings',
};

function Breadcrumb() {
  const location = useLocation();
  const path = location.pathname;

  // Handle dynamic routes like /investigation/:id
  const getRouteInfo = () => {
    // Check for exact match first
    if (routeConfig[path]) {
      return routeConfig[path];
    }

    // Handle dynamic investigation routes
    if (path.startsWith('/investigation/')) {
      const id = path.split('/')[2];
      return {
        name: `Investigation ${id.substring(0, 8)}...`,
        parent: '/workbench',
        description: 'Investigation details and evidence'
      };
    }

    // Handle IOC detail routes
    if (path.startsWith('/threat-intel/') && path !== '/threat-intel/feeds') {
      const ioc = path.split('/')[2];
      return {
        name: decodeURIComponent(ioc),
        parent: '/threat-intel',
        description: null
      };
    }

    return null;
  };

  const currentRoute = getRouteInfo();

  if (!currentRoute) {
    return null;
  }

  // Build breadcrumb trail
  const breadcrumbs = [];

  // Always start with home
  if (path !== '/') {
    breadcrumbs.push({ path: '/', name: 'Home' });
  }

  // Add parent section if exists
  if (currentRoute.parent && sectionNames[currentRoute.parent]) {
    breadcrumbs.push({
      path: currentRoute.parent,
      name: sectionNames[currentRoute.parent]
    });
  }

  // Add current page
  breadcrumbs.push({
    path: path,
    name: currentRoute.name,
    current: true,
    description: currentRoute.description
  });

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '0.75rem 1.5rem',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border-color)',
      fontSize: '0.85rem'
    }}>
      {/* Breadcrumb trail */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {breadcrumbs.map((crumb, index) => (
          <React.Fragment key={`${crumb.path}-${index}`}>
            {index > 0 && (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>/</span>
            )}
            {crumb.current ? (
              <span style={{
                color: 'var(--text-primary)',
                fontWeight: '600'
              }}>
                {crumb.name}
              </span>
            ) : (
              <Link
                to={crumb.path}
                style={{
                  color: 'var(--text-secondary)',
                  textDecoration: 'none',
                  transition: 'color 0.15s'
                }}
                onMouseEnter={(e) => e.target.style.color = 'var(--primary)'}
                onMouseLeave={(e) => e.target.style.color = 'var(--text-secondary)'}
              >
                {crumb.name}
              </Link>
            )}
          </React.Fragment>
        ))}
      </nav>

      {/* Page description */}
      {currentRoute.description && (
        <>
          <span style={{
            color: 'var(--text-muted)',
            margin: '0 0.5rem',
            fontSize: '0.75rem'
          }}>
            -
          </span>
          <span style={{
            color: 'var(--text-muted)',
            fontSize: '0.8rem'
          }}>
            {currentRoute.description}
          </span>
        </>
      )}
    </div>
  );
}

export default Breadcrumb;
