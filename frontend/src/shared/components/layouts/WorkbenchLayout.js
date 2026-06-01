/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * WorkbenchLayout Component
 *
 * Layout for investigation/analysis workbench pages with
 * resizable panels, header with actions, and sidebar support.
 */

import React, { useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import styles from './WorkbenchLayout.module.css';

/**
 * Panel Component
 */
export function Panel({
  title,
  icon,
  children,
  collapsible = false,
  defaultCollapsed = false,
  actions,
  className
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  return (
    <div className={`${styles.panel} ${collapsed ? styles.collapsed : ''} ${className || ''}`}>
      <div className={styles.panelHeader}>
        <div className={styles.panelTitle}>
          {icon && <span className={styles.panelIcon}>{icon}</span>}
          <span>{title}</span>
        </div>
        <div className={styles.panelActions}>
          {actions}
          {collapsible && (
            <button
              className={styles.collapseButton}
              onClick={() => setCollapsed(!collapsed)}
              aria-label={collapsed ? 'Expand panel' : 'Collapse panel'}
            >
              <svg
                width="12"
                height="12"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                style={{ transform: collapsed ? 'rotate(-90deg)' : 'rotate(0deg)' }}
              >
                <path d="M2 4l4 4 4-4" />
              </svg>
            </button>
          )}
        </div>
      </div>
      {!collapsed && (
        <div className={styles.panelContent}>
          {children}
        </div>
      )}
    </div>
  );
}

Panel.propTypes = {
  title: PropTypes.string.isRequired,
  icon: PropTypes.node,
  children: PropTypes.node,
  collapsible: PropTypes.bool,
  defaultCollapsed: PropTypes.bool,
  actions: PropTypes.node,
  className: PropTypes.string
};

/**
 * Tabs Component for panel content
 */
export function Tabs({ tabs, activeTab, onChange }) {
  return (
    <div className={styles.tabs} role="tablist">
      {tabs.map(tab => (
        <button
          key={tab.id}
          className={`${styles.tab} ${activeTab === tab.id ? styles.activeTab : ''}`}
          onClick={() => onChange(tab.id)}
          role="tab"
          aria-selected={activeTab === tab.id}
        >
          {tab.icon && <span className={styles.tabIcon}>{tab.icon}</span>}
          {tab.label}
          {tab.count !== undefined && (
            <span className={styles.tabCount}>{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

Tabs.propTypes = {
  tabs: PropTypes.arrayOf(PropTypes.shape({
    id: PropTypes.string.isRequired,
    label: PropTypes.string.isRequired,
    icon: PropTypes.node,
    count: PropTypes.number
  })).isRequired,
  activeTab: PropTypes.string.isRequired,
  onChange: PropTypes.func.isRequired
};

/**
 * WorkbenchLayout Component
 */
export function WorkbenchLayout({
  title,
  subtitle,
  status,
  headerActions,
  leftPanel,
  rightPanel,
  bottomPanel,
  children
}) {
  const [leftPanelWidth, setLeftPanelWidth] = useState(320);
  const [rightPanelWidth, setRightPanelWidth] = useState(360);
  const [bottomPanelHeight, setBottomPanelHeight] = useState(240);

  const handleLeftResize = useCallback((e) => {
    const startX = e.clientX;
    const startWidth = leftPanelWidth;

    const handleMouseMove = (moveEvent) => {
      const diff = moveEvent.clientX - startX;
      setLeftPanelWidth(Math.max(200, Math.min(600, startWidth + diff)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [leftPanelWidth]);

  const handleRightResize = useCallback((e) => {
    const startX = e.clientX;
    const startWidth = rightPanelWidth;

    const handleMouseMove = (moveEvent) => {
      const diff = startX - moveEvent.clientX;
      setRightPanelWidth(Math.max(280, Math.min(600, startWidth + diff)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [rightPanelWidth]);

  return (
    <div className={styles.container}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerContent}>
          <div className={styles.headerText}>
            <div className={styles.titleRow}>
              <h1 className={styles.title}>{title}</h1>
              {status && <div className={styles.status}>{status}</div>}
            </div>
            {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
          </div>
          <div className={styles.headerActions}>
            {headerActions}
          </div>
        </div>
      </header>

      {/* Main Area */}
      <div className={styles.body}>
        {/* Left Panel */}
        {leftPanel && (
          <>
            <aside
              className={styles.leftPanel}
              style={{ width: leftPanelWidth }}
            >
              {leftPanel}
            </aside>
            <div
              className={styles.resizer}
              onMouseDown={handleLeftResize}
              aria-hidden="true"
            />
          </>
        )}

        {/* Center Content */}
        <main className={styles.main}>
          <div className={styles.mainContent}>
            {children}
          </div>

          {/* Bottom Panel */}
          {bottomPanel && (
            <div
              className={styles.bottomPanel}
              style={{ height: bottomPanelHeight }}
            >
              {bottomPanel}
            </div>
          )}
        </main>

        {/* Right Panel */}
        {rightPanel && (
          <>
            <div
              className={styles.resizer}
              onMouseDown={handleRightResize}
              aria-hidden="true"
            />
            <aside
              className={styles.rightPanel}
              style={{ width: rightPanelWidth }}
            >
              {rightPanel}
            </aside>
          </>
        )}
      </div>
    </div>
  );
}

WorkbenchLayout.propTypes = {
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string,
  status: PropTypes.node,
  headerActions: PropTypes.node,
  leftPanel: PropTypes.node,
  rightPanel: PropTypes.node,
  bottomPanel: PropTypes.node,
  children: PropTypes.node
};

// Export sub-components
WorkbenchLayout.Panel = Panel;
WorkbenchLayout.Tabs = Tabs;

export default WorkbenchLayout;
