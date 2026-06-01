/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';
import NotesPanel from './NotesPanel';
import styles from './InvestigationSidebar.module.css';

/**
 * InvestigationSidebar -- dual-tab sidebar (Notes + Riggs) for the
 * Investigation Workbench V2.
 *
 * @param {string}   investigationId - UUID of the current investigation
 * @param {object}   investigation   - Full investigation object (passed through for future use)
 * @param {object}   currentUser     - Authenticated user object
 * @param {boolean}  chatOpen        - Whether the sidebar is open
 * @param {function} setChatOpen     - Toggle sidebar open/closed
 * @param {object}   licenseData     - Tenant license / plan data (reserved for Riggs tab gating)
 * @param {function} renderRiggs     - Render prop for Riggs chat content
 */
export default function InvestigationSidebar({
  investigationId,
  investigation,
  currentUser,
  chatOpen,
  setChatOpen,
  licenseData,
  renderRiggs,
}) {
  const [activeTab, setActiveTab] = useState('notes');

  return (
    <div
      className={`${styles.sidebar} ${chatOpen ? styles.sidebarOpen : ''}`}
      aria-label="Investigation sidebar"
    >
      {/* Header with tabs and close button */}
      <div className={styles.sidebarHeader}>
        <div className={styles.tabBar}>
          <button
            className={`${styles.tabButton} ${activeTab === 'notes' ? styles.tabButtonActive : ''}`}
            onClick={() => setActiveTab('notes')}
            aria-selected={activeTab === 'notes'}
            role="tab"
          >
            Notes
          </button>
          <button
            className={`${styles.tabButton} ${activeTab === 'riggs' ? styles.tabButtonActive : ''}`}
            onClick={() => setActiveTab('riggs')}
            aria-selected={activeTab === 'riggs'}
            role="tab"
          >
            Riggs
          </button>
        </div>

        <button
          className={styles.closeButton}
          onClick={() => setChatOpen(false)}
          title="Close sidebar"
          aria-label="Close sidebar"
        >
          X
        </button>
      </div>

      {/* Tab content */}
      <div className={styles.tabContent}>
        {activeTab === 'notes' && (
          <NotesPanel
            investigationId={investigationId}
            currentUser={currentUser}
          />
        )}

        {activeTab === 'riggs' && (
          <div className={styles.riggsContent}>
            {renderRiggs ? renderRiggs() : (
              <div className={styles.riggsPlaceholder}>
                Riggs chat unavailable
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
