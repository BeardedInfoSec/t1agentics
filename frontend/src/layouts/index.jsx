/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './Layout.module.css';

export const AuthLayout = ({ children }) => (
  <div className={styles.authRoot}>
    <div className={`${styles.contentCard} ${styles.authCard}`}>
      {children}
    </div>
  </div>
);

export const DataTableLayout = ({ title, subtitle, actions, children }) => (
  <div className={styles.tableRoot}>
    <div className={styles.layoutInner}>
      <div className={styles.headerRow}>
        <div>
          <h1 className={styles.headerTitle}>{title}</h1>
          {subtitle && <div className={styles.headerSubtitle}>{subtitle}</div>}
        </div>
        {actions && <div className={styles.actionBar}>{actions}</div>}
      </div>
      <div className={styles.contentCard}>{children}</div>
    </div>
  </div>
);

export const WorkbenchLayout = ({ title, subtitle, actions, children }) => (
  <div className={styles.workbenchRoot}>
    <div className={styles.layoutInner}>
      <div className={styles.headerRow}>
        <div>
          <h1 className={styles.headerTitle}>{title}</h1>
          {subtitle && <div className={styles.headerSubtitle}>{subtitle}</div>}
        </div>
        {actions && <div className={styles.actionBar}>{actions}</div>}
      </div>
      <div className={styles.contentCard}>{children}</div>
    </div>
  </div>
);

export const AdminLayout = ({ title, subtitle, actions, children }) => (
  <div className={styles.adminRoot}>
    <div className={styles.layoutInner}>
      <div className={styles.headerRow}>
        <div>
          <h1 className={styles.headerTitle}>{title}</h1>
          {subtitle && <div className={styles.headerSubtitle}>{subtitle}</div>}
        </div>
        {actions && <div className={styles.actionBar}>{actions}</div>}
      </div>
      <div className={styles.contentCard}>{children}</div>
    </div>
  </div>
);

export const CanvasLayout = ({ children }) => (
  <div className={styles.canvasRoot}>{children}</div>
);
