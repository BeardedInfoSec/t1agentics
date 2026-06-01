/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './Tabs.module.css';

const Tabs = ({ items, active, onChange }) => (
  <div className={styles.tabs}>
    {items.map((item) => (
      <button
        key={item.id}
        className={[styles.tab, active === item.id ? styles.active : ''].filter(Boolean).join(' ')}
        onClick={() => onChange(item.id)}
      >
        {item.label}
      </button>
    ))}
  </div>
);

export default Tabs;
