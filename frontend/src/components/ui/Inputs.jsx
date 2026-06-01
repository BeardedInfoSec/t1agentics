/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './Inputs.module.css';

export const Input = ({ label, className = '', ...props }) => (
  <label className={styles.field}>
    {label}
    <input className={[styles.input, className].filter(Boolean).join(' ')} {...props} />
  </label>
);

export const Select = ({ label, className = '', children, ...props }) => (
  <label className={styles.field}>
    {label}
    <select className={[styles.select, className].filter(Boolean).join(' ')} {...props}>
      {children}
    </select>
  </label>
);

export const Textarea = ({ label, className = '', ...props }) => (
  <label className={styles.field}>
    {label}
    <textarea className={[styles.textarea, className].filter(Boolean).join(' ')} {...props} />
  </label>
);
