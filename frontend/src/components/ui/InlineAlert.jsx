/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './InlineAlert.module.css';

const InlineAlert = ({ variant = 'info', children, className = '' }) => (
  <div className={[styles.alert, styles[variant], className].filter(Boolean).join(' ')}>
    {children}
  </div>
);

export default InlineAlert;
