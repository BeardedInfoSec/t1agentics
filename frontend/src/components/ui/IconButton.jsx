/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './IconButton.module.css';

const IconButton = ({ size = 'md', disabled = false, className = '', children, ...props }) => (
  <button
    className={[styles.dsIconButton, styles[size], disabled ? styles.disabled : '', className].filter(Boolean).join(' ')}
    disabled={disabled}
    {...props}
  >
    {children}
  </button>
);

export default IconButton;
