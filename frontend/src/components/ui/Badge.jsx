/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Badge Component
 * Status badges and labels
 *
 * Variants: default, success, warning, danger, info
 * Sizes: xs, sm, md, lg
 * Shapes: default (rounded), pill (fully rounded)
 * Styles: default (subtle bg), outlined (border only), solid (filled)
 */

import React from 'react';
import styles from './Badge.module.css';

const Badge = ({
  children,
  variant = 'default', // default, success, warning, danger, info
  size = 'md',         // xs, sm, md, lg
  dot = false,         // Show dot indicator
  pill = false,        // Fully rounded (pill shape)
  outlined = false,    // Border only, no background
  solid = false,       // Solid background (high contrast)
  className = '',
  ...props
}) => {
  const classNames = [
    styles.badge,
    styles[variant],
    styles[size],
    dot && styles.dot,
    pill && styles.pill,
    outlined && styles.outlined,
    solid && styles.solid,
    className,
  ].filter(Boolean).join(' ');

  return (
    <span
      className={classNames}
      {...props}
    >
      {dot && <span className={styles.dotIndicator} />}
      {children}
    </span>
  );
};

export default Badge;
