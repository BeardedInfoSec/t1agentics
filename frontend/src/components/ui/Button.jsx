/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Button Component
 * Reusable button with variants and sizes
 *
 * Variants: primary, secondary, danger, warning, info, ghost
 * Sizes: xs, sm, md, lg
 */

import React from 'react';
import { Loader2 } from 'lucide-react';
import styles from './Button.module.css';

const Button = ({
  children,
  variant = 'primary', // primary, secondary, danger, warning, info, ghost
  size = 'md',         // xs, sm, md, lg
  loading = false,
  disabled = false,
  icon,
  iconOnly = false,    // For icon-only buttons (close buttons, etc.)
  fullWidth = false,
  onClick,
  type = 'button',
  className = '',
  ...props
}) => {
  const classNames = [
    styles.button,
    styles[variant],
    styles[size],
    fullWidth && styles.fullWidth,
    iconOnly && styles.iconOnly,
    className,
  ].filter(Boolean).join(' ');

  return (
    <button
      type={type}
      className={classNames}
      disabled={disabled || loading}
      onClick={onClick}
      {...props}
    >
      {loading && <Loader2 className={styles.spinner} size={size === 'xs' ? 12 : size === 'sm' ? 14 : 16} />}
      {!loading && icon && <span className={styles.icon}>{icon}</span>}
      {children}
    </button>
  );
};

export default Button;
