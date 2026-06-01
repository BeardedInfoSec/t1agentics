/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Card Component
 * Container with elevation and padding
 */

import React from 'react';
import styles from './Card.module.css';

const Card = ({
  children,
  title,
  subtitle,
  actions,
  padding = 'default',
  className = '',
  ...props
}) => {
  return (
    <div className={`${styles.card} ${styles[padding]} ${className}`} {...props}>
      {(title || subtitle || actions) && (
        <div className={styles.cardHeader}>
          <div className={styles.cardTitleArea}>
            {title && <h3 className={styles.cardTitle}>{title}</h3>}
            {subtitle && <p className={styles.cardSubtitle}>{subtitle}</p>}
          </div>
          {actions && <div className={styles.cardActions}>{actions}</div>}
        </div>
      )}
      <div className={styles.cardBody}>{children}</div>
    </div>
  );
};

export default Card;
