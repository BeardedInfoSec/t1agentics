/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import Table from './Table';
import styles from './SocTable.module.css';

const SocTable = ({ columns, data, ...props }) => (
  <div className={styles.socTable}>
    <Table columns={columns} data={data} {...props} />
  </div>
);

export const StatusCell = ({ status, children }) => (
  <span className={styles.statusCell}>
    <span className={styles.statusDot} data-status={status} />
    {children}
  </span>
);

export default SocTable;
