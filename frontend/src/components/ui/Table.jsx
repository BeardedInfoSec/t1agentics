/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import styles from './Table.module.css';

const Table = ({
  columns,
  data,
  density = 'comfortable',
  loading,
  error,
  emptyMessage = 'No records found',
  onRowClick
}) => {
  if (loading) {
    return <div className={styles.loadingState}>Loading...</div>;
  }
  if (error) {
    return <div className={styles.errorState}>{error}</div>;
  }
  if (!data || data.length === 0) {
    return <div className={styles.emptyState}>{emptyMessage}</div>;
  }

  return (
    <div className={[styles.tableWrap, density === 'compact' ? styles.compact : ''].filter(Boolean).join(' ')}>
      <table className={styles.table}>
        <thead className={styles.thead}>
          <tr>
            {columns.map((col) => (
              <th key={col.key}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => (
            <tr
              key={row.id || idx}
              className={styles.row}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
            >
              {columns.map((col) => (
                <td key={col.key} className={styles.cell}>
                  {col.render ? col.render(row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Table;
