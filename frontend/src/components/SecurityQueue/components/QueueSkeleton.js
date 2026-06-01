/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * QueueSkeleton Component
 *
 * Renders shimmer placeholder rows matching the SecurityQueue table layout.
 * Replaces the spinner during initial data load.
 */

import React from 'react';
import styles from '../SecurityQueue.module.css';

const SKELETON_ROW_COUNT = 10;

function SkeletonRow({ index }) {
  // Vary widths for visual realism
  const titleWidth = [65, 80, 55, 72, 60, 75, 50, 68, 58, 70][index % 10];

  return (
    <tr className={styles.skeletonRow}>
      <td className={styles.cellCheckbox}>
        <div className={styles.skeletonCircle} />
      </td>
      <td className={styles.cellExpand}>
        <div className={styles.skeletonCircle} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: '60px' }} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: `${titleWidth}%` }} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: '50px' }} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: '55px' }} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: '70px' }} />
      </td>
      <td>
        <div className={styles.skeletonBar} style={{ width: '80px' }} />
      </td>
    </tr>
  );
}

function QueueSkeleton() {
  return (
    <div className={styles.tableContainer}>
      <table className={styles.queueTable}>
        <thead>
          <tr>
            <th className={styles.headerCheckbox} />
            <th className={styles.headerExpand} />
            <th className={styles.headerCell}>ID</th>
            <th className={styles.headerCell}>Title</th>
            <th className={styles.headerCell}>Status</th>
            <th className={styles.headerCell}>Severity</th>
            <th className={styles.headerCell}>Source</th>
            <th className={styles.headerCell}>Created</th>
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: SKELETON_ROW_COUNT }, (_, i) => (
            <SkeletonRow key={i} index={i} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default QueueSkeleton;
