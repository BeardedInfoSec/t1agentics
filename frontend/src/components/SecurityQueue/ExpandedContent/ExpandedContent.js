/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ExpandedContent Router
 *
 * Routes to the appropriate expanded content component based on item_type.
 * This is the ONLY branching on item_type for expanded views.
 */

import React from 'react';
import ExpandedAlertContent from './ExpandedAlertContent';
import ExpandedInvestigationContent from './ExpandedInvestigationContent';

/**
 * ExpandedContent Component - Router only
 * @param {Object} props
 * @param {import('../types').SecurityQueueItem} props.item - Queue item to render
 * @param {Function} props.onRefresh - Refresh data handler
 * @param {Function} props.onFieldUpdate - Patch item fields in-place (no refetch)
 * @param {Object} props.systemConfig - System configuration
 */
function ExpandedContent({ item, onRefresh, onFieldUpdate, systemConfig }) {
  if (item.item_type === 'investigation') {
    return (
      <ExpandedInvestigationContent
        item={item}
        onRefresh={onRefresh}
        onFieldUpdate={onFieldUpdate}
        systemConfig={systemConfig}
      />
    );
  }

  return (
    <ExpandedAlertContent
      item={item}
      onRefresh={onRefresh}
      onFieldUpdate={onFieldUpdate}
      systemConfig={systemConfig}
    />
  );
}

export default ExpandedContent;
