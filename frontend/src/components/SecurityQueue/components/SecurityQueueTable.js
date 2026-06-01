/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueueTable Component
 *
 * Renders the main queue table with columns, sorting, selection, and pagination.
 * Fetches full details when rows are expanded.
 */

import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search } from 'lucide-react';
import QueueRow from './QueueRow';
import ExpandedContent from '../ExpandedContent/ExpandedContent';
import Drawer from '../../ui/Drawer';
import Badge from '../../ui/Badge';
import { COLUMN_CONFIG, ROWS_PER_PAGE_OPTIONS } from '../constants';
import { getAuthHeaders, API_BASE_URL } from '../../../utils/api';
import { telemetry } from '../../../utils/telemetry';
import { formatDate, formatTimeRemaining, getStatusBadge } from '../utils';
import { severityToBadgeVariant } from '../../../styles/colors';
import { useMediaQuery } from '../../../hooks/useMediaQuery';
import styles from '../SecurityQueue.module.css';

/**
 * SecurityQueueTable Component
 */
function SecurityQueueTable({
  items,
  visibleColumns,
  setVisibleColumns,
  currentPage,
  rowsPerPage,
  onPageChange,
  onRowsPerPageChange,
  onItemClick,
  selectedIds = [],
  onSelectionChange,
  onRefresh,
  onUpdateItem,
  systemConfig,
}) {
  // Sorting state
  const [sortKey, setSortKey] = useState('created_at');
  const [sortDirection, setSortDirection] = useState('desc');

  // Context drawer state
  const [drawerItem, setDrawerItem] = useState(null);
  const [drawerLoading, setDrawerLoading] = useState(false);

  // Keyboard navigation state
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const tableRef = useRef(null);

  // Column drag-to-reorder state
  const dragColRef = useRef(null);
  const [dragOverCol, setDragOverCol] = useState(null);

  // Sort items
  const sortedItems = useMemo(() => {
    const sorted = [...items];
    sorted.sort((a, b) => {
      let aVal = a[sortKey];
      let bVal = b[sortKey];

      // Handle dates
      if (sortKey === 'created_at' || sortKey === 'updated_at') {
        aVal = new Date(aVal || 0).getTime();
        bVal = new Date(bVal || 0).getTime();
      }

      // Handle nested SLA
      if (sortKey === 'sla') {
        aVal = a.sla?.percent || 0;
        bVal = b.sla?.percent || 0;
      }

      // Handle nulls
      if (aVal == null) aVal = '';
      if (bVal == null) bVal = '';

      // String comparison
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [items, sortKey, sortDirection]);

  // Paginate items
  const paginatedItems = useMemo(() => {
    const start = (currentPage - 1) * rowsPerPage;
    return sortedItems.slice(start, start + rowsPerPage);
  }, [sortedItems, currentPage, rowsPerPage]);

  // Total pages
  const totalPages = Math.ceil(items.length / rowsPerPage);

  // Handle column header click for sorting
  const handleSort = useCallback((key) => {
    const config = COLUMN_CONFIG[key];
    if (!config?.sortable) return;

    if (sortKey === key) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDirection('desc');
    }
  }, [sortKey]);

  // Column drag-to-reorder handlers
  const handleDragStart = useCallback((e, colKey) => {
    dragColRef.current = colKey;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', colKey);
    // Make drag image semi-transparent
    if (e.currentTarget) {
      e.currentTarget.style.opacity = '0.5';
    }
  }, []);

  const handleDragEnd = useCallback((e) => {
    dragColRef.current = null;
    setDragOverCol(null);
    if (e.currentTarget) {
      e.currentTarget.style.opacity = '1';
    }
  }, []);

  const handleDragOver = useCallback((e, colKey) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragColRef.current && dragColRef.current !== colKey) {
      setDragOverCol(colKey);
    }
  }, []);

  const handleDrop = useCallback((e, targetColKey) => {
    e.preventDefault();
    const sourceColKey = dragColRef.current;
    if (!sourceColKey || sourceColKey === targetColKey || !setVisibleColumns) return;

    const newOrder = [...visibleColumns];
    const sourceIdx = newOrder.indexOf(sourceColKey);
    const targetIdx = newOrder.indexOf(targetColKey);
    if (sourceIdx === -1 || targetIdx === -1) return;

    newOrder.splice(sourceIdx, 1);
    newOrder.splice(targetIdx, 0, sourceColKey);
    setVisibleColumns(newOrder);

    dragColRef.current = null;
    setDragOverCol(null);
  }, [visibleColumns, setVisibleColumns]);

  // Handle row selection toggle
  const handleRowSelect = useCallback((queueId) => {
    const newSelection = selectedIds.includes(queueId)
      ? selectedIds.filter(id => id !== queueId)
      : [...selectedIds, queueId];
    onSelectionChange?.(newSelection);
  }, [selectedIds, onSelectionChange]);

  // Handle select all on current page
  const handleSelectAll = useCallback(() => {
    const pageIds = paginatedItems.map(item => item.queue_id);
    const allSelected = pageIds.every(id => selectedIds.includes(id));

    if (allSelected) {
      onSelectionChange?.(selectedIds.filter(id => !pageIds.includes(id)));
    } else {
      const newSelection = [...new Set([...selectedIds, ...pageIds])];
      onSelectionChange?.(newSelection);
    }
  }, [paginatedItems, selectedIds, onSelectionChange]);

  // Handle row click - opens context drawer with full details
  const handleRowClick = useCallback(async (queueId) => {
    // If clicking the already-open item, close drawer
    if (drawerItem?.queue_id === queueId) {
      setDrawerItem(null);
      return;
    }

    // Find the item
    const item = items.find(i => i.queue_id === queueId);
    if (!item) return;

    telemetry.track('queue', 'queue.row_click', { item_type: item.item_type, severity: item.severity });
    const drawerOpenStart = Date.now();

    // Show drawer immediately with loading state
    setDrawerLoading(true);

    try {
      let fetchedData = null;

      // Fetch full details based on item type
      let fetchedAlertData = null;
      if (item.item_type === 'investigation' && item.investigation_id) {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/investigations/${item.investigation_id}`,
          { headers: getAuthHeaders() }
        );
        if (response.ok) {
          fetchedData = await response.json();
        }
        // Also fetch the source alert to get raw_event with IOCs/enrichment
        if (item.alert_id) {
          try {
            const alertRes = await fetch(
              `${API_BASE_URL}/api/v1/alerts/${item.alert_id}`,
              { headers: getAuthHeaders() }
            );
            if (alertRes.ok) {
              fetchedAlertData = await alertRes.json();
            }
          } catch (e) { /* alert fetch is best-effort */ }
        }
      } else if (item.item_type === 'alert' && item.alert_id) {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/alerts/${item.alert_id}`,
          { headers: getAuthHeaders() }
        );
        if (response.ok) {
          fetchedData = await response.json();
        }
      }

      // Create enriched item with fetched data
      const enrichedItem = {
        ...item,
        investigation_context: item.item_type === 'investigation'
          ? { ...item.investigation_context, ...fetchedData }
          : item.investigation_context,
        alert_context: item.item_type === 'alert'
          ? { ...item.alert_context, ...fetchedData }
          : (fetchedAlertData || item.alert_context),
      };

      setDrawerItem(enrichedItem);
    } catch (error) {
      // Still show drawer with original data on error
      setDrawerItem(item);
    } finally {
      setDrawerLoading(false);
      telemetry.track('queue', 'queue.drawer_open', { item_type: item.item_type, load_time_ms: Date.now() - drawerOpenStart });
    }
  }, [items, drawerItem]);

  // Handle field updates from the expanded content panel.
  // Patches drawerItem locally and updates the parent items list so the
  // table row reflects the change — no full refetch needed.
  const handleItemFieldUpdate = useCallback((patch) => {
    setDrawerItem(prev => prev ? { ...prev, ...patch } : prev);
    if (drawerItem) {
      const id = drawerItem.item_type === 'alert' ? drawerItem.alert_id : drawerItem.investigation_id;
      onUpdateItem?.(id, drawerItem.item_type, patch);
    }
  }, [drawerItem, onUpdateItem]);

  // Auto-open the drawer when a ?drawer=<alert_id|investigation_id> param is
  // present in the URL. Lets the dashboard's Recent Critical Events click
  // drop into the queue with the preview already open — no extra click.
  // The param is consumed (removed from URL) after firing so a manual
  // refresh doesn't keep re-opening the drawer.
  const [searchParams, setSearchParams] = useSearchParams();
  const autoOpenedRef = useRef(false);
  useEffect(() => {
    if (autoOpenedRef.current) return;
    const target = searchParams.get('drawer');
    if (!target || items.length === 0) return;
    const match = items.find(
      (i) => i.alert_id === target || i.investigation_id === target,
    );
    if (!match) return;
    autoOpenedRef.current = true;
    handleRowClick(match.queue_id);
    // Strip the param so it's a one-shot trigger.
    const next = new URLSearchParams(searchParams);
    next.delete('drawer');
    setSearchParams(next, { replace: true });
  }, [items, searchParams, setSearchParams, handleRowClick]);

  // Mobile detection
  const isMobile = useMediaQuery('(max-width: 768px)');

  // Check if all items on page are selected
  const allPageSelected = paginatedItems.length > 0 &&
    paginatedItems.every(item => selectedIds.includes(item.queue_id));
  const somePageSelected = paginatedItems.some(item => selectedIds.includes(item.queue_id));

  // Generate page numbers for pagination
  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      if (currentPage <= 3) {
        for (let i = 1; i <= 4; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 2) {
        pages.push(1);
        pages.push('...');
        for (let i = totalPages - 3; i <= totalPages; i++) pages.push(i);
      } else {
        pages.push(1);
        pages.push('...');
        for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      }
    }
    return pages;
  };

  // ─── Keyboard navigation ─────────────────────────────────────────────
  // j/k or Arrow Down/Up: navigate rows
  // Enter: expand/collapse focused row
  // Space: select/deselect focused row
  // Escape: collapse all expanded rows
  // o: open (navigate to) focused item
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Only handle when table area is focused or no input is focused
      const active = document.activeElement;
      const isInput = active?.tagName === 'INPUT' || active?.tagName === 'TEXTAREA' || active?.tagName === 'SELECT';
      if (isInput) return;

      // Check if the table container or its children are active
      if (tableRef.current && !tableRef.current.contains(active) && active !== document.body) return;

      const itemCount = paginatedItems.length;
      if (itemCount === 0) return;

      switch (e.key) {
        case 'j':
        case 'ArrowDown': {
          e.preventDefault();
          setFocusedIndex(prev => {
            const next = Math.min(prev + 1, itemCount - 1);
            // Scroll focused row into view
            const rows = tableRef.current?.querySelectorAll('tbody tr[data-queue-id]');
            rows?.[next]?.scrollIntoView({ block: 'nearest' });
            return next;
          });
          break;
        }
        case 'k':
        case 'ArrowUp': {
          e.preventDefault();
          setFocusedIndex(prev => {
            const next = Math.max(prev - 1, 0);
            const rows = tableRef.current?.querySelectorAll('tbody tr[data-queue-id]');
            rows?.[next]?.scrollIntoView({ block: 'nearest' });
            return next;
          });
          break;
        }
        case 'Enter': {
          e.preventDefault();
          if (focusedIndex >= 0 && focusedIndex < itemCount) {
            const item = paginatedItems[focusedIndex];
            handleRowClick(item.queue_id);
          }
          break;
        }
        case ' ': {
          e.preventDefault();
          if (focusedIndex >= 0 && focusedIndex < itemCount) {
            const item = paginatedItems[focusedIndex];
            handleRowSelect(item.queue_id);
          }
          break;
        }
        case 'Escape': {
          if (drawerItem) {
            e.preventDefault();
            setDrawerItem(null);
          }
          break;
        }
        case 'o': {
          if (focusedIndex >= 0 && focusedIndex < itemCount) {
            e.preventDefault();
            const item = paginatedItems[focusedIndex];
            onItemClick?.(item);
          }
          break;
        }
        default:
          break;
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [paginatedItems, focusedIndex, drawerItem, handleRowClick, handleRowSelect, onItemClick]);

  // Reset focused index when page changes
  useEffect(() => {
    setFocusedIndex(-1);
  }, [currentPage, sortKey, sortDirection]);

  // ─── Mobile card renderer ───────────────────────────────────────────
  const renderMobileCard = (item) => {
    const isActive = drawerItem?.queue_id === item.queue_id;
    const isSelected = selectedIds.includes(item.queue_id);
    const { variant: statusVariant, text: statusText, pulse } = getStatusBadge(item);

    const rawInvId = (item.investigation_id || '').replace(/^INV-/i, '');
    const rawAlertId = (item.alert_id || '').replace(/^(alert-|ALT-)/i, '');
    const displayId = item.item_type === 'investigation'
      ? `INV-${rawInvId.substring(0, 8).toUpperCase()}`
      : `ALT-${rawAlertId.substring(0, 8).toUpperCase()}`;

    return (
      <div key={item.queue_id} className={`${styles.mobileCard} ${isSelected ? styles.mobileCardSelected : ''} ${isActive ? styles.rowActive : ''}`}>
        <div className={styles.mobileCardHeader} onClick={() => handleRowClick(item.queue_id)}>
          <div className={styles.mobileCardHeaderLeft}>
            <input
              type="checkbox"
              checked={isSelected}
              onChange={(e) => { e.stopPropagation(); handleRowSelect(item.queue_id); }}
              onClick={(e) => e.stopPropagation()}
              className={styles.checkbox}
            />
            <Badge variant={severityToBadgeVariant(item.severity)} size="xs" solid>
              {(item.severity || 'unknown').toUpperCase()}
            </Badge>
            <span className={styles.itemTypeIndicator} data-type={item.item_type}>
              {item.item_type === 'investigation' ? 'I' : 'A'}
            </span>
          </div>
          <div className={styles.mobileCardHeaderRight}>
            <Badge
              variant={statusVariant}
              size="xs"
              solid
              style={pulse ? { animation: 'pulse 2s infinite' } : undefined}
            >
              {statusText}
            </Badge>
          </div>
        </div>

        <div className={styles.mobileCardBody} onClick={() => handleRowClick(item.queue_id)}>
          <div className={styles.mobileCardTitle}>{item.title || 'Untitled'}</div>
          <div className={styles.mobileCardMeta}>
            <span className={styles.mobileCardId}>{displayId}</span>
            {item.sla && (
              <span className={styles.mobileCardSla}>
                {item.sla.status === 'breached' ? 'SLA BREACHED' :
                 item.sla.status === 'at_risk' ? `SLA: ${formatTimeRemaining(item.sla.remaining)} left` :
                 item.sla.status === 'met' ? 'SLA MET' :
                 `SLA: ${formatTimeRemaining(item.sla.remaining)} left`}
              </span>
            )}
            <span className={styles.mobileCardTime}>{formatDate(item.created_at)}</span>
          </div>
        </div>

      </div>
    );
  };

  // ─── Pagination (shared between mobile and desktop) ────────────────
  const paginationBlock = items.length > 0 && (
    <div className={`${styles.pagination} ${isMobile ? styles.paginationMobile : ''}`}>
      <div className={styles.paginationInfo}>
        {((currentPage - 1) * rowsPerPage) + 1}-{Math.min(currentPage * rowsPerPage, items.length)} of {items.length}
        {selectedIds.length > 0 && (
          <span className={styles.selectionCount}> ({selectedIds.length} sel)</span>
        )}
      </div>

      <div className={styles.paginationControls}>
        {!isMobile && (
          <select
            value={rowsPerPage}
            onChange={(e) => onRowsPerPageChange?.(Number(e.target.value))}
            className={styles.rowsPerPageSelect}
          >
            {ROWS_PER_PAGE_OPTIONS.map(opt => (
              <option key={opt} value={opt}>{opt} / page</option>
            ))}
          </select>
        )}

        <div className={styles.pageButtons}>
          <button
            className={styles.pageButton}
            onClick={() => onPageChange?.(1)}
            disabled={currentPage === 1}
            aria-label="First page"
          >
            &#171;
          </button>
          <button
            className={styles.pageButton}
            onClick={() => onPageChange?.(currentPage - 1)}
            disabled={currentPage === 1}
            aria-label="Previous page"
          >
            &#8249;
          </button>

          {getPageNumbers().map((page, idx) => (
            page === '...' ? (
              <span key={`ellipsis-${idx}`} className={styles.pageEllipsis}>...</span>
            ) : (
              <button
                key={page}
                className={`${styles.pageButton} ${currentPage === page ? styles.pageButtonActive : ''}`}
                onClick={() => onPageChange?.(page)}
              >
                {page}
              </button>
            )
          ))}

          <button
            className={styles.pageButton}
            onClick={() => onPageChange?.(currentPage + 1)}
            disabled={currentPage === totalPages}
            aria-label="Next page"
          >
            &#8250;
          </button>
          <button
            className={styles.pageButton}
            onClick={() => onPageChange?.(totalPages)}
            disabled={currentPage === totalPages}
            aria-label="Last page"
          >
            &#187;
          </button>
        </div>
      </div>
    </div>
  );

  // ─── Mobile card list ──────────────────────────────────────────────
  if (isMobile) {
    return (
      <div className={styles.tableContainer}>
        {paginatedItems.length === 0 ? (
          <div className={styles.emptyState}>
            <div className={styles.emptyContent}>
              <Search size={24} className={styles.emptyIcon} />
              <p>No items match your filters</p>
            </div>
          </div>
        ) : (
          <div className={styles.mobileCardList}>
            {/* Select all bar */}
            <div className={styles.mobileSelectAll}>
              <label className={styles.mobileSelectAllLabel}>
                <input
                  type="checkbox"
                  checked={allPageSelected}
                  ref={(el) => { if (el) el.indeterminate = somePageSelected && !allPageSelected; }}
                  onChange={handleSelectAll}
                  className={styles.checkbox}
                />
                Select all on page
              </label>
            </div>
            {paginatedItems.map(renderMobileCard)}
          </div>
        )}
        {paginationBlock}
      </div>
    );
  }

  // ─── Desktop table ─────────────────────────────────────────────────
  return (
    <div className={styles.tableContainer} ref={tableRef} tabIndex={-1}>
      <div className={styles.tableScrollWrap}>
      <table className={styles.queueTable} role="grid" aria-label="Security queue">
        <thead>
          <tr>
            {/* Select all checkbox */}
            <th className={styles.headerCheckbox}>
              <input
                type="checkbox"
                checked={allPageSelected}
                ref={(el) => {
                  if (el) el.indeterminate = somePageSelected && !allPageSelected;
                }}
                onChange={handleSelectAll}
                className={styles.checkbox}
                aria-label="Select all on page"
              />
            </th>

            {/* Data columns */}
            {visibleColumns.map((colKey) => {
              const config = COLUMN_CONFIG[colKey];
              if (!config) return null;

              const isSorted = sortKey === colKey;
              const isSortable = config.sortable;

              const isDragOver = dragOverCol === colKey;

              return (
                <th
                  key={colKey}
                  className={`${styles.headerCell} ${isSortable ? styles.sortable : ''} ${isSorted ? styles.sorted : ''} ${isDragOver ? styles.headerDragOver : ''}`}
                  style={{ width: config.width, minWidth: config.minWidth || config.width }}
                  onClick={() => handleSort(colKey)}
                  draggable
                  onDragStart={(e) => handleDragStart(e, colKey)}
                  onDragEnd={handleDragEnd}
                  onDragOver={(e) => handleDragOver(e, colKey)}
                  onDrop={(e) => handleDrop(e, colKey)}
                >
                  <div className={styles.headerContent}>
                    <span className={styles.dragHandle}>{'\u2847'}</span>
                    <span>{config.label}</span>
                    {isSortable && (
                      <span className={styles.sortIndicator}>
                        {isSorted && (sortDirection === 'asc' ? '\u25B2' : '\u25BC')}
                        {!isSorted && '\u21C5'}
                      </span>
                    )}
                  </div>
                </th>
              );
            })}
          </tr>
        </thead>

        <tbody>
          {paginatedItems.length === 0 ? (
            <tr>
              <td colSpan={visibleColumns.length + 1} className={styles.emptyState}>
                <div className={styles.emptyContent}>
                  <Search size={24} className={styles.emptyIcon} />
                  <p>No items match your filters</p>
                </div>
              </td>
            </tr>
          ) : (
            paginatedItems.map((item, idx) => (
              <QueueRow
                key={item.queue_id}
                item={item}
                columns={visibleColumns}
                isSelected={selectedIds.includes(item.queue_id)}
                isActive={drawerItem?.queue_id === item.queue_id}
                isFocused={idx === focusedIndex}
                onSelect={handleRowSelect}
                onClick={() => handleRowClick(item.queue_id)}
              />
            ))
          )}
        </tbody>
      </table>
      </div>

      <Drawer
        isOpen={!!drawerItem || drawerLoading}
        onClose={() => setDrawerItem(null)}
        title={drawerItem ? (drawerItem.title || 'Details') : 'Loading...'}
        size={drawerItem?.item_type === 'investigation' ? 'xl' : 'lg'}
        position="right"
      >
        <Drawer.Body>
          {drawerLoading ? (
            <div className={styles.expandedLoading}>
              <div className={styles.loadingSpinner}></div>
              <span>Loading details...</span>
            </div>
          ) : drawerItem ? (
            <ExpandedContent
              item={drawerItem}
              onRefresh={onRefresh}
              onFieldUpdate={handleItemFieldUpdate}
              systemConfig={systemConfig}
            />
          ) : null}
        </Drawer.Body>
      </Drawer>

      {paginationBlock}
    </div>
  );
}

export default React.memo(SecurityQueueTable);
