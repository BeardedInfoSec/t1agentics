/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import Button from './ui/Button';

/**
 * Column Customizer Component
 * Splunk-style column management: add/remove, reorder, save preferences
 */
function ColumnCustomizer({ availableColumns, selectedColumns, onColumnsChange, onClose, defaultColumns }) {
  const [selected, setSelected] = useState(selectedColumns || []);
  const [searchTerm, setSearchTerm] = useState('');
  const [draggedItem, setDraggedItem] = useState(null);

  const availableToAdd = availableColumns.filter(col => !selected.includes(col.key));
  const filteredAvailable = availableToAdd.filter(col =>
    col.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
    col.key.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleAdd = (columnKey) => {
    if (selected.length < 20) {
      setSelected([...selected, columnKey]);
    }
  };

  const handleRemove = (columnKey) => {
    setSelected(selected.filter(k => k !== columnKey));
  };

  const handleDragStart = (e, index) => {
    setDraggedItem(index);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e, index) => {
    e.preventDefault();
    if (draggedItem === null || draggedItem === index) return;

    const newSelected = [...selected];
    const draggedColumn = newSelected[draggedItem];
    newSelected.splice(draggedItem, 1);
    newSelected.splice(index, 0, draggedColumn);

    setSelected(newSelected);
    setDraggedItem(index);
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
  };

  const handleApply = () => {
    onColumnsChange(selected);
    onClose();
  };

  const handleReset = () => {
    // Use provided defaultColumns or fallback to a generic set
    const resetColumns = defaultColumns || availableColumns.slice(0, 6).map(c => c.key);
    setSelected(resetColumns);
  };

  const getColumnLabel = (key) => {
    const col = availableColumns.find(c => c.key === key);
    return col ? col.label : key;
  };

  return (
    <>
      {/* Overlay */}
      <div 
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 999,
          backdropFilter: 'blur(2px)'
        }}
        onClick={onClose}
      />

      {/* Modal */}
      <div style={{
        position: 'fixed',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        width: '800px',
        maxWidth: '90vw',
        maxHeight: '90vh',
        background: 'var(--bg-primary)',
        borderRadius: '12px',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.8)',
        zIndex: 1000,
        display: 'flex',
        flexDirection: 'column',
        border: '1px solid rgba(100, 116, 139, 0.3)'
      }}>
        {/* Header */}
        <div style={{
          padding: '1.5rem',
          borderBottom: '2px solid rgba(100, 116, 139, 0.2)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '700', margin: 0 }}>
            Table Settings
          </h2>
          <Button variant="ghost" size="sm" iconOnly onClick={onClose}>
            ✕
          </Button>
        </div>

        {/* Content */}
        <div style={{ 
          flex: 1, 
          display: 'grid', 
          gridTemplateColumns: '1fr 1fr',
          gap: '1.5rem',
          padding: '1.5rem',
          overflow: 'hidden'
        }}>
          {/* Available Columns */}
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ 
                display: 'block', 
                fontSize: '0.875rem', 
                fontWeight: '600', 
                marginBottom: '0.5rem',
                color: 'var(--text-primary)'
              }}>
                Available columns
              </label>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                Add columns from the list by selecting attributes.
              </p>
              <input
                type="text"
                placeholder="Search attributes to add columns"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.625rem',
                  background: 'var(--bg-secondary)',
                  border: '1px solid rgba(100, 116, 139, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.875rem'
                }}
              />
              <div style={{ 
                fontSize: '0.75rem', 
                color: 'var(--text-muted)', 
                marginTop: '0.5rem' 
              }}>
                {filteredAvailable.length} available
              </div>
            </div>
            
            <div style={{
              flex: 1,
              overflowY: 'auto',
              background: 'var(--bg-secondary)',
              border: '1px solid rgba(100, 116, 139, 0.2)',
              borderRadius: '8px',
              padding: '0.5rem'
            }}>
              {filteredAvailable.map(col => (
                <div
                  key={col.key}
                  onClick={() => handleAdd(col.key)}
                  style={{
                    padding: '0.625rem',
                    cursor: selected.length >= 20 ? 'not-allowed' : 'pointer',
                    borderRadius: '4px',
                    fontSize: '0.875rem',
                    transition: 'background 0.15s',
                    opacity: selected.length >= 20 ? 0.5 : 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                  onMouseEnter={(e) => {
                    if (selected.length < 20) {
                      e.currentTarget.style.background = 'rgba(100, 116, 139, 0.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent';
                  }}
                >
                  <input 
                    type="checkbox" 
                    checked={false}
                    readOnly
                    style={{ margin: 0 }}
                  />
                  {col.label}
                </div>
              ))}
            </div>
          </div>

          {/* Selected Columns */}
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ 
                display: 'block', 
                fontSize: '0.875rem', 
                fontWeight: '600', 
                marginBottom: '0.5rem',
                color: 'var(--text-primary)'
              }}>
                Selected columns
              </label>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                Sort the order of the columns for display.
              </p>
              <div style={{ 
                fontSize: '0.75rem', 
                color: 'var(--text-muted)' 
              }}>
                {selected.length} selected
                <span style={{ float: 'right' }}>Maximum 20</span>
              </div>
            </div>

            <div style={{
              flex: 1,
              overflowY: 'auto',
              background: 'var(--bg-secondary)',
              border: '1px solid rgba(100, 116, 139, 0.2)',
              borderRadius: '8px',
              padding: '0.5rem'
            }}>
              {selected.map((colKey, index) => (
                <div
                  key={colKey}
                  draggable
                  onDragStart={(e) => handleDragStart(e, index)}
                  onDragOver={(e) => handleDragOver(e, index)}
                  onDragEnd={handleDragEnd}
                  style={{
                    padding: '0.625rem',
                    borderRadius: '4px',
                    fontSize: '0.875rem',
                    background: draggedItem === index ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                    border: draggedItem === index ? '2px dashed rgba(59, 130, 246, 0.5)' : '2px solid transparent',
                    marginBottom: '0.25rem',
                    cursor: 'move',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    transition: 'all 0.15s'
                  }}
                  onMouseEnter={(e) => {
                    if (draggedItem !== index) {
                      e.currentTarget.style.background = 'rgba(100, 116, 139, 0.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (draggedItem !== index) {
                      e.currentTarget.style.background = 'transparent';
                    }
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ color: 'var(--text-muted)', cursor: 'grab' }}>⋮⋮</span>
                    {getColumnLabel(colKey)}
                  </div>
                  <Button variant="ghost" size="xs" iconOnly onClick={() => handleRemove(colKey)}>
                    ✕
                  </Button>
                </div>
              ))}
            </div>

            <div style={{ marginTop: '1rem' }}>
              <Button variant="secondary" fullWidth onClick={handleReset}>
                Reset table settings
              </Button>
              <p style={{ fontSize: '0.688rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Restore the alert queue to its default layout, including which columns are shown and their widths.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '2px solid rgba(100, 116, 139, 0.2)',
          display: 'flex',
          gap: '1rem',
          justifyContent: 'flex-end'
        }}>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="info" onClick={handleApply}>
            Apply
          </Button>
        </div>
      </div>
    </>
  );
}

export default ColumnCustomizer;
