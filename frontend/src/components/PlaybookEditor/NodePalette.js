/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Node Palette Component
 *
 * Displays available node types that can be dragged onto the canvas.
 */

import React, { useState } from 'react';
import {
  Zap, Bot, Shield, GitBranch, Code, FileText, Clock,
  Mail, Database, Upload, List, Variable, Bell,
  Ticket, Globe, Timer, Calendar, Square, Search,
  ChevronDown, ChevronRight, ChevronLeft
} from 'lucide-react';

const nodeCategories = [
  {
    name: 'Triggers',
    icon: Zap,
    color: '#f59e0b',
    nodes: [
      { type: 'trigger', label: 'Alert Trigger', description: 'Triggered when an alert matches' },
    ],
  },
  {
    name: 'AI',
    icon: Bot,
    color: '#8b5cf6',
    nodes: [
      { type: 'riggs_analyze', label: 'Riggs Analysis', description: 'AI-powered alert analysis' },
    ],
  },
  {
    name: 'Enrichment',
    icon: Search,
    color: '#3b82f6',
    nodes: [
      { type: 'enrich', label: 'Enrich IOCs', description: 'Enrich indicators via integrations' },
    ],
  },
  {
    name: 'Actions',
    icon: Shield,
    color: '#ef4444',
    nodes: [
      { type: 'action', label: 'Response Action', description: 'Execute a response action' },
      { type: 'approval_gate', label: 'Approval Gate', description: 'Wait for human approval' },
    ],
  },
  {
    name: 'Logic',
    icon: GitBranch,
    color: '#3CB371',
    nodes: [
      { type: 'condition', label: 'Condition', description: 'If/else branching' },
      { type: 'switch', label: 'Switch', description: 'Multi-way branching' },
      { type: 'loop', label: 'Loop', description: 'Iterate over a list' },
      { type: 'parallel', label: 'Parallel', description: 'Execute branches in parallel' },
      { type: 'merge', label: 'Merge', description: 'Merge parallel branches' },
    ],
  },
  {
    name: 'Code',
    icon: Code,
    color: '#06b6d4',
    nodes: [
      { type: 'python_code', label: 'Python Code', description: 'Custom Python (sandboxed)' },
      { type: 'function_call', label: 'Function Call', description: 'Call saved function' },
      { type: 'transform', label: 'Transform', description: 'Data transformation' },
    ],
  },
  {
    name: 'User Input',
    icon: FileText,
    color: '#ec4899',
    nodes: [
      { type: 'webform', label: 'Webform', description: 'Collect data via form' },
      { type: 'file_upload', label: 'File Upload', description: 'Request file upload' },
      { type: 'user_input', label: 'User Input', description: 'Simple text/choice input' },
    ],
  },
  {
    name: 'Data',
    icon: Database,
    color: '#14b8a6',
    nodes: [
      { type: 'list_lookup', label: 'List Lookup', description: 'Check against list' },
      { type: 'list_update', label: 'List Update', description: 'Add/remove from list' },
      { type: 'variable_set', label: 'Set Variable', description: 'Set execution variable' },
      { type: 'variable_get', label: 'Get Variable', description: 'Get execution variable' },
    ],
  },
  {
    name: 'Communication',
    icon: Bell,
    color: '#f97316',
    nodes: [
      { type: 'notify', label: 'Notify', description: 'Send notification' },
      { type: 'create_ticket', label: 'Create Ticket', description: 'Create ticket' },
      { type: 'webhook_call', label: 'Webhook', description: 'Call external webhook' },
    ],
  },
  {
    name: 'Flow Control',
    icon: Clock,
    color: '#64748b',
    nodes: [
      { type: 'delay', label: 'Delay', description: 'Wait for duration' },
      { type: 'schedule', label: 'Schedule', description: 'Schedule future execution' },
      { type: 'end', label: 'End', description: 'End playbook execution' },
    ],
  },
];

function NodePalette({ onAddNode, onCollapse }) {
  const [expandedCategories, setExpandedCategories] = useState(
    nodeCategories.reduce((acc, cat) => ({ ...acc, [cat.name]: true }), {})
  );
  const [searchTerm, setSearchTerm] = useState('');

  const toggleCategory = (categoryName) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [categoryName]: !prev[categoryName],
    }));
  };

  const filteredCategories = nodeCategories
    .map((category) => ({
      ...category,
      nodes: category.nodes.filter(
        (node) =>
          node.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
          node.description.toLowerCase().includes(searchTerm.toLowerCase())
      ),
    }))
    .filter((category) => category.nodes.length > 0);

  const handleDragStart = (e, nodeType) => {
    e.dataTransfer.setData('application/reactflow', nodeType);
    e.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div style={styles.palette}>
      <div style={styles.header}>
        <h3 style={styles.title}>Nodes</h3>
        <button onClick={onCollapse} style={styles.collapseButton}>
          <ChevronLeft size={18} />
        </button>
      </div>

      <div style={styles.searchWrapper}>
        <Search size={14} style={styles.searchIcon} />
        <input
          type="text"
          placeholder="Search nodes..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={styles.searchInput}
        />
      </div>

      <div style={styles.categories}>
        {filteredCategories.map((category) => (
          <div key={category.name} style={styles.category}>
            <button
              onClick={() => toggleCategory(category.name)}
              style={styles.categoryHeader}
            >
              <div style={styles.categoryTitle}>
                <category.icon size={16} style={{ color: category.color }} />
                <span>{category.name}</span>
              </div>
              {expandedCategories[category.name] ? (
                <ChevronDown size={16} />
              ) : (
                <ChevronRight size={16} />
              )}
            </button>

            {expandedCategories[category.name] && (
              <div style={styles.nodeList}>
                {category.nodes.map((node) => (
                  <div
                    key={node.type}
                    style={styles.nodeItem}
                    draggable
                    onDragStart={(e) => handleDragStart(e, node.type)}
                    onClick={() => onAddNode(node.type)}
                  >
                    <div
                      style={{
                        ...styles.nodeIndicator,
                        background: category.color,
                      }}
                    />
                    <div style={styles.nodeInfo}>
                      <div style={styles.nodeLabel}>{node.label}</div>
                      <div style={styles.nodeDescription}>{node.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const styles = {
  palette: {
    width: '260px',
    borderRight: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-secondary, #1e293b)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  title: {
    margin: 0,
    fontSize: '14px',
    fontWeight: '600',
    color: 'var(--text-primary, #f0f6fc)',
  },
  collapseButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '28px',
    height: '28px',
    border: 'none',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  searchWrapper: {
    position: 'relative',
    padding: '12px 16px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  searchIcon: {
    position: 'absolute',
    left: '28px',
    top: '50%',
    transform: 'translateY(-50%)',
    color: 'var(--text-secondary, #94a3b8)',
  },
  searchInput: {
    width: '100%',
    padding: '8px 12px 8px 32px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
  },
  categories: {
    flex: 1,
    overflow: 'auto',
    padding: '8px',
  },
  category: {
    marginBottom: '4px',
  },
  categoryHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
    padding: '10px 12px',
    border: 'none',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'background 0.2s',
  },
  categoryTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  nodeList: {
    padding: '4px 0 4px 16px',
  },
  nodeItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '10px',
    padding: '10px 12px',
    borderRadius: '6px',
    marginBottom: '4px',
    background: 'rgba(255,255,255,0.03)',
    cursor: 'grab',
    transition: 'all 0.2s',
  },
  nodeIndicator: {
    width: '4px',
    height: '32px',
    borderRadius: '2px',
    flexShrink: 0,
  },
  nodeInfo: {
    flex: 1,
    minWidth: 0,
  },
  nodeLabel: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-primary, #f0f6fc)',
    marginBottom: '2px',
  },
  nodeDescription: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
    lineHeight: '1.3',
  },
};

export default NodePalette;
