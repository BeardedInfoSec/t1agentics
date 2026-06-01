/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Data Path Picker Component
 *
 * Visual picker for JSONPath expressions to connect node outputs to inputs.
 */

import React, { useState, useEffect } from 'react';
import { Search, ChevronRight, ChevronDown, X, Check, Copy } from 'lucide-react';

const API_BASE = process.env.REACT_APP_API_URL || '';

const mergePaths = (primary = [], secondary = []) => {
  const map = new Map();
  const addPath = (item) => {
    if (!item?.path) return;
    if (!map.has(item.path)) {
      map.set(item.path, { ...item, sample_paths: [...(item.sample_paths || [])] });
      return;
    }
    const existing = map.get(item.path);
    const mergedSamples = new Set([...(existing.sample_paths || []), ...(item.sample_paths || [])]);
    map.set(item.path, {
      ...existing,
      ...item,
      sample_paths: Array.from(mergedSamples),
      current_value: existing.current_value ?? item.current_value,
      label: existing.label || item.label,
    });
  };
  primary.forEach(addPath);
  secondary.forEach(addPath);
  return Array.from(map.values());
};

const sortPaths = (paths = []) => {
  const order = { trigger: 0, node: 1, variables: 2, context: 3 };
  return [...paths].sort((a, b) => {
    const orderDiff = (order[a.source] ?? 9) - (order[b.source] ?? 9);
    if (orderDiff !== 0) return orderDiff;
    const aLabel = a.label || a.path || '';
    const bLabel = b.label || b.path || '';
    return aLabel.localeCompare(bLabel);
  });
};

const getSourceTitle = (source) => {
  if (source.source === 'trigger') return 'Trigger Data';
  if (source.source === 'variables') return 'Variables';
  if (source.source === 'context') return 'Execution Context';
  if (source.source === 'node') return source.label ? `Node: ${source.label}` : `Node: ${source.node_id || 'node'}`;
  return source.path;
};

const getSourceSubtitle = (source) => {
  if (source.source === 'node') return source.path;
  if (source.source === 'trigger') return source.path;
  if (source.source === 'variables') return source.path;
  if (source.source === 'context') return source.path;
  return source.description || source.path;
};

function DataPathPicker({ playbookId, executionId, nodeId, nodes, edges, previewTrigger, onSelect, onClose }) {
  const [availablePaths, setAvailablePaths] = useState([]);
  const [selectedPath, setSelectedPath] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedSources, setExpandedSources] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [customPath, setCustomPath] = useState('');

  // Load available paths and auto-expand trigger
  useEffect(() => {
    loadPaths();
    setExpandedSources({ '$.trigger': true });
  }, [playbookId, executionId, nodeId, previewTrigger]);

  const loadPaths = async () => {
    setIsLoading(true);
    let apiPaths = [];

    // If we have an execution ID, fetch from API
    if (executionId) {
      try {
        const url = `${API_BASE}/api/v1/playbooks/executions/${executionId}/data-paths${nodeId ? `?node_id=${nodeId}` : ''}`;
        const response = await fetch(url);
        if (response.ok) {
          const data = await response.json();
          apiPaths = data.paths || [];
        }
      } catch (err) {
      }
    }

    // Generate paths from nodes in canvas
    const generatedPaths = generatePathsFromNodes(nodes, edges, nodeId);
    const mergedPaths = mergePaths(apiPaths, generatedPaths);
    setAvailablePaths(mergedPaths);
    setIsLoading(false);
  };

  const generatePathsFromNodes = (nodes, edges, currentNodeId) => {
    const paths = [];

    // Always add trigger path with comprehensive alert field list
    paths.push({
      source: 'trigger',
      path: '$.trigger',
      description: 'Trigger data (alert, schedule, webhook)',
      current_value: previewTrigger || undefined,
      sample_paths: [
        // --- Primary entity (most actions use this) ---
        '$.trigger.alert.entity',
        // --- Network ---
        '$.trigger.alert.src_ip',
        '$.trigger.alert.dst_ip',
        '$.trigger.alert.hostname',
        '$.trigger.alert.src_port',
        '$.trigger.alert.dst_port',
        '$.trigger.alert.protocol',
        // --- Identity ---
        '$.trigger.alert.username',
        '$.trigger.alert.email',
        '$.trigger.alert.user_agent',
        // --- File ---
        '$.trigger.alert.file_hash',
        '$.trigger.alert.file_name',
        '$.trigger.alert.file_path',
        '$.trigger.alert.process_name',
        // --- Alert metadata ---
        '$.trigger.alert.severity',
        '$.trigger.alert.title',
        '$.trigger.alert.rule_name',
        '$.trigger.alert.source',
        '$.trigger.alert.id',
        '$.trigger.alert.tenant_id',
        // --- Full objects ---
        '$.trigger.alert.raw',
        '$.trigger.alert.iocs',
        '$.trigger.alert.entities',
        '$.trigger.alert.tags',
        // --- Webhook trigger ---
        '$.trigger.webhook.body',
        '$.trigger.webhook.headers',
        // --- Schedule trigger ---
        '$.trigger.timestamp',
      ],
    });

    // Find upstream nodes
    const upstreamNodes = findUpstreamNodes(nodes, edges, currentNodeId);

    for (const node of upstreamNodes) {
      const nodePaths = getNodeOutputPaths(node);
      const nodeType = node.type === 'signal' ? node.data?.kind : node.type;
      paths.push({
        source: 'node',
        node_id: node.id,
        node_type: nodeType,
        label: node.data?.title || node.data?.label || node.id,
        path: `$.nodes.${node.id}`,
        sample_paths: nodePaths,
      });
    }

    // Add variables path
    paths.push({
      source: 'variables',
      path: '$.variables',
      description: 'Execution variables',
      sample_paths: ['$.variables.*'],
    });

    return paths;
  };

  const findUpstreamNodes = (nodes, edges, targetNodeId) => {
    const upstream = [];
    const visited = new Set();

    const traceBack = (nodeId) => {
      for (const edge of edges) {
        if (edge.target === nodeId && !visited.has(edge.source)) {
          visited.add(edge.source);
          const node = nodes.find((n) => n.id === edge.source);
          if (node) {
            upstream.push(node);
            traceBack(edge.source);
          }
        }
      }
    };

    if (targetNodeId) {
      traceBack(targetNodeId);
    } else {
      // Include all nodes if no target specified
      upstream.push(...nodes);
    }

    return upstream;
  };

  const getNodeOutputPaths = (node) => {
    const base = `$.nodes.${node.id}`;
    const nodeType = node.type === 'signal' ? node.data?.kind : node.type;

    const typeOutputs = {
      riggs_analyze: [
        `${base}.verdict`,
        `${base}.confidence`,
        `${base}.recommendations`,
        `${base}.iocs`,
        `${base}.risk_score`,
      ],
      enrich: [
        `${base}.enrichments`,
        `${base}.enrichments[*].value`,
        `${base}.enrichments[*].result`,
        `${base}.count`,
      ],
      condition: [`${base}.branch`, `${base}.evaluated_value`],
      action: [`${base}.success`, `${base}.result`, `${base}.error`],
      webform: [`${base}.form_data`, `${base}.submitted_by`],
      file_upload: [`${base}.file_id`, `${base}.filename`, `${base}.file_path`],
      list_lookup: [`${base}.found`, `${base}.value`, `${base}.item`],
      transform: [`${base}.result`],
      python_code: [`${base}.result`],
      function_call: [`${base}.result`],
      notify: [`${base}.sent`],
      create_ticket: [`${base}.ticket_id`],
      webhook_call: [`${base}.status_code`, `${base}.response`],
    };

    return typeOutputs[nodeType] || [`${base}.result`];
  };

  const toggleSource = (source) => {
    setExpandedSources((prev) => ({
      ...prev,
      [source]: !prev[source],
    }));
  };

  const filteredPaths = availablePaths.filter((p) => {
    const searchLower = searchTerm.toLowerCase();
    return (
      p.path.toLowerCase().includes(searchLower) ||
      p.description?.toLowerCase().includes(searchLower) ||
      p.label?.toLowerCase().includes(searchLower) ||
      p.sample_paths?.some((sp) => sp.toLowerCase().includes(searchLower))
    );
  });

  const sortedPaths = sortPaths(filteredPaths);

  const handleSelect = () => {
    const pathToSelect = customPath || selectedPath;
    if (pathToSelect) {
      onSelect(pathToSelect);
    }
  };

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div style={styles.header}>
          <h3 style={styles.title}>Select Data Path</h3>
          <button onClick={onClose} style={styles.closeButton}>
            <X size={18} />
          </button>
        </div>

        <div style={styles.searchWrapper}>
          <Search size={14} style={styles.searchIcon} />
          <input
            type="text"
            placeholder="Search paths..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={styles.searchInput}
          />
        </div>

        <div style={styles.content}>
          {isLoading ? (
            <div style={styles.loading}>Loading available paths...</div>
          ) : (
            <>
              {sortedPaths.map((source, idx) => (
                <div key={idx} style={styles.sourceGroup}>
                  <button
                    onClick={() => toggleSource(source.path)}
                    style={styles.sourceHeader}
                  >
                    {expandedSources[source.path] ? (
                      <ChevronDown size={16} />
                    ) : (
                      <ChevronRight size={16} />
                    )}
                    <div style={styles.sourceInfo}>
                      <span style={styles.sourceTitle}>{getSourceTitle(source)}</span>
                      {getSourceSubtitle(source) && (
                        <span style={styles.sourceSubtitle}>{getSourceSubtitle(source)}</span>
                      )}
                    </div>
                    <span
                      style={{
                        ...styles.sourceType,
                        background: getSourceColor(source.source),
                      }}
                    >
                      {source.source}
                    </span>
                  </button>

                  {expandedSources[source.path] && (
                    <div style={styles.samplePaths}>
                      {source.current_value !== undefined && (
                        <div style={styles.currentValue}>
                          <div style={styles.currentValueLabel}>Current value</div>
                          <pre style={styles.currentValueBody}>
                            {JSON.stringify(source.current_value, null, 2)}
                          </pre>
                        </div>
                      )}
                      {source.sample_paths && source.sample_paths.map((path, pidx) => (
                        <div
                          key={pidx}
                          style={{
                            ...styles.pathItem,
                            ...(selectedPath === path ? styles.pathItemSelected : {}),
                          }}
                          onClick={() => setSelectedPath(path)}
                        >
                          <code style={styles.pathCode}>{path}</code>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigator.clipboard.writeText(path);
                            }}
                            style={styles.copyButton}
                          >
                            <Copy size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </div>

        <div style={styles.customPathSection}>
          <label style={styles.customLabel}>Or enter custom path:</label>
          <input
            type="text"
            value={customPath}
            onChange={(e) => {
              setCustomPath(e.target.value);
              setSelectedPath('');
            }}
            placeholder="$.custom.path"
            style={styles.customInput}
          />
        </div>

        <div style={styles.footer}>
          <div style={styles.selectedPreview}>
            {(customPath || selectedPath) && (
              <>
                <span style={styles.previewLabel}>Selected:</span>
                <code style={styles.previewPath}>{customPath || selectedPath}</code>
              </>
            )}
          </div>
          <div style={styles.footerButtons}>
            <button onClick={onClose} style={styles.cancelButton}>
              Cancel
            </button>
            <button
              onClick={handleSelect}
              style={styles.selectButton}
              disabled={!customPath && !selectedPath}
            >
              <Check size={16} />
              Select
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

const getSourceColor = (source) => {
  const colors = {
    trigger: 'rgba(245, 158, 11, 0.2)',
    node: 'rgba(60, 179, 113, 0.2)',
    variables: 'rgba(139, 92, 246, 0.2)',
    context: 'rgba(59, 130, 246, 0.2)',
  };
  return colors[source] || 'rgba(100, 116, 139, 0.2)';
};

const styles = {
  overlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  },
  modal: {
    width: '600px',
    maxHeight: '80vh',
    background: 'var(--bg-secondary, #1e293b)',
    borderRadius: '12px',
    border: '1px solid var(--border-color, #334155)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  title: {
    margin: 0,
    fontSize: '16px',
    fontWeight: '600',
    color: 'var(--text-primary, #f0f6fc)',
  },
  closeButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: 'none',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  searchWrapper: {
    position: 'relative',
    padding: '12px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  searchIcon: {
    position: 'absolute',
    left: '32px',
    top: '50%',
    transform: 'translateY(-50%)',
    color: 'var(--text-secondary, #94a3b8)',
  },
  searchInput: {
    width: '100%',
    padding: '10px 12px 10px 36px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
  },
  content: {
    flex: 1,
    overflow: 'auto',
    padding: '12px 20px',
  },
  loading: {
    textAlign: 'center',
    padding: '40px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  sourceGroup: {
    marginBottom: '8px',
  },
  sourceHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    width: '100%',
    padding: '10px 12px',
    border: 'none',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.03)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    cursor: 'pointer',
    textAlign: 'left',
  },
  sourceInfo: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  sourceTitle: {
    fontSize: '13px',
    fontWeight: '600',
  },
  sourceSubtitle: {
    fontFamily: 'monospace',
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  sourceType: {
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: '4px',
    textTransform: 'uppercase',
    fontWeight: '500',
  },
  samplePaths: {
    padding: '8px 0 8px 28px',
  },
  currentValue: {
    border: '1px solid rgba(148, 163, 184, 0.2)',
    borderRadius: '6px',
    padding: '8px',
    marginBottom: '8px',
    background: 'rgba(15, 23, 42, 0.6)',
  },
  currentValueLabel: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
    marginBottom: '6px',
  },
  currentValueBody: {
    margin: 0,
    fontSize: '11px',
    fontFamily: 'monospace',
    color: 'var(--text-primary, #f0f6fc)',
    maxHeight: '160px',
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
  },
  pathItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '8px 12px',
    borderRadius: '4px',
    marginBottom: '4px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  pathItemSelected: {
    background: 'rgba(60, 179, 113, 0.2)',
    border: '1px solid rgba(60, 179, 113, 0.4)',
  },
  pathCode: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  copyButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '24px',
    height: '24px',
    border: 'none',
    borderRadius: '4px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
    opacity: 0.5,
  },
  customPathSection: {
    padding: '12px 20px',
    borderTop: '1px solid var(--border-color, #334155)',
  },
  customLabel: {
    display: 'block',
    fontSize: '12px',
    color: 'var(--text-secondary, #94a3b8)',
    marginBottom: '8px',
  },
  customInput: {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    fontFamily: 'monospace',
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px 20px',
    borderTop: '1px solid var(--border-color, #334155)',
    background: 'rgba(0,0,0,0.2)',
  },
  selectedPreview: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  previewLabel: {
    fontSize: '12px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  previewPath: {
    fontFamily: 'monospace',
    fontSize: '12px',
    padding: '4px 8px',
    borderRadius: '4px',
    background: 'rgba(60, 179, 113, 0.2)',
    color: '#3CB371',
  },
  footerButtons: {
    display: 'flex',
    gap: '8px',
  },
  cancelButton: {
    padding: '10px 16px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
    cursor: 'pointer',
  },
  selectButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '10px 16px',
    border: 'none',
    borderRadius: '6px',
    background: 'linear-gradient(135deg, #3CB371, #2e8b57)',
    color: 'white',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
  },
};

export default DataPathPicker;
