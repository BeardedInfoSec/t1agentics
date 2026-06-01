/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, Link, useLocation, useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import './ThreatIntelShell.css';

const API_BASE = `${API_BASE_URL}/api/v1/threat-intel`;

// Interactive JSON Tree Visualizer Component
// expandLevel: 'tree' = expand 5 levels, 'compact' = expand 3 levels, 'all' = expand everything, 'none' = collapse all
const JsonTreeNode = ({ data, keyName, depth = 0, expandLevel = 'tree', onCopy }) => {
  // Determine initial expanded state based on expandLevel
  const getInitialExpanded = () => {
    if (expandLevel === 'all') return true;
    if (expandLevel === 'none') return false;
    const maxDepth = expandLevel === 'tree' ? 5 : 3;
    return depth < maxDepth;
  };

  const [expanded, setExpanded] = useState(getInitialExpanded);

  // Re-sync when expandLevel changes (switching between Tree/Compact or Expand/Collapse All)
  useEffect(() => {
    if (expandLevel === 'all') {
      setExpanded(true);
    } else if (expandLevel === 'none') {
      setExpanded(false);
    } else {
      const maxDepth = expandLevel === 'tree' ? 5 : 3;
      setExpanded(depth < maxDepth);
    }
  }, [expandLevel, depth]);

  const getValueColor = (value) => {
    if (value === null) return '#f472b6'; // pink
    if (typeof value === 'boolean') return '#c084fc'; // purple
    if (typeof value === 'number') return '#60a5fa'; // blue
    if (typeof value === 'string') {
      // URLs
      if (value.match(/^https?:\/\//)) return '#22d3ee'; // cyan
      // Emails
      if (value.includes('@') && value.includes('.')) return '#a78bfa'; // violet
      // IPs
      if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) return '#f59e0b'; // amber
      // Hashes
      if (value.match(/^[a-f0-9]{32,64}$/i)) return '#fb923c'; // orange
      return '#4ade80'; // green
    }
    return 'var(--text-primary)';
  };

  const formatValue = (value) => {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value.toString();
    if (typeof value === 'string') return `"${value}"`;
    return String(value);
  };

  const isExpandable = (val) => val !== null && typeof val === 'object';
  const isArray = Array.isArray(data);
  const entries = isExpandable(data) ? Object.entries(data) : [];
  const isEmpty = entries.length === 0;

  // Leaf node (primitive value)
  if (!isExpandable(data)) {
    return (
      <span
        style={{
          color: getValueColor(data),
          cursor: 'pointer',
          padding: '0 2px',
          borderRadius: '2px',
          transition: 'background 0.15s'
        }}
        onClick={() => onCopy?.(typeof data === 'string' ? data : formatValue(data))}
        onMouseEnter={(e) => e.target.style.background = 'rgba(255,255,255,0.1)'}
        onMouseLeave={(e) => e.target.style.background = 'transparent'}
        title="Click to copy"
      >
        {formatValue(data)}
      </span>
    );
  }

  // Empty object/array
  if (isEmpty) {
    return <span style={{ color: 'var(--text-muted)' }}>{isArray ? '[]' : '{}'}</span>;
  }

  return (
    <div style={{ marginLeft: depth > 0 ? '1rem' : 0 }}>
      {keyName !== undefined && (
        <span
          onClick={() => setExpanded(!expanded)}
          style={{
            cursor: 'pointer',
            userSelect: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.25rem'
          }}
        >
          <span style={{
            color: 'var(--text-muted)',
            fontSize: '0.6rem',
            width: '0.8rem',
            transition: 'transform 0.15s'
          }}>
            {expanded ? '▼' : '▶'}
          </span>
          <span style={{ color: '#93c5fd', fontWeight: 500 }}>{keyName}</span>
          <span style={{ color: 'var(--text-muted)' }}>:</span>
          {!expanded && (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginLeft: '0.25rem' }}>
              {isArray ? `[${entries.length}]` : `{${entries.length}}`}
            </span>
          )}
        </span>
      )}

      {(expanded || keyName === undefined) && (
        <div style={{
          borderLeft: depth > 0 ? '1px solid var(--border-color)' : 'none',
          paddingLeft: depth > 0 ? '0.5rem' : 0,
          marginLeft: keyName !== undefined ? '0.4rem' : 0
        }}>
          {entries.map(([key, value], idx) => (
            <div key={key} style={{
              padding: '0.15rem 0',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.25rem'
            }}>
              {isExpandable(value) ? (
                <JsonTreeNode
                  data={value}
                  keyName={isArray ? `[${key}]` : key}
                  depth={depth + 1}
                  expandLevel={expandLevel}
                  onCopy={onCopy}
                />
              ) : (
                <>
                  <span style={{ color: isArray ? 'var(--text-muted)' : '#93c5fd', fontWeight: isArray ? 400 : 500 }}>
                    {isArray ? `[${key}]` : key}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>:</span>
                  <JsonTreeNode data={value} depth={depth + 1} onCopy={onCopy} />
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Color helpers for JSON visualization
const getValueColor = (value) => {
  if (value === null) return '#f472b6'; // pink
  if (typeof value === 'boolean') return '#c084fc'; // purple
  if (typeof value === 'number') return '#60a5fa'; // blue
  if (typeof value === 'string') {
    if (value.match(/^https?:\/\//)) return '#22d3ee'; // cyan - URL
    if (value.includes('@') && value.includes('.')) return '#a78bfa'; // violet - email
    if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) return '#f59e0b'; // amber - IP
    if (value.match(/^[a-f0-9]{32,64}$/i)) return '#fb923c'; // orange - hash
    return '#4ade80'; // green
  }
  return 'var(--text-primary)';
};

const getTypeLabel = (value) => {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'object') return 'object';
  return typeof value;
};

// Helper to get initial expanded nodes (3 levels deep)
const getInitialExpandedNodes = (obj, path = 'root', depth = 0) => {
  const expanded = new Set();
  if (depth < 3 && obj !== null && typeof obj === 'object') {
    expanded.add(path);
    Object.entries(obj).forEach(([key, val]) => {
      const childPath = `${path}.${key}`;
      const childExpanded = getInitialExpandedNodes(val, childPath, depth + 1);
      childExpanded.forEach(id => expanded.add(id));
    });
  }
  return expanded;
};

// Graph View Component - Node-based JSON visualization with physics
const JsonGraphView = ({ data, onCopy, expandAllState }) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 20 }); // Start with offset to show root
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [containerHeight, setContainerHeight] = useState(400);
  // Initialize with 3 levels expanded, or all/none based on expandAllState
  const [expandedNodes, setExpandedNodes] = useState(() => {
    if (expandAllState === 'expanded') {
      // Expand all nodes
      const allExpandable = new Set();
      const traverse = (obj, path = 'root') => {
        if (obj !== null && typeof obj === 'object') {
          allExpandable.add(path);
          Object.entries(obj).forEach(([key, val]) => {
            traverse(val, `${path}.${key}`);
          });
        }
      };
      traverse(data);
      return allExpandable;
    }
    if (expandAllState === 'collapsed') {
      return new Set(['root']); // Only root expanded
    }
    return getInitialExpandedNodes(data);
  });
  const containerRef = useRef(null);

  // Node dragging state
  const [draggingNodeId, setDraggingNodeId] = useState(null);
  const [nodeOffsets, setNodeOffsets] = useState({}); // Manual position offsets
  const [tooltip, setTooltip] = useState({ visible: false, content: '', x: 0, y: 0 });
  const lastDragPos = useRef({ x: 0, y: 0 });

  // Calculate available height on mount and resize - use maximum space
  useEffect(() => {
    const calculateHeight = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Use all available height minus small bottom padding (20px)
        const availableHeight = window.innerHeight - rect.top - 20;
        setContainerHeight(Math.max(300, availableHeight));
      }
    };

    calculateHeight();
    window.addEventListener('resize', calculateHeight);
    return () => window.removeEventListener('resize', calculateHeight);
  }, []);

  // Toggle node expansion
  const toggleNode = (nodeId) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        // Collapse: remove this node and all its children
        for (const id of next) {
          if (id.startsWith(nodeId + '.')) {
            next.delete(id);
          }
        }
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  };

  // Build tree structure with proper parent-child relationships
  const buildTree = useCallback(() => {
    const nodes = [];
    const connections = [];
    const nodeMap = new Map(); // Track node info for positioning

    const traverse = (obj, path = 'root', depth = 0, parentId = null, siblingIndex = 0) => {
      const nodeId = path;
      const isExpandable = obj !== null && typeof obj === 'object';
      const isArray = Array.isArray(obj);
      const isExpanded = expandedNodes.has(nodeId);

      // Get child keys for expandable nodes (to show in tooltip)
      const childKeys = isExpandable ? Object.keys(obj) : [];

      const node = {
        id: nodeId,
        label: path === 'root' ? 'Response' : path.split('.').pop(),
        value: isExpandable ? null : obj,
        type: getTypeLabel(obj),
        depth,
        isExpandable,
        isArray,
        isExpanded,
        childCount: isExpandable ? childKeys.length : 0,
        childKeys,  // Store child keys for tooltip
        parentId,
        siblingIndex
      };

      nodes.push(node);
      nodeMap.set(nodeId, node);

      if (parentId) {
        connections.push({ from: parentId, to: nodeId });
      }

      // Only expand children if this node is expanded
      if (isExpandable && isExpanded) {
        Object.entries(obj).forEach(([key, val], idx) => {
          const childPath = `${path}.${key}`;
          traverse(val, childPath, depth + 1, nodeId, idx);
        });
      }
    };

    traverse(data);
    return { nodes, connections, nodeMap };
  }, [data, expandedNodes]);

  const { nodes, connections, nodeMap } = buildTree();

  // Position nodes using a proper tree layout algorithm
  const positionNodes = useCallback(() => {
    const positioned = {};
    const NODE_WIDTH = 180;
    const NODE_HEIGHT = 50;
    const H_SPACING = 40; // Horizontal spacing between levels
    const V_SPACING = 10; // Vertical spacing between siblings

    // Calculate subtree heights for each node (bottom-up)
    const subtreeHeights = new Map();

    const calcSubtreeHeight = (nodeId) => {
      const node = nodeMap.get(nodeId);
      if (!node) return NODE_HEIGHT;

      // Find children of this node
      const children = nodes.filter(n => n.parentId === nodeId);

      if (children.length === 0) {
        subtreeHeights.set(nodeId, NODE_HEIGHT);
        return NODE_HEIGHT;
      }

      let totalHeight = 0;
      children.forEach((child, idx) => {
        if (idx > 0) totalHeight += V_SPACING;
        totalHeight += calcSubtreeHeight(child.id);
      });

      subtreeHeights.set(nodeId, totalHeight);
      return totalHeight;
    };

    // Start from root
    calcSubtreeHeight('root');

    // Position nodes (top-down) - keep nodes aligned to top of their subtree region
    const positionNode = (nodeId, x, yStart, isRoot = false) => {
      const node = nodeMap.get(nodeId);
      if (!node) return;

      // Root stays at top, children center in their subtree
      const y = isRoot ? yStart : yStart;

      positioned[nodeId] = {
        x,
        y,
        ...node
      };

      // Position children stacked vertically
      const children = nodes.filter(n => n.parentId === nodeId);
      let childY = yStart;

      children.forEach(child => {
        const childSubtreeH = subtreeHeights.get(child.id) || NODE_HEIGHT;
        positionNode(child.id, x + NODE_WIDTH + H_SPACING, childY, false);
        childY += childSubtreeH + V_SPACING;
      });
    };

    positionNode('root', 20, 20, true);

    return positioned;
  }, [nodes, nodeMap]);

  const positionedNodes = positionNodes();

  // Calculate SVG dimensions
  const nodeValues = Object.values(positionedNodes);
  const maxX = nodeValues.length > 0 ? Math.max(...nodeValues.map(n => n.x)) + 200 : 400;
  const maxY = nodeValues.length > 0 ? Math.max(...nodeValues.map(n => n.y)) + 70 : 300;

  // Get all descendant node IDs for a given node
  const getDescendants = useCallback((nodeId) => {
    const descendants = [];
    const stack = [nodeId];
    while (stack.length > 0) {
      const current = stack.pop();
      const children = nodes.filter(n => n.parentId === current);
      children.forEach(child => {
        descendants.push(child.id);
        stack.push(child.id);
      });
    }
    return descendants;
  }, [nodes]);

  // Handle panning or node dragging
  const handleMouseDown = (e) => {
    // Don't start drag if clicking on expand button
    if (e.target.closest('.expand-btn')) {
      return;
    }

    // Check if clicking on a node
    const nodeElement = e.target.closest('.graph-node');
    if (nodeElement) {
      const nodeId = nodeElement.getAttribute('data-node-id');
      if (nodeId) {
        e.preventDefault();
        e.stopPropagation();
        setDraggingNodeId(nodeId);
        // Store raw screen coordinates
        lastDragPos.current = { x: e.clientX, y: e.clientY };
        return;
      }
    }

    // Background panning
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e) => {
    if (draggingNodeId) {
      // Calculate delta in screen space, then convert to SVG space
      const deltaX = (e.clientX - lastDragPos.current.x) / zoom;
      const deltaY = (e.clientY - lastDragPos.current.y) / zoom;

      // Move the dragged node directly
      setNodeOffsets(prev => {
        const newOffsets = { ...prev };

        // Update dragged node
        newOffsets[draggingNodeId] = {
          x: (prev[draggingNodeId]?.x || 0) + deltaX,
          y: (prev[draggingNodeId]?.y || 0) + deltaY
        };

        // Move descendants with decreasing strength (fluid following effect)
        const descendants = getDescendants(draggingNodeId);
        descendants.forEach((descId, index) => {
          // Deeper nodes follow less immediately
          const followStrength = Math.max(0.1, 0.7 - index * 0.1);
          newOffsets[descId] = {
            x: (prev[descId]?.x || 0) + deltaX * followStrength,
            y: (prev[descId]?.y || 0) + deltaY * followStrength
          };
        });

        return newOffsets;
      });

      lastDragPos.current = { x: e.clientX, y: e.clientY };
    } else if (isDragging) {
      // Background panning
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => {
    setDraggingNodeId(null);
    setIsDragging(false);
  };

  // Show tooltip for truncated values - position above the element
  const showTooltip = (content, e) => {
    const containerRect = containerRef.current.getBoundingClientRect();
    // Get the bounding rect of the element being hovered (works correctly with SVG elements)
    const targetRect = e.target.getBoundingClientRect();

    // Position tooltip centered above the hovered element
    const tooltipX = targetRect.left + (targetRect.width / 2) - containerRect.left;
    const tooltipY = targetRect.top - containerRect.top;

    setTooltip({
      visible: true,
      content: String(content),
      x: tooltipX,
      y: tooltipY
    });
  };

  const hideTooltip = () => {
    setTooltip(prev => ({ ...prev, visible: false }));
  };

  return (
    <div ref={containerRef} style={{ position: 'relative' }}>
      {/* Controls - zoom and layout only (Expand/Collapse All moved to toolbar) */}
      <div style={{
        position: 'absolute',
        top: '0.5rem',
        right: '0.5rem',
        display: 'flex',
        gap: '0.25rem',
        zIndex: 10
      }}>
        <button onClick={() => setZoom(z => Math.min(z + 0.15, 2))} style={zoomBtnStyle}>+</button>
        <button onClick={() => setZoom(z => Math.max(z - 0.15, 0.3))} style={zoomBtnStyle}>−</button>
        <button onClick={() => { setZoom(1); setPan({ x: 20, y: 20 }); }} style={zoomBtnStyle}>Reset View</button>
        <button onClick={() => setNodeOffsets({})} style={zoomBtnStyle}>Reset Layout</button>
      </div>

      <div
        style={{
          background: 'var(--bg-tertiary)',
          backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.08) 1px, transparent 1px)',
          backgroundSize: '20px 20px',
          borderRadius: '6px',
          overflow: 'hidden',
          height: `${containerHeight}px`,
          cursor: draggingNodeId ? 'grabbing' : (isDragging ? 'grabbing' : 'grab')
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          width="100%"
          height="100%"
          viewBox={`0 0 ${900} ${containerHeight}`}
        >
          {/* Use a group with transform for pan/zoom - more stable than viewBox changes */}
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            <rect className="graph-bg" x={-2000} y={-2000} width={maxX + 4000} height={maxY + 4000} fill="transparent" />

          {/* Draw connections with offset support */}
          {connections.map((conn, i) => {
            const from = positionedNodes[conn.from];
            const to = positionedNodes[conn.to];
            if (!from || !to) return null;

            // Apply offsets to connection endpoints
            const fromOffset = nodeOffsets[conn.from] || { x: 0, y: 0 };
            const toOffset = nodeOffsets[conn.to] || { x: 0, y: 0 };

            const startX = from.x + fromOffset.x + 180;
            const startY = from.y + fromOffset.y + 20;
            const endX = to.x + toOffset.x;
            const endY = to.y + toOffset.y + 20;
            const midX = (startX + endX) / 2;

            return (
              <path
                key={i}
                d={`M ${startX} ${startY} C ${midX} ${startY}, ${midX} ${endY}, ${endX} ${endY}`}
                fill="none"
                stroke="var(--border-color)"
                strokeWidth="1.5"
                opacity="0.6"
              />
            );
          })}

          {/* Draw nodes with offset support */}
          {Object.values(positionedNodes).map(node => {
            const offset = nodeOffsets[node.id] || { x: 0, y: 0 };
            const nodeX = node.x + offset.x;
            const nodeY = node.y + offset.y;
            const isTruncatedLabel = node.label.length > 18;
            const isTruncatedValue = !node.isExpandable && String(node.value).length > 20;

            return (
              <g
                key={node.id}
                className="graph-node"
                data-node-id={node.id}
                transform={`translate(${nodeX}, ${nodeY})`}
                style={{ cursor: draggingNodeId === node.id ? 'grabbing' : 'grab' }}
              >
                <rect
                  x="0"
                  y="0"
                  width="180"
                  height="40"
                  rx="6"
                  fill="var(--bg-secondary)"
                  stroke={draggingNodeId === node.id ? '#f59e0b' : (node.isExpandable ? (node.isExpanded ? '#22c55e' : '#3b82f6') : getValueColor(node.value))}
                  strokeWidth={draggingNodeId === node.id ? 2 : 1.5}
                />
                {/* Expand/collapse button - ONLY this triggers toggle */}
                {node.isExpandable && (
                  <g
                    className="expand-btn"
                    transform="translate(165, 12)"
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      e.preventDefault();
                      toggleNode(node.id);
                    }}
                    onMouseDown={(e) => {
                      // Prevent node drag when clicking expand button
                      e.stopPropagation();
                    }}
                  >
                    {/* Larger invisible hit area */}
                    <circle r="12" fill="transparent" />
                    {/* Visible button */}
                    <circle r="8" fill={node.isExpanded ? '#22c55e' : '#3b82f6'} opacity="0.2" />
                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fill={node.isExpanded ? '#22c55e' : '#3b82f6'}
                      fontSize="10"
                      fontWeight="bold"
                      style={{ pointerEvents: 'none' }}
                    >
                      {node.isExpanded ? '−' : '+'}
                    </text>
                  </g>
                )}
                {/* Label text - always show tooltip on hover */}
                <text
                  x="10"
                  y="16"
                  fill="#93c5fd"
                  fontSize="11"
                  fontWeight="600"
                  fontFamily="ui-monospace, monospace"
                  onMouseEnter={(e) => showTooltip(node.label, e)}
                  onMouseLeave={hideTooltip}
                  style={{ cursor: 'help' }}
                >
                  {isTruncatedLabel ? node.label.substring(0, 16) + '...' : node.label}
                </text>
                {/* Value text - show child keys for expandable, full value otherwise */}
                <text
                  x="10"
                  y="32"
                  fill={node.isExpandable ? 'var(--text-muted)' : getValueColor(node.value)}
                  fontSize="10"
                  fontFamily="ui-monospace, monospace"
                  style={{ cursor: node.isExpandable ? 'help' : 'pointer' }}
                  onMouseEnter={(e) => {
                    if (node.isExpandable) {
                      // Show child key names for expandable nodes
                      const childList = node.childKeys.slice(0, 15).join('\n');
                      const moreCount = node.childKeys.length - 15;
                      const tooltipText = moreCount > 0
                        ? `${childList}\n... and ${moreCount} more`
                        : childList;
                      showTooltip(tooltipText, e);
                    } else {
                      // Show full value for leaf nodes
                      showTooltip(node.value, e);
                    }
                  }}
                  onMouseLeave={hideTooltip}
                  onClick={(e) => {
                    if (!node.isExpandable) {
                      e.stopPropagation();
                      onCopy?.(String(node.value));
                    }
                  }}
                >
                  {node.isExpandable
                    ? `${node.isArray ? '[ ' : '{ '}${node.childCount} items${node.isArray ? ' ]' : ' }'}`
                    : isTruncatedValue
                      ? String(node.value).substring(0, 18) + '...'
                      : String(node.value)}
                </text>
              </g>
            );
          })}
          </g>
        </svg>
      </div>

      {/* Tooltip for truncated values - positioned ABOVE the hovered element */}
      {tooltip.visible && (
        <div
          style={{
            position: 'absolute',
            left: tooltip.x,
            top: tooltip.y,
            transform: 'translate(-50%, calc(-100% - 8px))',  // Center horizontally, position fully above with 8px gap
            background: '#1a1a2e',
            border: '1px solid #3b82f6',
            borderRadius: '6px',
            padding: '0.5rem 0.75rem',
            fontSize: '0.75rem',
            fontFamily: 'ui-monospace, monospace',
            color: '#e2e8f0',
            maxWidth: '450px',
            wordBreak: 'break-all',
            whiteSpace: 'pre-wrap',
            zIndex: 1000,
            boxShadow: '0 -4px 20px rgba(0,0,0,0.4)',
            pointerEvents: 'none'
          }}
        >
          {tooltip.content}
        </div>
      )}
    </div>
  );
};

const zoomBtnStyle = {
  padding: '0.25rem 0.5rem',
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border-color)',
  borderRadius: '4px',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: '0.7rem',
  fontWeight: 600
};

// Tree/Compact container with dynamic height (matching Graph view behavior)
const JsonTreeContainer = ({ viewMode, data, onCopy, expandAllState }) => {
  const [containerHeight, setContainerHeight] = useState(400);
  const containerRef = useRef(null);

  // Calculate available height on mount and resize - use maximum space
  useEffect(() => {
    const calculateHeight = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Use all available height minus small bottom padding (20px)
        const availableHeight = window.innerHeight - rect.top - 20;
        setContainerHeight(Math.max(300, availableHeight));
      }
    };

    calculateHeight();
    window.addEventListener('resize', calculateHeight);
    return () => window.removeEventListener('resize', calculateHeight);
  }, []);

  // Determine expand level based on expandAllState or viewMode default
  const getExpandLevel = () => {
    if (expandAllState === 'expanded') return 'all';
    if (expandAllState === 'collapsed') return 'none';
    return viewMode; // 'tree' or 'compact'
  };

  return (
    <div
      ref={containerRef}
      style={{
        background: 'var(--bg-tertiary)',
        borderRadius: '6px',
        padding: '0.75rem',
        height: `${containerHeight}px`,
        overflowY: 'auto',
        fontSize: '0.7rem',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
      }}
    >
      {viewMode === 'raw' ? (
        <pre style={{
          margin: 0,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          color: 'var(--text-secondary)'
        }}>
          {JSON.stringify(data, null, 2)}
        </pre>
      ) : (
        <JsonTreeNode
          key={`${viewMode}-${expandAllState}`}  // Force remount when switching modes or expand state
          data={data}
          depth={0}
          expandLevel={getExpandLevel()}
          onCopy={onCopy}
        />
      )}
    </div>
  );
};

// JSON Viewer with view mode toggle
const JsonViewer = ({ data, onCopy }) => {
  const [viewMode, setViewMode] = useState('tree'); // 'tree' | 'graph' | 'raw' | 'compact'
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [treeKey, setTreeKey] = useState(0); // Used to force re-render on expand/collapse all
  const [expandAllState, setExpandAllState] = useState(null); // null = default, 'expanded' | 'collapsed'

  // Expand all - increment key to force tree re-render with expanded state
  const handleExpandAll = useCallback(() => {
    setExpandAllState('expanded');
    setTreeKey(k => k + 1);
  }, []);

  // Collapse all - increment key to force tree re-render with collapsed state
  const handleCollapseAll = useCallback(() => {
    setExpandAllState('collapsed');
    setTreeKey(k => k + 1);
  }, []);

  // Search through JSON
  const searchJson = useCallback((obj, term, path = '') => {
    if (!term) return [];
    const results = [];
    const termLower = term.toLowerCase();

    const traverse = (val, currentPath) => {
      if (val === null || val === undefined) return;

      if (typeof val === 'object') {
        Object.entries(val).forEach(([k, v]) => {
          const newPath = currentPath ? `${currentPath}.${k}` : k;
          if (k.toLowerCase().includes(termLower)) {
            results.push({ path: newPath, key: k, value: v, type: 'key' });
          }
          traverse(v, newPath);
        });
      } else {
        const strVal = String(val).toLowerCase();
        if (strVal.includes(termLower)) {
          results.push({ path: currentPath, value: val, type: 'value' });
        }
      }
    };

    traverse(obj, '');
    return results.slice(0, 20); // Limit results
  }, []);

  useEffect(() => {
    if (searchTerm.length >= 2) {
      setSearchResults(searchJson(data, searchTerm));
    } else {
      setSearchResults([]);
    }
  }, [searchTerm, data, searchJson]);

  return (
    <div>
      {/* View Mode Toggle & Search */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '0.5rem',
        gap: '0.5rem',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          {[
            { id: 'tree', label: 'Tree', title: 'Interactive tree view' },
            { id: 'compact', label: 'Compact', title: 'Collapsed tree' },
            { id: 'raw', label: '{ }', title: 'Raw JSON' },
            // Only show Graph if data is an object with nested content
            ...(data && typeof data === 'object' && Object.keys(data).length > 0
              ? [{ id: 'graph', label: 'Graph', title: 'Node-based graph view' }]
              : [])
          ].map(mode => (
            <button
              key={mode.id}
              onClick={() => {
                setViewMode(mode.id);
                setExpandAllState(null); // Reset expand state when changing modes
                setTreeKey(k => k + 1); // Force re-render with default expand levels
              }}
              title={mode.title}
              style={{
                padding: '0.25rem 0.5rem',
                background: viewMode === mode.id ? 'var(--accent-color, #3b82f6)' : 'var(--bg-tertiary)',
                border: 'none',
                borderRadius: '4px',
                color: viewMode === mode.id ? 'white' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '0.65rem',
                fontWeight: viewMode === mode.id ? 600 : 400
              }}
            >
              {mode.label}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input
            type="text"
            placeholder="Search JSON..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              padding: '0.25rem 0.5rem',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              borderRadius: '4px',
              color: 'var(--text-primary)',
              fontSize: '0.7rem',
              width: '140px'
            }}
          />
          {viewMode !== 'raw' && (
            <>
              <button
                onClick={handleExpandAll}
                title="Expand all nodes"
                style={{
                  padding: '0.25rem 0.5rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.65rem'
                }}
              >
                Expand All
              </button>
              <button
                onClick={handleCollapseAll}
                title="Collapse all nodes"
                style={{
                  padding: '0.25rem 0.5rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.65rem'
                }}
              >
                Collapse All
              </button>
            </>
          )}
          <button
            onClick={() => onCopy?.(JSON.stringify(data, null, 2))}
            style={{
              padding: '0.25rem 0.5rem',
              background: 'var(--bg-tertiary)',
              border: 'none',
              borderRadius: '4px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.65rem'
            }}
          >
            Copy All
          </button>
        </div>
      </div>

      {/* Search Results */}
      {searchResults.length > 0 && (
        <div style={{
          background: 'rgba(59, 130, 246, 0.1)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '4px',
          padding: '0.5rem',
          marginBottom: '0.5rem',
          maxHeight: '120px',
          overflowY: 'auto'
        }}>
          <div style={{ fontSize: '0.6rem', color: '#3b82f6', fontWeight: 600, marginBottom: '0.25rem' }}>
            Found {searchResults.length} match{searchResults.length !== 1 ? 'es' : ''}
          </div>
          {searchResults.map((result, i) => (
            <div key={i} style={{
              fontSize: '0.65rem',
              padding: '0.15rem 0',
              borderBottom: i < searchResults.length - 1 ? '1px solid rgba(59, 130, 246, 0.1)' : 'none',
              display: 'flex',
              alignItems: 'baseline',
              gap: '0.5rem',
              overflow: 'hidden'
            }}>
              <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{result.path}</span>
              {result.type === 'value' && (
                <span
                  style={{
                    color: '#4ade80',
                    cursor: 'pointer',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    flex: 1,
                    minWidth: 0
                  }}
                  onClick={() => onCopy?.(String(result.value))}
                  title={String(result.value)}
                >
                  {String(result.value)}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Legend - at top */}
      <div style={{
        display: 'flex',
        gap: '0.85rem',
        marginBottom: '0.5rem',
        fontSize: '0.7rem',
        color: 'var(--text-muted)',
        flexWrap: 'wrap',
        padding: '0.4rem 0.6rem',
        background: 'var(--bg-tertiary)',
        borderRadius: '4px'
      }}>
        <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Types:</span>
        <span><span style={{ color: '#4ade80' }}>●</span> string</span>
        <span><span style={{ color: '#60a5fa' }}>●</span> number</span>
        <span><span style={{ color: '#c084fc' }}>●</span> boolean</span>
        <span><span style={{ color: '#f472b6' }}>●</span> null</span>
        <span><span style={{ color: '#f59e0b' }}>●</span> IP</span>
        <span><span style={{ color: '#22d3ee' }}>●</span> URL</span>
        <span><span style={{ color: '#3b82f6' }}>●</span> object</span>
        <span style={{ marginLeft: 'auto', fontStyle: 'italic' }}>Click values to copy</span>
      </div>

      {/* JSON Content */}
      {viewMode === 'graph' ? (
        <JsonGraphView key={treeKey} data={data} onCopy={onCopy} expandAllState={expandAllState} />
      ) : (
        <JsonTreeContainer key={treeKey} viewMode={viewMode} data={data} onCopy={onCopy} expandAllState={expandAllState} />
      )}
    </div>
  );
};

function IOCDetail() {
  const { iocValue } = useParams();
  const location = useLocation();
  const navigate = useNavigate();

  const bulkIOCs = location.state?.bulkIOCs || JSON.parse(sessionStorage.getItem('bulkIOCs') || '[]');

  useEffect(() => {
    if (location.state?.bulkIOCs?.length > 0) {
      sessionStorage.setItem('bulkIOCs', JSON.stringify(location.state.bulkIOCs));
    }
  }, [location.state?.bulkIOCs]);

  const handleBack = () => {
    if (window.history.length > 2) {
      navigate(-1);
    } else if (bulkIOCs.length > 0) {
      navigate(`/threat-intel?iocs=${encodeURIComponent(bulkIOCs.join(','))}`);
    } else {
      navigate('/threat-intel');
    }
  };

  const [loading, setLoading] = useState(true);
  const [enriching, setEnriching] = useState(false);
  const [ioc, setIoc] = useState(null);
  const [enrichments, setEnrichments] = useState([]);
  const [providerStatus, setProviderStatus] = useState([]);
  const [relatedEvents, setRelatedEvents] = useState([]);
  const [relatedInvestigations, setRelatedInvestigations] = useState([]);
  const [selectedRawProvider, setSelectedRawProvider] = useState(null);
  const [enrichError, setEnrichError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [copyNotification, setCopyNotification] = useState(null);

  const detectType = (value) => {
    if (!value) return 'ip';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash_md5';
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash_sha1';
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash_sha256';
    if (value.startsWith('http://') || value.startsWith('https://')) return 'url';
    if (value.includes('@')) return 'email';
    if (value.includes('.')) return 'domain';
    return 'ip';
  };

  const fetchIOC = async () => {
    setLoading(true);
    let needsEnrichment = true;
    try {
      const response = await fetch(`${API_BASE}/iocs/${encodeURIComponent(iocValue)}?type=${type}&with_enrichments=true`, { headers });
      if (response.ok) {
        const iocData = await response.json();
        setIoc(iocData);
        if (iocData.enrichments && iocData.enrichments.length > 0) {
          setEnrichments(iocData.enrichments);
          needsEnrichment = false; // Already have cached enrichments
        }
        if (iocData.provider_status && iocData.provider_status.length > 0) {
          setProviderStatus(iocData.provider_status);
        }
      }
    } catch (error) {
    }
    setLoading(false);

    // Auto-enrich if no cached data was found
    if (needsEnrichment) {
      enrichIOC(false); // Use force_refresh=false to use cache if available
    }
  };

  const enrichIOC = async (forceRefresh = true) => {
    setEnriching(true);
    setEnrichError(null);
    try {
      const type = detectType(iocValue);
      const response = await fetch(`${API_BASE}/enrich`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ value: iocValue, type: type, force_refresh: forceRefresh })
      });
      if (response.ok) {
        const data = await response.json();
        setIoc(data.ioc);
        if (data.provider_status) {
          setProviderStatus(data.provider_status);
        }
        const newEnrichments = data.enrichments || [];
        if (newEnrichments.length > 0) {
          setEnrichments(newEnrichments);
        } else if (forceRefresh && enrichments.length > 0) {
          setEnrichError('Re-enrichment returned no new data (providers may be rate-limited). Showing cached data.');
        } else {
          setEnrichments(newEnrichments);
        }
      } else if (response.status === 401) {
        setEnrichError('Session expired. Please log in again.');
      } else {
        setEnrichError(`Enrichment failed: ${response.status}`);
      }
    } catch (error) {
      setEnrichError(`Network error: ${error.message}`);
    }
    setEnriching(false);
  };

  const fetchRelatedEvents = async (alertIds) => {
    if (!alertIds || alertIds.length === 0) return;
    try {
      const events = [];
      for (const alertId of alertIds.slice(0, 10)) {
        const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${alertId}`);
        if (response.ok) events.push(await response.json());
      }
      setRelatedEvents(events);
    } catch (error) {
    }
  };

  const fetchRelatedInvestigations = async (investigationIds) => {
    if (!investigationIds || investigationIds.length === 0) return;
    try {
      const investigations = [];
      for (const invId of investigationIds.slice(0, 10)) {
        const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${invId}`);
        if (response.ok) investigations.push(await response.json());
      }
      setRelatedInvestigations(investigations);
    } catch (error) {
    }
  };

  useEffect(() => {
    if (iocValue) fetchIOC();
  }, [iocValue]);

  useEffect(() => {
    if (ioc) {
      if (ioc.alert_ids?.length > 0) fetchRelatedEvents(ioc.alert_ids);
      if (ioc.investigation_ids?.length > 0) fetchRelatedInvestigations(ioc.investigation_ids);
    }
  }, [ioc]);

  // Helper to extract VT attributes from various data structures
  const getVtAttrs = (rawData) => {
    if (!rawData) return null;
    if (rawData.data?.attributes) return rawData.data.attributes;
    if (rawData.attributes) return rawData.attributes;
    if (rawData.last_analysis_stats) return rawData;
    return null;
  };

  // Extract all enrichment data
  // Helper to find enrichment by provider (handles variations in naming)
  const findEnrichment = (providers) => {
    const names = Array.isArray(providers) ? providers : [providers];
    return enrichments.find(e => names.some(n => e.provider?.toLowerCase().replace(/_/g, '') === n.toLowerCase().replace(/_/g, '')));
  };

  const vtEnrichment = findEnrichment(['virustotal', 'vt']);
  const urlscanEnrichment = findEnrichment(['urlscanio', 'urlscan_io', 'urlscan']);
  const otxEnrichment = findEnrichment(['otx', 'alienvault_otx', 'alienvault']);
  const abuseipdbEnrichment = findEnrichment(['abuseipdb', 'abuse_ipdb']);
  const ipinfoEnrichment = findEnrichment(['ipinfo', 'ip_info']);
  const rdapEnrichment = findEnrichment(['rdap_arin', 'rdap_verisign', 'rdap', 'rdaparin']);

  // Get VT data
  const vtAttrs = getVtAttrs(vtEnrichment?.raw_data) || {};
  const vtStats = vtAttrs.last_analysis_stats || {};
  const vtTotal = (vtStats.malicious || 0) + (vtStats.harmless || 0) + (vtStats.undetected || 0) + (vtStats.suspicious || 0);

  // Calculate threat assessment
  const calculateThreatAssessment = () => {
    let threatLevel = 'unknown';
    let confidence = 0;
    let reasons = [];

    // Check VT
    if (vtStats.malicious > 0) {
      threatLevel = vtStats.malicious >= 5 ? 'malicious' : 'suspicious';
      confidence = Math.min(95, 50 + vtStats.malicious * 5);
      reasons.push(`${vtStats.malicious}/${vtTotal} security vendors flagged as malicious`);
    } else if (vtTotal > 0) {
      threatLevel = 'clean';
      confidence = Math.min(90, 40 + vtTotal);
      reasons.push(`0/${vtTotal} vendors flagged - appears clean`);
    }

    // Check OTX pulses and malware families
    const pulseCount = otxEnrichment?.raw_data?.pulse_info?.count || 0;
    const otxMalwareFamilies = [
      ...(otxEnrichment?.raw_data?.pulse_info?.related?.alienvault?.malware_families || []),
      ...(otxEnrichment?.raw_data?.pulse_info?.related?.other?.malware_families || [])
    ];

    if (pulseCount > 0) {
      // If malware families are detected, mark as malicious
      if (otxMalwareFamilies.length > 0) {
        threatLevel = 'malicious';
        confidence = Math.max(confidence, 85);
        reasons.push(`Associated with malware: ${otxMalwareFamilies.slice(0, 3).join(', ')}`);
      } else if (pulseCount >= 5 && threatLevel !== 'malicious') {
        threatLevel = 'suspicious';
      }
      reasons.push(`Found in ${pulseCount} threat intelligence pulse${pulseCount !== 1 ? 's' : ''}`);
    }

    // Check AbuseIPDB
    const abuseScore = abuseipdbEnrichment?.raw_data?.data?.abuseConfidenceScore || 0;
    if (abuseScore > 50) {
      threatLevel = 'malicious';
      confidence = Math.max(confidence, abuseScore);
      reasons.push(`${abuseScore}% abuse confidence score`);
    } else if (abuseScore > 0) {
      reasons.push(`${abuseScore}% abuse confidence score`);
    }

    // Check URLScan tags (handle both search results and fresh scan formats)
    const urlscanResults = urlscanEnrichment?.raw_data?.results || [];
    const maliciousTags = [];

    // Check search results format
    urlscanResults.forEach(scan => {
      (scan.task?.tags || []).forEach(tag => {
        if ((tag.includes('phishing') || tag.includes('malicious') || tag.includes('malware')) && !maliciousTags.includes(tag)) {
          maliciousTags.push(tag);
        }
      });
    });

    // Check fresh scan format (page/verdicts in raw_data directly)
    if (urlscanEnrichment?.raw_data?.verdicts?.overall?.malicious) {
      if (!maliciousTags.includes('malicious')) maliciousTags.push('malicious');
    }
    if (urlscanEnrichment?.raw_data?.task?.tags) {
      urlscanEnrichment.raw_data.task.tags.forEach(tag => {
        if ((tag.includes('phishing') || tag.includes('malicious') || tag.includes('malware')) && !maliciousTags.includes(tag)) {
          maliciousTags.push(tag);
        }
      });
    }

    if (maliciousTags.length > 0) {
      threatLevel = 'malicious';
      reasons.push(`Tagged as: ${maliciousTags.join(', ')}`);
    }

    return { threatLevel, confidence, reasons };
  };

  const { threatLevel, confidence, reasons } = calculateThreatAssessment();
  const iocType = ioc?.type || detectType(iocValue);

  // Get color scheme based on threat level
  const getThemeColors = () => {
    switch (threatLevel) {
      case 'malicious': return { primary: '#dc2626', bg: 'rgba(220, 38, 38, 0.1)', text: '#fca5a5' };
      case 'suspicious': return { primary: '#f59e0b', bg: 'rgba(245, 158, 11, 0.1)', text: '#fcd34d' };
      case 'clean': return { primary: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)', text: '#86efac' };
      default: return { primary: '#6b7280', bg: 'rgba(107, 114, 128, 0.1)', text: '#d1d5db' };
    }
  };
  const theme = getThemeColors();

  // Copy to clipboard with notification
  const copyToClipboard = (text, label = 'Copied!') => {
    navigator.clipboard.writeText(text);
    setCopyNotification(label);
    setTimeout(() => setCopyNotification(null), 2000);
  };

  if (loading) {
    return (
      <div className="threat-intel-shell">
        <div className="ti-shell">
          <header className="ti-topbar">
            <div className="ti-title-group">
              <span className="ti-badge">Threat Intel</span>
              <div>
                <div className="ti-title">IOC Profile</div>
                <div className="ti-subtitle">{iocValue || 'Loading indicator'}</div>
              </div>
            </div>
          </header>
          <div className="ti-panel" style={{ display: 'grid', placeItems: 'center' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
              <div className="spinner" style={{ width: '40px', height: '40px' }}></div>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Loading threat intelligence...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const hasEnrichmentData = enrichments.length > 0;

  return (
    <div className="threat-intel-shell">
      <div className="ti-shell">
        <header className="ti-topbar">
          <div className="ti-title-group">
            <span className="ti-badge">Threat Intel</span>
            <div>
              <div className="ti-title">IOC Profile</div>
              <div className="ti-subtitle">{iocValue}</div>
            </div>
          </div>
          <div className="ti-topbar-actions">
            <span className="ti-pill">Type: {iocType.toUpperCase()}</span>
            <span className="ti-pill">Verdict: {threatLevel}</span>
          </div>
        </header>
        <div className="ti-panel">
          <div style={{ maxWidth: '1400px', margin: '0 auto', position: 'relative' }}>
      {/* Copy Notification Toast */}
      {copyNotification && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          padding: '0.75rem 1.25rem',
          background: '#22c55e',
          color: 'white',
          borderRadius: '8px',
          fontSize: '0.9rem',
          fontWeight: '500',
          boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
          zIndex: 1000,
          animation: 'fadeIn 0.2s ease-out'
        }}>
          ✓ {copyNotification}
        </div>
      )}

      {/* Hero Header - Compact */}
      <div style={{
        background: `linear-gradient(135deg, ${theme.bg} 0%, var(--bg-secondary) 100%)`,
        borderRadius: '10px',
        padding: '0.75rem 1rem',
        marginBottom: '1rem',
        border: `1px solid ${theme.primary}40`,
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Top Row - Navigation and Actions */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', position: 'relative' }}>
          <button
            onClick={handleBack}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.3rem',
              padding: '0.3rem 0.6rem',
              background: 'var(--bg-tertiary)',
              border: 'none',
              borderRadius: '5px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.7rem'
            }}
          >
            ← Back
          </button>

          <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => copyToClipboard(iocValue, 'IOC copied to clipboard')}
              style={{
                padding: '0.3rem 0.5rem',
                background: 'var(--bg-tertiary)',
                border: 'none',
                borderRadius: '5px',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '0.7rem'
              }}
              title="Copy IOC to clipboard"
            >
              📋 Copy
            </button>

            {/* External Investigation Links */}
            <a
              href={`https://www.virustotal.com/gui/${iocType === 'ip' ? 'ip-address' : iocType === 'hash_md5' || iocType === 'hash_sha1' || iocType === 'hash_sha256' ? 'file' : 'domain'}/${encodeURIComponent(iocValue)}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: '0.3rem 0.5rem',
                background: 'var(--bg-tertiary)',
                border: 'none',
                borderRadius: '5px',
                color: '#4285f4',
                textDecoration: 'none',
                fontSize: '0.7rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.2rem'
              }}
              title="Open in VirusTotal"
            >
              🔍 VT
            </a>
            {(iocType === 'domain' || iocType === 'url') && (
              <a
                href={`https://urlscan.io/search/#${encodeURIComponent(iocValue)}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '0.3rem 0.5rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '5px',
                  color: '#00b4d8',
                  textDecoration: 'none',
                  fontSize: '0.7rem'
                }}
                title="Search on URLScan.io"
              >
                🌐 URLScan
              </a>
            )}
            {iocType === 'ip' && (
              <a
                href={`https://www.abuseipdb.com/check/${encodeURIComponent(iocValue)}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '0.3rem 0.5rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '5px',
                  color: '#ef4444',
                  textDecoration: 'none',
                  fontSize: '0.7rem'
                }}
                title="Check on AbuseIPDB"
              >
                🚫 AbuseIPDB
              </a>
            )}
            <a
              href={`https://otx.alienvault.com/indicator/${iocType === 'ip' ? 'ip' : iocType === 'domain' ? 'domain' : iocType === 'url' ? 'url' : 'file'}/${encodeURIComponent(iocValue)}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: '0.3rem 0.5rem',
                background: 'var(--bg-tertiary)',
                border: 'none',
                borderRadius: '5px',
                color: '#f97316',
                textDecoration: 'none',
                fontSize: '0.7rem'
              }}
              title="View on AlienVault OTX"
            >
              👽 OTX
            </a>

            <button
              onClick={() => enrichIOC(true)}
              disabled={enriching}
              style={{
                padding: '0.3rem 0.75rem',
                background: enriching ? 'var(--bg-tertiary)' : `linear-gradient(135deg, ${theme.primary} 0%, ${theme.primary}cc 100%)`,
                border: 'none',
                borderRadius: '5px',
                color: 'white',
                cursor: enriching ? 'wait' : 'pointer',
                fontSize: '0.7rem',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem'
              }}
            >
              {enriching ? (
                <>
                  <span className="spinner" style={{ width: '10px', height: '10px', borderWidth: '2px' }}></span>
                  Enriching...
                </>
              ) : (
                <>🔄 Enrich Now</>
              )}
            </button>
          </div>
        </div>

        {/* Error Display */}
        {enrichError && (
          <div style={{
            padding: '0.4rem 0.6rem',
            background: 'rgba(220, 38, 38, 0.15)',
            border: '1px solid rgba(220, 38, 38, 0.3)',
            borderRadius: '5px',
            marginBottom: '0.5rem',
            color: '#fca5a5',
            fontSize: '0.7rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            <span>⚠️ {enrichError}</span>
            <button onClick={() => setEnrichError(null)} style={{ background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer', fontSize: '0.8rem' }}>✕</button>
          </div>
        )}

        {/* Main IOC Display - Compact */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', position: 'relative' }}>
          {/* Threat Level Indicator - Smaller */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            padding: '0.6rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            minWidth: '80px'
          }}>
            <div style={{
              width: '50px',
              height: '50px',
              borderRadius: '50%',
              background: `conic-gradient(${theme.primary} ${confidence}%, var(--bg-secondary) ${confidence}%)`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '0.35rem'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '50%',
                background: 'var(--bg-tertiary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.85rem',
                fontWeight: '700',
                color: theme.primary
              }}>
                {confidence > 0 ? `${confidence}%` : '?'}
              </div>
            </div>
            <div style={{
              padding: '0.15rem 0.4rem',
              background: theme.bg,
              borderRadius: '10px',
              color: theme.primary,
              fontSize: '0.55rem',
              fontWeight: '700',
              textTransform: 'uppercase',
              letterSpacing: '0.3px'
            }}>
              {threatLevel}
            </div>
          </div>

          {/* IOC Details */}
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.3rem', flexWrap: 'wrap' }}>
              <span style={{
                padding: '0.15rem 0.4rem',
                background: '#3CB37120',
                color: '#3CB371',
                borderRadius: '4px',
                fontSize: '0.6rem',
                fontWeight: '600',
                textTransform: 'uppercase'
              }}>
                {iocType}
              </span>
              {ioc?.tags?.slice(0, 5).map((tag, i) => (
                <span key={i} style={{
                  padding: '0.1rem 0.3rem',
                  background: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  borderRadius: '3px',
                  fontSize: '0.55rem'
                }}>
                  {tag}
                </span>
              ))}
            </div>

            <h1 style={{
              fontSize: iocValue.length > 50 ? '0.85rem' : '1rem',
              fontWeight: '600',
              fontFamily: 'monospace',
              wordBreak: 'break-all',
              marginBottom: '0.35rem',
              color: 'var(--text-primary)',
              lineHeight: 1.3
            }}>
              {iocValue}
            </h1>

            {/* Quick Assessment - Inline */}
            {reasons.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {reasons.slice(0, 2).map((reason, i) => (
                  <div key={i} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    fontSize: '0.65rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span style={{ color: theme.primary }}>•</span>
                    {reason}
                  </div>
                ))}
              </div>
            )}

            {!hasEnrichmentData && (
              <div style={{
                marginTop: '0.5rem',
                padding: '0.5rem',
                background: 'var(--bg-tertiary)',
                borderRadius: '5px',
                border: '1px dashed var(--border-color)'
              }}>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', marginBottom: '0.2rem' }}>
                  <strong>No enrichment data yet.</strong>
                </p>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>
                  Click "Enrich Now" to fetch threat intelligence.
                </p>
              </div>
            )}
          </div>

          {/* Quick Stats & Metadata */}
          {hasEnrichmentData && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
              minWidth: '180px'
            }}>
              {/* Stats Grid */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '0.35rem'
              }}>
                <div style={{ padding: '0.35rem', background: 'var(--bg-tertiary)', borderRadius: '5px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.95rem', fontWeight: '700', color: vtStats.malicious > 0 ? '#dc2626' : '#22c55e' }}>
                    {vtStats.malicious || 0}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>VT Detections</div>
                </div>
                <div style={{ padding: '0.35rem', background: 'var(--bg-tertiary)', borderRadius: '5px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.95rem', fontWeight: '700', color: '#3CB371' }}>
                    {otxEnrichment?.raw_data?.pulse_info?.count || 0}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>OTX Pulses</div>
                </div>
                <div style={{ padding: '0.35rem', background: 'var(--bg-tertiary)', borderRadius: '5px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.95rem', fontWeight: '700', color: '#00b4d8' }}>
                    {urlscanEnrichment?.raw_data?.page ? 1 : (urlscanEnrichment?.raw_data?.results?.length || 0)}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>URL Scans</div>
                </div>
                <div style={{ padding: '0.35rem', background: 'var(--bg-tertiary)', borderRadius: '5px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                    {enrichments.length}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Sources</div>
                </div>
              </div>

              {/* Location & Org Metadata - Compact */}
              {(ipinfoEnrichment?.raw_data?.country || ipinfoEnrichment?.raw_data?.org) && (
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '0.25rem',
                  fontSize: '0.65rem'
                }}>
                  {ipinfoEnrichment?.raw_data?.country && (
                    <div style={{ padding: '0.2rem 0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.55rem' }}>Location</div>
                      <div style={{ fontWeight: '500', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ipinfoEnrichment.raw_data.city ? `${ipinfoEnrichment.raw_data.city}, ` : ''}{ipinfoEnrichment.raw_data.country}
                      </div>
                    </div>
                  )}
                  {ipinfoEnrichment?.raw_data?.org && (
                    <div style={{ padding: '0.2rem 0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.55rem' }}>Organization</div>
                      <div style={{ fontWeight: '500', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ipinfoEnrichment.raw_data.org}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* First/Last Seen Bar */}
      {(ioc?.first_seen || ioc?.last_seen) && (
        <div style={{
          display: 'flex',
          gap: '1.5rem',
          padding: '0.4rem 1rem',
          background: 'var(--bg-secondary)',
          borderRadius: '6px',
          marginBottom: '0.75rem',
          fontSize: '0.75rem',
          alignItems: 'center'
        }}>
          {ioc?.first_seen && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>First Seen:</span>
              <span style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>
                {new Date(ioc.first_seen).toLocaleDateString()} {new Date(ioc.first_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          )}
          {ioc?.last_seen && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>Last Seen:</span>
              <span style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>
                {new Date(ioc.last_seen).toLocaleDateString()} {new Date(ioc.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Tab Navigation */}
      {hasEnrichmentData && (
        <>
          <div style={{ display: 'flex', gap: '0.2rem', marginBottom: '0.75rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.25rem' }}>
            {['overview', 'vendors', 'raw'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  padding: '0.4rem 0.85rem',
                  background: activeTab === tab ? 'var(--bg-secondary)' : 'transparent',
                  border: 'none',
                  borderRadius: '5px 5px 0 0',
                  color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.8rem',
                  fontWeight: activeTab === tab ? '600' : '400',
                  textTransform: 'capitalize',
                  borderBottom: activeTab === tab ? `2px solid ${theme.primary}` : '2px solid transparent'
                }}
              >
                {tab === 'vendors' ? 'Vendor Results' : tab === 'raw' ? 'Raw Data' : tab}
              </button>
            ))}
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>

              {/* Executive Summary - Full Width */}
              <div style={{
                gridColumn: '1 / -1',
                background: 'linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%)',
                borderRadius: '6px',
                padding: '0.5rem',
                border: `1px solid ${theme.primary}30`
              }}>
                <h3 style={{ fontSize: '0.75rem', fontWeight: '700', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <span style={{ fontSize: '0.8rem' }}>📊</span> Intelligence Summary
                </h3>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.3rem' }}>
                  {/* VT Score */}
                  <div style={{ textAlign: 'center', padding: '0.2rem 0.15rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.3px' }}>VT</div>
                    <div style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      lineHeight: 1.2,
                      color: vtStats.malicious > 0 ? '#dc2626' : vtStats.suspicious > 0 ? '#f59e0b' : vtTotal > 0 ? '#22c55e' : 'var(--text-muted)'
                    }}>
                      {vtStats.malicious > 0
                        ? `${vtStats.malicious}/${vtTotal}`
                        : vtTotal > 0
                          ? `${vtStats.harmless || 0}/${vtTotal}`
                          : '—'}
                    </div>
                  </div>

                  {/* OTX Pulses */}
                  <div style={{ textAlign: 'center', padding: '0.2rem 0.15rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.3px' }}>OTX</div>
                    <div style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      lineHeight: 1.2,
                      color: (otxEnrichment?.raw_data?.pulse_info?.count || 0) > 0 ? '#f59e0b' : '#22c55e'
                    }}>
                      {otxEnrichment?.raw_data?.pulse_info?.count || 0}
                    </div>
                  </div>

                  {/* AbuseIPDB Score */}
                  <div style={{ textAlign: 'center', padding: '0.2rem 0.15rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.3px' }}>Abuse%</div>
                    <div style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      lineHeight: 1.2,
                      color: (abuseipdbEnrichment?.raw_data?.data?.abuseConfidenceScore || 0) > 50 ? '#dc2626' :
                             (abuseipdbEnrichment?.raw_data?.data?.abuseConfidenceScore || 0) > 20 ? '#f59e0b' : '#22c55e'
                    }}>
                      {abuseipdbEnrichment?.raw_data?.data?.abuseConfidenceScore ?? '—'}
                    </div>
                  </div>

                  {/* URL Scans */}
                  <div style={{ textAlign: 'center', padding: '0.2rem 0.15rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.3px' }}>Scans</div>
                    <div style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      lineHeight: 1.2,
                      color: 'var(--text-primary)'
                    }}>
                      {urlscanEnrichment?.raw_data?.page ? 1 : (urlscanEnrichment?.raw_data?.results?.length || 0)}
                    </div>
                  </div>

                  {/* VT Reputation */}
                  <div style={{ textAlign: 'center', padding: '0.2rem 0.15rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.3px' }}>Rep</div>
                    <div style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      lineHeight: 1.2,
                      color: (vtAttrs.reputation || 0) < 0 ? '#dc2626' : (vtAttrs.reputation || 0) > 0 ? '#22c55e' : 'var(--text-muted)'
                    }}>
                      {vtAttrs.reputation !== undefined ? (vtAttrs.reputation >= 0 ? '+' : '') + vtAttrs.reputation : '—'}
                    </div>
                  </div>
                </div>

                {/* Analyst Verdict Line */}
                <div style={{
                  marginTop: '0.35rem',
                  padding: '0.3rem 0.5rem',
                  background: theme.bg,
                  borderRadius: '4px',
                  border: `1px solid ${theme.primary}40`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem'
                }}>
                  <div style={{
                    width: '20px',
                    height: '20px',
                    borderRadius: '50%',
                    background: theme.primary,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.7rem',
                    flexShrink: 0
                  }}>
                    {threatLevel === 'malicious' ? '🚨' : threatLevel === 'suspicious' ? '⚠️' : threatLevel === 'clean' ? '✅' : '❓'}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ fontWeight: '600', color: theme.primary, textTransform: 'uppercase', fontSize: '0.7rem', letterSpacing: '0.3px' }}>
                      {threatLevel}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginLeft: '0.4rem' }}>
                      {reasons.length > 0 ? reasons[0] : 'Insufficient data'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Two-Column Masonry Layout - spans full width */}
              <div style={{
                gridColumn: '1 / -1',
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '0.75rem',
                gridAutoFlow: 'dense'
              }}>
                {/* VirusTotal Summary - Left Column */}
                {vtEnrichment && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#4285f4', fontSize: '0.6rem' }}>◆</span> VirusTotal
                    </h3>

                    <div style={{ display: 'flex', gap: '0.3rem', marginBottom: '0.3rem' }}>
                      <div style={{ flex: 1, padding: '0.15rem 0.25rem', background: 'var(--bg-tertiary)', borderRadius: '4px', textAlign: 'center' }}>
                        <div style={{
                          fontSize: '1rem',
                          fontWeight: '700',
                          color: vtStats.malicious > 0 ? '#dc2626' : vtStats.suspicious > 0 ? '#f59e0b' : '#22c55e',
                          lineHeight: 1.2
                        }}>
                          {vtStats.malicious || 0}
                        </div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Malicious</div>
                      </div>
                      <div style={{ flex: 1, padding: '0.15rem 0.25rem', background: 'var(--bg-tertiary)', borderRadius: '4px', textAlign: 'center' }}>
                        <div style={{ fontSize: '1rem', fontWeight: '700', color: '#f59e0b', lineHeight: 1.2 }}>
                          {vtStats.suspicious || 0}
                        </div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Suspicious</div>
                      </div>
                      <div style={{ flex: 1, padding: '0.15rem 0.25rem', background: 'var(--bg-tertiary)', borderRadius: '4px', textAlign: 'center' }}>
                        <div style={{ fontSize: '1rem', fontWeight: '700', color: '#22c55e', lineHeight: 1.2 }}>
                          {vtStats.harmless || 0}
                        </div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Clean</div>
                      </div>
                    </div>

                    {/* Detection bar */}
                    <div>
                      <div style={{ height: '3px', background: 'var(--bg-tertiary)', borderRadius: '2px', overflow: 'hidden', display: 'flex' }}>
                        {vtTotal > 0 && (
                          <>
                            <div style={{ width: `${(vtStats.malicious / vtTotal) * 100}%`, background: '#dc2626', height: '100%' }} />
                            <div style={{ width: `${(vtStats.suspicious / vtTotal) * 100}%`, background: '#f59e0b', height: '100%' }} />
                            <div style={{ width: `${(vtStats.harmless / vtTotal) * 100}%`, background: '#22c55e', height: '100%' }} />
                          </>
                        )}
                      </div>
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                        {vtTotal} vendors {vtAttrs.reputation !== undefined && <span>• Rep: <strong style={{ color: vtAttrs.reputation < 0 ? '#dc2626' : '#22c55e' }}>{vtAttrs.reputation}</strong></span>}
                      </div>
                    </div>
                  </div>
                )}

                {/* WHOIS & Network Info Section - Always top-right, spans up to 3 rows with internal scroll */}
                {(vtAttrs.whois || rdapEnrichment?.raw_data) && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem', gridColumn: 2, gridRow: '1 / span 3', display: 'flex', flexDirection: 'column', maxHeight: '320px' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem', flexShrink: 0 }}>
                      <span style={{ color: '#10b981', fontSize: '0.6rem' }}>◆</span> WHOIS / Network
                      {rdapEnrichment && <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', fontWeight: 400 }}>(RDAP)</span>}
                    </h3>
                    {(() => {
                      // Combine data from multiple sources
                      const whoisData = {};

                      // Add RDAP data first (authoritative registration data)
                      const rdap = rdapEnrichment?.raw_data || {};
                      if (rdap.startAddress && rdap.endAddress) {
                        whoisData['NetRange'] = `${rdap.startAddress} - ${rdap.endAddress}`;
                      }
                      // Extract CIDR from cidr0_cidrs
                      if (rdap.cidr0_cidrs && rdap.cidr0_cidrs.length > 0) {
                        const cidr = rdap.cidr0_cidrs[0];
                        whoisData['CIDR'] = `${cidr.v4prefix || cidr.v6prefix || ''}/${cidr.length || ''}`;
                      }
                      if (rdap.handle) whoisData['Handle'] = rdap.handle;
                      if (rdap.name) whoisData['NetName'] = rdap.name;
                      if (rdap.type) whoisData['NetType'] = rdap.type;
                      if (rdap.country) whoisData['Country'] = rdap.country;

                      // Extract org and abuse info from RDAP entities
                      if (rdap.entities) {
                        for (const entity of rdap.entities) {
                          const roles = entity.roles || [];
                          const vcard = entity.vcardArray?.[1] || [];

                          // Get organization name
                          if (roles.includes('registrant') || !whoisData['OrgName']) {
                            for (const item of vcard) {
                              if (item[0] === 'fn' && item[3]) {
                                whoisData['OrgName'] = item[3];
                                break;
                              }
                            }
                          }

                          // Get abuse contact
                          if (roles.includes('abuse')) {
                            for (const item of vcard) {
                              if (item[0] === 'email' && item[3]) {
                                whoisData['Abuse Email'] = item[3];
                              }
                              if (item[0] === 'tel' && item[3]) {
                                whoisData['Abuse Phone'] = item[3];
                              }
                            }
                            // Check nested entities for abuse contacts
                            for (const subEntity of (entity.entities || [])) {
                              const subVcard = subEntity.vcardArray?.[1] || [];
                              for (const item of subVcard) {
                                if (item[0] === 'email' && item[3] && !whoisData['Abuse Email']) {
                                  whoisData['Abuse Email'] = item[3];
                                }
                              }
                            }
                          }

                          // Get technical contact
                          if (roles.includes('technical')) {
                            for (const item of vcard) {
                              if (item[0] === 'email' && item[3]) {
                                whoisData['Tech Email'] = item[3];
                              }
                            }
                          }
                        }
                      }

                      // Extract registration/update dates from RDAP events
                      if (rdap.events) {
                        for (const event of rdap.events) {
                          if (event.eventAction === 'registration' && event.eventDate) {
                            whoisData['RegDate'] = event.eventDate.split('T')[0];
                          }
                          if (event.eventAction === 'last changed' && event.eventDate) {
                            whoisData['Updated'] = event.eventDate.split('T')[0];
                          }
                        }
                      }

                      // For domain RDAP
                      if (rdap.ldhName) whoisData['Domain'] = rdap.ldhName;
                      if (rdap.nameservers) {
                        const ns = rdap.nameservers.slice(0, 2).map(n => n.ldhName).filter(Boolean).join(', ');
                        if (ns) whoisData['Name Servers'] = ns;
                      }

                      // Parse VT WHOIS and merge (VT WHOIS can fill gaps)
                      if (vtAttrs.whois) {
                        const whoisLines = vtAttrs.whois.split('\n').filter(line => line.trim() && !line.startsWith('#') && !line.startsWith('%'));
                        whoisLines.forEach(line => {
                          const colonIndex = line.indexOf(':');
                          if (colonIndex > 0) {
                            const key = line.substring(0, colonIndex).trim();
                            const value = line.substring(colonIndex + 1).trim();
                            if (value && !whoisData[key]) {
                              // Only add if we don't already have this key
                              whoisData[key] = value;
                            }
                          }
                        });
                      }

                      // Priority fields for IP WHOIS (ARIN format)
                      const ipPriorityFields = [
                        'NetRange', 'CIDR', 'Route', 'NetName', 'NetType', 'Network Type',
                        'OrgName', 'Organization', 'Company', 'OrgId', 'ASN', 'AS Name', 'OriginAS',
                        'Address', 'City', 'Location', 'StateProv', 'Region', 'PostalCode', 'Postal', 'Country', 'Timezone',
                        'RegDate', 'Updated', 'Hostname', 'Company Domain', 'AS Domain',
                        'VPN', 'Proxy', 'Tor', 'Hosting',
                        'Abuse Email', 'OrgAbuseEmail', 'OrgAbuseName', 'Abuse Phone', 'OrgTechEmail', 'OrgNOCEmail', 'Parent'
                      ];

                      // Priority fields for domain WHOIS
                      const domainPriorityFields = [
                        'Registrar', 'Creation Date', 'Updated Date', 'Expiration Date', 'Registry Expiry Date',
                        'Name Server', 'Registrant Organization', 'Registrant Country', 'Admin Email', 'Tech Email'
                      ];

                      // Detect if this is IP WHOIS or domain WHOIS
                      const isIPWhois = whoisData['NetRange'] || whoisData['CIDR'] || whoisData['OrgName'] || whoisData['ASN'];
                      const priorityFields = isIPWhois ? ipPriorityFields : domainPriorityFields;

                      // Sort entries with priority fields first
                      const sortedEntries = Object.entries(whoisData).sort(([a], [b]) => {
                        const aIndex = priorityFields.findIndex(f => a.toLowerCase().includes(f.toLowerCase()));
                        const bIndex = priorityFields.findIndex(f => b.toLowerCase().includes(f.toLowerCase()));
                        if (aIndex >= 0 && bIndex >= 0) return aIndex - bIndex;
                        if (aIndex >= 0) return -1;
                        if (bIndex >= 0) return 1;
                        return 0;
                      });

                      // If we got parsed key-value pairs, show them
                      if (sortedEntries.length > 0) {
                        // Separate abuse contacts for special display
                        const abuseEntries = sortedEntries.filter(([k]) =>
                          k.toLowerCase().includes('abuse') || k.toLowerCase().includes('tech email') || k.toLowerCase().includes('noc')
                        );
                        const otherEntries = sortedEntries.filter(([k]) =>
                          !k.toLowerCase().includes('abuse') && !k.toLowerCase().includes('tech email') && !k.toLowerCase().includes('noc')
                        );

                        return (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', overflowY: 'auto', flex: 1 }}>
                            {/* Abuse contacts section - highlighted */}
                            {abuseEntries.length > 0 && (
                              <div style={{
                                background: 'rgba(59, 130, 246, 0.1)',
                                border: '1px solid rgba(59, 130, 246, 0.3)',
                                borderRadius: '4px',
                                padding: '0.3rem',
                                marginBottom: '0.2rem'
                              }}>
                                <div style={{ fontSize: '0.6rem', color: '#3b82f6', fontWeight: '600', marginBottom: '0.2rem', textTransform: 'uppercase' }}>
                                  Report Abuse To
                                </div>
                                {abuseEntries.map(([key, value], i) => (
                                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.1rem 0', fontSize: '0.7rem' }}>
                                    <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>{key.replace('OrgAbuse', 'Abuse ').replace('Org', '')}</span>
                                    {key.toLowerCase().includes('email') ? (
                                      <a href={`mailto:${value}`} style={{ color: '#3b82f6', fontWeight: '500', textDecoration: 'none' }}>{value}</a>
                                    ) : key.toLowerCase().includes('phone') ? (
                                      <a href={`tel:${value}`} style={{ color: '#3b82f6', fontWeight: '500', textDecoration: 'none' }}>{value}</a>
                                    ) : (
                                      <span style={{ color: '#3b82f6', fontWeight: '500' }}>{value}</span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                            {/* Other registration data */}
                            {otherEntries.map(([key, value], i) => (
                              <div key={i} style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'flex-start',
                                padding: '0.15rem 0.25rem',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '3px',
                                fontSize: '0.65rem',
                                gap: '0.4rem'
                              }}>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.55rem', flexShrink: 0, minWidth: '60px' }}>{key}</span>
                                <span style={{
                                  color: 'var(--text-primary)',
                                  fontWeight: '500',
                                  textAlign: 'right',
                                  wordBreak: 'break-word',
                                  flex: 1
                                }}>{value}</span>
                              </div>
                            ))}
                          </div>
                        );
                      }

                      // Otherwise show raw WHOIS with better formatting
                      if (vtAttrs.whois) {
                        return (
                          <pre style={{
                            background: 'var(--bg-tertiary)',
                            padding: '0.35rem',
                            borderRadius: '4px',
                            fontSize: '0.65rem',
                            color: 'var(--text-secondary)',
                            overflowY: 'auto',
                            flex: 1,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                            margin: 0
                          }}>
                            {vtAttrs.whois}
                          </pre>
                        );
                      }

                      return <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>No WHOIS data available</div>;
                    })()}
                  </div>
                )}

                {/* AlienVault OTX - Left Column */}
                {otxEnrichment && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#f97316', fontSize: '0.6rem' }}>◆</span> AlienVault OTX
                    </h3>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <div style={{ padding: '0.15rem 0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px', textAlign: 'center' }}>
                        <span style={{
                          fontSize: '1rem',
                          fontWeight: '700',
                          color: (otxEnrichment.raw_data?.pulse_info?.count || 0) > 0 ? '#f59e0b' : '#22c55e'
                        }}>
                          {otxEnrichment.raw_data?.pulse_info?.count || 0}
                        </span>
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginLeft: '0.25rem' }}>pulses</span>
                      </div>

                      {/* Show related malware families inline */}
                      {otxEnrichment.raw_data?.pulse_info?.related && (
                        <>
                          {[...(otxEnrichment.raw_data.pulse_info.related.alienvault?.malware_families || []),
                            ...(otxEnrichment.raw_data.pulse_info.related.other?.malware_families || [])].slice(0, 3).map((fam, i) => (
                            <span key={i} style={{
                              padding: '0.15rem 0.3rem',
                              background: 'rgba(220, 38, 38, 0.15)',
                              color: '#dc2626',
                              borderRadius: '3px',
                              fontSize: '0.7rem'
                            }}>{fam}</span>
                          ))}
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* AbuseIPDB Section - Left Column */}
                {abuseipdbEnrichment && abuseipdbEnrichment.raw_data?.data && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#ef4444', fontSize: '0.6rem' }}>◆</span> AbuseIPDB
                    </h3>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <div style={{ padding: '0.15rem 0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px', display: 'flex', alignItems: 'baseline', gap: '0.2rem' }}>
                        <span style={{
                          fontSize: '1rem',
                          fontWeight: '700',
                          color: (abuseipdbEnrichment.raw_data.data.abuseConfidenceScore || 0) > 50 ? '#dc2626' :
                                 (abuseipdbEnrichment.raw_data.data.abuseConfidenceScore || 0) > 20 ? '#f59e0b' : '#22c55e'
                        }}>
                          {abuseipdbEnrichment.raw_data.data.abuseConfidenceScore || 0}%
                        </span>
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>conf</span>
                      </div>
                      <div style={{ padding: '0.15rem 0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px', display: 'flex', alignItems: 'baseline', gap: '0.2rem' }}>
                        <span style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                          {abuseipdbEnrichment.raw_data.data.totalReports || 0}
                        </span>
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>reports</span>
                      </div>
                      {abuseipdbEnrichment.raw_data.data.usageType && (
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{abuseipdbEnrichment.raw_data.data.usageType}</span>
                      )}
                    </div>
                  </div>
                )}

                {/* IPInfo Widget - Dedicated section */}
                {ipinfoEnrichment?.raw_data && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem', gridColumn: 2 }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#8b5cf6', fontSize: '0.6rem' }}>◆</span> IPInfo
                    </h3>

                    {(() => {
                      const ip = ipinfoEnrichment.raw_data;
                      return (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                          {/* Location & Org Row */}
                          <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                            {ip.city && (
                              <div style={{ padding: '0.15rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.7rem' }}>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>Location </span>
                                <span style={{ fontWeight: '500' }}>{ip.city}{ip.region ? `, ${ip.region}` : ''}</span>
                              </div>
                            )}
                            {ip.country && (
                              <div style={{ padding: '0.15rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.7rem' }}>
                                <span style={{ fontWeight: '500' }}>{ip.country}</span>
                              </div>
                            )}
                          </div>

                          {/* Organization/Company */}
                          {(ip.org || ip.company?.name) && (
                            <div style={{ padding: '0.2rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.7rem' }}>
                              <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>Org </span>
                              <span style={{ fontWeight: '500' }}>{ip.company?.name || ip.org}</span>
                              {ip.company?.type && <span style={{ color: 'var(--text-muted)', marginLeft: '0.3rem' }}>({ip.company.type})</span>}
                            </div>
                          )}

                          {/* ASN Info */}
                          {ip.asn && (
                            <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                              {ip.asn.asn && (
                                <div style={{ padding: '0.15rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.7rem' }}>
                                  <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>ASN </span>
                                  <span style={{ fontWeight: '500', color: '#8b5cf6' }}>{ip.asn.asn}</span>
                                </div>
                              )}
                              {ip.asn.name && (
                                <div style={{ padding: '0.15rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.7rem', flex: 1 }}>
                                  <span style={{ fontWeight: '500' }}>{ip.asn.name}</span>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Privacy Flags - VPN, Proxy, Tor, Hosting */}
                          {ip.privacy && (ip.privacy.vpn || ip.privacy.proxy || ip.privacy.tor || ip.privacy.hosting) && (
                            <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.1rem' }}>
                              {ip.privacy.vpn && (
                                <span style={{ padding: '0.1rem 0.25rem', background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', borderRadius: '3px', fontSize: '0.65rem', fontWeight: '600' }}>VPN</span>
                              )}
                              {ip.privacy.proxy && (
                                <span style={{ padding: '0.1rem 0.25rem', background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', borderRadius: '3px', fontSize: '0.65rem', fontWeight: '600' }}>PROXY</span>
                              )}
                              {ip.privacy.tor && (
                                <span style={{ padding: '0.1rem 0.25rem', background: 'rgba(220, 38, 38, 0.15)', color: '#dc2626', borderRadius: '3px', fontSize: '0.65rem', fontWeight: '600' }}>TOR</span>
                              )}
                              {ip.privacy.hosting && (
                                <span style={{ padding: '0.1rem 0.25rem', background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', borderRadius: '3px', fontSize: '0.65rem', fontWeight: '600' }}>HOSTING</span>
                              )}
                            </div>
                          )}

                          {/* Abuse Contact - Clickable */}
                          {ip.abuse?.email && (
                            <div style={{
                              marginTop: '0.15rem',
                              padding: '0.25rem 0.3rem',
                              background: 'rgba(59, 130, 246, 0.1)',
                              border: '1px solid rgba(59, 130, 246, 0.25)',
                              borderRadius: '4px',
                              fontSize: '0.65rem'
                            }}>
                              <span style={{ color: 'var(--text-muted)' }}>Report abuse: </span>
                              <a href={`mailto:${ip.abuse.email}`} style={{ color: '#3b82f6', fontWeight: '500', textDecoration: 'none' }}>
                                {ip.abuse.email}
                              </a>
                              {ip.abuse.phone && (
                                <span style={{ marginLeft: '0.5rem' }}>
                                  <a href={`tel:${ip.abuse.phone}`} style={{ color: '#3b82f6', textDecoration: 'none' }}>{ip.abuse.phone}</a>
                                </span>
                              )}
                            </div>
                          )}

                          {/* Hostname */}
                          {ip.hostname && (
                            <div style={{ padding: '0.15rem 0.3rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.65rem' }}>
                              <span style={{ color: 'var(--text-muted)' }}>Hostname: </span>
                              <span style={{ fontFamily: 'monospace' }}>{ip.hostname}</span>
                            </div>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                )}

                {/* Categories from VT */}
                {vtAttrs.categories && Object.keys(vtAttrs.categories).length > 0 && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#3CB371', fontSize: '0.6rem' }}>◆</span> Categories
                    </h3>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {Object.entries(vtAttrs.categories).slice(0, 6).map(([vendor, category], i) => (
                        <div key={i} style={{
                          padding: '0.15rem 0.3rem',
                          background: 'var(--bg-tertiary)',
                          borderRadius: '3px',
                          fontSize: '0.7rem'
                        }}>
                          <span style={{ color: 'var(--text-muted)' }}>{vendor}: </span>
                          <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{category}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* URLScan.io - compact layout - handles both search results and fresh scan results */}
                {urlscanEnrichment && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#00b4d8', fontSize: '0.6rem' }}>◆</span> URLScan.io
                      {(urlscanEnrichment.raw_data?.results?.length > 0 || urlscanEnrichment.raw_data?.page) && (
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: '400' }}>
                          ({urlscanEnrichment.raw_data?.results?.length || 1})
                        </span>
                      )}
                      {urlscanEnrichment.raw_data?.status === 'scan_pending' && (
                        <span style={{ fontSize: '0.6rem', color: '#f59e0b', marginLeft: '0.25rem' }}>Pending...</span>
                      )}
                    </h3>

                    {/* Fresh scan result (has page/verdicts directly in raw_data) */}
                    {urlscanEnrichment.raw_data?.page && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        <div style={{
                          display: 'flex',
                          gap: '0.4rem',
                          padding: '0.3rem',
                          background: 'var(--bg-tertiary)',
                          borderRadius: '4px',
                          alignItems: 'center'
                        }}>
                          {urlscanEnrichment.raw_data.task?.screenshotURL && (
                            <a href={urlscanEnrichment.raw_data.task.screenshotURL} target="_blank" rel="noopener noreferrer">
                              <img
                                src={urlscanEnrichment.raw_data.task.screenshotURL}
                                alt="Screenshot"
                                style={{ width: '60px', height: '45px', objectFit: 'cover', borderRadius: '3px', flexShrink: 0 }}
                                onError={(e) => { e.target.style.display = 'none'; }}
                              />
                            </a>
                          )}
                          <div style={{ flex: 1, fontSize: '0.7rem', minWidth: 0 }}>
                            <div style={{ fontWeight: '500', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {urlscanEnrichment.raw_data.page?.title || urlscanEnrichment.raw_data.page?.domain || 'Scan Complete'}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.15rem' }}>
                              {urlscanEnrichment.raw_data.verdicts?.overall?.malicious && (
                                <span style={{
                                  padding: '0.1rem 0.25rem',
                                  background: 'rgba(220, 38, 38, 0.15)',
                                  color: '#dc2626',
                                  borderRadius: '3px',
                                  fontSize: '0.6rem',
                                  fontWeight: '600'
                                }}>MALICIOUS</span>
                              )}
                              {urlscanEnrichment.raw_data.verdicts?.overall?.score > 0 && !urlscanEnrichment.raw_data.verdicts?.overall?.malicious && (
                                <span style={{
                                  padding: '0.1rem 0.25rem',
                                  background: 'rgba(245, 158, 11, 0.15)',
                                  color: '#f59e0b',
                                  borderRadius: '3px',
                                  fontSize: '0.6rem'
                                }}>Score: {urlscanEnrichment.raw_data.verdicts.overall.score}</span>
                              )}
                              {urlscanEnrichment.raw_data.page?.server && (
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>
                                  {urlscanEnrichment.raw_data.page.server}
                                </span>
                              )}
                              {urlscanEnrichment.tags?.includes('fresh_scan') && (
                                <span style={{
                                  padding: '0.1rem 0.2rem',
                                  background: 'rgba(34, 197, 94, 0.15)',
                                  color: '#22c55e',
                                  borderRadius: '2px',
                                  fontSize: '0.55rem'
                                }}>Fresh Scan</span>
                              )}
                            </div>
                          </div>
                          {urlscanEnrichment.raw_data.task?.reportURL && (
                            <a href={urlscanEnrichment.raw_data.task.reportURL} target="_blank" rel="noopener noreferrer" style={{
                              color: '#00b4d8',
                              fontSize: '0.65rem',
                              textDecoration: 'none',
                              padding: '0.2rem 0.3rem',
                              background: 'rgba(0, 180, 216, 0.1)',
                              borderRadius: '3px'
                            }}>
                              Report
                            </a>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Search results (array in raw_data.results) */}
                    {!urlscanEnrichment.raw_data?.page && urlscanEnrichment.raw_data?.results?.length > 0 && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        {urlscanEnrichment.raw_data.results.slice(0, 3).map((scan, idx) => (
                          <div key={idx} style={{
                            display: 'flex',
                            gap: '0.4rem',
                            padding: '0.25rem',
                            background: 'var(--bg-tertiary)',
                            borderRadius: '4px',
                            alignItems: 'center'
                          }}>
                            {scan.screenshot && (
                              <a href={scan.screenshot} target="_blank" rel="noopener noreferrer">
                                <img
                                  src={scan.screenshot}
                                  alt="Screenshot"
                                  style={{ width: '50px', height: '38px', objectFit: 'cover', borderRadius: '3px', flexShrink: 0 }}
                                  onError={(e) => { e.target.style.display = 'none'; }}
                                />
                              </a>
                            )}
                            <div style={{ flex: 1, fontSize: '0.7rem', minWidth: 0 }}>
                              <div style={{ fontWeight: '500', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {scan.page?.title || scan.task?.domain || 'Unknown'}
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', flexWrap: 'wrap' }}>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.6rem' }}>
                                  {scan.task?.time && new Date(scan.task.time).toLocaleDateString()}
                                </span>
                                {scan.task?.tags?.slice(0, 2).map((tag, i) => (
                                  <span key={i} style={{
                                    padding: '0.1rem 0.2rem',
                                    background: tag.includes('phishing') || tag.includes('malicious') ? 'rgba(220, 38, 38, 0.15)' : 'var(--bg-secondary)',
                                    color: tag.includes('phishing') || tag.includes('malicious') ? '#dc2626' : 'var(--text-muted)',
                                    borderRadius: '2px',
                                    fontSize: '0.6rem'
                                  }}>{tag}</span>
                                ))}
                              </div>
                            </div>
                            {scan.result && (
                              <a href={scan.result} target="_blank" rel="noopener noreferrer" style={{
                                color: '#00b4d8',
                                fontSize: '0.65rem',
                                textDecoration: 'none'
                              }}>
                                View
                              </a>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Scan pending/submitted state */}
                    {!urlscanEnrichment.raw_data?.page && !urlscanEnrichment.raw_data?.results?.length && urlscanEnrichment.raw_data?.result_url && (
                      <div style={{ padding: '0.4rem', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                        <div style={{ fontSize: '0.7rem', color: '#f59e0b', marginBottom: '0.2rem' }}>
                          Scan in progress...
                        </div>
                        <a href={urlscanEnrichment.raw_data.result_url} target="_blank" rel="noopener noreferrer" style={{
                          color: '#00b4d8',
                          fontSize: '0.65rem',
                          textDecoration: 'none'
                        }}>
                          View Result (when ready)
                        </a>
                      </div>
                    )}

                    {/* No data at all */}
                    {!urlscanEnrichment.raw_data?.page && !urlscanEnrichment.raw_data?.results?.length && !urlscanEnrichment.raw_data?.result_url && (
                      <div style={{ padding: '0.35rem', background: 'var(--bg-tertiary)', borderRadius: '4px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                        No scans found
                      </div>
                    )}
                  </div>
                )}

                {/* Related Items */}
                {(relatedEvents.length > 0 || relatedInvestigations.length > 0) && (
                  <div style={{ background: 'var(--bg-secondary)', borderRadius: '6px', padding: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <span style={{ color: '#ec4899', fontSize: '0.6rem' }}>◆</span> Related
                      <span style={{ padding: '0.1rem 0.25rem', background: 'var(--bg-tertiary)', borderRadius: '4px', fontSize: '0.65rem' }}>
                        {relatedEvents.length + relatedInvestigations.length}
                      </span>
                    </h3>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      {relatedInvestigations.slice(0, 3).map((inv, i) => (
                        <Link key={`inv-${i}`} to={`/investigation/${inv.id}`} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.3rem',
                          padding: '0.25rem',
                          background: 'var(--bg-tertiary)',
                          borderRadius: '4px',
                          textDecoration: 'none',
                          color: 'var(--text-primary)'
                        }}>
                          <span style={{ fontSize: '0.7rem' }}>🔍</span>
                          <div style={{ flex: 1, overflow: 'hidden' }}>
                            <div style={{ fontWeight: '500', fontSize: '0.7rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inv.title || 'Investigation'}</div>
                          </div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>→</span>
                        </Link>
                      ))}
                      {relatedEvents.slice(0, 3).map((event, i) => (
                        <Link key={`event-${i}`} to={`/queue?id=${event.id}`} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.3rem',
                          padding: '0.25rem',
                          background: 'var(--bg-tertiary)',
                          borderRadius: '4px',
                          textDecoration: 'none',
                          color: 'var(--text-primary)'
                        }}>
                          <span style={{ fontSize: '0.7rem' }}>⚡</span>
                          <div style={{ flex: 1, overflow: 'hidden' }}>
                            <div style={{ fontWeight: '500', fontSize: '0.7rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{event.title || event.alert_name || 'Alert'}</div>
                          </div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>→</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Vendor Results Tab */}
          {activeTab === 'vendors' && (
            <div style={{ background: 'var(--bg-secondary)', borderRadius: '8px', padding: '0.75rem' }}>
              <h3 style={{ fontSize: '0.8rem', fontWeight: '600', marginBottom: '0.5rem' }}>Security Vendor Results</h3>

              {vtAttrs.last_analysis_results && Object.keys(vtAttrs.last_analysis_results).length > 0 ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.4rem' }}>
                  {Object.entries(vtAttrs.last_analysis_results)
                    .sort(([, a], [, b]) => {
                      // Order: malicious first, then suspicious, then harmless (clean), then undetected (unrated)
                      const order = { malicious: 0, suspicious: 1, harmless: 2, undetected: 3 };
                      return (order[a.category] ?? 4) - (order[b.category] ?? 4);
                    })
                    .map(([vendor, result]) => (
                      <div key={vendor} style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '0.4rem 0.6rem',
                        background: 'var(--bg-tertiary)',
                        borderRadius: '5px',
                        borderLeft: `3px solid ${
                          result.category === 'malicious' ? '#dc2626' :
                          result.category === 'suspicious' ? '#f59e0b' :
                          result.category === 'harmless' ? '#22c55e' : '#6b7280'
                        }`
                      }}>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{vendor}</span>
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '0.15rem 0.4rem',
                          borderRadius: '3px',
                          background: result.category === 'malicious' ? 'rgba(220, 38, 38, 0.15)' :
                                     result.category === 'suspicious' ? 'rgba(245, 158, 11, 0.15)' :
                                     result.category === 'harmless' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(107, 114, 128, 0.15)',
                          color: result.category === 'malicious' ? '#dc2626' :
                                 result.category === 'suspicious' ? '#f59e0b' :
                                 result.category === 'harmless' ? '#22c55e' : '#6b7280'
                        }}>
                          {result.result || result.category}
                        </span>
                      </div>
                    ))}
                </div>
              ) : (
                <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  No vendor analysis results available
                </div>
              )}
            </div>
          )}

          {/* Raw Data Tab */}
          {activeTab === 'raw' && (
            <div style={{ background: 'var(--bg-secondary)', borderRadius: '10px', padding: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                {enrichments.map((e, i) => (
                  <button
                    key={i}
                    onClick={() => setSelectedRawProvider(selectedRawProvider === e.provider ? null : e.provider)}
                    style={{
                      padding: '0.4rem 0.75rem',
                      background: selectedRawProvider === e.provider ? theme.bg : 'var(--bg-tertiary)',
                      border: selectedRawProvider === e.provider ? `1px solid ${theme.primary}` : '1px solid transparent',
                      borderRadius: '5px',
                      color: selectedRawProvider === e.provider ? theme.primary : 'var(--text-secondary)',
                      cursor: 'pointer',
                      fontSize: '0.75rem'
                    }}
                  >
                    {e.provider}
                  </button>
                ))}
              </div>

              {selectedRawProvider && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600' }}>{selectedRawProvider}</span>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                      ({Object.keys(enrichments.find(e => e.provider === selectedRawProvider)?.raw_data || {}).length} fields)
                    </span>
                  </div>
                  <JsonViewer
                    data={enrichments.find(e => e.provider === selectedRawProvider)?.raw_data || {}}
                    onCopy={(text) => copyToClipboard(text, 'Copied to clipboard')}
                  />
                </div>
              )}

              {!selectedRawProvider && (
                <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  Select a provider above to view raw JSON data
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Provider Status (shown when no enrichment data) */}
      {!hasEnrichmentData && providerStatus.length > 0 && (
        <div style={{ background: 'var(--bg-secondary)', borderRadius: '10px', padding: '1rem' }}>
          <h3 style={{ fontSize: '0.9rem', fontWeight: '600', marginBottom: '0.75rem' }}>Provider Status</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {providerStatus.map((p, i) => (
              <div key={i} style={{
                padding: '0.4rem 0.6rem',
                background: p.status === 'cached' ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-tertiary)',
                borderRadius: '5px',
                fontSize: '0.75rem',
                color: p.status === 'cached' ? '#3b82f6' : 'var(--text-secondary)'
              }}>
                {p.provider_name} • {p.status}
              </div>
            ))}
          </div>
        </div>
      )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IOCDetail;


