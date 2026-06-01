/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Visual Playbook Editor (VPE)
 *
 * A node-based visual editor for creating and editing playbooks.
 * Uses React Flow for the graph canvas.
 *
 * Features:
 * - Drag-and-drop node palette
 * - Visual node graph with connections
 * - Data path picker for connecting node outputs to inputs
 * - Real-time validation
 * - Riggs AI assistant sidebar
 * - Execution monitoring
 *
 * NOTE: Requires reactflow package. Install with:
 *   npm install reactflow
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  BackgroundVariant,
  useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Play, Save, Settings, Zap, GitBranch, Shield, Mail, Clock,
  Code, Database, FileText, CheckCircle, XCircle, AlertTriangle,
  ChevronLeft, ChevronRight, Plus, Trash2, Copy, Eye, ToggleLeft,
  ToggleRight, Bot, RefreshCw, Download, Upload, Search, Filter
} from 'lucide-react';
import NodePalette from './NodePalette';
import DataPathPicker from './DataPathPicker';
import RiggsAssistant from './RiggsAssistant';
import ExecutionView from './ExecutionView';
import Editor from '@monaco-editor/react';
import { registerPythonCompletions, generateCodeFromInputs } from './pythonCompletions';

// Import custom node types
import TriggerNode from './NodeTypes/TriggerNode';
import RiggsNode from './NodeTypes/RiggsNode';
import EnrichNode from './NodeTypes/EnrichNode';
import ActionNode from './NodeTypes/ActionNode';
import ConditionNode from './NodeTypes/ConditionNode';
import WebformNode from './NodeTypes/WebformNode';
import PythonCodeNode from './NodeTypes/PythonCodeNode';
import EndNode from './NodeTypes/EndNode';
import GenericNode from './NodeTypes/GenericNode';

const API_BASE = process.env.REACT_APP_API_URL || '';

// Node type mappings for React Flow
const nodeTypes = {
  trigger: TriggerNode,
  riggs_analyze: RiggsNode,
  enrich: EnrichNode,
  action: ActionNode,
  condition: ConditionNode,
  switch: GenericNode,
  loop: GenericNode,
  parallel: GenericNode,
  merge: GenericNode,
  python_code: PythonCodeNode,
  function_call: GenericNode,
  transform: GenericNode,
  approval_gate: ActionNode,
  webform: WebformNode,
  file_upload: GenericNode,
  user_input: GenericNode,
  list_lookup: GenericNode,
  list_update: GenericNode,
  variable_set: GenericNode,
  variable_get: GenericNode,
  notify: GenericNode,
  create_ticket: GenericNode,
  webhook_call: GenericNode,
  delay: GenericNode,
  schedule: GenericNode,
  end: EndNode,
};

// Default edge options
const defaultEdgeOptions = {
  type: 'smoothstep',
  animated: true,
  style: { stroke: '#3CB371', strokeWidth: 2 },
};

function PlaybookEditor({ playbookId = null, onClose }) {
  // State
  const [playbook, setPlaybook] = useState(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState(null);
  const [showPalette, setShowPalette] = useState(true);
  const [showAssistant, setShowAssistant] = useState(false);
  const [showDataPathPicker, setShowDataPathPicker] = useState(false);
  const [dataPathContext, setDataPathContext] = useState(null);
  const [executionView, setExecutionView] = useState(null);
  const [hasChanges, setHasChanges] = useState(false);

  // Refs
  const reactFlowWrapper = useRef(null);
  const connectingNodeId = useRef(null);
  const reactFlowInstance = useRef(null);
  const pythonCompletionRef = useRef(false);

  const handlePythonEditorMount = useCallback((editor, monaco) => {
    if (pythonCompletionRef.current) return;
    pythonCompletionRef.current = true;
    registerPythonCompletions(monaco);
  }, []);

  // Load playbook
  useEffect(() => {
    if (playbookId) {
      loadPlaybook(playbookId);
    } else {
      // New playbook - create default structure
      setPlaybook({
        name: 'New Playbook',
        description: '',
        trigger_conditions: {},
        canvas_data: { nodes: [], edges: [] },
        tags: [],
        alert_types: [],
        is_enabled: false,
        riggs_allowed: false,
      });
      setNodes([
        {
          id: 'trigger-1',
          type: 'trigger',
          position: { x: 250, y: 50 },
          data: { label: 'Alert Trigger', config: {}, type: 'trigger' },
        },
      ]);
      setEdges([]);
    }
  }, [playbookId]);

  const loadPlaybook = async (id) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/api/v1/playbooks/${id}`);
      if (!response.ok) throw new Error('Failed to load playbook');

      const data = await response.json();
      setPlaybook(data);

      // Parse canvas data
      const canvasData = data.canvas_data || { nodes: [], edges: [] };
      const normalizedNodes = (canvasData.nodes || []).map((node) => ({
        ...node,
        data: {
          ...(node.data || {}),
          type: node.data?.type || node.type,
        },
      }));
      setNodes(normalizedNodes);
      setEdges(canvasData.edges || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Save playbook
  const savePlaybook = async () => {
    if (!playbook) return;

    setIsSaving(true);
    setError(null);

    try {
      const canvasData = { nodes, edges };

      const payload = {
        name: playbook.name,
        description: playbook.description,
        trigger_conditions: playbook.trigger_conditions,
        canvas_data: canvasData,
        tags: playbook.tags,
        alert_types: playbook.alert_types,
        severity_filter: playbook.severity_filter || [],
        data_sources: playbook.data_sources || [],
        priority: playbook.priority || 50,
      };

      let response;
      if (playbookId) {
        response = await fetch(`${API_BASE}/api/v1/playbooks/${playbookId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } else {
        response = await fetch(`${API_BASE}/api/v1/playbooks`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      if (!response.ok) throw new Error('Failed to save playbook');

      const data = await response.json();
      if (data.playbook) {
        setPlaybook(data.playbook);
      }
      setHasChanges(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsSaving(false);
    }
  };

  // Execute playbook
  const executePlaybook = async () => {
    if (!playbookId) {
      setError('Please save the playbook before executing');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/v1/playbooks/${playbookId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trigger_context: {
            manual: true,
            triggered_at: new Date().toISOString(),
          },
        }),
      });

      if (!response.ok) throw new Error('Failed to execute playbook');

      const data = await response.json();
      setExecutionView(data);
    } catch (err) {
      setError(err.message);
    }
  };

  // Toggle playbook enabled state
  const toggleEnabled = async () => {
    if (!playbookId) return;

    try {
      const endpoint = playbook.is_enabled ? 'disable' : 'enable';
      const response = await fetch(`${API_BASE}/api/v1/playbooks/${playbookId}/${endpoint}`, {
        method: 'POST',
      });

      if (!response.ok) throw new Error('Failed to toggle enabled state');

      setPlaybook((prev) => ({ ...prev, is_enabled: !prev.is_enabled }));
    } catch (err) {
      setError(err.message);
    }
  };

  // Toggle Riggs allowed
  const toggleRiggsAllowed = async () => {
    if (!playbookId) return;

    try {
      const endpoint = playbook.riggs_allowed ? 'disallow-riggs' : 'allow-riggs';
      const response = await fetch(`${API_BASE}/api/v1/playbooks/${playbookId}/${endpoint}`, {
        method: 'POST',
      });

      if (!response.ok) throw new Error('Failed to toggle Riggs permission');

      setPlaybook((prev) => ({ ...prev, riggs_allowed: !prev.riggs_allowed }));
    } catch (err) {
      setError(err.message);
    }
  };

  // Node operations
  const onNodesChange = useCallback((changes) => {
    setNodes((nds) => {
      // Apply changes (position, selection, etc.)
      let newNodes = [...nds];
      for (const change of changes) {
        if (change.type === 'position' && change.position) {
          const nodeIndex = newNodes.findIndex((n) => n.id === change.id);
          if (nodeIndex !== -1) {
            newNodes[nodeIndex] = {
              ...newNodes[nodeIndex],
              position: change.position,
            };
          }
        } else if (change.type === 'select') {
          const node = newNodes.find((n) => n.id === change.id);
          if (node && change.selected) {
            setSelectedNode(node);
          } else if (!change.selected && selectedNode?.id === change.id) {
            setSelectedNode(null);
          }
        } else if (change.type === 'remove') {
          newNodes = newNodes.filter((n) => n.id !== change.id);
          if (selectedNode?.id === change.id) {
            setSelectedNode(null);
          }
        }
      }
      return newNodes;
    });
    setHasChanges(true);
  }, [selectedNode]);

  const onEdgesChange = useCallback((changes) => {
    setEdges((eds) => {
      let newEdges = [...eds];
      for (const change of changes) {
        if (change.type === 'select') {
          const edge = newEdges.find((e) => e.id === change.id);
          if (edge && change.selected) {
            setSelectedEdge(edge);
          } else if (!change.selected && selectedEdge?.id === change.id) {
            setSelectedEdge(null);
          }
        } else if (change.type === 'remove') {
          newEdges = newEdges.filter((e) => e.id !== change.id);
        }
      }
      return newEdges;
    });
    setHasChanges(true);
  }, [selectedEdge]);

  const onConnect = useCallback((params) => {
    const newEdge = {
      id: `e${params.source}-${params.target}`,
      source: params.source,
      target: params.target,
      sourceHandle: params.sourceHandle,
      targetHandle: params.targetHandle,
      type: 'smoothstep',
      animated: true,
      style: { stroke: '#3CB371', strokeWidth: 2 },
    };
    setEdges((eds) => [...eds, newEdge]);
    setHasChanges(true);
  }, []);

  const addNode = useCallback((nodeType, position = null) => {
    const id = `${nodeType}-${Date.now()}`;
    const pos = position || {
      x: 250 + Math.random() * 100,
      y: 150 + nodes.length * 80,
    };

    const nodeLabels = {
      trigger: 'Alert Trigger',
      riggs_analyze: 'Riggs Analysis',
      enrich: 'Enrich IOCs',
      action: 'Response Action',
      condition: 'Condition',
      switch: 'Switch',
      loop: 'Loop',
      parallel: 'Parallel',
      merge: 'Merge',
      python_code: 'Python Code',
      function_call: 'Function Call',
      transform: 'Transform',
      approval_gate: 'Approval Gate',
      webform: 'Webform',
      file_upload: 'File Upload',
      user_input: 'User Input',
      list_lookup: 'List Lookup',
      list_update: 'List Update',
      variable_set: 'Set Variable',
      variable_get: 'Get Variable',
      notify: 'Notify',
      create_ticket: 'Create Ticket',
      webhook_call: 'Webhook',
      delay: 'Delay',
      schedule: 'Schedule',
      end: 'End',
    };

    const newNode = {
      id,
      type: nodeType,
      position: pos,
      data: {
        label: nodeLabels[nodeType] || nodeType,
        config: {},
        type: nodeType,
      },
    };

    setNodes((nds) => [...nds, newNode]);
    setSelectedNode(newNode);
    setHasChanges(true);
  }, [nodes]);

  // Handle drop on canvas
  const onDrop = useCallback((event) => {
    event.preventDefault();

    const type = event.dataTransfer.getData('application/reactflow');
    if (!type || !reactFlowInstance.current) return;

    // Use React Flow's coordinate transformation to convert screen position to flow position
    const position = reactFlowInstance.current.screenToFlowPosition({
      x: event.clientX,
      y: event.clientY,
    });

    addNode(type, position);
  }, [addNode]);

  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const deleteSelectedNode = useCallback(() => {
    if (!selectedNode) return;

    // Don't allow deleting trigger node if it's the only one
    if (selectedNode.type === 'trigger') {
      const triggerCount = nodes.filter((n) => n.type === 'trigger').length;
      if (triggerCount <= 1) {
        setError('Cannot delete the only trigger node');
        return;
      }
    }

    setNodes((nds) => nds.filter((n) => n.id !== selectedNode.id));
    setEdges((eds) =>
      eds.filter((e) => e.source !== selectedNode.id && e.target !== selectedNode.id)
    );
    setSelectedNode(null);
    setHasChanges(true);
  }, [selectedNode, nodes]);

  const duplicateSelectedNode = useCallback(() => {
    if (!selectedNode) return;

    const newId = `${selectedNode.type}-${Date.now()}`;
    const newNode = {
      ...selectedNode,
      id: newId,
      position: {
        x: selectedNode.position.x + 50,
        y: selectedNode.position.y + 50,
      },
      data: { ...selectedNode.data },
    };

    setNodes((nds) => [...nds, newNode]);
    setSelectedNode(newNode);
    setHasChanges(true);
  }, [selectedNode]);

  const updateNodeConfig = useCallback((nodeId, config) => {
    setNodes((nds) =>
      nds.map((node) =>
        node.id === nodeId
          ? { ...node, data: { ...node.data, config: { ...node.data.config, ...config } } }
          : node
      )
    );
    setHasChanges(true);
  }, []);

  const updateNodeLabel = useCallback((nodeId, label) => {
    setNodes((nds) =>
      nds.map((node) =>
        node.id === nodeId
          ? { ...node, data: { ...node.data, label } }
          : node
      )
    );
    setHasChanges(true);
  }, []);

  // Data path picker
  const openDataPathPicker = useCallback((nodeId, fieldName) => {
    setDataPathContext({ nodeId, fieldName });
    setShowDataPathPicker(true);
  }, []);

  const selectDataPath = useCallback((path) => {
    if (dataPathContext) {
      updateNodeConfig(dataPathContext.nodeId, {
        [dataPathContext.fieldName]: path,
      });
    }
    setShowDataPathPicker(false);
    setDataPathContext(null);
  }, [dataPathContext, updateNodeConfig]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ctrl/Cmd + S to save
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        savePlaybook();
      }
      // Delete key to remove selected node
      if (e.key === 'Delete' && selectedNode) {
        deleteSelectedNode();
      }
      // Ctrl/Cmd + D to duplicate
      if ((e.ctrlKey || e.metaKey) && e.key === 'd' && selectedNode) {
        e.preventDefault();
        duplicateSelectedNode();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedNode, savePlaybook, deleteSelectedNode, duplicateSelectedNode]);

  if (isLoading) {
    return (
      <div style={styles.loading}>
        <RefreshCw size={24} className="spin" />
        <span>Loading playbook...</span>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <button onClick={onClose} style={styles.backButton}>
            <ChevronLeft size={20} />
          </button>
          <div style={styles.titleSection}>
            <input
              type="text"
              value={playbook?.name || ''}
              onChange={(e) => {
                setPlaybook((prev) => ({ ...prev, name: e.target.value }));
                setHasChanges(true);
              }}
              style={styles.titleInput}
              placeholder="Playbook Name"
            />
            {hasChanges && <span style={styles.unsavedBadge}>Unsaved</span>}
          </div>
        </div>

        <div style={styles.headerCenter}>
          {/* State toggles */}
          <button
            onClick={toggleEnabled}
            style={{
              ...styles.toggleButton,
              ...(playbook?.is_enabled ? styles.toggleButtonActive : {}),
            }}
            disabled={!playbookId}
            title={playbook?.is_enabled ? 'Disable playbook' : 'Enable playbook'}
          >
            {playbook?.is_enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
            <span>{playbook?.is_enabled ? 'Enabled' : 'Disabled'}</span>
          </button>

          <button
            onClick={toggleRiggsAllowed}
            style={{
              ...styles.toggleButton,
              ...(playbook?.riggs_allowed ? styles.toggleButtonActive : {}),
            }}
            disabled={!playbookId}
            title={playbook?.riggs_allowed ? 'Revoke Riggs access' : 'Allow Riggs access'}
          >
            <Bot size={18} />
            <span>{playbook?.riggs_allowed ? 'Riggs Allowed' : 'Riggs Disabled'}</span>
          </button>
        </div>

        <div style={styles.headerRight}>
          <button
            onClick={executePlaybook}
            style={styles.executeButton}
            disabled={!playbookId || !playbook?.is_enabled}
            title="Execute playbook"
          >
            <Play size={18} />
            <span>Test Run</span>
          </button>

          <button
            onClick={savePlaybook}
            style={styles.saveButton}
            disabled={isSaving || !hasChanges}
          >
            <Save size={18} />
            <span>{isSaving ? 'Saving...' : 'Save'}</span>
          </button>

          <button
            onClick={() => setShowAssistant(!showAssistant)}
            style={{
              ...styles.assistantButton,
              ...(showAssistant ? styles.assistantButtonActive : {}),
            }}
            title="Riggs AI Assistant"
          >
            <Bot size={18} />
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div style={styles.errorBanner}>
          <AlertTriangle size={16} />
          <span>{error}</span>
          <button onClick={() => setError(null)} style={styles.errorClose}>
            <XCircle size={16} />
          </button>
        </div>
      )}

      {/* Main content */}
      <div style={styles.main}>
        {/* Node Palette */}
        {showPalette && (
          <NodePalette
            onAddNode={addNode}
            onCollapse={() => setShowPalette(false)}
          />
        )}

        {/* Collapsed palette toggle */}
        {!showPalette && (
          <button
            onClick={() => setShowPalette(true)}
            style={styles.paletteToggle}
          >
            <ChevronRight size={20} />
          </button>
        )}

        {/* Canvas */}
        <div
          style={styles.canvas}
          ref={reactFlowWrapper}
          onDrop={onDrop}
          onDragOver={onDragOver}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onInit={(instance) => {
              reactFlowInstance.current = instance;
            }}
            nodeTypes={nodeTypes}
            defaultEdgeOptions={defaultEdgeOptions}
            minZoom={0.2}
            maxZoom={2}
            zoomOnScroll={true}
            zoomOnPinch={true}
            zoomOnDoubleClick={false}
            nodesDraggable={true}
            nodesConnectable={true}
            elementsSelectable={true}
            panOnDrag={[2]}
            panOnScroll={false}
            selectNodesOnDrag={false}
            nodeDragThreshold={1}
            snapToGrid={false}
            attributionPosition="bottom-left"
            fitView
            fitViewOptions={{
              padding: 0.2,
              maxZoom: 1,
            }}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(51, 65, 85, 0.5)" />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={(n) => {
                if (n.type === 'trigger') return '#f59e0b';
                if (n.type === 'riggs_analyze') return '#8b5cf6';
                if (n.type === 'enrich') return '#3b82f6';
                if (n.type === 'action') return '#ef4444';
                if (n.type === 'condition') return '#14b8a6';
                return '#3CB371';
              }}
              maskColor="rgba(15, 23, 42, 0.8)"
            />
          </ReactFlow>
        </div>

        {/* Node Config Panel */}
        {selectedNode && (
          <NodeConfigPanel
            node={selectedNode}
            onUpdateConfig={(config) => updateNodeConfig(selectedNode.id, config)}
            onUpdateLabel={(label) => updateNodeLabel(selectedNode.id, label)}
            onDelete={deleteSelectedNode}
            onDuplicate={duplicateSelectedNode}
            onOpenDataPath={openDataPathPicker}
            onClose={() => setSelectedNode(null)}
            onPythonMount={handlePythonEditorMount}
          />
        )}

        {/* Riggs Assistant */}
        {showAssistant && (
          <RiggsAssistant
            playbookId={playbookId}
            nodes={nodes}
            edges={edges}
            setNodes={setNodes}
            setEdges={setEdges}
            setHasChanges={setHasChanges}
            onClose={() => setShowAssistant(false)}
          />
        )}
      </div>

      {/* Data Path Picker Modal */}
      {showDataPathPicker && (
        <DataPathPicker
          playbookId={playbookId}
          executionId={executionView?.execution_id}
          nodeId={dataPathContext?.nodeId}
          nodes={nodes}
          edges={edges}
          onSelect={selectDataPath}
          onClose={() => {
            setShowDataPathPicker(false);
            setDataPathContext(null);
          }}
        />
      )}

      {/* Execution View Modal */}
      {executionView && (
        <ExecutionView
          execution={executionView}
          onClose={() => setExecutionView(null)}
          onRefresh={() => {
            // Refresh execution status
            fetch(`${API_BASE}/api/v1/playbooks/executions/${executionView.execution_id}`)
              .then((r) => r.json())
              .then(setExecutionView)
              .catch(e => console.error('Execution refresh error:', e));
          }}
        />
      )}
    </div>
  );
}

/**
 * Node Configuration Panel
 */
function NodeConfigPanel({
  node,
  onUpdateConfig,
  onUpdateLabel,
  onDelete,
  onDuplicate,
  onOpenDataPath,
  onClose,
  onPythonMount,
}) {
  const config = node.data?.config || {};

  const renderConfigFields = () => {
    switch (node.type) {
      case 'trigger':
        return (
          <>
            <div style={styles.configField}>
              <label>Alert Types</label>
              <input
                type="text"
                value={(config.alert_types || []).join(', ')}
                onChange={(e) =>
                  onUpdateConfig({
                    alert_types: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="phishing, malware, ..."
                style={styles.configInput}
              />
            </div>
            <div style={styles.configField}>
              <label>Severities</label>
              <input
                type="text"
                value={(config.severities || []).join(', ')}
                onChange={(e) =>
                  onUpdateConfig({
                    severities: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="critical, high, medium, low"
                style={styles.configInput}
              />
            </div>
          </>
        );

      case 'condition':
        return (
          <>
            <div style={styles.configField}>
              <label>Field Path</label>
              <div style={styles.pathInputWrapper}>
                <input
                  type="text"
                  value={config.field || ''}
                  onChange={(e) => onUpdateConfig({ field: e.target.value })}
                  placeholder="$.riggs.verdict"
                  style={styles.configInput}
                />
                <button
                  onClick={() => onOpenDataPath(node.id, 'field')}
                  style={styles.pathPickerButton}
                >
                  <Search size={14} />
                </button>
              </div>
            </div>
            <div style={styles.configField}>
              <label>Operator</label>
              <select
                value={config.operator || 'equals'}
                onChange={(e) => onUpdateConfig({ operator: e.target.value })}
                style={styles.configSelect}
              >
                <option value="equals">Equals</option>
                <option value="not_equals">Not Equals</option>
                <option value="contains">Contains</option>
                <option value="greater_than">Greater Than</option>
                <option value="less_than">Less Than</option>
                <option value="in">In</option>
                <option value="is_empty">Is Empty</option>
              </select>
            </div>
            <div style={styles.configField}>
              <label>Value</label>
              <input
                type="text"
                value={config.value || ''}
                onChange={(e) => onUpdateConfig({ value: e.target.value })}
                placeholder="MALICIOUS"
                style={styles.configInput}
              />
            </div>
          </>
        );

      case 'action':
      case 'approval_gate':
        return (
          <>
            <div style={styles.configField}>
              <label>Action Type</label>
              <select
                value={config.action_type || ''}
                onChange={(e) => onUpdateConfig({ action_type: e.target.value })}
                style={styles.configSelect}
              >
                <option value="">Select action...</option>
                <option value="contain_host">Contain Host</option>
                <option value="disable_user">Disable User</option>
                <option value="block_ip">Block IP</option>
                <option value="block_domain">Block Domain</option>
                <option value="quarantine_file">Quarantine File</option>
                <option value="reset_password">Reset Password</option>
              </select>
            </div>
            <div style={styles.configField}>
              <label>Target Path</label>
              <div style={styles.pathInputWrapper}>
                <input
                  type="text"
                  value={config.target_path || ''}
                  onChange={(e) => onUpdateConfig({ target_path: e.target.value })}
                  placeholder="$.trigger.alert.host"
                  style={styles.configInput}
                />
                <button
                  onClick={() => onOpenDataPath(node.id, 'target_path')}
                  style={styles.pathPickerButton}
                >
                  <Search size={14} />
                </button>
              </div>
            </div>
            <div style={styles.configField}>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={config.requires_approval !== false}
                  onChange={(e) => onUpdateConfig({ requires_approval: e.target.checked })}
                />
                Requires Approval
              </label>
            </div>
          </>
        );

      case 'enrich':
        return (
          <>
            <div style={styles.configField}>
              <label>Integrations</label>
              <input
                type="text"
                value={(config.integrations || []).join(', ')}
                onChange={(e) =>
                  onUpdateConfig({
                    integrations: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="virustotal, abuseipdb, ..."
                style={styles.configInput}
              />
            </div>
            <div style={styles.configField}>
              <label>Data Path</label>
              <div style={styles.pathInputWrapper}>
                <input
                  type="text"
                  value={config.data_path || ''}
                  onChange={(e) => onUpdateConfig({ data_path: e.target.value })}
                  placeholder="$.trigger.alert.iocs"
                  style={styles.configInput}
                />
                <button
                  onClick={() => onOpenDataPath(node.id, 'data_path')}
                  style={styles.pathPickerButton}
                >
                  <Search size={14} />
                </button>
              </div>
            </div>
          </>
        );

      case 'notify':
        return (
          <>
            <div style={styles.configField}>
              <label>Channel</label>
              <select
                value={config.channel || 'email'}
                onChange={(e) => onUpdateConfig({ channel: e.target.value })}
                style={styles.configSelect}
              >
                <option value="email">Email</option>
                <option value="slack">Slack</option>
                <option value="teams">Microsoft Teams</option>
                <option value="webhook">Webhook</option>
              </select>
            </div>
            <div style={styles.configField}>
              <label>Recipients</label>
              <input
                type="text"
                value={(config.recipients || []).join(', ')}
                onChange={(e) =>
                  onUpdateConfig({
                    recipients: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="security@company.com, ..."
                style={styles.configInput}
              />
            </div>
            <div style={styles.configField}>
              <label>Subject</label>
              <input
                type="text"
                value={config.subject || ''}
                onChange={(e) => onUpdateConfig({ subject: e.target.value })}
                placeholder="Alert: {$.trigger.alert.title}"
                style={styles.configInput}
              />
            </div>
            <div style={styles.configField}>
              <label>Message</label>
              <textarea
                value={config.message || ''}
                onChange={(e) => onUpdateConfig({ message: e.target.value })}
                placeholder="Use {$.path} for data references"
                style={styles.configTextarea}
                rows={4}
              />
            </div>
          </>
        );

      case 'delay':
        return (
          <div style={styles.configField}>
            <label>Duration (seconds)</label>
            <input
              type="number"
              value={config.duration_seconds || 60}
              onChange={(e) => onUpdateConfig({ duration_seconds: parseInt(e.target.value) || 60 })}
              min={1}
              style={styles.configInput}
            />
          </div>
        );

      case 'python_code': {
        const inputEntries = Array.isArray(config.inputs) ? config.inputs : [];
        const nodeFnName = node.data?.label || config.function_name || 'main';
        const currentCode = config.code || '';
        const autoCode = generateCodeFromInputs(inputEntries, nodeFnName);
        const isAutoGenerated = !currentCode || currentCode === autoCode
          || currentCode === generateCodeFromInputs([], nodeFnName);

        const updateInputEntry = (idx, patch) => {
          const updated = inputEntries.map((e, i) => i === idx ? { ...e, ...patch } : e);
          onUpdateConfig({
            inputs: updated,
            ...(isAutoGenerated ? { code: generateCodeFromInputs(updated, nodeFnName) } : {}),
          });
        };

        const addInput = () => {
          const updated = [...inputEntries, { key: '', value: '' }];
          onUpdateConfig({
            inputs: updated,
            ...(isAutoGenerated ? { code: generateCodeFromInputs(updated, nodeFnName) } : {}),
          });
        };

        const removeInput = (idx) => {
          const updated = inputEntries.filter((_, i) => i !== idx);
          onUpdateConfig({
            inputs: updated,
            ...(isAutoGenerated ? { code: generateCodeFromInputs(updated, nodeFnName) } : {}),
          });
        };

        return (
          <>
            {/* Inputs Editor */}
            <div style={styles.configField}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <label style={{ margin: 0 }}>Inputs</label>
                <button
                  onClick={addInput}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '4px',
                    padding: '4px 10px', border: '1px solid var(--border-color, #334155)',
                    borderRadius: '4px', background: 'rgba(60,179,113,0.15)',
                    color: '#3CB371', fontSize: '12px', cursor: 'pointer',
                  }}
                >
                  <Plus size={12} /> Add Input
                </button>
              </div>

              {inputEntries.map((entry, idx) => (
                <div key={idx} style={{
                  padding: '8px', marginBottom: '6px', borderRadius: '6px',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid var(--border-color, #334155)',
                }}>
                  <div style={{ display: 'flex', gap: '4px', marginBottom: '6px' }}>
                    <input
                      type="text"
                      value={entry.key || ''}
                      onChange={(e) => updateInputEntry(idx, { key: e.target.value })}
                      placeholder="variable name"
                      style={{ ...styles.configInput, marginTop: 0, flex: 1, fontSize: '12px', padding: '6px 8px' }}
                    />
                    <button
                      onClick={() => removeInput(idx)}
                      style={{
                        background: 'none', border: 'none', color: '#ef4444',
                        cursor: 'pointer', padding: '4px',
                      }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                  <input
                    type="text"
                    value={entry.value || ''}
                    onChange={(e) => updateInputEntry(idx, { value: e.target.value })}
                    placeholder="$.trigger.alert.* or literal value"
                    style={{ ...styles.configInput, marginTop: 0, fontSize: '12px', padding: '6px 8px' }}
                  />
                </div>
              ))}

              {inputEntries.length === 0 && (
                <small style={styles.helpText}>
                  No inputs defined. Click "Add Input" to map data into your code.
                </small>
              )}
            </div>

            {/* Monaco Code Editor */}
            <div style={styles.configField}>
              <label>Python Code</label>
              <div style={{ marginTop: '6px', border: '1px solid var(--border-color, #334155)', borderRadius: '6px', overflow: 'hidden' }}>
                <Editor
                  height="260px"
                  language="python"
                  theme="vs-dark"
                  value={currentCode || generateCodeFromInputs(inputEntries, nodeFnName)}
                  onChange={(val) => onUpdateConfig({ code: val || '' })}
                  onMount={onPythonMount}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 13,
                    wordWrap: 'on',
                    tabSize: 4,
                    insertSpaces: true,
                    automaticLayout: true,
                    scrollBeyondLastLine: false,
                    renderLineHighlight: 'line',
                    quickSuggestions: true,
                    suggestOnTriggerCharacters: true,
                    scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
                  }}
                />
              </div>
              <small style={styles.helpText}>
                Define a {nodeFnName}() function that receives inputs and returns a dict.
                {isAutoGenerated && inputEntries.length > 0 && ' Code auto-updates with inputs.'}
              </small>
            </div>
          </>
        );
      }

      default:
        return (
          <div style={styles.configField}>
            <p style={styles.noConfig}>
              Configure this node type using the JSON editor below.
            </p>
            <textarea
              value={JSON.stringify(config, null, 2)}
              onChange={(e) => {
                try {
                  const parsed = JSON.parse(e.target.value);
                  onUpdateConfig(parsed);
                } catch {
                  // Invalid JSON, don't update
                }
              }}
              style={{ ...styles.configTextarea, fontFamily: 'monospace' }}
              rows={8}
            />
          </div>
        );
    }
  };

  return (
    <div style={styles.configPanel}>
      <div style={styles.configHeader}>
        <h3>Configure Node</h3>
        <button onClick={onClose} style={styles.closeButton}>
          <XCircle size={18} />
        </button>
      </div>

      <div style={styles.configBody}>
        <div style={styles.configField}>
          <label>Label</label>
          <input
            type="text"
            value={node.data?.label || ''}
            onChange={(e) => onUpdateLabel(e.target.value)}
            style={styles.configInput}
          />
        </div>

        <div style={styles.configField}>
          <label>Type</label>
          <input
            type="text"
            value={node.type}
            disabled
            style={{ ...styles.configInput, background: 'rgba(255,255,255,0.05)' }}
          />
        </div>

        <div style={styles.configDivider} />

        {renderConfigFields()}
      </div>

      <div style={styles.configFooter}>
        <button onClick={onDuplicate} style={styles.configActionButton}>
          <Copy size={14} /> Duplicate
        </button>
        <button
          onClick={onDelete}
          style={{ ...styles.configActionButton, ...styles.deleteButton }}
        >
          <Trash2 size={14} /> Delete
        </button>
      </div>
    </div>
  );
}

// Styles
const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
  },
  loading: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
    height: '100vh',
    color: 'var(--text-secondary, #94a3b8)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-secondary, #1e293b)',
  },
  headerLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  headerCenter: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  backButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '36px',
    height: '36px',
    border: 'none',
    borderRadius: '8px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  titleSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  titleInput: {
    fontSize: '18px',
    fontWeight: '600',
    background: 'transparent',
    border: 'none',
    color: 'var(--text-primary, #f0f6fc)',
    padding: '4px 8px',
    borderRadius: '4px',
    minWidth: '200px',
  },
  unsavedBadge: {
    fontSize: '11px',
    padding: '2px 6px',
    borderRadius: '4px',
    background: 'rgba(245, 158, 11, 0.2)',
    color: '#f59e0b',
  },
  toggleButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '8px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  toggleButtonActive: {
    background: 'rgba(60, 179, 113, 0.2)',
    borderColor: '#3CB371',
    color: '#3CB371',
  },
  executeButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 16px',
    border: 'none',
    borderRadius: '8px',
    background: 'linear-gradient(135deg, #3b82f6, #2563eb)',
    color: 'white',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
  },
  saveButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 16px',
    border: 'none',
    borderRadius: '8px',
    background: 'linear-gradient(135deg, #3CB371, #2e8b57)',
    color: 'white',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
  },
  assistantButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '36px',
    height: '36px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '8px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  assistantButtonActive: {
    background: 'rgba(139, 92, 246, 0.2)',
    borderColor: '#8b5cf6',
    color: '#8b5cf6',
  },
  errorBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 16px',
    background: 'rgba(239, 68, 68, 0.2)',
    borderBottom: '1px solid rgba(239, 68, 68, 0.3)',
    color: '#ef4444',
    fontSize: '13px',
  },
  errorClose: {
    marginLeft: 'auto',
    background: 'none',
    border: 'none',
    color: '#ef4444',
    cursor: 'pointer',
  },
  main: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
  },
  paletteToggle: {
    position: 'absolute',
    left: 0,
    top: '50%',
    transform: 'translateY(-50%)',
    width: '24px',
    height: '48px',
    border: 'none',
    borderRadius: '0 8px 8px 0',
    background: 'var(--bg-secondary, #1e293b)',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
    zIndex: 10,
  },
  canvas: {
    flex: 1,
    position: 'relative',
    background: 'var(--bg-primary, #0f172a)',
  },
  canvasPlaceholder: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    background: `
      linear-gradient(rgba(51, 65, 85, 0.3) 1px, transparent 1px),
      linear-gradient(90deg, rgba(51, 65, 85, 0.3) 1px, transparent 1px)
    `,
    backgroundSize: '20px 20px',
  },
  canvasInfo: {
    textAlign: 'center',
    padding: '40px',
    background: 'var(--bg-secondary, #1e293b)',
    borderRadius: '16px',
    border: '1px solid var(--border-color, #334155)',
    maxWidth: '600px',
  },
  canvasInfoIcon: {
    color: 'var(--t1-emerald, #3CB371)',
    marginBottom: '16px',
  },
  installCode: {
    display: 'inline-block',
    padding: '8px 16px',
    background: 'rgba(0,0,0,0.3)',
    borderRadius: '6px',
    fontFamily: 'monospace',
    fontSize: '13px',
    marginTop: '12px',
  },
  nodeList: {
    marginTop: '24px',
    textAlign: 'left',
  },
  nodeItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '8px 12px',
    borderRadius: '6px',
    marginBottom: '4px',
    background: 'rgba(255,255,255,0.05)',
    cursor: 'pointer',
  },
  nodeItemSelected: {
    background: 'rgba(60, 179, 113, 0.2)',
    border: '1px solid #3CB371',
  },
  nodeType: {
    fontSize: '11px',
    padding: '2px 6px',
    borderRadius: '4px',
    background: 'rgba(60, 179, 113, 0.2)',
    color: '#3CB371',
    fontWeight: '500',
  },
  nodeLabel: {
    fontSize: '13px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  edgeList: {
    marginTop: '16px',
    textAlign: 'left',
  },
  edgeItem: {
    fontSize: '12px',
    color: 'var(--text-secondary, #94a3b8)',
    padding: '4px 0',
  },
  configPanel: {
    width: '320px',
    borderLeft: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-secondary, #1e293b)',
    display: 'flex',
    flexDirection: 'column',
  },
  configHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  closeButton: {
    background: 'none',
    border: 'none',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  configBody: {
    flex: 1,
    overflow: 'auto',
    padding: '16px',
  },
  configField: {
    marginBottom: '16px',
  },
  configInput: {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    marginTop: '6px',
  },
  configSelect: {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    marginTop: '6px',
  },
  configTextarea: {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    marginTop: '6px',
    resize: 'vertical',
  },
  pathInputWrapper: {
    display: 'flex',
    gap: '4px',
    marginTop: '6px',
  },
  pathPickerButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '36px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    cursor: 'pointer',
  },
  configDivider: {
    height: '1px',
    background: 'var(--border-color, #334155)',
    margin: '16px 0',
  },
  configFooter: {
    display: 'flex',
    gap: '8px',
    padding: '16px',
    borderTop: '1px solid var(--border-color, #334155)',
  },
  configActionButton: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    padding: '10px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
    cursor: 'pointer',
  },
  deleteButton: {
    borderColor: 'rgba(239, 68, 68, 0.3)',
    color: '#ef4444',
  },
  helpText: {
    display: 'block',
    marginTop: '6px',
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  noConfig: {
    fontSize: '13px',
    color: 'var(--text-secondary, #94a3b8)',
    marginBottom: '12px',
  },
};

export default PlaybookEditor;
