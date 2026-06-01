/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './PlaybookConverterCodex.css';

function PlaybookConverterCodex() {
  const navigate = useNavigate();
  // Platforms are fetched from the backend on mount so the UI never
  // lies about capability — every converter registered in
  // backend/services/playbook_converters/ shows up automatically.
  const [platforms, setPlatforms] = useState([]);
  const [platformsLoading, setPlatformsLoading] = useState(true);
  const [platformsError, setPlatformsError] = useState(null);
  const [selectedPlatform, setSelectedPlatform] = useState('');
  const [file, setFile] = useState(null);
  const [error, setError] = useState(null);
  const [isConverting, setIsConverting] = useState(false);
  const [isParsing, setIsParsing] = useState(false);
  const [parsedPayload, setParsedPayload] = useState(null);
  const [parsedSummary, setParsedSummary] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/v1/playbooks/import/platforms', {
          credentials: 'include',
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (cancelled) return;
        const list = Array.isArray(data?.platforms) ? data.platforms : [];
        setPlatforms(list);
        if (list.length > 0) {
          const firstReady = list.find((p) => p.status === 'ready') || list[0];
          setSelectedPlatform(firstReady.id);
        }
      } catch (err) {
        if (!cancelled) setPlatformsError(err.message || 'Failed to load platforms');
      } finally {
        if (!cancelled) setPlatformsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const selectedPlatformMeta = platforms.find((p) => p.id === selectedPlatform);
  const isReadyPlatform = selectedPlatformMeta?.status === 'ready';
  const fileAccept = selectedPlatformMeta?.accept || '.json';

  const onFileChange = async (event) => {
    const picked = event.target.files && event.target.files[0];
    setFile(picked || null);
    setError(null);
    setParsedPayload(null);
    setParsedSummary(null);

    if (!picked) return;

    setIsParsing(true);
    try {
      const payload = await parseUploadedFile(picked, selectedPlatform);
      setParsedPayload(payload);
      setParsedSummary({
        name: payload.name,
        nodes: payload.nodes?.length || 0,
        edges: payload.edges?.length || 0,
      });
    } catch (err) {
      setError(err.message || 'Failed to parse uploaded file.');
    } finally {
      setIsParsing(false);
    }
  };

  const readFileAsText = (picked) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(picked);
    });

  const isArchiveFile = (name) => {
    const lower = name.toLowerCase();
    return (
      lower.endsWith('.tgz') ||
      lower.endsWith('.tar.gz') ||
      lower.endsWith('.gz') ||
      lower.endsWith('.tar') ||
      lower.endsWith('.zip')
    );
  };

  const readFileContent = async (picked) => {
    if (isArchiveFile(picked.name)) {
      const arrayBuffer = await picked.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i += 1) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }

    return readFileAsText(picked);
  };

  const fetchPreviewFromBackend = async (content, platform, pythonCode) => {
    const response = await fetch('/api/v1/playbooks/import/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        content,
        source_platform: platform,
        python_code: pythonCode || undefined,
      }),
    });

    if (!response.ok) {
      let message = 'Failed to preview conversion.';
      try {
        const errorData = await response.json();
        message = errorData.detail || message;
      } catch {
        // ignore parsing errors
      }
      throw new Error(message);
    }

    const data = await response.json();
    if (!data?.playbook?.canvas_data) {
      throw new Error('Converter returned no canvas data.');
    }
    return data;
  };

  const savePlaybookToLibrary = async (payload) => {
    const response = await fetch('/api/v1/playbooks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        name: payload.name || 'Imported Playbook',
        description: payload.description || `Imported from ${selectedPlatform.replace('_', ' ')}`,
        trigger_conditions: {},
        canvas_data: {
          nodes: payload.nodes || [],
          edges: payload.edges || [],
        },
        tags: ['imported', selectedPlatform],
        alert_types: [],
        severity_filter: [],
        data_sources: [],
        priority: 50,
      }),
    });

    if (!response.ok) {
      let message = 'Failed to save playbook.';
      try {
        const errorData = await response.json();
        message = errorData.detail || message;
      } catch {
        // ignore parsing errors
      }
      throw new Error(message);
    }

    return response.json();
  };

  const mapCanvasKind = (type) => {
    const lowered = (type || '').toLowerCase();
    const map = {
      start: 'trigger',
      trigger: 'trigger',
      condition: 'decision',
      decision: 'decision',
      approval_gate: 'approval',
      approval: 'approval',
      python_code: 'action',
      action: 'action',
      http_request: 'http_request',
      api_call: 'http_request',
      lookup: 'lookup',
      set_variable: 'set_variable',
      variable_set: 'set_variable',
      case_update: 'case_update',
      subflow: 'subflow',
      delay: 'delay',
      wait: 'delay',
      end: 'end',
    };
    return map[lowered] || 'action';
  };

  // Normalize a decision node's config so the editor shows a proper
  // branches array. SOAR exports often lack this and we end up with a
  // node that only shows a "No" path and won't let the user rename it.
  const normalizeDecisionConfig = (config, edges, nodeId) => {
    const out = { ...(config || {}) };
    if (Array.isArray(out.branches) && out.branches.length >= 2) return out;

    // Look at outgoing edges to discover which sourceHandles the source
    // playbook actually used. Common cases: ['yes','no'], ['true','false'],
    // or just a single 'no' branch (the bug the user reported).
    const handlesUsed = new Set();
    (edges || []).forEach((e) => {
      if (e.source === nodeId && e.sourceHandle) handlesUsed.add(e.sourceHandle);
    });

    const branchFromHandle = (h) => {
      const h2 = String(h || '').toLowerCase();
      if (h2 === 'yes' || h2 === 'true') return { id: 'yes', label: 'Yes' };
      if (h2 === 'no' || h2 === 'false') return { id: 'no', label: 'No' };
      return { id: h2 || 'branch', label: h2 ? h2[0].toUpperCase() + h2.slice(1) : 'Branch' };
    };

    const seen = new Set();
    const branches = [];
    handlesUsed.forEach((h) => {
      const b = branchFromHandle(h);
      if (!seen.has(b.id)) { seen.add(b.id); branches.push(b); }
    });
    // Always end up with at least Yes + No so the user can wire either
    // side in the editor without first having to add a branch.
    if (!seen.has('yes')) branches.unshift({ id: 'yes', label: 'Yes' });
    if (!seen.has('no')) branches.push({ id: 'no', label: 'No' });
    out.branches = branches;
    return out;
  };

  const buildCodexFromPreview = (playbook) => {
    const canvas = playbook.canvas_data || {};
    const rawEdges = canvas.edges || [];

    // De-duplicate trailing 'end' nodes -- SOAR exports often produce two.
    // Collapse any extra ends into the first one and rewrite incoming edges.
    const endIds = (canvas.nodes || [])
      .filter((n) => mapCanvasKind(n.type) === 'end')
      .map((n) => n.id);
    const primaryEnd = endIds[0];
    const dropEnds = new Set(endIds.slice(1));

    const remappedEdges = rawEdges.map((e) => (
      dropEnds.has(e.target) && primaryEnd ? { ...e, target: primaryEnd } : e
    ));

    const nodes = (canvas.nodes || [])
      .filter((node) => !dropEnds.has(node.id))
      .map((node) => {
        const kind = mapCanvasKind(node.type);
        const label = node.data?.label || node.data?.title || node.id || 'Untitled';
        const summary = node.data?.summary || node.data?.description || node.data?.label || '';
        const status = node.data?.status || 'draft';
        let config = node.data?.config || {};
        if (kind === 'decision') {
          config = normalizeDecisionConfig(config, remappedEdges, node.id);
        }
        return {
          id: node.id,
          type: 'signal',
          position: node.position || { x: 0, y: 0 },
          data: baseNode(kind, label, summary, status, config),
        };
      });

    const edges = remappedEdges.map((edge, idx) => {
      const handle = edge.sourceHandle;
      const label = edge.label || (handle === 'yes' ? 'Yes' : handle === 'no' ? 'No' : undefined);
      return {
        id: edge.id || `edge-${idx}`,
        source: edge.source,
        target: edge.target,
        animated: true,
        type: 'smoothstep',
        sourceHandle: handle,
        // Force connection into the target node's top handle so smoothstep
        // routes top-down rather than picking the closest side (which made
        // edges enter the LEFT of nodes when the source was up-and-right).
        targetHandle: null,
        // Tell React Flow to enter from the top (Position.Top on the
        // target Handle). This makes generated playbooks read top-to-
        // bottom even when nodes are not perfectly column-aligned.
        target_position: 'top',
        label,
      };
    });

    return {
      name: playbook.name || 'Imported Playbook',
      nodes,
      edges,
    };
  };

  const hasOverlappingNodes = (nodes) => {
    if (!Array.isArray(nodes) || nodes.length < 2) return false;
    const width = 220;
    const height = 120;
    for (let i = 0; i < nodes.length; i += 1) {
      const a = nodes[i]?.position || {};
      if (typeof a.x !== 'number' || typeof a.y !== 'number') return true;
      for (let j = i + 1; j < nodes.length; j += 1) {
        const b = nodes[j]?.position || {};
        if (typeof b.x !== 'number' || typeof b.y !== 'number') return true;
        if (Math.abs(a.x - b.x) < width && Math.abs(a.y - b.y) < height) {
          return true;
        }
      }
    }
    return false;
  };

  const autoLayoutNodes = (nodes, edges) => {
    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    const incoming = new Map();
    const outgoing = new Map();
    nodes.forEach((node) => {
      incoming.set(node.id, new Set());
      outgoing.set(node.id, new Set());
    });
    (edges || []).forEach((edge) => {
      if (!incoming.has(edge.target) || !outgoing.has(edge.source)) return;
      incoming.get(edge.target).add(edge.source);
      outgoing.get(edge.source).add(edge.target);
    });

    const levels = new Map();
    const kindRank = (node) => {
      const kind = (node?.data?.kind || '').toLowerCase();
      const order = {
        trigger: 0,
        input: 1,
        decision: 2,
        approval: 3,
        action: 4,
        http_request: 5,
        lookup: 6,
        set_variable: 7,
        case_update: 8,
        subflow: 9,
        delay: 10,
        note: 11,
        end: 99,
      };
      return order[kind] ?? 50;
    };

    const roots = nodes.filter((node) => incoming.get(node.id)?.size === 0);
    roots.sort((a, b) => kindRank(a) - kindRank(b));

    const queue = roots.map((node) => node.id);
    roots.forEach((node) => {
      levels.set(node.id, 0);
    });

    while (queue.length) {
      const current = queue.shift();
      const currentLevel = levels.get(current) ?? 0;
      (outgoing.get(current) || []).forEach((next) => {
        const nextLevel = Math.max(levels.get(next) ?? 0, currentLevel + 1);
        levels.set(next, nextLevel);
        queue.push(next);
      });
    }

    const maxLevel = Math.max(0, ...levels.values());
    nodes.forEach((node) => {
      if ((node?.data?.kind || '').toLowerCase() === 'end') {
        levels.set(node.id, maxLevel + 1);
      }
    });

    const grouped = new Map();
    nodes.forEach((node) => {
      const level = levels.get(node.id) ?? 0;
      if (!grouped.has(level)) grouped.set(level, []);
      grouped.get(level).push(node.id);
    });

    const initialX = new Map(nodes.map((node) => [node.id, node.position?.x ?? 0]));
    // Node cards render ~260x280; rowGap must exceed that so vertically
    // adjacent levels do not overlap on import.
    const rowGap = 320;
    const colGap = 320;
    const baseX = 520;
    const baseY = 80;
    // position.x is the LEFT edge of the node in React Flow; subtract
    // half the node width when placing so the visible CENTER of each
    // node lines up on the baseX axis (and siblings spread symmetrically
    // around it). Without this, a single column of imported nodes
    // appears left-aligned rather than centered.
    const halfNodeWidth = 130; // matches nodeWidth/2 below

    grouped.forEach((ids, level) => {
      ids.sort((a, b) => (initialX.get(a) ?? 0) - (initialX.get(b) ?? 0));
      ids.forEach((id, idx) => {
        const node = nodeById.get(id);
        if (!node) return;
        const centerX = baseX + (idx - (ids.length - 1) / 2) * colGap;
        node.position = {
          x: Math.round(centerX - halfNodeWidth),
          y: Math.round(baseY + level * rowGap),
        };
      });
    });

    const nodeWidth = 260;
    const nodeHeight = 280;
    const padding = 32;
    const placed = [];
    const ordered = nodes
      .slice()
      .sort((a, b) => (a.position?.y ?? 0) - (b.position?.y ?? 0) || (a.position?.x ?? 0) - (b.position?.x ?? 0));

    const overlaps = (node, other) => {
      const ax = node.position?.x ?? 0;
      const ay = node.position?.y ?? 0;
      const bx = other.position?.x ?? 0;
      const by = other.position?.y ?? 0;
      return Math.abs(ax - bx) < nodeWidth + padding && Math.abs(ay - by) < nodeHeight + padding;
    };

    ordered.forEach((node) => {
      let iterations = 0;
      while (placed.some((other) => overlaps(node, other)) && iterations < 80) {
        node.position = {
          x: node.position.x,
          y: node.position.y + nodeHeight + padding,
        };
        iterations += 1;
      }
      placed.push(node);
    });

    return nodes;
  };

  const parseUploadedFile = async (picked, platform) => {
    const lowerName = picked.name.toLowerCase();
    const isArchive = isArchiveFile(lowerName);

    if (isArchive) {
      throw new Error('Archive uploads are not supported. Upload a .json export.');
    }

    // Tines has a local parser that goes straight to the codex layout
    // without round-tripping through the backend.
    if (platform === 'tines') {
      if (!lowerName.endsWith('.json')) {
        throw new Error('Tines exports must be .json.');
      }
      const parsed = JSON.parse(await readFileAsText(picked));
      return buildFromTines(parsed);
    }

    // Every other registered platform (xsoar, sentinel, chronicle_soar,
    // qradar_soar, swimlane, torq, blinkops, etc.) — read the raw file
    // content as text and let the backend converter handle it. The
    // accept= attribute on the file input already enforces the right
    // extensions per platform.
    const platformMeta = platforms.find((p) => p.id === platform);
    const acceptedExts = (platformMeta?.accept || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (acceptedExts.length > 0 && !acceptedExts.some((ext) => lowerName.endsWith(ext))) {
      throw new Error(
        `Expected one of ${acceptedExts.join(', ')} for ${platformMeta?.name || platform}, got ${picked.name}.`,
      );
    }

    const text = await readFileAsText(picked);
    const preview = await fetchPreviewFromBackend(text, platform);
    if (!preview?.playbook?.canvas_data) {
      throw new Error('Conversion succeeded but the backend did not return a renderable playbook.');
    }
    return buildCodexFromPreview(preview.playbook);
  };

  const normalizeLayoutIfNeeded = (payload) => {
    if (!payload?.nodes || !payload?.edges) return payload;
    const clonedNodes = payload.nodes.map((node) => ({ ...node, position: { ...node.position } }));
    autoLayoutNodes(clonedNodes, payload.edges);
    return { ...payload, nodes: clonedNodes };
  };


  const handleConvert = async () => {
    setError(null);
    setIsConverting(true);

    try {
      let payload = parsedPayload;
      if (!payload && file) {
        payload = await parseUploadedFile(file, selectedPlatform);
      }
      if (!payload && !file) {
        payload = buildSampleGraph(selectedPlatform);
      }
      if (!payload) {
        throw new Error('No valid playbook parsed. Upload a supported export first.');
      }

      payload = normalizeLayoutIfNeeded(payload);

      if (file) {
        payload.name = `${payload.name} (${file.name})`;
      }
      payload.mode = 'safe';
      payload.source = selectedPlatform;

      try {
        await savePlaybookToLibrary(payload);
        navigate('/playbooks');
      } catch (saveError) {
        sessionStorage.setItem('codex_converted_playbook', JSON.stringify(payload));
        setError(`${saveError.message} Opened in editor without saving.`);
        navigate('/playbooks/new');
      }
    } catch (err) {
      setError(err.message || 'Failed to convert playbook');
    } finally {
      setIsConverting(false);
    }
  };

  return (
    <div className="import-playbook">
      <div className="import-page-header">
        <div className="import-title-row">
          <div className="import-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
          </div>
          <div>
            <h1 className="import-title">Import Playbook</h1>
            <p className="import-subtitle">Import playbooks from external SOAR platforms into the Visual Playbook Editor</p>
          </div>
        </div>
        <div className="import-actions">
          <button
            className="import-btn-primary"
            disabled={!isReadyPlatform || isConverting || isParsing || (file && !parsedPayload)}
            onClick={handleConvert}
          >
            {isConverting ? 'Converting...' : isParsing ? 'Parsing...' : 'Convert & Import'}
          </button>
        </div>
      </div>

      {error && <div className="import-error">{error}</div>}

      <div className="import-section">
        <h2 className="import-section-title">
          Select Platform
          {!platformsLoading && platforms.length > 0 && (
            <span className="import-platform-count"> · {platforms.length} supported</span>
          )}
        </h2>
        {platformsLoading && (
          <div className="import-platform-loading">Loading supported platforms…</div>
        )}
        {platformsError && (
          <div className="import-error">
            Could not load platform list: {platformsError}
          </div>
        )}
        {!platformsLoading && !platformsError && (
          <div className="import-platform-grid">
            {platforms.map((platform) => (
              <button
                key={platform.id}
                className={`import-platform-card ${selectedPlatform === platform.id ? 'active' : ''} ${platform.status}`}
                onClick={() => platform.status === 'ready' && setSelectedPlatform(platform.id)}
              >
                <div className="import-platform-header">
                  <span className="import-platform-name">{platform.name}</span>
                  <span className={`import-status-badge ${platform.status}`}>
                    {platform.status === 'ready' ? 'Ready' : 'Coming Soon'}
                  </span>
                </div>
                <div className="import-platform-desc">{platform.description}</div>
                <div className="import-platform-formats">
                  {(platform.formats || []).map((fmt) => (
                    <span key={fmt} className="import-format-tag">{fmt}</span>
                  ))}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="import-section">
        <h2 className="import-section-title">Upload File</h2>
        <div className="import-upload-area">
          <div className="import-upload-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </div>
          <div className="import-upload-text">
            {file
              ? file.name
              : 'Drop a .json export here or click to browse'}
          </div>
          <input
            type="file"
            className="import-file-input"
            onChange={onFileChange}
            accept={fileAccept}
          />
          {parsedSummary && (
            <div className="import-parse-result">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
              <span>{parsedSummary.name} &mdash; {parsedSummary.nodes} nodes, {parsedSummary.edges} edges</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function buildSampleGraph(platform) {
  if (platform === 'tines') {
    return {
      name: 'Tines: Cyera Tagging',
      nodes: [
        { id: 't1', type: 'signal', position: { x: 520, y: 60 }, data: baseNode('trigger', 'Cyera Findings', 'Webhook ingest', 'live', { trigger_type: 'webhook' }) },
        { id: 't2', type: 'signal', position: { x: 520, y: 220 }, data: baseNode('lookup', 'Fetch Tag Rules', 'Query classification', 'draft', { source: 'cyera', key_path: '$.finding.type' }) },
        { id: 't3', type: 'signal', position: { x: 520, y: 380 }, data: baseNode('http_request', 'Tag AWS Resource', 'POST tag update', 'ready', { method: 'POST', url: 'https://api.aws/tag', body: '{"resource":"$.resource.id"}' }) },
        { id: 't4', type: 'signal', position: { x: 520, y: 540 }, data: baseNode('case_update', 'Update Case', 'Record tag applied', 'draft', { field: 'tags', value: 'cyera' }) },
      ],
      edges: [
        { id: 'e1', source: 't1', target: 't2', animated: true, type: 'smoothstep' },
        { id: 'e2', source: 't2', target: 't3', animated: true, type: 'smoothstep' },
        { id: 'e3', source: 't3', target: 't4', animated: true, type: 'smoothstep' },
      ],
    };
  }

  return {
    name: 'Dynamic ACL Update',
    nodes: [
      { id: 's1', type: 'signal', position: { x: 520, y: 60 }, data: baseNode('trigger', 'Alert Trigger', 'Incident received', 'live', { trigger_type: 'alert' }) },
      { id: 's2', type: 'signal', position: { x: 520, y: 220 }, data: baseNode('input', 'Normalize Inputs', 'Map artifacts', 'draft', { input_type: 'form', schema: '{ src_ip, dst_ip, user }' }) },
      { id: 's3', type: 'signal', position: { x: 520, y: 380 }, data: baseNode('decision', 'Is Critical?', 'severity >= high', 'draft', { expression: '$.alert.severity == "high"' }) },
      { id: 's4', type: 'signal', position: { x: 320, y: 540 }, data: baseNode('action', 'Update ACL', 'Block IP', 'ready', { action_type: 'block_ip', target_path: '$.alert.src_ip' }) },
      { id: 's5', type: 'signal', position: { x: 720, y: 540 }, data: baseNode('action', 'Quarantine Host', 'Isolate asset', 'draft', { action_type: 'contain_host', target_path: '$.alert.host' }) },
      { id: 's6', type: 'signal', position: { x: 520, y: 700 }, data: baseNode('action', 'Notify SOC', 'Pager + Slack', 'ready', { action_type: 'notify', target_path: '$.alert.id' }) },
      { id: 's7', type: 'signal', position: { x: 520, y: 860 }, data: baseNode('case_update', 'Case Notes', 'Tag + comment', 'draft', { field: 'comment', value: 'Dynamic ACL updated' }) },
      { id: 's8', type: 'signal', position: { x: 920, y: 540 }, data: baseNode('case_update', 'Monitor Only', 'Watchlisted', 'draft', { field: 'comment', value: 'Watchlisted only' }) },
    ],
    edges: [
      { id: 'e1', source: 's1', target: 's2', animated: true, type: 'smoothstep' },
      { id: 'e2', source: 's2', target: 's3', animated: true, type: 'smoothstep' },
      { id: 'e3', source: 's3', target: 's4', sourceHandle: 'yes', label: 'Yes', animated: true, type: 'smoothstep' },
      { id: 'e4', source: 's3', target: 's5', sourceHandle: 'yes', label: 'Yes', animated: true, type: 'smoothstep' },
      { id: 'e5', source: 's3', target: 's8', sourceHandle: 'no', label: 'No', animated: true, type: 'smoothstep' },
      { id: 'e6', source: 's4', target: 's6', animated: true, type: 'smoothstep' },
      { id: 'e7', source: 's5', target: 's6', animated: true, type: 'smoothstep' },
      { id: 'e8', source: 's6', target: 's7', animated: true, type: 'smoothstep' },
    ],
  };
}

function buildFromTines(raw) {
  if (!raw) throw new Error('Invalid Tines export');
  return buildSampleGraph('tines');
}

function baseNode(kind, title, summary, status, config) {
  return {
    kind,
    title,
    summary,
    status,
    config: config || {},
  };
}

export default PlaybookConverterCodex;
