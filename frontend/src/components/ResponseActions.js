/* Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0 */
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Globe, Hash, Monitor, UserX, Play, ChevronDown, Clock,
  CheckCircle, XCircle, Loader2, Zap, Link2, BookOpen, Filter
} from 'lucide-react';
import { API_BASE_URL, getCsrfToken } from '../utils/api';

const IOC_CFG = {
  ip:     { icon: Globe,   label: 'IP Address',  color: '#60a5fa', actions: ['Block IP', 'Lookup IP'] },
  domain: { icon: Globe,   label: 'Domain',      color: '#a78bfa', actions: ['Block Domain', 'Lookup Domain'] },
  hash:   { icon: Hash,    label: 'File Hash',   color: '#f59e0b', actions: ['Scan Hash'] },
  host:   { icon: Monitor, label: 'Host',        color: '#22d3ee', actions: ['Contain Host', 'Isolate Endpoint'] },
  user:   { icon: UserX,   label: 'User',        color: '#f472b6', actions: ['Disable Account'] },
  email:  { icon: Globe,   label: 'Email',       color: '#34d399', actions: ['Lookup Email'] },
};
const GROUP_MAP = { ips: 'ip', domains: 'domain', hashes: 'hash', hosts: 'host', users: 'user', emails: 'email' };
const scoreLevel = (s) => (s >= 80 ? 'high' : s >= 50 ? 'medium' : 'low');
const muted = { fontSize: '0.75rem', color: 'var(--text-muted, #64748b)', padding: '0.5rem 0' };
const subLabel = { fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted, #64748b)', marginBottom: '0.4rem' };
const col = { display: 'flex', flexDirection: 'column', gap: '0.35rem' };
const spinStyle = { animation: 'spin 1s linear infinite' };

const apiFetch = async (url, opts = {}) => {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { ...(opts.headers || {}), 'Content-Type': 'application/json' };
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }
  return fetch(url, { ...opts, headers, credentials: 'include' });
};

function extractIOCs(investigation, alertData) {
  const iocs = { ips: [], domains: [], hashes: [], hosts: [], users: [], emails: [] };
  const seen = new Set();
  const add = (type, value) => {
    if (!value || typeof value !== 'string') return;
    const v = value.trim();
    if (!v) return;
    const key = `${type}::${v.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    if (iocs[type]) iocs[type].push(v);
  };
  const pushArr = (arr, type) => {
    if (!Array.isArray(arr)) return;
    arr.forEach((v) => add(type, typeof v === 'string' ? v : v?.value));
  };
  const mapType = (t, val) => {
    if (t === 'ip' || t === 'private_ip') add('ips', val);
    else if (t === 'domain') add('domains', val);
    else if (t.startsWith('hash')) add('hashes', val);
    else if (t === 'hostname' || t === 'host') add('hosts', val);
    else if (t === 'email') add('emails', val);
    else if (t === 'user' || t === 'username') add('users', val);
  };
  // Source 1: investigation.extracted_iocs
  if (Array.isArray(investigation?.extracted_iocs)) {
    investigation.extracted_iocs.forEach((ioc) => mapType((ioc.type || '').toLowerCase(), ioc.value));
  }
  // Source 2: investigation.investigation_data.indicators
  const indicators = investigation?.investigation_data?.indicators;
  if (Array.isArray(indicators)) {
    indicators.forEach((ind) => mapType((ind.type || '').toLowerCase(), ind.value));
  }
  // Source 3: riggs_extracted_iocs
  const riggs = investigation?.investigation_data?.riggs_analysis?.riggs_extracted_iocs || {};
  ['ips', 'domains', 'hashes', 'hosts', 'users', 'emails'].forEach((k) => pushArr(riggs[k], k));
  // Source 4: alertData._extracted.iocs
  const ae = alertData?._extracted?.iocs || {};
  ['ips', 'domains', 'hashes', 'emails'].forEach((k) => pushArr(ae[k], k));
  // Source 5: alertData.raw_event (parsed)
  let raw = alertData?.raw_event;
  if (typeof raw === 'string') { try { raw = JSON.parse(raw); } catch { raw = null; } }
  if (raw && typeof raw === 'object') {
    const scan = (obj, d = 0) => {
      if (d > 4 || !obj) return;
      Object.values(obj).forEach((v) => {
        if (typeof v === 'string') {
          if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) add('ips', v);
          else if (/^[a-fA-F0-9]{32,64}$/.test(v)) add('hashes', v);
          else if (v.includes('@') && v.includes('.')) add('emails', v);
        } else if (typeof v === 'object' && v !== null) scan(v, d + 1);
      });
    };
    scan(raw);
    ['hostname', 'host', 'src_host', 'dst_host', 'computer_name', 'machine'].forEach((k) => { if (raw[k]) add('hosts', String(raw[k])); });
    ['user', 'username', 'src_user', 'dst_user', 'account_name'].forEach((k) => { if (raw[k]) add('users', String(raw[k])); });
  }
  return iocs;
}

// --- Section: Quick Actions ---
function QuickActionsSection({ iocs, onAction, executingAction }) {
  const allTypes = Object.entries(iocs).filter(([, v]) => v.length > 0);
  const total = allTypes.reduce((s, [, v]) => s + v.length, 0);
  return (
    <div className="response-section">
      <div className="response-section__header">
        <Zap size={14} style={{ color: '#f59e0b' }} />
        <span className="response-section__title">Quick Actions</span>
        <span className="response-section__count">{total} IOCs</span>
      </div>
      {total === 0 && <div style={muted}>No actionable IOCs detected in this investigation.</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {allTypes.map(([group, values]) => {
          const tk = GROUP_MAP[group] || group;
          const cfg = IOC_CFG[tk] || IOC_CFG.ip;
          const Icon = cfg.icon;
          return values.map((val) => (
            <div className="response-action-card" key={`${group}-${val}`}>
              <div className="response-action-card__icon" style={{ background: `${cfg.color}22`, color: cfg.color }}>
                <Icon size={16} />
              </div>
              <div className="response-action-card__info">
                <div className="response-action-card__name">{val}</div>
                <div className="response-action-card__description">{cfg.label}</div>
              </div>
              {cfg.actions.map((a) => {
                const running = executingAction?.value === val && executingAction?.action === a;
                return (
                  <button key={a} disabled={running}
                    className={`response-action-card__btn ${running ? 'response-action-card__btn--running' : ''}`}
                    onClick={() => onAction(tk, val, a)}>
                    {running ? 'Running...' : a}
                  </button>
                );
              })}
            </div>
          ));
        })}
      </div>
    </div>
  );
}

// --- Section: Available Integrations ---
function IntegrationsSection({ connectors, loading, expandedId, onToggle }) {
  return (
    <div className="response-section">
      <div className="response-section__header">
        <Link2 size={14} style={{ color: '#60a5fa' }} />
        <span className="response-section__title">Available Integrations</span>
        <span className="response-section__count">{loading ? '...' : `${connectors.length} connected`}</span>
      </div>
      {loading && <div style={muted}><Loader2 size={14} style={spinStyle} /> Loading connectors...</div>}
      {!loading && connectors.length === 0 && <div style={muted}>No connectors installed. Visit Connect to add integrations.</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
        {connectors.map((inst) => {
          const actions = inst.connector_actions || [];
          const expanded = expandedId === inst.id;
          return (
            <div className="response-connector" key={inst.id}>
              <div className="response-connector__header" onClick={() => onToggle(inst.id)}>
                <div className="response-connector__logo">{inst.connector_name?.[0]?.toUpperCase() || 'C'}</div>
                <span className="response-connector__name">{inst.display_name || inst.connector_name}</span>
                <span className="response-connector__action-count">{actions.length} action{actions.length !== 1 ? 's' : ''}</span>
                <span className={`response-connector__chevron ${expanded ? 'response-connector__chevron--expanded' : ''}`}>
                  <ChevronDown size={14} />
                </span>
              </div>
              {expanded && (
                <div className="response-connector__actions">
                  {actions.length === 0 && <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>No actions defined.</div>}
                  {actions.map((action, idx) => (
                    <div className="response-connector__action" key={action.id || idx}>
                      <span className="response-connector__action-name">{action.name || action.id}</span>
                      <button className="response-connector__action-btn"
                        onClick={() => console.log('[ResponseActions] Execute connector action:', inst.id, action.id)}>
                        Run
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// --- Section: Playbooks ---
function PlaybooksSection({ recommended, recLoading, allPlaybooks, pbLoading, searchTerm, onSearchChange, onExecute, executingPbId }) {
  const filtered = useMemo(() => {
    if (!searchTerm) return allPlaybooks;
    const q = searchTerm.toLowerCase();
    return allPlaybooks.filter((pb) =>
      (pb.name || '').toLowerCase().includes(q) || (pb.description || '').toLowerCase().includes(q) ||
      (pb.tags || []).some((t) => t.toLowerCase().includes(q))
    );
  }, [allPlaybooks, searchTerm]);

  const RunBtn = ({ pb }) => {
    const id = pb.playbook_id || pb.id;
    const running = executingPbId === id;
    return (
      <button disabled={running}
        className={`response-action-card__btn ${running ? 'response-action-card__btn--running' : ''}`}
        onClick={() => onExecute(pb)}>
        {running ? <Loader2 size={12} style={spinStyle} /> : <Play size={12} />}
        <span style={{ marginLeft: '0.25rem' }}>{running ? 'Running' : 'Run'}</span>
      </button>
    );
  };

  return (
    <div className="response-section">
      <div className="response-section__header">
        <BookOpen size={14} style={{ color: '#a78bfa' }} />
        <span className="response-section__title">Playbooks</span>
      </div>
      {/* AI Recommended */}
      <div style={{ marginBottom: '0.75rem' }}>
        <div style={subLabel}>AI Recommended</div>
        {recLoading && <div style={muted}><Loader2 size={14} style={spinStyle} /> Analyzing...</div>}
        {!recLoading && recommended.length === 0 && <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #64748b)' }}>No AI recommendations available.</div>}
        <div style={col}>
          {recommended.map((pb, idx) => {
            const score = pb.match_score ?? pb.relevance_score ?? 0;
            return (
              <div className="response-playbook-card" key={pb.playbook_id || pb.id || idx}>
                <span className={`response-playbook-card__score response-playbook-card__score--${scoreLevel(score)}`}>{Math.round(score)}%</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary, #f0f6fc)' }}>{pb.name || pb.playbook_name}</div>
                  {pb.reason && <div style={{ fontSize: '0.65rem', color: 'var(--text-muted, #64748b)', marginTop: '0.1rem' }}>{pb.reason}</div>}
                </div>
                <RunBtn pb={pb} />
              </div>
            );
          })}
        </div>
      </div>
      {/* All Playbooks */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <div style={subLabel}>All Playbooks</div>
          <div style={{ flex: 1 }} />
          <div style={{ position: 'relative' }}>
            <Filter size={12} style={{ position: 'absolute', left: 6, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input type="text" value={searchTerm} onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search playbooks..."
              style={{ fontSize: '0.7rem', padding: '0.3rem 0.5rem 0.3rem 1.5rem', background: 'rgba(100,116,139,0.08)',
                border: '1px solid rgba(148,163,184,0.12)', borderRadius: '6px', color: 'var(--text-primary, #f0f6fc)', outline: 'none', width: '160px' }} />
          </div>
        </div>
        {pbLoading && <div style={muted}><Loader2 size={14} style={spinStyle} /> Loading playbooks...</div>}
        {!pbLoading && filtered.length === 0 && <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #64748b)' }}>{searchTerm ? 'No matching playbooks.' : 'No playbooks available.'}</div>}
        <div style={{ ...col, maxHeight: '260px', overflowY: 'auto' }}>
          {filtered.map((pb) => {
            const pbId = pb.id || pb.playbook_id;
            return (
              <div className="response-playbook-card" key={pbId}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary, #f0f6fc)' }}>{pb.name}</div>
                  {pb.description && <div style={{ fontSize: '0.65rem', color: 'var(--text-muted, #64748b)', marginTop: '0.1rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{pb.description}</div>}
                </div>
                {pb.is_enabled === false && <span style={{ fontSize: '0.6rem', color: '#9ca3af', fontStyle: 'italic' }}>Disabled</span>}
                <RunBtn pb={pb} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// --- Section: Execution History ---
function ExecutionHistorySection({ history }) {
  const icon = (s) => {
    if (s === 'success') return <CheckCircle size={12} />;
    if (s === 'running') return <Loader2 size={12} style={spinStyle} />;
    if (s === 'failed') return <XCircle size={12} />;
    return <Clock size={12} />;
  };
  return (
    <div className="response-section">
      <div className="response-section__header">
        <Clock size={14} style={{ color: '#22d3ee' }} />
        <span className="response-section__title">Execution History</span>
        <span className="response-section__count">{history.length} action{history.length !== 1 ? 's' : ''}</span>
      </div>
      {history.length === 0 && <div style={muted}>No actions executed yet in this session.</div>}
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {history.map((e, idx) => (
          <div className="response-execution-row" key={idx}>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', minWidth: '60px' }}>{e.timestamp}</span>
            <span style={{ flex: 1, fontWeight: 600, color: 'var(--text-primary, #f0f6fc)' }}>{e.action}</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.target}</span>
            <span className={`response-status response-status--${e.status}`}>
              {icon(e.status)} <span style={{ marginLeft: '0.2rem' }}>{e.status}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// --- Main Component ---
export default function ResponseActions({ investigation, alertData }) {
  const [connectors, setConnectors] = useState([]);
  const [connectorsLoading, setConnectorsLoading] = useState(true);
  const [expandedConnector, setExpandedConnector] = useState(null);
  const [recommended, setRecommended] = useState([]);
  const [recLoading, setRecLoading] = useState(false);
  const [allPlaybooks, setAllPlaybooks] = useState([]);
  const [pbLoading, setPbLoading] = useState(true);
  const [pbSearch, setPbSearch] = useState('');
  const [executingPbId, setExecutingPbId] = useState(null);
  const [executingAction, setExecutingAction] = useState(null);
  const [execHistory, setExecHistory] = useState([]);

  const investigationId = investigation?.id || investigation?.investigation_id;
  const iocs = useMemo(() => extractIOCs(investigation, alertData), [investigation, alertData]);

  const addHistory = useCallback((action, target, status) => {
    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setExecHistory((prev) => [{ timestamp: ts, action, target, status }, ...prev]);
  }, []);

  const updateHistory = useCallback((action, target, status) => {
    setExecHistory((prev) => prev.map((e) =>
      e.action === action && e.target === target && e.status === 'running' ? { ...e, status } : e
    ));
  }, []);

  // Fetch connectors
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch(`${API_BASE_URL}/api/v1/connect/instances`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (!cancelled) setConnectors(Array.isArray(data) ? data : []);
      } catch { if (!cancelled) setConnectors([]); }
      finally { if (!cancelled) setConnectorsLoading(false); }
    })();
    return () => { cancelled = true; };
  }, []);

  // Fetch AI recommended playbooks
  useEffect(() => {
    if (!investigationId) return;
    let cancelled = false;
    (async () => {
      setRecLoading(true);
      try {
        const res = await apiFetch(`${API_BASE_URL}/api/v1/riggs/playbooks/recommend`, {
          method: 'POST', body: JSON.stringify({ investigation_id: investigationId }),
        });
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (!cancelled) setRecommended(data.recommendations || []);
      } catch {
        const cached = investigation?.investigation_data?.riggs_analysis?.playbook_recommendations;
        if (!cancelled && Array.isArray(cached)) setRecommended(cached);
      } finally { if (!cancelled) setRecLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [investigationId, investigation]);

  // Fetch all playbooks
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch(`${API_BASE_URL}/api/v1/playbooks?limit=50`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (!cancelled) setAllPlaybooks(data.playbooks || []);
      } catch { if (!cancelled) setAllPlaybooks([]); }
      finally { if (!cancelled) setPbLoading(false); }
    })();
    return () => { cancelled = true; };
  }, []);

  const handleQuickAction = useCallback((type, value, actionName) => {
    console.log('[ResponseActions] Quick action:', actionName, type, value);
    setExecutingAction({ type, value, action: actionName });
    addHistory(actionName, value, 'running');
    // Stub: simulate completion (real execution wired later)
    setTimeout(() => { setExecutingAction(null); updateHistory(actionName, value, 'success'); }, 1500);
  }, [addHistory, updateHistory]);

  const handlePlaybookExecute = useCallback(async (pb) => {
    const pbId = pb.playbook_id || pb.id;
    const pbName = pb.name || pb.playbook_name || pbId;
    setExecutingPbId(pbId);
    addHistory(`Playbook: ${pbName}`, investigationId || '-', 'running');
    try {
      const res = await apiFetch(`${API_BASE_URL}/api/v1/playbooks/${pbId}/execute`, {
        method: 'POST',
        body: JSON.stringify({ investigation_id: investigationId, trigger_context: { alert_data: alertData } }),
      });
      if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Execution failed'); }
      updateHistory(`Playbook: ${pbName}`, investigationId || '-', 'success');
    } catch (err) {
      console.error('[ResponseActions] Playbook execute error:', err);
      updateHistory(`Playbook: ${pbName}`, investigationId || '-', 'failed');
    } finally { setExecutingPbId(null); }
  }, [investigationId, alertData, addHistory, updateHistory]);

  const toggleConnector = useCallback((id) => setExpandedConnector((prev) => (prev === id ? null : id)), []);

  return (
    <div className="response-tab">
      <QuickActionsSection iocs={iocs} onAction={handleQuickAction} executingAction={executingAction} />
      <IntegrationsSection connectors={connectors} loading={connectorsLoading} expandedId={expandedConnector} onToggle={toggleConnector} />
      <PlaybooksSection recommended={recommended} recLoading={recLoading} allPlaybooks={allPlaybooks}
        pbLoading={pbLoading} searchTerm={pbSearch} onSearchChange={setPbSearch} onExecute={handlePlaybookExecute} executingPbId={executingPbId} />
      <ExecutionHistorySection history={execHistory} />
    </div>
  );
}
