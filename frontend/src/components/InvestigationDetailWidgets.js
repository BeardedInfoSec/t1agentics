/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import AlertDetailsDrawer from './AlertDetailsDrawer';
import IOCPanel from './IOCPanel';
import GridLayout, { WidthProvider } from 'react-grid-layout';
import InvestigationChat from './InvestigationChat';
import 'react-grid-layout/css/styles.css';
import { API_BASE_URL, authFetch } from '../utils/api';

// Use WidthProvider to automatically handle container width
const ResponsiveGridLayout = WidthProvider(GridLayout);

// WIDGET REGISTRY - Add new widgets here! (Heights in grid rows, optimized for laptop screens)
const WIDGET_REGISTRY = {
  // Meta Widgets
  'threat-intel': { title: '🛡️ Threat Intel', desc: 'IOC overview & risk', defaultW: 3, defaultH: 3, minW: 2, minH: 2 },
  'action-required': { title: '⚠️ Action Required', desc: 'Items needing attention', defaultW: 1, defaultH: 3, minW: 1, minH: 2 },
  'ai-summary': { title: '🤖 AI Summary', desc: 'AI investigation analysis', defaultW: 2, defaultH: 3, minW: 1, minH: 2 },

  // Detail Widgets
  'event-details': { title: '📋 Event Details', desc: 'Structured event data', defaultW: 3, defaultH: 6, minW: 2, minH: 3 },
  'timeline': { title: '📅 Timeline', desc: 'Event timeline', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'summary': { title: '📋 Summary', desc: 'Investigation summary', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },

  // IOC Widgets - Phase 1
  'ioc-network': { title: '🌐 Network', desc: 'Network IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'ioc-process': { title: '⚙️ Process', desc: 'Process IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'ioc-domains': { title: '🔗 URLs & Domains', desc: 'Domain IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'ioc-identity': { title: '👤 Identity', desc: 'Identity IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'ioc-file': { title: '📄 File', desc: 'File IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'ioc-email': { title: '📧 Email', desc: 'Email IOCs', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },

  // Phase 2 Widgets
  'cloud': { title: '☁️ Cloud Activity', desc: 'Cloud & SaaS indicators', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'mitre': { title: '⚔️ MITRE ATT&CK', desc: 'ATT&CK mapping', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },

  // Other Widgets
  'related-alerts': { title: '🚨 Related Alerts', desc: 'Alert table', defaultW: 2, defaultH: 4, minW: 1, minH: 2 },
  'notes-widget': { title: '📝 Notes', desc: 'Notes widget', defaultW: 2, defaultH: 4, minW: 1, minH: 2 },
  'raw-data': { title: '📄 Raw Data', desc: 'JSON payload', defaultW: 1, defaultH: 4, minW: 1, minH: 2 },
  'agent-actions': { title: '⚡ Agent Actions', desc: 'AI agent action requests', defaultW: 2, defaultH: 4, minW: 1, minH: 2 },
};

// Default layout - react-grid-layout format (i = widget id, x/y = grid position, w/h = grid units)
const DEFAULT_LAYOUT = [
  // Row 1: Threat Intel (full width)
  { i: 'threat-intel', x: 0, y: 0, w: 3, h: 3 },

  // Row 2: AI Summary + Action Required
  { i: 'ai-summary', x: 0, y: 3, w: 2, h: 3 },
  { i: 'action-required', x: 2, y: 3, w: 1, h: 3 },

  // Row 3: Identity, Network, Process
  { i: 'ioc-identity', x: 0, y: 6, w: 1, h: 4 },
  { i: 'ioc-network', x: 1, y: 6, w: 1, h: 4 },
  { i: 'ioc-process', x: 2, y: 6, w: 1, h: 4 },

  // Row 4: URLs & Domains, File, Email
  { i: 'ioc-domains', x: 0, y: 10, w: 1, h: 4 },
  { i: 'ioc-file', x: 1, y: 10, w: 1, h: 4 },
  { i: 'ioc-email', x: 2, y: 10, w: 1, h: 4 },

  // Row 5: Cloud, MITRE, Timeline
  { i: 'cloud', x: 0, y: 14, w: 1, h: 4 },
  { i: 'mitre', x: 1, y: 14, w: 1, h: 4 },
  { i: 'timeline', x: 2, y: 14, w: 1, h: 4 },

  // Row 6: Related Alerts + Raw Data
  { i: 'related-alerts', x: 0, y: 18, w: 2, h: 4 },
  { i: 'raw-data', x: 2, y: 18, w: 1, h: 4 },

  // Row 7: Agent Actions (AI-requested actions needing approval)
  { i: 'agent-actions', x: 0, y: 22, w: 3, h: 4 },
];

// Grid configuration
const GRID_COLS = 3;
const ROW_HEIGHT = 38; // Reduced for laptop screens

export default function InvestigationDetailWidgets() {
  const { id } = useParams();
  const containerRef = useRef(null);
  const [investigation, setInvestigation] = useState(null);
  const [relatedAlerts, setRelatedAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [newNote, setNewNote] = useState('');
  const [users, setUsers] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showAlertSlideout, setShowAlertSlideout] = useState(false);
  const [noteAttachments, setNoteAttachments] = useState([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [enlargedImage, setEnlargedImage] = useState(null);
  const [layout, setLayout] = useState(() => {
    try {
      const saved = localStorage.getItem('inv_widgets_v18');
      return saved ? JSON.parse(saved) : DEFAULT_LAYOUT;
    } catch {
      return DEFAULT_LAYOUT;
    }
  });
  const [editMode, setEditMode] = useState(false);
  const [showCatalog, setShowCatalog] = useState(false);
  const [actionRequests, setActionRequests] = useState([]);
  const [chatOpen, setChatOpen] = useState(false); // Start collapsed for laptop screens
  const [investigationEntities, setInvestigationEntities] = useState({}); // Entity risk scores from correlation system

  // Save layout to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('inv_widgets_v18', JSON.stringify(layout));
  }, [layout]);

  // Handle layout changes from react-grid-layout
  const onLayoutChange = (newLayout) => {
    setLayout(newLayout);
  };
  useEffect(() => { fetchInvestigation(); fetchUsers(); fetchActionRequests(); fetchLinkedAlerts(); fetchInvestigationEntities(); }, [id]);

  // Fetch investigation entities with risk scores from entity-based correlation system
  const fetchInvestigationEntities = async () => {

      const r = await fetch(`${API_BASE_URL}/api/v1/investigation-details/${id}/entities`, { headers });

      if (r.ok) {
        const data = await r.json();
        setInvestigationEntities(data);
      }
    } catch (e) {
      console.error('Entities fetch error:', e);
    }
  };

  // Fetch linked alerts with correlation explanations
  const fetchLinkedAlerts = async () => {

      // Use the new investigation-details endpoint for full alert data with correlation explanations
      const r = await fetch(`${API_BASE_URL}/api/v1/investigation-details/${id}/alerts?limit=100`, { headers });

      if (r.ok) {
        const data = await r.json();
        if (data.items && data.items.length > 0) {
          setRelatedAlerts(data.items);
        }
      } else {
        // Fallback to legacy linked-alerts endpoint if new one not available
        const legacyR = await fetch(`${API_BASE_URL}/api/v1/investigations/${id}/linked-alerts`, { headers });
        if (legacyR.ok) {
          const legacyData = await legacyR.json();
          if (legacyData.alerts && legacyData.alerts.length > 0) {
            // Add empty correlation metadata for legacy alerts
            const alertsWithCorrelation = legacyData.alerts.map(a => ({
              ...a,
              correlation: { decision_type: 'legacy', reasons: [], matched_entities: [] }
            }));
            setRelatedAlerts(alertsWithCorrelation);
          }
        }
      }
    } catch (e) {
      console.error('Linked alerts fetch error:', e);
    }
  };

  const fetchActionRequests = async () => {
    try {
      const r = await fetch(`${API_BASE_URL}/api/v1/actions/requests/investigation/${id}`);
      if (r.ok) {
        const data = await r.json();
        setActionRequests(data.requests || []);
      }
    } catch {}
  };

  const fetchUsers = async () => { 
    try {
      const r = await fetch(`${API_BASE_URL}/api/v1/users`); 
      if (r.ok) setUsers(await r.json()); 
    } catch {} 
  };
  
  const fetchInvestigation = async () => {
      const r = await fetch(`${API_BASE_URL}/api/v1/investigations/` + id, { headers });
      if (!r.ok) { setError('Failed'); setLoading(false); return; }
      const data = await r.json();
      try { const nr = await fetch(`${API_BASE_URL}/api/v1/investigations/` + id + '/notes', { headers }); if (nr.ok) data.notes = await nr.json(); } catch { data.notes = []; }
      setInvestigation(data);
      // Parse raw_alert if it's a string
      let parsedRawAlert = {};
      try { 
        if (data.raw_alert) {
          parsedRawAlert = typeof data.raw_alert === 'string' ? JSON.parse(data.raw_alert) : data.raw_alert;
        }
      } catch {}
      // Include investigation_id and raw_alert data in the fallback alert
      setRelatedAlerts(data.related_alerts || (data.alert_id ? [{ 
        id: data.alert_id, 
        investigation_id: data.investigation_id,
        title: data.alert_title, 
        severity: data.severity || 'medium', 
        source: 'Webhook', 
        created_at: data.created_at,
        updated_at: data.updated_at,
        raw_event: parsedRawAlert
      }] : []));
    } catch { setError('Error'); }
    finally { setLoading(false); }
  };

  const updateField = async (field, value) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/investigations/` + id, {
        method: 'PATCH',
        body: JSON.stringify({ [field]: value }),
      });
      if (r.ok) {
        setInvestigation(p => ({ ...p, [field]: value }));
      } else {
        const detail = await r.json().catch(() => ({}));
        console.error(`Failed to update ${field}:`, r.status, detail);
        if (typeof window !== 'undefined' && window.alert) {
          // Surface a concise error so the user knows their change didn't take.
          // Better than silent failure — this is a permission/CSRF issue most often.
          // (Toast wiring isn't in this widget's scope; using a plain alert.)
          window.alert(`Could not update ${field}: ${detail?.detail || detail?.message || r.statusText}`);
        }
      }
    } catch (e) {
      console.error(`Network error updating ${field}:`, e);
    }
  };

  const addNote = async () => {
    if (!newNote.trim() && !noteAttachments.length) return;
    let content = newNote;
    if (noteAttachments.length) { content += '\n\n[Attachments]'; noteAttachments.forEach((a, i) => content += '\n![img](' + a + ')'); }
    try {
      const r = await fetch(`${API_BASE_URL}/api/v1/investigations/` + id + '/notes', { 
        method: 'POST', 
        headers: { 
          'Content-Type': 'application/json',
        }, 
        body: JSON.stringify({ content, author: localStorage.getItem('username') || 'analyst' }) 
      });
      if (r.ok) { 
        const response = await r.json();
        // Backend returns { success: true, note: {...} } with timestamp instead of created_at
        const noteData = response.note || response;
        const newNoteData = {
          ...noteData,
          created_at: noteData.created_at || noteData.timestamp || new Date().toISOString()
        };
        // Force update investigation with new note
        setInvestigation(prev => {
          const updatedNotes = [...(prev.notes || []), newNoteData];
          return { ...prev, notes: updatedNotes };
        });
        setNewNote(''); 
        setNoteAttachments([]);
      } else {
      }
    } catch (e) {
    }
  };

  const handleNotePaste = (e) => { const items = e.clipboardData?.items; if (!items) return; for (let i = 0; i < items.length; i++) if (items[i].type.includes('image')) { e.preventDefault(); const reader = new FileReader(); reader.onload = ev => setNoteAttachments(p => [...p, ev.target.result]); reader.readAsDataURL(items[i].getAsFile()); break; } };
  const copyToClipboard = t => navigator.clipboard.writeText(t);
  const openAlertDetails = a => { setSelectedAlert(a); setShowAlertSlideout(true); };

  // Widget management functions for react-grid-layout
  const addWidget = wid => {
    if (layout.some(w => w.i === wid)) return; // Don't add duplicates
    const c = WIDGET_REGISTRY[wid];
    if (!c) return;
    const maxY = layout.length > 0 ? Math.max(...layout.map(w => w.y + w.h)) : 0;
    setLayout(p => [...p, {
      i: wid,
      x: 0,
      y: maxY,
      w: c.defaultW,
      h: c.defaultH,
      minW: c.minW || 1,
      minH: c.minH || 2
    }]);
  };

  const removeWidget = wid => setLayout(p => p.filter(w => w.i !== wid));
  const resetLayout = () => { setLayout([...DEFAULT_LAYOUT]); localStorage.removeItem('inv_widgets_v18'); };

  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-secondary)' }}>Loading...</div>;
  if (error || !investigation) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#f87171' }}>{error || 'Not found'}</div>;

  // Data extraction
  let invData = {}; try { invData = typeof investigation.investigation_data === 'string' ? JSON.parse(investigation.investigation_data) : investigation.investigation_data || {}; } catch {}
  let rawAlert = {}; try { if (investigation.raw_alert) rawAlert = typeof investigation.raw_alert === 'string' ? JSON.parse(investigation.raw_alert) : investigation.raw_alert; } catch {}
  const alertData = invData.alert_data || rawAlert || invData || {};
  const timeline = invData.timeline || alertData.timeline || [{ timestamp: investigation.created_at, event: 'Investigation initiated' }];
  const notes = investigation.notes || [];
  
  // =============================================================================
  // IOC EXTRACTION - Comprehensive extraction from all data sources
  // =============================================================================
  
  // File extensions that indicate a file, not a domain
  const fileExtensions = ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.msi', '.scr', '.com', '.pif', '.jar', '.py', '.sh', '.bin', '.elf', '.so', '.dylib', '.app', '.dmg', '.pkg', '.deb', '.rpm', '.zip', '.rar', '.7z', '.tar', '.gz', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx', '.txt', '.csv', '.xml', '.json', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.log', '.tmp', '.dat', '.db', '.sql', '.bak', '.cfg', '.ini', '.sys', '.drv', '.ocx', '.cpl', '.lnk'];
  
  // Check if a value looks like a file (has executable/file extension)
  const looksLikeFile = (value) => {
    if (!value || typeof value !== 'string') return false;
    const lower = value.toLowerCase();
    return fileExtensions.some(ext => lower.endsWith(ext));
  };
  
  // Check if a value looks like a valid domain (not a file)
  const looksLikeDomain = (value) => {
    if (!value || typeof value !== 'string') return false;
    // If it looks like a file, it's not a domain
    if (looksLikeFile(value)) return false;
    // Check for valid domain pattern (has dot, valid TLD-like ending)
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    return domainPattern.test(value);
  };
  
  // Smart category detection based on both type AND value
  const getSmartCategory = (type, value) => {
    if (!type && !value) return 'Other';
    const t = (type || '').toLowerCase();
    const v = (value || '').toLowerCase();
    
    // First check value patterns - these override type-based categorization
    if (looksLikeFile(value)) {
      // Determine if it's a process or just a file
      if (['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.scr', '.com', '.pif', '.sh', '.bin', '.elf'].some(ext => v.endsWith(ext))) {
        return 'Process';
      }
      return 'File';
    }
    
    // Type-based categorization
    if (['ip', 'ipv4', 'ipv6', 'src_ip', 'dst_ip', 'source_ip', 'dest_ip', 'destination_ip', 'port', 'hostname', 'protocol'].includes(t)) return 'Network';
    if (['domain', 'url', 'uri', 'fqdn', 'http'].includes(t)) {
      // Double-check it's actually a domain/URL, not a file
      if (looksLikeFile(value)) return 'File';
      return 'URLs & Domains';
    }
    if (['hash', 'md5', 'sha1', 'sha256', 'sha512', 'file_hash', 'path', 'filepath', 'filename', 'file_name', 'file_path'].includes(t)) return 'File';
    if (['username', 'user', 'email', 'user_name', 'account', 'sender', 'recipient', 'role', 'identity'].includes(t)) return 'Identity';
    if (['process', 'process_name', 'cmdline', 'command_line', 'pid', 'parent'].includes(t)) return 'Process';
    
    return 'Other';
  };
  
  // Legacy function for backward compatibility
  const getCategoryFromType = (type) => getSmartCategory(type, null);

  // Helper to extract IOCs from an object value
  const extractFromObject = (obj, sourceType, category) => {
    const results = [];
    if (!obj || typeof obj !== 'object') return results;
    
    // Common field mappings
    const fieldMappings = {
      ip: { type: 'IP', category: 'Network' },
      hostname: { type: 'Hostname', category: 'Network' },
      os: { type: 'OS', category: 'Network' },
      domain: { type: 'Domain', category: 'URLs & Domains' },
      url: { type: 'URL', category: 'URLs & Domains' },
      username: { type: 'Username', category: 'Identity' },
      user: { type: 'Username', category: 'Identity' },
      display_name: { type: 'Display Name', category: 'Identity' },
      email: { type: 'Email', category: 'Identity' },
      role: { type: 'Role', category: 'Identity' },
      auth_method: { type: 'Auth Method', category: 'Identity' },
      mfa_used: { type: 'MFA Used', category: 'Identity' },
      privileged: { type: 'Privileged', category: 'Identity' },
      sender: { type: 'Email Sender', category: 'Identity' },
      recipient: { type: 'Email Recipient', category: 'Identity' },
      subject: { type: 'Email Subject', category: 'Identity' },
      md5: { type: 'MD5', category: 'File' },
      sha1: { type: 'SHA1', category: 'File' },
      sha256: { type: 'SHA256', category: 'File' },
      path: { type: 'Path', category: 'File' },
      filename: { type: 'Filename', category: 'File' },
      signed: { type: 'Signed', category: 'File' },
      process: { type: 'Process', category: 'Process' },
      name: { type: 'Process', category: 'Process' },
      command_line: { type: 'Command', category: 'Process' },
      cmdline: { type: 'Command', category: 'Process' },
      parent: { type: 'Parent Process', category: 'Process' },
      pid: { type: 'PID', category: 'Process' },
    };
    
    Object.entries(obj).forEach(([key, value]) => {
      if (value === null || value === undefined) return;
      if (typeof value === 'object') return; // Skip nested objects
      
      const mapping = fieldMappings[key.toLowerCase()] || { type: key, category: category || 'Other' };
      const strValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value);
      
      if (strValue && strValue.trim()) {
        results.push({
          type: mapping.type,
          value: strValue,
          category: mapping.category
        });
      }
    });
    
    return results;
  };

  let extractedIOCs = [];
  const rawIOCs = invData.extracted_iocs || alertData.extracted_iocs || invData.indicators || alertData.indicators || [];
  
  if (Array.isArray(rawIOCs)) {
    rawIOCs.forEach(ioc => {
      if (!ioc || typeof ioc !== 'object') return;
      
      // If value is a string, use directly
      if (typeof ioc.value === 'string' && ioc.value.trim()) {
        // Check if it's a stringified JSON/Python dict object
        if (ioc.value.startsWith('{') || ioc.value.startsWith('[')) {
          try {
            // Handle Python-style dicts: single quotes, True/False, None
            let jsonStr = ioc.value
              .replace(/'/g, '"')           // Replace single quotes with double
              .replace(/: True/g, ': true')  // Python True -> JSON true
              .replace(/: False/g, ': false') // Python False -> JSON false
              .replace(/: None/g, ': null'); // Python None -> JSON null
            const parsed = JSON.parse(jsonStr);
            if (typeof parsed === 'object') {
              extractedIOCs.push(...extractFromObject(parsed, ioc.type, ioc.category || getSmartCategory(ioc.type, ioc.value)));
              return;
            }
          } catch {
            // Not valid JSON/dict, skip and don't add as raw string if it looks like unparsed data
            if (ioc.value.includes("'role'") || ioc.value.includes('"role"')) {
              return; // Skip malformed dict strings
            }
          }
        }
        extractedIOCs.push({
          type: ioc.type || 'unknown',
          value: ioc.value,
          category: ioc.category || getSmartCategory(ioc.type, ioc.value)
        });
      }
      // If value is an object, extract individual fields
      else if (typeof ioc.value === 'object' && ioc.value !== null) {
        extractedIOCs.push(...extractFromObject(ioc.value, ioc.type, ioc.category || getSmartCategory(ioc.type, null)));
      }
      // If value is a number or boolean
      else if (ioc.value !== null && ioc.value !== undefined) {
        extractedIOCs.push({
          type: ioc.type || 'unknown',
          value: String(ioc.value),
          category: ioc.category || getSmartCategory(ioc.type, String(ioc.value))
        });
      }
    });
  }
  
  // Also extract observables array if present
  const observables = alertData.observables || invData.observables || [];
  if (Array.isArray(observables)) {
    observables.forEach(obs => {
      if (obs?.type && obs?.value) {
        const val = String(obs.value);
        extractedIOCs.push({
          type: obs.type,
          value: val,
          category: getSmartCategory(obs.type, val)
        });
      }
    });
  }
  
  // Always extract comprehensive data from alertData structure
  if (alertData) {
    // =========== NETWORK ===========
    // Host info
    if (alertData.host?.ip) extractedIOCs.push({ type: 'Host IP', value: alertData.host.ip, category: 'Network' });
    if (alertData.host?.hostname) extractedIOCs.push({ type: 'Hostname', value: alertData.host.hostname, category: 'Network' });
    if (alertData.host?.os) extractedIOCs.push({ type: 'OS', value: alertData.host.os, category: 'Network' });
    
    // Network info
    if (alertData.network?.source_ip) extractedIOCs.push({ type: 'Source IP', value: alertData.network.source_ip, category: 'Network' });
    if (alertData.network?.destination_ip) extractedIOCs.push({ type: 'Dest IP', value: alertData.network.destination_ip, category: 'Network' });
    if (alertData.network?.port) extractedIOCs.push({ type: 'Port', value: String(alertData.network.port), category: 'Network' });
    if (alertData.network?.protocol) extractedIOCs.push({ type: 'Protocol', value: alertData.network.protocol, category: 'Network' });
    
    // =========== URLs & Domains ===========
    if (alertData.network?.domain) extractedIOCs.push({ type: 'Domain', value: alertData.network.domain, category: 'URLs & Domains' });
    if (alertData.network?.url) extractedIOCs.push({ type: 'URL', value: alertData.network.url, category: 'URLs & Domains' });
    if (Array.isArray(alertData.network?.domains)) {
      alertData.network.domains.forEach(d => extractedIOCs.push({ type: 'Domain', value: d, category: 'URLs & Domains' }));
    }
    // HTTP details
    if (alertData.network?.http?.url) extractedIOCs.push({ type: 'URL', value: alertData.network.http.url, category: 'URLs & Domains' });
    if (alertData.network?.http?.method) extractedIOCs.push({ type: 'HTTP Method', value: alertData.network.http.method, category: 'URLs & Domains' });
    if (alertData.network?.http?.user_agent) extractedIOCs.push({ type: 'User Agent', value: alertData.network.http.user_agent, category: 'URLs & Domains' });
    
    // =========== FILE ===========
    // File hashes - support both nested and flat structures
    if (alertData.file?.hashes?.md5) extractedIOCs.push({ type: 'MD5', value: alertData.file.hashes.md5, category: 'File' });
    if (alertData.file?.hashes?.sha1) extractedIOCs.push({ type: 'SHA1', value: alertData.file.hashes.sha1, category: 'File' });
    if (alertData.file?.hashes?.sha256) extractedIOCs.push({ type: 'SHA256', value: alertData.file.hashes.sha256, category: 'File' });
    if (alertData.file?.hashes?.sha512) extractedIOCs.push({ type: 'SHA512', value: alertData.file.hashes.sha512, category: 'File' });
    // Legacy hash structure
    if (alertData.file?.hash?.md5) extractedIOCs.push({ type: 'MD5', value: alertData.file.hash.md5, category: 'File' });
    if (alertData.file?.hash?.sha1) extractedIOCs.push({ type: 'SHA1', value: alertData.file.hash.sha1, category: 'File' });
    if (alertData.file?.hash?.sha256) extractedIOCs.push({ type: 'SHA256', value: alertData.file.hash.sha256, category: 'File' });
    // File metadata
    if (alertData.file?.path) extractedIOCs.push({ type: 'File Path', value: alertData.file.path, category: 'File' });
    if (alertData.file?.name) extractedIOCs.push({ type: 'Filename', value: alertData.file.name, category: 'File' });
    if (alertData.file?.signed !== undefined) extractedIOCs.push({ type: 'Signed', value: alertData.file.signed ? 'Yes' : 'No', category: 'File' });
    
    // =========== IDENTITY ===========
    // User info - comprehensive extraction
    if (alertData.user?.username) extractedIOCs.push({ type: 'Username', value: alertData.user.username, category: 'Identity' });
    if (alertData.user?.display_name) extractedIOCs.push({ type: 'Display Name', value: alertData.user.display_name, category: 'Identity' });
    if (alertData.user?.email) extractedIOCs.push({ type: 'User Email', value: alertData.user.email, category: 'Identity' });
    if (alertData.user?.role) extractedIOCs.push({ type: 'Role', value: alertData.user.role, category: 'Identity' });
    if (alertData.user?.auth_method) extractedIOCs.push({ type: 'Auth Method', value: alertData.user.auth_method, category: 'Identity' });
    if (alertData.user?.mfa_used !== undefined) extractedIOCs.push({ type: 'MFA Used', value: alertData.user.mfa_used ? 'Yes' : 'No', category: 'Identity' });
    if (alertData.user?.privileged !== undefined) extractedIOCs.push({ type: 'Privileged', value: alertData.user.privileged ? 'Yes' : 'No', category: 'Identity' });
    
    // =========== EMAIL ===========
    // Email info - phishing/communication context
    if (alertData.email?.sender) extractedIOCs.push({ type: 'Sender', value: alertData.email.sender, category: 'Email' });
    if (alertData.email?.recipient) extractedIOCs.push({ type: 'Recipient', value: alertData.email.recipient, category: 'Email' });
    if (alertData.email?.subject) extractedIOCs.push({ type: 'Subject', value: alertData.email.subject, category: 'Email' });
    if (alertData.email?.attachment !== undefined) extractedIOCs.push({ type: 'Has Attachment', value: alertData.email.attachment ? 'Yes' : 'No', category: 'Email' });
    
    // =========== PROCESS ===========
    if (alertData.process?.name) extractedIOCs.push({ type: 'Process', value: alertData.process.name, category: 'Process' });
    if (alertData.process?.command_line) extractedIOCs.push({ type: 'Command Line', value: alertData.process.command_line, category: 'Process' });
    if (alertData.process?.parent) extractedIOCs.push({ type: 'Parent Process', value: alertData.process.parent, category: 'Process' });
    if (alertData.process?.pid) extractedIOCs.push({ type: 'PID', value: String(alertData.process.pid), category: 'Process' });
    
    // =========== CLOUD ===========
    if (alertData.cloud?.account_id) extractedIOCs.push({ type: 'Account ID', value: alertData.cloud.account_id, category: 'Cloud' });
    if (alertData.cloud?.region) extractedIOCs.push({ type: 'Region', value: alertData.cloud.region, category: 'Cloud' });
    if (alertData.cloud?.service) extractedIOCs.push({ type: 'Service', value: alertData.cloud.service, category: 'Cloud' });
    if (alertData.cloud?.resource_id) extractedIOCs.push({ type: 'Resource ID', value: alertData.cloud.resource_id, category: 'Cloud' });
    if (alertData.cloud?.api_call) extractedIOCs.push({ type: 'API Call', value: alertData.cloud.api_call, category: 'Cloud' });
    if (alertData.cloud?.provider) extractedIOCs.push({ type: 'Provider', value: alertData.cloud.provider, category: 'Cloud' });
  }
  
  // Deduplicate by value within each category (keeps the first occurrence with its type)
  const seenIOCs = new Set();
  extractedIOCs = extractedIOCs.filter(ioc => {
    // Normalize value for comparison
    const normalizedValue = (ioc.value || '').toLowerCase().trim();
    const key = `${ioc.category}:${normalizedValue}`;
    if (seenIOCs.has(key)) return false;
    seenIOCs.add(key);
    return true;
  });
  
  // Group IOCs by category for rendering
  const iocsByCat = extractedIOCs.reduce((acc, ioc) => {
    (acc[ioc.category] = acc[ioc.category] || []).push(ioc);
    return acc;
  }, {});
  
  // Helper functions for risk assessment
  const isPrivateIP = (ip) => {
    if (!ip) return false;
    return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.');
  };
  
  const getRiskLevel = (ioc) => {
    const value = (ioc.value || '').toLowerCase();
    const type = (ioc.type || '').toLowerCase();
    
    if (type.includes('ip') && !isPrivateIP(ioc.value)) return 'high';
    if (value.includes('.ru') || value.includes('.cn') || value.includes('tor') || value.includes('onion')) return 'high';
    if (type === 'privileged' && value === 'yes') return 'high';
    if (type === 'mfa used' && value === 'no') return 'medium';
    if (type === 'signed' && value === 'no') return 'medium';
    if (isPrivateIP(ioc.value)) return 'low';
    return 'unknown';
  };

  const stateCol = s => ({ 'NEW': '#3b82f6', 'IN_PROGRESS': '#f59e0b', 'RESOLVED': '#22c55e', 'CLOSED': '#6b7280' }[(s || '').toUpperCase()] || '#6b7280');
  const dispCol = d => ({ 'MALICIOUS': '#dc2626', 'TRUE_POSITIVE': '#dc2626', 'SUSPICIOUS': '#f97316', 'BENIGN': '#22c55e', 'FALSE_POSITIVE': '#22c55e', 'UNKNOWN': '#6b7280' }[(d || '').toUpperCase()] || '#6b7280');
  const prioCol = p => ({ 'P1': '#dc2626', 'P2': '#ea580c', 'P3': '#eab308', 'P4': '#22c55e' }[p] || '#6b7280');
  const sevCol = s => ({ 'critical': '#dc2626', 'high': '#ea580c', 'medium': '#eab308', 'low': '#22c55e' }[(s || '').toLowerCase()] || '#6b7280');
  const fmtDate = d => d ? new Date(d).toLocaleDateString() + ' ' + new Date(d).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'N/A';
  const catColors = { 'Network': '#3b82f6', 'URLs & Domains': '#a855f7', 'File': '#3CB371', 'Identity': '#06b6d4', 'Process': '#f59e0b', 'Other': '#6b7280' };
  const mitre = alertData.mitre || invData.mitre;

  // =============================================================================
  // RENDER WIDGET CONTENT
  // =============================================================================
  const renderContent = (wid, fullPage = false) => {
    const maxH = fullPage ? 'none' : '100%';
    
    switch (wid) {
      case 'threat-intel': {
        // Combined metrics + IOC breakdown + Entity risk scores
        const highRiskCount = extractedIOCs.filter(ioc => {
          const risk = getRiskLevel(ioc);
          return risk === 'high' || risk === 'critical';
        }).length;
        const categories = [...new Set(extractedIOCs.map(i => i.category))].filter(c => c !== 'Other');
        const catColorMap = { 'Network': '#3b82f6', 'URLs & Domains': '#a855f7', 'File': '#06b6d4', 'Identity': '#22c55e', 'Process': '#f59e0b', 'Email': '#ec4899', 'Cloud': '#3CB371' };

        // Entity type colors and icons
        const entityTypeConfig = {
          'user': { color: '#22c55e', icon: '👤', label: 'Users' },
          'host': { color: '#3b82f6', icon: '💻', label: 'Hosts' },
          'mitre_technique': { color: '#ef4444', icon: '⚔️', label: 'MITRE' },
          'threat_object': { color: '#f59e0b', icon: '🔐', label: 'Threats' },
          'internal_ip': { color: '#06b6d4', icon: '🌐', label: 'Internal IPs' },
          'external_ioc': { color: '#a855f7', icon: '🎯', label: 'External IOCs' }
        };

        // Get entity counts from investigation entities (API returns entity_types array)
        const entityTypesArray = investigationEntities.entity_types || [];
        const entityTypes = {};
        entityTypesArray.forEach(et => {
          entityTypes[et.type] = et;
        });
        const totalEntities = entityTypesArray.reduce((sum, et) => sum + (et.values?.length || 0), 0);

        // Calculate average confidence for risk indicator
        let avgConfidence = 0;
        let totalValues = 0;
        Object.values(entityTypes).forEach(et => {
          (et.values || []).forEach(v => {
            avgConfidence += v.confidence || 0;
            totalValues++;
          });
        });
        avgConfidence = totalValues > 0 ? Math.round(avgConfidence / totalValues) : 0;

        return (
          <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '0.75rem' }}>
            {/* Top Row: Key Metrics - horizontal */}
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {[
                { v: extractedIOCs.length, l: 'IOCs', c: '#3b82f6', icon: '🎯' },
                { v: highRiskCount, l: 'High Risk', c: highRiskCount > 0 ? '#ef4444' : '#22c55e', icon: highRiskCount > 0 ? '⚠️' : '✓' },
                { v: relatedAlerts.length, l: 'Alerts', c: '#f59e0b', icon: '🚨' },
                { v: totalEntities, l: 'Entities', c: '#a855f7', icon: '🔗' }
              ].map((s, i) => (
                <div key={i} style={{
                  flex: 1,
                  background: `linear-gradient(135deg, ${s.c}15, ${s.c}08)`,
                  border: `1px solid ${s.c}30`,
                  borderRadius: 8,
                  padding: '0.6rem 0.75rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem'
                }}>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: s.c, lineHeight: 1 }}>{s.v}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', lineHeight: 1.2 }}>{s.l}</div>
                </div>
              ))}
            </div>

            {/* Entity Risk Scores Row */}
            {Object.keys(entityTypes).length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 500 }}>Entities:</span>
                {Object.entries(entityTypes).map(([type, data], i) => {
                  const config = entityTypeConfig[type] || { color: '#6b7280', icon: '📍', label: type };
                  const count = data.values?.length || 0;
                  // Get highest confidence value for this entity type
                  const topConfidence = Math.max(...(data.values || []).map(v => v.confidence || 0), 0);

                  return (
                    <div key={i} style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.2rem 0.5rem',
                      borderRadius: 12,
                      background: `${config.color}18`,
                      border: `1px solid ${config.color}35`,
                      cursor: 'pointer'
                    }} title={`${data.display_name}: ${count} value(s), top confidence: ${topConfidence}%`}>
                      <span style={{ fontSize: '0.7rem' }}>{config.icon}</span>
                      <span style={{ fontSize: '0.65rem', color: config.color, fontWeight: 500 }}>{config.label}</span>
                      <span style={{
                        fontSize: '0.6rem',
                        fontWeight: 700,
                        color: 'white',
                        background: config.color,
                        padding: '0.1rem 0.4rem',
                        borderRadius: 8,
                        minWidth: 18,
                        textAlign: 'center'
                      }}>{count}</span>
                      {topConfidence > 0 && (
                        <span style={{
                          fontSize: '0.55rem',
                          color: topConfidence >= 80 ? '#22c55e' : topConfidence >= 50 ? '#f59e0b' : '#6b7280',
                          fontWeight: 500
                        }}>
                          {topConfidence}%
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* IOC Categories Row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 500 }}>IOCs:</span>
              {categories.length > 0 ? categories.map((cat, i) => {
                const count = extractedIOCs.filter(ioc => ioc.category === cat).length;
                const color = catColorMap[cat] || '#6b7280';
                return (
                  <div key={i} style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    padding: '0.2rem 0.5rem',
                    borderRadius: 12,
                    background: `${color}18`,
                    border: `1px solid ${color}35`
                  }}>
                    <span style={{ fontSize: '0.65rem', color, fontWeight: 500 }}>{cat}</span>
                    <span style={{
                      fontSize: '0.6rem',
                      fontWeight: 700,
                      color: 'white',
                      background: color,
                      padding: '0.1rem 0.4rem',
                      borderRadius: 8,
                      minWidth: 18,
                      textAlign: 'center'
                    }}>{count}</span>
                  </div>
                );
              }) : (
                <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', fontStyle: 'italic' }}>No IOCs extracted</span>
              )}

              {/* Risk warning inline */}
              {highRiskCount > 0 && (
                <div style={{
                  marginLeft: 'auto',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                  padding: '0.2rem 0.6rem',
                  borderRadius: 12,
                  background: '#ef444418',
                  border: '1px solid #ef444435',
                  fontSize: '0.65rem',
                  color: '#f87171',
                  fontWeight: 500
                }}>
                  <span>⚠️</span>
                  <span>{highRiskCount} high-risk</span>
                </div>
              )}
            </div>
          </div>
        );
      }
      
      case 'event-details':
        // Use rawAlert directly for structured semantic display
        const eventData = rawAlert || alertData || {};
        const hasEventData = eventData && Object.keys(eventData).length > 0 && 
          (eventData.host || eventData.user || eventData.network || eventData.file || 
           eventData.email || eventData.process || eventData.mitre || eventData.source);
        
        return (
          <div style={{ height: maxH, overflow: 'auto' }}>
            {hasEventData ? (
              <pre style={{ fontSize: '0.75rem', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px', overflow: 'auto' }}>
                {JSON.stringify(eventData, null, 2)}
              </pre>
            ) : (
              <div style={{ padding: '1rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📋</div>
                <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>No structured event data available</div>
                <div style={{ fontSize: '0.75rem' }}>
                  Click on a Related Alert to view detailed event information
                </div>
              </div>
            )}
          </div>
        );
      
      case 'timeline':
        return <div style={{ height: maxH, overflow: 'auto' }}>{timeline.slice(0, fullPage ? 50 : 8).map((e, i) => <div key={i} style={{ padding: '0.25rem 0 0.25rem 0.75rem', borderLeft: '2px solid #3b82f640', position: 'relative' }}><div style={{ position: 'absolute', left: -4, top: 8, width: 6, height: 6, borderRadius: '50%', background: '#3b82f6' }} /><div style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>{fmtDate(e.timestamp)}</div><div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{e.event || e.description}</div></div>)}</div>;
      
      case 'summary':
        // Extract more summary data from multiple possible locations
        const summaryDesc = alertData.description || alertData.summary || alertData.message || 
                           investigation.description || investigation.alert_title || '';
        const host = alertData.host?.hostname || alertData.host?.name || alertData.hostname || 
                    alertData.computer_name || alertData.endpoint || '';
        const sourceIp = alertData.source_ip || alertData.src_ip || alertData.source?.ip || 
                        alertData.network?.source_ip || '';
        const destIp = alertData.destination_ip || alertData.dst_ip || alertData.dest_ip || 
                      alertData.destination?.ip || alertData.network?.destination_ip || '';
        const userName = alertData.user?.username || alertData.user?.name || alertData.username || '';
        const processName = alertData.process?.name || alertData.process_name || '';
        
        return (
          <div style={{ height: maxH, overflow: 'auto', fontSize: '0.75rem' }}>
            {summaryDesc ? (
              <p style={{ color: 'var(--text-secondary)', margin: '0 0 0.5rem 0', lineHeight: 1.5 }}>
                {summaryDesc}
              </p>
            ) : (
              <p style={{ color: 'var(--text-muted)', margin: '0 0 0.5rem 0', fontStyle: 'italic' }}>
                Security detection event
              </p>
            )}
            {host && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', minWidth: 55 }}>Host:</span>
                <code style={{ color: '#93c5fd', fontSize: '0.7rem' }}>{host}</code>
              </div>
            )}
            {userName && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', minWidth: 55 }}>User:</span>
                <code style={{ color: '#86efac', fontSize: '0.7rem' }}>{userName}</code>
              </div>
            )}
            {sourceIp && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', minWidth: 55 }}>Source:</span>
                <code style={{ color: '#93c5fd', fontSize: '0.7rem' }}>{sourceIp}</code>
              </div>
            )}
            {destIp && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', minWidth: 55 }}>Dest:</span>
                <code style={{ color: '#93c5fd', fontSize: '0.7rem' }}>{destIp}</code>
              </div>
            )}
            {processName && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', minWidth: 55 }}>Process:</span>
                <code style={{ color: '#fcd34d', fontSize: '0.7rem' }}>{processName}</code>
              </div>
            )}
            {mitre && (
              <div style={{ marginTop: '0.35rem' }}>
                <span style={{ display: 'inline-block', padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.6rem', background: '#dc262620', color: '#f87171' }}>
                  🎯 {mitre.technique_id}: {mitre.technique}
                </span>
              </div>
            )}
          </div>
        );
      
      case 'mitre':
        return mitre ? <div><span style={{ display: 'inline-block', padding: '0.2rem 0.4rem', borderRadius: 4, fontSize: '0.65rem', fontWeight: 600, background: '#dc262620', color: '#f87171', marginBottom: '0.25rem' }}>{mitre.technique_id}</span><div style={{ fontSize: '0.75rem', fontWeight: 500 }}>{mitre.technique}</div><div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Tactic: {mitre.tactic}</div></div> : null;
      
      // Individual IOC Category Widgets
      case 'ioc-network':
      case 'ioc-process':
      case 'ioc-domains':
      case 'ioc-identity':
      case 'ioc-file':
      case 'ioc-email': {
        const categoryMap = {
          'ioc-network': 'Network',
          'ioc-process': 'Process',
          'ioc-domains': 'URLs & Domains',
          'ioc-identity': 'Identity',
          'ioc-file': 'File',
          'ioc-email': 'Email'
        };
        const category = categoryMap[wid];
        const items = extractedIOCs.filter(ioc => ioc.category === category);
        
        if (!items || items.length === 0) return null;
        
        const catGradients = {
          'Network': 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
          'Process': 'linear-gradient(135deg, #f59e0b, #d97706)',
          'URLs & Domains': 'linear-gradient(135deg, #a855f7, #2e8b57)',
          'Identity': 'linear-gradient(135deg, #22c55e, #16a34a)',
          'File': 'linear-gradient(135deg, #06b6d4, #0891b2)',
          'Email': 'linear-gradient(135deg, #ec4899, #db2777)',
          'Cloud': 'linear-gradient(135deg, #3CB371, #4f46e5)'
        };
        const catIcons = { 'Network': '🌐', 'Process': '⚙️', 'URLs & Domains': '🔗', 'Identity': '👤', 'File': '📄', 'Email': '📧', 'Cloud': '☁️' };
        const catTextColors = { 'Network': '#93c5fd', 'Process': '#fcd34d', 'URLs & Domains': '#d8b4fe', 'Identity': '#86efac', 'File': '#67e8f9', 'Email': '#f9a8d4', 'Cloud': '#a5b4fc' };
        
        const getRisk = (ioc) => {
          const v = (ioc.value || '').toLowerCase();
          const t = (ioc.type || '').toLowerCase();
          if (ioc.severity === 'critical') return 'critical';
          if (ioc.severity === 'high') return 'high';
          if (t.includes('ip') && !v.startsWith('10.') && !v.startsWith('192.168.') && !v.startsWith('172.')) return 'high';
          if (v.includes('.ru') || v.includes('.cn') || v.includes('tor') || v.includes('onion')) return 'high';
          if (ioc.severity === 'medium') return 'medium';
          return null;
        };
        const isPrivateIP = (v) => v && (v.startsWith('10.') || v.startsWith('192.168.') || v.startsWith('172.') || v.startsWith('127.'));
        const truncate = (s, len = 45) => s && s.length > len ? s.substring(0, len) + '...' : s;
        const riskColors = { critical: { bg: '#dc262640', text: '#f87171' }, high: { bg: '#ea580c40', text: '#fb923c' }, medium: { bg: '#eab30840', text: '#facc15' } };
        
        // Action handlers
        const handleEnrich = (ioc) => {}
        const handleBlock = (ioc) => {}
        
        // Check if IOC type supports blocking
        const canBlock = (ioc) => {
          const t = (ioc.type || '').toLowerCase();
          return t.includes('ip') || t.includes('domain') || t.includes('url') || t.includes('hash') || t.includes('sha') || t.includes('md5');
        };
        
        // Special Identity card with actions
        if (category === 'Identity') {
          const userData = {};
          items.forEach(item => { userData[(item.type || '').toLowerCase()] = item.value; });
          const displayName = userData['display name'] || userData['username'] || 'Unknown';
          const email = userData['user email'] || userData['email sender'];
          const mfaUsed = userData['mfa used'];
          const privileged = userData['privileged'];
          const role = userData['role'];
          
          return (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg, #3b82f6, #3CB371)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1rem', fontWeight: 600, color: 'white' }}>
                  {displayName[0].toUpperCase()}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{displayName}</div>
                  {email && <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{email}</div>}
                </div>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', marginBottom: '0.5rem' }}>
                {mfaUsed && (
                  <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.6rem', background: mfaUsed === 'Yes' ? '#22c55e20' : '#f59e0b20', color: mfaUsed === 'Yes' ? '#4ade80' : '#fbbf24', border: `1px solid ${mfaUsed === 'Yes' ? '#22c55e40' : '#f59e0b40'}` }}>
                    {mfaUsed === 'Yes' ? '✓ MFA' : '⚠ No MFA'}
                  </span>
                )}
                {privileged === 'Yes' && (
                  <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.6rem', background: '#dc262620', color: '#f87171', border: '1px solid #dc262640' }}>Privileged</span>
                )}
                {role && (
                  <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.6rem', background: '#3b82f620', color: '#60a5fa', border: '1px solid #3b82f640' }}>{role}</span>
                )}
              </div>
              {/* Identity Actions */}
              <div style={{ display: 'flex', gap: '0.3rem', marginTop: 'auto' }}>
                <button onClick={() => handleEnrich({ type: 'user', value: displayName })} style={{ flex: 1, padding: '0.3rem', borderRadius: 4, border: '1px solid #3b82f640', background: '#3b82f615', color: '#60a5fa', fontSize: '0.6rem', cursor: 'pointer' }}>🔍 Lookup</button>
                <button style={{ flex: 1, padding: '0.3rem', borderRadius: 4, border: '1px solid #f59e0b40', background: '#f59e0b15', color: '#fbbf24', fontSize: '0.6rem', cursor: 'pointer' }}>🔐 Reset PWD</button>
              </div>
            </div>
          );
        }
        
        // Standard IOC list card with Enrich/Block actions - scrollable
        return (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
              {items.map((ioc, idx) => {
                const risk = getRisk(ioc);
                const isPrivate = isPrivateIP(ioc.value);
                const blockable = canBlock(ioc);
                
                return (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', padding: '0.35rem 0.4rem', borderRadius: 4, background: idx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent', marginBottom: '0.2rem' }}>
                    <span style={{ color: catColors[category] || '#6b7280', fontSize: '0.35rem' }}>●</span>
                    <code style={{ fontSize: '0.7rem', color: catTextColors[category] || '#a0e9ff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, minWidth: 0 }} title={ioc.value}>{ioc.value}</code>
                    {risk && <span style={{ padding: '0.1rem 0.2rem', borderRadius: 3, fontSize: '0.45rem', fontWeight: 600, background: riskColors[risk].bg, color: riskColors[risk].text }}>{risk.toUpperCase()}</span>}
                    {isPrivate && <span style={{ padding: '0.1rem 0.2rem', borderRadius: 3, fontSize: '0.4rem', background: '#22c55e15', color: '#4ade80' }}>Priv</span>}
                  </div>
                );
              })}
            </div>
            {/* Action buttons */}
            <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.4rem', paddingTop: '0.4rem', borderTop: '1px solid #ffffff10', flexShrink: 0 }}>
              <button onClick={() => items.forEach(handleEnrich)} style={{ flex: 1, padding: '0.25rem', borderRadius: 4, border: '1px solid #3b82f640', background: '#3b82f615', color: '#60a5fa', fontSize: '0.55rem', cursor: 'pointer', fontWeight: 500 }}>🔍 Enrich</button>
              {['Network', 'URLs & Domains', 'File'].includes(category) && (
                <button onClick={() => items.filter(canBlock).forEach(handleBlock)} style={{ flex: 1, padding: '0.25rem', borderRadius: 4, border: '1px solid #dc262640', background: '#dc262615', color: '#f87171', fontSize: '0.55rem', cursor: 'pointer', fontWeight: 500 }}>🚫 Block</button>
              )}
              <button onClick={() => items.forEach(i => copyToClipboard(i.value))} style={{ padding: '0.25rem 0.4rem', borderRadius: 4, border: '1px solid #ffffff20', background: '#ffffff08', color: 'var(--text-muted)', fontSize: '0.55rem', cursor: 'pointer' }}>📋</button>
            </div>
          </div>
        );
      }
      
      // =========== IOC OVERVIEW WIDGET ===========
      // =========== ACTION REQUIRED WIDGET ===========
      case 'action-required': {
        const highRiskIOCs = extractedIOCs.filter(ioc => {
          const risk = getRiskLevel(ioc);
          return risk === 'high' || risk === 'critical';
        });
        const privilegedUsers = extractedIOCs.filter(ioc => ioc.type === 'Privileged' && ioc.value === 'Yes');
        const noMFA = extractedIOCs.filter(ioc => ioc.type === 'MFA Used' && ioc.value === 'No');
        const actionItems = [];
        
        if (highRiskIOCs.length > 0) actionItems.push({ icon: '🚨', text: `${highRiskIOCs.length} high-risk IOCs need review`, severity: 'high' });
        if (privilegedUsers.length > 0) actionItems.push({ icon: '👑', text: 'Privileged account involved', severity: 'high' });
        if (noMFA.length > 0) actionItems.push({ icon: '🔓', text: 'Account without MFA', severity: 'medium' });
        if (extractedIOCs.length > 0) actionItems.push({ icon: '🔍', text: `${extractedIOCs.length} IOCs need enrichment`, severity: 'low' });
        
        return (
          <div style={{ height: '100%', overflow: 'auto' }}>
            {actionItems.length > 0 ? actionItems.map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem', borderRadius: 4, background: item.severity === 'high' ? '#dc262610' : item.severity === 'medium' ? '#f59e0b10' : '#3b82f610', marginBottom: '0.3rem', borderLeft: `3px solid ${item.severity === 'high' ? '#dc2626' : item.severity === 'medium' ? '#f59e0b' : '#3b82f6'}` }}>
                <span style={{ fontSize: '0.9rem' }}>{item.icon}</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{item.text}</span>
              </div>
            )) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#22c55e' }}>
                <span style={{ fontSize: '0.8rem' }}>✓ No immediate actions required</span>
              </div>
            )}
          </div>
        );
      }
      
      // =========== AI SUMMARY WIDGET ===========
      case 'ai-summary': {
        // Collect all agent analyses from investigation_data
        const tier1Analysis = invData.tier1_analysis || {};
        const tier2Analysis = invData.tier2_analysis || {};
        const tier3Analysis = invData.tier3_analysis || {};

        // Build array of agent contributions in order
        const agentContributions = [];
        if (tier1Analysis.agent_id) {
          agentContributions.push({ tier: 1, label: 'Riggs Triage', ...tier1Analysis });
        }
        if (tier2Analysis.agent_id) {
          agentContributions.push({ tier: 2, label: 'Riggs Analysis', ...tier2Analysis });
        }
        if (tier3Analysis.agent_id) {
          agentContributions.push({ tier: 3, label: 'Riggs Deep Analysis', ...tier3Analysis });
        }

        // Use most recent agent for primary display
        const agentAnalysis = tier3Analysis.agent_id ? tier3Analysis : (tier2Analysis.agent_id ? tier2Analysis : tier1Analysis);
        const severity = (alertData.severity || investigation.severity || 'medium').toLowerCase();

        // Use executive_summary from investigation, or agent reasoning
        let summaryText = investigation.executive_summary || agentAnalysis.summary || investigation.alert_title || 'Security incident detected';

        // Build risk assessment from agent verdict and confidence
        let riskAssessment = '';
        const verdict = agentAnalysis.verdict || '';
        const confidence = agentAnalysis.confidence || 0;

        if (verdict === 'true_positive' || verdict === 'malicious') {
          riskAssessment = `HIGH - ${verdict.replace('_', ' ').toUpperCase()} (${Math.round(confidence * 100)}% confidence)`;
        } else if (verdict === 'suspicious' || verdict === 'needs_investigation' || verdict === 'needs_escalation') {
          riskAssessment = `MEDIUM - SUSPICIOUS (${Math.round(confidence * 100)}% confidence)`;
        } else if (verdict === 'false_positive' || verdict === 'benign') {
          riskAssessment = `LOW - ${verdict.replace('_', ' ').toUpperCase()} (${Math.round(confidence * 100)}% confidence)`;
        } else if (severity === 'critical' || severity === 'high') {
          riskAssessment = 'HIGH - Requires immediate attention';
        } else if (severity === 'medium') {
          riskAssessment = 'MEDIUM - Further analysis needed';
        } else {
          riskAssessment = 'LOW - Standard security event';
        }

        // Use actual recommendations from agent, fallback to generated ones
        let recommendations = agentAnalysis.recommended_actions || [];

        // If no agent recommendations, use reasoning chain or fallback
        if (recommendations.length === 0 && agentAnalysis.reasoning_chain?.length > 0) {
          // Extract action items from reasoning chain
          agentAnalysis.reasoning_chain.slice(-3).forEach(step => {
            if (step.action || step.step) {
              recommendations.push(step.action || step.step);
            }
          });
        }

        // Fallback to basic recommendations if still empty
        if (recommendations.length === 0) {
          const hasPrivileged = extractedIOCs.some(ioc => ioc.type === 'Privileged' && ioc.value === 'Yes');
          const hasExternalIP = extractedIOCs.some(ioc => ioc.type?.includes('IP') && !isPrivateIP(ioc.value));
          const hasSuspiciousDomain = extractedIOCs.some(ioc => ioc.category === 'URLs & Domains' && (ioc.value?.includes('.ru') || ioc.value?.includes('.cn')));

          if (hasPrivileged) {
            recommendations.push('Verify account owner activity');
            recommendations.push('Check for credential exposure');
          } else if (hasSuspiciousDomain || hasExternalIP) {
            recommendations.push('Analyze network traffic');
            recommendations.push('Check for data exfiltration');
          } else {
            recommendations.push('Review event timeline');
          }

          if (mitre) {
            recommendations.push(`Hunt for ${mitre.technique_id} indicators`);
          }
        }

        // Helper to get verdict color
        const getVerdictColor = (v) => {
          if (!v) return '#6b7280';
          if (v === 'malicious' || v === 'true_positive') return '#ef4444';
          if (v === 'suspicious' || v === 'needs_escalation' || v === 'needs_investigation') return '#f59e0b';
          if (v === 'benign' || v === 'false_positive') return '#22c55e';
          return '#6b7280';
        };

        return (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: '0.4rem', overflow: 'auto' }}>
            {/* Agent contributions - shows notes from each agent */}
            {agentContributions.length > 0 && (
              <div style={{ marginBottom: '0.3rem' }}>
                <div style={{ fontSize: '0.55rem', color: 'var(--text-muted)', marginBottom: '0.3rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Agent Analysis Trail</div>
                {agentContributions.map((agent, idx) => (
                  <div key={idx} style={{
                    background: '#1a1a2e',
                    border: '1px solid #ffffff10',
                    borderLeft: `3px solid ${getVerdictColor(agent.verdict)}`,
                    borderRadius: 4,
                    padding: '0.4rem',
                    marginBottom: '0.3rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                      <span style={{
                        fontSize: '0.6rem',
                        fontWeight: 600,
                        color: agent.tier === 1 ? '#60a5fa' : agent.tier === 2 ? '#5eead4' : '#f472b6',
                        background: agent.tier === 1 ? '#60a5fa15' : agent.tier === 2 ? '#5eead415' : '#f472b615',
                        padding: '0.1rem 0.3rem',
                        borderRadius: 3
                      }}>
                        {agent.label} Agent
                      </span>
                      <span style={{
                        fontSize: '0.55rem',
                        color: getVerdictColor(agent.verdict),
                        fontWeight: 500
                      }}>
                        {agent.verdict?.replace(/_/g, ' ').toUpperCase()} ({Math.round((agent.confidence || 0) * 100)}%)
                      </span>
                    </div>
                    {agent.summary && (
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                        {agent.summary}
                      </div>
                    )}
                    {/* Show evidence summary if available */}
                    {agent.evidence && agent.evidence.length > 0 && (
                      <div style={{ fontSize: '0.55rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                        Evidence: {agent.evidence.map(e => e.type).filter((v, i, a) => a.indexOf(v) === i).join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Summary text if no agent contributions shown */}
            {agentContributions.length === 0 && (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>{summaryText}</div>
            )}

            {/* Risk Assessment */}
            <div style={{ padding: '0.4rem', borderRadius: 4, background: riskAssessment.startsWith('HIGH') ? '#dc262615' : riskAssessment.startsWith('MEDIUM') ? '#f59e0b15' : '#22c55e15' }}>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: '0.15rem' }}>RISK ASSESSMENT</div>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: riskAssessment.startsWith('HIGH') ? '#f87171' : riskAssessment.startsWith('MEDIUM') ? '#fbbf24' : '#4ade80' }}>{riskAssessment}</div>
            </div>

            {/* Recommendations */}
            <div style={{ flex: 1, overflow: 'auto' }}>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>RECOMMENDATIONS</div>
              {recommendations.slice(0, 5).map((rec, i) => (
                <div key={i} style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', padding: '0.15rem 0', borderBottom: '1px solid #ffffff08' }}>• {typeof rec === 'string' ? rec : rec.description || rec.action || JSON.stringify(rec)}</div>
              ))}
              {recommendations.length === 0 && (
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>Awaiting AI analysis...</div>
              )}
            </div>
          </div>
        );
      }
      
      // =========== CLOUD WIDGET ===========
      case 'cloud': {
        const cloudIOCs = extractedIOCs.filter(ioc => ioc.category === 'Cloud');
        if (cloudIOCs.length === 0) return null;
        
        const cloudData = {};
        cloudIOCs.forEach(ioc => { cloudData[(ioc.type || '').toLowerCase()] = ioc.value; });
        
        return (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ flex: 1, overflow: 'auto' }}>
              {cloudData['provider'] && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span style={{ fontSize: '1.2rem' }}>{cloudData['provider'] === 'AWS' ? '🟠' : cloudData['provider'] === 'Azure' ? '🔵' : cloudData['provider'] === 'GCP' ? '🔴' : '☁️'}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{cloudData['provider']}</span>
                </div>
              )}
              {cloudIOCs.map((ioc, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', padding: '0.25rem 0', borderBottom: '1px solid #ffffff08' }}>
                  <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', minWidth: 50 }}>{ioc.type}</span>
                  <code style={{ fontSize: '0.65rem', color: '#a5b4fc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</code>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.4rem', paddingTop: '0.4rem', borderTop: '1px solid #ffffff10' }}>
              <button style={{ flex: 1, padding: '0.25rem', borderRadius: 4, border: '1px solid #3CB37140', background: '#3CB37115', color: '#a5b4fc', fontSize: '0.55rem', cursor: 'pointer' }}>📋 View Logs</button>
              <button style={{ flex: 1, padding: '0.25rem', borderRadius: 4, border: '1px solid #f59e0b40', background: '#f59e0b15', color: '#fbbf24', fontSize: '0.55rem', cursor: 'pointer' }}>🔑 Check IAM</button>
            </div>
          </div>
        );
      }
      
      case 'iocs':
        // Full page IOCs tab uses the IOCPanel
        return (
          <IOCPanel 
            iocs={extractedIOCs} 
            onEnrich={(ioc) => {}}
            onBlock={(ioc) => {}}
          />
        );
      
      case 'related-alerts': {
        // Helper function to get correlation badge color
        const getCorrelationColor = (type) => {
          switch (type) {
            case 'auto_link': return '#22c55e';  // Green - high confidence auto-link
            case 'soft_link': return '#f59e0b';  // Amber - soft link, needs review
            case 'create_new': return '#3b82f6'; // Blue - created this investigation
            case 'legacy': return '#6b7280';     // Gray - legacy correlation
            default: return '#6b7280';
          }
        };

        // Helper function to format correlation score
        const formatScore = (corr) => {
          if (!corr || corr.score === undefined || corr.score === null) return null;
          return `${corr.score}/${corr.threshold || 100}`;
        };

        return (
          <div style={{ height: maxH, overflow: 'auto' }}>
            {/* Show total count */}
            <div style={{ padding: '0.25rem 0.25rem 0.5rem', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              {relatedAlerts.length} alert{relatedAlerts.length !== 1 ? 's' : ''} linked to this investigation
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
              <thead>
                <tr>
                  {['Alert ID', 'Title', 'Severity', 'Correlation', 'Time'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '0.25rem', fontSize: '0.6rem', textTransform: 'uppercase', color: 'var(--text-muted)', borderBottom: '1px solid #ffffff15' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {relatedAlerts.slice(0, fullPage ? 50 : 5).map((a, i) => {
                  const corr = a.correlation || {};
                  const scoreText = formatScore(corr);
                  const matchedEntities = corr.matched_entities || [];

                  return (
                    <tr key={i} onClick={() => openAlertDetails(a)} style={{ cursor: 'pointer' }} onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <td style={{ padding: '0.35rem 0.25rem', borderBottom: '1px solid #ffffff08' }}>
                        <code style={{ fontSize: '0.65rem', color: '#5eead4', background: '#3CB37115', padding: '0.1rem 0.3rem', borderRadius: 3 }}>
                          {a.alert_id || a.id || '-'}
                        </code>
                      </td>
                      <td style={{ padding: '0.35rem 0.25rem', borderBottom: '1px solid #ffffff08', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title || 'Alert'}</td>
                      <td style={{ padding: '0.35rem 0.25rem', borderBottom: '1px solid #ffffff08' }}>
                        <span style={{ padding: '0.1rem 0.3rem', borderRadius: 3, fontSize: '0.6rem', fontWeight: 600, background: sevCol(a.severity), color: 'white', textTransform: 'uppercase' }}>{a.severity || 'medium'}</span>
                      </td>
                      <td style={{ padding: '0.35rem 0.25rem', borderBottom: '1px solid #ffffff08' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <span style={{ padding: '0.1rem 0.3rem', borderRadius: 3, fontSize: '0.55rem', fontWeight: 600, background: getCorrelationColor(corr.decision_type), color: 'white', textTransform: 'uppercase' }}>
                              {corr.decision_type || 'linked'}
                            </span>
                            {scoreText && (
                              <span style={{ fontSize: '0.55rem', color: corr.score >= (corr.threshold || 100) ? '#22c55e' : '#f59e0b' }}>
                                {scoreText}
                              </span>
                            )}
                          </div>
                          {matchedEntities.length > 0 && (
                            <div style={{ display: 'flex', gap: '0.15rem', flexWrap: 'wrap' }}>
                              {matchedEntities.slice(0, 3).map((e, ei) => (
                                <span key={ei} style={{ padding: '0.05rem 0.2rem', borderRadius: 2, fontSize: '0.5rem', background: '#ffffff10', color: '#a5b4fc' }}>
                                  {e}
                                </span>
                              ))}
                              {matchedEntities.length > 3 && (
                                <span style={{ fontSize: '0.5rem', color: 'var(--text-muted)' }}>+{matchedEntities.length - 3}</span>
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                      <td style={{ padding: '0.35rem 0.25rem', borderBottom: '1px solid #ffffff08', color: 'var(--text-muted)', fontSize: '0.65rem' }}>{fmtDate(a.created_at)}</td>
                    </tr>
                  );
                })}
                {!relatedAlerts.length && <tr><td colSpan={5} style={{ textAlign: 'center', padding: '0.5rem', color: 'var(--text-muted)' }}>No alerts linked to this investigation</td></tr>}
              </tbody>
            </table>
            {relatedAlerts.length > (fullPage ? 50 : 5) && (
              <div style={{ textAlign: 'center', padding: '0.25rem', fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                Showing {fullPage ? 50 : 5} of {relatedAlerts.length} alerts
              </div>
            )}
          </div>
        );
      }
      
      case 'notes-widget':
        return <div style={{ height: maxH, overflow: 'auto' }}>{notes.map((n, i) => <div key={i} style={{ background: 'var(--bg-tertiary)', padding: '0.35rem', borderRadius: 4, marginBottom: '0.35rem', borderLeft: '2px solid #3b82f6' }}><div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.15rem' }}><span style={{ fontSize: '0.65rem', fontWeight: 500 }}>{n.author}</span><span style={{ fontSize: '0.55rem', color: 'var(--text-muted)' }}>{fmtDate(n.created_at)}</span></div><div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{(n.content || '').substring(0, 150)}</div></div>)}{!notes.length && <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.7rem' }}>No notes</div>}</div>;
      
      case 'raw-data': {
        // Get the full investigation data including raw_alert
        const rawDataToShow = invData || rawAlert || alertData || {};

        // Simple syntax highlighting for JSON (with HTML escaping for XSS safety)
        const escapeHtml = (str) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const syntaxHighlight = (json) => {
          if (typeof json !== 'string') {
            json = JSON.stringify(json, null, 2);
          }
          json = escapeHtml(json);
          return json.replace(/(&quot;(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\&])*&quot;(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
            let cls = '#a5d6ff'; // number - light blue
            if (/^"/.test(match)) {
              if (/:$/.test(match)) {
                cls = '#ff7b72'; // key - red/orange
              } else {
                cls = '#a5d6ff'; // string - light blue
              }
            } else if (/true|false/.test(match)) {
              cls = '#79c0ff'; // boolean - cyan
            } else if (/null/.test(match)) {
              cls = '#8b949e'; // null - gray
            }
            return `<span style="color:${cls}">${match}</span>`;
          });
        };

        return (
          <div style={{ height: maxH, overflow: 'auto', background: '#0d1117', borderRadius: 6, padding: '0.75rem' }}>
            <pre
              style={{
                margin: 0,
                fontSize: '0.7rem',
                fontFamily: 'Monaco, Consolas, monospace',
                lineHeight: 1.5,
                color: '#c9d1d9',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}
            >{JSON.stringify(rawDataToShow, null, 2)}</pre>
          </div>
        );
      }

      // =========== AGENT ACTIONS WIDGET ===========
      case 'agent-actions': {
        const getActionIcon = (actionType) => {
          const icons = {
            contain_host: '🔒', block_ip: '🚫', block_domain: '🌐', block_hash: '🔐',
            disable_user: '👤', reset_password: '🔑', revoke_sessions: '🚪',
            quarantine_file: '📁', isolate_endpoint: '💻', terminate_process: '⚡',
            collect_forensics: '🧪', run_scan: '🔍'
          };
          return icons[actionType] || '⚙️';
        };

        const getStatusColor = (status) => {
          switch (status) {
            case 'pending': return '#f59e0b';
            case 'approved': return '#3b82f6';
            case 'executing': return '#3CB371';
            case 'completed': return '#22c55e';
            case 'failed': return '#ef4444';
            case 'denied': return '#6b7280';
            default: return '#6b7280';
          }
        };

        const getPriorityColor = (priority) => {
          switch (priority) {
            case 'critical': return '#ef4444';
            case 'high': return '#f97316';
            case 'medium': return '#eab308';
            case 'low': return '#22c55e';
            default: return '#6b7280';
          }
        };

        const handleQuickApprove = async (requestId) => {
          try {
            const username = localStorage.getItem('username') || 'analyst';
            const r = await fetch(`${API_BASE_URL}/api/v1/actions/requests/${requestId}/approve`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ approved_by: username, execute_immediately: true })
            });
            if (r.ok) fetchActionRequests();
          } catch {}
        };

        const handleQuickDeny = async (requestId) => {
          try {
            const username = localStorage.getItem('username') || 'analyst';
            const r = await fetch(`${API_BASE_URL}/api/v1/actions/requests/${requestId}/deny`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ denied_by: username, denial_reason: 'Denied from investigation view' })
            });
            if (r.ok) fetchActionRequests();
          } catch {}
        };

        const pendingActions = actionRequests.filter(a => a.status === 'pending');
        const completedActions = actionRequests.filter(a => ['completed', 'denied', 'failed'].includes(a.status));

        return (
          <div style={{ height: maxH, overflow: 'auto' }}>
            {actionRequests.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                No agent actions for this investigation
              </div>
            ) : (
              <>
                {/* Pending Actions */}
                {pendingActions.length > 0 && (
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div style={{ fontSize: '0.65rem', fontWeight: 600, color: '#f59e0b', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                      Pending Approval ({pendingActions.length})
                    </div>
                    {pendingActions.map(action => (
                      <div key={action.request_id} style={{
                        background: 'rgba(245, 158, 11, 0.1)',
                        border: '1px solid rgba(245, 158, 11, 0.3)',
                        borderRadius: 6,
                        padding: '0.5rem',
                        marginBottom: '0.35rem'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            <span style={{ fontSize: '0.9rem' }}>{getActionIcon(action.action_type)}</span>
                            <span style={{ fontSize: '0.7rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                              {(action.action_type || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </span>
                            <span style={{
                              fontSize: '0.55rem',
                              padding: '0.1rem 0.3rem',
                              borderRadius: 3,
                              background: getPriorityColor(action.priority),
                              color: 'white',
                              fontWeight: 500,
                              textTransform: 'uppercase'
                            }}>
                              {action.priority}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '0.25rem' }}>
                            <button
                              onClick={() => handleQuickApprove(action.request_id)}
                              style={{
                                padding: '0.15rem 0.4rem',
                                fontSize: '0.6rem',
                                background: '#22c55e',
                                border: 'none',
                                borderRadius: 4,
                                color: 'white',
                                cursor: 'pointer'
                              }}
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => handleQuickDeny(action.request_id)}
                              style={{
                                padding: '0.15rem 0.4rem',
                                fontSize: '0.6rem',
                                background: 'transparent',
                                border: '1px solid #ef4444',
                                borderRadius: 4,
                                color: '#ef4444',
                                cursor: 'pointer'
                              }}
                            >
                              Deny
                            </button>
                          </div>
                        </div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                          Target: {action.target_value}
                        </div>
                        {action.reasoning && (
                          <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                            {action.reasoning.substring(0, 120)}...
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Completed/History */}
                {completedActions.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.65rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                      History ({completedActions.length})
                    </div>
                    {completedActions.map(action => (
                      <div key={action.request_id} style={{
                        background: 'var(--bg-tertiary)',
                        borderRadius: 4,
                        padding: '0.35rem 0.5rem',
                        marginBottom: '0.25rem',
                        borderLeft: `3px solid ${getStatusColor(action.status)}`
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <span style={{ fontSize: '0.75rem' }}>{getActionIcon(action.action_type)}</span>
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                            {(action.action_type || '').replace(/_/g, ' ')}
                          </span>
                          <span style={{
                            fontSize: '0.55rem',
                            padding: '0.1rem 0.25rem',
                            borderRadius: 3,
                            background: getStatusColor(action.status),
                            color: 'white'
                          }}>
                            {action.status}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          {action.target_value}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        );
      }

      default:
        return <div style={{ color: 'var(--text-muted)' }}>Unknown widget</div>;
    }
  };

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden', padding: '0.25rem' }}>
      {/* Main content area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', height: '100%' }}>
        {/* Header - Compact for laptops */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.75rem', borderBottom: '1px solid #ffffff15', background: 'var(--bg-secondary)', flexShrink: 0, borderRadius: '8px 8px 0 0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Link to="/queue" style={{ color: 'var(--text-muted)', fontSize: '0.75rem', textDecoration: 'none' }}>← Back</Link>
            <div style={{ background: 'linear-gradient(135deg, #3CB37120, #3b82f620)', border: '1px solid #3CB37140', borderRadius: 5, padding: '0.25rem 0.5rem', cursor: 'pointer' }} onClick={() => copyToClipboard(window.location.href)}><span style={{ fontSize: '0.85rem', color: '#5eead4', fontWeight: 700, fontFamily: 'monospace' }}>{investigation.investigation_id}</span></div>
            <h1 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0, maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{investigation.alert_title || investigation.title}</h1>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <button onClick={() => setEditMode(!editMode)} style={{ padding: '0.3rem 0.6rem', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 500, background: editMode ? '#22c55e' : '#ffffff15', color: editMode ? 'white' : 'var(--text-primary)' }}>{editMode ? '✓ Done' : '⚙️ Edit'}</button>
            {editMode && <><button onClick={() => setShowCatalog(true)} style={{ padding: '0.3rem 0.6rem', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 500, background: '#3b82f6', color: 'white' }}>+ Add</button><button onClick={resetLayout} style={{ padding: '0.3rem 0.6rem', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 500, background: '#ffffff15', color: 'var(--text-primary)' }}>↺ Reset</button></>}
            <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.65rem', fontWeight: 600, background: stateCol(investigation.state), color: 'white' }}>{investigation.state || 'NEW'}</span>
            <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, fontSize: '0.65rem', fontWeight: 600, background: sevCol(investigation.severity || alertData.severity), color: 'white' }}>{investigation.severity || alertData.severity || 'MEDIUM'}</span>
          </div>
        </div>

        {/* Tabs - Compact */}
        <div style={{ display: 'flex', gap: '0.15rem', padding: '0.35rem 0.75rem', background: 'var(--bg-tertiary)', flexShrink: 0, borderRadius: '0 0 8px 8px', marginBottom: '0.35rem' }}>
          {['overview', 'alerts', 'iocs', 'timeline'].map(t => <button key={t} onClick={() => setActiveTab(t)} style={{ padding: '0.3rem 0.75rem', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 500, background: activeTab === t ? '#3b82f6' : 'transparent', color: activeTab === t ? 'white' : 'var(--text-secondary)' }}>{t === 'overview' ? '📊 Overview' : t === 'alerts' ? `🚨 Alerts (${relatedAlerts.length})` : t === 'iocs' ? `🎯 IOCs (${extractedIOCs.length})` : `📅 Timeline (${timeline.length})`}</button>)}
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
          {activeTab === 'overview' ? (
            <div style={{ display: 'flex', flex: 1, overflow: 'hidden', height: '100%', position: 'relative' }}>
              {/* Widget Canvas - Using react-grid-layout */}
              <div ref={containerRef} style={{ flex: 1, overflow: 'auto', padding: '0.25rem', transition: 'padding 0.3s ease' }}>
                {(() => {
                  // Calculate which widgets are visible based on data
                  const iocsByCat = extractedIOCs.reduce((a, i) => { (a[i.category] = a[i.category] || []).push(i); return a; }, {});

                  const eventData = rawAlert || alertData || {};
                  const hasEventData = eventData && Object.keys(eventData).length > 0 &&
                    (eventData.host || eventData.user || eventData.network || eventData.file ||
                     eventData.email || eventData.process || eventData.mitre || eventData.source ||
                     eventData.detection || eventData.iocs || eventData.tags);

                  const visibleLayout = layout.filter(w => {
                    // Always show meta widgets
                    if (['threat-intel', 'action-required', 'ai-summary', 'summary', 'timeline', 'related-alerts', 'notes-widget', 'raw-data', 'agent-actions'].includes(w.i)) return true;

                    // Event details - show if structured data exists
                    if (w.i === 'event-details' && !hasEventData) return false;

                    // IOC category widgets - show if category has data
                    if (w.i === 'ioc-network' && !iocsByCat['Network']?.length) return false;
                    if (w.i === 'ioc-process' && !iocsByCat['Process']?.length) return false;
                    if (w.i === 'ioc-domains' && !iocsByCat['URLs & Domains']?.length) return false;
                    if (w.i === 'ioc-identity' && !iocsByCat['Identity']?.length) return false;
                    if (w.i === 'ioc-file' && !iocsByCat['File']?.length) return false;
                    if (w.i === 'ioc-email' && !iocsByCat['Email']?.length) return false;
                    if (w.i === 'cloud' && !iocsByCat['Cloud']?.length) return false;

                    // MITRE - show if mapping exists
                    if (w.i === 'mitre' && !mitre) return false;

                    return true;
                  });

                  return (
                    <ResponsiveGridLayout
                      className="layout"
                      layout={visibleLayout}
                      cols={GRID_COLS}
                      rowHeight={ROW_HEIGHT}
                      onLayoutChange={onLayoutChange}
                      draggableHandle=".widget-drag-handle"
                      isResizable={editMode}
                      isDraggable={editMode}
                      compactType="vertical"
                      preventCollision={false}
                      margin={[6, 6]}
                      measureBeforeMount={false}
                    >
                      {visibleLayout.map(w => {
                        const cfg = WIDGET_REGISTRY[w.i];
                        if (!cfg) return null;

                        return (
                          <div
                            key={w.i}
                            style={{
                              background: 'var(--bg-secondary)',
                              borderRadius: 8,
                              border: editMode ? '2px dashed #3b82f680' : '1px solid #ffffff10',
                              overflow: 'hidden',
                              display: 'flex',
                              flexDirection: 'column'
                            }}
                          >
                            <div
                              className="widget-drag-handle"
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                padding: '0.35rem 0.5rem',
                                borderBottom: '1px solid #ffffff10',
                                background: '#ffffff05',
                                cursor: editMode ? 'move' : 'default',
                                flexShrink: 0
                              }}
                            >
                              <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{cfg.title}</span>
                              {editMode && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); removeWidget(w.i); }}
                                  style={{ background: '#dc262630', border: 'none', borderRadius: 3, padding: '0.1rem 0.3rem', cursor: 'pointer', color: '#f87171', fontSize: '0.65rem' }}
                                >✕</button>
                              )}
                            </div>
                            <div style={{ padding: '0.5rem', flex: 1, overflow: 'auto' }}>
                              {renderContent(w.i)}
                            </div>
                          </div>
                        );
                      })}
                    </ResponsiveGridLayout>
                  );
                })()}
              </div>

              {/* Sidebar Toggle Button */}
              <div
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                style={{
                  position: 'absolute',
                  right: sidebarCollapsed ? 0 : 'calc(220px + 0.3rem)',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  width: 16,
                  height: 45,
                  background: 'var(--bg-tertiary)',
                  border: '1px solid #ffffff15',
                  borderRight: sidebarCollapsed ? '1px solid #ffffff15' : 'none',
                  borderRadius: '5px 0 0 5px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 10,
                  transition: 'right 0.3s ease'
                }}
                title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{sidebarCollapsed ? '◀' : '▶'}</span>
              </div>

              {/* Sidebar - Laptop optimized */}
              <div style={{
                width: sidebarCollapsed ? 0 : 220,
                flexShrink: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: '0.3rem',
                padding: sidebarCollapsed ? 0 : '0.4rem',
                borderLeft: sidebarCollapsed ? 'none' : '1px solid #ffffff15',
                background: 'var(--bg-tertiary)',
                overflowY: 'auto',
                overflowX: 'hidden',
                height: '100%',
                boxSizing: 'border-box',
                transition: 'width 0.3s ease, padding 0.3s ease',
                opacity: sidebarCollapsed ? 0 : 1,
                borderRadius: 8,
                marginLeft: '0.3rem'
              }}>
                {/* Details */}
                <div style={{ background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid #ffffff10', overflow: 'hidden' }}>
                  <div style={{ padding: '0.25rem 0.4rem', borderBottom: '1px solid #ffffff10', background: '#ffffff05' }}><span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Details</span></div>
                  <div style={{ padding: '0.35rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Created:</span><span>{fmtDate(investigation.created_at)}</span></div><div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Updated:</span><span>{fmtDate(investigation.updated_at)}</span></div></div>
                </div>

                {/* Management */}
                <div style={{ background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid #ffffff10', overflow: 'hidden' }}>
                  <div style={{ padding: '0.25rem 0.4rem', borderBottom: '1px solid #ffffff10', background: '#ffffff05' }}><span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Management</span></div>
                  <div style={{ padding: '0.35rem' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.3rem', marginBottom: '0.3rem' }}>
                      <div><label style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.1rem' }}>State</label><select value={investigation.state || 'NEW'} onChange={e => updateField('state', e.target.value)} style={{ width: '100%', padding: '0.25rem', background: 'var(--bg-tertiary)', border: `2px solid ${stateCol(investigation.state)}`, borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.7rem' }}><option value="NEW">New</option><option value="IN_PROGRESS">In Progress</option><option value="RESOLVED">Resolved</option><option value="CLOSED">Closed</option></select></div>
                      <div><label style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.1rem' }}>Disposition</label><select value={investigation.disposition || 'UNKNOWN'} onChange={e => updateField('disposition', e.target.value)} style={{ width: '100%', padding: '0.25rem', background: 'var(--bg-tertiary)', border: `2px solid ${dispCol(investigation.disposition)}`, borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.7rem' }}><option value="UNKNOWN">Unknown</option><option value="MALICIOUS">Malicious</option><option value="SUSPICIOUS">Suspicious</option><option value="BENIGN">Benign</option><option value="FALSE_POSITIVE">False Positive</option></select></div>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.3rem', marginBottom: '0.3rem' }}>
                      <div><label style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.1rem' }}>Priority</label><select value={investigation.priority || 'P3'} onChange={e => updateField('priority', e.target.value)} style={{ width: '100%', padding: '0.25rem', background: 'var(--bg-tertiary)', border: `2px solid ${prioCol(investigation.priority)}`, borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.7rem' }}><option value="P1">P1</option><option value="P2">P2</option><option value="P3">P3</option><option value="P4">P4</option></select></div>
                      <div><label style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.1rem' }}>Severity</label><select value={investigation.severity || alertData.severity || 'medium'} onChange={e => updateField('severity', e.target.value)} style={{ width: '100%', padding: '0.25rem', background: 'var(--bg-tertiary)', border: `2px solid ${sevCol(investigation.severity)}`, borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.7rem' }}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                    </div>
                    <div><label style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.1rem' }}>Owner</label><select value={investigation.owner || ''} onChange={e => updateField('owner', e.target.value)} style={{ width: '100%', padding: '0.25rem', background: 'var(--bg-tertiary)', border: '1px solid #ffffff20', borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.7rem' }}><option value="">Unassigned</option>{users.map(u => <option key={u.username} value={u.username}>{u.full_name || u.username}</option>)}</select></div>
                  </div>
                </div>

                {/* Notes - Compact */}
                <div style={{ background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid #ffffff10', overflow: 'hidden', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 160 }}>
                  <div style={{ padding: '0.25rem 0.4rem', borderBottom: '1px solid #ffffff10', background: '#ffffff05' }}><span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Notes ({notes.length})</span></div>
                  <div style={{ padding: '0.35rem', flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                    <textarea value={newNote} onChange={e => setNewNote(e.target.value)} onPaste={handleNotePaste} placeholder="Add note..." style={{ width: '100%', minHeight: 50, padding: '0.3rem', background: 'var(--bg-tertiary)', border: '1px solid #ffffff15', borderRadius: 4, color: 'var(--text-primary)', fontSize: '0.75rem', resize: 'vertical', marginBottom: '0.25rem', boxSizing: 'border-box' }} />
                    {noteAttachments.length > 0 && <div style={{ display: 'flex', gap: '0.2rem', flexWrap: 'wrap', marginBottom: '0.25rem' }}>{noteAttachments.map((a, i) => <div key={i} style={{ position: 'relative', width: 28, height: 28 }}><img src={a} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: 3, cursor: 'pointer' }} onClick={() => setEnlargedImage(a)} /><button onClick={() => setNoteAttachments(p => p.filter((_, j) => j !== i))} style={{ position: 'absolute', top: -3, right: -3, width: 10, height: 10, borderRadius: '50%', background: '#dc2626', border: 'none', color: 'white', fontSize: 7, cursor: 'pointer' }}>×</button></div>)}</div>}
                    <button onClick={addNote} disabled={!newNote.trim() && !noteAttachments.length} style={{ padding: '0.25rem', borderRadius: 4, border: 'none', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 500, background: '#3b82f6', color: 'white', marginBottom: '0.25rem', opacity: newNote.trim() || noteAttachments.length ? 1 : 0.5 }}>Add Note</button>
                    <div style={{ flex: 1, overflow: 'auto' }}>
                      {notes.map((n, i) => <div key={i} style={{ background: 'var(--bg-tertiary)', padding: '0.3rem', borderRadius: 4, marginBottom: '0.25rem', borderLeft: '2px solid #3b82f6' }}><div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.1rem' }}><span style={{ fontSize: '0.65rem', fontWeight: 500 }}>{n.author}</span><span style={{ fontSize: '0.55rem', color: 'var(--text-muted)' }}>{fmtDate(n.created_at)}</span></div><div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{(n.content || '').split('\n').map((line, li, arr) => { const m = line.match(/!\[.*?\]\((data:image\/[^)]+)\)/); return m ? <img key={li} src={m[1]} alt="" style={{ maxWidth: '100%', maxHeight: 50, borderRadius: 3, cursor: 'pointer' }} onClick={() => setEnlargedImage(m[1])} /> : <span key={li}>{line}{li < arr.length - 1 ? '\n' : ''}</span>; })}</div></div>)}
                      {!notes.length && <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.7rem' }}>No notes</div>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Full page tabs */
            <div style={{ flex: 1, padding: '1rem', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              <div style={{ background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid #ffffff10', flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                {activeTab === 'alerts' && <div style={{ padding: '1rem', overflow: 'auto' }}>{renderContent('related-alerts', true)}</div>}
                {activeTab === 'iocs' && renderContent('iocs', true)}
                {activeTab === 'timeline' && <div style={{ padding: '1rem', overflow: 'auto' }}>{renderContent('timeline', true)}</div>}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Chat Panel - Laptop optimized */}
      <div style={{
        width: chatOpen ? '280px' : '45px',
        flexShrink: 0,
        transition: 'width 0.3s ease',
        position: 'relative',
        height: '100%'
      }}>
        {chatOpen ? (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <InvestigationChat
              investigationId={id}
              isOpen={chatOpen}
              onToggle={() => setChatOpen(false)}
            />
          </div>
        ) : (
          <button
            onClick={() => setChatOpen(true)}
            style={{
              position: 'absolute',
              top: '0.5rem',
              right: '0.5rem',
              width: '40px',
              height: '40px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #3CB371, #5a67d8)',
              border: 'none',
              color: 'white',
              fontSize: '0.7rem',
              cursor: 'pointer',
              boxShadow: '0 2px 10px rgba(102, 126, 234, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
            title="Open Chat"
          >
            💬
          </button>
        )}
      </div>

      {/* Widget Catalog */}
      {showCatalog && <><div style={{ position: 'fixed', inset: 0, background: '#00000080', zIndex: 999 }} onClick={() => setShowCatalog(false)} /><div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', background: 'var(--bg-secondary)', borderRadius: 10, padding: '1rem', zIndex: 1000, width: 400, maxHeight: '70vh', overflow: 'auto' }}><div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}><h3 style={{ margin: 0, fontSize: '1rem' }}>Add Widget</h3><button onClick={() => setShowCatalog(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.25rem' }}>×</button></div><div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>{Object.entries(WIDGET_REGISTRY).map(([wid, cfg]) => { const added = layout.some(w => w.i === wid); return <div key={wid} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-tertiary)', borderRadius: 6, border: added ? '2px solid #22c55e' : '2px solid transparent' }}><div><div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{cfg.title}</div><div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{cfg.desc}</div></div><button onClick={() => added ? removeWidget(wid) : addWidget(wid)} style={{ padding: '0.3rem 0.6rem', borderRadius: 4, border: 'none', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 500, background: added ? '#dc262630' : '#3b82f6', color: added ? '#f87171' : 'white' }}>{added ? 'Remove' : 'Add'}</button></div>; })}</div></div></>}

      {/* Alert Slideout */}
      {showAlertSlideout && selectedAlert && (
        <AlertDetailsDrawer 
          alert={{ 
            ...selectedAlert, 
            alert_id: selectedAlert.id || selectedAlert.alert_id || investigation.alert_id, 
            investigation_id: selectedAlert.investigation_id || investigation.investigation_id,
            // Pass the investigation's parsed data as raw_event fallback
            raw_event: (selectedAlert.raw_event && Object.keys(selectedAlert.raw_event || {}).length > 0) 
              ? selectedAlert.raw_event 
              : (rawAlert && Object.keys(rawAlert).length > 0 ? rawAlert : invData),
            title: selectedAlert.title || investigation.alert_title, 
            severity: selectedAlert.severity || investigation.severity || 'medium', 
            source: selectedAlert.source || 'Webhook', 
            status: selectedAlert.status || 'open', 
            created_at: selectedAlert.created_at || investigation.created_at,
            updated_at: selectedAlert.updated_at || investigation.updated_at
          }} 
          onClose={() => setShowAlertSlideout(false)} 
          onRefresh={fetchInvestigation} 
        />
      )}

      {/* Image Enlargement Modal */}
      {enlargedImage && (
        <>
          <div 
            onClick={() => setEnlargedImage(null)}
            style={{ 
              position: 'fixed', 
              inset: 0, 
              background: 'rgba(0,0,0,0.9)', 
              zIndex: 9999,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'zoom-out'
            }}
          >
            <img 
              src={enlargedImage} 
              alt="Enlarged" 
              style={{ 
                maxWidth: '90vw', 
                maxHeight: '90vh', 
                objectFit: 'contain',
                borderRadius: 8,
                boxShadow: '0 4px 20px rgba(0,0,0,0.5)'
              }} 
            />
            <button 
              onClick={() => setEnlargedImage(null)}
              style={{
                position: 'absolute',
                top: 20,
                right: 20,
                width: 40,
                height: 40,
                borderRadius: '50%',
                background: 'rgba(255,255,255,0.1)',
                border: '1px solid rgba(255,255,255,0.3)',
                color: 'white',
                fontSize: '1.5rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              ×
            </button>
          </div>
        </>
      )}
    </div>
  );
}


