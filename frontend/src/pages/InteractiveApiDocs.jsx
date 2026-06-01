/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { authFetch, getCsrfToken } from '../utils/api';

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Styles                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

const METHOD_COLORS = {
  GET: '#3CB371',
  POST: '#86efac',
  PUT: '#e6a23c',
  PATCH: '#e6a23c',
  DELETE: '#e25555',
};

const s = {
  page: {
    display: 'flex',
    gap: '2rem',
    padding: '1.5rem',
    maxWidth: '1400px',
    margin: '0 auto',
    minHeight: 'calc(100vh - 120px)',
  },
  sidebar: {
    width: '240px',
    flexShrink: 0,
    position: 'sticky',
    top: '80px',
    alignSelf: 'flex-start',
    maxHeight: 'calc(100vh - 100px)',
    overflowY: 'auto',
  },
  sidebarTitle: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-xs)',
    fontWeight: 700,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    padding: '0.5rem 0.75rem',
    marginBottom: '0.25rem',
  },
  catBtn: (active) => ({
    display: 'block',
    width: '100%',
    textAlign: 'left',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: active ? 'var(--primary)' : 'var(--text-secondary)',
    fontWeight: active ? 600 : 400,
    padding: '0.5rem 0.75rem',
    borderRadius: 'var(--radius-sm)',
    background: active ? 'var(--primary-light)' : 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 0.15s',
    marginBottom: '2px',
  }),
  catCount: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    marginLeft: '0.5rem',
  },
  main: {
    flex: 1,
    minWidth: 0,
  },
  searchWrap: {
    marginBottom: '1.5rem',
  },
  searchInput: {
    width: '100%',
    padding: '0.75rem 1rem',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-primary)',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-md)',
    outline: 'none',
  },
  catHeader: {
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    fontSize: 'var(--text-xl)',
    color: 'var(--text-primary)',
    marginBottom: '0.25rem',
  },
  catDesc: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-secondary)',
    marginBottom: '1.5rem',
    lineHeight: 1.6,
  },
  card: {
    background: 'var(--glass-bg-solid)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-lg)',
    padding: '1.25rem 1.5rem',
    marginBottom: '1rem',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
  },
  endpointHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    marginBottom: '0.5rem',
    flexWrap: 'wrap',
  },
  methodBadge: (m) => ({
    fontFamily: 'var(--font-mono)',
    fontSize: '0.7rem',
    fontWeight: 700,
    padding: '0.2rem 0.5rem',
    borderRadius: 'var(--radius-sm)',
    color: '#fff',
    background: METHOD_COLORS[m] || '#888',
    whiteSpace: 'nowrap',
    lineHeight: '1.4',
  }),
  pathText: {
    fontFamily: 'var(--font-mono)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-primary)',
    wordBreak: 'break-all',
  },
  summary: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    fontWeight: 600,
    color: 'var(--text-primary)',
    marginBottom: '0.25rem',
  },
  desc: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-muted)',
    lineHeight: 1.6,
    marginBottom: '0.75rem',
  },
  toggleRow: {
    display: 'flex',
    gap: '0.5rem',
    flexWrap: 'wrap',
    marginBottom: '0.75rem',
  },
  toggleBtn: (active) => ({
    fontFamily: 'var(--font-sans)',
    fontSize: '0.75rem',
    fontWeight: 500,
    padding: '0.3rem 0.75rem',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border-color)',
    background: active ? 'var(--primary-light)' : 'transparent',
    color: active ? 'var(--primary)' : 'var(--text-muted)',
    cursor: 'pointer',
    transition: 'all 0.15s',
  }),
  codeBlock: {
    background: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-md)',
    padding: '1rem',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem',
    color: 'var(--text-primary)',
    lineHeight: 1.6,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    overflowX: 'auto',
    position: 'relative',
  },
  copyBtn: {
    position: 'absolute',
    top: '0.5rem',
    right: '0.5rem',
    fontFamily: 'var(--font-sans)',
    fontSize: '0.7rem',
    padding: '0.2rem 0.5rem',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border-color)',
    background: 'var(--bg-secondary)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
  },
  sectionLabel: {
    fontFamily: 'var(--font-sans)',
    fontSize: '0.7rem',
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: '0.5rem',
    marginTop: '0.75rem',
  },
  warningBanner: {
    background: 'rgba(226, 85, 85, 0.1)',
    border: '1px solid rgba(226, 85, 85, 0.3)',
    borderRadius: 'var(--radius-sm)',
    padding: '0.5rem 0.75rem',
    fontFamily: 'var(--font-sans)',
    fontSize: '0.78rem',
    color: '#e25555',
    marginBottom: '0.75rem',
  },
  // Try It styles
  tryItWrap: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-md)',
    padding: '1rem',
    marginTop: '0.75rem',
  },
  inputLabel: {
    fontFamily: 'var(--font-sans)',
    fontSize: '0.75rem',
    fontWeight: 600,
    color: 'var(--text-secondary)',
    marginBottom: '0.25rem',
    display: 'block',
  },
  input: {
    width: '100%',
    padding: '0.5rem 0.75rem',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    color: 'var(--text-primary)',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-sm)',
    outline: 'none',
    marginBottom: '0.5rem',
    boxSizing: 'border-box',
  },
  textarea: {
    width: '100%',
    minHeight: '120px',
    padding: '0.75rem',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    color: 'var(--text-primary)',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-sm)',
    outline: 'none',
    resize: 'vertical',
    marginBottom: '0.5rem',
    boxSizing: 'border-box',
  },
  sendBtn: (loading) => ({
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    fontWeight: 600,
    padding: '0.5rem 1.25rem',
    borderRadius: 'var(--radius-sm)',
    border: 'none',
    background: loading ? 'var(--text-muted)' : 'var(--primary)',
    color: '#fff',
    cursor: loading ? 'not-allowed' : 'pointer',
    transition: 'all 0.15s',
  }),
  responseWrap: {
    marginTop: '0.75rem',
  },
  responseStatus: (ok) => ({
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    fontWeight: 700,
    color: ok ? '#3CB371' : '#e25555',
    marginBottom: '0.5rem',
  }),
  loadingMsg: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-muted)',
    textAlign: 'center',
    padding: '3rem 1rem',
  },
  emptyMsg: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-muted)',
    textAlign: 'center',
    padding: '2rem 1rem',
  },
};

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Helpers                                                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

/** Extract {param} patterns from a path */
function extractPathParams(path) {
  const matches = path.match(/\{([^}]+)\}/g);
  if (!matches) return [];
  return matches.map((m) => m.slice(1, -1));
}

/** Replace {param} in path with actual values */
function buildUrl(path, paramValues) {
  let url = path;
  for (const [key, val] of Object.entries(paramValues)) {
    url = url.replace(`{${key}}`, encodeURIComponent(val));
  }
  return url;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Endpoint Card                                                             */
/* ─────────────────────────────────────────────────────────────────────────── */

function EndpointCard({ endpoint }) {
  const [showSection, setShowSection] = useState(null); // 'curl' | 'example' | 'tryit'
  const [paramValues, setParamValues] = useState({});
  const [requestBody, setRequestBody] = useState(
    endpoint.request_body ? JSON.stringify(endpoint.request_body, null, 2) : ''
  );
  const [response, setResponse] = useState(null);
  const [responseStatus, setResponseStatus] = useState(null);
  const [sending, setSending] = useState(false);
  const [copied, setCopied] = useState(false);

  const pathParams = extractPathParams(endpoint.path);
  const isDestructive = endpoint.method === 'DELETE' ||
    (endpoint.method === 'POST' && /close|delete|stop|cancel|reject|emergency/i.test(endpoint.path));

  const handleCopy = useCallback((text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, []);

  const handleSend = async () => {
    setSending(true);
    setResponse(null);
    setResponseStatus(null);

    try {
      const url = buildUrl(endpoint.path, paramValues);
      const opts = {
        method: endpoint.method,
      };

      if (['POST', 'PUT', 'PATCH'].includes(endpoint.method) && requestBody.trim()) {
        opts.headers = { 'Content-Type': 'application/json' };
        opts.body = requestBody;
      }

      const res = await authFetch(url, opts);
      setResponseStatus(res.status);

      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('json')) {
        const data = await res.json();
        setResponse(JSON.stringify(data, null, 2));
      } else {
        const text = await res.text();
        setResponse(text || '(empty response)');
      }
    } catch (err) {
      setResponseStatus(0);
      setResponse(`Network error: ${err.message}`);
    } finally {
      setSending(false);
    }
  };

  const toggle = (section) => {
    setShowSection((prev) => (prev === section ? null : section));
  };

  return (
    <div style={s.card}>
      {/* Header */}
      <div style={s.endpointHeader}>
        <span style={s.methodBadge(endpoint.method)}>{endpoint.method}</span>
        <span style={s.pathText}>{endpoint.path}</span>
      </div>

      {/* Summary + description */}
      {endpoint.summary && <div style={s.summary}>{endpoint.summary}</div>}
      {endpoint.description && <div style={s.desc}>{endpoint.description}</div>}

      {/* Destructive warning */}
      {isDestructive && (
        <div style={s.warningBanner}>
          This is a destructive operation. Use with caution in production.
        </div>
      )}

      {/* Toggle buttons */}
      <div style={s.toggleRow}>
        {endpoint.curl_example && (
          <button style={s.toggleBtn(showSection === 'curl')} onClick={() => toggle('curl')}>
            cURL
          </button>
        )}
        {(endpoint.response_example || endpoint.request_body) && (
          <button style={s.toggleBtn(showSection === 'example')} onClick={() => toggle('example')}>
            Examples
          </button>
        )}
        <button style={s.toggleBtn(showSection === 'tryit')} onClick={() => toggle('tryit')}>
          Try It
        </button>
      </div>

      {/* cURL section */}
      {showSection === 'curl' && endpoint.curl_example && (
        <div style={{ position: 'relative' }}>
          <div style={s.codeBlock}>
            {endpoint.curl_example}
          </div>
          <button style={s.copyBtn} onClick={() => handleCopy(endpoint.curl_example)}>
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      )}

      {/* Examples section */}
      {showSection === 'example' && (
        <div>
          {endpoint.request_body && (
            <>
              <div style={s.sectionLabel}>Request Body</div>
              <div style={s.codeBlock}>
                {JSON.stringify(endpoint.request_body, null, 2)}
              </div>
            </>
          )}
          {endpoint.response_example && (
            <>
              <div style={s.sectionLabel}>Response</div>
              <div style={s.codeBlock}>
                {JSON.stringify(endpoint.response_example, null, 2)}
              </div>
            </>
          )}
        </div>
      )}

      {/* Try It section */}
      {showSection === 'tryit' && (
        <div style={s.tryItWrap}>
          {/* Path params */}
          {pathParams.length > 0 && (
            <>
              <div style={s.sectionLabel}>Path Parameters</div>
              {pathParams.map((param) => (
                <div key={param}>
                  <label style={s.inputLabel}>{param}</label>
                  <input
                    style={s.input}
                    placeholder={`Enter ${param}`}
                    value={paramValues[param] || ''}
                    onChange={(e) => setParamValues((prev) => ({ ...prev, [param]: e.target.value }))}
                  />
                </div>
              ))}
            </>
          )}

          {/* Request body */}
          {['POST', 'PUT', 'PATCH'].includes(endpoint.method) && (
            <>
              <div style={s.sectionLabel}>Request Body (JSON)</div>
              <textarea
                style={s.textarea}
                value={requestBody}
                onChange={(e) => setRequestBody(e.target.value)}
                spellCheck={false}
              />
            </>
          )}

          {/* Send button */}
          <button style={s.sendBtn(sending)} onClick={handleSend} disabled={sending}>
            {sending ? 'Sending...' : `Send ${endpoint.method}`}
          </button>

          {/* Response */}
          {response !== null && (
            <div style={s.responseWrap}>
              <div style={s.responseStatus(responseStatus >= 200 && responseStatus < 300)}>
                {responseStatus === 0 ? 'Network Error' : `HTTP ${responseStatus}`}
              </div>
              <div style={{ position: 'relative' }}>
                <div style={{ ...s.codeBlock, maxHeight: '400px', overflowY: 'auto' }}>
                  {response}
                </div>
                <button style={s.copyBtn} onClick={() => handleCopy(response)}>
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Main Component                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

export default function InteractiveApiDocs() {
  const [categories, setCategories] = useState([]);
  const [activeCategory, setActiveCategory] = useState(null);
  const [categoryData, setCategoryData] = useState(null);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [catLoading, setCatLoading] = useState(false);
  const [error, setError] = useState(null);

  // Load category index
  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const res = await authFetch('/api/v1/docs/interactive/');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (mounted) {
          setCategories(data.categories || []);
          if (data.categories?.length > 0) {
            setActiveCategory(data.categories[0].key);
          }
        }
      } catch (err) {
        if (mounted) setError(err.message);
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, []);

  // Load category endpoints when selection changes
  useEffect(() => {
    if (!activeCategory) return;
    let mounted = true;
    setCatLoading(true);
    (async () => {
      try {
        const res = await authFetch(`/api/v1/docs/interactive/${activeCategory}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (mounted) setCategoryData(data);
      } catch (err) {
        if (mounted) setCategoryData(null);
      } finally {
        if (mounted) setCatLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, [activeCategory]);

  // Filter endpoints by search
  const filteredEndpoints = categoryData?.endpoints?.filter((ep) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      ep.path.toLowerCase().includes(q) ||
      (ep.summary || '').toLowerCase().includes(q) ||
      (ep.description || '').toLowerCase().includes(q) ||
      ep.method.toLowerCase().includes(q)
    );
  }) || [];

  if (loading) {
    return <div style={s.loadingMsg}>Loading API documentation...</div>;
  }

  if (error) {
    return (
      <div style={s.loadingMsg}>
        Failed to load documentation: {error}
      </div>
    );
  }

  return (
    <div style={s.page} className="interactive-docs-page">
      {/* Sidebar */}
      <nav style={s.sidebar} className="interactive-docs-sidebar">
        <div style={s.sidebarTitle}>API Categories</div>
        {categories.map((cat) => (
          <button
            key={cat.key}
            style={s.catBtn(activeCategory === cat.key)}
            onClick={() => setActiveCategory(cat.key)}
            onMouseEnter={(e) => {
              if (activeCategory !== cat.key) e.target.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={(e) => {
              if (activeCategory !== cat.key) e.target.style.color = 'var(--text-secondary)';
            }}
          >
            {cat.title}
            <span style={s.catCount}>{cat.endpoint_count}</span>
          </button>
        ))}
      </nav>

      {/* Main content */}
      <div style={s.main}>
        {/* Search */}
        <div style={s.searchWrap}>
          <input
            style={s.searchInput}
            type="text"
            placeholder="Search endpoints by path, method, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Category header */}
        {categoryData && !catLoading && (
          <>
            <h2 style={s.catHeader}>{categoryData.title}</h2>
            <p style={s.catDesc}>{categoryData.description}</p>
          </>
        )}

        {/* Loading state */}
        {catLoading && <div style={s.loadingMsg}>Loading endpoints...</div>}

        {/* Endpoint cards */}
        {!catLoading && filteredEndpoints.length === 0 && search && (
          <div style={s.emptyMsg}>No endpoints match "{search}"</div>
        )}

        {!catLoading && filteredEndpoints.map((ep, i) => (
          <EndpointCard key={`${ep.method}-${ep.path}-${i}`} endpoint={ep} />
        ))}
      </div>

      {/* Responsive */}
      <style>{`
        @media (max-width: 900px) {
          .interactive-docs-page { flex-direction: column !important; }
          .interactive-docs-sidebar {
            position: static !important;
            width: 100% !important;
            flex-direction: row !important;
            flex-wrap: wrap !important;
            gap: 0.25rem !important;
            max-height: none !important;
          }
        }
      `}</style>
    </div>
  );
}
