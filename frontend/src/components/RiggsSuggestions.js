/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authFetch, API_BASE_URL } from '../utils/api';
import { Button } from './ui';
import styles from './RiggsSuggestions.module.css';

const COMPLEXITY_COLORS = {
  simple: '#01B574',
  moderate: '#f59e0b',
  complex: '#ef4444',
};

const CATEGORY_LABELS = {
  threat_response: 'Threat Response',
  enrichment: 'Enrichment',
  notification: 'Notification',
  compliance: 'Compliance',
  hunting: 'Threat Hunting',
};

function RiggsSuggestions() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(true);
  const [building, setBuilding] = useState(null); // suggestion index being built

  const fetchSuggestions = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/builder/suggest-from-integrations`, {
        method: 'POST',
        body: JSON.stringify({ max_suggestions: 15, include_gap_analysis: true }),
      });

      if (response.ok) {
        const result = await response.json();
        setData(result);
      } else if (response.status === 403) {
        setError('upgrade');
      } else {
        const err = await response.json().catch(() => ({}));
        setError(err.detail || 'Failed to fetch suggestions');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const buildPlaybook = async (suggestion, index) => {
    setBuilding(index);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/builder/generate`, {
        method: 'POST',
        body: JSON.stringify({
          requirements: `${suggestion.description}. Use these integrations: ${(suggestion.integrations_used || []).join(', ')}`,
          name: suggestion.name,
          alert_type: suggestion.category === 'threat_response' ? 'security_alert' : null,
        }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.playbook?.id) {
          navigate(`/playbooks/${result.playbook.id}`);
        }
      } else {
        const err = await response.json().catch(() => ({}));
        setError(err.detail || 'Failed to build playbook');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBuilding(null);
    }
  };

  // Initial state — show CTA to fetch
  if (!data && !loading && !error) {
    return (
      <div className={styles.container}>
        <div className={styles.header} onClick={() => setExpanded(!expanded)}>
          <div className={styles.headerLeft}>
            <span className={styles.riggsIcon}>🧠</span>
            <span className={styles.headerTitle}>Riggs Suggestions</span>
            <span className={styles.riggsBadge}>AI</span>
          </div>
          <span className={styles.chevron}>{expanded ? '▾' : '▸'}</span>
        </div>
        {expanded && (
          <div className={styles.body}>
            <p className={styles.description}>
              Riggs can analyze your installed integrations and suggest playbooks you can build right now.
            </p>
            <Button variant="secondary" size="sm" onClick={fetchSuggestions}>
              Ask Riggs for Suggestions
            </Button>
          </div>
        )}
      </div>
    );
  }

  // Upgrade gate — in the OSS self-hosted build there is no commercial
  // upgrade path, so just render a neutral message instead of a "contact us"
  // CTA that would link to the (now-deleted) marketing site.
  if (error === 'upgrade') {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <span className={styles.riggsIcon}>🧠</span>
            <span className={styles.headerTitle}>Riggs Suggestions</span>
          </div>
        </div>
        <div className={styles.body}>
          <p className={styles.description}>
            Riggs integration-aware suggestions are not enabled for this license.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header} onClick={() => setExpanded(!expanded)}>
        <div className={styles.headerLeft}>
          <span className={styles.riggsIcon}>🧠</span>
          <span className={styles.headerTitle}>Riggs Suggestions</span>
          {data?.installed_summary && (
            <span className={styles.countBadge}>
              {data.installed_summary.count} integration{data.installed_summary.count !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className={styles.headerRight}>
          <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); fetchSuggestions(); }}>
            {loading ? 'Analyzing...' : 'Refresh'}
          </Button>
          <span className={styles.chevron}>{expanded ? '▾' : '▸'}</span>
        </div>
      </div>

      {expanded && (
        <div className={styles.body}>
          {loading && (
            <div className={styles.loadingState}>
              <div className={styles.loadingIcon}>🧠</div>
              <div>Riggs is analyzing your integrations...</div>
            </div>
          )}

          {error && error !== 'upgrade' && (
            <div className={styles.error}>{error}</div>
          )}

          {/* Suggestions */}
          {data?.suggestions?.length > 0 && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>
                Playbooks You Can Build Now ({data.suggestions.length})
              </div>
              <div className={styles.grid}>
                {data.suggestions.map((s, i) => (
                  <div key={i} className={styles.card}>
                    <div className={styles.cardHeader}>
                      <span className={styles.cardName}>{s.name}</span>
                      <span
                        className={styles.complexityBadge}
                        style={{ color: COMPLEXITY_COLORS[s.complexity] || '#94a3b8' }}
                      >
                        {s.complexity}
                      </span>
                    </div>
                    <p className={styles.cardDesc}>{s.description}</p>
                    {s.integrations_used?.length > 0 && (
                      <div className={styles.integrationTags}>
                        {s.integrations_used.map((int_id, j) => (
                          <span key={j} className={styles.integrationTag}>{int_id}</span>
                        ))}
                      </div>
                    )}
                    {s.category && (
                      <span className={styles.categoryTag}>
                        {CATEGORY_LABELS[s.category] || s.category}
                      </span>
                    )}
                    <Button
                      variant="secondary" size="sm"
                      onClick={() => buildPlaybook(s, i)}
                      disabled={building !== null}
                      style={{ marginTop: '8px' }}
                    >
                      {building === i ? 'Building...' : 'Build with Riggs'}
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Gap Analysis */}
          {data?.gap_analysis?.length > 0 && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>Unlock More Playbooks</div>
              <div className={styles.gapList}>
                {data.gap_analysis.map((gap, i) => (
                  <div key={i} className={styles.gapCard}>
                    <div className={styles.gapHeader}>
                      <span className={styles.gapCategory}>
                        Add: {gap.missing_category?.replace('_', ' ')}
                      </span>
                    </div>
                    <p className={styles.gapRec}>{gap.recommendation}</p>
                    {gap.example_integrations?.length > 0 && (
                      <div className={styles.integrationTags}>
                        {gap.example_integrations.map((ex, j) => (
                          <span key={j} className={styles.integrationTag}>{ex}</span>
                        ))}
                      </div>
                    )}
                    {gap.unlocked_playbooks?.length > 0 && (
                      <div className={styles.unlockedList}>
                        {gap.unlocked_playbooks.map((pb, j) => (
                          <span key={j} className={styles.unlockedItem}>+ {pb}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {data && !data.suggestions?.length && !loading && (
            <div className={styles.emptyState}>
              Install integrations from the T1 Connect marketplace to get personalized playbook suggestions.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default RiggsSuggestions;
