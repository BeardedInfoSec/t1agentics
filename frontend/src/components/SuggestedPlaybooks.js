/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { PlayCircle, Clock, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronRight, Loader2, BookOpen } from 'lucide-react';
import { authFetch, API_BASE_URL } from '../utils/api';

// Match score badge colors
const scoreColors = {
  high: { bg: 'rgba(34, 197, 94, 0.15)', text: '#22c55e', border: 'rgba(34, 197, 94, 0.3)' },
  medium: { bg: 'rgba(234, 179, 8, 0.15)', text: '#eab308', border: 'rgba(234, 179, 8, 0.3)' },
  low: { bg: 'rgba(148, 163, 184, 0.12)', text: '#94a3b8', border: 'rgba(148, 163, 184, 0.2)' }
};

const getScoreLevel = (score) => {
  if (score >= 80) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
};

const SuggestedPlaybooks = ({ investigationId, investigation, compact = false }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [executingId, setExecutingId] = useState(null);
  const [executionResults, setExecutionResults] = useState({});

  // Fetch playbook recommendations
  useEffect(() => {
    const fetchRecommendations = async () => {
      if (!investigationId) return;

      setLoading(true);
      setError(null);

      try {
        const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/playbooks/recommend`, {
          method: 'POST',
          body: JSON.stringify({
            investigation_id: investigationId,
            max_recommendations: 5
          })
        });

        if (!response.ok) {
          throw new Error('Failed to fetch playbook recommendations');
        }

        const data = await response.json();
        setPlaybooks(data.recommendations || []);
      } catch (err) {
        setError(err.message);

        // Also check if recommendations are already in investigation data
        if (investigation?.investigation_data?.riggs_analysis?.playbook_recommendations) {
          setPlaybooks(investigation.investigation_data.riggs_analysis.playbook_recommendations);
          setError(null);
        }
      } finally {
        setLoading(false);
      }
    };

    fetchRecommendations();
  }, [investigationId, investigation]);

  // Execute a playbook
  const handleExecute = async (playbook) => {
    setExecutingId(playbook.playbook_id);

    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/playbooks/execute`, {
        method: 'POST',
        body: JSON.stringify({
          investigation_id: investigationId,
          playbook_id: playbook.playbook_id
        })
      });

      const data = await response.json();

      setExecutionResults(prev => ({
        ...prev,
        [playbook.playbook_id]: {
          success: response.ok,
          status: data.status,
          message: data.message || (response.ok ? 'Execution started' : 'Execution failed'),
          execution_id: data.execution_id,
          approval_id: data.approval_id
        }
      }));
    } catch (err) {
      setExecutionResults(prev => ({
        ...prev,
        [playbook.playbook_id]: {
          success: false,
          status: 'error',
          message: err.message
        }
      }));
    } finally {
      setExecutingId(null);
    }
  };

  // Get status icon
  const getStatusIcon = (result) => {
    if (!result) return null;

    switch (result.status) {
      case 'running':
      case 'executing':
        return <Loader2 size={14} className="animate-spin" style={{ color: '#60a5fa' }} />;
      case 'success':
      case 'completed':
        return <CheckCircle size={14} style={{ color: '#22c55e' }} />;
      case 'failed':
      case 'error':
        return <XCircle size={14} style={{ color: '#ef4444' }} />;
      case 'pending_approval':
        return <Clock size={14} style={{ color: '#eab308' }} />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <BookOpen size={16} style={{ color: '#6366f1' }} />
          <span style={styles.title}>SUGGESTED PLAYBOOKS</span>
        </div>
        <div style={styles.loading}>
          <Loader2 size={20} className="animate-spin" style={{ color: '#6366f1' }} />
          <span>Loading recommendations...</span>
        </div>
      </div>
    );
  }

  if (error && playbooks.length === 0) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <BookOpen size={16} style={{ color: '#6366f1' }} />
          <span style={styles.title}>SUGGESTED PLAYBOOKS</span>
        </div>
        <div style={styles.empty}>
          <AlertTriangle size={16} style={{ color: '#94a3b8' }} />
          <span>Unable to load recommendations</span>
        </div>
      </div>
    );
  }

  if (playbooks.length === 0) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <BookOpen size={16} style={{ color: '#6366f1' }} />
          <span style={styles.title}>SUGGESTED PLAYBOOKS</span>
        </div>
        <div style={styles.empty}>
          <span>No playbook recommendations available</span>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div
        style={styles.header}
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        {isCollapsed ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
        <BookOpen size={16} style={{ color: '#6366f1' }} />
        <span style={styles.title}>SUGGESTED PLAYBOOKS</span>
        <span style={styles.count}>{playbooks.length}</span>
      </div>

      {!isCollapsed && (
        <div style={styles.list}>
          {playbooks.map((playbook, index) => {
            const scoreLevel = getScoreLevel(playbook.match_score);
            const colors = scoreColors[scoreLevel];
            const result = executionResults[playbook.playbook_id];
            const isExecuting = executingId === playbook.playbook_id;

            return (
              <div key={playbook.playbook_id || index} style={styles.playbookCard}>
                <div style={styles.playbookHeader}>
                  <span style={styles.playbookName}>{playbook.playbook_name}</span>
                  {playbook.reasoning && (
                    <span style={{ fontSize: '10px', color: '#64748b', flexShrink: 0 }}>
                      {playbook.reasoning.length > 50 ? playbook.reasoning.slice(0, 50) + '...' : playbook.reasoning}
                    </span>
                  )}
                </div>
                {playbook.estimated_duration_minutes && (
                  <div style={styles.duration}>
                    <Clock size={10} />
                    <span>~{playbook.estimated_duration_minutes}m</span>
                  </div>
                )}
                <span style={{
                  ...styles.scoreBadge,
                  background: colors.bg,
                  color: colors.text,
                  borderColor: colors.border
                }}>
                  {playbook.match_score}%
                </span>
                <div style={styles.playbookFooter}>
                  {result ? (
                    <div style={styles.resultStatus}>
                      {getStatusIcon(result)}
                      <span style={{
                        color: result.success ? '#22c55e' :
                               result.status === 'pending_approval' ? '#eab308' : '#ef4444'
                      }}>
                        {result.message}
                      </span>
                    </div>
                  ) : (
                    <button
                      style={{
                        ...styles.executeButton,
                        opacity: isExecuting ? 0.7 : 1,
                        cursor: isExecuting ? 'not-allowed' : 'pointer'
                      }}
                      onClick={() => handleExecute(playbook)}
                      disabled={isExecuting}
                    >
                      {isExecuting ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <PlayCircle size={12} />
                      )}
                      <span>
                        {playbook.requires_approval ? 'Request Approval' :
                         playbook.auto_execute ? 'Auto-Execute' : 'Run'}
                      </span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const styles = {
  container: {
    background: 'rgba(11, 20, 55, 0.5)',
    borderRadius: '12px',
    border: '1px solid rgba(255, 255, 255, 0.06)',
    marginBottom: '8px',
    overflow: 'hidden'
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 10px',
    cursor: 'pointer',
    borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
    background: 'rgba(15, 20, 53, 0.5)'
  },
  title: {
    fontSize: '10px',
    fontWeight: 600,
    letterSpacing: '0.05em',
    color: '#94a3b8',
    flex: 1
  },
  count: {
    fontSize: '10px',
    fontWeight: 600,
    color: '#3CB371',
    background: 'rgba(60, 179, 113, 0.15)',
    padding: '1px 7px',
    borderRadius: '10px'
  },
  loading: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    padding: '12px',
    color: '#94a3b8',
    fontSize: '11px'
  },
  empty: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    padding: '12px',
    color: '#64748b',
    fontSize: '11px'
  },
  list: {
    padding: '4px 6px'
  },
  playbookCard: {
    background: 'rgba(255, 255, 255, 0.02)',
    borderRadius: '8px',
    border: '1px solid rgba(255, 255, 255, 0.04)',
    padding: '6px 10px',
    marginBottom: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '8px'
  },
  playbookHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flex: 1,
    minWidth: 0
  },
  playbookName: {
    fontSize: '11.5px',
    fontWeight: 600,
    color: '#e2e8f0',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis'
  },
  scoreBadge: {
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 7px',
    borderRadius: '10px',
    border: '1px solid',
    flexShrink: 0
  },
  reasoning: {
    fontSize: '10.5px',
    color: '#94a3b8',
    lineHeight: 1.3,
    marginBottom: '4px'
  },
  actions: {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '3px',
    marginBottom: '4px'
  },
  actionsLabel: {
    fontSize: '10px',
    color: '#64748b',
    marginRight: '2px'
  },
  actionTag: {
    fontSize: '9px',
    color: '#94a3b8',
    background: 'rgba(148, 163, 184, 0.1)',
    padding: '1px 5px',
    borderRadius: '4px'
  },
  moreActions: {
    fontSize: '9px',
    color: '#64748b'
  },
  duration: {
    display: 'flex',
    alignItems: 'center',
    gap: '3px',
    fontSize: '10px',
    color: '#64748b',
    flexShrink: 0
  },
  playbookFooter: {
    display: 'flex',
    alignItems: 'center',
    flexShrink: 0
  },
  executeButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    padding: '4px 10px',
    fontSize: '10.5px',
    fontWeight: 500,
    color: '#fff',
    background: 'rgba(60, 179, 113, 0.7)',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s'
  },
  resultStatus: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    fontSize: '10.5px'
  }
};

export default SuggestedPlaybooks;
