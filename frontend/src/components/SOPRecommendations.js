/* Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0 */
import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL, getCsrfToken } from '../utils/api';

const CONTENT_ICONS = {
  sop: '\uD83D\uDCCB',
  playbook: '\u25B6\uFE0F',
  escalation: '\u26A0\uFE0F',
  policy: '\uD83D\uDCD6',
  procedure: '\uD83D\uDCC4',
};

function getIcon(contentType) {
  return CONTENT_ICONS[contentType] || '\uD83D\uDCC4';
}

function getScoreInfo(score) {
  if (score >= 0.7) return { label: 'HIGH MATCH', color: 'rgba(34,197,94,0.15)', textColor: '#22c55e' };
  if (score >= 0.4) return { label: 'PARTIAL MATCH', color: 'rgba(245,158,11,0.15)', textColor: '#f59e0b' };
  return { label: 'LOW MATCH', color: 'rgba(100,116,139,0.15)', textColor: '#9ca3af' };
}

export default function SOPRecommendations({ investigationId }) {
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState(null);
  const [feedbackSent, setFeedbackSent] = useState({});

  const fetchRecommendations = useCallback(async () => {
    if (!investigationId) return;
    setLoading(true);
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/knowledge-base/investigations/${investigationId}/recommendations`,
        { credentials: 'include' }
      );
      if (!res.ok) throw new Error(res.statusText);
      const data = await res.json();
      setRecommendations((data.recommendations || []).slice(0, 5));
    } catch {
      setRecommendations([]);
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchRecommendations();
  }, [fetchRecommendations]);

  const sendFeedback = async (kbId, helpful) => {
    const key = `${kbId}-${helpful}`;
    if (feedbackSent[key]) return;
    try {
      const csrf = getCsrfToken();
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRF-Token'] = csrf;
      await fetch(`${API_BASE_URL}/api/v1/knowledge-base/recommendations/feedback`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ kb_id: kbId, investigation_id: investigationId, helpful }),
      });
      setFeedbackSent((prev) => ({ ...prev, [key]: true }));
    } catch {
      /* silent */
    }
  };

  if (loading || recommendations.length === 0) return null;

  return (
    <div className="sop-recommendations">
      <div className="riggs-widget__header">
        <span className="riggs-widget__title">{'\uD83D\uDCD6'} Recommended SOPs &amp; Procedures</span>
        <span className="riggs-widget__count">{recommendations.length}</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {recommendations.map((rec) => {
          const score = getScoreInfo(rec.relevance_score);
          const isExpanded = expandedId === rec.kb_id;
          const steps = (rec.key_steps || []).slice(0, 3);

          return (
            <div
              key={rec.kb_id}
              className="sop-card"
              onClick={() => setExpandedId(isExpanded ? null : rec.kb_id)}
            >
              <div className="sop-card__icon">{getIcon(rec.content_type)}</div>

              <div className="sop-card__info">
                <div className="sop-card__title">{rec.title}</div>
                {rec.match_reasons && rec.match_reasons.length > 0 && (
                  <div className="sop-card__match">{rec.match_reasons.join(', ')}</div>
                )}
                {steps.length > 0 && (
                  <div className="sop-card__steps">
                    {steps.map((step, i) => (
                      <div key={i} className="sop-card__step">{step}</div>
                    ))}
                  </div>
                )}
                {isExpanded && rec.summary && (
                  <div style={{
                    marginTop: '0.5rem',
                    fontSize: '0.7rem',
                    color: 'var(--text-secondary, rgba(255,255,255,0.75))',
                    lineHeight: 1.5,
                    borderTop: '1px solid rgba(148,163,184,0.1)',
                    paddingTop: '0.4rem',
                  }}>
                    {rec.summary}
                  </div>
                )}
                <div className="sop-card__feedback" onClick={(e) => e.stopPropagation()}>
                  <span style={{ fontSize: '0.6rem', color: 'var(--text-muted, #64748b)' }}>Helpful?</span>
                  <button
                    className="sop-card__feedback-btn"
                    style={feedbackSent[`${rec.kb_id}-true`] ? { background: 'rgba(34,197,94,0.15)', color: '#22c55e' } : {}}
                    onClick={() => sendFeedback(rec.kb_id, true)}
                  >
                    {'\uD83D\uDC4D'}
                  </button>
                  <button
                    className="sop-card__feedback-btn"
                    style={feedbackSent[`${rec.kb_id}-false`] ? { background: 'rgba(239,68,68,0.15)', color: '#ef4444' } : {}}
                    onClick={() => sendFeedback(rec.kb_id, false)}
                  >
                    {'\uD83D\uDC4E'}
                  </button>
                </div>
              </div>

              <span
                className="sop-card__score"
                style={{ background: score.color, color: score.textColor }}
              >
                {score.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
