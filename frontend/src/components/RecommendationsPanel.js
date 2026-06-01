/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';

// Category badge colors - heavily muted to reduce visual noise
// Only "immediate" retains any color emphasis, all others use subtle gray tones
const categoryColors = {
  immediate: { bg: 'rgba(239, 68, 68, 0.12)', text: '#f87171', border: 'rgba(239, 68, 68, 0.2)' },
  containment: { bg: 'rgba(148, 163, 184, 0.12)', text: '#94a3b8', border: 'rgba(148, 163, 184, 0.2)' },
  investigate: { bg: 'rgba(148, 163, 184, 0.12)', text: '#94a3b8', border: 'rgba(148, 163, 184, 0.2)' },
  document: { bg: 'rgba(107, 114, 128, 0.1)', text: '#6b7280', border: 'rgba(107, 114, 128, 0.15)' },
  remediation: { bg: 'rgba(148, 163, 184, 0.12)', text: '#94a3b8', border: 'rgba(148, 163, 184, 0.2)' },
  default: { bg: 'rgba(107, 114, 128, 0.1)', text: '#6b7280', border: 'rgba(107, 114, 128, 0.15)' }
};

// Parse category from recommendation text or structure
const parseCategory = (recommendation) => {
  if (typeof recommendation === 'object' && recommendation.category) {
    return recommendation.category.toLowerCase();
  }

  const text = typeof recommendation === 'string' ? recommendation : recommendation.action || '';
  const lowerText = text.toLowerCase();

  if (lowerText.includes('block') || lowerText.includes('disable') || lowerText.includes('terminate') || lowerText.includes('immediately')) {
    return 'immediate';
  }
  if (lowerText.includes('isolate') || lowerText.includes('quarantine') || lowerText.includes('contain')) {
    return 'containment';
  }
  if (lowerText.includes('review') || lowerText.includes('investigate') || lowerText.includes('analyze') || lowerText.includes('check')) {
    return 'investigate';
  }
  if (lowerText.includes('document') || lowerText.includes('export') || lowerText.includes('report') || lowerText.includes('share')) {
    return 'document';
  }
  if (lowerText.includes('remediate') || lowerText.includes('fix') || lowerText.includes('patch') || lowerText.includes('update')) {
    return 'remediation';
  }

  return 'default';
};

// Extract recommendation text
const getRecommendationText = (recommendation) => {
  if (typeof recommendation === 'string') {
    return recommendation;
  }
  return recommendation.action || recommendation.text || recommendation.description || JSON.stringify(recommendation);
};

// Extract rationale if available
const getRationale = (recommendation) => {
  if (typeof recommendation === 'object') {
    return recommendation.rationale || recommendation.reason || recommendation.why || null;
  }
  return null;
};

const RecommendationsPanel = ({ investigation, onUpdate }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [completedItems, setCompletedItems] = useState(new Set());
  const [recommendations, setRecommendations] = useState([]);

  // Extract recommendations from investigation data
  useEffect(() => {
    if (!investigation) return;

    const data = investigation.investigation_data || {};
    const allRecommendations = [];

    // Priority order: riggs_analysis > tier2_analysis > tier1_analysis
    const sources = [
      data.riggs_analysis?.recommendations,
      data.tier2_analysis?.recommendations,
      data.tier1_analysis?.recommendations,
      data.recommendations
    ];

    for (const source of sources) {
      if (source && Array.isArray(source) && source.length > 0) {
        allRecommendations.push(...source);
        break; // Use first available source
      }
    }

    // Also check for action_items or suggested_actions
    if (allRecommendations.length === 0) {
      const actionSources = [
        data.riggs_analysis?.action_items,
        data.tier2_analysis?.action_items,
        data.action_items,
        data.suggested_actions
      ];

      for (const source of actionSources) {
        if (source && Array.isArray(source) && source.length > 0) {
          allRecommendations.push(...source);
          break;
        }
      }
    }

    setRecommendations(allRecommendations);

    // Load completed items from investigation
    if (investigation.recommendations_completed) {
      setCompletedItems(new Set(investigation.recommendations_completed));
    }
  }, [investigation]);

  const toggleItem = (index) => {
    const newCompleted = new Set(completedItems);
    if (newCompleted.has(index)) {
      newCompleted.delete(index);
    } else {
      newCompleted.add(index);
    }
    setCompletedItems(newCompleted);

    // Persist to backend if callback provided
    if (onUpdate) {
      onUpdate({ recommendations_completed: Array.from(newCompleted) });
    }
  };

  // Show empty state instead of returning null (which causes blank areas)
  if (!recommendations || recommendations.length === 0) {
    return (
      <div style={{
        padding: '24px',
        textAlign: 'center',
        color: 'var(--text-tertiary, #64748b)',
        fontSize: '13px'
      }}>
        <div style={{ fontSize: '24px', marginBottom: '8px', opacity: 0.5 }}>
          <span role="img" aria-label="clipboard">📋</span>
        </div>
        No recommendations available yet.
        <div style={{ fontSize: '11px', marginTop: '4px', opacity: 0.7 }}>
          Recommendations will appear after analysis completes.
        </div>
      </div>
    );
  }

  const completedCount = completedItems.size;
  const totalCount = recommendations.length;

  return (
    <div style={{
      overflow: 'hidden',
      height: '100%',
      display: 'flex',
      flexDirection: 'column'
    }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '0.5rem',
          cursor: 'pointer',
          userSelect: 'none'
        }}
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            fontSize: '0.7rem',
            fontWeight: '700',
            letterSpacing: '0.05em',
            color: '#e5e7eb',
            textTransform: 'uppercase'
          }}>
            RIGGS' RECOMMENDED ACTIONS
          </span>
          <span style={{
            fontSize: '0.65rem',
            color: completedCount === totalCount ? '#22c55e' : '#9ca3af',
            backgroundColor: completedCount === totalCount ? 'rgba(34, 197, 94, 0.15)' : 'rgba(75, 85, 99, 0.3)',
            padding: '2px 8px',
            borderRadius: '10px',
            fontWeight: completedCount === totalCount ? '600' : '400'
          }}>
            {completedCount === totalCount ? 'All Complete' : `${completedCount}/${totalCount} complete`}
          </span>
        </div>
        <button
          style={{
            background: 'none',
            border: 'none',
            color: '#9ca3af',
            fontSize: '0.65rem',
            cursor: 'pointer',
            padding: '3px 8px',
            borderRadius: '4px',
            transition: 'background-color 0.15s'
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = 'rgba(75, 85, 99, 0.3)'}
          onMouseLeave={(e) => e.target.style.backgroundColor = 'transparent'}
        >
          {isCollapsed ? 'Show' : 'Hide'}
        </button>
      </div>

      {/* Progress Bar */}
      <div style={{
        height: '4px',
        background: 'rgba(75, 85, 99, 0.3)',
        borderRadius: '2px',
        marginBottom: '0.75rem',
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: `${(completedCount / totalCount) * 100}%`,
          background: completedCount === totalCount
            ? 'linear-gradient(90deg, #22c55e, #10b981)'
            : completedCount > 0
              ? 'linear-gradient(90deg, #3b82f6, #6366f1)'
              : 'transparent',
          borderRadius: '2px',
          transition: 'width 0.3s ease, background 0.3s ease'
        }} />
      </div>

      {/* Content - scrollable */}
      {!isCollapsed && (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {recommendations.map((rec, index) => {
            const category = parseCategory(rec);
            const colors = categoryColors[category] || categoryColors.default;
            const text = getRecommendationText(rec);
            const rationale = getRationale(rec);
            const isCompleted = completedItems.has(index);

            return (
              <div
                key={index}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  padding: '8px 0',
                  borderBottom: index < recommendations.length - 1 ? '1px solid rgba(255, 255, 255, 0.08)' : 'none',
                  opacity: isCompleted ? 0.5 : 1,
                  transition: 'opacity 0.2s'
                }}
              >
                {/* Checkbox */}
                <div
                  onClick={() => toggleItem(index)}
                  style={{
                    width: '16px',
                    height: '16px',
                    borderRadius: '4px',
                    border: isCompleted ? 'none' : '2px solid rgba(107, 114, 128, 0.5)',
                    backgroundColor: isCompleted ? '#22c55e' : 'transparent',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    marginTop: '2px',
                    transition: 'all 0.15s'
                  }}
                >
                  {isCompleted && (
                    <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
                      <path d="M2 6L5 9L10 3" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  )}
                </div>

                {/* Content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  {/* Category Badge */}
                  <span style={{
                    fontSize: '0.6rem',
                    fontWeight: '600',
                    letterSpacing: '0.03em',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    backgroundColor: colors.bg,
                    color: colors.text,
                    border: `1px solid ${colors.border}`,
                    textTransform: 'uppercase',
                    display: 'inline-block',
                    marginBottom: '4px'
                  }}>
                    {category}
                  </span>

                  {/* Recommendation Text */}
                  <div style={{
                    fontSize: '0.8rem',
                    color: isCompleted ? '#9ca3af' : '#f3f4f6',
                    textDecoration: isCompleted ? 'line-through' : 'none',
                    lineHeight: '1.4'
                  }}>
                    {text}
                  </div>

                  {/* Rationale */}
                  {rationale && (
                    <div style={{
                      fontSize: '0.7rem',
                      color: '#6b7280',
                      paddingLeft: '8px',
                      borderLeft: '2px solid rgba(75, 85, 99, 0.3)',
                      marginTop: '4px',
                      lineHeight: '1.4'
                    }}>
                      {rationale}
                    </div>
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

export default RecommendationsPanel;
