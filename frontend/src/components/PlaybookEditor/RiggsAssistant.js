/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Riggs AI Assistant Component
 *
 * Provides AI-powered assistance for building and improving playbooks.
 */

import React, { useState, useRef } from 'react';
import {
  Bot, Send, RefreshCw, Lightbulb, Zap,
  X, RotateCcw
} from 'lucide-react';
import { API_BASE_URL, getAuthHeaders, getCsrfToken } from '../../utils/api';

function RiggsAssistant({
  playbookId, nodes, edges,
  setNodes, setEdges, setHasChanges,
  onClose,
}) {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        'I can edit this canvas for you. Try:\n' +
        '- "Add a VirusTotal enrichment node after Riggs Analysis"\n' +
        '- "Why is this branch unreachable?"\n' +
        '- "Replace the Slack notify with a Jira ticket"\n' +
        '- "What does the condition node do?"',
    },
  ]);
  // Snapshot stack for undo. Each entry: { nodes, edges, summary }.
  const undoStack = useRef([]);

  const applyMutations = (mutations) => {
    if (!mutations || mutations.length === 0) return 0;

    // Snapshot BEFORE mutating so undo restores the prior state.
    undoStack.current.push({
      nodes: nodes.map((n) => ({ ...n, data: { ...(n.data || {}) }, position: { ...(n.position || {}) } })),
      edges: edges.map((e) => ({ ...e })),
      summary: `${mutations.length} edit${mutations.length === 1 ? '' : 's'}`,
    });
    // Cap the undo stack so we don't leak memory across long sessions.
    if (undoStack.current.length > 20) undoStack.current.shift();

    let nextNodes = nodes;
    let nextEdges = edges;

    for (const m of mutations) {
      if (m.op === 'add_node') {
        nextNodes = [...nextNodes, m.node];
      } else if (m.op === 'remove_node') {
        nextNodes = nextNodes.filter((n) => n.id !== m.node_id);
        nextEdges = nextEdges.filter((e) => e.source !== m.node_id && e.target !== m.node_id);
      } else if (m.op === 'update_node') {
        nextNodes = nextNodes.map((n) =>
          n.id === m.node_id
            ? {
                ...n,
                data: {
                  ...(n.data || {}),
                  ...(m.data || {}),
                  // shallow-merge config rather than replacing it wholesale
                  config: {
                    ...((n.data && n.data.config) || {}),
                    ...((m.data && m.data.config) || {}),
                  },
                },
              }
            : n
        );
      } else if (m.op === 'add_edge') {
        nextEdges = [...nextEdges, m.edge];
      } else if (m.op === 'remove_edge') {
        nextEdges = nextEdges.filter((e) => e.id !== m.edge_id);
      }
    }

    setNodes(nextNodes);
    setEdges(nextEdges);
    if (setHasChanges) setHasChanges(true);
    return mutations.length;
  };

  const undoLast = () => {
    const snap = undoStack.current.pop();
    if (!snap) return;
    setNodes(snap.nodes);
    setEdges(snap.edges);
    if (setHasChanges) setHasChanges(true);
    setMessages((prev) => [
      ...prev,
      { role: 'assistant', content: `Undid: ${snap.summary}.` },
    ]);
  };

  const callBackend = async (userText) => {
    const csrf = getCsrfToken();
    const headers = {
      ...getAuthHeaders(),
      'Content-Type': 'application/json',
    };
    if (csrf) headers['X-CSRF-Token'] = csrf;

    const response = await fetch(`${API_BASE_URL}/api/v1/riggs/playbooks/vpe-assist`, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify({
        message: userText,
        playbook_id: playbookId || null,
        canvas: { nodes, edges },
      }),
    });
    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Backend ${response.status}: ${txt.slice(0, 200)}`);
    }
    return response.json();
  };

  const sendMessage = async (overrideText) => {
    // Guard against being called as an onClick handler — React passes a
    // SyntheticEvent as the first arg, which we must ignore.
    const useOverride = typeof overrideText === 'string';
    const text = (useOverride ? overrideText : query).trim();
    if (!text) return;

    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setQuery('');
    setIsLoading(true);

    try {
      const data = await callBackend(text);
      const applied = applyMutations(data.mutations || []);
      let content = data.reply || 'Done.';
      if (applied > 0) {
        content += `\n\nApplied ${applied} edit${applied === 1 ? '' : 's'} to the canvas.`;
      }
      if (data.rejected && data.rejected.length > 0) {
        content += `\n\nSkipped ${data.rejected.length} unsafe edit${data.rejected.length === 1 ? '' : 's'}.`;
      }
      setMessages((prev) => [...prev, { role: 'assistant', content }]);
    } catch (err) {
      console.error('Riggs VPE assist error:', err);
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'I hit a backend error. Try again in a moment.' },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const analyzePlaybook = () => sendMessage('Analyze this playbook and suggest improvements.');
  const askBuild = () => sendMessage('Help me build a phishing response playbook.');

  return (
    <div style={styles.assistant}>
      <div style={styles.header}>
        <div style={styles.headerTitle}>
          <Bot size={20} style={{ color: '#8b5cf6' }} />
          <span>Riggs Assistant</span>
        </div>
        <button onClick={onClose} style={styles.closeButton}>
          <X size={18} />
        </button>
      </div>

      <div style={styles.quickActions}>
        <button onClick={analyzePlaybook} style={styles.quickAction} disabled={isLoading}>
          <Lightbulb size={14} />
          Analyze & Improve
        </button>
        <button onClick={askBuild} style={styles.quickAction} disabled={isLoading}>
          <Zap size={14} />
          Build from Template
        </button>
        <button
          onClick={undoLast}
          style={styles.quickAction}
          disabled={isLoading || undoStack.current.length === 0}
          title="Undo Riggs's last edit"
        >
          <RotateCcw size={14} />
          Undo
        </button>
      </div>

      <div style={styles.messages}>
        {messages.map((msg, idx) => (
          <div
            key={idx}
            style={{
              ...styles.message,
              ...(msg.role === 'user' ? styles.userMessage : styles.assistantMessage),
            }}
          >
            {msg.role === 'assistant' && (
              <div style={styles.avatarWrapper}>
                <Bot size={16} />
              </div>
            )}
            <div style={styles.messageContent}>
              {msg.content.split('\n').map((line, i) => (
                <p key={i} style={styles.messageLine}>{line}</p>
              ))}
            </div>
          </div>
        ))}

        {isLoading && (
          <div style={styles.loadingMessage}>
            <RefreshCw size={16} className="spin" />
            <span>Riggs is thinking...</span>
          </div>
        )}
      </div>

      <div style={styles.inputArea}>
        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              sendMessage();
            }
          }}
          placeholder="Ask Riggs anything..."
          rows={1}
          style={{
            ...styles.input,
            resize: 'none',
            overflow: 'hidden',
            lineHeight: '1.4',
            fontFamily: 'inherit',
            maxHeight: '100px',
          }}
          onInput={(e) => {
            e.target.style.height = 'auto';
            e.target.style.height = Math.min(e.target.scrollHeight, 100) + 'px';
          }}
          disabled={isLoading}
        />
        <button
          onClick={sendMessage}
          style={styles.sendButton}
          disabled={isLoading || !query.trim()}
        >
          <Send size={18} />
        </button>
      </div>
    </div>
  );
}

const styles = {
  assistant: {
    width: '360px',
    borderLeft: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-secondary, #1e293b)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  headerTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    fontSize: '14px',
    fontWeight: '600',
    color: 'var(--text-primary, #f0f6fc)',
  },
  closeButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '28px',
    height: '28px',
    border: 'none',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  quickActions: {
    display: 'flex',
    gap: '8px',
    padding: '12px 16px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  quickAction: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.03)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '12px',
    cursor: 'pointer',
  },
  messages: {
    flex: 1,
    overflow: 'auto',
    padding: '16px',
  },
  message: {
    display: 'flex',
    gap: '10px',
    marginBottom: '16px',
  },
  userMessage: {
    flexDirection: 'row-reverse',
  },
  assistantMessage: {
    flexDirection: 'row',
  },
  avatarWrapper: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    background: 'rgba(139, 92, 246, 0.2)',
    color: '#8b5cf6',
    flexShrink: 0,
  },
  messageContent: {
    maxWidth: '80%',
    padding: '12px 16px',
    borderRadius: '12px',
    background: 'rgba(255,255,255,0.05)',
  },
  messageLine: {
    margin: '0 0 8px 0',
    fontSize: '13px',
    lineHeight: '1.5',
    color: 'var(--text-primary, #f0f6fc)',
  },
  loadingMessage: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '12px',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
  },
  inputArea: {
    display: 'flex',
    gap: '8px',
    padding: '16px',
    borderTop: '1px solid var(--border-color, #334155)',
  },
  input: {
    flex: 1,
    padding: '12px 16px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '8px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
  },
  sendButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '44px',
    height: '44px',
    border: 'none',
    borderRadius: '8px',
    background: 'linear-gradient(135deg, #8b5cf6, #7c3aed)',
    color: 'white',
    cursor: 'pointer',
  },
};

export default RiggsAssistant;
