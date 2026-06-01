/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

/**
 * Investigation Chat Component
 *
 * Real-time chat interface for investigations with WebSocket support.
 * Supports:
 * - Human analyst messages
 * - AI agent messages (T1, T2, T3)
 * - System notifications
 * - Typing indicators
 * - Message types (text, findings, recommendations, actions)
 * - AI speculation markers (visual distinction for uncertain statements)
 * - Typewriter mode for AI responses (progressive text reveal)
 */

// ── Typewriter Text Component ──
// Progressively reveals text word-by-word for a natural chat feel.
// Click anywhere on the text to skip to full reveal.
function TypewriterText({ text, speed = 30, onComplete, onTick, renderMarkdown, children }) {
  const [displayedCount, setDisplayedCount] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const words = useMemo(() => text.split(/(\s+)/), [text]); // Split preserving whitespace
  const totalParts = words.length;
  const intervalRef = useRef(null);
  const tickCountRef = useRef(0);

  useEffect(() => {
    if (isComplete) return;
    intervalRef.current = setInterval(() => {
      setDisplayedCount(prev => {
        const next = prev + 1;
        // Auto-scroll every ~8 words during reveal
        tickCountRef.current++;
        if (tickCountRef.current % 8 === 0) onTick?.();
        if (next >= totalParts) {
          clearInterval(intervalRef.current);
          setIsComplete(true);
          onComplete?.();
          return totalParts;
        }
        return next;
      });
    }, 1000 / speed);

    return () => clearInterval(intervalRef.current);
  }, [totalParts, speed, isComplete, onComplete, onTick]);

  const skipToEnd = useCallback(() => {
    clearInterval(intervalRef.current);
    setDisplayedCount(totalParts);
    setIsComplete(true);
    onComplete?.();
  }, [totalParts, onComplete]);

  const partialText = words.slice(0, displayedCount).join('');

  return (
    <div onClick={skipToEnd} style={{ cursor: isComplete ? 'default' : 'pointer' }}>
      {renderMarkdown ? renderMarkdown(partialText) : <span>{partialText}</span>}
      {!isComplete && (
        <span style={{
          display: 'inline-block',
          width: '2px',
          height: '1em',
          background: '#3CB371',
          marginLeft: '1px',
          animation: 'blink 0.8s step-end infinite',
          verticalAlign: 'text-bottom'
        }} />
      )}
    </div>
  );
}

// Speculation patterns - words that indicate AI uncertainty
const SPECULATION_PATTERNS = [
  'likely', 'possibly', 'may ', 'might', 'could be', 'suggests',
  'appears to', 'seems', 'probably', 'uncertain', 'unclear',
  'potentially', 'I believe', 'I think', 'it\'s possible',
  'indicative of', 'consistent with', 'typically', 'often'
];

// Factual patterns - words that indicate confirmed facts
const FACTUAL_PATTERNS = [
  'confirmed', 'verified', 'detected', 'observed', 'recorded',
  'found', 'identified', 'logged', 'established', 'known'
];

/**
 * Analyzes message content for speculation vs factual statements
 * Returns: { hasSpeculation: boolean, speculationLevel: 'low'|'medium'|'high' }
 */
function analyzeSpeculation(text) {
  if (!text || typeof text !== 'string') return { hasSpeculation: false, speculationLevel: 'low' };

  const lowerText = text.toLowerCase();
  let speculationCount = 0;
  let factualCount = 0;

  SPECULATION_PATTERNS.forEach(pattern => {
    if (lowerText.includes(pattern.toLowerCase())) {
      speculationCount++;
    }
  });

  FACTUAL_PATTERNS.forEach(pattern => {
    if (lowerText.includes(pattern.toLowerCase())) {
      factualCount++;
    }
  });

  const hasSpeculation = speculationCount > 0;
  let speculationLevel = 'low';

  if (speculationCount >= 3 || (speculationCount > factualCount && speculationCount >= 2)) {
    speculationLevel = 'high';
  } else if (speculationCount >= 1) {
    speculationLevel = 'medium';
  }

  return { hasSpeculation, speculationLevel, speculationCount, factualCount };
}
// Quick action shortcuts for common agent requests
const QUICK_ACTIONS = [
  {
    category: 'Analysis',
    icon: '🔍',
    actions: [
      { label: 'Summarize findings', prompt: 'Please summarize the key findings from this investigation so far.' },
      { label: 'Analyze IOCs', prompt: 'Analyze all IOCs in this investigation and provide your assessment of their risk level.' },
      { label: 'Check for patterns', prompt: 'Are there any patterns or correlations between the indicators in this investigation?' },
      { label: 'Timeline analysis', prompt: 'Create a timeline of events based on the evidence in this investigation.' },
    ]
  },
  {
    category: 'Enrichment',
    icon: '📊',
    actions: [
      { label: 'Enrich all IOCs', prompt: 'Please enrich all IOCs in this investigation with threat intelligence data.' },
      { label: 'Check reputation', prompt: 'What is the reputation of the primary indicators in this investigation?' },
      { label: 'Find related IOCs', prompt: 'Are there any related IOCs or infrastructure connected to the indicators in this case?' },
      { label: 'OSINT lookup', prompt: 'Perform OSINT lookups on the key indicators and report your findings.' },
    ]
  },
  {
    category: 'Response',
    icon: '🛡️',
    actions: [
      { label: 'Recommend actions', prompt: 'Based on your analysis, what response actions do you recommend for this investigation?' },
      { label: 'Containment options', prompt: 'What containment options are available for the affected systems or accounts?' },
      { label: 'Block indicators', prompt: 'Should we block any of the malicious indicators? Please specify which ones and why.' },
      { label: 'Escalation needed?', prompt: 'Does this investigation require escalation? If so, to what tier and why?' },
    ]
  },
  {
    category: 'Documentation',
    icon: '📝',
    actions: [
      { label: 'Draft executive summary', prompt: 'Please draft an executive summary for this investigation suitable for management review.' },
      { label: 'List next steps', prompt: 'What are the recommended next steps for this investigation?' },
      { label: 'Create incident report', prompt: 'Generate a formal incident report based on the investigation findings.' },
      { label: 'Update disposition', prompt: 'Based on the evidence, what should the disposition of this investigation be and why?' },
    ]
  }
];

function InvestigationChat({ investigationId, isOpen = true, onToggle, embedded = false, pendingMessage, onPromptConsumed }) {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [waitingForRiggs, setWaitingForRiggs] = useState(false);
  const [connected, setConnected] = useState(false);
  const [typingUsers, setTypingUsers] = useState([]);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [error, setError] = useState(null);
  const [messageCount, setMessageCount] = useState(0);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [chatMode, setChatMode] = useState(() => localStorage.getItem('t1_chat_mode') || 'typewriter');
  const newMessageIdsRef = useRef(new Set()); // Track IDs of messages received via WebSocket (not history)
  const historyLoadedRef = useRef(false);

  const wsRef = useRef(null);
  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const inputRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const userScrolledUpRef = useRef(false);
  const isConnectingRef = useRef(false);  // Prevent multiple simultaneous connections
  const mountedRef = useRef(true);  // Track if component is mounted

  const username = localStorage.getItem('username') || 'analyst';

  // Handle pending message from V3 workbench card actions
  useEffect(() => {
    if (pendingMessage && typeof pendingMessage === 'string') {
      setNewMessage(pendingMessage);
      if (onPromptConsumed) onPromptConsumed();
      // Focus the input after a tick so the user can see and send the prompt
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [pendingMessage, onPromptConsumed]);

  // Fetch message count on mount (even when chat is collapsed, so badge works)
  useEffect(() => {
    if (!investigationId) return;
    const fetchCount = async () => {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/chat/investigations/${investigationId}/stats`,
          { headers: getAuthHeaders(), credentials: 'include' }
        );
        if (response.ok) {
          const data = await response.json();
          setMessageCount(data.total_messages || 0);
        }
      } catch (err) {
        // Silently fail — count is cosmetic
      }
    };
    fetchCount();
  }, [investigationId]);

  // Keep messageCount in sync with messages array when chat is open
  useEffect(() => {
    if (messages.length > 0) {
      setMessageCount(messages.length);
    }
  }, [messages.length]);

  // Persist chat mode preference
  const toggleChatMode = useCallback(() => {
    setChatMode(prev => {
      const next = prev === 'typewriter' ? 'instant' : 'typewriter';
      localStorage.setItem('t1_chat_mode', next);
      return next;
    });
  }, []);

  // Check if user is near the bottom of the chat
  const isNearBottom = useCallback(() => {
    const container = messagesContainerRef.current;
    if (!container) return true;
    const threshold = 150; // pixels from bottom
    return container.scrollHeight - container.scrollTop - container.clientHeight < threshold;
  }, []);

  // Scroll to bottom of messages (only if user hasn't scrolled up)
  const scrollToBottom = useCallback((force = false) => {
    if (force || !userScrolledUpRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);

  // Handle scroll events to detect when user scrolls up
  const handleScroll = useCallback(() => {
    userScrolledUpRef.current = !isNearBottom();
  }, [isNearBottom]);

  // Connect to WebSocket
  const connectWebSocket = useCallback(() => {
    if (!investigationId || !isOpen) return;

    // Prevent multiple simultaneous connection attempts
    if (isConnectingRef.current) {
      return;
    }

    // Don't reconnect if already connected
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    isConnectingRef.current = true;

    // Close existing connection if in a bad state
    if (wsRef.current && wsRef.current.readyState !== WebSocket.CLOSED) {
      wsRef.current.close();
      wsRef.current = null;
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${wsProtocol}://${window.location.host}/ws/chat/${investigationId}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) {
          ws.close();
          return;
        }
        isConnectingRef.current = false;
        setConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;

        // Request chat history
        ws.send(JSON.stringify({ type: 'get_history', limit: 50 }));
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          handleWebSocketMessage(data);
        } catch (e) {
        }
      };

      ws.onclose = (event) => {
        isConnectingRef.current = false;

        if (!mountedRef.current) return;

        setConnected(false);

        // Only attempt reconnect if component is still mounted and open
        // and this wasn't a normal closure (1000) or going away (1001)
        if (mountedRef.current && isOpen &&
            reconnectAttemptsRef.current < 5 &&
            event.code !== 1000 && event.code !== 1001) {
          reconnectAttemptsRef.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectTimeoutRef.current = setTimeout(connectWebSocket, delay);
        }
      };

      ws.onerror = (error) => {
        isConnectingRef.current = false;
        if (mountedRef.current) {
          setError('Connection error');
        }
      };

    } catch (e) {
      isConnectingRef.current = false;
      setError('Failed to connect');
    }
  }, [investigationId, isOpen]);

  // Handle incoming WebSocket messages
  const handleWebSocketMessage = useCallback((data) => {
    switch (data.type) {
      case 'chat_history':
        setMessages(data.messages || []);
        setLoading(false);
        historyLoadedRef.current = true;
        // Force scroll on initial load
        userScrolledUpRef.current = false;
        setTimeout(() => scrollToBottom(true), 100);
        break;

      case 'new_message':
        // Track this as a "new" message (not from history) for typewriter effect
        if (historyLoadedRef.current && data.message?.id) {
          newMessageIdsRef.current.add(data.message.id);
        }
        // Avoid duplicate messages - check if message already exists by id
        setMessages(prev => {
          const exists = prev.some(m => m.id === data.message.id);
          if (exists) return prev;
          return [...prev, data.message];
        });
        setTimeout(scrollToBottom, 100);

        // Clear "Riggs is thinking" when agent responds
        if (data.message.sender_type?.startsWith('agent')) {
          setWaitingForRiggs(false);
        }

        // Remove typing indicator for sender
        if (data.message.sender_id) {
          setTypingUsers(prev => prev.filter(u => u.user_id !== data.message.sender_id));
        }
        break;

      case 'message_updated':
        setMessages(prev => prev.map(m =>
          m.id === data.message.id ? data.message : m
        ));
        break;

      case 'message_deleted':
        setMessages(prev => prev.filter(m => m.id !== data.message_id));
        break;

      case 'typing_indicator':
      case 'typing_update':
        if (data.is_typing && data.user_id !== username) {
          setTypingUsers(prev => {
            const exists = prev.find(u => u.user_id === data.user_id);
            if (exists) return prev;
            return [...prev, {
              user_id: data.user_id,
              username: data.username || data.user_name,
              is_agent: data.is_agent
            }];
          });
        } else {
          setTypingUsers(prev => prev.filter(u => u.user_id !== data.user_id));
        }
        break;

      case 'user_joined':
        setOnlineUsers(prev => {
          const exists = prev.find(u => u.user_id === data.user_id);
          if (exists) return prev;
          return [...prev, { user_id: data.user_id, username: data.username }];
        });
        break;

      case 'user_left':
        setOnlineUsers(prev => prev.filter(u => u.user_id !== data.user_id));
        setTypingUsers(prev => prev.filter(u => u.user_id !== data.user_id));
        break;

      case 'users_list':
        setOnlineUsers(data.users || []);
        break;

      case 'pong':
        // Heartbeat acknowledged
        break;

      case 'error':
        break;

      default:
    }
  }, [username, scrollToBottom]);

  // Track which quick action was used (for analytics)
  const [pendingQuickAction, setPendingQuickAction] = useState(null);

  // Handle quick action selection
  const handleQuickAction = useCallback((prompt, category, label) => {
    setNewMessage(prompt);
    setPendingQuickAction({ category, label });
    setShowShortcuts(false);
    inputRef.current?.focus();
  }, []);

  // Send message via WebSocket
  const sendMessage = useCallback(async (e) => {
    e?.preventDefault();

    if (!newMessage.trim() || !connected) return;

    setSending(true);

    try {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        // Build message payload with analytics metadata if from quick action
        const payload = {
          type: 'chat_message',
          message: newMessage.trim()
        };

        if (pendingQuickAction) {
          payload.metadata = {
            quick_action: true,
            quick_action_category: pendingQuickAction.category,
            quick_action_label: pendingQuickAction.label
          };
        }

        wsRef.current.send(JSON.stringify(payload));
        setNewMessage('');
        setPendingQuickAction(null);
        setWaitingForRiggs(true);

        // Clear typing indicator
        wsRef.current.send(JSON.stringify({ type: 'typing_stop' }));
      } else {
        // Fallback to REST API
        const response = await fetch(
          `${API_BASE_URL}/api/v1/chat/investigations/${investigationId}/messages`,
          {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ message: newMessage.trim() })
          }
        );

        if (response.ok) {
          const msg = await response.json();
          setMessages(prev => [...prev, msg]);
          setNewMessage('');
          setTimeout(scrollToBottom, 100);
        }
      }
    } catch (err) {
    } finally {
      setSending(false);
    }
  }, [newMessage, connected, investigationId, scrollToBottom]);

  // Handle input change with typing indicator
  const handleInputChange = useCallback((e) => {
    setNewMessage(e.target.value);

    // Send typing indicator
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'typing_start' }));

      // Clear after 3 seconds of no typing
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
      typingTimeoutRef.current = setTimeout(() => {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'typing_stop' }));
        }
      }, 3000);
    }
  }, []);

  // Track mounted state
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Connect on mount or when investigationId/isOpen changes
  useEffect(() => {
    if (isOpen && investigationId) {
      // Small delay to let React finish rendering
      const connectTimer = setTimeout(() => {
        if (mountedRef.current) {
          connectWebSocket();
        }
      }, 100);

      return () => {
        clearTimeout(connectTimer);
      };
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId, isOpen]);

  // Cleanup on unmount only
  useEffect(() => {
    return () => {
      // Only close on actual unmount
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmounting');
        wsRef.current = null;
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, []);

  // Load messages via REST if WebSocket fails
  useEffect(() => {
    if (!connected && isOpen && messages.length === 0) {
      const fetchMessages = async () => {
        try {
          const response = await fetch(
            `${API_BASE_URL}/api/v1/chat/investigations/${investigationId}/messages?limit=50`,
            { headers: getAuthHeaders() }
          );
          if (response.ok) {
            const data = await response.json();
            setMessages(data.messages || []);
            setLoading(false);
          }
        } catch (err) {
          setLoading(false);
        }
      };

      const timer = setTimeout(fetchMessages, 2000);
      return () => clearTimeout(timer);
    }
  }, [connected, isOpen, investigationId, messages.length]);

  // Get sender display info
  const getSenderInfo = (msg) => {
    const icons = {
      human: null,
      agent_t1: { icon: 'R', color: '#3b82f6', name: 'Riggs' },
      agent_t2: { icon: 'R', color: '#3CB371', name: 'Riggs' },
      agent_t3: { icon: 'R', color: '#ec4899', name: 'Riggs' },
      system: { icon: 'SYS', color: '#6b7280', name: 'System' },
      integration: { icon: 'INT', color: '#10b981', name: 'Integration' }
    };
    return icons[msg.sender_type] || null;
  };

  // Get message type styling
  const getMessageTypeStyle = (type) => {
    const styles = {
      finding: { border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.1)', label: 'Finding' },
      recommendation: { border: '#3b82f6', bg: 'rgba(59, 130, 246, 0.1)', label: 'Recommendation' },
      action_request: { border: '#ef4444', bg: 'rgba(239, 68, 68, 0.1)', label: 'Action Request' },
      action_result: { border: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)', label: 'Action Result' },
      enrichment: { border: '#3CB371', bg: 'rgba(60, 179, 113, 0.1)', label: 'Enrichment' },
      question: { border: '#06b6d4', bg: 'rgba(6, 182, 212, 0.1)', label: 'Question' },
      error: { border: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', label: 'Error' }
    };
    return styles[type] || null;
  };

  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();

    if (isToday) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
           date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Render a single message
  const renderMessage = (msg, index) => {
    const isOwnMessage = msg.sender_id === username;
    const senderInfo = getSenderInfo(msg);
    const typeStyle = getMessageTypeStyle(msg.message_type);
    const isAgent = msg.sender_type?.startsWith('agent_');
    const isSystem = msg.sender_type === 'system';

    // Analyze AI messages for speculation
    const speculation = isAgent ? analyzeSpeculation(msg.message) : { hasSpeculation: false };

    return (
      <div
        key={msg.id || index}
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: isOwnMessage ? 'flex-end' : 'flex-start',
          marginBottom: '0.75rem'
        }}
      >
        {/* Sender name (for non-own messages) */}
        {!isOwnMessage && !isSystem && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.25rem',
            marginLeft: '0.5rem'
          }}>
            {senderInfo && (
              <span style={{
                background: senderInfo.color,
                color: 'white',
                padding: '0.1rem 0.4rem',
                borderRadius: '4px',
                fontSize: '0.65rem',
                fontWeight: '600'
              }}>
                {senderInfo.icon}
              </span>
            )}
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              {typeof msg.sender_name === 'string' ? msg.sender_name : (typeof msg.sender_id === 'string' ? msg.sender_id : 'Unknown')}
            </span>
            {/* Speculation indicator for AI messages */}
            {isAgent && speculation.hasSpeculation && (
              <span
                title={`AI confidence indicator: ${speculation.speculationLevel} certainty (${speculation.speculationCount} speculative, ${speculation.factualCount} factual statements)`}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                  padding: '0.1rem 0.4rem',
                  borderRadius: '4px',
                  fontSize: '0.6rem',
                  fontWeight: '500',
                  background: speculation.speculationLevel === 'high'
                    ? 'rgba(234, 179, 8, 0.15)'
                    : speculation.speculationLevel === 'medium'
                      ? 'rgba(234, 179, 8, 0.1)'
                      : 'rgba(107, 114, 128, 0.1)',
                  color: speculation.speculationLevel === 'high'
                    ? '#eab308'
                    : speculation.speculationLevel === 'medium'
                      ? '#d97706'
                      : 'var(--text-secondary)',
                  border: speculation.speculationLevel === 'high'
                    ? '1px solid rgba(234, 179, 8, 0.3)'
                    : '1px solid transparent'
                }}>
                {speculation.speculationLevel === 'high' ? '⚠' : 'ℹ'}
                <span>{speculation.speculationLevel === 'high' ? 'Speculative' : 'Contains Assumptions'}</span>
              </span>
            )}
          </div>
        )}

        {/* Message bubble */}
        <div style={{
          maxWidth: '80%',
          padding: typeStyle ? '0.75rem' : '0.6rem 0.9rem',
          borderRadius: isOwnMessage ? '12px 12px 4px 12px' : '12px 12px 12px 4px',
          background: isOwnMessage
            ? 'linear-gradient(135deg, #3CB371, #5a67d8)'
            : isSystem
              ? 'rgba(107, 114, 128, 0.2)'
              : typeStyle?.bg || 'var(--bg-tertiary)',
          border: typeStyle ? `1px solid ${typeStyle.border}40` : 'none',
          color: isOwnMessage ? 'white' : 'var(--text-primary)'
        }}>
          {/* Type label */}
          {typeStyle && (
            <div style={{
              fontSize: '0.65rem',
              fontWeight: '600',
              color: typeStyle.border,
              marginBottom: '0.4rem',
              textTransform: 'uppercase',
              letterSpacing: '0.5px'
            }}>
              {typeStyle.label}
            </div>
          )}

          {/* Message content */}
          {(() => {
            // Safely coerce message to string (guards against objects causing React error #300)
            const msgText = typeof msg.message === 'string' ? msg.message
              : (msg.message != null ? JSON.stringify(msg.message) : '');

            const shouldTypewrite = isAgent
              && chatMode === 'typewriter'
              && newMessageIdsRef.current.has(msg.id);

            const markdownComponents = {
              p: ({children}) => <p style={{ margin: '0 0 0.75rem 0' }}>{children}</p>,
              ul: ({children}) => <ul style={{ margin: '0.5rem 0', paddingLeft: '1.5rem', listStyleType: 'disc' }}>{children}</ul>,
              ol: ({children}) => <ol style={{ margin: '0.5rem 0', paddingLeft: '1.5rem', listStyleType: 'decimal' }}>{children}</ol>,
              li: ({children}) => <li style={{ marginBottom: '0.35rem', paddingLeft: '0.25rem' }}>{children}</li>,
              code: ({inline, className, children}) => {
                if (inline) {
                  return <code style={{ background: 'rgba(0,0,0,0.3)', padding: '0.15rem 0.4rem', borderRadius: '4px', fontSize: '0.8rem', fontFamily: 'monospace' }}>{children}</code>;
                }
                return (
                  <pre style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px', overflow: 'auto', fontSize: '0.8rem', margin: '0.5rem 0', fontFamily: 'monospace' }}>
                    <code>{children}</code>
                  </pre>
                );
              },
              strong: ({children}) => <strong style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{children}</strong>,
              em: ({children}) => <em style={{ fontStyle: 'italic', opacity: 0.9 }}>{children}</em>,
              h1: ({children}) => <h4 style={{ margin: '1rem 0 0.5rem', fontWeight: '600', fontSize: '1rem' }}>{children}</h4>,
              h2: ({children}) => <h4 style={{ margin: '1rem 0 0.5rem', fontWeight: '600', fontSize: '0.95rem' }}>{children}</h4>,
              h3: ({children}) => <h5 style={{ margin: '0.75rem 0 0.35rem', fontWeight: '600', fontSize: '0.9rem' }}>{children}</h5>,
              h4: ({children}) => <h6 style={{ margin: '0.5rem 0 0.25rem', fontWeight: '600', fontSize: '0.85rem' }}>{children}</h6>,
              blockquote: ({children}) => <blockquote style={{ borderLeft: '3px solid var(--primary)', paddingLeft: '0.75rem', margin: '0.5rem 0', opacity: 0.85 }}>{children}</blockquote>,
              a: ({href, children}) => <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline' }}>{children}</a>,
            };

            const renderMd = (text) => (
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                {typeof text === 'string' ? text : String(text || '')}
              </ReactMarkdown>
            );

            if (isAgent || msg.message_type !== 'text') {
              return (
                <div
                  className="chat-markdown"
                  style={{
                    fontSize: '0.85rem',
                    lineHeight: '1.6',
                    wordBreak: 'break-word'
                  }}
                >
                  {shouldTypewrite ? (
                    <TypewriterText
                      text={msgText}
                      speed={35}
                      renderMarkdown={renderMd}
                      onTick={() => scrollToBottom()}
                      onComplete={() => {
                        newMessageIdsRef.current.delete(msg.id);
                        scrollToBottom();
                      }}
                    />
                  ) : (
                    renderMd(msgText)
                  )}
                </div>
              );
            }
            return (
              <div style={{
                fontSize: '0.85rem',
                lineHeight: '1.5',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}>
                {msgText}
              </div>
            );
          })()}

          {/* Metadata for special message types */}
          {msg.metadata && msg.message_type === 'action_request' && (
            <div style={{
              marginTop: '0.5rem',
              padding: '0.5rem',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: '6px',
              fontSize: '0.75rem'
            }}>
              <div><strong>Action:</strong> {typeof msg.metadata.action_type === 'string' ? msg.metadata.action_type.replace(/_/g, ' ') : String(msg.metadata.action_type || '')}</div>
              <div><strong>Target:</strong> <code>{typeof msg.metadata.target === 'string' ? msg.metadata.target : JSON.stringify(msg.metadata.target || '')}</code></div>
              {msg.metadata.confidence != null && typeof msg.metadata.confidence === 'number' && (
                <div><strong>Confidence:</strong> {(msg.metadata.confidence * 100).toFixed(0)}%</div>
              )}
            </div>
          )}
        </div>

        {/* Timestamp */}
        <div style={{
          fontSize: '0.65rem',
          color: 'var(--text-tertiary)',
          marginTop: '0.2rem',
          marginRight: isOwnMessage ? 0 : 'auto',
          marginLeft: isOwnMessage ? 'auto' : '0.5rem'
        }}>
          {formatTime(msg.created_at)}
        </div>
      </div>
    );
  };

  if (!isOpen) {
    return (
      <button
        onClick={onToggle}
        style={{
          position: 'fixed',
          bottom: '1.5rem',
          right: '1.5rem',
          width: '50px',
          height: '50px',
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #3CB371, #5a67d8)',
          border: 'none',
          color: 'white',
          fontSize: '1.25rem',
          cursor: 'pointer',
          boxShadow: '0 4px 20px rgba(60, 179, 113, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        </svg>
        {/* Message count badge */}
        {messageCount > 0 && (
          <span style={{
            position: 'absolute',
            top: '-4px',
            right: '-4px',
            background: '#ef4444',
            color: 'white',
            fontSize: '0.65rem',
            fontWeight: '600',
            minWidth: '18px',
            height: '18px',
            borderRadius: '9px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0 4px',
            boxShadow: '0 2px 4px rgba(0,0,0,0.3)'
          }}>
            {messageCount > 99 ? '99+' : messageCount}
          </span>
        )}
      </button>
    );
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      maxHeight: '100%',
      minHeight: 0,
      background: embedded ? 'transparent' : 'var(--bg-secondary)',
      borderRadius: embedded ? 0 : '12px',
      border: embedded ? 'none' : '1px solid rgba(255, 255, 255, 0.05)',
      overflow: 'hidden'
    }}>
      {/* Header - hidden when embedded (slide-out panel has its own header) */}
      {!embedded && (
        <div style={{
          padding: '0.75rem 1rem',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'var(--bg-tertiary)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1rem' }}>Investigation Chat</span>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: connected ? '#22c55e' : '#ef4444'
            }} />
            {onlineUsers.length > 0 && (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                {onlineUsers.length} online
              </span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={toggleChatMode}
              title={chatMode === 'typewriter' ? 'Typewriter mode (click for instant)' : 'Instant mode (click for typewriter)'}
              style={{
                background: 'none',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '4px',
                padding: '0.2rem 0.5rem',
                cursor: 'pointer',
                fontSize: '0.7rem',
                color: chatMode === 'typewriter' ? '#3CB371' : 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                transition: 'all 0.2s'
              }}
            >
              {chatMode === 'typewriter' ? (
                <><span style={{ fontSize: '0.75rem' }}>&#9998;</span> Live</>
              ) : (
                <><span style={{ fontSize: '0.75rem' }}>&#9889;</span> Instant</>
              )}
            </button>
            {onToggle && (
              <button
                onClick={onToggle}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  padding: '0.25rem',
                  fontSize: '1.25rem'
                }}
              >
                x
              </button>
            )}
          </div>
        </div>
      )}

      {/* Connection status indicator for embedded mode */}
      {embedded && (
        <div style={{
          padding: '0.4rem 1rem',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.7rem',
          color: 'var(--text-secondary)'
        }}>
          <span style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            background: connected ? '#22c55e' : '#ef4444'
          }} />
          {connected ? 'Connected' : 'Connecting...'}
          <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {onlineUsers.length > 0 && (
              <span>{onlineUsers.length} online</span>
            )}
            <button
              onClick={toggleChatMode}
              title={chatMode === 'typewriter' ? 'Typewriter mode (click for instant)' : 'Instant mode (click for typewriter)'}
              style={{
                background: 'none',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '4px',
                padding: '0.15rem 0.4rem',
                cursor: 'pointer',
                fontSize: '0.65rem',
                color: chatMode === 'typewriter' ? '#3CB371' : 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                transition: 'all 0.2s'
              }}
            >
              {chatMode === 'typewriter' ? (
                <><span style={{ fontSize: '0.7rem' }}>&#9998;</span> Live</>
              ) : (
                <><span style={{ fontSize: '0.7rem' }}>&#9889;</span> Instant</>
              )}
            </button>
          </span>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div style={{
          padding: '0.5rem 1rem',
          background: 'rgba(239, 68, 68, 0.1)',
          borderBottom: '1px solid rgba(239, 68, 68, 0.2)',
          fontSize: '0.8rem',
          color: '#ef4444',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{error}</span>
          <button
            onClick={connectWebSocket}
            style={{
              background: 'rgba(239, 68, 68, 0.2)',
              border: 'none',
              borderRadius: '4px',
              padding: '0.25rem 0.5rem',
              color: '#ef4444',
              cursor: 'pointer',
              fontSize: '0.75rem'
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Messages area */}
      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        style={{
          flex: '1 1 0',
          minHeight: 0,
          overflowY: 'auto',
          padding: '1rem',
          display: 'flex',
          flexDirection: 'column'
        }}
      >
        {loading ? (
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem' }}></div>
            Loading messages...
          </div>
        ) : messages.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
              Hey {username}!
            </div>
            <p style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
              I'm <strong>Riggs</strong>, your investigation partner. What are we looking at?
            </p>
            <p style={{ fontSize: '0.75rem', opacity: 0.7 }}>
              Ask me to analyze IOCs, summarize findings, or recommend next steps.
            </p>
          </div>
        ) : (
          messages.map((msg, idx) => renderMessage(msg, idx))
        )}

        {/* Riggs thinking indicator - iMessage style bubble */}
        {waitingForRiggs && (
          <div style={{
            alignSelf: 'flex-start',
            maxWidth: '85%',
            marginTop: '0.25rem'
          }}>
            <div style={{
              fontSize: '0.6rem',
              color: 'var(--text-muted)',
              marginBottom: '0.2rem',
              fontWeight: '600'
            }}>
              <span style={{ color: '#3CB371' }}>Riggs</span>
            </div>
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.6rem 1rem',
              background: 'rgba(60, 179, 113, 0.08)',
              borderRadius: '4px 12px 12px 12px',
              borderLeft: '2px solid #3CB371'
            }}>
              <div style={{ display: 'flex', gap: '3px', alignItems: 'center' }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3CB371', animation: 'riggsThink 1.4s infinite', animationDelay: '0s' }} />
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3CB371', animation: 'riggsThink 1.4s infinite', animationDelay: '0.2s' }} />
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3CB371', animation: 'riggsThink 1.4s infinite', animationDelay: '0.4s' }} />
              </div>
            </div>
          </div>
        )}

        {/* Other users typing */}
        {typingUsers.length > 0 && (
          <div style={{
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            fontStyle: 'italic',
            marginTop: '0.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            {typingUsers.map(u => u.username || u.user_id).join(', ')} {typingUsers.length === 1 ? 'is' : 'are'} typing
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions Panel */}
      {showShortcuts && (
        <div style={{
          borderTop: '1px solid rgba(255, 255, 255, 0.05)',
          background: 'var(--bg-tertiary)',
          maxHeight: '300px',
          overflowY: 'auto'
        }}>
          <div style={{
            padding: '0.5rem 1rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: '1px solid rgba(255, 255, 255, 0.05)'
          }}>
            <span style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-primary)' }}>
              Quick Actions
            </span>
            <button
              onClick={() => setShowShortcuts(false)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '1rem',
                padding: '0.25rem'
              }}
            >
              x
            </button>
          </div>
          <div style={{ padding: '0.5rem' }}>
            {QUICK_ACTIONS.map((category, catIdx) => (
              <div key={catIdx} style={{ marginBottom: '0.75rem' }}>
                <div style={{
                  fontSize: '0.7rem',
                  fontWeight: '600',
                  color: 'var(--text-secondary)',
                  marginBottom: '0.4rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem'
                }}>
                  <span>{category.icon}</span>
                  <span>{category.category}</span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                  {category.actions.map((action, actIdx) => (
                    <button
                      key={actIdx}
                      onClick={() => handleQuickAction(action.prompt, category.category, action.label)}
                      style={{
                        padding: '0.35rem 0.6rem',
                        background: 'var(--bg-secondary)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: '12px',
                        color: 'var(--text-primary)',
                        fontSize: '0.7rem',
                        cursor: 'pointer',
                        transition: 'all 0.15s'
                      }}
                      onMouseEnter={(e) => {
                        e.target.style.background = 'rgba(60, 179, 113, 0.2)';
                        e.target.style.borderColor = 'rgba(60, 179, 113, 0.4)';
                      }}
                      onMouseLeave={(e) => {
                        e.target.style.background = 'var(--bg-secondary)';
                        e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                      }}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input area */}
      <form onSubmit={sendMessage} style={{
        padding: '0.75rem 1rem',
        borderTop: '1px solid rgba(255, 255, 255, 0.05)',
        display: 'flex',
        gap: '0.5rem',
        background: 'var(--bg-tertiary)'
      }}>
        {/* Quick Actions Toggle Button */}
        <button
          type="button"
          onClick={() => setShowShortcuts(!showShortcuts)}
          disabled={!connected}
          style={{
            padding: '0.6rem',
            background: showShortcuts ? 'rgba(60, 179, 113, 0.2)' : 'var(--bg-secondary)',
            border: showShortcuts ? '1px solid rgba(60, 179, 113, 0.4)' : '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '50%',
            color: showShortcuts ? 'var(--primary)' : 'var(--text-secondary)',
            cursor: connected ? 'pointer' : 'not-allowed',
            fontSize: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '36px',
            height: '36px',
            flexShrink: 0,
            transition: 'all 0.2s'
          }}
          title="Quick Actions"
        >
          /
        </button>
        <textarea
          ref={inputRef}
          value={newMessage}
          onChange={handleInputChange}
          placeholder={connected ? "Type a message or use / for shortcuts..." : "Connecting..."}
          disabled={!connected || sending}
          rows={1}
          style={{
            flex: 1,
            padding: '0.6rem 1rem',
            background: 'var(--bg-secondary)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '20px',
            color: 'var(--text-primary)',
            fontSize: '0.85rem',
            outline: 'none',
            resize: 'none',
            overflow: 'hidden',
            lineHeight: '1.4',
            fontFamily: 'inherit',
            maxHeight: '120px',
          }}
          onFocus={(e) => e.target.style.borderColor = 'var(--primary)'}
          onBlur={(e) => e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)'}
          onKeyDown={(e) => {
            if (e.key === '/' && newMessage === '') {
              e.preventDefault();
              setShowShortcuts(true);
            }
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              sendMessage(e);
            }
          }}
          onInput={(e) => {
            e.target.style.height = 'auto';
            e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
            e.target.style.overflow = e.target.scrollHeight > 120 ? 'auto' : 'hidden';
          }}
        />
        <button
          type="submit"
          disabled={!newMessage.trim() || !connected || sending}
          style={{
            padding: '0.6rem 1rem',
            background: newMessage.trim() && connected
              ? 'linear-gradient(135deg, #3CB371, #5a67d8)'
              : 'var(--bg-tertiary)',
            border: 'none',
            borderRadius: '20px',
            color: newMessage.trim() && connected ? 'white' : 'var(--text-tertiary)',
            cursor: newMessage.trim() && connected ? 'pointer' : 'not-allowed',
            fontSize: '0.85rem',
            fontWeight: '500',
            transition: 'all 0.2s'
          }}
        >
          {sending ? '...' : 'Send'}
        </button>
      </form>

      <style>{`
        @keyframes typing {
          0%, 60%, 100% { opacity: 0.3; }
          30% { opacity: 1; }
        }
        @keyframes blink {
          50% { opacity: 0; }
        }
        @keyframes riggsThink {
          0%, 80%, 100% { opacity: 0.2; transform: scale(0.8); }
          40% { opacity: 1; transform: scale(1); }
        }
        .chat-markdown p:last-child {
          margin-bottom: 0;
        }
        .chat-markdown ul:last-child,
        .chat-markdown ol:last-child {
          margin-bottom: 0;
        }
      `}</style>
    </div>
  );
}

export default InvestigationChat;
