/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useMemo } from 'react';

// =============================================================================
// CONFIGURATION
// =============================================================================

const categoryConfig = {
  'Network': { color: '#3b82f6', icon: '🌐', gradient: 'linear-gradient(135deg, #3b82f6, #1d4ed8)' },
  'Process': { color: '#f59e0b', icon: '⚙️', gradient: 'linear-gradient(135deg, #f59e0b, #d97706)' },
  'URLs & Domains': { color: '#a855f7', icon: '🔗', gradient: 'linear-gradient(135deg, #a855f7, #2e8b57)' },
  'Identity': { color: '#22c55e', icon: '👤', gradient: 'linear-gradient(135deg, #22c55e, #16a34a)' },
  'Email': { color: '#ec4899', icon: '📧', gradient: 'linear-gradient(135deg, #ec4899, #db2777)' },
  'File': { color: '#06b6d4', icon: '📄', gradient: 'linear-gradient(135deg, #06b6d4, #0891b2)' },
  'Other': { color: '#6b7280', icon: '📋', gradient: 'linear-gradient(135deg, #6b7280, #4b5563)' }
};

const severityConfig = {
  critical: { bg: '#dc262640', border: '#dc2626', text: '#f87171', label: 'Critical' },
  high: { bg: '#ea580c40', border: '#ea580c', text: '#fb923c', label: 'High' },
  medium: { bg: '#eab30840', border: '#eab308', text: '#facc15', label: 'Medium' },
  low: { bg: '#22c55e40', border: '#22c55e', text: '#4ade80', label: 'Low' },
  unknown: { bg: 'transparent', border: 'transparent', text: 'transparent', label: '' }
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

const getRiskLevel = (ioc) => {
  const value = (ioc.value || '').toLowerCase();
  const type = (ioc.type || '').toLowerCase();
  
  if (ioc.severity === 'critical' || ioc.risk === 'critical') return 'critical';
  if (ioc.severity === 'high' || ioc.risk === 'high') return 'high';
  if (ioc.malicious || ioc.threatIntel?.malicious) return 'critical';
  if (value.includes('tor') || value.includes('onion')) return 'high';
  
  if (type === 'privileged' && value === 'yes') return 'high';
  if (type === 'mfa used' && value === 'no') return 'medium';
  if (type === 'signed' && value === 'no') return 'medium';
  
  if (ioc.severity === 'medium' || ioc.risk === 'medium') return 'medium';
  if (ioc.suspicious || ioc.threatIntel?.suspicious) return 'medium';
  
  // External IPs get higher default risk
  if (type.includes('ip') && !isPrivateIP(value)) return 'high';
  
  return ioc.risk || 'unknown';
};

const isPrivateIP = (ip) => {
  if (!ip) return false;
  return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.');
};

const truncateValue = (value, maxLength = 20) => {
  if (!value || value.length <= maxLength) return value;
  return value.substring(0, maxLength) + '...';
};

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const IOCPanel = ({ 
  iocs = [], 
  onEnrich, 
  onBlock,
  compact = false 
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState('All');
  const [copiedValue, setCopiedValue] = useState(null);

  const copyToClipboard = (value) => {
    navigator.clipboard.writeText(value);
    setCopiedValue(value);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Process and enrich IOCs
  const processedIOCs = useMemo(() => {
    return iocs.map(ioc => ({
      ...ioc,
      riskLevel: getRiskLevel(ioc),
      isPrivate: isPrivateIP(ioc.value)
    }));
  }, [iocs]);

  // Filter IOCs
  const filteredIOCs = useMemo(() => {
    let filtered = processedIOCs;
    
    if (activeFilter !== 'All') {
      filtered = filtered.filter(ioc => ioc.category === activeFilter);
    }
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(ioc => 
        (ioc.value || '').toLowerCase().includes(term) ||
        (ioc.type || '').toLowerCase().includes(term)
      );
    }
    
    return filtered;
  }, [processedIOCs, activeFilter, searchTerm]);

  // Group by category
  const groupedIOCs = useMemo(() => {
    const groups = {};
    
    // Separate identity-related items for special handling
    const identityItems = [];
    const emailItems = [];
    
    filteredIOCs.forEach(ioc => {
      const type = (ioc.type || '').toLowerCase();
      
      // Route to Identity card
      if (['username', 'display name', 'role', 'auth method', 'mfa used', 'privileged', 'user email'].includes(type)) {
        identityItems.push(ioc);
        return;
      }
      
      // Route to Email card
      if (['email', 'email sender', 'email recipient', 'email subject', 'has attachment'].includes(type)) {
        emailItems.push(ioc);
        return;
      }
      
      // Normal grouping
      const cat = ioc.category || 'Other';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(ioc);
    });
    
    // Add identity and email as special groups if they have items
    if (identityItems.length > 0) groups['Identity'] = identityItems;
    if (emailItems.length > 0) groups['Email'] = emailItems;
    
    return groups;
  }, [filteredIOCs]);

  // =============================================================================
  // RENDER FUNCTIONS
  // =============================================================================

  // Severity Badge
  const SeverityBadge = ({ level }) => {
    const config = severityConfig[level] || severityConfig.unknown;
    if (level === 'unknown' || level === 'low') return null;
    
    return (
      <span style={{
        padding: '0.15rem 0.5rem',
        borderRadius: 4,
        fontSize: '0.65rem',
        fontWeight: 600,
        textTransform: 'uppercase',
        background: config.bg,
        color: config.text,
        border: `1px solid ${config.border}`,
        whiteSpace: 'nowrap'
      }}>
        {config.label}
      </span>
    );
  };

  // Card Header
  const CardHeader = ({ category, count, onEnrichAll }) => {
    const config = categoryConfig[category] || categoryConfig.Other;
    
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '0.75rem 1rem',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        background: 'rgba(0,0,0,0.2)'
      }}>
        <span style={{
          width: 28,
          height: 28,
          borderRadius: 6,
          background: config.gradient,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '0.9rem',
          marginRight: '0.75rem'
        }}>
          {config.icon}
        </span>
        <span style={{ 
          fontWeight: 600, 
          fontSize: '0.95rem',
          color: 'var(--text-primary)'
        }}>
          {category}
        </span>
        <div style={{ flex: 1 }} />
        <button
          onClick={onEnrichAll}
          style={{
            padding: '0.3rem 0.6rem',
            borderRadius: 4,
            border: '1px solid rgba(59, 130, 246, 0.4)',
            background: 'rgba(59, 130, 246, 0.1)',
            color: '#60a5fa',
            fontSize: '0.7rem',
            cursor: 'pointer',
            marginRight: '0.5rem'
          }}
        >
          Enrich
        </button>
        <button style={{
          padding: '0.3rem 0.5rem',
          borderRadius: 4,
          border: '1px solid rgba(255,255,255,0.2)',
          background: 'transparent',
          color: 'var(--text-muted)',
          fontSize: '0.75rem',
          cursor: 'pointer'
        }}>
          ⋮
        </button>
      </div>
    );
  };

  // Network Card
  const NetworkCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <CardHeader category="Network" count={items.length} onEnrichAll={() => {}} />
        <div style={{ padding: '0.5rem' }}>
          {items.slice(0, compact ? 4 : undefined).map((ioc, idx) => (
            <div key={idx} style={{
              display: 'flex',
              alignItems: 'center',
              padding: '0.5rem 0.75rem',
              borderRadius: 6,
              marginBottom: '0.25rem',
              background: idx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent',
              gap: '0.75rem'
            }}>
              <span style={{ color: categoryConfig.Network.color, fontSize: '0.5rem' }}>●</span>
              <code style={{ 
                fontSize: '0.85rem', 
                color: '#e0f2fe',
                fontFamily: 'monospace',
                minWidth: 100
              }}>
                {ioc.value}
              </code>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>◇</span>
              <SeverityBadge level={ioc.riskLevel} />
              {ioc.isPrivate && (
                <span style={{
                  padding: '0.15rem 0.5rem',
                  borderRadius: 4,
                  fontSize: '0.65rem',
                  background: 'rgba(34, 197, 94, 0.15)',
                  color: '#4ade80',
                  border: '1px solid rgba(34, 197, 94, 0.3)'
                }}>
                  Internal Network | Private IP
                </span>
              )}
              <div style={{ flex: 1 }} />
              <span style={{
                padding: '0.15rem 0.4rem',
                borderRadius: 4,
                fontSize: '0.6rem',
                background: 'rgba(59, 130, 246, 0.15)',
                color: '#60a5fa',
                border: '1px solid rgba(59, 130, 246, 0.3)'
              }}>
                {ioc.type}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  // Process Card
  const ProcessCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <CardHeader category="Processes" count={items.length} onEnrichAll={() => {}} />
        <div style={{ padding: '0.5rem' }}>
          {items.slice(0, compact ? 4 : undefined).map((ioc, idx) => {
            const isProcess = (ioc.type || '').toLowerCase() === 'process';
            
            return (
              <div key={idx} style={{
                display: 'flex',
                alignItems: 'center',
                padding: '0.5rem 0.75rem',
                borderRadius: 6,
                marginBottom: '0.25rem',
                background: idx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent',
                gap: '0.75rem'
              }}>
                <span style={{ color: categoryConfig.Process.color, fontSize: '0.5rem' }}>●</span>
                <code style={{ 
                  fontSize: '0.85rem', 
                  color: '#fef3c7',
                  fontFamily: 'monospace',
                  fontWeight: isProcess ? 600 : 400
                }}>
                  {truncateValue(ioc.value, 25)}
                </code>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>◇</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {ioc.context || 'c:/windows/system32'}
                </span>
                <div style={{ flex: 1 }} />
                {isProcess && (
                  <>
                    <button
                      onClick={() => onEnrich && onEnrich(ioc)}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: 4,
                        border: '1px solid rgba(59, 130, 246, 0.4)',
                        background: 'rgba(59, 130, 246, 0.1)',
                        color: '#60a5fa',
                        fontSize: '0.65rem',
                        cursor: 'pointer'
                      }}
                    >
                      🔎 Enrich
                    </button>
                    <button
                      onClick={() => onBlock && onBlock(ioc)}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: 4,
                        border: '1px solid rgba(220, 38, 38, 0.4)',
                        background: 'rgba(220, 38, 38, 0.1)',
                        color: '#f87171',
                        fontSize: '0.65rem',
                        cursor: 'pointer'
                      }}
                    >
                      🚫 Block
                    </button>
                  </>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // URLs & Domains Card
  const DomainsCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <CardHeader category="URLs & Domains" count={items.length} onEnrichAll={() => {}} />
        <div style={{ padding: '0.5rem' }}>
          {items.slice(0, compact ? 4 : undefined).map((ioc, idx) => (
            <div key={idx} style={{
              display: 'flex',
              alignItems: 'center',
              padding: '0.5rem 0.75rem',
              borderRadius: 6,
              marginBottom: '0.25rem',
              background: idx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent',
              gap: '0.5rem'
            }}>
              <span style={{ color: categoryConfig['URLs & Domains'].color, fontSize: '0.5rem' }}>●</span>
              <code style={{ 
                fontSize: '0.8rem', 
                color: '#e9d5ff',
                fontFamily: 'monospace'
              }}>
                {truncateValue(ioc.value, 20)}
              </code>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>◇</span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', flex: 1 }}>
                {ioc.context || truncateValue(ioc.value, 30)}
              </span>
              <SeverityBadge level={ioc.riskLevel} />
              <button
                onClick={() => onEnrich && onEnrich(ioc)}
                style={{
                  padding: '0.2rem 0.5rem',
                  borderRadius: 4,
                  border: '1px solid rgba(59, 130, 246, 0.4)',
                  background: 'rgba(59, 130, 246, 0.1)',
                  color: '#60a5fa',
                  fontSize: '0.65rem',
                  cursor: 'pointer'
                }}
              >
                🔎 Enrich
              </button>
              <button
                onClick={() => onBlock && onBlock(ioc)}
                style={{
                  padding: '0.2rem 0.5rem',
                  borderRadius: 4,
                  border: '1px solid rgba(220, 38, 38, 0.4)',
                  background: 'rgba(220, 38, 38, 0.1)',
                  color: '#f87171',
                  fontSize: '0.65rem',
                  cursor: 'pointer'
                }}
              >
                🚫 Block
              </button>
            </div>
          ))}
        </div>
      </div>
    );
  };

  // Identity Card
  const IdentityCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    const userData = {};
    items.forEach(item => {
      userData[(item.type || '').toLowerCase()] = item.value;
    });

    const username = userData['username'];
    const displayName = userData['display name'];
    const role = userData['role'];
    const authMethod = userData['auth method'];
    const mfaUsed = userData['mfa used'];
    const privileged = userData['privileged'];
    const userEmail = userData['user email'];

    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <CardHeader category="Identity" count={items.length} onEnrichAll={() => {}} />
        <div style={{ padding: '1rem' }}>
          {/* User Profile */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
            <div style={{
              width: 48,
              height: 48,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #3b82f6, #3CB371)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.25rem',
              fontWeight: 600,
              color: 'white'
            }}>
              {(displayName || username || '?')[0].toUpperCase()}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: '1rem' }}>
                {displayName || username || 'Unknown User'}
              </div>
              {userEmail && (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  {userEmail}
                </div>
              )}
            </div>
            {mfaUsed && (
              <button style={{
                padding: '0.3rem 0.75rem',
                borderRadius: 6,
                border: `1px solid ${mfaUsed === 'Yes' ? 'rgba(34, 197, 94, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`,
                background: mfaUsed === 'Yes' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                color: mfaUsed === 'Yes' ? '#4ade80' : '#fbbf24',
                fontSize: '0.75rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}>
                {mfaUsed === 'Yes' ? '✓' : '⚠'} Setup MFA
              </button>
            )}
          </div>

          {/* Account Indicators */}
          <div style={{ 
            display: 'flex', 
            flexWrap: 'wrap',
            gap: '0.5rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid rgba(255,255,255,0.1)'
          }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: '0.5rem' }}>
              Account Indicators ▾
            </span>
            {privileged === 'Yes' && (
              <span style={{
                padding: '0.2rem 0.6rem',
                borderRadius: 12,
                fontSize: '0.7rem',
                background: 'rgba(220, 38, 38, 0.2)',
                color: '#f87171',
                border: '1px solid rgba(220, 38, 38, 0.3)'
              }}>
                Privileged
              </span>
            )}
            {role && (
              <span style={{
                padding: '0.2rem 0.6rem',
                borderRadius: 12,
                fontSize: '0.7rem',
                background: 'rgba(59, 130, 246, 0.2)',
                color: '#60a5fa',
                border: '1px solid rgba(59, 130, 246, 0.3)'
              }}>
                {role}
              </span>
            )}
            {authMethod && (
              <span style={{
                padding: '0.2rem 0.6rem',
                borderRadius: 12,
                fontSize: '0.7rem',
                background: 'rgba(139, 92, 246, 0.2)',
                color: '#5eead4',
                border: '1px solid rgba(139, 92, 246, 0.3)'
              }}>
                {authMethod}
              </span>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Email Card
  const EmailCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    const emailData = {};
    items.forEach(item => {
      emailData[(item.type || '').toLowerCase()] = item.value;
    });

    const sender = emailData['email sender'] || emailData['email'];
    const recipient = emailData['email recipient'];
    const subject = emailData['email subject'];
    const hasAttachment = emailData['has attachment'];

    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          padding: '0.75rem 1rem',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
          background: 'rgba(0,0,0,0.2)'
        }}>
          <span style={{
            width: 28,
            height: 28,
            borderRadius: 6,
            background: categoryConfig.Email.gradient,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.9rem',
            marginRight: '0.75rem'
          }}>
            📧
          </span>
          <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>Email Communication</span>
          <div style={{ flex: 1 }} />
          <button style={{
            padding: '0.3rem 0.75rem',
            borderRadius: 6,
            border: '1px solid rgba(139, 92, 246, 0.4)',
            background: 'rgba(139, 92, 246, 0.1)',
            color: '#5eead4',
            fontSize: '0.7rem',
            cursor: 'pointer'
          }}>
            Assign Incident
          </button>
        </div>
        
        <div style={{ padding: '1rem' }}>
          {/* Sender Profile */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
            <div style={{
              width: 48,
              height: 48,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #f59e0b, #ef4444)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.25rem',
              fontWeight: 600,
              color: 'white'
            }}>
              {(sender || '?')[0].toUpperCase()}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: '1rem' }}>
                {sender?.split('@')[0] || 'Unknown Sender'}
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {sender}
              </div>
            </div>
            <button style={{
              padding: '0.3rem 0.75rem',
              borderRadius: 6,
              border: '1px solid rgba(245, 158, 11, 0.4)',
              background: 'rgba(245, 158, 11, 0.1)',
              color: '#fbbf24',
              fontSize: '0.75rem',
              cursor: 'pointer'
            }}>
              Setup MFA →
            </button>
          </div>

          {/* Subject if present */}
          {subject && (
            <div style={{
              padding: '0.5rem 0.75rem',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: 6,
              marginBottom: '0.75rem',
              fontSize: '0.85rem'
            }}>
              <span style={{ color: 'var(--text-muted)', marginRight: '0.5rem' }}>Subject:</span>
              "{subject}"
            </div>
          )}

          {/* Attack Info */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: '1fr 1fr', 
            gap: '1rem',
            padding: '0.75rem',
            background: 'rgba(0,0,0,0.2)',
            borderRadius: 6,
            marginBottom: '0.75rem'
          }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Attacker</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 500, color: '#f87171' }}>Compromised Account</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Since 10 May</div>
            </div>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Detection</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 500 }}>New Suspicious Email</div>
              <div style={{ fontSize: '0.7rem', color: '#60a5fa', cursor: 'pointer' }}>Enrich</div>
            </div>
          </div>

          {/* Recipient */}
          {recipient && (
            <div style={{ 
              display: 'flex',
              alignItems: 'center',
              padding: '0.5rem 0.75rem',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: 6,
              gap: '0.5rem'
            }}>
              <span style={{ color: '#ec4899', fontSize: '0.5rem' }}>●</span>
              <code style={{ fontSize: '0.85rem', color: '#fbcfe8' }}>{recipient}</code>
              <div style={{ flex: 1 }} />
              <span style={{
                padding: '0.15rem 0.4rem',
                borderRadius: 4,
                fontSize: '0.6rem',
                background: 'rgba(236, 72, 153, 0.15)',
                color: '#f472b6'
              }}>
                Recipient
              </span>
              <button
                onClick={() => onEnrich && onEnrich({ type: 'email', value: recipient })}
                style={{
                  padding: '0.2rem 0.5rem',
                  borderRadius: 4,
                  border: '1px solid rgba(139, 92, 246, 0.4)',
                  background: 'rgba(139, 92, 246, 0.1)',
                  color: '#5eead4',
                  fontSize: '0.65rem',
                  cursor: 'pointer'
                }}
              >
                🔍 Assign Insert
              </button>
            </div>
          )}
        </div>
      </div>
    );
  };

  // File Card
  const FileCard = ({ items }) => {
    if (!items || items.length === 0) return null;
    
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 8,
        border: '1px solid rgba(255,255,255,0.1)',
        overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          padding: '0.75rem 1rem',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
          background: 'rgba(0,0,0,0.2)'
        }}>
          <span style={{
            width: 28,
            height: 28,
            borderRadius: 6,
            background: categoryConfig.File.gradient,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.9rem',
            marginRight: '0.75rem'
          }}>
            📄
          </span>
          <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>File</span>
          <div style={{ flex: 1 }} />
          <button style={{
            padding: '0.3rem 0.6rem',
            borderRadius: 4,
            border: '1px solid rgba(59, 130, 246, 0.4)',
            background: 'rgba(59, 130, 246, 0.1)',
            color: '#60a5fa',
            fontSize: '0.7rem',
            cursor: 'pointer',
            marginRight: '0.5rem'
          }}>
            Enrich
          </button>
          <button style={{
            padding: '0.3rem 0.5rem',
            borderRadius: 4,
            border: '1px solid rgba(255,255,255,0.2)',
            background: 'transparent',
            color: 'var(--text-muted)',
            fontSize: '0.7rem',
            cursor: 'pointer'
          }}>
            ⊙ Copy
          </button>
        </div>
        <div style={{ padding: '0.5rem' }}>
          {items.slice(0, compact ? 4 : undefined).map((ioc, idx) => {
            const isHash = ['md5', 'sha1', 'sha256', 'sha512', 'hash'].includes((ioc.type || '').toLowerCase());
            
            return (
              <div key={idx} style={{
                display: 'flex',
                alignItems: 'center',
                padding: '0.5rem 0.75rem',
                borderRadius: 6,
                marginBottom: '0.25rem',
                background: idx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent',
                gap: '0.5rem'
              }}>
                <span style={{ color: categoryConfig.File.color, fontSize: '0.5rem' }}>●</span>
                <code style={{ 
                  fontSize: '0.75rem', 
                  color: '#a5f3fc',
                  fontFamily: 'monospace',
                  minWidth: 180,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  {truncateValue(ioc.value, 30)}
                </code>
                <SeverityBadge level={ioc.riskLevel} />
                <div style={{ flex: 1 }} />
                {isHash && (
                  <>
                    <button
                      onClick={() => onEnrich && onEnrich(ioc)}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: 4,
                        border: '1px solid rgba(59, 130, 246, 0.4)',
                        background: 'rgba(59, 130, 246, 0.1)',
                        color: '#60a5fa',
                        fontSize: '0.65rem',
                        cursor: 'pointer'
                      }}
                    >
                      🔎 Enrich
                    </button>
                    <button
                      onClick={() => onBlock && onBlock(ioc)}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: 4,
                        border: '1px solid rgba(220, 38, 38, 0.4)',
                        background: 'rgba(220, 38, 38, 0.1)',
                        color: '#f87171',
                        fontSize: '0.65rem',
                        cursor: 'pointer'
                      }}
                    >
                      🚫 Block
                    </button>
                  </>
                )}
                <button
                  onClick={() => copyToClipboard(ioc.value)}
                  style={{
                    padding: '0.2rem 0.5rem',
                    borderRadius: 4,
                    border: '1px solid rgba(107, 114, 128, 0.4)',
                    background: 'rgba(107, 114, 128, 0.1)',
                    color: '#9ca3af',
                    fontSize: '0.65rem',
                    cursor: 'pointer'
                  }}
                >
                  {copiedValue === ioc.value ? '✓' : '⊙ Copy'}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // =============================================================================
  // MAIN RENDER
  // =============================================================================

  const filterOptions = ['All', 'Network', 'URLs & Domains', 'Identity', 'File', 'Process'];

  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      height: '100%',
      background: 'var(--bg-primary)'
    }}>
      {/* Header with Filters */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        padding: '0.75rem 1rem',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        flexWrap: 'wrap'
      }}>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Type:</span>
        {filterOptions.map(filter => (
          <button
            key={filter}
            onClick={() => setActiveFilter(filter)}
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: 6,
              border: activeFilter === filter ? '1px solid #3b82f6' : '1px solid rgba(255,255,255,0.2)',
              background: activeFilter === filter ? 'rgba(59, 130, 246, 0.2)' : 'transparent',
              color: activeFilter === filter ? '#60a5fa' : 'var(--text-secondary)',
              fontSize: '0.8rem',
              cursor: 'pointer'
            }}
          >
            {filter}
          </button>
        ))}
        
        <div style={{ flex: 1 }} />
        
        {/* Context toggle */}
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>👤</span> Context
        </span>
        
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <input
            type="text"
            placeholder="Search IOCs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              padding: '0.4rem 0.75rem 0.4rem 2rem',
              borderRadius: 6,
              border: '1px solid rgba(255,255,255,0.2)',
              background: 'rgba(255,255,255,0.05)',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
              width: 180
            }}
          />
          <span style={{ 
            position: 'absolute', 
            left: '0.6rem', 
            top: '50%', 
            transform: 'translateY(-50%)',
            fontSize: '0.8rem',
            opacity: 0.5
          }}>🔍</span>
        </div>
      </div>

      {/* Cards Grid */}
      <div style={{ 
        flex: 1, 
        overflow: 'auto', 
        padding: '1rem',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))',
        gap: '1rem',
        alignContent: 'start'
      }}>
        <NetworkCard items={groupedIOCs['Network']} />
        <ProcessCard items={groupedIOCs['Process']} />
        <DomainsCard items={groupedIOCs['URLs & Domains']} />
        <IdentityCard items={groupedIOCs['Identity']} />
        <EmailCard items={groupedIOCs['Email']} />
        <FileCard items={groupedIOCs['File']} />
      </div>

      {/* Footer */}
      <div style={{
        padding: '0.5rem 1rem',
        borderTop: '1px solid rgba(255,255,255,0.1)',
        display: 'flex',
        justifyContent: 'flex-end',
        fontSize: '0.75rem',
        color: 'var(--text-muted)'
      }}>
        1-{Math.min(10, filteredIOCs.length)} of {filteredIOCs.length} Indicators →
      </div>
    </div>
  );
};

export default IOCPanel;
