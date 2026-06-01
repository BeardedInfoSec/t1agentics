/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { authFetch, API_BASE_URL } from '../utils/api';
import { Button, Badge, Modal, Input, Select, Textarea } from './ui';
import { Lock, Ban, Globe, ShieldX, UserX, KeyRound, LogOut, FileLock, MonitorStop, Power, Eye, Search, FlaskConical, Mail, Settings } from 'lucide-react';
import { WorkbenchLayout } from '../layouts';
import styles from './ActionApprovals.module.css';

function ActionApprovals() {
  const [activeTab, setActiveTab] = useState('queue');
  const [requests, setRequests] = useState([]);
  const [historyRequests, setHistoryRequests] = useState([]);
  const [stats, setStats] = useState({
    total_pending: 0,
    by_priority: {},
    by_action_type: {},
    oldest_pending_hours: 0
  });
  const [actionTypes, setActionTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [showDenyModal, setShowDenyModal] = useState(false);
  const [denyReason, setDenyReason] = useState('');
  const [processingId, setProcessingId] = useState(null);
  const [filterPriority, setFilterPriority] = useState('all');
  const [filterActionType, setFilterActionType] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const priorityParam = filterPriority !== 'all' ? `?priority=${filterPriority}` : '';
      const [requestsRes, statsRes, typesRes] = await Promise.all([
        authFetch(`${API_BASE_URL}/api/v1/actions/requests/queue${priorityParam}`).catch(() => ({ ok: false })),
        authFetch(`${API_BASE_URL}/api/v1/actions/requests/stats`).catch(() => ({ ok: false })),
        authFetch(`${API_BASE_URL}/api/v1/actions/requests/types`).catch(() => ({ ok: false }))
      ]);

      if (requestsRes.ok) {
        const data = await requestsRes.json();
        let filteredRequests = data.requests || [];
        if (filterActionType !== 'all') {
          filteredRequests = filteredRequests.filter(r => r.action_type === filterActionType);
        }
        setRequests(filteredRequests);
      }

      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data.stats || data);
      }

      if (typesRes.ok) {
        const data = await typesRes.json();
        setActionTypes(data.action_types || []);
      }
    } catch (err) {
      console.error('Action queue fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [filterPriority, filterActionType]);

  const fetchHistory = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterStatus !== 'all') params.append('status', filterStatus);
      if (filterPriority !== 'all') params.append('priority', filterPriority);
      if (filterActionType !== 'all') params.append('action_type', filterActionType);

      const res = await authFetch(`${API_BASE_URL}/api/v1/actions/requests/history?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setHistoryRequests(data.requests || []);
      }
    } catch (err) {
      console.error('Action history fetch error:', err);
    }
  }, [filterStatus, filterPriority, filterActionType]);

  useEffect(() => {
    if (activeTab === 'queue') {
      fetchData();
      if (autoRefresh) {
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
      }
    } else {
      fetchHistory();
    }
  }, [fetchData, fetchHistory, autoRefresh, activeTab]);

  const handleApprove = async (requestId, executeImmediately = true) => {
    setProcessingId(requestId);
    try {
      const username = localStorage.getItem('username') || 'unknown';
      const response = await authFetch(`${API_BASE_URL}/api/v1/actions/requests/${requestId}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approved_by: username, execute_immediately: executeImmediately })
      });
      if (response.ok) {
        fetchData();
        setShowApproveModal(false);
        setSelectedRequest(null);
      } else {
        const error = await response.json();
      }
    } catch (err) {
    } finally {
      setProcessingId(null);
    }
  };

  const handleDeny = async (requestId) => {
    setProcessingId(requestId);
    try {
      const username = localStorage.getItem('username') || 'unknown';
      const response = await authFetch(`${API_BASE_URL}/api/v1/actions/requests/${requestId}/deny`, {
        method: 'POST',
        body: JSON.stringify({ denied_by: username, denial_reason: denyReason || 'No reason provided' })
      });
      if (response.ok) {
        fetchData();
        setShowDenyModal(false);
        setSelectedRequest(null);
        setDenyReason('');
      } else {
        const error = await response.json();
      }
    } catch (err) {
    } finally {
      setProcessingId(null);
    }
  };

  const getActionTypeIcon = (actionType) => {
    const icons = {
      contain_host: Lock,
      block_ip: Ban,
      block_domain: Globe,
      block_hash: ShieldX,
      disable_user: UserX,
      reset_password: KeyRound,
      revoke_sessions: LogOut,
      quarantine_file: FileLock,
      isolate_endpoint: MonitorStop,
      terminate_process: Power,
      add_to_watchlist: Eye,
      trigger_scan: Search,
      collect_forensics: FlaskConical,
      send_notification: Mail
    };
    const Icon = icons[actionType] || Settings;
    return <Icon size={16} />;
  };

  const formatTimeAgo = (timestamp) => {
    if (!timestamp) return 'Unknown';
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleString();
  };

  if (loading) {
    return (
      <WorkbenchLayout title="Action Approvals" subtitle="Review and approve agent actions">
        <div className={styles.emptyState}>Loading approval queue...</div>
      </WorkbenchLayout>
    );
  }

  const renderRequestCard = (request, showActions = true) => (
    <div key={request.request_id} className={styles.requestCard}>
      <div className={styles.requestHeader}>
        <div className={styles.requestMeta}>
          <div className={styles.iconBadge}>{getActionTypeIcon(request.action_type)}</div>
          <div>
            <div className={styles.requestTitle}>{request.action_type?.replace(/_/g, ' ')}</div>
            <div className={styles.requestSub}>{formatTimeAgo(request.created_at)}</div>
          </div>
        </div>
        <div>
          <Badge variant={request.priority === 'critical' ? 'error' : request.priority === 'high' ? 'warning' : 'info'}>
            {request.priority}
          </Badge>
        </div>
      </div>
      <div className={styles.requestBody}>
        <div>
          <div className={styles.requestSub}>Target</div>
          <div className={styles.monoBox}>{request.target_type}: {request.target_value}</div>
        </div>
        <div>
          <div className={styles.requestSub}>Confidence</div>
          <progress className={styles.progress} value={request.confidence || 0} max={1} />
        </div>
        {request.reasoning && (
          <div>
            <div className={styles.requestSub}>Agent Reasoning</div>
            <div className={styles.monoBox}>{request.reasoning}</div>
          </div>
        )}
      </div>
      {showActions && (
        <div className={styles.requestFooter}>
          <Button
            variant="danger"
            onClick={() => { setSelectedRequest(request); setShowDenyModal(true); }}
            disabled={processingId === request.request_id}
          >
            Deny
          </Button>
          <Button
            onClick={() => { setSelectedRequest(request); setShowApproveModal(true); }}
            disabled={processingId === request.request_id}
          >
            Approve
          </Button>
        </div>
      )}
    </div>
  );

  return (
    <WorkbenchLayout
      title="Action Approvals"
      subtitle="Review and approve high-impact agent actions"
      actions={
        <label className={styles.autoRefresh}>
          <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
          Auto-refresh
        </label>
      }
    >
      <div className={styles.approvalsRoot}>
        <div className={styles.tabs}>
          <button
            className={`${styles.tabButton} ${activeTab === 'queue' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('queue')}
          >
            Pending Queue
          </button>
          <button
            className={`${styles.tabButton} ${activeTab === 'history' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('history')}
          >
            History
          </button>
        </div>

        <div className={styles.statGrid}>
          <div className={styles.statCard}>
            <div className={styles.statLabel}>Pending Approvals</div>
            <div className={styles.statValue}>{stats.total_pending || requests.length || 0}</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statLabel}>Critical Priority</div>
            <div className={styles.statValue}>{stats.by_priority?.critical || stats.pending_by_priority?.critical || 0}</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statLabel}>High Priority</div>
            <div className={styles.statValue}>{stats.by_priority?.high || stats.pending_by_priority?.high || 0}</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statLabel}>Oldest Pending (hrs)</div>
            <div className={styles.statValue}>{stats.oldest_pending_hours || 0}</div>
          </div>
        </div>

        <div className={styles.filterRow}>
          <Select label="Status" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="denied">Denied</option>
          </Select>
          <Select label="Priority" value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
          <Select label="Action Type" value={filterActionType} onChange={(e) => setFilterActionType(e.target.value)}>
            <option value="all">All</option>
            {actionTypes.map((type) => (
              <option key={type.id || type.action_type || type} value={type.action_type || type}>
                {type.display_name || type.action_type?.replace(/_/g, ' ') || type}
              </option>
            ))}
          </Select>
        </div>

        {activeTab === 'queue' ? (
          requests.length === 0 ? (
            <div className={styles.emptyState}>No pending approvals.</div>
          ) : (
            <div className={styles.cardList}>
              {requests.map((request) => renderRequestCard(request, true))}
            </div>
          )
        ) : (
          historyRequests.length === 0 ? (
            <div className={styles.emptyState}>No action history.</div>
          ) : (
            <div className={styles.cardList}>
              {historyRequests.map((request) => (
                <div key={request.request_id} className={styles.requestCard}>
                  <div className={styles.requestHeader}>
                    <div className={styles.requestMeta}>
                      <div className={styles.iconBadge}>{getActionTypeIcon(request.action_type)}</div>
                      <div>
                        <div className={styles.requestTitle}>{request.action_type?.replace(/_/g, ' ')}</div>
                        <div className={styles.requestSub}>{formatDate(request.updated_at)}</div>
                      </div>
                    </div>
                    <Badge variant={request.status === 'approved' ? 'success' : request.status === 'denied' ? 'error' : 'info'}>
                      {request.status}
                    </Badge>
                  </div>
                  <div className={styles.requestBody}>
                    <div>
                      <div className={styles.requestSub}>Target</div>
                      <div className={styles.monoBox}>{request.target_type}: {request.target_value}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      <Modal
        open={showApproveModal}
        title="Confirm Action Approval"
        onClose={() => { setShowApproveModal(false); setSelectedRequest(null); }}
        onConfirm={() => handleApprove(selectedRequest.request_id, true)}
        confirmLabel="Approve"
      >
        {selectedRequest && (
          <div>
            <p>Approve this action and execute immediately?</p>
            <div className={styles.monoBox}>{selectedRequest.target_value}</div>
          </div>
        )}
      </Modal>

      <Modal
        open={showDenyModal}
        title="Deny Action Request"
        danger
        onClose={() => { setShowDenyModal(false); setSelectedRequest(null); setDenyReason(''); }}
        onConfirm={() => handleDeny(selectedRequest.request_id)}
        confirmLabel="Deny"
      >
        {selectedRequest && (
          <div>
            <p>Provide a denial reason (optional).</p>
            <Textarea value={denyReason} onChange={(e) => setDenyReason(e.target.value)} placeholder="Explain why this action is being denied" />
          </div>
        )}
      </Modal>
    </WorkbenchLayout>
  );
}

export default ActionApprovals;
