/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { useToast } from './ui/Toast';
import { API_BASE_URL } from '../utils/api';
import {
  Button,
  IconButton,
  Card,
  Modal,
  Badge,
  Input,
  Select,
  InlineAlert,
} from './ui';
import {
  Plus,
  Mail,
  Pause,
  Play,
  Plug,
  RefreshCw,
  Pencil,
  Trash2,
  Info,
  Inbox,
  ShieldAlert,
  ShieldCheck,
  Activity,
} from 'lucide-react';

const getAuthHeaders = () => ({
  'Content-Type': 'application/json',
});

const INITIAL_MAILBOX = {
  name: '',
  mailbox_type: 'phishing_reports',
  imap_server: '',
  imap_port: 993,
  use_ssl: true,
  username: '',
  password: '',
  folder: 'INBOX',
  poll_interval_seconds: 300,
  auto_process: true,
  create_alerts: true,
  auto_ai_analysis: true,
  auto_acknowledge: true,
  alert_severity: 'medium',
};

/* ---------- stat card ---------- */
const StatCard = ({ icon, value, label }) => (
  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      gap: '14px',
      padding: '16px 20px',
      background: 'var(--bg-tertiary)',
      border: '1px solid var(--border-color)',
      borderRadius: 'var(--radius-lg)',
    }}
  >
    <div
      style={{
        width: 40,
        height: 40,
        borderRadius: 'var(--radius-md)',
        background: 'var(--primary-light)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--primary)',
        flexShrink: 0,
      }}
    >
      {icon}
    </div>
    <div>
      <div
        style={{
          fontSize: '1.5rem',
          fontWeight: 700,
          color: 'var(--text-primary)',
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          marginTop: 2,
        }}
      >
        {label}
      </div>
    </div>
  </div>
);

/* ---------- mailbox row ---------- */
const MailboxRow = ({
  mailbox,
  polling,
  onToggleActive,
  onTest,
  onPoll,
  onEdit,
  onDelete,
}) => {
  const typeMap = {
    phishing_reports: { label: 'Phishing', variant: 'warning' },
    alert_inbox: { label: 'Alert Inbox', variant: 'info' },
    security_alerts: { label: 'Security', variant: 'error' },
  };
  const typeInfo = typeMap[mailbox.mailbox_type] || {
    label: 'Email',
    variant: 'info',
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        padding: '14px 16px',
        background: mailbox.is_active
          ? 'var(--bg-tertiary)'
          : 'var(--bg-secondary)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-color)',
        opacity: mailbox.is_active ? 1 : 0.65,
        transition: 'opacity 160ms ease',
      }}
    >
      {/* Status dot */}
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: 'var(--radius-full)',
          background: mailbox.is_active ? 'var(--primary)' : 'var(--text-muted)',
          boxShadow: mailbox.is_active
            ? '0 0 6px rgba(60, 179, 113, 0.45)'
            : 'none',
          flexShrink: 0,
          marginRight: 14,
        }}
      />

      {/* Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            marginBottom: 4,
          }}
        >
          <span
            style={{
              fontWeight: 600,
              fontSize: '0.9rem',
              color: 'var(--text-primary)',
            }}
          >
            {mailbox.name}
          </span>
          <Badge variant={typeInfo.variant}>{typeInfo.label}</Badge>
          {!mailbox.is_active && <Badge variant="info">Paused</Badge>}
        </div>
        <div
          style={{
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}
        >
          {mailbox.username} &middot; {mailbox.imap_server}:{mailbox.imap_port}
        </div>
        <div
          style={{
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            marginTop: 3,
          }}
        >
          Last poll:{' '}
          {mailbox.last_poll_at
            ? new Date(mailbox.last_poll_at).toLocaleString()
            : 'Never'}
          {' | '}
          {mailbox.emails_processed || 0} emails processed
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 6, marginLeft: 12 }}>
        <IconButton
          title={mailbox.is_active ? 'Pause polling' : 'Resume polling'}
          onClick={() => onToggleActive(mailbox)}
        >
          {mailbox.is_active ? <Pause size={15} /> : <Play size={15} />}
        </IconButton>
        <IconButton title="Test connection" onClick={() => onTest(mailbox.id)}>
          <Plug size={15} />
        </IconButton>
        <IconButton
          title="Poll now"
          onClick={() => onPoll(mailbox.id)}
          disabled={polling || !mailbox.is_active}
        >
          <RefreshCw
            size={15}
            style={{
              animation: polling ? 'spin 1s linear infinite' : 'none',
            }}
          />
        </IconButton>
        <IconButton title="Edit" onClick={() => onEdit(mailbox)}>
          <Pencil size={15} />
        </IconButton>
        <IconButton title="Delete" onClick={() => onDelete(mailbox.id)}>
          <Trash2 size={15} />
        </IconButton>
      </div>
    </div>
  );
};

/* ---------- checkbox field ---------- */
const CheckboxField = ({ checked, onChange, label }) => (
  <label
    style={{
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      cursor: 'pointer',
      fontSize: '0.85rem',
      color: 'var(--text-secondary)',
    }}
  >
    <input
      type="checkbox"
      checked={checked}
      onChange={onChange}
      style={{
        accentColor: 'var(--primary)',
        width: 16,
        height: 16,
        cursor: 'pointer',
      }}
    />
    {label}
  </label>
);

/* ========== main component ========== */
function InboundEmailIntegration() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [mailboxes, setMailboxes] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editingMailbox, setEditingMailbox] = useState(null);
  const [stats, setStats] = useState(null);
  const [polling, setPolling] = useState({});
  const [newMailbox, setNewMailbox] = useState({ ...INITIAL_MAILBOX });

  /* ---- data fetching ---- */
  const fetchMailboxes = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/mailboxes?include_inactive=true`,
        { headers: getAuthHeaders(), credentials: 'include' }
      );
      if (res.ok) {
        const data = await res.json();
        setMailboxes(data.mailboxes || []);
      }
    } catch (_) {
      /* silent */
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/phishing-reports/stats?days=30`,
        { headers: getAuthHeaders(), credentials: 'include' }
      );
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (_) {
      /* silent */
    }
  }, []);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      await Promise.all([fetchMailboxes(), fetchStats()]);
      setLoading(false);
    };
    load();
  }, [fetchMailboxes, fetchStats]);

  /* ---- CRUD ---- */
  const saveMailbox = async () => {
    try {
      const isEdit = !!editingMailbox;
      const url = isEdit
        ? `${API_BASE_URL}/api/v1/email/inbound/mailboxes/${editingMailbox.id}`
        : `${API_BASE_URL}/api/v1/email/inbound/mailboxes`;
      const res = await fetch(url, {
        method: isEdit ? 'PUT' : 'POST',
        headers: getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify(newMailbox),
      });
      if (res.ok) {
        fetchMailboxes();
        closeForm();
      }
    } catch (_) {
      /* silent */
    }
  };

  const deleteMailbox = async (id) => {
    if (!window.confirm('Are you sure you want to delete this mailbox?'))
      return;
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/mailboxes/${id}`,
        { method: 'DELETE', headers: getAuthHeaders(), credentials: 'include' }
      );
      if (res.ok) fetchMailboxes();
    } catch (_) {
      /* silent */
    }
  };

  const testMailboxConnection = async (id) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/mailboxes/${id}/test`,
        { method: 'POST', headers: getAuthHeaders(), credentials: 'include' }
      );
      const data = await res.json();
      if (data.success) {
        toast.success(`Connection successful. ${data.email_count} emails found.`);
      } else {
        toast.error(`Connection failed: ${data.message}`);
      }
    } catch (_) {
      toast.error('Failed to test connection');
    }
  };

  const triggerPoll = async (id) => {
    setPolling((p) => ({ ...p, [id]: true }));
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/mailboxes/${id}/poll`,
        { method: 'POST', headers: getAuthHeaders(), credentials: 'include' }
      );
      if (res.ok) {
        const data = await res.json();
        toast.success(
          `Poll complete. ${data.emails_processed || 0} new emails processed.`
        );
        fetchStats();
        fetchMailboxes();
      }
    } catch (_) {
      /* silent */
    } finally {
      setPolling((p) => ({ ...p, [id]: false }));
    }
  };

  const toggleMailboxActive = async (mailbox) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/email/inbound/mailboxes/${mailbox.id}`,
        {
          method: 'PUT',
          headers: getAuthHeaders(),
          credentials: 'include',
          body: JSON.stringify({ ...mailbox, is_active: !mailbox.is_active }),
        }
      );
      if (res.ok) fetchMailboxes();
    } catch (_) {
      /* silent */
    }
  };

  /* ---- form helpers ---- */
  const openAddForm = () => {
    setNewMailbox({ ...INITIAL_MAILBOX });
    setEditingMailbox(null);
    setShowForm(true);
  };

  const openEditForm = (mailbox) => {
    setEditingMailbox(mailbox);
    setNewMailbox({ ...mailbox });
    setShowForm(true);
  };

  const closeForm = () => {
    setShowForm(false);
    setEditingMailbox(null);
    setNewMailbox({ ...INITIAL_MAILBOX });
  };

  const update = (field, value) =>
    setNewMailbox((prev) => ({ ...prev, [field]: value }));

  /* ---- loading ---- */
  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: 400,
        }}
      >
        <div className="spinner" />
      </div>
    );
  }

  /* ---- render ---- */
  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      {/* Page header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: 24,
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: '1.5rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <Mail size={22} style={{ color: 'var(--primary)' }} />
            Inbound Email Integration
          </h1>
          <p
            style={{
              margin: '6px 0 0',
              color: 'var(--text-secondary)',
              fontSize: '0.875rem',
            }}
          >
            Configure mailboxes to receive security alerts via email
          </p>
        </div>
        <Button variant="primary" icon={<Plus size={16} />} onClick={openAddForm} data-tour="inbox-add-button">
          Add Mailbox
        </Button>
      </div>

      {/* How it works */}
      <InlineAlert variant="info">
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <Info
            size={18}
            style={{ flexShrink: 0, marginTop: 1, opacity: 0.85 }}
          />
          <div style={{ lineHeight: 1.6 }}>
            <strong style={{ color: 'var(--text-primary)' }}>
              How it works
            </strong>
            <br />
            Emails received in configured mailboxes are automatically converted
            to alerts and processed by AI agents. Users can forward suspicious
            emails to your inbox (e.g.,{' '}
            <code
              style={{
                background: 'rgba(56, 189, 248, 0.12)',
                padding: '1px 6px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem',
              }}
            >
              security@company.com
            </code>
            ) and they will appear in the Alerts queue for triage.
          </div>
        </div>
      </InlineAlert>

      {/* Stats row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 12,
          margin: '20px 0',
        }}
      >
        <StatCard
          icon={<Mail size={20} />}
          value={mailboxes.reduce(
            (sum, m) => sum + (m.emails_processed || 0),
            0
          )}
          label="Emails Processed"
        />
        <StatCard
          icon={<ShieldAlert size={20} />}
          value={stats?.summary?.confirmed_phishing || 0}
          label="Confirmed Threats"
        />
        <StatCard
          icon={<ShieldCheck size={20} />}
          value={stats?.summary?.false_positives || 0}
          label="False Positives"
        />
        <StatCard
          icon={<Activity size={20} />}
          value={mailboxes.filter((m) => m.is_active).length}
          label="Active Mailboxes"
        />
      </div>

      {/* Mailbox list */}
      <Card
        title="Configured Mailboxes"
        subtitle={`${mailboxes.length} mailbox${mailboxes.length !== 1 ? 'es' : ''}`}
      >
        {mailboxes.length === 0 ? (
          <div
            style={{
              padding: '48px 16px',
              textAlign: 'center',
            }}
          >
            <Inbox
              size={40}
              style={{
                color: 'var(--text-muted)',
                marginBottom: 12,
              }}
            />
            <p
              style={{
                margin: 0,
                color: 'var(--text-secondary)',
                fontWeight: 500,
              }}
            >
              No mailboxes configured
            </p>
            <p
              style={{
                fontSize: '0.85rem',
                color: 'var(--text-muted)',
                margin: '6px 0 20px',
              }}
            >
              Add a mailbox to start receiving phishing reports via email
            </p>
            <Button
              variant="primary"
              icon={<Plus size={16} />}
              onClick={openAddForm}
              data-tour="inbox-add-button"
            >
              Add Your First Mailbox
            </Button>
          </div>
        ) : (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              marginTop: 4,
            }}
          >
            {mailboxes.map((mailbox) => (
              <MailboxRow
                key={mailbox.id}
                mailbox={mailbox}
                polling={polling[mailbox.id]}
                onToggleActive={toggleMailboxActive}
                onTest={testMailboxConnection}
                onPoll={triggerPoll}
                onEdit={openEditForm}
                onDelete={deleteMailbox}
              />
            ))}
          </div>
        )}
      </Card>

      {/* Add / Edit Modal. The shared ui/Modal expects `isOpen` (not
          `open`) and doesn't render its own confirm/cancel buttons —
          we provide the footer ourselves below. */}
      <Modal
        isOpen={showForm}
        title={editingMailbox ? 'Edit Mailbox' : 'Add Inbound Mailbox'}
        onClose={closeForm}
        size="lg"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }} data-tour="inbox-form-modal">
          {/* Section: General */}
          <fieldset
            style={{
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '14px 16px',
              margin: 0,
            }}
          >
            <legend
              style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                padding: '0 6px',
              }}
            >
              General
            </legend>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 12,
              }}
            >
              <Input
                label="Name"
                type="text"
                value={newMailbox.name}
                onChange={(e) => update('name', e.target.value)}
                placeholder="Phishing Reports Inbox"
              />
              <Select
                label="Mailbox Type"
                value={newMailbox.mailbox_type}
                onChange={(e) => update('mailbox_type', e.target.value)}
              >
                <option value="phishing_reports">Phishing Reports</option>
                <option value="alert_inbox">Alert Inbox</option>
              </Select>
            </div>
          </fieldset>

          {/* Section: IMAP Connection */}
          <fieldset
            style={{
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '14px 16px',
              margin: 0,
            }}
          >
            <legend
              style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                padding: '0 6px',
              }}
            >
              IMAP Connection
            </legend>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '2fr 1fr',
                gap: 12,
              }}
            >
              <Input
                label="IMAP Server"
                type="text"
                value={newMailbox.imap_server}
                onChange={(e) => update('imap_server', e.target.value)}
                placeholder="imap.gmail.com"
              />
              <Input
                label="Port"
                type="number"
                value={newMailbox.imap_port}
                onChange={(e) =>
                  update('imap_port', parseInt(e.target.value) || 993)
                }
              />
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 12,
                marginTop: 12,
              }}
            >
              <Input
                label="Username / Email"
                type="text"
                value={newMailbox.username}
                onChange={(e) => update('username', e.target.value)}
                placeholder="phishing@company.com"
              />
              <Input
                label="Password / App Password"
                type="password"
                value={newMailbox.password}
                onChange={(e) => update('password', e.target.value)}
                placeholder="App password"
                autoComplete="new-password"
              />
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 12,
                marginTop: 12,
              }}
            >
              <Input
                label="Folder"
                type="text"
                value={newMailbox.folder}
                onChange={(e) => update('folder', e.target.value)}
                placeholder="INBOX"
              />
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <CheckboxField
                  checked={newMailbox.use_ssl}
                  onChange={(e) => update('use_ssl', e.target.checked)}
                  label="Use SSL / TLS"
                />
              </div>
            </div>
          </fieldset>

          {/* Section: Processing */}
          <fieldset
            style={{
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '14px 16px',
              margin: 0,
            }}
          >
            <legend
              style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                padding: '0 6px',
              }}
            >
              Processing
            </legend>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 12,
              }}
            >
              <Input
                label="Poll Interval (seconds)"
                type="number"
                value={newMailbox.poll_interval_seconds}
                onChange={(e) =>
                  update(
                    'poll_interval_seconds',
                    parseInt(e.target.value) || 300
                  )
                }
              />
              <Select
                label="Alert Severity"
                value={newMailbox.alert_severity}
                onChange={(e) => update('alert_severity', e.target.value)}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Select>
            </div>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
                marginTop: 14,
              }}
            >
              <CheckboxField
                checked={newMailbox.create_alerts}
                onChange={(e) => update('create_alerts', e.target.checked)}
                label="Create alerts automatically"
              />
              <CheckboxField
                checked={newMailbox.auto_ai_analysis}
                onChange={(e) => update('auto_ai_analysis', e.target.checked)}
                label="Auto AI analysis"
              />
              <CheckboxField
                checked={newMailbox.auto_acknowledge}
                onChange={(e) => update('auto_acknowledge', e.target.checked)}
                label="Send confirmation emails to reporters"
              />
            </div>
          </fieldset>

          {/* Footer actions. The Modal component doesn't render its
              own confirm/cancel buttons; we own them here. */}
          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 8,
            paddingTop: 12,
            marginTop: 4,
            borderTop: '1px solid var(--border-color)',
          }}>
            <Button variant="secondary" onClick={closeForm}>
              Cancel
            </Button>
            <Button variant="primary" onClick={saveMailbox}>
              {editingMailbox ? 'Save Changes' : 'Add Mailbox'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

export default InboundEmailIntegration;
