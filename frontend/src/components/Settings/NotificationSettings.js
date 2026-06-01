/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useToast } from '../ui/Toast';
import { API_BASE_URL, authFetch, getActionButtonStyle, getBadgeStyle } from './settingsUtils';

const initialSmtpConfig = {
  host: 'mailhog',
  port: 1025,
  username: '',
  password: '',
  use_tls: false,
  use_ssl: false,
  from_email: 'notifications@T1 Agentics.local',
  from_name: 'T1 Agentics SOC',
  enabled: true
};

const initialChannel = {
  name: '',
  channel_type: 'slack',
  webhook_url: '',
  enabled: true
};

const initialRule = {
  name: '',
  enabled: true,
  event_types: [],
  severity_filter: [],
  recipients: [],
  subject_template: '[T1 Agentics] {event_type}: {title}',
  body_template: '',
  include_approval_links: false,
  approval_ttl_minutes: 60,
  approval_require_auth: false
};

function NotificationSettings({ isPlatformTenant = false }) {
  const toast = useToast();
  const [smtpConfig, setSmtpConfig] = useState(initialSmtpConfig);
  const [loadingSmtp, setLoadingSmtp] = useState(true);
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState(null);
  const [testEmailAddress, setTestEmailAddress] = useState('');
  const [sendingTestEmail, setSendingTestEmail] = useState(false);

  const [notificationRules, setNotificationRules] = useState([]);
  const [showAddRule, setShowAddRule] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [newRule, setNewRule] = useState(initialRule);
  const [recipientInput, setRecipientInput] = useState('');
  const [eventTypes, setEventTypes] = useState([]);
  const [severityOptions, setSeverityOptions] = useState([]);

  const [webhookChannels, setWebhookChannels] = useState([]);
  const [channelTypes, setChannelTypes] = useState([]);
  const [loadingChannels, setLoadingChannels] = useState(true);
  const [showAddChannel, setShowAddChannel] = useState(false);
  const [editingChannel, setEditingChannel] = useState(null);
  const [testingChannel, setTestingChannel] = useState(null);
  const [newChannel, setNewChannel] = useState(initialChannel);

  const [approvalSettings, setApprovalSettings] = useState({
    default_ttl_minutes: 60,
    require_auth_default: false
  });

  useEffect(() => {
    fetchSmtpConfig();
    fetchNotificationRules();
    fetchEventTypes();
    fetchWebhookChannels();
    fetchChannelTypes();
  }, []);

  // ── SMTP Functions ──
  const fetchSmtpConfig = async () => {
    try {
      setLoadingSmtp(true);
      const response = await authFetch(`${API_BASE_URL}/api/v1/notifications/smtp`);
      if (response.ok) {
        const data = await response.json();
        if (data) {
          setSmtpConfig({
            host: data.host || '', port: data.port || 587, username: data.username || '',
            password: '', use_tls: data.use_tls ?? true, use_ssl: data.use_ssl ?? false,
            from_email: data.from_email || '', from_name: data.from_name || 'T1 Agentics SOC',
            enabled: data.enabled ?? false
          });
        }
      }
    } catch (error) { console.error('SMTP config fetch error:', error); } finally { setLoadingSmtp(false); }
  };

  const saveSmtpConfig = async (e) => {
    e.preventDefault();
    setSavingSmtp(true); setSmtpTestResult(null);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/notifications/smtp`, {
        method: 'POST', body: JSON.stringify(smtpConfig)
      });
      if (response.ok) setSmtpTestResult({ success: true, message: 'SMTP configuration saved successfully!' });
      else { const err = await response.json(); setSmtpTestResult({ success: false, error: err.detail || 'Failed to save SMTP configuration' }); }
    } catch (error) { setSmtpTestResult({ success: false, error: 'Failed to save SMTP configuration' }); }
    finally { setSavingSmtp(false); }
  };

  const testSmtpConnection = async () => {
    setTestingSmtp(true); setSmtpTestResult(null);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/notifications/smtp/test`, { method: 'POST' });
      setSmtpTestResult(await response.json());
    } catch (error) { setSmtpTestResult({ success: false, error: 'Connection test failed' }); }
    finally { setTestingSmtp(false); }
  };

  const sendTestEmail = async () => {
    if (!testEmailAddress) { setSmtpTestResult({ success: false, error: 'Please enter a test email address' }); return; }
    setSendingTestEmail(true); setSmtpTestResult(null);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/notifications/smtp/test-email`, {
        method: 'POST',
        body: JSON.stringify({ recipient: testEmailAddress, subject: 'T1 Agentics Test Email', message: 'This is a test email from T1 Agentics SOC Platform.' })
      });
      setSmtpTestResult(await response.json());
    } catch (error) { setSmtpTestResult({ success: false, error: 'Failed to send test email' }); }
    finally { setSendingTestEmail(false); }
  };

  // ── Notification Rules Functions ──
  const fetchNotificationRules = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/rules`); if (r.ok) setNotificationRules((await r.json()) || []); } catch {}
  };
  const fetchEventTypes = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/event-types`); if (r.ok) { const d = await r.json(); setEventTypes(d.event_types || []); setSeverityOptions(d.severities || []); } } catch {}
  };
  const saveNotificationRule = async (e) => {
    e.preventDefault();
    try {
      const url = editingRule ? `${API_BASE_URL}/api/v1/notifications/rules/${editingRule}` : `${API_BASE_URL}/api/v1/notifications/rules`;
      const response = await authFetch(url, { method: editingRule ? 'PUT' : 'POST', body: JSON.stringify(newRule) });
      if (response.ok) { await fetchNotificationRules(); closeRuleModal(); }
      else { const err = await response.json(); toast.error(err.detail || 'Failed to save rule'); }
    } catch (error) { toast.error('Failed to save notification rule'); }
  };
  const deleteNotificationRule = async (ruleId) => {
    if (!window.confirm('Delete this notification rule?')) return;
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/rules/${ruleId}`, { method: 'DELETE' }); if (r.ok) await fetchNotificationRules(); } catch {}
  };
  const openEditRule = (rule) => {
    setEditingRule(rule.id);
    setNewRule({
      name: rule.name, enabled: rule.enabled, event_types: rule.event_types || [],
      severity_filter: rule.severity_filter || [], recipients: rule.recipients || [],
      subject_template: rule.subject_template || '[T1 Agentics] {event_type}: {title}',
      body_template: rule.body_template || '', include_approval_links: rule.include_approval_links || false,
      approval_ttl_minutes: rule.approval_ttl_minutes || 60, approval_require_auth: rule.approval_require_auth || false
    });
    setShowAddRule(true);
  };
  const closeRuleModal = () => { setShowAddRule(false); setEditingRule(null); setNewRule(initialRule); setRecipientInput(''); };
  const addRecipient = () => {
    if (recipientInput.trim() && recipientInput.includes('@')) {
      setNewRule({ ...newRule, recipients: [...newRule.recipients, recipientInput.trim()] });
      setRecipientInput('');
    }
  };
  const removeRecipient = (email) => setNewRule({ ...newRule, recipients: newRule.recipients.filter(r => r !== email) });
  const toggleEventType = (eventId) => {
    const current = newRule.event_types || [];
    setNewRule({ ...newRule, event_types: current.includes(eventId) ? current.filter(e => e !== eventId) : [...current, eventId] });
  };
  const toggleSeverity = (sevId) => {
    const current = newRule.severity_filter || [];
    setNewRule({ ...newRule, severity_filter: current.includes(sevId) ? current.filter(s => s !== sevId) : [...current, sevId] });
  };

  // ── Webhook Channel Functions ──
  const fetchWebhookChannels = async () => {
    try { setLoadingChannels(true); const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/channels`); if (r.ok) setWebhookChannels((await r.json()) || []); } catch {} finally { setLoadingChannels(false); }
  };
  const fetchChannelTypes = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/channels/types`); if (r.ok) { const d = await r.json(); setChannelTypes(d.channel_types || []); } } catch {}
  };
  const saveWebhookChannel = async (e) => {
    e.preventDefault();
    try {
      const url = editingChannel ? `${API_BASE_URL}/api/v1/notifications/channels/${editingChannel}` : `${API_BASE_URL}/api/v1/notifications/channels`;
      const response = await authFetch(url, { method: editingChannel ? 'PUT' : 'POST', body: JSON.stringify(newChannel) });
      if (response.ok) { await fetchWebhookChannels(); closeChannelModal(); }
      else { const err = await response.json(); toast.error(err.detail || 'Failed to save channel'); }
    } catch (error) { toast.error('Failed to save webhook channel'); }
  };
  const deleteWebhookChannel = async (channelId) => {
    if (!window.confirm('Delete this webhook channel?')) return;
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/channels/${channelId}`, { method: 'DELETE' }); if (r.ok) await fetchWebhookChannels(); } catch {}
  };
  const testWebhookChannel = async (channelId) => {
    setTestingChannel(channelId);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/notifications/channels/${channelId}/test`, { method: 'POST' });
      const result = await r.json();
      if (result.success) toast.success('Test message sent successfully!');
      else toast.error(`Test failed: ${result.error || 'Unknown error'}`);
    } catch (error) { toast.error('Failed to test channel'); }
    finally { setTestingChannel(null); }
  };
  const openEditChannel = (channel) => {
    setEditingChannel(channel.id);
    setNewChannel({ name: channel.name, channel_type: channel.channel_type, webhook_url: channel.webhook_url, enabled: channel.enabled });
    setShowAddChannel(true);
  };
  const closeChannelModal = () => { setShowAddChannel(false); setEditingChannel(null); setNewChannel(initialChannel); };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {isPlatformTenant ? (
        <>
          {/* Local Email Gateway Info */}
          <div className="settings-info-banner settings-info-banner--primary">
            <div>
              <div className="settings-info-banner-title">Local Email Gateway Active</div>
              <div className="settings-info-banner-desc">
                Emails are sent via built-in Mailhog server. View all sent emails at{' '}
                <a href="http://localhost:8025" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline' }}>
                  http://localhost:8025
                </a>
              </div>
            </div>
          </div>

          {/* SMTP Configuration */}
          <SMTPConfig
            smtpConfig={smtpConfig} setSmtpConfig={setSmtpConfig}
            loadingSmtp={loadingSmtp} savingSmtp={savingSmtp} testingSmtp={testingSmtp}
            smtpTestResult={smtpTestResult}
            onSave={saveSmtpConfig} onTest={testSmtpConnection}
          />

          {/* Test Email */}
          <TestEmailSection
            testEmailAddress={testEmailAddress} setTestEmailAddress={setTestEmailAddress}
            sendingTestEmail={sendingTestEmail} smtpHost={smtpConfig.host} onSend={sendTestEmail}
          />
        </>
      ) : (
        <div className="settings-info-banner settings-info-banner--primary">
          <div>
            <div className="settings-info-banner-title">Platform-Managed Email Delivery</div>
            <div className="settings-info-banner-desc">
              Email delivery is configured and managed by the platform administrator. Contact your platform admin to update SMTP settings.
            </div>
          </div>
        </div>
      )}

      {/* Notification Rules */}
      <NotificationRulesSection
        rules={notificationRules}
        onAdd={() => setShowAddRule(true)} onEdit={openEditRule} onDelete={deleteNotificationRule}
      />

      {/* Webhook Channels */}
      <WebhookChannelsSection
        channels={webhookChannels} channelTypes={channelTypes}
        loadingChannels={loadingChannels} testingChannel={testingChannel}
        onAdd={() => setShowAddChannel(true)} onEdit={openEditChannel}
        onDelete={deleteWebhookChannel} onTest={testWebhookChannel}
      />

      {/* Approval Links Settings */}
      <ApprovalLinksSection
        approvalSettings={approvalSettings} setApprovalSettings={setApprovalSettings}
      />

      {/* Add/Edit Channel Modal */}
      {showAddChannel && (
        <ChannelModal
          editingChannel={editingChannel} newChannel={newChannel} setNewChannel={setNewChannel}
          channelTypes={channelTypes} onSave={saveWebhookChannel} onClose={closeChannelModal}
        />
      )}

      {/* Add/Edit Rule Modal */}
      {showAddRule && (
        <RuleModal
          editingRule={editingRule} newRule={newRule} setNewRule={setNewRule}
          recipientInput={recipientInput} setRecipientInput={setRecipientInput}
          eventTypes={eventTypes} severityOptions={severityOptions}
          onSave={saveNotificationRule} onClose={closeRuleModal}
          onAddRecipient={addRecipient} onRemoveRecipient={removeRecipient}
          onToggleEventType={toggleEventType} onToggleSeverity={toggleSeverity}
        />
      )}
    </div>
  );
}

// ── SMTP Config ──
function SMTPConfig({ smtpConfig, setSmtpConfig, loadingSmtp, savingSmtp, testingSmtp, smtpTestResult, onSave, onTest }) {
  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">SMTP Configuration</h3>
          <p className="settings-card-desc">Using local Mailhog by default. Configure external SMTP for production.</p>
        </div>
        <label className="settings-checkbox">
          <input type="checkbox" checked={smtpConfig.enabled}
            onChange={(e) => setSmtpConfig({ ...smtpConfig, enabled: e.target.checked })} />
          <span style={{ fontWeight: 600 }}>Enable Email Notifications</span>
        </label>
      </div>

      {loadingSmtp ? (
        <div className="settings-loading"><div className="spinner"></div></div>
      ) : (
        <form onSubmit={onSave}>
          <div className="settings-form-row" style={{ marginBottom: '0.75rem' }}>
            <div className="settings-form-group">
              <label className="settings-form-label">SMTP Host</label>
              <input type="text" value={smtpConfig.host} onChange={(e) => setSmtpConfig({ ...smtpConfig, host: e.target.value })} placeholder="smtp.gmail.com" className="settings-form-input" />
            </div>
            <div className="settings-form-group">
              <label className="settings-form-label">Port</label>
              <input type="number" value={smtpConfig.port} onChange={(e) => setSmtpConfig({ ...smtpConfig, port: parseInt(e.target.value) })} placeholder="587" className="settings-form-input" />
            </div>
          </div>

          <div className="settings-form-row" style={{ marginBottom: '0.75rem' }}>
            <div className="settings-form-group">
              <label className="settings-form-label">Username</label>
              <input type="text" value={smtpConfig.username} onChange={(e) => setSmtpConfig({ ...smtpConfig, username: e.target.value })} placeholder="your-email@gmail.com" className="settings-form-input" />
            </div>
            <div className="settings-form-group">
              <label className="settings-form-label">Password <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}>(App Password for Gmail)</span></label>
              <input type="password" value={smtpConfig.password} onChange={(e) => setSmtpConfig({ ...smtpConfig, password: e.target.value })} placeholder="Leave blank to keep existing" autoComplete="new-password" className="settings-form-input" />
            </div>
          </div>

          <div className="settings-form-row" style={{ marginBottom: '0.75rem' }}>
            <div className="settings-form-group">
              <label className="settings-form-label">From Email</label>
              <input type="email" value={smtpConfig.from_email} onChange={(e) => setSmtpConfig({ ...smtpConfig, from_email: e.target.value })} placeholder="noreply@yourdomain.com" className="settings-form-input" />
            </div>
            <div className="settings-form-group">
              <label className="settings-form-label">From Name</label>
              <input type="text" value={smtpConfig.from_name} onChange={(e) => setSmtpConfig({ ...smtpConfig, from_name: e.target.value })} placeholder="T1 Agentics SOC" className="settings-form-input" />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1.25rem' }}>
            <label className="settings-checkbox">
              <input type="checkbox" checked={smtpConfig.use_tls}
                onChange={(e) => setSmtpConfig({ ...smtpConfig, use_tls: e.target.checked, use_ssl: false })} />
              <span>Use TLS (STARTTLS)</span>
            </label>
            <label className="settings-checkbox">
              <input type="checkbox" checked={smtpConfig.use_ssl}
                onChange={(e) => setSmtpConfig({ ...smtpConfig, use_ssl: e.target.checked, use_tls: false })} />
              <span>Use SSL</span>
            </label>
          </div>

          {smtpTestResult && (
            <div className={`settings-alert ${smtpTestResult.success ? 'settings-alert--success' : 'settings-alert--error'}`}>
              {smtpTestResult.success ? 'Success: ' : 'Error: '}{smtpTestResult.message || smtpTestResult.error}
            </div>
          )}

          <div className="settings-btn-row">
            <button type="submit" className="button button-primary" disabled={savingSmtp}>
              {savingSmtp ? 'Saving...' : 'Save Configuration'}
            </button>
            <button type="button" onClick={onTest} disabled={testingSmtp || !smtpConfig.host} style={getActionButtonStyle('blue')}>
              {testingSmtp ? 'Testing...' : 'Test Connection'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

// ── Test Email Section ──
function TestEmailSection({ testEmailAddress, setTestEmailAddress, sendingTestEmail, smtpHost, onSend }) {
  return (
    <div className="settings-card">
      <h3 className="settings-card-title" style={{ marginBottom: '1rem' }}>Send Test Email</h3>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
        <div style={{ flex: 1 }}>
          <label className="settings-form-label">Recipient Email</label>
          <input type="email" value={testEmailAddress} onChange={(e) => setTestEmailAddress(e.target.value)}
            placeholder="test@example.com" className="settings-form-input" />
        </div>
        <button onClick={onSend} disabled={sendingTestEmail || !testEmailAddress || !smtpHost}
          style={{ ...getActionButtonStyle('green'), padding: '0.6rem 1.25rem', whiteSpace: 'nowrap' }}>
          {sendingTestEmail ? 'Sending...' : 'Send Test Email'}
        </button>
      </div>
    </div>
  );
}

// ── Notification Rules Section ──
function NotificationRulesSection({ rules, onAdd, onEdit, onDelete }) {
  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">Notification Rules</h3>
          <p className="settings-card-desc">Configure when and to whom notifications are sent</p>
        </div>
        <button onClick={onAdd} className="button button-primary">+ Add Rule</button>
      </div>

      {rules.length === 0 ? (
        <div className="settings-empty">
          <div className="settings-empty-title">No notification rules configured</div>
          <p className="settings-empty-desc">Create rules to receive email notifications for security events</p>
          <button onClick={onAdd} className="button button-primary" style={{ marginTop: '1rem' }}>+ Create Your First Rule</button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {rules.map((rule) => (
            <RuleCard key={rule.id} rule={rule} onEdit={() => onEdit(rule)} onDelete={() => onDelete(rule.id)} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Rule Card ──
function RuleCard({ rule, onEdit, onDelete }) {
  return (
    <div className={`settings-feature-card ${rule.enabled ? 'settings-feature-card--active' : 'settings-feature-card--disabled'}`}>
      <div className="settings-feature-card-info">
        <div className="settings-feature-card-name">
          {rule.name}
          {!rule.enabled && <span style={getBadgeStyle('gray')}>DISABLED</span>}
        </div>
        <div className="settings-feature-card-meta">
          <strong>Events:</strong> {rule.event_types?.length > 0 ? rule.event_types.join(', ') : 'All events'}
          {rule.severity_filter?.length > 0 && (
            <span> | <strong>Severity:</strong> {rule.severity_filter.join(', ')}</span>
          )}
        </div>
        {rule.recipients?.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
            {rule.recipients.map((email, idx) => (
              <span key={idx} style={getBadgeStyle('green')}>{email}</span>
            ))}
          </div>
        )}
      </div>
      <div className="settings-feature-card-actions">
        <button onClick={onEdit} style={getActionButtonStyle('purple', false)}>Edit</button>
        <button onClick={onDelete} style={getActionButtonStyle('red')}>Delete</button>
      </div>
    </div>
  );
}

// ── Webhook Channels Section ──
function WebhookChannelsSection({ channels, channelTypes, loadingChannels, testingChannel, onAdd, onEdit, onDelete, onTest }) {
  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">Webhook Channels</h3>
          <p className="settings-card-desc">Send notifications to Slack, Teams, Webex, Discord, or custom webhooks</p>
        </div>
        <button onClick={onAdd} className="button button-primary">+ Add Channel</button>
      </div>

      {loadingChannels ? (
        <div className="settings-loading"><div className="spinner"></div></div>
      ) : channels.length === 0 ? (
        <div className="settings-empty">
          <div className="settings-empty-title">No webhook channels configured</div>
          <p className="settings-empty-desc">Connect Slack, Teams, or other messaging platforms</p>
          <button onClick={onAdd} className="button button-primary" style={{ marginTop: '1rem' }}>+ Add Your First Channel</button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {channels.map((channel) => {
            const channelType = channelTypes.find(t => t.id === channel.channel_type) || {};
            return (
              <ChannelCard
                key={channel.id} channel={channel} channelType={channelType}
                testing={testingChannel === channel.id}
                onEdit={() => onEdit(channel)} onDelete={() => onDelete(channel.id)}
                onTest={() => onTest(channel.id)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Channel Card ──
function ChannelCard({ channel, channelType, testing, onEdit, onDelete, onTest }) {
  return (
    <div className={`settings-feature-card ${channel.enabled ? 'settings-feature-card--active' : 'settings-feature-card--disabled'}`}>
      <div className="settings-feature-card-info">
        <div className="settings-feature-card-name">
          {channel.name}
          <span className="settings-type-chip">{channelType.name || channel.channel_type}</span>
          {!channel.enabled && <span style={getBadgeStyle('gray')}>DISABLED</span>}
        </div>
        <div className="settings-mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
          {channel.webhook_url.substring(0, 50)}...
        </div>
      </div>
      <div className="settings-feature-card-actions">
        <button onClick={onTest} disabled={testing} style={getActionButtonStyle('green')}>{testing ? 'Testing...' : 'Test'}</button>
        <button onClick={onEdit} style={getActionButtonStyle('purple', false)}>Edit</button>
        <button onClick={onDelete} style={getActionButtonStyle('red')}>Delete</button>
      </div>
    </div>
  );
}

// ── Approval Links Section ──
function ApprovalLinksSection({ approvalSettings, setApprovalSettings }) {
  return (
    <div className="settings-card">
      <div style={{ marginBottom: '1.25rem' }}>
        <h3 className="settings-card-title">Approval Links</h3>
        <p className="settings-card-desc">Configure settings for Yes/No approval links sent via email or chat</p>
      </div>

      <div className="settings-form-row">
        <div className="settings-form-group">
          <label className="settings-form-label">Default Link Expiration (minutes)</label>
          <input type="number" value={approvalSettings.default_ttl_minutes}
            onChange={(e) => setApprovalSettings({ ...approvalSettings, default_ttl_minutes: parseInt(e.target.value) || 60 })}
            min="5" max="10080" className="settings-form-input" />
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
            Links expire after this time. Max: 7 days (10080 minutes)
          </p>
        </div>
        <div>
          <label className="settings-checkbox" style={{ paddingTop: '1.75rem' }}>
            <input type="checkbox" checked={approvalSettings.require_auth_default}
              onChange={(e) => setApprovalSettings({ ...approvalSettings, require_auth_default: e.target.checked })}
              style={{ width: '18px', height: '18px' }} />
            <span>Require authentication by default</span>
          </label>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem', marginLeft: '26px' }}>
            If enabled, users must be logged in to use approval links
          </p>
        </div>
      </div>

      <div className="settings-security-panel">
        <div className="settings-security-title">Security Features</div>
        <ul className="settings-security-list">
          <li>Each link can only be used once (one-time use)</li>
          <li>Links automatically expire after the configured time</li>
          <li>Using one link (Yes/No) invalidates the paired link</li>
          <li>All approvals are logged with timestamp and user info</li>
        </ul>
      </div>
    </div>
  );
}

// ── Channel Modal ──
function ChannelModal({ editingChannel, newChannel, setNewChannel, channelTypes, onSave, onClose }) {
  return (
    <div className="settings-modal-overlay">
      <div className="settings-modal settings-modal--sm">
        <h3 className="settings-modal-title">{editingChannel ? 'Edit Webhook Channel' : 'Add Webhook Channel'}</h3>
        <form onSubmit={onSave}>
          <div className="settings-form-group">
            <label className="settings-form-label">Channel Name</label>
            <input type="text" value={newChannel.name} onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
              placeholder="SOC Alerts Channel" required className="settings-form-input" />
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Channel Type</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
              {channelTypes.map((type) => (
                <button key={type.id} type="button" onClick={() => setNewChannel({ ...newChannel, channel_type: type.id })}
                  className={`settings-subtab ${newChannel.channel_type === type.id ? 'settings-subtab--active' : ''}`}>
                  {type.name}
                </button>
              ))}
            </div>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Webhook URL</label>
            <input type="url" value={newChannel.webhook_url} onChange={(e) => setNewChannel({ ...newChannel, webhook_url: e.target.value })}
              placeholder="https://hooks.slack.com/services/..." required className="settings-form-input settings-mono" />
          </div>

          <div className="settings-form-group">
            <label className="settings-checkbox">
              <input type="checkbox" checked={newChannel.enabled} onChange={(e) => setNewChannel({ ...newChannel, enabled: e.target.checked })} />
              <span>Enable this channel</span>
            </label>
          </div>

          <div className="settings-modal-footer">
            <button type="button" onClick={onClose} className="settings-modal-cancel">Cancel</button>
            <button type="submit" className="button button-primary">{editingChannel ? 'Update Channel' : 'Add Channel'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Rule Modal ──
function RuleModal({ editingRule, newRule, setNewRule, recipientInput, setRecipientInput, eventTypes, severityOptions, onSave, onClose, onAddRecipient, onRemoveRecipient, onToggleEventType, onToggleSeverity }) {
  return (
    <div className="settings-modal-overlay">
      <div className="settings-modal">
        <h3 className="settings-modal-title">{editingRule ? 'Edit Notification Rule' : 'Create Notification Rule'}</h3>
        <form onSubmit={onSave}>
          <div className="settings-form-group">
            <label className="settings-form-label">Rule Name</label>
            <input type="text" value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              placeholder="Critical Alerts Notification" required className="settings-form-input" />
          </div>

          <div className="settings-form-group">
            <label className="settings-checkbox">
              <input type="checkbox" checked={newRule.enabled} onChange={(e) => setNewRule({ ...newRule, enabled: e.target.checked })} />
              <span>Enable this rule</span>
            </label>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Event Types</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
              {eventTypes.map((event) => (
                <button key={event.id} type="button" onClick={() => onToggleEventType(event.id)}
                  className={`settings-subtab ${newRule.event_types.includes(event.id) ? 'settings-subtab--active' : ''}`}
                  title={event.description}>
                  {event.name}
                </button>
              ))}
            </div>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>Leave empty to match all events</p>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Severity Filter</label>
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              {severityOptions.map((sev) => (
                <button key={sev.id} type="button" onClick={() => onToggleSeverity(sev.id)}
                  style={{
                    padding: '0.4rem 0.85rem', borderRadius: 'var(--radius-md)', fontSize: '0.8rem', fontWeight: '600', cursor: 'pointer',
                    background: newRule.severity_filter.includes(sev.id) ? `${sev.color}30` : 'var(--bg-tertiary)',
                    border: newRule.severity_filter.includes(sev.id) ? `2px solid ${sev.color}` : '2px solid var(--border-subtle)',
                    color: newRule.severity_filter.includes(sev.id) ? sev.color : 'var(--text-primary)'
                  }}>
                  {sev.name}
                </button>
              ))}
            </div>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>Leave empty to match all severities</p>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Recipients</label>
            <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.4rem' }}>
              <input type="email" value={recipientInput} onChange={(e) => setRecipientInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), onAddRecipient())}
                placeholder="email@example.com" className="settings-form-input" style={{ flex: 1 }} />
              <button type="button" onClick={onAddRecipient} style={getActionButtonStyle('green')}>+ Add</button>
            </div>
            {newRule.recipients.length > 0 && (
              <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                {newRule.recipients.map((email, idx) => (
                  <span key={idx} style={{ ...getBadgeStyle('green'), display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    {email}
                    <button type="button" onClick={() => onRemoveRecipient(email)}
                      style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0, fontSize: '0.85rem', lineHeight: 1 }}>x</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Subject Template</label>
            <input type="text" value={newRule.subject_template} onChange={(e) => setNewRule({ ...newRule, subject_template: e.target.value })}
              placeholder="[T1 Agentics] {event_type}: {title}" className="settings-form-input" />
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
              Variables: {'{event_type}'}, {'{title}'}, {'{severity}'}, {'{alert_id}'}
            </p>
          </div>

          {/* Approval Links */}
          <div className="settings-highlight-box" style={{ marginBottom: '1rem' }}>
            <div className="settings-highlight-box-title">Approval Links</div>
            <label className="settings-checkbox" style={{ marginBottom: '0.75rem' }}>
              <input type="checkbox" checked={newRule.include_approval_links}
                onChange={(e) => setNewRule({ ...newRule, include_approval_links: e.target.checked })}
                style={{ width: '18px', height: '18px' }} />
              <div>
                <span style={{ fontWeight: 500 }}>Include Approve/Reject links in email</span>
                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', margin: '0.2rem 0 0' }}>Recipients can approve or reject directly from the email</p>
              </div>
            </label>

            {newRule.include_approval_links && (
              <div style={{ marginLeft: '1.75rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div>
                  <label className="settings-form-label">Link Expiration (TTL)</label>
                  <select value={newRule.approval_ttl_minutes} onChange={(e) => setNewRule({ ...newRule, approval_ttl_minutes: parseInt(e.target.value) })}
                    className="settings-pref-select">
                    <option value={15}>15 minutes</option>
                    <option value={30}>30 minutes</option>
                    <option value={60}>1 hour</option>
                    <option value={120}>2 hours</option>
                    <option value={240}>4 hours</option>
                    <option value={480}>8 hours</option>
                    <option value={1440}>24 hours</option>
                  </select>
                </div>
                <label className="settings-checkbox">
                  <input type="checkbox" checked={newRule.approval_require_auth}
                    onChange={(e) => setNewRule({ ...newRule, approval_require_auth: e.target.checked })} />
                  <span>Require authentication to use links</span>
                </label>
                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', margin: 0 }}>Links are one-time use only. Once clicked, they cannot be reused.</p>
              </div>
            )}
          </div>

          <div className="settings-modal-footer">
            <button type="button" onClick={onClose} className="settings-modal-cancel">Cancel</button>
            <button type="submit" className="button button-primary">{editingRule ? 'Update Rule' : 'Create Rule'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NotificationSettings;
