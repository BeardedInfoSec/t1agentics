/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

/**
 * ConnectSetupWizard - 3-step modal wizard for installing a connector.
 * Step 1: Review connector info
 * Step 2: Configure credentials
 * Step 3: Activate and test connection
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { authFetch, API_BASE_URL } from '../../utils/api';

// SVG icons
const XIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 6L6 18" /><path d="M6 6l12 12" />
  </svg>
);

const CheckIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const CheckCircleIcon = ({ size = 32 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
    <polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

const AlertCircleIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);

const BookOpenIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
  </svg>
);

const ExternalLinkIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
  </svg>
);

const getAutoDoc = (connector) => {
  const name = connector.name || 'This connector';
  const vendor = connector.vendor && connector.vendor !== 'Generic' ? connector.vendor : name;
  const authType = connector.auth_type || 'none';

  // If the catalog entry ships vendor-specific setup_instructions, render
  // those verbatim instead of the generic auth_type blurb. The blurb is
  // factually wrong for some vendors (Discord's "Settings > Access Tokens"
  // doesn't exist) so we only fall back to it when no real docs ship.
  if (connector.setup_instructions && connector.setup_instructions.trim()) {
    const header = `${name.toUpperCase()} — SETUP GUIDE\n${'═'.repeat(42)}\n\n`;
    let body = connector.setup_instructions;
    if (connector.documentation_url) {
      body += `\n\n---\nOfficial docs: ${connector.documentation_url}`;
    }
    if (connector.base_url) {
      body += `\n\nDefault Base URL: ${connector.base_url}`;
    }
    return header + body;
  }

  const sections = [`${name.toUpperCase()} — SETUP GUIDE`, '═'.repeat(42), ''];

  switch (authType) {
    case 'api_key':
      sections.push(
        'GETTING YOUR API KEY', '',
        `1. Log into your ${vendor} account`,
        '2. Navigate to Settings > API Keys (or Developer > API)',
        '3. Create a new API key with the required permissions',
        '4. Copy the key and paste it into the API Key field below',
        '', 'Keep your API key secure — treat it like a password.',
      );
      break;
    case 'bearer':
    case 'bearer_token':
      sections.push(
        'GETTING YOUR BEARER TOKEN', '',
        `1. Log into your ${vendor} account`,
        '2. Navigate to Settings > Access Tokens or Developer',
        '3. Generate a new token with the required scopes',
        '4. Copy the token and paste it into the Token field below',
        '', 'IMPORTANT: Tokens may expire. Set a long expiry or plan to rotate.',
      );
      break;
    case 'basic':
    case 'basic_auth':
      sections.push(
        'CREDENTIALS', '',
        'Username   Your account email or login username',
        'Password   Your account password or app-specific password',
        '',
        'TIP: If multi-factor authentication (MFA) is enabled,',
        'generate an App Password instead of using your login password.',
      );
      break;
    case 'oauth2':
    case 'oauth2_client':
      sections.push(
        'OAUTH2 CLIENT CREDENTIALS SETUP', '',
        `1. Open the ${vendor} developer / admin console`,
        '2. Create a new application (type: Service Account or',
        '   Machine-to-Machine / Client Credentials)',
        '3. Note the Client ID and Client Secret',
        '4. Enter the Token URL from the vendor docs',
        '5. Set the Scopes required for the actions you need',
      );
      break;
    case 'aws':
      sections.push(
        'AWS CREDENTIALS SETUP', '',
        '1. Open the AWS IAM Console',
        '2. Create or select an IAM user/role for T1 Agentics',
        '3. Attach a policy with the required permissions',
        '4. Under Security Credentials, create an Access Key',
        '5. Note the Access Key ID and Secret Access Key',
        '6. Enter the AWS Region for your resources (e.g., us-east-1)',
      );
      break;
    default:
      sections.push(
        'CONFIGURATION', '',
        `Refer to the ${vendor} documentation for setup instructions.`,
      );
  }

  if (connector.base_url) {
    sections.push('', 'BASE URL', '', `Default: ${connector.base_url}`);
  }

  if (connector.actions && connector.actions.length > 0) {
    sections.push('', '', `AVAILABLE ACTIONS (${connector.actions.length})`, '');
    connector.actions.slice(0, 10).forEach(a => {
      const desc = a.description ? ` — ${a.description.substring(0, 55)}${a.description.length > 55 ? '...' : ''}` : '';
      sections.push(`  ${a.name}${desc}`);
    });
    if (connector.actions.length > 10) {
      sections.push(`  ...and ${connector.actions.length - 10} more`);
    }
  }

  return sections.join('\n');
};

const AUTH_TYPE_LABELS = {
  api_key: 'API Key',
  bearer: 'Bearer Token',
  bearer_token: 'Bearer Token',
  basic: 'Basic Auth',
  basic_auth: 'Basic Auth',
  oauth2_client: 'OAuth2 Client Credentials',
  oauth2: 'OAuth2',
  aws: 'AWS Credentials',
  custom_header: 'Custom Headers',
  none: 'No Authentication',
};

const STEP_LABELS = ['Review', 'Credentials', 'Activate'];

export default function ConnectSetupWizard({ connector, onComplete, onClose, credentials, onCredentialCreated }) {
  const [step, setStep] = useState(0);
  const [credMode, setCredMode] = useState('new'); // 'new' | 'existing'
  const [selectedCredId, setSelectedCredId] = useState('');
  const [credForm, setCredForm] = useState({ name: `${connector.name} Credential` });
  const [authFields, setAuthFields] = useState({});
  const [baseUrl, setBaseUrl] = useState(connector.base_url || '');
  const [testingAuth, setTestingAuth] = useState(false);
  const [authTestResult, setAuthTestResult] = useState(null);
  const [authTestPassed, setAuthTestPassed] = useState(false);
  const [activating, setActivating] = useState(false);
  const [activationSteps, setActivationSteps] = useState([]);
  const [activationDone, setActivationDone] = useState(false);
  const [activationError, setActivationError] = useState(null);
  const [showDocs, setShowDocs] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const authType = connector.auth_type || 'none';

  // Filter matching credentials
  const matchingCreds = (credentials || []).filter(c => c.auth_type === authType);

  // Auto-select existing cred if available
  useEffect(() => {
    if (matchingCreds.length > 0 && !selectedCredId) {
      setSelectedCredId(matchingCreds[0].id);
    }
  }, [matchingCreds, selectedCredId]);

  // Get credential form fields based on auth type
  const getAuthFields = () => {
    switch (authType) {
      case 'api_key':
        return [
          { key: 'api_key', label: 'API Key', type: 'password', required: true },
          {
            key: 'header_name',
            label: 'Header Name',
            type: 'text',
            placeholder: connector.auth_config?.header_name || 'Authorization',
            defaultValue: connector.auth_config?.header_name || '',
          },
        ];
      case 'bearer':
      case 'bearer_token': {
        // When the connector's auth_config declares a prefix (e.g. Discord
        // requires "Bot " in the Authorization header), warn the analyst
        // not to include it in their pasted token — the platform adds it.
        const prefix = connector.auth_config?.prefix;
        const hint = prefix
          ? `Paste the raw token only. The platform automatically adds the "${prefix.trim()}" prefix to the Authorization header. If you paste "${prefix.trim()} <token>", auth will fail with a 401.`
          : null;
        return [
          { key: 'token', label: 'Token', type: 'password', required: true, hint },
        ];
      }
      case 'basic':
      case 'basic_auth':
        return [
          { key: 'username', label: 'Username', type: 'text', required: true },
          { key: 'password', label: 'Password', type: 'password', required: true },
        ];
      case 'oauth2_client':
      case 'oauth2':
        return [
          { key: 'client_id', label: 'Client ID', type: 'text', required: true },
          { key: 'client_secret', label: 'Client Secret', type: 'password', required: true },
          {
            key: 'token_url',
            label: 'Token URL',
            type: 'text',
            required: true,
            placeholder: connector.auth_config?.token_url || '',
            defaultValue: connector.auth_config?.token_url || '',
          },
          { key: 'scope', label: 'Scope (optional)', type: 'text', required: false },
        ];
      case 'aws':
        return [
          { key: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
          { key: 'secret_access_key', label: 'Secret Access Key', type: 'password', required: true },
          { key: 'region', label: 'Region', type: 'text', required: false, placeholder: 'us-east-1', defaultValue: 'us-east-1' },
          { key: 'session_token', label: 'Session Token (optional)', type: 'password', required: false },
        ];
      case 'custom_header':
        return [
          { key: 'headers_json', label: 'Headers (JSON)', type: 'textarea', required: true, placeholder: '{"X-API-Key": "your-key"}' },
        ];
      case 'none':
      default:
        return [];
    }
  };

  const authFieldDefs = getAuthFields();

  // Initialize default values for auth fields
  useEffect(() => {
    const defaults = {};
    authFieldDefs.forEach(f => {
      if (f.defaultValue) defaults[f.key] = f.defaultValue;
    });
    if (Object.keys(defaults).length > 0) {
      setAuthFields(prev => ({ ...defaults, ...prev }));
    }
    // Only run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleAuthFieldChange = (key, value) => {
    setAuthFields(prev => ({ ...prev, [key]: value }));
    // Reset test result when credentials change
    setAuthTestPassed(false);
    setAuthTestResult(null);
  };

  // Test authentication
  const handleTestAuth = useCallback(async () => {
    setTestingAuth(true);
    setAuthTestResult(null);
    try {
      const payload = {
        base_url: baseUrl || connector.base_url || '',
        auth_type: authType,
        auth_config: connector.auth_config || {},
        temp_credential: authFields,
      };
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/test-auth`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      const passed = res.ok && data.success !== false;
      if (mountedRef.current) {
        setAuthTestResult({
          success: passed,
          message: data.message || (res.ok ? 'Authentication successful' : 'Authentication failed'),
        });
        setAuthTestPassed(passed);
      }
    } catch (err) {
      if (mountedRef.current) {
        setAuthTestResult({
          success: false,
          message: err.message || 'Authentication test failed',
        });
        setAuthTestPassed(false);
      }
    } finally {
      if (mountedRef.current) setTestingAuth(false);
    }
  }, [connector, authType, authFields, baseUrl]);

  // Are all required credential fields filled?
  const allRequiredFieldsFilled = () => {
    return authFieldDefs
      .filter(f => f.required)
      .every(f => authFields[f.key] && authFields[f.key].trim().length > 0);
  };

  // Can proceed to next step
  const canProceed = () => {
    if (step === 0) return true;
    if (step === 1) {
      if (authType === 'none') return true;
      if (credMode === 'existing') return !!selectedCredId;
      // New credential: require all fields filled AND auth test passed
      return allRequiredFieldsFilled() && authTestPassed;
    }
    return false;
  };

  // Activation process
  const handleActivate = useCallback(async () => {
    setActivating(true);
    setActivationError(null);
    setActivationDone(false);

    const steps = [];
    const updateStep = (label, status) => {
      const existing = steps.find(s => s.label === label);
      if (existing) {
        existing.status = status;
      } else {
        steps.push({ label, status });
      }
      setActivationSteps([...steps]);
    };

    try {
      let credentialId = null;

      // Step 1: Create credential (if new)
      if (authType !== 'none') {
        if (credMode === 'existing') {
          credentialId = selectedCredId;
          updateStep('Using existing credential', 'done');
        } else {
          updateStep('Creating credential...', 'active');
          const credRes = await authFetch(`${API_BASE_URL}/api/v1/connect/credentials`, {
            method: 'POST',
            body: JSON.stringify({
              name: credForm.name,
              auth_type: authType,
              secret_data: authFields,
            }),
          });

          if (!credRes.ok) {
            const errData = await credRes.json().catch(() => ({}));
            throw new Error(errData.detail || 'Failed to create credential');
          }

          const credData = await credRes.json();
          credentialId = credData.id;
          if (onCredentialCreated) onCredentialCreated(credData);
          updateStep('Creating credential...', 'done');
        }
      }

      // Step 2: Install connector instance
      updateStep('Installing connector...', 'active');
      const installPayload = {
        connector_id: connector.id,
        credential_id: credentialId,
        display_name: connector.name,
      };
      if (baseUrl) installPayload.config = { base_url: baseUrl };
      const installRes = await authFetch(`${API_BASE_URL}/api/v1/connect/instances`, {
        method: 'POST',
        body: JSON.stringify(installPayload),
      });

      if (!installRes.ok) {
        const errData = await installRes.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to install connector');
      }

      const instanceData = await installRes.json();
      updateStep('Installing connector...', 'done');

      // Step 3: Test connection
      updateStep('Testing connection...', 'active');
      try {
        const testRes = await authFetch(`${API_BASE_URL}/api/v1/connect/instances/${instanceData.id}/test`, {
          method: 'POST',
        });
        const testData = await testRes.json();
        if (testRes.ok && testData.success !== false) {
          updateStep('Testing connection...', 'done');
        } else {
          updateStep('Testing connection...', 'done');
          // Non-fatal: connection created but test may fail
        }
      } catch {
        updateStep('Testing connection...', 'done');
      }

      // Step 4: Enable instance
      updateStep('Enabling connection...', 'active');
      try {
        await authFetch(`${API_BASE_URL}/api/v1/connect/instances/${instanceData.id}/toggle`, {
          method: 'POST',
        });
      } catch {
        // Non-fatal
      }
      updateStep('Enabling connection...', 'done');

      if (mountedRef.current) {
        setActivationDone(true);
      }
    } catch (err) {
      if (mountedRef.current) {
        setActivationError(err.message || 'Activation failed');
        // Mark current active step as error
        const activeStep = steps.find(s => s.status === 'active');
        if (activeStep) {
          activeStep.status = 'error';
          setActivationSteps([...steps]);
        }
      }
    } finally {
      if (mountedRef.current) setActivating(false);
    }
  }, [authType, credMode, selectedCredId, credForm.name, authFields, baseUrl, connector, onCredentialCreated]);

  // Render step content
  const renderStepContent = () => {
    switch (step) {
      case 0:
        return renderReviewStep();
      case 1:
        return renderCredentialsStep();
      case 2:
        return renderActivateStep();
      default:
        return null;
    }
  };

  // Step 1: Review
  const renderReviewStep = () => (
    <div className="wizard-connector-info">
      <div className="wizard-connector-detail">
        <span className="wizard-connector-detail-label">Connector</span>
        <span className="wizard-connector-detail-value">{connector.name}</span>
      </div>
      <div className="wizard-connector-detail">
        <span className="wizard-connector-detail-label">Vendor</span>
        <span className="wizard-connector-detail-value">{connector.vendor || 'Community'}</span>
      </div>
      <div className="wizard-connector-detail">
        <span className="wizard-connector-detail-label">Category</span>
        <span className="wizard-connector-detail-value">{connector.category || 'General'}</span>
      </div>
      <div className="wizard-connector-detail">
        <span className="wizard-connector-detail-label">Authentication</span>
        <span className="wizard-connector-detail-value">{AUTH_TYPE_LABELS[authType] || authType}</span>
      </div>
      <div className="wizard-connector-detail">
        <span className="wizard-connector-detail-label">Actions Available</span>
        <span className="wizard-connector-detail-value">
          {connector.action_count || (connector.actions && connector.actions.length) || 0}
        </span>
      </div>
      {connector.description && (
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary, #8b949e)', lineHeight: 1.6, margin: '0.5rem 0 0' }}>
          {connector.description}
        </p>
      )}
    </div>
  );

  // Step 2: Credentials
  const renderCredentialsStep = () => {
    if (authType === 'none') {
      return (
        <div style={{ textAlign: 'center', padding: '2rem 0' }}>
          <p style={{ color: 'var(--text-secondary, #8b949e)', fontSize: '0.9rem' }}>
            This connector does not require authentication.
          </p>
        </div>
      );
    }

    return (
      <div data-tour="connect-credentials-form">
        {/* Choose existing or new */}
        {matchingCreds.length > 0 && (
          <div className="wizard-cred-section">
            <h4 className="wizard-cred-section-title">Choose Credential</h4>
            <div
              className={`wizard-cred-option ${credMode === 'existing' ? 'selected' : ''}`}
              onClick={() => setCredMode('existing')}
            >
              <input
                type="radio"
                name="credMode"
                checked={credMode === 'existing'}
                onChange={() => setCredMode('existing')}
              />
              <span className="wizard-cred-option-label">Use existing credential</span>
            </div>
            <div
              className={`wizard-cred-option ${credMode === 'new' ? 'selected' : ''}`}
              onClick={() => setCredMode('new')}
            >
              <input
                type="radio"
                name="credMode"
                checked={credMode === 'new'}
                onChange={() => setCredMode('new')}
              />
              <span className="wizard-cred-option-label">Create new credential</span>
            </div>
          </div>
        )}

        {/* Existing credential dropdown */}
        {credMode === 'existing' && matchingCreds.length > 0 && (
          <div className="wizard-cred-section">
            <div className="connect-form-group">
              <label className="connect-form-label">Select Credential</label>
              <select
                className="connect-select"
                value={selectedCredId}
                onChange={e => setSelectedCredId(e.target.value)}
              >
                {matchingCreds.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
          </div>
        )}

        {/* New credential form */}
        {credMode === 'new' && (
          <div className="wizard-cred-section">
            <h4 className="wizard-cred-section-title">New Credential</h4>
            <div className="connect-form-group" style={{ marginBottom: '0.75rem' }}>
              <label className="connect-form-label">Credential Name</label>
              <input
                className="connect-input"
                type="text"
                value={credForm.name}
                onChange={e => setCredForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., My VirusTotal Key"
              />
            </div>

            {/* Base URL (shown when connector has a configurable base URL or none set) */}
            <div className="connect-form-group" style={{ marginBottom: '0.75rem' }}>
              <label className="connect-form-label">Base URL</label>
              <input
                className="connect-input"
                type="text"
                value={baseUrl}
                onChange={e => { setBaseUrl(e.target.value); setAuthTestPassed(false); setAuthTestResult(null); }}
                placeholder={connector.base_url || 'https://api.example.com'}
              />
              {connector.base_url && (
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary, #6e7681)', marginTop: '0.25rem', display: 'block' }}>
                  Default: {connector.base_url}
                </span>
              )}
            </div>

            {authFieldDefs.map(field => (
              <div key={field.key} className="connect-form-group" style={{ marginBottom: '0.75rem' }}>
                <label className="connect-form-label">
                  {field.label}
                  {field.required && <span style={{ color: 'var(--accent-red, #ef4444)' }}> *</span>}
                </label>
                {field.type === 'textarea' ? (
                  <textarea
                    className="connect-textarea"
                    value={authFields[field.key] || ''}
                    onChange={e => handleAuthFieldChange(field.key, e.target.value)}
                    placeholder={field.placeholder || ''}
                    rows={3}
                  />
                ) : (
                  <input
                    className={`connect-input ${field.type === 'password' ? 'mono' : ''}`}
                    type={field.type}
                    value={authFields[field.key] || ''}
                    onChange={e => handleAuthFieldChange(field.key, e.target.value)}
                    placeholder={field.placeholder || ''}
                  />
                )}
                {field.hint && (
                  <div style={{
                    marginTop: '0.4rem',
                    padding: '0.5rem 0.65rem',
                    fontSize: '0.78rem',
                    color: 'var(--text-secondary, #8b949e)',
                    background: 'rgba(60, 179, 113, 0.06)',
                    border: '1px solid rgba(60, 179, 113, 0.18)',
                    borderRadius: '6px',
                    lineHeight: 1.45,
                  }}>
                    {field.hint}
                  </div>
                )}
              </div>
            ))}

            {/* Test Authentication — required before proceeding */}
            <div style={{
              marginTop: '1.25rem',
              padding: '1rem',
              background: 'var(--bg-tertiary, #151b23)',
              border: `1px solid ${authTestPassed ? 'var(--accent-green, #10b981)' : 'var(--border-subtle, rgba(148, 163, 184, 0.12))'}`,
              borderRadius: '8px',
            }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary, #8b949e)', marginBottom: '0.75rem' }}>
                Test your credentials before proceeding. Authentication must pass to continue.
              </div>
              <button
                className={`connect-btn ${authTestPassed ? 'connect-btn-success' : 'connect-btn-primary'}`}
                onClick={handleTestAuth}
                disabled={testingAuth || !allRequiredFieldsFilled()}
                style={{ width: '100%', padding: '0.65rem 1rem', fontSize: '0.9rem', fontWeight: 600 }}
                data-tour={authTestPassed ? 'connect-test-success' : 'connect-test-button'}
              >
                {testingAuth ? (
                  <>
                    <span className="connect-spinner sm" style={{ marginRight: '0.5rem' }} />
                    Testing...
                  </>
                ) : authTestPassed ? (
                  <>
                    <CheckIcon size={16} />
                    <span style={{ marginLeft: '0.5rem' }}>Authentication Passed — Re-test</span>
                  </>
                ) : (
                  'Test Authentication'
                )}
              </button>
              {authTestResult && (
                <div style={{
                  marginTop: '0.75rem',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  background: authTestResult.success
                    ? 'rgba(16, 185, 129, 0.1)'
                    : 'rgba(239, 68, 68, 0.1)',
                  color: authTestResult.success
                    ? 'var(--accent-green, #10b981)'
                    : 'var(--accent-red, #ef4444)',
                  border: `1px solid ${authTestResult.success ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                }}>
                  {authTestResult.success ? <CheckIcon size={14} /> : <AlertCircleIcon size={14} />}
                  <span>{authTestResult.message}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  // Step 3: Activate
  const renderActivateStep = () => {
    if (activationDone) {
      return (
        <div className="wizard-success-message">
          <div className="wizard-success-icon">
            <CheckCircleIcon size={32} />
          </div>
          <h3>Connection Active!</h3>
          <p>{connector.name} has been installed and is ready to use.</p>
        </div>
      );
    }

    return (
      <div>
        {!activating && activationSteps.length === 0 && !activationError && (
          <div style={{ textAlign: 'center', padding: '1rem 0' }}>
            <h4 style={{ margin: '0 0 0.75rem', color: 'var(--text-primary, #f0f6fc)' }}>Ready to Activate</h4>
            <p style={{ color: 'var(--text-secondary, #8b949e)', fontSize: '0.85rem', margin: '0 0 1.5rem' }}>
              This will create and configure your {connector.name} connection.
            </p>
            <div style={{
              background: 'var(--bg-tertiary, #151b23)',
              border: '1px solid var(--border-subtle, rgba(148, 163, 184, 0.12))',
              borderRadius: '8px',
              padding: '1rem',
              textAlign: 'left',
              fontSize: '0.8rem',
              color: 'var(--text-secondary, #8b949e)',
            }}>
              <div style={{ marginBottom: '0.35rem' }}>
                {authType !== 'none'
                  ? (credMode === 'existing' ? 'Use existing credential' : `Create credential: "${credForm.name}"`)
                  : 'No credential needed'}
              </div>
              <div style={{ marginBottom: '0.35rem' }}>Install {connector.name} connector</div>
              <div style={{ marginBottom: '0.35rem' }}>Test connection</div>
              <div>Enable connector</div>
            </div>
          </div>
        )}

        {/* Activation progress */}
        {activationSteps.length > 0 && (
          <div className="wizard-activation-progress">
            {activationSteps.map((s, i) => (
              <div key={i} className={`wizard-activation-step ${s.status}`}>
                <span className="wizard-activation-icon">
                  {s.status === 'active' && <span className="connect-spinner sm" />}
                  {s.status === 'done' && <CheckIcon size={14} />}
                  {s.status === 'error' && <XIcon size={14} />}
                </span>
                <span>{s.label.replace('...', s.status === 'done' ? '' : '...')}</span>
              </div>
            ))}
          </div>
        )}

        {/* Error */}
        {activationError && (
          <div className="connect-error" style={{ marginTop: '1rem' }}>
            <AlertCircleIcon size={14} />
            <span>{activationError}</span>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="wizard-overlay" onClick={onClose}>
      <div className="wizard-layout" onClick={e => e.stopPropagation()}>
      <div className="wizard-modal" data-tour="connect-wizard-modal">
        {/* Header */}
        <div className="wizard-modal-header">
          <h2>Install {connector.name}</h2>
          <div className="wizard-header-actions">
            <button
              className={`wizard-docs-btn${showDocs ? ' active' : ''}`}
              onClick={() => setShowDocs(s => !s)}
              title="Setup documentation"
            >
              <BookOpenIcon size={14} />
              <span>Docs</span>
            </button>
            <button className="wizard-close" onClick={onClose}>
              <XIcon size={18} />
            </button>
          </div>
        </div>

        {/* Step indicators */}
        <div className="wizard-steps">
          {STEP_LABELS.map((label, i) => (
            <React.Fragment key={label}>
              {i > 0 && (
                <div className={`wizard-step-connector ${step > i - 1 ? 'completed' : ''}`} />
              )}
              <div className={`wizard-step ${step === i ? 'active' : ''} ${step > i ? 'completed' : ''}`}>
                <span className="wizard-step-number">
                  {step > i ? <CheckIcon size={12} /> : i + 1}
                </span>
                <span className="wizard-step-label">{label}</span>
              </div>
            </React.Fragment>
          ))}
        </div>

        {/* Content */}
        <div className="wizard-content">
          {renderStepContent()}
        </div>

        {/* Footer */}
        <div className="wizard-footer">
          <div className="wizard-footer-left">
            {step === 1 && credMode === 'new' && authType !== 'none' && !authTestPassed && allRequiredFieldsFilled() && (
              <span style={{ fontSize: '0.75rem', color: 'var(--accent-yellow, #f59e0b)' }}>
                Test authentication to continue
              </span>
            )}
          </div>
          <div className="wizard-footer-right">
            {step > 0 && step < 2 && !activating && (
              <button
                className="connect-btn connect-btn-outline"
                onClick={() => setStep(s => s - 1)}
              >
                Back
              </button>
            )}

            {step < 2 && (
              <button
                className="connect-btn connect-btn-primary"
                disabled={!canProceed()}
                onClick={() => setStep(s => s + 1)}
                data-tour="connect-wizard-next"
              >
                Next
              </button>
            )}

            {step === 2 && !activationDone && !activating && (
              <button
                className="connect-btn connect-btn-success"
                onClick={handleActivate}
                disabled={activating}
                data-tour="connect-save-button"
              >
                {activationError ? 'Try Again' : 'Activate Connection'}
              </button>
            )}

            {step === 2 && activationDone && (
              <button
                className="connect-btn connect-btn-primary"
                onClick={onComplete}
              >
                Done
              </button>
            )}

            {step === 2 && activating && (
              <button className="connect-btn connect-btn-outline" disabled>
                <span className="connect-spinner sm" />
                Activating...
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Documentation panel — rendered beside the modal, not inside it */}
      {showDocs && (
        <div className="wizard-docs-panel">
          <div className="wizard-docs-panel-header">
            <div className="wizard-docs-panel-title">
              <BookOpenIcon size={14} />
              <span>{connector.name} — Setup Guide</span>
            </div>
            <button className="wizard-close" onClick={() => setShowDocs(false)}>
              <XIcon size={16} />
            </button>
          </div>
          <div className="wizard-docs-panel-body">
            <pre className="wizard-docs-text">
              {connector.setup_doc || getAutoDoc(connector)}
            </pre>
          </div>
          {connector.documentation_url && (
            <div className="wizard-docs-panel-footer">
              <a
                href={connector.documentation_url}
                target="_blank"
                rel="noreferrer"
                className="wizard-docs-external-link"
              >
                <ExternalLinkIcon size={12} />
                Official documentation
              </a>
            </div>
          )}
        </div>
      )}
      </div>
    </div>
  );
}
