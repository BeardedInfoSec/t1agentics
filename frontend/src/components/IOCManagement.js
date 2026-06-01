/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL } from '../utils/api';
import './IOCManagement.css';

/**
 * IOCManagement - Whitelist and IOC Submission Management
 *
 * Features:
 * - Whitelist (Do Not Enrich) management
 * - IOC submission (manual, bulk, CSV upload)
 * - Conflict detection between whitelist and blocklist
 */
function IOCManagement({ mode = 'whitelist', hideTabNavigation = false }) {
  const [activeTab, setActiveTab] = useState(mode); // 'whitelist' or 'submit'

  // Sync activeTab with mode prop when mode changes
  React.useEffect(() => {
    setActiveTab(mode);
  }, [mode]);
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Pagination
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');

  // Form states
  const [inputMode, setInputMode] = useState('single'); // 'single', 'bulk', 'csv'
  const [singleValue, setSingleValue] = useState('');
  const [bulkValues, setBulkValues] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);

  // Form options
  const [iocType, setIocType] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [category, setCategory] = useState('other');
  const [reason, setReason] = useState('');
  const [tags, setTags] = useState('');
  const [enrich, setEnrich] = useState(false);
  const [force, setForce] = useState(false);

  // Conflict modal
  const [conflictModal, setConflictModal] = useState(null);const loadWhitelist = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: '25',
        ...(search && { search })
      });

      const response = await fetch(`${API_BASE_URL}/api/v1/ioc-management/whitelist?${params}`, {
      });

      if (response.ok) {
        const data = await response.json();
        setEntries(data.entries || []);
        setTotalPages(data.pages || 1);
      }
    } catch (err) {
      setError('Failed to load whitelist');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => {
    if (activeTab === 'whitelist') {
      loadWhitelist();
    }
  }, [activeTab, loadWhitelist]);

  const handleSubmit = async (forceOverride) => {
    setError(null);
    setSuccess(null);
    setLoading(true);

    // forceOverride must be explicitly true (not an event object or other truthy value)
    const useForce = forceOverride === true;

    try {
      let endpoint, body, method = 'POST';

      if (activeTab === 'whitelist') {
        if (inputMode === 'single') {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/whitelist?force=${useForce}`;
          body = JSON.stringify({
            ioc_value: singleValue.trim(),
            ioc_type: iocType || null,
            reason,
            category,
            notes: ''
          });
        } else if (inputMode === 'bulk') {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/whitelist/bulk`;
          body = JSON.stringify({
            values: bulkValues,
            ioc_type: iocType || null,
            reason,
            category
          });
        } else if (inputMode === 'csv' && selectedFile) {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/whitelist/upload`;
          const formData = new FormData();
          formData.append('file', selectedFile);
          formData.append('category', category);
          if (reason) formData.append('reason', reason);

          const response = await fetch(endpoint, {
            method: 'POST',
            body: formData
          });
          const result = await response.json();
          handleResult(result);
          return;
        }
      } else {
        // Submit IOCs
        if (inputMode === 'single') {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/submit?force=${useForce}`;
          body = JSON.stringify({
            value: singleValue.trim(),
            ioc_type: iocType || null,
            severity,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            notes: reason,
            enrich
          });
        } else if (inputMode === 'bulk') {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/submit/bulk`;
          body = JSON.stringify({
            values: bulkValues,
            ioc_type: iocType || null,
            severity,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            notes: reason,
            enrich: false // Never bulk enrich
          });
        } else if (inputMode === 'csv' && selectedFile) {
          endpoint = `${API_BASE_URL}/api/v1/ioc-management/submit/upload`;
          const formData = new FormData();
          formData.append('file', selectedFile);
          formData.append('severity', severity);
          if (tags) formData.append('tags', tags);
          formData.append('enrich', 'false');

          const response = await fetch(endpoint, {
            method: 'POST',
            body: formData
          });
          const result = await response.json();
          handleResult(result);
          return;
        }
      }

      const response = await fetch(endpoint, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body
      });

      const result = await response.json();
      handleResult(result);

    } catch (err) {
      setError('Operation failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResult = (result) => {
    setLoading(false); // Always stop loading when we have a result
    if (result.conflict) {
      // Show conflict modal
      setConflictModal(result);
    } else if (result.success) {
      let message = activeTab === 'whitelist' ? 'Added to whitelist' : 'IOC(s) submitted';
      if (result.added !== undefined) {
        message = `${result.added} added, ${result.skipped || 0} skipped`;
        if (result.whitelisted) {
          message += `, ${result.whitelisted} whitelisted`;
        }
      }
      if (result.warning) {
        message += ` - ${result.warning}`;
      }
      setSuccess(message);
      resetForm();
      if (activeTab === 'whitelist') {
        loadWhitelist();
      }
    } else {
      setError(result.message || 'Operation failed');
    }
  };

  const handleForceSubmit = async () => {
    setConflictModal(null);
    // Re-submit with force=true passed directly
    handleSubmit(true);
  };

  const handleDelete = async (entryId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/ioc-management/whitelist/${entryId}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        loadWhitelist();
        setSuccess('Entry removed');
      }
    } catch (err) {
      setError('Failed to delete entry');
    }
  };

  const resetForm = () => {
    setSingleValue('');
    setBulkValues('');
    setSelectedFile(null);
    setReason('');
    setTags('');
  };

  const getTypeIcon = (type) => {
    const icons = {
      ip: 'IP', domain: 'DOM', url: 'URL', hash_sha256: 'SHA256', hash_sha1: 'SHA1',
      hash_md5: 'MD5', email: 'EMAIL', cve: 'CVE'
    };
    return icons[type] || type?.toUpperCase() || 'IOC';
  };

  return (
    <div className="ioc-management">
      {/* Page Header - only show if not hiding tab navigation (standalone mode) */}
      {!hideTabNavigation && (
        <div className="ioc-management-header">
          <h1 className="ioc-management-title">IOC Management</h1>
          <p className="ioc-management-subtitle">Manage whitelist and submit indicators of compromise</p>
        </div>
      )}

      {/* Tabs - only show if not hiding tab navigation */}
      {!hideTabNavigation && (
        <div className="ioc-tabs">
          <button
            className={`ioc-tab ${activeTab === 'whitelist' ? 'active' : ''}`}
            onClick={() => setActiveTab('whitelist')}
          >
            Whitelist (Do Not Enrich)
          </button>
          <button
            className={`ioc-tab ${activeTab === 'submit' ? 'active' : ''}`}
            onClick={() => setActiveTab('submit')}
          >
            Submit IOCs (Block)
          </button>
        </div>
      )}

      {/* Alerts */}
      {error && (
        <div className="ioc-alert error">
          <span>{error}</span>
          <button className="ioc-alert-close" onClick={() => setError(null)}>×</button>
        </div>
      )}
      {success && (
        <div className="ioc-alert success">
          <span>{success}</span>
          <button className="ioc-alert-close" onClick={() => setSuccess(null)}>×</button>
        </div>
      )}

      {/* Input Form Card */}
      <div className="ioc-card">
        <div className="ioc-card-header">
          <h3 className="ioc-card-title">
            {activeTab === 'whitelist' ? 'Add to Whitelist' : 'Submit IOC to Block'}
          </h3>
        </div>
        <div className="ioc-card-body">
          {/* Input Mode Toggle */}
          <div className="ioc-mode-toggle">
            <button
              className={`ioc-mode-btn ${inputMode === 'single' ? 'active' : ''}`}
              onClick={() => setInputMode('single')}
            >
              Single Entry
            </button>
            <button
              className={`ioc-mode-btn ${inputMode === 'bulk' ? 'active' : ''}`}
              onClick={() => setInputMode('bulk')}
            >
              Bulk (Paste)
            </button>
            <button
              className={`ioc-mode-btn ${inputMode === 'csv' ? 'active' : ''}`}
              onClick={() => setInputMode('csv')}
            >
              CSV Upload
            </button>
          </div>

          {/* Single Entry */}
          {inputMode === 'single' && (
            <div className="ioc-form-group">
              <label className="ioc-form-label required">IOC Value</label>
              <input
                type="text"
                className="ioc-form-input"
                placeholder="e.g., 192.168.1.1, evil.com, abc123..."
                value={singleValue}
                onChange={e => setSingleValue(e.target.value)}
              />
            </div>
          )}

          {/* Bulk Entry */}
          {inputMode === 'bulk' && (
            <div className="ioc-form-group">
              <label className="ioc-form-label required">IOC Values (one per line or comma-separated)</label>
              <textarea
                className="ioc-form-textarea"
                placeholder="192.168.1.1&#10;evil.com&#10;malware.exe&#10;..."
                value={bulkValues}
                onChange={e => setBulkValues(e.target.value)}
              />
              <div className="ioc-form-hint">Lines starting with # are ignored (comments)</div>
            </div>
          )}

          {/* CSV Upload */}
          {inputMode === 'csv' && (
            <div className="ioc-form-group">
              <label className="ioc-form-label required">Upload CSV File</label>
              <div className={`ioc-file-upload ${selectedFile ? 'has-file' : ''}`}>
                <div className="ioc-file-upload-icon">{selectedFile ? 'Done' : 'Upload'}</div>
                <div className="ioc-file-upload-text">
                  {selectedFile ? '' : 'Click or drag to upload CSV file'}
                </div>
                {selectedFile && (
                  <div className="ioc-file-upload-name">{selectedFile.name}</div>
                )}
                <input
                  type="file"
                  accept=".csv"
                  onChange={e => setSelectedFile(e.target.files[0])}
                />
              </div>
              <div className="ioc-form-hint">
                CSV format: value (required), type (optional), {activeTab === 'whitelist' ? 'reason' : 'severity'} (optional)
              </div>
            </div>
          )}

          {/* Common Options */}
          <div className="ioc-form-grid">
            <div className="ioc-form-group">
              <label className="ioc-form-label">IOC Type</label>
              <select className="ioc-form-select" value={iocType} onChange={e => setIocType(e.target.value)}>
                <option value="">Auto-detect</option>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash_sha256">SHA256 Hash</option>
                <option value="hash_sha1">SHA1 Hash</option>
                <option value="hash_md5">MD5 Hash</option>
                <option value="email">Email</option>
                <option value="cve">CVE</option>
              </select>
            </div>

            {activeTab === 'whitelist' ? (
              <div className="ioc-form-group">
                <label className="ioc-form-label">Category</label>
                <select className="ioc-form-select" value={category} onChange={e => setCategory(e.target.value)}>
                  <option value="internal">Internal Infrastructure</option>
                  <option value="trusted_vendor">Trusted Vendor</option>
                  <option value="false_positive">False Positive</option>
                  <option value="business_critical">Business Critical</option>
                  <option value="cdn_provider">CDN Provider</option>
                  <option value="security_tool">Security Tool</option>
                  <option value="other">Other</option>
                </select>
              </div>
            ) : (
              <div className="ioc-form-group">
                <label className="ioc-form-label">Severity</label>
                <select className="ioc-form-select" value={severity} onChange={e => setSeverity(e.target.value)}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            )}
          </div>

          {activeTab === 'whitelist' && (
            <div className="ioc-form-group">
              <label className="ioc-form-label required">Reason for Whitelisting</label>
              <input
                type="text"
                className="ioc-form-input"
                placeholder="e.g., Internal DNS server, Known CDN..."
                value={reason}
                onChange={e => setReason(e.target.value)}
                required
              />
            </div>
          )}

          {activeTab === 'submit' && (
            <>
              <div className="ioc-form-group">
                <label className="ioc-form-label required">Reason for Blocking</label>
                <input
                  type="text"
                  className="ioc-form-input"
                  placeholder="e.g., Known malware C2, Phishing domain, APT indicator..."
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  required
                />
              </div>
              <div className="ioc-form-group">
                <label className="ioc-form-label">Tags (comma-separated)</label>
                <input
                  type="text"
                  className="ioc-form-input"
                  placeholder="e.g., malware, phishing, apt..."
                  value={tags}
                  onChange={e => setTags(e.target.value)}
                />
              </div>
              {inputMode === 'single' && (
                <div className="ioc-form-group">
                  <label className="ioc-checkbox-label">
                    <input
                      type="checkbox"
                      checked={enrich}
                      onChange={e => setEnrich(e.target.checked)}
                    />
                    Enrich immediately after submission
                  </label>
                </div>
              )}
            </>
          )}

          <div className="ioc-form-actions">
            <button
              className="ioc-btn ioc-btn-primary"
              onClick={() => handleSubmit(false)}
              disabled={loading || !reason.trim() || (inputMode === 'single' && !singleValue) || (inputMode === 'bulk' && !bulkValues) || (inputMode === 'csv' && !selectedFile)}
            >
              {loading ? (
                <>
                  <span className="ioc-spinner"></span>
                  Processing...
                </>
              ) : (
                activeTab === 'whitelist' ? 'Add to Whitelist' : 'Submit IOC(s)'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Whitelist Table */}
      {activeTab === 'whitelist' && (
        <div className="ioc-card">
          <div className="ioc-card-header">
            <h3 className="ioc-card-title">Current Whitelist</h3>
            <div className="ioc-search">
              <span className="ioc-search-icon">Search:</span>
              <input
                type="text"
                placeholder="Search..."
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
              />
            </div>
          </div>

          {loading ? (
            <div className="ioc-empty-state">
              <div className="ioc-spinner" style={{ width: 32, height: 32, borderWidth: 3 }}></div>
              <p className="ioc-empty-state-text">Loading...</p>
            </div>
          ) : entries.length === 0 ? (
            <div className="ioc-empty-state">
              <div className="ioc-empty-state-icon">Empty</div>
              <h3 className="ioc-empty-state-title">No entries in whitelist</h3>
              <p className="ioc-empty-state-text">Add IOCs above to prevent them from being enriched</p>
            </div>
          ) : (
            <>
              <div className="ioc-table-container">
                <table className="ioc-table">
                  <thead>
                    <tr>
                      <th>IOC Value</th>
                      <th>Type</th>
                      <th>Category</th>
                      <th>Reason</th>
                      <th>Added</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map((entry, idx) => (
                      <tr key={entry.id || idx}>
                        <td>
                          <code className="ioc-table-value">{entry.ioc_value}</code>
                        </td>
                        <td>
                          <span className="ioc-table-type">
                            {getTypeIcon(entry.ioc_type)} {entry.ioc_type}
                          </span>
                        </td>
                        <td>
                          <span className={`ioc-category-badge ${entry.category || 'other'}`}>
                            {(entry.category || 'other').replace('_', ' ')}
                          </span>
                        </td>
                        <td>{entry.reason || '-'}</td>
                        <td>
                          <div className="ioc-table-meta">
                            {entry.added_by}<br />
                            {new Date(entry.created_at).toLocaleDateString()}
                          </div>
                        </td>
                        <td>
                          <button
                            className="ioc-btn ioc-btn-danger ioc-btn-sm"
                            onClick={() => handleDelete(entry.id)}
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="ioc-pagination">
                  <button
                    className="ioc-btn ioc-btn-secondary ioc-btn-sm"
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                  >
                    Previous
                  </button>
                  <span className="ioc-pagination-info">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    className="ioc-btn ioc-btn-secondary ioc-btn-sm"
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Conflict Modal */}
      {conflictModal && (
        <div className="ioc-modal-overlay" onClick={() => setConflictModal(null)}>
          <div className="ioc-modal" onClick={e => e.stopPropagation()}>
            <div className="ioc-modal-header">
              <span className="ioc-modal-icon">Warning</span>
              <h3 className="ioc-modal-title">Conflict Detected</h3>
            </div>
            <div className="ioc-modal-body">
              <p>{conflictModal.message}</p>

              {conflictModal.blocklist_entry && (
                <div className="ioc-modal-details">
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Status:</span>
                    <span className="ioc-modal-details-value">{conflictModal.blocklist_entry.reputation || 'Unknown'}</span>
                  </div>
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Severity:</span>
                    <span className="ioc-modal-details-value">{conflictModal.blocklist_entry.severity || 'Unknown'}</span>
                  </div>
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Source:</span>
                    <span className="ioc-modal-details-value">{conflictModal.blocklist_entry.source || 'Unknown'}</span>
                  </div>
                </div>
              )}

              {conflictModal.whitelist_entry && (
                <div className="ioc-modal-details">
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Whitelisted by:</span>
                    <span className="ioc-modal-details-value">{conflictModal.whitelist_entry.added_by || 'Unknown'}</span>
                  </div>
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Reason:</span>
                    <span className="ioc-modal-details-value">{conflictModal.whitelist_entry.reason || 'No reason provided'}</span>
                  </div>
                  <div className="ioc-modal-details-row">
                    <span className="ioc-modal-details-label">Category:</span>
                    <span className="ioc-modal-details-value">{conflictModal.whitelist_entry.category || 'other'}</span>
                  </div>
                </div>
              )}

              <p style={{ marginTop: '1rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                {activeTab === 'whitelist'
                  ? 'Force whitelisting will remove this IOC from the blocklist.'
                  : 'Force submitting will remove this IOC from the whitelist.'}
              </p>
            </div>

            <div className="ioc-modal-actions">
              <button
                className="ioc-btn ioc-btn-secondary"
                onClick={() => setConflictModal(null)}
              >
                Cancel
              </button>
              <button
                className="ioc-btn ioc-btn-warning"
                onClick={handleForceSubmit}
              >
                {activeTab === 'whitelist' ? 'Whitelist Anyway' : 'Block Anyway'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default IOCManagement;


