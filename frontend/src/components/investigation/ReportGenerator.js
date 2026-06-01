/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';
import { apiClient } from '../../utils/api';
import styles from './ReportGenerator.module.css';

const TEMPLATES = [
  {
    id: 'executive_summary',
    label: 'Executive Summary',
    description: 'High-level overview for leadership -- verdict, impact, and key recommendations.',
  },
  {
    id: 'detailed_technical',
    label: 'Detailed Technical',
    description: 'Full IOC table, enrichment results, MITRE mapping, timeline, and analyst notes.',
  },
  {
    id: 'incident_response',
    label: 'Incident Response',
    description: 'Timeline-focused IR report with containment actions, evidence, and lessons learned.',
  },
];

const FORMATS = [
  { id: 'markdown', label: 'Markdown' },
  { id: 'pdf', label: 'PDF' },
];

/**
 * ReportGenerator -- modal for generating investigation reports.
 *
 * @param {string}   investigationId - UUID of the current investigation
 * @param {string}   investigationTitle - Title for the filename
 * @param {boolean}  open           - Whether the modal is visible
 * @param {function} onClose        - Close the modal
 */
export default function ReportGenerator({ investigationId, investigationTitle, open, onClose }) {
  const [selectedTemplate, setSelectedTemplate] = useState('executive_summary');
  const [selectedFormat, setSelectedFormat] = useState('markdown');
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [markdownPreview, setMarkdownPreview] = useState(null);

  if (!open) return null;

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    setMarkdownPreview(null);

    try {
      if (selectedFormat === 'pdf') {
        const response = await apiClient.post(
          `/api/v1/investigations/${investigationId}/report`,
          { template: selectedTemplate, format: 'pdf' },
          { responseType: 'blob' }
        );

        // Download the PDF
        const blob = new Blob([response.data], { type: 'application/pdf' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${investigationTitle || investigationId}_${selectedTemplate}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        onClose();
      } else {
        const response = await apiClient.post(
          `/api/v1/investigations/${investigationId}/report`,
          { template: selectedTemplate, format: 'markdown' }
        );

        const markdown = response.data?.report || '';
        setMarkdownPreview(markdown);
      }
    } catch (err) {
      console.error('[ReportGenerator] error:', err);
      setError(err?.response?.data?.detail || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyMarkdown = () => {
    if (markdownPreview) {
      navigator.clipboard.writeText(markdownPreview);
    }
  };

  const handleDownloadMarkdown = () => {
    if (!markdownPreview) return;
    const blob = new Blob([markdownPreview], { type: 'text/markdown' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${investigationTitle || investigationId}_${selectedTemplate}.md`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <h3 className={styles.title}>Generate Report</h3>
          <button className={styles.closeBtn} onClick={onClose}>X</button>
        </div>

        {!markdownPreview ? (
          <>
            {/* Template Selection */}
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Template</div>
              <div className={styles.templateGrid}>
                {TEMPLATES.map((t) => (
                  <button
                    key={t.id}
                    className={`${styles.templateCard} ${selectedTemplate === t.id ? styles.templateCardActive : ''}`}
                    onClick={() => setSelectedTemplate(t.id)}
                  >
                    <div className={styles.templateName}>{t.label}</div>
                    <div className={styles.templateDesc}>{t.description}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Format Selection */}
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Format</div>
              <div className={styles.formatRow}>
                {FORMATS.map((f) => (
                  <button
                    key={f.id}
                    className={`${styles.formatBtn} ${selectedFormat === f.id ? styles.formatBtnActive : ''}`}
                    onClick={() => setSelectedFormat(f.id)}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className={styles.error}>{error}</div>
            )}

            {/* Actions */}
            <div className={styles.actions}>
              <button className={styles.cancelBtn} onClick={onClose} disabled={generating}>
                Cancel
              </button>
              <button
                className={styles.generateBtn}
                onClick={handleGenerate}
                disabled={generating}
              >
                {generating ? 'Generating...' : 'Generate Report'}
              </button>
            </div>
          </>
        ) : (
          <>
            {/* Markdown Preview */}
            <div className={styles.previewContainer}>
              <pre className={styles.previewContent}>{markdownPreview}</pre>
            </div>
            <div className={styles.actions}>
              <button className={styles.cancelBtn} onClick={() => setMarkdownPreview(null)}>
                Back
              </button>
              <button className={styles.copyBtn} onClick={handleCopyMarkdown}>
                Copy
              </button>
              <button className={styles.generateBtn} onClick={handleDownloadMarkdown}>
                Download .md
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
