/**
 * Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { Button, Input, Select, Textarea, Card, useToast, InlineAlert } from './ui';
import { intakeFormsService } from '../data/services/intakeFormsService';
import { CheckCircle, AlertTriangle, Paperclip, X as XIcon, Upload } from 'lucide-react';

/**
 * Renders an active intake form by slug. Authenticated users in the same
 * tenant submit; the submission becomes an alert in the SOC queue.
 *
 * Field types supported in P1: text, textarea, email, url, select,
 * multiselect, datetime. file uploads are stubbed (renders disabled input).
 */
export default function IntakeFormSubmit() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const toast = useToast();

  const [form, setForm] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);

  const [values, setValues] = useState({});
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(null); // { submission_id, alert_id, message }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      try {
        const data = await intakeFormsService.getBySlug(slug);
        if (cancelled) return;
        setForm(data);
        // Initialize value state from defaults
        const init = {};
        for (const f of data.fields || []) {
          if (f.type === 'multiselect') init[f.key] = [];
          else init[f.key] = f.default ?? '';
        }
        setValues(init);
      } catch (e) {
        if (!cancelled) setLoadError(e?.response?.data?.detail || e.message || 'Form not found');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [slug]);

  const setVal = (key, val) => {
    setValues((v) => ({ ...v, [key]: val }));
    setErrors((e) => ({ ...e, [key]: null }));
  };

  const validate = () => {
    const newErrors = {};
    for (const f of form.fields || []) {
      const v = values[f.key];
      if (f.required) {
        const empty = v === undefined || v === null || v === ''
          || (Array.isArray(v) && v.length === 0);
        if (empty) {
          newErrors[f.key] = 'Required';
          continue;
        }
      }
      if (v && f.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
        newErrors[f.key] = 'Enter a valid email';
      }
      if (v && f.type === 'url') {
        try { new URL(v); } catch { newErrors[f.key] = 'Enter a valid URL (include https://)'; }
      }
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) {
      toast.error('Please fix the highlighted fields');
      return;
    }
    setSubmitting(true);
    try {
      const payload = {};
      for (const f of form.fields || []) {
        if (values[f.key] !== undefined && values[f.key] !== '') {
          payload[f.key] = values[f.key];
        }
      }
      const res = await intakeFormsService.submit(slug, payload);
      setSubmitted(res);
      toast.success('Submitted — thanks!');
    } catch (err) {
      const msg = err?.response?.data?.detail || err.message || 'Submission failed';
      toast.error(typeof msg === 'string' ? msg : 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <PageWrap><div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div></PageWrap>;
  }

  if (loadError || !form) {
    return (
      <PageWrap>
        <Card title="Form unavailable">
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', color: 'var(--text-secondary)' }}>
            <AlertTriangle size={18} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
            <div>
              <div>
                {loadError || 'This form does not exist or is not currently active. Check the link with whoever shared it with you.'}
              </div>
            </div>
          </div>
        </Card>
      </PageWrap>
    );
  }

  if (submitted) {
    return (
      <PageWrap>
        <Card>
          <div style={{ textAlign: 'center', padding: '1rem 0.5rem' }}>
            <CheckCircle size={40} style={{ color: 'var(--primary)', marginBottom: '0.75rem' }} />
            <h2 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Submission received</h2>
            <p style={{ color: 'var(--text-secondary)', marginTop: 0, marginBottom: '1.5rem' }}>
              {submitted.submit_message || form.submit_message || 'Thanks — your submission was received and is being triaged.'}
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <Button variant="primary" onClick={() => {
                setSubmitted(null);
                const init = {};
                for (const f of form.fields || []) init[f.key] = f.type === 'multiselect' ? [] : '';
                setValues(init);
              }}>
                Submit another
              </Button>
            </div>
            {submitted.alert_id && (
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '1.5rem' }}>
                Reference id: <code>{submitted.alert_id}</code>
              </div>
            )}
          </div>
        </Card>
      </PageWrap>
    );
  }

  return (
    <PageWrap>
      <Card>
        <h1 style={{ marginTop: 0, marginBottom: form.intro ? '0.5rem' : '1.5rem' }}>{form.title}</h1>
        {form.intro && (
          <div style={{ color: 'var(--text-secondary)', marginTop: 0, marginBottom: '1.5rem' }} className="intake-md">
            <ReactMarkdown>{form.intro}</ReactMarkdown>
            <style>{`
              .intake-md p { margin: 0 0 0.6rem; }
              .intake-md p:last-child { margin-bottom: 0; }
              .intake-md h1, .intake-md h2, .intake-md h3 { color: var(--text-primary); margin: 0.6rem 0 0.4rem; }
              .intake-md ul, .intake-md ol { margin: 0 0 0.6rem; padding-left: 1.5rem; }
              .intake-md a { color: var(--primary, #3CB371); text-decoration: underline; }
              .intake-md code { padding: 2px 6px; background: rgba(255,255,255,0.06); border-radius: 4px; font-size: 0.85em; }
              .intake-md strong { color: var(--text-primary); }
            `}</style>
          </div>
        )}

        <form onSubmit={onSubmit} style={{ display: 'grid', gap: '1rem' }}>
          {(form.fields || []).map((f) => (
            <FieldInput
              key={f.key}
              field={f}
              value={values[f.key]}
              error={errors[f.key]}
              onChange={(v) => setVal(f.key, v)}
              slug={slug}
            />
          ))}

          <div style={{ marginTop: '0.5rem' }}>
            <Button type="submit" variant="primary" loading={submitting} disabled={submitting}>
              Submit
            </Button>
          </div>
        </form>
      </Card>
    </PageWrap>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */

function PageWrap({ children }) {
  // Standalone layout for end-user submitters. Renders outside AppShell —
  // no SOC sidebar, no top nav. Just a minimal T1 Agentics header,
  // the form in a centered card, and clean negative space.
  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-primary, #0a0e15)',
      display: 'flex',
      flexDirection: 'column',
    }}>
      <header style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.6rem',
        padding: '1.1rem 1.5rem',
        borderBottom: '1px solid var(--border-color, rgba(148,163,184,0.12))',
      }}>
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.95rem',
          fontWeight: 700,
          letterSpacing: '0.02em',
          color: 'var(--text-primary)',
        }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%',
            background: 'var(--primary, #3CB371)',
          }} />
          T1 Agentics
        </span>
      </header>
      <main style={{
        flex: 1,
        padding: '2.5rem 1rem 3rem',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'flex-start',
      }}>
        <div style={{ width: '100%', maxWidth: '720px' }}>
          {children}
        </div>
      </main>
    </div>
  );
}

function FieldInput({ field, value, error, onChange, slug }) {
  const baseLabel = field.required ? `${field.label} *` : field.label;
  const help = field.help
    ? <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{field.help}</div>
    : null;
  const errEl = error
    ? <div style={{ fontSize: '0.78rem', color: 'var(--danger)', marginTop: '0.25rem' }}>{error}</div>
    : null;

  switch (field.type) {
    case 'textarea':
      return (
        <div>
          <Textarea
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder || ''}
            rows={4}
          />
          {help}{errEl}
        </div>
      );

    case 'email':
      return (
        <div>
          <Input
            type="email"
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder || 'you@company.com'}
          />
          {help}{errEl}
        </div>
      );

    case 'url':
      return (
        <div>
          <Input
            type="url"
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder || 'https://'}
          />
          {help}{errEl}
        </div>
      );

    case 'datetime':
      return (
        <div>
          <Input
            type="datetime-local"
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
          />
          {help}{errEl}
        </div>
      );

    case 'select':
      return (
        <div>
          <Select
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
          >
            <option value="">— Select —</option>
            {(field.options || []).map((opt) => (
              <option key={typeof opt === 'string' ? opt : opt.value} value={typeof opt === 'string' ? opt : opt.value}>
                {typeof opt === 'string' ? opt : (opt.label || opt.value)}
              </option>
            ))}
          </Select>
          {help}{errEl}
        </div>
      );

    case 'multiselect': {
      const selected = Array.isArray(value) ? value : [];
      return (
        <div>
          <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
            {baseLabel}
          </label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {(field.options || []).map((opt) => {
              const v = typeof opt === 'string' ? opt : opt.value;
              const lbl = typeof opt === 'string' ? opt : (opt.label || opt.value);
              const isOn = selected.includes(v);
              return (
                <button
                  type="button"
                  key={v}
                  onClick={() => onChange(isOn ? selected.filter((x) => x !== v) : [...selected, v])}
                  style={{
                    padding: '0.4rem 0.75rem',
                    borderRadius: 'var(--radius-full)',
                    border: `1px solid ${isOn ? 'var(--primary)' : 'var(--border-color)'}`,
                    background: isOn ? 'var(--primary-light)' : 'var(--bg-secondary)',
                    color: isOn ? 'var(--primary)' : 'var(--text-primary)',
                    fontSize: '0.85rem',
                    cursor: 'pointer',
                  }}
                >
                  {lbl}
                </button>
              );
            })}
          </div>
          {help}{errEl}
        </div>
      );
    }

    case 'file':
      return (
        <FileUploadField
          field={field}
          value={value}
          error={error}
          onChange={onChange}
          slug={slug}
          baseLabel={baseLabel}
          help={help}
          errEl={errEl}
        />
      );

    case 'text':
    default:
      return (
        <div>
          <Input
            label={baseLabel}
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder || ''}
          />
          {help}{errEl}
        </div>
      );
  }
}

/* ─────────────────────────────────────────────────────────────────────────── */

function FileUploadField({ field, value, error, onChange, slug, baseLabel, help, errEl }) {
  // `value` is the attachment_id (string) once an upload completes. We keep
  // the original filename + size locally so the UI can show what's attached
  // after upload without a separate fetch.
  const [meta, setMeta] = useState(null);   // { filename, size_bytes, content_type }
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [uploadErr, setUploadErr] = useState(null);
  const inputRef = React.useRef(null);

  const formatSize = (bytes) => {
    if (!bytes && bytes !== 0) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const onPick = async (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';  // allow re-picking the same file later
    if (!file) return;
    setUploadErr(null);
    setUploading(true);
    setProgress(0);
    try {
      const res = await intakeFormsService.uploadAttachment(
        slug,
        field.key,
        file,
        (evt) => {
          if (evt.total) setProgress(Math.round((evt.loaded / evt.total) * 100));
        },
      );
      onChange(res.attachment_id);
      setMeta({
        filename: res.filename,
        size_bytes: res.size_bytes,
        content_type: res.content_type,
      });
    } catch (err) {
      const msg = err?.response?.data?.detail || err.message || 'Upload failed';
      setUploadErr(typeof msg === 'string' ? msg : 'Upload failed');
      onChange('');
      setMeta(null);
    } finally {
      setUploading(false);
    }
  };

  const onRemove = () => {
    setMeta(null);
    setUploadErr(null);
    onChange('');
  };

  const hasUpload = !!value && !!meta;

  return (
    <div>
      <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
        {baseLabel}
      </label>

      {!hasUpload && !uploading && (
        <div
          onClick={() => inputRef.current?.click()}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.55rem',
            padding: '1.1rem',
            border: `1.5px dashed ${error || uploadErr ? 'var(--danger)' : 'var(--border-color, rgba(148,163,184,0.35))'}`,
            borderRadius: 8,
            background: 'rgba(255,255,255,0.02)',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'background 120ms, border-color 120ms',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
        >
          <Upload size={16} />
          <span style={{ fontSize: '0.88rem' }}>Click to choose a file</span>
        </div>
      )}

      {uploading && (
        <div style={{
          padding: '0.85rem 1rem',
          border: '1px solid var(--border-color, rgba(148,163,184,0.25))',
          borderRadius: 8,
          background: 'rgba(20,184,166,0.06)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <Upload size={14} style={{ color: 'var(--primary)' }} />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>Uploading… {progress}%</span>
          </div>
          <div style={{ height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${progress}%`,
              background: 'var(--primary, #3CB371)',
              transition: 'width 120ms',
            }} />
          </div>
        </div>
      )}

      {hasUpload && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.65rem',
          padding: '0.65rem 0.85rem',
          border: '1px solid var(--border-color, rgba(148,163,184,0.25))',
          borderRadius: 8,
          background: 'rgba(60,179,113,0.06)',
        }}>
          <Paperclip size={16} style={{ color: 'var(--primary)', flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: '0.88rem',
              color: 'var(--text-primary)',
              fontWeight: 500,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}>
              {meta.filename}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {formatSize(meta.size_bytes)}{meta.content_type ? ` · ${meta.content_type}` : ''}
            </div>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={onRemove}
            title="Remove this file"
          >
            <XIcon size={14} />
          </Button>
        </div>
      )}

      <input
        ref={inputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={onPick}
      />

      {uploadErr && (
        <div style={{ fontSize: '0.78rem', color: 'var(--danger)', marginTop: '0.3rem' }}>
          {uploadErr}
        </div>
      )}
      {help}{errEl}
    </div>
  );
}
