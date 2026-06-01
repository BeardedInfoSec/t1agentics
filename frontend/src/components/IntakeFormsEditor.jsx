/**
 * Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { Button, Input, Select, Textarea, useToast, InlineAlert, Badge } from './ui';
import { intakeFormsService } from '../data/services/intakeFormsService';
import {
  ArrowLeft, ArrowUp, ArrowDown, Trash2, Plus, Copy, Eye,
  Type, AlignLeft, Mail, Link as LinkIcon, ChevronDown,
  ChevronRight,
  ListChecks, Calendar, Paperclip, GripVertical, Zap,
  Sparkles, X as XIcon,
} from 'lucide-react';

const FIELD_TYPES = [
  { value: 'text',        label: 'Single-line text',  icon: Type,        accent: '#34d399' },
  { value: 'textarea',    label: 'Multi-line text',   icon: AlignLeft,   accent: '#5eead4' },
  { value: 'email',       label: 'Email',             icon: Mail,        accent: '#a78bfa' },
  { value: 'url',         label: 'URL',               icon: LinkIcon,    accent: '#a78bfa' },
  { value: 'select',      label: 'Dropdown (single)', icon: ChevronDown, accent: '#fbbf24' },
  { value: 'multiselect', label: 'Dropdown (multi)',  icon: ListChecks,  accent: '#fbbf24' },
  { value: 'datetime',    label: 'Date / time',       icon: Calendar,    accent: '#34d399' },
  { value: 'file',        label: 'File upload',       icon: Paperclip,   accent: '#94a3b8' },
];
const TYPE_META = Object.fromEntries(FIELD_TYPES.map((t) => [t.value, t]));
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const slugifyKey = (label) =>
  (label || '')
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, '')
    .trim()
    .replace(/\s+/g, '_')
    .replace(/^[^a-z]+/, '')
    .slice(0, 40);

const blankField = () => ({
  key: '', label: '', type: 'text', required: false,
  help: '', placeholder: '', options: [],
});

const blankForm = () => ({
  name: '', description: '', title: '', intro: '', submit_message: '',
  fields: [],
  alert_template: { title: '', description: '', severity: 'medium', source: 'intake_form', category: '' },
  status: 'draft',
  triage_strategy: 'enrich',
  auto_trigger_playbook_id: null,
});

const renderTemplate = (tpl, payload) => {
  if (!tpl) return '';
  return tpl.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key) => {
    const v = payload?.[key];
    if (Array.isArray(v)) return v.join(', ');
    return v == null || v === '' ? `{{${key}}}` : String(v);
  });
};

/* ─────────────────────────────────────────────────────────────────────────── */

export default function IntakeFormsEditor() {
  const { id } = useParams();
  const isNew = !id || id === 'new';
  const navigate = useNavigate();
  const toast = useToast();

  const [form, setForm] = useState(blankForm());
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [validationError, setValidationError] = useState(null);
  const [slug, setSlug] = useState('');
  const [activeFieldIdx, setActiveFieldIdx] = useState(null);

  // "Build with Riggs" — AI-generated form drafting. Open by default for
  // new forms (highest-leverage moment to discover the feature); closed for
  // edits of existing forms (the user already has a draft).
  const [riggsOpen, setRiggsOpen] = useState(isNew);
  const [riggsPrompt, setRiggsPrompt] = useState('');
  const [riggsLoading, setRiggsLoading] = useState(false);

  // Section collapse state. Default open for new forms (the user needs to
  // fill these in); default collapsed for existing forms (the user is
  // most likely tweaking fields, the setup is already done).
  const [sectionCollapse, setSectionCollapse] = useState({
    identify:  !isNew,
    submitter: !isNew,
    alert:     !isNew,
  });
  const toggleSection = (key) =>
    setSectionCollapse((s) => ({ ...s, [key]: !s[key] }));

  // True when the editor has user-meaningful content. Distinguishes "design
  // from scratch" from "modify what's there" mode for the Riggs panel.
  const hasExistingDraft = (
    form.fields.length > 0 ||
    !!form.name?.trim() ||
    !!form.title?.trim()
  );

  const handleGenerateWithRiggs = async () => {
    const desc = riggsPrompt.trim();
    if (desc.length < 10) {
      toast.error('Give Riggs a bit more to work with — at least a sentence.');
      return;
    }
    setRiggsLoading(true);
    try {
      // Pass current form when in modify mode so Riggs preserves the parts
      // the user isn't asking to change. Pure-create mode sends just the
      // description.
      const currentForm = hasExistingDraft ? form : null;
      const res = await intakeFormsService.generateWithRiggs(desc, currentForm);
      const draft = res?.form;
      if (!draft) throw new Error('No form returned');
      setForm((prev) => ({
        name:           draft.name           || '',
        description:    draft.description    || '',
        title:          draft.title          || '',
        intro:          draft.intro          || '',
        submit_message: draft.submit_message || '',
        fields:         Array.isArray(draft.fields) ? draft.fields : [],
        alert_template: {
          title:       draft.alert_template?.title       || '',
          description: draft.alert_template?.description || '',
          severity:    draft.alert_template?.severity    || 'medium',
          source:      draft.alert_template?.source      || 'intake_form',
          category:    draft.alert_template?.category    || '',
        },
        status: 'draft',
        // Preserve any triage config the user already set in this session;
        // Riggs's drafting flow doesn't touch these fields.
        triage_strategy: prev.triage_strategy || 'enrich',
        auto_trigger_playbook_id: prev.auto_trigger_playbook_id || null,
      }));
      setValidationError(null);
      setRiggsOpen(false);
      setRiggsPrompt('');
      if (res?.warning) {
        toast.error(res.warning);
      } else {
        const verb = currentForm ? 'updated' : 'drafted';
        toast.success(`Riggs ${verb} a ${draft.fields?.length || 0}-field form. Review and refine before saving.`);
      }
    } catch (e) {
      const msg = e?.response?.data?.detail || e.message || 'Generation failed';
      toast.error(typeof msg === 'string' ? msg : 'Riggs could not generate a form right now.');
    } finally {
      setRiggsLoading(false);
    }
  };

  const load = useCallback(async () => {
    if (isNew) return;
    setLoading(true);
    try {
      const data = await intakeFormsService.get(id);
      setForm({
        name:           data.name || '',
        description:    data.description || '',
        title:          data.title || '',
        intro:          data.intro || '',
        submit_message: data.submit_message || '',
        fields:         Array.isArray(data.fields) ? data.fields : [],
        alert_template: {
          title:       data.alert_template?.title       || '',
          description: data.alert_template?.description || '',
          severity:    data.alert_template?.severity    || 'medium',
          source:      data.alert_template?.source      || 'intake_form',
          category:    data.alert_template?.category    || '',
        },
        status: data.status || 'draft',
        triage_strategy: data.triage_strategy || 'enrich',
        auto_trigger_playbook_id: data.auto_trigger_playbook_id || null,
      });
      setSlug(data.slug || '');
    } catch (e) {
      setLoadError(e.message || 'Failed to load form');
    } finally {
      setLoading(false);
    }
  }, [id, isNew]);

  useEffect(() => { load(); }, [load]);

  const updateField = (idx, patch) => {
    setForm((f) => ({
      ...f,
      fields: f.fields.map((fld, i) => (i === idx ? { ...fld, ...patch } : fld)),
    }));
  };

  const addField = (type = 'text') => {
    // Add the field but DON'T auto-expand it. Auto-expanding caused the
    // sections below to shift downward + the page to jump as the user was
    // still in the type picker. The user can click the new field to expand.
    setForm((f) => ({ ...f, fields: [...f.fields, { ...blankField(), type }] }));
    setActiveFieldIdx(null);
  };

  const removeField = (idx) => {
    setForm((f) => ({ ...f, fields: f.fields.filter((_, i) => i !== idx) }));
    if (activeFieldIdx === idx) setActiveFieldIdx(null);
  };

  const moveField = (idx, dir) => {
    setForm((f) => {
      const next = [...f.fields];
      const j = idx + dir;
      if (j < 0 || j >= next.length) return f;
      [next[idx], next[j]] = [next[j], next[idx]];
      return { ...f, fields: next };
    });
    // Keep the selection following the moved field so the properties
    // panel doesn't suddenly show a different field after a reorder.
    setActiveFieldIdx((cur) => {
      if (cur === null) return null;
      if (cur === idx) return idx + dir;
      if (cur === idx + dir) return idx;
      return cur;
    });
  };

  const validate = () => {
    if (!form.name.trim())  return 'Form name is required';
    if (!form.title.trim()) return 'Submitter-facing title is required';
    const keys = new Set();
    for (const fld of form.fields) {
      if (!fld.key)   return 'A field is missing its key';
      if (!/^[a-z][a-z0-9_]*$/.test(fld.key)) return `Field key "${fld.key}" must be snake_case`;
      if (!fld.label) return `Field "${fld.key}" needs a label`;
      if (keys.has(fld.key)) return `Duplicate field key: ${fld.key}`;
      keys.add(fld.key);
      if ((fld.type === 'select' || fld.type === 'multiselect') && (!fld.options || fld.options.length === 0)) {
        return `Field "${fld.key}" (${fld.type}) needs at least one option`;
      }
    }
    return null;
  };

  const save = async (statusOverride) => {
    setValidationError(null);
    const err = validate();
    if (err) { setValidationError(err); return; }
    const payload = {
      ...form,
      status: statusOverride || form.status,
      fields: form.fields.map((f) => {
        const cleaned = { ...f };
        if (f.type === 'select' || f.type === 'multiselect') {
          cleaned.options = (f.options || []).map((o) => (typeof o === 'string' ? o : o.value)).filter(Boolean);
        } else {
          delete cleaned.options;
        }
        return cleaned;
      }),
    };
    setSaving(true);
    try {
      let result;
      if (isNew) {
        result = await intakeFormsService.create(payload);
        toast.success(`Form "${result.name}" created`);
        navigate(`/admin/intake-forms/${result.id}`, { replace: true });
      } else {
        result = await intakeFormsService.update(id, payload);
        toast.success(`Form "${result.name}" saved`);
        setForm((f) => ({ ...f, status: result.status }));
        setSlug(result.slug || slug);
      }
    } catch (e) {
      const msg = e?.response?.data?.detail || e.message || 'Save failed';
      setValidationError(typeof msg === 'string' ? msg : 'Save failed');
      toast.error('Could not save form');
    } finally {
      setSaving(false);
    }
  };

  const handleCopyLink = () => {
    if (!slug) return;
    const url = `${window.location.origin}/intake/${slug}`;
    navigator.clipboard.writeText(url).then(
      () => toast.success('Submit link copied'),
      () => toast.error('Could not copy to clipboard')
    );
  };

  /* ── Live preview values: synthesize a sample payload for templates ────── */
  const samplePayload = useMemo(() => {
    const p = {};
    for (const f of form.fields) {
      if (!f.key) continue;
      p[f.key] = previewSampleValue(f);
    }
    return p;
  }, [form.fields]);

  if (loading) {
    return <PageShell title="Intake form"><LoadingState /></PageShell>;
  }
  if (loadError) {
    return (
      <PageShell title="Intake form">
        <InlineAlert variant="error">{loadError}</InlineAlert>
        <div style={{ marginTop: '1rem' }}>
          <Button variant="ghost" onClick={() => navigate('/admin/intake-forms')}>
            <ArrowLeft size={14} /> Back to list
          </Button>
        </div>
      </PageShell>
    );
  }

  const statusVariant = form.status === 'active' ? 'success' : form.status === 'archived' ? 'default' : 'warning';

  return (
    <PageShell
      title={isNew ? 'New Intake Form' : (form.name || 'Untitled')}
      subtitleSlot={
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <Badge variant={statusVariant}>{form.status}</Badge>
          {!isNew && slug && (
            <code style={{ fontSize: '0.78rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary, rgba(255,255,255,0.04))', padding: '2px 8px', borderRadius: 6 }}>
              /intake/{slug}
            </code>
          )}
          {form.fields.length > 0 && (
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {form.fields.length} field{form.fields.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
      }
      actions={
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Button variant="ghost" onClick={() => navigate('/admin/intake-forms')}>
            <ArrowLeft size={14} /> Back
          </Button>
          {!riggsOpen && (
            <Button
              variant="secondary"
              onClick={() => setRiggsOpen(true)}
              title={hasExistingDraft ? 'Let Riggs modify this form per a natural-language request' : 'Let Riggs draft this form from a description'}
            >
              <Sparkles size={14} /> {hasExistingDraft ? 'Edit with Riggs' : 'Build with Riggs'}
            </Button>
          )}
          {!isNew && slug && form.status === 'active' && (
            <Button variant="secondary" onClick={handleCopyLink}>
              <Copy size={14} /> Copy link
            </Button>
          )}
          {!isNew && form.status !== 'active' && (
            <Button variant="primary" onClick={() => save('active')} loading={saving}>
              <Zap size={14} /> Activate
            </Button>
          )}
          {!isNew && form.status === 'active' && (
            <Button variant="secondary" onClick={() => save('draft')} loading={saving}>
              Set to draft
            </Button>
          )}
          <Button variant="primary" onClick={() => save()} loading={saving}>
            {isNew ? 'Create form' : 'Save'}
          </Button>
        </div>
      }
    >
      {validationError && (
        <div style={{ marginBottom: '1rem' }}>
          <InlineAlert variant="error">{validationError}</InlineAlert>
        </div>
      )}

      {/* ── Build with Riggs panel ─────────────────────────────────────────── */}
      {riggsOpen && (
        <div style={{
          marginBottom: '1rem',
          background: 'linear-gradient(135deg, rgba(60,179,113,0.10) 0%, rgba(20,184,166,0.06) 100%)',
          border: '1px solid rgba(60,179,113,0.35)',
          borderRadius: 12,
          padding: '1rem 1.15rem',
          position: 'relative',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '0.65rem' }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: 'rgba(60,179,113,0.18)',
              color: 'var(--primary, #3CB371)',
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
            }}>
              <Sparkles size={16} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.95rem' }}>
                {hasExistingDraft ? 'Edit with Riggs' : 'Let Riggs draft this for you'}
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                {hasExistingDraft
                  ? 'Tell Riggs what to change. Existing fields and copy that aren’t affected by your request stay put.'
                  : 'Describe what the form is for and what info the SOC needs. Riggs picks the fields, writes the labels, and drafts the alert template. You refine before saving.'}
              </div>
            </div>
            <Button variant="ghost" size="xs" onClick={() => setRiggsOpen(false)} title="Close">
              <XIcon size={14} />
            </Button>
          </div>
          <Textarea
            value={riggsPrompt}
            onChange={(e) => setRiggsPrompt(e.target.value)}
            rows={3}
            placeholder={hasExistingDraft
              ? 'e.g. "Add a checkbox for urgency. Remove the optional notes field. Make the title shorter."'
              : 'e.g. "A form for employees to report suspicious emails. Capture the sender, subject, full email body, attached files, and whether they clicked any links."'}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.65rem', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {hasExistingDraft && 'Riggs keeps the parts of the form you didn’t ask to change.'}
            </div>
            <Button
              variant="primary"
              onClick={handleGenerateWithRiggs}
              loading={riggsLoading}
              disabled={riggsLoading || riggsPrompt.trim().length < 10}
            >
              <Sparkles size={14} /> {riggsLoading ? (hasExistingDraft ? 'Updating…' : 'Generating…') : (hasExistingDraft ? 'Apply changes' : 'Generate form')}
            </Button>
          </div>
        </div>
      )}

      {/* ── Two-pane layout: editor + live preview ────────────────────────── */}
      <div className="intake-grid">
        {/* LEFT PANE: editor */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', minWidth: 0 }}>
          <Section
            stepNum={1}
            title="Identify the form"
            subtitle="Internal name and description for admins. Submitter doesn't see these."
            collapsible
            collapsed={sectionCollapse.identify}
            onToggleCollapsed={() => toggleSection('identify')}
            summary={
              form.name?.trim()
                ? `${form.name} · ${form.status}`
                : 'not yet named'
            }
          >
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <Input
                label="Internal name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Phishing Report"
              />
              <Select
                label="Status"
                value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}
              >
                <option value="draft">Draft (not accepting submissions)</option>
                <option value="active">Active (accepting submissions)</option>
                <option value="archived">Archived</option>
              </Select>
            </div>
            <div style={{ marginTop: '0.85rem' }}>
              <Textarea
                label="Description (admin-only)"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={2}
                placeholder="What is this form for? Who should see it?"
              />
            </div>
          </Section>

          <Section
            stepNum={2}
            title="What submitters see"
            subtitle="The headline, blurb, and confirmation message your users read."
            collapsible
            collapsed={sectionCollapse.submitter}
            onToggleCollapsed={() => toggleSection('submitter')}
            summary={
              form.title?.trim()
                ? `"${form.title.length > 50 ? form.title.slice(0, 47) + '…' : form.title}"`
                : 'no title yet'
            }
          >
            <Input
              label="Title"
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
              placeholder="e.g. Report a Suspicious Email"
            />
            <div style={{ marginTop: '0.85rem' }}>
              <Textarea
                label="Intro (markdown OK)"
                value={form.intro}
                onChange={(e) => setForm({ ...form, intro: e.target.value })}
                rows={2}
                placeholder="Optional context shown above the fields"
              />
            </div>
            <div style={{ marginTop: '0.85rem' }}>
              <Input
                label="Confirmation after submit"
                value={form.submit_message}
                onChange={(e) => setForm({ ...form, submit_message: e.target.value })}
                placeholder="Thanks — your report was received and is being triaged."
              />
            </div>
          </Section>

          {/* ── Fields builder ────────────────────────────────────────────── */}
          <Section
            stepNum={3}
            title="Fields"
            subtitle="The questions on the form. Drag handle is reserved for P2 — use ↑/↓ for now."
          >
            {form.fields.length === 0 ? (
              <FieldEmptyState onPick={addField} />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {form.fields.map((fld, idx) => (
                  <FieldBlock
                    key={idx}
                    field={fld}
                    isFirst={idx === 0}
                    isLast={idx === form.fields.length - 1}
                    selected={activeFieldIdx === idx}
                    onSelect={() => setActiveFieldIdx(activeFieldIdx === idx ? null : idx)}
                    onChange={(patch) => updateField(idx, patch)}
                    onRemove={() => removeField(idx)}
                    onMove={(dir) => moveField(idx, dir)}
                  />
                ))}
                <FieldTypePicker compact onPick={addField} />
              </div>
            )}
          </Section>

          {/* ── Alert template ────────────────────────────────────────────── */}
          <Section
            stepNum={4}
            title="What happens on submit"
            subtitle="Submissions become alerts. Use {{field_key}} to substitute submitted values."
            tint="primary"
            collapsible
            collapsed={sectionCollapse.alert}
            onToggleCollapsed={() => toggleSection('alert')}
            summary={
              form.alert_template?.title?.trim()
                ? `${(form.alert_template.severity || 'medium').toUpperCase()} · ${form.alert_template.category || 'uncategorized'}`
                : 'not configured'
            }
          >
            <Input
              label="Alert title"
              value={form.alert_template.title}
              onChange={(e) => setForm({
                ...form,
                alert_template: { ...form.alert_template, title: e.target.value },
              })}
              placeholder="Phishing report from {{reporter_email}}"
            />
            <div style={{ marginTop: '0.85rem' }}>
              <Textarea
                label="Alert description"
                value={form.alert_template.description}
                onChange={(e) => setForm({
                  ...form,
                  alert_template: { ...form.alert_template, description: e.target.value },
                })}
                rows={3}
                placeholder="Suspicious email reported. Subject: {{email_subject}}. Notes: {{notes}}"
              />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.85rem', marginTop: '0.85rem' }}>
              <Select
                label="Severity"
                value={form.alert_template.severity}
                onChange={(e) => setForm({
                  ...form,
                  alert_template: { ...form.alert_template, severity: e.target.value },
                })}
              >
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
              <Input
                label="Source"
                value={form.alert_template.source}
                onChange={(e) => setForm({
                  ...form,
                  alert_template: { ...form.alert_template, source: e.target.value },
                })}
                placeholder="intake_form"
              />
              <Input
                label="Category"
                value={form.alert_template.category}
                onChange={(e) => setForm({
                  ...form,
                  alert_template: { ...form.alert_template, category: e.target.value },
                })}
                placeholder="phishing"
              />
            </div>

            {/* Triage strategy — how this form's submissions get processed
                after the alert lands. Riggs LLM triage is skipped for
                intake-form alerts regardless of strategy. */}
            <div
              style={{
                marginTop: '1.25rem',
                paddingTop: '1.25rem',
                borderTop: '1px solid var(--border-color)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <strong style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                  Triage strategy
                </strong>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Riggs LLM triage is skipped for intake-form submissions.
                </span>
              </div>
              <Select
                label="How submissions are processed"
                value={form.triage_strategy || 'enrich'}
                onChange={(e) => setForm({ ...form, triage_strategy: e.target.value })}
              >
                <option value="direct">Direct — alert + investigation in NEW. No enrichment, no playbook.</option>
                <option value="enrich">Enrich — same + run IOC enrichment. (Default)</option>
                <option value="playbook">Playbook — same + auto-fire the chosen playbook.</option>
              </Select>
              {form.triage_strategy === 'playbook' && (
                <div style={{ marginTop: '0.85rem' }}>
                  <Input
                    label="Auto-trigger playbook ID"
                    value={form.auto_trigger_playbook_id || ''}
                    onChange={(e) => setForm({
                      ...form,
                      auto_trigger_playbook_id: e.target.value.trim() || null,
                    })}
                    placeholder="UUID of the playbook to fire on submission"
                  />
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                    The playbook receives the submission payload as its trigger context.
                    Pick a UUID from the Playbooks page for now — a picker will land here in a follow-up.
                  </div>
                </div>
              )}
            </div>
          </Section>
        </div>

        {/* RIGHT PANE: live preview only. Field editing happens inline
            inside the selected row in the left pane — that way the
            admin sees the field they're editing in context with the
            rest of the form, and the preview stays purely about how
            the submitter sees it. */}
        <aside className="intake-preview-pane">
          <div className="intake-preview-sticky">
            <div className="intake-preview-tabs">
              <Eye size={14} />
              <span>Live preview</span>
              <span style={{ flex: 1 }} />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Updates as you type
              </span>
            </div>

            <div className="intake-preview-frame">
              <FormPreview form={form} />
            </div>

            <div className="intake-preview-meta">
              <div className="intake-preview-meta-title">When submitted, alert will look like:</div>
              <PreviewAlertCard form={form} samplePayload={samplePayload} />
            </div>
          </div>
        </aside>
      </div>

      <style>{`
        .intake-grid {
          display: grid;
          /* Fixed-ish right rail. On a 2284px viewport the old
             1.4fr / 1fr ratio gave the right rail ~950px — way more
             than Properties + Preview ever need, and it pushed the
             field list narrow. Pinning the right rail between 380px
             and 460px keeps the field-editor area dominant on wide
             screens and the right rail at a comfortable form-card
             width. */
          grid-template-columns: minmax(0, 1fr) minmax(380px, 460px);
          gap: 1.25rem;
          align-items: start;
        }
        @media (max-width: 1100px) {
          .intake-grid { grid-template-columns: 1fr; }
        }
        .intake-preview-pane { min-width: 0; }
        .intake-preview-sticky {
          position: sticky;
          top: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }
        .intake-preview-tabs {
          display: flex;
          align-items: center;
          gap: 0.4rem;
          padding: 0.6rem 0.85rem;
          background: var(--bg-secondary, rgba(255,255,255,0.03));
          border: 1px solid var(--border-color, rgba(148,163,184,0.18));
          border-radius: 10px 10px 0 0;
          font-size: 0.85rem;
          color: var(--text-secondary);
          font-weight: 600;
        }
        .intake-preview-frame {
          background: linear-gradient(180deg, rgba(60,179,113,0.04) 0%, rgba(8,10,15,0.4) 100%);
          border: 1px solid var(--border-color, rgba(148,163,184,0.18));
          border-top: none;
          border-radius: 0 0 10px 10px;
          padding: 1rem;
          max-height: 60vh;
          overflow-y: auto;
        }
        .intake-preview-meta {
          background: var(--bg-secondary, rgba(255,255,255,0.03));
          border: 1px solid var(--border-color, rgba(148,163,184,0.18));
          border-radius: 10px;
          padding: 0.85rem;
        }
        .intake-preview-meta-title {
          font-size: 0.72rem;
          font-weight: 700;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.06em;
          margin-bottom: 0.55rem;
        }
        .intake-md p { margin: 0 0 0.5rem; }
        .intake-md p:last-child { margin-bottom: 0; }
        .intake-md h1, .intake-md h2, .intake-md h3 {
          color: var(--text-primary);
          margin: 0.5rem 0 0.4rem;
          font-size: 0.95rem;
        }
        .intake-md h1 { font-size: 1.05rem; }
        .intake-md ul, .intake-md ol { margin: 0 0 0.5rem; padding-left: 1.25rem; }
        .intake-md a { color: var(--primary, #3CB371); text-decoration: underline; }
        .intake-md code {
          padding: 1px 5px;
          background: rgba(255,255,255,0.06);
          border-radius: 4px;
          font-size: 0.78rem;
        }
        .intake-md strong { color: var(--text-primary); }
      `}</style>
    </PageShell>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Page shell: dark gradient header + main content area                        */
/* ─────────────────────────────────────────────────────────────────────────── */

function PageShell({ title, subtitleSlot, actions, children }) {
  return (
    <div style={{ padding: '1.25rem 1.5rem 3rem', maxWidth: 1500, margin: '0 auto' }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        gap: '1rem',
        marginBottom: '1.5rem',
        flexWrap: 'wrap',
      }}>
        <div style={{ minWidth: 0 }}>
          <h1 style={{
            margin: 0,
            fontSize: 'clamp(1.4rem, 2vw, 1.75rem)',
            fontWeight: 700,
            letterSpacing: '-0.02em',
            color: 'var(--text-primary)',
          }}>
            {title}
          </h1>
          {subtitleSlot && <div style={{ marginTop: '0.55rem' }}>{subtitleSlot}</div>}
        </div>
        {actions && <div>{actions}</div>}
      </div>
      {children}
    </div>
  );
}

function LoadingState() {
  return (
    <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
      Loading…
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Section card with step number + tinted accent strip                         */
/* ─────────────────────────────────────────────────────────────────────────── */

function Section({
  stepNum,
  title,
  subtitle,
  tint = 'default',
  actions,
  children,
  // Collapse support — when collapsible is true, header becomes a click
  // target that toggles `collapsed`. `summary` renders inline next to the
  // title in collapsed state so the user can tell at a glance what's set.
  collapsible = false,
  collapsed = false,
  onToggleCollapsed,
  summary,
}) {
  const accentColor = tint === 'primary' ? '#3CB371' : '#5eead4';
  const isInteractive = collapsible && typeof onToggleCollapsed === 'function';

  return (
    <div style={{
      background: 'var(--bg-secondary, rgba(15,22,35,0.45))',
      border: '1px solid var(--border-color, rgba(148,163,184,0.16))',
      borderRadius: 12,
      overflow: 'hidden',
      position: 'relative',
    }}>
      <div style={{
        position: 'absolute',
        left: 0, top: 0, bottom: 0,
        width: 3,
        background: accentColor,
        opacity: 0.7,
      }} />
      <div
        onClick={isInteractive ? onToggleCollapsed : undefined}
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          padding: collapsed
            ? '0.65rem 1.1rem 0.65rem 1.35rem'
            : '1rem 1.1rem 0.75rem 1.35rem',
          cursor: isInteractive ? 'pointer' : 'default',
          userSelect: isInteractive ? 'none' : 'auto',
        }}
      >
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
            {stepNum && (
              <span style={{
                width: 22, height: 22,
                borderRadius: '50%',
                background: accentColor,
                color: '#000',
                fontWeight: 800,
                fontSize: '0.72rem',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>{stepNum}</span>
            )}
            <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {title}
            </h2>
            {collapsed && summary && (
              <span style={{
                fontSize: '0.82rem',
                color: 'var(--text-muted)',
                marginLeft: '0.4rem',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                minWidth: 0,
              }}>
                — {summary}
              </span>
            )}
          </div>
          {!collapsed && subtitle && (
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.3rem', paddingLeft: stepNum ? 30 : 0 }}>
              {subtitle}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
          {actions}
          {isInteractive && (
            <ChevronRight
              size={16}
              style={{
                color: 'var(--text-muted)',
                transition: 'transform 120ms',
                transform: collapsed ? 'rotate(0deg)' : 'rotate(90deg)',
              }}
            />
          )}
        </div>
      </div>
      {!collapsed && (
        <div style={{ padding: '0.5rem 1.1rem 1.1rem 1.35rem' }}>
          {children}
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Field block (collapsed/expanded states + type-tinted accent)                */
/* ─────────────────────────────────────────────────────────────────────────── */

function FieldBlock({ field, isFirst, isLast, selected, onSelect, onChange, onRemove, onMove }) {
  const meta = TYPE_META[field.type] || TYPE_META.text;
  const Icon = meta.icon;
  const hasSample = !!field.sample_value;
  const isOption = field.type === 'select' || field.type === 'multiselect';

  return (
    <div
      style={{
        background: selected
          ? `${meta.accent}10`
          : 'var(--bg-tertiary, rgba(255,255,255,0.025))',
        border: `1px solid ${selected ? meta.accent + '99' : 'var(--border-color, rgba(148,163,184,0.18))'}`,
        borderRadius: 10,
        overflow: 'hidden',
        transition: 'border-color 120ms, background 120ms',
      }}
    >
      {/* Header row — click toggles the inline editor for this field */}
      <div
        onClick={onSelect}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.6rem',
          padding: '0.55rem 0.75rem',
          cursor: 'pointer',
          background: selected ? `${meta.accent}14` : 'transparent',
        }}
      >
        <GripVertical size={14} style={{ color: 'var(--text-muted)', opacity: 0.5, flexShrink: 0 }} />
        <div style={{
          width: 28, height: 28, borderRadius: 7,
          background: `${meta.accent}22`,
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          color: meta.accent,
          flexShrink: 0,
        }}>
          <Icon size={14} />
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'baseline', minWidth: 0 }}>
            <span style={{
              fontWeight: 600, color: 'var(--text-primary)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {field.label || <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Untitled field</span>}
            </span>
            {field.required && (
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#ef4444' }}>required</span>
            )}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
            <span style={{ color: meta.accent, fontWeight: 600 }}>{meta.label}</span>
            {field.key && <span>·</span>}
            {field.key && <code style={{ fontSize: '0.7rem' }}>{field.key}</code>}
            {hasSample && (
              <span title="Has Riggs-generated sample value" style={{ color: '#3CB371', display: 'inline-flex', alignItems: 'center', marginLeft: '0.15rem' }}>
                <Sparkles size={10} />
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.2rem' }} onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" size="xs" disabled={isFirst} onClick={() => onMove(-1)} title="Move up">
            <ArrowUp size={12} />
          </Button>
          <Button variant="ghost" size="xs" disabled={isLast} onClick={() => onMove(1)} title="Move down">
            <ArrowDown size={12} />
          </Button>
          <Button variant="ghost" size="xs" onClick={onRemove} title="Remove">
            <Trash2 size={12} />
          </Button>
          <ChevronRight
            size={14}
            style={{
              color: 'var(--text-muted)',
              marginLeft: '0.15rem',
              alignSelf: 'center',
              transition: 'transform 120ms',
              transform: selected ? 'rotate(90deg)' : 'rotate(0deg)',
            }}
          />
        </div>
      </div>

      {/* Inline editor — only visible when this field is selected */}
      {selected && (
        <div
          onClick={(e) => e.stopPropagation()}
          style={{
            padding: '0.85rem 0.95rem 0.95rem',
            borderTop: `1px solid ${meta.accent}33`,
            display: 'flex',
            flexDirection: 'column',
            gap: '0.65rem',
          }}
        >
          <Input
            label="Label"
            value={field.label}
            onChange={(e) => {
              const newLabel = e.target.value;
              const patch = { label: newLabel };
              if (!field.key || field.key === slugifyKey(field.label)) {
                patch.key = slugifyKey(newLabel);
              }
              onChange(patch);
            }}
            placeholder="Reporter email"
          />

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.5fr 1fr', gap: '0.6rem' }}>
            <Input
              label="Key"
              value={field.key}
              onChange={(e) => onChange({ key: e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '') })}
              placeholder="reporter_email"
            />
            <Select
              label="Type"
              value={field.type}
              onChange={(e) => onChange({ type: e.target.value })}
            >
              {FIELD_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </Select>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: 'var(--text-secondary)', paddingBottom: '0.4rem', alignSelf: 'end' }}>
              <input
                type="checkbox"
                checked={!!field.required}
                onChange={(e) => onChange({ required: e.target.checked })}
              />
              Required
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
            <Input
              label="Help text"
              value={field.help || ''}
              onChange={(e) => onChange({ help: e.target.value })}
              placeholder="Shown under the field"
            />
            <Input
              label="Placeholder"
              value={field.placeholder || ''}
              onChange={(e) => onChange({ placeholder: e.target.value })}
              placeholder="e.g. you@company.com"
            />
          </div>

          {isOption && (
            <Textarea
              label="Options (one per line)"
              value={(field.options || []).map((o) => typeof o === 'string' ? o : (o.value || '')).join('\n')}
              onChange={(e) => onChange({
                options: e.target.value.split('\n').map((s) => s.trim()).filter(Boolean),
              })}
              rows={3}
              placeholder={'Phishing\nMalware\nOther'}
            />
          )}

          <div style={{
            padding: '0.6rem 0.7rem',
            background: 'rgba(60,179,113,0.06)',
            border: '1px dashed rgba(60,179,113,0.35)',
            borderRadius: 8,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.35rem' }}>
              <Sparkles size={12} style={{ color: 'var(--primary)' }} />
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Preview sample
              </span>
            </div>
            <Input
              value={field.sample_value || ''}
              onChange={(e) => onChange({ sample_value: e.target.value })}
              placeholder={previewFallback(field)}
            />
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
              What the live preview shows for this field. Riggs fills it in automatically — edit to override.
            </div>
          </div>

          {field.type === 'file' && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              File uploads work end-to-end. Submitters see a drop zone; the resulting attachment id flows into the alert payload.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Field type picker — shown when no fields exist or compact "add another"     */
/* ─────────────────────────────────────────────────────────────────────────── */

function FieldEmptyState({ onPick }) {
  return (
    <div>
      <div style={{
        textAlign: 'center',
        padding: '1.2rem 1rem 0.4rem',
        color: 'var(--text-muted)',
        fontSize: '0.9rem',
      }}>
        Pick a field type to start building.
      </div>
      <FieldTypePicker onPick={onPick} />
    </div>
  );
}

function FieldTypePicker({ onPick, compact = false }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: compact ? 'repeat(auto-fill, minmax(150px, 1fr))' : 'repeat(auto-fill, minmax(170px, 1fr))',
      gap: '0.5rem',
      marginTop: compact ? '0.4rem' : '0.75rem',
    }}>
      {FIELD_TYPES.map((t) => {
        const Icon = t.icon;
        return (
          <button
            key={t.value}
            type="button"
            onClick={() => onPick(t.value)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: compact ? '0.45rem 0.6rem' : '0.6rem 0.75rem',
              borderRadius: 8,
              border: `1px dashed ${t.accent}55`,
              background: `${t.accent}08`,
              color: 'var(--text-primary)',
              fontSize: '0.83rem',
              fontWeight: 500,
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all 120ms',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = `${t.accent}18`;
              e.currentTarget.style.borderStyle = 'solid';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = `${t.accent}08`;
              e.currentTarget.style.borderStyle = 'dashed';
            }}
          >
            <span style={{
              width: 22, height: 22, borderRadius: 5,
              background: `${t.accent}22`,
              color: t.accent,
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
            }}>
              <Icon size={12} />
            </span>
            <Plus size={10} style={{ color: 'var(--text-muted)' }} />
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Live preview of the submitter view                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

// Sample data the preview pre-fills into each field type so the user can see
// how the rendered form will look in action.
const SAMPLE_FOR_TYPE = {
  text:        'Sample text value',
  textarea:    'Sample multi-line content for preview…',
  email:       'reporter@example.com',
  url:         'https://example.com/article',
  datetime:    new Date().toISOString().slice(0, 16),
  file:        'phishing-email.eml',
};

const fallbackLabel = (field) => {
  if (field.label) return field.label;
  return TYPE_META[field.type]?.label || 'Field';
};

// Riggs fills field.sample_value with a domain-specific example
// ("phisher@suspicious-domain.com" instead of "user@example.com").
// Manual-build fields don't have it, so fall back to the generic samples.
const previewSampleValue = (field) => {
  if (field.sample_value !== undefined && field.sample_value !== null && field.sample_value !== '') {
    if (field.type === 'multiselect') {
      if (Array.isArray(field.sample_value)) return field.sample_value;
      // Allow comma-separated string fallback
      return String(field.sample_value).split(',').map((s) => s.trim()).filter(Boolean);
    }
    return field.sample_value;
  }
  if (field.type === 'select')      return (field.options?.[0]) || 'Option A';
  if (field.type === 'multiselect') return (field.options?.slice(0, 2)) || ['Option A'];
  return SAMPLE_FOR_TYPE[field.type] ?? 'Sample value';
};

// Placeholder string for the field-properties "Preview sample" input,
// shown when sample_value is empty so the admin sees what the generic
// fallback would render.
const previewFallback = (field) => {
  if (field.type === 'select')      return (field.options?.[0]) || 'Option A';
  if (field.type === 'multiselect') return (field.options || []).slice(0, 2).join(', ') || 'Option A';
  return SAMPLE_FOR_TYPE[field.type] ?? 'Sample value';
};

function FormPreview({ form }) {
  const isEmpty = !form.title && form.fields.length === 0;

  if (isEmpty) {
    return (
      <div style={{
        padding: '2rem 0.5rem',
        textAlign: 'center',
        color: 'var(--text-muted)',
        fontSize: '0.85rem',
      }}>
        Your form preview will appear here as you build.
      </div>
    );
  }

  return (
    <div>
      <h3 style={{ margin: 0, marginBottom: form.intro ? '0.4rem' : '1rem', fontSize: '1.05rem', color: 'var(--text-primary)' }}>
        {form.title || <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Untitled form</span>}
      </h3>
      {form.intro && (
        <div style={{ marginBottom: '1rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }} className="intake-md">
          <ReactMarkdown>{form.intro}</ReactMarkdown>
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
        {form.fields.length === 0 ? (
          <div style={{ padding: '0.75rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', border: '1px dashed var(--border-color)', borderRadius: 6 }}>
            Add a field below to see it appear here.
          </div>
        ) : (
          form.fields.map((f, idx) => <PreviewField key={idx} field={f} />)
        )}
      </div>
      {form.fields.length > 0 && (
        <button
          type="button"
          disabled
          style={{
            marginTop: '1rem',
            padding: '0.5rem 1rem',
            borderRadius: 6,
            background: 'var(--primary, #3CB371)',
            color: '#fff',
            border: 'none',
            fontSize: '0.85rem',
            fontWeight: 600,
            cursor: 'default',
            opacity: 0.85,
          }}
        >
          Submit
        </button>
      )}
    </div>
  );
}

function PreviewField({ field }) {
  const label = fallbackLabel(field);
  const labelIsFallback = !field.label;
  const sample = previewSampleValue(field);

  const labelEl = (
    <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
      <span style={labelIsFallback ? { color: 'var(--text-muted)', fontStyle: 'italic' } : undefined}>
        {label}
      </span>
      {field.required && <span style={{ color: '#ef4444' }}> *</span>}
    </div>
  );
  const inputStyle = {
    width: '100%',
    padding: '0.45rem 0.6rem',
    background: 'var(--bg-tertiary, rgba(0,0,0,0.25))',
    border: '1px solid var(--border-color, rgba(148,163,184,0.18))',
    borderRadius: 6,
    color: 'var(--text-primary)',
    fontSize: '0.85rem',
    boxSizing: 'border-box',
    fontFamily: 'inherit',
  };

  let inner;
  switch (field.type) {
    case 'textarea':
      inner = (
        <textarea
          disabled
          rows={3}
          value={sample}
          onChange={() => {}}
          placeholder={field.placeholder || ''}
          style={inputStyle}
        />
      );
      break;
    case 'select':
      inner = (
        <select disabled value={sample} onChange={() => {}} style={inputStyle}>
          <option value={sample}>{sample}</option>
        </select>
      );
      break;
    case 'multiselect':
      inner = (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
          {(Array.isArray(sample) ? sample : [sample]).map((o) => (
            <span key={o} style={{
              padding: '0.25rem 0.55rem',
              border: '1px solid #3CB37155',
              background: 'rgba(60,179,113,0.10)',
              color: 'var(--primary, #3CB371)',
              borderRadius: 999,
              fontSize: '0.75rem',
              fontWeight: 600,
            }}>{o}</span>
          ))}
          {(field.options || []).slice(2, 5).map((o) => (
            <span key={o} style={{
              padding: '0.25rem 0.55rem',
              border: '1px solid var(--border-color)',
              borderRadius: 999,
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
            }}>{o}</span>
          ))}
        </div>
      );
      break;
    case 'file':
      inner = (
        <div style={{ ...inputStyle, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>📎</span>
          <span>{sample}</span>
        </div>
      );
      break;
    case 'datetime':
      inner = <input disabled type="datetime-local" value={sample} onChange={() => {}} style={inputStyle} />;
      break;
    default:
      inner = (
        <input
          disabled
          value={sample}
          onChange={() => {}}
          placeholder={field.placeholder || ''}
          style={inputStyle}
        />
      );
  }

  return (
    <div>
      {labelEl}
      {inner}
      {field.help && (
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
          {field.help}
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Preview of the resulting alert                                              */
/* ─────────────────────────────────────────────────────────────────────────── */

const SEVERITY_COLOR = { low: '#94a3b8', medium: '#fbbf24', high: '#f97316', critical: '#ef4444' };

function PreviewAlertCard({ form, samplePayload }) {
  const tpl = form.alert_template;
  const renderedTitle = renderTemplate(tpl.title, samplePayload)
    || `Intake form submission: ${form.name || 'untitled form'}`;
  const renderedDesc = renderTemplate(tpl.description, samplePayload);
  const sevColor = SEVERITY_COLOR[tpl.severity] || SEVERITY_COLOR.medium;

  return (
    <div style={{
      background: 'var(--bg-tertiary, rgba(0,0,0,0.25))',
      border: '1px solid var(--border-color, rgba(148,163,184,0.18))',
      borderLeft: `3px solid ${sevColor}`,
      borderRadius: 8,
      padding: '0.7rem 0.85rem',
    }}>
      <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', marginBottom: '0.3rem' }}>
        <span style={{
          fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
          color: sevColor,
          padding: '2px 6px',
          background: `${sevColor}22`,
          borderRadius: 4,
        }}>
          {tpl.severity || 'medium'}
        </span>
        {tpl.source && <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{tpl.source}</span>}
        {tpl.category && <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>· {tpl.category}</span>}
      </div>
      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.88rem', marginBottom: renderedDesc ? '0.3rem' : 0 }}>
        {renderedTitle}
      </div>
      {renderedDesc && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
          {renderedDesc}
        </div>
      )}
    </div>
  );
}
