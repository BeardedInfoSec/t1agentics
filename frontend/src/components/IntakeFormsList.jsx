/**
 * Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Badge, Table, useToast } from './ui';
import { AdminLayout } from '../layouts';
import { intakeFormsService } from '../data/services/intakeFormsService';
import * as LucideIcons from 'lucide-react';
import { Edit, Copy, Trash2, ExternalLink, Sparkles, X as XIcon, BookOpen } from 'lucide-react';

const STATUS_VARIANT = {
  active:   'success',
  draft:    'warning',
  archived: 'default',
};

export default function IntakeFormsList() {
  const navigate = useNavigate();
  const toast = useToast();

  const [forms, setForms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');

  // Template picker state
  const [templatesOpen, setTemplatesOpen] = useState(false);
  const [templates, setTemplates] = useState([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templateCategory, setTemplateCategory] = useState('All');
  const [creatingFromTemplate, setCreatingFromTemplate] = useState(null);

  const openTemplates = async () => {
    setTemplatesOpen(true);
    if (templates.length === 0) {
      setTemplatesLoading(true);
      try {
        const res = await intakeFormsService.listTemplates();
        setTemplates(res.templates || []);
      } catch (e) {
        toast.error(e.message || 'Could not load templates');
      } finally {
        setTemplatesLoading(false);
      }
    }
  };

  const useTemplate = async (template) => {
    setCreatingFromTemplate(template.template_id);
    try {
      const created = await intakeFormsService.createFromTemplate(template.template_id);
      toast.success(`Created "${created.name}" from template`);
      setTemplatesOpen(false);
      navigate(`/admin/intake-forms/${created.id}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || e.message || 'Could not create from template');
    } finally {
      setCreatingFromTemplate(null);
    }
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = statusFilter ? { status: statusFilter } : {};
      const res = await intakeFormsService.list(params);
      setForms(res.items || []);
    } catch (e) {
      setError(e.message || 'Failed to load forms');
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  const handleCopyLink = (form) => {
    const url = `${window.location.origin}/intake/${form.slug}`;
    navigator.clipboard.writeText(url).then(
      () => toast.success(`Link copied for "${form.name}"`),
      () => toast.error('Could not copy to clipboard')
    );
  };

  const handleDelete = async (form) => {
    if (!window.confirm(`Delete "${form.name}"? This cannot be undone — submissions will also be deleted.`)) {
      return;
    }
    try {
      await intakeFormsService.remove(form.id);
      toast.success(`Deleted "${form.name}"`);
      load();
    } catch (e) {
      toast.error(e.message || 'Delete failed');
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Form',
      render: (row) => (
        <div>
          <div style={{ fontWeight: 600 }}>{row.name}</div>
          {row.description && (
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>
              {row.description.length > 80 ? row.description.slice(0, 80) + '…' : row.description}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => (
        <Badge variant={STATUS_VARIANT[row.status] || 'default'}>
          {row.status}
        </Badge>
      ),
    },
    {
      key: 'fields',
      label: 'Fields',
      render: (row) => (Array.isArray(row.fields) ? row.fields.length : 0),
    },
    {
      key: 'slug',
      label: 'Submit URL',
      render: (row) => (
        row.status === 'active' ? (
          <code style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            /intake/{row.slug}
          </code>
        ) : (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>—</span>
        )
      ),
    },
    {
      key: 'created_at',
      label: 'Created',
      render: (row) => row.created_at
        ? new Date(row.created_at).toLocaleDateString()
        : '—',
    },
    {
      key: 'actions',
      label: '',
      render: (row) => (
        <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
          {row.status === 'active' && (
            <Button variant="ghost" size="xs" onClick={() => handleCopyLink(row)} title="Copy submit URL">
              <Copy size={14} />
            </Button>
          )}
          {row.status === 'active' && (
            <Button
              variant="ghost"
              size="xs"
              onClick={() => window.open(`/intake/${row.slug}`, '_blank')}
              title="Open submit page"
            >
              <ExternalLink size={14} />
            </Button>
          )}
          <Button variant="ghost" size="xs" onClick={() => navigate(`/admin/intake-forms/${row.id}`)} title="Edit">
            <Edit size={14} />
          </Button>
          <Button variant="ghost" size="xs" onClick={() => handleDelete(row)} title="Delete">
            <Trash2 size={14} />
          </Button>
        </div>
      ),
    },
  ];

  const actions = (
    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
      <select
        value={statusFilter}
        onChange={(e) => setStatusFilter(e.target.value)}
        style={{
          padding: '0.4rem 0.6rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-color)',
          background: 'var(--bg-secondary)',
          color: 'var(--text-primary)',
          fontSize: '0.85rem',
        }}
      >
        <option value="">All statuses</option>
        <option value="draft">Draft</option>
        <option value="active">Active</option>
        <option value="archived">Archived</option>
      </select>
      <Button variant="secondary" onClick={openTemplates} data-tour="intake-browse-templates">
        <BookOpen size={14} /> Browse templates
      </Button>
      <Button variant="primary" onClick={() => navigate('/admin/intake-forms/new')} data-tour="intake-new-form">
        + New Form
      </Button>
    </div>
  );

  // Distinct categories from the loaded templates
  const categories = ['All', ...Array.from(new Set(templates.map((t) => t.category).filter(Boolean)))];
  const filteredTemplates = templateCategory === 'All'
    ? templates
    : templates.filter((t) => t.category === templateCategory);

  return (
    <AdminLayout
      title="Intake Forms"
      subtitle="Authenticated forms whose submissions become alerts triaged by Riggs."
      actions={actions}
    >
      <Table
        columns={columns}
        data={forms}
        loading={loading}
        error={error}
        onRowClick={(row) => navigate(`/admin/intake-forms/${row.id}`)}
        emptyMessage={
          <div style={{ textAlign: 'center', padding: '2rem 1rem' }}>
            <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '0.5rem' }}>
              No intake forms yet
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1rem' }}>
              Pick a template to start fast, or build a custom form. Riggs can also draft a form for you from a description.
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <Button variant="primary" size="sm" onClick={openTemplates}>
                <BookOpen size={14} /> Browse templates
              </Button>
              <Link to="/admin/intake-forms/new">
                <Button variant="secondary" size="sm">+ Blank form</Button>
              </Link>
            </div>
          </div>
        }
      />

      {/* Template picker modal */}
      {templatesOpen && (
        <TemplatePicker
          templates={filteredTemplates}
          allTemplates={templates}
          categories={categories}
          activeCategory={templateCategory}
          onCategory={setTemplateCategory}
          loading={templatesLoading}
          creatingId={creatingFromTemplate}
          onClose={() => setTemplatesOpen(false)}
          onSelect={useTemplate}
        />
      )}
    </AdminLayout>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Template picker — modal grid of builtin form templates                      */
/* ─────────────────────────────────────────────────────────────────────────── */

function TemplatePicker({
  templates, allTemplates, categories, activeCategory, onCategory,
  loading, creatingId, onClose, onSelect,
}) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.65)',
        backdropFilter: 'blur(2px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '4rem 1rem 1rem',
        overflowY: 'auto',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--bg-primary, #0a0e15)',
          border: '1px solid var(--border-color, rgba(148,163,184,0.25))',
          borderRadius: 12,
          width: '100%',
          maxWidth: 1100,
          maxHeight: 'calc(100vh - 6rem)',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 80px rgba(0,0,0,0.55)',
        }}
      >
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--border-color, rgba(148,163,184,0.18))',
          flexShrink: 0,
        }}>
          <BookOpen size={18} style={{ color: 'var(--primary)' }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Browse intake form templates
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {allTemplates.length} ready-made forms covering common SOC intake scenarios. Pick one to start a draft you can edit and activate.
            </div>
          </div>
          <Button variant="ghost" size="xs" onClick={onClose} title="Close">
            <XIcon size={14} />
          </Button>
        </div>

        <div style={{
          display: 'flex',
          gap: '0.4rem',
          padding: '0.75rem 1.25rem',
          flexWrap: 'wrap',
          borderBottom: '1px solid var(--border-color, rgba(148,163,184,0.12))',
        }}>
          {categories.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => onCategory(c)}
              style={{
                padding: '0.35rem 0.75rem',
                borderRadius: 999,
                border: `1px solid ${activeCategory === c ? 'var(--primary)' : 'var(--border-color, rgba(148,163,184,0.25))'}`,
                background: activeCategory === c ? 'rgba(60,179,113,0.15)' : 'transparent',
                color: activeCategory === c ? 'var(--primary)' : 'var(--text-secondary)',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {c}
            </button>
          ))}
        </div>

        <div style={{ padding: '1rem 1.25rem', overflowY: 'auto', flex: 1 }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
              Loading templates…
            </div>
          ) : templates.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
              No templates in this category.
            </div>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: '0.75rem',
            }}>
              {templates.map((tpl) => (
                <TemplateCard
                  key={tpl.template_id}
                  template={tpl}
                  creating={creatingId === tpl.template_id}
                  disabled={!!creatingId && creatingId !== tpl.template_id}
                  onUse={() => onSelect(tpl)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const SEVERITY_TINT = {
  low:      { bg: 'rgba(148,163,184,0.15)', fg: '#94a3b8' },
  medium:   { bg: 'rgba(251,191,36,0.15)',  fg: '#fbbf24' },
  high:     { bg: 'rgba(249,115,22,0.18)',  fg: '#f97316' },
  critical: { bg: 'rgba(239,68,68,0.18)',   fg: '#ef4444' },
};

function TemplateCard({ template, creating, disabled, onUse }) {
  const Icon = (template.icon && LucideIcons[template.icon]) || LucideIcons.FileText;
  const sevTint = SEVERITY_TINT[template.default_severity] || SEVERITY_TINT.medium;

  return (
    <div
      onClick={!disabled && !creating ? onUse : undefined}
      style={{
        background: 'var(--bg-secondary, rgba(255,255,255,0.025))',
        border: '1px solid var(--border-color, rgba(148,163,184,0.2))',
        borderRadius: 10,
        padding: '0.95rem 1rem',
        cursor: disabled ? 'default' : (creating ? 'wait' : 'pointer'),
        opacity: disabled ? 0.5 : 1,
        transition: 'border-color 120ms, background 120ms',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.6rem',
      }}
      onMouseEnter={(e) => {
        if (disabled || creating) return;
        e.currentTarget.style.borderColor = 'var(--primary, #3CB371)';
        e.currentTarget.style.background = 'rgba(60,179,113,0.06)';
      }}
      onMouseLeave={(e) => {
        if (disabled || creating) return;
        e.currentTarget.style.borderColor = 'var(--border-color, rgba(148,163,184,0.2))';
        e.currentTarget.style.background = 'var(--bg-secondary, rgba(255,255,255,0.025))';
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: 'rgba(60,179,113,0.15)',
          color: 'var(--primary, #3CB371)',
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={18} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: '0.92rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            lineHeight: 1.3,
          }}>
            {template.name}
          </div>
          {template.description && (
            <div style={{
              fontSize: '0.78rem',
              color: 'var(--text-muted)',
              marginTop: '0.25rem',
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }}>
              {template.description}
            </div>
          )}
        </div>
      </div>

      <div style={{
        display: 'flex',
        gap: '0.4rem',
        alignItems: 'center',
        fontSize: '0.7rem',
        color: 'var(--text-muted)',
        flexWrap: 'wrap',
      }}>
        <span style={{
          padding: '2px 7px',
          background: sevTint.bg,
          color: sevTint.fg,
          fontWeight: 700,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          borderRadius: 4,
          fontSize: '0.65rem',
        }}>
          {template.default_severity || 'medium'}
        </span>
        <span>{template.field_count} field{template.field_count === 1 ? '' : 's'}</span>
        <span>·</span>
        <span>{template.estimated_minutes} min to fill</span>
      </div>

      <Button
        variant={creating ? 'ghost' : 'primary'}
        size="sm"
        onClick={(e) => { e.stopPropagation(); onUse(); }}
        disabled={disabled || creating}
        style={{ alignSelf: 'flex-start' }}
      >
        {creating ? 'Creating…' : (<><Sparkles size={12} /> Use template</>)}
      </Button>
    </div>
  );
}
