/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Form Builder Component
 *
 * Visual form designer for creating webforms used in playbook execution.
 * Supports drag-and-drop field ordering and various field types.
 */

import React, { useState, useCallback } from 'react';
import { useToast } from '../ui/Toast';
import {
  Plus, Trash2, GripVertical, Save, X, Settings,
  Type, Hash, Mail, List, CheckSquare, Circle, Calendar,
  Upload, Eye, EyeOff, ChevronDown, ChevronUp
} from 'lucide-react';

const FIELD_TYPES = [
  { value: 'text', label: 'Text', icon: Type, description: 'Single line text input' },
  { value: 'textarea', label: 'Text Area', icon: Type, description: 'Multi-line text input' },
  { value: 'number', label: 'Number', icon: Hash, description: 'Numeric input' },
  { value: 'email', label: 'Email', icon: Mail, description: 'Email address input' },
  { value: 'select', label: 'Dropdown', icon: List, description: 'Single selection dropdown' },
  { value: 'multiselect', label: 'Multi Select', icon: CheckSquare, description: 'Multiple selection checkboxes' },
  { value: 'checkbox', label: 'Checkbox', icon: CheckSquare, description: 'Boolean checkbox' },
  { value: 'radio', label: 'Radio Buttons', icon: Circle, description: 'Single selection radio buttons' },
  { value: 'date', label: 'Date', icon: Calendar, description: 'Date picker' },
  { value: 'datetime', label: 'Date & Time', icon: Calendar, description: 'Date and time picker' },
  { value: 'file', label: 'File Upload', icon: Upload, description: 'File upload field' },
  { value: 'hidden', label: 'Hidden', icon: EyeOff, description: 'Hidden field (prefilled)' },
];

function FormBuilder({
  initialForm = null,
  onSave,
  onCancel,
  isModal = false
}) {
  const toast = useToast();
  const [formName, setFormName] = useState(initialForm?.name || '');
  const [formDescription, setFormDescription] = useState(initialForm?.description || '');
  const [submitLabel, setSubmitLabel] = useState(initialForm?.submit_label || 'Submit');
  // Stash prefill paths on each field for editing; we project back out to a
  // top-level prefill_mapping at save time so the wire shape stays simple.
  const [fields, setFields] = useState(() => {
    const incoming = initialForm?.fields || [];
    const mapping = initialForm?.prefill_mapping || {};
    return incoming.map((f) => ({ ...f, prefill_path: mapping[f.name] || f.prefill_path || '' }));
  });
  const [expandedField, setExpandedField] = useState(null);
  const [draggedIndex, setDraggedIndex] = useState(null);
  const [showPreview, setShowPreview] = useState(false);

  const addField = useCallback((type = 'text') => {
    const newField = {
      id: `field_${Date.now()}`,
      name: `field_${fields.length + 1}`,
      label: `Field ${fields.length + 1}`,
      type: type,
      required: false,
      default: '',
      placeholder: '',
      help_text: '',
      options: type === 'select' || type === 'multiselect' || type === 'radio'
        ? [{ label: 'Option 1', value: 'option1' }]
        : null,
      validation: null,
    };
    setFields([...fields, newField]);
    setExpandedField(newField.id);
  }, [fields]);

  const updateField = useCallback((fieldId, updates) => {
    setFields(fields.map(f =>
      f.id === fieldId ? { ...f, ...updates } : f
    ));
  }, [fields]);

  const removeField = useCallback((fieldId) => {
    setFields(fields.filter(f => f.id !== fieldId));
    if (expandedField === fieldId) {
      setExpandedField(null);
    }
  }, [fields, expandedField]);

  const moveField = useCallback((fromIndex, toIndex) => {
    const newFields = [...fields];
    const [moved] = newFields.splice(fromIndex, 1);
    newFields.splice(toIndex, 0, moved);
    setFields(newFields);
  }, [fields]);

  const handleDragStart = (e, index) => {
    setDraggedIndex(index);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e, index) => {
    e.preventDefault();
    if (draggedIndex === null || draggedIndex === index) return;
    moveField(draggedIndex, index);
    setDraggedIndex(index);
  };

  const handleDragEnd = () => {
    setDraggedIndex(null);
  };

  const handleSave = () => {
    if (!formName.trim()) {
      toast.warning('Please enter a form name');
      return;
    }
    if (fields.length === 0) {
      toast.warning('Please add at least one field');
      return;
    }

    // Validate field names are unique
    const names = fields.map(f => f.name);
    if (new Set(names).size !== names.length) {
      toast.warning('Field names must be unique');
      return;
    }

    const prefill_mapping = {};
    fields.forEach((f) => {
      if (f.prefill_path && String(f.prefill_path).trim()) {
        prefill_mapping[f.name] = String(f.prefill_path).trim();
      }
    });

    const form = {
      name: formName,
      description: formDescription,
      submit_label: submitLabel,
      fields: fields.map(({ id, prefill_path, ...field }) => field), // Remove temporary id + per-field prefill_path (it lifts to prefill_mapping)
      prefill_mapping,
    };

    onSave(form);
  };

  const addOption = (fieldId) => {
    const field = fields.find(f => f.id === fieldId);
    if (!field) return;

    const options = field.options || [];
    updateField(fieldId, {
      options: [...options, { label: `Option ${options.length + 1}`, value: `option${options.length + 1}` }]
    });
  };

  const updateOption = (fieldId, optionIndex, key, value) => {
    const field = fields.find(f => f.id === fieldId);
    if (!field) return;

    const newOptions = [...(field.options || [])];
    newOptions[optionIndex] = { ...newOptions[optionIndex], [key]: value };
    updateField(fieldId, { options: newOptions });
  };

  const removeOption = (fieldId, optionIndex) => {
    const field = fields.find(f => f.id === fieldId);
    if (!field) return;

    const newOptions = (field.options || []).filter((_, i) => i !== optionIndex);
    updateField(fieldId, { options: newOptions });
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <h2 style={styles.title}>
          {initialForm ? 'Edit Form' : 'Create Form'}
        </h2>
        <div style={styles.headerActions}>
          <button
            style={{ ...styles.iconButton, ...(showPreview ? styles.iconButtonActive : {}) }}
            onClick={() => setShowPreview(!showPreview)}
            title="Preview Form"
          >
            <Eye size={16} />
          </button>
          {onCancel && (
            <button style={styles.iconButton} onClick={onCancel} title="Cancel">
              <X size={16} />
            </button>
          )}
        </div>
      </div>

      <div style={styles.content}>
        {/* Left: Form Builder */}
        <div style={{ ...styles.builderPane, ...(showPreview ? { width: '50%' } : {}) }}>
          {/* Form Settings */}
          <div style={styles.section}>
            <h3 style={styles.sectionTitle}>Form Settings</h3>
            <div style={styles.formGroup}>
              <label style={styles.label}>Form Name *</label>
              <input
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="Enter form name"
                style={styles.input}
              />
            </div>
            <div style={styles.formGroup}>
              <label style={styles.label}>Description</label>
              <textarea
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Describe the form's purpose"
                style={styles.textarea}
                rows={2}
              />
            </div>
            <div style={styles.formGroup}>
              <label style={styles.label}>Submit Button Text</label>
              <input
                type="text"
                value={submitLabel}
                onChange={(e) => setSubmitLabel(e.target.value)}
                placeholder="Submit"
                style={styles.input}
              />
            </div>
          </div>

          {/* Fields */}
          <div style={styles.section}>
            <div style={styles.sectionHeader}>
              <h3 style={styles.sectionTitle}>Fields ({fields.length})</h3>
              <div style={styles.addFieldDropdown}>
                <select
                  onChange={(e) => {
                    if (e.target.value) {
                      addField(e.target.value);
                      e.target.value = '';
                    }
                  }}
                  style={styles.addFieldSelect}
                  defaultValue=""
                >
                  <option value="" disabled>+ Add Field</option>
                  {FIELD_TYPES.map(ft => (
                    <option key={ft.value} value={ft.value}>{ft.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div style={styles.fieldsList}>
              {fields.length === 0 ? (
                <div style={styles.emptyFields}>
                  <p>No fields added yet.</p>
                  <p style={styles.emptyHint}>Select a field type above to add your first field.</p>
                </div>
              ) : (
                fields.map((field, index) => (
                  <FieldEditor
                    key={field.id}
                    field={field}
                    index={index}
                    isExpanded={expandedField === field.id}
                    onToggle={() => setExpandedField(expandedField === field.id ? null : field.id)}
                    onUpdate={(updates) => updateField(field.id, updates)}
                    onRemove={() => removeField(field.id)}
                    onAddOption={() => addOption(field.id)}
                    onUpdateOption={(optIdx, key, value) => updateOption(field.id, optIdx, key, value)}
                    onRemoveOption={(optIdx) => removeOption(field.id, optIdx)}
                    onDragStart={(e) => handleDragStart(e, index)}
                    onDragOver={(e) => handleDragOver(e, index)}
                    onDragEnd={handleDragEnd}
                    isDragging={draggedIndex === index}
                  />
                ))
              )}
            </div>
          </div>

          {/* Save Button */}
          <div style={styles.actions}>
            {onCancel && (
              <button style={styles.cancelButton} onClick={onCancel}>
                Cancel
              </button>
            )}
            <button style={styles.saveButton} onClick={handleSave}>
              <Save size={16} />
              Save Form
            </button>
          </div>
        </div>

        {/* Right: Preview */}
        {showPreview && (
          <div style={styles.previewPane}>
            <h3 style={styles.previewTitle}>Preview</h3>
            <FormPreview
              name={formName}
              description={formDescription}
              fields={fields}
              submitLabel={submitLabel}
            />
          </div>
        )}
      </div>
    </div>
  );
}


function FieldEditor({
  field,
  index,
  isExpanded,
  onToggle,
  onUpdate,
  onRemove,
  onAddOption,
  onUpdateOption,
  onRemoveOption,
  onDragStart,
  onDragOver,
  onDragEnd,
  isDragging
}) {
  const fieldTypeConfig = FIELD_TYPES.find(ft => ft.value === field.type) || FIELD_TYPES[0];
  const Icon = fieldTypeConfig.icon;
  const needsOptions = ['select', 'multiselect', 'radio'].includes(field.type);

  return (
    <div
      style={{
        ...styles.fieldEditor,
        ...(isDragging ? styles.fieldEditorDragging : {}),
      }}
      draggable
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDragEnd={onDragEnd}
    >
      {/* Field Header */}
      <div style={styles.fieldHeader} onClick={onToggle}>
        <div style={styles.fieldDragHandle}>
          <GripVertical size={16} />
        </div>
        <div style={styles.fieldTypeIcon}>
          <Icon size={14} />
        </div>
        <div style={styles.fieldInfo}>
          <span style={styles.fieldLabel}>{field.label || 'Untitled'}</span>
          <span style={styles.fieldMeta}>
            {fieldTypeConfig.label}
            {field.required && <span style={styles.requiredBadge}>Required</span>}
          </span>
        </div>
        <div style={styles.fieldActions}>
          <button
            style={styles.fieldActionButton}
            onClick={(e) => { e.stopPropagation(); onRemove(); }}
            title="Remove field"
          >
            <Trash2 size={14} />
          </button>
          {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </div>

      {/* Field Settings (Expanded) */}
      {isExpanded && (
        <div style={styles.fieldSettings}>
          <div style={styles.fieldSettingsGrid}>
            <div style={styles.formGroup}>
              <label style={styles.label}>Field Name (ID)</label>
              <input
                type="text"
                value={field.name}
                onChange={(e) => onUpdate({ name: e.target.value.replace(/\s/g, '_').toLowerCase() })}
                style={styles.input}
                placeholder="field_name"
              />
            </div>
            <div style={styles.formGroup}>
              <label style={styles.label}>Label</label>
              <input
                type="text"
                value={field.label}
                onChange={(e) => onUpdate({ label: e.target.value })}
                style={styles.input}
                placeholder="Field Label"
              />
            </div>
            <div style={styles.formGroup}>
              <label style={styles.label}>Field Type</label>
              <select
                value={field.type}
                onChange={(e) => onUpdate({
                  type: e.target.value,
                  options: ['select', 'multiselect', 'radio'].includes(e.target.value)
                    ? field.options || [{ label: 'Option 1', value: 'option1' }]
                    : null
                })}
                style={styles.select}
              >
                {FIELD_TYPES.map(ft => (
                  <option key={ft.value} value={ft.value}>{ft.label}</option>
                ))}
              </select>
            </div>
            <div style={styles.formGroup}>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={field.required}
                  onChange={(e) => onUpdate({ required: e.target.checked })}
                  style={styles.checkbox}
                />
                Required field
              </label>
            </div>
          </div>

          {field.type !== 'checkbox' && field.type !== 'hidden' && (
            <div style={styles.formGroup}>
              <label style={styles.label}>Placeholder</label>
              <input
                type="text"
                value={field.placeholder || ''}
                onChange={(e) => onUpdate({ placeholder: e.target.value })}
                style={styles.input}
                placeholder="Enter placeholder text"
              />
            </div>
          )}

          <div style={styles.formGroup}>
            <label style={styles.label}>Help Text</label>
            <input
              type="text"
              value={field.help_text || ''}
              onChange={(e) => onUpdate({ help_text: e.target.value })}
              style={styles.input}
              placeholder="Additional instructions for users"
            />
          </div>

          {field.type !== 'checkbox' && (
            <div style={styles.formGroup}>
              <label style={styles.label}>Default Value</label>
              <input
                type="text"
                value={field.default || ''}
                onChange={(e) => onUpdate({ default: e.target.value })}
                style={styles.input}
                placeholder="Default value"
              />
            </div>
          )}

          <div style={styles.formGroup}>
            <label style={styles.label}>Prefill from execution context</label>
            <input
              type="text"
              value={field.prefill_path || ''}
              onChange={(e) => onUpdate({ prefill_path: e.target.value })}
              style={styles.input}
              placeholder="e.g. $.alert.subject or trigger.alert.src_ip"
            />
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              JSONPath into the running playbook's context. Resolved when the form is rendered; analyst can edit before submit.
            </div>
          </div>

          {/* Options for select/radio/multiselect */}
          {needsOptions && (
            <div style={styles.optionsSection}>
              <div style={styles.optionsHeader}>
                <label style={styles.label}>Options</label>
                <button style={styles.addOptionButton} onClick={onAddOption}>
                  <Plus size={12} /> Add Option
                </button>
              </div>
              <div style={styles.optionsList}>
                {(field.options || []).map((option, idx) => (
                  <div key={idx} style={styles.optionItem}>
                    <input
                      type="text"
                      value={option.label}
                      onChange={(e) => onUpdateOption(idx, 'label', e.target.value)}
                      style={{ ...styles.input, flex: 1 }}
                      placeholder="Label"
                    />
                    <input
                      type="text"
                      value={option.value}
                      onChange={(e) => onUpdateOption(idx, 'value', e.target.value)}
                      style={{ ...styles.input, flex: 1 }}
                      placeholder="Value"
                    />
                    <button
                      style={styles.removeOptionButton}
                      onClick={() => onRemoveOption(idx)}
                      disabled={(field.options || []).length <= 1}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* File validation */}
          {field.type === 'file' && (
            <div style={styles.formGroup}>
              <label style={styles.label}>Allowed File Types (comma-separated)</label>
              <input
                type="text"
                value={field.validation?.allowed_types?.join(', ') || ''}
                onChange={(e) => onUpdate({
                  validation: {
                    ...field.validation,
                    allowed_types: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                  }
                })}
                style={styles.input}
                placeholder="e.g., .pdf, .doc, .txt"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function FormPreview({ name, description, fields, submitLabel }) {
  return (
    <div style={styles.previewForm}>
      {name && <h4 style={styles.previewFormName}>{name}</h4>}
      {description && <p style={styles.previewFormDescription}>{description}</p>}

      {fields.map((field, idx) => (
        <div key={idx} style={styles.previewField}>
          {field.type !== 'hidden' && (
            <label style={styles.previewLabel}>
              {field.label}
              {field.required && <span style={styles.previewRequired}>*</span>}
            </label>
          )}

          {field.type === 'text' && (
            <input type="text" style={styles.previewInput} placeholder={field.placeholder} disabled />
          )}
          {field.type === 'textarea' && (
            <textarea style={styles.previewTextarea} placeholder={field.placeholder} disabled rows={3} />
          )}
          {field.type === 'number' && (
            <input type="number" style={styles.previewInput} placeholder={field.placeholder} disabled />
          )}
          {field.type === 'email' && (
            <input type="email" style={styles.previewInput} placeholder={field.placeholder} disabled />
          )}
          {field.type === 'select' && (
            <select style={styles.previewSelect} disabled>
              <option>Select...</option>
              {(field.options || []).map((opt, i) => (
                <option key={i} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          )}
          {field.type === 'multiselect' && (
            <div style={styles.previewCheckboxGroup}>
              {(field.options || []).map((opt, i) => (
                <label key={i} style={styles.previewCheckboxItem}>
                  <input type="checkbox" disabled /> {opt.label}
                </label>
              ))}
            </div>
          )}
          {field.type === 'radio' && (
            <div style={styles.previewRadioGroup}>
              {(field.options || []).map((opt, i) => (
                <label key={i} style={styles.previewRadioItem}>
                  <input type="radio" name={field.name} disabled /> {opt.label}
                </label>
              ))}
            </div>
          )}
          {field.type === 'checkbox' && (
            <label style={styles.previewCheckboxItem}>
              <input type="checkbox" disabled /> {field.label}
            </label>
          )}
          {field.type === 'date' && (
            <input type="date" style={styles.previewInput} disabled />
          )}
          {field.type === 'datetime' && (
            <input type="datetime-local" style={styles.previewInput} disabled />
          )}
          {field.type === 'file' && (
            <input type="file" style={styles.previewInput} disabled />
          )}

          {field.help_text && (
            <div style={styles.previewHelpText}>{field.help_text}</div>
          )}
        </div>
      ))}

      <button style={styles.previewSubmitButton} disabled>
        {submitLabel}
      </button>
    </div>
  );
}


const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-secondary, #1e293b)',
  },
  title: {
    margin: 0,
    fontSize: '18px',
    fontWeight: '600',
  },
  headerActions: {
    display: 'flex',
    gap: '8px',
  },
  iconButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: 'none',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  iconButtonActive: {
    background: 'var(--accent-color, #3b82f6)',
    color: 'white',
  },
  content: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
  },
  builderPane: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'auto',
    padding: '20px',
  },
  previewPane: {
    width: '50%',
    borderLeft: '1px solid var(--border-color, #334155)',
    padding: '20px',
    overflow: 'auto',
    background: 'var(--bg-tertiary, #0d1424)',
  },
  previewTitle: {
    margin: '0 0 16px 0',
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--text-secondary, #94a3b8)',
  },
  section: {
    marginBottom: '24px',
  },
  sectionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px',
  },
  sectionTitle: {
    margin: '0 0 12px 0',
    fontSize: '14px',
    fontWeight: '600',
    color: 'var(--text-secondary, #94a3b8)',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  },
  formGroup: {
    marginBottom: '12px',
  },
  label: {
    display: 'block',
    fontSize: '12px',
    fontWeight: '500',
    color: 'var(--text-secondary, #94a3b8)',
    marginBottom: '6px',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: 'var(--text-primary, #f0f6fc)',
    cursor: 'pointer',
  },
  checkbox: {
    width: '16px',
    height: '16px',
  },
  input: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    boxSizing: 'border-box',
  },
  textarea: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    resize: 'vertical',
    boxSizing: 'border-box',
  },
  select: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
  },
  addFieldSelect: {
    padding: '6px 10px',
    border: '1px solid var(--accent-color, #3b82f6)',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--accent-color, #3b82f6)',
    fontSize: '12px',
    cursor: 'pointer',
  },
  fieldsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  emptyFields: {
    textAlign: 'center',
    padding: '32px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  emptyHint: {
    fontSize: '12px',
    marginTop: '8px',
  },
  fieldEditor: {
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '8px',
    background: 'var(--bg-secondary, #1e293b)',
    overflow: 'hidden',
  },
  fieldEditorDragging: {
    opacity: 0.5,
    border: '1px dashed var(--accent-color, #3b82f6)',
  },
  fieldHeader: {
    display: 'flex',
    alignItems: 'center',
    padding: '10px 12px',
    cursor: 'pointer',
    gap: '8px',
  },
  fieldDragHandle: {
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'grab',
  },
  fieldTypeIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '24px',
    height: '24px',
    borderRadius: '4px',
    background: 'var(--accent-color, #3b82f6)20',
    color: 'var(--accent-color, #3b82f6)',
  },
  fieldInfo: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  fieldLabel: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-primary, #f0f6fc)',
  },
  fieldMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  requiredBadge: {
    padding: '2px 6px',
    borderRadius: '4px',
    background: '#ef444420',
    color: '#ef4444',
    fontSize: '10px',
  },
  fieldActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  fieldActionButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '4px',
    border: 'none',
    borderRadius: '4px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  fieldSettings: {
    padding: '12px',
    borderTop: '1px solid var(--border-color, #334155)',
    background: 'var(--bg-primary, #0f172a)',
  },
  fieldSettingsGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '12px',
    marginBottom: '12px',
  },
  optionsSection: {
    marginTop: '12px',
    padding: '12px',
    borderRadius: '6px',
    background: 'var(--bg-secondary, #1e293b)',
  },
  optionsHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '8px',
  },
  addOptionButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    padding: '4px 8px',
    border: 'none',
    borderRadius: '4px',
    background: 'var(--accent-color, #3b82f6)20',
    color: 'var(--accent-color, #3b82f6)',
    fontSize: '11px',
    cursor: 'pointer',
  },
  optionsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  optionItem: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
  },
  removeOptionButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '6px',
    border: 'none',
    borderRadius: '4px',
    background: 'transparent',
    color: '#ef4444',
    cursor: 'pointer',
  },
  actions: {
    display: 'flex',
    gap: '12px',
    justifyContent: 'flex-end',
    marginTop: 'auto',
    paddingTop: '20px',
  },
  cancelButton: {
    padding: '10px 20px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '14px',
    cursor: 'pointer',
  },
  saveButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 20px',
    border: 'none',
    borderRadius: '6px',
    background: 'var(--accent-color, #3b82f6)',
    color: 'white',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
  },
  // Preview styles
  previewForm: {
    padding: '20px',
    borderRadius: '8px',
    background: 'var(--bg-secondary, #1e293b)',
  },
  previewFormName: {
    margin: '0 0 8px 0',
    fontSize: '18px',
    fontWeight: '600',
    color: 'var(--text-primary, #f0f6fc)',
  },
  previewFormDescription: {
    margin: '0 0 20px 0',
    fontSize: '13px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  previewField: {
    marginBottom: '16px',
  },
  previewLabel: {
    display: 'block',
    fontSize: '13px',
    fontWeight: '500',
    marginBottom: '6px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  previewRequired: {
    color: '#ef4444',
    marginLeft: '4px',
  },
  previewInput: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
    boxSizing: 'border-box',
  },
  previewTextarea: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
    resize: 'vertical',
    boxSizing: 'border-box',
  },
  previewSelect: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'var(--bg-primary, #0f172a)',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
  },
  previewCheckboxGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  previewRadioGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  previewCheckboxItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  previewRadioItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  previewHelpText: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
    marginTop: '4px',
  },
  previewSubmitButton: {
    width: '100%',
    padding: '10px',
    marginTop: '16px',
    border: 'none',
    borderRadius: '6px',
    background: 'var(--accent-color, #3b82f6)',
    color: 'white',
    fontSize: '14px',
    fontWeight: '500',
    opacity: 0.5,
    cursor: 'not-allowed',
  },
};

export default FormBuilder;
