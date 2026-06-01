/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { getAuthHeaders, getCsrfToken, API_BASE_URL } from '../../utils/api';
import styles from './InvestigationSidebar.module.css';

/**
 * Format a timestamp into a human-readable relative string.
 * Falls back to a short date if the timestamp is older than 30 days.
 */
function relativeTime(dateStr) {
  if (!dateStr) return '';
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  if (diffSec < 60) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  if (diffDay < 30) return `${diffDay}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * NotesPanel -- displays and manages investigation notes with markdown support.
 *
 * @param {string} investigationId - UUID of the current investigation
 * @param {object} currentUser     - Authenticated user object (must have .id and .username/.name)
 */
export default function NotesPanel({ investigationId, currentUser }) {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorMode, setEditorMode] = useState('edit'); // 'edit' | 'preview'
  const [editorContent, setEditorContent] = useState('');
  const [editingNoteId, setEditingNoteId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const textareaRef = useRef(null);

  // ---------------------------------------------------------------------------
  // Fetch notes
  // ---------------------------------------------------------------------------
  const fetchNotes = useCallback(async () => {
    if (!investigationId) return;
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}/notes`,
        { headers: getAuthHeaders(), credentials: 'include' }
      );
      if (!res.ok) throw new Error(`Failed to fetch notes: ${res.status}`);
      const data = await res.json();
      // Normalise: API may return { notes: [...] } or bare array
      const list = Array.isArray(data) ? data : (data.notes || []);
      // Newest first
      list.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setNotes(list);
    } catch (err) {
      console.error('[NotesPanel] fetchNotes error:', err);
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchNotes();
  }, [fetchNotes]);

  // ---------------------------------------------------------------------------
  // Create / Update note
  // ---------------------------------------------------------------------------
  const handleSave = async () => {
    const content = editorContent.trim();
    if (!content || saving) return;
    setSaving(true);

    try {
      const isEdit = editingNoteId !== null;
      const url = isEdit
        ? `${API_BASE_URL}/api/v1/investigations/${investigationId}/notes/${editingNoteId}`
        : `${API_BASE_URL}/api/v1/investigations/${investigationId}/notes`;
      const method = isEdit ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify({ content }),
      });

      if (!res.ok) throw new Error(`Save failed: ${res.status}`);

      // Reset editor
      setEditorOpen(false);
      setEditorContent('');
      setEditingNoteId(null);
      setEditorMode('edit');
      await fetchNotes();
    } catch (err) {
      console.error('[NotesPanel] handleSave error:', err);
    } finally {
      setSaving(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Delete note
  // ---------------------------------------------------------------------------
  const handleDelete = async (noteId) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}/notes/${noteId}`,
        {
          method: 'DELETE',
          headers: getAuthHeaders(),
          credentials: 'include',
        }
      );
      if (!res.ok) throw new Error(`Delete failed: ${res.status}`);
      await fetchNotes();
    } catch (err) {
      console.error('[NotesPanel] handleDelete error:', err);
    }
  };

  // ---------------------------------------------------------------------------
  // Start editing an existing note
  // ---------------------------------------------------------------------------
  const startEdit = (note) => {
    setEditorOpen(true);
    setEditorContent(note.content || '');
    setEditingNoteId(note.id);
    setEditorMode('edit');
  };

  // ---------------------------------------------------------------------------
  // Open new note editor
  // ---------------------------------------------------------------------------
  const openNewNote = () => {
    setEditorOpen(true);
    setEditorContent('');
    setEditingNoteId(null);
    setEditorMode('edit');
  };

  // ---------------------------------------------------------------------------
  // Cancel editor
  // ---------------------------------------------------------------------------
  const cancelEditor = () => {
    setEditorOpen(false);
    setEditorContent('');
    setEditingNoteId(null);
    setEditorMode('edit');
  };

  // ---------------------------------------------------------------------------
  // Image paste handler
  // ---------------------------------------------------------------------------
  const handlePaste = async (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (!file) return;

        setUploading(true);
        try {
          const formData = new FormData();
          formData.append('file', file);

          const csrf = getCsrfToken();
          const headers = {};
          if (csrf) headers['X-CSRF-Token'] = csrf;

          const res = await fetch(
            `${API_BASE_URL}/api/v1/investigations/${investigationId}/notes/upload`,
            {
              method: 'POST',
              headers,
              credentials: 'include',
              body: formData,
            }
          );

          if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
          const data = await res.json();
          const imageUrl = data.url || data.file_url || '';

          if (imageUrl && textareaRef.current) {
            const ta = textareaRef.current;
            const start = ta.selectionStart;
            const end = ta.selectionEnd;
            const before = editorContent.slice(0, start);
            const after = editorContent.slice(end);
            const markdown = `![image](${imageUrl})`;
            const newContent = before + markdown + after;
            setEditorContent(newContent);

            // Restore cursor after the inserted text
            requestAnimationFrame(() => {
              const pos = start + markdown.length;
              ta.selectionStart = pos;
              ta.selectionEnd = pos;
              ta.focus();
            });
          }
        } catch (err) {
          console.error('[NotesPanel] image upload error:', err);
        } finally {
          setUploading(false);
        }
        return; // Only handle the first image
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Ownership check
  // ---------------------------------------------------------------------------
  const isOwnNote = (note) => {
    if (!currentUser) return false;
    const authorId = note.author_id || note.user_id || note.created_by;
    return authorId === currentUser.id;
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className={styles.notesContainer}>
        <div className={styles.loadingState}>
          <div className={styles.loadingDots}>
            <div className={styles.loadingDot} />
            <div className={styles.loadingDot} />
            <div className={styles.loadingDot} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.notesContainer}>
      {/* Toolbar */}
      <div className={styles.notesToolbar}>
        <span className={styles.notesTitle}>
          Notes{notes.length > 0 ? ` (${notes.length})` : ''}
        </span>
        <button
          className={styles.addNoteButton}
          onClick={openNewNote}
          disabled={editorOpen}
        >
          + Add Note
        </button>
      </div>

      {/* Editor */}
      {editorOpen && (
        <div className={styles.editorContainer}>
          {/* Edit / Preview tabs */}
          <div className={styles.editorTabs}>
            <button
              className={`${styles.editorTab} ${editorMode === 'edit' ? styles.editorTabActive : ''}`}
              onClick={() => setEditorMode('edit')}
            >
              Edit
            </button>
            <button
              className={`${styles.editorTab} ${editorMode === 'preview' ? styles.editorTabActive : ''}`}
              onClick={() => setEditorMode('preview')}
            >
              Preview
            </button>
          </div>

          {editorMode === 'edit' ? (
            <textarea
              ref={textareaRef}
              className={styles.editorTextarea}
              placeholder="Write a note... (Markdown supported)"
              value={editorContent}
              onChange={(e) => setEditorContent(e.target.value)}
              onPaste={handlePaste}
              autoFocus
            />
          ) : (
            <div className={`${styles.editorPreview} ${styles.noteContent}`}>
              {editorContent.trim() ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {editorContent}
                </ReactMarkdown>
              ) : (
                <span style={{ color: 'var(--text-tertiary)' }}>Nothing to preview</span>
              )}
            </div>
          )}

          {/* Upload indicator */}
          {uploading && (
            <div className={styles.uploadIndicator}>
              <span className={styles.uploadSpinner} />
              Uploading image...
            </div>
          )}

          {/* Toolbar */}
          <div className={styles.editorToolbar}>
            <button className={styles.cancelButton} onClick={cancelEditor}>
              Cancel
            </button>
            <button
              className={styles.saveButton}
              onClick={handleSave}
              disabled={!editorContent.trim() || saving}
            >
              {saving ? 'Saving...' : editingNoteId ? 'Update' : 'Save'}
            </button>
          </div>
        </div>
      )}

      {/* Notes list or empty state */}
      {notes.length === 0 ? (
        <div className={styles.emptyState}>
          <div className={styles.emptyStateIcon}>--</div>
          <div className={styles.emptyStateText}>
            No notes yet. Add one to get started.
          </div>
        </div>
      ) : (
        <div className={styles.notesList}>
          {notes.map((note) => (
            <div key={note.id} className={styles.noteCard}>
              <div className={styles.noteHeader}>
                <span className={styles.noteAuthor}>
                  {note.author_name || note.username || 'Unknown'}
                </span>
                <span className={styles.noteTimestamp}>
                  {relativeTime(note.created_at)}
                </span>
              </div>
              <div className={styles.noteContent}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {note.content || ''}
                </ReactMarkdown>
              </div>
              {isOwnNote(note) && (
                <div className={styles.noteActions}>
                  <button
                    className={styles.noteActionButton}
                    onClick={() => startEdit(note)}
                  >
                    Edit
                  </button>
                  <button
                    className={`${styles.noteActionButton} ${styles.noteActionButtonDanger}`}
                    onClick={() => handleDelete(note.id)}
                  >
                    Delete
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
