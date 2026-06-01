import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Badge, Modal, Input, Select, SocTable } from './ui';
import { DataTableLayout } from '../layouts';
import { authFetch } from '../utils/api';
import RiggsSuggestions from './RiggsSuggestions';
import styles from './PlaybookList.module.css';

function PlaybookList() {
  const navigate = useNavigate();
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState({
    enabled: null,
    tag: '',
    search: ''
  });
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [confirmToggle, setConfirmToggle] = useState(null);

  const fetchPlaybooks = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams();
      if (filter.enabled !== null) {
        params.append('enabled', filter.enabled);
      }
      if (filter.tag) {
        params.append('tag', filter.tag);
      }

      const response = await authFetch(`/api/v1/playbooks?${params.toString()}`);

      if (!response.ok) {
        throw new Error(`Failed to fetch playbooks: ${response.status}`);
      }

      const data = await response.json();
      setPlaybooks(data.playbooks || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybooks();
  }, [filter.enabled, filter.tag]);

  const filteredPlaybooks = playbooks.filter(pb => {
    if (!filter.search) return true;
    const searchLower = filter.search.toLowerCase();
    return (
      pb.name.toLowerCase().includes(searchLower) ||
      (pb.description && pb.description.toLowerCase().includes(searchLower)) ||
      (pb.tags && pb.tags.some(tag => tag.toLowerCase().includes(searchLower)))
    );
  });

  const toggleEnabled = async (playbookId, currentStatus) => {
    try {
      const response = await authFetch(`/api/v1/playbooks/${playbookId}`, {
        method: 'PUT',
        body: JSON.stringify({ is_enabled: !currentStatus })
      });

      if (!response.ok) {
        throw new Error('Failed to update playbook');
      }

      fetchPlaybooks();
    } catch (err) {
      setError(err.message);
    }
  };

  const deletePlaybook = async (playbookId) => {
    try {
      const response = await authFetch(`/api/v1/playbooks/${playbookId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to delete playbook');
      }

      fetchPlaybooks();
    } catch (err) {
      setError(err.message);
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Name',
      render: (pb) => <strong>{pb.name}</strong>
    },
    {
      key: 'description',
      label: 'Description',
      render: (pb) => pb.description || <span className={styles.muted}>No description</span>
    },
    {
      key: 'status',
      label: 'Status',
      render: (pb) => (
        <span className={`${styles.badge} ${pb.is_enabled ? styles.badgeEnabled : styles.badgeDisabled}`}>
          {pb.is_enabled ? 'Enabled' : 'Disabled'}
        </span>
      )
    },
    {
      key: 'tags',
      label: 'Tags',
      render: (pb) => (
        pb.tags && pb.tags.length > 0 ? (
          pb.tags.slice(0, 3).map((tag, idx) => (
            <span key={idx} className={`${styles.badge} ${styles.badgeTag}`}>{tag}</span>
          ))
        ) : (
          <span className={styles.muted}>�</span>
        )
      )
    },
    {
      key: 'priority',
      label: 'Priority',
      render: (pb) => pb.priority || 50
    },
    {
      key: 'updated',
      label: 'Updated',
      render: (pb) => pb.updated_at ? new Date(pb.updated_at).toLocaleDateString() : '�'
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (pb) => (
        <div className={styles.actionRow} onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" size="sm" onClick={() => setConfirmToggle(pb)}>
            {pb.is_enabled ? 'Disable' : 'Enable'}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => navigate(`/playbooks/${pb.id}`)}>
            Edit
          </Button>
          <Button variant="danger" size="sm" onClick={() => setConfirmDelete(pb)}>
            Delete
          </Button>
        </div>
      )
    }
  ];

  return (
    <DataTableLayout
      title="Playbooks"
      subtitle="Manage and version automation playbooks"
      actions={
        <div className={styles.playbookActions}>
          <Button variant="secondary" onClick={() => navigate('/playbooks/import-soar')}>
            Import SOAR
          </Button>
          <Button onClick={() => navigate('/playbooks/new')}>
            Create New Playbook
          </Button>
        </div>
      }
    >
      {error && <div className={styles.emptyState}>Error: {error}</div>}

      <div className={styles.filters}>
        <Input
          label="Search"
          type="text"
          placeholder="Search by name, description, or tags..."
          value={filter.search}
          onChange={(e) => setFilter({ ...filter, search: e.target.value })}
        />
        <Select
          label="Status"
          value={filter.enabled === null ? 'all' : filter.enabled ? 'enabled' : 'disabled'}
          onChange={(e) => {
            const value = e.target.value;
            setFilter({
              ...filter,
              enabled: value === 'all' ? null : value === 'enabled'
            });
          }}
        >
          <option value="all">All</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </Select>
        <Input
          label="Tag"
          type="text"
          placeholder="Filter by tag..."
          value={filter.tag}
          onChange={(e) => setFilter({ ...filter, tag: e.target.value })}
        />
      </div>

      <RiggsSuggestions />

      <SocTable
        columns={columns}
        data={filteredPlaybooks}
        loading={loading}
        emptyMessage={filter.search || filter.tag || filter.enabled !== null
          ? 'No playbooks match your filters'
          : 'No playbooks yet'}
        onRowClick={(row) => navigate(`/playbooks/${row.id}`)}
      />

      {filteredPlaybooks.length > 0 && (
        <div className={styles.resultsCount}>
          Showing {filteredPlaybooks.length} of {playbooks.length} playbooks
        </div>
      )}

      <Modal
        open={!!confirmToggle}
        title="Change Playbook Status"
        onClose={() => setConfirmToggle(null)}
        onConfirm={() => {
          toggleEnabled(confirmToggle.id, confirmToggle.is_enabled);
          setConfirmToggle(null);
        }}
        confirmLabel={confirmToggle?.is_enabled ? 'Disable' : 'Enable'}
      >
        {confirmToggle && (
          <p>Change status for "{confirmToggle.name}"?</p>
        )}
      </Modal>

      <Modal
        open={!!confirmDelete}
        title="Delete Playbook"
        danger
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => {
          deletePlaybook(confirmDelete.id);
          setConfirmDelete(null);
        }}
        confirmLabel="Delete"
      >
        {confirmDelete && (
          <p>This will permanently delete "{confirmDelete.name}".</p>
        )}
      </Modal>
    </DataTableLayout>
  );
}

export default PlaybookList;
