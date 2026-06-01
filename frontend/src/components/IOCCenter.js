/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import IOCManagement from './IOCManagement';
import { API_BASE_URL, authFetch, getAuthHeaders } from '../utils/api';
import { useToast } from './ui/Toast';
import './ThreatIntelShell.css';
import ThreatIntelTabs from './ThreatIntelTabs';

const API_BASE = `${API_BASE_URL}/api/v1/threat-intel`;
const FEEDS_API_BASE = `${API_BASE_URL}/api/v1/threat-feeds`;

// Auth headers imported from shared utils/api (includes CSRF token and credentials)

// Default column configuration
const DEFAULT_COLUMNS = [
  { id: 'value', label: 'IOC', visible: true, sortable: true },
  { id: 'type', label: 'Type', visible: true, sortable: true, filterable: true },
  { id: 'verdict', label: 'Verdict', visible: true, sortable: true, filterable: true },
  { id: 'severity', label: 'Severity', visible: true, sortable: true, filterable: true },
  { id: 'source', label: 'Source', visible: true, sortable: true, filterable: true },
  { id: 'feed_name', label: 'Feed', visible: false, sortable: true, filterable: true },
  { id: 'occurrences', label: 'Hits', visible: false, sortable: true },
  { id: 'first_seen', label: 'First Seen', visible: false, sortable: true },
  { id: 'last_seen', label: 'Last Seen', visible: true, sortable: true },
  { id: 'tags', label: 'Tags', visible: false, sortable: false },
];

function IOCCenter() {
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();

  // Determine initial view based on URL path
  const getInitialView = () => {
    if (location.pathname === '/threat-intel/iocs' || location.pathname === '/threat-intel/database') return 'database';
    if (location.pathname === '/threat-intel/feeds') return 'feeds';
    if (location.pathname === '/threat-intel/lookup') return 'lookup';
    if (location.pathname === '/threat-intel/submit') return 'submit';
    if (location.pathname === '/threat-intel/whitelist') return 'whitelist';
    // Default to database view instead of lookup
    return 'database';
  };

  // Main view: 'lookup', 'database', 'whitelist', 'submit'
  const [mainView, setMainView] = useState(getInitialView);

  // IOC List state
  const [iocs, setIocs] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearchTerm, setDebouncedSearchTerm] = useState('');
  const searchInputRef = useRef(null);

  // Pagination state - load from localStorage
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(() => {
    const saved = localStorage.getItem('iocCenterRowsPerPage');
    return saved ? parseInt(saved, 10) : 20;
  });

  // Column configuration
  const [columns, setColumns] = useState(() => {
    const saved = localStorage.getItem('iocCenterColumns');
    return saved ? JSON.parse(saved) : DEFAULT_COLUMNS;
  });
  const [showColumnConfig, setShowColumnConfig] = useState(false);

  // Column filter state
  const [columnFilters, setColumnFilters] = useState({
    type: null,
    verdict: null,
    severity: null,
    source: null,
    feed_name: null
  });
  const [activeFilterColumn, setActiveFilterColumn] = useState(null);

  // Time range filter
  const [timeRange, setTimeRange] = useState(null); // null = all time

  // Quick lookup state
  const [lookupValue, setLookupValue] = useState('');
  const [lookupType, setLookupType] = useState('auto');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState(null);

  // Bulk lookup state (from alert context)
  const [bulkLookupResults, setBulkLookupResults] = useState([]);
  const [bulkLookupLoading, setBulkLookupLoading] = useState(false);
  const [showBulkResults, setShowBulkResults] = useState(false);

  // Enrichment state
  const [enrichingIOC, setEnrichingIOC] = useState(null);

  // Selection state for bulk operations
  const [selectedIOCs, setSelectedIOCs] = useState(new Set());
  const [showBulkEditModal, setShowBulkEditModal] = useState(false);
  const [bulkEditData, setBulkEditData] = useState({ verdict: '', severity: '', tags_add: '', tags_remove: '' });
  const [deleteConfirm, setDeleteConfirm] = useState(null); // IOC value to confirm delete
  const [bulkDeleteConfirm, setBulkDeleteConfirm] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  // Supported types from API
  const [supportedTypes, setSupportedTypes] = useState([]);

  // Sort state
  const [sortConfig, setSortConfig] = useState({ key: 'last_seen', direction: 'desc' });

  // File upload state
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadFormat, setUploadFormat] = useState('txt_lines');
  const [uploadSourceName, setUploadSourceName] = useState('Manual Upload');
  const [uploadSeverity, setUploadSeverity] = useState('medium');
  const [uploadTags, setUploadTags] = useState('');
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [uploadPreview, setUploadPreview] = useState(null);
  const [uploadError, setUploadError] = useState(null);
  const fileInputRef = useRef(null);

  // Save columns to localStorage when changed
  useEffect(() => {
    localStorage.setItem('iocCenterColumns', JSON.stringify(columns));
  }, [columns]);

  // Save rowsPerPage to localStorage when changed
  useEffect(() => {
    localStorage.setItem('iocCenterRowsPerPage', rowsPerPage.toString());
  }, [rowsPerPage]);

  // Update view when URL changes
  useEffect(() => {
    if (location.pathname === '/threat-intel/iocs') {
      setMainView('database');
    } else if (location.pathname === '/threat-intel') {
      // Default to database when no specific path
      setMainView('database');
    }
  }, [location.pathname]);

  // Handle bulk IOC lookups from query parameter (from alert context)
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const iocsParam = params.get('iocs');

    if (iocsParam) {
      const iocValues = iocsParam.split(',').filter(v => v.trim());
      if (iocValues.length > 0) {
        setShowBulkResults(true);
        performBulkLookup(iocValues);
      }
    }
  }, [location.search]);

  // Bulk lookup function
  const performBulkLookup = async (iocValues) => {
    setBulkLookupLoading(true);
    setBulkLookupResults([]);

    const results = [];

    for (const value of iocValues) {
      try {
        const type = detectIOCType(value);
        let endpoint;

        if (type === 'ip') {
          endpoint = `${API_BASE}/lookup/ip/${encodeURIComponent(value)}`;
        } else if (type === 'domain') {
          endpoint = `${API_BASE}/lookup/domain/${encodeURIComponent(value)}`;
        } else if (type.startsWith('hash')) {
          endpoint = `${API_BASE}/lookup/hash/${encodeURIComponent(value)}`;
        } else {
          // For URLs and other types, use enrich endpoint
          const response = await authFetch(`${API_BASE}/enrich`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ value, type })
          });
          const data = await response.json();
          results.push({ value, type, ...data, success: true });
          continue;
        }

        const response = await authFetch(endpoint, { headers: getAuthHeaders() });
        if (response.ok) {
          const data = await response.json();
          results.push({ value, type, ...data, success: true });
        } else {
          results.push({ value, type, success: false, error: 'Lookup failed' });
        }
      } catch (error) {
        results.push({ value, type: 'unknown', success: false, error: error.message });
      }
    }

    setBulkLookupResults(results);
    setBulkLookupLoading(false);
  };

  // Auto-detect IOC type (moved up so it can be used by performBulkLookup)
  const detectIOCType = useCallback((value) => {
    if (!value) return 'ip';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (value.includes(':') && /^[0-9a-fA-F:]+$/.test(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash_md5';
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash_sha1';
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash_sha256';
    if (value.startsWith('http://') || value.startsWith('https://')) return 'url';
    if (value.includes('@') && value.includes('.')) return 'email';
    if (value.includes('.') && !value.includes('/') && !value.includes('@')) return 'domain';
    return 'ip';
  }, []);

  // Debounce search term - wait 300ms after user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearchTerm(searchTerm);
      setCurrentPage(1); // Reset to page 1 on search change
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Fetch IOCs - only re-fetches when debounced search changes, NOT on every keystroke
  const fetchIOCs = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      // Use debounced search term for API query
      if (debouncedSearchTerm) params.append('query', debouncedSearchTerm);
      if (columnFilters.type) params.append('type', columnFilters.type);
      if (columnFilters.severity) params.append('severity', columnFilters.severity);
      if (columnFilters.verdict) params.append('verdict', columnFilters.verdict);
      if (timeRange) {
        const now = new Date();
        const since = new Date(now.getTime() - timeRange * 24 * 60 * 60 * 1000);
        params.append('since', since.toISOString());
      }
      params.append('limit', String(rowsPerPage));
      params.append('offset', String((currentPage - 1) * rowsPerPage));

      const response = await authFetch(`${API_BASE}/iocs?${params}`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      setIocs(data.iocs || []);
      setTotalCount(data.total || data.iocs?.length || 0);
    } catch (error) {
      // silently handle fetch errors
    }
  }, [debouncedSearchTerm, columnFilters, timeRange, currentPage, rowsPerPage]);

  // Fetch stats
  const fetchStats = async () => {
    try {
      const response = await authFetch(`${API_BASE}/stats`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      setStats(data);
    } catch (error) {
      // silently handle fetch errors
    }
  };

  // Fetch supported types
  const fetchTypes = async () => {
    try {
      const response = await authFetch(`${API_BASE}/types`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      setSupportedTypes(data.types || []);
    } catch (error) {
      // silently handle fetch errors
    }
  };

  // Initial load - only runs once
  useEffect(() => {
    const initialLoad = async () => {
      setLoading(true);
      await Promise.all([fetchIOCs(), fetchStats(), fetchTypes()]);
      setLoading(false);
    };
    initialLoad();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Refetch IOCs when search/filters/page change - NO loading spinner, just update data
  useEffect(() => {
    // Skip on initial mount (loading handles that)
    if (loading) return;
    fetchIOCs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearchTerm, columnFilters, timeRange, currentPage, rowsPerPage]);

  // Close filter dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (activeFilterColumn && !e.target.closest('.column-filter-dropdown')) {
        setActiveFilterColumn(null);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [activeFilterColumn]);

  // File upload functions
  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setUploadFile(file);
      setUploadResult(null);
      setUploadError(null);
      setUploadPreview(null);
      // Auto-preview
      previewFile(file);
    }
  };

  const previewFile = async (file) => {
    if (!file) return;
    
    setUploadLoading(true);
    setUploadError(null);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('format', uploadFormat);
      formData.append('max_preview', '50');const response = await authFetch(`${FEEDS_API_BASE}/upload/preview`, {
        method: 'POST',
        body: formData
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Preview failed');
      }
      
      const result = await response.json();
      setUploadPreview(result);
    } catch (error) {
      setUploadError(error.message);
    } finally {
      setUploadLoading(false);
    }
  };

  const handleUpload = async () => {
    if (!uploadFile) return;
    
    setUploadLoading(true);
    setUploadError(null);
    setUploadResult(null);
    
    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      formData.append('format', uploadFormat);
      formData.append('source_name', uploadSourceName);
      formData.append('severity', uploadSeverity);
      formData.append('tags', uploadTags);const response = await authFetch(`${FEEDS_API_BASE}/upload`, {
        method: 'POST',
        body: formData
      });
      
      const result = await response.json();
      
      if (result.success) {
        setUploadResult(result);
        setUploadFile(null);
        setUploadPreview(null);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      } else {
        setUploadError(result.error || 'Upload failed');
      }
    } catch (error) {
      setUploadError(error.message);
    } finally {
      setUploadLoading(false);
    }
  };

  const clearUpload = () => {
    setUploadFile(null);
    setUploadPreview(null);
    setUploadResult(null);
    setUploadError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Quick lookup
  const performLookup = async () => {
    if (!lookupValue.trim()) return;

    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const type = lookupType === 'auto' ? detectIOCType(lookupValue) : lookupType;

      let endpoint;
      if (type === 'ip') {
        endpoint = `${API_BASE}/lookup/ip/${encodeURIComponent(lookupValue)}`;
      } else if (type === 'domain') {
        endpoint = `${API_BASE}/lookup/domain/${encodeURIComponent(lookupValue)}`;
      } else if (type.startsWith('hash')) {
        endpoint = `${API_BASE}/lookup/hash/${encodeURIComponent(lookupValue)}`;
      } else {
        const response = await authFetch(`${API_BASE}/enrich`, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({ value: lookupValue, type })
        });
        const data = await response.json();
        setLookupResult(data);
        setLookupLoading(false);
        fetchIOCs();
        return;
      }

      const response = await authFetch(endpoint, { headers: getAuthHeaders() });
      const data = await response.json();
      setLookupResult(data);
      fetchIOCs();
    } catch (error) {
      setLookupError(error.message || 'Lookup failed');
    }
    setLookupLoading(false);
  };

  // Enrich a specific IOC
  const enrichIOC = async (ioc) => {
    setEnrichingIOC(ioc.value);
    try {
      const response = await authFetch(`${API_BASE}/enrich`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          value: ioc.value,
          type: ioc.type,
          force_refresh: true
        })
      });
      const data = await response.json();
      setIocs(prev => prev.map(i =>
        i.value === ioc.value ? { ...i, ...data.ioc, enrichments: data.enrichments } : i
      ));
    } catch (error) {
    }
    setEnrichingIOC(null);
  };

  // Delete a single IOC
  const deleteIOC = async (iocValue) => {
    setActionLoading(true);
    try {
      const response = await authFetch(`${API_BASE}/iocs/${encodeURIComponent(iocValue)}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      if (response.ok) {
        setIocs(prev => prev.filter(i => i.value !== iocValue));
        setDeleteConfirm(null);
        setSelectedIOCs(prev => {
          const newSet = new Set(prev);
          newSet.delete(iocValue);
          return newSet;
        });
      } else {
        const error = await response.json();
        toast.error('Delete failed: ' + (error.detail || 'Unknown error'));
      }
    } catch (error) {
      toast.error('Delete failed: ' + error.message);
    }
    setActionLoading(false);
  };

  // Bulk delete IOCs
  const bulkDeleteIOCs = async () => {
    setActionLoading(true);
    try {
      const response = await authFetch(`${API_BASE}/iocs/bulk-delete`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ iocs: Array.from(selectedIOCs) })
      });
      const data = await response.json();
      if (response.ok) {
        setIocs(prev => prev.filter(i => !selectedIOCs.has(i.value)));
        setSelectedIOCs(new Set());
        setBulkDeleteConfirm(false);
      } else {
        toast.error('Bulk delete failed: ' + (data.detail || 'Unknown error'));
      }
    } catch (error) {
      toast.error('Bulk delete failed: ' + error.message);
    }
    setActionLoading(false);
  };

  // Bulk update IOCs
  const bulkUpdateIOCs = async () => {
    setActionLoading(true);
    try {
      const payload = {
        iocs: Array.from(selectedIOCs),
        verdict: bulkEditData.verdict || null,
        severity: bulkEditData.severity || null,
        tags_add: bulkEditData.tags_add ? bulkEditData.tags_add.split(',').map(t => t.trim()).filter(t => t) : null,
        tags_remove: bulkEditData.tags_remove ? bulkEditData.tags_remove.split(',').map(t => t.trim()).filter(t => t) : null
      };

      const response = await authFetch(`${API_BASE}/iocs/bulk-update`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (response.ok) {
        // Refresh the IOC list to show updates
        fetchIOCs();
        setSelectedIOCs(new Set());
        setShowBulkEditModal(false);
        setBulkEditData({ verdict: '', severity: '', tags_add: '', tags_remove: '' });
      } else {
        toast.error('Bulk update failed: ' + (data.detail || 'Unknown error'));
      }
    } catch (error) {
      toast.error('Bulk update failed: ' + error.message);
    }
    setActionLoading(false);
  };

  // Toggle selection for a single IOC
  const toggleSelection = (iocValue) => {
    setSelectedIOCs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(iocValue)) {
        newSet.delete(iocValue);
      } else {
        newSet.add(iocValue);
      }
      return newSet;
    });
  };

  // Select/deselect all visible IOCs
  const toggleSelectAll = () => {
    if (selectedIOCs.size === paginatedIOCs.length) {
      setSelectedIOCs(new Set());
    } else {
      setSelectedIOCs(new Set(paginatedIOCs.map(i => i.value)));
    }
  };

  const getVerdictColor = (verdict) => {
    const colors = {
      clean: '#22c55e',
      benign: '#22c55e',
      suspicious: '#eab308',
      malicious: '#dc2626',
      unknown: '#6b7280'
    };
    return colors[verdict?.toLowerCase()] || colors.unknown;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#eab308',
      low: '#22c55e',
      unknown: '#6b7280'
    };
    return colors[severity?.toLowerCase()] || colors.unknown;
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num?.toLocaleString() || '0';
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Get unique values for column filters
  const getUniqueValues = (key) => {
    const values = new Set();
    iocs.forEach(ioc => {
      if (ioc[key]) values.add(ioc[key]);
    });
    return Array.from(values).sort();
  };

  // Filter IOCs - server handles search, we only do column filters client-side
  // Note: search is done server-side via the `query` param, no client-side search filter needed
  const filteredIOCs = iocs.filter(ioc => {
    if (columnFilters.type && ioc.type !== columnFilters.type) return false;
    if (columnFilters.verdict && ioc.verdict !== columnFilters.verdict) return false;
    if (columnFilters.severity && ioc.severity !== columnFilters.severity) return false;
    if (columnFilters.source && ioc.source !== columnFilters.source) return false;
    return true;
  });

  // Sort
  const sortedIOCs = [...filteredIOCs].sort((a, b) => {
    const aVal = a[sortConfig.key] || '';
    const bVal = b[sortConfig.key] || '';
    if (sortConfig.direction === 'asc') {
      return aVal > bVal ? 1 : -1;
    }
    return aVal < bVal ? 1 : -1;
  });

  // Server-side pagination: totalCount comes from API, sortedIOCs is already the current page
  const totalPages = Math.ceil(totalCount / rowsPerPage);
  const paginatedIOCs = sortedIOCs; // Already paginated server-side

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [columnFilters, searchTerm, timeRange]);

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const clearAllFilters = () => {
    setColumnFilters({ type: null, verdict: null, severity: null, source: null, feed_name: null });
    setSearchTerm('');
    setTimeRange(null);
  };

  // Toggle column visibility
  const toggleColumn = (columnId) => {
    setColumns(prev => prev.map(col =>
      col.id === columnId ? { ...col, visible: !col.visible } : col
    ));
  };

  // Move column up/down
  const moveColumn = (columnId, direction) => {
    const idx = columns.findIndex(c => c.id === columnId);
    if ((direction === -1 && idx === 0) || (direction === 1 && idx === columns.length - 1)) return;
    const newColumns = [...columns];
    const [removed] = newColumns.splice(idx, 1);
    newColumns.splice(idx + direction, 0, removed);
    setColumns(newColumns);
  };

  // Reset columns to default
  const resetColumns = () => {
    setColumns(DEFAULT_COLUMNS);
  };

  // Get visible columns
  const visibleColumns = columns.filter(c => c.visible);

  const activeFilterCount = Object.values(columnFilters).filter(v => v !== null).length + (timeRange ? 1 : 0);

  // Column filter dropdown component
  const ColumnFilterDropdown = ({ column, label, options }) => {
    const isActive = activeFilterColumn === column;
    const hasFilter = columnFilters[column] !== null;

    return (
      <div className="column-filter-dropdown" style={{ position: 'relative', display: 'inline-block' }}>
        <button
          onClick={(e) => {
            e.stopPropagation();
            setActiveFilterColumn(isActive ? null : column);
          }}
          style={{
            background: hasFilter ? 'rgba(60, 179, 113, 0.2)' : 'transparent',
            border: 'none',
            color: hasFilter ? '#3CB371' : 'var(--text-muted)',
            cursor: 'pointer',
            padding: '0.25rem 0.5rem',
            borderRadius: '4px',
            fontSize: '0.7rem',
            fontWeight: '600',
            textTransform: 'uppercase',
            display: 'flex',
            alignItems: 'center',
            gap: '0.25rem'
          }}
        >
          {label}
          <span style={{ fontSize: '0.55rem', marginLeft: '2px' }}>{hasFilter ? '\u2715' : (isActive ? '\u25B2' : '\u25BC')}</span>
        </button>

        {isActive && (
          <div style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '6px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            zIndex: 100,
            minWidth: '150px',
            maxHeight: '250px',
            overflow: 'auto'
          }}>
            <div
              onClick={() => {
                setColumnFilters(prev => ({ ...prev, [column]: null }));
                setActiveFilterColumn(null);
              }}
              style={{
                padding: '0.5rem 0.75rem',
                cursor: 'pointer',
                fontSize: '0.75rem',
                color: columnFilters[column] === null ? '#3CB371' : 'var(--text-secondary)',
                fontWeight: columnFilters[column] === null ? '600' : '400',
                borderBottom: '1px solid var(--bg-tertiary)'
              }}
            >
              All
            </div>
            {options.map(opt => (
              <div
                key={opt}
                onClick={() => {
                  setColumnFilters(prev => ({ ...prev, [column]: opt }));
                  setActiveFilterColumn(null);
                }}
                style={{
                  padding: '0.5rem 0.75rem',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  color: columnFilters[column] === opt ? '#3CB371' : 'var(--text-secondary)',
                  fontWeight: columnFilters[column] === opt ? '600' : '400'
                }}
                onMouseEnter={(e) => e.target.style.background = 'var(--bg-tertiary)'}
                onMouseLeave={(e) => e.target.style.background = 'transparent'}
              >
                {opt}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem' }}>
        <div className="spinner"></div>
        <p style={{ color: 'var(--text-muted)', marginTop: '1rem' }}>Loading Threat Intelligence...</p>
      </div>
    );
  }

  // Render upload view
  const renderUploadView = () => (
    <div className="card" style={{ marginBottom: '1rem' }}>
      <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem' }}>Upload IOC File</h3>

      {/* File selection */}
      <div style={{ marginBottom: '1rem' }}>
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
          accept=".txt,.csv,.json,.stix"
          style={{ display: 'none' }}
        />
        <div
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: '2px dashed var(--border-color)',
            borderRadius: '8px',
            padding: '2rem',
            textAlign: 'center',
            cursor: 'pointer',
            background: 'var(--bg-secondary)',
            transition: 'all 0.2s'
          }}
          onDragOver={(e) => { e.preventDefault(); e.currentTarget.style.borderColor = 'var(--primary)'; }}
          onDragLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
          onDrop={(e) => {
            e.preventDefault();
            e.currentTarget.style.borderColor = 'var(--border-color)';
            const file = e.dataTransfer.files[0];
            if (file) {
              setUploadFile(file);
              setUploadResult(null);
              setUploadError(null);
              previewFile(file);
            }
          }}
        >
          {uploadFile ? (
            <div>
              <span style={{ fontSize: '1.5rem' }}>📄</span>
              <p style={{ margin: '0.5rem 0', fontWeight: '500' }}>{uploadFile.name}</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {(uploadFile.size / 1024).toFixed(1)} KB
              </p>
            </div>
          ) : (
            <div>
              <span style={{ fontSize: '2rem' }}>📁</span>
              <p style={{ margin: '0.5rem 0', color: 'var(--text-muted)' }}>
                Click or drag file to upload
              </p>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Supports: TXT, CSV, JSON, STIX
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Upload options */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
        <div>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Format</label>
          <select
            value={uploadFormat}
            onChange={(e) => { setUploadFormat(e.target.value); if (uploadFile) previewFile(uploadFile); }}
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.8rem'
            }}
          >
            <option value="txt_lines">Plain Text (one per line)</option>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="json_lines">JSON Lines</option>
            <option value="stix">STIX 2.x</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Source Name</label>
          <input
            type="text"
            value={uploadSourceName}
            onChange={(e) => setUploadSourceName(e.target.value)}
            placeholder="Manual Upload"
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.8rem'
            }}
          />
        </div>
        <div>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Severity</label>
          <select
            value={uploadSeverity}
            onChange={(e) => setUploadSeverity(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.8rem'
            }}
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Tags (comma-separated)</label>
          <input
            type="text"
            value={uploadTags}
            onChange={(e) => setUploadTags(e.target.value)}
            placeholder="e.g., phishing, malware"
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.8rem'
            }}
          />
        </div>
      </div>

      {/* Preview */}
      {uploadPreview && (
        <div style={{ marginBottom: '1rem', padding: '1rem', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: '600', marginBottom: '0.5rem' }}>
            Preview: {uploadPreview.total_iocs_found} IOCs detected
          </h4>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
            {Object.entries(uploadPreview.by_type || {}).map(([type, iocs]) => (
              <span key={type} style={{
                padding: '0.25rem 0.5rem',
                background: 'var(--bg-secondary)',
                borderRadius: '4px',
                fontSize: '0.75rem'
              }}>
                {type}: {iocs.length}
              </span>
            ))}
          </div>
          <div style={{ maxHeight: '150px', overflowY: 'auto', fontSize: '0.75rem', fontFamily: 'monospace' }}>
            {uploadPreview.sample?.slice(0, 10).map((ioc, i) => (
              <div key={i} style={{ padding: '0.25rem 0', borderBottom: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--text-muted)', marginRight: '0.5rem' }}>[{ioc.type}]</span>
                {ioc.value}
              </div>
            ))}
            {uploadPreview.total_iocs_found > 10 && (
              <div style={{ color: 'var(--text-muted)', padding: '0.5rem 0' }}>
                ... and {uploadPreview.total_iocs_found - 10} more
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error */}
      {uploadError && (
        <div style={{ marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#ef4444' }}>
          {uploadError}
        </div>
      )}

      {/* Success result */}
      {uploadResult && (
        <div style={{ marginBottom: '1rem', padding: '1rem', background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '6px' }}>
          <h4 style={{ color: '#22c55e', marginBottom: '0.5rem' }}>Upload Complete!</h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', fontSize: '0.85rem' }}>
            <div><strong>{uploadResult.iocs_found}</strong> Found</div>
            <div><strong>{uploadResult.iocs_new}</strong> New</div>
            <div><strong>{uploadResult.iocs_updated}</strong> Updated</div>
            <div><strong>{uploadResult.iocs_skipped}</strong> Skipped</div>
          </div>
        </div>
      )}

      {/* Actions */}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          onClick={handleUpload}
          disabled={!uploadFile || uploadLoading}
          style={{
            padding: '0.6rem 1.5rem',
            background: uploadFile && !uploadLoading ? 'var(--primary)' : 'var(--bg-tertiary)',
            color: uploadFile && !uploadLoading ? 'white' : 'var(--text-muted)',
            border: 'none',
            borderRadius: '6px',
            cursor: uploadFile && !uploadLoading ? 'pointer' : 'not-allowed',
            fontWeight: '500',
            fontSize: '0.85rem'
          }}
        >
          {uploadLoading ? 'Processing...' : 'Upload & Import'}
        </button>
        {uploadFile && (
          <button
            onClick={clearUpload}
            style={{
              padding: '0.6rem 1rem',
              background: 'transparent',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );

  const timeRangeOptions = [
    { value: null, label: 'All Time' },
    { value: 1, label: '24 Hours' },
    { value: 7, label: '7 Days' },
    { value: 14, label: '14 Days' },
    { value: 30, label: '30 Days' },
    { value: 60, label: '60 Days' },
    { value: 90, label: '90 Days' }
  ];

  return (
    <div className="threat-intel-shell">
      <div className="ti-shell">
        <header className="ti-topbar">
          <div className="ti-title-group">
            <span className="ti-badge">Threat Intel</span>
            <div>
              <div className="ti-title">IOC Center</div>
              <div className="ti-subtitle">Lookup, enrich, and manage indicators across your sources.</div>
            </div>
          </div>
          <div className="ti-topbar-actions">
            {mainView === 'database' && stats && (
              <span className="ti-pill">Total IOCs: {formatNumber(stats.iocs?.total || 0)}</span>
            )}
            {mainView === 'lookup' && (
              <span className="ti-pill">Live enrichment ready</span>
            )}
          </div>
        </header>
        <div className="ti-panel">
          <div style={{ padding: '0' }}>
      {/* Tab Navigation */}
      <ThreatIntelTabs
        active={mainView === 'database' ? 'database' : mainView}
        onNavigate={(item) => {
          if (item.id === 'feeds' || item.id === 'edl') {
            navigate(item.path);
            return;
          }
          setMainView(item.id);
          navigate(item.path);
        }}
        items={[
          { id: 'database', label: 'IOC Database', path: '/threat-intel/database' },
          { id: 'lookup', label: 'Lookup & Enrich', path: '/threat-intel/lookup' },
          { id: 'submit', label: 'Submit IOCs', path: '/threat-intel/submit' },
          { id: 'whitelist', label: 'Whitelist', path: '/threat-intel/whitelist' },
          { id: 'feeds', label: 'Threat Feeds', path: '/threat-intel/feeds' },
          { id: 'edl', label: 'EDL Lists', path: '/threat-intel/edl' },
        ]}
      />

      {/* Upload View */}
      {mainView === 'upload' && renderUploadView()}

      {/* Whitelist View */}
      {mainView === 'whitelist' && <IOCManagement mode="whitelist" hideTabNavigation={true} />}

      {/* Submit IOCs View */}
      {mainView === 'submit' && <IOCManagement mode="submit" hideTabNavigation={true} />}

      {/* Lookup View */}
      {mainView === 'lookup' && (
        <>
          {/* Quick Lookup Bar */}
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Enter IP, domain, hash, or URL..."
              value={lookupValue}
              onChange={(e) => setLookupValue(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && performLookup()}
              style={{
                flex: 1,
                padding: '0.6rem 0.75rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '0.85rem'
              }}
            />
            <select
              value={lookupType}
              onChange={(e) => setLookupType(e.target.value)}
              style={{
                padding: '0.6rem 0.5rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '0.85rem'
              }}
            >
              <option value="auto">Auto-detect</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_md5">MD5</option>
              <option value="hash_sha1">SHA1</option>
              <option value="hash_sha256">SHA256</option>
              <option value="email">Email</option>
            </select>
            <button
              onClick={performLookup}
              disabled={lookupLoading || !lookupValue.trim()}
              style={{
                padding: '0.6rem 1.25rem',
                background: lookupLoading ? 'var(--bg-tertiary)' : 'var(--primary)',
                border: 'none',
                borderRadius: '6px',
                color: 'white',
                fontWeight: '600',
                cursor: lookupLoading ? 'not-allowed' : 'pointer',
                fontSize: '0.85rem'
              }}
            >
              {lookupLoading ? 'Checking...' : 'Lookup'}
            </button>
          </div>

          {/* Lookup Result */}
          {lookupResult && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '1rem',
              padding: '0.75rem 1rem',
              background: 'var(--bg-secondary)',
              borderRadius: '8px',
              borderLeft: `4px solid ${getVerdictColor(lookupResult.verdict || lookupResult.consensus_verdict)}`,
              marginBottom: '1rem'
            }}>
              <code style={{ fontSize: '0.9rem', fontWeight: '600' }}>
                {lookupResult.ip || lookupResult.domain || lookupResult.hash || lookupResult.ioc?.value || lookupValue}
              </code>
              <span style={{
                padding: '0.25rem 0.6rem',
                background: getVerdictColor(lookupResult.verdict || lookupResult.consensus_verdict) + '20',
                color: getVerdictColor(lookupResult.verdict || lookupResult.consensus_verdict),
                borderRadius: '4px',
                fontSize: '0.8rem',
                fontWeight: '700',
                textTransform: 'uppercase'
              }}>
                {lookupResult.verdict || lookupResult.consensus_verdict || 'Unknown'}
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {lookupResult.sources_checked || lookupResult.enrichments?.length || 0} sources
                {lookupResult.sources_flagged > 0 && <span style={{ color: '#dc2626' }}> • {lookupResult.sources_flagged} flagged</span>}
              </span>
              <button
                onClick={() => navigate(`/threat-intel/${encodeURIComponent(lookupResult.ioc?.value || lookupValue)}`)}
                style={{
                  marginLeft: 'auto',
                  padding: '0.4rem 0.75rem',
                  background: 'var(--primary)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  cursor: 'pointer',
                  fontSize: '0.8rem',
                  fontWeight: '500'
                }}
              >
                View Details
              </button>
            </div>
          )}

          {lookupError && (
            <div style={{
              padding: '0.75rem 1rem',
              background: 'rgba(220, 38, 38, 0.1)',
              borderRadius: '6px',
              color: '#dc2626',
              fontSize: '0.85rem',
              marginBottom: '1rem'
            }}>
              {lookupError}
            </div>
          )}
        </>
      )}

      {/* Bulk Lookup Results - From Alert Context */}
      {showBulkResults && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: '600' }}>Alert IOC Analysis</span>
            <span style={{
              marginLeft: '0.5rem',
              background: 'rgba(245, 158, 11, 0.15)',
              color: '#f59e0b',
              padding: '0.15rem 0.5rem',
              borderRadius: '10px',
              fontSize: '0.75rem',
              fontWeight: '600'
            }}>
              {bulkLookupResults.length}
            </span>
            <button
              onClick={() => {
                setShowBulkResults(false);
                setBulkLookupResults([]);
                navigate('/threat-intel', { replace: true });
              }}
              style={{
                marginLeft: 'auto',
                background: 'transparent',
                border: '1px solid var(--border-color)',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '0.75rem',
                padding: '0.25rem 0.5rem',
                borderRadius: '4px'
              }}
            >
              Close
            </button>
          </div>

          {bulkLookupLoading ? (
            <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
              <div className="spinner" style={{ margin: '0 auto 0.5rem' }}></div>
              Analyzing indicators...
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {bulkLookupResults.map((result, idx) => {
                const getVerdictColor = (verdict) => {
                  if (!verdict) return '#6b7280';
                  const v = verdict.toLowerCase();
                  if (v === 'malicious') return '#dc2626';
                  if (v === 'suspicious') return '#ea580c';
                  if (v === 'benign' || v === 'clean') return '#22c55e';
                  return '#6b7280';
                };

                const getTypeColor = (type) => {
                  if (type === 'ip') return '#3b82f6';
                  if (type === 'domain') return '#a855f7';
                  if (type?.startsWith('hash')) return '#ea580c';
                  if (type === 'url') return '#14b8a6';
                  return '#6b7280';
                };

                const enrichment = result.enrichments?.[0] || {};
                const vtData = enrichment.raw_data?.data?.attributes || {};
                const vtStats = vtData.last_analysis_stats || {};
                let verdict = result.verdict || 'unknown';
                let vtMalicious = vtStats.malicious || 0;
                let vtSuspicious = vtStats.suspicious || 0;
                let vtHarmless = vtStats.harmless || 0;
                let vtTotal = vtMalicious + vtSuspicious + vtHarmless + (vtStats.undetected || 0);
                const reputation = vtData.reputation;
                const categories = vtData.categories ? Object.values(vtData.categories).slice(0, 2) : [];
                const country = vtData.country;
                const asOwner = vtData.as_owner;
                const verdictColor = getVerdictColor(verdict);

                return (
                  <div
                    key={idx}
                    onClick={() => navigate(`/threat-intel/${encodeURIComponent(result.value)}`, {
                      state: { bulkIOCs: bulkLookupResults.map(r => r.value) }
                    })}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.5rem 0.75rem',
                      background: 'var(--bg-secondary)',
                      borderLeft: `3px solid ${verdictColor}`,
                      cursor: 'pointer',
                      borderRadius: '6px'
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
                  >
                    {/* Type badge */}
                    <span style={{
                      fontSize: '0.7rem',
                      padding: '0.15rem 0.4rem',
                      borderRadius: '4px',
                      background: `${getTypeColor(result.type)}20`,
                      color: getTypeColor(result.type),
                      fontWeight: '600',
                      textTransform: 'uppercase',
                      minWidth: '50px',
                      textAlign: 'center'
                    }}>
                      {result.type?.replace('hash_', '') || '?'}
                    </span>

                    {/* IOC Value */}
                    <code style={{
                      fontSize: '0.85rem',
                      color: 'var(--text-primary)',
                      fontWeight: '500',
                      flex: '0 0 200px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    }}>
                      {result.value}
                    </code>

                    {/* VT Stats or info */}
                    <div style={{
                      flex: 1,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      fontSize: '0.7rem',
                      color: 'var(--text-muted)',
                      minWidth: 0
                    }}>
                      {vtTotal > 0 && (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <span style={{ color: 'var(--text-muted)', opacity: 0.7 }}>VT</span>
                          {vtMalicious > 0 ? (
                            <span style={{ color: '#dc2626', fontWeight: '600' }}>{vtMalicious}</span>
                          ) : vtSuspicious > 0 ? (
                            <span style={{ color: '#ea580c', fontWeight: '600' }}>{vtSuspicious}</span>
                          ) : (
                            <span style={{ color: '#22c55e', fontWeight: '600' }}>0</span>
                          )}
                          <span style={{ opacity: 0.6 }}>/{vtTotal}</span>
                        </span>
                      )}
                      {reputation !== undefined && reputation !== 0 && (
                        <span style={{ color: reputation < 0 ? '#dc2626' : '#22c55e' }}>
                          Rep: {reputation}
                        </span>
                      )}
                      {country && <span>{country}</span>}
                      {asOwner && (
                        <span style={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '150px'
                        }}>
                          {asOwner}
                        </span>
                      )}
                      {categories.length > 0 && (
                        <span style={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          opacity: 0.8
                        }}>
                          {categories.join(', ')}
                        </span>
                      )}
                      {!result.success && (
                        <span style={{ color: '#dc2626', fontStyle: 'italic' }}>
                          {result.error || 'Failed'}
                        </span>
                      )}
                      {result.success && vtTotal === 0 && !country && categories.length === 0 && (
                        <span style={{ fontStyle: 'italic', opacity: 0.6 }}>No data</span>
                      )}
                    </div>

                    {/* Verdict badge */}
                    <span style={{
                      padding: '0.15rem 0.5rem',
                      borderRadius: '3px',
                      fontSize: '0.65rem',
                      fontWeight: '600',
                      textTransform: 'uppercase',
                      background: `${verdictColor}15`,
                      color: verdictColor,
                      minWidth: '65px',
                      textAlign: 'center'
                    }}>
                      {verdict}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Stats Section - Database view - Clickable filter buttons */}
      {mainView === 'database' && stats && (
        <div style={{
          display: 'flex',
          gap: '0.5rem',
          marginBottom: '0.75rem',
          flexWrap: 'wrap'
        }}>
          {/* Total - click to clear filter */}
          <button
            onClick={() => {
              setColumnFilters(prev => ({ ...prev, type: null }));
              setCurrentPage(1);
            }}
            style={{
              background: !columnFilters.type ? 'var(--accent-color)' : 'var(--bg-secondary)',
              border: !columnFilters.type ? '1px solid var(--accent-color)' : '1px solid var(--bg-tertiary)',
              borderRadius: '6px',
              padding: '0.4rem 0.75rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            <span style={{ fontSize: '1rem', fontWeight: '700', color: !columnFilters.type ? 'white' : '#3CB371' }}>
              {formatNumber(stats.iocs?.total || 0)}
            </span>
            <span style={{ fontSize: '0.7rem', color: !columnFilters.type ? 'rgba(255,255,255,0.8)' : 'var(--text-muted)' }}>Total</span>
          </button>
          {/* Type filter buttons - show all types */}
          {stats.iocs?.by_type && Object.entries(stats.iocs.by_type)
            .sort((a, b) => b[1] - a[1])  // Sort by count descending
            .map(([type, count]) => {
              const isActive = columnFilters.type === type;
              return (
                <button
                  key={type}
                  onClick={() => {
                    setColumnFilters(prev => ({
                      ...prev,
                      type: prev.type === type ? null : type  // Toggle filter
                    }));
                    setCurrentPage(1);
                  }}
                  style={{
                    background: isActive ? 'var(--accent-color)' : 'var(--bg-secondary)',
                    border: isActive ? '1px solid var(--accent-color)' : '1px solid var(--bg-tertiary)',
                    borderRadius: '6px',
                    padding: '0.4rem 0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span style={{ fontSize: '0.9rem', fontWeight: '600', color: isActive ? 'white' : 'var(--text-primary)' }}>
                    {formatNumber(count)}
                  </span>
                  <span style={{ fontSize: '0.65rem', color: isActive ? 'rgba(255,255,255,0.8)' : 'var(--text-muted)', textTransform: 'uppercase' }}>
                    {type.replace('hash_', '').replace('_', ' ')}
                  </span>
                </button>
              );
            })}
        </div>
      )}

      {/* Database View - Table with filters */}
      {mainView === 'database' && (
        <>
          {/* Filter Bar */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '8px',
            padding: '0.75rem',
            marginBottom: '0.75rem'
          }}>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              {/* Search */}
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search IOCs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  flex: 1,
                  minWidth: '180px',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.8rem'
                }}
              />

              {/* Time Range Filter */}
              <select
                value={timeRange || ''}
                onChange={(e) => setTimeRange(e.target.value ? parseInt(e.target.value) : null)}
                style={{
                  padding: '0.5rem 0.75rem',
                  background: timeRange ? 'rgba(60, 179, 113, 0.1)' : 'var(--bg-primary)',
                  border: timeRange ? '1px solid rgba(60, 179, 113, 0.3)' : '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: timeRange ? '#3CB371' : 'var(--text-primary)',
                  fontSize: '0.8rem',
                  fontWeight: timeRange ? '600' : '400'
                }}
              >
                {timeRangeOptions.map(opt => (
                  <option key={opt.value || 'all'} value={opt.value || ''}>{opt.label}</option>
                ))}
              </select>

              {/* Rows per page */}
              <select
                value={rowsPerPage}
                onChange={(e) => setRowsPerPage(parseInt(e.target.value))}
                style={{
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.8rem'
                }}
              >
                {[10, 15, 20, 30, 40, 50].map(n => (
                  <option key={n} value={n}>{n} rows</option>
                ))}
              </select>

              {/* Column Configuration Button */}
              <div style={{ position: 'relative' }}>
                <button
                  onClick={() => setShowColumnConfig(!showColumnConfig)}
                  style={{
                    padding: '0.5rem 0.75rem',
                    background: showColumnConfig ? 'rgba(60, 179, 113, 0.2)' : 'var(--bg-primary)',
                    border: showColumnConfig ? '1px solid rgba(60, 179, 113, 0.4)' : '1px solid var(--bg-tertiary)',
                    borderRadius: '6px',
                    color: showColumnConfig ? '#3CB371' : 'var(--text-primary)',
                    fontSize: '0.8rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem'
                  }}
                >
                  Columns
                  <span style={{ fontSize: '0.65rem' }}>{showColumnConfig ? '\u25B2' : '\u25BC'}</span>
                </button>

                {/* Column Config Dropdown */}
                {showColumnConfig && (
                  <div style={{
                    position: 'absolute',
                    top: '100%',
                    right: 0,
                    marginTop: '0.5rem',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--bg-tertiary)',
                    borderRadius: '8px',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                    zIndex: 200,
                    minWidth: '220px',
                    padding: '0.5rem 0'
                  }}>
                    <div style={{
                      padding: '0.5rem 0.75rem',
                      borderBottom: '1px solid var(--bg-tertiary)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                        Configure Columns
                      </span>
                      <button
                        onClick={resetColumns}
                        style={{
                          padding: '0.2rem 0.4rem',
                          background: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: '4px',
                          color: '#ef4444',
                          fontSize: '0.65rem',
                          cursor: 'pointer'
                        }}
                      >
                        Reset
                      </button>
                    </div>
                    {columns.map((col, idx) => (
                      <div
                        key={col.id}
                        style={{
                          padding: '0.4rem 0.75rem',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '0.5rem',
                          background: col.visible ? 'rgba(60, 179, 113, 0.05)' : 'transparent'
                        }}
                      >
                        <label style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          cursor: 'pointer',
                          flex: 1,
                          fontSize: '0.75rem',
                          color: col.visible ? 'var(--text-primary)' : 'var(--text-muted)'
                        }}>
                          <input
                            type="checkbox"
                            checked={col.visible}
                            onChange={() => toggleColumn(col.id)}
                            style={{ cursor: 'pointer' }}
                          />
                          {col.label}
                        </label>
                        <div style={{ display: 'flex', gap: '0.15rem' }}>
                          <button
                            onClick={() => moveColumn(col.id, -1)}
                            disabled={idx === 0}
                            style={{
                              padding: '0.15rem 0.3rem',
                              background: 'transparent',
                              border: '1px solid var(--bg-tertiary)',
                              borderRadius: '3px',
                              color: idx === 0 ? 'var(--text-muted)' : 'var(--text-secondary)',
                              fontSize: '0.6rem',
                              cursor: idx === 0 ? 'not-allowed' : 'pointer'
                            }}
                          >
                            {'\u25B2'}
                          </button>
                          <button
                            onClick={() => moveColumn(col.id, 1)}
                            disabled={idx === columns.length - 1}
                            style={{
                              padding: '0.15rem 0.3rem',
                              background: 'transparent',
                              border: '1px solid var(--bg-tertiary)',
                              borderRadius: '3px',
                              color: idx === columns.length - 1 ? 'var(--text-muted)' : 'var(--text-secondary)',
                              fontSize: '0.6rem',
                              cursor: idx === columns.length - 1 ? 'not-allowed' : 'pointer'
                            }}
                          >
                            {'\u25BC'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Clear filters */}
              {activeFilterCount > 0 && (
                <button
                  onClick={clearAllFilters}
                  style={{
                    padding: '0.5rem 0.75rem',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '6px',
                    color: '#ef4444',
                    fontWeight: '600',
                    cursor: 'pointer',
                    fontSize: '0.75rem'
                  }}
                >
                  Clear ({activeFilterCount})
                </button>
              )}
            </div>

            {/* Active filter pills */}
            {activeFilterCount > 0 && (
              <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                {Object.entries(columnFilters).map(([key, value]) => value && (
                  <span
                    key={key}
                    onClick={() => setColumnFilters(prev => ({ ...prev, [key]: null }))}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                      padding: '0.2rem 0.5rem',
                      background: 'rgba(60, 179, 113, 0.15)',
                      border: '1px solid rgba(60, 179, 113, 0.3)',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      color: '#3CB371',
                      cursor: 'pointer'
                    }}
                  >
                    {key}: {value}
                    <span style={{ marginLeft: '0.25rem' }}>x</span>
                  </span>
                ))}
                {timeRange && (
                  <span
                    onClick={() => setTimeRange(null)}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                      padding: '0.2rem 0.5rem',
                      background: 'rgba(60, 179, 113, 0.15)',
                      border: '1px solid rgba(60, 179, 113, 0.3)',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      color: '#3CB371',
                      cursor: 'pointer'
                    }}
                  >
                    Last {timeRange} days
                    <span style={{ marginLeft: '0.25rem' }}>x</span>
                  </span>
                )}
              </div>
            )}

            <div style={{ marginTop: '0.5rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              Showing {paginatedIOCs.length} of {totalCount} IOCs
            </div>
          </div>

          {/* IOC Table */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '8px',
            overflow: 'hidden'
          }}>
            {paginatedIOCs.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '3rem' }}>
                <h3 style={{ marginBottom: '0.5rem', fontSize: '1rem' }}>No IOCs Found</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  Use the Quick Lookup to enrich your first IOC
                </p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                {/* Bulk Actions Bar */}
                {selectedIOCs.size > 0 && (
                  <div style={{
                    padding: '0.75rem 1rem',
                    background: 'linear-gradient(135deg, rgba(60, 179, 113, 0.15) 0%, rgba(118, 75, 162, 0.15) 100%)',
                    borderBottom: '1px solid rgba(60, 179, 113, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    flexWrap: 'wrap'
                  }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600', color: '#3CB371' }}>
                      {selectedIOCs.size} selected
                    </span>
                    <button
                      onClick={() => setShowBulkEditModal(true)}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'rgba(60, 179, 113, 0.2)',
                        border: '1px solid rgba(60, 179, 113, 0.4)',
                        borderRadius: '4px',
                        color: '#3CB371',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Bulk Edit
                    </button>
                    <button
                      onClick={() => setBulkDeleteConfirm(true)}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid rgba(239, 68, 68, 0.4)',
                        borderRadius: '4px',
                        color: '#ef4444',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Delete Selected
                    </button>
                    <button
                      onClick={() => setSelectedIOCs(new Set())}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'transparent',
                        border: '1px solid var(--bg-tertiary)',
                        borderRadius: '4px',
                        color: 'var(--text-muted)',
                        fontSize: '0.75rem',
                        cursor: 'pointer'
                      }}
                    >
                      Clear Selection
                    </button>
                  </div>
                )}

                <table className="ti-table">
                  <thead>
                    <tr style={{ background: 'var(--bg-tertiary)' }}>
                      {/* Selection Checkbox */}
                      <th style={{ padding: '0.6rem 0.5rem', width: '40px', textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={selectedIOCs.size === paginatedIOCs.length && paginatedIOCs.length > 0}
                          onChange={toggleSelectAll}
                          style={{ cursor: 'pointer' }}
                        />
                      </th>
                      {visibleColumns.map(col => (
                        <th key={col.id} style={{ padding: '0.6rem 0.75rem', textAlign: col.id === 'value' ? 'left' : 'center' }}>
                          {col.filterable ? (
                            <ColumnFilterDropdown
                              column={col.id}
                              label={col.label}
                              options={col.id === 'verdict' ? ['malicious', 'suspicious', 'clean', 'unknown'] :
                                       col.id === 'severity' ? ['critical', 'high', 'medium', 'low', 'unknown'] :
                                       getUniqueValues(col.id)}
                            />
                          ) : col.sortable ? (
                            <button
                              onClick={() => handleSort(col.id)}
                              style={{
                                background: 'none',
                                border: 'none',
                                color: sortConfig.key === col.id ? '#3CB371' : 'var(--text-muted)',
                                cursor: 'pointer',
                                fontSize: '0.7rem',
                                fontWeight: '600',
                                textTransform: 'uppercase',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.25rem'
                              }}
                            >
                              {col.label}
                              {sortConfig.key === col.id && (
                                <span style={{ fontSize: '0.55rem' }}>{sortConfig.direction === 'asc' ? '\u25B2' : '\u25BC'}</span>
                              )}
                            </button>
                          ) : (
                            <span style={{ fontSize: '0.7rem', fontWeight: '600', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                              {col.label}
                            </span>
                          )}
                        </th>
                      ))}
                      <th style={{ padding: '0.6rem 0.75rem', textAlign: 'center', fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '600', textTransform: 'uppercase', minWidth: '120px' }}>
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedIOCs.map((ioc, idx) => (
                      <tr
                        key={idx}
                        style={{
                          borderBottom: '1px solid var(--bg-tertiary)',
                          cursor: 'pointer',
                          background: selectedIOCs.has(ioc.value) ? 'rgba(60, 179, 113, 0.08)' : 'transparent'
                        }}
                        onClick={() => navigate(`/threat-intel/${encodeURIComponent(ioc.value)}`)}
                        onMouseEnter={(e) => e.currentTarget.style.background = selectedIOCs.has(ioc.value) ? 'rgba(60, 179, 113, 0.12)' : 'rgba(60, 179, 113, 0.05)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = selectedIOCs.has(ioc.value) ? 'rgba(60, 179, 113, 0.08)' : 'transparent'}
                      >
                        {/* Selection Checkbox */}
                        <td style={{ padding: '0.6rem 0.5rem', width: '40px', textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selectedIOCs.has(ioc.value)}
                            onChange={() => toggleSelection(ioc.value)}
                            style={{ cursor: 'pointer' }}
                          />
                        </td>
                        {visibleColumns.map(col => (
                          <td key={col.id} style={{ padding: '0.6rem 0.75rem', textAlign: col.id === 'value' ? 'left' : 'center' }}>
                            {col.id === 'value' ? (
                              <code
                                title={ioc.value}
                                style={{
                                  background: 'rgba(60, 179, 113, 0.1)',
                                  padding: '0.2rem 0.4rem',
                                  borderRadius: '4px',
                                  fontSize: '0.75rem',
                                  color: '#a0e9ff',
                                  maxWidth: '250px',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                  display: 'inline-block',
                                  cursor: 'help'
                                }}
                              >
                                {ioc.value}
                              </code>
                            ) : col.id === 'type' ? (
                              <span style={{
                                padding: '0.2rem 0.5rem',
                                background: '#3CB37120',
                                color: '#3CB371',
                                borderRadius: '4px',
                                fontSize: '0.7rem',
                                fontWeight: '500',
                                textTransform: 'uppercase'
                              }}>
                                {ioc.type?.replace('hash_', '')}
                              </span>
                            ) : col.id === 'verdict' ? (
                              <span style={{
                                padding: '0.2rem 0.5rem',
                                background: getVerdictColor(ioc.verdict) + '20',
                                color: getVerdictColor(ioc.verdict),
                                borderRadius: '4px',
                                fontSize: '0.7rem',
                                fontWeight: '600',
                                textTransform: 'uppercase'
                              }}>
                                {ioc.verdict || 'unknown'}
                              </span>
                            ) : col.id === 'severity' ? (
                              <span style={{
                                padding: '0.2rem 0.5rem',
                                background: getSeverityColor(ioc.severity) + '20',
                                color: getSeverityColor(ioc.severity),
                                borderRadius: '4px',
                                fontSize: '0.7rem',
                                fontWeight: '600',
                                textTransform: 'uppercase'
                              }}>
                                {ioc.severity || 'unknown'}
                              </span>
                            ) : col.id === 'tags' ? (
                              <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', justifyContent: 'center' }}>
                                {(ioc.tags || []).slice(0, 3).map((tag, i) => (
                                  <span key={i} style={{
                                    padding: '0.15rem 0.35rem',
                                    background: 'rgba(60, 179, 113, 0.15)',
                                    color: '#a78bfa',
                                    borderRadius: '3px',
                                    fontSize: '0.65rem'
                                  }}>
                                    {tag}
                                  </span>
                                ))}
                                {(ioc.tags || []).length > 3 && (
                                  <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>+{ioc.tags.length - 3}</span>
                                )}
                              </div>
                            ) : col.id === 'first_seen' || col.id === 'last_seen' ? (
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                                {formatDate(ioc[col.id])}
                              </span>
                            ) : col.id === 'occurrences' ? (
                              <span style={{
                                padding: '0.15rem 0.4rem',
                                background: ioc.occurrences > 10 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(100, 116, 139, 0.15)',
                                color: ioc.occurrences > 10 ? '#f87171' : 'var(--text-muted)',
                                borderRadius: '4px',
                                fontSize: '0.7rem',
                                fontWeight: '500'
                              }}>
                                {ioc.occurrences || 1}
                              </span>
                            ) : (
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                                {ioc[col.id] || '-'}
                              </span>
                            )}
                          </td>
                        ))}
                        <td style={{ padding: '0.6rem 0.75rem', textAlign: 'center', whiteSpace: 'nowrap' }} onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => enrichIOC(ioc)}
                            disabled={enrichingIOC === ioc.value}
                            style={{
                              padding: '0.3rem 0.5rem',
                              background: enrichingIOC === ioc.value ? 'var(--bg-tertiary)' : 'rgba(60, 179, 113, 0.1)',
                              border: '1px solid rgba(60, 179, 113, 0.3)',
                              borderRadius: '4px',
                              color: '#3CB371',
                              cursor: enrichingIOC === ioc.value ? 'not-allowed' : 'pointer',
                              fontSize: '0.7rem',
                              marginRight: '0.35rem'
                            }}
                          >
                            {enrichingIOC === ioc.value ? '...' : 'Enrich'}
                          </button>
                          <button
                            onClick={() => navigate(`/threat-intel/${encodeURIComponent(ioc.value)}`)}
                            style={{
                              padding: '0.3rem 0.5rem',
                              background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                              border: 'none',
                              borderRadius: '4px',
                              color: 'white',
                              cursor: 'pointer',
                              fontSize: '0.7rem'
                            }}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination with Page Numbers */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.75rem',
                borderTop: '1px solid var(--bg-tertiary)',
                background: 'var(--bg-tertiary)',
                flexWrap: 'wrap',
                gap: '0.5rem'
              }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Showing {((currentPage - 1) * rowsPerPage) + 1}-{Math.min(currentPage * rowsPerPage, totalCount)} of {totalCount}
                </div>
                <div style={{ display: 'flex', gap: '0.25rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  {/* First & Previous */}
                  <button
                    onClick={() => setCurrentPage(1)}
                    disabled={currentPage === 1}
                    style={{
                      padding: '0.35rem 0.5rem',
                      background: currentPage === 1 ? 'var(--bg-secondary)' : 'var(--bg-primary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                      cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                      fontSize: '0.7rem'
                    }}
                  >
                    {'\u00AB'}
                  </button>
                  <button
                    onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                    disabled={currentPage === 1}
                    style={{
                      padding: '0.35rem 0.5rem',
                      background: currentPage === 1 ? 'var(--bg-secondary)' : 'var(--bg-primary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                      cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                      fontSize: '0.7rem'
                    }}
                  >
                    {'\u2039'}
                  </button>

                  {/* Page Numbers */}
                  {(() => {
                    const pages = [];
                    const maxVisible = 7;
                    let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
                    let end = Math.min(totalPages, start + maxVisible - 1);
                    if (end - start < maxVisible - 1) {
                      start = Math.max(1, end - maxVisible + 1);
                    }

                    if (start > 1) {
                      pages.push(
                        <button key={1} onClick={() => setCurrentPage(1)} style={{
                          padding: '0.35rem 0.5rem',
                          background: 'var(--bg-primary)',
                          border: '1px solid var(--bg-tertiary)',
                          borderRadius: '4px',
                          color: 'var(--text-primary)',
                          cursor: 'pointer',
                          fontSize: '0.7rem',
                          minWidth: '28px'
                        }}>1</button>
                      );
                      if (start > 2) {
                        pages.push(<span key="ellipsis1" style={{ padding: '0 0.25rem', color: 'var(--text-muted)' }}>...</span>);
                      }
                    }

                    for (let i = start; i <= end; i++) {
                      pages.push(
                        <button
                          key={i}
                          onClick={() => setCurrentPage(i)}
                          style={{
                            padding: '0.35rem 0.5rem',
                            background: i === currentPage ? 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)' : 'var(--bg-primary)',
                            border: i === currentPage ? 'none' : '1px solid var(--bg-tertiary)',
                            borderRadius: '4px',
                            color: i === currentPage ? 'white' : 'var(--text-primary)',
                            cursor: 'pointer',
                            fontSize: '0.7rem',
                            fontWeight: i === currentPage ? '600' : '400',
                            minWidth: '28px'
                          }}
                        >
                          {i}
                        </button>
                      );
                    }

                    if (end < totalPages) {
                      if (end < totalPages - 1) {
                        pages.push(<span key="ellipsis2" style={{ padding: '0 0.25rem', color: 'var(--text-muted)' }}>...</span>);
                      }
                      pages.push(
                        <button key={totalPages} onClick={() => setCurrentPage(totalPages)} style={{
                          padding: '0.35rem 0.5rem',
                          background: 'var(--bg-primary)',
                          border: '1px solid var(--bg-tertiary)',
                          borderRadius: '4px',
                          color: 'var(--text-primary)',
                          cursor: 'pointer',
                          fontSize: '0.7rem',
                          minWidth: '28px'
                        }}>{totalPages}</button>
                      );
                    }

                    return pages;
                  })()}

                  {/* Next & Last */}
                  <button
                    onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                    disabled={currentPage === totalPages}
                    style={{
                      padding: '0.35rem 0.5rem',
                      background: currentPage === totalPages ? 'var(--bg-secondary)' : 'var(--bg-primary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: currentPage === totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                      cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                      fontSize: '0.7rem'
                    }}
                  >
                    {'\u203A'}
                  </button>
                  <button
                    onClick={() => setCurrentPage(totalPages)}
                    disabled={currentPage === totalPages}
                    style={{
                      padding: '0.35rem 0.5rem',
                      background: currentPage === totalPages ? 'var(--bg-secondary)' : 'var(--bg-primary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: currentPage === totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                      cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                      fontSize: '0.7rem'
                    }}
                  >
                    {'\u00BB'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '12px',
            padding: '1.5rem',
            maxWidth: '400px',
            width: '90%'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>
              Delete IOC?
            </h3>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Are you sure you want to delete this IOC?
            </p>
            <code style={{
              display: 'block',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              padding: '0.5rem 0.75rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              color: '#f87171',
              marginBottom: '1rem',
              wordBreak: 'break-all'
            }}>
              {deleteConfirm}
            </code>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              This action cannot be undone. The IOC and all associated enrichment data will be permanently removed.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setDeleteConfirm(null)}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'transparent',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => deleteIOC(deleteConfirm)}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: actionLoading ? 'var(--bg-tertiary)' : 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  fontWeight: '600',
                  cursor: actionLoading ? 'not-allowed' : 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                {actionLoading ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Delete Confirmation Modal */}
      {bulkDeleteConfirm && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '12px',
            padding: '1.5rem',
            maxWidth: '450px',
            width: '90%'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>
              Delete {selectedIOCs.size} IOCs?
            </h3>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Are you sure you want to delete these IOCs? This action cannot be undone.
            </p>
            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              padding: '0.75rem',
              borderRadius: '6px',
              marginBottom: '1rem',
              maxHeight: '150px',
              overflow: 'auto'
            }}>
              {Array.from(selectedIOCs).map(ioc => (
                <div key={ioc} style={{ fontSize: '0.75rem', color: '#f87171', marginBottom: '0.25rem' }}>
                  {ioc}
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setBulkDeleteConfirm(false)}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'transparent',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                Cancel
              </button>
              <button
                onClick={bulkDeleteIOCs}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: actionLoading ? 'var(--bg-tertiary)' : 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  fontWeight: '600',
                  cursor: actionLoading ? 'not-allowed' : 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                {actionLoading ? 'Deleting...' : `Delete ${selectedIOCs.size} IOCs`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Edit Modal */}
      {showBulkEditModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--bg-tertiary)',
            borderRadius: '12px',
            padding: '1.5rem',
            maxWidth: '500px',
            width: '90%'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>
              Bulk Edit {selectedIOCs.size} IOCs
            </h3>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Only filled fields will be updated. Leave fields empty to keep existing values.
            </p>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Verdict
              </label>
              <select
                value={bulkEditData.verdict}
                onChange={(e) => setBulkEditData(prev => ({ ...prev, verdict: e.target.value }))}
                style={{
                  width: '100%',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              >
                <option value="">-- No change --</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Severity
              </label>
              <select
                value={bulkEditData.severity}
                onChange={(e) => setBulkEditData(prev => ({ ...prev, severity: e.target.value }))}
                style={{
                  width: '100%',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              >
                <option value="">-- No change --</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Add Tags (comma-separated)
              </label>
              <input
                type="text"
                value={bulkEditData.tags_add}
                onChange={(e) => setBulkEditData(prev => ({ ...prev, tags_add: e.target.value }))}
                placeholder="tag1, tag2, tag3"
                style={{
                  width: '100%',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Remove Tags (comma-separated)
              </label>
              <input
                type="text"
                value={bulkEditData.tags_remove}
                onChange={(e) => setBulkEditData(prev => ({ ...prev, tags_remove: e.target.value }))}
                placeholder="tag1, tag2"
                style={{
                  width: '100%',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  setShowBulkEditModal(false);
                  setBulkEditData({ verdict: '', severity: '', tags_add: '', tags_remove: '' });
                }}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'transparent',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                Cancel
              </button>
              <button
                onClick={bulkUpdateIOCs}
                disabled={actionLoading || (!bulkEditData.verdict && !bulkEditData.severity && !bulkEditData.tags_add && !bulkEditData.tags_remove)}
                style={{
                  padding: '0.5rem 1rem',
                  background: actionLoading ? 'var(--bg-tertiary)' : 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  fontWeight: '600',
                  cursor: actionLoading || (!bulkEditData.verdict && !bulkEditData.severity && !bulkEditData.tags_add && !bulkEditData.tags_remove) ? 'not-allowed' : 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                {actionLoading ? 'Updating...' : `Update ${selectedIOCs.size} IOCs`}
              </button>
            </div>
          </div>
        </div>
      )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IOCCenter;


