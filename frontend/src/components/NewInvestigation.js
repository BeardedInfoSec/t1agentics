/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import FieldExtractionPanel from './FieldExtractionPanel';
import { API_BASE_URL } from '../utils/api';
import { useToast } from './ui/Toast';

function NewInvestigation() {
  const navigate = useNavigate();
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [extractedFields, setExtractedFields] = useState({});
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    source: '',
    metadata: ''
  });
  const submittedRef = useRef(false); // Prevent duplicate submissions

  // Pre-fill from alert if coming from Investigate button
  useEffect(() => {
    const alertId = searchParams.get('alert_id');
    const alertIds = searchParams.get('alert_ids'); // For bulk investigate
    const title = searchParams.get('title');
    
    if (alertId && !submittedRef.current) {
      submittedRef.current = true; // Mark as submitted
      // Fetch full alert data and auto-submit (single alert)
      fetchAlertDataAndInvestigate(alertId, title);
    } else if (alertIds && !submittedRef.current) {
      submittedRef.current = true;
      // Fetch multiple alerts for bulk investigation
      const ids = alertIds.split(',');
      if (ids.length === 1) {
        // Only one alert, treat as single
        fetchAlertDataAndInvestigate(ids[0], title);
      } else {
        // Multiple alerts - future feature
        // For now, just investigate the first one
        fetchAlertDataAndInvestigate(ids[0], title);
      }
    }
  }, [searchParams]);

  const fetchAlertDataAndInvestigate = async (alertId, title) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts?limit=1000`);
      const alerts = await response.json();
      const alert = alerts.find(a => a.alert_id === alertId);
      
      
      if (alert) {
        // Parse raw_event if it's a string
        let rawEventData = alert.raw_event || alert.raw_data || {};
        if (typeof rawEventData === 'string') {
          try {
            rawEventData = JSON.parse(rawEventData);
          } catch (e) {
            rawEventData = {};
          }
        }
        
        const metadata = {
          alert_id: alert.alert_id,
          external_id: alert.external_id,
          source_type: alert.source_type,
          severity: alert.severity,
          // Only spread if it's actually an object
          ...(typeof rawEventData === 'object' && rawEventData !== null ? rawEventData : {})
        };
        
        
        const investigationData = {
          title: alert.title || title || '',
          description: alert.description || '',
          source: alert.source || '',
          metadata: JSON.stringify(metadata, null, 2)
        };
        
        
        setFormData(investigationData);
        
        // Extract fields from raw_event or raw_data  
        let rawData = alert.raw_event || alert.raw_data;
        
        
        // If raw_event is a string, parse it
        if (rawData && typeof rawData === 'string') {
          try {
            rawData = JSON.parse(rawData);
          } catch (e) {
            rawData = null;
          }
        }
        
        // Only extract if we have a valid object (not null, not array, not string)
        if (rawData && typeof rawData === 'object' && !Array.isArray(rawData) && Object.keys(rawData).length > 0) {
          extractFields(rawData);
        } else {
        }
        
        // AUTO-SUBMIT INVESTIGATION
        await submitInvestigation(investigationData, true);
        
      } else if (title) {
        // Fallback if alert not found
        setFormData(prev => ({
          ...prev,
          title: title
        }));
      }
    } catch (error) {
      if (title) {
        setFormData(prev => ({
          ...prev,
          title: title
        }));
      }
    }
  };
  
  const extractFields = (rawData) => {
    // Flatten nested objects into key-value pairs
    const fields = {};
    
    const flatten = (obj, prefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          flatten(value, newKey);
        } else {
          fields[newKey] = value;
        }
      }
    };
    
    flatten(rawData);
    setExtractedFields(fields);
  };

  const [examples] = useState([
    {
      name: 'Suspicious Login',
      data: {
        title: 'Multiple Failed Login Attempts',
        description: 'User account admin experienced 15 failed login attempts from IP 192.168.1.100 within 5 minutes',
        source: 'authentication_logs',
        metadata: JSON.stringify({
          user: 'admin',
          ip: '192.168.1.100',
          attempts: 15,
          timeframe: '5 minutes'
        }, null, 2)
      }
    },
    {
      name: 'Malware Detection',
      data: {
        title: 'Suspicious File Execution',
        description: 'Malware detected with hash 44d88612fea8a8f36de82e1278abb02f attempting to execute on host WORKSTATION-01',
        source: 'endpoint_protection',
        metadata: JSON.stringify({
          host: 'WORKSTATION-01',
          hash: '44d88612fea8a8f36de82e1278abb02f',
          file_path: 'C:\\Users\\Public\\Downloads\\suspicious.exe'
        }, null, 2)
      }
    },
    {
      name: 'Phishing Email',
      data: {
        title: 'Potential Phishing Email',
        description: 'Email received from suspicious domain malicious-site.com containing URL http://malicious-site.com/login',
        source: 'email_gateway',
        metadata: JSON.stringify({
          from: 'attacker@malicious-site.com',
          to: 'victim@company.com',
          subject: 'Urgent: Account Verification Required',
          url: 'http://malicious-site.com/login'
        }, null, 2)
      }
    }
  ]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const loadExample = (example) => {
    setFormData(example.data);
  };

  const submitInvestigation = async (data, isAutoSubmit = false) => {
    setLoading(true);

    try {
      // Parse metadata if provided
      let metadata = {};
      if (data.metadata) {
        try {
          metadata = JSON.parse(data.metadata);
        } catch (error) {
          if (!isAutoSubmit) {
            toast.warning('Invalid JSON in metadata field');
          }
          setLoading(false);
          return;
        }
      }

      // Create alert object
      const alert = {
        title: data.title,
        description: data.description,
        source: data.source || 'manual_submission',
        metadata: metadata
      };


      // Submit to API
      const response = await fetch(`${API_BASE_URL}/api/v1/investigate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(alert)
      });


      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create investigation: ${response.status}`);
      }

      const result = await response.json();
      
      if (!result.investigation_id) {
        throw new Error('Investigation created but no ID returned');
      }
      
      // Small delay to ensure database save completes
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // Navigate to investigation detail
      navigate(`/investigation/${result.investigation_id}`);
    } catch (error) {
      if (!isAutoSubmit) {
        toast.error('Failed to create investigation: ' + error.message);
      } else {
        // Show error in console for debugging auto-submit
      }
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    await submitInvestigation(formData, false);
  };

  return (
    <div className="new-investigation">
      {/* Auto-Submit Indicator */}
      {searchParams.get('alert_id') && loading && (
        <div className="card" style={{ 
          marginBottom: '2rem',
          background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
          border: 'none'
        }}>
          <div style={{ textAlign: 'center', padding: '1rem' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem' }}></div>
            <h3 style={{ margin: '0 0 0.5rem 0', color: 'white' }}>
              🚀 Auto-Investigating Alert
            </h3>
            <p style={{ margin: 0, color: 'rgba(255,255,255,0.9)' }}>
              Analyzing alert data and starting investigation...
            </p>
          </div>
        </div>
      )}
      
      <h2 style={{ fontSize: '1.75rem', marginBottom: '1rem' }}>Create New Investigation</h2>
      <p style={{ color: '#a0a0a0', marginBottom: '2rem' }}>
        Submit an alert or security event for autonomous investigation by T1 Agentics.
      </p>

      {/* Examples */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <h3 className="card-title">Quick Examples</h3>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          {examples.map((example, index) => (
            <button
              key={index}
              className="button button-secondary"
              onClick={() => loadExample(example)}
            >
              {example.name}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit}>
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h3 className="card-title">Alert Details</h3>
          
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: '#e0e0e0', fontWeight: '500' }}>
              Title *
            </label>
            <input
              type="text"
              name="title"
              value={formData.title}
              onChange={handleChange}
              required
              placeholder="Brief description of the alert"
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(0, 0, 0, 0.2)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '6px',
                color: '#e0e0e0',
                fontSize: '1rem'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: '#e0e0e0', fontWeight: '500' }}>
              Description
            </label>
            <textarea
              name="description"
              value={formData.description}
              onChange={handleChange}
              placeholder="Detailed description, logs, or context. Include IPs, domains, hashes, etc."
              rows="6"
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(0, 0, 0, 0.2)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '6px',
                color: '#e0e0e0',
                fontSize: '1rem',
                fontFamily: 'monospace',
                resize: 'vertical'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: '#e0e0e0', fontWeight: '500' }}>
              Source
            </label>
            <input
              type="text"
              name="source"
              value={formData.source}
              onChange={handleChange}
              placeholder="e.g., firewall, IDS, endpoint_protection"
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(0, 0, 0, 0.2)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '6px',
                color: '#e0e0e0',
                fontSize: '1rem'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: '#e0e0e0', fontWeight: '500' }}>
              Metadata (JSON)
            </label>
            <textarea
              name="metadata"
              value={formData.metadata}
              onChange={handleChange}
              placeholder='{"user": "admin", "ip": "192.168.1.1", "host": "server-01"}'
              rows="6"
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(0, 0, 0, 0.2)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '6px',
                color: '#e0e0e0',
                fontSize: '0.875rem',
                fontFamily: 'monospace',
                resize: 'vertical'
              }}
            />
            <div style={{ fontSize: '0.75rem', color: '#a0a0a0', marginTop: '0.5rem' }}>
              Optional: Additional structured data in JSON format
            </div>
          </div>
        </div>

        {/* Extracted Fields Panel - NEW SPLUNK-STYLE */}
        {Object.keys(extractedFields).length > 0 && (
          <FieldExtractionPanel fields={extractedFields} />
        )}

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button
            type="submit"
            className="button button-primary"
            disabled={loading || !formData.title}
            style={{ minWidth: '200px' }}
          >
            {loading ? 'Investigating...' : 'Start Investigation'}
          </button>
          <button
            type="button"
            className="button button-secondary"
            onClick={() => navigate('/queue')}
            disabled={loading}
          >
            Cancel
          </button>
        </div>
      </form>

      {loading && (
        <div className="card" style={{ marginTop: '2rem' }}>
          <div className="loading">
            <div className="spinner"></div>
            <p>T1 Agentics is analyzing the alert...</p>
            <p style={{ fontSize: '0.875rem', color: '#a0a0a0', marginTop: '0.5rem' }}>
              Extracting indicators, performing enrichment, and generating report
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default NewInvestigation;
