-- ============================================================================
-- PLAYBOOK SYSTEM SCHEMA MIGRATION
-- Visual Playbook Editor (VPE) with Riggs AI control
-- Date: 2026-01-22
-- ============================================================================

-- ============================================================================
-- CORE PLAYBOOK DEFINITION
-- Node-based visual playbooks with state management and tagging
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Basic info
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Trigger configuration
    trigger_conditions JSONB DEFAULT '{}',  -- When to run this playbook

    -- Canvas (node graph) - contains full React Flow data
    canvas_data JSONB NOT NULL DEFAULT '{"nodes": [], "edges": []}',

    -- State management
    is_enabled BOOLEAN DEFAULT FALSE,          -- Must be explicitly enabled
    riggs_allowed BOOLEAN DEFAULT FALSE,       -- Can Riggs run this autonomously?
    requires_approval BOOLEAN DEFAULT TRUE,    -- Require human approval before Riggs runs it?

    -- Tagging for automatic selection
    tags TEXT[] DEFAULT '{}',                  -- e.g., ['phishing', 'email', 'credential-theft']
    alert_types TEXT[] DEFAULT '{}',           -- Alert types this handles: ['phishing', 'malware']
    severity_filter TEXT[] DEFAULT '{}',       -- Severities: ['critical', 'high', 'medium', 'low']
    data_sources TEXT[] DEFAULT '{}',          -- Sources: ['email-gateway', 'edr', 'siem']

    -- Priority for selection (higher = preferred when multiple match)
    priority INTEGER DEFAULT 50 CHECK (priority >= 1 AND priority <= 100),

    -- Version tracking
    version INTEGER DEFAULT 1,
    previous_version_id UUID REFERENCES playbooks(id),

    -- Riggs AI
    riggs_suggestions JSONB DEFAULT '[]',      -- Pending Riggs recommendations
    last_riggs_review TIMESTAMP WITH TIME ZONE,
    riggs_confidence FLOAT CHECK (riggs_confidence >= 0 AND riggs_confidence <= 1),

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_playbooks_tags ON playbooks USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_playbooks_alert_types ON playbooks USING GIN (alert_types);
CREATE INDEX IF NOT EXISTS idx_playbooks_severity ON playbooks USING GIN (severity_filter);
CREATE INDEX IF NOT EXISTS idx_playbooks_data_sources ON playbooks USING GIN (data_sources);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks (is_enabled, riggs_allowed);
CREATE INDEX IF NOT EXISTS idx_playbooks_priority ON playbooks (priority DESC);
CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks (name);

-- ============================================================================
-- PLAYBOOK EXECUTION TRACKING
-- Tracks runtime state of playbook executions
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id VARCHAR(30) UNIQUE NOT NULL,  -- Human-readable: PBX-A1B2C3

    -- Links
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    playbook_version INTEGER,                  -- Version at time of execution
    alert_id UUID,
    investigation_id UUID,

    -- Execution state
    status VARCHAR(30) DEFAULT 'pending' CHECK (status IN (
        'pending',           -- Not yet started
        'running',           -- Currently executing
        'waiting_approval',  -- Paused at approval gate
        'waiting_input',     -- Paused waiting for user input/form
        'waiting_file',      -- Paused waiting for file upload
        'completed',         -- Finished successfully
        'failed',            -- Finished with error
        'cancelled',         -- Manually cancelled
        'timeout'            -- Execution timed out
    )),

    -- Current position in graph
    current_node_id VARCHAR(100),

    -- Runtime data
    execution_context JSONB DEFAULT '{}',      -- Data passed between nodes (variables, results)
    node_results JSONB DEFAULT '{}',           -- Results keyed by node_id
    error_message TEXT,

    -- Trigger info
    triggered_by VARCHAR(50) DEFAULT 'manual' CHECK (triggered_by IN (
        'manual',           -- Human triggered
        'riggs',            -- Riggs auto-triggered
        'alert',            -- Alert trigger
        'schedule',         -- Scheduled execution
        'webhook',          -- Webhook trigger
        'playbook'          -- Called from another playbook
    )),
    triggered_by_user_id UUID,

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    timeout_at TIMESTAMP WITH TIME ZONE,       -- When execution should timeout

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_exec_id ON playbook_executions(execution_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_playbook ON playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_status ON playbook_executions(status);
CREATE INDEX IF NOT EXISTS idx_pb_exec_alert ON playbook_executions(alert_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_investigation ON playbook_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_started ON playbook_executions(started_at DESC);

-- ============================================================================
-- CUSTOM PYTHON FUNCTIONS (SANDBOXED)
-- User-defined Python functions for playbooks
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_functions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,

    -- Code
    code TEXT NOT NULL,                        -- Python code

    -- Schema
    input_schema JSONB DEFAULT '{}',           -- Expected inputs (JSON Schema)
    output_schema JSONB DEFAULT '{}',          -- Expected outputs (JSON Schema)

    -- Security
    is_approved BOOLEAN DEFAULT FALSE,         -- Requires security review
    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE,
    security_notes TEXT,                       -- Notes from security review

    -- Usage tracking
    usage_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_func_name ON playbook_functions(name);
CREATE INDEX IF NOT EXISTS idx_pb_func_approved ON playbook_functions(is_approved);

-- ============================================================================
-- CUSTOM LISTS (ALLOWLISTS, BLOCKLISTS, LOOKUPS)
-- User-defined lists for playbook decision making
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_lists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,

    -- Type
    list_type VARCHAR(50) NOT NULL CHECK (list_type IN (
        'allowlist',        -- Items to allow/skip
        'blocklist',        -- Items to block/flag
        'lookup',           -- Key-value lookups
        'enum'              -- Enumerated values
    )),

    -- Data
    items JSONB NOT NULL DEFAULT '[]',         -- Array or key-value pairs
    item_count INTEGER DEFAULT 0,              -- Cached count

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_list_name ON playbook_lists(name);
CREATE INDEX IF NOT EXISTS idx_pb_list_type ON playbook_lists(list_type);

-- ============================================================================
-- WEBFORMS FOR USER INPUT
-- Customizable forms for collecting data during playbook execution
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_forms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Form definition
    fields JSONB NOT NULL DEFAULT '[]',        -- Array of form field definitions

    -- Behavior
    submit_action VARCHAR(50) DEFAULT 'continue' CHECK (submit_action IN (
        'continue',         -- Continue playbook execution
        'approve',          -- Treat as approval
        'reject',           -- Treat as rejection
        'branch'            -- Branch based on form data
    )),

    -- Access control
    require_auth BOOLEAN DEFAULT TRUE,         -- Require authentication to submit
    allowed_roles TEXT[] DEFAULT '{}',         -- Roles that can submit

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_form_name ON playbook_forms(name);

-- ============================================================================
-- FORM SUBMISSIONS
-- Tracks submitted form data during playbook execution
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_form_submissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Links
    form_id UUID NOT NULL REFERENCES playbook_forms(id) ON DELETE CASCADE,
    execution_id UUID REFERENCES playbook_executions(id) ON DELETE SET NULL,
    node_id VARCHAR(100),                      -- Node that requested the form

    -- Submission data
    form_data JSONB NOT NULL DEFAULT '{}',

    -- Submitter info
    submitted_by VARCHAR(255),                 -- Email or user ID
    submitted_by_user_id UUID,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- File references (if form had file uploads)
    files JSONB DEFAULT '[]'                   -- Array of file IDs
);

CREATE INDEX IF NOT EXISTS idx_pb_form_sub_form ON playbook_form_submissions(form_id);
CREATE INDEX IF NOT EXISTS idx_pb_form_sub_exec ON playbook_form_submissions(execution_id);
CREATE INDEX IF NOT EXISTS idx_pb_form_sub_submitted ON playbook_form_submissions(submitted_at DESC);

-- ============================================================================
-- FILE UPLOADS
-- Tracks files uploaded during playbook execution
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Links
    execution_id UUID REFERENCES playbook_executions(id) ON DELETE SET NULL,
    form_submission_id UUID REFERENCES playbook_form_submissions(id) ON DELETE SET NULL,

    -- File info
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255),
    file_type VARCHAR(100),                    -- MIME type
    file_size BIGINT,                          -- Size in bytes

    -- Storage
    storage_path TEXT NOT NULL,                -- S3/local path
    storage_type VARCHAR(20) DEFAULT 'local' CHECK (storage_type IN ('local', 's3', 'azure')),

    -- Security
    checksum VARCHAR(64),                      -- SHA-256
    scanned BOOLEAN DEFAULT FALSE,
    scan_result VARCHAR(20) CHECK (scan_result IN ('clean', 'malicious', 'unknown', NULL)),

    -- Metadata
    uploaded_by VARCHAR(255),
    uploaded_by_user_id UUID,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_file_exec ON playbook_files(execution_id);
CREATE INDEX IF NOT EXISTS idx_pb_file_form ON playbook_files(form_submission_id);
CREATE INDEX IF NOT EXISTS idx_pb_file_uploaded ON playbook_files(uploaded_at DESC);

-- ============================================================================
-- PLAYBOOK EXECUTION APPROVALS
-- Tracks approval/rejection of nodes requiring human approval
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_node_approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Links
    execution_id UUID NOT NULL REFERENCES playbook_executions(id) ON DELETE CASCADE,
    node_id VARCHAR(100) NOT NULL,

    -- What needs approval
    action_type VARCHAR(100),                  -- Type of action
    action_details JSONB DEFAULT '{}',         -- Action parameters
    reason TEXT,                               -- Why approval is needed

    -- Approval status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'approved', 'rejected', 'expired'
    )),

    -- Timing
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Review
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,

    UNIQUE(execution_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_pb_approval_exec ON playbook_node_approvals(execution_id);
CREATE INDEX IF NOT EXISTS idx_pb_approval_status ON playbook_node_approvals(status);
CREATE INDEX IF NOT EXISTS idx_pb_approval_requested ON playbook_node_approvals(requested_at DESC);

-- ============================================================================
-- PLAYBOOK TEMPLATES
-- Pre-built playbook templates users can import
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),                     -- phishing, malware, identity, etc.

    -- Template data (same as playbooks but no state)
    canvas_data JSONB NOT NULL,
    trigger_conditions JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    alert_types TEXT[] DEFAULT '{}',

    -- Source
    source VARCHAR(50) DEFAULT 'builtin' CHECK (source IN (
        'builtin',          -- Shipped with platform
        'community',        -- Community contributed
        'custom'            -- User created
    )),

    -- Popularity
    usage_count INTEGER DEFAULT 0,
    rating FLOAT,

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pb_template_category ON playbook_templates(category);
CREATE INDEX IF NOT EXISTS idx_pb_template_source ON playbook_templates(source);
CREATE INDEX IF NOT EXISTS idx_pb_template_tags ON playbook_templates USING GIN (tags);

-- ============================================================================
-- SEED INITIAL TEMPLATES
-- ============================================================================

INSERT INTO playbook_templates (id, name, description, category, canvas_data, tags, alert_types, source)
VALUES
    (
        uuid_generate_v4(),
        'Basic Phishing Response',
        'Simple phishing alert triage with IOC enrichment and containment options',
        'phishing',
        '{
            "nodes": [
                {"id": "trigger-1", "type": "trigger", "position": {"x": 250, "y": 50}, "data": {"label": "Alert Trigger", "config": {"alert_types": ["phishing"]}}},
                {"id": "riggs-1", "type": "riggs_analyze", "position": {"x": 250, "y": 150}, "data": {"label": "Riggs Analysis", "config": {}}},
                {"id": "condition-1", "type": "condition", "position": {"x": 250, "y": 250}, "data": {"label": "Is Malicious?", "config": {"field": "$.riggs.verdict", "operator": "equals", "value": "MALICIOUS"}}},
                {"id": "enrich-1", "type": "enrich", "position": {"x": 100, "y": 350}, "data": {"label": "Enrich IOCs", "config": {"integrations": ["virustotal"]}}},
                {"id": "action-1", "type": "action", "position": {"x": 100, "y": 450}, "data": {"label": "Block Sender", "config": {"action_type": "block_email", "requires_approval": true}}},
                {"id": "end-1", "type": "end", "position": {"x": 400, "y": 350}, "data": {"label": "End (Benign)"}}
            ],
            "edges": [
                {"id": "e1", "source": "trigger-1", "target": "riggs-1"},
                {"id": "e2", "source": "riggs-1", "target": "condition-1"},
                {"id": "e3", "source": "condition-1", "target": "enrich-1", "sourceHandle": "true"},
                {"id": "e4", "source": "condition-1", "target": "end-1", "sourceHandle": "false"},
                {"id": "e5", "source": "enrich-1", "target": "action-1"}
            ]
        }',
        ARRAY['phishing', 'email', 'automated'],
        ARRAY['phishing'],
        'builtin'
    ),
    (
        uuid_generate_v4(),
        'Malware Detection Response',
        'Malware alert handling with file analysis and endpoint containment',
        'malware',
        '{
            "nodes": [
                {"id": "trigger-1", "type": "trigger", "position": {"x": 250, "y": 50}, "data": {"label": "Alert Trigger", "config": {"alert_types": ["malware"]}}},
                {"id": "enrich-1", "type": "enrich", "position": {"x": 250, "y": 150}, "data": {"label": "Hash Lookup", "config": {"integrations": ["virustotal"], "observable_type": "hash"}}},
                {"id": "condition-1", "type": "condition", "position": {"x": 250, "y": 250}, "data": {"label": "Is Known Malware?", "config": {"field": "$.enrich.virustotal.positives", "operator": "greater_than", "value": 5}}},
                {"id": "action-1", "type": "action", "position": {"x": 100, "y": 350}, "data": {"label": "Isolate Host", "config": {"action_type": "contain_host", "requires_approval": true}}},
                {"id": "riggs-1", "type": "riggs_analyze", "position": {"x": 400, "y": 350}, "data": {"label": "Riggs Deep Analysis", "config": {}}}
            ],
            "edges": [
                {"id": "e1", "source": "trigger-1", "target": "enrich-1"},
                {"id": "e2", "source": "enrich-1", "target": "condition-1"},
                {"id": "e3", "source": "condition-1", "target": "action-1", "sourceHandle": "true"},
                {"id": "e4", "source": "condition-1", "target": "riggs-1", "sourceHandle": "false"}
            ]
        }',
        ARRAY['malware', 'endpoint', 'containment'],
        ARRAY['malware', 'endpoint_detection'],
        'builtin'
    ),
    (
        uuid_generate_v4(),
        'User Input Collection',
        'Template demonstrating webform and file upload nodes',
        'utility',
        '{
            "nodes": [
                {"id": "trigger-1", "type": "trigger", "position": {"x": 250, "y": 50}, "data": {"label": "Manual Trigger", "config": {"manual": true}}},
                {"id": "form-1", "type": "webform", "position": {"x": 250, "y": 150}, "data": {"label": "Collect Details", "config": {"fields": [{"name": "description", "type": "textarea", "label": "Incident Description", "required": true}]}}},
                {"id": "upload-1", "type": "file_upload", "position": {"x": 250, "y": 250}, "data": {"label": "Upload Evidence", "config": {"allowed_types": ["image/*", "application/pdf"], "max_size_mb": 10}}},
                {"id": "end-1", "type": "end", "position": {"x": 250, "y": 350}, "data": {"label": "Complete"}}
            ],
            "edges": [
                {"id": "e1", "source": "trigger-1", "target": "form-1"},
                {"id": "e2", "source": "form-1", "target": "upload-1"},
                {"id": "e3", "source": "upload-1", "target": "end-1"}
            ]
        }',
        ARRAY['form', 'input', 'utility'],
        ARRAY[],
        'builtin'
    )
ON CONFLICT DO NOTHING;

-- ============================================================================
-- UPDATE FUNCTION FOR TIMESTAMPS
-- ============================================================================

CREATE OR REPLACE FUNCTION update_playbook_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers
DROP TRIGGER IF EXISTS playbooks_updated_at ON playbooks;
CREATE TRIGGER playbooks_updated_at
    BEFORE UPDATE ON playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

DROP TRIGGER IF EXISTS playbook_functions_updated_at ON playbook_functions;
CREATE TRIGGER playbook_functions_updated_at
    BEFORE UPDATE ON playbook_functions
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

DROP TRIGGER IF EXISTS playbook_lists_updated_at ON playbook_lists;
CREATE TRIGGER playbook_lists_updated_at
    BEFORE UPDATE ON playbook_lists
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

DROP TRIGGER IF EXISTS playbook_forms_updated_at ON playbook_forms;
CREATE TRIGGER playbook_forms_updated_at
    BEFORE UPDATE ON playbook_forms
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Playbook system schema migration completed!';
    RAISE NOTICE '  - Created playbooks table with tagging and state management';
    RAISE NOTICE '  - Created playbook_executions table';
    RAISE NOTICE '  - Created playbook_functions table (sandboxed Python)';
    RAISE NOTICE '  - Created playbook_lists table (allowlists, blocklists)';
    RAISE NOTICE '  - Created playbook_forms table';
    RAISE NOTICE '  - Created playbook_form_submissions table';
    RAISE NOTICE '  - Created playbook_files table';
    RAISE NOTICE '  - Created playbook_node_approvals table';
    RAISE NOTICE '  - Created playbook_templates table with 3 seed templates';
END $$;
