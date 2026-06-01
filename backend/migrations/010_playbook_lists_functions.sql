-- ============================================================================
-- PLAYBOOK CUSTOM LISTS AND FUNCTIONS TABLES
-- Adds support for custom lists and Python functions in playbooks
-- Date: 2026-02-04
-- ============================================================================

-- Custom lists for playbooks (allowlists, blocklists, etc.)
CREATE TABLE IF NOT EXISTS playbook_lists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    list_type VARCHAR(50) DEFAULT 'generic',  -- allowlist, blocklist, generic
    items JSONB DEFAULT '[]'::jsonb,
    item_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Index for list lookups
CREATE INDEX IF NOT EXISTS idx_playbook_lists_name ON playbook_lists(name);
CREATE INDEX IF NOT EXISTS idx_playbook_lists_type ON playbook_lists(list_type);

-- Custom Python functions for playbooks
CREATE TABLE IF NOT EXISTS playbook_functions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    code TEXT NOT NULL,
    parameters JSONB DEFAULT '[]'::jsonb,  -- [{name, type, description, required}]
    return_type VARCHAR(50) DEFAULT 'any',
    status VARCHAR(50) DEFAULT 'pending',  -- pending, approved, rejected
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    approval_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Index for function lookups
CREATE INDEX IF NOT EXISTS idx_playbook_functions_name ON playbook_functions(name);
CREATE INDEX IF NOT EXISTS idx_playbook_functions_status ON playbook_functions(status);

-- Comments
COMMENT ON TABLE playbook_lists IS 'Custom lists (allowlists, blocklists) for use in playbook conditions';
COMMENT ON TABLE playbook_functions IS 'Custom Python functions for advanced playbook logic';
