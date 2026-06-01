-- Minimal test SQL to check if new tables work
-- Run this manually to test if there are syntax errors

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create minimal investigations table
CREATE TABLE IF NOT EXISTS investigations_test (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) UNIQUE NOT NULL
);

-- Test 1: Can we reference investigation_id?
CREATE TABLE IF NOT EXISTS investigation_notes_test (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) NOT NULL REFERENCES investigations_test(investigation_id) ON DELETE CASCADE,
    note_type VARCHAR(50) NOT NULL CHECK (note_type IN (
        'AI_ANALYSIS', 'AI_RECOMMENDATION', 'AI_OBSERVATION',
        'HUMAN_NOTE', 'SYSTEM_NOTE', 'ESCALATION'
    )),
    author VARCHAR(100) NOT NULL,
    author_type VARCHAR(20) NOT NULL CHECK (author_type IN ('AI', 'HUMAN', 'SYSTEM')),
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Test 2: Can we create read-only table with rules?
CREATE TABLE IF NOT EXISTS ai_action_log_test (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) NOT NULL REFERENCES investigations_test(investigation_id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'PARTIAL', 'SKIPPED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create rules to make it read-only
CREATE OR REPLACE RULE ai_action_log_test_no_update AS 
    ON UPDATE TO ai_action_log_test DO INSTEAD NOTHING;

CREATE OR REPLACE RULE ai_action_log_test_no_delete AS 
    ON DELETE TO ai_action_log_test DO INSTEAD NOTHING;

-- Verify
SELECT 'Tables created successfully!' as status;
\dt *_test
