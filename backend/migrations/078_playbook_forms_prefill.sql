-- Migration 078: Per-field prefill mapping on playbook_forms
--
-- Adds a JSONB column that maps form field names to JSONPath-like
-- expressions resolved against the playbook execution context when
-- the form is rendered. Shape: {"<field_name>": "$.alert.subject"}.
--
-- webform_service merges this with the node-level prefill mapping
-- in node_config (node-level wins on conflict), so a form can carry
-- sensible defaults while a specific playbook step can still override
-- on a per-use basis.

ALTER TABLE playbook_forms
    ADD COLUMN IF NOT EXISTS prefill_mapping JSONB NOT NULL DEFAULT '{}'::jsonb;
