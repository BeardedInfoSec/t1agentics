-- 077: Per-form triage strategy for intake submissions
--
-- Intake forms are user-submitted statements of suspicion, not vendor
-- telemetry. Today they ride the same Riggs triage pipeline as alerts,
-- which produces "45% confidence — needs investigation" noise on every
-- submission because Riggs has no idea the user already classified the
-- intent by picking the form template.
--
-- This migration lets each form opt into one of three handling paths:
--
--   direct   — alert created + investigation in state=NEW. No
--              enrichment, no Riggs, no playbook. (HR-style forms like
--              lost-or-stolen-device.)
--   enrich   — same + run IOC enrichment on submitted indicators.
--              (Default. IOC-rich forms like phishing reports.)
--   playbook — same + auto-fire the chosen playbook with the form
--              submission as context.
--
-- Riggs LLM triage is unconditionally skipped for intake-form alerts.
-- That happens in routes/intake_forms.py, not in this migration.

ALTER TABLE intake_forms
    ADD COLUMN IF NOT EXISTS triage_strategy VARCHAR(16) NOT NULL DEFAULT 'enrich'
        CHECK (triage_strategy IN ('direct', 'enrich', 'playbook'));

ALTER TABLE intake_forms
    ADD COLUMN IF NOT EXISTS auto_trigger_playbook_id UUID;

-- Index so the submission path can quickly find forms wired to a given
-- playbook (e.g. if we ever need a "what forms fire this playbook?"
-- admin view).
CREATE INDEX IF NOT EXISTS idx_intake_forms_playbook
    ON intake_forms(auto_trigger_playbook_id)
    WHERE auto_trigger_playbook_id IS NOT NULL;
