-- 059: Drop dead investigation_id column on intake_form_submissions
--
-- Background: migration 057 created intake_form_submissions with an
-- investigation_id column that was meant to link a submission to the
-- investigation it eventually produced. No code path ever populated it
-- (per the platform-architecture audit, doc 12). The same migration
-- also defined a 'completed' status value that nothing ever writes.
--
-- Dropping both rather than wiring them up. The link from submission ->
-- investigation already exists via alert_id (submission.alert_id ->
-- alerts.id, then alerts.investigation_id once triage creates a case).
-- The 'completed' status is redundant with 'processing' + alert
-- resolution state.

ALTER TABLE intake_form_submissions
    DROP COLUMN IF EXISTS investigation_id;

-- Replace the CHECK constraint to remove 'completed'. Postgres doesn't
-- have ALTER CONSTRAINT for CHECKs, so drop + re-add.
ALTER TABLE intake_form_submissions
    DROP CONSTRAINT IF EXISTS intake_form_submissions_status_check;

ALTER TABLE intake_form_submissions
    ADD CONSTRAINT intake_form_submissions_status_check
        CHECK (status IN ('submitted', 'processing', 'failed'));
