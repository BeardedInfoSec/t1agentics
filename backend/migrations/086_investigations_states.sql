-- 086: Allow OPEN / AWAITING_HUMAN / RESOLVED investigation states
--
-- The application state machine (backend/app.py) emits OPEN, AWAITING_HUMAN,
-- and RESOLVED in addition to the originally-enumerated states. The
-- investigations_state_check constraint did not include them, so any code
-- path that closed an investigation without a disposition (writing
-- state=RESOLVED, disposition=UNKNOWN) failed with a 500:
--   "violates check constraint investigations_state_check".
--
-- Widen the constraint to cover all 15 states the app can produce.

ALTER TABLE investigations DROP CONSTRAINT investigations_state_check;

ALTER TABLE investigations ADD CONSTRAINT investigations_state_check
    CHECK (((state)::text = ANY ((ARRAY[
        'NEW'::character varying,
        'TRIAGE_RUNNING'::character varying,
        'TRIAGE_PROVISIONAL'::character varying,
        'ENRICHMENT_RUNNING'::character varying,
        'MERGE_PENDING'::character varying,
        'ANALYZING'::character varying,
        'CONFIRMED'::character varying,
        'NEEDS_REVIEW'::character varying,
        'RIGGS_REVIEW'::character varying,
        'ESCALATED'::character varying,
        'IN_PROGRESS'::character varying,
        'CLOSED'::character varying,
        'OPEN'::character varying,
        'AWAITING_HUMAN'::character varying,
        'RESOLVED'::character varying
    ])::text[])));
