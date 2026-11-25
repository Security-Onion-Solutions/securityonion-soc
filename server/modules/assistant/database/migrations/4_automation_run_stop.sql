-- automation_runs_state_check is the name Postgres gives migration 2's inline CHECK. The
-- vocabulary stays closed because idx_automation_runs_one_in_flight is only correct while it
-- is; stopped is terminal, so that index's predicate does not change.
ALTER TABLE automation_runs DROP CONSTRAINT IF EXISTS automation_runs_state_check;
ALTER TABLE automation_runs ADD CONSTRAINT automation_runs_state_check
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'stopped'));
ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS started_by text;  -- NULL for scheduled runs
ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS stopped_by text;  -- set when Stop is pressed; NULL unless the run is stopping or stopped
ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS stopped_at timestamptz;  -- set with stopped_by, when Stop is pressed; ended_at is later, when the run finishes ending

-- The run behind each session_ids entry, appended with it. Items written before this
-- migration start empty, and their earlier sessions keep the positional attribution.
ALTER TABLE automation_work_items ADD COLUMN IF NOT EXISTS session_run_ids text[] NOT NULL DEFAULT '{}';

-- Run history matches items by run_id, failed_run_ids and session_run_ids in one OR; an
-- unindexed branch would turn the per-run EXISTS behind hide-empty into a full scan.
CREATE INDEX IF NOT EXISTS idx_automation_work_items_session_run_ids
    ON automation_work_items USING GIN (session_run_ids);
