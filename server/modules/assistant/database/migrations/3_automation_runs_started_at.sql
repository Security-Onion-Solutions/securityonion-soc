-- Agent Monitor lists finished runs across every automation newest-first.
CREATE INDEX IF NOT EXISTS idx_automation_runs_started_at
    ON automation_runs (started_at DESC, id);
