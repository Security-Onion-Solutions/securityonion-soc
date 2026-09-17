CREATE TABLE IF NOT EXISTS automations (
    -- The only identity an automation has. Runs, work items and the triage stamps on
    -- alerts all reference it, so it must never change.
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Cosmetic label for the UI. Deliberately not unique and referenced by nothing, so
    -- editing it cannot orphan history or reset an alert's attempt counts.
    display_name       text        NOT NULL DEFAULT '',
    kind               text        NOT NULL,  -- AutomationKind.GetName(); fixed once created
    params             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled            boolean     NOT NULL DEFAULT FALSE,
    interval_seconds   int         NOT NULL,
    user_id            text        NOT NULL,  -- owner; each run's sessions execute as this user
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    last_run_time      timestamptz            -- NULL until the first run ends
);

-- Runs and work items reference automations by id but carry no foreign key: deleting an
-- automation with work in flight must be refused, and a cascade would silently do the
-- opposite. DeleteAutomation clears the history explicitly instead.
CREATE TABLE IF NOT EXISTS automation_runs (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    automation_id      uuid        NOT NULL,
    -- CHECK rather than a comment because idx_automation_runs_one_in_flight below is
    -- only correct while this vocabulary stays closed: a state added without extending
    -- the index predicate would silently stop being deduped.
    state              text        NOT NULL
                                   CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    started_at         timestamptz NOT NULL DEFAULT now(),
    ended_at           timestamptz,           -- NULL while the run is in flight
    error              text                   -- set only when state = 'failed'
);

-- Two runs of one automation must never be in flight at once. Enforced here rather than
-- by asking first and inserting second, which races. Terminal runs fall outside the
-- predicate, so history accumulates freely while the in-flight set stays capped at one.
--
-- 'queued' belongs in the predicate even though nothing writes it yet: the engine opens
-- the run row before admitting the run to the execution pool, which is a bounded FIFO, so
-- a run can sit queued while nothing executes it. Dropping it here would let a second run
-- open during that window, which is the race this index exists to prevent.
CREATE UNIQUE INDEX IF NOT EXISTS idx_automation_runs_one_in_flight
    ON automation_runs (automation_id)
    WHERE state IN ('queued', 'running');

-- The run history view reads one automation newest-first.
CREATE INDEX IF NOT EXISTS idx_automation_runs_automation_id_started_at
    ON automation_runs (automation_id, started_at DESC);

CREATE TABLE IF NOT EXISTS automation_work_items (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    automation_id      uuid        NOT NULL,
    -- The run that created this item. Items are owned by the automation, not the run:
    -- unfinished work survives the run that found it so a later run resumes it, which
    -- is why this is nullable and does not cascade.
    run_id             uuid        REFERENCES automation_runs (id) ON DELETE SET NULL,
    group_key          text        NOT NULL,  -- what this item is about, in the kind's terms
    payload            jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- opaque outside the kind
    state              text        NOT NULL DEFAULT 'pending'
                                   CHECK (state IN ('pending', 'running', 'applying', 'done', 'failed')),
    attempts           int         NOT NULL DEFAULT 0,
    session_id         text,                  -- lives in Elasticsearch, so no foreign key
    result             jsonb,                 -- the kind's conclusion, opaque outside the kind
    error              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Claiming, resuming and reconciling all read the same set: one automation's unfinished
-- items, oldest first. Partial, so a task claims as fast on its three-hundredth run as
-- on its first.
CREATE INDEX IF NOT EXISTS idx_automation_work_items_open
    ON automation_work_items (automation_id, created_at)
    WHERE state IN ('pending', 'running', 'applying');

-- One open item per group. A kind that rescans and re-enqueues would otherwise open a
-- second item for a group whose first is still in flight. Inserts infer this index with
-- ON CONFLICT DO NOTHING, which is what makes enqueueing idempotent after a crash --
-- inference requires the predicate below to match the statement's verbatim.
CREATE UNIQUE INDEX IF NOT EXISTS idx_automation_work_items_one_open_per_group
    ON automation_work_items (automation_id, group_key)
    WHERE state IN ('pending', 'running', 'applying');

CREATE TABLE IF NOT EXISTS automation_run_sessions (
    run_id             uuid        NOT NULL REFERENCES automation_runs (id) ON DELETE CASCADE,
    session_id         text        NOT NULL,  -- Elasticsearch document id; no foreign key
    work_item_id       uuid        REFERENCES automation_work_items (id) ON DELETE SET NULL,
    purpose            text        NOT NULL DEFAULT '',  -- the kind's name for this session's role
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, session_id)
);

CREATE TABLE IF NOT EXISTS automation_run_result_audit (
    run_id             uuid        NOT NULL REFERENCES automation_runs (id) ON DELETE CASCADE,
    alert_id           text        NOT NULL,  -- Elasticsearch document id; no foreign key
    work_item_id       uuid        REFERENCES automation_work_items (id) ON DELETE SET NULL,
    recommendation     text        NOT NULL,
    reason             text        NOT NULL DEFAULT '',
    -- True when this alert was never analyzed on its own: the conclusion came from the
    -- sampled alert that stood in for its group.
    inherited          boolean     NOT NULL DEFAULT FALSE,
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, alert_id)
);
