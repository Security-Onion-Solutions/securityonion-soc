-- automation_id names an automation defined in Salt pillar, not a row in this database, so
-- there is nothing to reference.
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
    -- One root session per attempt, in attempt order. Sessions live in Elasticsearch, so
    -- there is nothing to reference; a root's delegated children are reachable from it by
    -- walking parentSessionId.
    session_ids        text[]      NOT NULL DEFAULT '{}',
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
