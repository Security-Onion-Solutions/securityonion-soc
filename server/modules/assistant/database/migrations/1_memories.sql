cdCREATE TABLE IF NOT EXISTS memories (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz,
    user_id            text        NOT NULL,  -- user ID
    memory_text        text        NOT NULL,
    session_id         text,                  -- originating session (NULL for seeded/system memories)
    embedding          vector      NOT NULL,
    model_id           text        NOT NULL,  -- embedding model that produced `embedding`
    target_user_id     text,                  -- NULL = global scope; value = owning user only
    user_defined       boolean     NOT NULL DEFAULT FALSE,
    usage_count        int         NOT NULL DEFAULT 0
);

-- FindNearbyMemories always filters on model_id and usually a target_user_id scope
CREATE INDEX IF NOT EXISTS idx_memories_model_id_target_user_id
    ON memories (model_id, target_user_id);
