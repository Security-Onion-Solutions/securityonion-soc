CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS memories (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    user_id            text        NOT NULL,  -- user ID
    memory_text        text        NOT NULL,
    session_id         text,                  -- originating session (NULL for seeded/system memories)
    embedding          vector,
    model_id           text        NOT NULL,  -- embedding model that produced `embedding`
    target_user_id     text                   -- NULL = global scope; value = owning user only
);

CREATE INDEX IF NOT EXISTS idx_memories_user_id
    ON memories (user_id);

