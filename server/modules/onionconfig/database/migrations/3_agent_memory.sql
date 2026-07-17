CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS memories (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    memory_text text        NOT NULL,
    session_id  text,                  -- originating session (NULL for seeded/system memories)
    embedding   vector,                -- unconstrained dimension — see note below
    model_id    text        NOT NULL,  -- embedding model that produced `embedding`
    user_id     text                   -- NULL = global scope; value = owning user only
);

CREATE INDEX IF NOT EXISTS idx_memories_user_id
    ON memories (user_id);

CREATE INDEX IF NOT EXISTS idx_memories_text_trgm
    ON memories USING gin (memory_text gin_trgm_ops);
