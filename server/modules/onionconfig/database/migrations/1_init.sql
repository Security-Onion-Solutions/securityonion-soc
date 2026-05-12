-- Initial schema for onionconfig settings storage.

CREATE TABLE IF NOT EXISTS settings (
    setting_id         VARCHAR(1024) NOT NULL,
    value              JSONB,
    duplicated_from_id VARCHAR(1024),
    node_id            VARCHAR(128),
    PRIMARY KEY (setting_id, COALESCE(node_id, ''))
);

CREATE TABLE IF NOT EXISTS audit_settings (
    id         BIGSERIAL     PRIMARY KEY,
    setting_id VARCHAR(1024) NOT NULL,
    node_id    VARCHAR(128),
    ts         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    user_id    VARCHAR(128)  NOT NULL,
    old_value  JSONB,
    new_value  JSONB,
    note       TEXT
);

-- Indexes for settings
CREATE INDEX IF NOT EXISTS idx_settings_setting_id        ON settings (setting_id);
CREATE INDEX IF NOT EXISTS idx_settings_node_id           ON settings (node_id);
CREATE INDEX IF NOT EXISTS idx_settings_duplicated_from_id ON settings (duplicated_from_id);

-- Indexes for audit_settings
CREATE INDEX IF NOT EXISTS idx_audit_settings_setting_id ON audit_settings (setting_id);
CREATE INDEX IF NOT EXISTS idx_audit_settings_node_id    ON audit_settings (node_id);
CREATE INDEX IF NOT EXISTS idx_audit_settings_user_id    ON audit_settings (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_settings_ts         ON audit_settings (ts);
