-- Migration: CREATE TABLE notifications and notification_user_states

CREATE TABLE IF NOT EXISTS notifications (
    id VARCHAR(64) PRIMARY KEY,
    source VARCHAR(32) NOT NULL,            -- 'detection', 'metric', 'agent_ai', 'report'
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,          -- 'info', 'low', 'medium', 'high', 'critical'
    fields JSONB DEFAULT '{}'::jsonb,
    links JSONB DEFAULT '{}'::jsonb,
    attachments JSONB DEFAULT '[]'::jsonb,
    silence_key VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_source ON notifications(source);

CREATE TABLE IF NOT EXISTS notification_user_states (
    notification_id VARCHAR(64) REFERENCES notifications(id) ON DELETE CASCADE,
    user_id VARCHAR(128) NOT NULL,          -- SOC Username / Kratos Subject ID
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP WITH TIME ZONE,
    is_dismissed BOOLEAN DEFAULT FALSE,
    dismissed_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (notification_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_notification_user_states_user ON notification_user_states(user_id, is_read, is_dismissed);
