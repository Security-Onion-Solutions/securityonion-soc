-- Migration: CREATE TABLE alarm_states

CREATE TABLE IF NOT EXISTS alarm_states (
    alarm_id VARCHAR(64) NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ok',
    current_value TEXT NOT NULL DEFAULT '',
    threshold TEXT NOT NULL DEFAULT '',
    operator VARCHAR(16) NOT NULL DEFAULT 'gt',
    metric VARCHAR(64) NOT NULL DEFAULT '',
    metric_key VARCHAR(64) NOT NULL DEFAULT '',
    triggered_at TIMESTAMP WITH TIME ZONE,
    cleared_at TIMESTAMP WITH TIME ZONE,
    first_breached_at TIMESTAMP WITH TIME ZONE,
    duration_active_seconds INTEGER DEFAULT 0,
    last_evaluated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alarm_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_alarm_states_status ON alarm_states(status);
CREATE INDEX IF NOT EXISTS idx_alarm_states_alarm_id ON alarm_states(alarm_id);
CREATE INDEX IF NOT EXISTS idx_alarm_states_node_id ON alarm_states(node_id);
