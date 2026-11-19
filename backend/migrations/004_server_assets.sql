-- ============================================================
-- 004_server_assets.sql
-- User-scoped server assets derived from Asset Discovery
-- ============================================================

CREATE TABLE IF NOT EXISTS server_assets (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    discovery_run_id INTEGER NOT NULL,
    hostname VARCHAR(500),
    ip_address VARCHAR(100),
    target VARCHAR(500) NOT NULL,
    host_status VARCHAR(30),
    os_name VARCHAR(500),
    open_port_count INTEGER NOT NULL DEFAULT 0,
    services_data TEXT,
    last_seen TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_server_assets_user
        FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_server_assets_assessment
        FOREIGN KEY (assessment_id) REFERENCES assessments(id),
    CONSTRAINT fk_server_assets_discovery_run
        FOREIGN KEY (discovery_run_id) REFERENCES asset_discovery_runs(id)
);

CREATE INDEX IF NOT EXISTS ix_server_assets_id
    ON server_assets(id);

CREATE INDEX IF NOT EXISTS ix_server_assets_user_id
    ON server_assets(user_id);

CREATE INDEX IF NOT EXISTS ix_server_assets_assessment_id
    ON server_assets(assessment_id);

CREATE INDEX IF NOT EXISTS ix_server_assets_discovery_run_id
    ON server_assets(discovery_run_id);

CREATE INDEX IF NOT EXISTS ix_server_assets_last_seen
    ON server_assets(last_seen);
