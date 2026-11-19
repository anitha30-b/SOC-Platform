-- ============================================================
-- 006_security_headers_runs.sql
-- User-scoped Security Headers inspection runs
-- ============================================================

CREATE TABLE IF NOT EXISTS security_headers_runs (
    id INTEGER PRIMARY KEY,
    job_id VARCHAR(100) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    target_url VARCHAR(500) NOT NULL,
    final_url VARCHAR(500),
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',
    http_status INTEGER,
    header_count INTEGER NOT NULL DEFAULT 0,
    present_header_count INTEGER NOT NULL DEFAULT 0,
    missing_header_count INTEGER NOT NULL DEFAULT 0,
    security_score NUMERIC(5,2),
    result_data TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_security_headers_runs_user
        FOREIGN KEY (user_id) REFERENCES users(id),

    CONSTRAINT fk_security_headers_runs_assessment
        FOREIGN KEY (assessment_id) REFERENCES assessments(id)
);

CREATE SEQUENCE IF NOT EXISTS security_headers_runs_id_seq
    OWNED BY security_headers_runs.id;

SELECT setval(
    'security_headers_runs_id_seq',
    COALESCE((SELECT MAX(id) FROM security_headers_runs), 0) + 1,
    false
);

ALTER TABLE security_headers_runs
    ALTER COLUMN id SET DEFAULT nextval(
        'security_headers_runs_id_seq'::regclass
    );

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_id
    ON security_headers_runs(id);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_job_id
    ON security_headers_runs(job_id);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_user_id
    ON security_headers_runs(user_id);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_assessment_id
    ON security_headers_runs(assessment_id);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_target_url
    ON security_headers_runs(target_url);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_status
    ON security_headers_runs(status);

CREATE INDEX IF NOT EXISTS ix_security_headers_runs_created_at
    ON security_headers_runs(created_at);
