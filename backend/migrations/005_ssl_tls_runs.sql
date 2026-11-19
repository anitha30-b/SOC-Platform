-- ============================================================
-- 005_ssl_tls_runs.sql
-- User-scoped SSL/TLS inspection runs
-- ============================================================

CREATE TABLE IF NOT EXISTS ssl_tls_runs (
    id INTEGER PRIMARY KEY,
    job_id VARCHAR(100) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 443,
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',
    tls_protocol VARCHAR(30),
    cipher_name VARCHAR(255),
    cipher_bits INTEGER,
    certificate_subject TEXT,
    certificate_issuer TEXT,
    certificate_serial VARCHAR(255),
    certificate_valid_from TIMESTAMP,
    certificate_valid_until TIMESTAMP,
    san_count INTEGER NOT NULL DEFAULT 0,
    hostname_verified BOOLEAN,
    certificate_verified BOOLEAN,
    days_remaining INTEGER,
    result_data TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_ssl_tls_runs_user
        FOREIGN KEY (user_id) REFERENCES users(id),

    CONSTRAINT fk_ssl_tls_runs_assessment
        FOREIGN KEY (assessment_id) REFERENCES assessments(id)
);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_id
    ON ssl_tls_runs(id);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_job_id
    ON ssl_tls_runs(job_id);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_user_id
    ON ssl_tls_runs(user_id);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_assessment_id
    ON ssl_tls_runs(assessment_id);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_target_host
    ON ssl_tls_runs(target_host);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_status
    ON ssl_tls_runs(status);

CREATE INDEX IF NOT EXISTS ix_ssl_tls_runs_created_at
    ON ssl_tls_runs(created_at);
