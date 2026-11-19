-- Migration: 003_asset_discovery_runs
-- Purpose: Persist assessment-owned Nmap discovery results for the user dashboard.
-- Apply after backing up the database and deploying the matching model code.

CREATE TABLE IF NOT EXISTS public.asset_discovery_runs (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(100) NOT NULL UNIQUE,
    user_id INTEGER NOT NULL
        CONSTRAINT fk_asset_discovery_runs_user_id REFERENCES public.users(id),
    assessment_id INTEGER NOT NULL
        CONSTRAINT fk_asset_discovery_runs_assessment_id REFERENCES public.assessments(id),
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'RUNNING',
    host_count INTEGER NOT NULL DEFAULT 0,
    open_port_count INTEGER NOT NULL DEFAULT 0,
    result_data TEXT NULL,
    started_at TIMESTAMP WITHOUT TIME ZONE NULL,
    completed_at TIMESTAMP WITHOUT TIME ZONE NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_asset_discovery_runs_user_id
    ON public.asset_discovery_runs (user_id);

CREATE INDEX IF NOT EXISTS ix_asset_discovery_runs_assessment_id
    ON public.asset_discovery_runs (assessment_id);

CREATE INDEX IF NOT EXISTS ix_asset_discovery_runs_status
    ON public.asset_discovery_runs (status);

CREATE INDEX IF NOT EXISTS ix_asset_discovery_runs_created_at
    ON public.asset_discovery_runs (created_at);
