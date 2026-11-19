CREATE TABLE IF NOT EXISTS public.collector_execution_runs (
    id BIGSERIAL PRIMARY KEY,
    run_id VARCHAR(100) NOT NULL,
    telemetry_source_id INTEGER NOT NULL,
    endpoint_asset_id INTEGER NOT NULL,
    started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITHOUT TIME ZONE NULL,
    status VARCHAR(20) NOT NULL,
    collected_count INTEGER NOT NULL DEFAULT 0,
    accepted_count INTEGER NOT NULL DEFAULT 0,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    error_details TEXT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_collector_execution_runs_source
        FOREIGN KEY (telemetry_source_id)
        REFERENCES public.telemetry_sources(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_collector_execution_runs_endpoint
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_collector_execution_runs_source_run
        UNIQUE (telemetry_source_id, run_id),

    CONSTRAINT ck_collector_execution_runs_status
        CHECK (status IN ('SUCCESS', 'PARTIAL', 'FAILED')),

    CONSTRAINT ck_collector_execution_runs_counts
        CHECK (
            collected_count >= 0
            AND accepted_count >= 0
            AND duplicate_count >= 0
            AND error_count >= 0
        )
);

CREATE INDEX IF NOT EXISTS idx_collector_execution_runs_endpoint_started
    ON public.collector_execution_runs(endpoint_asset_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_collector_execution_runs_source_started
    ON public.collector_execution_runs(telemetry_source_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_collector_execution_runs_status
    ON public.collector_execution_runs(status);
