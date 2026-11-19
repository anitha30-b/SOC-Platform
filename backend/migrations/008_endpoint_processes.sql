-- Migration: 008_endpoint_processes
-- Purpose: Persist the current process inventory reported by client endpoints.

CREATE TABLE IF NOT EXISTS public.endpoint_processes (
    id SERIAL PRIMARY KEY,
    endpoint_asset_id INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    parent_pid INTEGER NULL,
    name VARCHAR(500) NOT NULL,
    executable TEXT NULL,
    command_line TEXT NULL,
    username VARCHAR(255) NULL,
    status VARCHAR(50) NULL,
    cpu_percent DOUBLE PRECISION NULL,
    memory_percent DOUBLE PRECISION NULL,
    first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    CONSTRAINT fk_endpoint_processes_endpoint_asset_id
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_endpoint_processes_endpoint_pid
        UNIQUE (endpoint_asset_id, pid)
);

CREATE INDEX IF NOT EXISTS ix_endpoint_processes_endpoint_asset_id
    ON public.endpoint_processes(endpoint_asset_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_processes_name
    ON public.endpoint_processes(name);

CREATE INDEX IF NOT EXISTS ix_endpoint_processes_username
    ON public.endpoint_processes(username);

CREATE INDEX IF NOT EXISTS ix_endpoint_processes_status
    ON public.endpoint_processes(status);

CREATE INDEX IF NOT EXISTS ix_endpoint_processes_last_seen
    ON public.endpoint_processes(last_seen);
