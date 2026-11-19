-- Migration: 011_endpoint_system_hardening
-- Purpose: Persist Windows system hardening control results reported by client endpoints.

CREATE TABLE IF NOT EXISTS public.endpoint_system_hardening (
    id SERIAL PRIMARY KEY,
    endpoint_asset_id INTEGER NOT NULL,

    control_id VARCHAR(255) NOT NULL,
    control_name VARCHAR(500) NOT NULL,
    category VARCHAR(255) NOT NULL,

    status VARCHAR(30) NOT NULL,
    observed_value TEXT NULL,
    details TEXT NULL,

    first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    CONSTRAINT fk_endpoint_system_hardening_endpoint_asset_id
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_endpoint_system_hardening_endpoint_control
        UNIQUE (endpoint_asset_id, control_id)
);

CREATE INDEX IF NOT EXISTS ix_endpoint_system_hardening_endpoint_asset_id
    ON public.endpoint_system_hardening(endpoint_asset_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_system_hardening_control_id
    ON public.endpoint_system_hardening(control_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_system_hardening_category
    ON public.endpoint_system_hardening(category);

CREATE INDEX IF NOT EXISTS ix_endpoint_system_hardening_status
    ON public.endpoint_system_hardening(status);

CREATE INDEX IF NOT EXISTS ix_endpoint_system_hardening_last_seen
    ON public.endpoint_system_hardening(last_seen);
