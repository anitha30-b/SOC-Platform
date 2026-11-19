-- Migration: 009_endpoint_services
-- Purpose: Persist the current service inventory reported by client endpoints.

CREATE TABLE IF NOT EXISTS public.endpoint_services (
    id SERIAL PRIMARY KEY,
    endpoint_asset_id INTEGER NOT NULL,
    service_name VARCHAR(500) NOT NULL,
    display_name VARCHAR(500) NULL,
    status VARCHAR(50) NULL,
    startup_type VARCHAR(50) NULL,
    executable TEXT NULL,
    command_line TEXT NULL,
    username VARCHAR(255) NULL,
    pid INTEGER NULL,
    first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    CONSTRAINT fk_endpoint_services_endpoint_asset_id
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_endpoint_services_endpoint_name
        UNIQUE (endpoint_asset_id, service_name)
);

CREATE INDEX IF NOT EXISTS ix_endpoint_services_endpoint_asset_id
    ON public.endpoint_services(endpoint_asset_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_services_service_name
    ON public.endpoint_services(service_name);

CREATE INDEX IF NOT EXISTS ix_endpoint_services_status
    ON public.endpoint_services(status);

CREATE INDEX IF NOT EXISTS ix_endpoint_services_username
    ON public.endpoint_services(username);

CREATE INDEX IF NOT EXISTS ix_endpoint_services_last_seen
    ON public.endpoint_services(last_seen);
