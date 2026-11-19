CREATE TABLE IF NOT EXISTS public.endpoint_server_configuration (
    id SERIAL PRIMARY KEY,
    endpoint_asset_id INTEGER NOT NULL,
    hostname VARCHAR(500) NULL,
    os_name VARCHAR(500) NULL,
    os_version VARCHAR(500) NULL,
    architecture VARCHAR(100) NULL,
    processor VARCHAR(1000) NULL,
    memory_total_gb NUMERIC(12, 2) NULL,
    disk_total_gb NUMERIC(12, 2) NULL,
    disk_free_gb NUMERIC(12, 2) NULL,
    disk_usage_percent NUMERIC(6, 2) NULL,
    uptime_seconds BIGINT NULL,
    uptime VARCHAR(255) NULL,
    timezone VARCHAR(255) NULL,
    domain_or_workgroup VARCHAR(500) NULL,
    windows_edition VARCHAR(500) NULL,
    power_plan VARCHAR(500) NULL,
    first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    CONSTRAINT fk_endpoint_server_configuration_endpoint_asset_id
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_endpoint_server_configuration_endpoint
        UNIQUE (endpoint_asset_id)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_server_configuration_endpoint_asset_id
    ON public.endpoint_server_configuration(endpoint_asset_id);

CREATE INDEX IF NOT EXISTS idx_endpoint_server_configuration_hostname
    ON public.endpoint_server_configuration(hostname);

CREATE INDEX IF NOT EXISTS idx_endpoint_server_configuration_os_name
    ON public.endpoint_server_configuration(os_name);

CREATE INDEX IF NOT EXISTS idx_endpoint_server_configuration_last_seen
    ON public.endpoint_server_configuration(last_seen);
