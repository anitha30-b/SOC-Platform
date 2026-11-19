-- Asset identifiers are unique within an owner and telemetry source.

-- Apply with the matching models and registration handlers.

-- Retains asset rows and primary keys.

BEGIN;

SET LOCAL lock_timeout = '5s';

SET LOCAL statement_timeout = '60s';

ALTER TABLE public.endpoint_assets

    ADD CONSTRAINT uq_endpoint_assets_owner_identifier

    UNIQUE (user_id, endpoint_id);

ALTER TABLE public.endpoint_assets

    ADD CONSTRAINT uq_endpoint_assets_source_identifier

    UNIQUE (telemetry_source_id, endpoint_id);

DROP INDEX public.ix_endpoint_assets_endpoint_id;

CREATE INDEX ix_endpoint_assets_endpoint_id

    ON public.endpoint_assets (endpoint_id);

ALTER TABLE public.network_device_assets

    ADD CONSTRAINT uq_network_device_assets_owner_identifier

    UNIQUE (user_id, device_id);

ALTER TABLE public.network_device_assets

    ADD CONSTRAINT uq_network_device_assets_source_identifier

    UNIQUE (telemetry_source_id, device_id);

DROP INDEX public.ix_network_device_assets_device_id;

CREATE INDEX ix_network_device_assets_device_id

    ON public.network_device_assets (device_id);

ALTER TABLE public.database_assets

    ADD CONSTRAINT uq_database_assets_owner_identifier

    UNIQUE (user_id, database_id);

ALTER TABLE public.database_assets

    ADD CONSTRAINT uq_database_assets_source_identifier

    UNIQUE (telemetry_source_id, database_id);

DROP INDEX public.ix_database_assets_database_id;

CREATE INDEX ix_database_assets_database_id

    ON public.database_assets (database_id);

COMMIT;
