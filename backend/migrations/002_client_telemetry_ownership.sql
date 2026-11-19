-- Migration: 002_client_telemetry_ownership
-- Purpose: Register authenticated telemetry sources and assign ownership
-- to newly ingested events. Existing security events remain unassigned.
-- Apply after backing up the database and deploying the matching model code.

CREATE TABLE IF NOT EXISTS public.telemetry_sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    client_id INTEGER NULL
        CONSTRAINT fk_telemetry_sources_client_id REFERENCES public.clients(id),
    owner_user_id INTEGER NULL
        CONSTRAINT fk_telemetry_sources_owner_user_id REFERENCES public.users(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by INTEGER NOT NULL
        CONSTRAINT fk_telemetry_sources_created_by REFERENCES public.users(id),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITHOUT TIME ZONE NULL
);

ALTER TABLE public.security_events
    ADD COLUMN IF NOT EXISTS client_id INTEGER NULL;

ALTER TABLE public.security_events
    ADD COLUMN IF NOT EXISTS telemetry_source_id INTEGER NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_security_events_client_id_clients'
          AND conrelid = 'public.security_events'::regclass
    ) THEN
        ALTER TABLE public.security_events
            ADD CONSTRAINT fk_security_events_client_id_clients
            FOREIGN KEY (client_id) REFERENCES public.clients(id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_security_events_telemetry_source_id'
          AND conrelid = 'public.security_events'::regclass
    ) THEN
        ALTER TABLE public.security_events
            ADD CONSTRAINT fk_security_events_telemetry_source_id
            FOREIGN KEY (telemetry_source_id)
            REFERENCES public.telemetry_sources(id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_security_events_client_id
    ON public.security_events (client_id);

CREATE INDEX IF NOT EXISTS ix_security_events_telemetry_source_id
    ON public.security_events (telemetry_source_id);

CREATE INDEX IF NOT EXISTS ix_telemetry_sources_client_id
    ON public.telemetry_sources (client_id);

CREATE INDEX IF NOT EXISTS ix_telemetry_sources_owner_user_id
    ON public.telemetry_sources (owner_user_id);

CREATE INDEX IF NOT EXISTS ix_telemetry_sources_enabled
    ON public.telemetry_sources (enabled);
