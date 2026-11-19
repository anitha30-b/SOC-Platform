CREATE TABLE IF NOT EXISTS public.saved_searches (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    owner_user_id INTEGER NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    client_id INTEGER NULL
        REFERENCES public.clients(id) ON DELETE CASCADE,
    search_text TEXT NOT NULL DEFAULT '',
    severity VARCHAR(20) NOT NULL DEFAULT 'all',
    source VARCHAR(255) NOT NULL DEFAULT 'all',
    event_type VARCHAR(100) NOT NULL DEFAULT 'all',
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_saved_searches_severity
        CHECK (severity IN ('all', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ERROR', 'WARNING')),

    CONSTRAINT ck_saved_searches_name
        CHECK (length(trim(name)) > 0)
);

CREATE INDEX IF NOT EXISTS ix_saved_searches_owner_created
    ON public.saved_searches(owner_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_saved_searches_client_created
    ON public.saved_searches(client_id, created_at DESC);
