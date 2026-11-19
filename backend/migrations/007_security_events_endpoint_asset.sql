-- ============================================================
-- 007_security_events_endpoint_asset.sql
-- Associate tenant-scoped security events with endpoint assets
-- ============================================================

ALTER TABLE public.security_events
    ADD COLUMN IF NOT EXISTS endpoint_asset_id INTEGER NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_security_events_endpoint_asset_id'
          AND conrelid = 'public.security_events'::regclass
    ) THEN
        ALTER TABLE public.security_events
            ADD CONSTRAINT fk_security_events_endpoint_asset_id
            FOREIGN KEY (endpoint_asset_id)
            REFERENCES public.endpoint_assets(id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_security_events_endpoint_asset_id
    ON public.security_events (endpoint_asset_id);
