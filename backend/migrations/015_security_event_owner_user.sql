BEGIN;

ALTER TABLE public.security_events
ADD COLUMN IF NOT EXISTS owner_user_id INTEGER NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_security_events_owner_user_id_users'
          AND conrelid = 'public.security_events'::regclass
    ) THEN
        ALTER TABLE public.security_events
        ADD CONSTRAINT fk_security_events_owner_user_id_users
        FOREIGN KEY (owner_user_id)
        REFERENCES public.users(id)
        ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS ix_security_events_owner_user_id
ON public.security_events(owner_user_id);

COMMIT;
