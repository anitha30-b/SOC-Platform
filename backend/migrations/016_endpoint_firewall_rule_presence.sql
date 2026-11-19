BEGIN;

ALTER TABLE public.endpoint_firewall_rules
ADD COLUMN IF NOT EXISTS is_present BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE public.endpoint_firewall_rules
ADD COLUMN IF NOT EXISTS removed_at TIMESTAMP WITHOUT TIME ZONE NULL;

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_is_present
ON public.endpoint_firewall_rules(is_present);

COMMIT;
