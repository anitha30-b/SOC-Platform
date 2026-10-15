-- Migration: 001_siem_search_indexes
-- Purpose: Reproduce the SIEM PostgreSQL search indexes.
-- Prerequisite: The security_events table must already exist.
-- IMPORTANT: Do not wrap this file in a transaction. CREATE INDEX CONCURRENTLY
-- cannot run inside a transaction block. Apply with psql without the -1 flag.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_source_trgm
    ON public.security_events USING GIN (source gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_event_type_trgm
    ON public.security_events USING GIN (event_type gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_message_trgm
    ON public.security_events USING GIN (message gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_target_trgm
    ON public.security_events USING GIN (target gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_mitre_technique_id_trgm
    ON public.security_events USING GIN (mitre_technique_id gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_mitre_technique_name_trgm
    ON public.security_events USING GIN (mitre_technique_name gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_mitre_tactic_trgm
    ON public.security_events USING GIN (mitre_tactic gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_security_events_alert_status
    ON public.security_events (alert_status);
