# SIEM PostgreSQL Search Index Migration

## Purpose

`001_siem_search_indexes.sql` installs the PostgreSQL `pg_trgm`
extension and creates seven GIN trigram indexes for SIEM substring search,
plus a B-tree index on `security_events.alert_status`.

## Prerequisites

- PostgreSQL with `pg_trgm` available.
- The `public.security_events` table and referenced columns must exist.
- The database role must have the required extension and index privileges.

## Apply to a new or provisioned database

Verify that `DATABASE_URL` points to the intended database, then run from
the repository root:

    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/migrations/001_siem_search_indexes.sql

Do not wrap the script in a transaction. `CREATE INDEX CONCURRENTLY`
cannot run inside a transaction block.

The migration is intentionally not invoked during application startup.
The live database already has these indexes; there is no need to rerun
the script there merely to validate it.

## Verify

Check extension availability:

    SELECT extversion FROM pg_extension WHERE extname = 'pg_trgm';

Verify the eight indexes:

    SELECT i.relname, x.indisvalid, x.indisready
    FROM pg_class i
    JOIN pg_index x ON x.indexrelid = i.oid
    JOIN pg_class t ON t.oid = x.indrelid
    WHERE t.relname = 'security_events'
      AND i.relname IN (
        'ix_security_events_source_trgm',
        'ix_security_events_event_type_trgm',
        'ix_security_events_message_trgm',
        'ix_security_events_target_trgm',
        'ix_security_events_mitre_technique_id_trgm',
        'ix_security_events_mitre_technique_name_trgm',
        'ix_security_events_mitre_tactic_trgm',
        'ix_security_events_alert_status'
      )
    ORDER BY i.relname;

All eight indexes should be present, with `indisvalid` and `indisready`
both true.

## Operational notes

- The migration does not alter or delete SIEM event records.
- It does not change application search queries, correlation rules,
  or detection thresholds.
- Monitor query latency, index usage, storage, and ingestion overhead.
- If a concurrent index build fails, inspect the index state before
  retrying; a failed build can leave an invalid index.
