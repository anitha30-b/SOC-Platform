# SOC Platform company source handoff

This archive is a reviewable source/build snapshot. It is NOT a production-ready
certification or a tested company-server installer. Check HANDOFF_MANIFEST.json
for the commit, local modifications, included file hashes and verification scope.

## Included

Backend/frontend source and reviewed tests, runtime Python requirements, frontend
package lock and production build, tracked schema migrations, and the local MITRE
catalogue snapshot when present. Discovery results and customer reports are NOT
included. The runtime Python requirements are root pins, not a cross-platform lock.

## Company IT setup and acceptance

1. Supply a Linux server and confirm OS, Python/Node versions, domain, capacity,
   scanner privileges, approved target policy and network access. Development used
   Python 3.14.7; clean installation on the company OS remains untested.
2. Create a dedicated service account and fresh staging PostgreSQL database. Review
   migrations, rehearse backup/restore, before changing an existing database. API imports no longer perform DDL; bootstrap
   missing tables explicitly as described below. Do not point an unreviewed startup at a production database.
3. In a clean virtual environment, install backend/requirements.txt and run the
   reviewed isolated suites from the extracted project root with
   `python deployment/verify_source.py`. Provision OS tools independently (DNSRecon, Nmap,
   Nuclei, ZAP, etc.). Python requirements do not install scanner binaries.
4. Supply real secrets through the service environment. deployment/backend.env.example
   lists basic inputs; inspect all feature-specific environment variables before
   enabling integrations. Existing encryption keys must be preserved if an existing
   encrypted database is migrated. This archive contains no database migration data.
5. ZAP_URL and ZAP_API_KEY configure the ZAP connection. Configure the daemon with
   the same key; keep its API private. Generate a new company key. The developer's
   private local key is excluded; moving it out of current source does not remove
   it from earlier Git commits.
6. DNSRecon's current subdomain profile expects the OS wordlist at
   /usr/share/dnsrecon/dnsrecon/data/subdomains-top1mil-5000.txt. Confirm the package
   provides it. Quick explicitly uses the bundled 250-label subset with limited
   coverage; Full remains the default. Review wordlist provenance and terms before
   redistribution. MITRE uses backend/data/mitre; verify the included snapshot is found.
7. Serve frontend/dist with the company HTTPS web server. Reverse proxy /api/ to
   the loopback backend, stripping /api; forward WebSocket Upgrade/Connection
   headers and allow suitable timeouts. Review CORS, allowed origins and TLS.
   Port 5173 is the development server, not the company production web server.
8. Use one API worker while memory-backed running jobs and listener ownership are
   being reviewed. Do not enable multiple workers or auto-reload in production.
   Completed discovery history is persisted; durable execution/restart recovery
   across ALL tool jobs has not been established. Review collectors and firewall
   startup privileges before enabling them on a company host.
9. Grant only the intended tools to each account. Subdomain Discovery still needs
   an administrator permission grant. Isolated subdomain checks passed before
   this handoff; live DNS and browser verification remain pending.
10. Verify real user/admin workflows over HTTPS/WSS, tenant isolation, scanner
    cancellation/failure handling, report downloads, backups, monitoring and load.
    Run scans only against explicitly approved lab targets.

## Remaining acceptance items

- Clean install, company-server setup, restore rehearsal, load/soak testing and
  independent security review remain pending.
- ZAP's live zero-finding history/report pipeline was verified; positive finding
  detection and live delivery were not demonstrated by that zero-finding run.
- Payment gateway/subscriptions have not been implemented or verified.
- A complete production assessment of every tool/module is still pending.
- Company approval of third-party software/data licences is required for release.
- The archive excludes virtual environments, node_modules, .env/private files,
  backups, logs, databases and live customer evidence. Provision those separately
  through approved processes; do not distribute developer credentials or records.

## Backend startup corrections and shared-server controls

Install updated backend/requirements.txt, including email-validator. Importing
main no longer creates or alters tables. All ORM modules are registered before
schema setup, and startup verifies the schema before starting any services.

For a new staging database, from the repository root, after checking the private
file's DATABASE_URL and reviewing backend/migrations:

    backend/.venv/bin/python deployment/initialize_database.py --env-file /etc/soc-platform/backend.env --apply

This creates missing tables and adds soc_assets.url if absent. It does not apply
all historical SQL migrations, seed users, grant permissions or start collectors.
Back up an existing database and review/apply its required migrations separately.
Keep SOC_INITIALIZE_DATABASE_ON_STARTUP=false under the normal API service; a
separate database owner can perform bootstrap while the runtime role has no DDL.
The explicit bootstrap file takes precedence over a shell DATABASE_URL.

These controls default to false, including when absent from an old .env.
Set only IT-approved services to true, then restart the backend:

| Setting | Effect when true |
| --- | --- |
| SOC_INITIALIZE_DATABASE_ON_STARTUP | Bootstrap missing tables before schema validation |
| SOC_ENABLE_FIREWALL_OPERATIONS | Permit SOC firewall setup and runtime IP-block actions |
| SOC_ENABLE_SIEM_INGESTION | Start the configured SIEM ingestion loop |
| SOC_ENABLE_SNORT_COLLECTOR | Start reading the configured Snort journal |
| SOC_ENABLE_HOST_COLLECTORS | Start local journal/tshark subprocesses |
| SOC_ENABLE_SERVER_MONITOR | Start periodic network checks for registered assets |
| SOC_ENABLE_POSTGRES_LISTENERS | Start customer/admin database notification listeners |

Invalid booleans prevent startup. Disabled firewall operations also block calls
from detection rules. Other collector flags do not enable the firewall. Database
listeners do not enable host capture. With listeners disabled, stored records and
HTTP APIs work, but PostgreSQL-driven live push is unavailable. Monitoring and
collector panels need their corresponding services enabled for new observations.
The API does not need root simply to serve dashboards.

For live PostgreSQL listeners, DATABASE_URL must also be accepted by psycopg2
(e.g. postgresql://... rather than a SQLAlchemy-only driver-qualified URL).
Use one worker. Host collectors require their own approved OS privileges and
shutdown terminates only child processes owned by this API instance.

For clean startup verification, create a new virtual environment, install the
complete requirements file and run the disposable cluster check (as non-root):

    python -m pip install -r backend/requirements.txt
    python -m pip check
    python deployment/verify_backend_startup.py

Use --postgres-bin /path/to/postgresql/bin if initdb/pg_ctl are not on PATH.
The check runs full API import, schema bootstrap/idempotency, ASGI startup and
shutdown, disabled-service guards, and a real loopback Uvicorn HTTP server. It
creates/stops its own temporary database and never uses a company .env.

The disposable startup verifier uses authenticated loopback TCP and disables
Unix sockets, so it does not need write permission to the system PostgreSQL
socket directory. A failed check preserves redacted PostgreSQL/API logs under
.backups (or --diagnostics-dir) before deleting its temporary cluster.
