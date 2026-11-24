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
   migrations, rehearse backup/restore, and review main.py's import-time create_all
   before starting it. Do not point an unreviewed startup at a production database.
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
