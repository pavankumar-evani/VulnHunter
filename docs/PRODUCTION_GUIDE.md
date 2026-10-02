# Quanta — Production Guide

How to get Quanta running for real, connect your own scanners, and keep it healthy. For
the architecture and sizing see [DEPLOYMENT_ARCHITECTURE.md](DEPLOYMENT_ARCHITECTURE.md);
for each source's credentials see [CONNECTOR_ONBOARDING.md](CONNECTOR_ONBOARDING.md).

## What you get without anything else

Connect a scanner, and Quanta pulls findings on a schedule, classifies assets, enriches them
with CISA KEV and EPSS, scores and ranks them live, assigns owners, runs the approval and
ticket workflows, and reports. **None of that needs Claude Code or an AI model.**

Two capabilities do need the Claude Code CLI on the server (they are the AI parts): generating
remediation playbooks, OT plans and dependency-upgrade plans, and AI Assist. Without it those
screens say so and everything else keeps working.

## Get running in about 15 minutes (Docker)

You need a Linux host with Docker, a DNS name pointing at it, and ports 80 and 443 open.

```bash
git clone <your-Quanta-repository-URL> quanta && cd quanta
cp .env.production.example .env
python3 cli/quanta_admin.py gen-secret     # paste into QUANTA_SESSION_SECRET
python3 cli/quanta_admin.py gen-key        # paste into QUANTA_ENCRYPTION_KEY, and store a copy safely
# edit .env: QUANTA_DOMAIN, QUANTA_DB_PASSWORD, QUANTA_BOOTSTRAP_ADMIN_EMAIL, QUANTA_ADMIN_PASSWORD
docker compose up -d --build
docker compose logs -f quanta              # shows the configuration check
```

Open `https://<your domain>`, sign in as the bootstrap administrator and **change the
password**. The container created the schema, ran any migrations, made that first admin, and
ran `check`. No demo accounts or sample data exist.

Without Docker: `pip install -r dashboard/requirements.txt` (and the three other requirement
files), set the same environment variables, then `python cli/quanta_admin.py init`,
`create-admin`, `check`, and `python dashboard/app.py` behind your own TLS proxy.

## Connect your first source (5 minutes each)

1. **Connections** in the sidebar, then **Add a connection**.
2. Pick the source, fill in the fields (see CONNECTOR_ONBOARDING.md), press **Test connection**.
3. Choose a schedule (hourly is a good start) and save.
4. Press **Sync now**. The row shows *Syncing…*, then a plain-language result: how many findings
   were fetched, new, updated, and whether threat intel was refreshed.
5. Open **Queue**: your real findings, ranked, with KEV and EPSS where a CVE is known.

Credentials are encrypted with `QUANTA_ENCRYPTION_KEY`, are never shown again, and a blank
secret on edit keeps the stored one. Without that key the page refuses to store anything and
says why.

### What a sync does

* **Finding sources** (Tenable, Qualys, Prisma Cloud, Cortex XSIAM): new findings are added with
  the next `FIND-N` id; a finding seen again keeps its id and first-seen date and gets a new
  last-seen. Tenable is a complete export, so findings it no longer reports **leave the queue**
  (that is how a fixed vulnerability disappears, and how verification sees the fix). The others
  never remove anything automatically.
* **Asset sources** (Infoblox, Axonius, Active Directory): IP and MAC ground truth is reconciled
  into the asset inventory.
* Informational scanner rows are skipped; rows with no host are skipped and counted.
* Assets are classified by explicit rules (`remediation/ingest/classify.py`). Anything it cannot
  place is `unknown` rather than guessed; unknown assets are still scored and queued.
* Every sync is audited, and a connection cannot run twice at once.

## Day-2 operations

| Task | How |
|---|---|
| Is everything configured safely? | `python cli/quanta_admin.py check` (container: `docker compose exec quanta python cli/quanta_admin.py check`) |
| Add or recover an admin | `create-admin`, `reset-password` (password from `QUANTA_ADMIN_PASSWORD` or a prompt) |
| Back up | `python cli/quanta_admin.py backup --out ./backups` (database, findings, config; **not** the encryption key) |
| Restore | stop the app, `restore --from <zip> --yes` |
| Upgrade | pull the new version, `docker compose up -d --build`; migrations apply on start and are recorded |
| Rotate the encryption key | put the new key first in `QUANTA_ENCRYPTION_KEY` (comma-separated, newest first), run `rotate-keys`, then drop the old one |
| Liveness / readiness | `/healthz`, `/readyz` (no login; 503 when the database is unreachable) |
| Metrics | set `QUANTA_METRICS_TOKEN`; scrape `/metrics` with `Authorization: Bearer <token>` |
| Logs | JSON, one object per line, with an `X-Request-ID` that also appears in the response header |

Back up on a schedule (a nightly cron calling `backup`) and test a restore before you need one.

## Production behaviour (`QUANTA_PRODUCTION=true`)

* The app refuses to start without a stable `QUANTA_SESSION_SECRET`, or while a seeded demo
  account still has its published password.
* Every API route requires a signed-in session (set `QUANTA_ALLOW_PUBLIC_READS=true` only if you
  truly want anonymous reads).
* Plain HTTP is served only to the proxy; terminate TLS in front (the compose file does).

## Hardening checklist

- [ ] TLS in front, HSTS on (Caddyfile does both)
- [ ] `check` reports no failures
- [ ] Single sign-on configured (`OIDC_*` variables) and local passwords reserved for break-glass
- [ ] Outbound firewall allows only your scanners, the CISA/FIRST feeds, your SMTP relay and your model endpoint
- [ ] Database not reachable from outside the host or private network
- [ ] Backups scheduled, restore tested, encryption key stored separately
- [ ] An independent penetration test before exposing it beyond a trusted network

## Known limits (honest list)

* Several replicas are supported on Kubernetes (`docs/KUBERNETES.md`): PostgreSQL, a ReadWriteMany volume
  for the findings and policy files, database-lease locks, a leader-elected scheduler and a job queue
  with workers. On a single host, `docker compose` still runs one instance, which is the simplest option
  for a small deployment. Secrets can be supplied as files (`QUANTA_SESSION_SECRET_FILE` and friends) so a
  key vault can mount them.
* Connectors are built to each vendor's public API and tested against simulated responses. Your
  first sync of each source is the live validation; report what differs.
* OpenVAS/GVM keeps its own start/status/import page rather than a scheduled sync.
* SLA clocks use calendar time, not business hours.
