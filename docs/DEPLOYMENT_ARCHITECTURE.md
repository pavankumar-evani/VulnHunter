# Quanta — Deployment Architecture & Infrastructure Requirements

How to run Quanta inside your own environment, what it needs, how to size it, and — stated
plainly — which parts exist today and which are target design. Quanta is built to be
deployed and operated by the customer in their own tenant, so that data residency, identity
and audit stay inside their boundary.

## 1. Deployment principles

- **Customer-owned, isolated tenant.** A dedicated cloud account/subscription or on-prem
  segment for Quanta, separate from general-purpose workloads, with the customer's own
  guardrails applied. Nothing is shared with other customers.
- **Allowlisted egress only.** The application needs outbound access to a short, named list:
  the scanners and asset sources you connect, the public threat-intel feeds (CISA KEV,
  FIRST.org EPSS, NVD), the ITSM/SIEM you push to, and — if enabled — your model endpoint.
  Everything else is denied.
- **Controlled integration bus.** Integrations enter through an API gateway or approved
  data feeds, not open network paths into production systems. Quanta never needs inbound
  access to the systems it reports on: it pulls exports/APIs and generates artifacts.
- **Identity and audit stay inside.** SSO (OIDC) and RBAC from your IdP; every state change
  is in the activity log; logs export to your SIEM through the approved egress path.
- **Execution boundary unchanged.** Deployment topology does not change the core safety
  model: no component here executes a fix against real infrastructure.

## 2. Reference architecture (layers)

| Layer | Contents | Notes |
|---|---|---|
| 1 · Edge | Reverse proxy / ingress with TLS (cert-manager or managed certs), WAF optional | Users reach the app over corporate VPN or VDI |
| 2 · Application (containers) | Quanta dashboard/API (`Dockerfile`), the Claude Code subagent runner, background scheduler | Stateless except for the shared stores below; non-root, health-checked on `/api/status` |
| 3 · Data | PostgreSQL (primary + standby) for record stores; object storage for generated artifacts, audit exports and backups | `QUANTA_DATABASE_URL` selects PostgreSQL; SQLite remains the single-host default |
| 4 · Platform services | Secrets manager / KMS (credentials, signing keys), certificate manager, observability stack | Connector credentials are entered per request and never stored; the session secret and DB password live here |
| 5 · AI services (optional) | Model endpoint via an internal gateway with spend caps; vector store only if retrieval is added | Customer-hosted or approved managed models; per-call and per-day budget caps already enforced |

## 3. What exists today vs. target

| Capability | Today | Target |
|---|---|---|
| Container image + compose | `Dockerfile`, `docker-compose.yml` (app + PostgreSQL), non-root, healthcheck | Helm chart / Kubernetes manifests |
| PostgreSQL | Supported through `QUANTA_DATABASE_URL`; schema created on first run | Managed HA PostgreSQL with automated failover |
| Multi-replica app | **Not yet.** The advisory file lock serialises writers on one host | Row-level locking / job queue so replicas can share one database |
| Background work | In-process scheduler, one node | Queue + worker pool (a message broker) for scans, exports and long pipeline runs |
| Object storage | Local volumes (`remediation/output`, `live-data`) | S3-compatible bucket (S3, GCS, Azure Blob, MinIO) with versioning and retention |
| Secrets / KMS | Environment variables | Secrets manager injection + KMS-encrypted volumes |
| Encryption in transit | Local HTTPS built in; proxy TLS recommended | TLS 1.3 at ingress, mTLS to the database |
| Observability | `/api/status`, activity log | Metrics, structured logs and alerts exported to the customer's stack |

## 4. Sizing guide

Indicative starting points for the application tier, to be validated in a proof of concept.
"Users" means concurrently active people, not licences (Quanta licences are unlimited-user).

| | Small | Medium | Large |
|---|---|---|---|
| Active users | 1–50 | 50–200 | 200–1,000 |
| Tracked assets (guide) | up to ~1,500 | up to ~7,500 | 25,000+ |
| App nodes | 2 × 2 vCPU / 8 GB | 2–3 × 4 vCPU / 16 GB | 3–6 × 4–8 vCPU / 16–32 GB, autoscaled |
| PostgreSQL | 2 vCPU / 4 GB, 20 GB SSD (+ standby) | 2–4 vCPU / 8 GB, 50–100 GB | 4+ vCPU / 16 GB, 200 GB+ (+ standby) |
| Cache / queue | none required today | optional | recommended once a worker pool exists |
| Object storage | 20 GB | 100 GB | 500 GB+ |

The ~9,400-finding demo dataset runs comfortably on the Small profile. The dominant costs
are scanner exports and report generation, not interactive use.

## 5. Platform requirements

- **Runtime:** Python 3.11+ (the container image uses 3.12), or any OCI-compatible runtime.
  Kubernetes 1.28+ when orchestrated.
- **Database:** PostgreSQL 16+ (or SQLite for a single host). Tables are created
  automatically; there is no separate migration step today.
- **Network:** TLS-terminating proxy; egress allowlist (section 1); DNS; NTP.
- **Identity:** an OIDC provider for SSO; optionally read-only LDAP for approver
  group validation.
- **Bastion / deploy host** for applying manifests or compose files, with access to the
  image registry.

## 6. Operating it

- **Required settings for any real deployment:** `QUANTA_SESSION_SECRET` (stable),
  `QUANTA_PRODUCTION=true`, `QUANTA_REQUIRE_LOGIN_FOR_READS=true`. See `.env.example`.
- **Backups:** the database and the output/live-data volumes. Test restores; an untested
  backup is not a backup.
- **Upgrades:** build a new image, run the test suite in CI, roll one instance at a time.
  Single-replica today, so plan a short maintenance window.
- **Monitoring:** alert on `/api/status` going `degraded`, scheduler not alive, and a
  threat-intel feed older than your policy allows.
- **Support:** tickets are in-app and stay in your database; optional email escalation to
  the vendor via `QUANTA_SUPPORT_EMAIL`.

## 7. Honest limits

Single-node writers, in-process scheduling, and environment-variable secrets are the three
gaps between this and a fully highly-available deployment. Each is listed above with its
target. Nothing in this document is a certification or a guarantee of regulatory
compliance; deploying into an environment that is already certified inherits that
environment's controls, it does not confer them.
