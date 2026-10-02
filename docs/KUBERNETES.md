# Running Quanta on Kubernetes

The Helm chart is in `deploy/helm/quanta/`. It runs Quanta as several copies behind one address:
a **web** tier, a pool of **queue workers**, and a **scheduler** that only one copy runs at a time,
with every secret read from a key vault.

```
                       ┌────────────── key vault (Azure Key Vault / AWS Secrets Manager / GCP / HashiCorp Vault)
                       │  (read with the cluster's cloud identity; nothing secret is in the chart)
 ingress ─▶ web × N ───┤
                       ├──▶ PostgreSQL  ◀── worker × M      database holds records, leases and the job queue
                            each pod keeps a local copy of the findings and policy files,
                            reconciled with the database (no shared volume needed)
```

## Install

```bash
helm install quanta deploy/helm/quanta -n quanta --create-namespace -f my-values.yaml
```

Start from one of the files in `deploy/helm/quanta/ci/` (they are also what CI renders):
`externalsecrets-values.yaml` (Azure Key Vault through External Secrets), `csi-azure-values.yaml`,
`csi-aws-values.yaml`, `existing-secret-values.yaml`.

Before installing you need: a container image built from the repo's `Dockerfile` in your registry; a
PostgreSQL database (managed is best); and your key vault set up as below.

## Secrets: kept in a key vault, never in the chart

Three values are required and the rest are optional. Create them in your vault:

| Setting | What it is | Vault entry (default name) |
|---|---|---|
| `QUANTA_SESSION_SECRET` | signs login sessions; `python cli/quanta_admin.py gen-secret` | `quanta-session-secret` |
| `QUANTA_ENCRYPTION_KEY` | encrypts stored connector credentials; `gen-key`; comma-separate several to rotate | `quanta-encryption-key` |
| `QUANTA_DATABASE_URL` | `postgresql+psycopg2://quanta:<password>@host:5432/quanta?sslmode=require` | `quanta-database-url` |
| optional: `QUANTA_ADMIN_PASSWORD`, `QUANTA_METRICS_TOKEN`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `OIDC_CLIENT_SECRET` | | `quanta-admin-password`, … |

Names are mapped in `secrets.keyMap` (Azure Key Vault does not allow underscores, hence the hyphens).
Add an optional one to `secrets.optionalKeys`; it must then exist in the vault.

The pods never see these as environment variables. Each secret is mounted as a read-only file under
`/var/run/secrets/quanta/` and the app is told where with `NAME_FILE` (for example
`QUANTA_SESSION_SECRET_FILE`); an explicit `NAME` still wins. A `_FILE` that points at a missing or empty
file stops the pod, instead of starting with a random session secret.

Pick one mode with `secrets.mode`:

* **`externalSecrets`** (recommended). The [External Secrets Operator](https://external-secrets.io)
  reads the vault using a `(Cluster)SecretStore` you create once, and the chart declares an `ExternalSecret`
  that syncs it into a Secret mounted as files. Change a value in the vault and it reaches the pods
  within `refreshInterval`.
* **`csi`**. The [Secrets Store CSI driver](https://secrets-store.csi.k8s.io) mounts the vault objects
  directly into the pod as files. The value is never a Kubernetes Secret at all. The chart generates the
  `SecretProviderClass` for `azure`, `aws` and `gcp`; for HashiCorp Vault pass the provider's parameters
  through `secrets.csi.parameters`.
* **`existingSecret`**. A Secret you manage (sealed-secrets, SOPS, a platform controller), with one key per
  setting.
* **`inline`**. Development only. The chart refuses it unless you set `secrets.allowInline=true`, because
  the values would pass through your values file and Helm's release history.

Give the vault access to the **service account**, not to a stored credential: Microsoft Entra Workload ID
(`azure.workload.identity/client-id` annotation and `azure.workload.identity/use: "true"` pod label),
EKS IRSA (`eks.amazonaws.com/role-arn`), or GKE Workload Identity (`iam.gke.io/gcp-service-account`).
Those go in `serviceAccount.annotations` and `serviceAccount.podLabels`. The identity needs read access to
only these entries.

**Rotation.** Quanta re-reads a changed secret file every 15 seconds (web pods) or each poll (workers), so a
rotated vault value reaches the running app without a restart for `QUANTA_ENCRYPTION_KEY`,
`QUANTA_METRICS_TOKEN`, `SMTP_USERNAME`, `SMTP_PASSWORD` and `QUANTA_ADMIN_PASSWORD`. How fast the file
itself changes depends on the mode: External Secrets updates the Secret every `refreshInterval` and the
kubelet re-projects it within about a minute; the CSI driver only rotates if its secret-rotation reconciler
is enabled. An unreadable or empty file keeps the old value. Two settings are read once at startup and need a
rolling restart (`kubectl rollout restart deploy/quanta-web deploy/quanta-worker`): `QUANTA_SESSION_SECRET`
(and rotating it signs everyone out) and `QUANTA_DATABASE_URL`. To rotate the encryption key, put the new
key first and the old one second (`new,old`), wait for it to be picked up, run
`python cli/quanta_admin.py rotate-keys`, then remove the old key.

## How several copies stay correct

| Concern | How it is handled |
|---|---|
| First start (schema, sample-data clean-up, first admin) | An init container on every pod runs `quanta-admin prepare` under a database lease, so it happens once and the other pods wait. PostgreSQL schema creation and migrations also take an advisory lock. |
| Locks around read-modify-write | `QUANTA_LOCK_BACKEND=db`: the same `FileLock` calls now take a lease row in the database (name, owner, expiry). It works across nodes, which a lock file on a network volume does not guarantee. A holder that crashes just stops renewing and the lease expires. |
| Scheduled work | Every web pod runs the schedulers but only the holder of the `scheduler` lease acts. If it dies, another pod takes over after `config.leaderTtlSeconds` (60 by default). |
| Connection syncs and ticket pushes | The leader (or a person pressing **Sync now**) puts a job in a database queue. Workers claim jobs with `SELECT … FOR UPDATE SKIP LOCKED` on PostgreSQL, so no two take the same one. A worker heartbeats while it works; if it dies the job returns to the queue after the visibility timeout, and after 3 failed attempts it is kept as `dead` for inspection. A connection already queued or running is not queued again. |
| Findings and policy files | `QUANTA_FILES_BACKEND=db` (the chart's default): the database is the source of truth and each pod reconciles its local copy with it (see below). |
| Rolling updates | Workers finish the job they are running on SIGTERM (`worker.terminationGracePeriodSeconds`). Web pods use `maxUnavailable: 0`. |

Inspect the queue with `kubectl exec deploy/quanta-worker -- python cli/quanta_admin.py jobs`, the
`/api/admin/jobs` endpoint, or the `quanta_jobs_queued` and `quanta_jobs_dead` metrics.

## Findings and policy files: in the database, not on a shared volume

The findings system of record (`remediation/output/normalized-findings.json`), generated playbooks,
`REMEDIATION_PLAN.md` and the admin-edited policy (`remediation/config/*.yaml`) are files that dozens of
modules read directly. With `files.backend: db` (the default) each pod keeps a local copy and
`remediation/utils/file_sync.py` reconciles it with a `file_snapshots` table:

* a change made only in the database is pulled; a change made only locally is pushed; if both changed, the
  database copy wins and the conflict is logged and counted;
* the first replica to start seeds the database with the defaults in the image (including the policy YAML);
  a replica that starts later takes the cluster's state, and a sample file the cluster has since removed is
  not resurrected from its image;
* a pass is one query plus a stat of the tracked files, throttled to every 3 seconds
  (`files.syncSeconds`); the findings merge runs it under its lease before and after writing, so two replicas
  merging in turn never lose data or reuse an id;
* a deletion is propagated as a tombstone.

No shared volume is needed, so any storage class works and pods reschedule freely. The trade-offs, plainly:
a file is stored whole, so two admins saving the same policy file at the same moment resolve to whichever the
database saw first; the findings file is one row, which suits tens of thousands of findings, not millions; and
`remediation/live-data/` (raw scanner exports) is not synced because it is transient.

Prefer a shared volume anyway (for example so the files are visible on a share)? Set
`files.backend: volume` and `persistence.enabled: true` with a ReadWriteMany class; the chart then seeds the
policy files once and refuses more than one replica without it.

## Network and hardening

* Pods run as a non-root user (10001) with all capabilities dropped, no privilege escalation, a
  `RuntimeDefault` seccomp profile, and no Kubernetes API token mounted.
* `networkPolicy.enabled` lets only your ingress controller reach the web pods; workers accept no inbound
  traffic, and outbound is limited to DNS, HTTPS, PostgreSQL and SMTP. Tighten with CIDR blocks.
* Turn on `web.trustForwardedHeaders` only together with the network policy, so a client cannot forge
  `X-Forwarded-For` and bypass per-IP rate limits.
* TLS ends at the ingress (`ingress.tls`, typically cert-manager). The app serves plain HTTP inside the cluster.
* Scrape `/metrics` with a `ServiceMonitor` (`serviceMonitor.enabled`); the endpoint needs
  `QUANTA_METRICS_TOKEN` in `optionalKeys`.

## Honest limits

* The chart is verified in CI by `helm lint`, `helm template` and `kubeconform` against each scenario in
  `deploy/helm/quanta/ci/` (`.github/workflows/helm.yml`), and the coordination logic (leases, leader
  election, queue, workers, secret files) is unit-tested. It has **not** yet been installed on a live cluster
  against a real vault; treat the first install as the validation and report what differs.
* The database file backend resolves simultaneous edits of the same file by "database wins"; it is not a
  collaborative editor.
* The queue gives at-least-once delivery, so a job handler must tolerate running twice. Connection syncs do:
  each run is claimed atomically and merging is idempotent.
* Leader election is as strict as the lease ttl allows. For a few seconds around a leader failure two pods may
  both believe they lead; scheduled work is idempotent for that reason.
* The chart does not install a database, the External Secrets Operator or the CSI driver; it expects them.
