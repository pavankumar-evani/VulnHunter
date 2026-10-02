# Running Quanta on Kubernetes

The Helm chart is in `deploy/helm/quanta/`. It runs Quanta as several copies behind one address:
a **web** tier, a pool of **queue workers**, and a **scheduler** that only one copy runs at a time,
with every secret read from a key vault.

```
                       ┌────────────── key vault (Azure Key Vault / AWS Secrets Manager / GCP / HashiCorp Vault)
                       │  (read with the cluster's cloud identity; nothing secret is in the chart)
 ingress ─▶ web × N ───┤
                       ├──▶ PostgreSQL  ◀── worker × M      database holds records, leases and the job queue
                       └──▶ shared volume (ReadWriteMany)    findings file + policy YAML
```

## Install

```bash
helm install quanta deploy/helm/quanta -n quanta --create-namespace -f my-values.yaml
```

Start from one of the files in `deploy/helm/quanta/ci/` (they are also what CI renders):
`externalsecrets-values.yaml` (Azure Key Vault through External Secrets), `csi-azure-values.yaml`,
`csi-aws-values.yaml`, `existing-secret-values.yaml`.

Before installing you need: a container image built from the repo's `Dockerfile` in your registry; a
PostgreSQL database (managed is best); a ReadWriteMany storage class; and your key vault set up as below.

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

**Rotation.** Quanta reads secrets once at startup, so after a vault value changes, restart the pods:
`kubectl rollout restart deploy/quanta-web deploy/quanta-worker`. To rotate the encryption key without
downtime, put the new key first and the old one second (`new,old`), restart, run
`python cli/quanta_admin.py rotate-keys`, then remove the old key.

## How several copies stay correct

| Concern | How it is handled |
|---|---|
| First start (schema, sample-data clean-up, first admin) | An init container on every pod runs `quanta-admin prepare` under a database lease, so it happens once and the other pods wait. PostgreSQL schema creation and migrations also take an advisory lock. |
| Locks around read-modify-write | `QUANTA_LOCK_BACKEND=db`: the same `FileLock` calls now take a lease row in the database (name, owner, expiry). It works across nodes, which a lock file on a network volume does not guarantee. A holder that crashes just stops renewing and the lease expires. |
| Scheduled work | Every web pod runs the schedulers but only the holder of the `scheduler` lease acts. If it dies, another pod takes over after `config.leaderTtlSeconds` (60 by default). |
| Connection syncs and ticket pushes | The leader (or a person pressing **Sync now**) puts a job in a database queue. Workers claim jobs with `SELECT … FOR UPDATE SKIP LOCKED` on PostgreSQL, so no two take the same one. A worker heartbeats while it works; if it dies the job returns to the queue after the visibility timeout, and after 3 failed attempts it is kept as `dead` for inspection. A connection already queued or running is not queued again. |
| Rolling updates | Workers finish the job they are running on SIGTERM (`worker.terminationGracePeriodSeconds`). Web pods use `maxUnavailable: 0`. |

Inspect the queue with `kubectl exec deploy/quanta-worker -- python cli/quanta_admin.py jobs`, the
`/api/admin/jobs` endpoint, or the `quanta_jobs_queued` and `quanta_jobs_dead` metrics.

## What the shared volume is for, and what it is not

Two things are still plain files that every copy must see: the **findings system of record**
(`remediation/output/normalized-findings.json`, with generated playbooks) and the **policy YAML**
(`remediation/config/`). The chart mounts one ReadWriteMany volume for them (`persistence`), seeds the
policy files from the image once, and refuses to render more than one replica without it. Locks and the
queue do **not** depend on the volume, only on the database.

Be aware of the trade-off: the findings file is read and rewritten whole under a lease, and the dashboard
caches it by modification time. That is comfortable up to tens of thousands of findings and a handful of
replicas; it is not a substitute for moving the findings into the database, which is the next step for a very
large estate. Use a storage class with proper atomic rename and mtime semantics (Azure Files premium, EFS,
Filestore, CephFS); avoid a plain NFS export with aggressive client caching.

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
* The queue gives at-least-once delivery, so a job handler must tolerate running twice. Connection syncs do:
  each run is claimed atomically and merging is idempotent.
* Leader election is as strict as the lease ttl allows. For a few seconds around a leader failure two pods may
  both believe they lead; scheduled work is idempotent for that reason.
* The chart does not install a database, the External Secrets Operator or the CSI driver; it expects them.
