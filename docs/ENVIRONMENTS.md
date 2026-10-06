# Environments: Dev, Test and Prod

Quanta runs in three environments. They run **the same build**; only configuration differs. The environment is set by `QUANTA_ENV` (`dev`, `test` or `prod`). When it is unset, the older `QUANTA_PRODUCTION=true` flag means `prod` and anything else means `dev`. An unrecognised value stops the application from starting (a typo must not silently mean "not production"). Definition: `remediation/utils/environment.py`.

| | Dev | Test | Prod |
|---|---|---|---|
| Purpose | Build and try new features, modify workflows | Verify the exact build that will ship | Real data, real users |
| Who deploys | Pipeline, automatically on a release tag | Pipeline, after Dev succeeds | Pipeline, after Test succeeds **and a required reviewer approves** |
| `QUANTA_ENV` | `dev` | `test` | `prod` |
| `QUANTA_PRODUCTION` (hard rules: session secret, no demo passwords, closed anonymous reads) | off | on | on |
| Simulated connectors | allowed | allowed | **off**, unless `QUANTA_ALLOW_SIMULATION=true` is set on purpose (a hosted demonstration site, which then shows a "SIMULATED DATA ENABLED" strip) |
| Bundled sample data | allowed | allowed | **must be absent** (`clear-sample-data`; the release check fails otherwise) |
| Demo accounts | allowed | no | **must be absent** |
| Feature flags (`remediation/config/features.yaml`) | features in `[dev]`, `[dev,test]`, `[dev,test,prod]` | `[dev,test]`, `[dev,test,prod]` | only `[dev,test,prod]` |
| Banner | coloured DEV strip with version | coloured TEST strip with version | none (version in the footer) |
| Replicas | 1 | 2 | 3 web, 2 workers, PodDisruptionBudget 2 |
| NetworkPolicy | off | on | on |
| Database | its own, may be SQLite on one host | its own PostgreSQL | its own PostgreSQL, backed up before every release |
| Secrets | own vault, never prod values | own vault | own vault, read-only files in the pods |
| Helm overlay | `deploy/helm/quanta/values-dev.yaml` | `values-test.yaml` | `values-prod.yaml` |
| Compose (single host) | `docker-compose.dev.yml`, `.env.dev.example` | `docker-compose.test.yml`, `.env.test.example` | `docker-compose.yml`, `.env.production.example` |

## What differs, and what must not

**May differ (configuration):** `QUANTA_ENV`, replica counts and resources, host names and TLS secrets, secrets and database URL, the vault, feature flags, whether simulation is allowed, log verbosity.

**Must not differ:** the image. One image is built per release tag, tagged with the SemVer and the git SHA, and promoted unchanged. Nothing environment-specific is baked into it (`Dockerfile` takes only `VERSION`, `BUILD_SHA`, `BUILD_TIME`, shown by `GET /api/status` and `quanta_release.py info`). If a bug appears only in Prod, the answer is never "rebuild for Prod".

## Data policy

- **Prod never contains simulated data or the bundled sample data.** The container entrypoint sets the sample findings aside when `QUANTA_PRODUCTION=true`; `python cli/quanta_release.py check --target prod` fails if they are present, if a demo account has its published password, or if simulation is allowed without a visible decision (it warns, and the app banner says so).
- **Simulated connectors** replay recorded vendor responses through the real connector code. They exist so Dev and Test can exercise workflows without a vendor account. They are covered by the `simulation-connectors` flag (`[dev,test]`).
- **Dev and Test never hold a copy of production data.** Use synthetic or anonymised data.
- **Each environment has its own database, its own vault and its own encryption key.** A backup from one environment is never restored into another.

## Feature flags

A new workflow ships dark and is promoted one step per release: `[dev]` -> `[dev, test]` -> `[dev, test, prod]`. `QUANTA_FEATURES_ON` / `QUANTA_FEATURES_OFF` (comma lists) override the file without a rebuild; OFF wins, so an incident can switch a feature off at once. `GET /api/features` (login required) lists what is on. A menu item with a `feature` key is hidden when its flag is off. Once a flag has been on everywhere for a release or two, delete the flag and the guard.

## Running a single-host Dev or Test

```bash
cp .env.dev.example .env.dev          # fill the placeholders; QUANTA_ENCRYPTION_KEY: python cli/quanta_admin.py gen-key
docker compose -f docker-compose.yml -f docker-compose.dev.yml --env-file .env.dev up --build
# Test, on port 5051 with production rules:
docker compose -f docker-compose.yml -f docker-compose.test.yml --env-file .env.test up --build
```

The override files add `QUANTA_ENV`, ports and the simulation setting; the proxy service is behind the `proxy` profile there. They are checked statically (`tests/test_environments_deploy.py`) and have not been run in this repository's CI.
