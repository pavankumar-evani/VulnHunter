# Release process

## Principles

1. **One immutable build, promoted unchanged.** A release tag produces one container image (`ghcr.io/<owner>/quanta`, tagged with the SemVer and the git SHA, with an SBOM and provenance attestation). Dev, Test and Prod all run that image; only configuration (`values-<env>.yaml`, secrets from each environment's vault) changes.
2. **Prod is gated.** The `prod` GitHub Environment has required reviewers; nothing reaches Prod without a person approving it after Test has passed.
3. **Every deploy is atomic and reversible.** `helm upgrade --install --atomic --wait` rolls itself back if the new pods do not become ready; Helm keeps the release history, and the pipeline saves `helm get values` and `helm history` as artifacts before each deploy.
4. **The database is always backward compatible** (expand / backfill / contract, below), so an application rollback leaves the database valid.
5. **Demo and simulated data stay out of Prod** (see `docs/ENVIRONMENTS.md`).

## Branching and versions

- Trunk-based: `master` is always releasable. Work happens on short-lived branches and reaches `master` only through a pull request with green CI. **No direct pushes to master.**
- SemVer in the `VERSION` file: MAJOR for a breaking change (an API, a config key, a contract migration), MINOR for a feature, PATCH for a fix. `Chart.yaml` `appVersion`, the Dockerfile `ARG VERSION` default and any compose image reference must equal `VERSION`; `quanta_release.py check` fails on drift.
- CHANGELOG discipline: every change adds a line under `## [Unreleased]`. On release, that section is renamed `## [X.Y.Z] - date` and a fresh `[Unreleased]` is opened. The release check needs either a heading for the version or entries under Unreleased.
- Features that are not ready ship behind a flag in `[dev]` (`remediation/config/features.yaml`).

## Promotion

1. Merge the PR(s). Bump `VERSION`, `Chart.yaml` `appVersion`, `ARG VERSION` in the `Dockerfile`; finalise the CHANGELOG heading.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`. The **Release** workflow runs:
   - `verify`: tag equals `VERSION`, CHANGELOG entry, the full unit-test suite exactly as CI runs it, `quanta_release.py check --target dev`.
   - `build`: builds and pushes the image once, with `VERSION`, `BUILD_SHA`, `BUILD_TIME` build args, SBOM and provenance.
   - `deploy-dev` (environment `dev`): Helm upgrade with `values-dev.yaml`.
   - `deploy-test` (environment `test`, needs dev): Helm upgrade with `values-test.yaml`, then a smoke test: `/healthz`, `/readyz`, and `GET /api/status` must report the released version and `environment: test`.
   - `deploy-prod` (environment `prod`, needs test): waits for the required reviewers, then Helm upgrade with `values-prod.yaml` and a readiness check.
3. Before approving Prod: run `python cli/quanta_release.py check --target prod --env-file <prod settings> --backup-dir <dir>` and take a backup (`python cli/quanta_release.py backup`). The check fails when the backup is older than 24 hours, the session secret is under 32 characters, the encryption key is missing, TLS is disabled outside an ingress, demo accounts or bundled sample data exist, the licence mode is unset, or replicas > 1 are configured against SQLite.
4. Set up once (a workflow file cannot create these): GitHub Environments `dev`, `test`, `prod`, each with its own `KUBE_CONFIG` secret (a base64 kubeconfig) and a `QUANTA_URL` variable; **`prod` with required reviewers** (and optionally a wait timer and a deployment-branch rule limiting it to tags); the repository variable `DEPLOY_ENABLED=true` to switch the deploy jobs on. Until then the workflow runs verify and build and the deploy jobs are skipped, so it stays green without a cluster.

## Hotfix

Branch from the released tag's commit (or master if master is unchanged since), fix with a test, bump PATCH, PR with green CI, tag. The same pipeline and the same gates apply; Dev and Test run first, and may be quick because the change is small. A hotfix never skips Test. If Prod is down and the previous version is good, **roll back first** (below), then fix forward.

## Database changes: expand, backfill, contract

`remediation/utils/migrations.py` runs at startup. `tests/test_migration_policy.py` enforces that every migration is **expand-only**: no `DROP`, `RENAME`, `TRUNCATE`, or `DELETE` without a `WHERE`, numbered consecutively, safe to run twice.

- **Expand** (release N): add the new table or nullable column. The old application version still works on the new schema.
- **Backfill** (release N or N+1): fill the new column from the old data, idempotently.
- **Contract** (a later release, after the release that stopped using the old shape is one you would no longer roll back to): drop or rename the old column. This is the only kind of migration that needs a database restore to undo, so it is a MAJOR or clearly flagged release, ships alone, and has a fresh backup first. No contract migration exists today; add one only with a documented release gap and an entry in `CONTRACT_ALLOWED` in the policy test.

## Rollback runbook

`python cli/quanta_release.py rollback-plan --environment prod --from X.Y.Z --to A.B.C --revision N` prints these steps for your release. It runs nothing.

1. **Application.** `helm history quanta -n quanta-prod` to find the last good revision, then `helm rollback quanta <revision> -n quanta-prod --wait` (or run the **Rollback** workflow, which is protected by the same environment gate). Helm restores the previous image and chart.
2. **Configuration.** `helm get values quanta -n quanta-prod --revision <revision>` shows what that revision ran with; the pipeline's saved `values-before.yaml` artifact is the copy to re-apply if values were changed outside Helm.
3. **Database.** Because migrations are expand-only, the previous version works on the migrated schema: **no restore is needed** for an expand-only release. Restore the pre-upgrade backup (stop the app, `quanta_admin restore --yes <backup.zip>` for SQLite, or your platform's restore for PostgreSQL, then start the previous version) only for a contract release or damaged data. A restore loses everything written since the backup, so take a backup of the failed state first.
4. **Verify.** `/readyz` returns 200; `/api/status` shows the rolled-back version and `environment: prod`; sign in; open Connections and run one sync; check the finding count matches expectations; confirm no alert storm.
5. **Record and fix forward.** Open an issue for the defect and keep the rollback in the change record.

## Change record (keep one per release)

Version and git SHA; the CHANGELOG section; the image digest; who approved Prod and when; the backup file name; the Helm revision before and after; the saved `helm get values` / `helm history` artifacts; the smoke-test and post-deploy verification results; any rollback, with the reason.

## Honest limits

The release and rollback workflows, the Helm overlays and the compose overrides are **checked statically** (YAML parsing and rule tests in `tests/test_environments_deploy.py`; `helm` and `docker` are not available in the test environment). They have **not been run against a live cluster or registry**, and `quanta_release.py` has been exercised against temporary directories and patched environments, not a real production. Expect to adjust namespaces, the ingress class, secret-store names and the `KUBE_CONFIG` handling on the first real run. The pipeline guarantees the gates and the recorded history; it cannot make an unsafe change safe, and it does not replace a person reading the CHANGELOG before approving Prod.
