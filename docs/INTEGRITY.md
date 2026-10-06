# Integrity and self-heal

`remediation/integrity/` answers three questions: is the code running the code that was released, are the stores consistent, and what can be repaired
safely without a person deciding. It reports first and repairs only a short, fixed list of things.

## Code baseline (`manifest.py`)

`python cli/quanta_admin.py integrity-manifest` writes `remediation/integrity/manifest.json` (override with `QUANTA_INTEGRITY_MANIFEST`): a SHA-256 for
every Python file, static JS/CSS/HTML, `.claude/agents` and `.claude/commands` prompt, deploy file, root `Dockerfile`/compose/`VERSION` and
non-config YAML under `dashboard/`, `remediation/`, `cli/`, `scripts/` and `deploy/`. The Dockerfile runs it after `COPY . .`, so an image carries its own baseline.

| Kind | Files | A difference means |
|---|---|---|
| code | everything above except `remediation/config/*.yaml` | must not change: modified, missing or unexpected files are reported as `code-modified` |
| policy | `remediation/config/*.yaml` | expected: reported as `policy-changed`, never as tampering; the newest activity-log entry that names the file shows who, where the log has one |

Never tracked: runtime data (`normalized-findings.json`, `users.json`, databases, locks, `.bak`), `tests/`, `docs/`, `remediation/output/`, demo apps.
With no manifest the state is `no-baseline`, never `ok`.

## Checks (`checks.py`)

Read-only. Each returns `ok`, `info`, `warn` or `fail`; "could not check" is `info`/`warn`, never `ok`.

| Check | Looks at | Repair |
|---|---|---|
| Database integrity | SQLite `PRAGMA integrity_check`; PostgreSQL answers a probe (reachability only) | manual: restore a backup |
| Tables present, schema version | tables in `db.metadata` vs the database; `schema_migrations` vs `MIGRATIONS` (pending, or written by a newer release) | `recreate_missing_tables`; `migrate` |
| Findings file | valid JSON list, `.bak` present | `restore_findings_from_bak` |
| Orphans | assignments for findings no longer in the file; approved/triggered approvals with no artifact in `remediation/output/` | manual: review (never auto-deleted) |
| Lock files | owner pid dead on this host (the `FileLock` rule); ownerless and old | `remove_stale_locks` |
| File snapshots | with `QUANTA_FILES_BACKEND=db`, local files vs `file_snapshots` | `rebuild_file_snapshots` |
| Disk space | volume holding the database (warn below 1 GiB or 5%, fail below 100 MiB) | manual |
| Clock | PostgreSQL `now()` vs this host (warn above 5 s, fail above 60 s); on SQLite, future-dated activity entries | manual: NTP |
| API keys, licence | keys expired and not revoked, or expiring within 14 days; licence state | manual |

## Repairs (`heal.py`)

Four named actions. `heal.run` previews unless `confirm=True`; each executed action is written to the activity log as `integrity.heal.<name>` (also on failure).

- `remove_stale_locks`: deletes `.lock` files whose owner is gone. A lock held by a live process is left alone and re-checked at the moment of deletion.
- `restore_findings_from_bak`: only when the primary is invalid JSON and the `.bak` is a valid list. The bad file is kept as `normalized-findings.json.corrupt-<time>`.
- `recreate_missing_tables`: creates absent tables via `ensure_schema`; existing tables and rows are untouched.
- `rebuild_file_snapshots`: seeds snapshots for local files that have none; a local file that differs from the database copy is copied aside (`.local-<time>`) before the normal sync lets the database win. It does not pull or overwrite anything itself.

Everything else (corrupt database, orphaned rows, modified code, low disk, clock skew, expiring keys) is reported with the manual step. Nothing deletes customer data.

## Using it

```bash
python cli/quanta_admin.py integrity-manifest                 # at build time
python cli/quanta_admin.py check-integrity                    # report; exit 1 on a failure or modified code
python cli/quanta_admin.py check-integrity --heal             # preview repairs
python cli/quanta_admin.py check-integrity --heal --confirm   # apply them
```

- `GET /api/integrity` (admin): the report plus the available repairs. `POST /api/integrity/heal` (admin) with `{"actions": [...], "confirm": false}`; preview unless `confirm` is true.
- `/readyz` includes an `integrity` line from the newest summary (`not checked yet` until something has run). It never makes readiness fail: restarting a pod does not remove a stale lock file.
- An hourly leader tick runs the checks and writes `integrity.alert` to the activity log (and mails `QUANTA_ALERT_EMAIL` when SMTP is configured) once per distinct set of problems, then `integrity.recovered`. It never repairs. Off with `QUANTA_INTEGRITY_CHECKS=false`.
- Administration > Activity Log > Integrity tab shows the same report with Preview and Apply buttons.

## Honest limits

- The manifest is a tripwire for drift and casual tampering. Someone who can change the code can also rewrite `manifest.json`; sign or copy it off the host in your release pipeline if that matters.
- Policy changes are attributed only where the activity log names the file; many policy saves are not logged, and then nobody is named.
- The PostgreSQL probe is reachability, not a consistency check, and clock skew can only be measured against PostgreSQL.
- Stale-lock detection judges a lock held on another host only by age.
- The orphan checks compare against the findings file as it is now; they are skipped when it is missing, unreadable or empty.
- Not run against a live multi-replica or PostgreSQL deployment; tested with temporary SQLite databases and directories.
