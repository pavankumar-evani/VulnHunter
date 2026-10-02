# Scaling limits, what they mean, and how to work past them

Three limits remain in the multi-replica design. None is a defect; each is a deliberate trade made to
ship something correct and simple first. This page says what each one means in practice, how to tell if you
are near it, and the concrete next step.

## 1. "At-least-once" queue delivery

**What it means.** A worker takes a job, does the work, then tells the queue it is done. If the worker dies
*between doing the work and reporting it*, the queue cannot know the work happened, so after the visibility
timeout it hands the job to another worker. The job can therefore run twice, never zero times. The
alternative, "at-most-once", would lose a job when a worker dies mid-way; for syncing and ticketing that is
worse.

**What protects you today.** Every job handler is written to be safe to repeat:

| Job | Why a repeat is harmless |
|---|---|
| Pull sync (Tenable, Qualys, ...) | The connection is claimed atomically (a second run is refused while one is running) and merging is keyed on source + asset + reference + CVE, so the same data updates rather than duplicates. |
| ServiceNow / Jira push | An incident is keyed on `correlation_id` and an issue on the `quanta-<finding id>` label; Quanta looks for an existing one before creating. A repeat finds it. |
| **Splunk push** | **Not protected.** Splunk is an append-only stream, so a crash between sending an event and recording the link can send that finding's event twice. |

**How to work further.**
* For Splunk, send a stable event id (HEC `id` / an indexed field set to the finding id) so duplicates can be
  dropped downstream, or move to HEC acknowledgements and record the link before acknowledging.
* For any new handler, apply the rule: *identify the effect with a key you control and check for it first.*
* Watch `quanta_jobs_dead` and the `jobs` table's `attempts` column; a job with many attempts is one whose
  handler is failing or whose worker keeps dying.

## 2. Leader election is as strict as its lease time allows

**What it means.** Exactly one replica should run the schedulers. The leader holds a lease that it must renew
before it expires (60 seconds by default). If the leader freezes (a long pause, a stalled VM) *without*
crashing, its lease expires and a new leader is elected, but the old one may wake up and finish the tick it
was in the middle of. For that short overlap, two replicas may both believe they lead. This is the standard
caveat of every lease-based election; it is not specific to Quanta.

**What protects you today.** Scheduled work is idempotent for exactly this reason: syncs go through the queue
with a dedupe key and the per-connection claim, and report and alert senders record what they sent.

**How to work further.**
* Add a *fencing token*: add an epoch number to the lease row that increases on every takeover, have the
  leader pass it with each action, and have the database reject an action carrying a stale epoch.
* On PostgreSQL, a session-level advisory lock is released the instant the connection drops, which closes the
  gap for a crashed leader (not a frozen one); fencing is still needed for the frozen case.
* Shorten `config.leaderTtlSeconds` for faster failover, at the cost of more renewals and a higher chance of a
  needless handover during a slow database moment.

## 3. Findings are stored as one whole file

**What it means.** The findings system of record is a single JSON document. Every change (a merge of 50 new
findings, an enrichment) reads the whole document, changes it, and writes the whole thing back, and in
multi-replica mode that whole document is also one row in the database. Cost therefore grows with the *total*
number of findings, not with the size of the change. Measured with `scripts/bench_findings_scale.py` on a
developer machine (indicative, not a guarantee):

| Findings | File size | Read | Merge 50 new | Push to database |
|---:|---:|---:|---:|---:|
| 10,000 | 7 MB | 0.09 s | 0.6 s | 0.3 s |
| 50,000 | 37 MB | 0.6 s | 3.6 s | 1.1 s |
| 200,000 | 148 MB | 4.7 s | 12 s | 2.0 s |

*Comfortable* is up to roughly 50,000 findings: a merge is a few seconds and runs in a background worker.
Beyond about 100,000 you will feel it (memory held per request, multi-second merges, long lock holds, bigger
conflict windows); past a few hundred thousand it is the wrong shape. A typical large enterprise has tens of
thousands of open findings, so most deployments never reach this; a managed-service provider consolidating
many tenants could.

**How to work further.** Replace the file with a table, in stages that each ship on their own:

1. **Measure your own estate.** Run the benchmark with your real count; if the merge time is under a few
   seconds you are fine and can stop here.
2. **A `findings` table behind a repository interface.** Columns for what is filtered and joined on
   (`id`, `source`, `asset_name`, `severity`, `cve`, `status`, `first_seen`, `last_seen`) plus a JSON column for
   the rest. Put every read and write behind one module so callers stop touching the file directly.
3. **Row-level writes.** Merge becomes an SQL upsert of just the changed rows (cost proportional to the change),
   with the reconcile/removal expressed as a delete by source. This also removes the whole-file conflict
   window and the long lock.
4. **Query instead of load-all.** Move the queue, overview and export endpoints to filtered, paginated queries
   so a request no longer parses every finding.
5. **Keep the file as an export.** The remediation subagents read and write files by design (that is the safety
   model), so produce `normalized-findings.json` on demand for them and import their output, instead of making
   the file the system of record.

The database-backed file sync (`QUANTA_FILES_BACKEND=db`) stays as the mechanism for the small policy YAML and
generated playbooks, which are the right size for it.
