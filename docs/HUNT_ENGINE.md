# Proactive hunt engine

`remediation/hunting/engine/` turns data Quanta already holds into **hypotheses to test**, not a list of vulnerabilities. It borrows PEAK (Prepare / Execute / Act: the
scope, data and benign explanations are prepared up front), TaHiTI (hypothesis first, outcome always recorded), the SANS hunting maturity ladder (the four hunt types) and
MITRE ATT&CK (techniques and tactics). Quanta is not a SIEM: it never runs a search on its own. Running a lead stays the existing confirm-gated Splunk search on the hunt record,
or the analyst runs the query in their own tool and records the result.

## Hypothesis

Statement form: *If `<who>` is active in our environment, we would expect to see `<evidence>` on `<where>`.* Each carries `why_now` (records that triggered it; every item names a
record Quanta holds), techniques and tactics, scope with counts, data sources with readiness, queries, expected malicious and likely benign, scoping/time box, effort, expected
value, a scored priority with its working, the next step and a SOAR playbook it could feed.

Id: `hyp-` + hash of generator and subject, so a refresh updates rather than duplicates.

Lifecycle: `suggested -> accepted -> running -> evidence-recorded -> concluded (true-positive | benign | inconclusive-needs-data) -> promoted`, or `dismissed` (with a reason) from
any open state. Accepting creates an ordinary `hunts` record (`source: "hypothesis"`, `source_ref: <id>`) with the SPL leads, so the existing run, verdict and report flow works.
`running` and `evidence-recorded` follow the linked hunt (a hunt that has run, a lead with a recorded result); closing the hunt concludes the suggestion
(confirmed = true-positive, not-found = benign, needs-data = inconclusive). Promotion creates a detection use case (status `proposed`, never counted as coverage) and marks the hunt
`detection_created`.

## Generators

Each is a pure function of a `Context` and returns hypotheses plus plain-sentence **gap notes** when its data is absent (so "nothing suggested" is never mistaken for "nothing to suggest").

| Generator | Type | Reads | Gap note when |
|---|---|---|---|
| `intel-report` | intel-driven | imported reports (techniques, actors, CVEs) and the findings carrying their CVEs | no reports imported; a report names no technique or indicator |
| `threat-actor` | intel-driven | MITRE group catalogue for the configured `industry`, matched to techniques tagged in the estate | no `industry` set |
| `cvd-advisory` | intel-driven | CVD advisories matched to the estate (CVE match is exact, name match is not a version check) | feed empty or unreadable |
| `kev-exposure` | hypothesis-driven | `generate.candidates()` (the existing KEV/EPSS source), reframed as post-exploitation behaviour | none |
| `coverage-gap` | hypothesis-driven | techniques in open findings, alerts and intel that no enabled detection rule claims; includes a draft Sigma rule | no rules recorded (coverage cannot be judged) |
| `low-and-slow`, `alert-burst`, `off-hours-privileged` | baseline-anomaly | stored alerts (counting; thresholds in `hunt_engine.yaml`), Access Governance for privileged accounts | no alerts; no entitlements; always notes that rare parent/child and first-seen admin tools need process telemetry Quanta does not store |
| `exposed-asset` | hypothesis-driven | assets marked `external`, with KEV/Critical findings, recorded controls (absent record = "unknown", not "none") | no asset marked external |
| `identity-misuse` | hypothesis-driven | Access Governance findings IAM001 (leaver), IAM002 (dormant), IAM006 (shared/ownerless) | no entitlements loaded |
| `lessons-learned` | hypothesis-driven | alerts closed true-positive and hunts concluded confirmed: where else the technique appears | nothing confirmed yet |
| `credential-exposure` | intel-driven | dark-web credential-exposure hits (new/reviewing) | no hits |
| `model-assisted` | model-assisted | untagged open alerts the Naive Bayes TTP classifier places confidently on one technique (3 or more) | none |

## Score

`priority.score` (0-100) is the sum of `priority.breakdown`, each row `{factor, points, max, note}`: likelihood (max 30: KEV, ransomware use, EPSS, a prior true positive, intel
relevance, a measured anomaly), impact (max 25: internet-facing, crown jewel/privileged, Critical, blast radius), coverage_gap (max 15; unknown coverage counts a third, never a
pass), freshness (max 10), learned_yield (-15..+10), effort (S 0, M -4, L -9). Weights are in `remediation/config/hunt_engine.yaml`.

## Learning loop

Outcome statistics are computed per `pattern_key` (`<generator>:<technique>`) from concluded hypotheses. With at least `min_samples` conclusions, true positives raise the score and
benign conclusions lower it; `suppress_after_benign` benign and no true positive hides the pattern from the default list (`include_suppressed=true` shows it). `learned.note` reads
"Because of past outcomes: ...". Dismissals are remembered: a dismissed hypothesis returns only when `material_new_refs` new evidence items appear, or any new *strong* item
(KEV finding, true-positive alert, dark-web hit, high-priority report); the `reopened` event keeps the earlier reason.

## Data readiness

Each data source is `connected` only when a connection proves it (a Cortex XSIAM connection for endpoint telemetry, Prisma Cloud for cloud audit), otherwise `cannot-tell`. Quanta
never says "not connected": your logs may live in a system it cannot see. `data_readiness.can_run_in_quanta` is true only with an enabled `splunk-search` connection.

## Refresh and capacity

`POST /api/hunting/suggestions/refresh` (admin) and an automatic leader tick (at most every `refresh_minutes`). Idempotent. Suggestions the generators stop producing are marked not
current (hidden, kept). At most `max_suggestions` (default 25) are listed; `total`, `shown`, `capped` say so.

## API

| Route | Auth | Notes |
|---|---|---|
| `GET /api/hunting/suggestions?type=&tactic=&status=&include_suppressed=&limit=` | login | default lists current `suggested`, ranked; with `status` lists that status |
| `GET /api/hunting/suggestions/{id}` | login | adds `events` (history) and `hunt` (the linked hunt record) |
| `POST /api/hunting/suggestions/refresh` | admin | returns counts and `gaps` |
| `POST /api/hunting/suggestions/{id}/accept` | admin | body `{"owner": "optional"}`; creates the hunt |
| `POST /api/hunting/suggestions/{id}/dismiss` | admin | `{"reason": "not-relevant|already-covered|no-data|accepted-risk|other", "notes": ""}` (`other` needs notes) |
| `POST /api/hunting/suggestions/{id}/conclude` | admin | `{"outcome": "true-positive|benign|inconclusive-needs-data", "notes": "required"}`; closes the hunt |
| `POST /api/hunting/suggestions/{id}/promote` | admin | concluded only; creates a proposed detection use case |

404 unknown id, 400 bad input, 409 move the lifecycle does not allow. `/api/hunting` is already licensed under the `soc` module in `licensing.yaml`.

List response:

```json
{"suggestions": [{
  "id": "hyp-3f9a1c2b7d4e", "generator": "kev-exposure", "hunt_type": "hypothesis-driven", "pattern_key": "kev-exposure:T1190",
  "title": "Post-exploitation behaviour after CVE-2021-34527",
  "hypothesis": "If an adversary who exploited CVE-2021-34527 (...) is active in our environment, we would expect to see ... on 3 exposed host(s).",
  "why_now": [{"kind": "finding", "ref": "FIND-12", "label": "FIND-12 on WEB-1", "detail": "Vuln, KEV", "strong": true, "link": "/queue"}],
  "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "tactics": ["Initial Access"]}],
  "tactics": ["Initial Access"],
  "scope": {"assets": ["WEB-1"], "identities": [], "segments": [], "counts": {"assets": 1, "identities": 0, "segments": 0}},
  "data_sources": [{"name": "web server access logs", "class": "web", "label": "Web / WAF logs", "status": "cannot-tell", "detail": "..."}],
  "data_readiness": {"status": "cannot-tell", "siem_connected": false, "can_run_in_quanta": false, "note": "..."},
  "queries": [{"technique": "T1190", "name": "...", "domain": "network", "source": "SIEM", "language": "splunk-spl", "query": "search ...", "kql": "union * | where ...",
               "sigma": "title: ...", "description": "...", "result": null, "notes": ""}],
  "description": "plain-language summary and how to test it",
  "expected_malicious": ["..."], "likely_benign": ["..."], "scoping": "...", "effort": "S", "expected_value": "high",
  "priority": {"score": 61.4, "breakdown": [{"factor": "likelihood", "points": 27.2, "max": 30, "note": "..."}]},
  "next_step": "...", "soar_playbook": {"suggested": "Isolate host after approval", "note": "..."},
  "learned": {"points": 0.0, "note": "No history for this pattern yet.", "suppressed": false, "stats": {"concluded": 0, "true_positive": 0, "benign": 0, "inconclusive": 0, "dismissed": 0}},
  "gaps": ["..."], "draft_detection": null, "signals": {}, "evidence_refs": ["finding:FIND-12"],
  "status": "suggested", "outcome": null, "outcome_notes": null, "dismissal_reason": null, "hunt_id": null, "promoted_key": null, "current": true,
  "decided_by": null, "created_at": "2026-10-06T12:00:00Z", "updated_at": "2026-10-06T12:00:00Z"}],
 "total": 14, "shown": 14, "cap": 25, "capped": false, "suppressed_hidden": 0,
 "gaps": [{"generator": "baseline", "note": "Rare parent/child process pairs ... need process telemetry that Quanta does not store"}],
 "last_refresh": "2026-10-06T12:00:00Z", "note": "A suggestion is a hypothesis to test, not a finding. ..."}
```

## Honest limits

- Built from stored findings, alerts, intel, advisories, entitlements and hits. No log text is stored, so rare parent/child, first-seen admin tools, and beaconing/bursts from raw logs are not
  computed here (the SOC log analysis tool covers pasted logs); alert-based bursts and low-and-slow are.
- Industry relevance needs `industry` set in `hunt_engine.yaml`; actor matches are an illustrative MITRE cross-reference, not attribution.
- Query field names are Sigma's and must be mapped to your data model. KQL is a small `union *` rendering, not a tuned Sentinel/Defender query.
- Attack chains and relationship graphs are not read; exposure ranking uses asset facing, findings, recorded controls and team size as a blast-radius proxy.
- Suggestion reads need login only and are not team-scoped.
- Never run against a live SIEM; the Splunk run path is the existing, unchanged one.
