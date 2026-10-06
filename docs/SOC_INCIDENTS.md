# SOC incidents: automatic grouping, routing and the analyst queue

Analysts do not create cases. Every alert that Quanta investigates lands in an **incident** on its own: grouped with related alerts, summarised, given a
kill-chain view, and routed to an analyst or a tier queue with the reason written down. The existing `soc_cases` row is kept: it is the work item an incident is
routed as, and it carries the service-level clocks, so nothing about cases was removed or migrated away.

Code: `remediation/soc/incidents/` (`correlate.py`, `summary.py`, `routing.py`, `roster.py`, `service.py`, `stream.py`, `store.py`, `migrate.py`).
Policy: `remediation/config/soc_routing.yaml` (read on every call). Routes: `dashboard/app.py`, under `/api/soc/incidents`, `/api/soc/routing`, `/api/soc/analysts`.
All routes need an administrator session (the RBAC model has no separate analyst role); they are licensed with the `soc` module.

## How an alert becomes an incident

1. An alert arrives (`POST /api/ingest/alerts`, `/api/ingest/alerts/ocsf`, a SOAR or SIEM push). Auto-investigation runs as before.
2. `incidents.service.ingest(alert, investigation)` takes the investigated alert in. With `incidents.enabled: false` the older one-case-per-alert rule
   (`soc_ops.yaml` `auto_case`) applies instead. An alert that was never investigated (below the `auto_investigate` severity floor, or past
   `max_per_request`) is not grouped until someone investigates it.
3. **Correlation** (`correlate.py`). The alert is scored against each open incident whose last alert is within `window_minutes` (24 h). Each reason adds its weight
   once and is stored on the alert's link, so the analyst sees why it was grouped. The highest score at or above `join_threshold` (1.0) wins.

   | Reason | Weight | Applies when |
   |---|---|---|
   | `shared_host` | 1.0 | the alert's host (a private address counts as a host) is already in the incident |
   | `shared_user` | 1.0 | the same account |
   | `shared_indicator` | 1.0 | the same public IP address, domain or file hash |
   | `same_rule_burst` | 0.6 | the same detection rule fired again within `burst_minutes` (60) |
   | `shared_cve` | 0.6 | hosts in both carry the same known-exploited or alert-related vulnerability |
   | `same_technique` | 0.3 | the same ATT&CK technique on another host |
   | `kill_chain_progression` | 0.4 | a different kill-chain stage, counted only when another reason already applies |

   Different technique on a different host with nothing else in common is never grouped. A missing field means the rule does not apply; nothing is guessed.
4. **Duplicates.** The same rule on the same host within `duplicate_minutes` (30) of an alert already in the incident is a **duplicate**: grouped and counted
   (`duplicate_count`, role `duplicate`), not a new line of work. No alert is dropped.
5. **Kill chain and severity.** Each alert's technique maps to an ATT&CK tactic (`remediation/hunting/attack_tactics.yaml`; an unmapped technique has no stage).
   The incident's `kill_chain` is the distinct tactics in order. Severity is the highest alert severity, raised one level when the alerts span 3 stages, or 2
   stages when one is a late stage (`late_stage` list); capped at Critical. `base_severity` keeps the unraised value; a `severity_raised` event gives the reason.
6. **Confidence** is how likely the incident is a real threat: the strongest alert's own figure from the decision layer (a true-positive verdict's confidence,
   one minus a false-positive verdict's, 0.5 for escalate-l2) plus 0.05 per extra corroborating alert, up to +0.15. `null` when no alert has one.
7. **Summary.** One deterministic paragraph from stored fields only: what happened, the kill chain, hosts/accounts/indicators, the first-look verdict and its
   reasons, vulnerability context, owner, and the recommendation (tier, runbook). A part with no data is left out. Optional model refinement is
   `POST /api/soc/incidents/{id}/ai-summary`: dry-run unless `confirm: true`, the prompt carries counts and labels only (never alert text, host or account names),
   spend goes through the existing AI usage limit, and the text is stored beside the deterministic summary (`summary_ai`) only with `save: true`.
8. The incident gets its `soc_case` (source `auto`), then is **routed**.

## Auto-closing (and why nothing closes with the shipped policy)

An alert is auto-closed only when **all** hold: the verdict is `likely-false-positive`; the decision layer's gate says `auto` (its policy declares the decision
reversible and local, and calibrated confidence is at or above the `auto` threshold in `decision_policy.yaml`); the severity is not in
`auto_close.never_for_severities` (Critical is always listed); no known-exploited vulnerability is open on the host; and it did not correlate into a live incident.
It lands in an incident with status `auto_closed` (no case, no assignee), the alert is closed `false-positive` with `action_taken: auto-closed` (so rule-noise
history ignores it: a system closure is not a person's judgement), and the timeline records the gate result and the undo route. Same-rule/same-host repeats
are grouped into the same auto-closed incident. `POST /api/soc/incidents/{id}/undo-auto-close` reopens the alerts, records the system's verdict as **overridden**
in calibration, creates the case and routes it.

With the shipped `decision_policy.yaml` the first-look verdict's best confidence band is 0.9 and the `auto` threshold is 0.95, so the gate returns `review` and
**no alert is auto-closed** until an administrator lowers the threshold or raises the band probability. That is intentional.

## Routing (`routing.py`, `soc_routing.yaml`)

**Tier required** starts at the severity's base tier (Critical 2, High 2, otherwise 1) and rules only raise it: known-exploited vulnerability on a host (2),
crown-jewel asset (3), Critical on a high-criticality asset (3), a late kill-chain stage reached after another (3), low confidence on a High/Critical incident (2),
four or more hosts (2). The tier never goes down on its own.

**Candidates** are analysts who are active, marked available, inside their shift (UTC `HH:MM`; none set = always; a shift can cross midnight) or on call for a
priority in `on_call_priorities` (P1, P2), at a tier at or above the one required, and under their capacity (their own, else `default_capacity`).
**Order** among candidates: has the needed specialty (from the alert category or the asset type; ignored when no analyst on the roster has specialties recorded,
and said so when nobody available has it); handled a related incident (same host or account) within `continuity_hours`, or already owns this one; lowest sufficient
tier (keeps seniors free); lightest weighted load (open incidents weighted by priority and by SLA state: ok 1x, at risk 1.5x, breached 2x); then email, so the result
repeats. The reasons, including the other qualified analysts and their load, are stored as `routing_reason` and in the `routed` event.

**Nobody qualified**: the incident goes to the tier's queue (`queue`, `assignee: null`), an `unrouted` event is written, an activity-log entry
`soc.incident.unrouted` is made once, and `routing.lead_email` is mailed when set and SMTP is configured. It is retried on every sweep.

**Re-routing**: when an alert joins and raises the severity or tier, the incident is re-evaluated; the current owner is kept while they still qualify. Escalation
(`/escalate`, or automatic) moves it up and clears the owner before routing again.

**Sweep** (`service.sweep`, hourly on the leader tick, or `POST /api/soc/incidents/sweep`): syncs tiers moved by the case sweep, auto-escalates an incident whose
clock is `breached` (`escalation.on_sla`; the acknowledgement clock before the first escalation, then the pick-up clock, once per tier), re-routes incidents whose
owner no longer qualifies (marked unavailable, off shift, removed, tier too low), and retries queued ones. Work that is going well is not moved to even out load.
`PUT /api/soc/analysts` re-routes immediately what an unavailability change affects.

## States

`new` -> `triaging` -> `investigating` -> `contained` -> `resolved`, plus `auto_closed` and `merged`. `accept` moves `new` to `triaging`, takes it from the queue
when unowned (or only its owner may accept), and acknowledges the SLA clock. `advance` moves between the working states. **`resolve` requires a verdict** (`true-positive`,
`false-positive`, `benign`, or `duplicate`, `insufficient-data`, `accepted-risk`) and a written summary of 20+ characters; the verdict judges the decision
layer's logged recommendation for each alert (accepted when it agrees, overridden when it does not). `reopen` needs a reason.

## API

All JSON; errors are `{"detail": "..."}` with 400 (rule), 401, 403, 404.

### `GET /api/soc/incidents`
Query: `assignee`, `queue` (`L1`..), `status`, `severity`, `tier`, `mine=true`, `unassigned=true`, `open_only=true`. Newest-urgent first (open, then priority, then age); merged incidents are hidden unless `status=merged`.
```json
{"incidents": [{"id": 12, "title": "Shell spawned by web server (+1 related alert(s))", "severity": "High", "base_severity": "High", "priority": "P3", "tier": 2,
  "queue": "L2", "status": "new", "assignee": "ana@corp.example", "verdict": null, "confidence": 0.86, "summary": "High incident: 2 alert(s), starting with ...",
  "routing_reason": ["Severity High starts at tier 2.", "Raised to tier 2: a known-exploited vulnerability is open on a host involved (known-exploited-vulnerability-on-host).",
                     "Tier 2 needed; priority P3.", "Routed to ana@corp.example: L2 is the lowest sufficient tier; weighted load 0.0 (0 open of 12)."],
  "correlation": [{"alert_id": 31, "role": "correlated", "score": 1.0, "reasons": [{"reason": "shared_host", "weight": 1.0, "detail": "Same host: web-1."}]}],
  "kill_chain": [{"tactic": "Initial Access", "order": 2, "late_stage": false, "alert_ids": [30], "techniques": ["T1190"], "first_seen": "2026-10-15T09:00:00Z"}],
  "entities": {"hosts": ["web-1"], "users": [], "indicators": ["185.220.101.9"]}, "assets": ["WEB-1"], "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
  "cves": ["CVE-2021-44228"], "case_id": 7, "source": "auto", "merged_into": null, "escalation_count": 0,
  "created_at": "2026-10-15T09:00:00Z", "updated_at": "2026-10-15T09:01:00Z", "last_alert_at": "2026-10-15T09:00:40Z", "assigned_at": "2026-10-15T09:00:01Z", "resolved_at": null,
  "sla": {"ack": {"target_minutes": 120, "elapsed_minutes": 1.0, "remaining_minutes": 119.0, "state": "running", "done": false}, "pickup": null, "resolve": {"state": "running"}, "worst": "ok"}}],
 "counts": {"new": 1}, "enabled": true, "statuses": ["new", "triaging", "investigating", "contained", "resolved", "auto_closed", "merged"],
 "verdicts": ["true-positive", "false-positive", "benign", "duplicate", "insufficient-data", "accepted-risk"]}
```

### `GET /api/soc/incidents/{id}`
Everything above plus:
```json
{"case": {"case_id": 7, "status": "new", "tier": 2, "priority": "P3", "impact": "single", "sla": {...}, "auto_escalated_tiers": []},
 "alerts": [{"id": 30, "title": "...", "severity": "High", "asset": "WEB-1", "technique": "T1190", "rule_name": "web-shell", "status": "investigating", "disposition": null,
             "received_at": "...", "role": "primary", "reasons": [{"reason": "first_alert", "weight": 0, "detail": "This alert started the incident."}],
             "verdict": "likely-true-positive", "verdict_confidence": 0.9, "tactic": "Initial Access"}],
 "alert_count": 2, "duplicate_count": 0,
 "timeline": [{"id": 88, "incident_id": 12, "kind": "created", "actor": "system", "body": "Incident created from alert 30: ...", "data": {"alert_id": 30}, "created_at": "..."}],
 "recommended": {"runbooks": [{"id": "rb-web-exploit", "name": "..."}], "playbooks": [{"playbook_id": 3, "name": "...", "score": 0.4, "basis": "history", "why": "..."}],
                 "playbook_basis": "history", "next_steps": ["Accept the incident to start the clock and begin triage."]},
 "related_incidents": [{"id": 9, "title": "...", "severity": "Medium", "status": "resolved", "assignee": "bo@corp.example", "shared": {"host": ["web-1"]}, "created_at": "..."}],
 "summary_ai": null}
```
Timeline `kind`s: `created`, `investigation`, `alert_added`, `routed`, `reassigned`, `unrouted`, `severity_raised`, `accepted`, `status`, `note`, `escalated`, `auto_escalated`, `resolved`, `reopened`, `merged_in`, `merged`, `split`, `auto_closed`, `auto_close_undone`, `ai_summary`.
Starting a recommended playbook is a separate, existing, confirm-gated action; nothing is started by viewing it.

### Actions: `POST /api/soc/incidents/{id}/{action}`
Body is one JSON object; only the fields an action names are read. Returns the updated incident (`split` returns `{"original", "new"}`).

| Action | Body | Notes |
|---|---|---|
| `accept` | `{}` | owner, or anyone when it is in a queue |
| `advance` | `{"status": "investigating", "note": "..."}` | `triaging`, `investigating`, `contained` |
| `reassign` | `{"assignee": "x@corp.example", "reason": "on leave"}` | target must be an active analyst of a high enough tier; unavailable targets are allowed with a warning on the event |
| `escalate` | `{"summary": "20+ chars", "to_tier": 3}` | clears the owner and re-routes up |
| `resolve` | `{"verdict": "true-positive", "summary": "20+ chars"}` | verdict required |
| `reopen` | `{"reason": "..."}` | |
| `merge` | `{"source_id": 11}` | merges incident 11 INTO this one; the source becomes `merged` |
| `split` | `{"alert_ids": [31]}` | those alerts become a new routed incident; one must stay |
| `undo-auto-close` | `{"reason": "optional"}` | |
| `note` | `{"note": "..."}` | |

### `POST /api/soc/incidents/manual` (the exception)
`{"title": "...", "reason": "10+ chars, required", "severity": "Medium", "assets": ["MAIL-1"], "alert_ids": [], "summary": null}`. Source `manual-exception`; the reason is on the first timeline event and in the
activity log (`soc.incident.manual_create`); it is routed by the same rules. The older `POST /api/soc/cases` still works and is unchanged.

### `GET /api/soc/routing/preview?alert_id=N`
Writes nothing. `{"would_join": 12 | null, "would_be_duplicate_of_alert": null, "correlation": {"score": 1.0, "reasons": [...], "join_threshold": 1.0},
"routing": {"assignee": "ana@corp.example", "queue": "L2", "tier": 2, "reasons": [...], "candidates": [{"email": "...", "tier": 2, "eligible": true, "load": 0.0, "rank": 1}, {"email": "...", "eligible": false, "why_not": "outside their shift"}], "unrouted": false}}`.
For an alert already in an incident it returns `already_in_incident` and that incident's stored routing. The priority used in a preview that joins an incident is the incident's current one.

### `GET /api/soc/analysts` and `PUT /api/soc/analysts`
GET keeps its earlier fields (`email`, `tier`, `open_cases`, `at_capacity`) and adds `skills`, `available`, `shift_start`, `shift_end`, `on_call`, `capacity`, `capacity_set`, `on_shift`, `open_incidents`.
PUT sets only the fields sent: `{"email": "ana@corp.example", "tier": 2, "skills": ["cloud","identity"], "available": false, "shift_start": "08:00", "shift_end": "17:00", "on_call": true, "capacity": 10}`
(known specialties: endpoint, network, identity, cloud, email, ot, malware, forensics; `capacity: 0` or `null` returns to the default). Returns `{"analyst": {...}, "rerouted_incident_ids": [..]}`; incidents the analyst no longer qualifies for are re-routed at once.
`POST /api/soc/analysts` and `DELETE /api/soc/analysts/{email}` are unchanged.

### `GET /api/soc/incidents/stream` (Server-Sent Events)
Session cookie auth (administrator), GET only, no write ability. `Content-Type: text/event-stream`.
```
: connected, resuming after event 214
retry: 4000

id: 215
event: incident.created
data: {"id": 215, "type": "incident.created", "incident_id": 12, "kind": "created", "actor": "system", "at": "2026-10-15T09:00:00Z", "label": "Incident created from alert 30: ..."}

: heartbeat
```
Types: `incident.created`, `incident.assigned` (kinds `routed`, `reassigned`, `unrouted`, `accepted`), `incident.updated` (everything else). The payload names the incident; refetch it
with `GET /api/soc/incidents/{id}`. With no `Last-Event-ID` header (or `?after=`) the stream starts from now. A connection lasts at most `stream.max_seconds` (3600; `?max_seconds=` can only shorten it)
and ends with `: closing, reconnect to continue`; `EventSource` reconnects and resumes from the last id, so nothing is missed. Heartbeat comment every 15 s. Events are read from the database, so any replica serves the stream.

### `POST /api/soc/incidents/sweep`, `POST /api/soc/incidents/{id}/ai-summary`
See above. Sweep returns `{"synced": [], "escalated": [], "rerouted": [], "retried": []}`.

## Migration

Migration 7 (`soc_incidents_and_analyst_routing`, expand-only) adds the routing columns to `soc_analysts`, creates `soc_incidents`, `soc_incident_alerts`,
`soc_incident_events`, and gives every existing case that has no incident one (source `migrated`, linked by `case_id`, alerts linked, status mapped: `in_progress`/`pending` to
`investigating`, `resolved`/`closed` to `resolved` with the case's resolution as the verdict). The cases are untouched and the step is idempotent.

## Honest limits

- Rules and weights are judgement, not learned; tune `soc_routing.yaml`. Correlation uses entities Quanta already holds on the alert; an alert with no host, account or indicator can only group by rule or technique.
- Alerts must be investigated to be grouped. Technique-to-tactic mapping covers the techniques in `attack_tactics.yaml`; others have no stage and do not count toward progression.
- Asset criticality comes from the live findings' `asset.criticality` and the `crown_jewels` list; with neither, those tier rules never fire. CVE links come from the first-look investigation's host findings (name match on the host).
- Availability and shifts are what people (or an API call from a rota tool) record; Quanta reads no calendar or HR system. Shifts are UTC and have no day-of-week or holiday support.
- Routing balances at assignment time and on the sweep; it does not move healthy work to even out load.
- Lead notification is the activity log, the live stream and an optional email; there is no paging or chat integration.
- Auto-close needs the decision policy to allow it (see above) and its accuracy depends on the calibration data accumulating; silence after an auto-close is not counted as agreement.
- Case-level features (log analysis, the SOC metrics page) still work on the linked case; the metrics are still computed from cases, not incidents.
- Not run against a live SIEM, a live multi-replica deployment or a large alert volume; the stream polls the database every `poll_seconds` per open connection.
