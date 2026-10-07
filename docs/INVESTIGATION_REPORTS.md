# Investigation reports and hunt reports

Two reports that turn the SOC and hunting data Quanta already holds into something an analyst can act on:

- **The incident investigation report** (`/api/soc/incidents/{id}/report`): what an analyst opens when a ticket arrives, already investigated.
- **The hunt report** (`/api/hunting/hunts/{id}/report`): what a hunt ends in, one row per trial hit.

Both are assembled from stored data and (only after a person confirms) a few read-only outside lookups. Neither is written by a model. Neither closes, blocks or changes anything.

All routes need an administrator login, except `POST /api/ingest/itsm-ticket`, which needs a Quanta API key with the `soc:write` scope. Everything is licensed with the `soc` module (`remediation/config/licensing.yaml`).

## The rules every report follows

1. **Evidence only.** Each statement in an incident report carries `evidence`: references (`E1`, `E2`, ...) to items in the report's own `evidence` list. Each item says where it came from (a stored alert, a stored investigation, a reputation lookup, a SIEM search, an access record, a finding, a count over stored data) and when. A statement with no valid reference is **dropped** and counted in `dropped_statements`; the report never fills a gap with text.
2. **Unknown is a value.** An owner, privilege level, criticality or tool action that no record gives is `"unknown"`. An indicator that was not looked up is `not-looked-up` with verdict `unknown`, never "clean". `no-detections` means a reputation service knows it and no engine flags it, which is not the same as safe.
3. **Bounded.** Historical correlation counts only stored alerts and incidents inside a look-back (`history_days`, default 90) and says "None in 90 days" or how many days Quanta actually holds. Live SIEM searches come from a fixed query playbook with hard stop conditions and a look-back ceiling.
4. **A person confirms anything that leaves Quanta.** Reputation lookups and SIEM searches are previewed first; `confirm: true` runs them. Past the default look-back a written justification is required (the same rule as the rest of the SOC). Private addresses are never sent to the reputation service.
5. **A person approves anything that changes an environment.** Recommended actions that would change one are flagged `needs_second_person`. Quanta's only write to an outside system here is the optional comment on the ITSM ticket, a dry run unless confirmed.

## Query playbook

`remediation/config/query_playbook.yaml` holds the searches an investigation may run, the budgets and the look-back defaults.

```yaml
max_lookback_days: 90      # default and cap for every search
history_days: 90           # stored-data correlation window
budget: {max_queries: 6, max_rows: 100, rows_per_query: 10, time_budget_seconds: 60, max_consecutive_errors: 2}
reputation: {max_lookups: 15, malicious_min: 5}
patterns:
  - {id: web-exploit-requests, for: {techniques: [T1190]}, needs: [host], lookback_days: 7, spl: 'search host="{host}" ...'}
```

The plan is made once, up front, from the alerts' entities and ATT&CK techniques (technique-specific patterns first). A search's result is never used to plan another, so an investigation cannot recurse. The run stops at the **first** limit reached and records why: `completed`, `stopped: query budget`, `stopped: row budget`, `stopped: time budget` or `stopped: repeated errors`. Searches planned but not run are listed. A value that is not plain host, user or address text is refused, not escaped. A look-back wider than `max_lookback_days` needs a written justification of at least 20 characters (kept in the activity log), and is capped at `extended_lookback_days` in `soc_triage.yaml`.

## Incident report

### GET /api/soc/incidents/{id}/report

`?format=json` (default) or `?format=md`. The first call builds the report from stored data and saves it as version 1; later calls return the saved one. Returns:

```json
{
  "report": {
    "schema": 1, "version": 2, "incident_id": 14, "generated_at": "2026-10-06T12:00:00Z", "generated_by": "analyst@example.org", "look_back_days": 90,
    "incident": {"title": "Shell spawned by web server", "severity": "High", "status": "investigating", "tier": 2, "priority": "P2", "assignee": "l2@example.org"},
    "mode": {"siem": "not-connected | connected-not-run | ran", "reputation": "not-run | ran | failed", "stored_data_only": true},
    "verdict": {
      "label": "true-positive | false-positive | action-needed", "basis": "automated | analyst-resolved", "confidence": 0.82,
      "statement": "True positive: the evidence indicates a real threat.",
      "rationale": [{"text": "Alert #31: a known-exploited vulnerability on WEB-1 matches the alert's technique (CVE-2021-44228).", "evidence": ["E4", "E3"]}]
    },
    "summary": [{"text": "High incident of 3 alert(s) (1 duplicate), starting with 'Shell spawned by web server' at 2026-10-06T09:58:00Z.", "evidence": ["E1", "E2"]}],
    "history": [{"kind": "host", "value": "WEB-1", "look_back_days": 90, "covered_days": 90, "alerts": 2, "other_incidents": 1, "incident_ids": [9], "true_positive": 1, "noise": 0, "open": 1,
                 "first_seen": "2026-09-01T10:00:00Z", "last_seen": "2026-09-26T10:00:00Z", "alert_ids": [12, 20],
                 "text": "2 other alert(s) involve host WEB-1 in the last 90 days (first 2026-09-01, last 2026-09-26), in 1 other incident(s); 1 closed as true positive, 0 as benign or false positive, 1 still open.",
                 "evidence": ["E7"]},
                {"kind": "address", "value": "185.220.101.9", "alerts": 0, "text": "None in 90 days: no other stored alert involves address 185.220.101.9.", "evidence": ["E8"]}],
    "entities": [
      {"kind": "host", "value": "WEB-1", "owner": "unknown", "team": "web", "criticality": "high", "asset_type": "unix-server", "open_findings": 3, "kev_findings": 1, "evidence": ["E1", "E9"]},
      {"kind": "user", "value": "svc-web", "privilege": "privileged | not-privileged | unknown", "privilege_detail": "holds privileged access on PROD-DB", "owner": "unknown", "evidence": ["E1", "E10"]},
      {"kind": "address", "value": "185.220.101.9", "scope": "public", "evidence": ["E1"]}],
    "iocs": [{"value": "185.220.101.9", "type": "address", "verdict": "malicious | suspicious | no-detections | unknown",
              "reputation": {"status": "looked-up | not-looked-up | private-not-sent | lookup-failed", "source": "reputation service (vt)", "at": "2026-10-06T12:00:00Z", "malicious": 30, "total": 46, "result": "seen"},
              "context": ["alert #31 'Shell spawned by web server'"],
              "blast_radius": {"alerts": 3, "hosts": 3, "users": 2, "incidents": 3, "host_names": ["web-1", "web-2", "db-1"], "user_names": ["carol", "svc-web"], "incident_ids": [9, 14], "alert_ids": [31, 33]},
              "evidence": ["E11", "E12"]}],
    "attack": [{"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "tactics": ["Initial Access"],
                "next_step": "Look for the same source IP probing and then receiving a 200 on an unusual path...", "runbook": {"id": "rb-exploit-public-app", "title": "...", "steps": ["..."]},
                "look_in": ["web server access logs"], "mitigations": ["Update Software"], "alerts": [31], "evidence": ["E1", "E13"]}],
    "attack_flow": {
      "stages": ["Initial Access", "Execution", "Unmapped"],
      "nodes": [{"id": "a31", "kind": "alert", "label": "Shell spawned by web server", "stage": "Initial Access", "technique": "T1190", "severity": "High", "at": "2026-10-06T09:58:00Z", "host": "WEB-1", "evidence": ["E1"]},
                {"id": "e1", "kind": "entity", "entity_kind": "host", "label": "WEB-1", "stage": null, "evidence": ["E1"]}],
      "edges": [{"from": "a31", "to": "a33", "kind": "next-stage | same-stage", "label": "then"}, {"from": "a31", "to": "e1", "kind": "involves", "label": "involves"}],
      "note": "Stages follow the ATT&CK tactic Quanta tags on each alert ... not proof of causation."},
    "timeline": [{"at": "2026-10-06T09:58:00Z", "event": "Alert raised: Shell spawned by web server on WEB-1", "alert_id": 31, "evidence": ["E1"]}],
    "root_cause": {"is_hypothesis": true, "label": "hypothesis", "text": "Hypothesis (the evidence is partial): the earliest stage Quanta can place is Initial Access ...", "evidence": ["E1"],
                   "gaps": ["No SIEM connection: nothing outside Quanta's stored data was checked."]},
    "tool_actions": [{"alert_id": 31, "technology": "apikey:edr", "action": "Blocked by EDR | unknown", "state": "blocked | allowed | other | unknown", "advice": "...", "evidence": ["E1"]}],
    "recommended_actions": [{"action": "Isolate the host if exploitation is confirmed", "why": "Runbook step 3", "source": "runbook rb-exploit-public-app", "needs_second_person": true, "evidence": ["E14"]}],
    "references": [{"kind": "search | reputation lookup | stored-data correlation", "name": "Shells started by service processes", "query": "search host=\"WEB-1\" ...",
                    "source": "SIEM, read-only search run for this report (splunk)", "at": "2026-10-06T12:00:03Z", "look_back_days": 7, "result": "4 event(s)"}],
    "live_search": {"requested": true, "connected": true, "ran": true, "connection": "splunk", "look_back_cap_days": 90, "stop_reason": "stopped: query budget", "queries_run": 6, "rows_seen": 41,
                    "elapsed_seconds": 2.4, "budget": {"max_queries": 6, "max_rows": 100}, "planned": [], "not_run": [], "skipped": [], "results": [], "note": "only when not run"},
    "followups": [{"id": 3, "question": "Has 185.220.101.9 been seen before?", "answer": "None in 90 days: ...", "kind": "entity-history", "evidence": ["E15"], "asked_by": "analyst@example.org"}],
    "gaps": ["The tools' action is unknown for 1 alert(s)."],
    "limits": ["..."], "dropped_statements": 1,
    "evidence": [{"ref": "E1", "kind": "alert", "source": "stored alert #31 (apikey:edr / w1)", "detail": "High: Shell spawned by web server on WEB-1", "at": "2026-10-06T09:58:05Z"}]
  },
  "open_followups": [{"id": 4, "question": "...", "answer": "...", "merged": false}],
  "versions": [{"version": 1, "live": 0, "generated_by": "system", "generated_at": "2026-10-06T10:00:00Z"}]
}
```

Verdict: `true-positive` if any alert's saved investigation was a likely true positive; `false-positive` only if every real alert's was a likely false positive; otherwise `action-needed` (also when nothing has been investigated). Once an analyst resolves the incident, their verdict wins (`basis: analyst-resolved`). The verdict is a recommendation for a person to validate.

`root_cause.is_hypothesis` is true unless several independent sources (SIEM, reputation, findings, access records) back the account and no gap is known. `ioc.blast_radius` counts every stored alert (and the incidents they belong to) that carries the same value, including this incident's own.

### POST /api/soc/incidents/{id}/report/refresh

Rebuilds the report (a new version). From stored data it just runs. With `reputation` or `siem` it returns a preview until `confirm` is true.

```json
{"confirm": false, "reputation": true, "siem": true, "reputation_connection_id": null, "siem_connection_id": null, "lookback_days": 90, "justification": null}
```

Preview response (nothing sent):

```json
{"preview_only": true, "indicators_that_would_be_sent": ["185.220.101.9"], "reputation_connection": "vt", "siem_connection": "splunk",
 "searches_that_would_run": [{"name": "Suspicious requests to the host", "query": "search host=\"WEB-1\" ...", "look_back_days": 7}],
 "planned_but_over_budget": 2, "skipped": [], "budget": {"max_queries": 6, "max_rows": 100, "rows_per_query": 10, "time_budget_seconds": 60, "max_consecutive_errors": 2}, "look_back_cap_days": 90, "message": "..."}
```

With `confirm: true`: `{"preview_only": false, "report": {...}, "open_followups": [...]}`. If no SIEM is connected the report says so and uses stored data only. Errors: 400 (no connection configured; look-back past the ceiling without a justification, or past `extended_lookback_days`), 404.

### POST /api/soc/incidents/{id}/follow-up

```json
{"question": "Has 185.220.101.9 been seen before?", "kind": "entity-history", "value": "185.220.101.9", "siem": false, "confirm": false, "lookback_days": null, "justification": null}
```

`kind` is `similar-alerts`, `entity-history` or `indicator-sightings`; both `kind` and `value` are inferred from the question when omitted (a host, user, address, domain or hash named in it). The answer is counted over stored alerts and incidents inside the history window, with its evidence. A question that names nothing Quanta can look up is answered "Cannot be answered from stored data" with `answerable: false`; it is recorded but has no evidence, so merging it adds nothing. `siem: true` adds one read-only search for the value, previewed until `confirm`.

```json
{"followup": {"id": 3, "incident_id": 14, "kind": "entity-history", "value": "185.220.101.9", "question": "...", "answer": "None in 90 days: no other stored alert involves 185.220.101.9.",
              "data": [], "evidence": [{"kind": "history", "source": "count over stored alerts and incidents", "detail": "0 stored alert(s) involve ... within 90 days", "at": "2026-10-06T12:00:00Z"}],
              "answerable": true, "merged": false, "asked_by": "analyst@example.org", "asked_at": "2026-10-06T12:00:00Z"},
 "merged": false, "message": "Recorded on the incident. Merge it into the report to include it."}
```

`GET /api/soc/incidents/{id}/followups` lists them. `POST /api/soc/incidents/{id}/report/merge-followups` with `{"followup_ids": [3], "merged": true}` marks them merged (or not) and rebuilds the report from stored data; merged follow-ups appear in `report.followups` with their evidence.

### POST /api/soc/incidents/{id}/report/post-to-ticket

Posts a concise comment (verdict, first summary lines, up to five recommended actions with "needs a second person" marked, what is not known, and a link) to the ServiceNow or Jira ticket linked to the incident. `{"confirm": false}` is a dry run: it returns the exact comment and per-ticket status. With `confirm: true` it posts. Statuses per ticket: `dry-run`, `posted`, `already-posted` (the identical comment was posted before), `no-connection`, `unsupported`, `failed` (with the reason; the others still go; the write is not retried). ServiceNow gets an internal work note; Jira gets a comment. Set `QUANTA_PUBLIC_URL` to include a link to the SOC page. An optional `comment` replaces the generated text. 400 if no ticket is linked.

```json
{"preview_only": true, "comment": "Quanta investigation, incident #14 (report v2, ...)\nVerdict: action-needed (automated; confidence unknown). ...",
 "results": [{"system": "servicenow", "ticket": "INC0012345", "connection": "snow", "status": "dry-run", "comment_digest": "3f9a...", "message": "Nothing was sent. Send confirm: true to post this comment."}]}
```

### POST /api/ingest/itsm-ticket (API key, scope `soc:write`)

A ticket-created event from the ITSM tool. It becomes an alert (source `itsm:<system>`, external id `<system>:<ticket id>`), the ticket is linked to it, and the usual auto-investigation, incident grouping and routing follow; the report (version 1) is built before the response returns, so the analyst opens an investigated incident. A repeat of the same ticket is ignored.

```json
{"system": "servicenow", "ticket_id": "INC0012345", "title": "EDR: shell spawned by web server", "description": "Outbound connection to 185.220.101.9 from the web tier",
 "priority": 2, "asset": "WEB-1", "user": "svc-web", "source_ip": "198.51.100.4", "ips": [], "domains": [], "hashes": [], "urls": [], "technique": "T1190", "rule_name": "edr-web-shell",
 "created_at": "2026-10-06T09:58:00Z", "action_taken": "Blocked", "connection_id": null}
```

Response: `{"created": true, "alert_id": 31, "incident_id": 14, "ticket": {"system": "servicenow", "ticket_id": "INC0012345"}, "severity": "High", "report_version": 1}`. `system` is `servicenow`, `jira` or `other`. ServiceNow priority 1 to 5 maps to Critical, High, Medium, Low, Informational; Jira priority names and common words map likewise. A ticket with no recognisable severity is stored as Medium and the alert's detail says so. Indicators in the description are extracted as well as those sent. `incident_id` is null when the incident layer or auto-investigation is switched off; the alert is still stored. Errors: 400 (bad ticket id, empty title, unknown system), 401 (no or wrong-scope key).

To keep a ServiceNow or Jira business rule from re-sending the ticket on every update, send it on creation only.

## Hunt report

### GET /api/hunting/hunts/{id}/report

`?format=json` (default), `md` or `html`; also `/report.md` and `/report.html`. (The older default of Markdown moved to `?format=md`.) The HTML is a standalone, escaped, print-friendly page with no script.

```json
{
  "schema": 1, "hunt_id": 7, "generated_at": "2026-10-06T12:00:00Z", "topic": "Exploitation of CVE-2021-44228",
  "gist": "CVE-2021-44228 (Log4Shell) is on CISA's Known Exploited Vulnerabilities list and is open on 2 assets.", "hypothesis": "...", "source": "generated | intel | manual", "status": "active", "outcome": null,
  "scope": {"techniques": [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}], "hosts": ["WEB-1", "WEB-2"], "data_sources": ["process creation"]},
  "look_back": {"windows": ["-30d"], "days_max": 30, "text": "-30d"},
  "counts": {"trial_hits": 4, "run": 3, "no_hit": 1, "needs_investigation": 2, "not_run": 1, "leads_with_raw_hits": 2, "hits": 5, "entities": 4},
  "entities_observed": ["WEB-1", "WEB-2"],
  "verdict": {"label": "no-ioc-match | needs-investigation | confirmed | not-run", "rationale": "...", "correlated_entities": ["WEB-1"], "evidence": [1, 3]},
  "executive_summary": [{"text": "Hunt verdict: needs-investigation. ...", "trial_hits": [1, 3]}],
  "trial_hits": [{
    "n": 1, "index": 0, "name": "Shells spawned by server or office processes", "technique": "T1059", "domain": "endpoint | network | identity-email", "source_tool": "SIEM",
    "status": "no-hit | needs-investigation | not-run", "hits": 5, "hits_after_allowlist": 3, "allowlisted_rows": 2, "allowlist_partial": false, "assessment": "suspicious", "judged_benign": false,
    "entities": ["WEB-1", "WEB-2"], "window": "-30d", "ran_at": "2026-10-06T10:00:00Z", "error": null, "notes": "",
    "lead": {"hunt_id": 7, "index": 0, "path": "/hunting?hunt=7&lead=0"}, "allowlist_entries": [2],
    "queries": {"spl": "search ...", "sigma": "title: ...", "kql": "union * | where ...", "note": null}}],
  "per_domain": {"endpoint": {"trial_hits": 3, "run": 2, "no_hit": 1, "needs_investigation": 1, "not_run": 1, "hits": 3, "entities": ["WEB-1"]}},
  "allowlist": {"entries": [{"id": 2, "lead_key": "T1059|Shells spawned by server or office processes", "field": "host", "value": "SCAN-1", "note": "Nightly vulnerability scanner", "created_by": "a@example.org", "created_at": "..."}],
                "applied_entries": [], "rows_set_aside": 2, "note": "..."},
  "detection_recommendations": [{"trial_hit": 1, "technique": "T1059", "recommendation": "promote | assess-then-promote | consider | covered | done", "text": "Promote '...' to a detection use case ...", "priority": "high", "usecase_key": "hunt-1a2b3c4d5e"}],
  "timing": {"time_box_hours": 8, "time_box_source": "default | hunt", "created_at": "...", "due_at": "...", "report_ready_at": null, "time_to_report_hours": null, "state": "open | within-time-box | late | overdue"},
  "analyst_notes": "", "follow_ups": "", "limits": ["..."]
}
```

How the table is decided: a trial hit is `not-run` until a result is recorded (an errored one stays `not-run` with the error shown); `no-hit` when it ran with no hits left after the allow-list, or an analyst assessed its hits benign; otherwise `needs-investigation` (an unassessed hit is never assumed benign). The hunt verdict is `confirmed` if a hit an analyst judged malicious remains, else `needs-investigation` if any trial hit does, else `no-ioc-match` if any ran (the rationale says when only some ran), else `not-run`. The same entity in the results of two trial hits is listed in `correlated_entities`. `domain` comes from the lead or the technique's library entry.

### Allow-list: POST /api/hunting/hunts/{id}/allowlist

Records that a value is benign for one lead (for example a vulnerability scanner's address). It applies to every later run of the same lead (matched by technique and lead name), also in other hunts.

```json
{"lead_index": 0, "field": "host", "value": "SCAN-1", "note": "Nightly vulnerability scanner, change CHG-1042"}
```

`field` is one of the entity fields in `ALLOW_FIELDS` (`host`, `user`, `src_ip`, `dest_ip`, ...). Matching is exact and case-insensitive on that field; wildcards are not supported. A note of at least 10 characters is required and is shown in the report. Matching rows are removed from the lead's sample and counted in `allowlisted_rows`; if the stored sample was truncated, the rows never seen cannot be checked, so `allowlist_partial` is true and the count after the allow-list is not claimed exact. Returns `{"entry": {...}, "report": {...}}`. `GET .../allowlist` lists entries for the hunt's leads; `DELETE .../allowlist/{entry_id}` removes one. A duplicate (same lead, field and value) is a 400.

### Time-box and metrics

`POST /api/hunting/hunts/{id}/time-box` with `{"hours": 24}` (1 to `max_time_box_hours`, default 168) overrides the default of `default_time_box_hours` (8). `timing.state` is `within-time-box` or `late` once the report is ready, `overdue` or `open` before. The report is ready when the hunt is closed, or when every trial hit has a result (the time of the last run). `GET /api/hunting/report-metrics` returns `{hunts, reports_ready, median_hours, mean_hours, within_time_box, late, overdue, open, per_hunt}`: "time to report" is creation to ready.

### Where the report comes from

A published threat-intel report (`POST /api/ingest/threat-intel`) already creates a hunt when relevant, with one trial hit per attack step from the hunt library; the report is that hunt's view. Trial hits run only after a person confirms in the read-only SIEM connection (`/api/hunting/hunts/{id}/run-all`), or an analyst records results by hand; promotion to a detection use case uses the existing Detection engineering flow.

## Honest limits

- None of this has been run against a live SIEM, reputation service, ServiceNow or Jira. The connectors are built against public documentation and tested against hand-rolled fakes (`tests/test_investigation_report_*.py`, `tests/test_hunt_report_*.py`).
- The ServiceNow comment is an internal work note found by incident number; the Jira comment uses Atlassian document format. Instances with custom tables or permissions may need adjustment.
- Historical correlation and IOC blast radius count only what Quanta has stored. They say how many days of alerts Quanta holds when that is shorter than the window.
- "What the tools did" comes only from an alert's own `action_taken`; Quanta does not query the EDR or firewall for it.
- The root cause is a hypothesis unless several independent sources agree, and even then it is for a person to confirm. ATT&CK stages show the tactic order of the alerts, not proof of causation.
- The Sigma and KQL renderings use Sigma field names; map them to your data model. A lead that is not a library detection has SPL only.
- The query playbook is a small fixed set; it will not find what its patterns do not ask for. That is the point: it is bounded.
- Needs-a-second-person flags on runbook text use a conservative keyword rule (isolate, disable, block, reset, and similar); a playbook states its own.
