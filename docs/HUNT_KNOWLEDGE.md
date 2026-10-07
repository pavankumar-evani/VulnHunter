# Hunting knowledge base

`remediation/hunting/knowledge/` gives the hunting module the public MITRE knowledge (ATT&CK Enterprise, Mobile, ICS and ATLAS for AI systems), 91 hand-authored threat scenarios,
a generator that turns relevant groups and malware families into hypotheses, on-demand hunt reports, analytic framework views (Diamond Model, kill chains, PEAK, maturity), a library
of out-of-the-box rules, controls and use cases, and an optional, confirm-gated model-assisted agent. **Quanta never runs a query on a customer system here.** Running a lead stays the
existing confirm-gated path on a hunt.

## The catalog (real data, refreshed by a script)

`scripts/build_hunt_knowledge.py` downloads MITRE's public data and writes compact files to `remediation/hunting/knowledge/data/`:

| File | Content |
|---|---|
| `enterprise.json`, `mobile.json`, `ics.json` | tactics; techniques and sub-techniques: id, name, tactics, platforms, data components, trimmed description, trimmed detection guidance, mitigation ids |
| `groups.json`, `software.json`, `mitigations.json` | groups (aliases, techniques, software), malware and tools (type, aliases, platforms, techniques), mitigations |
| `atlas.json`, `atlas_mitigations.json`, `atlas_cases.json` | ATLAS tactics, techniques, mitigations and case studies |
| `renamed.json` | old technique id to current id (ATT&CK v19 moved Defense Evasion into Stealth and Defense Impairment; tags such as T1562.001 still resolve to T1685) |
| `manifest.json` | source URLs, versions, retrieval date, counts, file hashes |

Shipped build (retrieved 2026-10-07): ATT&CK 19.2 (Enterprise 697 techniques and sub-techniques, Mobile 124, ICS 97), ATLAS 5.6.0 (170 techniques, 35 mitigations, 57 case studies), 180 groups,
953 software entries (malware and tools), 143 mitigations; 1.4 MB. Run `python scripts/build_hunt_knowledge.py` to refresh (`--from-dir DIR` for an offline copy of the four source files,
`--skip mobile ics`). A failed download writes nothing; the loader reports an empty catalog (`available: false`) rather than guessing. Text is trimmed; every id links to MITRE for the full text.
ATT&CK and ATLAS content is MITRE's and is used under their terms; keep the manifest with any copy.

## Scenario packs

`scenarios/*.yaml` (91 scenarios in 14 categories: phishing, social engineering, insider threat, drive-by, cloud, identity, system services, user activity, network, ransomware, supply chain,
AI/ML, malware, OT and mobile) with `_playbooks.yaml` (12 response playbook ids; each step says whether it changes a customer system and so needs approval). A scenario has an id, title,
hypothesis template (`If ..., we would expect to see ... on {scope}.`), technique ids that must exist in the catalog (a test enforces it), kill-chain phases, Diamond hints, the data classes it
needs, **leads**, expected malicious and likely benign evidence, tuning notes, severity and priority, a playbook id and response steps.

A lead is a Sigma-style `selection` (rendered to Sigma, Splunk SPL, KQL and EQL from the one definition, so they agree) or explicit `spl`/`kql`/`eql` text for what one event cannot say (counts,
baselines). Each language is reported as `provided`, `not-expressible` (with the reason, for example beaconing is a statistic) or `not-provided`; nothing is filled in with a guess. Every SPL
passes `siem_search_connector.check_query`. Add a scenario by appending to a pack; `scenarios.problems()` (and the tests) list what is wrong.

## Hypotheses from intelligence and data (the generator)

`knowledge-group` and `knowledge-software` hypotheses are added to the engine refresh (`remediation/hunting/knowledge/generator.py`, registered in `engine/generators.py`). A group or family is
relevant only when a stored report names it (alias match), MITRE documents it as targeting the `industry` set in `hunt_engine.yaml`, or (for ranking) its techniques are tagged on your findings or
alerts. Its catalogued techniques are narrowed to those **not claimed by an enabled detection rule** and **not hunted in the last 90 days**, preferring techniques with ready-made leads and one per
tactic. With no rules recorded, coverage is unknown and scored as a third, never as covered. Volume is capped (`remediation/config/hunt_knowledge.yaml`: 6 groups, 4 families, 6 techniques each),
ranked by the engine's visible score breakdown, and the learning loop and dismissal memory apply as for every generator (the id is stable per group or family). Evidence kind `catalog` names the
group or family. Gaps are reported when data is missing.

**Data readiness** names the classes of data a hypothesis needs (from the scenarios and the catalog's data components) and what Quanta can tell about each: `connected` (a connection proves it),
`data-held` (Access Governance entitlements, the attack-surface inventory), `alerts-seen` (alerts arrived from a product that normally produces it) or `cannot-tell`. It never says "missing". Overall:
`ready`, `partial`, `cannot-tell`. Uploaded log summaries are not retained, so they are not evidence.

## API

Reads need login; writes and the model path need an administrator. All under `/api/hunting/knowledge` (licensed with the SOC module through the `/api/hunting` prefix).

| Route | Auth | Notes |
|---|---|---|
| `GET /status` | login | catalog manifest and counts, scenario count and problems, languages, AI switch |
| `GET /search?q=&kinds=&limit=` | login | techniques, groups, software, case studies, ranked |
| `GET /matrix?framework=enterprise\|mobile\|ics\|atlas&overlays=true` | login | matrix plus per-technique overlay |
| `GET /techniques/{id}` | login | technique, scenarios, data classes and readiness, controls, your estate, framework views; old ids resolve (`renamed_from`) |
| `GET /groups?q=`, `/groups/{id or alias}` | login | group, scenarios, relevance to you (reports, industry, tagged techniques; "not attribution") |
| `GET /software?q=&type=`, `/software/{id or name}` | login | |
| `GET /scenarios?category=&technique=&q=`, `/scenarios/{id}` | login | detail has rendered leads, readiness, framework views and content |
| `GET /library?category=&tactic=&platform=&data_source=&status=&framework=&scenario=&q=` | login | out-of-the-box library with coverage status and facets |
| `GET /planned` | login | planning list; `POST /planned/{key}/discard` (admin) |
| `POST /promote` | admin | `use-case`, `rule` or `control`; always a draft |
| `POST /report` | admin | build and store a hunt report version |
| `GET /reports?kind=&id=`, `GET /reports/{id}?format=json\|markdown\|html` | login | |
| `POST /reports/{id}/create-hunt` | admin | creates a proposed hunt through the engine's accept flow; nothing runs |
| `GET\|POST /hypotheses/{id}/frameworks` | login | framework views for a stored hypothesis, current to its status |
| `POST /ai-draft`, `GET /ai-drafts`, `POST /ai-drafts/{id}/discard` | admin | confirm-gated model drafts |

`matrix` overlay (per technique id): `{"covered": true|false|null, "findings": 1, "alerts": 0, "hunts": [3], "suggestions": ["hyp-..."], "scenarios": ["net-beaconing"]}`; `covered` is `null` (unknown,
never "covered") when no rules are recorded, and always `null` for ATLAS. `summary` has `coverage_known`, counts and `unmatched_tags` (technique ids on your records that are not in the catalog).

`library` response (abridged): `{"items": [{"id": "identity-dcsync", "title": "...", "category": "identity", "severity": "critical", "priority": "high", "tactics": ["Credential Access"], "platforms": ["Windows"],
"data_sources": ["host-auth", "network-flow"], "frameworks": ["enterprise"], "techniques": [{"id": "T1003.006", "name": "DCSync"}], "coverage": {"status": "cannot-tell", "covered": 0, "of": 1,
"detail": "...", "use_case_status": null}, "coverage_status": "cannot-tell", "rules": 2, "controls_available": 6, "use_case_key": "ootb-identity-dcsync", "readiness": "cannot-tell", "hypothesis": "If ..."}],
"total": 91, "shown": 91, "facets": {"category": {...}, "tactic": {...}, "platform": {...}, "data_source": {...}, "framework": {...}, "coverage": {...}}, "coverage_note": "...", "rules_recorded": false}`.
Coverage status: `enabled` (every ATT&CK technique claimed by an enabled rule), `proposed` (a non-rejected use case exists), `absent` (rules recorded, none cover it), `cannot-tell` (no rules recorded).
A proposed use case, a disabled rule or a planned control is never counted.

### Report

`POST /report` body `{"subject": {"kind": "technique|group|software|scenario|tactic|atlas-technique", "id": "T1558.003"}, "lookback_days": 30, "scope": {"assets": ["DC-1"], "identities": [], "segments": []}}`
(groups also accept an alias, tactics a name or slug). Returns `{"id": 7, "version": 2, "subject": {...}, "created_at": "...", "report": {...}, "urls": {"json": ..., "markdown": ..., "html": ...}}`.
`report` has: `subject`, `title`, `generated_at`, `lookback_days`, `scope`, `catalog` (versions), `hypothesis` (`statement`, `who`, `expect`, `where`, `basis`), `techniques` (id, name, tactics, platforms,
description, `detection_guidance`, `data_classes`, `mitigations`, `covered` true/false/null, `recently_hunted`, `in_estate`, `has_ready_lead`), `scenarios`, `intel` (stored reports with `why_relevant`, indicators,
`source`), `frameworks` (below), `data_readiness`, `leads` (each with `languages: {sigma|splunk-spl|kql|eql: {status, query|reason}}`), `expected_evidence`, `what_a_hit_means`, `containment` (playbooks and
`recommendations_for_a_person`), `recommendations` (`detections`, `controls`, `use_cases`, `coverage`), `execution_plan` (ordered, with phase and who), `limits`, `ran_anything: false`, `actions`.
A group or tactic is cut to the 12 most useful techniques and `limits` lists the rest. Up to 10 versions are kept per subject.

### Framework views

`frameworks` = `{"diamond", "kill_chain", "attack", "unified_kill_chain", "peak", "maturity"}`.
- `diamond`: `vertices.{adversary,capability,infrastructure,victim}` each `{status, items: [{value, detail, source}], hints, note}` plus `candidates` for the adversary (technique overlap, never attribution) and
  `meta` (timestamp, phase, result, direction, methodology, resources, technology). Statuses: adversary `unknown|hypothesised|named-by-intel`; infrastructure `unknown|indicators-known`; victim `unknown|scoped`;
  capability `unknown|known`. `unknown_vertices` lists what nothing supports.
- `kill_chain` (Lockheed Martin, indicative mapping), `attack` (position across tactics per framework), `unified_kill_chain` (18 phases).
- `peak`: `current` (prepare|execute|act), `next_action`, checklists. `maturity`: Hunting Maturity Model level for this hunt and a `limiting_factor` when readiness is unknown.

### Promote

`POST /promote` `{"kind": "use-case", "scenario_id": "identity-dcsync"}` -> a **proposed** use case `ootb-identity-dcsync` (a recorded decision is never overwritten); `{"kind": "rule", "scenario_id": ..., "lead_index": 0}` ->
a Sigma rule imported **disabled**; `{"kind": "control", "control_id": "M1026", "scenario_ids": [...], "note": ""}` -> **planned** on a separate list, never the controls inventory. Every answer carries
`counted_as_coverage: false`. ATLAS controls come from `controls_atlas.yaml` (class and action per MITRE ATLAS mitigation, no invented NIST mapping).

### Model-assisted agent

`POST /ai-draft` `{"kind": "hypothesis-refine|query-draft|result-summary", "subject": {...}, "intel_text"|"hypothesis"+"language"+"schema_hint"|"results_text" or "hunt_id", "confirm": false}`.
Without `confirm` it returns `{"dry_run": true, "prompt": "...", "sent": [{"field", "chars", "origin", "redactions"}], "checks": [...]}` and spends nothing. With `confirm: true` it runs through the existing AI path
(`_enforce_ai_usage_limit` for the daily token cap, `_run_ai_call_and_record_usage` for the call, the per-call budget and the usage log, so it counts as a model call) and stores a draft labelled
**AI-drafted, unvalidated**. No model (no Claude CLI) means 503 and nothing is stored; `ai.enabled: false` in `hunt_knowledge.yaml` means 403. The model sees catalog text and what the administrator typed,
secret-shaped strings are replaced first, pasted text is wrapped as untrusted data, and a prompt over `ai.max_prompt_chars` is refused, not truncated. Validation: technique ids must exist (unknown ones are removed and
listed); a drafted query must pass the read-only gate (`siem_search_connector.check_query` for SPL, `safe_query` for KQL, EQL and Sigma); a hypothesis must have the "If ..., we would expect to see ..." form. An
invalid draft is kept with `validation.ok: false` and its errors. A draft is never applied, run or counted as coverage.

## Tables

Migration 13 (expand-only, tables only): `hunt_knowledge_reports`, `hunt_knowledge_drafts`, `hunt_planned_items`.

## Honest limits

- Never run against a live SIEM; the leads are renderings for a person to adapt. Field names are Sigma's. KQL and EQL are small renderings of the same selection, not tuned production queries.
- The catalog is a snapshot (see `manifest.json`); trimmed text; ATT&CK v19 restructured tactics, so tags from older versions resolve through `renamed.json` where MITRE recorded a successor.
- Coverage can be judged only from enabled rules that name ATT&CK ids; ATLAS coverage is not judged. Readiness is inference, never proof.
- Group relevance is a cross-reference, not attribution. Kill-chain and Unified-Kill-Chain mappings are indicative. The scenario packs are authored from public knowledge and have not been validated against a live environment.
- The model path was tested with a fake model only; it has not been run against a real Claude session in tests.
