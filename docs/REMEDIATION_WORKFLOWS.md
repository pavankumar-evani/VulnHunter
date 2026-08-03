# VulnHunter — Remediation Workflows

**How to use this doc:** read this for the full `/remediate` lifecycle end to end — every
stage a finding passes through, in order, from raw vendor export to a human running a
reviewed playbook. If you just want to run the pipeline, see
[USER_GUIDE.md](USER_GUIDE.md). For subagent tool-scopes, see
[AI_COMMANDS.md](AI_COMMANDS.md). For the external systems referenced along the way, see
[INTEGRATIONS.md](INTEGRATIONS.md). For the design rationale behind any of this, see
[KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md). Also see [FAQ.md](FAQ.md),
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), or the [docs/README.md](README.md) index.

---

## The lifecycle, in order

```
Tenable export / Armis export / manual threat intel
        │
        ▼
1. INGEST + NORMALIZE          vuln-ingest-normalizer      → normalized-findings.json
        │
        ▼
2. THREAT-INTEL ENRICHMENT      threat-intel-enricher       → + kev / epss fields
        │
        ▼
3. RISK-TIER + PRIORITY/SLA     remediation-planner          → REMEDIATION_PLAN.md
   SCORING                      (+ live priority_engine.py    (+ live /queue page)
        │                        on every dashboard load)
        ▼
4. PLAYBOOK GENERATION           remediation-fixer-windows    → remediation/output/*.yml
        │                        remediation-fixer-unix
        ▼
5. HUMAN REVIEW                  (a person, or an org's approved automation platform)
        │
        ▼
6. (MANUAL) APPLY                 never performed by this repo
```

Two other things happen alongside this main line, not as separate stages: **MITRE
ATT&CK tagging** (a text heuristic applied whenever a finding is displayed) and
**ServiceNow ticketing** (an optional action a human can trigger per finding). Both are
covered in their own sections below.

---

## 1. Ingest

**Subagent:** `vuln-ingest-normalizer` (`Read, Glob, Write`)

Three source types, each with a genuinely different shape:

- **Tenable** — CSV export (`Plugin ID, CVE, Risk, CVSS v3.0 Base Score, Host, IP
  Address, FQDN, OS, Name, Synopsis, Solution, Port, Protocol, ...`). Column
  order/presence can vary by export, so the normalizer reads the header row rather than
  assuming fixed positions.
- **Armis** — JSON, `{"devices": [{"deviceId", "deviceName", "deviceType", "ipAddress",
  "riskLevel", "alerts": [...] }]}`. Each alert on each device becomes one finding.
- **Manual threat intel** — JSON, `{"entries": [{"intelId", "source", "title",
  "affectedAsset", "cve", "severity", "recommendedAction", "dateAdded"}]}`. There is
  deliberately no "connector" for this source — by definition it's analyst-curated, not
  pulled from an API (see [INTEGRATIONS.md](INTEGRATIONS.md)).

By default, `/remediate` with no arguments ingests the bundled samples in
`remediation/sample-data/`; pass real file paths (including live-connector output — see
[INTEGRATIONS.md](INTEGRATIONS.md)) to ingest anything else.

## 2. Normalize

Same subagent, same stage. Every record — regardless of source — is mapped into one
common schema, documented field-by-field in
[`remediation/schema/normalized-finding-schema.md`](../remediation/schema/normalized-finding-schema.md).
The two judgment calls worth knowing about:

- **`asset.type` classification** — the normalizer inspects OS strings, Armis device
  types, and Tenable finding names to bucket every finding into one of seven classes:
  `windows-server`, `windows-endpoint`, `unix-server`, `network-routing-switching`,
  `network-security-device`, `iot-ot-device`, `application`, `certificate`, or `unknown`
  if genuinely unclear (the normalizer is instructed not to guess and mislabel, since a
  wrong asset type routes a finding to the wrong — or no — fixer).
- **Stable, non-positional IDs** — findings get sequential `FIND-N` IDs, but on repeat
  runs existing findings keep their original ID (matched by `source` + `source_ref`, not
  position in the file); only genuinely new records get new numbers. This matters because
  generated playbook filenames, tests, and reports reference specific finding IDs — those
  references have to stay valid across ingestion runs.

`remediation_domain` is set from `asset.type`: `windows-server` and `unix-server` (the
only two domains with a working fixer today) copy straight through; every other type gets
`null`, meaning "planned, but not yet auto-remediable" (see §6 below for why).

Output: `remediation/output/normalized-findings.json`.

## 3. Threat-intel enrichment

**Subagent:** `threat-intel-enricher` (`Read, Write, Bash`)

Runs `remediation/enrichment/kev_epss.py` via Bash against
`remediation/output/normalized-findings.json`, attaching to every finding with a CVE:

- **`kev`** — is this CVE confirmed actively exploited in the wild, per CISA's Known
  Exploited Vulnerabilities catalog? `{"listed": true/false, "date_added", ...}` when a
  CVE exists; `null` when there's no CVE to check (many Armis policy findings and nearly
  all certificate findings have none).
- **`epss`** — a 0–1 probability of exploitation in the next 30 days, per FIRST.org's
  EPSS API, plus percentile rank.

Both APIs are free, public, and require no authentication — and, unlike the
Tenable/Armis/ServiceNow connectors, both were verified against the real live endpoints
during development (see [INTEGRATIONS.md](INTEGRATIONS.md)). If the enrichment script
fails (no network access, say), the subagent is instructed to report that plainly rather
than fabricate KEV/EPSS values — `/remediate`'s orchestrating command then proceeds to
planning anyway, noting in the chat summary that enrichment data is unavailable for that
run, rather than blocking the whole pipeline on an external dependency.

## 4. Risk-tier + priority/SLA scoring

This is where two related but genuinely distinct scoring mechanisms exist side by side —
worth understanding precisely, since it's easy to conflate them.

### `remediation-planner`'s snapshot (`Read, Write`)

A Claude Code subagent that runs once per `/remediate` invocation and writes
`REMEDIATION_PLAN.md`. For every finding it decides:

- **`action_type`** — `patch`, `config-change`, `service-disable`,
  `network-restriction`, `credential-rotation`, `firmware-update`, or
  `manual-investigation`.
- **`automation_target`** — `ansible-windows`/`ansible-unix` only when
  `remediation_domain` matches; everything else is `manual-only`. The planner is
  explicitly instructed not to invent automation for unsupported domains.
- **`risk_tier`** — `auto-approvable` / `needs-change-approval` / `manual-only`, based on
  blast radius and asset criticality. Domain controllers, auth servers, core network
  devices, and anything with plausible outage risk default to `needs-change-approval`.
  The planner defaults to the more conservative tier whenever uncertain.
- **`rollback_plan`** — one sentence on how to undo the change.
- **`priority`** (`High`/`Medium`/`Low`) — severity + asset criticality, **overridden**
  by KEV/EPSS: a KEV-listed finding is escalated to top priority regardless of asset
  type; an EPSS ≥ 0.5 finding is elevated even without KEV. **Crucially, KEV/EPSS affect
  priority, never `risk_tier`** — an actively-exploited CVE on a domain controller is
  still `needs-change-approval`, just more urgent to get approved. This is a deliberate,
  explicitly-documented rule in the agent's own instructions, not an omission.

### `priority_engine.py`'s live scoring (`remediation/config/priority_engine.py`)

A plain Python module the **dashboard** uses to re-score every finding on every page
load, from whatever `remediation/config/priority_rules.yaml` currently says — a weighted
score (severity + asset-criticality keyword match + asset-type weight), a KEV override
(forces top priority, toggleable), an EPSS escalation threshold (default 0.5, toggleable),
and an SLA due date computed from `sla_days` per priority tier (defaults: Critical 3 days,
High 7, Medium 30, Low 90).

### Why both exist

Per the module's own docstring: *"This is deliberately separate from
remediation-planner's own priority logic: the planner is a Claude Code subagent that
produces a point-in-time REMEDIATION_PLAN.md snapshot; this module is what the dashboard
uses to re-score findings live whenever an admin edits the rules file, without needing to
re-run the whole pipeline."* Concretely: `REMEDIATION_PLAN.md` is a static artifact from
the moment `/remediate` last ran — the dashboard's `/remediate` page shows exactly that
snapshot. The dashboard's `/queue` page instead re-computes priority and SLA live, every
time it's loaded, against the rules file as it currently stands — so an admin can tune
`priority_rules.yaml` (or edit it via the dashboard's `/priority-rules` page) and see the
queue and Overview KPIs reorder immediately, with no pipeline re-run and no new Claude API
spend. `remediation/config/priority_rules.yaml`'s own header comments describe the same
relationship and note the two mirror each other's KEV-override logic today (no
`remediation/config/README.md` exists yet as a separate doc — the module docstring and
the YAML file's own comments are the source of truth for this distinction).

## MITRE ATT&CK tagging (applied alongside, not a pipeline stage)

**Module:** `remediation/enrichment/attack_mapping.py`

A **keyword heuristic** against each finding's title/description text, applied whenever
findings are displayed (surfaced on the dashboard's `/queue` page as `attack_techniques`
tags) rather than as a discrete pipeline stage with its own output file. The module's own
docstring is explicit that this is not authoritative: *"there is no universal,
authoritative CVE-to-ATT&CK-technique mapping... treat every mapping here as a suggestion
to verify, not a fact to cite."* Some patterns are deliberately left unmapped (e.g.
certificate expiry — a lifecycle issue, not an attack technique) rather than forced into
a weak match.

## 5. Playbook generation

**Subagents:** `remediation-fixer-windows`, `remediation-fixer-unix` (both `Read, Write`
only)

Each generates one Ansible playbook per eligible finding — `remediation_domain ==
"windows-server"` and `automation_target == "ansible-windows"` for the Windows fixer;
the Unix equivalent for the other — written to
`remediation/output/<finding-id>-<slug>.yml`. Every playbook includes: a header comment
naming the finding ID(s), the risk tier, and a rollback instruction copied from the plan;
a pre-change state check; and, if `risk_tier` is `needs-change-approval`, a prominent
`# CHANGE APPROVAL REQUIRED before running` comment. Neither fixer has `Bash` or any
network tool — they generate a file, nothing more, and cannot execute it themselves even
if a prompt tried to instruct one to.

## ServiceNow ticketing (an available action, not a required stage)

**Module:** `remediation/connectors/servicenow_connector.py`

Creates an Incident per finding via ServiceNow's Table API, keyed on `correlation_id` so
re-sending the same finding doesn't create a duplicate ticket. This is not a required
step in the lifecycle above — it's an action available from the dashboard's
`/servicenow` page (preview the exact payload with zero credentials, then explicitly
confirm to actually send) whenever an organization wants findings tracked in their own
ITSM tool alongside `REMEDIATION_PLAN.md`. See [INTEGRATIONS.md](INTEGRATIONS.md) for its
verification status (built against docs, not yet exercised against a live instance).

## 6. Human review, and 7. (manual) apply

Every generated playbook is an artifact — reviewed by a person, or run through an
org's own approved automation platform (Ansible Tower/AWX, Intune, SCCM) with its own
RBAC. Nothing in this repository runs a playbook against a real host at any point in this
lifecycle. See [USER_GUIDE.md §5](USER_GUIDE.md#5-reviewing-and-approving-a-generated-ansible-playbook)
for the review checklist.

---

## Asset classes with no fixer yet — and why

Every asset class gets ingested, normalized, enriched, and included in the risk-tiered
plan. The gap for the classes below is specifically **fix-generation automation**, not
visibility — each lands in `REMEDIATION_PLAN.md`'s "no automated remediation path today"
section with the reason stated:

| Asset class | Why no fixer exists yet |
|---|---|
| **Network routing/switching** (`network-routing-switching`) | Needs a `remediation-fixer-network` subagent generating vendor CLI config diffs (Cisco IOS/IOS XE, Junos via Ansible's network collections) — same `Read`/`Write`-only tool scoping as the existing fixers, not yet built. |
| **Network security devices/firewalls** (`network-security-device`) | Same gap as above — no fixer subagent exists for this domain yet. |
| **IoT/OT devices, mobile/endpoints** (`iot-ot-device`) | Realistically a per-vendor integration effort given how fragmented IoT/OT management APIs are; the roadmap suggests starting with the highest-volume device types in a real fleet (Armis-visible cameras and building-automation controllers) once that integration work is scoped. |
| **Application** (`application`, e.g. Log4Shell-class library/framework CVEs) | A library/dependency upgrade goes through the app's own build/release pipeline (Maven/Gradle, npm, pip, ...) — a fundamentally different mechanism per language/package manager, unlike the OS-level fixers' shared Ansible approach. |
| **Certificate/TLS** (`certificate`) | Mechanically simple (renew via ACME, disable a deprecated protocol) but organization-specific enough (which CA, which ACME client, which web server) that no generic fixer exists yet. |

Full detail and the roadmap for each:
[KNOWLEDGE_TRANSFER.md §9, Tier 2](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade).

---

## See also

- [USER_GUIDE.md](USER_GUIDE.md) — how to run `/remediate` and read its output.
- [AI_COMMANDS.md](AI_COMMANDS.md) — exact tool-scopes for every subagent named above.
- [INTEGRATIONS.md](INTEGRATIONS.md) — verification status of every external system
  referenced in this lifecycle.
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) — how this workflow's controls map
  (informationally) to compliance framework categories.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — full
  architecture, roadmap, and design rationale.
