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

Three other things happen alongside this main line, not as separate stages: **MITRE
ATT&CK tagging** (a text heuristic applied whenever a finding is displayed), **ServiceNow
ticketing** (an optional action a human can trigger per finding), and **Remediation
Policy** (cadence/approval/PAM-backend resolution, applied to every finding on every
dashboard load). All three are covered in their own sections below.

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

## Remediation Policy (applied alongside, not a separate pipeline stage)

**Module:** `remediation/config/remediation_policy_engine.py` · **Config:**
`remediation/config/remediation_policy.yaml` · **Dashboard page:** `/remediation-policy`

Where §4 above decides *whether* a finding is auto-approvable and *how urgent* it is,
Remediation Policy decides the operational question underneath both: **when** should this
actually get remediated, does it need a human's explicit approval click first, and which
real credential-broker system should a generated playbook reference. It's resolved live
on every dashboard load (same "recomputed live, not baked into a static file" convention
as `priority_engine.py`), attached to every finding in `/api/queue` as `remediation_policy`.

**18 domains, each independently configurable** — one per real category this app
already tracks (`infra_category`/`scan_type`, see `remediation/schema/
normalized-finding-schema.md`), plus `dev` (any asset tagged `environment: dev` on
Asset Inventory, regardless of its underlying asset type) and `default` (forward-
compatibility fallback only — with all 16 real categories now explicitly covered,
0 of the 9,110+ real sample findings currently resolve to `default`). Domain
resolution order: an asset's `environment` tag if it's `"dev"` and a `dev` policy
exists → the finding's `infra_category` → its `scan_type` → `default`.

**Per-domain fields:**

| Field | Meaning |
|---|---|
| `change_type` | ITIL 4 Change Enablement vocabulary: `standard` (pre-approved/repeatable, no per-instance sign-off), `normal` (full assessment + approval), `emergency` (expedited, still approved, never skipped). |
| `cadence` | `weekly` / `monthly` / `quarterly` / `half-yearly` / `yearly` / `on-demand`. |
| `maintenance_window` | `day_of_week` (or `"daily"`), `start_time`/`end_time` (24h), `timezone` — resolved to the next real calendar date by `next_maintenance_window()`. |
| `auto_remediate` | Only meaningful when `change_type` is `standard` — whether the generated playbook needs a per-instance Approve click before it's "ready", or not. |
| `requires_approval_group` | An AD/LDAP security-group name authorized to approve this domain's remediations, or `null`. |
| `downtime_expected` | Whether the maintenance window is expected to interrupt service. |
| `communication_template` | A `$placeholder`-style downtime-notice template (`string.Template.safe_substitute()` — an unknown placeholder is left as literal text, never crashes the page, since this is admin-edited config, not trusted code). Rendered live per finding as `remediation_policy.rendered_communication` and actually sendable — see below. |
| `pam_backend` / `pam_credential_path` | Which real PAM system's Ansible lookup snippet a generated playbook's `vars:` block should reference — see below. |

**KEV emergency override:** a CISA KEV-listed finding always escalates to `change_type:
emergency` regardless of its domain's configured default (`kev_emergency_override` in the
YAML) — the same override convention `priority_rules.yaml`'s own `kev_override` already
established for priority scoring.

**The full domain table, each grounded in a real, citable standard or convention (not
invented defaults):**

| Domain | Real findings | Change type / cadence / auto-remediate | Why |
|---|---|---|---|
| `endpoint` | 482 | standard / weekly / yes | The user's literal example: SCCM-managed EUC devices, weekly patch-and-restart via a Windows Group Policy-managed window. |
| `os` | 1,099 | normal / monthly / no | The user's literal example: servers need approval + communicated downtime. |
| `dev` | 0 today (opt-in via Asset Inventory) | standard / weekly / yes | The user's literal example: non-prod assets auto-update in an off-hours window. |
| `network` | 1,096 | normal / monthly / no | Routers/switches carry real outage risk on a bad config push — approval-gated like `os`. |
| `network-security` | 1,097 | normal / monthly / no | Firewalls/IPS — HA-paired devices patch one node at a time, so `downtime_expected: false`. |
| `ot` | 1,103 | normal / quarterly / no | [NIST SP 800-82 Rev.3](https://csrc.nist.gov/pubs/sp/800/82/r3/final): OT patch cadence is risk-based, not a 30-day IT SLA — real windows can be "months apart." |
| `virtualization` | 291 | normal / quarterly / no | Hypervisor patching live-migrates workloads off first — a real operational event, not a hard outage. |
| `cloud` | ~1,400 | normal / monthly / no | AWS/Azure/GCP/Kubernetes/Terraform findings — see the cloud-specific PAM backends below. |
| `apps` | 1,045 | standard / weekly / yes | Mirrors `endpoint` — end-user apps ride the same SCCM-managed device cycle. |
| `printer` | 141 | standard / quarterly / yes | Vendor firmware push via centralized print management, low blast radius. |
| `iac` | 219 | standard / on-demand / yes | The fix is a Terraform/CloudFormation template merged via PR, not a maintenance window — `auto_remediate` here means "auto-mergeable on green CI," a different real mechanism than SCCM. |
| `runtime` | 218 | normal / on-demand / no | Behavioral detections (e.g. Falco-style alerts) are investigative SOC triage, not a patchable CVE — see "Asset classes with no fixer yet" below. |
| `sca` | 410 | standard / on-demand / yes | Grounded in the real, current [Renovate/Dependabot convention](https://www.systemshardening.com/articles/cicd/renovate-dependabot-security/): patch-level dependency bumps auto-merge on green CI. |
| `dast` | 300 | normal / on-demand / no | Code/config fix through the app's own release pipeline (review + QA), not a maintenance window. |
| `cert-mgmt` | 302 | standard / on-demand / yes | Grounded in the real, current [ACME/Let's Encrypt 90-day automated-renewal standard](https://letsecure.me/acme-automation-ssl-renewal-best-practices-2026/) — scoped to routine domain-validated renewal only, not an internal-CA/root change. |
| `secrets` | 110 | **emergency** / on-demand / no | A leaked credential is treated as an assumed compromise — immediate human-verified rotation, never auto-remediated. |
| `ai-ml` | 100 | normal / on-demand / no | Architecture/code-level fix reviewed by a security-architecture function, not a patch. |
| `default` | 0 today | normal / quarterly / no | Conservative fallback for any future category not yet explicitly covered. |

### Cloud-native PAM backends (AWS/Azure/GCP — same "keyless, short-lived" posture as Vault/CyberArk)

`pam_backend` also accepts three cloud-native, keyless credential-broker patterns —
grounded exactly the same way as Vault/CyberArk (real, current, independently verified,
never a standing stored secret):

- **`aws-sts-assume-role`** — real [`amazon.aws.sts_assume_role`](https://docs.ansible.com/projects/ansible/latest/collections/amazon/aws/sts_assume_role_module.html) module; the runner's own base AWS credentials assume a role for temporary, short-lived STS credentials.
- **`azure-managed-identity`** — the real, [production-recommended `azure.azcollection` managed-identity auth mode](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-ansible-playbooks) — no stored secret, the runner's own Azure-assigned identity is used directly.
- **`gcp-workload-identity`** — real [GCP Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation) — exchanges the runner's own external identity for a short-lived GCP access token, no service-account key file.

The `cloud` domain's real sample data now covers Kubernetes/Docker/OpenShift alongside
genuine AWS-specific (Amazon S3, Lambda, IAM, RDS, CloudFormation, ECR, Systems
Manager), Azure-specific (Azure Active Directory, Storage, DevOps, CLI), and
GCP-specific (Cloud Storage, Cloud SDK, gcloud) CVEs, all real and NVD-sourced — see
`remediation/sample-data/generate_bulk_findings.py`'s `cloud` category.

### Communication templates — drafted, rendered, and sendable, not just stored config

Every finding's resolved policy carries a real, rendered `rendered_communication`
string (`render_communication()`, computed live in `dashboard/data.py`, using the
approved-by name from a real approval if one exists, or "pending approval" otherwise).
On `/remediation-approvals`, each request has a "Communication" action that shows this
exact rendered text and lets an admin send it to a real recipient via
`POST /api/remediation-approvals/{id}/send-communication` — the same
dry-run-preview-then-confirm shape as every other real-send action in this app
(AI Assist, ServiceNow, Notification Settings), reusing Round 11's real SMTP sender
(`remediation/notifications/email_sender.py`) with zero new email-sending code. Without
`confirm`, it returns the subject/body for review; with `confirm: true` it actually
sends, honestly failing (503) if SMTP isn't configured rather than pretending to
deliver.

**The three literal examples this config was originally built to express directly:**
`endpoint` ships as weekly/`standard`/`auto_remediate: true` with a Tuesday 02:00–04:00
UTC window and `restart_required: true` ("every week need to restart... via SCCM using
Windows Group Policy"); `os` ships as monthly/`normal`/`auto_remediate: false` with
`downtime_expected: true`, a named `requires_approval_group`, and `pam_backend: vault`
("need to define upgrade cycles... approvals... scheduled downtime"); `dev` ships as
weekly/`standard`/`auto_remediate: true` with a nightly 01:00–05:00 UTC window and no
approval group ("auto-upgrade dev environment in specific hours").

### AD/PAM integration — what it is, and the deliberate scope limit

This repo has one non-negotiable safety line, stated in `remediation-fixer-windows.md`/
`-unix.md`: those subagents **never execute anything against real infrastructure** — they
only have `Read`/`Write` tools, so it isn't even possible. Remediation Policy's
"identity/PAM integration" is built to extend the *human-in-the-loop* workflow, not to
create a new execution path that would contradict that line:

- **AD (`dashboard/auth/ad_directory.py`)** is a real, **read-only** LDAP connector
  (`ldap3`) used only to check whether the person clicking Approve on
  `/remediation-approvals` is actually a member of the policy's
  `requires_approval_group`. It never creates, modifies, or deletes an AD object, never
  resets a password. Dormant until `AD_SERVER`/`AD_BASE_DN` (and optionally
  `AD_BIND_USER`/`AD_BIND_PASSWORD`) are set as real environment variables — like every
  other connector in this repo, it was built against the public LDAP protocol and has not
  been exercised against a real Active Directory environment. When AD isn't configured,
  an approval still proceeds, but `ad_group_validated` is honestly `null` ("we didn't
  check"), never fabricated as `true`/`false`.
- **PAM** is never a Python-side "fetch a secret and use it" connector inside this app.
  `pam_vars_snippet()` returns a real, standard Ansible snippet — `community.hashi_vault.
  vault_kv2_get` for Vault, `cyberark.pas.cyberark_credential` for CyberArk's Central
  Credential Provider, `cyberark.conjur.conjur_variable` for Conjur, or one of three
  cloud-native keyless patterns (`amazon.aws.sts_assume_role` for AWS, `azure.
  azcollection` managed identity for Azure, GCP Workload Identity Federation for GCP —
  see "Cloud-native PAM backends" below) — embedded in a generated playbook's
  `vars:`/`tasks:` block by the remediation-fixer subagents when a finding's resolved
  policy names a `pam_backend`. The actual credential-broker call happens later, at
  playbook-run-time, on whatever machine an organization's own change-management
  process uses to run that playbook — this application never fetches or holds a live
  privileged secret or token, cloud or on-prem.

### Remediation Approvals (`remediation/remediation_approvals/`, `/remediation-approvals`)

The human decision point this creates: for any finding whose resolved policy has
`change_type: normal` or `emergency`, a request can be created (scheduled against the
policy's next real maintenance window), then an admin approves or rejects it — recording
who, when, and (if AD is configured and the policy names a group) whether they were
verified. This is deliberately **not** the same thing as the Exceptions/waiver workflow
(`/exceptions`): an exception means "accept the risk instead of fixing"; an approval here
means "yes, proceed with this specific fix." A `pending` request whose scheduled window
has passed with no decision is reported as `expired` (computed on read, never silently
left `pending` forever) — the same derive-status-on-read pattern Exceptions already uses
for its own expiry.

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
| **IoT/OT devices** (`iot-ot-device`) | Realistically a per-vendor integration effort given how fragmented IoT/OT management APIs are; the roadmap suggests starting with the highest-volume device types in a real fleet (Armis-visible cameras and building-automation controllers) once that integration work is scoped. |
| **Application** (`application`, e.g. Log4Shell-class library/framework CVEs) | A library/dependency upgrade goes through the app's own build/release pipeline (Maven/Gradle, npm, pip, ...) — a fundamentally different mechanism per language/package manager, unlike the OS-level fixers' shared Ansible approach. |
| **Certificate/TLS** (`certificate`) | Mechanically simple (renew via ACME, disable a deprecated protocol) but organization-specific enough (which CA, which ACME client, which web server) that no generic fixer exists yet. |
| **Cloud infrastructure** (`cloud-infrastructure`) | Needs a `remediation-fixer-cloud` subagent generating Terraform/CloudFormation/ARM diffs — a different diff format per cloud provider, unlike one shared Ansible approach. |
| **End-user client software** (`client-application`) | Needs an endpoint-management/patch-deployment integration (Intune, SCCM, Jamf) to push an app update — a different mechanism from the OS-level Ansible fixers. |
| **Infrastructure-as-Code** (`iac-resource`) | Needs a `remediation-fixer-iac` subagent generating a Terraform/CloudFormation diff that corrects the flagged resource attribute directly in the template. |
| **Code repository** (`code-repository`) | Needs a `remediation-fixer-repo` subagent — bump the flagged dependency via a PR (Dependabot-style, CVE-bearing) or purge history and rotate the credential (secret-scanning, no CVE); two different fix mechanisms under one asset type. |
| **Container/host runtime** (`container-runtime`) | A Falco-style runtime detection is a behavioral alert, not a patchable CVE or config drift — response is investigative (security-team triage), not automatable the way a static CVE is. |
| **AI/ML systems** (`ai-ml-system`) | A prompt-injection, agent-design, or model-supply-chain finding needs a design/code change specific to that system — no general-purpose patch or config diff applies. |
| **Windows endpoints** (`windows-endpoint` — laptops/desktops) | The real-world tool is SCCM/Microsoft Configuration Manager (see a finding's `remediation_mechanism` field) — no working SCCM API integration exists in this app yet. |
| **Mobile devices** (`mobile-device` — phones/tablets) | The real-world tool is an MDM platform, e.g. Microsoft Intune (see `remediation_mechanism`) — no working MDM API integration exists in this app yet. |
| **Printers** (`printer`) | Needs vendor-specific firmware tooling (HP/Xerox/Canon/Lexmark/Ricoh each ship their own) — no general-purpose fixer exists across printer vendors, same reasoning as IoT/OT. |
| **Virtualization hosts** (`virtualization-host` — hypervisors) | The real-world tool is vendor hypervisor patch tooling, e.g. VMware Update Manager (see `remediation_mechanism`) — no working integration exists in this app yet. |

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
