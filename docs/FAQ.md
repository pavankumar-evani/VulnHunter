# VulnHunter — FAQ

**How to use this doc:** specific yes/no and "does it actually..." questions about this
product, answered plainly. If you want task-oriented how-to instead, see
[USER_GUIDE.md](USER_GUIDE.md). For the full architecture and design rationale, see
[KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md). Also see
[AI_COMMANDS.md](AI_COMMANDS.md), [INTEGRATIONS.md](INTEGRATIONS.md),
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md),
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), [SUPPORT.md](SUPPORT.md), or the
[docs/README.md](README.md) index.

---

### Does this actually scan production infrastructure?

No. `/remediate` does not connect to, probe, or scan any host, network device, or IoT/OT
device itself. It **ingests** vulnerability/asset-risk data that Tenable and Armis (or an
analyst, for manual threat intel) already produced, via file exports
(`remediation/sample-data/*.csv|*.json` for the bundled demo data) or, if you have
credentials, their live APIs (`remediation/connectors/tenable_connector.py`,
`armis_connector.py`). Those connectors are **built against each vendor's publicly
documented API contract and unit-tested against mocked HTTP — they have never been
exercised against a real Tenable.io or Armis tenant**, because no API credentials were
available while building them (see
[remediation/connectors/README.md](../remediation/connectors/README.md) and
[INTEGRATIONS.md](INTEGRATIONS.md) for exactly what "tested" does and doesn't mean here).
If you point them at a real tenant, verify the output against a manually-checked sample
first — field names and nesting can differ from the public docs by API version and tenant
configuration.

### Does anything ever auto-apply to real systems?

No, by construction, not by policy. Specifics:

- `remediation-fixer-windows` and `remediation-fixer-unix` — the two subagents that
  generate Ansible playbooks — have **only `Read`/`Write` tool access** in their
  `.claude/agents/*.md` frontmatter. No `Bash`, no network tool, no credentials. They
  cannot connect to a host even if a prompt somehow instructed one to "just apply this."
- `vuln-fixer` (the code pipeline's fixer) always works on a new git branch and pushes it
  for review; it never commits to `main`.
- Every generated artifact — a playbook, a pushed branch, `REMEDIATION_PLAN.md` — is
  something a human (or your org's existing approved automation platform, e.g. Ansible
  Tower/AWX) reviews and runs. Nothing in this repo has execution reach to real
  infrastructure at all.
- The headless CLI (`cli/vulnhunter.py`) and the dashboard's `/run` and `/servicenow`
  forms default to dry-run/preview; spending real API usage or sending a real ServiceNow
  ticket requires an explicit flag or confirm checkbox.

Full detail: [KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision)
and [USER_GUIDE.md §6](USER_GUIDE.md#6-the-safety-model-in-practice).

### What languages can the code scanner find vulnerabilities in?

Per `.claude/agents/vuln-scanner.md`'s documented detection guidance: **Python,
JavaScript/TypeScript, Java, Go, PHP, and Perl**, plus generic checks (hardcoded secrets,
insecure config, dependency risk, unsafe Docker practices) that apply regardless of
language. Each language has its own idiomatic vulnerable-pattern list (e.g. Java XXE via
`DocumentBuilderFactory`, PHP local file inclusion via unsanitized `include`/`require`
paths, Go `text/template` used where `html/template` should be) — see the agent file for
the full per-language breakdown.

**Important distinction:** the scanner's *target* language coverage (what it can find
vulnerabilities in) is unrelated to the scanner's *own* implementation, which is a Claude
Code subagent (Python-adjacent tooling, prompt-driven, running via `Read`/`Grep`/`Glob`/
`Bash`) regardless of what language it's scanning. A real commercial scanner (Semgrep,
Snyk, CodeQL) differentiates on target-language breadth, not implementation language —
that's the same standard applied here. The multi-language fixtures in
`vulnerable-demo-multilang/` and the 31 tests in `tests/test_multilang_scanner_patterns.py`
verify **static text consistency** between the scanner's documented patterns and the
fixture files — not that the scanner was actually run live against Java/Go/PHP/Node code,
since no runtime for those languages was available in the environment this was built in
(see [KNOWLEDGE_TRANSFER.md §11.1](../KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened)).

### Is this SOC2/NIST/PCI compliant?

No. That's an audit/certification question, not a code question. SOC2 requires an audit
by a licensed CPA firm over months of operational evidence; NIST CSF alignment is a
self-attestation or third-party assessment; PCI has its own formal validation process.
No repository, however well-built, can claim any of these on its own — doing so would be
a legal/regulatory risk, not a feature gap (see
[KNOWLEDGE_TRANSFER.md §9, Tier 3](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)).
This repo can build toward the underlying *controls* (audit logging, least-privilege tool
scoping, etc.) that a real compliance program would also need — see
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for an informational (not certifying) map
of which existing capabilities relate to which control category, and what's still missing.

### Does it support multiple tenants/clients (MSSP)?

There's a tenant switcher in the dashboard sidebar (`dashboard/static/js/tenant.js`) —
"All Tenants (MSSP view)", "Acme Financial Corp (demo)", "Northwind Bank (demo)" — that
partitions the same real findings by asset-type category, so the Remediation Queue page
demos what an MSSP-style per-client view could look like. **This is explicitly a UI-only
illustration, not real per-tenant authentication or data isolation**: there is one
process, one dataset on disk, and no auth layer at all — anyone who can reach the
dashboard's port can switch "tenants" freely and see everything regardless of which one
is selected. A banner on the Queue page repeats this whenever a non-"All" tenant is
active. Building *real* multi-tenant MSSP support needs a database and an auth/RBAC layer
first — a business/architecture decision, not something that can be bolted onto the
current filesystem-reading MVP incrementally without rebuilding it. See
[KNOWLEDGE_TRANSFER.md §11](../KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)
and its subsection
[§11.1](../KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened)
for the full reasoning on what's real here and what isn't.

### What happens to my data / where does it live?

Everything is local files in this repository — git history, JSON, YAML, Markdown. There
is no cloud service and no telemetry:

- Scan findings: `SECURITY_REPORT.md` in the scanned repo, committed to a local branch by
  `vuln-fixer` if you run `--fix`.
- Remediation data: `remediation/output/normalized-findings.json` and generated `.yml`
  playbooks, `REMEDIATION_PLAN.md` at the project root.
- Live connector output (if you use real Tenable/Armis credentials):
  `remediation/live-data/` — gitignored, since it's real vulnerability data about real
  infrastructure and must never be committed.
- CLI audit logs: `.vulnhunter/logs/*.json` — gitignored.
- The only network calls anything in this repo makes on your behalf are: the real Claude
  API (when you actually run a pipeline, not on `--dry-run`), CISA's KEV feed and
  FIRST.org's EPSS API (free, no-auth, during `/remediate`'s enrichment stage), and
  whichever of Tenable/Armis/ServiceNow you explicitly configure credentials for.

### How much does running a real scan cost?

It calls the real Claude API, which costs real money against your Claude usage/plan.
`cli/vulnhunter.py` applies a `--max-budget-usd` spend cap (default `$2.00`) to every real
invocation as a safety net, but that default is not a guarantee it fits your budget or
your plan's actual pricing — you're responsible for understanding what a
`/vulnhunt --fix` or `/remediate --generate` run costs before running it unattended (e.g.
on every CI push). Always run `--dry-run` first to see exactly what would execute without
spending anything. Full detail: [cli/README.md](../cli/README.md)'s "Cost warning"
section.

### What if I find a bug or need help?

See [SUPPORT.md](SUPPORT.md) — the short version: open a GitHub issue on this repo for
bugs/features, use the private contact in [SECURITY.md](../SECURITY.md) for security
issues, and check [KNOWLEDGE_TRANSFER.md §12](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)
first for known environment gotchas (Docker unavailability, GitHub secret-scanning
false-positives on fake demo credentials, etc.) before filing something that's already
documented.
