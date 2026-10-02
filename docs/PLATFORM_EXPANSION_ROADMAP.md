# From vulnerability management to integrated risk management: audit and roadmap

This page answers six questions with evidence: what the remediation engine can and cannot do today for each
kind of finding, whether analysts get guidance, and how threat modelling, GRC, threat hunting / SOC, and AI
usage analytics could be built into the same application. The first half is an audit of the code as it is; the
second half is a researched plan. Sources are linked at the end.

## 1. What Quanta does today, by finding type

Legend: **Real** = implemented and tested. **Partial** = exists but limited. **None** = not there.

| Finding type | Ingest | Fix | Analyst guidance (before this change) | Main gap |
|---|---|---|---|---|
| Infrastructure OS / network / cloud | Real (Tenable, Qualys, OpenVAS, Prisma, XSIAM, CSV, push API) | **Real for Windows, Unix, OT** (reviewable Ansible playbook or isolation plan, lint-gated, approval, rollout rings, rescan verification). None for network devices, cloud, certificates, endpoints | One sentence from the scanner | No network / cloud / certificate fixers |
| SCA (dependencies) | Real (SBOM-aware) | Partial: an upgrade *plan*, no manifest edit or pull request | Plan steps; the vendor line is often "see advisory" | No ecosystem-specific automation, no reachability |
| Secrets in code | Real (Quanta's scanner and repo alerts) | Real for code (move to environment variable on a branch); rotation is advice only | Thin | No vault integration or automatic rotation |
| SAST | Real for Quanta's *own* scanner only | Real for mechanical cases (SQL injection, secrets, `eval`, Docker `USER`, debug flag) on a branch | Report file only; the dashboard showed no fix detail | **No third-party SAST connector** (Semgrep, SonarQube, CodeQL); SAST not in the queue / SLA / ownership flow |
| DAST | Partial (accepted via push API; no scanner connector) | None | One line if the sender supplied it | No ZAP / Burp / Nuclei connector, no endpoint-to-source mapping |
| Container / base image | Partial (Dockerfile rules; sample runtime alerts) | Partial (add non-root `USER`) | Thin | No image-scan connector (Trivy, Grype), no base-image tracking |
| IaC (Terraform / Kubernetes) | Partial (asset type exists; sample rows only) | None (no fixer) | Sample text only | No Checkov / tfsec connector, no fixer |
| CI/CD pipeline | **None** | None | None | No pipeline checks at all |
| Code / test coverage | **None** (deliberately out of scope so far) | None | None | No coverage ingestion |

Cross-cutting: the code-scan path and the queue path do not share a schema; `scan_type` is inferred from asset type
rather than recorded; and **no fixer ever executes anything** by design (artifact generation only).

### Analyst guidance: now built

Before: guidance was whatever the scanner said, text a model wrote per run, or generic keyword controls. The code
scan page did not show the fix at all.

Now (`remediation/guidance/`): a **curated knowledge base of 29 entries** (injection, XSS, access control,
authentication, cryptography, secrets, dependencies, containers, IaC, CI/CD, test coverage, patching, network,
OT, cloud, TLS, AI/ML, end-of-life) written from OWASP cheat sheets, CIS, NIST and CISA guidance, plus a generic
fallback that is labelled generic. Each entry has ordered steps, how to confirm the fix, what to do if it cannot
ship now, effort, and references. The engine matches by CWE, then scan type, asset type and keywords, and says
why. It then **tailors** the guidance with what Quanta knows about the finding: the package and fixed version with
the usual upgrade command, the Windows KB and `Get-HotFix` check, the Linux package check, CISA KEV status and due
date, EPSS, a breached SLA, and the scanner's own recommendation (hidden when it is just "see vendor advisory").
It shows in the finding detail ("How to fix this") and on the Code Scan page ("How to fix" per row), and it states
plainly what Quanta can automate for that finding. It is deterministic, reviewable and editable by your own team.
Limits: it covers the common classes, not every CWE; an unrecognised finding gets the general approach.

### Compensating controls specific to the client's infrastructure

Today the control text is **generic** (keyword rules). The *mechanism* for client-specific controls exists
(`control_coverage.py` computes existing coverage, recommended additions and residual risk per asset from a
firewall-and-EDR file, and `network_reachability.py` traces the path to the internet), but both input files **ship
empty and are hand-maintained**, so by default nothing is client-specific. Guidance now uses them when present and
says when they are not.

Making it genuinely client-specific is a data problem, not a modelling one:

1. **Populate the inventory automatically** instead of by hand: pull security-group and firewall rules from the cloud
   and firewall APIs, EDR policy and sensor state from CrowdStrike / Cortex, WAF rules from the WAF, and topology
   from Infoblox / Axonius / cloud networking. Store them in a `controls` table (asset, control class, state, source,
   last seen) rather than YAML.
2. **Derive candidate controls from the technique, not from keywords**: map the finding's CVE / CWE to ATT&CK
   techniques, and take the *mitigations* MITRE publishes for each technique (and NIST 800-53 control families) as the
   principled candidate set. That replaces guesswork with a citable list.
3. **Subtract what is already in place** (the client's inventory), recommend the missing ones, and compute residual
   risk. Be explicit that an unverified control is "claimed", and only a control observed by a connector counts as
   "verified".
4. **Say what it cost to be wrong**: a compensating control lowers risk, it does not close the finding; exceptions
   carry an expiry and re-review.

## 2. Threat modelling

**What it is**: structured identification of how a system can be attacked, before and independent of any scanner
finding. The established methods are STRIDE per element of a data-flow diagram, attack trees, PASTA and VAST; the
established open tools are OWASP Threat Dragon (diagram, rule-suggested STRIDE threats, model stored as code),
pytm (model in Python) and Threagile (model as YAML, runs risk rules, produces a risk report and diagrams).
Recent work adds LLM-assisted generation (STRIDE-GPT, multi-agent attack-tree generation) and extensions for
agentic AI systems; those need human review.

**What Quanta uniquely has**: live data about the estate (assets, owners, network topology, SBOMs, IaC, findings,
KEV / EPSS). Most threat-modelling tools start from a blank diagram; Quanta can start from the real system.

**Plan** (each stage ships on its own):
1. **Model as data.** A `threat_models` store: a system = components, data stores, data flows, trust boundaries,
   data classification, and the assets they run on. Import / export Threagile YAML and Threat Dragon JSON so teams
   keep their tools.
2. **Auto-seed from Quanta's data.** Draft the diagram from the asset inventory, `network_topology`, SBOM, IaC and cloud
   connectors; mark every inferred element as "inferred" until a person confirms it.
3. **Rule engine.** STRIDE per element and per trust-boundary crossing, plus Threagile-style architecture risk rules,
   mapped to ATT&CK techniques and CAPEC patterns, each threat with likelihood / impact in the same scoring
   vocabulary the queue uses.
4. **Join to reality.** A threat is linked to the live findings that would let it happen, so its risk moves when a KEV
   finding appears on a component; and to the controls that mitigate it, so unmitigated threats are visible.
5. **LLM assistance, clearly labelled.** Suggest additional threats and attack trees from a description or diagram; they are
   proposals with a "suggested, unreviewed" state and never silently change a model. Include the OWASP LLM Top 10 and
   agentic-AI threats for AI components.
6. **Re-model on change.** When the architecture (IaC diff, new asset, new internet exposure) changes, flag the model
   as stale and show what is new.

## 3. GRC (governance, risk, compliance)

**Core modules of a GRC platform** (from the market survey): a control library mapped across frameworks, a risk
register, policy management and attestations, evidence collection and continuous control monitoring, an
audit / assessment workflow, and reporting. Modern platforms collect evidence through read-only APIs rather than
screenshots, and NIST's **OSCAL** gives machine-readable catalogs, profiles, assessment plans and results, so
controls and audit outcomes can be exchanged as data.

**What Quanta already has that GRC needs**: exception and risk-acceptance workflow with expiry and approval, a
remediation approvals workflow, an append-only audit log, SLAs, ownership and teams, a support (ITSM) desk,
asset inventory, and a conceptual compliance map (`docs/COMPLIANCE_MAPPING.md`) that nothing in code consumes.
It does **not** have a risk register, a control catalog, evidence collection, policy library or attestations.

**Plan**:
1. **Framework and control catalog** loaded from OSCAL (NIST 800-53 and CSF 2.0 are published; licensed
   standards such as ISO 27001 are customer-supplied), with a crosswalk table for one-to-many mapping.
2. **Risk register** with inherent and residual risk, owner, treatment (accept / mitigate / transfer / avoid), review
   date and key risk indicators. Risks are *fed* by findings, threat-model threats and exceptions, not typed in
   from scratch.
3. **Controls tested by evidence.** Each control gets automated checks that read Quanta's own data: patching within
   SLA, scan freshness, exceptions with expiry, privileged-access reviews, backup of the audit log. Every result is a
   timestamped evidence record linked to the control and the period.
4. **Assessments and attestations.** Assessment campaigns, control owners attesting, findings from assessments flowing into the
   same remediation and ticketing machinery; export OSCAL assessment results for auditors.
5. **Policy library** with versions, owners and acknowledgement tracking.
6. **Be explicit about scope.** Quanta supplies evidence and workflow; it does not certify compliance, and the docs must keep saying so.

## 4. Threat hunting and SOC analyst capability (later phase)

**Boundary first.** Quanta is not a SIEM and should not try to become one. The sensible position is
*exposure-aware* hunting and triage: it knows which assets carry exploitable, internet-reachable vulnerabilities,
which a SIEM does not.

**Methods to build on**: hypothesis-driven hunting with the PEAK (Prepare, Execute, Act) and TaHiTI (initiate,
hunt, finalize) frameworks, with MITRE ATT&CK as the taxonomy and Sigma as the portable detection format. For
data, OCSF is the open schema being adopted to normalise telemetry across SIEM, SOAR and XDR.

**Plan**:
1. **Vulnerability-driven hunt generation**: for each KEV-listed or high-EPSS CVE present in the estate, create a
   hunt hypothesis ("exploitation of CVE-X on these assets") mapped to ATT&CK techniques, with the affected assets and a
   Sigma rule or query set attached.
2. **Hunt workspace**: hypothesis, scope, data sources, queries run (translated to the customer's SIEM with pySigma, run
   *there* through the existing Splunk / XSIAM connectors), results, outcome (confirmed / not found / needs data), and
   follow-ups. Reuse tickets, assignments and the audit log.
3. **Alert triage with context**: ingest alerts (XSIAM already supplies incidents; add an OCSF-based path) and enrich each
   with the asset's open vulnerabilities, KEV status, owner, exposure and attack path. A triage queue and case view
   built on the existing ITSM desk.
4. **Runbooks**: guided response steps for common alert types using the same curated-knowledge pattern as the
   remediation guidance; execution stays with the customer's SOAR.
5. **Hunt metrics**: hunts completed, detections created from hunts, coverage of ATT&CK techniques that matter to the estate.

## 5. AI token and usage analytics

**Today**: Quanta records tokens (input, output, cache) and cost per Claude call it makes itself, shows a per-user
table in Admin Settings, and enforces a per-user daily token cap. It does **not** capture anything outside Quanta's own
four AI routes, has no per-team or per-model view, no dollar budgets or alerts, and its own CLI runs are not logged.

**How to capture AI usage across an organization** (from the research): there are four evidence sources, and a complete
picture combines them.
1. **A gateway / proxy** that applications and agents call instead of the provider. It sees every request, so it records
   tokens, model, latency and cost per key / team / application and can enforce budgets and model allow-lists. This is the
   most accurate source for AI that goes through it.
2. **Provider usage and cost APIs** (the vendors' admin / usage endpoints, Azure OpenAI and Bedrock metrics in the cloud
   provider, Vertex) pulled on a schedule by connectors. Covers usage that bypasses the gateway, at organization or
   workspace granularity.
3. **OpenTelemetry GenAI telemetry**: applications already instrumented with the OpenTelemetry GenAI semantic
   conventions (`gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`) can send it to an OTLP
   receiver in Quanta. Cost is derived from a maintained price table.
4. **Discovery of unsanctioned use ("shadow AI")**: compare the approved list with identity-provider and OAuth consent
   records, CASB / proxy / DNS logs for AI domains, browser-extension inventories, and cloud billing for AI services.

**Plan**: generalise `ai_usage_log` into an `ai_usage_events` table (source, organisation unit, team, application, model,
input / output / cache tokens, cost, latency, time, hashed user); never store prompt or response text by default.
Analytics: spend and tokens by team / application / model / day, cache-hit rate, top consumers, anomaly alerts, USD
budgets per team with threshold alerts, a model allow-list report, and a shadow-AI list with owners to confirm or
block. Because Quanta already governs AI use inside the product, this extends an existing control rather than adding a new product.

## 6. Recommended order and the unifying idea

The thing that makes this one application rather than five is a **single entity graph**: assets, vulnerabilities,
threats, controls, risks, evidence, tickets and people, all linked. A finding raises a risk; a threat is realised by
findings and mitigated by controls; a control produces evidence; a risk has an owner and a ticket. Build the links
once and every module reuses them.

| Phase | Deliver | Why this order |
|---|---|---|
| 1 | Analyst guidance (**done**); SARIF + CycloneDX ingest for Semgrep, CodeQL, ZAP, Trivy, Checkov, gitleaks; CI/CD pipeline checks (OWASP CI/CD risks); explicit `scan_type`, `location` fields | Closes the coverage gaps the audit found; SARIF is one adapter for many tools |
| 2 | Controls inventory populated by connectors; ATT&CK-mitigation-based client-specific compensating controls | Makes compensating controls real; needed by threat modelling and GRC |
| 3 | AI usage analytics (gateway, provider APIs, OTel, discovery) | Self-contained, high demand, builds on existing governance |
| 4 | Threat modelling (model as data, auto-seed, STRIDE rules, join to findings and controls) | Needs phase 2 data to be valuable |
| 5 | GRC (catalog, risk register, evidence, assessments) | Consumes risks and controls from phases 2 and 4 |
| 6 | Threat hunting and SOC triage | Largest scope, needs the graph and the SIEM connectors; keep the boundary with SIEM |

Honest risks: breadth can dilute depth, and each phase should be shippable and demonstrably useful alone;
every connector remains unproven against a live tenant until a pilot; and AI-assisted outputs must stay labelled
as suggestions.

## Sources

- OWASP Threat Dragon, pytm and Threagile overview: https://versprite.com/threat-modeling-tools/threat-modeling-tools-compared/ and https://github.com/Threagile/threagile
- STRIDE-GPT: https://github.com/mrwadams/stride-gpt ; ASTRIDE for agentic AI: https://arxiv.org/pdf/2512.04785 ; multi-agent attack-tree generation: https://arxiv.org/pdf/2607.27528
- GRC platform modules and framework mapping: https://www.centraleyes.com/best-grc-tools/ ; OSCAL and continuous monitoring: https://regscale.com/continuous-monitoring-built-on-oscal/ and https://csrc.nist.gov/projects/open-security-controls-assessment-language
- PEAK and TaHiTI hunting frameworks: https://expel.com/cyberspeak/what-are-threat-hunting-frameworks/ and https://hunt.io/glossary/tahiti-threat-hunting-framework
- OCSF: https://github.com/ocsf/ocsf-schema
- OpenTelemetry GenAI conventions and LLM cost tracking: https://opentelemetry.io/blog/2026/genai-observability/ and https://www.honeycomb.io/resources/getting-started/how-to-track-token-cost-across-llm-workflows
- Shadow AI discovery signals: https://www.token.security/blog/detect-shadow-ai-enterprise and https://www.flexera.com/blog/ai/enterprise-ai-governance-guide/
- OWASP Top 10 CI/CD risks and cheat sheet: https://owasp.org/projects/top-10-cicd-security-risks and https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html ; SLSA: https://slsa.dev/
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
