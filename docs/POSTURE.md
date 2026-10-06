# Security Posture Review

`/posture` (Risk, Governance & Compliance module, administrator only) assesses the estate Quanta has recorded, and this Quanta deployment itself, against ten frameworks, and turns every gap into a concrete next step
with the exact setting that closes it. It reads what Quanta already holds and advises; it changes nothing.

## What it assesses

| Framework | Standard it follows | Areas | Checks |
|---|---|---|---|
| Zero trust | CISA Zero Trust Maturity Model 2.0 (NIST SP 800-207) | identity, devices, networks, applications, data, visibility, automation, governance | 25 |
| Secure by design | CISA Secure by Design principles, plus this deployment's own hardening | ownership, transparency, leadership, hardening | 27 |
| Threat modelling | OWASP threat-modelling guidance, ASVS | coverage, quality, treatment, currency | 12 |
| Defence in depth | layered controls | perimeter, network, host, application, data, identity, monitoring, response | 14 |
| Architecture review | exposure, concentration, ownership, segmentation, resilience | | 16 |
| Secure development lifecycle | NIST SSDF (SP 800-218) | prepare, protect, produce, respond | 18 |
| AI development lifecycle | NIST SP 800-218A, OWASP Top 10 for LLM applications (2025) | govern, data, model, deploy, operate | 30 |
| Software supply chain | SLSA v1.1, OpenSSF Scorecard | inventory, integrity, provenance, delivery | 16 |
| AI supply chain | CycloneDX ML-BOM, MITRE ATLAS | models, tools, data, providers, assurance | 24 |
| Open-source dependencies | exposure, exploitation, remediation, hygiene | | 12 |

194 checks in all. Each reads recorded data (findings, the firewall, controls, applications and SBOMs, the API inventory, threat models, the AI register, the identity roster, GRC records, scan runs, gate decisions,
connections) or this deployment's environment settings. Nothing is probed or scanned.

## How a check answers

`pass` (in place), `partial` (in place for some of the estate, with the share), `fail` (shown not to be in place, with the data that proves it), `unknown` (nothing recorded could answer it) and `na`.

- **Unknown is never a pass.** An estate with nothing recorded gets unknowns, not good scores. Unknown and not-applicable checks are left out of the score and listed on the Overview as "Not observable", with what to record or connect.
- **Some things cannot be observed from here and say so:** build provenance and signing (SLSA levels), backups, training-data provenance, model evaluation and red-team results, model weight integrity, end-of-life components, Quanta's own SBOM and dependency vulnerabilities, MFA enforcement.
- **A score appears only when enough was observable.** If less than 30% of a framework's check weight could be observed, it shows "not enough recorded to score" and lists what to connect.

## Scores, stages and actions

A framework's score is the weight-averaged score of the checks that could be observed, 0 to 100. The stage (Traditional, Initial, Advanced, Optimal) borrows the CISA maturity vocabulary. **These numbers are Quanta's own summary: none of the standards publishes a score.**
Thresholds, the 30% minimum, the stage boundaries and shared limits (stale after 90 days, known-exploited open 14 days, Critical open 30 days, SBOM age, coverage, administrator count) are in `remediation/config/posture_policy.yaml`.

The action list ranks every gap by `weight x the gap that remains`, one action per distinct setting, highest first. Each action names where the change is made: an environment variable, a config file key, a Helm value, a Quanta page or a process.

## This deployment (secure by design, hardening area)

Seventeen checks read the deployment's own settings: production mode, session secret length (presence and length only, never the value), credential encryption key, TLS, Content-Security-Policy, login required for reads,
demo accounts still using the published password, API keys without expiry, licence mode, OIDC, number of administrators, recent audit activity, database backend, webhook secrets, and a bootstrap password left in the environment.
Secret values never appear in any result (tested).

## Adding a check or a framework

A framework is a module in `remediation/posture/` exposing `FRAMEWORK` (id, title, summary, areas, refs) and `run(ctx) -> list[check]`; register its name in `FRAMEWORK_MODULES` in `__init__.py`. Build each check with `model.check(...)`,
read data through `ctx.get(key, loader)` (cached; an unreadable source becomes "unknown", not an error), use `ctx.thr` for thresholds and `ctx.now` for ages (never the clock), and name only settings that exist
(the tests assert that a cited env var or YAML key really appears in the file it names).

## Honest limits

It reads recorded data, so it is only as good as what is connected. It does not scan hosts, run code, or verify a control works: "verified" in the controls inventory is a person's record, not a test. The framework mappings are Quanta's reading
of each standard, not a certification or audit. The scoring is a disclosed choice. It has not been checked against an independent assessment of a real estate.
