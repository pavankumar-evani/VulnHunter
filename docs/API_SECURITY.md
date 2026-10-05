# API security

Quanta's API Security area (page `/api-security`, administrators only) builds an inventory of your APIs, checks it against the OWASP API Security Top 10 (2023), investigates who reached what, aligns data sensitivity to **your own** classification framework, and manages runtime-protection policies that **you** apply. Code: `remediation/apisec/`; thresholds, patterns, detectors and the rollout checklist: `remediation/config/api_security.yaml`.

**What it is not.** Quanta cannot sniff traffic: it reads what it is given (specifications, access-log exports, pushed records, CI results). It never changes a WAF, gateway or any customer system. Everything is built against public documentation and unit-tested with sample data; none of it has been run against a live gateway, WAF, CI system or traffic source.

## 1. Inventory and discovery

* **Specifications**: upload OpenAPI 3.x / Swagger 2.0 (JSON or YAML) on the Import tab, fetch from a URL (outbound, so it asks for confirmation; SSRF-guarded; redirects not followed), or send from a pipeline: `POST /api/ingest/openapi?service=shop-api` (API key scope `api:write`).
* **Traffic**: upload an access-log export (JSON lines, JSON array, common/combined log format, CSV) or push records with `POST /api/ingest/api-traffic`. Gateway field names are matched through aliases (`httpMethod`, `resourcePath`, `responseLatency`, ...). Time units: `latency_ms`/`duration_ms`/`responseLatency` are milliseconds, `request_time`/`upstream_response_time` seconds, a bare `latency`/`duration` milliseconds.
* **Kept**: method, path template (identifiers become `{id}`), status, timing, byte counts, caller identity, client address, and the *names* of query parameters and of request/response fields. **Never kept**: query values, bodies, header values, tokens (a bearer token is decoded in memory for its algorithm and lifetime, then dropped; a sampled response payload is classified in memory and dropped).
* **Per endpoint**: exposure (external when public client addresses were seen, internal when only private ones, or set by a person), authentication mechanisms observed and declared, data returned under your classes, owner, status, daily metrics.
* **Drift**: observed but undocumented endpoints are **shadow** (only when a spec for that service exists; with none the service is listed as a gap instead); documented but never seen are listed; deprecated-but-live and long-unseen endpoints are reported.
* **Generated specification**: `GET /api/api-security/generated-spec?service=` builds an OpenAPI 3 document from observed traffic. It states only what was seen (types and required-ness are unknown and left blank).

## 2. Authentication, authorization, identity

Rules raise indicators, not proof: unauthenticated successes on non-public paths, tokens with `alg: none` (Critical if such requests succeeded), no expiry, long lifetime, `jku`/`x5u` headers, shared-secret signatures, credentials in URLs, object enumeration by one caller (BOLA indicator), admin-looking paths reachable externally (BFLA indicator).

The **Callers** tab joins identity to endpoints reached, volume, bytes returned, distinct objects and your data classes, with indicators for volume, exfiltration, enumeration and probing. Identities can be stored hashed (`actor_handling: hash`). A draft protection policy can be created from an investigation; it is never saved or sent automatically.

## 3. Your data classification

Quanta ships **no** sensitivity taxonomy. Import your framework (JSON or CSV: name, priority where 1 is most sensitive, detectors, your own field-name patterns). Built-in *detectors* only say what kind of data a field/value looks like (email, payment card with Luhn check, national identifier, ...). Data that maps to none of your classes is reported as **unclassified**, never assumed sensitive or harmless. Classes at priority ≤ `severity.sensitive_priority_max` lift finding severity by one level.

## 4. OWASP API Security Top 10 (2023) findings

Each finding has the category, severity, endpoint, an **evidence chain** (ordered observations with their source: specification, traffic, classification, policy) and, where a request can confirm it, a **cURL** built only from placeholders (`${TOKEN}`, `${OTHER_USERS_OBJECT_ID}`) so a developer can confirm a true or false positive against a system they are authorised to test. Paths with characters unsafe for a shell produce no command. Findings publish to the main queue (`POST /api/api-security/publish`, confirm-gated, source `api-security`, scan type DAST, complete set so fixed findings leave) and receive curated fix guidance by rule id (`remediation/guidance/knowledge.yaml`, entries `api-*`).

| Category | Raised when |
|---|---|
| API1 BOLA | one caller touches ≥ N distinct object ids on an id-addressed endpoint in a day |
| API2 Broken authentication | unauthenticated success on a non-public path; JWT weaknesses; credential in URL |
| API3 Property level | sensitive properties returned that the spec does not declare; privileged request fields undeclared |
| API4 Resource consumption | one caller dominates with no rate-limit policy; large unpaged responses |
| API5 Function level | admin-looking path reachable from public addresses |
| API6 Business flows | sensitive flow (login, checkout, reset...) at automation volume with no rate limit |
| API7 SSRF | URL-like parameters |
| API8 Misconfiguration | plain HTTP observed |
| API9 Inventory | shadow endpoints; deprecated endpoints still live |
| API10 Unsafe consumption | third-party dependency from a service that serves your sensitive data |

## 5. Shift-left testing in CI

Run an API security tester of your choice against staging, then post results (`POST /api/ingest/api-test-results`, scope `api:write`). Format and ready-to-use GitHub Actions and GitLab CI examples are on the **CI and rollout** tab (`GET /api/api-security/ci-templates`). The response carries `gate.passed` (fail on `ci.fail_on`, default High; override `?fail_on=`; `?report_only=true` to start without blocking); failures become queue findings (source `api-ci-<repository>`; `?reconcile=true` for a complete result set); a run counts as evidence for the DevSecOps control `api-security-testing`. A SARIF file can go to `/api/ingest/sarif?scan_type=dast` instead. Uploading the spec from the pipeline returns the drift against live traffic.

## 6. Runtime protection policies

Policies (rate limit, malicious sources, data-loss limit, geographic restriction, custom signature) are data: scope (endpoints/services), mode (**monitor** or **block**), parameters. They are validated (including that a data class is one of yours).

* New policies default to monitor. A **block** policy can be sent only after a *different* administrator approves that exact version; any edit voids approval.
* **Send to my endpoint** posts a signed request (`X-Quanta-Timestamp`, `X-Quanta-Signature: sha256=` HMAC of `timestamp.body`, `X-Quanta-Delivery`) to a URL you own (connection type *API protection policy endpoint*, same signing as the SOAR response webhook). Confirm-gated; the preview shows the exact payload. Your automation verifies the signature and applies, adjusts or rejects it.
* Your automation reports the edge result with `POST /api/inbound/api-policy-status` `{"push_id", "status": "applied"|"rejected", "detail"}` (scope `api:write`).
* **Alerts**: every send and every reported result raises a per-policy alert on the notification webhook and, when SMTP and `QUANTA_ALERT_EMAIL` are set, by email, and is written to the audit trail (events and sends tables, shown on the page).
* **Review artifacts**: AWS WAF (WAFv2 rule + IP-set resources) and Google Cloud Armor rules, monitor → Count / preview. Data-loss limits are not expressible at an edge request filter (they count responses), and Cloud Armor custom rules cannot match bodies; the artifact says so rather than emitting something that looks protective. Generated from public rule formats, never validated against a live account.

## 7. Metrics

Per endpoint per day: calls, errors (status ≥ 400), exceptions (≥ 500), latency (average and maximum; no percentiles), bytes in/out, distinct callers, security events (from WAF/gateway fields). **Error rate = errors / calls**, computed, never stored. Trend compares the latest window with the one before and says nothing when either has too few calls.

## 8. Onboarding, rollout and roles

The **CI and rollout** tab holds the onboarding checklist (steps are ticked from data where Quanta can see them, otherwise stated by an administrator), two rollout orders (runtime protection first, or pipeline testing first, both editable in YAML), the maturity journey and who does what (SOC, AppSec, developers, API office, platform team). Quanta has an administrator role and an ordinary-user role with team scoping; developers see their team's API findings in the main queue after publishing. SSO (OIDC) code exists but has never been run against a live identity provider.
