# Connecting your tools to Quanta

There are two directions, and most deployments use both.

| Direction | Who starts it | Whose credential | Use it for |
|---|---|---|---|
| **Quanta calls the tool** (outbound) | Quanta, on a schedule | The **vendor's** API key, stored encrypted in Quanta under *Connections* | Pulling findings from Tenable, Qualys, Prisma Cloud, Cortex XSIAM, Infoblox, Axonius, Active Directory; opening tickets in ServiceNow and Jira; sending events to Splunk |
| **The tool calls Quanta** (inbound) | The tool, a pipeline or a person | A **Quanta API key** you issue, with only the access it needs | A scanner or SOAR playbook pushing findings, a CI job uploading an export, ServiceNow reporting a ticket change, a BI tool reading findings |
| **A file** | A person or a script | A signed-in admin, or an API key | A source that cannot be reached by API: export a CSV and import it |

Nothing here needs a code change. Machine-readable descriptions: `GET /openapi.json` (every route),
`GET /api/connections/schema` (every connection type as JSON Schema, admin only).

## 1. Outbound: connections

Admin → **Connections** → *Add a connection*. Choose the source, enter its credentials, test, set a schedule.
Credentials are encrypted with `QUANTA_ENCRYPTION_KEY` (held outside the database) and never shown again.
Each sync runs as a queued job, merges into the findings queue (a re-run updates rather than duplicates),
enriches with CISA KEV and EPSS, and is recorded in the activity log.

| Source | Kind | What you give Quanta | What you get |
|---|---|---|---|
| Tenable | pull | access key + secret key (an API user with read access) | host findings; a complete export, so fixed findings leave the queue |
| Qualys | pull | username, password, platform/API URL | host findings |
| Prisma Cloud | pull | access key id + secret, API URL | cloud posture findings |
| Cortex XSIAM | pull | API key + key id, FQDN | correlated detections |
| Infoblox / Axonius / Active Directory | pull | endpoint + credentials | asset inventory (owners and discovery), not findings |
| **ServiceNow** | **push** | instance name (`acme` for `acme.service-now.com`), integration user, password, and a **rule** | an incident per matching finding, and its state read back |
| **Jira Cloud** | **push** | site URL, account email, API token, project key, and a **rule** | an issue per matching finding, and its state read back |
| **Splunk** | **push** | HEC URL and token, and a **rule** | each matching finding as an event, once |

### Push rules: which findings become tickets

A push connection carries a rule, so "open an incident for every new Critical or KEV finding" is a setting:

| Field | Meaning | Default |
|---|---|---|
| `min_severity` | send findings at or above this severity | High |
| `kev_only` | only findings on the CISA KEV list | off |
| `min_epss` | only findings with at least this exploit probability (0 to 1) | none |
| `max_per_run` | most tickets per run, so a first sync cannot flood the service desk | 50 |

Each run picks matching findings not yet pushed through that connection, most urgent first (KEV, then EPSS,
then severity). ServiceNow incidents are keyed on `correlation_id` and Jira issues on a `quanta-<finding id>`
label, so a re-run never creates a duplicate. One failing finding does not stop the batch; its error is kept
on its link and it is retried on the next run.

### State coming back

Quanta keeps a link between each finding and its ticket. On every run it reads the current state of the open
ones and maps it to Quanta's four work states: ServiceNow `1` new → open, `2` in progress, `3/4/5` on hold or
awaiting → blocked, `6/7/8` resolved/closed/cancelled → resolved; Jira by *status category* (`new`,
`indeterminate`, `done`), which holds across custom workflows. If the finding has an assignment, its status
follows, so the owner's work is reflected without anyone copying a status by hand. A resolved ticket marks the
assignment resolved; it does **not** close the finding, because the next scan decides whether the
vulnerability is really gone. The finding's detail view lists its tickets and their state.

Prefer to be told rather than to poll? Have ServiceNow or Jira call the inbound endpoint below on update.

## 2. Inbound: Quanta API keys

Admin → **Connections** → *Create an API key*. Pick a name, the access it needs, and an expiry. The key is
shown once; Quanta keeps only a hash. Send it as `Authorization: Bearer qk_…` or `X-API-Key: qk_…`.
Revoke it at any time; it stops working immediately. Each key is rate limited (`QUANTA_API_KEY_RATE_MAX`,
600 a minute by default) and its use is in the activity log.

| Scope | Allows |
|---|---|
| `ingest:write` | `POST /api/ingest/findings`, `POST /api/ingest/scanner-csv`, and (in production) `POST /api/ingest/generic` |
| `tickets:update` | `POST /api/inbound/ticket-status` |
| `read:findings` | `GET /api/export/findings` |
| `api:write` | `POST /api/ingest/api-traffic`, `POST /api/ingest/openapi`, `POST /api/ingest/api-test-results`, `POST /api/inbound/api-policy-status` (see [API_SECURITY.md](API_SECURITY.md)) |

Only `/api/ingest/`, `/api/inbound/` and `/api/export/` accept a key in place of a browser login, and each
checks the key itself. Every other route still requires a signed-in user when `QUANTA_REQUIRE_LOGIN_FOR_READS`
is on. In production the older `/api/ingest/generic` webhook now requires an `ingest:write` key too.

### Push findings

```bash
curl -X POST https://quanta.example.com/api/ingest/findings \
  -H "Authorization: Bearer $QUANTA_KEY" -H "Content-Type: application/json" \
  -d '{
    "source": "my-scanner",
    "reconcile": false,
    "findings": [{
      "title": "OpenSSL heap overflow",
      "severity": "High",
      "asset": {"name": "web01", "ip": "10.0.0.5", "os": "Ubuntu 22.04"},
      "cve": "CVE-2024-1234", "cvss": 8.1,
      "source_ref": "scan-77-plugin-5120",
      "recommended_fix": "Upgrade openssl to 3.0.13"
    }]
  }'
```

Required: `title`, `severity` (Critical, High, Medium or Low; Moderate is accepted), `asset.name`. Everything
else is optional and anything Quanta can work out (asset type, remediation domain, dates, KEV and EPSS) it
does. Unknown extra fields are ignored. `source` is a short lowercase name for where the data comes from.

A finding is identified by `source` + asset + `source_ref` (your own id; the title if omitted) + CVE, so
sending it again **updates** it. Records are checked one at a time: a bad record is reported by index in
`errors` and does not reject the rest. `reconcile: true` says this request is the **complete** current export
for `source`: that source's findings missing from it are removed, which is how fixed vulnerabilities leave the
queue. A reconcile with any invalid record is refused whole, so a partial export can never delete data.
At most 5,000 findings per request.

### Upload a scanner export

```bash
curl -X POST "https://quanta.example.com/api/ingest/scanner-csv?source=tenable-export&reconcile=true" \
  -H "Authorization: Bearer $QUANTA_KEY" --data-binary @export.csv
```

The Tenable column layout (`Plugin ID, CVE, Risk, CVSS v3.0 Base Score, Host, IP Address, FQDN, OS, Name,
Synopsis, Solution, Port, Protocol, First Discovered, Last Observed`). Qualys and other scanners can export
or be transformed to it. The same upload is on the Connections page as *Import a scanner file* for an admin.

### Upload scanner results in SARIF

SARIF 2.1.0 is the common output of Semgrep, CodeQL, SonarQube (export), OWASP ZAP, Trivy, Grype, Checkov, tfsec,
KICS, gitleaks, Hadolint, actionlint and many others, so one endpoint covers SAST, DAST, SCA, secrets, IaC, container
and pipeline findings.

```bash
curl -X POST "https://quanta.example.com/api/ingest/sarif?source=semgrep&asset=shop-api&reconcile=true"   -H "Authorization: Bearer $QUANTA_KEY" --data-binary @semgrep.sarif
```

* `scan_type` (`sast`, `dast`, `sca`, `secrets`, `iac`, `container`, `cicd`) is worked out from the tool name; pass it to override.
* `asset` names the repository or application (a web scan uses the host in the URL when you give none).
* A finding keeps its identity through the tool's own fingerprint, or a hash of rule + file + code, so a moved line is not a new
  finding. `reconcile=true` says this file is the complete current result for that source, so fixed findings leave the queue.
* Severity comes from a numeric `security-severity` when the tool supplies one, otherwise the SARIF level (error = High,
  warning = Medium, note = Low). Suppressed results are skipped. Each finding keeps its file and line (or URL), rule id, CWE ids
  and the tool's own fix text, and shows them in the finding detail.
* The admin **Import a scanner file** button accepts a SARIF file as well as a CSV; `quanta-admin import-sarif FILE --source NAME` does it from the command line.

### Check your pipelines

```bash
python cli/quanta_admin.py scan-pipelines . --format sarif --out pipelines.sarif --fail-on High
curl -X POST "https://quanta.example.com/api/ingest/sarif?source=pipelines&scan_type=cicd&asset=shop-repo"   -H "Authorization: Bearer $QUANTA_KEY" --data-binary @pipelines.sarif
```

Deterministic rules over GitHub Actions workflows, GitLab CI files and Jenkinsfiles, mapped to the OWASP Top 10 CI/CD risks:
unpinned third-party actions, `pull_request_target` that checks out the pull request, untrusted event data in `run:` scripts,
token permissions left broad, secrets echoed or written into the file, self-hosted runners reachable from pull requests, and
downloads piped into a shell. Each finding has the file and line and a fix, and a missing `permissions:` block comes with a
ready patch. It reads the file only: branch protection, approvers and runner settings are outside it, so a clean result means
"no file-level weaknesses", not "secure".

### Upload test coverage

```bash
curl -X POST "https://quanta.example.com/api/ingest/coverage?source=coverage&asset=shop-api&threshold=60"   -H "Authorization: Bearer $QUANTA_KEY" --data-binary @coverage.xml
```

Cobertura XML, JaCoCo XML or lcov. Only files whose path suggests security-relevant code (authentication, authorization, sessions,
cryptography, validation, payments, uploads, parsers) and that fall below the threshold become findings; the response also gives
the overall percentage. The path match is a heuristic on file names.

### Report the security controls you observe

An EDR, firewall or cloud-posture integration can tell Quanta which controls protect which assets, which is what makes
compensating-control advice specific to your environment (see *Security Controls* in the app).

```bash
curl -X POST https://quanta.example.com/api/ingest/controls   -H "Authorization: Bearer $QUANTA_KEY" -H "Content-Type: application/json"   -d '{"source": "falcon", "controls": [
        {"asset_name": "WEB-*", "control_class": "edr", "name": "CrowdStrike Falcon, prevention on"},
        {"asset_name": "WIN-DC01", "control_class": "network-filtering", "name": "Perimeter firewall, deny by default"}]}'
```

Needs a key with `controls:write`. `control_class` is one of `patching`, `vuln-scanning`, `exploit-protection`, `network-segmentation`,
`network-filtering`, `access-restriction`, `least-privilege`, `sandboxing`, `edr`, `app-control`, `disable-feature`, `mfa`,
`password-policy`, `audit-logging`, `encryption`, `os-hardening`, `web-filtering`, `secure-development`, `threat-intel`,
`user-training` (`GET /api/controls` lists them with labels). `asset_name` may be a pattern such as `WEB-*`. Reported controls are
stored as **verified**; ones typed in or imported as CSV on the Controls page are **claimed**. Sending the same one again refreshes it.

### Report AI usage

AI usage across the organization (the *AI Usage* page) is built from four kinds of source. Quanta stores counts, models, times and
attribution only, never prompts or responses.

* **Provider usage APIs.** Add an *Anthropic usage* or *OpenAI usage* connection on the Connections page with that provider's **Admin**
  key (a workspace or project key does not work). Quanta pulls daily token counts by model and workspace or project on a schedule;
  re-pulls update the same buckets.
* **A gateway, proxy or script** posts events:

```bash
curl -X POST https://quanta.example.com/api/ingest/ai-usage   -H "Authorization: Bearer $QUANTA_KEY" -H "Content-Type: application/json"   -d '{"source": "gateway", "events": [{"ts": "2026-10-01T10:00:00Z", "model": "claude-sonnet", "provider": "anthropic",
        "team": "Platform Engineering", "application": "support-bot", "user_ref": "u-017",
        "input_tokens": 1200, "output_tokens": 300, "cache_read_tokens": 800, "event_key": "req-8841"}]}'
```

  Needs a key with `ai-usage:write`. Send an `event_key` (a request id) so a re-send updates instead of doubling. Send a pseudonymous
  `user_ref` (a hash) if people should not be identifiable. `cost_usd` is optional.
* **OpenTelemetry.** Point an OTLP/HTTP **JSON** exporter at `POST /api/ingest/otlp/v1/traces` with the same key
  (`OTEL_EXPORTER_OTLP_PROTOCOL=http/json`). Spans carrying the GenAI attributes (`gen_ai.request.model`, `gen_ai.usage.input_tokens`,
  `gen_ai.usage.output_tokens`) become events; `service.name` is the application. Protobuf is not read.
* **Unreviewed AI tools.** Upload a proxy, DNS or CASB export on the AI Usage page (CSV with `domain`, optional `user` and `count`,
  or any text log). Hostnames that match the list of known AI services (`remediation/config/ai_domains.yaml`) become applications to mark
  sanctioned, unreviewed or blocked. Quanta records and reports; it does not block.

**Cost** is shown only where it is known: reported by the source, or estimated from prices you enter in `remediation/config/ai_pricing.yaml`
(shipped empty on purpose; contracts differ and a wrong figure is worse than a blank). Everything else is counted as "unknown cost", never as
zero. **Budgets** (organization, team or application; day, week or month; dollars and/or tokens; warn at a percentage) show used,
projected and state. Unusual days are flagged against the median of the days before (`ai_usage_policy.yaml`), and `allowed_models` lists
usage of any model outside your approved set. Quanta's own Claude calls are included as source `quanta`.

### Send SIEM or XDR alerts for triage

```bash
curl -X POST https://quanta.example.com/api/ingest/alerts   -H "Authorization: Bearer $QUANTA_KEY" -H "Content-Type: application/json"   -d '{"alerts": [{"external_id": "ALERT-1042", "source": "splunk", "title": "Shell spawned by w3wp.exe", "severity": "High",
       "asset": "WEB-1", "technique": "T1190", "detail": "w3wp.exe started cmd.exe", "occurred_at": "2026-10-02T09:14:00Z"}]}'
```

Needs a key with `soc:write`. An alert is unique per `source` + `external_id`, so a re-send changes nothing. `technique` is an ATT&CK id and
`asset` is the host name Quanta knows it by; both are optional but are what lets Quanta add context. Severity is Critical, High, Medium, Low or
Informational. Quanta ranks the triage queue by the alert's severity plus what it knows about the host (known-exploited vulnerabilities, a
vulnerability matching the technique, a high exploitation probability, no recorded owner) and lists the reasons. It never changes the alert's own
severity and never decides that an alert is real. Closing an alert needs a disposition.

### Report a ticket's state

```bash
curl -X POST https://quanta.example.com/api/inbound/ticket-status \
  -H "Authorization: Bearer $QUANTA_KEY" -H "Content-Type: application/json" \
  -d '{"finding_id": "FIND-42", "system": "servicenow", "state": "2", "external_ref": "INC0012345"}'
```

`system` is `servicenow`, `jira` or `other`. `state` is a ServiceNow number or word, a Jira status category or
name, or one of `open`, `in_progress`, `blocked`, `resolved`. In ServiceNow, a business rule or Flow on the
incident table that calls this URL when `state` changes is enough; use the finding id Quanta put in the
incident's `correlation_id`.

### Send API specifications, traffic and CI test results

Scope `api:write`. Full behaviour in [API_SECURITY.md](API_SECURITY.md).

```bash
# An OpenAPI/Swagger document (raw body); the response includes the drift against observed traffic
curl -X POST "https://quanta.example.com/api/ingest/openapi?service=shop-api" \
  -H "Authorization: Bearer $QUANTA_KEY" --data-binary @openapi.yaml

# Request records from a gateway, WAF or log shipper (query values, bodies and tokens are never kept)
curl -X POST https://quanta.example.com/api/ingest/api-traffic -H "Authorization: Bearer $QUANTA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"service":"shop-api","records":[{"method":"GET","path":"/v1/users/42","status":200,"latency_ms":12,"bytes_out":512,"actor":"u-17","client_ip":"203.0.113.9","auth":"bearer"}]}'

# Results of an API security test run in CI; `gate.passed` tells the pipeline whether to fail
curl -X POST "https://quanta.example.com/api/ingest/api-test-results?reconcile=true" -H "Authorization: Bearer $QUANTA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"my-tester","repository":"org/shop-api","results":[{"method":"GET","path":"/users/{id}","test":"object-level authorization","owasp":"API1:2023","status":"fail","severity":"High"}]}'

# Your automation reports what the edge service said about a protection policy Quanta sent it
curl -X POST https://quanta.example.com/api/inbound/api-policy-status -H "Authorization: Bearer $QUANTA_KEY" \
  -H "Content-Type: application/json" -d '{"push_id":12,"status":"applied","detail":"web ACL updated"}'
```

Optional query parameters on the test-results route: `fail_on` (Critical, High, Medium, Low), `report_only=true`, `reconcile=true`.

#### Receiving a protection policy (the signed request Quanta sends you)

Add a connection of type *API protection policy endpoint*. Quanta `POST`s JSON `{"type": "api-protection-policy", "delivery_id", "policy": {...}, "requested_by", "approved_by"}` with
`X-Quanta-Timestamp` (unix seconds), `X-Quanta-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" with your signing secret>` and `X-Quanta-Delivery`. Verify the signature and reject a stale timestamp,
then apply the rule in your own change process. Quanta changes no WAF itself.

### Read findings out

```bash
curl "https://quanta.example.com/api/export/findings?severity=critical&kev=true&limit=1000&offset=0" \
  -H "Authorization: Bearer $QUANTA_KEY"
```

Filters: `source`, `severity`, `kev`. Paged with `limit` (at most 5,000) and `offset`.

## 3. Per vendor, end to end

* **ServiceNow.** Create an integration user that can create and read incidents. Add a ServiceNow connection
  (instance name, user, password, rule). Quanta opens incidents and reads their state back each run. Optionally
  add a business rule on `incident` that POSTs state changes to `/api/inbound/ticket-status` with a
  `tickets:update` key for near-instant updates.
* **Jira.** Create an API token for a service account with create/browse rights in the project. Add a Jira
  connection. Issues carry the label `quanta-<finding id>`; state comes back by status category.
* **Splunk.** Create an HTTP Event Collector token and add a Splunk connection with a rule. It is an append-only
  stream, so each finding is sent once.
* **Tenable and Qualys.** Add the connection for a scheduled pull, or, if your policy keeps scanner credentials out of
  other systems, have the scanner's own export job upload to `/api/ingest/scanner-csv` with an `ingest:write` key.
* **Prisma Cloud and Cortex XSIAM.** Add the connection. Their findings arrive already in Quanta's schema.
* **Anything else (a SOAR playbook, an EDR, a custom collector).** Post to `/api/ingest/findings`.

Every connector is built against the vendor's public API and tested against simulated responses; none has been
exercised against a live vendor account in this repository. Your first sync of each source is the live
validation, and the disclosure on each connection's page says so.
