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
