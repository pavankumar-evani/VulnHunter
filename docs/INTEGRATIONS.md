# VulnHunter — Integrations

**How to use this doc:** read this to understand every external system VulnHunter
actually talks to — what each integration does, and critically, what's genuinely
**live-verified** versus **built against public docs but never exercised against a real
tenant**. This distinction is treated as load-bearing throughout this repo, not a
footnote — see [remediation/connectors/README.md](../remediation/connectors/README.md)
and [KNOWLEDGE_TRANSFER.md §9](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)
for the source language this doc draws from. Also see [USER_GUIDE.md](USER_GUIDE.md),
[FAQ.md](FAQ.md), [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md), or the
[docs/README.md](README.md) index.

---

## Summary table

| Integration | What it does | Verification status |
|---|---|---|
| Tenable.io connector | Pulls vulnerability findings via the async Vulnerability Export API - **dashboard Test Connection + Fetch form at `/tenable`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Armis connector | Pulls device-risk alerts via token auth + paginated AQL search | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Qualys VMDR connector | Pulls host detections via the VM API (XML) + knowledge-base QID lookup - **dashboard Test Connection + Fetch form at `/qualys`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live subscription |
| ServiceNow connector | Creates an Incident per finding via the Table API, idempotently | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live instance |
| Jira Cloud connector | Creates an Issue per finding via the REST API v3, idempotently (label-keyed) | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live site |
| Splunk HEC connector | Pushes each finding to Splunk as an HTTP Event Collector event | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live instance |
| CrowdStrike Falcon connector | Pulls EDR/XDR alerts via OAuth2 client-credentials + query/fetch-entities | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Prisma Cloud connector | Pulls cloud posture/compliance alerts via login + alert-search - **dashboard Test Connection + Fetch form at `/prismacloud`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Cortex XSIAM connector | Pulls correlated incidents via the Standard-auth incidents API - **dashboard Test Connection + Fetch form at `/cortex-xsiam`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Infoblox connector | Pulls DNS host records via WAPI, normalizes into asset-inventory entries (not findings) - **dashboard Test Connection + Fetch form at `/infoblox`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live grid |
| Axonius connector | Pulls aggregated device records via the devices API, normalizes into asset-inventory entries (not findings) - **dashboard Test Connection + Fetch form at `/axonius`** | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Active Directory (asset-inventory) connector | Pulls computer objects via LDAP, normalizes into asset-inventory entries (not findings) - **dashboard Test Connection + Fetch form at `/active-directory`** | Built against Microsoft's documented AD schema, **unit-tested against a hand-rolled fake LDAP connection only** — never exercised against a live domain controller |
| OpenVAS / Greenbone (GVM) connector | The one **scan engine** in this table, not a pull connector onto a scanner you already run - launches a real authenticated GMP scan, polls it, imports results - **dashboard Connect/Start Scan/Poll/Import form at `/openvas`** | Built against Greenbone's public GMP protocol docs via `python-gvm`, **unit-tested against a hand-rolled fake GMP client only** — never exercised against a live GVM server. See [`docs/VULNERABILITY_ENGINE_ARCHITECTURE.md`](VULNERABILITY_ENGINE_ARCHITECTURE.md) |
| CISA KEV enrichment | Flags CVEs confirmed actively exploited in the wild | **Live-verified** — built and tested against the real, free, public endpoint |
| FIRST.org EPSS enrichment | Attaches a 0–1 exploitation-probability score per CVE | **Live-verified** — built and tested against the real, free, public endpoint |

The last two are the only integrations in this repo that have actually talked to their
real target service during development. Everything else has a real, working
implementation of its vendor's documented contract, backed by tests — but "tested" there
means "tested against mocked HTTP (or, for Active Directory, a fake LDAP connection)
shaped like the documentation," not "confirmed to work against a real account." Every
connector marked with a dashboard form above is reachable from **Connectors / Adaptors**
(`/adaptors`) without touching a CLI - see [GOING_LIVE.md](GOING_LIVE.md) for exactly
what credentials each one needs.

---

## Tenable.io connector

**File:** [`remediation/connectors/tenable_connector.py`](../remediation/connectors/tenable_connector.py)

Implements Tenable.io's asynchronous Vulnerability Export API: requests an export job,
polls its status until `FINISHED`, downloads each chunk, and flattens each record into
the same CSV column shape as `remediation/sample-data/tenable_export.csv` — so
`vuln-ingest-normalizer.md` needs zero changes to consume live output.

**Verification status:** built against Tenable's publicly documented API contract.
Covered by 18 tests in `tests/test_connectors.py`, all against mocked HTTP (no network,
no credentials needed) — auth header/flow construction, endpoint URLs, pagination
handling, response-to-CSV-row mapping, and defensive handling of error conditions (bad
response shape, an export job that errors out, a pagination cursor that never
terminates). **It has not been exercised against a real Tenable.io tenant**, because no
API credentials were available while building it. Before pointing it at a real account:
get read-only credentials, run it against a test/non-production tenant first if
possible, and diff the output against a manually-verified sample from your actual tenant
— field names and nesting can differ from the public docs depending on API version and
tenant configuration (`TenableConnector.to_csv_row()` is the place to adjust if so).

**Dashboard form:** `/tenable` (also reachable via **Connectors / Adaptors**) offers a
real **Test Connection** button (`GET /session` - the lightest authenticated call
Tenable's API has) and a **Fetch Live Data** button (the full export workflow above,
writing to `remediation/live-data/tenable_export.csv`). Both take an access key + secret
key fresh on every request, never stored server-side. Fetch is confirm-gated and
admin-only (`rbac.require_admin`) since it's a real, potentially multi-minute call
against production Tenable infrastructure. Bringing the fetched file into this
dashboard's own pages still needs the agent-driven `/remediate <file>` step described
above - the dashboard form does not (and should not) skip that.

## Armis connector

**File:** [`remediation/connectors/armis_connector.py`](../remediation/connectors/armis_connector.py)

Implements Armis's access-token auth flow, then a paginated AQL search for alerts
(`in:alerts` by default), resolving each alert's owning device and assembling the result
into the same nested `{"devices": [{"alerts": [...]}]}` shape as
`remediation/sample-data/armis_export.json`.

**Verification status:** same caveat as Tenable — built against Armis's publicly
documented REST API v1, covered by the same 18-test `tests/test_connectors.py` suite
(mocked HTTP), **never exercised against a real Armis tenant**. Verify field names
against your tenant's current API version before trusting live output
(`ArmisConnector._alert_to_sample_shape()` is the adjustment point).

## Qualys VMDR connector

**File:** [`remediation/connectors/qualys_connector.py`](../remediation/connectors/qualys_connector.py)

Implements Qualys Cloud Platform's documented VM API (the long-established, XML-based
API that is still the real, primary integration surface for host-based VM detections):
fetches host detections (`GET .../vm/detection/`, paginated via an `id_min` continuation
link), resolves every QID seen to a CVE/title/severity via the knowledge base
(`GET .../knowledge_base/vuln/`), and flattens the result into **Tenable's exact CSV
column shape** (`tenable_connector.CSV_FIELDNAMES`) - a deliberate reuse decision, not an
accidental coincidence: both vendors report the same real-world facts (host, CVE,
severity, port/protocol, first/last seen), so producing the same flat shape means
`vuln-ingest-normalizer.md` needs zero changes to ingest Qualys output alongside Tenable's.

**Verification status:** built against Qualys's publicly documented VM API (XML) and
knowledge-base contract. Covered by 20 tests in `tests/test_qualys_connector.py` — Basic
Auth + `X-Requested-With` header construction, host-detection XML parsing (including
`id_min` pagination), knowledge-base QID→CVE resolution, the 1–5 severity-level mapping,
and CSV-row flattening — all against mocked HTTP (real Qualys-shaped XML text, no
network). **It has not been exercised against a real Qualys subscription**, same reason
as every other connector here: no credentials were available while building it.
`platform_url` is a required constructor argument (no honest single default - Qualys
assigns a different API URL per platform/region).

**Dashboard form:** `/qualys` (also reachable via **Connectors / Adaptors**) offers a
real **Test Connection** button (a host-detection list call truncated to one result) and
a **Fetch Live Data** button (the full fetch → knowledge-base-lookup → flatten workflow
above, writing to `remediation/live-data/qualys_export.csv`). Same credential-handling,
confirm-gating, and "still needs `/remediate <file>`" caveats as Tenable's dashboard form
above.

## OpenVAS / Greenbone (GVM) connector - the scan engine

**File:** [`remediation/connectors/openvas_connector.py`](../remediation/connectors/openvas_connector.py)
**Full design doc:** [`docs/VULNERABILITY_ENGINE_ARCHITECTURE.md`](VULNERABILITY_ENGINE_ARCHITECTURE.md)

Every other connector in this document pulls data out of a scanner or CMDB someone
already owns. This one is different: it drives Greenbone Community Edition (GVM, the
free/open-source scan engine descended from the original Nessus) directly, via GMP
(Greenbone Management Protocol - XML over a TLS socket or a local Unix socket, not
HTTP), using Greenbone's own `python-gvm` client library. It creates a target, creates
and starts a task, polls the task until done, and pulls real per-host CVE results back -
this is the piece that lets a company with **no existing vulnerability scanner** get
real findings out of VulnHunter, not just a company that already pays for Tenable or
Qualys.

Results are flattened into **Tenable's exact CSV column shape**
(`tenable_connector.CSV_FIELDNAMES`), same reuse decision as the Qualys connector above -
GVM is a CVE-scoped host-vulnerability source like Tenable/Qualys, so it needs the same
`/remediate <file>` asset-classification step, and reusing their CSV shape means zero
normalizer changes.

**Verification status:** built against Greenbone's publicly documented GMP protocol.
Covered by 21 tests in `tests/test_openvas_connector.py` - connection ownership
semantics, target/task creation and scan startup, status polling (Done/Stopped/timeout),
CVE extraction (both documented GMP result shapes), NVT tag parsing, and CSV-row
mapping - all against a hand-rolled fake GMP client (real GMP-shaped XML elements, no
network), the same test-double convention `active_directory_connector.py` established
for this repo's other stateful-protocol connector. **It has not been exercised against a
real GVM server**, same reason as every other connector here: none was available while
building it. `DEFAULT_SCAN_CONFIG_ID`/`DEFAULT_SCANNER_ID` are Greenbone's own documented
default seed IDs (present on every fresh install) - a customized instance may need to
override them.

**Dashboard form:** `/openvas` (also reachable via **Connectors / Adaptors**) is shaped
differently from every connector above it, because launching a scan is a lifecycle, not
a single fetch: **Test Connection**, then **Start Scan** (confirm-gated, requires an
explicit "I own or am authorized to scan" attestation), then **Check Status** (poll as
many times as needed - a real scan can take hours), then **Import Results** (confirm-
gated, writes `remediation/live-data/openvas_export.csv`). See
`docs/VULNERABILITY_ENGINE_ARCHITECTURE.md` §2 for why this couldn't be one button the
way Tenable/Qualys's Fetch is.

## ServiceNow connector

**File:** [`remediation/connectors/servicenow_connector.py`](../remediation/connectors/servicenow_connector.py)

Creates an Incident per finding via ServiceNow's Table API against the generic
`incident` table (present in every ServiceNow instance with no additional plugin —
orgs with the Security Operations "Vulnerability Response" module may prefer targeting
`sn_vul_vulnerable_item` instead, by swapping the `table` constructor argument).
**Idempotent**: it checks the finding's `correlation_id` before creating an Incident, so
re-running the connector against the same findings doesn't create duplicate tickets. The
dashboard's `/servicenow` page previews the exact request body `build_incident_body()`
would send — a pure function, no network calls — for every finding, with **zero
credentials required**; sending anything for real requires supplying real credentials and
explicitly confirming.

**Verification status:** built against ServiceNow's publicly documented Table API
contract (referenced directly in the module's docstring). Covered by 16 tests in
`tests/test_servicenow_connector.py` — idempotency behavior, request-body construction,
batch error handling — all against mocked HTTP. **It has not been exercised against a
real ServiceNow instance**, same reason as the other two connectors: no credentials were
available while building it.

## Jira Cloud connector

**File:** [`remediation/connectors/jira_connector.py`](../remediation/connectors/jira_connector.py)

Creates an Issue per finding via Jira Cloud's documented REST API v3 (HTTP Basic auth
with an Atlassian account email + API token). Jira has no built-in correlation-id field
the way ServiceNow's Table API does, so idempotency is keyed off a `vulnhunter-<finding_id>`
label instead: `find_existing_issue()` searches for that label via JQL before creating,
and every created issue is tagged with it, so re-running the connector against the same
findings doesn't create duplicate tickets. The issue description is built as a minimal,
valid Atlassian Document Format (ADF) document — a pure function
(`build_issue_body()`), no network calls — so the dashboard's `/jira` page can preview
the exact request body for every finding with **zero credentials required**; sending
anything for real requires a real base URL/email/API token and explicitly confirming.

**Verification status:** built against Jira Cloud's publicly documented REST API v3
contract (referenced directly in the module's docstring). Covered by 19 tests in
`tests/test_jira_connector.py` — auth/construction, ADF body construction, the
label-based idempotency check, and batch error handling — all against mocked HTTP. **It
has not been exercised against a real Jira Cloud site**, same reason as every other
connector here: no credentials were available while building it. Before pointing it at a
real site: get an API token from a real Atlassian account, confirm the target project
key exists, and verify the ADF description renders as expected in your instance's issue
view.

## Splunk HEC connector

**File:** [`remediation/connectors/splunk_connector.py`](../remediation/connectors/splunk_connector.py)

Sends each finding to Splunk as an event via the documented HTTP Event Collector (HEC)
contract — token auth via an `Authorization: Splunk <token>` header (not Basic auth, not
OAuth), one `POST` per event. This is genuinely one-directional and push-based, the
opposite direction from Tenable/Armis/CrowdStrike (which pull data out of the vendor):
here VulnHunter is the client, and Splunk is the destination, the same way any app ships
a log event to a SIEM. The whole normalized finding is passed through as the event body
(`build_hec_event()`, a pure function, no network) rather than a hand-picked subset, so
nothing gets silently dropped before it reaches Splunk — this also powers the
dashboard's `/splunk` preview with **zero credentials required**. Deliberately **no
idempotency/dedup check** before sending, unlike ServiceNow/Jira's find-existing-then-skip
pattern: HEC events are an append-only stream, not a ticket system, so re-sending the
same finding on a pipeline re-run is normal and expected (Splunk correlates/dedups
downstream in search, not at ingest time).

**Verification status:** built against Splunk's publicly documented HEC ingestion
contract (referenced directly in the module's docstring). Covered by 19 tests in
`tests/test_splunk_connector.py` — auth/construction, HEC event-envelope construction,
send behavior, and batch handling (including a test that specifically proves there's no
dedup) — all against mocked HTTP. **It has not been exercised against a real Splunk
instance**, same reason as every other connector here: no credentials were available
while building it. Before pointing it at a real instance: confirm the HEC token's
default index/sourcetype match what you expect, or pass explicit overrides.

## CrowdStrike Falcon connector

**File:** [`remediation/connectors/crowdstrike_connector.py`](../remediation/connectors/crowdstrike_connector.py)

Pulls EDR/XDR alerts via CrowdStrike Falcon's documented OAuth2 client-credentials flow,
then a query-then-fetch-entities pattern (`GET /alerts/queries/alerts/v1` for matching
alert composite IDs, `POST /alerts/entities/alerts/v2` to resolve them into full alert
objects), and normalizes each into VulnHunter's Finding schema
(`normalize_alert()`). Like Armis, this is a **pull** connector with no dashboard form —
only a reference page at `/xdr` describing what it does and how to use it from Python,
since there's nothing to preview/send, only to fetch and normalize. Unlike Prisma
Cloud/Cortex XSIAM below (the same kind of direct-normalize pull connector), CrowdStrike
was not in this round's requested connector list, so it hasn't been given a dashboard
Test Connection + Fetch form - the same pattern is available to add if it's needed next.
Falcon EDR alerts are behavioral detections, not CVE-scoped vulnerability findings, so a
normalized CrowdStrike finding's `cve`/`cvss`/`kev`/`epss` are always `null` — a
deliberate, expected property of this source (documented in the module's own docstring),
not a gap in the mapping. Severity mapping prefers Falcon's own `severity_name` when it
matches a known tier, and otherwise falls back to numeric thresholds against
`severity` (≥90 Critical, ≥70 High, ≥40 Medium, else Low) — those thresholds are a
reasonable-but-arbitrary starting point, not sourced from official CrowdStrike docs, and
should be tuned against a real tenant before relying on them for triage prioritization.

**Verification status:** built against CrowdStrike Falcon's publicly documented Alerts
API contract (referenced directly in the module's docstring). Covered by 24 tests in
`tests/test_crowdstrike_connector.py` — OAuth2 auth flow, alert-ID query params,
alert-detail fetch, severity/platform mapping, and the fetch-then-normalize
orchestration — all against mocked HTTP. **It has not been exercised against a real
CrowdStrike Falcon tenant**, same reason as every other connector here: no credentials
were available while building it. Before trusting live output, verify field names
against your tenant's current API version and retune the severity thresholds above
against real alert data.

## Prisma Cloud connector

**File:** [`remediation/connectors/prismacloud_connector.py`](../remediation/connectors/prismacloud_connector.py)

Implements Prisma Cloud's (Palo Alto Networks CNAPP) documented login + alert-search API
contract: exchanges an access key ID + secret key for a token
(`POST /login` → `x-redlock-auth` header, Prisma Cloud's real, documented header name —
not a Bearer `Authorization` header), then fetches open alerts (`POST /v2/alert`).
Like `crowdstrike_connector.py`, Prisma Cloud alerts are cloud posture/compliance
violations, not CVE-scoped known-vulnerability findings — so this connector normalizes
directly into VulnHunter's Finding schema itself (`cve`/`cvss`/`kev`/`epss` always
`null`, `asset.type` always `cloud-infrastructure`) rather than routing through
`vuln-ingest-normalizer.md`. `id` is left `null` on every normalized finding, the same
convention `crowdstrike_connector.normalize_alert()` already establishes. Fetches a
single page of alerts only — a documented scope limit (like `axonius_connector.py`), not
silently dropped.

**Verification status:** built against Prisma Cloud's publicly documented API contract.
Covered by 16 tests in `tests/test_prismacloud_connector.py` — login/token-exchange
construction, alert-search request shape, severity mapping, and Finding-schema
normalization — all against mocked HTTP. **It has not been exercised against a real
Prisma Cloud tenant**, same reason as every other connector here: no credentials were
available while building it. `base_url` is a required constructor argument (no honest
single default - Prisma Cloud assigns a different API URL per region/stack).

**Dashboard form:** `/prismacloud` (also reachable via **Connectors / Adaptors**) offers
a real **Test Connection** button (the login call itself) and a **Fetch Live Data**
button. Unlike Tenable/Qualys, Fetch here writes already-normalized findings straight to
`remediation/live-data/prismacloud_findings.json`, ID-sequenced the same way the generic
ingest adapter's `_next_finding_id` already is — but, like that adapter's own explicit,
disclosed choice, deliberately **not** auto-merged into
`remediation/output/normalized-findings.json` or the live queue.

## Cortex XSIAM connector

**File:** [`remediation/connectors/cortex_xsiam_connector.py`](../remediation/connectors/cortex_xsiam_connector.py)

Implements Cortex XSIAM/XDR's documented "Standard" authentication
(`x-xdr-auth-id` + `Authorization` headers) + incident-search API contract
(`POST .../incidents/get_incidents`) - a genuinely different product from the
SOAR-orchestration-focused Cortex XSOAR (still reference-catalog-only, no working code).
A separate "Advanced" auth mode (HMAC request signature) exists for tenants that require
it, not implemented here. Like Prisma Cloud, XSIAM incidents are correlated detections,
not CVE-scoped findings, so this connector normalizes directly into the Finding schema
(`cve`/`cvss`/`kev`/`epss` always `null`). `asset.type` is left `unknown` rather than
guessed - a correlated incident can span multiple hosts of unknown/mixed platform.

**Verification status:** built against Cortex XSIAM's publicly documented API contract.
Covered by 19 tests in `tests/test_cortex_xsiam_connector.py` — auth header construction,
the get_incidents request shape (status filter, paging window), severity mapping
(including the `info`→`Low` collapse), the epoch-ms→ISO-date conversion, and Finding-
schema normalization — all against mocked HTTP. **It has not been exercised against a
real Cortex XSIAM tenant**, same reason as every other connector here: no credentials
were available while building it. `base_url` is a required constructor argument (no
honest single default - tenant- and region-specific).

**Dashboard form:** `/cortex-xsiam` (also reachable via **Connectors / Adaptors**) offers
a real **Test Connection** button (a get_incidents call capped to one result) and a
**Fetch Live Data** button. Same "writes already-normalized findings, not auto-merged"
behavior as Prisma Cloud's dashboard form above, to
`remediation/live-data/cortex_xsiam_findings.json`.

## Infoblox connector

**File:** [`remediation/connectors/infoblox_connector.py`](../remediation/connectors/infoblox_connector.py)

Pulls DNS host records from an Infoblox NIOS grid via the documented WAPI (Web API)
`record:host` object (`GET /wapi/{version}/record:host`, HTTP Basic auth), and normalizes
each into VulnHunter's shared **asset-inventory** shape (`name`, `ip`, `mac`, `type`,
`source`, `source_ref`, `extra`) — unlike every connector above, this produces asset
records, not vulnerability findings, because Infoblox is a DNS/IPAM system, not a
vulnerability scanner. A DNS host record doesn't carry MAC address or OS/platform data (those live
on separate Infoblox `lease`/`ipv4address` objects this connector doesn't fetch), so
`mac` is always `null` and `type` is always `"unknown"` on an Infoblox-sourced asset
record — a deliberate, documented property of this source, not a mapping gap.

**Verification status:** built against Infoblox NIOS's publicly documented WAPI
contract (referenced directly in the module's docstring). Covered by 16 tests in
`tests/test_infoblox_connector.py` — auth/session construction, request URL/param
construction, host-record-to-asset mapping, and defensive handling of a host record with
no IPs — all against mocked HTTP. **It has not been exercised against a real Infoblox
grid**, same reason as every other connector here: no credentials were available while
building it. Before trusting live output, verify field names against your grid's current
WAPI version.

**Dashboard form:** `/infoblox` (also reachable via **Connectors / Adaptors**) offers a
real **Test Connection** button (a record:host fetch capped to one result - WAPI has no
dedicated ping endpoint) and a **Fetch Live Data** button. Unlike Tenable/Qualys, Fetch
here doesn't write a raw export file - it reconciles each fetched record's real `ip`
directly into `asset_ownership.json` via `asset_inventory.reconcile_pulled_assets()`, the
same real, bounded action the Asset Inventory page's CMDB CSV import already performs.
An asset with no existing findings against it is still stored (so its `ip` is already
correct the moment a finding against it does show up) but won't appear on the Asset
Inventory table until then - that table is built from findings, not a separate asset
registry (see this connector's own module docstring).

## Axonius connector

**File:** [`remediation/connectors/axonius_connector.py`](../remediation/connectors/axonius_connector.py)

Pulls aggregated device records from Axonius's documented REST API (`POST /api/devices`
with an offset/limit pagination body, `api-key`/`api-secret` header auth), and normalizes
each into the same asset-inventory shape Infoblox produces. Axonius's own value
proposition is aggregating asset data across many source adapters (CMDB, EDR, cloud,
network) into one inventory, so each normalized record keeps the reporting `adapters`
list in `extra`. Two documented scope limits: the exact response envelope key has varied
across Axonius API versions in public docs (`"assets"` is used as the most
standard/likely key), and this connector fetches a single page only — a real integration
needs an offset/limit pagination loop the same way `ArmisConnector.search_all_pages()`
does.

**Verification status:** built against Axonius's publicly documented REST API contract
(referenced directly in the module's docstring). Covered by 17 tests in
`tests/test_axonius_connector.py` — auth header construction, request body construction,
device-to-asset mapping (including the OS-type-to-asset-type mapping and IP/MAC
list-fallback extraction), and defensive handling of a device with missing fields — all
against mocked HTTP. **It has not been exercised against a real Axonius tenant**, same
reason as every other connector here: no credentials were available while building it.

**Dashboard form:** `/axonius` (also reachable via **Connectors / Adaptors**) offers a
real **Test Connection** button (a devices fetch capped to one result - Axonius's REST
API has no dedicated ping endpoint) and a **Fetch Live Data** button. Same
reconcile-into-`asset_ownership.json` behavior as Infoblox's dashboard form above, via
the same shared `asset_inventory.reconcile_pulled_assets()` helper.

## Active Directory connector (asset-inventory)

**File:** [`remediation/connectors/active_directory_connector.py`](../remediation/connectors/active_directory_connector.py)

Implements a standard LDAP (RFC 4511) simple bind + computer-object search
(`(objectClass=computer)`) against an on-prem Active Directory domain controller, via
the real `ldap3` Python library - already a dependency of this project (see
`dashboard/auth/ad_directory.py`, pinned in `dashboard/requirements.txt`). **A distinct
concern from `dashboard/auth/ad_directory.py`**, which is a completely different,
narrower feature: it only checks whether a named user is a member of one AD group, to
gate the Remediation Approval workflow, configured server-wide via
`AD_SERVER`/`AD_BASE_DN` environment variables. This connector instead pulls the
domain's computer objects as asset-inventory records (the same
`{name, ip, mac, type, source, source_ref, extra}` shape Infoblox/Axonius already
produce), takes credentials per-request like this dashboard's other new connector forms,
and performs a completely separate real-world action. Both are real, both use `ldap3`,
neither depends on the other. `ip` and `mac` are always `null` on an AD-sourced record —
AD computer objects don't carry a network address (that's DHCP/DNS's job) — the same
honest "don't guess what the source doesn't carry" choice `infoblox_connector.py` already
makes for `mac`. `type` is inferred from the `operatingSystem` string ("server" in the
string → `windows-server`, any other recognizably-Windows string → `windows-endpoint`,
anything else → `unknown` rather than guessed).

**Verification status:** built against Microsoft's documented AD computer-object schema
and RFC 4511. Covered by 18 tests in `tests/test_active_directory_connector.py` —
connection ownership/unbind semantics, the test-connection search shape, the
computer-object search filter/attributes, safe attribute extraction, OS-string-based
type inference, the `userAccountControl` ACCOUNTDISABLE-bit decode, and normalization
into the shared asset shape — against a hand-rolled fake `ldap3.Connection`/`Entry`
double (the same test-double convention `tests/test_ad_directory.py` already
established for this repo's other LDAP code), not ldap3's own `MOCK_SYNC` strategy.
**It has not been exercised against a real Active Directory domain controller**, same
reason as every other connector here: no credentials were available while building it.
Verify attribute names against your own domain's schema before trusting live output - a
computer object's populated attributes can vary by AD schema version and domain
functional level.

**Dashboard form:** `/active-directory` (also reachable via **Connectors / Adaptors**)
offers a real **Test Connection** button (a simple bind + a trivial rootDSE-style search)
and a **Fetch Live Data** button. Since AD computer objects carry no ip/mac, there is
usually nothing for Fetch to reconcile into `asset_ownership.json` from this source
alone — Fetch here mainly proves connectivity and surfaces what the domain's computer
inventory actually looks like (name, OS, enabled/disabled); real ip/mac ground truth
still comes from Tenable/Qualys/Infoblox/Axonius.

## CISA KEV enrichment (live-verified)

**File:** [`remediation/enrichment/kev_epss.py`](../remediation/enrichment/kev_epss.py)

Fetches CISA's Known Exploited Vulnerabilities catalog — a static JSON feed, free, no
authentication required — and flags whether each finding's CVE is confirmed actively
exploited in the wild, plus the date it was added to KEV and known ransomware-campaign
use.

**Verification status:** unlike the three connectors above, **this was built and tested
against the real, live public endpoint during development**, not just mocked. Most of
`tests/test_enrichment.py`'s 13 tests mock HTTP for CI determinism and speed (same
pattern as `test_connectors.py`), but one — the live smoke test — calls the actual CISA
KEV feed and FIRST.org EPSS API and asserts against a well-known, stable historical fact
(PrintNightmare, CVE-2021-34527, has been KEV-listed since 2021 and won't stop being so).
It skips itself rather than failing the build if the network is unavailable.

## FIRST.org EPSS enrichment (live-verified)

**File:** [`remediation/enrichment/kev_epss.py`](../remediation/enrichment/kev_epss.py) (same
module as KEV, run together by `threat-intel-enricher`)

Calls FIRST.org's EPSS API for a 0–1 probability that each CVE will be exploited in the
next 30 days, plus its percentile rank against all scored CVEs. Free, no authentication
required. Complements KEV: KEV is "confirmed exploited already," EPSS is "how likely is
exploitation soon," and the two signals can disagree — a CVE can score high EPSS without
being KEV-listed yet, or vice versa.

**Verification status:** same as KEV — live-verified, including the one real-API smoke
test in `tests/test_enrichment.py`, both free and requiring no credentials, which is why
both were built *and* tested against production endpoints, unlike the Tenable/Armis/
ServiceNow connectors above.

Both KEV and EPSS results feed `remediation-planner`'s `priority` assignment (never
`risk_tier`) — see [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) for how that fits
into the full pipeline.

---

## MITRE ATT&CK tagging (a related but separate mechanism)

**File:** [`remediation/enrichment/attack_mapping.py`](../remediation/enrichment/attack_mapping.py)

Not an external API integration — included here because it's easy to mistake for one. It
is a **keyword heuristic** against a finding's title/description text, explicitly
documented in its own module docstring as non-authoritative: "there is no universal,
authoritative CVE-to-ATT&CK-technique mapping... treat every mapping here as a suggestion
to verify, not a fact to cite." Surfaced on the dashboard's `/queue` page as a tactical
grouping aid, not a certified technique attribution.

---

## Generic XDR/EDR/SIEM ingestion adapter (vendor-agnostic, live-verifiable today)

**File:** [`remediation/connectors/generic_connector.py`](../remediation/connectors/generic_connector.py)
**Endpoint:** `POST /api/ingest/generic`

Tenable/Armis/ServiceNow each got a bespoke connector because each has a real,
documented, vendor-specific API contract to build against. Building one more bespoke
connector per additional named product (Qualys, Splunk, Sentinel, QRadar, CrowdStrike,
Defender, ...) without real API access to any of them would mean shipping code that
looks plausible but was never verified against anything real.

Instead: almost every modern SIEM/XDR/EDR/SOAR tool supports sending a **custom outbound
webhook** with a JSON body you control. This adapter is the receiving side of that -
validate an inbound payload against a documented minimal shape (`title`, `severity`,
`asset_name`, `asset_type` required; `cve`, `description`, `source_ref`, etc. optional),
normalize it into VulnHunter's normalized Finding schema, and write it to
`remediation/live-data/generic-ingested.json` (gitignored, same convention as live
Tenable/Armis output). IDs continue the real pipeline's `FIND-N` sequence so an ingested
finding's ID never collides with a real one. **Deliberately not auto-merged** into the
live queue - consistent with how live Tenable/Armis connector output also isn't
auto-merged; a batch response reports exactly what was accepted vs. rejected (with
per-item validation errors) so a calling tool's automation can react to partial failures.

This is the one real, generic, testable answer to "integrate with any XDR/EDR/SIEM,"
rather than a promise to build N vendor-specific ones with no way to verify them.

---

## Reference catalog: researched, not yet built

The connector *pattern* — vendor auth flow, paginated fetch, mapping into a stable
internal schema, mocked-HTTP unit tests, an explicit "built vs. verified" caveat — is now
proven thirteen times over for vulnerability-finding connectors (Tenable, Armis, Qualys,
OpenVAS/GVM, ServiceNow, Jira, Splunk, CrowdStrike, Prisma Cloud, Cortex XSIAM) and
asset-inventory connectors (Infoblox, Axonius, Active Directory), plus the generic
webhook adapter above for anything that can push data to VulnHunter rather than needing
VulnHunter to pull from it.

The entries below are the same idea one stage earlier: real, researched facts about
each product's actual public API (auth model, real endpoint/data shape, what would flow)
— visible on the dashboard's consolidated **Adaptors** hub (`/adaptors`, browse by
category) via `dashboard/static/js/adaptorCatalog.js` — but with **no working code or
tests behind them yet**. That's the honest, one-step-earlier label this repo already
uses elsewhere ("built against docs, unit-tested, never exercised against a live
tenant" for the twelve connectors above); these simply haven't had the "built against
docs" step done yet either. Each is gated on picking a specific vendor and building +
testing the bespoke pull/push logic (or, better, getting sandbox/tenant access to verify
against) — not a technical blocker, a scoping one. See
[KNOWLEDGE_TRANSFER.md §11](../KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)
for the full reasoning on why building all of these out fully was deliberately scoped out
rather than attempted alongside everything else.

| Connector | Category | Auth model | Integration shape |
|---|---|---|---|
| Microsoft Entra ID | Identity / IAM | Azure AD (Entra ID) OAuth2 app registration (client-credentials) | Pull: Graph riskyUsers/riskDetections + app-registration endpoints → identity-risk findings |
| AWS IAM Access Analyzer | Identity / IAM | AWS IAM (SigV4-signed requests) | Pull: `ListFindings` → over-permissive resource policies/unused access |
| Rapid7 InsightVM | Vulnerability Scanners | API key (`X-Api-Key`) | Pull: assets/vulnerabilities endpoints |
| Black Duck (Synopsys) | Application Security Testing (SAST/SCA) | API token (Bearer) | Pull: vulnerable-BOM-components → `scan_type=sca` findings |
| Polaris (Synopsys) | Application Security Testing (SAST/SCA) | API token (Bearer) | Pull: issues API for latest analysis run → SAST findings |
| SonarQube | Application Security Testing (SAST/SCA) | User token (Bearer or Basic) | Pull: `/api/issues/search?types=VULNERABILITY` → SAST findings with real CWE |
| Snyk | Application Security Testing (SAST/SCA) | API token (`Authorization: token`) | Pull: org/project/issues → sca/iac/container findings |
| Wiz | Cloud Security (CNAPP) | OAuth2 client-credentials (GraphQL API) | Pull: issues/vulnerabilities → `asset.type=cloud-infrastructure` |
| AWS Security Hub | Cloud Security (CNAPP) | AWS IAM (SigV4-signed requests) | Pull: `GetFindings` (AWS Security Finding Format, a published schema) |
| Microsoft Defender for Cloud | Cloud Security (CNAPP) | Azure AD (Entra ID) service principal | Pull: assessments/alerts APIs → cloud-infrastructure findings |
| GCP Security Command Center | Cloud Security (CNAPP) | GCP service account (OAuth2 JSON key / WIF) | Pull: SCC `ListFindings` → cloud-infrastructure findings |
| IBM QRadar | SIEM / SOAR | SEC token (API key) | Push: offenses/events, same direction as Splunk HEC |
| Microsoft Sentinel | SIEM / SOAR | Azure AD service principal | Push (Log Analytics Data Collector) or pull (incidents API) |
| Palo Alto Cortex XSOAR | SIEM / SOAR | API key | Push: create an Incident per finding, triggers org playbooks |
| Elastic / ELK SIEM | SIEM / SOAR | API key (base64 `id:api_key`) | Push: index findings via the `_bulk` API |
| SentinelOne | XDR / EDR | API token | Pull: threats API → behavioral findings (cve/cvss/kev/epss null, same as CrowdStrike) |
| Microsoft Defender for Endpoint | XDR / EDR | Azure AD app registration (Graph Security API) | Pull: alerts endpoint → behavioral findings |
| BishopFox (Cosmos) | External Risk / Attack Surface Management | API key | Pull: discovered-asset/finding endpoints → external-exposure findings |
| BitSight | External Risk / Attack Surface Management | API token (Bearer or Basic) | Pull: outside-in observations for a company GUID |
| Palo Alto Panorama | Network Security Management | API key (PAN-OS XML API) | Push: commit a policy/address-object change (remediation-actuation) |
| Cisco Firepower Management Center | Network Security Management | Token-based (`X-auth-access-token`) | Push: commit an access-control-policy/network-object change |
| Fortinet FortiManager | Network Security Management | JSON-RPC session token (or API key) | Push: commit a policy/address-object change |
| F5 BIG-IP | Network Security Management | Basic Auth or `/mgmt/shared/authn/login` token | Push: commit a WAF (ASM) policy/virtual-server change |
| Slack | Communication / On-Call | Bot token (OAuth2) or Incoming Webhook | Push: post notification-worthy events to a channel |
| Microsoft Teams | Communication / On-Call | Incoming Webhook, or Graph API for adaptive cards | Push: same notification events as Slack |
| PagerDuty | Communication / On-Call | Events API v2 routing key | Push: page only the highest-urgency subset (confirmed KEV + SLA-breached Critical) |

The four **Network Security Management** entries above are the first
**remediation-actuation** connectors in this catalog — every entry before them either pulls
findings in or pushes a notification/ticket about a finding already known, while these push
an actual firewall/WAF policy or config change out. Treated with the same
reviewable-artifact-first safety posture as this repo's own playbook generation (see
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md)) — a generated config diff for human
review, never an unattended push — and directly foreshadows the still-open "Remediation
Engine: honest scheduling/policy/playbook visualization" roadmap item.

---

## See also

- [remediation/connectors/README.md](../remediation/connectors/README.md) — the
  connectors' own setup/usage instructions and the source of the "honesty about test
  coverage" language this doc follows.
- [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) — how ingestion and enrichment fit
  into the full remediation lifecycle.
- [USER_GUIDE.md](USER_GUIDE.md) and [FAQ.md](FAQ.md) — practical usage and scope
  questions.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — full
  architecture and roadmap.
