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
| Tenable.io connector | Pulls vulnerability findings via the async Vulnerability Export API | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Armis connector | Pulls device-risk alerts via token auth + paginated AQL search | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| ServiceNow connector | Creates an Incident per finding via the Table API, idempotently | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live instance |
| Jira Cloud connector | Creates an Issue per finding via the REST API v3, idempotently (label-keyed) | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live site |
| Splunk HEC connector | Pushes each finding to Splunk as an HTTP Event Collector event | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live instance |
| CrowdStrike Falcon connector | Pulls EDR/XDR alerts via OAuth2 client-credentials + query/fetch-entities | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| Infoblox connector | Pulls DNS host records via WAPI, normalizes into asset-inventory entries (not findings) | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live grid |
| Axonius connector | Pulls aggregated device records via the devices API, normalizes into asset-inventory entries (not findings) | Built against public docs, **unit-tested against mocked HTTP only** — never exercised against a live tenant |
| CISA KEV enrichment | Flags CVEs confirmed actively exploited in the wild | **Live-verified** — built and tested against the real, free, public endpoint |
| FIRST.org EPSS enrichment | Attaches a 0–1 exploitation-probability score per CVE | **Live-verified** — built and tested against the real, free, public endpoint |

The last two are the only integrations in this repo that have actually talked to their
real target service during development. Everything else has a real, working
implementation of its vendor's documented contract, backed by tests — but "tested" there
means "tested against mocked HTTP shaped like the documentation," not "confirmed to work
against a real account."

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
(`normalize_alert()`). Like Tenable and Armis, this is a **pull** connector — there's no
dashboard send form, only a reference page at `/xdr` describing what it does and how to
use it from Python, since there's nothing to preview/send, only to fetch and normalize.
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

## Infoblox connector

**File:** [`remediation/connectors/infoblox_connector.py`](../remediation/connectors/infoblox_connector.py)

Pulls DNS host records from an Infoblox NIOS grid via the documented WAPI (Web API)
`record:host` object (`GET /wapi/{version}/record:host`, HTTP Basic auth), and normalizes
each into VulnHunter's shared **asset-inventory** shape (`name`, `ip`, `mac`, `type`,
`source`, `source_ref`, `extra`) — unlike every connector above, this produces asset
records, not vulnerability findings, because Infoblox is a DNS/IPAM system, not a
vulnerability scanner. Like CrowdStrike, this is a **pull** connector with no dashboard
send form — a reference page at `/infoblox` describes what it does and how to use it
from Python. A DNS host record doesn't carry MAC address or OS/platform data (those live
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

## Axonius connector

**File:** [`remediation/connectors/axonius_connector.py`](../remediation/connectors/axonius_connector.py)

Pulls aggregated device records from Axonius's documented REST API (`POST /api/devices`
with an offset/limit pagination body, `api-key`/`api-secret` header auth), and normalizes
each into the same asset-inventory shape Infoblox produces. Axonius's own value
proposition is aggregating asset data across many source adapters (CMDB, EDR, cloud,
network) into one inventory, so each normalized record keeps the reporting `adapters`
list in `extra`. Like Infoblox, this is a **pull** connector with a reference page at
`/axonius`, not a dashboard send form. Two documented scope limits: the exact response
envelope key has varied across Axonius API versions in public docs (`"assets"` is used
as the most standard/likely key), and this connector fetches a single page only — a real
integration needs an offset/limit pagination loop the same way `ArmisConnector.search_all_pages()`
does.

**Verification status:** built against Axonius's publicly documented REST API contract
(referenced directly in the module's docstring). Covered by 17 tests in
`tests/test_axonius_connector.py` — auth header construction, request body construction,
device-to-asset mapping (including the OS-type-to-asset-type mapping and IP/MAC
list-fallback extraction), and defensive handling of a device with missing fields — all
against mocked HTTP. **It has not been exercised against a real Axonius tenant**, same
reason as every other connector here: no credentials were available while building it.

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

## Not yet built

The connector *pattern* — vendor auth flow, paginated fetch, mapping into a stable
internal schema, mocked-HTTP unit tests, an explicit "built vs. verified" caveat — is now
proven eight times over for vulnerability-finding connectors (Tenable, Armis, ServiceNow,
Jira, Splunk, CrowdStrike) and asset-inventory connectors (Infoblox, Axonius), plus the
generic webhook adapter above for anything that can push data to VulnHunter rather than
needing VulnHunter to pull from it. A **bespoke, vendor-specific pull connector**
(matching a particular product's own auth/pagination/query language, the way Tenable's
and Armis's do) is the same pattern again for:

- **Microsoft Sentinel**
- **IBM QRadar**
- **Microsoft Defender**
- **Qualys**

None of these are built. Each is gated on picking a specific vendor and having real API
docs (or, better, sandbox/tenant access to verify against) — not a technical blocker, a
scoping one. See
[KNOWLEDGE_TRANSFER.md §11](../KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)
for the full reasoning on why these (and dark-web monitoring, and "AI-based
anomaly/behavioral detection") were deliberately scoped out rather than attempted
alongside everything else — this document doesn't re-argue that case, only points at it.

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
