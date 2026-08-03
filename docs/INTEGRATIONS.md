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

## Not yet built

The connector *pattern* — vendor auth flow, paginated fetch, mapping into a stable
internal schema, mocked-HTTP unit tests, an explicit "built vs. verified" caveat — is now
proven three times over (Tenable, Armis, ServiceNow). Adding SIEM/XDR adapters is the
same pattern again:

- **Splunk**
- **Microsoft Sentinel**
- **IBM QRadar**
- **CrowdStrike**
- **Microsoft Defender**

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
