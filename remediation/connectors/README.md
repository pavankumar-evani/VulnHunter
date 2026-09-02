# Live Tenable/Armis Connectors

Real API client code for Tenable.io's Vulnerability Export API and Armis's REST API v1,
replacing the static sample-file ingestion in `remediation/sample-data/` with live data —
while keeping `vuln-ingest-normalizer.md` completely unchanged, because both connectors
write output in the exact same file shapes as the samples.

## ⚠️ Honesty about test coverage

**These connectors have NOT been exercised against a real Tenable.io or Armis tenant.**
No API credentials were available while building them. What they *are* tested against
(see `tests/test_connectors.py`, 18 tests, all mocked HTTP — no network, no credentials
needed) is each vendor's **publicly documented** API contract: correct auth header/flow
construction, correct endpoint URLs, correct pagination handling, correct mapping from
the documented response shape into the sample-compatible file format, and defensive
handling of error conditions (bad response shape, an export that errors out, a pagination
cursor that never terminates).

Before pointing this at a real account:
1. Get read-only API credentials for your Tenable.io / Armis tenant.
2. Run `fetch_live_data.py` against a **test/non-production** tenant first if possible.
3. **Diff the output against a manually-verified sample** from your actual tenant — field
   names and nesting can differ from the public docs depending on API version and your
   tenant's configuration. `TenableConnector.to_csv_row()` and
   `ArmisConnector._alert_to_sample_shape()` are the two places to adjust if so.

## Setup

```bash
pip install -r remediation/connectors/requirements.txt
export TENABLE_ACCESS_KEY=...
export TENABLE_SECRET_KEY=...
export ARMIS_SECRET_KEY=...
export ARMIS_BASE_URL=https://your-instance.armis.com
```

Credentials are read from environment variables only — never pass them as command-line
arguments (they'd leak into shell history and process listings).

## Usage

```bash
python remediation/connectors/fetch_live_data.py --source tenable
python remediation/connectors/fetch_live_data.py --source armis
python remediation/connectors/fetch_live_data.py --source all
```

Writes to `remediation/live-data/` (gitignored — this is real vulnerability data about
real infrastructure, it must never be committed). Then point `/remediate` at the live
files instead of the samples:

```
/remediate remediation/live-data/tenable_export.csv remediation/live-data/armis_export.json
```

## What each connector implements

**`tenable_connector.py`** — Tenable.io's asynchronous vulnerability export workflow:
request an export job, poll its status until `FINISHED`, download each chunk, flatten
each record into the same CSV columns as `tenable_export.csv`.

**`armis_connector.py`** — Armis's access-token auth flow, then a paginated AQL search
for alerts (`in:alerts` by default), resolving each alert's owning device and assembling
the result into the same nested `{"devices": [{"alerts": [...]}]}` shape as
`armis_export.json`.

Both accept an injectable `session` parameter specifically so they can be unit tested
without any real HTTP calls — see `tests/test_connectors.py`.

## SSRF guardrail (applies to every connector accepting a host/URL, not just this pair)

Any connector whose constructor takes an admin-supplied host, base URL, or platform
URL (Qualys, Prisma Cloud, Cortex XSIAM, Infoblox, Axonius, Active Directory, OpenVAS,
plus the push connectors) must have its target validated with
`remediation/connectors/url_safety.py`'s `assert_safe_target()` (or
`assert_safe_instance_label()` for a field interpolated into a fixed URL template, like
ServiceNow's `instance`) **before** the connector is constructed — see
`dashboard/app.py`'s `_require_safe_target()`/`_require_safe_instance_label()` helpers
and where each connector route calls them. This blocks cloud metadata endpoints/
loopback/link-local addresses; private RFC1918 ranges are allowed on purpose, since
on-prem tools are the expected common case here. `tenable_connector.py`/
`armis_connector.py` above don't take a connector call-site here in `dashboard/app.py`
today (see docs/enterprise-suite/rbac-governance.html's "AI & security guardrails"
section), so this doesn't apply to them yet — it would if either gained a dashboard
route with a user-supplied base URL.

## Manual/threat-intel source

There is deliberately no "connector" for the third source (manual threat intel) — by
definition it's analyst-curated, not pulled from an API. `threat_intel.json`'s format
(see `remediation/sample-data/threat_intel.json`) is simply what an analyst (or a ticket
export from wherever your team tracks findings) should be shaped as.
