# Going live: what's needed for real production integration

**How to use this doc:** a direct, honest answer to "what do I actually need to
connect this to real systems" - exact credentials, exact steps, per connector, and
which pieces are ready today versus which still need real-world engineering. See
[INTEGRATIONS.md](INTEGRATIONS.md) for the fuller technical writeup of what each
connector does and its verification status; this doc is the operational checklist for
actually flipping one on.

## The honest starting point

Every real finding shown in this dashboard today comes from a bundled sample dataset
(`remediation/output/normalized-findings.json`), not a live system. That's the one fact
that has to be stated plainly before anything else here: **going live requires real
credentials for whichever system you want to connect, and this project has never had
any** - not Tenable, not ServiceNow, not any of the others. No amount of code changes
on my end substitutes for that. What I can do, and have done below: make sure the code
path is actually ready the moment you have credentials, and tell you precisely what to
get and where to put it.

Two genuinely different situations, by connector:

- **Ready today, zero code changes needed**: ServiceNow, Jira, Splunk. Real credentials
  typed into that connector's own page and never stored server-side - per-request, by
  design (see [ADR-style reasoning in adaptors.js](../dashboard/static/js/pages/adaptors.js)).
- **Needs a script or Python session run outside the dashboard**: Tenable, Armis,
  CrowdStrike Falcon, Infoblox, Axonius. These pull data rather than push it, and
  (except CMDB import) have no dashboard form - see each one's own section below for
  exactly what to run.

None of the 8 API-based connectors below have ever been exercised against a real
account - every one of them is a real, complete implementation of its vendor's
documented API contract, tested against mocked HTTP that mimics that documentation, but
"mimics the documentation" and "confirmed against your actual tenant" are different
claims. Treat your first real run of each as a validation pass, not a guaranteed-correct
production cutover - see each section's "first real run" note.

## Finding-source connectors (replace the sample dataset with real data)

These are the two that actually change what findings the dashboard shows.

### Tenable.io

**What you need:** a Tenable.io API access key + secret key (Tenable.io → Settings →
My Account → API Keys - requires an account with API access enabled on your license).

**Steps:**
1. Set real environment variables on the server: `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`
   (see [.env.example](../.env.example)).
2. Run `python remediation/connectors/fetch_live_data.py --source tenable`. This calls
   the real Tenable.io Vulnerability Export API and writes
   `remediation/live-data/tenable_export.csv` - can take several minutes for a large
   tenant (it's a real async export job, not a quick call).
3. Run `/remediate remediation/live-data/tenable_export.csv` in an interactive Claude
   Code session. This is the step that actually normalizes real Tenable rows into
   `remediation/output/normalized-findings.json` - the one file the dashboard reads.
   It's an agent-driven step, not a plain script, because the real normalizer
   classifies each asset's type from free-text fields the same way a person would -
   see [INTEGRATIONS.md](INTEGRATIONS.md) for why.
4. Reload the dashboard - it now reflects your real Tenable data.

**First real run:** `TenableConnector.to_csv_row()` is the adjustment point if real
field names/nesting differ from the documented shape (API version and tenant
configuration can both affect this) - diff a handful of real rows against what Tenable's
own UI shows for the same assets before trusting the output at scale.

### Armis

**What you need:** an Armis Secret Key and your tenant's API base URL (Armis console →
Settings → API Management).

**Steps:** same shape as Tenable - set `ARMIS_SECRET_KEY`/`ARMIS_BASE_URL`, run
`python remediation/connectors/fetch_live_data.py --source armis` (writes
`remediation/live-data/armis_export.json`), then `/remediate remediation/live-data/armis_export.json`.

**First real run:** `ArmisConnector._alert_to_sample_shape()` is the adjustment point if
your tenant's AQL search response shape differs from the documented one.

## Ticketing / SIEM connectors (push real findings out - ready today)

No environment variables, no server restart - these take credentials fresh on every
request, directly in their own page, and use them once.

### ServiceNow

**What you need:** your ServiceNow instance name (the `xxx` in `xxx.service-now.com`),
a username, and a password with permission to create records on the target table
(`incident` by default - a table any ServiceNow instance has with no extra plugin, or
point it at your own Vulnerability Response table name if you use that module).

**Steps:** open **Connectors / Adaptors** → ServiceNow card → the preview form. Fill in
instance/username/password, check "I have real credentials...", Submit. Strongly
recommend pointing this at a non-production ServiceNow instance first if you have one -
this is the connector's first-ever real-world exercise.

### Jira Cloud

**What you need:** your site URL (`https://yourcompany.atlassian.net`), the email
address of a Jira account, an API token for that account (Atlassian account settings →
Security → API tokens - not your login password), and a real project key.

**Steps:** same shape - Connectors / Adaptors → Jira card → fill in the four fields →
confirm → Submit.

### Splunk

**What you need:** a real HTTP Event Collector (HEC) URL and token (Splunk → Settings →
Data Inputs → HTTP Event Collector - create a token if one doesn't exist, and confirm
the HEC input is enabled).

**Steps:** same shape - Connectors / Adaptors → Splunk card → HEC URL + token → confirm
→ Submit. Splunk HEC is an append-only event stream, not a ticket system - re-running
this against the same findings later is expected behavior, not a bug (see the page's own
disclosure).

## Pull connectors with no dashboard form yet (Python-only today)

These fetch data FROM the vendor rather than pushing to it, and - unlike Tenable/Armis -
don't have a `fetch_live_data.py` entry either. Going live with any of these today means
running a short Python script yourself (or asking for one to be written - see
"Recommended next step" below).

### CrowdStrike Falcon

**What you need:** an OAuth2 client ID + client secret (Falcon console → Support and
resources → API clients and keys - create a client with the alert-read scope).

**How to use it today:**
```python
from remediation.connectors.crowdstrike_connector import CrowdStrikeConnector
conn = CrowdStrikeConnector(client_id="...", client_secret="...")
findings = conn.fetch_and_normalize_alerts()
```
`findings` is a list already shaped like this repo's normalized-finding schema - write
it to `remediation/live-data/crowdstrike_export.json` yourself and feed it into
`/remediate` the same way as Tenable/Armis above.

### Infoblox

**What you need:** your grid master hostname, a username, and a password with WAPI
read access to `record:host`.

**How to use it today:**
```python
from remediation.connectors.infoblox_connector import InfobloxConnector
conn = InfobloxConnector(grid_master="grid.example.com", username="...", password="...")
assets = conn.fetch_and_normalize_hosts()
```
`assets` is asset-inventory data (name/ip/mac/type), not findings - reconcile it into
`remediation/inventory/asset_inventory.py` the same way CMDB CSV import already does on
the **Asset Inventory** page.

### Axonius

**What you need:** an Axonius API key + API secret (Axonius console → API page).

**How to use it today:**
```python
from remediation.connectors.axonius_connector import AxoniusConnector
conn = AxoniusConnector(base_url="...", api_key="...", api_secret="...")
devices = conn.fetch_and_normalize_devices()
```
Same asset-inventory reconciliation as Infoblox above.

## Already fully ready, no credentials needed

**CMDB Import (CSV)** - Asset Inventory page → bulk-import owner/team from any CMDB's
CSV export. Not an API integration at all (a local file upload), so there's nothing to
configure - it's genuinely production-ready as-is today.

## Recommended next step

The highest-leverage single thing that would move this from "capable of going live" to
"actually live" is picking **one** real credential set and running it end to end - Tenable
is the natural first choice, since it's the connector that would change what the
dashboard's own findings actually are, not just where they get pushed. Once real
credentials exist for anything, I can also close the remaining gap noted above (adding
a `fetch_live_data.py`-style script, or a dashboard form, for CrowdStrike/Infoblox/
Axonius) - that's real, bounded engineering work, just not yet built because there was
never a credential to build and test it against.
