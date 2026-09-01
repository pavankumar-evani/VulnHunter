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

- **Ready today, entirely from the dashboard - no CLI, no script**: ServiceNow, Jira,
  Splunk (push - findings out), and Tenable, Qualys, Prisma Cloud, Cortex XSIAM,
  Infoblox, Axonius, Active Directory (pull - data in). Every one of these takes real
  credentials fresh on every request, typed into that connector's own page under
  **Connectors / Adaptors** - never stored server-side, by design (see the "Credential
  storage" note each connector's connection-settings panel already shows).
- **Needs a script or Python session run outside the dashboard**: CrowdStrike Falcon
  only, for now. It pulls data rather than pushing it, and has no dashboard form yet -
  see its own section below for exactly what to run. The same Test Connection + Fetch
  pattern the pull connectors above already have is straightforward to add for
  CrowdStrike too, once there's a real credential to build and test it against.

None of the 12 connectors below have ever been exercised against a real account - every
one of them is a real, complete implementation of its vendor's documented API contract,
tested against mocked HTTP (or, for Active Directory, a hand-rolled fake LDAP
connection) that mimics that documentation, but "mimics the documentation" and
"confirmed against your actual tenant" are different claims. Treat your first real run
of each as a validation pass, not a guaranteed-correct production cutover - see each
section's "first real run" note.

## Finding-source connectors (replace the sample dataset with real data)

These four change what findings this dashboard's own pages show - the rest either push
findings out to another system, or pull asset-inventory data (not findings).

### Tenable.io

**What you need:** a Tenable.io API access key + secret key (Tenable.io → Settings →
My Account → API Keys - requires an account with API access enabled on your license).

**From the dashboard (recommended):** open **Connectors / Adaptors** → Tenable.io card
(or go straight to `/tenable`). Enter the access key + secret key, click **Test
Connection** for an immediate real credential check (`GET /session`, Tenable's lightest
authenticated call), then check the confirm box and click **Fetch Live Data** to run the
real export workflow - writes to `remediation/live-data/tenable_export.csv`, reporting
the real row count. Then run `/remediate remediation/live-data/tenable_export.csv` in an
interactive Claude Code session (see below for why this one step stays agent-driven),
and reload the dashboard.

**Equivalent, from a terminal:**
```bash
export TENABLE_ACCESS_KEY=...
export TENABLE_SECRET_KEY=...
python remediation/connectors/fetch_live_data.py --source tenable
/remediate remediation/live-data/tenable_export.csv
```
Useful for scripting/automation; the dashboard form above calls the same connector code.

**Why `/remediate` stays a manual, agent-driven step:** the real normalizer classifies
each asset's type (windows-server vs. unix-server vs. ...) from free-text OS fields the
same way a person would - that's judgment, not a deterministic mapping, so neither the
dashboard's Fetch button nor `fetch_live_data.py` skip straight to updating this
dashboard's own pages. See [INTEGRATIONS.md](INTEGRATIONS.md) for why.

**First real run:** `TenableConnector.to_csv_row()` is the adjustment point if real
field names/nesting differ from the documented shape (API version and tenant
configuration can both affect this) - diff a handful of real rows against what Tenable's
own UI shows for the same assets before trusting the output at scale.

### Qualys VMDR

**What you need:** a Qualys username + password with API access, and your subscription's
platform URL (Qualys → Help → About, or your onboarding email - e.g.
`https://qualysapi.qualys.com` for US Platform 1; Qualys assigns a different one per
platform/region, so there's no single default that works for every subscription).

**From the dashboard:** **Connectors / Adaptors** → Qualys VMDR card (or `/qualys`).
Enter platform URL + username + password, **Test Connection**, then confirm + **Fetch
Live Data** - writes to `remediation/live-data/qualys_export.csv` in the exact same
column shape as Tenable's export (a deliberate reuse decision - see
[INTEGRATIONS.md](INTEGRATIONS.md)). Then run
`/remediate remediation/live-data/qualys_export.csv` the same way as Tenable above.

**First real run:** `QualysConnector.fetch_host_detections_page()`/`fetch_knowledge_base()`
are the adjustment points if your pod's real XML response differs from the documented
shape.

### Prisma Cloud

**What you need:** a Prisma Cloud access key ID + secret key (Prisma Cloud console →
Settings → Access Control → Access Keys), and your stack's base URL (e.g.
`https://api.prismacloud.io`, `https://api2.prismacloud.io`,
`https://api.eu.prismacloud.io` - check your login URL's region).

**From the dashboard:** **Connectors / Adaptors** → Prisma Cloud card (or
`/prismacloud`). Enter base URL + access key ID + secret key, **Test Connection** (the
login call itself), then confirm + **Fetch Live Data**. Unlike Tenable/Qualys, this
writes already-normalized findings straight to
`remediation/live-data/prismacloud_findings.json` - no `/remediate` step needed, since
Prisma Cloud alerts are cloud posture/compliance violations (not CVE-scoped host
vulnerabilities), so no asset-type classification judgment is required. That said, this
output is deliberately **not** auto-merged into the live queue, the same explicit choice
the generic ingest adapter makes for its own output - see
[INTEGRATIONS.md](INTEGRATIONS.md) for why, and for what merging it in for real would
involve.

**First real run:** `PrismaCloudConnector.fetch_alerts()` fetches a single page only (a
documented scope limit) - a real integration at scale needs the pagination loop
described in that method's own docstring.

### Cortex XSIAM

**What you need:** a Cortex XSIAM API key + API Key ID (XSIAM console → Settings →
Configurations → API Keys - create a "Standard" key, not "Advanced"), and your tenant's
base URL (tenant- and region-specific, e.g.
`https://api-yourfqdn.xdr.us.paloaltonetworks.com`).

**From the dashboard:** **Connectors / Adaptors** → Palo Alto Cortex XSIAM card (or
`/cortex-xsiam`). Enter base URL + API key ID + API key, **Test Connection**, then
confirm + **Fetch Live Data**. Same "already-normalized, not auto-merged" behavior as
Prisma Cloud above, writing to `remediation/live-data/cortex_xsiam_findings.json`.

**First real run:** if your tenant requires "Advanced" auth (an HMAC request
signature) instead of "Standard," this connector needs that signing logic added - not
implemented here, see `cortex_xsiam_connector.py`'s module docstring.

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

## Asset-inventory connectors (real ip/mac ground truth - ready today)

These reconcile real network/directory data into `asset_ownership.json` (the same store
the Asset Inventory page's "Edit owner" form and CMDB CSV import already write to), not
findings. An asset with no existing findings against it is still stored (so its data is
already correct the moment a finding against it does show up) but won't appear on the
Asset Inventory table until then - that table is built from findings, not a separate
asset registry.

### Infoblox

**What you need:** your grid master hostname, a username, and a password with WAPI
read access to `record:host`.

**From the dashboard:** **Connectors / Adaptors** → Infoblox card (or `/infoblox`).
Enter grid master + username + password, **Test Connection** (a record:host fetch
capped to one result), then confirm + **Fetch Live Data** to pull real host records and
reconcile their real `ip` into the asset inventory.

### Axonius

**What you need:** an Axonius API key + API secret, and your tenant's base URL
(Axonius console → API page).

**From the dashboard:** **Connectors / Adaptors** → Axonius card (or `/axonius`). Same
shape as Infoblox - base URL + API key + API secret, Test Connection, confirm + Fetch.

### Active Directory (asset inventory)

**What you need:** an AD domain controller hostname (or `ldap://`/`ldaps://` URL), a
base DN (e.g. `DC=corp,DC=local`), and optionally a bind DN + password (a real AD often
requires an authenticated bind - anonymous works only if your directory allows it).

**From the dashboard:** **Connectors / Adaptors** → Active Directory card (or
`/active-directory`). Enter server + base DN (+ bind DN/password if needed), **Test
Connection** (a real LDAP simple bind + a trivial search), then confirm + **Fetch Live
Data** to pull the domain's computer objects. Note: AD computer objects carry no ip/mac
(that's DHCP/DNS's job, not AD's), so there's usually nothing for this specific fetch to
write into the asset inventory - it mainly proves connectivity and shows what the
domain's computer inventory looks like. For real ip/mac ground truth, use
Tenable/Qualys/Infoblox/Axonius above.

**A separate, pre-existing feature worth knowing about:** this dashboard already has a
*different* Active Directory integration - a read-only group-membership check
(`dashboard/auth/ad_directory.py`) that gates the Remediation Approval workflow,
configured server-wide via `AD_SERVER`/`AD_BASE_DN` environment variables. That one only
checks whether a named approver is in a specific AD group; it has nothing to do with the
asset-inventory connector above, and configuring one doesn't configure the other.

## Pull connector with no dashboard form yet (Python-only today)

Fetches data FROM the vendor rather than pushing to it, and has no `fetch_live_data.py`
entry either. Going live with it today means running a short Python script yourself.

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
it to `remediation/live-data/crowdstrike_export.json` yourself.

## Already fully ready, no credentials needed

**CMDB Import (CSV)** - Asset Inventory page → bulk-import owner/team from any CMDB's
CSV export. Not an API integration at all (a local file upload), so there's nothing to
configure - it's genuinely production-ready as-is today.

## Recommended next step

The highest-leverage single thing that would move this from "capable of going live" to
"actually live" is picking **one** real credential set and running it end to end -
Tenable is the natural first choice, since it's a connector that would change what the
dashboard's own findings actually are, not just where they get pushed or what asset data
gets reconciled. Once real credentials exist for anything, I can also close the
remaining gap noted above (adding a dashboard Test Connection + Fetch form for
CrowdStrike, the same pattern every other pull connector now has) - that's real, bounded
engineering work, just not yet built because there was never a credential to build and
test it against.
