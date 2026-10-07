# Quanta — Connecting Your Sources

What to have ready for each source, what to enter on **Connections**, and what you should see.
Credentials are stored encrypted (needs `QUANTA_ENCRYPTION_KEY`) and are never displayed again.
For each: use the account your security team already issues for read-only API access, with the
smallest role that can read vulnerability or asset data. See [GOING_LIVE.md](GOING_LIVE.md) for
vendor-side detail.

Host and URL fields are checked before anything is contacted: cloud metadata addresses,
loopback and link-local targets are refused. Private (RFC 1918) addresses are allowed, since
on-premises security tools live there.

| Source | You provide | Pulls | Behaviour |
|---|---|---|---|
| **Tenable.io** | access key, secret key | Vulnerability findings | Full export. Findings no longer reported are removed on each sync. |
| **Qualys VMDR** | platform URL (your region's API base), username, password | Vulnerability findings | Added and refreshed; never auto-removed (large tenants can truncate). |
| **Prisma Cloud** | API base URL, access key ID, secret key | Cloud posture alerts | Added and refreshed. |
| **Cortex XSIAM** | API base URL, API key ID, API key | Correlated incidents | Added and refreshed. |
| **Infoblox** | grid master host, username, password | Host IP/MAC records | Reconciled into the asset inventory. |
| **Axonius** | base URL, API key, API secret | Device records | Reconciled into the asset inventory. |
| **Active Directory** | server, base DN, optional bind DN and password, LDAPS | Computer objects | Names only (AD carries no IP/MAC); no findings. |
| **Microsoft Sentinel search** | Log Analytics workspace id, Entra tenant, client id and secret (Log Analytics Reader) | Nothing synced; read-only KQL on demand | Hunts and investigations, after a person confirms. See [SIEM_CONNECTORS.md](SIEM_CONNECTORS.md). |
| **Google SecOps search** | API URL, instance resource, OAuth2 access token | Nothing synced; read-only UDM search on demand | As above. Quanta does not mint tokens or touch rules. |
| **Elastic search** | URL, API key (read on the hunted indexes), language eql or esql, index pattern | Nothing synced; read-only EQL or ES\|QL on demand | As above. Only the search, query and info endpoints are reachable. |
| **CrowdStrike Falcon lookup** | API client id and secret (Hosts: Read, Alerts: Read) | Nothing synced; host and detection lookups on demand | As above. Five fixed read calls; no containment. |
| **TAXII 2.1 server** | API root URL and a token, key or username and password | Nothing synced by the scanner sync; reports polled by the report watcher | Add the connection, then a source on Threat Intelligence > Report sources. See [INTEL_WATCHER.md](INTEL_WATCHER.md). |

OpenVAS/GVM launches scans that run for a long time, so it stays on its own page under
Connectors / Adaptors (start, check status, import).

## The first sync, step by step

1. **Test connection** must say *Connected*. If not, the message is the vendor's own error:
   401/403 means the credentials or role, a timeout means a network path or proxy.
2. **Sync now**. For a large tenant the first pull can take minutes; the row keeps showing
   *Syncing…* and the page refreshes itself.
3. Read the result line, for example *Fetched 1,240 findings: 1,240 new, 0 updated; skipped 310
   informational rows. Threat intel (KEV, EPSS) refreshed.*
4. Open **Queue**, **Assets** and **Ownership**. Findings are scored live from the data the scanner
   provided; owners and teams can be set per asset or bulk-imported from your CMDB.
5. Set a schedule (hourly or daily) once the first result looks right.

## If something looks wrong

| You see | Likely cause | What to do |
|---|---|---|
| *Failed: 401 / 403* | wrong key, expired key, or the role cannot read the data | regenerate the key; check the role |
| *Failed: … getaddrinfo / timeout* | the Quanta host cannot reach the source | firewall, DNS, proxy; allow the host outbound |
| *Failed: could not be decrypted* | `QUANTA_ENCRYPTION_KEY` changed | restore the previous key; re-enter the credentials |
| Fewer findings than the scanner shows | informational rows skipped; Qualys truncation | informational rows are by design; check the skipped count in the message |
| Many assets of type *unknown* | OS strings the rules do not recognise | they are still scored and queued by severity; send the OS strings so the classification rules can grow (`remediation/ingest/classify.py`) |
| *Threat-intel refresh failed* | the CISA/FIRST feeds are unreachable from the host | allow outbound to them, or run **Refresh** from Overview later |

Every sync, success or failure, is in the Activity Log with who or what started it.
