# Normalized Finding Schema

Every source connector (Tenable, Armis, manual threat intel — and any future source:
Qualys, CrowdStrike, ServiceNow, etc.) maps its own export format into this one shape.
Everything downstream (`remediation-planner`, `remediation-fixer-*`) only ever reads this
schema — it never needs to know about Tenable CSV columns or Armis JSON fields directly.
This is the same "read-only scanner / scoped tool" separation-of-concerns idea as the
`/vulnhunt` pipeline, applied to infra findings instead of source code.

```json
{
  "id": "FIND-1",
  "source": "tenable | armis | threat-intel",
  "source_ref": "<plugin ID / device ID / intel ID from the origin system>",
  "asset": {
    "name": "WIN-DC01",
    "ip": "10.20.30.41",
    "type": "windows-server | windows-endpoint | unix-server | network-routing-switching | network-security-device | iot-ot-device | application | certificate",
    "os": "Microsoft Windows Server 2019 Datacenter"
  },
  "title": "MS Windows Print Spooler Remote Code Execution (PrintNightmare)",
  "cve": "CVE-2021-34527",
  "cvss": 8.8,
  "severity": "Critical | High | Medium | Low",
  "description": "Plain-English impact, not just the vendor synopsis.",
  "recommended_fix": "What the source system suggests (patch, config change, etc.)",
  "remediation_domain": "windows-server | unix-server | network-routing-switching | network-security-device | iot-ot-device | application | certificate | null",
  "first_seen": "2026-07-28",
  "last_seen": "2026-08-02",
  "kev": {
    "listed": true,
    "date_added": "2021-11-03",
    "vulnerability_name": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability",
    "known_ransomware_campaign_use": "Known",
    "due_date": "2021-11-17"
  },
  "epss": {
    "score": 0.9976,
    "percentile": 0.9996
  }
}
```

## Field notes

- **`asset.type`** is the routing key: it decides which `remediation-fixer-*` subagent (if
  any) can handle this finding. Only `windows-server` and `unix-server` have a working
  fixer today — everything else is normalized and planned, but generation of an actual
  fix artifact is left as "not yet automated, route to the relevant team" (see
  `remediation-planner.md`). `application` and `certificate` were added alongside the
  original infra-focused types to make explicit that this pipeline covers more than
  OS-level patching: application-layer library CVEs (e.g. Log4Shell) and TLS/certificate
  lifecycle findings (expiry, deprecated protocols) are a different remediation domain
  again — a code/library upgrade or a cert renewal, not an OS package update.
- **`remediation_domain`** is set by the normalizer from `asset.type`, but kept as a
  separate field (not just reusing `asset.type`) because in a real deployment some asset
  types might route to more than one remediation mechanism (e.g. a Windows endpoint patched
  via Intune vs. a Windows Server patched via WSUS/Ansible) — that routing nuance lives
  here, not baked into the asset classification itself.
- **`cve`** is nullable — Armis in particular frequently reports policy/configuration
  findings (open Telnet, unauthenticated management UI) with no CVE attached, and so do
  most certificate-lifecycle findings (an expiring cert isn't a CVE).
- **`kev`** and **`epss`** are added by `threat-intel-enricher` (a pipeline stage after
  normalization, before planning) — they don't exist yet on the normalizer's raw output.
  Both are `null` when `cve` is `null` (KEV/EPSS are inherently CVE-scoped). When `cve` is
  set but the CVE isn't in KEV, `kev` is `{"listed": false}` rather than `null` — that's a
  deliberate distinction between "checked, and it's not exploited-in-the-wild" vs. "not
  applicable to this finding at all." See
  [remediation/enrichment/kev_epss.py](../enrichment/kev_epss.py).
- IDs (`FIND-N`) are assigned by the normalizer, sequential across all sources combined,
  so `remediation-planner` and `remediation-fixer-*` have one consistent key regardless of
  which system a finding originated from.

## Why this matters beyond the hackathon demo

This is the actual hard part of "AI remediation" in a real enterprise: Tenable, Armis,
and analyst-curated threat intel each use completely different schemas, severity scales,
and asset identifiers (hostname vs. IP vs. device ID vs. FQDN). Any automation that skips
normalization and tries to special-case three source formats through the whole pipeline
turns into an unmaintainable mess the moment a fourth source (Qualys, ServiceNow, CMDB
enrichment) shows up. Normalize once, at the edge, into one schema — everything else stays
source-agnostic.
