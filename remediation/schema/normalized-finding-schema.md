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
    "type": "windows-server | windows-endpoint | unix-server | network-routing-switching | network-security-device | iot-ot-device | virtualization-host | cloud-infrastructure | application | certificate | client-application | mobile-device | printer | iac-resource | code-repository | container-runtime | ai-ml-system",
    "os": "Microsoft Windows Server 2019 Datacenter"
  },
  "title": "MS Windows Print Spooler Remote Code Execution (PrintNightmare)",
  "cve": "CVE-2021-34527",
  "cvss": 8.8,
  "severity": "Critical | High | Medium | Low",
  "description": "Plain-English impact, not just the vendor synopsis.",
  "recommended_fix": "What the source system suggests (patch, config change, etc.)",
  "remediation_domain": "windows-server | unix-server | iot-ot-device | application | null",
  "dependency": {
    "package": "log4j-core",
    "ecosystem": "maven",
    "version": "2.14.1",
    "fixed_version": "2.17.1",
    "direct": false
  },
  "remediation_mechanism": "SCCM / Microsoft Configuration Manager | MDM (e.g. Microsoft Intune) | Vendor firmware update | Vendor hypervisor patch tooling | null",
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
  },
  "poc_available": true,
  "user_interaction_required": false
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
  `client-application` covers desktop/endpoint software (browsers, PDF readers, chat
  clients) rather than a server-side application. `cloud-infrastructure` is listed for
  completeness (real vulnerability-management platforms, including Tenable and Armis, do
  cover AWS/Azure/GCP asset/posture scanning) - same "supported category, not faked"
  treatment `scan_type_mapping.py` already documents for DAST.
  `iac-resource` (Infrastructure-as-Code misconfigurations - Checkov/tfsec-style static
  analysis of Terraform/CloudFormation templates, no CVE), `code-repository`
  (GitHub/GitLab-style findings - Dependabot-style dependency alerts *with* a CVE,
  secret-scanning alerts without one), `container-runtime` (Falco-style runtime/
  container behavioral detections, no CVE), `ai-ml-system` (hand-authored AI/ML
  security findings - prompt injection, model supply-chain, excessive agency, etc.,
  no CVE - see `remediation/enrichment/ai_vuln_taxonomy.py`), `mobile-device`
  (phone/tablet OS and app CVEs - patched via an MDM platform, e.g. Microsoft Intune,
  not SCCM directly), `printer` (networked printer/MFP firmware CVEs - HP, Xerox,
  Canon, Lexmark, Ricoh, etc.), and `virtualization-host` (hypervisor/VM-platform CVEs -
  VMware ESXi/vCenter, Microsoft Hyper-V, Proxmox VE, Citrix Hypervisor) round out the
  taxonomy. `windows-endpoint` (laptops/desktops - patched via SCCM/Microsoft
  Configuration Manager) is now a real, populated category rather than a documented-
  but-empty asset type. See `remediation/enrichment/infra_classification.py` for how
  `asset.type` rolls up into the Infrastructure Vulnerabilities hub's Server/End-User
  Device/Network/Network Security/OT/Virtualization/Cloud/Printer/IaC/Runtime
  sub-categories (`ai-ml-system` deliberately does NOT roll up there - AI Vulnerabilities
  is its own top-level Security Domains entry, not an infra sub-category), and
  `remediation/enrichment/scan_type_mapping.py` for the broader Infra-VM/SCA/Cert-
  Mgmt/SAST/DAST/IaC/Secrets/Runtime/AI-ML methodology taxonomy.
- **`remediation_domain`** is set by the normalizer from `asset.type`, and reflects
  whether a *working* `remediation-fixer-*` subagent exists for it today - only
  `windows-server`/`unix-server`/`iot-ot-device`/`application` do, so this is `null` for
  every other asset type, including the new ones added alongside
  `windows-endpoint`/`mobile-device`/`printer`/`virtualization-host` above (no automated
  fixer exists for any of them yet). `iot-ot-device`'s fixer (`remediation-fixer-ot`) is a
  deliberately different shape from the other two OS-level fixers - it generates a
  compensating-control/vendor-coordination recommendation, never a direct patch script,
  since OT devices are usually unsafe to patch live (see that subagent's own file, and the
  Remediation Engine document's "Three remediation tracks" section, for why).
  `application`'s fixer (`remediation-fixer-application`) is a fourth, different shape
  again - a dependency-upgrade plan generated from the `dependency` field below, not an OS
  patch or a compensating control - and only applies to `application`-type findings that
  have a real CVE (the SCA case; see `remediation/enrichment/scan_type_mapping.py`), not
  every `application` finding.
- **`remediation_mechanism`** is a purely informational, reference-only field (not a
  working integration - there is no SCCM/Intune API call anywhere in this codebase) that
  names the REAL-WORLD tool that would normally patch that asset class, so a finding on
  an end-user device or hypervisor at least says which team/tool owns it, even though
  this app can't generate a fix artifact for it the way it can for `windows-server`/
  `unix-server`. `null` for asset types where no single obvious tool applies (e.g.
  `network-routing-switching`, which varies too much by vendor to name one mechanism
  honestly).
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
- **`poc_available`** and **`user_interaction_required`** are added by
  `remediation/enrichment/poc_enrichment.py` (a pipeline stage, same timing as
  `kev`/`epss`) from two real, never-fabricated NVD API 2.0 fields already present in
  the raw CVE data `generate_bulk_findings.py` fetched: `references[].tags` containing
  `"Exploit"`, and the CVSS `userInteraction` metric (v4.0 first, falling back to
  v3.1/v3.0 for CVEs not yet scored under v4.0 - see `poc_enrichment.py`). Both are `null` when `cve` is
  `null`, or when the CVE predates this repo's local NVD cache (an honest gap, not a
  guess). `remediation/enrichment/exploit_criteria.py` combines these with `kev`/`epss`
  into a configurable, admin-editable `exploit_criteria_matches` field - computed LIVE
  by the dashboard (like `eol_status`/`compensating_controls`), not persisted into this
  file, so it isn't shown in the example above.
- **`dependency`** is nullable — populated by `vuln-ingest-normalizer` only when (a) the
  finding is `application`-type with a real CVE (the SCA case) and (b) a CycloneDX SBOM
  file was supplied alongside the scanner exports and it contains a component matching
  this finding's affected package. Matching a CVE/title to a specific SBOM component is a
  judgment call the normalizer's own LLM reasoning makes directly from the SBOM's raw
  JSON (see that subagent's file) — there's no mechanical CVE-to-package lookup table for
  it. `fixed_version` is populated only when the normalizer is confident of the real safe
  version from its own knowledge of that CVE; left `null` rather than guessed when it
  isn't, the same "don't fabricate" rule this pipeline applies everywhere else. `direct`
  is `true` when the package is a direct dependency of the scanned application, `false`
  for a transitive one - `remediation/enrichment/sbom.py`'s `compute_blast_radius()`
  answers the related "how many other components does fixing this affect" question,
  computed live by the dashboard from the same SBOM file, not persisted into this field.
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
