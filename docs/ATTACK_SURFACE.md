# External attack surface (import-based)

Page `/attack-surface` (Module 4, Infrastructure & Exposure; administrators). Code in `remediation/asm/`, policy in `remediation/config/asm_policy.yaml`.

**Quanta never scans and never contacts a target.** You run discovery tools against domains and ranges you own or are authorised in writing to test; Quanta reads their output. It sees only what you import, and says how old that is everywhere it shows a number.

## Inputs

| Tool | Flag for Quanta | Becomes |
|---|---|---|
| subfinder | `-oJ` | subdomains (kind `subdomain`, or `domain` when it equals a declared domain) |
| dnsx | `-json` | resolved addresses, CNAMEs, DNS status (feeds the takeover check) |
| httpx | `-json` (add `-tech-detect -web-server -tls-grab`) | web endpoints (`url`, keyed by origin), services, technologies, certificate facts |
| naabu | `-json` | services `host:port/proto`, addresses |
| nuclei | `-jsonl` | check results attached to the endpoint or service they matched |
| seeds | CSV `domain,example.com` / `cidr,203.0.113.0/24` | your declared scope (administrator only) |

JSON lines or a JSON array are both accepted. A missing field is simply absent; a malformed line is counted and skipped; an unknown tool, empty input, or output of a different tool is a clear 400. Limits: 50 MB and 200,000 records per import, 100,000 assets, 5,000 change rows per run (counts stay complete).

Send it from the page (Import and scope tab) or from a pipeline:

```
curl -sS -X POST 'https://quanta.example/api/ingest/asm?tool=httpx&scope=example.com&complete=false&publish=false' \
  -H "Authorization: Bearer $QUANTA_API_KEY" --data-binary @httpx.json
```

`POST /api/ingest/asm` needs an API key with scope `asm:write`. It cannot change the scope: `tool=seeds` is refused there. `publish=true` also refreshes the queue findings.

## Assets, delta and scope

Every asset has a stable key `kind:value` (`domain`, `subdomain`, `ip`, `service host:port/proto`, `url scheme://host[:port]`), so importing the same data twice changes nothing. Each import records a run and a delta:

- **new**: first seen (or seen again after it had disappeared, shown as `reappeared`).
- **changed**: an existing endpoint or service gained a technology or a different certificate (fingerprint, expiry or issuer).
- **disappeared**: absent from a **complete** import (`complete=true`) by a tool that can speak for absence (subfinder and dnsx for subdomains, httpx for endpoints, naabu for services), limited to the `scope` you name (a domain or range), and only if that tool had seen the asset before. A partial file never removes anything; nuclei and seeds cannot.

Scope is what you declare (domains and CIDR ranges; the scope page or seeds CSV). An asset outside it is stored and flagged `outside scope`, counted separately, never raises a finding and never joins the graph. An address is in scope if it is in a declared range or was seen with an in-scope name. With no scope declared everything counts as in scope and the page says so. Owner and team come from the existing asset ownership records.

## Findings

Source `asm`, published as the complete set each time (`POST /api/asm/publish` with `confirm`, or `publish=true` on import), so findings the data no longer shows are removed. Rules, all explicit and editable in `asm_policy.yaml`:

| Rule | Raised when | scan type |
|---|---|---|
| ASM-NUCLEI | a nuclei result (CVE id and CVSS carried so KEV/EPSS enrichment works; `info` counted, not raised) | dast |
| ASM-PORT | a risky service (RDP, SMB, Telnet, databases, management APIs) is reachable; SSH judged separately (Medium on a host that also serves a website) | infra-vm |
| ASM-TLS | expired, expiring within `warn_days`, self-signed or mismatched certificate (asset type certificate) | cert-mgmt |
| ASM-TAKEOVER | a CNAME to a provider that allows claiming names whose target no longer resolves or returns 404. **A name match**, and the finding says so | dast |
| ASM-MGMT | a title or address contains a management-interface word (a word match, confirmed by a person) | dast |
| ASM-TECH | a reported version is below your minimum for that product. Only where a version was reported; never guessed; not a vulnerability lookup | dast |
| ASM-SHADOW | in scope, seen from outside, absent from the asset inventory (findings from other sources, recorded owners). With no inventory the rule does not run and says so | infra-vm |

Each finding carries evidence, how fresh the evidence is ("Last observed 2026-10-01 (3 days ago) by httpx") and the exact next step. A rule with no data to judge raises nothing and the findings tab lists the gap (for example "no naabu output imported") so an empty result is never read as clean.

## Stale data

Set an expected import cadence (hours). If nothing arrives within it, the summary turns `stale`, every view says the data is out of date, and the leader tick raises one SOC alert "Stale attack-surface data" per episode (source `asm`). Data age is on every API response and page tab.

## API (administrator unless noted)

`POST /api/ingest/asm` (key `asm:write`), `POST /api/asm/import`, `GET /api/asm/summary|assets|changes|scope|findings|how-to-feed`, `PUT /api/asm/scope`, `PUT /api/asm/settings`, `POST /api/asm/publish`.

## Graph

The infrastructure relationship graph gains a bounded lane (at most 150 nodes): domain, address, exposed service or endpoint, technology, from in-scope active assets only.

## Honest limits

- Built against the tools' public documentation of their JSON output and tested on sample lines; never run against live output at scale.
- No active discovery: a host nobody imported does not exist to Quanta, and an unscanned port is unknown, not closed.
- Takeover and management-interface rules are name and word matches; technology rules compare against your own minimums, not a vulnerability database.
- Disappearance is only as good as the claim that an import was complete.
- Endpoints are keyed by origin, so two different paths on one origin are one asset (nuclei matches keep their full matched URL).
