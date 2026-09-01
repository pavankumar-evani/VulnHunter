# VulnHunter vs. ServiceNow VR and modern alternatives

**How to use this doc:** pavane's stated pain points with ServiceNow's Vulnerability
Response (VR)/USEM module — too much documentation, very high cost, too complex, not
user/support-friendly — plus a request to research whether VulnHunter can be repositioned
as a modern in-house alternative, informed by four named platforms: Nucleus Security,
DefectDojo Pro, Brinqa, and ArmorCode. This doc separates **verified facts** (cited,
independently re-checked) from the source material's unverified claims, states
VulnHunter's actual current capability against that real data (not aspiration), and ends
with a prioritized, phased roadmap. See also [INTEGRATIONS.md](INTEGRATIONS.md) for the
authoritative list of what VulnHunter's connectors actually do today, and
[KNOWLEDGE_TRANSFER.md §9](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)
for the broader roadmap this feeds into.

---

## 1. A caveat on the source material, stated up front

The attached deck ("Affordable Alternatives to ServiceNow VR Module") is explicitly
self-labeled **"AI Generated Draft"** on every slide, was built by a tool called
"Sidekick," and its own final slide is a disclaimer that its output "may contain
information that is inaccurate, dated, incomplete, or not aligned to your specific
needs... must not be considered final deliverables." Concretely:

- The deck repeatedly references **"Tyson"** ("consolidating vulnerability findings from
  all key Tyson tools," "integrate Tyson's stack," "positions Tyson for scalable...
  vulnerability management") — a company name with no connection to VulnHunter or
  Deloitte. This is a leftover/hallucinated artifact from generating the deck, not a
  real requirement — a concrete sign the deck was not built specifically for this
  project and wasn't proofread before being shared.
- Its "References" slide lists two sources with the actual URL replaced by a literal
  `[Link]` placeholder — there is no real citation trail behind its numbers.
- Its specific statistics (70–80% cost reduction, 90%+ cost reduction, connector
  counts) have no source attached at all.

None of that means the four named platforms are a bad shortlist — Nucleus Security,
DefectDojo, Brinqa, and ArmorCode are all real, established products in this space, and
the deck's overall direction (legacy VR platforms are expensive and complex; modern
API-first alternatives cost less and integrate faster) matches independently-sourced
industry commentary below. But every specific number in this document was re-derived
from real, cited sources rather than carried over from the deck — where the deck's claim
turned out to be wrong, that's called out explicitly.

## 2. ServiceNow VR: what's actually verifiable about the complaint

**Cost** — ServiceNow doesn't publish standard pricing, but real signals exist:
list prices for Security Operations range from roughly **$11,000 per fulfilled user/year**
(Vulnerability Response Standard) up to **$24,500/year** (Security Incident Response
Enterprise), with typical negotiated discounts of 20–40%. VR pricing also has a
**device-based** component — you pay for every device in the scanned perimeter, not just
per analyst seat. Real-world benchmarked deployments (mixing VR, SIR, threat intel, and
automation playbooks) run **$40,000–$120,000/year**.
([The Negotiation Experts](https://thenegotiationexperts.com/blog/servicenow-secops-licensing-costs/))

**Complexity** — independently corroborated, not just pavane's own impression: Gartner
Peer Insights reviews describe VR's Exceptions Management flow as a questionnaire that
opens a dialog box, which calls an assessment table, which is itself mapped to another
assessment table linked to approvals; some VR components are "relics from the initial
release of the app," making troubleshooting difficult; reviewers note it's hard for
beginners and becomes complex once multi-cloud infrastructure is involved.
([Gartner Peer Insights](https://www.gartner.com/reviews/product/servicenow-vulnerability-response))

This matches pavane's stated complaint closely enough that it's a real, sourced pain
point — not just this project's opinion of ServiceNow.

## 3. The four alternatives: deck claims vs. verified facts

| Platform | Deck's claim | Verified | Source |
|---|---|---|---|
| **Nucleus Security** | "100+" connectors, "70–80% cost reduction" | **200+ built-in connectors + FlexConnect** universal adapter (new ones added monthly); no independently-sourced cost-reduction percentage found | [PeerSpot](https://www.peerspot.com/products/comparisons/nucleus-security_vs_servicenow-security-operations), [Gartner](https://www.gartner.com/reviews/product/nucleus-security-platform) |
| **DefectDojo (Pro)** | "500+" connectors, "near zero cost" | **~200+ integrations** (deck overstated by ~2.5x); Pro (SaaS) tier is **$300/month ($3,600/year)**, storage-based pricing — "near zero cost" is only true of the separate, free open-source **Community Edition**, not the named "Pro" tier | [DefectDojo](https://defectdojo.com/upgrade-to-defectdojo-pro), [tool.news](https://tool.news/tools/defectdojo/) |
| **Brinqa** | "hundreds" of connectors | **260+ sources** (security, IT, cloud, identity, application, business systems) — roughly accurate; no public pricing found | [Brinqa](https://www.brinqa.com/resources/brinqa-cyberrisk-graph) |
| **ArmorCode** | "350+" integrations | **320–350+ integrations** — accurate; one real price signal: AWS Marketplace lists a 12-month "Bronze Tier" at **$4,500/unit** (scope of "unit" not published) | [ArmorCode](https://www.armorcode.com/integrations), [CSO Online](https://www.csoonline.com/article/4041891/aspm-buyers-guide-seven-products-to-help-secure-your-applications.html) |

Each platform's real differentiator, from its own material and independent reviews:

- **Nucleus** — fastest onboarding, no per-connector overage fees, connectors "easy to
  stand up... within minutes" per real user reviews.
- **DefectDojo** — deduplication is the headline feature: matches findings by
  vulnerability type + CWE, file path + line number, endpoint + parameter, or a custom
  hash, and cites a real example of 500 findings from 5 overlapping scanners collapsing
  to roughly 150 unique vulnerabilities.
- **Brinqa** — the Cyber Risk Graph links every vulnerability to business context (asset
  criticality, ownership), not just a CVSS score.
- **ArmorCode** — no-code remediation playbooks and the broadest single-platform
  coverage across code, cloud, and infrastructure.

One thing this research could **not** verify: the deck's specific claim that Nucleus and
Brinqa integrate with **BishopFox** by name. BishopFox is a pentest/red-team vendor, a
different integration shape (findings import) than a live API connector like Tenable or
Prisma Cloud — worth confirming directly with either vendor before assuming it, rather
than treating the deck's claim as settled.

## 4. VulnHunter's actual current position

Real strengths already shipped (from the codebase, not aspiration):

- **Live-verified threat intel** — CISA KEV + FIRST.org EPSS are the *only* two
  integrations in this repo actually confirmed working against their real target service
  (everything else, see below, is unverified). That's a genuine, working, zero-cost
  real-time enrichment layer none of the four alternatives were checked against here.
- **Deliberately simple, single dashboard** — a direct answer to "too complex, not
  user/support-friendly": no workflow-engine layer comparable to VR's chained
  dialog → assessment-table → assessment-table → approval flow.
- **Real Risk Score** (Impact × Likelihood, NIST SP 800-30-inspired) plus
  internal/external-facing asset classification on the Risk Management page — the same
  "link findings to business context" idea Brinqa leads with, already present in some
  form.
- **Zero license cost** — internal tooling, no per-seat or per-device fee. Against VR's
  real $40K–$120K/year benchmark or even DefectDojo Pro's $3,600/year, VulnHunter is the
  cheapest option by construction — though this isn't a fully apples-to-apples
  comparison, since it's not a supported commercial product with vendor SLAs.
- **Remediation-plan/playbook generation** (Ansible) — directionally similar to
  ArmorCode's playbook pitch, though it generates a reviewable script for a human to run
  rather than fully no-code point-and-click automation.
- Per-team RBAC, concurrent-write-safe stores, a deterministic search assistant, and
  now-clickable charts/KPIs (this session's production-readiness work) are real,
  additional ground gained since the source deck was written.

Confirmed real gaps (from [INTEGRATIONS.md](INTEGRATIONS.md) and the codebase, not
assumption):

- **Only 12 real connectors** (Tenable, Armis, Qualys, ServiceNow, Jira, Splunk,
  CrowdStrike, Prisma Cloud, Cortex XSIAM, Infoblox, Axonius, Active Directory) versus
  200–350+ for each alternative above. **12 of VulnHunter's 14 total integrations —
  including both threat-intel feeds' connector-side counterparts — have never been
  exercised against a real live account**, only mocked HTTP (or, for Active Directory, a
  fake LDAP connection) built against public docs. Every competitor's connector count
  implicitly assumes production-tested-by-paying-customers; VulnHunter's cannot make
  that claim yet.
- ~~**No cross-scanner deduplication at all.**~~ — **built** (`remediation/enrichment/dedup.py`):
  matches by `(cve, asset.name)`, falling back to `(normalized_title, asset.name)` when
  no CVE is present; never deletes a record, only tags each finding with its dedup group
  and a deterministic primary selection. This was the single most consistently-cited
  differentiator across all four alternatives researched here, and Phase 1 item 1 below.
- **No BitSight or BishopFox connector** — both explicitly named as pain points/
  requirements, neither exists in this codebase today. Prisma Cloud and Cortex XSIAM
  (also named here) were built in a later wave that additionally added Qualys and
  Active Directory - see [INTEGRATIONS.md](INTEGRATIONS.md) and
  [GOING_LIVE.md](GOING_LIVE.md).
- **No log-correlation feature** — the Splunk connector only pushes findings *out* to
  Splunk; it doesn't correlate incoming SIEM/log data back onto a finding. "Log
  correlation" wasn't precisely scoped anywhere in this research or the codebase — it
  needs its own design pass before it's buildable, not just a connector to add.

## 5. Prioritized roadmap

**Phase 1 — highest value, no new vendor dependency:**
1. ~~**Cross-scanner deduplication engine.**~~ — **done** (see §4 above). Closed the
   single most-cited gap versus every alternative researched.
2. **Live-verify at least the two highest-value existing connectors** (Tenable,
   ServiceNow) against a real sandbox/test tenant. **Still not done** — adding more
   unverified connectors on top of the 12 that have never touched a live account
   compounds the credibility gap rather than closing it; this remains the single
   highest-leverage next move once real credentials exist for anything (see
   [GOING_LIVE.md](GOING_LIVE.md)'s "Recommended next step").

**Phase 2 — new connectors, in the order pavane named them:**
3. ~~Prisma Cloud, then XSIAM~~ — **done**. Both now have full connector implementations
   *and* a dashboard Test Connection + Fetch form (a step beyond what this phase
   originally scoped) - see [INTEGRATIONS.md](INTEGRATIONS.md). A later, more specific
   ask additionally named Tenable, Qualys, Infoblox, Axonius, and Active Directory for
   the same dashboard-form treatment, all now done too.
4. **BitSight — still not built.** BishopFox still needs its integration shape confirmed
   first (see §3) since a pentest vendor likely means a findings-import format, not a
   live API pull like the others.

**Phase 3 — deferred until scoped:**
5. Log correlation — define concretely what this means for VulnHunter (which log
   sources, what "correlation" produces) before estimating or building anything.
6. No-code-style remediation actions — grow the existing Ansible-playbook generator
   toward a "one-click apply" mode for auto-approvable, low-risk fixes only, rather than
   promising full no-code automation VulnHunter doesn't have the safety rails for yet.

## 6. Recommendation

Don't try to out-feature all four alternatives at once. VulnHunter's real, already-true
advantages are **cost** ($0 internal vs. a real $40K–$120K/year ServiceNow VR benchmark)
and **simplicity** (one dashboard vs. VR's workflow engine) — both directly answer
pavane's original complaint and don't need new work to be true today. Phase 1 item 1
(deduplication) and Phase 2 (Prisma Cloud/XSIAM, plus Tenable/Qualys/Infoblox/Axonius/
Active Directory dashboard forms) are both done now. The highest-leverage next move is
Phase 1, item 2 (live-verifying Tenable/ServiceNow against a real sandbox tenant): it's
the one gap that can't be closed by writing more code - it needs a real credential,
which this project has never had for any system. Happy to scope Phase 3, or reprioritize
based on what matters most.

## Sources

- [ServiceNow SecOps Licensing Costs — The Negotiation Experts](https://thenegotiationexperts.com/blog/servicenow-secops-licensing-costs/)
- [ServiceNow Vulnerability Response — Gartner Peer Insights](https://www.gartner.com/reviews/product/servicenow-vulnerability-response)
- [Nucleus Security vs ServiceNow Security Operations — PeerSpot](https://www.peerspot.com/products/comparisons/nucleus-security_vs_servicenow-security-operations)
- [Nucleus Security Platform — Gartner Peer Insights](https://www.gartner.com/reviews/product/nucleus-security-platform)
- [DefectDojo — Upgrade to Pro](https://defectdojo.com/upgrade-to-defectdojo-pro)
- [DefectDojo Review 2026 — tool.news](https://tool.news/tools/defectdojo/)
- [Brinqa CyberRisk Graph](https://www.brinqa.com/resources/brinqa-cyberrisk-graph)
- [ArmorCode Integrations](https://www.armorcode.com/integrations)
- [ASPM buyer's guide — CSO Online](https://www.csoonline.com/article/4041891/aspm-buyers-guide-seven-products-to-help-secure-your-applications.html)
