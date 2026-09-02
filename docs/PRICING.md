# VulnHunter Pricing

**VulnHunter is a commercial product**, licensed annually by environment size, with a
real, credited support SLA at every paid tier. This file is the source of truth for the
pricing/SLA/licensing model — the published enterprise documentation suite's pricing
page (`docs/enterprise-suite/pricing.html`) restates this content visually; if the two
ever disagree, this file is authoritative and the HTML page should be updated to match.

## Tiers (annual, per dedicated-tenant environment)

| | Standard — Detect &amp; Prioritize | Professional — Detect &amp; Remediate | Enterprise |
|---|---|---|---|
| **Price** | $12,000/year | $38,000/year | $85,000/year+ (custom above 25,000 assets) |
| **Assets** | Up to 1,500 | Up to 7,500 | Unlimited |
| **Users** | Unlimited | Unlimited | Unlimited |
| Connectors | Up to 3 | All, unlimited | All, unlimited |
| OpenVAS/GVM scan engine | Add-on (+$6,000/yr) | ✓ included | ✓ included |
| **Remediation engine (generated playbooks)** | — | ✓ | ✓ |
| Approval &amp; exception workflow | — | ✓ | ✓ |
| Deployment | Dedicated single-tenant | Dedicated single-tenant | Dedicated single-tenant or self-hosted |
| Account management | Self-service | Quarterly business review | Dedicated Technical Account Manager |

Additional assets beyond a tier's cap: $2,000 per 1,000 assets/year true-up (Standard,
Professional) — included and unlimited at Enterprise. **Unlimited named users at every
tier** — priced by environment size, never by headcount.

### Why Standard → Professional is priced on a capability gap, not just more assets

ServiceNow's own current Vulnerability Response/USEM documentation describes
remediation as a phased *task* process — "verifying import completion, triaging new
vulnerabilities, and monitoring progress to completion" — workflow/ticket automation,
not automated generation of an actual fix artifact. Tenable, Qualys, and Rapid7 don't
generate fixes at any price either — they're scanners that feed a ticketing system like
ServiceNow. **Professional is priced on VulnHunter being the one product in this
comparison set that turns a finding into a real, reviewable Ansible playbook
automatically** — a capability gap, not a bundling choice.

## Cost per asset vs. the market (why this is priced right, not "too costly")

The flat tiers above are the sellable SKUs, but the fair comparison is cost per asset
per year — the unit this whole market actually bills on (ServiceNow is the one
exception: it bills per fulfiller-user, a structurally different, worse-scaling metric
as a team grows).

| Platform | Per asset/year | Basis |
|---|---|---|
| **VulnHunter Enterprise** | **$3.40** | at the 25,000-asset custom-quote threshold |
| **VulnHunter Professional** | **$5.07** | $38,000 ÷ 7,500-asset cap |
| **VulnHunter Standard** | **$8.00** | $12,000 ÷ 1,500-asset cap |
| Rapid7 InsightVM | ~$19–23 | $1.62–$1.93/asset/month, ≥512-asset minimum |
| Tenable Vulnerability Management | ~$28–45 | list price, base tier |
| Microsoft Defender Vulnerability Management | ~$24–36 | $2–3/user/month — endpoint-adjacent, not full infra/cloud scanning |
| CrowdStrike Falcon Spotlight | ~$67–110 | $7.50–$11.17/endpoint add-on, stacked on a required $59–99/endpoint base agent |
| Qualys VMDR | ~$50–250 | quote-only; public estimates vary widely by source/bundle |

**Even Standard ($8.00/asset/year) undercuts Rapid7 — the cheapest named real
competitor — by roughly 3x, and Tenable by roughly 4–5x.** Professional and Enterprise
widen that gap further. See "Sources" below for citations; these are third-party
estimates for quote-only products and should be verified against a direct vendor quote
before use in a real negotiation.

## Licensing options

- **Term-based subscription (standard)** — annual, auto-renewing. Every researched
  competitor has moved to this model; nobody in vulnerability management sells a
  perpetual license anymore.
- **Per-endpoint metering (alternative to a flat tier)** — $6.50/endpoint/year, no tier
  commitment, 500-endpoint minimum — priced the same way Tenable, Qualys, Rapid7, and
  CrowdStrike Spotlight all bill (per unit under management). "Endpoint" is the same
  billable unit as "asset" elsewhere in this document. Still 3x+ cheaper per unit than
  every named competitor above.
- **Scan-engine add-on (Standard tier only)** — $6,000/year adds the OpenVAS/GVM scan
  engine without a full Professional upgrade (the same "core + priced add-on module"
  pattern CrowdStrike uses for Falcon Spotlight). Included by default in Professional
  and Enterprise.
- **Multi-year commitment discount** — 10% (2-year) / 15% (3-year), prepaid or annual
  invoicing. Deliberately more modest than the ~38–45% Qualys reportedly discounts at
  3-year/10,000+-asset scale, since VulnHunter's list price already starts well below
  that comparison point.

## Vertical modules — OT/IoT & AppSec

OT/IoT and Application Security are different buying centers and, per
`docs/enterprise-suite/remediation-engine.html`'s "Three remediation tracks" section,
genuinely different remediation mechanisms - priced as separate modules, not folded
into the core per-asset tiers, the same way Tenable sells Tenable.ot separately from
Tenable.io.

**OT/IoT Security Module** — $18,000/year, up to 2,000 OT/IoT devices (add-on to
Professional or Enterprise). Includes OT-aware risk scoring, the dedicated OT/IoT hub
page, and the OT remediation workflow (`remediation-fixer-ot` - a compensating-control/
vendor-coordination recommendation, never a direct patch script). Additional devices:
$600/100/year. Honest scope: a risk-management and remediation-workflow layer for
OT/IoT findings from existing sources - not a replacement for deep OT-protocol network
monitoring (Claroty/Dragos/Nozomi Networks, quote-only); designed to sit alongside one.

**Application Security Module** — $9,000/year, up to 25 applications/repositories
(add-on to any tier). Includes SAST via `/vulnhunt` with real auto-fix (`vuln-fixer`
opens an actual git branch + PR) - a capability Checkmarx/Veracode don't ship natively.
Also ingests DAST/SCA/Secrets/Container findings (no automated fixer for these yet -
same disclosed gap as network devices, a real roadmap item). Additional apps:
$300/year each beyond 25. For comparison: Veracode SAST alone lists $15,000-$25,000/year
for up to 100 apps; Checkmarx SAST lists $10,000-$15,000/year for the same range.

## Enterprise SLA

| Commitment | Standard | Professional | Enterprise |
|---|---|---|---|
| Uptime | 99.5% | 99.9% | 99.95% |
| Sev1 (critical) response | 1 business day | 4 hours | 1 hour |
| Sev2 (major) response | 2 business days | 8 hours | 4 hours |
| Sev3 (normal) response | 3 business days | 1 business day | 1 business day |
| Support hours | Business hours, email/ticket | Business hours, email/ticket/chat | 24×7×365, phone/chat/dedicated Slack |
| Uptime credit | 10% below 99.5%, 25% below 98% | 10% below 99.9%, 25% below 99% | 10% below 99.95%, 25% below 99.5% |

Credits apply to the following month's invoice as a percentage of that month's fee.
Response clocks start from ticket creation; measured monthly.

## Competitive landscape (beyond ServiceNow VR/USEM)

| Platform | Category | List pricing signal |
|---|---|---|
| ServiceNow VR/USEM | ITSM-native vulnerability response | $11,000–$24,500/fulfilled-user/year; real deployments $40,000–$120,000/year |
| Tenable Vulnerability Management | Network/host vuln scanning | $28–45/asset/year list; 500–2,000 assets = $25K–$150K/year real spend |
| Qualys VMDR | Network/host vuln scanning | Quote-only; estimates vary widely by module bundle |
| Rapid7 InsightVM | Network/host vuln scanning | $1.62–$1.93/asset/month, ≥512-asset minimum |
| Microsoft Defender Vulnerability Management | Endpoint-focused, Microsoft-ecosystem | $2–3/user/month; also bundled free into Microsoft 365 E5 |
| CrowdStrike Falcon Spotlight | Endpoint-focused add-on to Falcon EDR | $7.50–$11.17/endpoint/year, on top of a required $59–99/endpoint base agent |
| Nucleus Security / Brinqa / ArmorCode / DefectDojo | Aggregation/correlation onto scanners you already own | $300/mo (DefectDojo Pro) to custom-quote |
| Claroty / Dragos / Nozomi Networks | OT/ICS deep protocol monitoring | Quote-only, per-asset or per-site |
| Tenable.ot (OT Security) | OT/ICS vulnerability management | Priced separately from Tenable IT; real "up to 500 assets" SKU; ~$50K reported |
| Snyk | AppSec (developer-centric) | Free-$25/contributing developer/month |
| Veracode / Checkmarx | AppSec (SAST/DAST/SCA) | SAST alone $10K-$25K/year for up to 100 apps |
| GitHub Advanced Security | AppSec (code/secret scanning) | $19-$49/active committer/month |

**Why ServiceNow's headline number looks small until you scale it:** $11,000 is a
per-user starting price that grows with every analyst added, plus a separate
device-based component — exactly why real deployments land at $40K–$120K/year.
VulnHunter's unlimited-user model doesn't recreate that growth curve.

### Sources

- [Vendr — ServiceNow pricing](https://www.vendr.com/marketplace/servicenow)
- [Gartner Peer Insights — ServiceNow VR](https://www.gartner.com/reviews/product/servicenow-vulnerability-response)
- [VendorBenchmark — Tenable](https://vendorbenchmark.com/vendors/tenable-pricing)
- [UnderDefense — Tenable](https://underdefense.com/industry-pricings/tenable-pricing-2025-ultimate-guide-for-security-products/)
- [VendorBenchmark — Qualys](https://vendorbenchmark.com/vendors/qualys-pricing)
- [Costbench — Rapid7 InsightVM](https://costbench.com/software/vulnerability-management/rapid7-insightvm/)
- [Microsoft — Defender VM pricing](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-defender-vulnerability-management-pricing)
- [Costbench — CrowdStrike Falcon Spotlight](https://costbench.com/software/vulnerability-management/crowdstrike-falcon-spotlight/)
- [CDW — Tenable.ot licensing (real SKU, up to 500 assets)](https://www.cdw.com/product/tenable.ot-subscription-license-1-year-up-to-500-assets/6145843)
- [PeerSpot — Tenable OT Security pricing](https://www.peerspot.com/products/tenable-ot-security-reviews)
- [Vendr — Snyk pricing](https://www.vendr.com/marketplace/snyk)
- [UnderDefense — Veracode pricing](https://underdefense.com/industry-pricings/veracode-pricing-2026-ultimate-guide-for-security-products/)
- [Beagle Security — Checkmarx pricing](https://beaglesecurity.com/blog/article/checkmarx-pricing.html)

## §readiness — Launch readiness (read before quoting this to a real customer)

The pricing, licensing, and SLA above are the real, decided commercial model — not
aspirational. Honoring the SLA table operationally still requires standing up, and does
**not** exist yet as of this writing:

1. **Support operations** — a ticketing system, an on-call rotation for Enterprise's
   24×7 tier, and a documented escalation path.
2. **Uptime monitoring + a public status page** — what makes the uptime commitment
   above measurable and auditable by a paying customer.

Do not commit a customer to the SLA table above until both exist for real, or the
commitment is not honest.

## Keeping this in sync

This file, `docs/enterprise-suite/pricing.html`, and `docs/enterprise-suite/executive-brief.html`
all state the same pricing model. If pricing, licensing, or SLA terms change, update
all three (see `docs/enterprise-suite/MANIFEST.md` for how to republish the HTML
versions) and check `docs/VR_PLATFORM_COMPARISON.md` for competitive-positioning
language that assumes the old numbers.
