# VulnHunter Pricing

**VulnHunter is a commercial product**, licensed annually by environment size, with a
real, credited support SLA at every paid tier. This file is the source of truth for the
pricing/SLA model — the published enterprise documentation suite's pricing page
(`docs/enterprise-suite/pricing.html`) restates this content visually; if the two ever
disagree, this file is authoritative and the HTML page should be updated to match.

## Tiers (annual, per dedicated-tenant environment)

| | Standard | Professional | Enterprise |
|---|---|---|---|
| **Price** | $12,000/year | $38,000/year | $85,000/year+ (custom above 25,000 assets) |
| **Assets** | Up to 1,500 | Up to 7,500 | Unlimited |
| Connectors | Up to 3 | All, unlimited | All, unlimited |
| OpenVAS/GVM scan engine | — | ✓ | ✓ |
| Remediation workflow (approvals, exceptions, policy) | ✓ | ✓ | ✓ |
| Deployment | Dedicated single-tenant | Dedicated single-tenant | Dedicated single-tenant or self-hosted |
| Account management | Self-service | Quarterly business review | Dedicated Technical Account Manager |

Additional assets beyond a tier's cap: $2,000 per 1,000 assets/year (Standard,
Professional) — included and unlimited at Enterprise.

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

## Terms

- Annual prepay is the standard billing term (prices above).
- 2-year commitment: 10% discount. 3-year commitment: 15% discount.

## Market position

ServiceNow Vulnerability Response lists at $11,000–$24,500/fulfilled-user/year, with
real benchmarked deployments running $40,000–$120,000/year plus a device-based
component (sources: [VR_PLATFORM_COMPARISON.md](VR_PLATFORM_COMPARISON.md)). VulnHunter's
Professional tier is the direct comparison point: $38,000/year with a real SLA included.

## §7 — Launch readiness (read before quoting this to a real customer)

The pricing and SLA above are the real, decided commercial model — not aspirational.
Honoring the SLA table operationally still requires standing up, and does **not**
exist yet as of this writing:

1. **Support operations** — a ticketing system, an on-call rotation for Enterprise's
   24×7 tier, and a documented escalation path.
2. **Uptime monitoring + a public status page** — what makes the uptime commitment
   above measurable and auditable by a paying customer.

Do not commit a customer to the SLA table above until both exist for real, or the
commitment is not honest.

## Keeping this in sync

This file, `docs/enterprise-suite/pricing.html`, and `docs/enterprise-suite/executive-brief.html`
all state the same pricing model. If pricing or SLA terms change, update all three (see
`docs/enterprise-suite/MANIFEST.md` for how to republish the HTML versions) and check
`docs/VR_PLATFORM_COMPARISON.md` for competitive-positioning language that assumes the
old numbers.
