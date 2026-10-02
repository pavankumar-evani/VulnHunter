# Quanta — An Investor-Lens Review

> **What this is.** A candid assessment written from the point of view of a cybersecurity
> seed or Series A investor, grounded in the product as it exists in this repository and in
> public market and investor-criteria research. It is analysis prepared by an AI assistant,
> **not feedback from any real investor**. Real feedback needs real conversations; use this
> to prepare for them, not to replace them.

## The one-paragraph verdict

Quanta has a sharp, defensible *point of view* (remediation is the unsolved half of
vulnerability management, and a model that can only write reviewable artifacts is a safer
bet for regulated buyers than an autonomous agent) and an unusually complete product for its
stage: detection ingestion, a transparent scoring formula, a governed remediation engine with
deterministic safety gates, ownership and an ITSM desk. What it does not yet have is the thing
investors actually fund at this stage: **proof that someone other than its builder gets value
from it.** Today it is a strong prototype with disclosed gaps. The next 90 days should be
spent turning "built" into "used".

## What an investor will like

1. **A real wedge, stated plainly.** "Detection tools stop at the ticket; Quanta generates,
   gates, stages and verifies the fix." That is a specific, testable claim, and the market is
   moving toward it: exposure management is forecast to grow from about USD 5.1B in 2026 to
   about USD 27B by 2034 (roughly 23% a year), and AI-native security is the fastest-growing
   investment theme ([Fortune Business Insights](https://www.fortunebusinessinsights.com/exposure-management-market-111546),
   [Venture Briefing](https://venturebriefing.com/analysis/cybersecurity-startup-funding-landscape-2026)).
2. **Trust by construction.** Fixer agents hold read and write on files only: no shell, no
   network, no credentials. Enterprise buyers who have been burned by "autonomous remediation"
   read that as a feature. The new layers (a deterministic safety lint that blocks approval,
   rollout rings, closed-loop verification, evidence packs) make "safe to adopt" concrete.
3. **Honest disclosure.** The documents say what is unverified (connectors tested against
   simulated responses, no penetration test yet, single-node writers). Investors and CISOs both
   discount vendors who hide gaps; this reads as credibility.
4. **Breadth that shortens a pilot.** Eight pull connectors, three push connectors, seventeen
   asset types, ownership analytics, a support desk with SLAs, a container image and PostgreSQL
   path. A design partner can see a full workflow in a week.
5. **Unit economics claim with substance.** A per-asset price a fraction of the incumbents,
   unlimited users, and no per-seat growth tax is a clean story for mid-market and MSSPs.

## What an investor will push on

1. **No customers, no design partners, no usage.** Investors increasingly expect named
   enterprise design partners at pre-seed and roughly USD 1–3M ARR before a Series A
   ([Qubit Capital](https://qubit.capital/blog/cybersecurity-fundraising),
   [Venture Briefing](https://venturebriefing.com/analysis/cybersecurity-startup-funding-landscape-2026)).
   This is the single biggest gap and nothing in the code can close it.
2. **Credibility of the team story.** Cybersecurity is credibility-driven: investors ask why
   *this* team wins. Name the domain depth, the operator credentials, and the advisors.
3. **Defensibility.** Scanners, ticketing and "AI that writes a playbook" are all being
   bundled by large platforms, and the incumbent in ITSM is buying its way into exposure
   management. The moat cannot be features. Candidates: (a) the governed-remediation workflow
   and its evidence trail become the system of record auditors rely on, (b) outcome data (which
   fixes hold, per domain) that compounds with every customer, (c) a neutral position across
   scanners the incumbents each push their own of.
4. **"Never executes" cuts both ways.** It is the trust story, and also a ceiling on the value
   story. Expect: *who runs the playbook, and is that where the time goes?* You need a clean
   answer: integration with the customer's own change tooling, and measured time saved.
5. **Connector reality.** Every connector is built to public docs and untested against a live
   tenant. Investors will treat connector claims as unproven until two or three run against a
   real customer environment.
6. **Security posture of a security vendor.** No third-party penetration test, no SOC 2 or
   equivalent, and public-by-default reads that are only opt-in to close. Expect this to gate any
   enterprise deal and most diligence. It is cheap to start and expensive to delay.
7. **Pricing signal.** Being three to five times cheaper than the cheapest scanner can read as
   "low value" rather than "disruptive", and the comparison is partly apples to oranges because
   Quanta sits above scanners. Price on outcomes (remediated risk, hours saved), not only per
   asset.
8. **Single-node architecture.** Writers are serialised by an advisory file lock and scheduling
   is in-process. Fine for a pilot; a diligence engineer will ask when this stops being true.

## Questions to prepare for, with the honest answer today

| Question | Honest answer now | What would make it strong |
|---|---|---|
| Who is using it? | No external customer yet | Two signed design partners with a measured baseline |
| What is the moat? | Workflow plus evidence trail; not yet outcome data | Fix-hold-rate and time-to-remediate across customers |
| Why won't ServiceNow or a scanner vendor do this? | They stop at tasks and tickets today; that can change | A neutral, multi-scanner position and a faster loop |
| How do you make money? | Annual license by environment size, three tiers | A paid pilot converting at a stated rate |
| Is it secure? | Designed to a strict boundary, not yet independently tested | A third-party penetration test and a SOC 2 Type I plan |
| Does it scale? | Single node today; PostgreSQL path exists | A queue and worker pool, tested multi-replica |
| What does the AI actually do? | Drafts artifacts under deterministic gates | Published eval results on fix correctness |

## Metrics an investor will ask for

- Time to first value in a pilot (hours from connect to first prioritised queue).
- Request-to-approval and request-to-trigger times, and the **fix-hold rate** after the next
  scan. Quanta already computes these from real history and returns "no data" rather than an
  estimate (`/api/remediation-metrics`).
- Share of findings with an owner, and unowned-urgent count falling over time.
- Support desk SLA compliance and mean time to resolve (the ITSM analytics).
- Pilot conversion rate and annual contract value; expansion across teams.

## A 90-day plan that answers the objections

1. **Weeks 1–3:** recruit two design partners; agree success criteria and capture baselines
   before any agent runs. Offer a paid or fixed-scope pilot.
2. **Weeks 2–6:** run two or three connectors against real tenants; fix what breaks; turn
   "tested against simulated responses" into "validated live" for those connectors.
3. **Weeks 3–8:** commission a penetration test; start a SOC 2 readiness plan; close the
   public-read default for the pilot deployments.
4. **Weeks 6–10:** replace the in-process scheduler and file lock with a queue and
   row-level locking so two replicas can run; document the result.
5. **Weeks 8–12:** publish a short results note from the pilots: hours saved, fix-hold rate,
   SLA compliance, with the customer's permission. That note is the fundraising deck.

## Market context

- Security and vulnerability management is a large, slow-growing category (about USD 17B in
  2026, around 6% a year); exposure management is the faster segment
  ([Research and Markets](https://www.researchandmarkets.com/reports/6012594/security-and-vulnerability-management-market),
  [Fortune Business Insights](https://www.fortunebusinessinsights.com/exposure-management-market-111546)).
- Typical rounds: seed around USD 4–6M, Series A around USD 20–40M
  ([Venture Briefing](https://venturebriefing.com/analysis/cybersecurity-startup-funding-landscape-2026)).
- Diligence in the category runs four to ten weeks with CISO reference calls; having two
  references ready is worth more than any slide.

*Figures above come from third-party market-research summaries and should be re-checked
against the original reports before use in a fundraising document.*
