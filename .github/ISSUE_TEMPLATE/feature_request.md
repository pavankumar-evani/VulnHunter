---
name: Feature request
about: Propose a new asset class, data source, or capability
title: "[Feature] "
labels: enhancement
assignees: ''
---

**What's the gap?**
e.g. "no fixer exists yet for network-routing-switching findings" — see
[REMEDIATION_PLAN.md](../../REMEDIATION_PLAN.md)'s "no automated remediation path today"
section and [KNOWLEDGE_TRANSFER.md §9 Roadmap](../../KNOWLEDGE_TRANSFER.md#9-roadmap)
for known gaps before filing a duplicate.

**Proposed approach**

**If this is a new remediation-fixer-* subagent:**
- [ ] Confirm it will only ever have `tools: Read, Write` — no `Bash`, no network tool,
      no credentials. This is the safety model, not a limitation to lift (see
      [KNOWLEDGE_TRANSFER.md §4.3](../../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision)).
- [ ] Confirm the plan for updating `remediation-planner`'s `automation_target` routing
      and `.claude/commands/remediate.md`'s delegation logic.
- [ ] Confirm test cases will be added to `tests/test_pipeline_artifacts.py` mirroring
      `RemediationPlaybooksMatchThePlan`.

**Would this require a new data source connector?**
If yes, note whether it's a static export format (like the current CSV/JSON samples) or
a live API integration (see Tier 2c in the commercialization roadmap).
