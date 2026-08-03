---
name: Bug report
about: Something in a pipeline, agent, or generated artifact is wrong
title: "[Bug] "
labels: bug
assignees: ''
---

**Which pipeline?**
`/vulnhunt` or `/remediate` (or both)

**Which component?**
e.g. `vuln-scanner`, `remediation-planner`, `remediation-fixer-windows`, the demo app,
the test suite, a generated artifact.

**What happened?**
A clear description of the incorrect behavior.

**What did you expect to happen?**

**Steps to reproduce**
1.
2.
3.

**Relevant output**
Paste the relevant section of `SECURITY_REPORT.md`, `REMEDIATION_PLAN.md`, a generated
playbook, or test output. Redact anything sensitive first.

**Does the test suite catch this?**
Run `python -m unittest discover -s tests -p "test_*.py" -v` — if this bug should have
been caught but wasn't, that's worth a new test case (see
[TEST_CASES.md](../../TEST_CASES.md) for the existing pattern).
