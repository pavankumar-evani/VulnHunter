## What does this change?

## Why?

## Which pipeline/component does this touch?
- [ ] `/vulnhunt` (`vuln-scanner` / `vuln-triage-reporter` / `vuln-fixer`)
- [ ] `/remediate` (`vuln-ingest-normalizer` / `remediation-planner` /
      `remediation-fixer-windows` / `remediation-fixer-unix`)
- [ ] `vulnerable-demo-app/` (the `/vulnhunt` scan target)
- [ ] `remediation/sample-data/` or `remediation/schema/`
- [ ] Tests, docs, deliverables, or CI only

## Safety model checklist (skip if not touching `.claude/agents/*.md`)
- [ ] I have not widened any subagent's `tools:` list beyond what its job requires —
      scanners stay read-only, remediation fixers stay `Read`/`Write`-only with no
      `Bash`/network/credential access. See
      [KNOWLEDGE_TRANSFER.md §4.3](KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision).
- [ ] Any new fixer only acts on findings pre-approved by the planner/scanner stage.

## Testing
- [ ] `python -m unittest discover -s tests -p "test_*.py" -v` passes locally
- [ ] I added/updated test cases in `tests/test_pipeline_artifacts.py` and
      `TEST_CASES.md` for new behavior
- [ ] If I changed agent prompts, I re-ran the relevant pipeline against
      `vulnerable-demo-app/` or `remediation/sample-data/` and checked the output by hand
