---
description: Run the infra remediation pipeline (ingest -> normalize -> plan -> generate remediation artifacts) against Tenable/Armis/threat-intel exports.
argument-hint: [--generate]
allowed-tools: Task, Read, Bash
---

Run the VulnHunter remediation pipeline. Arguments: $ARGUMENTS

By default this ingests the sample data in `remediation/sample-data/` (`tenable_export.csv`,
`armis_export.json`, `threat_intel.json`) — if the user passed different file paths in
`$ARGUMENTS`, use those instead. If `--generate` is present, also generate remediation
artifacts (Ansible playbooks) at the end; otherwise stop after the plan and ask the user
whether to proceed with generation.

Steps:

1. Delegate to **vuln-ingest-normalizer** with the input file path(s). Wait for
   `remediation/output/normalized-findings.json` to exist before proceeding.
2. Delegate to **remediation-planner** with that normalized findings file. Wait for
   `REMEDIATION_PLAN.md` to be written.
3. Print a short chat summary: total findings, how many are auto-remediable today (have a
   working fixer) vs. manual-only, and the breakdown by risk tier. Point the user at
   `REMEDIATION_PLAN.md` for full detail.
4. If `--generate` was passed (or the user confirms after seeing the plan): split the plan
   into windows-server findings and unix-server findings, delegate the former to
   **remediation-fixer-windows** and the latter to **remediation-fixer-unix** (both can run
   independently of each other). Report back which playbooks were generated.

Always make clear, in the chat summary and in `REMEDIATION_PLAN.md`, that generated
playbooks are artifacts for human/change-management review and execution — this pipeline
never touches real infrastructure itself, by design (the fixer subagents only have
Read/Write tools, no network/exec access to any target).

Keep the main chat output concise — the detailed findings and plan belong in
`REMEDIATION_PLAN.md`, not in the conversation.
