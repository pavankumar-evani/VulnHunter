---
description: Run the full VulnHunter pipeline (scan, triage/report, optionally auto-fix) against a target codebase.
argument-hint: [path-to-target-repo] [--fix]
allowed-tools: Task, Read, Bash
---

Run the VulnHunter security pipeline against the target path: $ARGUMENTS

Parse the arguments: the first token is the target path (default to the current
directory if omitted). If `--fix` is present anywhere in the arguments, auto-fixes
should be applied at the end; otherwise stop after the report and ask the user whether
to proceed with fixes.

Steps:

1. Delegate to the **vuln-scanner** subagent, passing it the target path. Wait for it to
   return the JSON findings array. Do not proceed until you have valid JSON.
2. Delegate to the **vuln-triage-reporter** subagent, passing it the JSON findings and
   the target path, so it writes `SECURITY_REPORT.md` in the target repo.
3. Print a short summary in the chat: total findings, breakdown by severity, and how many
   are auto-fixable. Tell the user the full report is at `<target>/SECURITY_REPORT.md`.
4. If `--fix` was passed, delegate to the **vuln-fixer** subagent with the JSON findings
   and target path, and report back the branch/PR result. If `--fix` was NOT passed, ask
   the user: "Want me to auto-fix the N safe findings now? (this will create a branch and
   open a PR)" and wait for their answer before invoking vuln-fixer.

Keep the main chat output concise — the detailed findings belong in SECURITY_REPORT.md,
not in the conversation.
