---
description: Run the full VulnHunter pipeline (scan, triage/report, optionally auto-fix) against a target codebase, or re-verify one already-fixed finding.
argument-hint: [path-to-target-repo] [--fix] | [path-to-target-repo] --verify FINDING-ID BRANCH
allowed-tools: Task, Read, Bash
---

Run the VulnHunter security pipeline against the target path: $ARGUMENTS

Parse the arguments: the first token is the target path (default to the current
directory if omitted).

**If `--verify FINDING-ID BRANCH` is present** (used after a `vuln-fixer` branch has
been pushed, ideally after it's been merged, to confirm the fix actually worked rather
than trusting the fixer's own report): skip the scan/report/fix steps below entirely.
Instead:
1. Read `<target>/SECURITY_REPORT.md`. If it doesn't exist, say so plainly and stop —
   there's nothing to re-verify against without a prior scan's report.
2. Find `FINDING-ID`'s own entry in that report's "Findings" section and reconstruct its
   `file`/`line`/`title`/`cwe`/`severity`/`description`/`evidence` fields from it (the
   same fields `vuln-scanner` originally produced — the report is written from that
   exact JSON, see `vuln-triage-reporter.md`). If no finding with that ID is in the
   report, say so plainly and stop rather than guessing which one the user meant.
3. Delegate to the **vuln-verifier** subagent with that finding object and `BRANCH`.
   Wait for its JSON verdict.
4. Log the outcome to the real activity log via Bash:
   `python remediation/audit/record_verification.py --finding-id FINDING-ID --branch
   BRANCH --status <verdict's status> --detail "<verdict's detail>"` (run from the repo
   root, not the target path — this script is part of VulnHunter itself, not the
   scanned target). If this call fails for any reason (e.g. no network path to the
   database file), still report the verdict to the user - a logging failure should
   never hide a real verification result.
5. Report the verdict to the user in plain text: resolved / still-present / inconclusive,
   with the one-line `detail` from vuln-verifier's own output. If `"still-present"`, say
   so plainly and suggest re-running `--fix` or reviewing the branch manually — do not
   soften a real still-vulnerable result.

Otherwise (no `--verify`), run the normal scan/report/fix pipeline. If `--fix` is present
anywhere in the arguments, auto-fixes should be applied at the end; otherwise stop after
the report and ask the user whether to proceed with fixes.

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
