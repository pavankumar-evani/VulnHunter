# VulnHunter 🔍🛡️

**An autonomous Claude Code security agent that finds vulnerabilities in your codebase
— and fixes the safe ones automatically.**

Built for the Deloitte Claude Code Hackathon.

## The problem

Static analysis tools produce reports nobody reads. Security debt piles up because
finding a vulnerability and *actually fixing it* are two different jobs, and most tools
only do the first one.

## What VulnHunter does

One command — `/vulnhunt <path>` — runs a 3-stage agent pipeline:

1. **Scan** — a read-only subagent (`vuln-scanner`) statically analyzes the target repo
   for injection flaws, hardcoded secrets, insecure config, risky dependencies, and
   unsafe Docker practices. Outputs structured findings with severity + CWE.
2. **Triage & Report** — a second subagent (`vuln-triage-reporter`) turns raw findings
   into a clean, ranked `SECURITY_REPORT.md`, explaining real-world impact in plain
   English, not just CWE jargon.
3. **Fix** — a third subagent (`vuln-fixer`) applies safe, mechanical fixes (parameterize
   a SQL query, move a hardcoded secret to an environment variable, drop container
   privileges) to a new git branch and pushes it, ready for a pull request. Anything that
   needs a real design decision is explicitly left for a human, with a reason why.

Each stage is a separate Claude Code subagent with its own scoped tool access —
`vuln-scanner` is read-only by design, so the tool that finds vulnerabilities literally
cannot introduce new ones.

## Architecture

```
/vulnhunt <path> [--fix]        (slash command, orchestrates the pipeline)
        │
        ▼
  vuln-scanner            Read, Grep, Glob, Bash        → JSON findings
        │
        ▼
  vuln-triage-reporter    Write                          → SECURITY_REPORT.md
        │
        ▼
  vuln-fixer              Read, Edit, Write, Bash        → branch + push (only if --fix)
```

## Demo

A deliberately vulnerable Flask app lives in `vulnerable-demo-app/` with 6 planted,
labeled vulnerabilities (SQL injection, command injection, `eval()` misuse, hardcoded API
key, plaintext passwords, debug mode, insecure Dockerfile). This is what we run
VulnHunter against on stage.

```bash
# 1. Point VulnHunter at the vulnerable demo app
claude
/vulnhunt vulnerable-demo-app

# 2. Review SECURITY_REPORT.md, then let it auto-fix the safe findings
/vulnhunt vulnerable-demo-app --fix
```

Expected result: ~6 findings detected in seconds, 3-4 auto-fixed on a pushed branch, the
remaining flagged for human review with a clear reason (e.g. "removing eval() here
requires redesigning the /calc endpoint — needs a human decision"). Opening the actual PR
from that branch is one click away in GitHub's web UI or VS Code's Source Control panel.

## Why this approach

- **Separation of concerns mirrors real security teams**: a scanner shouldn't have write
  access, a fixer should never guess on ambiguous cases. This is also VulnHunter's safety
  mechanism instead of container sandboxing — `vuln-scanner` is architecturally incapable
  of modifying files (no Edit/Write tool access at all), and `vuln-fixer` only ever acts
  on findings pre-approved as `auto_fixable` by the scan stage, on a fresh branch, never
  on `main` directly.
- **It's demoable end-to-end in under 2 minutes.**
- **It scales**: point it at any repo, any language, no retraining — it's prompting +
  tool scoping, not a bespoke rules engine.
- **Zero extra tooling**: only `git`, which is already everywhere — no `gh` CLI or Docker
  runtime required to run the pipeline itself.

## Project structure

```
.
├── .claude/
│   ├── agents/
│   │   ├── vuln-scanner.md
│   │   ├── vuln-triage-reporter.md
│   │   └── vuln-fixer.md
│   └── commands/
│       └── vulnhunt.md
├── vulnerable-demo-app/        # intentionally vulnerable Flask app for the demo
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── init_db.py
└── README.md
```

## Disclaimer

`vulnerable-demo-app/` is intentionally insecure and exists **only** to demonstrate
VulnHunter. Do not deploy it anywhere reachable.
