# Security Policy

## Reporting a Vulnerability

This is a security tooling project, so we hold it to the standard it's meant to enforce
on others. If you find a security issue in VulnHunter itself — in the code pipeline, the
remediation pipeline, the demo app's handling outside its intended sandboxed use, or
anywhere else in this repository — please report it privately rather than opening a
public issue.

**Contact:** pavane@deloitte.com

Please include:
- A description of the issue and its potential impact
- Steps to reproduce (a minimal example, if possible)
- Which component is affected (`.claude/agents/*`, `.claude/commands/*`,
  `vulnerable-demo-app/`, `remediation/`, or elsewhere)

We aim to acknowledge reports within 5 business days.

## Scope Notes

- **`vulnerable-demo-app/`** is *intentionally* vulnerable and exists solely as a scan
  target for `/vulnhunt`. Findings against it are expected, not a security report.
- **`remediation/sample-data/`** contains fabricated Tenable/Armis/threat-intel exports
  for demo purposes. Hostnames, IPs, and device names are fictional. Referenced CVE IDs
  are real public CVEs used only to make remediation guidance realistic — no exploit code
  or technique detail is included.
- **Generated artifacts** in `remediation/output/` (Ansible playbooks) are unreviewed
  drafts. They must never be run against real infrastructure without human review and,
  where flagged `needs-change-approval`, formal change-management sign-off. See
  [KNOWLEDGE_TRANSFER.md §4.3](KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision)
  for the full safety model.

## Supported Versions

This project does not yet have a formal release/versioning process (tracked in the
roadmap). Until then, only the `master` branch and the latest state of active feature
branches are supported for security reports.
