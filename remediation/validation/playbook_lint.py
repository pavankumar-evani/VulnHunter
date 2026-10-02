"""
Deterministic safety lint for generated remediation playbooks.

The remediation fixers are LLM subagents. Their output is only ever a reviewable
artifact, but a reviewer still deserves a mechanical answer to "does this artifact meet
the minimum bar we require of every generated fix?" before anyone is asked to approve it.
This module is that answer: pure Python, no network, no model call, same result every
time. It checks structure and safety hygiene, not whether the fix is technically correct
(only a human reviewer, and then a re-scan, can say that).

Rules (id - severity):
  PB001 error   - header names the finding ("# Finding: FIND-N")
  PB002 error   - header states the risk tier ("# Risk tier: ...")
  PB003 error   - a real rollback procedure is documented ("# Rollback: ...", 15+ chars)
  PB004 error   - a needs-change-approval fix carries the visible "CHANGE APPROVAL REQUIRED" gate
  PB005 error   - body parses as a YAML list of plays that each define tasks
  PB006 error   - no literal credential material (password/secret/token/api key values)
  PB007 error   - never targets every host ("all" / "*")
  PB008 warning - a pre-change check/baseline task exists
  PB009 warning - a post-change verification task exists
  PB010 warning - raw shell/command execution is used (prefer a purpose-built module)
  PB011 warning - failures are not silenced (ignore_errors: true)
  PB012 warning - target host is parameterised (target_host), so scope is explicit at run time

`passed` means no errors; warnings never block, they inform the reviewer.
"""
import re

import yaml

_SECRET_KEY = re.compile(r"(?i)^\s*-?\s*(password|passwd|secret|token|api[_-]?key|client_secret|private_key)\s*:\s*(\S.*)$")
_PLACEHOLDER = re.compile(r"(\{\{.*\}\}|lookup\(|vault|<.*>|\$\{.*\}|changeme|example|placeholder|\*{3,}|xxx)", re.I)
_SHELL_MODULES = ("shell", "command", "raw", "win_shell", "win_command", "ansible.builtin.shell",
                  "ansible.builtin.command", "ansible.builtin.raw", "ansible.windows.win_shell",
                  "ansible.windows.win_command")
_PRE_WORDS = re.compile(r"(?i)\b(check|baseline|before|pre-?change|current state|snapshot|backup)\b")
_POST_WORDS = re.compile(r"(?i)\b(verify|verif|confirm|post-?change|after|validate|assert)\b")


def _issue(rule, severity, message):
    return {"rule": rule, "severity": severity, "message": message}


def _header(content):
    lines = []
    for line in content.splitlines():
        if line.strip().startswith("#"):
            lines.append(line.strip().lstrip("#").strip())
        elif line.strip() == "---":
            break
        elif line.strip():
            break
    return "\n".join(lines)


def _tasks(plays):
    for play in plays:
        for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
            for task in play.get(key) or []:
                if isinstance(task, dict):
                    yield task


def lint_playbook(content):
    issues = []
    head = _header(content)

    if not re.search(r"(?im)^finding:\s*FIND-\d+", head):
        issues.append(_issue("PB001", "error", "Header does not name the finding (expected '# Finding: FIND-N ...')."))
    tier = re.search(r"(?im)^risk tier:\s*([\w-]+)", head)
    if not tier:
        issues.append(_issue("PB002", "error", "Header does not state the risk tier."))
    rollback = re.search(r"(?is)^rollback:\s*(.+?)(?:\n\s*\n|\Z)", head, re.M)
    if not rollback or len(re.sub(r"\s+", " ", rollback.group(1)).strip()) < 15:
        issues.append(_issue("PB003", "error", "No usable rollback procedure documented ('# Rollback: ...')."))
    if tier and tier.group(1).lower() == "needs-change-approval" and "CHANGE APPROVAL REQUIRED" not in content:
        issues.append(_issue("PB004", "error", "Risk tier needs-change-approval but the 'CHANGE APPROVAL REQUIRED' gate is missing."))

    try:
        plays = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        plays = None
        issues.append(_issue("PB005", "error", f"Not valid YAML: {str(exc).splitlines()[0]}"))
    else:
        if not isinstance(plays, list) or not plays or not all(isinstance(p, dict) for p in plays) \
                or not all((p.get("tasks") or p.get("pre_tasks") or p.get("post_tasks")) for p in plays):
            plays = None
            issues.append(_issue("PB005", "error", "Body must be a YAML list of plays, each defining tasks."))

    for n, line in enumerate(content.splitlines(), 1):
        m = _SECRET_KEY.match(line)
        if m and not _PLACEHOLDER.search(m.group(2)) and not line.strip().startswith("#"):
            issues.append(_issue("PB006", "error", f"Line {n}: literal value for '{m.group(1)}'. Use a vault/lookup reference."))

    if plays:
        for play in plays:
            hosts = str(play.get("hosts", "")).strip().lower()
            if hosts in ("all", "*", "'all'", '"all"'):
                issues.append(_issue("PB007", "error", "Play targets every host ('all'). Scope it to the affected host."))
            if "target_host" not in str(play.get("hosts", "")):
                issues.append(_issue("PB012", "warning", "Play hosts is not parameterised with target_host."))
        names = [str(t.get("name", "")) for t in _tasks(plays)]
        if not any(_PRE_WORDS.search(n) for n in names):
            issues.append(_issue("PB008", "warning", "No pre-change check/baseline task found."))
        if not any(_POST_WORDS.search(n) for n in names):
            issues.append(_issue("PB009", "warning", "No post-change verification task found."))
        for t in _tasks(plays):
            if any(k in t for k in _SHELL_MODULES):
                issues.append(_issue("PB010", "warning", f"Task '{t.get('name', '?')}' uses raw shell/command execution."))
            if t.get("ignore_errors") is True:
                issues.append(_issue("PB011", "warning", f"Task '{t.get('name', '?')}' silences failures (ignore_errors)."))

    errors = [i for i in issues if i["severity"] == "error"]
    warnings = [i for i in issues if i["severity"] == "warning"]
    return {"passed": not errors, "errors": errors, "warnings": warnings}
