#!/usr/bin/env python3
"""
Headless CLI wrapper for VulnHunter's two pipelines.

This does NOT reimplement vuln-scanner/vuln-fixer/remediation-planner/etc. in Python -
that would create a second source of truth alongside the .claude/agents/*.md prompts and
the two would drift. Instead, it shells out to the `claude` CLI in non-interactive mode
(`claude -p`), which loads this project's .claude/agents and .claude/commands exactly as
an interactive session would, and simply removes the requirement for a human to be typing
into a live Claude Code session. This is what makes the pipelines usable from CI, cron, or
any other automation - the prompt logic lives in exactly one place.

IMPORTANT: every invocation here calls the real Claude API and spends real usage/credits.
Nothing in this module runs automatically - see cli/README.md before using it for real.

Usage:
    python cli/vulnhunter.py scan <path> [--fix] [--dry-run]
    python cli/vulnhunter.py remediate [--generate] [--finding-id FIND-N] [--dry-run]
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = REPO_ROOT / ".vulnhunter" / "logs"

DEFAULT_PERMISSION_MODE = "acceptEdits"
DEFAULT_ALLOWED_TOOLS = "Read Grep Glob Bash Edit Write"
DEFAULT_MAX_BUDGET_USD = "2.00"


class ClaudeBinaryNotFound(RuntimeError):
    pass


def find_claude_binary():
    """Locate the claude CLI binary. Checked in order:
    1. CLAUDE_BIN env var (explicit override)
    2. `claude` on PATH
    3. CLAUDE_CODE_EXECPATH env var (set inside an active Claude Code session -
       useful for testing this wrapper from within Claude Code itself, but this is
       NOT how it should be discovered in a real CI runner, which should have
       `claude` properly installed and on PATH)
    """
    if os.environ.get("CLAUDE_BIN"):
        return os.environ["CLAUDE_BIN"]
    on_path = shutil.which("claude")
    if on_path:
        return on_path
    if os.environ.get("CLAUDE_CODE_EXECPATH"):
        return os.environ["CLAUDE_CODE_EXECPATH"]
    raise ClaudeBinaryNotFound(
        "Could not find the `claude` CLI binary. Install Claude Code, or set the "
        "CLAUDE_BIN environment variable to its full path."
    )


def build_command(
    prompt,
    claude_bin="claude",
    output_format="json",
    permission_mode=DEFAULT_PERMISSION_MODE,
    allowed_tools=DEFAULT_ALLOWED_TOOLS,
    max_budget_usd=DEFAULT_MAX_BUDGET_USD,
    model=None,
):
    """Pure function: builds the subprocess argument list for a headless Claude Code
    invocation. Deliberately has no side effects and does not touch the filesystem or
    network, so it can be unit tested without spending API credits. `model` (an alias
    like "sonnet"/"opus"/"fable", or a full model name) is passed straight through to
    Claude Code's own real --model flag (verified via `claude --help`) when set - None
    (the default) omits the flag entirely, letting Claude Code pick its own default,
    same as every call in this app before the AI governance policy
    (remediation/config/ai_governance.yaml) existed."""
    cmd = [claude_bin, "-p", prompt, "--output-format", output_format]
    if permission_mode:
        cmd += ["--permission-mode", permission_mode]
    if allowed_tools:
        cmd += ["--allowedTools", allowed_tools]
    if max_budget_usd:
        cmd += ["--max-budget-usd", str(max_budget_usd)]
    if model:
        cmd += ["--model", model]
    return cmd


def scan_prompt(path, fix=False):
    return f"/vulnhunt {path}" + (" --fix" if fix else "")


def remediate_prompt(generate=False, finding_id=None):
    """`finding_id`, when given, scopes the run to a single already-known finding
    (skipping full re-ingest/normalize/enrich/plan - see .claude/commands/remediate.md's
    own `--finding-id` handling) - this is what the dashboard's "Trigger Remediation"
    button on an already-approved finding uses, via /api/run."""
    prompt = "/remediate" + (" --generate" if generate else "")
    if finding_id:
        prompt += f" --finding-id {finding_id}"
    return prompt


def write_audit_log(pipeline, command, result):
    """Every invocation gets a timestamped audit record - who ran what, when, and what
    came back. This is the seed of the audit trail a real deployment needs (see
    KNOWLEDGE_TRANSFER.md's commercialization roadmap, Tier 2a)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = LOG_DIR / f"{timestamp}-{pipeline}.json"
    record = {
        "timestamp": timestamp,
        "pipeline": pipeline,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    log_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return log_path


def run(prompt, pipeline_name, dry_run=False, on_result=None, **build_kwargs):
    """`on_result`, when given, is called with the real subprocess.CompletedProcess
    right after a real (non-dry-run) call returns - lets a caller like dashboard/app.py
    record real per-user AI usage (remediation/audit/ai_usage_log.py) using the
    actually-authenticated request's user, without this function needing to know
    anything about who's calling it or changing its own int-exit-code return contract
    that main() below (and every existing caller) already depends on."""
    try:
        claude_bin = build_kwargs.pop("claude_bin", None) or find_claude_binary()
    except ClaudeBinaryNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 127

    command = build_command(prompt, claude_bin=claude_bin, **build_kwargs)

    if dry_run:
        print("Would run:", " ".join(command))
        print(f"(working directory: {REPO_ROOT})")
        return 0

    print("Running:", " ".join(command))
    print("This calls the real Claude API and will spend usage/credits.")
    result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8")

    log_path = write_audit_log(pipeline_name, command, result)
    print(f"Audit log written to {log_path}")

    if on_result:
        on_result(result)

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    try:
        parsed = json.loads(result.stdout)
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(result.stdout)

    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="Headless CLI wrapper for VulnHunter's /vulnhunt and /remediate pipelines.",
    )
    parser.add_argument("--dry-run", action="store_true",
                         help="Print the command that would run, without calling the API.")
    parser.add_argument("--claude-bin", default=None,
                         help="Path to the claude CLI binary (overrides CLAUDE_BIN/PATH discovery).")
    parser.add_argument("--max-budget-usd", default=DEFAULT_MAX_BUDGET_USD,
                         help=f"Spend cap for this invocation (default: ${DEFAULT_MAX_BUDGET_USD}).")
    parser.add_argument("--permission-mode", default=DEFAULT_PERMISSION_MODE,
                         help=f"Claude Code permission mode (default: {DEFAULT_PERMISSION_MODE}).")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run /vulnhunt against a target path.")
    scan_parser.add_argument("path", help="Path to the target repo/directory to scan.")
    scan_parser.add_argument("--fix", action="store_true", help="Also auto-fix safe findings.")

    remediate_parser = subparsers.add_parser("remediate", help="Run /remediate.")
    remediate_parser.add_argument("--generate", action="store_true",
                                   help="Also generate remediation playbooks for automatable findings.")
    remediate_parser.add_argument("--finding-id", default=None,
                                   help="Scope this run to a single already-known finding ID "
                                        "(e.g. FIND-12) instead of the full batch pipeline.")

    args = parser.parse_args(argv)

    build_kwargs = dict(
        claude_bin=args.claude_bin,
        permission_mode=args.permission_mode,
        max_budget_usd=args.max_budget_usd,
    )

    if args.command == "scan":
        prompt = scan_prompt(args.path, fix=args.fix)
        return run(prompt, "vulnhunt", dry_run=args.dry_run, **build_kwargs)
    elif args.command == "remediate":
        prompt = remediate_prompt(generate=args.generate, finding_id=args.finding_id)
        return run(prompt, "remediate", dry_run=args.dry_run, **build_kwargs)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
