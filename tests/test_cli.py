"""
Tests for cli/vulnhunter.py's command-construction logic.

These deliberately never invoke the real `claude` binary or the network - that would
spend real API usage/credits on every CI run, which is not acceptable for a test suite.
Instead they test the pure functions (scan_prompt, remediate_prompt, build_command) that
decide WHAT would be run, and use --dry-run for the one end-to-end path that's exercised.
"""
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "cli"))

import vulnhunter as cli  # noqa: E402


class PromptConstruction(unittest.TestCase):
    def test_scan_prompt_without_fix(self):
        self.assertEqual(cli.scan_prompt("vulnerable-demo-app"), "/vulnhunt vulnerable-demo-app")

    def test_scan_prompt_with_fix(self):
        self.assertEqual(
            cli.scan_prompt("vulnerable-demo-app", fix=True),
            "/vulnhunt vulnerable-demo-app --fix",
        )

    def test_remediate_prompt_without_generate(self):
        self.assertEqual(cli.remediate_prompt(), "/remediate")

    def test_remediate_prompt_with_generate(self):
        self.assertEqual(cli.remediate_prompt(generate=True), "/remediate --generate")

    def test_remediate_prompt_with_finding_id(self):
        self.assertEqual(cli.remediate_prompt(finding_id="FIND-12"), "/remediate --finding-id FIND-12")

    def test_remediate_prompt_with_generate_and_finding_id(self):
        self.assertEqual(
            cli.remediate_prompt(generate=True, finding_id="FIND-12"),
            "/remediate --generate --finding-id FIND-12",
        )


class CommandConstruction(unittest.TestCase):
    def test_build_command_includes_print_and_prompt(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude")
        self.assertEqual(cmd[0], "claude")
        self.assertIn("-p", cmd)
        self.assertIn("/vulnhunt foo", cmd)

    def test_build_command_defaults_to_json_output(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude")
        self.assertIn("--output-format", cmd)
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")

    def test_build_command_includes_permission_mode(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude", permission_mode="acceptEdits")
        self.assertIn("--permission-mode", cmd)
        self.assertEqual(cmd[cmd.index("--permission-mode") + 1], "acceptEdits")

    def test_build_command_includes_max_budget(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude", max_budget_usd="5.00")
        self.assertIn("--max-budget-usd", cmd)
        self.assertEqual(cmd[cmd.index("--max-budget-usd") + 1], "5.00")

    def test_build_command_omits_flags_when_falsy(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude",
                                 permission_mode=None, allowed_tools=None, max_budget_usd=None)
        self.assertNotIn("--permission-mode", cmd)
        self.assertNotIn("--allowedTools", cmd)
        self.assertNotIn("--max-budget-usd", cmd)

    def test_build_command_includes_model_when_set(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude", model="sonnet")
        idx = cmd.index("--model")
        self.assertEqual(cmd[idx + 1], "sonnet")

    def test_build_command_omits_model_flag_when_not_set(self):
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude", model=None)
        self.assertNotIn("--model", cmd)

    def test_build_command_never_includes_dangerous_skip_permissions(self):
        """Regression guard: this wrapper must never default to bypassing permission
        checks entirely - that flag exists in the underlying CLI but this project's
        default posture is scoped tool allowlists, not a blanket bypass."""
        cmd = cli.build_command("/vulnhunt foo", claude_bin="claude")
        joined = " ".join(cmd)
        self.assertNotIn("dangerously-skip-permissions", joined)


class ClaudeBinaryDiscovery(unittest.TestCase):
    def test_explicit_env_var_takes_priority(self):
        import os
        old = os.environ.get("CLAUDE_BIN")
        os.environ["CLAUDE_BIN"] = "/custom/path/claude"
        try:
            self.assertEqual(cli.find_claude_binary(), "/custom/path/claude")
        finally:
            if old is None:
                os.environ.pop("CLAUDE_BIN", None)
            else:
                os.environ["CLAUDE_BIN"] = old


class DryRunEndToEnd(unittest.TestCase):
    """The one test that actually invokes the CLI script as a subprocess - but always
    with --dry-run, so it never calls the real Claude API."""

    def test_dry_run_scan_prints_command_without_calling_api(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "cli" / "vulnhunter.py"),
             "--dry-run", "scan", "vulnerable-demo-app"],
            capture_output=True, text=True, encoding="utf-8", cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Would run:", result.stdout)
        self.assertIn("/vulnhunt vulnerable-demo-app", result.stdout)

    def test_dry_run_remediate_with_generate(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "cli" / "vulnhunter.py"),
             "--dry-run", "remediate", "--generate"],
            capture_output=True, text=True, encoding="utf-8", cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("/remediate --generate", result.stdout)


class RunFunctionOnResultCallback(unittest.TestCase):
    """Calls cli.run() directly (not via subprocess) so this can assert on_result's
    behavior without ever spending real API usage - a dry run returns before the real
    subprocess.run() call, so on_result must never fire for one."""

    def test_dry_run_never_invokes_on_result(self):
        calls = []
        exit_code = cli.run(
            "/vulnhunt foo", "vulnhunt", dry_run=True, on_result=lambda result: calls.append(result),
            claude_bin="claude",
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(calls, [])

    def test_missing_binary_never_invokes_on_result(self):
        calls = []
        with unittest.mock.patch.object(cli, "find_claude_binary", side_effect=cli.ClaudeBinaryNotFound("nope")):
            exit_code = cli.run(
                "/vulnhunt foo", "vulnhunt", dry_run=False, on_result=lambda result: calls.append(result),
            )
        self.assertEqual(exit_code, 127)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
