"""The container entrypoint runs an explicit command as given instead of always starting the web application."""
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parent.parent / "deploy" / "entrypoint.sh").read_text(encoding="utf-8")


class EntrypointTests(unittest.TestCase):
    def test_an_explicit_command_is_exec_ed_before_any_setup(self):
        passthrough = SCRIPT.index('exec "$@"')
        self.assertLess(passthrough, SCRIPT.index("quanta_admin.py init"))
        self.assertLess(SCRIPT.index('if [ "$#" -gt 0 ]'), passthrough)

    def test_without_a_command_it_still_prepares_and_starts_the_app(self):
        for needle in ("quanta_admin.py init", "quanta_admin.py bootstrap", "exec python dashboard/app.py"):
            self.assertIn(needle, SCRIPT)

    def test_the_workflow_generates_its_key_through_the_pass_through(self):
        wf = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "helm-kind.yml").read_text(encoding="utf-8")
        self.assertIn("python cli/quanta_admin.py gen-key", wf)


if __name__ == "__main__":
    unittest.main()
