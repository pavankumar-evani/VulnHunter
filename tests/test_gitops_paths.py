"""gitops path policy: non-canonical paths are refused and denied patterns match case-insensitively."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.gitops import policy  # noqa: E402


class PathTests(unittest.TestCase):
    def setUp(self):
        self.pol = policy.load()

    def check(self, path):
        policy.check_files(self.pol, [{"path": path, "content": "x"}])

    def test_plain_path_allowed(self):
        self.check("requirements.txt")
        self.check("app/db.py")

    def test_denied_workflow_still_refused(self):
        with self.assertRaises(policy.PolicyError):
            self.check(".github/workflows/x.yml")

    def test_non_canonical_forms_refused(self):
        for p in ("./.github/workflows/x.yml", ".github//workflows/x.yml", "a/./b.py", "a/../b.py", "a"+chr(92)+"b.py",
                  "/etc/passwd", "a/b.py\x00.txt", "a/b/", "", "../x"):
            with self.assertRaises(policy.PolicyError, msg=repr(p)):
                self.check(p)

    def test_case_insensitive_denied(self):
        for p in (".GitHub/Workflows/x.yml", ".GITHUB/workflows/X.YML"):
            with self.assertRaises(policy.PolicyError, msg=p):
                self.check(p)


if __name__ == "__main__":
    unittest.main()
