"""Integrity manifest: build, verify, tamper detection, policy vs code, no-baseline."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.integrity import manifest


def make_tree(root):
    root = Path(root)
    files = {
        "dashboard/app.py": "print('app')\n",
        "dashboard/static/js/a.js": "export const a = 1;\n",
        "dashboard/static/style.css": "body{}\n",
        "remediation/mod.py": "X = 1\n",
        "remediation/config/priority_rules.yaml": "weight: 1\n",
        "remediation/config/requirements.txt": "pyyaml\n",
        ".claude/agents/scanner.md": "# agent\n",
        ".claude/commands/run.md": "# cmd\n",
        "deploy/entrypoint.sh": "#!/bin/sh\n",
        "Dockerfile": "FROM python\n",
        "VERSION": "1.2.3\n",
        # never tracked
        "remediation/output/normalized-findings.json": "[]",
        "dashboard/auth/users.json": "[]",
        "remediation/mod.pyc": "x",
        "tests/test_x.py": "x",
        "dashboard/__pycache__/app.cpython-311.pyc": "x",
    }
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_tree(self.tmp.name)
        self._env = os.environ.pop("QUANTA_INTEGRITY_MANIFEST", None)

    def tearDown(self):
        if self._env is not None:
            os.environ["QUANTA_INTEGRITY_MANIFEST"] = self._env
        self.tmp.cleanup()

    def test_scan_tracks_code_and_policy_and_skips_runtime_data(self):
        files = manifest.scan(self.root)
        self.assertEqual(files["remediation/config/priority_rules.yaml"]["kind"], "policy")
        for rel in ("dashboard/app.py", "dashboard/static/js/a.js", "dashboard/static/style.css", ".claude/agents/scanner.md", ".claude/commands/run.md",
                    "deploy/entrypoint.sh", "Dockerfile", "remediation/mod.py"):
            self.assertEqual(files[rel]["kind"], "code", rel)
        for rel in ("remediation/output/normalized-findings.json", "dashboard/auth/users.json", "remediation/mod.pyc", "tests/test_x.py", "remediation/config/requirements.txt"):
            self.assertNotIn(rel, files)
        self.assertFalse(any("__pycache__" in r for r in files))

    def test_no_baseline_is_never_ok(self):
        result = manifest.verify(self.root)
        self.assertEqual(result["state"], "no-baseline")
        self.assertIsNone(result["baseline"])
        self.assertIn("integrity-manifest", result["message"])

    def test_unchanged_tree_is_ok(self):
        manifest.write(self.root)
        result = manifest.verify(self.root)
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["code"], {"modified": [], "missing": [], "unexpected": []})

    def test_written_manifest_does_not_include_itself(self):
        path, data = manifest.write(self.root)
        self.assertTrue(path.exists())
        self.assertNotIn("remediation/integrity/manifest.json", data["files"])
        self.assertEqual(data["quanta_version"], "1.2.3")
        self.assertEqual(manifest.verify(self.root)["state"], "ok")

    def test_modified_missing_and_unexpected_code_are_reported(self):
        manifest.write(self.root)
        (self.root / "dashboard/app.py").write_text("print('tampered')\n", encoding="utf-8")
        (self.root / "remediation/mod.py").unlink()
        (self.root / "dashboard/backdoor.py").write_text("x", encoding="utf-8")
        r = manifest.verify(self.root)
        self.assertEqual(r["state"], "code-modified")
        self.assertEqual(r["code"]["modified"], ["dashboard/app.py"])
        self.assertEqual(r["code"]["missing"], ["remediation/mod.py"])
        self.assertEqual(r["code"]["unexpected"], ["dashboard/backdoor.py"])

    def test_policy_change_is_expected_not_tampering_and_names_the_editor(self):
        manifest.write(self.root)
        (self.root / "remediation/config/priority_rules.yaml").write_text("weight: 9\n", encoding="utf-8")
        activity = [{"actor": "admin@x", "action": "priority_rules.save", "target": None, "details": {}, "timestamp": "2026-10-01T00:00:00Z"},
                    {"actor": "other@x", "action": "login.success", "target": None, "details": {}, "timestamp": "2026-09-01T00:00:00Z"}]
        r = manifest.verify(self.root, activity=activity)
        self.assertEqual(r["state"], "policy-changed")
        self.assertEqual(r["code"]["modified"], [])
        self.assertEqual(r["policy"]["modified"], ["remediation/config/priority_rules.yaml"])
        self.assertEqual(r["policy"]["editors"]["remediation/config/priority_rules.yaml"]["actor"], "admin@x")

    def test_policy_change_with_no_log_entry_has_no_editor_rather_than_a_guess(self):
        manifest.write(self.root)
        (self.root / "remediation/config/priority_rules.yaml").write_text("weight: 9\n", encoding="utf-8")
        r = manifest.verify(self.root, activity=[])
        self.assertEqual(r["policy"]["editors"], {})

    def test_code_modification_wins_over_policy_change(self):
        manifest.write(self.root)
        (self.root / "remediation/config/priority_rules.yaml").write_text("weight: 9\n", encoding="utf-8")
        (self.root / "dashboard/static/js/a.js").write_text("evil", encoding="utf-8")
        self.assertEqual(manifest.verify(self.root)["state"], "code-modified")

    def test_unreadable_manifest_is_no_baseline(self):
        p = manifest.manifest_path(self.root)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(manifest.verify(self.root)["state"], "no-baseline")

    def test_env_override_for_manifest_location(self):
        alt = Path(self.tmp.name) / "elsewhere" / "m.json"
        os.environ["QUANTA_INTEGRITY_MANIFEST"] = str(alt)
        try:
            manifest.write(self.root)
            self.assertTrue(alt.exists())
            self.assertEqual(json.loads(alt.read_text())["format"], manifest.FORMAT_VERSION)
        finally:
            os.environ.pop("QUANTA_INTEGRITY_MANIFEST", None)

    def test_real_repo_builds_a_manifest_with_policy_and_code(self):
        files = manifest.scan(manifest.REPO_ROOT)
        kinds = {m["kind"] for m in files.values()}
        self.assertEqual(kinds, {"code", "policy"})
        self.assertIn("dashboard/app.py", files)


if __name__ == "__main__":
    unittest.main()
