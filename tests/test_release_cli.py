import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cli"))
import quanta_release as qr  # noqa: E402

GOOD_PROD_ENV = {"QUANTA_SESSION_SECRET": "x" * 40, "QUANTA_ENCRYPTION_KEY": "k", "QUANTA_LICENSE_MODE": "off",
                 "QUANTA_DATABASE_URL": "postgresql+psycopg2://u:p@h/db", "QUANTA_ENV": "prod"}


def levels(results):
    return {n: l for l, n, _ in results}


class FakeRepo:
    def __init__(self, version="1.2.3", changelog="## [Unreleased]\n\n### Added\n- thing\n"):
        self.d = tempfile.TemporaryDirectory()
        r = Path(self.d.name)
        (r / "VERSION").write_text(version + "\n", encoding="utf-8")
        (r / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        h = r / "deploy" / "helm" / "quanta"
        h.mkdir(parents=True)
        (h / "Chart.yaml").write_text(f'appVersion: "{version}"\n', encoding="utf-8")
        for t in ("dev", "test", "prod"):
            (h / f"values-{t}.yaml").write_text(f"config:\n  environment: {t}\nweb:\n  replicas: 2\n", encoding="utf-8")
        (r / "Dockerfile").write_text(f"ARG VERSION={version}\n", encoding="utf-8")
        self.root = r

    def close(self):
        self.d.cleanup()


class VersionTests(unittest.TestCase):
    def test_semver_and_changelog(self):
        f = FakeRepo()
        self.addCleanup(f.close)
        self.assertEqual(levels(qr.check_version(f.root)), {"version": "PASS", "changelog": "PASS"})
        (f.root / "VERSION").write_text("1.2\n", encoding="utf-8")
        self.assertEqual(levels(qr.check_version(f.root))["version"], "FAIL")

    def test_changelog_heading_or_nothing(self):
        f = FakeRepo(changelog="## [Unreleased]\n\n## [1.0.0]\n- old\n")
        self.addCleanup(f.close)
        self.assertEqual(levels(qr.check_version(f.root))["changelog"], "FAIL")
        (f.root / "CHANGELOG.md").write_text("## [Unreleased]\n\n## [1.2.3] - 2026\n- x\n", encoding="utf-8")
        self.assertEqual(levels(qr.check_version(f.root))["changelog"], "PASS")


class BackupTests(unittest.TestCase):
    def test_prod_needs_fresh_backup(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(levels(qr.check_backup("prod", d, 24))["backup"], "FAIL")
            z = Path(d) / "quanta-backup-20260101T000000Z.zip"
            z.write_bytes(b"x")
            self.assertEqual(levels(qr.check_backup("prod", d, 24))["backup"], "PASS")
            self.assertEqual(levels(qr.check_backup("prod", d, 24, now=time.time() + 48 * 3600))["backup"], "FAIL")
            self.assertEqual(levels(qr.check_backup("dev", "nowhere", 24))["backup"], "PASS")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.f = FakeRepo()
        self.addCleanup(self.f.close)
        import quanta_admin
        p = mock.patch.object(quanta_admin, "is_sample_dataset", return_value=False)
        p.start()
        self.addCleanup(p.stop)
        from auth import users
        q = mock.patch.object(users, "verify_login", return_value=False)
        q.start()
        self.addCleanup(q.stop)

    def test_good_prod_config(self):
        r = levels(qr.check_config("prod", dict(GOOD_PROD_ENV), self.f.root))
        self.assertNotIn("FAIL", r.values(), r)

    def test_each_prod_rule_fails(self):
        cases = {
            "session secret": {"QUANTA_SESSION_SECRET": "short"},
            "encryption key": {"QUANTA_ENCRYPTION_KEY": ""},
            "TLS": {"QUANTA_DISABLE_TLS": "true"},
            "licence mode": {"QUANTA_LICENSE_MODE": ""},
            "database": {"QUANTA_DATABASE_URL": "sqlite:///x.db"},
            "QUANTA_ENV": {"QUANTA_ENV": "dev"},
        }
        for name, change in cases.items():
            env = {**GOOD_PROD_ENV, **change}
            self.assertEqual(levels(qr.check_config("prod", env, self.f.root)).get(name), "FAIL", name)

    def test_tls_ok_behind_ingress_and_simulation_warns(self):
        env = {**GOOD_PROD_ENV, "QUANTA_DISABLE_TLS": "true", "QUANTA_BEHIND_INGRESS": "true", "QUANTA_ALLOW_SIMULATION": "true"}
        r = levels(qr.check_config("prod", env, self.f.root))
        self.assertEqual((r["TLS"], r["simulation"]), ("PASS", "WARN"))

    def test_sample_data_and_demo_accounts_fail(self):
        import quanta_admin
        from auth import users
        with mock.patch.object(quanta_admin, "is_sample_dataset", return_value=True), mock.patch.object(users, "verify_login", return_value=True):
            r = levels(qr.check_config("prod", dict(GOOD_PROD_ENV), self.f.root))
        self.assertEqual((r["sample data"], r["demo accounts"]), ("FAIL", "FAIL"))

    def test_dev_skips_production_rules(self):
        self.assertNotIn("FAIL", levels(qr.check_config("dev", {}, self.f.root)).values())


class DeploymentFilesTests(unittest.TestCase):
    def test_consistent_repo_passes_and_drift_fails(self):
        f = FakeRepo()
        self.addCleanup(f.close)
        self.assertNotIn("FAIL", levels(qr.check_deployment_files("prod", f.root)).values())
        (f.root / "Dockerfile").write_text("ARG VERSION=9.9.9\n", encoding="utf-8")
        self.assertEqual(levels(qr.check_deployment_files("prod", f.root))["Dockerfile"], "FAIL")
        (f.root / "deploy" / "helm" / "quanta" / "values-test.yaml").write_text("config:\n  environment: prod\n", encoding="utf-8")
        self.assertEqual(levels(qr.check_deployment_files("test", f.root))["helm values"], "FAIL")
        (f.root / "deploy" / "helm" / "quanta" / "values-dev.yaml").unlink()
        self.assertEqual(levels(qr.check_deployment_files("dev", f.root))["helm values"], "FAIL")

    def test_the_real_repo_is_consistent(self):
        for t in ("dev", "test", "prod"):
            bad = [r for r in qr.check_deployment_files(t, ROOT) + qr.check_version(ROOT) if r[0] == "FAIL"]
            self.assertEqual(bad, [], t)


class CommandTests(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = qr.main(argv)
        return code, out.getvalue()

    def test_info(self):
        with mock.patch.dict(os.environ, {"QUANTA_ENV": "test", "QUANTA_BUILD_SHA": "abc123"}):
            code, out = self.run_cli(["info"])
        self.assertEqual(code, 0)
        self.assertIn("abc123", out)
        self.assertIn("test", out)

    def test_check_exit_codes(self):
        with mock.patch.object(qr, "run_checks", return_value=[("PASS", "a", "ok")]):
            self.assertEqual(self.run_cli(["check", "--target", "dev"])[0], 0)
        with mock.patch.object(qr, "run_checks", return_value=[("PASS", "a", "ok"), ("FAIL", "b", "bad")]):
            self.assertEqual(self.run_cli(["check", "--target", "prod"])[0], 1)

    def test_check_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e.env"
            p.write_text("# c\nQUANTA_SESSION_SECRET=abc\nQUANTA_LICENSE_MODE='off'\n", encoding="utf-8")
            self.assertEqual(qr.read_env_file(p), {"QUANTA_SESSION_SECRET": "abc", "QUANTA_LICENSE_MODE": "off"})

    def test_rollback_plan_prints_only(self):
        with mock.patch("subprocess.run") as run, mock.patch("os.system") as system:
            code, out = self.run_cli(["rollback-plan", "--environment", "prod", "--from", "1.3.0", "--to", "1.2.4", "--revision", "7"])
        run.assert_not_called()
        system.assert_not_called()
        self.assertEqual(code, 0)
        for needle in ("helm rollback quanta 7", "--wait", "helm history", "helm get values", "expand-only", "contract", "/readyz", "1.2.4"):
            self.assertIn(needle, out)

    def test_backup_delegates(self):
        import quanta_admin
        with mock.patch.object(quanta_admin, "cmd_backup") as b:
            self.run_cli(["backup", "--out", "somewhere"])
        self.assertEqual(b.call_args[0][0].out, "somewhere")


if __name__ == "__main__":
    unittest.main()
