"""Repository-name rule, git host URL encoding, XML entity refusal, licence keygen, production secret rules."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cli"))

from dashboard.auth import rbac  # noqa: E402
from remediation.appsec import manifest_gen, store  # noqa: E402
from remediation.appsec.sbom_parse import SbomError  # noqa: E402
from remediation.connectors import git_host_connector as gh  # noqa: E402
from remediation.ingest import coverage  # noqa: E402

BOMB = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><project>&a;</project>'


class RepoNameTests(unittest.TestCase):
    def test_dot_segments_rejected(self):
        for r in ("a/..", "../a", "a/./b", ".hidden/x", "a/.b"):
            self.assertIsNone(store._REPO.match(r), r)
        for r in ("owner/repo", "o/r.js", "grp/sub/proj"):
            self.assertTrue(store._REPO.match(r), r)

    def test_github_segments_encoded(self):
        self.assertEqual(gh._Base._rp("o/r e"), "o/r%20e")
        self.assertEqual(gh.GitLabConnector._pid("g/p"), "g%2Fp")


class XmlTests(unittest.TestCase):
    def test_coverage_refuses_entities(self):
        with self.assertRaises(coverage.CoverageError):
            coverage.parse_cobertura(BOMB)

    def test_pom_refuses_entities(self):
        with self.assertRaises(SbomError):
            manifest_gen.from_pom(BOMB)


class KeygenTests(unittest.TestCase):
    def run_keygen(self, d, *extra):
        import quanta_license
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            try:
                quanta_license.main(["keygen", "--out-dir", d, *extra])
                code = 0
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def test_no_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_keygen(d)[0], 0)
            first = (Path(d) / "vendor_private.pem").read_bytes()
            code, _ = self.run_keygen(d)
            self.assertNotEqual(code, 0)
            self.assertEqual((Path(d) / "vendor_private.pem").read_bytes(), first)
            self.assertEqual(self.run_keygen(d, "--force")[0], 0)
            self.assertNotEqual((Path(d) / "vendor_private.pem").read_bytes(), first)

    @unittest.skipIf(os.name == "nt", "POSIX modes only")
    def test_private_key_mode(self):
        with tempfile.TemporaryDirectory() as d:
            self.run_keygen(d)
            self.assertEqual((Path(d) / "vendor_private.pem").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "nt", "Windows warning only")
    def test_windows_warns(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("WARNING", self.run_keygen(d)[1])


class ProductionSecretTests(unittest.TestCase):
    def env(self, **kw):
        base = {"QUANTA_PRODUCTION": "", "QUANTA_REQUIRE_LOGIN_FOR_READS": "", "QUANTA_SESSION_SECRET": "", "QUANTA_SESSION_SECRET_FILE": ""}
        base.update(kw)
        return patch.dict(os.environ, base)

    def test_short_secret_refused_without_echo(self):
        with self.env(QUANTA_PRODUCTION="true", QUANTA_SESSION_SECRET="shortsecret"):
            with self.assertRaises(RuntimeError) as cm:
                rbac.validate_production_requirements()
        self.assertNotIn("shortsecret", str(cm.exception))

    def test_long_secret_ok_and_file_secret(self):
        with self.env(QUANTA_PRODUCTION="true", QUANTA_SESSION_SECRET="s" * 32):
            rbac.validate_production_requirements()
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "s"
            f.write_text("k" * 40 + "\n")
            with self.env(QUANTA_PRODUCTION="1", QUANTA_SESSION_SECRET_FILE=str(f)):
                rbac.validate_production_requirements()
            f.write_text("tiny\n")
            with self.env(QUANTA_PRODUCTION="1", QUANTA_SESSION_SECRET_FILE=str(f)):
                with self.assertRaises(RuntimeError):
                    rbac.validate_production_requirements()

    def test_unrecognised_production_value_refused(self):
        with self.env(QUANTA_PRODUCTION="ture"):
            with self.assertRaises(RuntimeError):
                rbac.validate_production_requirements()
        for v in ("0", "false", "no", "off", ""):
            with self.env(QUANTA_PRODUCTION=v):
                rbac.validate_production_requirements()


if __name__ == "__main__":
    unittest.main()
