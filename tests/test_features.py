import os
import re
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
from remediation.utils import features  # noqa: E402


class FeatureFlagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__import__("tempfile").mkdtemp()) / "features.yaml"
        self.tmp.write_text(yaml.safe_dump({
            "dev-only": {"description": "d", "enabled_in": ["dev"]},
            "to-test": {"description": "t", "enabled_in": ["dev", "test"]},
            "everywhere": {"description": "e", "enabled_in": ["dev", "test", "prod"]},
        }), encoding="utf-8")
        self.p = mock.patch.object(features, "FEATURES_FILE", self.tmp)
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_promotion_ladder(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("QUANTA_FEATURES_ON", "QUANTA_FEATURES_OFF"):
                os.environ.pop(k, None)
            self.assertTrue(features.enabled("dev-only", env="dev"))
            self.assertFalse(features.enabled("dev-only", env="test"))
            self.assertFalse(features.enabled("dev-only", env="prod"))
            self.assertTrue(features.enabled("to-test", env="test"))
            self.assertFalse(features.enabled("to-test", env="prod"))
            self.assertTrue(features.enabled("everywhere", env="prod"))

    def test_unknown_is_false_and_never_raises(self):
        self.assertFalse(features.enabled("nope", env="dev"))
        self.assertFalse(features.enabled(None, env="dev"))
        with mock.patch.object(features, "FEATURES_FILE", Path("does-not-exist.yaml")):
            self.assertFalse(features.enabled("dev-only", env="dev"))

    def test_overrides(self):
        with mock.patch.dict(os.environ, {"QUANTA_FEATURES_ON": "dev-only, ghost", "QUANTA_FEATURES_OFF": "everywhere"}):
            self.assertTrue(features.enabled("dev-only", env="prod"))
            self.assertTrue(features.enabled("ghost", env="prod"))
            self.assertFalse(features.enabled("everywhere", env="dev"))
        with mock.patch.dict(os.environ, {"QUANTA_FEATURES_ON": "x", "QUANTA_FEATURES_OFF": "x"}):
            self.assertFalse(features.enabled("x", env="dev"))  # OFF wins

    def test_uses_quanta_env(self):
        with mock.patch.dict(os.environ, {"QUANTA_ENV": "prod"}):
            os.environ.pop("QUANTA_FEATURES_ON", None)
            self.assertFalse(features.enabled("dev-only"))
        with mock.patch.dict(os.environ, {"QUANTA_ENV": "dev"}):
            os.environ.pop("QUANTA_FEATURES_ON", None)
            os.environ.pop("QUANTA_FEATURES_OFF", None)
            self.assertTrue(features.enabled("dev-only"))

    def test_invalid_env_treated_as_prod(self):
        with mock.patch.dict(os.environ, {"QUANTA_ENV": "typo"}):
            os.environ.pop("QUANTA_FEATURES_ON", None)
            self.assertFalse(features.enabled("dev-only"))


class ShippedFlagsTests(unittest.TestCase):
    def test_shipped_file_shape(self):
        data = yaml.safe_load((ROOT / "remediation" / "config" / "features.yaml").read_text(encoding="utf-8"))
        for n in ("relationship-graphs", "security-posture-review", "simulation-connectors"):
            self.assertIn(n, data)
        for n, spec in data.items():
            self.assertTrue(spec["description"], n)
            self.assertTrue(set(spec["enabled_in"]) <= {"dev", "test", "prod"}, n)
        self.assertNotIn("prod", data["simulation-connectors"]["enabled_in"])

    def test_nav_feature_keys_name_real_flags(self):
        flags = set(yaml.safe_load((ROOT / "remediation" / "config" / "features.yaml").read_text(encoding="utf-8")))
        nav = (ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")
        used = set(re.findall(r'feature:\s*"([^"]+)"', nav))
        self.assertTrue(used)
        self.assertTrue(used <= flags, used - flags)
        for line in nav.splitlines():
            if 'label: "Relationship graph"' in line:
                self.assertIn('feature: "relationship-graphs"', line)


class FeaturesApiTests(unittest.TestCase):
    def test_requires_login_and_returns_snapshot(self):
        from dashboard import app as app_module
        c = TestClient(app_module.app)
        with mock.patch.dict(os.environ, {"QUANTA_REQUIRE_LOGIN_FOR_READS": "false"}):
            r = c.get("/api/features")
        self.assertEqual(r.status_code, 401)
        with mock.patch.object(app_module.rbac, "require_login", lambda: {"email": "a"}):
            pass
        app_module.app.dependency_overrides[app_module.rbac.require_login] = lambda: {"email": "a@quanta.local", "role": "admin"}
        try:
            r = c.get("/api/features")
        finally:
            app_module.app.dependency_overrides.clear()
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("relationship-graphs", body["features"])
        self.assertIn(body["environment"], ("dev", "test", "prod"))

    def test_status_reports_environment(self):
        from dashboard import app as app_module
        r = TestClient(app_module.app).get("/api/status")
        self.assertEqual(r.status_code, 200)
        env = r.json()["environment"]
        for k in ("version", "build_sha", "build_time", "environment", "simulation_allowed"):
            self.assertIn(k, env)


if __name__ == "__main__":
    unittest.main()
