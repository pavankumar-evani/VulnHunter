"""QUANTA_PRODUCTION has one definition (rbac.production_enabled); the startup check and every runtime behaviour that depends on it must agree."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

import app as dashboard_app  # noqa: E402
from auth import rbac  # noqa: E402


def env(value):
    base = {k: v for k, v in os.environ.items() if k not in ("QUANTA_PRODUCTION", "QUANTA_ENABLE_CSP", "QUANTA_REQUIRE_LOGIN_FOR_READS", "QUANTA_ALLOW_PUBLIC_READS")}
    if value is not None:
        base["QUANTA_PRODUCTION"] = value
    return patch.dict(os.environ, base, clear=True)


class ProductionFlagTests(unittest.TestCase):
    def test_every_recognised_true_value_is_production(self):
        for value in ("1", "true", "TRUE", "yes", "on", "On", " on "):
            with env(value):
                self.assertTrue(rbac.production_enabled(), value)

    def test_false_and_unset_values_are_not_production(self):
        for value in (None, "", "0", "false", "no", "off"):
            with env(value):
                self.assertFalse(rbac.production_enabled(), repr(value))

    def test_on_means_the_same_thing_everywhere(self):
        # the old behaviour: the startup check treated "on" as production while the runtime did not, so reads stayed public and the policy stayed off
        with env("on"):
            self.assertTrue(dashboard_app._csp_enabled())
            self.assertTrue(dashboard_app._require_login_for_reads_enabled())

    def test_off_means_off_everywhere(self):
        with env("off"):
            self.assertFalse(dashboard_app._csp_enabled())
            self.assertFalse(dashboard_app._require_login_for_reads_enabled())


if __name__ == "__main__":
    unittest.main()
