import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.utils import environment as env  # noqa: E402


class EnvironmentTests(unittest.TestCase):
    def test_the_name_comes_from_quanta_env(self):
        for v in ("dev", "test", "prod", " PROD ", "Test"):
            self.assertEqual(env.name({"QUANTA_ENV": v}), v.strip().lower())

    def test_unset_is_dev_unless_the_older_production_flag_is_on(self):
        self.assertEqual(env.name({}), "dev")
        self.assertEqual(env.name({"QUANTA_PRODUCTION": "true"}), "prod")
        self.assertEqual(env.name({"QUANTA_PRODUCTION": "on"}), "prod")
        self.assertEqual(env.name({"QUANTA_PRODUCTION": "false"}), "dev")

    def test_an_explicit_environment_wins_over_the_older_flag(self):
        self.assertEqual(env.name({"QUANTA_ENV": "test", "QUANTA_PRODUCTION": "true"}), "test")

    def test_a_typo_is_an_error_not_a_silent_dev(self):
        with self.assertRaises(env.EnvironmentError_):
            env.name({"QUANTA_ENV": "production"})
        with self.assertRaises(env.EnvironmentError_):
            env.name({"QUANTA_ENV": "stagging"})

    def test_simulation_runs_in_dev_and_test_but_not_in_prod_unless_allowed(self):
        self.assertTrue(env.simulation_allowed({"QUANTA_ENV": "dev"}))
        self.assertTrue(env.simulation_allowed({"QUANTA_ENV": "test"}))
        self.assertFalse(env.simulation_allowed({"QUANTA_ENV": "prod"}))
        self.assertFalse(env.simulation_allowed({"QUANTA_ENV": "prod", "QUANTA_ALLOW_SIMULATION": "no"}))
        self.assertTrue(env.simulation_allowed({"QUANTA_ENV": "prod", "QUANTA_ALLOW_SIMULATION": "true"}))

    def test_the_older_production_flag_also_closes_simulation(self):
        self.assertFalse(env.simulation_allowed({"QUANTA_PRODUCTION": "true"}))

    def test_info_reports_the_build_and_never_invents_one(self):
        out = env.info({"QUANTA_ENV": "test", "QUANTA_BUILD_SHA": "abc1234", "QUANTA_BUILD_TIME": "2026-10-06T10:00:00Z"})
        self.assertEqual((out["environment"], out["build_sha"], out["build_time"], out["simulation_allowed"]), ("test", "abc1234", "2026-10-06T10:00:00Z", True))
        blank = env.info({})
        self.assertEqual((blank["build_sha"], blank["build_time"]), (None, None))

    def test_the_version_file_holds_a_semantic_version(self):
        import re
        self.assertRegex(env.version(), r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


if __name__ == "__main__":
    unittest.main()
