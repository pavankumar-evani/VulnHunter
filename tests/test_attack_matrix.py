"""The ATT&CK matrix join (remediation/hunting/matrix.py) and its route."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.hunting import matrix  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

CAT = {"T1190": {"name": "Exploit Public-Facing Application", "tactics": ["Initial Access"]},
       "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
       "T1003": {"name": "OS Credential Dumping", "tactics": ["Credential Access"]},
       "T1486": {"name": "Data Encrypted for Impact", "tactics": ["Impact"]}}


def by_id(m):
    return {c["technique_id"]: c for c in m["techniques"]}


class MatrixBuildTests(unittest.TestCase):
    def build(self, **kw):
        return matrix.build(catalogue=CAT, **kw)

    def test_states_in_priority_order(self):
        m = self.build(rules=[{"name": "web-shell", "enabled": True, "techniques": ["T1190"]}],
                       findings=[{"attack_techniques": [{"technique_id": "T1190", "technique_name": "x"}, {"technique_id": "T1059", "technique_name": "y"}]}],
                       alerts=[{"technique": "T1003"}], hunts=[{"id": 4, "techniques": [{"technique_id": "T1059"}]}])
        c = by_id(m)
        self.assertEqual(c["T1190"]["state"], "covered")
        self.assertEqual(c["T1059"]["state"], "hunted")      # a hunt, no rule
        self.assertEqual(c["T1003"]["state"], "gap")         # an alert only
        self.assertEqual(c["T1486"]["state"], "quiet")
        self.assertEqual(c["T1059"]["hunts"], [4])
        self.assertEqual(m["totals"]["observed"], 3)
        self.assertEqual((m["totals"]["observed_covered"], m["totals"]["observed_hunted"], m["totals"]["observed_gap"]), (1, 1, 1))

    def test_disabled_rule_does_not_cover(self):
        m = self.build(rules=[{"name": "r", "enabled": False, "techniques": ["T1190"]}], findings=[{"attack_techniques": [{"technique_id": "T1190"}]}])
        self.assertEqual(by_id(m)["T1190"]["state"], "gap")
        self.assertEqual(by_id(m)["T1190"]["rules_disabled"], ["r"])

    def test_subtechnique_rolls_up_and_resolved_findings_ignored(self):
        m = self.build(rules=[{"name": "r", "enabled": True, "techniques": ["T1059.001"]}], findings=[{"status": "resolved", "attack_techniques": [{"technique_id": "T1059"}]}])
        self.assertEqual(by_id(m)["T1059"]["state"], "covered")
        self.assertEqual(by_id(m)["T1059"]["findings"], 0)

    def test_unknown_technique_is_unmapped_not_guessed(self):
        m = self.build(alerts=[{"technique": "T9999"}])
        self.assertEqual(by_id(m)["T9999"]["tactic"], "Unmapped")
        self.assertEqual(m["tactics"][-1], "Unmapped")

    def test_columns_follow_kill_chain_order_and_suggestions_attach(self):
        m = self.build(suggestions=[{"id": "hyp-1", "techniques": [{"technique_id": "T1190", "technique_name": "Exploit", "tactics": ["Initial Access"]}]}])
        self.assertEqual(m["tactics"], ["Initial Access", "Execution", "Credential Access", "Impact"])
        self.assertEqual(by_id(m)["T1190"]["suggestions"], ["hyp-1"])

    def test_no_rules_says_so(self):
        self.assertFalse(self.build()["totals"]["rules_recorded"])

    def test_default_catalogue_loads_from_yaml(self):
        cat = matrix.tactic_catalogue()
        self.assertIn("T1190", cat)
        self.assertEqual(cat["T1190"]["tactics"], ["Initial Access"])


class MatrixRouteTests(unittest.TestCase):
    PW = "test-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[])]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": self.PW})

    def test_admin_only_and_shape(self):
        self.assertEqual(self.client.get("/api/hunting/attack-matrix").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/hunting/attack-matrix").status_code, 403)
        self.login("admin@t.local")
        r = self.client.get("/api/hunting/attack-matrix")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(set(body), {"tactics", "techniques", "totals", "note"})
        self.assertTrue(body["techniques"])
        self.assertIn("state", body["techniques"][0])


if __name__ == "__main__":
    unittest.main()
