"""Tests for remediation/validation/playbook_lint.py - the deterministic safety lint."""
import glob
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.validation.playbook_lint import lint_playbook  # noqa: E402

GOOD = """# Finding: FIND-9 - Example (CVE-2026-0001) on HOST1
# Risk tier: needs-change-approval - production server.
# CHANGE APPROVAL REQUIRED before running.
# Rollback: restore from the pre-change snapshot, or reinstall the previous package version.
---
- name: "FIND-9: fix"
  hosts: "{{ target_host | default('HOST1') }}"
  tasks:
    - name: Check current package version (pre-change baseline)
      ansible.builtin.package_facts:
    - name: Upgrade the package
      ansible.builtin.package:
        name: example
        state: latest
    - name: Verify the fixed version is installed
      ansible.builtin.assert:
        that: true
"""


def rules(result, kind="errors"):
    return sorted(i["rule"] for i in result[kind])


class LintTests(unittest.TestCase):
    def test_a_well_formed_playbook_passes_with_no_findings(self):
        r = lint_playbook(GOOD)
        self.assertTrue(r["passed"], r)
        self.assertEqual((r["errors"], r["warnings"]), ([], []))

    def test_missing_header_pieces_are_errors(self):
        r = lint_playbook(GOOD.replace("# Finding: FIND-9 - Example (CVE-2026-0001) on HOST1\n", "")
                          .replace("# Risk tier: needs-change-approval - production server.\n", ""))
        self.assertFalse(r["passed"])
        self.assertIn("PB001", rules(r))
        self.assertIn("PB002", rules(r))

    def test_rollback_must_be_real(self):
        self.assertIn("PB003", rules(lint_playbook(GOOD.replace("# Rollback: restore from the pre-change snapshot, or reinstall the previous package version.", "# Rollback: n/a"))))
        self.assertIn("PB003", rules(lint_playbook(GOOD.replace("# Rollback:", "# Note:"))))

    def test_change_approval_gate_required_for_that_tier(self):
        r = lint_playbook(GOOD.replace("# CHANGE APPROVAL REQUIRED before running.\n", ""))
        self.assertIn("PB004", rules(r))
        ok = lint_playbook(GOOD.replace("needs-change-approval", "auto-approvable").replace("# CHANGE APPROVAL REQUIRED before running.\n", ""))
        self.assertNotIn("PB004", rules(ok))

    def test_invalid_or_empty_yaml_is_an_error(self):
        self.assertIn("PB005", rules(lint_playbook("# Finding: FIND-1\n# Risk tier: x\n# Rollback: restore the snapshot first\n---\n- [broken")))
        self.assertIn("PB005", rules(lint_playbook(GOOD.split("---")[0] + "---\n- name: no tasks here\n  hosts: x\n")))

    def test_literal_credentials_are_an_error_but_vault_references_are_not(self):
        bad = GOOD.replace("name: example", "name: example\n        password: hunter2hunter2")
        self.assertIn("PB006", rules(lint_playbook(bad)))
        fine = GOOD.replace("name: example", "name: example\n        password: \"{{ lookup('vault', 'x') }}\"")
        self.assertNotIn("PB006", rules(lint_playbook(fine)))

    def test_targeting_all_hosts_is_an_error(self):
        r = lint_playbook(GOOD.replace("\"{{ target_host | default('HOST1') }}\"", "all"))
        self.assertIn("PB007", rules(r))

    def test_warnings_do_not_block(self):
        content = GOOD.replace("Check current package version (pre-change baseline)", "Gather facts") \
                      .replace("Verify the fixed version is installed", "Finish") \
                      .replace("ansible.builtin.package:\n        name: example\n        state: latest",
                               "ansible.builtin.shell: yum -y update example\n      ignore_errors: true")
        r = lint_playbook(content)
        self.assertTrue(r["passed"], r)
        self.assertEqual(rules(r, "warnings"), ["PB008", "PB009", "PB010", "PB011"])

    def test_every_shipped_sample_playbook_passes(self):
        files = glob.glob(str(REPO_ROOT / "remediation" / "output" / "FIND-*.yml"))
        self.assertTrue(files)
        for f in files:
            r = lint_playbook(Path(f).read_text(encoding="utf-8"))
            self.assertTrue(r["passed"], f"{f}: {r['errors']}")


if __name__ == "__main__":
    unittest.main()


# ----------------------------------------------------------------------- API wiring
import tempfile  # noqa: E402
from unittest.mock import patch  # noqa: E402

sys.path[:0] = [str(REPO_ROOT / "dashboard"), str(REPO_ROOT / "cli")]
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

BAD = GOOD.replace("# Rollback: restore from the pre-change snapshot, or reinstall the previous package version.", "# Rollback: n/a")


def _finding():
    return {"id": "FIND-9", "title": "t", "priority": "High", "severity": "High", "asset": {"name": "HOST1"},
            "cve": None, "first_seen": "2026-08-01", "score": 5, "last_seen": "2026-08-02",
            "sla": {"breached": False, "days_remaining": 20, "due_date": "2026-08-20"},
            "remediation_policy": {"next_window": {"date": "2026-09-01"}, "requires_approval_group": None}}


class ApiWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.content = {"v": GOOD}
        self.patches = [
            patch.object(db_module, "get_engine", return_value=self.engine),
            patch.object(dashboard_data, "load_live_queue", side_effect=lambda: [_finding()]),
            patch.object(dashboard_data, "load_remediation_findings", side_effect=lambda: [_finding()]),
            patch.object(dashboard_data, "load_playbooks", side_effect=lambda: [{
                "filename": "FIND-9-x.yml", "finding_id": "FIND-9", "needs_approval": True,
                "content": self.content["v"], "line_count": 1, "rollback_plan": "r"}]),
            patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
        ]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", "test-password-123", "Admin", role="admin", engine=self.engine)
        auth_users.create_user("second@t.local", "test-password-123", "Second", role="admin", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email="admin@t.local"):
        r = self.client.post("/api/auth/login", json={"email": email, "password": "test-password-123"})
        self.assertEqual(r.status_code, 200)

    def request_approval(self):
        return self.client.post("/api/remediation-approvals", json={"finding_id": "FIND-9", "requested_by": "admin@t.local"}).json()

    def test_playbook_detail_includes_its_lint_result(self):
        r = self.client.get("/api/playbooks/FIND-9-x.yml").json()
        self.assertTrue(r["lint"]["passed"])

    def test_approvals_list_carries_lint_and_verification(self):
        self.login()
        self.request_approval()
        a = self.client.get("/api/remediation-approvals").json()["approvals"][0]
        self.assertTrue(a["playbook_lint"]["passed"])
        self.assertEqual(a["verification"]["state"], "not-triggered")

    def test_a_playbook_that_fails_lint_cannot_be_approved(self):
        self.login()
        approval = self.request_approval()
        self.content["v"] = BAD
        self.login("second@t.local")        # a different administrator must approve
        r = self.client.post(f"/api/remediation-approvals/{approval['id']}/approve", json={"decided_by": "admin@t.local"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("PB003", r.json()["detail"])
        self.content["v"] = GOOD
        ok = self.client.post(f"/api/remediation-approvals/{approval['id']}/approve", json={"decided_by": "admin@t.local"})
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_verification_endpoint_and_evidence_pack(self):
        self.login()
        approval = self.request_approval()
        v = self.client.get("/api/remediation-verification").json()
        self.assertEqual(v["summary"]["not-triggered"], 1)
        pack = self.client.get(f"/api/remediation-approvals/{approval['id']}/evidence").json()
        self.assertEqual(pack["finding"]["id"], "FIND-9")
        self.assertTrue(pack["playbook"]["lint"]["passed"])
        self.assertEqual(self.client.get("/api/remediation-approvals/NOPE/evidence").status_code, 404)

    def test_evidence_requires_admin(self):
        self.assertEqual(self.client.get("/api/remediation-approvals/X/evidence").status_code, 401)


class DatabaseUrl(unittest.TestCase):
    def test_defaults_to_the_local_sqlite_file_and_honours_the_override(self):
        import os
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("QUANTA_DATABASE_URL", None)
            self.assertTrue(db_module.database_url().startswith("sqlite:///"))
        with patch.dict(os.environ, {"QUANTA_DATABASE_URL": "postgresql+psycopg2://u:p@h/quanta"}):
            self.assertEqual(db_module.database_url(), "postgresql+psycopg2://u:p@h/quanta")
