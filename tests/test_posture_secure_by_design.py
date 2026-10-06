"""Tests for the Secure by Design posture framework: empty data, deployment settings, seeded good and bad cases, no secrets, determinism."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from sqlalchemy import create_engine  # noqa: E402

from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.exceptions import store as exceptions  # noqa: E402
from remediation.grc import risks  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.posture import secure_by_design as sbd  # noqa: E402
from remediation.posture.model import Context  # noqa: E402
from remediation.support import store as support  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from auth import users  # noqa: E402

SECRET = "SUPER-SECRET-VALUE-123"
ACTOR = "pat.owner@corp.test"
NOW = datetime.datetime.now(datetime.timezone.utc)
GOOD_ENV = {"QUANTA_PRODUCTION": "true", "QUANTA_SESSION_SECRET": SECRET + "x" * 20, "QUANTA_ENCRYPTION_KEY": SECRET + "-KEY",
            "OIDC_ISSUER": "https://idp.corp.test", "OIDC_CLIENT_ID": "quanta", "OIDC_CLIENT_SECRET": SECRET + "-OIDC", "OIDC_REDIRECT_URI": "https://q.corp.test/cb",
            "QUANTA_DATABASE_URL": "postgresql+psycopg2://quanta:" + SECRET + "@db.corp.test/quanta", "QUANTA_LICENSE_MODE": "warn"}
DATA_DRIVEN = ("sbd-own-support-sla", "sbd-own-exceptions", "sbd-lead-risk-register", "sbd-lead-policy-acks", "sbd-hard-demo-accounts",
               "sbd-hard-api-keys", "sbd-hard-admin-count", "sbd-hard-audit-activity", "sbd-trans-own-sbom", "sbd-trans-own-dependencies")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'p.db'}")
        db_module.ensure_schema(self.engine)
        self.lock = Path(self.tmp.name) / "l.lock"

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def ctx(self, env=None, now=NOW):
        c = Context(engine=self.engine, findings=[], env=env if env is not None else {}, now=now)
        c.thr = posture_engine.policy()["thresholds"]
        return c

    def checks(self, env=None, now=NOW):
        return {c["id"]: c for c in sbd.run(self.ctx(env, now))}

    def mkuser(self, email, pw, role="user"):
        users.create_user(email, pw, email, role=role, engine=self.engine, lock_path=self.lock)


class EmptyDataTests(Base):
    def test_data_driven_checks_are_not_scored(self):
        c = self.checks({})
        for cid in DATA_DRIVEN:
            self.assertIn(c[cid]["status"], ("unknown", "na"), cid)
        self.assertEqual(c["sbd-hard-webhook-secret"]["status"], "na")

    def test_bare_env_fails_with_setting_named(self):
        c = self.checks({})
        for cid, key in (("sbd-hard-production", "QUANTA_PRODUCTION"), ("sbd-hard-session-secret", "QUANTA_SESSION_SECRET"),
                         ("sbd-hard-encryption-key", "QUANTA_ENCRYPTION_KEY"), ("sbd-hard-login-for-reads", "QUANTA_REQUIRE_LOGIN_FOR_READS"),
                         ("sbd-hard-oidc", "OIDC_ISSUER"), ("sbd-hard-csp", "QUANTA_ENABLE_CSP")):
            self.assertEqual(c[cid]["status"], "fail", cid)
            self.assertEqual(c[cid]["change"]["key"], key)

    def test_production_env_passes(self):
        c = self.checks(GOOD_ENV)
        for cid in ("sbd-hard-production", "sbd-hard-session-secret", "sbd-hard-encryption-key", "sbd-hard-tls", "sbd-hard-csp", "sbd-hard-login-for-reads",
                    "sbd-hard-oidc", "sbd-hard-database", "sbd-hard-licence-mode", "sbd-hard-rate-limits", "sbd-hard-admin-password-env"):
            self.assertEqual(c[cid]["status"], "pass", cid)

    def test_short_secret_and_leftover_password_fail(self):
        c = self.checks({"QUANTA_SESSION_SECRET": "short", "QUANTA_ADMIN_PASSWORD": SECRET, "QUANTA_DISABLE_TLS": "true", "QUANTA_RATE_LIMIT_MAX": "0"})
        self.assertEqual(c["sbd-hard-session-secret"]["status"], "fail")
        self.assertIn("5 characters", c["sbd-hard-session-secret"]["evidence"][0])
        self.assertEqual(c["sbd-hard-admin-password-env"]["status"], "fail")
        self.assertEqual(c["sbd-hard-tls"]["status"], "fail")
        self.assertEqual(c["sbd-hard-rate-limits"]["status"], "fail")


class SeededTests(Base):
    def test_demo_accounts_and_admins(self):
        self.mkuser("admin@quanta.local", sbd.DEMO_PASSWORD, "admin")
        c = self.checks()
        self.assertEqual(c["sbd-hard-demo-accounts"]["status"], "fail")
        self.assertEqual(c["sbd-hard-admin-count"]["status"], "partial")
        self.mkuser("sam.admin@corp.test", "A-Strong-Password-9", "admin")
        users.set_password("admin@quanta.local", "Another-Strong-One-7", engine=self.engine, lock_path=self.lock)
        c = self.checks()
        self.assertEqual(c["sbd-hard-demo-accounts"]["status"], "pass")
        self.assertEqual(c["sbd-hard-admin-count"]["status"], "pass")

    def test_api_keys(self):
        apikeys.create("CI no expiry", ["ingest:write"], ACTOR, engine=self.engine, now=NOW)
        self.assertEqual(self.checks()["sbd-hard-api-keys"]["status"], "fail")
        self.engine.dispose()
        for k in apikeys.list_keys(self.engine):
            apikeys.revoke(k["id"], ACTOR, engine=self.engine, now=NOW)
        apikeys.create("CI expiring", ["ingest:write"], ACTOR, expires_days=30, engine=self.engine, now=NOW)
        c = self.checks()["sbd-hard-api-keys"]
        self.assertEqual(c["status"], "pass")
        self.assertIn("1 of 1", c["evidence"][0])

    def test_exceptions(self):
        exceptions.create_exception("FIND-1", "old waiver", ACTOR, "lee.approver@corp.test", "2025-06-01", engine=self.engine,
                                    as_of=datetime.date(2025, 1, 1), lock_path=self.lock)
        self.assertEqual(self.checks()["sbd-own-exceptions"]["status"], "fail")
        exceptions.create_exception("FIND-2", "current", ACTOR, "lee.approver@corp.test", "2099-06-01", engine=self.engine, lock_path=self.lock)
        exceptions.create_exception("FIND-3", "current", ACTOR, "lee.approver@corp.test", "2099-06-01", engine=self.engine, lock_path=self.lock)
        exceptions.create_exception("FIND-4", "current", ACTOR, "lee.approver@corp.test", "2099-06-01", engine=self.engine, lock_path=self.lock)
        c = self.checks()["sbd-own-exceptions"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.75)
        self.assertIn("1 exceptions have expired", c["evidence"][1])

    def test_risk_register(self):
        risks.create({"title": "Unowned risk", "inherent_likelihood": 3, "inherent_impact": 3}, ACTOR, engine=self.engine)
        self.assertEqual(self.checks()["sbd-lead-risk-register"]["status"], "fail")
        risks.create({"title": "Owned risk", "inherent_likelihood": 3, "inherent_impact": 3, "owner": ACTOR, "review_date": "2099-01-01"}, ACTOR, engine=self.engine)
        c = self.checks()["sbd-lead-risk-register"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)

    def test_audit_activity(self):
        activity_log.record_activity(ACTOR, "x.old", engine=self.engine, as_of=NOW - datetime.timedelta(days=400))
        self.assertEqual(self.checks()["sbd-hard-audit-activity"]["status"], "fail")
        activity_log.record_activity(ACTOR, "x.new", engine=self.engine, as_of=NOW)
        self.assertEqual(self.checks()["sbd-hard-audit-activity"]["status"], "pass")

    def test_support_sla(self):
        t = support.create_ticket(ACTOR, "question", "How do I", "Please explain", engine=self.engine, now=NOW)
        support.update_ticket(t["id"], ACTOR, status="resolved", resolution="done", engine=self.engine, now=NOW)
        c = self.checks()["sbd-own-support-sla"]
        self.assertIn(c["status"], ("pass", "unknown"))
        t = support.create_ticket(ACTOR, "question", "Late one", "Slow", engine=self.engine, now=NOW - datetime.timedelta(days=60))
        support.update_ticket(t["id"], ACTOR, status="resolved", resolution="late", engine=self.engine, now=NOW)
        c2 = self.checks()["sbd-own-support-sla"]
        self.assertNotEqual(c2["status"], "unknown")
        self.assertRegex(c2["evidence"][0], r"\d")


class ShapeTests(Base):
    def test_shape_unique_deterministic_no_secrets(self):
        self.mkuser("admin@quanta.local", sbd.DEMO_PASSWORD, "admin")
        env = {**GOOD_ENV, "QUANTA_ADMIN_PASSWORD": SECRET, "QUANTA_GIT_WEBHOOK_SECRET": SECRET}
        a, b = sbd.run(self.ctx(env)), sbd.run(self.ctx(env))
        self.assertEqual(a, b)
        ids = [c["id"] for c in a]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 27)
        areas = {x[0] for x in sbd.FRAMEWORK["areas"]}
        for c in a:
            self.assertTrue({"id", "framework", "area", "title", "status", "score", "weight", "evidence", "recommendation", "change", "refs", "data_used"} <= set(c))
            self.assertIn(c["area"], areas)
            self.assertEqual(c["framework"], "secure-by-design")
            self.assertTrue(c["evidence"], c["id"])
            if c["id"] in DATA_DRIVEN[:8] and c["status"] != "unknown":
                self.assertRegex(" ".join(c["evidence"]), r"\d", c["id"])
        self.assertNotIn(SECRET, json.dumps(a))

    def test_changes_name_real_settings(self):
        nav = (ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        for c in sbd.run(self.ctx({})):
            ch = c["change"]
            if not ch:
                continue
            if ch["kind"] == "page":
                self.assertIn(f'"{ch["where"]}"', nav, c["id"])
            elif ch["kind"] in ("env", "yaml"):
                self.assertIn(ch["key"], (ROOT / ch["where"]).read_text(encoding="utf-8"), c["id"])


if __name__ == "__main__":
    unittest.main()
