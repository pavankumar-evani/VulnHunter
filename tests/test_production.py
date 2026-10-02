"""
Tests for production readiness: schema migrations, the admin CLI (init, create-admin, check,
backup, restore, key rotation), health/readiness/metrics endpoints, request IDs, the
production-safe read default and the demo-account guard.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import observability  # noqa: E402
import quanta_admin  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.connections import crypto, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from remediation.utils import migrations  # noqa: E402


class MigrationTests(unittest.TestCase):
    def test_pending_then_applied_once_and_recorded(self):
        e = create_engine("sqlite:///:memory:")
        self.assertEqual([v for v, _ in migrations.pending(e)], [1, 2, 3, 4])
        with e.begin() as c:  # an old support_tickets table without the ITSM columns
            c.execute(text("CREATE TABLE support_tickets (id INTEGER PRIMARY KEY, kind VARCHAR NOT NULL, severity VARCHAR NOT NULL, subject VARCHAR NOT NULL, "
                           "description TEXT NOT NULL, status VARCHAR NOT NULL, requester_email VARCHAR NOT NULL, assignee_email VARCHAR, resolution TEXT, "
                           "created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL, resolved_at VARCHAR)"))
        ran = migrations.apply(e)
        self.assertEqual([v for v, _ in ran], [1, 2, 3, 4])
        cols = {r[1] for r in e.connect().execute(text("PRAGMA table_info(support_tickets)"))}
        self.assertTrue({"team", "priority", "csat_score"} <= cols)
        self.assertEqual(migrations.apply(e), [])
        self.assertEqual(migrations.pending(e), [])
        e.dispose()


class AdminCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.patches = [
            patch.object(db_module, "DEFAULT_DB_PATH", self.tmp / "q.db"),
            patch.object(db_module, "_default_engine", None),
            patch.object(quanta_admin, "FINDINGS", self.tmp / "nf.json"),
            patch.object(quanta_admin, "CONFIG_DIR", self.tmp / "cfg"),
            patch.object(quanta_admin, "PLAN_FILE", self.tmp / "PLAN.md"),
            patch.object(quanta_admin, "SAMPLE_BACKUP", self.tmp / ".sample-backup"),
            patch.dict(os.environ, {"QUANTA_DATABASE_URL": "", "QUANTA_ADMIN_PASSWORD": "a-strong-passphrase-1", "QUANTA_SESSION_SECRET": "s" * 32}),
        ]
        (self.tmp / "cfg").mkdir()
        (self.tmp / "cfg" / "priority_rules.yaml").write_text("a: 1\n")
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        db_module._default_engine = None

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = quanta_admin.main(list(argv))
        return code, buf.getvalue()

    def test_gen_key_produces_a_usable_key(self):
        _, out = self.run_cli("gen-key")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": out.strip()}):
            self.assertTrue(crypto.available())

    def test_init_creates_no_demo_accounts_and_create_admin_works(self):
        self.run_cli("init")
        self.assertEqual(auth_users.list_users(), [])
        self.run_cli("create-admin", "--email", "boss@corp.test", "--name", "Boss")
        (u,) = auth_users.list_users()
        self.assertEqual((u["email"], u["role"]), ("boss@corp.test", "admin"))
        self.assertIsNotNone(auth_users.verify_login("boss@corp.test", "a-strong-passphrase-1"))
        _, out = self.run_cli("list-users")
        self.assertIn("boss@corp.test", out)

    def test_bootstrap_creates_the_first_admin_once_and_only_when_configured(self):
        _, out = self.run_cli("bootstrap")
        self.assertIn("No administrator yet", out)
        self.assertEqual(auth_users.list_users(), [])
        with patch.dict(os.environ, {"QUANTA_BOOTSTRAP_ADMIN_EMAIL": "first@corp.test"}):
            self.run_cli("bootstrap")
            self.assertEqual([u["email"] for u in auth_users.list_users()], ["first@corp.test"])
            _, out = self.run_cli("bootstrap")
        self.assertIn("already exists", out)
        self.assertEqual(len(auth_users.list_users()), 1)

    def test_clear_sample_data_only_touches_the_bundled_sample(self):
        real = [{"id": "FIND-1", "source": "tenable", "source_ref": "999", "asset": {"name": "prod-1"}}]
        (self.tmp / "nf.json").write_text(json.dumps(real))
        _, out = self.run_cli("clear-sample-data", "--yes")
        self.assertIn("nothing to clear", out)
        self.assertEqual(json.loads((self.tmp / "nf.json").read_text()), real)
        sample = [{"id": "FIND-1", "source": "tenable", "source_ref": "57608", "asset": {"name": "WIN-DC01"}}]
        (self.tmp / "nf.json").write_text(json.dumps(sample))
        self.assertTrue(quanta_admin.is_sample_dataset(self.tmp / "nf.json"))
        with self.assertRaises(SystemExit):
            self.run_cli("clear-sample-data")
        self.run_cli("clear-sample-data", "--yes")
        self.assertEqual(json.loads((self.tmp / "nf.json").read_text()), [])
        self.assertTrue((self.tmp / ".sample-backup" / "nf.json").exists())

    def test_check_fails_in_production_while_sample_data_is_still_loaded(self):
        self.run_cli("init")
        self.run_cli("create-admin", "--email", "boss@corp.test")
        (self.tmp / "nf.json").write_text(json.dumps([{"id": "FIND-1", "source_ref": "57608", "asset": {"name": "WIN-DC01"}}]))
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}):
            code, out = self.run_cli("check")
        self.assertEqual(code, 1)
        self.assertIn("bundled SAMPLE data", out)

    def test_reset_password(self):
        self.run_cli("init")
        self.run_cli("create-admin", "--email", "boss@corp.test")
        with patch.dict(os.environ, {"QUANTA_ADMIN_PASSWORD": "another-passphrase-2"}):
            self.run_cli("reset-password", "--email", "boss@corp.test")
        self.assertIsNone(auth_users.verify_login("boss@corp.test", "a-strong-passphrase-1"))
        self.assertIsNotNone(auth_users.verify_login("boss@corp.test", "another-passphrase-2"))

    def test_check_flags_demo_accounts_and_missing_admin(self):
        self.run_cli("init")
        code, out = self.run_cli("check")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] administrators", out)
        self.run_cli("create-admin", "--email", "boss@corp.test")
        auth_users.create_user("admin@quanta.local", quanta_admin.DEMO_PASSWORD, "Demo", role="admin")
        code, out = self.run_cli("check")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] demo accounts", out)

    def test_check_passes_on_a_clean_production_setup(self):
        self.run_cli("init")
        self.run_cli("create-admin", "--email", "boss@corp.test")
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}):
            code, out = self.run_cli("check")
        self.assertEqual(code, 0, out)
        self.assertIn("[PASS] demo accounts", out)

    def test_check_fails_without_a_session_secret(self):
        self.run_cli("init")
        self.run_cli("create-admin", "--email", "boss@corp.test")
        with patch.dict(os.environ, {"QUANTA_SESSION_SECRET": ""}):
            code, out = self.run_cli("check")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] session secret", out)

    def test_backup_and_restore_round_trip(self):
        self.run_cli("init")
        self.run_cli("create-admin", "--email", "boss@corp.test")
        (self.tmp / "nf.json").write_text(json.dumps([{"id": "FIND-1"}]))
        self.run_cli("backup", "--out", str(self.tmp / "b"))
        (zip_path,) = list((self.tmp / "b").glob("quanta-backup-*.zip"))
        with zipfile.ZipFile(zip_path) as z:
            self.assertTrue({"database/quanta.db", "data/normalized-findings.json", "config/priority_rules.yaml", "manifest.json"} <= set(z.namelist()))
        # lose everything, then restore
        db_module._default_engine.dispose()
        db_module._default_engine = None
        (self.tmp / "q.db").unlink()
        (self.tmp / "nf.json").unlink()
        with self.assertRaises(SystemExit):
            self.run_cli("restore", "--from", str(zip_path))  # refuses without --yes
        self.run_cli("restore", "--from", str(zip_path), "--yes")
        self.assertEqual(json.loads((self.tmp / "nf.json").read_text()), [{"id": "FIND-1"}])
        self.assertEqual([u["email"] for u in auth_users.list_users()], ["boss@corp.test"])

    def test_rotate_keys_reencrypts_stored_credentials(self):
        old, new = crypto.generate_key(), crypto.generate_key()
        self.run_cli("init")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": old}):
            c = store.create("T", "tenable", {"access_key": "AK", "secret_key": "SK"}, "a")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": f"{new},{old}"}):
            self.run_cli("rotate-keys")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": new}):
            self.assertEqual(store.get_values(c["id"])[1]["secret_key"], "SK")

    def test_backup_never_contains_the_encryption_key_or_plain_secrets(self):
        key = crypto.generate_key()
        self.run_cli("init")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": key}):
            store.create("T", "tenable", {"access_key": "AK-PLAINTEXT", "secret_key": "SK-PLAINTEXT"}, "a")
            self.run_cli("backup", "--out", str(self.tmp / "b"))
        (zip_path,) = list((self.tmp / "b").glob("*.zip"))
        with zipfile.ZipFile(zip_path) as z:
            blob = b"".join(z.read(n) for n in z.namelist())
        self.assertNotIn(b"SK-PLAINTEXT", blob)
        self.assertNotIn(key.encode(), blob)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine),
                        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for p in self.patches:
            p.start()
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def test_healthz_and_readyz_need_no_login_even_in_production(self):
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true", "QUANTA_SESSION_SECRET": "s" * 32}):
            self.assertEqual(self.client.get("/healthz").json(), {"status": "ok"})
            r = self.client.get("/readyz")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["checks"]["database"], "ok")

    def test_readyz_reports_a_broken_database_as_503(self):
        with patch.object(db_module, "get_engine", side_effect=RuntimeError("down")):
            r = self.client.get("/readyz")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["status"], "not-ready")

    def test_production_closes_anonymous_reads_by_default(self):
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true", "QUANTA_SESSION_SECRET": "s" * 32}, clear=False):
            self.assertEqual(self.client.get("/api/queue").status_code, 401)
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true", "QUANTA_ALLOW_PUBLIC_READS": "true", "QUANTA_SESSION_SECRET": "s" * 32}):
            self.assertEqual(self.client.get("/api/queue").status_code, 200)

    def test_non_production_keeps_the_documented_open_read_default(self):
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "", "QUANTA_REQUIRE_LOGIN_FOR_READS": ""}):
            self.assertEqual(self.client.get("/api/queue").status_code, 200)

    def test_metrics_are_off_without_a_token_and_guarded_with_one(self):
        with patch.dict(os.environ, {"QUANTA_METRICS_TOKEN": ""}):
            self.assertEqual(self.client.get("/metrics").status_code, 404)
        with patch.dict(os.environ, {"QUANTA_METRICS_TOKEN": "tok-123"}):
            self.assertEqual(self.client.get("/metrics").status_code, 401)
            self.assertEqual(self.client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code, 401)
            r = self.client.get("/metrics", headers={"Authorization": "Bearer tok-123"})
            self.assertEqual(r.status_code, 200)
            self.assertIn("quanta_findings_total", r.text)
            self.assertIn("quanta_connections_failing", r.text)
            self.assertNotIn("password", r.text.lower())

    def test_every_response_carries_a_request_id_and_a_safe_client_one_is_kept(self):
        r = self.client.get("/healthz")
        self.assertTrue(r.headers["X-Request-ID"])
        r = self.client.get("/healthz", headers={"X-Request-ID": "abc12345-trace"})
        self.assertEqual(r.headers["X-Request-ID"], "abc12345-trace")
        r = self.client.get("/healthz", headers={"X-Request-ID": "bad id\r\nX-Evil: 1"})
        self.assertNotIn("Evil", r.headers["X-Request-ID"])

    def test_json_log_formatter_emits_parseable_structured_lines(self):
        import logging
        rec = logging.LogRecord("quanta.access", logging.INFO, "f", 1, "GET %s %s", ("/x", 200), None)
        rec.request_id, rec.status = "rid1", 200
        d = json.loads(observability.JsonFormatter().format(rec))
        self.assertEqual((d["message"], d["request_id"], d["status"], d["level"]), ("GET /x 200", "rid1", 200, "INFO"))


class DemoGuardTests(unittest.TestCase):
    def test_production_refuses_to_start_with_a_published_demo_password(self):
        engine = create_engine("sqlite:///:memory:")
        with patch.object(db_module, "get_engine", return_value=engine):
            auth_users.create_user("admin@quanta.local", dashboard_app_module.DEMO_PASSWORD, "Demo", role="admin", engine=engine)
            with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}):
                with self.assertRaises(RuntimeError) as cm:
                    dashboard_app_module.assert_no_demo_accounts()
                self.assertIn("admin@quanta.local", str(cm.exception))
            with patch.dict(os.environ, {"QUANTA_PRODUCTION": ""}):
                dashboard_app_module.assert_no_demo_accounts()  # fine outside production
        engine.dispose()

    def test_a_changed_password_passes(self):
        engine = create_engine("sqlite:///:memory:")
        with patch.object(db_module, "get_engine", return_value=engine):
            auth_users.create_user("admin@quanta.local", "a-real-passphrase-9", "Admin", role="admin", engine=engine)
            with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}):
                dashboard_app_module.assert_no_demo_accounts()
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
