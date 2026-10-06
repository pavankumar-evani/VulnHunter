"""
Tests for module licensing: the signed licence, its states, the modes, the route-to-module map (every API route must have an entry), the 403 in enforce mode, and the focused-module sidebar.
Keys are generated per test run; no network.
"""
import datetime
import re
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
import quanta_license  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation import capabilities  # noqa: E402
from remediation.licensing import license as lic  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)
PRIV, PUB = lic.generate_keypair()


def token(modules=("soc", "infra"), expires="2027-06-30", **kw):
    return lic.issue(PRIV, kw.pop("customer", "Acme Ltd"), modules, expires, **kw)


def env(tok=None, mode="enforce", key=PUB, tmp=None):
    e = {"QUANTA_LICENSE_MODE": mode}
    if tok is not None:
        e["QUANTA_LICENSE"] = tok
    if key is not None:
        kf = Path(tmp) / "pub.pem"
        kf.write_bytes(key)
        e["QUANTA_LICENSE_PUBLIC_KEY_FILE"] = str(kf)
    return e


class SigningTests(unittest.TestCase):
    def test_a_licence_verifies_and_carries_its_claims(self):
        c = lic.verify(token(), PUB)
        self.assertEqual((c["customer"], c["modules"], c["expires"], c["v"]), ("Acme Ltd", ["infra", "soc"], "2027-06-30", 1))

    def test_any_alteration_or_another_key_is_refused(self):
        tok = token()
        body, sig = tok.split(".")
        forged = lic._b64(lic._unb64(body).replace(b'"infra"', b'"grc"')) + "." + sig
        for bad in (forged, tok[:-3] + ("AAA" if not tok.endswith("AAA") else "BBB"), "nonsense", "", "a.b.c"):
            with self.assertRaises(lic.LicenseError, msg=bad[:20]):
                lic.verify(bad, PUB)
        _, other_pub = lic.generate_keypair()
        with self.assertRaises(lic.LicenseError):
            lic.verify(tok, other_pub)

    def test_issue_validates_its_inputs(self):
        for kw in ({"modules": []}, {"modules": ["nope"]}, {"modules": ["admin"]}, {"customer": " "}, {"expires": "next year"}):
            args = {"customer": "A", "modules": ["soc"], "expires": "2027-01-01", **kw}
            with self.assertRaises((lic.LicenseError, ValueError)):
                lic.issue(PRIV, args["customer"], args["modules"], args["expires"])


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def st(self, tok=None, mode="enforce", key=PUB, today=TODAY):
        return lic.status(today, env(tok, mode, key, self.tmp.name))

    def test_off_is_the_default_and_everything_is_available(self):
        s = lic.status(TODAY, {})
        self.assertEqual((s["mode"], s["enforced"], s["state"]), ("off", False, "unrestricted"))
        self.assertTrue(set(lic.MODULE_IDS) <= set(s["modules"]))
        self.assertEqual(lic.mode({"QUANTA_LICENSE_MODE": "bogus"}), "off")

    def test_valid_expiring_grace_and_expired(self):
        self.assertEqual(self.st(token(expires="2027-06-30"))["state"], "valid")
        near = self.st(token(expires="2026-11-01"))
        self.assertEqual((near["state"], near["days_left"]), ("expiring", 17))
        grace = self.st(token(expires="2026-10-10"))
        self.assertEqual(grace["state"], "grace")
        self.assertIn("soc", grace["modules"])  # still working during the grace period
        gone = self.st(token(expires="2026-09-01"))
        self.assertEqual(gone["state"], "expired")
        self.assertEqual(gone["modules"], ["admin"])
        custom = self.st(token(expires="2026-10-01", grace_days=30))
        self.assertEqual(custom["state"], "grace")  # a licence can carry its own grace period

    def test_missing_unreadable_or_unverifiable_entitles_only_the_core(self):
        self.assertEqual((self.st(None)["state"], self.st(None)["modules"]), ("missing", ["admin"]))
        self.assertEqual(self.st(token(), key=None)["state"], "invalid")  # no verification key
        _, other = lic.generate_keypair()
        bad = self.st(token(), key=other)
        self.assertEqual((bad["state"], bad["modules"]), ("invalid", ["admin"]))
        self.assertIn("signature", bad["message"])
        e = env(None, "enforce", PUB, self.tmp.name)
        e["QUANTA_LICENSE_FILE"] = str(Path(self.tmp.name) / "absent.licence")
        self.assertEqual(lic.status(TODAY, e)["state"], "invalid")

    def test_the_licence_can_come_from_a_file(self):
        f = Path(self.tmp.name) / "l.licence"
        f.write_text(token(["ai"]) + "\n")
        e = env(None, "enforce", PUB, self.tmp.name)
        e["QUANTA_LICENSE_FILE"] = str(f)
        s = lic.status(TODAY, e)
        self.assertEqual((s["state"], s["modules"]), ("valid", ["admin", "ai"]))

    def test_warn_reports_but_never_enforces(self):
        s = self.st(token(["soc"]), mode="warn")
        self.assertEqual((s["mode"], s["enforced"], s["state"]), ("warn", False, "valid"))
        self.assertIn("Warn mode", self.st(None, mode="warn")["message"])
        self.assertTrue(lic.check("/api/ai-usage/summary", s)[0])


class RouteMapTests(unittest.TestCase):
    def test_every_api_route_belongs_to_core_or_a_module(self):
        missing = set()
        for r in fastapi_app.routes:
            p = getattr(r, "path", "")
            if p.startswith("/api/"):
                base = p.split("{")[0].rstrip("/")
                if lic.module_for_path(base)[0] is None:
                    missing.add("/".join(p.split("/")[:3]))
        self.assertEqual(sorted(missing), [], "add these to remediation/config/licensing.yaml (core, a module, or shared)")

    def test_the_longest_prefix_wins_and_shared_prefixes_need_any_one_module(self):
        self.assertEqual(lic.module_for_path("/api/ingest/alerts"), ("module", ["soc"]))
        self.assertEqual(lic.module_for_path("/api/ingest/findings"), ("core", None))
        self.assertEqual(lic.module_for_path("/api/ingest/sbom"), ("module", ["devsecops"]))
        self.assertEqual(lic.module_for_path("/api/splunk/fetch"), ("module", ["soc", "remediation"]))
        self.assertEqual(lic.module_for_path("/api/soc/cases/3"), ("module", ["soc"]))
        self.assertEqual(lic.module_for_path("/api/socket-not-ours"), (None, None))  # a prefix match needs a path boundary
        st = {"enforced": True, "modules": ["remediation", "admin"]}
        self.assertTrue(lic.check("/api/splunk/fetch", st)[0])
        self.assertFalse(lic.check("/api/soc/cases", st)[0])
        self.assertTrue(lic.check("/api/queue", {"enforced": True, "modules": ["admin"]})[0])  # core is never blocked

    def test_the_same_module_ids_everywhere(self):
        cfg_mods = set(lic.config()["modules"])
        self.assertEqual(cfg_mods, set(lic.MODULE_IDS))
        self.assertEqual([m for m in lic.MODULE_IDS], [d["id"] for d in capabilities.catalog()])
        nav = (REPO_ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")
        nav_ids = re.findall(r'\{ group: "[^"]+", id: "([a-z]+)", number:', nav)
        self.assertEqual(nav_ids, list(lic.MODULE_IDS))
        for bundle in lic.config()["editions"].values():
            self.assertTrue(set(bundle) <= set(lic.MODULE_IDS))


class EnforcementApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[])]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def with_env(self, tok, mode="enforce"):
        return patch.dict("os.environ", env(tok, mode, PUB, self.tmp.name), clear=False)

    def test_with_the_mode_off_nothing_changes(self):
        r = self.client.get("/api/license").json()
        self.assertEqual((r["state"], r["enforced"]), ("unrestricted", False))
        self.assertEqual(self.client.get("/api/api-security/overview").status_code, 200)

    def test_enforce_blocks_an_unlicensed_module_and_leaves_core_and_licensed_ones_alone(self):
        with self.with_env(token(["appsec"])):
            self.assertEqual(self.client.get("/api/api-security/overview").status_code, 200)
            r = self.client.get("/api/soc/cases")
            self.assertEqual(r.status_code, 403)
            self.assertEqual((r.json()["modules"], r.json()["license_state"]), (["soc"], "valid"))
            self.assertEqual(self.client.get("/api/hunting/hunts").status_code, 403)
            self.assertEqual(self.client.get("/api/queue").status_code, 200)  # the findings store is core
            self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
            lic_info = self.client.get("/api/license").json()
            self.assertEqual([m["id"] for m in lic_info["all_modules"] if m["licensed"]], ["appsec", "admin"])

    def test_machine_ingest_routes_follow_their_module(self):
        with self.with_env(token(["appsec"])):
            self.assertEqual(self.client.post("/api/ingest/alerts", json={}).status_code, 403)  # soc, refused before the key check
            self.assertNotEqual(self.client.post("/api/ingest/api-traffic", json={"records": []}).status_code, 403)  # appsec: reaches the key check (401)

    def test_no_licence_at_all_leaves_only_the_core(self):
        with self.with_env(None):
            self.assertEqual(self.client.get("/api/api-security/overview").status_code, 403)
            self.assertEqual(self.client.get("/api/queue").status_code, 200)
            self.assertEqual(self.client.get("/api/license").json()["state"], "missing")

    def test_warn_mode_blocks_nothing(self):
        with self.with_env(None, "warn"):
            self.assertEqual(self.client.get("/api/api-security/overview").status_code, 200)
            self.assertFalse(self.client.get("/api/license").json()["enforced"])

    def test_the_catalog_marks_unlicensed_modules(self):
        with self.with_env(token(["soc"])):
            d = self.client.get("/api/capabilities").json()
        self.assertEqual({a["id"]: a["licensed"] for a in d["areas"]}["soc"], True)
        self.assertEqual({a["id"]: a["licensed"] for a in d["areas"]}["appsec"], False)
        self.assertEqual(d["license"]["customer"], "Acme Ltd")

    def test_an_expired_licence_closes_the_modules(self):
        with self.with_env(token(["soc"], expires="2020-01-01")):
            self.assertEqual(self.client.get("/api/soc/cases").status_code, 403)
            self.assertEqual(self.client.get("/api/license").json()["state"], "expired")


class CliTests(unittest.TestCase):
    def test_keygen_issue_and_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            quanta_license.main(["keygen", "--out-dir", d])
            out = Path(d) / "a.licence"
            quanta_license.main(["issue", "--private-key", str(Path(d) / "vendor_private.pem"), "--customer", "Acme", "--edition", "secops", "--expires", "2030-01-01", "--out", str(out)])
            c = lic.verify(out.read_text().strip(), (Path(d) / "vendor_public.pem").read_bytes())
            self.assertEqual((c["customer"], c["edition"], c["modules"]), ("Acme", "secops", ["infra", "remediation", "soc"]))
            quanta_license.main(["verify", "--public-key", str(Path(d) / "vendor_public.pem"), "--license", str(out)])
            with self.assertRaises(SystemExit):
                quanta_license.main(["issue", "--private-key", str(Path(d) / "vendor_private.pem"), "--customer", "Acme", "--expires", "2030-01-01"])  # no modules and no edition
            _, other = lic.generate_keypair()
            (Path(d) / "other.pem").write_bytes(other)
            with self.assertRaises(SystemExit):
                quanta_license.main(["verify", "--public-key", str(Path(d) / "other.pem"), "--license", str(out)])


class SidebarFocusTests(unittest.TestCase):
    """The sidebar shows one module at a time; these read the source because there is no browser in the suite."""

    def setUp(self):
        self.nav = (REPO_ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")

    def test_it_lists_other_modules_only_in_the_picker_or_behind_switch_module(self):
        self.assertIn("Switch module", self.nav)
        self.assertIn("quanta.module", self.nav)
        self.assertIn("isLicensed", self.nav)
        self.assertIn("not licensed", self.nav)

    def test_the_router_gates_an_unlicensed_module_page(self):
        app_js = (REPO_ROOT / "dashboard" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("setLicense", app_js)
        self.assertIn("is not part of your licence", app_js)


if __name__ == "__main__":
    unittest.main()
