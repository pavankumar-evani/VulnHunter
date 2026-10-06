"""Tests for the zero trust posture framework (remediation/posture/zero_trust.py)."""
import datetime
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, insert  # noqa: E402

from remediation.appsec import store as app_store  # noqa: E402
from remediation.controls import store as controls  # noqa: E402
from remediation.exceptions import store as ex_store  # noqa: E402
from remediation.firewall import store as fw_store  # noqa: E402
from remediation.grc import policies, risks  # noqa: E402
from remediation.hunting import store as hunting_store  # noqa: E402
from remediation.iam import store as iam_store  # noqa: E402
from remediation.inventory import asset_inventory  # noqa: E402
from remediation.posture import engine as posture_engine, model, zero_trust  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
ENTS_OK = "user,account,system,entitlement,privileged,last login,status\nana@corp.test,ana,erp.corp.test,viewer,no,2026-10-01,active\nbo@corp.test,bo,erp.corp.test,viewer,no,2026-10-02,active\n"
ENTS_STALE = "user,account,system,entitlement,privileged,last login,status\nana@corp.test,ana,erp.corp.test,viewer,no,2025-01-01,active\nbo@corp.test,bo,erp.corp.test,viewer,no,2025-01-02,active\n"
ROSTER_OK = "user,status\nana@corp.test,active\nbo@corp.test,active\n"
ROSTER_LEFT = "user,status,end_date\nana@corp.test,terminated,2026-08-01\nbo@corp.test,active,\n"
FW_GOOD = ("Name,Source Zone,Destination Zone,Source Address,Destination Address,Service,Action,Log,Hit Count,Last Hit,Created,Owner,Comment\n"
           "allow-web,untrust,dmz,any,10.1.1.10,tcp/443,allow,yes,500,2026-10-01,2026-09-01,pat.owner@corp.test,site\n")
FW_BAD = FW_GOOD + "allow-rdp-in,untrust,dmz,any,10.1.1.20,rdp,allow,no,0,,2024-01-01,,\nallow-all,any,any,any,any,any,allow,yes,9,2026-10-01,2024-01-01,,\n"
TOPOLOGY = {"assets": [{"match": {"name_prefix": "web-"}, "path_to_internet": [{"hop_type": "firewall", "name": "Edge-FW", "default_action": "allow"}]}]}


def finding(i, host, sev="High", typ="unix-server", os_=None, last_seen="2026-10-01", kev=None, status="open", first_seen="2026-09-01"):
    a = {"name": host, "type": typ}
    if os_:
        a["os"] = os_
    return {"id": f"FIND-{i}", "title": f"Issue {i}", "severity": sev, "status": status, "asset": a, "first_seen": first_seen, "last_seen": last_seen, "kev": kev}


def mkctx(engine, findings=(), env=None, now=NOW):
    ctx = model.Context(engine=engine, findings=list(findings), env=env if env is not None else {}, now=now)
    pol = posture_engine.policy()
    ctx.policy, ctx.thr = pol, pol["thresholds"]
    return ctx


def add_conn(engine, name, ctype="tenable", enabled=1, schedule=0, last_run="2026-10-05T00:00:00Z", status="ok"):
    with engine.begin() as conn:
        conn.execute(insert(db_module.connections), {"name": name, "type": ctype, "config": "{}", "secrets_blob": None, "enabled": enabled, "schedule_minutes": schedule,
                                                     "last_run_at": last_run, "last_status": status, "last_message": "", "last_count": 1, "created_by": ACTOR,
                                                     "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"})


def add_endpoint(engine, template, auth_state="declared", detected=None, in_spec=True):
    obs = {"detected": detected or {}}
    with engine.begin() as conn:
        conn.execute(insert(db_module.api_endpoints), {"service": "shop", "method": "GET", "path_key": template, "template": template, "in_spec": in_spec, "observed": bool(detected),
                                                       "spec_json": json.dumps({"auth_state": auth_state}) if in_spec else None, "observed_json": json.dumps(obs),
                                                       "status": "active", "calls_total": 1, "created_at": "2026-10-01", "updated_at": "2026-10-01"})


def add_user(engine, email, role):
    with engine.begin() as conn:
        conn.execute(insert(db_module.users), {"email": email, "name": email, "role": role, "team": None, "password_hash": "x"})


class ZeroTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.lock = str(Path(self.tmp.name) / "x.lock")
        p = patch("remediation.enrichment.network_reachability.load_topology", return_value={"assets": []})
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_zt(self, findings=(), env=None, now=NOW):
        return {c["id"]: c for c in zero_trust.run(mkctx(self.engine, findings, env, now))}

    # ---- (a)
    def test_empty_estate_never_passes(self):
        checks = self.run_zt()
        self.assertTrue(checks)
        self.assertFalse([c["id"] for c in checks.values() if c["status"] in ("pass", "partial")])
        # the only checks that may answer on an empty estate read settings, and an unset setting is an honest fail
        self.assertEqual({c["id"] for c in checks.values() if c["status"] not in ("unknown", "na")}, {"zt-id-sso"})

    # ---- (b) identity
    def test_leavers_pass_and_fail(self):
        iam_store.import_entitlements("idp", ENTS_OK, "csv", ACTOR, self.engine)
        self.assertEqual(self.run_zt()["zt-id-leavers"]["status"], "unknown")  # entitlements but no roster
        iam_store.import_roster(ROSTER_OK, self.engine)
        self.assertEqual(self.run_zt()["zt-id-leavers"]["status"], "pass")
        iam_store.import_roster(ROSTER_LEFT, self.engine)
        c = self.run_zt()["zt-id-leavers"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 2 entitlements", c["evidence"][0])
        self.assertIn("ana@corp.test", " ".join(c["evidence"]))

    def test_hygiene_pass_and_fail(self):
        iam_store.import_entitlements("idp", ENTS_OK, "csv", ACTOR, self.engine)
        iam_store.import_roster(ROSTER_OK, self.engine)
        self.assertEqual(self.run_zt()["zt-id-hygiene"]["status"], "pass")
        iam_store.import_entitlements("idp", ENTS_STALE, "csv", ACTOR, self.engine)
        self.assertEqual(self.run_zt()["zt-id-hygiene"]["status"], "fail")

    def test_sso_none_partial_full(self):
        self.assertEqual(self.run_zt()["zt-id-sso"]["status"], "fail")
        part = self.run_zt(env={"OIDC_ISSUER": "https://login.corp.test", "OIDC_CLIENT_ID": "x"})["zt-id-sso"]
        self.assertEqual(part["status"], "partial")
        self.assertEqual(part["score"], 0.5)
        env = {v: "VALUE-XYZ" for v in zero_trust.OIDC_VARS}
        c = self.run_zt(env=env)["zt-id-sso"]
        self.assertEqual(c["status"], "pass")
        self.assertNotIn("VALUE-XYZ", json.dumps(c))  # presence only, never the value

    def test_admin_share(self):
        for i in range(4):
            add_user(self.engine, f"user{i}@corp.test", "admin" if i == 0 else "user")
        self.assertEqual(self.run_zt()["zt-id-admins"]["status"], "pass")
        for i in range(4):
            add_user(self.engine, f"extra{i}@corp.test", "admin")
        self.assertEqual(self.run_zt()["zt-id-admins"]["status"], "fail")

    # ---- devices
    def test_owners_good_and_bad(self):
        fs = [finding(1, "app-01.corp.test"), finding(2, "app-02.corp.test")]
        self.assertEqual(self.run_zt(fs)["zt-dev-owners"]["status"], "fail")
        asset_inventory.set_owner("app-01.corp.test", ACTOR, "platform", engine=self.engine, lock_path=self.lock)
        asset_inventory.set_owner("app-02.corp.test", ACTOR, "platform", engine=self.engine, lock_path=self.lock)
        self.assertEqual(self.run_zt(fs)["zt-dev-owners"]["status"], "pass")

    def test_edr_verified_vs_claimed(self):
        fs = [finding(1, "srv-01.corp.test"), finding(2, "srv-02.corp.test")]
        controls.upsert("srv-*", "edr", "EDR agent", "claimed", "manual", ACTOR, engine=self.engine)
        c = self.run_zt(fs)["zt-dev-edr"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("2 more are only claimed", c["evidence"][0])
        controls.upsert("srv-*", "edr", "EDR agent", "verified", "edr-feed", ACTOR, engine=self.engine)
        self.assertEqual(self.run_zt(fs)["zt-dev-edr"]["status"], "pass")

    def test_eol_systems(self):
        good = [finding(1, "a.corp.test", os_="Ubuntu 24.04")]
        self.assertIn(self.run_zt(good)["zt-dev-eol"]["status"], ("pass", "unknown"))
        bad = [finding(1, "a.corp.test", os_="Windows Server 2008 R2"), finding(2, "b.corp.test", os_="Windows 7")]
        c = self.run_zt(bad)["zt-dev-eol"]
        if c["status"] != "unknown":
            self.assertEqual(c["status"], "fail")

    # ---- networks
    def test_firewall_good_and_bad(self):
        fw_store.import_rules("edge-fw", FW_GOOD, "csv", ACTOR, self.engine, now=NOW)
        self.assertEqual(self.run_zt()["zt-net-firewall"]["status"], "pass")
        fw_store.import_rules("edge-fw", FW_BAD, "csv", ACTOR, self.engine, now=NOW)
        c = self.run_zt()["zt-net-firewall"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("allow-", " ".join(c["evidence"]))
        seg = self.run_zt()["zt-net-segmentation"]
        self.assertIn(seg["status"], ("partial", "fail"))
        hyg = self.run_zt()["zt-net-hygiene"]
        self.assertNotEqual(hyg["status"], "pass")

    def test_topology_recorded(self):
        fs = [finding(1, "web-01.corp.test"), finding(2, "db-01.corp.test")]
        self.assertEqual(self.run_zt(fs)["zt-net-topology"]["status"], "fail")
        with patch("remediation.enrichment.network_reachability.load_topology", return_value={"assets": [{"match": {"name_prefix": ""}, "path_to_internet": [{"hop_type": "firewall", "name": "FW", "default_action": "deny"}]}]}):
            self.assertEqual(self.run_zt(fs)["zt-net-topology"]["status"], "pass")
        with patch("remediation.enrichment.network_reachability.load_topology", return_value=TOPOLOGY):
            c = self.run_zt(fs)["zt-net-topology"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)

    # ---- applications
    def test_sbom_and_critical(self):
        app_store.upsert_application("shop", {"internet_facing": True, "environment": "production"}, ACTOR, self.engine)
        self.assertEqual(self.run_zt()["zt-app-sbom"]["status"], "fail")
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.app_sboms), {"application": "shop", "format": "cyclonedx", "source": "ci", "uploaded_at": "2026-10-01T00:00:00Z", "uploaded_by": ACTOR,
                                                       "graph_json": "{}", "notes_json": "[]", "component_count": 3})
        self.assertEqual(self.run_zt()["zt-app-sbom"]["status"], "pass")
        self.assertEqual(self.run_zt([finding(1, "shop", sev="High", typ="application")])["zt-app-critical"]["status"], "pass")
        c = self.run_zt([finding(1, "shop", sev="Critical", typ="application")])["zt-app-critical"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 open Critical", c["evidence"][0])
        # an old SBOM no longer counts
        self.assertEqual(self.run_zt(now=NOW + datetime.timedelta(days=400))["zt-app-sbom"]["status"], "fail")

    def test_api_auth(self):
        add_endpoint(self.engine, "/orders")
        self.assertEqual(self.run_zt()["zt-app-api-auth"]["status"], "pass")
        add_endpoint(self.engine, "/open1", "none")
        add_endpoint(self.engine, "/open2", "none")
        self.assertEqual(self.run_zt()["zt-app-api-auth"]["status"], "fail")

    # ---- data
    def test_data_classes_and_mapping(self):
        add_endpoint(self.engine, "/users", detected={"email": 4, "health": 1})
        self.assertEqual(self.run_zt()["zt-data-classes"]["status"], "unknown")
        self.assertEqual(self.run_zt()["zt-data-unclassified"]["status"], "fail")
        from remediation.apisec import store as api_store
        api_store.import_classes('{"classes":[{"name":"Restricted","priority":1,"detectors":["email","health"],"field_patterns":[]}]}', ACTOR, engine=self.engine)
        checks = self.run_zt()
        self.assertEqual(checks["zt-data-classes"]["status"], "pass")
        self.assertEqual(checks["zt-data-unclassified"]["status"], "pass")

    # ---- visibility
    def test_alert_recency(self):
        hunting_store.receive_alert({"external_id": "a1", "title": "Beacon", "severity": "High"}, self.engine)
        fresh = self.run_zt(now=datetime.datetime.now(datetime.timezone.utc))["zt-vis-alerts"]
        self.assertEqual(fresh["status"], "pass")
        stale = self.run_zt(now=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=200))["zt-vis-alerts"]
        self.assertEqual(stale["status"], "fail")

    def test_connections_and_freshness(self):
        add_conn(self.engine, "scan-a")
        self.assertEqual(self.run_zt()["zt-vis-connections"]["status"], "pass")
        add_conn(self.engine, "scan-b", "qualys", status="error")
        add_conn(self.engine, "scan-c", "tenable", last_run="2025-01-01T00:00:00Z")
        self.assertEqual(self.run_zt()["zt-vis-connections"]["status"], "fail")
        fs = [finding(i, f"h{i}.corp.test", last_seen="2026-10-02") for i in range(3)]
        self.assertEqual(self.run_zt(fs)["zt-vis-freshness"]["status"], "pass")
        old = [finding(i, f"h{i}.corp.test", last_seen="2025-01-02") for i in range(3)]
        self.assertEqual(self.run_zt(old)["zt-vis-freshness"]["status"], "fail")

    # ---- automation
    def test_sync_schedule_and_playbooks(self):
        add_conn(self.engine, "scan-a", schedule=0)
        self.assertEqual(self.run_zt()["zt-auto-sync"]["status"], "fail")
        add_conn(self.engine, "scan-b", "qualys", schedule=60)
        self.assertEqual(self.run_zt()["zt-auto-sync"]["status"], "partial")
        from remediation.soar import playbooks
        playbooks.save("Notify", "x", {"mode": "manual"}, [{"type": "add-note", "params": {"text": "hello"}}], ACTOR, enabled=False, engine=self.engine)
        self.assertEqual(self.run_zt()["zt-auto-playbooks"]["status"], "fail")
        playbooks.save("Notify2", "x", {"mode": "manual"}, [{"type": "add-note", "params": {"text": "hello"}}], ACTOR, engine=self.engine)
        self.assertEqual(self.run_zt()["zt-auto-playbooks"]["status"], "pass")

    # ---- governance
    def test_exceptions_expiry(self):
        ex_store.create_exception("FIND-1", "Vendor fix pending", ACTOR, "ciso@corp.test", "2026-12-31", engine=self.engine, as_of=datetime.date(2026, 10, 1), lock_path=self.lock)
        self.assertEqual(self.run_zt()["zt-gov-exceptions"]["status"], "pass")
        c = self.run_zt(now=datetime.datetime(2027, 2, 1, tzinfo=datetime.timezone.utc))["zt-gov-exceptions"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1 exceptions", c["evidence"][0])

    def test_policy_and_risk_reviews(self):
        policies.create("Access policy", "text", ACTOR, ACTOR, status="active", review_date="2027-03-01", engine=self.engine)
        self.assertEqual(self.run_zt()["zt-gov-policies"]["status"], "pass")
        policies.create("Old policy", "text", ACTOR, ACTOR, status="active", review_date="2025-01-01", engine=self.engine)
        self.assertEqual(self.run_zt()["zt-gov-policies"]["status"], "partial")
        risks.create({"title": "Supplier outage", "inherent_likelihood": 3, "inherent_impact": 3, "review_date": "2027-01-01"}, ACTOR, engine=self.engine)
        self.assertEqual(self.run_zt()["zt-gov-risks"]["status"], "pass")
        risks.create({"title": "No date", "inherent_likelihood": 3, "inherent_impact": 3}, ACTOR, engine=self.engine)
        self.assertEqual(self.run_zt()["zt-gov-risks"]["status"], "partial")

    # ---- (c)(d)(e)
    def seed_everything(self):
        fw_store.import_rules("edge-fw", FW_BAD, "csv", ACTOR, self.engine, now=NOW)
        iam_store.import_entitlements("idp", ENTS_STALE, "csv", ACTOR, self.engine)
        iam_store.import_roster(ROSTER_LEFT, self.engine)
        add_conn(self.engine, "scan-a", schedule=0, status="error")
        add_endpoint(self.engine, "/open", "none", detected={"email": 2})
        app_store.upsert_application("shop", {"internet_facing": True}, ACTOR, self.engine)
        controls.upsert("srv-*", "edr", "EDR", "claimed", "manual", ACTOR, engine=self.engine)
        ex_store.create_exception("FIND-1", "r", ACTOR, "ciso@corp.test", "2026-12-31", engine=self.engine, as_of=datetime.date(2026, 10, 1), lock_path=self.lock)
        policies.create("Old policy", "text", ACTOR, ACTOR, status="active", review_date="2025-01-01", engine=self.engine)
        for i in range(8):
            add_user(self.engine, f"adm{i}@corp.test", "admin")
        return [finding(1, "srv-01.corp.test", os_="Windows Server 2008 R2", last_seen="2025-01-01"), finding(2, "shop", sev="Critical", typ="application", last_seen="2025-01-01")]

    def test_shape_ids_and_numbers(self):
        for case in ("empty", "bad"):
            fs = self.seed_everything() if case == "bad" else ()
            now = NOW + datetime.timedelta(days=200) if case == "bad" else NOW
            checks = zero_trust.run(mkctx(self.engine, fs, now=now))
            ids = [c["id"] for c in checks]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertGreaterEqual(len(checks), 24)
            areas = {a for a, _ in zero_trust.FRAMEWORK["areas"]}
            for c in checks:
                self.assertEqual(set(c), {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"})
                self.assertEqual(c["framework"], "zero-trust")
                self.assertIn(c["area"], areas)
                self.assertTrue(c["id"].startswith("zt-"))
                self.assertTrue(c["recommendation"], c["id"])
                self.assertTrue(any(re.search(r"\d", e) for e in c["evidence"]), c["id"])
            per_area = {a: sum(1 for c in checks if c["area"] == a) for a in areas}
            for a, n in per_area.items():
                self.assertTrue(2 <= n <= 4, (a, n))

    def test_deterministic(self):
        fs = self.seed_everything()
        a = zero_trust.run(mkctx(self.engine, fs))
        b = zero_trust.run(mkctx(self.engine, fs))
        self.assertEqual(a, b)

    def test_changes_name_real_settings(self):
        fs = self.seed_everything()
        checks = zero_trust.run(mkctx(self.engine, fs, now=NOW + datetime.timedelta(days=200)))
        nav = (REPO_ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")
        seen = 0
        for c in checks:
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] == "page":
                self.assertIn(f'"{ch["where"]}"', nav, c["id"])
            elif ch["kind"] == "yaml":
                text = (REPO_ROOT / ch["where"]).read_text(encoding="utf-8")
                self.assertIn(ch["key"], text, c["id"])
            elif ch["kind"] == "env":
                hits = [p for p in (REPO_ROOT / "dashboard" / "auth").glob("*.py") if ch["key"] in p.read_text(encoding="utf-8")]
                self.assertTrue(hits, c["id"])
            self.assertTrue(ch["effect"])
        self.assertGreaterEqual(seen, 10)
        # a secret is never echoed: the SSO check reports presence only
        env = {"OIDC_CLIENT_SECRET": "super-secret-value", "OIDC_ISSUER": "https://login.corp.test"}
        c = {x["id"]: x for x in zero_trust.run(mkctx(self.engine, env=env))}["zt-id-sso"]
        self.assertNotIn("super-secret-value", json.dumps(c))


if __name__ == "__main__":
    unittest.main()
