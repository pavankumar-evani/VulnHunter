"""
Tests for threat hunting and SOC triage: query translation, hunts proposed from live exposure, the hunt workspace, alert intake and
triage with vulnerability context, runbooks, metrics, and the API.
"""
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
from remediation.enrichment import attack_mapping  # noqa: E402
from remediation.hunting import generate, store, translate, triage  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}


def f(i, host="WEB-1", cve="CVE-2021-1", kev=True, epss=0.9, sev="Critical", tech=(T1190,), **kw):
    d = {"id": f"FIND-{i}", "title": f"Vuln {cve}", "cve": cve, "severity": sev, "asset": {"name": host}, "attack_techniques": list(tech),
         "kev": {"listed": kev, "known_ransomware_campaign_use": "Unknown"} if kev else None, "epss": {"score": epss}}
    d.update(kw)
    return d


class TranslateTests(unittest.TestCase):
    def test_modifiers_lists_and_scope(self):
        spl = translate.to_spl({"Image|endswith": ["\\cmd.exe", "/bin/sh"], "EventID": 4624, "User": "root"}, hosts={"B", "A"})
        self.assertTrue(spl.startswith('search (host="A" OR host="B") '))
        self.assertIn('(Image="*\\\\cmd.exe" OR Image="*/bin/sh")', spl)
        self.assertIn("EventID=4624", spl)
        self.assertIn('User="root"', spl)

    def test_quotes_are_escaped_and_bad_input_refused(self):
        self.assertIn('x="*a\\"b*"', translate.to_spl({"x|contains": 'a"b'}))
        for bad in ({"a b": 1}, {"f|regex": "x"}, {}):
            with self.assertRaises(ValueError):
                translate.to_spl(bad)

    def test_every_library_detection_translates_and_every_tagged_technique_has_an_entry(self):
        lib = generate.library()
        for tid, entry in lib.items():
            self.assertTrue(entry["detections"] and entry["data_sources"], tid)
            for d in entry["detections"]:
                translate.to_spl(d["selection"], {"H"})
        tagged = {t[1] for t in attack_mapping._PATTERNS if t[1]}
        self.assertEqual(sorted(tagged - set(lib)), [])


class GenerateTests(unittest.TestCase):
    def test_a_kev_cve_becomes_one_hunt_with_hosts_techniques_and_queries(self):
        out = generate.propose([f(1, "WEB-1"), f(2, "WEB-2"), f(3, "DB-1", cve="CVE-2", kev=False, epss=0.1)])
        self.assertEqual([h["source_ref"] for h in out], ["CVE-2021-1"])
        h = out[0]
        self.assertEqual(h["assets"], ["WEB-1", "WEB-2"])
        self.assertEqual([t["technique_id"] for t in h["techniques"]], ["T1190"])
        self.assertTrue(h["queries"] and all('host="WEB-1"' in q["query"] for q in h["queries"]))
        self.assertIn("Known Exploited", h["hypothesis"])

    def test_high_epss_alone_qualifies_and_ranking_prefers_kev_and_ransomware(self):
        out = generate.propose([f(1, cve="CVE-A", kev=False, epss=0.8), f(2, cve="CVE-B", kev=True, epss=0.2),
                                f(3, cve="CVE-C", kev=True, epss=0.2, kev_extra=1)])
        self.assertEqual({h["source_ref"] for h in out}, {"CVE-A", "CVE-B", "CVE-C"})
        self.assertEqual(out[-1]["source_ref"], "CVE-A")
        self.assertIn("EPSS", next(h for h in out if h["source_ref"] == "CVE-A")["hypothesis"])

    def test_closed_excepted_and_cve_less_findings_are_ignored_and_existing_hunts_skipped(self):
        fs = [f(1, status="resolved"), f(2, cve="CVE-X", exception={"active": True}), f(3, cve=None), f(4, cve="CVE-Y")]
        self.assertEqual([h["source_ref"] for h in generate.propose(fs)], ["CVE-Y"])
        self.assertEqual(generate.propose(fs, existing_refs={"CVE-Y"}), [])

    def test_untagged_findings_still_produce_a_hunt_but_say_there_are_no_queries(self):
        (h,) = generate.propose([f(1, tech=())])
        self.assertEqual(h["queries"], [])
        self.assertIn("no queries were generated", h["notes"])
        (h2,) = generate.propose([f(1, tech=({"technique_id": "T9999", "technique_name": "Unknown", "tactic": "x"},))])
        self.assertIn("T9999", h2["notes"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_hunt_lifecycle_and_closing_needs_an_outcome(self):
        h = store.create_hunt(generate.propose([f(1)])[0], "a", self.e)
        self.assertEqual((h["status"], h["source"]), ("proposed", "generated"))
        with self.assertRaises(ValueError):
            store.update_hunt(h["id"], {"status": "closed"}, self.e)
        qs = h["queries"]
        qs[0]["result"] = "no-hits"
        store.update_hunt(h["id"], {"status": "active", "queries": qs, "notes": "looked at proxy logs"}, self.e)
        done = store.update_hunt(h["id"], {"status": "closed", "outcome": "not-found", "detection_created": True}, self.e)
        self.assertEqual((done["status"], done["outcome"], done["detection_created"]), ("closed", "not-found", True))
        self.assertTrue(done["closed_at"])
        self.assertEqual(done["queries"][0]["result"], "no-hits")
        reopened = store.update_hunt(h["id"], {"status": "active"}, self.e)
        self.assertIsNone(reopened["closed_at"])

    def test_validation_and_one_hunt_per_cve(self):
        for bad in ({"title": "", "hypothesis": "x"}, {"title": "t", "hypothesis": " "}):
            with self.assertRaises(ValueError):
                store.create_hunt(bad, "a", self.e)
        p = generate.propose([f(1)])[0]
        store.create_hunt(p, "a", self.e)
        with self.assertRaises(ValueError):
            store.create_hunt(p, "a", self.e)
        self.assertEqual(store.existing_refs(self.e), {"CVE-2021-1"})
        h = store.create_hunt({"title": "t", "hypothesis": "h"}, "a", self.e)
        for bad in ({"outcome": "maybe"}, {"status": "weird"}, {"queries": [{"result": "great"}]}):
            with self.assertRaises(ValueError):
                store.update_hunt(h["id"], bad, self.e)
        with self.assertRaises(KeyError):
            store.update_hunt(999, {"notes": "x"}, self.e)

    def test_alerts_dedupe_validate_and_close_with_a_disposition(self):
        a, created = store.receive_alert({"source": "siem", "external_id": "7", "title": "Shell from w3wp", "severity": "high", "asset": "WEB-1"}, self.e)
        self.assertTrue(created)
        self.assertEqual((a["severity"], a["status"]), ("High", "new"))
        again, created2 = store.receive_alert({"source": "siem", "external_id": "7", "title": "changed", "severity": "low"}, self.e)
        self.assertFalse(created2)
        self.assertEqual(again["title"], "Shell from w3wp")
        self.assertTrue(store.receive_alert({"source": "xdr", "external_id": "7", "title": "other source"}, self.e)[1])
        for bad in ({"external_id": "", "title": "x"}, {"external_id": "1", "title": ""}, {"external_id": "1", "title": "x", "severity": "dire"}):
            with self.assertRaises(ValueError):
                store.receive_alert(bad, self.e)
        with self.assertRaises(ValueError):
            store.update_alert(a["id"], {"status": "closed"}, self.e)
        closed = store.update_alert(a["id"], {"status": "closed", "disposition": "true-positive", "assignee": "s@t"}, self.e)
        self.assertEqual((closed["disposition"], closed["assignee"]), ("true-positive", "s@t"))
        self.assertTrue(closed["closed_at"])
        self.assertEqual(len(store.list_alerts(self.e, status="closed")), 1)


class TriageTests(unittest.TestCase):
    def alert(self, **kw):
        return {"severity": "High", "asset": "WEB-1", "technique": "T1190", "title": "Suspicious request", **kw}

    def test_context_raises_priority_and_explains_why(self):
        base = triage.enrich(self.alert(asset="UNKNOWN"), [f(1)], owners={"unknown": "o"})
        rich = triage.enrich(self.alert(), [f(1), f(2, cve="CVE-2", kev=False, epss=0.7)], owners={})
        self.assertEqual(base["priority"], 70)
        self.assertEqual(rich["priority"], 70 + 30 + 20 + 10 + 10)
        self.assertEqual((rich["open_findings"], rich["kev_findings"]), (2, 1))
        self.assertTrue(any("matches technique T1190" in r for r in rich["reasons"]))
        self.assertTrue(any("no recorded owner" in r for r in rich["reasons"]))
        self.assertTrue(rich["findings"][0]["kev"])

    def test_owned_host_and_resolved_findings_do_not_add_context(self):
        e = triage.enrich(self.alert(), [f(1, status="resolved")], owners={"web-1": "team-a"})
        self.assertEqual((e["priority"], e["owner"], e["open_findings"]), (70, "team-a", 0))
        self.assertTrue(any("no open findings" in r for r in e["reasons"]))

    def test_an_alert_with_no_host_says_so_instead_of_guessing(self):
        e = triage.enrich(self.alert(asset=None), [f(1)])
        self.assertEqual(e["open_findings"], 0)
        self.assertTrue(any("names no host" in r for r in e["reasons"]))

    def test_runbook_matches_technique_then_keywords_then_falls_back(self):
        self.assertEqual(triage.runbook_for({"technique": "T1190"})["id"], "rb-exploit-public-app")
        self.assertEqual(triage.runbook_for({"technique": "T1021"})["id"], "rb-lateral")
        self.assertEqual(triage.runbook_for({"title": "Possible webshell dropped"})["id"], "rb-exploit-public-app")
        self.assertEqual(triage.runbook_for({"title": "Odd thing"})["id"], "rb-generic")
        for b in triage.runbooks():
            self.assertTrue(b["steps"], b["id"])

    def test_metrics_count_coverage_only_for_active_or_closed_hunts(self):
        e = create_engine("sqlite:///:memory:")
        findings = [f(1), f(2, tech=({"technique_id": "T1068", "technique_name": "Priv esc", "tactic": "x"},))]
        h = store.create_hunt(generate.propose(findings)[0], "a", e)
        m0 = triage.metrics(store.list_hunts(e), [], findings, generate.library())
        self.assertEqual((m0["coverage"]["estate_techniques"], m0["coverage"]["hunted"]), (2, 0))
        store.update_hunt(h["id"], {"status": "closed", "outcome": "confirmed", "detection_created": True}, e)
        a, _ = store.receive_alert({"external_id": "1", "title": "x"}, e)
        store.update_alert(a["id"], {"status": "closed", "disposition": "false-positive"}, e)
        m = triage.metrics(store.list_hunts(e), store.list_alerts(e), findings, generate.library())
        self.assertEqual((m["hunts"]["confirmed"], m["hunts"]["detections_created"], m["coverage"]["hunted"]), (1, 1, 2))
        self.assertEqual((m["alerts"]["closed"], m["alerts"]["false_positive"], m["alerts"]["open"]), (1, 1, 0))
        self.assertEqual(m["coverage"]["pct"], 100)


class HuntingApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fake = [f(1, "WEB-1"), f(2, "DB-1", cve="CVE-2", tech=())]
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=self.fake)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "siem", "scopes": ["soc:write"]}).json()["key"]
        self.other = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def push(self, alerts, key=None):
        return self.client.post("/api/ingest/alerts", json={"alerts": alerts}, headers={"Authorization": f"Bearer {key or self.key}"})

    def test_admin_only(self):
        for path in ("/api/hunting/overview", "/api/hunting/proposals", "/api/hunting/hunts", "/api/soc/alerts"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.login("user@t.local")
        for path in ("/api/hunting/overview", "/api/hunting/proposals", "/api/hunting/hunts", "/api/soc/alerts"):
            self.assertEqual(self.client.get(path).status_code, 403, path)

    def test_proposal_to_closed_hunt(self):
        self.login("admin@t.local")
        props = self.client.get("/api/hunting/proposals").json()["proposals"]
        self.assertEqual({p["source_ref"] for p in props}, {"CVE-2021-1", "CVE-2"})
        r = self.client.post("/api/hunting/proposals/accept", json={"source_ref": "CVE-2021-1"})
        self.assertEqual(r.status_code, 200, r.text)
        h = r.json()
        self.assertEqual(self.client.post("/api/hunting/proposals/accept", json={"source_ref": "CVE-2021-1"}).status_code, 404)
        self.assertEqual(self.client.get("/api/hunting/overview").json()["proposals"], 1)
        bad = self.client.put(f"/api/hunting/hunts/{h['id']}", json={"status": "closed"})
        self.assertEqual(bad.status_code, 400)
        ok = self.client.put(f"/api/hunting/hunts/{h['id']}", json={"status": "closed", "outcome": "not-found", "notes": "clean"})
        self.assertEqual((ok.status_code, ok.json()["outcome"]), (200, "not-found"), ok.text)
        self.assertEqual(self.client.get("/api/hunting/hunts/999").status_code, 404)
        mine = self.client.post("/api/hunting/hunts", json={"title": "Own hunt", "hypothesis": "Odd DNS"})
        self.assertEqual((mine.status_code, mine.json()["source"]), (200, "manual"))
        self.assertEqual(self.client.post("/api/hunting/hunts", json={"title": "x"}).status_code, 400)

    def test_alert_intake_needs_the_soc_scope_and_is_idempotent(self):
        a = {"external_id": "A1", "title": "Shell spawned by w3wp", "severity": "High", "asset": "WEB-1", "technique": "T1190"}
        self.assertEqual(self.client.post("/api/ingest/alerts", json={"alerts": [a]}).status_code, 401)
        self.assertEqual(self.push([a], self.other).status_code, 401)
        r = self.push([a, {"external_id": "", "title": "bad"}])
        self.assertEqual((r.status_code, r.json()["created"], r.json()["rejected"]), (200, 1, 1), r.text)
        self.assertEqual(self.push([a]).json()["already_known"], 1)

    def test_triage_queue_orders_by_context_and_alert_can_be_worked(self):
        self.push([{"external_id": "1", "title": "Quiet one", "severity": "High", "asset": "NOPE"},
                   {"external_id": "2", "title": "Web shell on server", "severity": "High", "asset": "WEB-1", "technique": "T1190"}])
        self.login("admin@t.local")
        rows = self.client.get("/api/soc/alerts").json()["alerts"]
        self.assertEqual([r["external_id"] for r in rows], ["2", "1"])
        self.assertGreater(rows[0]["context"]["priority"], rows[1]["context"]["priority"])
        one = self.client.get(f"/api/soc/alerts/{rows[0]['id']}").json()
        self.assertEqual(one["context"]["runbook"]["id"], "rb-exploit-public-app")
        self.assertEqual(one["context"]["kev_findings"], 1)
        aid = rows[0]["id"]
        self.assertEqual(self.client.put(f"/api/soc/alerts/{aid}", json={"status": "closed"}).status_code, 400)
        ok = self.client.put(f"/api/soc/alerts/{aid}", json={"status": "closed", "disposition": "true-positive"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual([r["external_id"] for r in self.client.get("/api/soc/alerts").json()["alerts"]], ["1", "2"])  # closed sorts last
        self.assertEqual(self.client.get("/api/soc/alerts/999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
