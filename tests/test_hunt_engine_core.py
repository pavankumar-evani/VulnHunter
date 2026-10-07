"""Hunt engine: generators (positive, negative, gap note), evidence resolution, scoring breakdown, readiness, query renderings, dedupe stability."""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.hunting.engine import context, generators, model, readiness, render, scoring, service  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
T1059 = {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"}


def fnd(i, host="WEB-1", cve="CVE-2021-1", kev=True, sev="Critical", tech=(T1190,), **kw):
    d = {"id": f"FIND-{i}", "title": f"Vuln {cve}", "cve": cve, "severity": sev, "asset": {"name": host}, "attack_techniques": list(tech), "first_seen": "2026-09-01", "last_seen": "2026-10-04",
         "kev": {"listed": True, "date_added": "2026-09-30", "known_ransomware_campaign_use": "Unknown"} if kev else None, "epss": {"score": 0.9}}
    d.update(kw)
    return d


def alert(i, asset="WEB-1", sev="Low", day=1, hour=10, disp=None, technique=None, rule="R1", title=None, user=None, status="new", detail=""):
    return {"id": i, "source": "x", "external_id": str(i), "title": title or f"alert {i}", "severity": sev, "asset": asset, "technique": technique, "detail": detail, "status": status,
            "disposition": disp, "occurred_at": f"2026-10-{day:02d}T{hour:02d}:00:00Z", "received_at": f"2026-10-{day:02d}T{hour:02d}:00:00Z", "rule_name": rule,
            "entities": {"host": asset, "user": user, "ips": [], "domains": [], "hashes": [], "urls": []}}


def rule(name="r", techniques=("T1059",)):
    return {"id": 1, "name": name, "enabled": True, "techniques": list(techniques)}


def ctx(**kw):
    cfg = kw.pop("cfg", None) or context.config()
    return context.Context(now=NOW, cfg=cfg, **kw)


def resolves(c, e):
    """Every evidence item must name a record the Context holds."""
    k, r = e["kind"], e["ref"]
    if k == "finding":
        return any(f["id"] == r for f in c.findings or [])
    if k == "alert":
        return any(str(a["id"]) == r for a in c.alerts or [])
    if k == "intel":
        return any(str(x["id"]) == r for x in c.intel or [])
    if k == "cvd":
        return any(x["id"] == r for x in c.cvd or [])
    if k == "darkweb":
        return any(str(x["id"]) == r for x in c.darkweb or [])
    if k == "iam":
        return any(f"{x['id']}:{x['user']}" == r for x in c.iam_findings or [])
    if k == "hunt":
        return any(str(x["id"]) == r for x in c.hunts or [])
    if k == "asset":
        return r in (c.ownership or {})
    if k == "catalog":      # a group or malware family in the ATT&CK catalog (the knowledge generator)
        from remediation.hunting.knowledge import catalog as kcat
        return bool(kcat.get().group(r) or kcat.get().software_item(r))
    if k == "actor":
        from remediation.enrichment import threat_actor_groups as g
        return any(x["id"] == r for x in g.THREAT_ACTOR_GROUPS)
    return False


def run(c):
    items, gaps = service.run_generators(c)
    return items, gaps


def gen(c):
    return {g["generator"] for g in run(c)[0]}


class GeneratorTests(unittest.TestCase):
    def check_all_resolve(self, c):
        items, _ = run(c)
        self.assertTrue(items)
        for h in items:
            self.assertTrue(h["why_now"], h["id"])
            for e in h["why_now"]:
                self.assertTrue(resolves(c, e), (h["generator"], e))
            self.assertTrue(h["hypothesis"].startswith("If ") and ", we would expect to see " in h["hypothesis"])
        return items

    def test_kev_exposure_positive_and_negative(self):
        c = ctx(findings=[fnd(1), fnd(2, host="DB-1", cve="CVE-9", kev=False, sev="Low", tech=(), epss={"score": 0.1})], ownership={})
        items = self.check_all_resolve(c)
        kev = [h for h in items if h["generator"] == "kev-exposure"]
        self.assertEqual(len(kev), 1)
        self.assertEqual(kev[0]["scope"]["assets"], ["WEB-1"])
        self.assertTrue(kev[0]["queries"] and kev[0]["queries"][0]["language"] == "splunk-spl")
        self.assertNotIn("kev-exposure", gen(ctx(findings=[fnd(2, kev=False, epss={"score": 0.1})], ownership={})))

    def test_intel_reports_and_gap(self):
        rep = {"id": 7, "title": "APT99 report", "content_hash": "h1", "relevance": 70, "priority": "high", "reasons": ["CVE open"], "received_at": "2026-10-05T00:00:00Z",
               "extracted": {"cves": ["CVE-2021-1"], "techniques": ["T1190"], "actors": ["APT99"], "ips": [], "domains": [], "hashes": []}}
        c = ctx(findings=[fnd(1)], intel=[rep])
        items = self.check_all_resolve(c)
        r = [h for h in items if h["generator"] == "intel-report"][0]
        self.assertIn("APT99", r["hypothesis"])
        low = dict(rep, priority="low", id=8, content_hash="h2")
        self.assertNotIn("intel-report", gen(ctx(findings=[fnd(1)], intel=[low])))
        _, gaps = run(ctx(findings=[fnd(1)], intel=[]))
        self.assertTrue(any("No threat-intelligence reports" in g["note"] for g in gaps))

    def test_threat_actor_needs_industry_and_estate_technique(self):
        cfg = context.config()
        cfg["industry"] = "Healthcare"
        c = ctx(findings=[fnd(1, tech=(T1190,))], cfg=cfg)   # APT41 targets healthcare and lists T1190
        self.assertIn("threat-actor", gen(c))
        for h in run(c)[0]:
            for e in h["why_now"]:
                self.assertTrue(resolves(c, e))
        cfg2 = dict(cfg, industry=None)
        items, gaps = run(ctx(findings=[fnd(1)], cfg=cfg2))
        self.assertNotIn("threat-actor", {h["generator"] for h in items})
        self.assertTrue(any("No industry is set" in g["note"] for g in gaps))
        self.assertNotIn("threat-actor", gen(ctx(findings=[fnd(1, tech=(T1190,))], cfg=dict(cfg, industry="Insurance"))))   # no catalogued group targets it

    def test_cvd_matches(self):
        adv = {"id": "ADV-1", "source": "cvd", "title": "Foo RCE", "cves": ["CVE-2021-1"], "vendor": "Foo", "product": "Foo", "severity": "Critical", "published": "2026-10-01",
               "match_basis": ["cve"], "finding_ids": ["FIND-1"]}
        c = ctx(findings=[fnd(1)], cvd=[adv])
        self.check_all_resolve(c)
        self.assertIn("cvd-advisory", gen(c))
        _, gaps = run(ctx(findings=[fnd(1)], cvd=[]))
        self.assertTrue(any("CVD" in g["note"] for g in gaps))

    def test_coverage_gap_positive_negative_gap(self):
        f = fnd(1, tech=(T1059,), kev=False)
        c = ctx(findings=[f], rules=[rule("other", ("T1190",))])
        self.assertIn("coverage-gap", gen(c))
        self.assertNotIn("coverage-gap", gen(ctx(findings=[f], rules=[rule("shell", ("T1059.001",))])))
        items, gaps = run(ctx(findings=[f], rules=[]))
        self.assertNotIn("coverage-gap", {h["generator"] for h in items})
        self.assertTrue(any("coverage cannot be judged" in g["note"] for g in gaps))
        h = [x for x in run(c)[0] if x["generator"] == "coverage-gap"][0]
        self.assertEqual(h["priority"]["breakdown"][2]["points"], 15)
        self.assertIn("title:", h["draft_detection"])

    def test_baseline_low_and_slow_positive_negative_gap(self):
        al = [alert(i, day=i, rule=f"R{i}") for i in range(1, 6)]
        c = ctx(findings=[], alerts=al)
        items = self.check_all_resolve(c)
        self.assertIn("low-and-slow", {h["generator"] for h in items})
        tp = [alert(i, day=i, disp="true-positive" if i == 1 else None) for i in range(1, 6)]
        self.assertNotIn("low-and-slow", gen(ctx(findings=[], alerts=tp)))
        hi = [alert(i, day=i, sev="High") for i in range(1, 6)]
        self.assertNotIn("low-and-slow", gen(ctx(findings=[], alerts=hi)))
        _, gaps = run(ctx(findings=[], alerts=[]))
        self.assertTrue(any("No alerts are stored" in g["note"] for g in gaps))
        _, gaps = run(c)
        self.assertTrue(any("process telemetry" in g["note"] for g in gaps))

    def test_baseline_burst_and_offhours(self):
        burst = [alert(i, hour=10, rule="Spray") for i in range(1, 10)]
        for i, a in enumerate(burst):
            a["occurred_at"] = f"2026-10-02T10:{i:02d}:00Z"
        self.assertIn("alert-burst", gen(ctx(findings=[], alerts=burst)))
        ent = [{"user": "ann", "account": "ann", "system": "S", "entitlement": "Domain Admin", "privileged": True, "status": "active", "last_login": None, "manager": None}]
        off = [alert(1, hour=2, user="ann"), alert(2, hour=3, user="ann")]
        c = ctx(findings=[], alerts=off, entitlements=ent)
        self.check_all_resolve(c)
        self.assertIn("off-hours-privileged", gen(c))
        self.assertNotIn("off-hours-privileged", gen(ctx(findings=[], alerts=[alert(1, hour=11, user="ann"), alert(2, hour=12, user="ann")], entitlements=ent)))
        _, gaps = run(ctx(findings=[], alerts=off, entitlements=None))
        self.assertTrue(any("Off-hours" in g["note"] for g in gaps))

    def test_exposure(self):
        own = {"WEB-1": {"facing": "external", "team": "web"}, "WEB-2": {"facing": "internal", "team": "web"}}
        c = ctx(findings=[fnd(1)], ownership=own, controls=[{"asset_name": "WEB-*", "control_class": "waf", "name": "WAF", "state": "verified"}])
        items = self.check_all_resolve(c)
        h = [x for x in items if x["generator"] == "exposed-asset"][0]
        self.assertIn("T1190", [t["technique_id"] for t in h["techniques"]])
        self.assertTrue(h["signals"]["internet_facing"])
        self.assertNotIn("exposed-asset", gen(ctx(findings=[fnd(1, host="WEB-2")], ownership=own)))
        _, gaps = run(ctx(findings=[fnd(1)], ownership={}))
        self.assertTrue(any("internet-facing" in g["note"] for g in gaps))

    def test_identity(self):
        ent = [{"user": "bob", "account": "bob", "system": "ERP", "entitlement": "Admin", "privileged": True, "status": "active", "last_login": "2026-01-01", "manager": None}]
        iam = [{"id": "IAM001", "severity": "Critical", "user": "bob", "system": "ERP", "title": "A person who has left still has access", "detail": "left", "entitlement": "Admin", "recommendation": ""},
               {"id": "IAM007", "severity": "Low", "user": "bob", "system": "ERP", "title": "never used", "detail": "x", "entitlement": "Admin", "recommendation": ""}]
        c = ctx(findings=[], entitlements=ent, iam_findings=iam)
        items = self.check_all_resolve(c)
        self.assertEqual([h["generator"] for h in items], ["identity-misuse"])
        self.assertEqual(items[0]["scope"]["identities"], ["bob"])
        self.assertIn("TargetUserName", items[0]["queries"][0]["query"])
        _, gaps = run(ctx(findings=[], entitlements=None))
        self.assertTrue(any("Access Governance" in g["note"] for g in gaps))

    def test_lessons_learned(self):
        c = ctx(findings=[fnd(1, host="A", tech=(T1059,), kev=False), fnd(2, host="B", tech=(T1059,), kev=False)], alerts=[alert(5, asset="A", disp="true-positive", technique="T1059")])
        items = self.check_all_resolve(c)
        h = [x for x in items if x["generator"] == "lessons-learned"][0]
        self.assertEqual(h["scope"]["assets"], ["B"])
        c2 = ctx(findings=[fnd(1, host="A", tech=(T1059,), kev=False)], alerts=[alert(5, asset="A", disp="true-positive", technique="T1059")])
        self.assertNotIn("lessons-learned", gen(c2))
        _, gaps = run(ctx(findings=[], alerts=[alert(5)]))
        self.assertTrue(any("confirmed as a true positive" in g["note"] for g in gaps))

    def test_darkweb(self):
        hit = {"id": 3, "kind": "credential-exposure", "status": "new", "term": "corp.com", "title": "Exposure", "source": "leak", "severity": "High", "first_seen": "2026-10-05T00:00:00Z"}
        c = ctx(findings=[], darkweb=[hit])
        self.check_all_resolve(c)
        self.assertIn("credential-exposure", gen(c))
        self.assertNotIn("credential-exposure", gen(ctx(findings=[], darkweb=[dict(hit, status="dismissed")])))
        _, gaps = run(ctx(findings=[], darkweb=[]))
        self.assertTrue(any("dark-web" in g["note"] for g in gaps))

    def test_a_failing_generator_is_reported_not_swallowed(self):
        orig = generators.GENERATORS
        generators.GENERATORS = (("boom", lambda c, lib: 1 / 0),) + orig
        try:
            items, gaps = run(ctx(findings=[fnd(1)]))
        finally:
            generators.GENERATORS = orig
        self.assertTrue(any(g["generator"] == "boom" and "failed" in g["note"] for g in gaps))
        self.assertTrue(items)


class ModelAndScoringTests(unittest.TestCase):
    def test_ids_are_stable_and_distinct(self):
        self.assertEqual(model.hypothesis_id("a", "x"), model.hypothesis_id("a", "x"))
        self.assertNotEqual(model.hypothesis_id("a", "x"), model.hypothesis_id("a", "y"))
        a, _ = run(ctx(findings=[fnd(1)]))
        b, _ = run(ctx(findings=[fnd(1)]))
        self.assertEqual([h["id"] for h in a], [h["id"] for h in b])
        self.assertEqual(len({h["id"] for h in a}), len(a))

    def test_breakdown_sums_to_score_and_explains_every_factor(self):
        items, _ = run(ctx(findings=[fnd(1)], ownership={"WEB-1": {"facing": "external"}}))
        for h in items:
            rows = h["priority"]["breakdown"]
            self.assertEqual([r["factor"] for r in rows], ["likelihood", "impact", "coverage_gap", "freshness", "learned_yield", "effort"])
            self.assertTrue(all(r["note"] for r in rows))
            self.assertAlmostEqual(max(0, min(100, sum(r["points"] for r in rows))), h["priority"]["score"], places=1)

    def test_unknown_coverage_is_never_a_pass_and_effort_lowers(self):
        base = {"coverage": "unknown"}
        s = scoring.score(base, "S", 0, "", {})
        self.assertEqual(s["breakdown"][2]["points"], 5.0)
        self.assertLess(scoring.score(base, "L", 0, "", {})["score"], s["score"] + 1)
        self.assertEqual(scoring.score({"coverage": "covered"}, "S", 0, "", {})["breakdown"][2]["points"], 0)

    def test_learned_adjust_needs_samples_and_suppresses(self):
        cfg = context.config()
        self.assertEqual(scoring.learned_adjust(None, cfg)[0], 0)
        one = {"concluded": 1, "true_positive": 0, "benign": 1, "inconclusive": 0, "dismissed": 0}
        self.assertEqual(scoring.learned_adjust(one, cfg)[0], 0)
        ben = {"concluded": 3, "true_positive": 0, "benign": 3, "inconclusive": 0, "dismissed": 0}
        pts, note, sup = scoring.learned_adjust(ben, cfg)
        self.assertLess(pts, 0)
        self.assertTrue(sup and "past outcomes" in note)
        tp = {"concluded": 3, "true_positive": 3, "benign": 0, "inconclusive": 0, "dismissed": 0}
        self.assertGreater(scoring.learned_adjust(tp, cfg)[0], 0)


class ReadinessAndRenderTests(unittest.TestCase):
    def test_cannot_tell_is_the_default_never_not_connected(self):
        r = readiness.assess(["process creation (EDR, Sysmon 1)", "DNS logs"], [])
        self.assertTrue(all(s["status"] == "cannot-tell" for s in r["sources"]))
        self.assertFalse(r["summary"]["can_run_in_quanta"])
        r = readiness.assess(["process creation (EDR, Sysmon 1)", "DNS logs"], [{"type": "cortex-xsiam", "enabled": True}, {"type": "splunk-search", "enabled": True}])
        self.assertEqual([s["status"] for s in r["sources"]], ["connected", "cannot-tell"])
        self.assertEqual(r["summary"]["status"], "partial")
        self.assertTrue(r["summary"]["can_run_in_quanta"])
        off = readiness.assess(["DNS logs"], [{"type": "splunk-search", "enabled": False}])
        self.assertFalse(off["summary"]["siem_connected"])

    def test_every_query_has_spl_kql_sigma_and_description(self):
        qs, missing = render.queries_for(["T1190", "T1078", "T1999"], ["WEB-1"], ["bob"])
        self.assertEqual(missing, ["T1999"])
        for q in qs:
            self.assertTrue(q["query"].startswith("search") and q["kql"].startswith("union *") and "title:" in q["sigma"] and q["description"])
        self.assertIn('"bob"', [q for q in qs if q["technique"] == "T1078"][0]["query"])

    def test_kql_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            render.to_kql({"a b": 1})
        with self.assertRaises(ValueError):
            render.to_kql({"f|regex": "x"})


if __name__ == "__main__":
    unittest.main()
