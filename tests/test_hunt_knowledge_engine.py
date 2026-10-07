"""Knowledge generator (uncovered techniques of relevant groups, data readiness, learning loop and dismissal memory), framework views, out-of-the-box content, report packages."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from remediation.hunting import store as hunt_store, usecase_store, usecases  # noqa: E402
from remediation.hunting.engine import context, service, store as engine_store  # noqa: E402
from remediation.hunting.knowledge import catalog, config as kcfg, content, frameworks, generator, readiness, report, scenarios, store as kstore  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from tests.test_hunt_engine_core import NOW, alert, ctx, fnd, rule  # noqa: E402

C = catalog.get()
APT29 = C.group("G0016")


def report_row(i=1, title="APT29 targets cloud tenants", actors=("APT29",), techs=(), prio="high", rel=60, ips=("203.0.113.5",), received="2026-10-05T00:00:00Z"):
    return {"id": i, "title": title, "priority": prio, "relevance": rel, "reasons": ["a technique is tagged in your estate"], "received_at": received, "content_hash": f"h{i}", "source": "paste",
            "extracted": {"actors": list(actors), "techniques": list(techs), "cves": [], "ips": list(ips), "domains": [], "hashes": [], "urls": []}}


def cfg(industry=None):
    c = context.config()
    return {**c, "industry": industry}


def know(c):
    items, gaps = service.run_generators(c)
    return [h for h in items if h["generator"].startswith("knowledge")], gaps, items


def tested(h):
    return h["knowledge"]["techniques_tested"]


def parents(ts):
    return {t.split(".")[0] for t in ts}


class GeneratorTests(unittest.TestCase):
    def test_a_group_named_in_intel_gets_a_hypothesis_over_its_uncovered_techniques(self):
        c = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule(techniques=("T1059",))], connections=[], alerts=[], hunts=[], cfg=cfg())
        hs, gaps, _ = know(c)
        h = next(x for x in hs if x["knowledge"]["subject"]["id"] == "G0016")
        self.assertEqual(h["generator"], "knowledge-group")
        self.assertTrue(h["hypothesis"].startswith("If APT29 ") and ", we would expect to see " in h["hypothesis"])
        self.assertNotIn("T1059", parents(tested(h)))              # covered by an enabled rule, so not re-suggested
        self.assertTrue(set(tested(h)) <= set(APT29["techniques"]))   # every tested technique is one the catalog says the group uses
        self.assertLessEqual(len(tested(h)), 6)
        self.assertTrue(h["queries"] and all(q["language"] == "splunk-spl" for q in h["queries"]))
        self.assertTrue(any(q.get("scenario") for q in h["queries"]))       # scenario leads came along
        self.assertEqual(h["hunt_type"], "intel-driven")
        self.assertTrue(h["priority"]["breakdown"])                  # the engine's visible score
        self.assertTrue(any("not attribution" in g for g in h["gaps"]))

    def test_nothing_is_emitted_for_a_group_whose_techniques_are_all_covered(self):
        every = sorted(parents(APT29["techniques"]))
        c = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule(techniques=tuple(every))], connections=[], alerts=[], hunts=[], cfg=cfg())
        hs, gaps, _ = know(c)
        self.assertFalse([h for h in hs if h["knowledge"]["subject"]["id"] == "G0016"])
        self.assertTrue(any("APT29" in g["note"] and "covered" in g["note"] for g in gaps))

    def test_recently_hunted_techniques_are_left_out_and_old_hunts_are_not(self):
        c0 = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        first = tested(next(x for x in know(c0)[0] if x["knowledge"]["subject"]["id"] == "G0016"))
        hunts = [{"id": 5, "created_at": "2026-10-01T00:00:00Z", "techniques": [{"technique_id": t} for t in first]}]
        c1 = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=hunts, cfg=cfg())
        again = tested(next(x for x in know(c1)[0] if x["knowledge"]["subject"]["id"] == "G0016"))
        self.assertFalse(parents(again) & parents(first))
        old = [{"id": 5, "created_at": "2025-01-01T00:00:00Z", "techniques": [{"technique_id": t} for t in first]}]
        c2 = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=old, cfg=cfg())
        self.assertEqual(tested(next(x for x in know(c2)[0] if x["knowledge"]["subject"]["id"] == "G0016")), first)

    def test_with_no_rules_coverage_is_unknown_and_scored_as_a_third_never_covered(self):
        c = ctx(findings=[fnd(1)], intel=[report_row()], rules=[], connections=[], alerts=[], hunts=[], cfg=cfg())
        hs, gaps, _ = know(c)
        h = hs[0]
        row = next(r for r in h["priority"]["breakdown"] if r["factor"] == "coverage_gap")
        self.assertIn("could not be judged", row["note"])
        self.assertAlmostEqual(row["points"], 5.0)
        self.assertTrue(any("No detection rules are recorded" in g["note"] for g in gaps))

    def test_industry_alone_suggests_documented_groups_and_no_industry_no_intel_suggests_nothing(self):
        c = ctx(findings=[], intel=[], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg("Financial Services & Banking"))
        hs, _, _ = know(c)
        self.assertTrue(hs)
        self.assertTrue(all(any("MITRE as targeting" in n for n in [h["why_now"][0]["label"]]) for h in hs if h["generator"] == "knowledge-group"))
        c2 = ctx(findings=[], intel=[], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        hs2, gaps2, _ = know(c2)
        self.assertEqual(hs2, [])
        self.assertTrue(any("No industry" in g["note"] for g in gaps2))
        self.assertTrue(any("No threat-intelligence reports" in g["note"] for g in gaps2))

    def test_malware_family_named_in_a_report_title(self):
        c = ctx(findings=[], intel=[report_row(title="New Cobalt Strike campaign hits retailers", actors=())], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        hs, _, _ = know(c)
        sw = [h for h in hs if h["generator"] == "knowledge-software"]
        self.assertEqual([h["knowledge"]["subject"]["name"] for h in sw], ["Cobalt Strike"])
        self.assertTrue(sw[0]["hypothesis"].startswith("If Cobalt Strike (malware) is active"))

    def test_volume_is_capped_by_config(self):
        base = kcfg.load()
        small = {**base, "generator": {**base["generator"], "max_groups": 1, "max_software": 0, "max_techniques": 3}}
        reports = [report_row(1, actors=("APT29",)), report_row(2, title="APT28 phish", actors=("APT28",)), report_row(3, title="FIN7 again", actors=("FIN7",))]
        c = ctx(findings=[], intel=reports, rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        with patch.object(kcfg, "load", return_value=small):
            hs, _, _ = know(c)
        self.assertEqual(len(hs), 1)
        self.assertLessEqual(len(tested(hs[0])), 3)

    def test_disabled_and_missing_catalog_are_reported_not_hidden(self):
        base = kcfg.load()
        c = ctx(findings=[], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        with patch.object(kcfg, "load", return_value={**base, "enabled": False}):
            self.assertEqual(know(c)[0], [])
        with tempfile.TemporaryDirectory() as d, patch.object(catalog, "get", return_value=catalog.Catalog(d)):
            hs, gaps = generator.gen_knowledge(c, {})
        self.assertEqual(hs, [])
        self.assertTrue(any("catalog is not loaded" in g for g in gaps))

    def test_every_evidence_item_names_a_record_that_exists(self):
        findings = [fnd(1, tech=({"technique_id": "T1047", "technique_name": "WMI", "tactic": "Execution"},))]
        c = ctx(findings=findings, intel=[report_row()], rules=[rule()], connections=[], alerts=[alert(7, technique="T1021", asset="WEB-1")], hunts=[], cfg=cfg("Financial Services & Banking"))
        hs, _, _ = know(c)
        self.assertTrue(hs)
        for h in hs:
            self.assertTrue(h["why_now"])
            for e in h["why_now"]:
                if e["kind"] == "catalog":
                    self.assertTrue(C.group(e["ref"]) or C.software_item(e["ref"]), e)
                elif e["kind"] == "intel":
                    self.assertIn(e["ref"], {str(r["id"]) for r in c.intel})
                elif e["kind"] == "finding":
                    self.assertIn(e["ref"], {f["id"] for f in c.findings})
                elif e["kind"] == "alert":
                    self.assertIn(e["ref"], {str(a["id"]) for a in c.alerts})
                else:
                    self.fail(e)

    def test_readiness_says_cannot_tell_and_never_says_missing(self):
        c = ctx(findings=[], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        h = know(c)[0][0]
        self.assertEqual(h["data_readiness"]["status"], "cannot-tell")
        self.assertTrue(all(d["status"] == "cannot-tell" for d in h["data_sources"]))
        self.assertTrue(h["knowledge"]["readiness"]["needs"])
        self.assertEqual({n["status"] for n in h["knowledge"]["readiness"]["needs"]}, {"cannot-tell"})
        self.assertNotIn("not connected", str(h["data_readiness"]).lower())

    def test_readiness_uses_connections_alerts_and_held_data(self):
        sig = readiness.signals([{"type": "cortex-xsiam", "enabled": True}, {"type": "splunk-search", "enabled": True}, {"type": "prismacloud", "enabled": False}],
                                [{"source": "CrowdStrike Falcon"}, {"source": "Okta Verify"}], [{"user": "a"}], 12)
        cl = sig["classes"]
        self.assertEqual(cl["endpoint"]["status"], "connected")
        self.assertEqual(cl["identity-provider"]["status"], "alerts-seen")
        self.assertEqual(cl["directory"]["status"], "data-held")
        self.assertEqual(cl["external-exposure"]["status"], "data-held")
        self.assertEqual(cl["cloud-audit"]["status"], "cannot-tell")      # a disabled connection proves nothing
        self.assertTrue(sig["can_run_in_quanta"] and sig["siem_connected"])
        a = readiness.assess(["endpoint", "identity-provider"], sig)
        self.assertEqual(a["status"], "partial")
        self.assertEqual(readiness.assess(["endpoint", "directory"], sig)["status"], "ready")
        self.assertEqual(readiness.assess(["dns"], sig)["status"], "cannot-tell")
        self.assertEqual(readiness.assess([], sig)["status"], "none-required")
        self.assertIn("SIEM connection exists", readiness.assess(["dns"], sig)["needs"][0]["evidence"][0])

    def test_readiness_flows_into_the_hypothesis(self):
        c = ctx(findings=[], intel=[report_row()], rules=[rule()], alerts=[{"id": 1, "source": "CrowdStrike Falcon", "status": "new"}], hunts=[], cfg=cfg(),
                connections=[{"type": "cortex-xsiam", "enabled": True}])
        h = know(c)[0][0]
        eps = [d for d in h["knowledge"]["readiness"]["needs"] if d["class"] == "endpoint"]
        self.assertEqual(eps[0]["status"], "connected")
        self.assertIn(h["data_readiness"]["status"], ("connected", "partial"))


class EngineIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def refresh(self, **kw):
        c = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg(), **kw)
        return service.refresh(c.findings, self.e, now=NOW, ctx=c)

    def hyp(self):
        return next(h for h in engine_store.all_rows(self.e) if h["generator"] == "knowledge-group")

    def test_refresh_persists_and_is_idempotent(self):
        self.refresh()
        h1 = self.hyp()
        n = len(engine_store.all_rows(self.e))
        self.refresh()
        self.assertEqual(len(engine_store.all_rows(self.e)), n)
        self.assertEqual(self.hyp()["id"], h1["id"])
        self.assertIn("knowledge", h1)

    def test_accept_creates_a_normal_hunt_with_the_scenario_leads_and_nothing_runs(self):
        self.refresh()
        h = self.hyp()
        a = service.accept(h["id"], "admin@t", engine=self.e)
        hunt = hunt_store.get_hunt(a["hunt_id"], self.e)
        self.assertEqual(hunt["status"], "proposed")
        self.assertTrue(hunt["queries"])
        self.assertTrue(all(q["result"] is None for q in hunt["queries"]))       # nothing was run
        self.assertTrue(all(q["query"].startswith("search ") for q in hunt["queries"]))

    def test_dismissal_is_remembered_until_evidence_changes_materially(self):
        self.refresh()
        h = self.hyp()
        service.dismiss(h["id"], "not-relevant", "test", "a", engine=self.e)
        self.refresh()
        self.assertEqual(engine_store.get(h["id"], self.e)["status"], "dismissed")
        self.assertNotIn(h["id"], {x["id"] for x in service.listing(self.e)["suggestions"]})
        c = ctx(findings=[fnd(1)], intel=[report_row(1), report_row(2, title="More APT29 reporting"), report_row(3, title="Even more APT29"), report_row(4, title="APT29 again", prio="high")],
                rules=[rule()], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg())
        r = service.refresh(c.findings, self.e, now=NOW, ctx=c)
        self.assertEqual(engine_store.get(h["id"], self.e)["status"], "suggested")
        self.assertEqual(r["reopened"], 1)

    def test_learning_loop_changes_the_score_and_can_suppress(self):
        c0 = ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
        base = know(c0)[0][0]
        key = base["pattern_key"]
        benign = {key: {"concluded": 3, "true_positive": 0, "benign": 3, "inconclusive": 0, "dismissed": 0}}
        low = know(ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg(), stats=benign))[0][0]
        self.assertLess(low["priority"]["score"], base["priority"]["score"])
        self.assertTrue(low["learned"]["suppressed"])
        tp = {key: {"concluded": 3, "true_positive": 3, "benign": 0, "inconclusive": 0, "dismissed": 0}}
        hi = know(ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg(), stats=tp))[0][0]
        self.assertGreater(hi["priority"]["score"], base["priority"]["score"])

    def test_the_other_generators_are_unaffected_by_a_failing_knowledge_generator(self):
        with patch.object(generator, "gen_knowledge", side_effect=RuntimeError("boom")):
            # the registered tuple holds the original function, so patch the tuple entry instead
            from remediation.hunting.engine import generators
            gens = tuple((n, (lambda c, lib: (_ for _ in ()).throw(RuntimeError("boom"))) if n == "knowledge" else f) for n, f in generators.GENERATORS)
            with patch.object(generators, "GENERATORS", gens):
                c = ctx(findings=[fnd(1)], intel=[], rules=[rule()], connections=[], alerts=[], hunts=[], cfg=cfg())
                items, gaps = service.run_generators(c)
        self.assertTrue([h for h in items if h["generator"] == "kev-exposure"])
        self.assertTrue(any("knowledge generator failed" in g["note"] for g in gaps))


class FrameworkTests(unittest.TestCase):
    def test_diamond_never_invents_an_adversary_and_keeps_unknown_unknown(self):
        d = frameworks.diamond({"techniques": ["T1558.003", "T1003.006"], "scope": {}}, C)
        v = d["vertices"]
        self.assertEqual(v["adversary"]["status"], "unknown")
        self.assertEqual(v["adversary"]["items"], [])
        self.assertEqual(v["infrastructure"]["status"], "unknown")
        self.assertEqual(v["victim"]["status"], "unknown")
        self.assertEqual(v["capability"]["status"], "known")
        self.assertIn("adversary", d["unknown_vertices"])
        self.assertEqual(d["meta"]["result"]["value"], "unknown")
        self.assertEqual(d["meta"]["resources"]["value"], "unknown")
        self.assertEqual(d["meta"]["timestamp"]["first_evidence"], "unknown")
        for cnd in v["adversary"]["candidates"]:
            self.assertIn("overlap", cnd)
        if v["adversary"]["candidates"]:
            self.assertIn("not attribution", v["adversary"]["note"])
            self.assertEqual(v["adversary"]["items"], [])      # candidates never become the adversary

    def test_diamond_fills_a_vertex_only_from_a_source_and_says_which(self):
        intel = [report_row(actors=("APT29",), ips=("203.0.113.9",))]
        d = frameworks.diamond({"techniques": ["T1059.001"], "intel": intel, "scope": {"assets": ["WEB-1"], "identities": ["a@x"], "counts": {}}, "outcome": "true-positive", "evidence_dates": ["2026-10-05"]}, C)
        v = d["vertices"]
        self.assertEqual(v["adversary"]["status"], "named-by-intel")
        self.assertIn("intel report", v["adversary"]["items"][0]["source"])
        self.assertEqual(v["infrastructure"]["items"][0]["value"], "203.0.113.9")
        self.assertEqual({i["detail"] for i in v["victim"]["items"]}, {"asset", "identity"})
        self.assertEqual(d["meta"]["result"]["value"], "activity-confirmed")
        self.assertEqual(d["meta"]["timestamp"]["first_evidence"], "2026-10-05")
        g = frameworks.diamond({"techniques": ["T1059.001"], "groups": [{"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"]}]}, C)
        self.assertEqual(g["vertices"]["adversary"]["status"], "hypothesised")
        self.assertIn("not an attribution", g["vertices"]["adversary"]["note"])

    def test_kill_chain_attack_position_and_unified_views(self):
        kc = frameworks.kill_chain_view(["T1566.002", "T1486"], C)
        self.assertEqual(kc["earliest"], "delivery")
        self.assertEqual(kc["latest"], "actions-on-objectives")
        self.assertEqual([p["id"] for p in kc["phases"]][:3], ["reconnaissance", "weaponization", "delivery"])
        self.assertEqual(frameworks.kill_chain_view([], C)["covered"], [])
        self.assertIn("Unknown", frameworks.kill_chain_view([], C)["reading"])
        pos = frameworks.attack_position_view(["T1566.002", "T1486"], C)[0]
        self.assertEqual((pos["first"], pos["last"]), ("Initial Access", "Impact"))
        uk = frameworks.unified_view(["T1566.002"], C)
        self.assertEqual(len(uk["phases"]), 18)
        self.assertFalse(next(p for p in uk["phases"] if p["id"] == "pivoting")["covered"])
        atlas = frameworks.kill_chain_view(["AML.T0051"], C)
        self.assertTrue(atlas["covered"])
        self.assertEqual(frameworks.kill_chain_view(["T0000"], C)["unmapped_techniques"], ["T0000"])      # an unknown id is reported, not mapped

    def test_current_attack_tactics_stealth_and_defense_impairment_are_mapped(self):
        kc = frameworks.kill_chain_view(["T1685", "T1036.005"], C)
        self.assertIn("installation", kc["covered"])

    def test_peak_and_maturity_follow_the_status(self):
        s = {"status": "suggested", "hypothesis": "If x", "techniques": ["T1059"], "data_sources": ["a"], "readiness": {"status": "cannot-tell"}, "has_queries": True, "has_benign": True, "scope": {"counts": {"assets": 1}}}
        p = frameworks.peak(s)
        self.assertEqual(p["current"], "prepare")
        self.assertIn("log sources", p["next_action"])
        self.assertEqual(frameworks.peak({**s, "status": "accepted"})["current"], "execute")
        self.assertEqual(frameworks.peak({**s, "status": "concluded"})["current"], "act")
        self.assertIn("Promote", frameworks.peak({**s, "status": "concluded"})["next_action"])
        self.assertEqual(frameworks.maturity({**s, "scenario": {"id": "x"}})["level"], 2)
        self.assertEqual(frameworks.maturity({**s, "generator": "coverage-gap"})["level"], 3)
        self.assertEqual(frameworks.maturity({**s, "status": "promoted"})["level"], 4)
        self.assertTrue(frameworks.maturity(s)["limiting_factor"])
        self.assertIn("not your team", frameworks.maturity(s)["note"])

    def test_views_has_every_framework_key(self):
        v = frameworks.views({"techniques": ["T1059"], "scope": {}}, C)
        self.assertEqual(set(v), {"diamond", "kill_chain", "attack", "unified_kill_chain", "peak", "maturity"})


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def test_library_coverage_statuses_and_drafts_are_never_coverage(self):
        scn = scenarios.get("identity-kerberoasting")
        st = {"rules": [], "usecases": [], "planned": {}, "signals": None}
        lib = content.library(st)
        item = next(i for i in lib["items"] if i["id"] == "identity-kerberoasting")
        self.assertEqual(item["coverage_status"], "cannot-tell")
        st["rules"] = [{"enabled": True, "techniques": ["T1003"]}]
        self.assertEqual(next(i for i in content.library(st)["items"] if i["id"] == "identity-kerberoasting")["coverage_status"], "absent")
        # a proposed use case is shown as proposed and still not coverage
        case = content.use_case_for(scn, C)
        usecase_store.sync([case], self.e)
        st["usecases"] = usecase_store.list_all(self.e)
        it = next(i for i in content.library(st)["items"] if i["id"] == "identity-kerberoasting")
        self.assertEqual(it["coverage_status"], "proposed")
        self.assertTrue(it["coverage"]["detail"].startswith("A detection use case exists"))
        self.assertNotIn("T1558", usecases.covered_techniques(st["rules"]))
        # only an enabled rule that names the technique makes it enabled
        st["rules"] = [{"enabled": False, "techniques": ["T1558"]}]
        self.assertNotEqual(next(i for i in content.library(st)["items"] if i["id"] == "identity-kerberoasting")["coverage_status"], "enabled")
        st["rules"] = [{"enabled": True, "techniques": ["T1558"]}]
        self.assertEqual(next(i for i in content.library(st)["items"] if i["id"] == "identity-kerberoasting")["coverage_status"], "enabled")

    def test_library_filters_and_facets(self):
        st = {"rules": [], "usecases": [], "planned": {}, "signals": None}
        allv = content.library(st)
        self.assertGreaterEqual(allv["total"], 85)
        for f in ("category", "tactic", "platform", "data_source", "coverage", "framework"):
            self.assertTrue(allv["facets"][f], f)
        self.assertTrue(all(i["category"] == "cloud" for i in content.library(st, filters={"category": "cloud"})["items"]))
        self.assertTrue(all("Credential Access" in i["tactics"] for i in content.library(st, filters={"tactic": "Credential Access"})["items"]))
        self.assertTrue(content.library(st, filters={"tactic": "credential-access"})["items"])
        self.assertTrue(all("ai-gateway" in i["data_sources"] for i in content.library(st, filters={"data_source": "ai-gateway"})["items"]))
        self.assertTrue(all("atlas" in i["frameworks"] for i in content.library(st, filters={"framework": "atlas"})["items"]))
        self.assertEqual([i["id"] for i in content.library(st, filters={"q": "kerberoast"})["items"]][:1], ["identity-kerberoasting"])
        self.assertEqual(content.library(st, filters={"status": "enabled"})["shown"], 0)
        self.assertIn("never counted", content.library(st)["coverage_note"])

    def test_controls_come_from_mitre_with_nist_and_atlas_gets_classes_but_no_invented_nist(self):
        ctrls = content.controls_for(["T1059.001"], C)
        self.assertTrue(ctrls)
        mapped = [x for x in ctrls if x["mapped"]]
        self.assertTrue(mapped and all(x["nist"] for x in mapped))
        self.assertTrue(all(x["id"].startswith("M") for x in ctrls))
        atlas = content.controls_for(["AML.T0051"], C)
        self.assertTrue(atlas)
        self.assertTrue(all(x["id"].startswith("AML.M") for x in atlas))
        self.assertTrue(all(x["nist"] == [] and "no NIST mapping" in x["nist_note"] for x in atlas))
        self.assertTrue(any(x["class"] == "ai-guardrails" for x in atlas))
        self.assertEqual(all(x["status"] == "suggested" for x in atlas), True)
        with open(content.ATLAS_CONTROLS_PATH, encoding="utf-8") as fh:
            mit = yaml.safe_load(fh)["mitigations"]
        self.assertEqual(set(mit), set(C.atlas_mitigations))        # every ATLAS mitigation is covered, none invented

    def test_promote_use_case_rule_and_control_land_as_drafts(self):
        r = content.promote("use-case", {"scenario_id": "cloud-disabled-logging"}, "a", self.e, C)
        self.assertEqual((r["status"], r["counted_as_coverage"]), ("proposed", False))
        self.assertEqual(usecase_store.get("ootb-cloud-disabled-logging", self.e)["status"], "proposed")
        self.assertTrue(content.promote("use-case", {"scenario_id": "cloud-disabled-logging"}, "a", self.e, C)["already_existed"])
        usecase_store.set_status("ootb-cloud-disabled-logging", "accepted", "engineer will build it", "a", self.e)
        content.promote("use-case", {"scenario_id": "cloud-disabled-logging"}, "a", self.e, C)
        self.assertEqual(usecase_store.get("ootb-cloud-disabled-logging", self.e)["status"], "accepted")      # a recorded decision is never overwritten
        rr = content.promote("rule", {"scenario_id": "sys-lolbin-proxy-execution", "lead_index": 0}, "a", self.e, C)
        self.assertFalse(rr["enabled"])
        from remediation.hunting import detection
        rules = detection.list_rules(self.e)
        self.assertEqual([x["enabled"] for x in rules], [False])
        self.assertEqual(usecases.covered_techniques(rules), set())            # a disabled rule is not coverage
        with self.assertRaises(content.PromoteError):
            content.promote("rule", {"scenario_id": "net-beaconing", "lead_index": 0}, "a", self.e, C)     # no single-event Sigma for it
        c = content.promote("control", {"control_id": "AML.M0029", "scenario_id": "ai-mcp-tool-abuse"}, "a", self.e, C)
        self.assertEqual((c["status"], c["is_implemented"]), ("planned", False))
        self.assertEqual(kstore.get_planned("control:AML.M0029", self.e)["is_implemented"], False)
        from remediation.controls import store as controls_store
        self.assertEqual(controls_store.list_controls(engine=self.e), [])      # nothing entered the controls inventory
        for bad in ({"kind": "use-case", "args": {"scenario_id": "nope"}}, {"kind": "control", "args": {"control_id": "M0000"}}, {"kind": "banana", "args": {}}):
            with self.assertRaises(content.PromoteError):
                content.promote(bad["kind"], bad["args"], "a", self.e, C)

    def test_scenario_content_has_rules_controls_use_case_and_response(self):
        sc = content.scenario_content(scenarios.get("identity-dcsync"), C)
        self.assertTrue(sc["rules"] and sc["controls"] and sc["use_case"]["sigma"])
        self.assertEqual(sc["use_case"]["key"], "ootb-identity-dcsync")
        self.assertIn("steps", sc["response"]["definition"])
        self.assertIn("Quanta does not contain", sc["response"]["note"])


class ReportTests(unittest.TestCase):
    def ctx(self, **kw):
        return ctx(findings=[fnd(1)], intel=[report_row()], rules=[rule()], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg(), **kw)

    def test_each_subject_kind_has_the_full_package(self):
        for kind, sid in (("technique", "T1558.003"), ("group", "G0016"), ("software", "S0154"), ("scenario", "net-beaconing"), ("tactic", "credential-access"), ("atlas-technique", "AML.T0051")):
            r = report.build(kind, sid, self.ctx())
            for key in ("subject", "hypothesis", "techniques", "scenarios", "intel", "frameworks", "data_readiness", "leads", "expected_evidence", "what_a_hit_means", "containment", "recommendations",
                        "execution_plan", "limits"):
                self.assertIn(key, r, (kind, key))
            self.assertTrue(r["hypothesis"]["statement"].startswith("If "), kind)
            self.assertTrue(r["leads"], kind)
            self.assertTrue(r["execution_plan"][0]["phase"] == "prepare")
            self.assertFalse(r["ran_anything"])
            self.assertEqual(set(r["frameworks"]), {"diamond", "kill_chain", "attack", "unified_kill_chain", "peak", "maturity"})
            self.assertTrue(report.to_markdown(r).startswith("# Hunt report:"))
            self.assertIn("<html", report.to_html(r).lower())
            self.assertEqual(r["languages"], ["sigma", "splunk-spl", "kql", "eql"])

    def test_report_text_is_honest_about_what_it_did_not_do(self):
        r = report.build("group", "APT29", self.ctx())
        self.assertEqual(r["frameworks"]["diamond"]["vertices"]["adversary"]["status"], "named-by-intel")      # the stored report names it
        r = report.build("group", "APT29", ctx(findings=[], intel=[], rules=[rule()], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg()))
        self.assertIn("Nothing was run", r["limits"][0])
        md = report.to_markdown(r)
        self.assertIn("Built without running anything", md)
        self.assertIn("recommendations for a person", r["containment"]["note"].lower().replace("recommendations for a person to decide and carry out.", "recommendations for a person"))
        self.assertEqual(r["frameworks"]["diamond"]["vertices"]["adversary"]["status"], "hypothesised")
        self.assertTrue(report.build("group", "APT29", self.ctx())["intel"][0]["why_relevant"])

    def test_leads_come_in_each_language_with_honest_statuses(self):
        r = report.build("scenario", "net-beaconing", self.ctx())
        lead = r["leads"][0]
        self.assertEqual(set(lead["languages"]), {"sigma", "splunk-spl", "kql", "eql"})
        self.assertEqual(lead["languages"]["sigma"]["status"], "not-expressible")
        t = report.build("technique", "T1059.001", self.ctx())
        self.assertTrue(any(l["languages"]["sigma"]["status"] == "provided" for l in t["leads"]))
        # a technique with neither a scenario lead nor a library entry says so instead of inventing a query
        x = report.build("technique", "T1087.004", self.ctx())
        self.assertTrue(any("No ready-made lead exists" in s for s in x["limits"]) or x["leads"])

    def test_scope_and_lookback_are_validated_and_carried(self):
        r = report.build("technique", "T1059.001", self.ctx(), 45, {"assets": ["WEB-1", "bad;rm -rf"], "identities": ["a@x.com"]})
        self.assertEqual(r["lookback_days"], 45)
        self.assertEqual(r["scope"]["assets"], ["WEB-1"])
        self.assertIn("WEB-1", r["hypothesis"]["statement"])
        self.assertEqual(r["frameworks"]["diamond"]["vertices"]["victim"]["status"], "scoped")
        for bad in (0, 9999):
            with self.assertRaises(report.SubjectError):
                report.build("technique", "T1059.001", self.ctx(), bad)

    def test_bad_subjects_and_mismatched_kinds_are_refused(self):
        for kind, sid in (("technique", "T0000"), ("group", "Nobody"), ("software", "S0000"), ("scenario", "none"), ("tactic", "nope"), ("banana", "x"), ("technique", ""), ("technique", "AML.T0051"), ("atlas-technique", "T1059")):
            with self.assertRaises(report.SubjectError, msg=(kind, sid)):
                report.build(kind, sid, self.ctx())

    def test_an_old_technique_id_resolves_to_its_successor(self):
        r = report.build("technique", "T1562.001", self.ctx())
        self.assertEqual(r["subject"]["id"], "T1685")
        self.assertEqual(r["subject"]["given_as"], "T1562.001")

    def test_estate_overlay_and_coverage_on_techniques(self):
        f = fnd(1, tech=({"technique_id": "T1190", "technique_name": "x", "tactic": "Initial Access"},))
        c = ctx(findings=[f], intel=[], rules=[rule(techniques=("T1059",))], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg())
        t = report.build("technique", "T1059.001", c)["techniques"][0]
        self.assertTrue(t["covered"])
        t2 = report.build("technique", "T1190", c)["techniques"][0]
        self.assertFalse(t2["covered"])
        self.assertEqual(t2["in_estate"]["findings"], 1)
        c0 = ctx(findings=[], intel=[], rules=[], connections=[], alerts=[], hunts=[], usecases=[], cfg=cfg())
        self.assertIsNone(report.build("technique", "T1190", c0)["techniques"][0]["covered"])      # unknown, never "covered"

    def test_create_hunt_goes_through_the_accept_flow_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            e = create_engine(f"sqlite:///{Path(d) / 't.db'}")
            db_module.ensure_schema(e)
            c = self.ctx()
            r = report.build("technique", "T1059.001", c)
            out = report.create_hunt(r, c, "admin@t", e)
            hunt = hunt_store.get_hunt(out["hunt_id"], e)
            self.assertEqual(hunt["status"], "proposed")
            self.assertEqual(hunt["source"], "hypothesis")
            self.assertTrue(hunt["queries"] and all(q["result"] is None for q in hunt["queries"]))
            self.assertEqual(engine_store.get(out["suggestion"]["id"], e)["status"], "accepted")
            e.dispose()


if __name__ == "__main__":
    unittest.main()
