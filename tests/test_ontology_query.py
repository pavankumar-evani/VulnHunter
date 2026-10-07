"""The multi-hop query engine and the named questions, on the small hand-built estate in ontology_fixtures.py."""
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import ontology_fixtures as fx  # noqa: E402
from remediation.ontology import query  # noqa: E402

G = fx.estate_graph()


def labels(path):
    return [n["id"] for n in path["nodes"]]


def pat(start, *steps, **kw):
    return {"start": start, "steps": list(steps), **kw}


def step(relation, to, **kw):
    return {"relation": relation, "to": to, **kw}


class PathTests(unittest.TestCase):
    def test_a_typed_chain_returns_the_expected_path_with_provenance(self):
        res = query.run(G, pat({"class": "Application"},
                               step("depends-on", {"class": "Component"}, repeat="star"),
                               step("exploits", {"class": "Vulnerability", "where": [{"attr": "kev", "op": "eq", "value": True}]}, direction="in")))
        self.assertEqual(res["count"], 1)
        p = res["paths"][0]
        self.assertEqual(labels(p), ["devsecops/app:orders", "pkg:maven:org.apache.logging.log4j:log4j-core", "cve:CVE-A"])
        self.assertEqual([e["relation"] for e in p["edges"]], ["depends-on", "exploits"])
        self.assertEqual(p["edges"][0]["fact"]["source"], "SBOM (ci)")
        self.assertEqual(p["edges"][0]["fact"]["observed_at"], "2026-10-01T10:00:00Z")
        self.assertEqual(p["edges"][1]["fact"]["confidence"], "heuristic")
        self.assertEqual(p["edges_without_provenance"], 0)
        self.assertEqual(p["nodes"][0]["origin"], [{"module": "devsecops", "id": "app:orders"}])

    def test_provenance_can_be_left_out(self):
        res = query.run(G, pat({"class": "Team"}, step("owns", {"class": "Asset"}), provenance=False))
        self.assertNotIn("fact", res["paths"][0]["edges"][0])

    def test_unknown_provenance_is_reported_as_unknown(self):
        res = query.run(G, pat({"class": "AIAsset"}, step("invokes", {"class": "Tool"})))
        self.assertFalse(res["paths"][0]["edges"][0]["fact"]["known"])
        self.assertEqual(res["paths"][0]["edges_without_provenance"], 1)

    def test_a_relation_also_follows_its_special_cases(self):
        # fw-edge reaches nothing directly, but routes-to is a kind of reaches: the hop reaches web-01
        res = query.run(G, pat({"class": "NetworkNode"}, step("reaches", {"class": "Asset"})))
        self.assertEqual([labels(p) for p in res["paths"]], [["infra/hop:fw-edge", "asset:web-01"]])

    def test_star_includes_zero_hops_and_plus_does_not(self):
        start = {"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "web-01"}]}
        star = query.run(G, pat(start, step("reaches", {"class": "Asset"}, repeat="star")))
        plus = query.run(G, pat(start, step("reaches", {"class": "Asset"}, repeat="plus")))
        self.assertEqual(sorted(labels(p)[-1] for p in star["paths"]), ["asset:db-01", "asset:web-01"])
        self.assertEqual([labels(p) for p in plus["paths"]], [["asset:web-01", "asset:db-01"]])

    def test_max_depth_limits_a_repeated_step(self):
        # internet -> fw-edge -> web-01 -> db-01 is three hops
        start = {"class": "Internet"}
        one = query.run(G, pat(start, step("reaches", {"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "db-01"}]}, repeat="plus", max_depth=2)))
        three = query.run(G, pat(start, step("reaches", {"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "db-01"}]}, repeat="plus", max_depth=3)))
        self.assertEqual((one["count"], three["count"]), (0, 1))
        self.assertEqual(labels(three["paths"][0]), ["infra/internet", "infra/hop:fw-edge", "asset:web-01", "asset:db-01"])

    def test_direction_in_and_the_inverse_name_are_the_same_walk(self):
        a = query.run(G, pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "web-01"}]}, step("owns", {"class": "Team"}, direction="in")))
        b = query.run(G, pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "web-01"}]}, step("owned-by", {"class": "Team"})))
        self.assertEqual([labels(p) for p in a["paths"]], [["asset:web-01", "team:platform"]])
        self.assertEqual([labels(p) for p in b["paths"]], [labels(p) for p in a["paths"]])

    def test_a_class_matches_its_subclasses(self):
        res = query.run(G, pat({"class": "Asset"}, step("invokes", {"class": "Tool"})))     # the AI system is an Asset (AIAsset is-a Asset)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["paths"][0]["nodes"][0]["class"], "AIAsset")
        res = query.run(G, pat({"class": "AIAsset", "where": [{"attr": "reviewed", "op": "eq", "value": False}]}, step("invokes", {"class": "Tool"})))
        self.assertEqual(res["count"], 0)

    def test_paths_do_not_revisit_a_node(self):
        g = copy.deepcopy(G)
        g["edges"].append({"source": "asset:db-01", "target": "asset:web-01", "kind": "reaches", "label": None, "weight": 1})
        res = query.run(g, pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "web-01"}]}, step("reaches", {"class": "Asset"}, repeat="plus")))
        self.assertEqual([labels(p) for p in res["paths"]], [["asset:web-01", "asset:db-01"]])

    def test_a_single_node_pattern_works(self):
        res = query.run(G, pat({"class": "Finding", "where": [{"attr": "severity", "op": "eq", "value": "critical"}]}))
        self.assertEqual([labels(p) for p in res["paths"]], [["finding:F1"]])

    def test_results_are_deterministic(self):
        p = pat({"class": "Finding"}, step("affects", {"class": "Asset"}))
        self.assertEqual(query.run(G, p), query.run(G, p))


class FilterTests(unittest.TestCase):
    def count(self, where, cls="Finding"):
        return query.run(G, pat({"class": cls, "where": where}))["count"]

    def test_the_operators(self):
        self.assertEqual(self.count([{"attr": "severity", "op": "in", "value": ["critical", "low"]}]), 2)
        self.assertEqual(self.count([{"attr": "epss", "op": "ge", "value": 0.5}, {"attr": "severity", "op": "ne", "value": "high"}]), 1)
        self.assertEqual(self.count([{"attr": "label", "op": "contains", "value": "FINDING 2"}]), 1)
        self.assertEqual(self.count([{"attr": "epss", "op": "lt", "value": 0.4}]), 0)
        self.assertEqual(self.count([{"attr": "kev", "op": "exists", "value": True}]), 2)
        self.assertEqual(self.count([{"attr": "kev", "op": "exists", "value": False}]), 1)

    def test_an_unrecorded_attribute_satisfies_no_condition_not_even_ne(self):
        # F3 has no CVE, so kev is unknown: neither "kev = false" nor "kev != true" may pick it
        self.assertEqual(self.count([{"attr": "kev", "op": "eq", "value": False}]), 1)
        self.assertEqual(self.count([{"attr": "kev", "op": "ne", "value": True}]), 1)

    def test_a_regex_in_contains_is_just_text(self):
        self.assertEqual(self.count([{"attr": "label", "op": "contains", "value": "Finding .*"}]), 0)
        self.assertEqual(self.count([{"attr": "label", "op": "contains", "value": ".*"}]), 0)


class CapTests(unittest.TestCase):
    def test_depth_steps_limit_and_where_caps_are_refused(self):
        s = {"class": "Asset"}
        with self.assertRaises(query.QueryError):
            query.parse(pat(s, step("reaches", s, repeat="star", max_depth=query.LIMITS["max_depth"] + 1)))
        with self.assertRaises(query.QueryError):
            query.parse(pat(s, *[step("reaches", s)] * (query.LIMITS["max_steps"] + 1)))
        with self.assertRaises(query.QueryError):
            query.parse(pat(s, limit=query.LIMITS["max_limit"] + 1))
        with self.assertRaises(query.QueryError):
            query.parse(pat(s, limit=0))
        with self.assertRaises(query.QueryError):
            query.parse(pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "x"}] * (query.LIMITS["max_where"] + 1)}))
        with self.assertRaises(query.QueryError):
            query.parse(pat({"class": "Asset", "where": [{"attr": "label", "op": "in", "value": ["x"] * (query.LIMITS["max_in"] + 1)}]}))
        with self.assertRaises(query.QueryError):
            query.parse(pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "x" * (query.LIMITS["max_text"] + 1)}]}))

    def test_the_result_limit_truncates_and_says_so(self):
        res = query.run(G, pat({"class": "Thing"}, limit=3))
        self.assertEqual(res["count"], 3)
        self.assertTrue(res["truncated"])
        self.assertIn("first 3", res["note"])

    def test_the_work_budget_stops_a_runaway_search(self):
        with patch.dict(query.LIMITS, {"work_budget": 5}):
            res = query.run(G, pat({"class": "Thing"}, step("affects", {"class": "Thing"}, direction="in"), step("affects", {"class": "Thing"})))
        self.assertTrue(res["truncated"])
        self.assertIn("stopped", res["note"])

    def test_partial_path_cap(self):
        with patch.dict(query.LIMITS, {"max_partial_paths": 2}):
            res = query.run(G, pat({"class": "Thing"}, step("affects", {"class": "Thing"}, direction="in")))
        self.assertTrue(res["truncated"])
        self.assertIn("partial paths", res["note"])


class RejectionTests(unittest.TestCase):
    def bad(self, p, fragment=None):
        with self.assertRaises(query.QueryError) as cm:
            query.run(G, p)
        if fragment:
            self.assertIn(fragment, str(cm.exception))

    def test_unknown_class_relation_attribute_and_operator(self):
        self.bad(pat({"class": "Nope"}), "unknown class")
        self.bad(pat({"class": "Asset"}, step("befriends", {"class": "Asset"})), "unknown relation")
        self.bad(pat({"class": "Asset", "where": [{"attr": "colour", "op": "eq", "value": "x"}]}), "no attribute")
        self.bad(pat({"class": "Asset", "where": [{"attr": "label", "op": "matches", "value": "x"}]}), "op must be")

    def test_values_must_fit_the_declared_type(self):
        self.bad(pat({"class": "Asset", "where": [{"attr": "internet_facing", "op": "eq", "value": "yes"}]}), "true or false")
        self.bad(pat({"class": "Asset", "where": [{"attr": "verified_controls", "op": "gt", "value": "1"}]}), "number")
        self.bad(pat({"class": "Finding", "where": [{"attr": "severity", "op": "eq", "value": "catastrophic"}]}), "one of")
        self.bad(pat({"class": "Asset", "where": [{"attr": "internet_facing", "op": "contains", "value": "t"}]}), "text attribute")

    def test_an_ontologically_impossible_hop_is_refused_before_running(self):
        self.bad(pat({"class": "Asset"}, step("affects", {"class": "Finding"})), "cannot go from Asset to Finding")
        self.bad(pat({"class": "Alert"}, step("owns", {"class": "Asset"}, repeat="star")), "cannot start")
        self.bad(pat({"class": "Asset"}, step("affects", {"class": "Finding"}, repeat="star", direction="in")), "cannot be repeated")

    def test_injection_shaped_input_is_inert(self):
        for value in ("__import__('os').system('x')", "{{7*7}}", "'; DROP TABLE x; --", "${jndi:ldap://x}", "<script>alert(1)</script>"):
            self.bad(pat({"class": value}), "unknown class")
            self.bad(pat({"class": "Asset", "where": [{"attr": value, "op": "eq", "value": "x"}]}), "no attribute")
            self.bad(pat({"class": "Asset"}, step(value, {"class": "Asset"})), "unknown relation")
            self.bad(pat({"class": "Asset", "where": [{"attr": "label", "op": value, "value": "x"}]}), "op must be")
        res = query.run(G, pat({"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "__import__('os').system('x')"}]}))
        self.assertEqual(res["count"], 0)       # as a value it is only text compared for equality

    def test_unknown_keys_and_wrong_shapes_are_refused(self):
        self.bad({"start": {"class": "Asset"}, "steps": [], "exec": "1"}, "unknown field")
        self.bad({"start": {"class": "Asset", "script": "x"}}, "unknown field")
        self.bad(pat({"class": "Asset"}, {"relation": "reaches", "to": {"class": "Asset"}, "callback": "x"}), "unknown field")
        self.bad("Asset-reaches->Asset", "must be an object")
        self.bad(["Asset"], "must be an object")
        self.bad({"steps": []}, "start is required")
        self.bad({"start": {"class": "Asset"}, "steps": "reaches"}, "list")
        self.bad(pat({"class": "Asset"}, step("reaches", {"class": "Asset"}, direction="sideways")), "direction")
        self.bad(pat({"class": "Asset"}, step("reaches", {"class": "Asset"}, repeat="forever")), "repeat")
        self.bad(pat({"class": "Asset"}, step("reaches", {"class": "Asset"}, max_depth=3)), "star and plus only")
        self.bad(pat({"class": "Asset"}, limit="all"), "limit")
        self.bad(pat({"class": ""}), "non-empty")
        self.bad(pat({"class": 5}), "non-empty")

    def test_the_query_never_changes_the_graph(self):
        before = copy.deepcopy(G)
        query.run(G, pat({"class": "Asset"}, step("affects", {"class": "Finding"}, direction="in")))
        self.assertEqual(G, before)


class EmptyResultTests(unittest.TestCase):
    def test_no_nodes_of_the_class(self):
        res = query.run(G, pat({"class": "Playbook"}))
        self.assertEqual(res["count"], 0)
        self.assertIn("no Playbook nodes", res["reason"])

    def test_an_attribute_nobody_records_says_so(self):
        res = query.run(G, pat({"class": "Tool", "where": [{"attr": "side_effects", "op": "eq", "value": "write"}]}))
        self.assertEqual(res["count"], 0)
        self.assertIn("none of the 1 Tool nodes records side_effects", res["reason"])
        self.assertIn("does not hold that fact", res["reason"])

    def test_a_recorded_attribute_that_never_matches(self):
        res = query.run(G, pat({"class": "Vulnerability", "where": [{"attr": "epss", "op": "gt", "value": 0.99}]}))
        self.assertIn("2 of 2 Vulnerability nodes record epss, none satisfies", res["reason"])

    def test_a_step_with_no_links_at_all(self):
        res = query.run(G, pat({"class": "Alert"}, step("involves", {"class": "Asset"})))
        self.assertIn("no Alert nodes", res["reason"])
        res = query.run(G, pat({"class": "Application"}, step("calls", {"class": "Application"})))
        self.assertIn("no calls links are recorded", res["reason"])

    def test_candidates_exist_but_nothing_links_to_them(self):
        res = query.run(G, pat({"class": "Team"}, step("owns", {"class": "Asset", "where": [{"attr": "label", "op": "eq", "value": "db-01"}]})))
        self.assertEqual(res["count"], 0)
        self.assertIn("1 Asset nodes match, but none is linked", res["reason"])

    def test_the_stages_show_where_the_search_narrowed(self):
        res = query.run(G, pat({"class": "Asset"}, step("affects", {"class": "Finding"}, direction="in")))
        self.assertEqual([s["matched"] for s in res["stages"]], [3, 3])

    def test_an_empty_estate_gives_an_honest_empty_result(self):
        res = query.run({"module": "estate", "nodes": [], "edges": [], "note": "Nothing is recorded yet."}, pat({"class": "Asset"}))
        self.assertEqual(res["count"], 0)
        self.assertIn("no Asset nodes", res["reason"])
        self.assertEqual(res["estate"]["note"], "Nothing is recorded yet.")


class QuestionTests(unittest.TestCase):
    def test_every_shipped_question_parses_against_the_ontology(self):
        qs = query.load_questions()
        self.assertGreaterEqual(len(qs), 4)
        for q in qs:
            self.assertIsNone(q.get("error"), q["id"])
            self.assertTrue(q["text"])
            self.assertTrue(q["limits"], f"{q['id']} must state its honest limits")

    def test_internet_facing_kev_with_no_verified_control(self):
        res = query.run_question(G, "internet-facing-kev-no-control")
        self.assertEqual(res["count"], 1)
        # web-01 is exposed (through fw-edge), has no verified control and carries F1 for the KEV-listed CVE-A
        self.assertEqual(labels(res["paths"][0]), ["asset:web-01", "finding:F1", "cve:CVE-A"])
        self.assertEqual(res["question"]["id"], "internet-facing-kev-no-control")

    def test_a_verified_control_takes_the_asset_out_of_the_answer(self):
        g = fx.estate_graph(controls=[{"id": 9, "asset_name": "web-*", "control_class": "edr", "name": "EDR", "state": "verified", "source": "s", "last_seen": "2026-10-01T00:00:00Z"}])
        self.assertEqual(query.run_question(g, "internet-facing-kev-no-control")["count"], 0)

    def test_no_controls_inventory_means_unknown_not_none(self):
        g = fx.estate_graph(controls=None)
        res = query.run_question(g, "internet-facing-kev-no-control")
        self.assertEqual(res["count"], 0)
        self.assertIn("verified_controls", res["reason"])

    def test_findings_on_assets_with_no_owner(self):
        res = query.run_question(G, "findings-on-unowned-assets")
        self.assertEqual([labels(p) for p in res["paths"]], [["finding:F2", "asset:db-01"]])

    def test_kev_through_the_dependency_chain(self):
        res = query.run_question(G, "kev-through-dependency-chain")
        self.assertEqual([labels(p)[0] for p in res["paths"]], ["devsecops/app:orders"])

    def test_the_ai_question_is_empty_with_the_reason_because_quanta_holds_no_side_effect_data(self):
        res = query.run_question(G, "ai-write-tools-from-untrusted-data")
        self.assertEqual(res["count"], 0)
        self.assertIn("side_effects", res["reason"])

    def test_the_ai_question_answers_when_a_record_carries_the_facts(self):
        g = copy.deepcopy(G)
        for n in g["nodes"]:
            if n["id"] == "ai/tool:shell":
                n["meta"]["side_effects"] = "write"
            if n["id"] == "ai/data-source:web":
                n["meta"]["trust"] = "untrusted"
        res = query.run_question(g, "ai-write-tools-from-untrusted-data")
        self.assertEqual([labels(p) for p in res["paths"]], [["ai/tool:shell", "ai/system:bot", "ai/data-source:web"]])

    def test_an_unknown_question(self):
        with self.assertRaises(KeyError):
            query.run_question(G, "nope")

    def test_a_question_the_ontology_no_longer_fits_is_listed_with_its_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "q.yaml"
            p.write_text("questions:\n  - id: stale\n    title: t\n    pattern:\n      start: {class: Gone}\n", encoding="utf-8")
            qs = query.load_questions(p)
            self.assertIn("unknown class", qs[0]["error"])
            with self.assertRaises(query.QueryError):
                query.run_question(G, "stale", path=p)
            p.write_text("questions:\n  - id: a\n  - id: a\n", encoding="utf-8")
            with self.assertRaises(Exception):
                query.load_questions(p)


class ExplainTests(unittest.TestCase):
    def test_a_pattern_reads_as_one_line(self):
        p = query.parse(pat({"class": "Asset", "where": [{"attr": "internet_facing", "op": "eq", "value": True}]},
                            step("runs", {"class": "Application"}),
                            step("depends-on", {"class": "Component"}, repeat="star"),
                            step("exploits", {"class": "Vulnerability", "where": [{"attr": "kev", "op": "eq", "value": True}]}, direction="in")))
        self.assertEqual(query.explain(p), "Asset(internet_facing = true) -runs-> Application -depends-on*-> Component <-exploits- Vulnerability(kev = true)")


if __name__ == "__main__":
    unittest.main()
