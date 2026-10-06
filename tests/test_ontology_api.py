"""/api/ontology*: who may call what, the shapes returned, and that a bad pattern is a 400 and never a crash."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_appsec_api import ApiBase  # noqa: E402


class OntologyApiTests(ApiBase):
    def test_the_vocabulary_and_the_question_list_are_readable_without_login(self):
        self.client.cookies.clear()
        r = self.client.get("/api/ontology")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(set(d), {"version", "classes", "relations", "mappings"})
        self.assertIn("Asset", {c["id"] for c in d["classes"]})
        self.assertIn("depends-on", {x["id"] for x in d["relations"]})
        q = self.client.get("/api/ontology/questions")
        self.assertEqual(q.status_code, 200)
        self.assertTrue(all(x["text"] and not x.get("error") for x in q.json()["questions"]))

    def test_validate_and_query_need_an_administrator(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/ontology/validate").status_code, 401)
        self.assertEqual(self.client.post("/api/ontology/query", json={"question": "findings-on-unowned-assets"}).status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/ontology/validate").status_code, 403)
        self.assertEqual(self.client.post("/api/ontology/query", json={"question": "findings-on-unowned-assets"}).status_code, 403)
        self.login("admin@t.local")
        self.assertEqual(self.client.get("/api/ontology/validate").status_code, 200)

    def test_validate_reports_every_module_and_the_estate(self):
        self.login("admin@t.local")
        d = self.client.get("/api/ontology/validate").json()
        self.assertEqual(set(d["modules"]), {"soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin"})
        self.assertIn("estate", d)
        self.assertTrue(d["conforms"], {m: r["violations"][:2] for m, r in d["modules"].items() if not r["conforms"]})
        self.assertEqual(set(d["provenance"]), {"facts", "with_any", "per_field", "by_source_kind", "by_confidence"})
        one = self.client.get("/api/ontology/validate?module=infra").json()
        self.assertEqual(set(one["modules"]), {"infra"})
        self.assertEqual(self.client.get("/api/ontology/validate?module=nope").status_code, 404)

    def test_a_named_question_runs_over_the_estate(self):
        self.login("admin@t.local")
        r = self.client.post("/api/ontology/query", json={"question": "kev-through-dependency-chain"})
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["question"]["id"], "kev-through-dependency-chain")
        self.assertIn("count", d)
        self.assertIn("stages", d)
        if not d["count"]:
            self.assertTrue(d["reason"])

    def test_a_structured_pattern_runs_and_finds_the_seeded_findings(self):
        self.login("admin@t.local")
        body = {"pattern": {"start": {"class": "Finding", "where": [{"attr": "severity", "op": "eq", "value": "critical"}]},
                            "steps": [{"relation": "instance-of", "to": {"class": "Vulnerability", "where": [{"attr": "kev", "op": "eq", "value": True}]}}]}}
        r = self.client.post("/api/ontology/query", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["count"], 1)
        self.assertEqual(d["paths"][0]["nodes"][-1]["label"], "CVE-2021-44228")
        self.assertEqual(d["text"], "Finding(severity = critical) -instance-of-> Vulnerability(kev = true)")

    def test_a_bad_request_is_a_400_with_the_reason(self):
        self.login("admin@t.local")
        for body, fragment in (({"pattern": {"start": {"class": "Nope"}}}, "unknown class"),
                               ({"pattern": {"start": {"class": "Asset"}, "steps": [], "exec": "x"}}, "unknown field"),
                               ({"pattern": {"start": {"class": "Asset"}, "steps": [{"relation": "affects", "to": {"class": "Finding"}}]}}, "cannot go from"),
                               ({}, "exactly one"),
                               ({"pattern": {"start": {"class": "Asset"}}, "question": "x"}, "exactly one")):
            r = self.client.post("/api/ontology/query", json=body)
            self.assertEqual(r.status_code, 400, (body, r.text))
            self.assertIn(fragment, r.json()["detail"])

    def test_free_text_is_not_a_pattern(self):
        self.login("admin@t.local")
        self.assertEqual(self.client.post("/api/ontology/query", json={"pattern": "Asset-reaches->Asset"}).status_code, 422)
        self.assertEqual(self.client.post("/api/ontology/query", json={"question": "x" * 200}).status_code, 422)

    def test_an_unknown_question_is_a_404(self):
        self.login("admin@t.local")
        self.assertEqual(self.client.post("/api/ontology/query", json={"question": "no-such-question"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
