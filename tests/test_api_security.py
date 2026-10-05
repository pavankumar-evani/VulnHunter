"""
Tests for API security: spec and log intake, the inventory and its drift, your classification framework, the OWASP API Top 10 rules with their evidence and requests,
caller activity, metrics, runtime protection policies (versions, approval, signed send, alerts, edge results, WAF artifacts), the CI gate, the rollout checklist, and
the routes. No network: HTTP is replaced by fakes.
"""
import base64
import datetime
import hashlib
import hmac
import json
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
from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.apisec import cicd, classify, generate, identity, logs, metrics, openapi, paths, policies, rollout, rules, store, waf  # noqa: E402
from remediation.connections import registry  # noqa: E402
from remediation.connectors import webhook_connector as wh  # noqa: E402
from remediation.guidance import engine as guidance  # noqa: E402
from remediation.ingest import api_findings  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)
PUBLIC = "34.120.5.9"
SPEC = """openapi: 3.0.0
info: {title: Shop API, version: "1.0"}
servers: [{url: "https://shop.example.com/v1"}]
components:
  securitySchemes: {b: {type: http, scheme: bearer}}
  schemas:
    User: {type: object, properties: {id: {type: string}, name: {type: string}}}
security: [{b: []}]
paths:
  /users/{userId}:
    get:
      parameters: [{name: userId, in: path, required: true}]
      responses: {"200": {content: {application/json: {schema: {$ref: "#/components/schemas/User"}}}}}
  /orders:
    post:
      requestBody: {content: {application/json: {schema: {type: object, properties: {item: {type: string}}}}}}
      responses: {"201": {description: created}}
  /health:
    get: {security: [], responses: {"200": {description: ok}}}
  /legacy/report:
    get: {deprecated: true, responses: {"200": {description: ok}}}
"""


def rec(method="GET", path="/v1/users/1", **kw):
    r = {"method": method, "path": path, "host": "shop.example.com", "status": 200, "ip": PUBLIC, "auth": "bearer", "scheme": "https", "user": "u1", "responseLatency": 10}
    r.update(kw)
    return logs.normalise(r)


def jwt(header, claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc(header)}.{enc(claims)}.sig"


class PathTests(unittest.TestCase):
    def test_identifiers_become_parameters(self):
        self.assertEqual(paths.key_of("/users/123/orders"), "/users/{}/orders")
        self.assertEqual(paths.key_of("/users/{userId}/orders"), "/users/{}/orders")
        self.assertEqual(paths.key_of("/items/9f1c2e7a-1b2c-4d5e-8f90-a1b2c3d4e5f6"), "/items/{}")
        self.assertEqual(paths.key_of("/me"), "/me")
        self.assertEqual(paths.key_of("/v1/health"), "/v1/health")

    def test_spec_templates_win_over_the_heuristic(self):
        key, ids = paths.resolve("/users/me", {"/users/{}"})
        self.assertEqual((key, ids), ("/users/{}", ["me"]))
        self.assertEqual(paths.resolve("/users/42", set())[0], "/users/{}")

    def test_url_split_keeps_only_parameter_names(self):
        self.assertEqual(paths.split_url("https://x.io/a/b?api_key=SECRET&n=1"), ("/a/b", ["api_key", "n"]))

    def test_object_id_detection(self):
        self.assertTrue(paths.has_object_id("/users/{}"))
        self.assertTrue(paths.has_object_id("/search", ["user_id"]))
        self.assertFalse(paths.has_object_id("/search", ["valid", "paid"]))


class OpenApiTests(unittest.TestCase):
    def test_parses_operations_auth_and_base_path(self):
        p = openapi.parse(SPEC)
        eps = {(e["method"], e["path"]): e for e in p["endpoints"]}
        self.assertEqual(p["hosts"], ["shop.example.com"])
        self.assertIn(("GET", "/v1/users/{userId}"), eps)
        self.assertEqual(eps[("GET", "/v1/users/{userId}")]["auth"], ["bearer"])
        self.assertEqual(eps[("GET", "/v1/users/{userId}")]["response_fields"], ["id", "name"])
        self.assertEqual(eps[("GET", "/v1/health")]["auth_state"], "none")  # declared open is not the same as silent
        self.assertEqual(eps[("POST", "/v1/orders")]["request_fields"], ["item"])
        self.assertTrue(eps[("GET", "/v1/legacy/report")]["deprecated"])

    def test_silent_spec_is_unspecified_and_json_works(self):
        p = openapi.parse(json.dumps({"openapi": "3.0.0", "info": {"title": "x", "version": "1"}, "paths": {"/a": {"get": {"responses": {}}}}}))
        self.assertEqual(p["endpoints"][0]["auth_state"], "unspecified")

    def test_swagger_two(self):
        p = openapi.parse(json.dumps({"swagger": "2.0", "host": "api.x.io", "basePath": "/v2", "schemes": ["http"], "paths": {"/a": {"get": {"responses": {"200": {"schema": {"properties": {"k": {}}}}}}}}}))
        self.assertEqual(p["plain_http_servers"], ["http://api.x.io/v2"])
        self.assertEqual(p["endpoints"][0]["path"], "/v2/a")

    def test_rejects_non_specs_and_alias_bombs(self):
        for bad in ("hello", "{}", json.dumps({"openapi": "3.0.0"}), "a: [1"):
            with self.assertRaises(openapi.SpecError):
                openapi.parse(bad)
        with self.assertRaises(openapi.SpecError):
            openapi.parse("x: &a [1]\n" + "\n".join(f"y{i}: *a" for i in range(150)))


class LogTests(unittest.TestCase):
    def test_json_lines_gateway_style(self):
        recs, st = logs.parse('{"httpMethod":"GET","resourcePath":"/v1/users/7?token=abc","status":"200","responseLatency":12,"ip":"34.1.1.1","user":"u1","responseLength":512}\n{"nope":1}')
        r = recs[0]
        self.assertEqual((r["method"], r["path"], r["query_params"], r["status"], r["latency_ms"], r["bytes_out"], r["actor"]), ("GET", "/v1/users/7", ["token"], 200, 12.0, 512, "u1"))
        self.assertEqual((st["format"], st["skipped"]), ("jsonl", 1))

    def test_common_log_format_and_csv_and_array(self):
        r, st = logs.parse('1.2.3.4 - bob [10/Oct/2023:13:55:36 +0000] "POST /a/1 HTTP/1.1" 500 512 "-" "curl"')
        self.assertEqual((st["format"], r[0]["actor"], r[0]["status"], r[0]["ts"].year), ("clf", "bob", 500, 2023))
        r, st = logs.parse("method,path,status,request_time\nGET,/x/1,200,0.25")
        self.assertEqual((st["format"], r[0]["latency_ms"]), ("csv", 250.0))  # nginx request_time is seconds
        r, st = logs.parse(json.dumps({"records": [{"method": "GET", "path": "/a"}]}))
        self.assertEqual(st["format"], "json")

    def test_query_values_and_tokens_are_never_kept(self):
        tok = jwt({"alg": "none"}, {"exp": 2000000000, "iat": 1999990000})
        r = logs.normalise({"method": "GET", "path": "/a?api_key=SECRETVALUE", "authorization": "Bearer " + tok})
        self.assertNotIn("SECRETVALUE", json.dumps({k: v for k, v in r.items() if k != "ts"}, default=str))
        self.assertNotIn(tok, json.dumps({k: v for k, v in r.items() if k != "ts"}, default=str))
        self.assertEqual((r["auth"], r["jwt"]["alg"], r["jwt"]["lifetime_hours"]), ("bearer", "none", round(10000 / 3600, 2)))

    def test_auth_is_none_only_on_explicit_evidence(self):
        self.assertIsNone(logs.normalise({"method": "GET", "path": "/a"})["auth"])
        self.assertEqual(logs.normalise({"method": "GET", "path": "/a", "authorization": ""})["auth"], "none")
        self.assertEqual(logs.normalise({"method": "GET", "path": "/a", "auth": "anonymous"})["auth"], "none")

    def test_empty_and_unreadable_inputs(self):
        for bad in ("", "   ", "garbage\nmore garbage"):
            with self.assertRaises(logs.LogError):
                logs.parse(bad)

    def test_sampled_values_are_classified_then_dropped(self):
        r = logs.normalise({"method": "GET", "path": "/a", "response_sample": {"contact": "a@b.co", "pay": "4111 1111 1111 1111", "n": "x"}})
        self.assertEqual(r["detected"], {"email": 1, "payment-card": 1})
        self.assertNotIn("4111", json.dumps(r, default=str))

    def test_security_events_from_waf_fields(self):
        self.assertTrue(logs.normalise({"method": "GET", "path": "/a", "waf_action": "BLOCK"})["security_event"])
        self.assertFalse(logs.normalise({"method": "GET", "path": "/a", "waf_action": "allow"})["security_event"])


class ClassifyTests(unittest.TestCase):
    def test_field_and_value_detectors(self):
        f = classify.detect_fields(["ip_address", "userEmail", "first_name", "token_type", "access_token"])
        self.assertEqual(sorted(f), ["credential", "email", "ip-address", "person-name"])
        self.assertTrue(classify.luhn_ok("4111 1111 1111 1111"))
        self.assertFalse(classify.luhn_ok("4111 1111 1111 1112"))
        self.assertIn("payment-card", classify.detect_value("4111111111111111"))
        self.assertNotIn("payment-card", classify.detect_value("4111111111111112"))

    def test_framework_json_csv_and_validation(self):
        c = classify.parse_framework("name,priority,description,detectors,field_patterns\nRestricted,1,top,payment-card;national-id,loyaltyid\nInternal,3,,email,")
        self.assertEqual([(x["name"], x["priority"]) for x in c], [("Restricted", 1), ("Internal", 3)])
        self.assertEqual(c[0]["field_patterns"], ["loyaltyid"])
        for bad in ('name,priority\nA,x', 'name,priority,detectors\nA,1,not-a-detector', 'name,priority\nA,1\nA,2', '{"classes": []}', "name,priority\nA,0"):
            with self.assertRaises(ValueError):
                classify.parse_framework(bad)

    def test_unmapped_data_is_unclassified_not_assumed(self):
        cl = classify.parse_framework("name,priority,detectors\nRestricted,1,payment-card")
        a = classify.assess_data({"email": 3, "payment-card": 1}, ["loyalty_id"], cl)
        self.assertEqual([c["name"] for c in a["classes"]], ["Restricted"])
        self.assertEqual(a["unclassified"], ["email"])
        self.assertEqual(classify.assess_data({"email": 3}, [], [])["top_priority"], None)

    def test_customers_own_field_patterns_classify_their_data(self):
        cl = classify.parse_framework("name,priority,field_patterns\nTier1,1,loyaltyid")
        self.assertEqual(classify.assess_data({}, ["loyalty_id"], cl)["classes"][0]["name"], "Tier1")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def ingest(self, records, **kw):
        return store.ingest_records(records, engine=self.e, today=TODAY, **kw)

    def test_spec_then_traffic_documents_and_shadows(self):
        out = store.import_spec(SPEC, None, "upload", "a@t", engine=self.e)
        self.assertEqual((out["service"], out["operations"], out["added"]), ("shop-api", 4, 4))
        self.ingest([rec(path="/v1/users/5"), rec(path="/v1/users/6"), rec(path="/v1/secret/dump")], default_service="shop-api")
        d = store.drift("shop-api", self.e)
        self.assertEqual([s["template"] for s in d["shadow"]], ["/v1/secret/dump"])
        self.assertEqual(sorted(x["template"] for x in d["documented_never_seen"]), ["/v1/health", "/v1/legacy/report", "/v1/orders"])
        users = next(e for e in store.list_endpoints(self.e) if e["template"] == "/v1/users/{userId}")
        self.assertEqual((users["in_spec"], users["observed"], users["calls_total"]), (True, True, 2))

    def test_traffic_first_then_spec_merges_under_the_spec_service(self):
        self.ingest([rec(path="/v1/users/5"), rec(path="/v1/users/6")])  # service falls back to the host
        self.assertEqual({e["service"] for e in store.list_endpoints(self.e)}, {"shop.example.com"})
        store.import_spec(SPEC, None, "upload", "a@t", engine=self.e)
        eps = store.list_endpoints(self.e)
        self.assertEqual({e["service"] for e in eps}, {"shop-api"})
        users = next(e for e in eps if e["template"] == "/v1/users/{userId}")
        self.assertEqual((users["in_spec"], users["calls_total"]), (True, 2))
        self.assertEqual(len(store.metrics_rows(self.e)), 1)

    def test_a_second_import_adds_not_replaces(self):
        self.ingest([rec(path="/v1/users/5")])
        self.ingest([rec(path="/v1/users/6", status=500)])
        rows = store.metrics_rows(self.e)
        self.assertEqual((rows[0]["calls"], rows[0]["errors"], rows[0]["exceptions"]), (2, 1, 1))

    def test_metrics_actors_and_distinct_objects(self):
        self.ingest([rec(path=f"/v1/users/{i}", user="scraper") for i in range(1, 31)] + [rec(path="/v1/users/1", user="other")])
        rows = {r["actor"]: r for r in store.actor_rows(engine=self.e)}
        self.assertEqual((rows["scraper"]["calls"], rows["scraper"]["distinct_objects"], rows["other"]["distinct_objects"]), (30, 30, 1))

    def test_actor_handling_hash_hides_identity(self):
        with patch.dict(store.config.load()["thresholds"], {"actor_handling": "hash"}):
            self.ingest([rec(user="alice@example.com")])
        actors = [r["actor"] for r in store.actor_rows(engine=self.e)]
        self.assertTrue(actors[0].startswith("h:"))
        self.assertNotIn("alice", actors[0])

    def test_exposure_and_unauth_evidence_are_observed(self):
        self.ingest([rec(path="/v1/orders", method="POST", auth="none", ip="10.0.0.5"), rec(path="/v1/orders", method="POST", auth="none", status=401, ip=PUBLIC)])
        o = store.list_endpoints(self.e)[0]["obs"]
        self.assertEqual((o["unauth_success"], o["internal_calls"], o["external_calls"]), (1, 1, 1))

    def test_a_spec_replaces_the_previous_one_and_unmarks_removed_operations(self):
        store.import_spec(SPEC, "shop", "upload", "a", engine=self.e)
        smaller = SPEC.split("  /orders:")[0] + "  /health:\n    get: {security: [], responses: {\"200\": {description: ok}}}\n"
        out = store.import_spec(smaller, "shop", "upload", "a", engine=self.e)
        self.assertEqual(out["removed_from_spec"], 2)
        self.assertEqual(len(store.list_specs(self.e)), 1)

    def test_endpoint_attributes(self):
        self.ingest([rec()])
        eid = store.list_endpoints(self.e)[0]["id"]
        ep = store.update_endpoint(eid, owner="team-a", exposure="partner", status="accepted-risk", fields={"owner", "exposure", "status"}, engine=self.e)
        self.assertEqual((ep["owner"], ep["exposure_override"], ep["status"]), ("team-a", "partner", "accepted-risk"))
        with self.assertRaises(ValueError):
            store.update_endpoint(eid, exposure="moon", fields={"exposure"}, engine=self.e)
        with self.assertRaises(KeyError):
            store.update_endpoint(999, owner="x", fields={"owner"}, engine=self.e)

    def test_framework_import_replace_and_clear(self):
        store.import_classes("name,priority,detectors\nA,1,email", "a", engine=self.e)
        store.import_classes("name,priority,detectors\nB,2,phone", "a", engine=self.e)
        self.assertEqual([c["name"] for c in store.list_classes(self.e)], ["B"])
        store.import_classes("name,priority,detectors\nC,1,email", "a", replace=False, engine=self.e)
        self.assertEqual([c["name"] for c in store.list_classes(self.e)], ["C", "B"])
        self.assertEqual(store.clear_classes(self.e), 2)


class RuleTests(unittest.TestCase):
    """Each OWASP API rule: what makes it fire, what keeps it quiet, and that every finding carries evidence."""

    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def fresh(self):
        self.e = create_engine("sqlite:///:memory:")

    def run_rules(self, records, spec=SPEC, classes="", policy_list=(), service="shop-api", deps=None):
        if spec:
            store.import_spec(spec, service, "upload", "a", engine=self.e)
        if records:
            store.ingest_records(records, default_service=service, engine=self.e, today=TODAY)
        if classes:
            store.import_classes(classes, "a", engine=self.e)
        views, findings, gaps = rules.run(store.list_endpoints(self.e), store.list_specs(self.e), store.list_classes(self.e), store.actor_rows(engine=self.e),
                                          deps if deps is not None else store.dependencies(self.e), list(policy_list), TODAY)
        return views, findings, gaps

    def by_rule(self, findings, rule):
        return [f for f in findings if f["rule"] == rule]

    def test_every_finding_has_an_evidence_chain_and_a_fix(self):
        _, findings, _ = self.run_rules([rec(path="/v1/hidden", auth="none")])
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f["evidence"] and f["fix"] and f["owasp"] == rules.OWASP[f["rule"]])
            self.assertTrue(all(e["step"] and e["source"] and e["detail"] for e in f["evidence"]))

    def test_api1_object_enumeration_needs_many_ids_from_one_caller(self):
        many = [rec(path=f"/v1/users/{i}", user="scraper") for i in range(1, 61)]
        _, findings, _ = self.run_rules(many)
        f = self.by_rule(findings, "API1:2023")[0]
        self.assertIn("scraper", " ".join(e["detail"] for e in f["evidence"]))
        self.assertTrue(f["request"]["testable"])
        self.assertIn("${OTHER_USERS_OBJECT_ID}", f["request"]["command"])
        self.assertIn("${TOKEN}", f["request"]["command"])
        few = [rec(path=f"/v1/users/{i}", user=f"u{i}") for i in range(1, 61)]
        self.fresh()
        self.assertEqual(self.by_rule(self.run_rules(few)[1], "API1:2023"), [])  # many ids, but many different callers

    def test_api2_unauthenticated_success_but_not_on_a_public_path(self):
        _, findings, _ = self.run_rules([rec(method="POST", path="/v1/orders", auth="none"), rec(path="/v1/health", auth="none")])
        titles = [f["title"] for f in self.by_rule(findings, "API2:2023")]
        self.assertEqual(titles, ["Unauthenticated access to POST /v1/orders"])
        f = self.by_rule(findings, "API2:2023")[0]
        self.assertFalse(f["request"]["command"].count("Authorization"))  # the confirming request carries no credentials

    def test_api2_unauthenticated_failures_do_not_count_as_open(self):
        _, findings, _ = self.run_rules([rec(method="POST", path="/v1/orders", auth="none", status=401)])
        self.assertEqual(self.by_rule(findings, "API2:2023"), [])

    def test_api2_jwt_weaknesses(self):
        none_tok = "Bearer " + jwt({"alg": "none"}, {"sub": "x"})
        _, findings, _ = self.run_rules([rec(path="/v1/orders", method="POST", authorization=none_tok)])
        sev = {f["title"].split(" on ")[0]: f["severity"] for f in self.by_rule(findings, "API2:2023")}
        self.assertEqual(sev["Unsigned tokens accepted"], "Critical")  # the request that carried alg none succeeded
        self.assertIn("Tokens without an expiry used", sev)
        long_tok = "Bearer " + jwt({"alg": "RS256", "jku": "http://x"}, {"exp": 2000000000, "iat": 1900000000, "aud": "a"})
        _, f2, _ = self.run_rules([rec(path="/v1/orders", method="POST", authorization=long_tok)], spec=None)
        t = [f["title"] for f in self.by_rule(f2, "API2:2023")]
        self.assertTrue(any("Long-lived" in x for x in t) and any("key location" in x for x in t))

    def test_api2_credential_in_url(self):
        _, findings, _ = self.run_rules([rec(path="/v1/orders?api_key=ABC")])
        self.assertTrue(any("Credential in the URL" in f["title"] for f in self.by_rule(findings, "API2:2023")))

    def test_api3_undeclared_sensitive_properties(self):
        r = rec(path="/v1/users/9", response_fields=["id", "name", "ssn", "email"])
        _, findings, _ = self.run_rules([r])
        f = self.by_rule(findings, "API3:2023")[0]
        self.assertIn("ssn", f["evidence"][0]["detail"])
        self.assertNotIn("name", f["evidence"][0]["detail"].split("specification: ")[1])  # declared fields are not reported
        self.fresh()
        self.assertEqual(self.by_rule(self.run_rules([rec(path="/v1/users/9", response_fields=["id", "name"])])[1], "API3:2023"), [])

    def test_api3_mass_assignment_candidates(self):
        _, findings, _ = self.run_rules([rec(method="POST", path="/v1/orders", request_fields=["item", "role", "is_admin"])])
        f = [x for x in self.by_rule(findings, "API3:2023") if "mass assignment" in x["title"]][0]
        self.assertIn("is_admin", f["evidence"][0]["detail"])
        self.assertIn("role", f["request"]["command"])

    def test_api4_dominant_caller_without_a_rate_limit_policy(self):
        records = [rec(path="/v1/users/1", user="bot") for _ in range(120)] + [rec(path="/v1/users/1", user="human") for _ in range(10)]
        _, findings, _ = self.run_rules(records)
        self.assertTrue(self.by_rule(findings, "API4:2023"))
        pol = policies.save({"name": "rl", "kind": "rate-limit", "params": {"limit": 100, "window_seconds": 60, "by": "ip"}}, "a", engine=self.e)
        _, covered, _ = self.run_rules([], spec=None, policy_list=[pol])
        self.assertEqual(self.by_rule(covered, "API4:2023"), [])  # an enabled rate-limit policy covers it

    def test_api4_large_responses_without_paging(self):
        records = [rec(path="/v1/users/1", bytes_out=9_000_000, user=f"u{i}") for i in range(60)]
        _, findings, _ = self.run_rules(records)
        self.assertTrue(any("Large responses" in f["title"] for f in self.by_rule(findings, "API4:2023")))
        records = [rec(path="/v1/users/1?limit=10", bytes_out=9_000_000, user=f"u{i}") for i in range(60)]
        self.assertFalse(any("Large responses" in f["title"] for f in self.by_rule(self.run_rules(records)[1], "API4:2023")))

    def test_api5_admin_paths_reachable_from_outside(self):
        _, findings, _ = self.run_rules([rec(method="DELETE", path="/v1/admin/users/4")])
        f = self.by_rule(findings, "API5:2023")[0]
        self.assertEqual(f["severity"], "Critical")
        self.fresh()
        internal = self.run_rules([rec(method="DELETE", path="/v1/admin/users/4", ip="10.0.0.1")], spec=None)[1]
        self.assertEqual(self.by_rule(internal, "API5:2023"), [])

    def test_api6_sensitive_flow_automation(self):
        records = [rec(method="POST", path="/v1/login", user="stuffer") for _ in range(1100)]
        _, findings, _ = self.run_rules(records)
        self.assertTrue(self.by_rule(findings, "API6:2023"))

    def test_api7_url_parameters(self):
        _, findings, _ = self.run_rules([rec(path="/v1/fetch?url=http://x")])
        f = self.by_rule(findings, "API7:2023")[0]
        self.assertIn("url", f["evidence"][0]["detail"])
        self.assertIn("url=VALUE", f["request"]["command"])

    def test_api8_plain_http(self):
        _, findings, _ = self.run_rules([rec(scheme="http")])
        self.assertTrue(self.by_rule(findings, "API8:2023"))

    def test_api9_shadow_and_zombie_and_the_no_spec_gap(self):
        _, findings, gaps = self.run_rules([rec(path="/v1/secret/dump"), rec(path="/v1/legacy/report")])
        titles = [f["title"] for f in self.by_rule(findings, "API9:2023")]
        self.assertIn("Shadow endpoint GET /v1/secret/dump", titles)
        self.assertTrue(any(t.startswith("Deprecated endpoint still in use") for t in titles))
        self.fresh()
        _, nospec, gaps2 = self.run_rules([rec(path="/v1/anything")], spec=None, service="other")
        self.assertEqual(self.by_rule(nospec, "API9:2023"), [])  # without a spec nothing can be called shadow
        self.assertIn("no-specification", [g["kind"] for g in gaps2])

    def test_accepted_risk_silences_the_finding_it_covers(self):
        self.run_rules([rec(path="/v1/secret/dump")])
        eid = next(e["id"] for e in store.list_endpoints(self.e) if "secret" in e["template"])
        store.update_endpoint(eid, status="accepted-risk", fields={"status"}, engine=self.e)
        _, findings, _ = self.run_rules([], spec=None)
        self.assertEqual([f for f in self.by_rule(findings, "API9:2023") if "secret" in f["title"]], [])

    def test_api10_third_party_dependency_with_sensitive_data(self):
        cl = "name,priority,detectors\nRestricted,1,email"
        records = [rec(path="/v1/users/1", response_sample={"mail": "a@b.co"}, source_service="shop-api", dest_exposure="third-party")]
        _, findings, _ = self.run_rules(records, classes=cl)
        deps = [{"source_service": "shop-api", "dest_service": "pay.vendor.io", "dest_exposure": "third-party", "calls": 5, "last_seen": "2026-10-01"}]
        _, f2, _ = self.run_rules([], spec=None, classes=cl, deps=deps)
        self.assertTrue(self.by_rule(f2, "API10:2023"))

    def test_severity_is_lifted_by_your_framework_not_by_ours(self):
        base = [rec(path="/v1/things/1", auth="none", response_sample={"mail": "a@b.co"})]
        title = "Unauthenticated access to GET /v1/things/{id}"
        plain = {f["title"]: f["severity"] for f in self.run_rules(base)[1]}[title]
        self.fresh()
        lifted = {f["title"]: f["severity"] for f in self.run_rules(base, classes="name,priority,detectors\nRestricted,1,email")[1]}[title]
        self.assertEqual((plain, lifted), ("High", "Critical"))

    def test_unclassified_data_is_a_gap_not_a_finding(self):
        _, findings, gaps = self.run_rules([rec(path="/v1/users/1", response_sample={"mail": "a@b.co"})])
        self.assertIn("unclassified-data", [g["kind"] for g in gaps])

    def test_queue_items_are_valid_dast_findings(self):
        _, findings, _ = self.run_rules([rec(path="/v1/secret/dump", auth="none", method="POST")])
        items = rules.to_queue_items(findings, store.list_specs(self.e))
        good, errors = api_findings.normalise_batch(items)
        self.assertEqual(errors, [])
        self.assertTrue(all(g["scan_type"] == "dast" and g["asset"]["type"] == "application" and g["rule_id"] in rules.OWASP for g in good))
        self.assertIn("Evidence chain:", good[0]["description"])

    def test_curl_never_emits_unsafe_path_characters(self):
        v = {"service": "shop-api", "method": "GET", "template": "/v1/$(touch pwned)/x", "path_key": "/v1/x"}
        self.assertIsNone(rules.curl(v, []))
        v["template"] = "/v1/a`b`/x"
        self.assertIsNone(rules.curl(v, []))
        ok = rules.curl({"service": "shop.example.com", "method": "GET", "template": "/v1/users/{id}/orders/{orderId}", "path_key": "x"}, [])
        self.assertIn('"https://shop.example.com/v1/users/${OBJECT_ID}/orders/${ORDERID}"', ok["command"])

    def test_findings_get_curated_guidance_by_rule_id(self):
        _, findings, _ = self.run_rules([rec(method="POST", path="/v1/orders", auth="none")])
        item = rules.to_queue_items(findings, store.list_specs(self.e))[0]
        item["asset"] = {"name": item["asset"]["name"], "type": "application"}
        g = guidance.build({**item, "id": "F-1"}, client_controls=False)
        self.assertTrue(g["curated"])
        self.assertTrue(g["id"].startswith("api-"))
        self.assertIn("rule API", g["matched_by"])

    def test_every_owasp_category_has_curated_guidance(self):
        for rid in rules.OWASP:
            g = guidance.build({"title": "x", "description": "y", "rule_id": rid, "scan_type": "dast", "asset": {"name": "a", "type": "application"}}, client_controls=False)
            self.assertTrue(g["curated"] and rid.split(":")[0].lower() in g["title"].lower().replace("(", "").replace(")", "") + " " + g["id"] or g["curated"], rid)
            self.assertTrue(g["steps"] and g["verify"], rid)


class MetricsTests(unittest.TestCase):
    def rows(self, per_day):
        out = []
        for d, calls, errors, lat in per_day:
            out.append({"endpoint_id": 1, "day": d, "calls": calls, "errors": errors, "exceptions": 0, "latency_sum_ms": lat * calls, "latency_n": calls, "latency_max_ms": lat * 2,
                        "bytes_in": 0, "bytes_out": 0, "security_events": 0})
        return out

    def test_error_rate_is_errors_over_calls_and_never_stored(self):
        s = metrics.series(self.rows([("2026-10-14", 200, 10, 50)]))[0]
        self.assertEqual((s["error_rate"], s["avg_latency_ms"], s["max_latency_ms"]), (0.05, 50.0, 100.0))
        self.assertIsNone(metrics.rate(0, 0))
        self.assertNotIn("error_rate", [c.name for c in db_module.api_metrics.columns])

    def test_trend_flags_and_too_little_data(self):
        prev = [(f"2026-10-0{d}", 100, 1, 50) for d in range(2, 9)]
        recent = [(f"2026-10-{d}", 250, 40, 120) for d in range(9, 16)]
        t = metrics.trend(self.rows(prev + recent), TODAY)
        self.assertEqual({f["metric"] for f in t["flags"]}, {"calls", "error rate", "average latency"})
        quiet = metrics.trend(self.rows([("2026-10-14", 10, 0, 5)]), TODAY)
        self.assertEqual(quiet["flags"], [])
        self.assertIn("Too few calls", quiet["note"])

    def test_overview_counts_distinct_callers_once(self):
        eps = [{"id": 1, "service": "s", "method": "GET", "template": "/a"}]
        actors = [{"endpoint_id": 1, "day": "2026-10-14", "actor": "u1"}, {"endpoint_id": 1, "day": "2026-10-15", "actor": "u1"}, {"endpoint_id": 1, "day": "2026-10-15", "actor": "u2"}]
        o = metrics.overview(eps, self.rows([("2026-10-14", 100, 0, 5), ("2026-10-15", 100, 0, 5)]), actors, days=30, today=TODAY)
        self.assertEqual(o["endpoints"][0]["distinct_actors"], 2)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        store.import_spec(SPEC, "shop-api", "upload", "a", engine=self.e)
        store.import_classes("name,priority,detectors\nRestricted,1,email", "a", engine=self.e)
        records = [rec(path=f"/v1/users/{i}", user="scraper", bytes_out=600_000, response_sample={"mail": "a@b.co"}) for i in range(1, 101)]
        records += [rec(path="/v1/users/1", user="calm")]
        store.ingest_records(records, default_service="shop-api", engine=self.e, today=TODAY)
        eps, specs, cl = store.list_endpoints(self.e), store.list_specs(self.e), store.list_classes(self.e)
        self.actors = store.actor_rows(engine=self.e)
        views, _, _ = rules.run(eps, specs, cl, self.actors, [], [], TODAY)
        self.byid = {v["id"]: v for v in views}

    def test_listing_ranks_by_indicators(self):
        lst = identity.listing(self.actors, self.byid)
        self.assertEqual(lst[0]["actor"], "scraper")
        self.assertIn("enumeration", lst[0]["indicators"])
        self.assertEqual(next(x for x in lst if x["actor"] == "calm")["indicators"], ["sensitive"])  # reached Restricted data, but no volume, enumeration or exfiltration

    def test_investigation_joins_identity_to_endpoints_and_your_classes(self):
        inv = identity.investigate("scraper", self.actors, self.byid)
        self.assertEqual(inv["calls"], 100)
        self.assertEqual(inv["data_classes"], [{"name": "Restricted", "priority": 1}])
        types = {i["type"] for i in inv["indicators"]}
        self.assertTrue({"enumeration", "sensitive"} <= types)
        self.assertEqual(inv["endpoints"][0]["data_classes"], ["Restricted"])
        self.assertIsNone(identity.investigate("nobody", self.actors, self.byid))

    def test_drafts_are_monitor_mode_and_valid_policies(self):
        inv = identity.investigate("scraper", self.actors, self.byid)
        self.assertTrue(inv["suggested_policies"])
        for d in inv["suggested_policies"]:
            self.assertEqual(d["mode"], "monitor")
            policies.clean(d, classes=store.list_classes(self.e))  # a draft must pass the same validation as a saved policy

    def test_exfiltration_threshold(self):
        big = [{"endpoint_id": 1, "day": "2026-10-14", "actor": "x", "calls": 10, "errors": 0, "bytes_out": 60_000_000, "distinct_objects": 1, "ips": []}]
        self.assertIn("exfiltration", {i["type"] for i in identity.indicators("x", big, {}, identity.config.load()["thresholds"])})


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def mk(self, **kw):
        d = {"name": "rl", "kind": "rate-limit", "params": {"limit": 100, "window_seconds": 60, "by": "ip"}}
        d.update(kw)
        return policies.save(d, "alice", engine=self.e)

    def test_defaults_to_monitor_and_validates_each_kind(self):
        self.assertEqual(self.mk()["mode"], "monitor")
        bad = [{"kind": "rate-limit", "params": {"limit": 1, "window_seconds": 60}}, {"kind": "rate-limit", "params": {"limit": 100, "window_seconds": 61}},
               {"kind": "rate-limit", "params": {"limit": 100, "window_seconds": 60, "by": "actor"}}, {"kind": "malicious-source", "params": {"cidrs": ["nope"]}},
               {"kind": "geo-restriction", "params": {"countries": ["USA"]}}, {"kind": "data-loss", "params": {"by": "actor", "window_seconds": 60}},
               {"kind": "custom-signature", "params": {"target": "body", "match": "regex", "pattern": "(?=x)"}}, {"kind": "custom-signature", "params": {"target": "body", "match": "regex", "pattern": "("}},
               {"kind": "custom-signature", "params": {"target": "header", "match": "contains", "pattern": "x"}}, {"kind": "weird", "params": {}}]
        for i, b in enumerate(bad):
            with self.assertRaises(policies.PolicyError, msg=str(b)):
                policies.save({"name": f"bad{i}", **b}, "a", engine=self.e)
        with self.assertRaises(policies.PolicyError):
            self.mk(name="")
        with self.assertRaises(policies.PolicyError):
            self.mk(scope={"endpoints": ["fetch /x"]})

    def test_data_class_must_be_one_of_yours(self):
        d = {"name": "dl", "kind": "data-loss", "params": {"by": "actor", "window_seconds": 3600, "max_records": 100, "data_class": "Restricted"}}
        with self.assertRaises(policies.PolicyError):
            policies.save(d, "a", classes=[{"name": "Other"}], engine=self.e)
        self.assertEqual(policies.save(d, "a", classes=[{"name": "Restricted"}], engine=self.e)["params"]["data_class"], "Restricted")

    def test_versions_events_and_pending_push(self):
        p = self.mk()
        self.assertEqual((p["version"], p["push_state"]), (1, "draft"))
        same = policies.save({"name": "rl", "kind": "rate-limit", "params": p["params"]}, "bob", policy_id=p["id"], engine=self.e)
        self.assertEqual(same["version"], 1)  # nothing changed, so no new version
        conn = FakeEndpoint()
        policies.send(p["id"], "alice", conn, engine=self.e)
        edited = policies.save({"name": "rl", "kind": "rate-limit", "mode": "monitor", "params": {"limit": 50, "window_seconds": 60, "by": "ip"}}, "bob", policy_id=p["id"], engine=self.e)
        self.assertEqual((edited["version"], edited["push_state"]), (2, "pending-push"))
        actions = [e["action"] for e in policies.events(p["id"], engine=self.e)]
        self.assertTrue({"created", "updated", "pushed"} <= set(actions))
        with self.assertRaises(policies.PolicyError):
            policies.save({"name": "rl", "kind": "geo-restriction", "params": {"countries": ["US"]}}, "a", policy_id=p["id"], engine=self.e)

    def test_block_needs_a_different_approver_for_that_exact_version(self):
        p = self.mk(mode="block")
        ok, why = policies.can_push(p)
        self.assertFalse(ok)
        self.assertIn("second administrator", why)
        with self.assertRaises(policies.PolicyError):
            policies.approve(p["id"], "alice", engine=self.e)  # the author cannot approve their own change
        approved = policies.approve(p["id"], "bob", engine=self.e)
        self.assertTrue(policies.can_push(approved)[0])
        edited = policies.save({"name": "rl", "kind": "rate-limit", "mode": "block", "params": {"limit": 20, "window_seconds": 60, "by": "ip"}}, "alice", policy_id=p["id"], engine=self.e)
        self.assertFalse(policies.can_push(edited)[0])  # any edit voids the approval
        with self.assertRaises(policies.PolicyError):
            policies.send(p["id"], "alice", FakeEndpoint(), engine=self.e)

    def test_monitor_mode_needs_no_approval(self):
        self.assertTrue(policies.can_push(self.mk())[0])

    def test_send_records_the_outcome_and_failure_is_not_lost(self):
        p = self.mk()
        ok = policies.send(p["id"], "alice", FakeEndpoint(), engine=self.e)
        self.assertEqual((ok["status"], ok["http_status"], ok["version"]), ("sent", 200, 1))
        self.assertEqual(len(ok["payload_sha256"]), 64)
        bad = policies.send(p["id"], "alice", FakeEndpoint(fail=True), engine=self.e)
        self.assertEqual(bad["status"], "failed")
        self.assertEqual(policies.get(p["id"], self.e)["push_state"], "failed")
        self.assertEqual(len(policies.pushes(p["id"], engine=self.e)), 2)

    def test_edge_result_is_reported_back_and_validated(self):
        p = self.mk()
        push = policies.send(p["id"], "alice", FakeEndpoint(), engine=self.e)
        done = policies.report_status(push["id"], "applied", "web ACL updated", "apikey:waf", engine=self.e)
        self.assertEqual((done["status"], done["reported_by"]), ("applied", "apikey:waf"))
        self.assertEqual(policies.get(p["id"], self.e)["push_state"], "applied")
        with self.assertRaises(policies.PolicyError):
            policies.report_status(push["id"], "great", "", "x", engine=self.e)
        with self.assertRaises(KeyError):
            policies.report_status(999, "applied", "", "x", engine=self.e)

    def test_alerts_go_to_every_channel_and_one_failing_does_not_stop_the_others(self):
        push = {"policy_name": "rl", "version": 3, "mode": "block", "status": "failed", "http_status": 502, "message": "bad gateway"}
        self.assertIn("FAILED", policies.alert_text(push))
        hook, mails = FakeNotify(), []
        out = policies.notify(push, hook, lambda to, s, b: mails.append((to, s, b)), ["soc@example.com"])
        self.assertEqual([(o["channel"], o["ok"]) for o in out], [("notification webhook", True), ("email", True)])
        self.assertIn("rl", hook.sent[0])
        broken = policies.notify(push, FakeNotify(fail=True), lambda *a: mails.append(a), ["soc@example.com"])
        self.assertEqual([o["ok"] for o in broken], [False, True])
        self.assertEqual(policies.notify(push, None, None, []), [])

    def test_scope_matching(self):
        p = self.mk(scope={"endpoints": ["GET /users/{id}", "* /admin/*"]})
        self.assertTrue(policies.covers(p, "s", "GET", "/users/{}"))
        self.assertFalse(policies.covers(p, "s", "POST", "/users/{}"))
        self.assertTrue(policies.covers(p, "s", "DELETE", "/admin/users/{}"))
        self.assertTrue(policies.covers(self.mk(name="all"), "s", "GET", "/anything"))
        self.assertTrue(policies.covers(self.mk(name="svc", scope={"services": ["shop"]}), "shop", "GET", "/x"))
        self.assertFalse(policies.covers(self.mk(name="svc2", scope={"services": ["shop"]}), "other", "GET", "/x"))

    def test_delete_is_audited(self):
        p = self.mk()
        self.assertTrue(policies.remove(p["id"], "alice", engine=self.e))
        self.assertIn("deleted", [e["action"] for e in policies.events(engine=self.e)])
        self.assertFalse(policies.remove(p["id"], "alice", engine=self.e))


class FakeEndpoint:
    def __init__(self, fail=False):
        self.fail, self.got = fail, []

    def push(self, payload):
        if self.fail:
            raise wh.WebhookError("The endpoint answered 502")
        self.got.append(payload)
        return {"status": 200}


class FakeNotify:
    def __init__(self, fail=False):
        self.fail, self.sent = fail, []

    def send(self, text):
        if self.fail:
            raise wh.WebhookError("down")
        self.sent.append(text)


class WafTests(unittest.TestCase):
    def pol(self, kind, params, mode="monitor", scope=None, **kw):
        return policies.clean({"name": "p", "kind": kind, "mode": mode, "params": params, "scope": scope or {}, **kw}) | {"id": 7, "version": 2, "enabled": True}

    def test_rate_limit_monitor_is_count_and_block_is_block(self):
        a = waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 300, "by": "ip"}, scope={"endpoints": ["GET /users/{id}"]}), "aws-waf")
        rule = a["artifact"]["rules"][0]
        self.assertEqual(rule["Action"], {"Count": {}})
        rb = rule["Statement"]["RateBasedStatement"]
        self.assertEqual((rb["Limit"], rb["EvaluationWindowSec"], rb["AggregateKeyType"]), (100, 300, "IP"))
        self.assertIn("^/users/[^/]+$", json.dumps(rb["ScopeDownStatement"]))
        blk = waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 60, "by": "ip"}, mode="block"), "aws-waf")["artifact"]["rules"][0]
        self.assertEqual(blk["Action"], {"Block": {}})

    def test_cloud_armor_preview_and_throttle(self):
        a = waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 60, "by": "ip"}), "cloud-armor")["artifact"]["rules"][0]
        self.assertTrue(a["preview"])
        self.assertEqual((a["action"], a["rateLimitOptions"]["rateLimitThreshold"]), ("throttle", {"count": 100, "intervalSec": 60}))
        self.assertFalse(waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 60, "by": "ip"}, mode="block"), "cloud-armor")["artifact"]["rules"][0]["preview"])

    def test_malicious_sources_become_ip_sets_and_split_rules(self):
        cidrs = [f"10.0.{i}.0/24" for i in range(25)] + ["2001:db8::/32"]
        aws = waf.generate(self.pol("malicious-source", {"cidrs": cidrs}), "aws-waf")["artifact"]
        self.assertEqual({r["IPAddressVersion"] for r in aws["resources"]}, {"IPV4", "IPV6"})
        self.assertEqual(len(waf.generate(self.pol("malicious-source", {"cidrs": cidrs}), "cloud-armor")["artifact"]["rules"]), 3)

    def test_geo_allow_only_is_negated(self):
        aws = waf.generate(self.pol("geo-restriction", {"countries": ["US", "DE"], "type": "allow-only"}), "aws-waf")["artifact"]["rules"][0]["Statement"]
        self.assertIn("NotStatement", aws)
        arm = waf.generate(self.pol("geo-restriction", {"countries": ["US"], "type": "deny"}), "cloud-armor")["artifact"]["rules"][0]
        self.assertIn("origin.region_code == 'US'", arm["match"]["expr"]["expression"])

    def test_signatures_and_quote_escaping(self):
        arm = waf.generate(self.pol("custom-signature", {"target": "header", "header_name": "User-Agent", "match": "contains", "pattern": "sql'map"}), "cloud-armor")["artifact"]["rules"][0]
        self.assertIn("request.headers['user-agent'].contains('sql\\'map')", arm["match"]["expr"]["expression"])
        body = waf.generate(self.pol("custom-signature", {"target": "body", "match": "contains", "pattern": "x"}), "cloud-armor")
        self.assertFalse(body["supported"])  # Cloud Armor custom rules cannot read bodies, and it says so
        self.assertTrue(waf.generate(self.pol("custom-signature", {"target": "body", "match": "contains", "pattern": "x"}), "aws-waf")["supported"])

    def test_data_loss_is_not_pretended_at_the_edge(self):
        for t in waf.TARGETS:
            r = waf.generate(self.pol("data-loss", {"by": "actor", "window_seconds": 3600, "max_records": 10}), t)
            self.assertFalse(r["supported"])
            self.assertIsNone(r["artifact"])
            self.assertIn("responses", " ".join(r["notes"]))

    def test_every_artifact_says_it_was_not_applied(self):
        r = waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 60, "by": "ip"}), "aws-waf")
        self.assertIn("Quanta has not applied it", " ".join(r["notes"]))
        with self.assertRaises(ValueError):
            waf.generate(self.pol("rate-limit", {"limit": 100, "window_seconds": 60, "by": "ip"}), "azure")


class ConnectorTests(unittest.TestCase):
    def test_policy_webhook_signs_like_the_response_webhook(self):
        calls = []

        class Sess:
            def post(self, url, data=None, headers=None, timeout=None):
                calls.append((url, data, headers))
                return type("R", (), {"status_code": 200})()
        c = wh.PolicyWebhook("https://edge.example.com/hook", "s3cret", session=Sess(), clock=lambda: 1_700_000_000)
        c.push({"type": "api-protection-policy", "delivery_id": "d-1", "policy": {"name": "p"}})
        url, body, h = calls[0]
        self.assertEqual(h["X-Quanta-Signature"], "sha256=" + hmac.new(b"s3cret", f"1700000000.{body}".encode(), hashlib.sha256).hexdigest())
        self.assertEqual((h["X-Quanta-Timestamp"], h["X-Quanta-Delivery"]), ("1700000000", "d-1"))
        with self.assertRaises(wh.WebhookError):
            c.push({"type": "something-else"})
        with self.assertRaises(ValueError):
            wh.PolicyWebhook("https://x", "")

    def test_an_error_status_raises(self):
        class Sess:
            def post(self, *a, **k):
                return type("R", (), {"status_code": 503})()
        with self.assertRaises(wh.WebhookError):
            wh.PolicyWebhook("https://x.example.com/h", "s", session=Sess()).push({"type": "api-protection-policy"})

    def test_registered_as_a_tool_connection_with_the_ssrf_guard(self):
        spec = registry.SPECS["api-policy-endpoint"]
        self.assertEqual(spec["kind"], "tool")
        with patch("remediation.connectors.url_safety.assert_safe_target"):
            cfg, sec = registry.split_values("api-policy-endpoint", {"url": "https://edge.example.com/h", "signing_secret": "s"})
        self.assertIsInstance(spec["build"]({**cfg, **sec}), wh.PolicyWebhook)
        with self.assertRaises(ValueError):
            registry.split_values("api-policy-endpoint", {"url": "http://169.254.169.254/x", "signing_secret": "s"})


class CicdTests(unittest.TestCase):
    def body(self, **kw):
        b = {"tool": "t", "repository": "org/shop-api", "results": [
            {"method": "GET", "path": "/users/{id}", "test": "bola", "owasp": "API1:2023", "status": "fail", "severity": "High", "evidence": "200 for other user", "curl": "curl -i x"},
            {"method": "POST", "path": "/login", "test": "rate", "owasp": "API4:2023", "status": "pass"},
            {"method": "GET", "path": "/x", "test": "info", "status": "fail", "severity": "Low"}]}
        b.update(kw)
        return b

    def test_gate_threshold(self):
        up = cicd.parse(self.body())
        g = cicd.gate(up["results"])
        self.assertEqual((g["passed"], g["blocking"], g["failed"], g["passed_tests"], g["fail_on"]), (False, 1, 2, 1, "High"))
        self.assertTrue(cicd.gate(up["results"], "Critical")["passed"])
        self.assertFalse(cicd.gate(up["results"], "low")["passed"])
        with self.assertRaises(ValueError):
            cicd.gate(up["results"], "urgent")

    def test_validation_reports_each_bad_result(self):
        up = cicd.parse(self.body(results=[{"method": "FETCH", "path": "/a", "status": "fail"}, {"method": "GET", "path": "a", "status": "fail"}, {"method": "GET", "path": "/a", "status": "meh"},
                                           {"method": "GET", "path": "/a", "status": "fail", "owasp": "API99:2023"}, {"method": "GET", "path": "/ok", "status": "pass"}]))
        self.assertEqual(len(up["results"]), 1)
        self.assertEqual([e["index"] for e in up["errors"]], [0, 1, 2, 3])
        for bad in ({"results": []}, {"repository": "r"}, "x"):
            with self.assertRaises(ValueError):
                cicd.parse(bad)

    def test_only_failures_become_findings_and_they_validate(self):
        up = cicd.parse(self.body())
        items = cicd.to_queue_items(up)
        self.assertEqual(len(items), 2)
        good, errors = api_findings.normalise_batch(items)
        self.assertEqual(errors, [])
        self.assertEqual(good[0]["asset"], {"name": "org/shop-api", "ip": None, "type": "code-repository", "os": None})
        self.assertIn("Request to reproduce", good[0]["description"])

    def test_control_characters_are_stripped_from_supplied_text(self):
        up = cicd.parse(self.body(results=[{"method": "GET", "path": "/a", "status": "fail", "evidence": "a\x00b\x1bc", "curl": "curl\x07 x"}]))
        self.assertNotRegex(up["results"][0]["evidence"] + up["results"][0]["curl"], r"[\x00-\x08\x1b]")

    def test_source_is_a_valid_per_repository_ingest_source(self):
        s = cicd.source_for("Org/Shop_API.git")
        self.assertEqual(api_findings.check_source(s), s)
        self.assertLessEqual(len(cicd.source_for("x" * 300)), 40)

    def test_templates_cover_both_ci_systems(self):
        self.assertTrue({"github-actions", "gitlab-ci", "spec-drift", "results-format"} <= set(cicd.TEMPLATES))
        for k in ("github-actions", "gitlab-ci"):
            self.assertIn("api-test-results", cicd.TEMPLATES[k])
            self.assertIn("gate.passed", cicd.TEMPLATES[k])
        json.loads(cicd.TEMPLATES["results-format"])


class GenerateAndRolloutTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_generated_spec_states_only_what_was_observed(self):
        store.ingest_records([rec(path="/v1/users/5?expand=x", response_fields=["id", "mail"], response_sample={"mail": "a@b.co"}), rec(method="POST", path="/v1/orders", auth="none", request_fields=["item"])],
                             engine=self.e, today=TODAY)
        store.import_classes("name,priority,detectors\nRestricted,1,email", "a", engine=self.e)
        doc = generate.build("shop.example.com", store.list_endpoints(self.e), store.list_classes(self.e))
        self.assertEqual(doc["openapi"], "3.0.3")
        op = doc["paths"]["/v1/users/{id}"]["get"]
        self.assertEqual(op["x-quanta-data-classes"], ["Restricted"])
        self.assertEqual([p["name"] for p in op["parameters"]], ["id", "expand"])
        self.assertEqual(op["security"], [{"bearer": []}])
        self.assertEqual(doc["paths"]["/v1/orders"]["post"]["security"], [])
        self.assertEqual(doc["components"]["securitySchemes"]["bearer"], {"type": "http", "scheme": "bearer"})
        self.assertIsNone(generate.build("nope", store.list_endpoints(self.e), []))
        self.assertTrue(openapi.parse(json.dumps(doc))["endpoints"])  # it is itself a readable specification

    def test_checklist_is_observed_where_it_can_be_and_stated_otherwise(self):
        facts, manual = rollout.gather(self.e)
        rb = rollout.build(facts, manual)
        by = {i["id"]: i for i in rb["items"]}
        self.assertFalse(by["spec"]["done"] or by["traffic"]["done"] or by["ci-results"]["done"])
        self.assertEqual((by["spec"]["basis"], by["architecture"]["basis"]), ("observed", "stated"))
        store.import_spec(SPEC, "shop-api", "upload", "a", engine=self.e)
        store.ingest_records([rec()], default_service="shop-api", engine=self.e, today=TODAY)
        apikeys.create("log shipper", ["api:write"], "a", engine=self.e)
        facts, manual = rollout.gather(self.e, owners_missing=0)
        by = {i["id"]: i for i in rollout.build(facts, manual)["items"]}
        self.assertTrue(by["spec"]["done"] and by["traffic"]["done"] and by["api-key"]["done"] and by["owners"]["done"])
        self.assertFalse(by["classification"]["done"] or by["map-data"]["done"])

    def test_stated_steps_are_ticked_by_hand_and_observed_ones_cannot_be(self):
        rollout.set_item("architecture", True, "agreed Tuesday", "alice", self.e)
        facts, manual = rollout.gather(self.e)
        item = next(i for i in rollout.build(facts, manual)["items"] if i["id"] == "architecture")
        self.assertEqual((item["done"], item["note"], item["set_by"]), (True, "agreed Tuesday", "alice"))
        with self.assertRaises(KeyError):
            rollout.set_item("spec", True, "", "alice", self.e)

    def test_two_tracks_order_the_phases_differently(self):
        facts, manual = rollout.gather(self.e)
        a = [p["phase"] for p in rollout.build(facts, manual, "runtime-first")["phases"]]
        b = [p["phase"] for p in rollout.build(facts, manual, "shift-left-first")["phases"]]
        self.assertLess(a.index("runtime"), a.index("shift-left"))
        self.assertLess(b.index("shift-left"), b.index("runtime"))

    def test_roles_and_the_honest_sso_note(self):
        rb = rollout.build(*rollout.gather(self.e))
        self.assertTrue({"SOC", "AppSec", "Developers", "API office"} <= {r["role"] for r in rb["roles"]})
        self.assertIn("never been run against a live identity provider", rb["sso_note"])


class FakeResp:
    def __init__(self, body=b"", status=200):
        self.status_code, self._b = status, body

    def iter_content(self, n):
        yield self._b


class ApiRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.merged = []
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.findings_merge, "merge", side_effect=lambda f, s, reconcile=False: self.merged.append((s, reconcile, len(f))) or {"added": len(f), "updated": 0, "removed": 0}),
                  patch.object(dashboard_app_module, "_enrich_in_background", lambda bg: None)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("admin2@t.local", PW, "Admin2", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        _, self.key = apikeys.create("shipper", ["api:write"], "admin@t.local", engine=self.engine)
        _, self.other_key = apikeys.create("ingest-only", ["ingest:write"], "admin@t.local", engine=self.engine)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email="admin@t.local"):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def auth(self, key=None):
        return {"Authorization": f"Bearer {key or self.key}"}

    def push_records(self, records, service="shop-api"):
        return self.client.post("/api/ingest/api-traffic", json={"service": service, "records": records}, headers=self.auth())

    def test_every_dashboard_route_is_admin_only(self):
        gets = ["overview", "endpoints", "specs", "findings", "callers", "classification", "metrics", "policies", "policy-log", "rollout", "ci-templates", "drift?service=x", "generated-spec?service=x"]
        for g in gets:
            self.assertEqual(self.client.get(f"/api/api-security/{g}").status_code, 401, g)
        self.login("user@t.local")
        for g in gets:
            self.assertEqual(self.client.get(f"/api/api-security/{g}").status_code, 403, g)
        self.assertEqual(self.client.post("/api/api-security/policies", json={"name": "x", "kind": "rate-limit"}).status_code, 403)
        self.assertEqual(self.client.post("/api/api-security/publish", json={"confirm": True}).status_code, 403)
        self.assertEqual(self.client.post("/api/api-security/specs", json={"content": SPEC}).status_code, 403)

    def test_machine_routes_need_a_key_with_the_right_scope(self):
        body = {"records": [{"method": "GET", "path": "/a"}]}
        self.assertEqual(self.client.post("/api/ingest/api-traffic", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/api-traffic", json=body, headers=self.auth(self.other_key)).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/openapi", content=SPEC, headers=self.auth(self.other_key)).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/api-test-results", json={}, headers=self.auth(self.other_key)).status_code, 401)
        self.assertEqual(self.client.post("/api/inbound/api-policy-status", json={"push_id": 1, "status": "applied"}).status_code, 401)
        self.assertEqual(self.push_records([{"method": "GET", "path": "/a"}]).status_code, 200)

    def test_spec_and_traffic_through_the_api_give_an_inventory_and_drift(self):
        r = self.client.post("/api/ingest/openapi?service=shop-api", content=SPEC, headers=self.auth())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["operations"], 4)
        t = self.push_records([{"method": "GET", "path": "/v1/users/3", "host": "shop.example.com", "client_ip": PUBLIC, "auth": "bearer", "user": "u"},
                               {"method": "GET", "path": "/v1/undocumented/thing", "host": "shop.example.com", "client_ip": PUBLIC, "auth": "none", "status": 200}, {"bad": 1}])
        self.assertEqual(t.status_code, 200, t.text)
        self.assertEqual(t.json()["read"], {"read": 3, "skipped": 1})
        self.assertEqual([s["template"] for s in t.json()["drift"]["shop-api"]["shadow"]], ["/v1/undocumented/thing"])
        self.login()
        ov = self.client.get("/api/api-security/overview").json()
        self.assertEqual((ov["summary"]["endpoints"], ov["summary"]["by_state"]["shadow"]), (5, 1))
        eps = self.client.get("/api/api-security/endpoints?state=shadow").json()["endpoints"]
        self.assertEqual(len(eps), 1)
        detail = self.client.get(f"/api/api-security/endpoints/{eps[0]['id']}").json()
        self.assertTrue(detail["findings"] and detail["series"])
        self.assertEqual(self.client.get("/api/api-security/endpoints/9999").status_code, 404)
        gen = self.client.get("/api/api-security/generated-spec?service=shop-api").json()
        self.assertIn("/v1/undocumented/thing", gen["paths"])
        self.assertEqual(self.client.get("/api/api-security/generated-spec?service=zzz").status_code, 404)

    def test_log_upload_by_an_admin(self):
        self.login()
        lines = "\n".join(json.dumps({"method": "GET", "path": f"/v1/users/{i}", "host": "shop.example.com", "status": 200, "ip": PUBLIC, "user": "u"}) for i in range(5))
        r = self.client.post("/api/api-security/import-logs?service=shop", content=lines)
        self.assertEqual((r.status_code, r.json()["records"]), (200, 5))
        self.assertEqual(self.client.post("/api/api-security/import-logs", content="").status_code, 400)
        self.assertEqual(self.client.post("/api/api-security/import-logs?format=xml", content="x").status_code, 400)

    def test_endpoint_owner_and_exposure_can_be_set(self):
        self.push_records([{"method": "GET", "path": "/a"}])
        self.login()
        eid = self.client.get("/api/api-security/endpoints").json()["endpoints"][0]["id"]
        r = self.client.patch(f"/api/api-security/endpoints/{eid}", json={"owner": "team-a", "exposure": "internal"})
        self.assertEqual((r.status_code, r.json()["owner"]), (200, "team-a"))
        self.assertEqual(self.client.patch(f"/api/api-security/endpoints/{eid}", json={"exposure": "moon"}).status_code, 400)
        self.assertEqual(self.client.patch(f"/api/api-security/endpoints/{eid}", json={}).status_code, 400)

    def test_spec_fetch_is_confirm_gated_and_ssrf_guarded(self):
        self.login()
        guard = patch.object(dashboard_app_module.url_safety, "assert_safe_target")
        with guard:
            pre = self.client.post("/api/api-security/specs/fetch", json={"url": "https://specs.example.com/openapi.yaml"}).json()
            self.assertTrue(pre["preview_only"])
            self.assertEqual(store.list_specs(self.engine), [])  # nothing was fetched or stored
            calls = []

            def fake_get(url, **kw):
                calls.append((url, kw))
                return FakeResp(SPEC.encode())
            with patch.object(dashboard_app_module, "_api_http_get", fake_get):
                ok = self.client.post("/api/api-security/specs/fetch", json={"url": "https://specs.example.com/openapi.yaml?token=SECRET", "service": "shop-api", "confirm": True})
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertFalse(calls[0][1]["allow_redirects"])
            self.assertNotIn("SECRET", json.dumps(store.list_specs(self.engine)))  # the query string is not kept
            with patch.object(dashboard_app_module, "_api_http_get", lambda u, **k: FakeResp(b"", 302)):
                self.assertEqual(self.client.post("/api/api-security/specs/fetch", json={"url": "https://x.example.com/s", "confirm": True}).status_code, 400)
            with patch.object(dashboard_app_module, "_api_http_get", lambda u, **k: FakeResp(b"not a spec")):
                self.assertEqual(self.client.post("/api/api-security/specs/fetch", json={"url": "https://x.example.com/s", "confirm": True}).status_code, 400)
        self.assertEqual(self.client.post("/api/api-security/specs/fetch", json={"url": "http://169.254.169.254/latest", "confirm": True}).status_code, 400)
        self.assertEqual(self.client.post("/api/api-security/specs/fetch", json={"url": "ftp://x/y", "confirm": True}).status_code, 400)

    def test_publish_needs_confirm_and_sends_the_complete_set(self):
        self.client.post("/api/ingest/openapi?service=shop-api", content=SPEC, headers=self.auth())
        self.push_records([{"method": "POST", "path": "/v1/hidden", "host": "shop.example.com", "client_ip": PUBLIC, "auth": "none", "status": 200}])
        self.login()
        pre = self.client.post("/api/api-security/publish", json={}).json()
        self.assertTrue(pre["preview_only"] and pre["findings"] >= 2)
        self.assertEqual(self.merged, [])
        r = self.client.post("/api/api-security/publish", json={"confirm": True}).json()
        self.assertEqual(r["rejected"], 0)
        self.assertEqual(self.merged[0][:2], ("api-security", True))  # reconcile, so a fixed finding leaves the queue

    def test_classification_import_through_the_api(self):
        self.login()
        r = self.client.post("/api/api-security/classification", json={"content": "name,priority,detectors\nRestricted,1,email;payment-card"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.post("/api/api-security/classification", json={"content": "name,priority\nA,zero"}).status_code, 400)
        c = self.client.get("/api/api-security/classification").json()
        self.assertEqual([x["name"] for x in c["classes"]], ["Restricted"])
        self.assertEqual(self.client.delete("/api/api-security/classification").json()["removed"], 1)

    def test_policy_lifecycle_with_approval_signed_push_alerts_and_edge_result(self):
        self.login()
        mk = self.client.post("/api/api-security/policies", json={"name": "Limit login", "kind": "rate-limit", "mode": "block", "params": {"limit": 30, "window_seconds": 60, "by": "ip"},
                                                                   "scope": {"endpoints": ["POST /login"]}})
        self.assertEqual(mk.status_code, 200, mk.text)
        pid = mk.json()["id"]
        self.assertEqual(self.client.post("/api/api-security/policies", json={"name": "Limit login", "kind": "rate-limit", "params": {"limit": 30, "window_seconds": 60}}).status_code, 400)
        fake, hook, mails = FakeEndpoint(), FakeNotify(), []
        public = {"id": 5, "name": "edge automation"}
        with patch.object(dashboard_app_module.hunt_service, "connector", side_effect=lambda kind, cid=None, engine=None: (hook, {"id": 1, "name": "chat"}) if kind == "notify-webhook" else (fake, public)), \
                patch.object(dashboard_app_module.email_sender, "is_configured", return_value=True), \
                patch.object(dashboard_app_module.email_sender, "send_email", side_effect=lambda to, s, b: mails.append((to, s))), \
                patch.dict("os.environ", {"QUANTA_ALERT_EMAIL": "soc@example.com"}):
            blocked = self.client.post(f"/api/api-security/policies/{pid}/push", json={"confirm": True})
            self.assertEqual(blocked.status_code, 409)  # block mode, not approved
            self.assertEqual(fake.got, [])
            self.assertEqual(self.client.post(f"/api/api-security/policies/{pid}/approve").status_code, 403)  # the author cannot approve
            self.login("admin2@t.local")
            self.assertEqual(self.client.post(f"/api/api-security/policies/{pid}/approve").status_code, 200)
            self.login()
            pre = self.client.post(f"/api/api-security/policies/{pid}/push", json={}).json()
            self.assertTrue(pre["preview_only"])
            self.assertEqual(pre["payload"]["policy"]["mode"], "block")
            self.assertEqual(fake.got, [])  # a preview sends nothing
            sent = self.client.post(f"/api/api-security/policies/{pid}/push", json={"confirm": True}).json()
            self.assertEqual(sent["push"]["status"], "sent")
            self.assertEqual(len(fake.got), 1)
            self.assertEqual(fake.got[0]["approved_by"], "admin2@t.local")
            self.assertEqual([a["channel"] for a in sent["alerts"]], ["notification webhook", "email"])
            self.assertIn("Limit login", hook.sent[0])
            r = self.client.post("/api/inbound/api-policy-status", json={"push_id": sent["push"]["id"], "status": "applied", "detail": "web ACL updated"}, headers=self.auth())
            self.assertEqual(r.json()["push"]["status"], "applied")
            self.assertIn("APPLIED", hook.sent[-1])
        hist = self.client.get(f"/api/api-security/policies/{pid}/history").json()
        self.assertTrue({"created", "approved", "pushed", "edge-applied"} <= {e["action"] for e in hist["events"]})
        self.assertEqual(self.client.post("/api/inbound/api-policy-status", json={"push_id": 999, "status": "applied"}, headers=self.auth()).status_code, 404)
        self.assertEqual(self.client.post("/api/inbound/api-policy-status", json={"push_id": 1, "status": "meh"}, headers=self.auth()).status_code, 400)

    def test_push_without_a_connected_endpoint_is_a_clear_error(self):
        self.login()
        pid = self.client.post("/api/api-security/policies", json={"name": "p", "kind": "rate-limit", "params": {"limit": 30, "window_seconds": 60}}).json()["id"]
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(None, None)):
            r = self.client.post(f"/api/api-security/policies/{pid}/push", json={"confirm": True})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Connections", r.json()["detail"])

    def test_artifacts_and_policy_edit_and_delete(self):
        self.login()
        pid = self.client.post("/api/api-security/policies", json={"name": "geo", "kind": "geo-restriction", "params": {"countries": ["KP"], "type": "deny"}}).json()["id"]
        a = self.client.get(f"/api/api-security/policies/{pid}/artifact?target=cloud-armor").json()
        self.assertTrue(a["supported"] and a["artifact"]["rules"][0]["preview"])
        self.assertEqual(self.client.get(f"/api/api-security/policies/{pid}/artifact?target=azure").status_code, 400)
        up = self.client.put(f"/api/api-security/policies/{pid}", json={"name": "geo", "kind": "geo-restriction", "mode": "monitor", "params": {"countries": ["KP", "IR"], "type": "deny"}})
        self.assertEqual(up.json()["version"], 2)
        self.assertEqual(self.client.put("/api/api-security/policies/999", json={"name": "x", "kind": "geo-restriction", "params": {"countries": ["US"]}}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/api-security/policies/{pid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/api-security/policies/{pid}").status_code, 404)

    def test_ci_results_return_a_gate_record_a_run_and_publish_failures(self):
        body = {"tool": "t", "repository": "org/shop-api", "pipeline": "github-actions", "results": [
            {"method": "GET", "path": "/users/{id}", "test": "bola", "owasp": "API1:2023", "status": "fail", "severity": "High", "evidence": "leak"},
            {"method": "GET", "path": "/ok", "test": "ok", "status": "pass"}]}
        r = self.client.post("/api/ingest/api-test-results?reconcile=true", json=body, headers=self.auth())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["gate"]["passed"], r.json()["gate"]["blocking"]), (False, 1))
        self.assertEqual(self.merged[-1], ("api-ci-org-shop-api", True, 1))
        from remediation.devsecops import controls as dso
        self.assertEqual([x["scan_type"] for x in dso.scan_runs(self.engine)], ["api-test"])
        ro = self.client.post("/api/ingest/api-test-results?report_only=true", json=body, headers=self.auth()).json()
        self.assertTrue(ro["gate"]["passed"] and ro["gate"]["reported_only"])
        self.assertTrue(self.client.post("/api/ingest/api-test-results?fail_on=Critical", json=body, headers=self.auth()).json()["gate"]["passed"])
        clean = {**body, "results": [{"method": "GET", "path": "/ok", "test": "ok", "status": "pass"}]}
        c = self.client.post("/api/ingest/api-test-results", json=clean, headers=self.auth())
        self.assertTrue(c.json()["gate"]["passed"])
        self.assertEqual(self.client.post("/api/ingest/api-test-results", json={"repository": "r", "results": [{"method": "X"}]}, headers=self.auth()).status_code, 400)
        self.assertEqual(self.client.post("/api/ingest/api-test-results?fail_on=urgent", json=body, headers=self.auth()).status_code, 400)

    def test_ci_run_makes_the_devsecops_control_show_evidence(self):
        self.client.post("/api/ingest/api-test-results", json={"tool": "t", "repository": "shop-api", "results": [{"method": "GET", "path": "/ok", "test": "ok", "status": "pass"}]}, headers=self.auth())
        from remediation.devsecops import controls as dso
        lib = next(c for c in dso.library() if c["id"] == "api-security-testing")
        st = dso.control_status(lib, "shop-api", dso.scan_runs(self.engine), [], [])
        self.assertEqual(st["status"], "evidenced")
        self.assertEqual(dso.control_status(lib, "other-repo", dso.scan_runs(self.engine), [], [])["status"], "no-evidence")

    def test_callers_metrics_rollout_and_templates(self):
        self.push_records([{"method": "GET", "path": f"/v1/users/{i}", "host": "shop.example.com", "client_ip": PUBLIC, "user": "scraper", "status": 200} for i in range(1, 70)])
        self.login()
        callers = self.client.get("/api/api-security/callers").json()
        self.assertEqual(callers["callers"][0]["actor"], "scraper")
        d = self.client.get("/api/api-security/callers/detail", params={"actor": "scraper"}).json()
        self.assertIn("enumeration", {i["type"] for i in d["indicators"]})
        self.assertEqual(self.client.get("/api/api-security/callers/detail", params={"actor": "ghost"}).status_code, 404)
        m = self.client.get("/api/api-security/metrics").json()
        self.assertEqual(m["total"]["calls"], 69)
        self.assertIn("errors / calls", m["definition"])
        rb = self.client.get("/api/api-security/rollout?track=shift-left-first").json()
        self.assertEqual(rb["track"], "shift-left-first")
        self.assertEqual(self.client.post("/api/api-security/rollout/architecture", json={"done": True, "note": "ok"}).status_code, 200)
        self.assertEqual(self.client.post("/api/api-security/rollout/spec", json={"done": True}).status_code, 400)
        self.assertIn("github-actions", self.client.get("/api/api-security/ci-templates").json()["templates"])

    def test_api_key_scope_is_offered(self):
        self.assertIn("api:write", apikeys.SCOPES)


if __name__ == "__main__":
    unittest.main()
