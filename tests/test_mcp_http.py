"""End-to-end tests of POST /mcp and GET /api/mcp/status through the real app: off by default, never anonymous (even with public reads), key scope and team binding,
audit entries in the real activity log, and that a key in a URL is refused."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"


def fnd(n, team, severity="High"):
    return {"id": f"FIND-{n}", "source": "t", "title": f"Issue {n}", "severity": severity, "score": 10 - n, "asset": {"name": f"h{n}", "type": "unix-server"},
            "team": team, "cve": None, "kev": None, "epss": None}


class McpHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.rows = [fnd(1, "blue", "Critical"), fnd(2, "red"), fnd(3, "blue", "Low")]
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine),
                        patch.object(dashboard_app_module.dashboard_data, "load_live_queue", lambda: [dict(r) for r in self.rows]),
                        patch.object(dashboard_app_module, "_annotate_finding_teams", lambda rows, **kw: rows),
                        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                        patch.dict(os.environ, {"QUANTA_MCP_ENABLED": "true"})]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        self.key = self.make_key(["mcp:read", "read:findings"])
        self.client.cookies.clear()

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def make_key(self, scopes, name="assistant", **extra):
        r = self.client.post("/api/api-keys", json={"name": name, "scopes": scopes, **extra})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["key"]

    def rpc(self, method, params=None, key=None, headers=None, url="/mcp", req_id=1):
        h = {"Authorization": f"Bearer {key or self.key}", "Accept": "application/json, text/event-stream", **(headers or {})}
        return self.client.post(url, headers=h, json={"jsonrpc": "2.0", "id": req_id, "method": method, **({"params": params} if params is not None else {})})

    def call(self, name, args=None, **kw):
        return self.rpc("tools/call", {"name": name, "arguments": args or {}}, **kw)

    def test_off_unless_enabled(self):
        with patch.dict(os.environ, {"QUANTA_MCP_ENABLED": ""}):
            self.assertEqual(self.rpc("ping").status_code, 404)
        self.assertEqual(self.rpc("ping").status_code, 200)

    def test_never_anonymous_even_when_reads_are_public_or_a_session_exists(self):
        self.assertEqual(self.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code, 401)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})   # a logged-in admin session does not substitute for a key
        r = self.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(r.status_code, 401)
        self.assertIn("Bearer", r.headers["www-authenticate"])
        self.client.cookies.clear()
        for bad in ("Bearer qk_deadbeef_" + "A" * 43, "Bearer garbage", "Basic abc"):
            self.assertEqual(self.client.post("/mcp", headers={"Authorization": bad}, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code, 401)
        with patch.dict(os.environ, {"QUANTA_REQUIRE_LOGIN_FOR_READS": "true"}):
            self.assertEqual(self.rpc("ping").status_code, 200)          # the key is the credential here; no session needed
            self.assertEqual(self.client.post("/mcp", json={}).status_code, 401)

    def test_other_keys_and_the_x_api_key_header_do_not_open_it(self):
        other = self.make_key(["read:findings", "ingest:write"], name="ci") if self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW}) else None
        self.client.cookies.clear()
        r = self.rpc("ping", key=other)
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_scope", r.headers["www-authenticate"])
        r = self.client.post("/mcp", headers={"X-API-Key": self.key}, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(r.status_code, 401)

    def test_a_token_in_the_url_is_refused_even_with_a_valid_header(self):
        self.assertEqual(self.rpc("ping", url=f"/mcp?access_token={self.key}").status_code, 400)
        self.assertEqual(self.rpc("ping", url="/mcp?x=1").status_code, 400)

    def test_browser_origin_and_other_methods_are_refused(self):
        self.assertEqual(self.rpc("ping", headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.client.get("/mcp", headers={"Authorization": f"Bearer {self.key}"}).status_code, 405)
        self.assertEqual(self.client.delete("/mcp").status_code, 405)

    def test_handshake_list_and_call_over_http(self):
        init = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}, headers={"MCP-Protocol-Version": "2025-11-25"})
        self.assertEqual(init.json()["result"]["protocolVersion"], "2025-11-25")
        n = self.client.post("/mcp", headers={"Authorization": f"Bearer {self.key}"}, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual((n.status_code, n.content), (202, b""))
        names = [t["name"] for t in self.rpc("tools/list").json()["result"]["tools"]]
        self.assertIn("search_findings", names)
        out = self.call("search_findings", {"limit": 5}).json()["result"]["structuredContent"]
        self.assertEqual({i["id"] for i in out["items"]}, {"FIND-1", "FIND-2", "FIND-3"})
        self.assertEqual(self.rpc("ping", headers={"MCP-Protocol-Version": "1999-01-01"}).status_code, 400)
        self.assertEqual(self.client.post("/mcp", headers={"Authorization": f"Bearer {self.key}"}, content=b"{oops").json()["error"]["code"], -32700)

    def test_a_team_bound_key_sees_only_that_teams_findings(self):
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        k = self.make_key(["mcp:read", "read:findings"], name="blue-bot", team="blue")
        self.assertEqual(self.client.get("/api/api-keys").json()["keys"][0]["team"], "blue")
        self.client.cookies.clear()
        out = self.call("search_findings", key=k).json()["result"]["structuredContent"]
        self.assertEqual({i["id"] for i in out["items"]}, {"FIND-1", "FIND-3"})
        self.assertTrue(self.call("get_finding", {"finding_id": "FIND-2"}, key=k).json()["result"]["isError"])   # another team's finding does not exist for this key
        self.assertEqual(self.call("posture_summary", key=k).status_code, 403)

    def test_calls_and_denials_land_in_the_real_activity_log_without_bodies(self):
        self.call("search_findings", {"query": "needle-xyz"})
        self.call("not_a_tool")
        self.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        entries = activity_log.list_activity(engine=self.engine)
        actions = [(e["action"], (e["details"] or {}).get("outcome")) for e in entries if e["action"].startswith("mcp.")]
        self.assertIn(("mcp.tool_call", "ok"), actions)
        self.assertIn(("mcp.denied", "unknown_tool"), actions)
        self.assertIn(("mcp.denied", "unauthenticated"), actions)
        blob = json.dumps(entries)
        self.assertNotIn("needle-xyz", blob)
        self.assertNotIn(self.key, blob)
        self.assertNotIn("Issue 1", blob)

    def test_status_is_admin_only_and_shows_tools_and_counts(self):
        self.assertEqual(self.client.get("/api/mcp/status").status_code, 401)
        self.call("top_priorities")
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        s = self.client.get("/api/mcp/status").json()
        self.assertIs(s["enabled"], True)
        self.assertTrue(s["endpoint_url"].endswith("/mcp"))
        self.assertEqual(s["required_scope"], "mcp:read")
        self.assertIn("top_priorities", [t["name"] for t in s["tools"]])
        self.assertGreaterEqual(s["recent_audit_counts"].get("tool_call:ok", 0), 1)
        self.assertNotIn(self.key, json.dumps(s))
        with patch.dict(os.environ, {"QUANTA_MCP_ENABLED": ""}):
            self.assertIs(self.client.get("/api/mcp/status").json()["enabled"], False)

    def test_mcp_read_is_a_known_scope_and_the_login_gate_never_needs_to_exempt_it(self):
        self.assertIn("mcp:read", apikeys.SCOPES)
        self.assertFalse("/mcp".startswith(dashboard_app_module._API_KEY_PATH_PREFIXES))


if __name__ == "__main__":
    unittest.main()
