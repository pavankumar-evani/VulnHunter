"""
A freshly deployed production instance has no findings, no plan, no playbooks and no
approvals. Every parameterless GET route must still answer without a server error, so the
first page a customer opens is never a stack trace. (4xx and deliberate 503s are fine; a 500 is a bug.)
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
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.ingest import merge  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

# routes that call out to the network or an external tool by design
SKIP = {"/api/threat-intel/refresh-now", "/api/status"}
# Server-Sent Events routes answer with a stream that is held open on purpose (up to an hour), so a plain GET never returns. They have their
# own tests (tests/test_events.py, tests/test_soc_incidents_api.py).
STREAM_SUFFIXES = ("/stream", "/events")


class EmptyStateTests(unittest.TestCase):
    def test_every_parameterless_get_route_survives_an_empty_deployment(self):
        tmp = tempfile.TemporaryDirectory()
        empty = Path(tmp.name) / "nf.json"
        empty.write_text("[]")
        engine = create_engine(f"sqlite:///{Path(tmp.name) / 't.db'}")
        with patch.object(db_module, "get_engine", return_value=engine), \
                patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)), \
                patch.object(dashboard_data, "load_remediation_findings", return_value=[]), \
                patch.object(merge, "DEFAULT_PATH", empty):
            auth_users.create_user("admin@t.local", "test-password-123", "Admin", role="admin", engine=engine)
            client = TestClient(fastapi_app, raise_server_exceptions=False)
            self.assertEqual(client.post("/api/auth/login", json={"email": "admin@t.local", "password": "test-password-123"}).status_code, 200)
            checked, failures = 0, []
            for route in fastapi_app.routes:
                path = getattr(route, "path", "")
                if "GET" not in getattr(route, "methods", set()) or "{" in path or not path.startswith("/api/") or path in SKIP or path.endswith(STREAM_SUFFIXES):
                    continue
                r = client.get(path)
                checked += 1
                if r.status_code == 500:  # a 503 (e.g. SSO not configured) is a deliberate answer, not a crash
                    failures.append((path, r.status_code, r.text[:160]))
            client.close()
        engine.dispose()
        tmp.cleanup()
        # The routes above filled the module's short-lived caches from an EMPTY deployment. Leave them as found, or whichever test runs next
        # within the cache's lifetime reads an empty queue instead of the real one.
        for name in dir(dashboard_data):
            cache = getattr(dashboard_data, name)
            if name.endswith("_CACHE") and isinstance(cache, dict):
                for k in cache:
                    cache[k] = 0.0 if k == "expires_at" else None
        self.assertGreater(checked, 40)
        self.assertEqual(failures, [], f"{len(failures)} route(s) failed on an empty deployment: {failures[:5]}")


if __name__ == "__main__":
    unittest.main()
