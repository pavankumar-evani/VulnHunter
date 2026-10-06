"""The live-updates stream (dashboard/events.py and GET /api/events): sign-in required, SSE framing, topics, bounded queues, replay."""
import asyncio
import json
import os
import sys
import threading
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "dashboard"))
sys.path.insert(0, os.path.join(REPO_ROOT, "cli"))
sys.path.insert(0, REPO_ROOT)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import events  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import rbac  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


def frames(text):
    """Parse an SSE body into [{id, event, data}]; comments (heartbeats) are skipped."""
    out = []
    for block in text.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(":"))
        if "event" in fields:
            fields["data"] = json.loads(fields["data"])
            out.append(fields)
    return out


class HubTests(unittest.TestCase):
    def test_publish_reaches_matching_subscribers_only(self):
        async def run():
            hub = events.Hub()
            a, b = hub.subscribe(["activity"]), hub.subscribe(["soc"])
            hub.publish("activity", {"action": "x"})
            await asyncio.sleep(0.01)
            return len(a.queue), len(b.queue)
        self.assertEqual(asyncio.run(run()), (1, 0))

    def test_a_dotted_topic_matches_its_parent(self):
        async def run():
            hub = events.Hub()
            s = hub.subscribe(["soc"])
            hub.publish("soc.incident", {"id": 1})
            await asyncio.sleep(0.01)
            return len(s.queue)
        self.assertEqual(asyncio.run(run()), 1)

    def test_a_slow_subscriber_is_bounded_and_told_what_it_missed(self):
        async def run():
            hub = events.Hub()
            s = hub.subscribe()
            for i in range(events.MAX_QUEUE + 25):
                hub.publish("activity", {"n": i})
            await asyncio.sleep(0.05)
            return len(s.queue), s.dropped, s.queue[0]["data"]["n"]
        size, dropped, oldest = asyncio.run(run())
        self.assertEqual(size, events.MAX_QUEUE)
        self.assertEqual(dropped, 25)
        self.assertEqual(oldest, 25)          # the oldest 25 were discarded, never the newest

    def test_subscriber_limit_and_cleanup(self):
        async def run():
            hub = events.Hub()
            subs = [hub.subscribe() for _ in range(events.MAX_SUBSCRIBERS)]
            over = hub.subscribe()
            subs[0].close()
            return over, hub.subscriber_count()
        over, count = asyncio.run(run())
        self.assertIsNone(over)
        self.assertEqual(count, events.MAX_SUBSCRIBERS - 1)

    def test_publish_from_a_worker_thread_is_delivered(self):
        async def run():
            hub = events.Hub()
            s = hub.subscribe()
            threading.Thread(target=hub.publish, args=("activity", {"t": 1})).start()
            await asyncio.wait_for(s.wakeup.wait(), 2)
            return len(s.queue)
        self.assertEqual(asyncio.run(run()), 1)

    def test_replay_after_last_event_id_only_returns_newer_matching_events(self):
        hub = events.Hub()
        first = hub.publish("activity", {})
        hub.publish("soc", {})
        hub.publish("activity", {})
        got = hub.replay_after(first["id"], {"activity"})
        self.assertEqual([e["topic"] for e in got], ["activity"])
        self.assertGreater(got[0]["id"], first["id"])

    def test_the_frame_format_names_the_event_and_carries_json(self):
        frame = events.format_event({"id": 7, "topic": "activity", "data": {"action": "a.b"}, "ts": 1.5}, dropped=3)
        self.assertTrue(frame.startswith("id: 7\nevent: activity\ndata: ") and frame.endswith("\n\n"))
        self.assertEqual(json.loads(frame.split("data: ", 1)[1])["dropped"], 3)

    def test_the_stream_sends_a_heartbeat_when_idle_and_ends_at_max_seconds(self):
        async def run():
            hub = events.Hub()
            s = hub.subscribe()
            return [f async for f in events.stream(s, heartbeat=0.05, max_seconds=0.2)], hub.subscriber_count()
        out, left = asyncio.run(run())
        self.assertTrue(any(f.startswith(": heartbeat") for f in out))
        self.assertEqual(left, 0)             # the subscription is released when the stream ends


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        fastapi_app.dependency_overrides.clear()

    def sign_in(self):
        fastapi_app.dependency_overrides[rbac.require_login] = lambda: {"email": "t@quanta.test", "role": "user"}

    def test_signing_in_is_required(self):
        self.assertEqual(self.client.get("/api/events?once=true").status_code, 401)

    def test_a_signed_in_user_gets_an_event_stream_with_a_hello_frame(self):
        self.sign_in()
        r = self.client.get("/api/events?once=true")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/event-stream"))
        self.assertIn("no-cache", r.headers["cache-control"])
        self.assertEqual(frames(r.text)[0]["event"], "hello")

    def test_last_event_id_replays_what_was_missed(self):
        self.sign_in()
        ev = events.publish("activity", {"action": "test.replay"})
        r = self.client.get("/api/events?once=true&topics=activity", headers={"Last-Event-ID": str(ev["id"] - 1)})
        got = [f for f in frames(r.text) if f["event"] == "activity"]
        self.assertTrue(any(f["data"]["data"].get("action") == "test.replay" for f in got))

    def test_the_route_is_read_only(self):
        self.sign_in()
        self.assertEqual(self.client.post("/api/events").status_code, 405)

    def test_recording_an_activity_publishes_only_its_action_name(self):
        seen = []
        original = activity_log.listener
        activity_log.listener = lambda action: seen.append(action)
        try:
            engine = create_engine("sqlite:///:memory:")
            db_module.ensure_schema(engine)
            activity_log.record_activity("someone@example.test", "unit.test", "secret-target", {"k": "v"}, engine=engine)
        finally:
            activity_log.listener = original
        self.assertEqual(seen, ["unit.test"])


if __name__ == "__main__":
    unittest.main()
