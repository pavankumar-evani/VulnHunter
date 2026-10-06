"""A small in-process publish/subscribe hub behind the Server-Sent Events route (GET /api/events).

Read-only by design: the browser can only listen. Server code calls publish(topic, data); every connected
subscriber gets the event through its own bounded queue. A slow client never slows a publisher and never
grows memory: when its queue is full the OLDEST event is dropped and counted (the client is told on its
next event via `dropped`). State is per process; with several replicas an event reaches only the clients
connected to the replica that published it (the front end falls back to polling anyway, so nothing depends
on delivery).
"""
from __future__ import annotations

import asyncio
import itertools
import json
import threading
import time
from collections import deque

MAX_QUEUE = 100        # events held per subscriber
MAX_SUBSCRIBERS = 200  # open streams per process; more are refused with 503
HEARTBEAT_SECONDS = 15
REPLAY = 50            # recent events kept for Last-Event-ID resume
TOPIC_MAX = 64


def _topic_match(topics, topic):
    return not topics or topic in topics or any(topic.startswith(t + ".") for t in topics)


class Subscription:
    def __init__(self, hub, loop, topics):
        self.hub, self.loop, self.topics = hub, loop, topics
        self.queue = deque()
        self.dropped = 0
        self.wakeup = asyncio.Event()

    def accepts(self, topic):
        return _topic_match(self.topics, topic)

    def push(self, event):  # runs on the subscriber's event loop
        if len(self.queue) >= MAX_QUEUE:
            self.queue.popleft()
            self.dropped += 1
        self.queue.append(event)
        self.wakeup.set()

    def close(self):
        self.hub._remove(self)


class Hub:
    def __init__(self):
        self._lock = threading.Lock()
        self._subs = []
        self._ids = itertools.count(1)
        self._recent = deque(maxlen=REPLAY)

    def subscriber_count(self):
        with self._lock:
            return len(self._subs)

    def subscribe(self, topics=None):
        """Must be called from the running event loop. Returns None when the process is at its subscriber limit."""
        with self._lock:
            if len(self._subs) >= MAX_SUBSCRIBERS:
                return None
            sub = Subscription(self, asyncio.get_running_loop(), set(topics or []))
            self._subs.append(sub)
            return sub

    def _remove(self, sub):
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def publish(self, topic, data=None):
        """Safe from any thread (route handlers run in a thread pool). Never raises into the caller."""
        topic = str(topic)[:TOPIC_MAX]
        event = {"id": next(self._ids), "topic": topic, "data": data if data is not None else {}, "ts": round(time.time(), 3)}
        with self._lock:
            self._recent.append(event)
            subs = [s for s in self._subs if s.accepts(topic)]
        for s in subs:
            try:
                s.loop.call_soon_threadsafe(s.push, event)
            except RuntimeError:  # that subscriber's loop is gone
                self._remove(s)
        return event

    def replay_after(self, last_id, topics=None):
        with self._lock:
            return [e for e in self._recent if e["id"] > last_id and _topic_match(topics, e["topic"])]


hub = Hub()
publish = hub.publish


def format_event(event, dropped=0):
    """One SSE frame. The topic is the SSE event name, so EventSource.addEventListener(topic) works."""
    payload = {"topic": event["topic"], "data": event["data"], "ts": event["ts"]}
    if dropped:
        payload["dropped"] = dropped
    return f"id: {event['id']}\nevent: {event['topic']}\ndata: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n"


def heartbeat_frame():
    return ": heartbeat\n\n"


async def stream(sub, last_id=0, once=False, heartbeat=HEARTBEAT_SECONDS, max_seconds=None):
    """Async generator of SSE frames. `once` sends the hello frame (plus any replay) and ends: used by tests and by clients
    that only want to confirm the stream is available. max_seconds ends a stream after that long so a proxy can recycle it."""
    started = time.monotonic()
    try:
        yield "retry: 5000\n\n"
        yield format_event({"id": 0, "topic": "hello", "data": {"subscribers": sub.hub.subscriber_count()}, "ts": round(time.time(), 3)})
        for ev in sub.hub.replay_after(last_id, sub.topics):
            yield format_event(ev)
        if once:
            return
        while True:
            if max_seconds is not None and time.monotonic() - started >= max_seconds:
                return
            try:
                await asyncio.wait_for(sub.wakeup.wait(), timeout=heartbeat)
            except asyncio.TimeoutError:
                yield heartbeat_frame()
                continue
            sub.wakeup.clear()
            while sub.queue:
                ev = sub.queue.popleft()
                dropped, sub.dropped = sub.dropped, 0
                yield format_event(ev, dropped)
    finally:
        sub.close()
