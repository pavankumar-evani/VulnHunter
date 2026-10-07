// Live updates for the whole app: ONE Server-Sent Events stream (GET /api/events) shared by every page, with a
// graceful fallback to smart polling. Pages call subscribe(topic, cb) and get an unsubscribe function back.
//   - SSE is feature-detected: no EventSource, a refused stream (401/403/404/503) or repeated failures -> polling.
//   - Polling backs off exponentially (with jitter) while nothing changes, snaps back when something does, and pauses
//     completely while the tab is hidden.
//   - A page may also register a poller for a topic: poll(topic, fn, {every}) - used as the fallback source of that topic.
// Everything browser-specific is injected through `env`, so the logic is tested under Node (tests/test_ui_kit_js.py).

export const POLL_MIN_MS = 15000;
export const POLL_MAX_MS = 120000;

// Exponential backoff with an upper bound; `rand` in [0,1) adds up to +25% jitter. attempt 0 = the base delay.
export function backoffDelay(attempt, base = POLL_MIN_MS, max = POLL_MAX_MS, rand = 0) {
  const raw = Math.min(max, base * Math.pow(2, Math.max(0, attempt)));
  return Math.round(raw * (1 + 0.25 * rand));
}

export class Bus {
  constructor() { this.subs = new Map(); }
  subscribe(topic, cb) {
    if (!this.subs.has(topic)) this.subs.set(topic, new Set());
    this.subs.get(topic).add(cb);
    return () => { const s = this.subs.get(topic); if (s) { s.delete(cb); if (!s.size) this.subs.delete(topic); } };
  }
  emit(topic, payload) {
    const direct = this.subs.get(topic) || new Set();
    const wild = this.subs.get("*") || new Set();
    for (const cb of [...direct, ...wild]) {
      try { cb(payload, topic); } catch (err) { if (typeof console !== "undefined") console.error("live subscriber failed", err); }
    }
  }
  topics() { return [...this.subs.keys()].filter((t) => t !== "*"); }
  count() { let n = 0; this.subs.forEach((s) => { n += s.size; }); return n; }
}

export function createLive(env = {}) {
  const bus = new Bus();
  const pollers = new Map(); // topic -> { fn, every, attempt, timer, last }
  const state = { mode: "idle", failures: 0, connectedAt: null, lastEventAt: null };
  const E = {
    EventSource: env.EventSource !== undefined ? env.EventSource : (typeof EventSource !== "undefined" ? EventSource : null),
    setTimeout: env.setTimeout || ((...a) => setTimeout(...a)),
    clearTimeout: env.clearTimeout || ((...a) => clearTimeout(...a)),
    hidden: env.hidden || (() => (typeof document !== "undefined" ? document.hidden : false)),
    onVisible: env.onVisible || ((cb) => { if (typeof document !== "undefined") document.addEventListener("visibilitychange", () => { if (!document.hidden) cb(); }); }),
    rand: env.rand || Math.random,
    now: env.now || Date.now,
    url: env.url || "/api/events",
  };
  let source = null;
  let started = false;

  function setMode(mode) { if (state.mode !== mode) { state.mode = mode; bus.emit("live.mode", { mode }); } }

  function schedule(topic) {
    const p = pollers.get(topic);
    if (!p) return;
    E.clearTimeout(p.timer);
    p.timer = E.setTimeout(() => runPoll(topic), backoffDelay(p.attempt, p.every, Math.max(p.every, POLL_MAX_MS), E.rand()));
  }

  async function runPoll(topic) {
    const p = pollers.get(topic);
    if (!p) return;
    if (E.hidden()) { p.timer = null; p.waiting = true; return; } // resumed by onVisible
    // while SSE is healthy it is the source of truth; poll only rarely as a safety net
    if (state.mode === "sse" && E.now() - (state.lastEventAt || 0) < 3 * 60000) { p.attempt = Math.max(p.attempt, 3); schedule(topic); return; }
    try {
      const result = await p.fn();
      const sig = JSON.stringify(result === undefined ? null : result);
      if (p.last !== undefined && sig === p.last) p.attempt += 1; // nothing changed: slow down
      else { p.attempt = 0; if (p.last !== undefined) bus.emit(topic, { source: "poll", result }); }
      p.last = sig;
    } catch { p.attempt += 1; }
    schedule(topic);
  }

  function resumePolling() {
    pollers.forEach((p, topic) => { if (p.waiting) { p.waiting = false; p.attempt = 0; runPoll(topic); } });
  }

  function openStream() {
    if (!E.EventSource || source) return;
    state.lastTry = E.now();
    try { source = new E.EventSource(E.url); } catch { source = null; setMode("poll"); return; }
    source.onopen = () => { state.failures = 0; state.connectedAt = E.now(); setMode("sse"); };
    source.onmessage = (ev) => handle(ev);
    source.onerror = () => {
      state.failures += 1;
      // EventSource retries by itself, but a 401/404/503 closes it for good (readyState 2): give up and poll.
      if (source && (source.readyState === 2 || state.failures >= 3)) { try { source.close(); } catch { /* already closed */ } source = null; setMode("poll"); }
      else setMode("poll");
    };
    // topic-named events (the server uses the topic as the SSE event name): listen for the ones that are subscribed.
    source.__listening = new Set();
    listenTopics();
  }

  function handle(ev) {
    state.lastEventAt = E.now();
    let msg = null;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg && msg.topic && msg.topic !== "hello") bus.emit(msg.topic, msg.data || {});
  }

  function listenTopics() {
    if (!source || !source.addEventListener) return;
    for (const t of new Set([...bus.topics(), "activity", "notifications", "findings", "soc.incident"])) {
      if (source.__listening.has(t)) continue;
      source.__listening.add(t);
      source.addEventListener(t, (ev) => handle(ev));
    }
  }

  const api = {
    state,
    bus,
    // Start (once). Safe to call from every page; later calls do nothing.
    start() {
      if (started) return api;
      started = true;
      E.onVisible(resumePolling);
      if (E.EventSource) openStream(); else setMode("poll");
      return api;
    },
    subscribe(topic, cb) {
      api.start();
      const off = bus.subscribe(topic, cb);
      listenTopics();
      return off;
    },
    // Register a fallback poller for a topic. Returns a stop function. The poller's own result changing emits the topic.
    poll(topic, fn, { every = POLL_MIN_MS } = {}) {
      api.start();
      const p = { fn, every, attempt: 0, timer: null, last: undefined, waiting: false };
      pollers.set(topic, p);
      runPoll(topic); // first run records a baseline silently
      return () => { E.clearTimeout(p.timer); pollers.delete(topic); };
    },
    // After signing in: try the stream again if it was refused before (at most once a minute).
    retrySSE() {
      if (!started || source || !E.EventSource || E.now() - (state.lastTry || 0) < 60000) return;
      state.lastTry = E.now();
      state.failures = 0;
      openStream();
    },
    emit: (topic, payload) => bus.emit(topic, payload),
    stop() {
      if (source) { try { source.close(); } catch { /* ignore */ } source = null; }
      pollers.forEach((p) => E.clearTimeout(p.timer));
      pollers.clear();
      started = false;
      setMode("idle");
    },
  };
  return api;
}

// The shared instance every page uses.
export const live = createLive();
export const subscribe = (topic, cb) => live.subscribe(topic, cb);
