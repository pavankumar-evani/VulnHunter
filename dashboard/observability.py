"""
Operational visibility: structured logs, request IDs, and Prometheus-format metrics.

* Logging: `QUANTA_LOG_FORMAT=json` emits one JSON object per line (timestamp, level, logger,
  message, plus request fields), ready for any log shipper; the default is a readable line.
  `QUANTA_LOG_LEVEL` (default INFO).
* Request IDs: every response carries `X-Request-ID` (a client-supplied one is honoured if it
  is short and plain), and the access log line includes it, so one id ties a user report to a
  server log entry.
* Metrics: `/metrics` in Prometheus text format, off unless `QUANTA_METRICS_TOKEN` is set, in
  which case callers send `Authorization: Bearer <token>`. It exposes counts and sync
  health, never data.

None of this logs request bodies, query strings with credentials, or cookies.
"""
import json
import logging
import os
import re
import time
import uuid

_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
access_log = logging.getLogger("quanta.access")
_started = time.monotonic()
_counters = {"requests_total": 0, "requests_5xx": 0, "requests_4xx": 0}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
               "level": record.levelname, "logger": record.name, "message": record.getMessage()}
        for k in ("request_id", "method", "path", "status", "duration_ms", "user"):
            if hasattr(record, k):
                out[k] = getattr(record, k)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out)


def configure_logging():
    level = getattr(logging, os.environ.get("QUANTA_LOG_LEVEL", "INFO").upper(), logging.INFO)
    root = logging.getLogger("quanta")
    root.setLevel(level)
    if not root.handlers:
        h = logging.StreamHandler()
        h.setFormatter(JsonFormatter() if os.environ.get("QUANTA_LOG_FORMAT", "").lower() == "json"
                       else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root.addHandler(h)
        root.propagate = False


def request_id_for(request):
    supplied = request.headers.get("x-request-id", "")
    return supplied if _SAFE_ID.match(supplied) else uuid.uuid4().hex


async def request_logging(request, call_next):
    rid = request_id_for(request)
    start = time.monotonic()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = rid
        return response
    finally:
        ms = round((time.monotonic() - start) * 1000, 1)
        _counters["requests_total"] += 1
        if status >= 500:
            _counters["requests_5xx"] += 1
        elif status >= 400:
            _counters["requests_4xx"] += 1
        path = request.url.path
        if not path.startswith("/static/") and path not in ("/healthz", "/readyz", "/metrics"):
            access_log.info("%s %s %s", request.method, path, status,
                            extra={"request_id": rid, "method": request.method, "path": path, "status": status, "duration_ms": ms})


def metrics_text(gauges):
    """Prometheus text exposition. `gauges` is {name: (help, value)}; values may be None (skipped)."""
    lines = []

    def emit(name, help_, value, kind="gauge"):
        if value is None:
            return
        lines.extend([f"# HELP {name} {help_}", f"# TYPE {name} {kind}", f"{name} {value}"])

    emit("quanta_uptime_seconds", "Seconds since the process started", round(time.monotonic() - _started))
    emit("quanta_http_requests_total", "HTTP requests served", _counters["requests_total"], "counter")
    emit("quanta_http_requests_4xx_total", "HTTP 4xx responses", _counters["requests_4xx"], "counter")
    emit("quanta_http_requests_5xx_total", "HTTP 5xx responses", _counters["requests_5xx"], "counter")
    for name, (help_, value) in gauges.items():
        emit(name, help_, value)
    return "\n".join(lines) + "\n"
