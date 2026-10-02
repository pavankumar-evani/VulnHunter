"""
OpenTelemetry GenAI intake: reads OTLP/HTTP JSON trace exports into AI usage events.

Applications and gateways instrumented with the OpenTelemetry GenAI semantic conventions record each model call as a span with
attributes such as `gen_ai.request.model`, `gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens`. Point the exporter at
`POST /api/ingest/otlp/v1/traces` (protocol `http/json`) with an API key and those spans become usage events, attributed by
`service.name` (the application), and optionally `quanta.team` / `team` and `enduser.id` / `user.id` attributes.

Only JSON is accepted: set OTEL_EXPORTER_OTLP_PROTOCOL=http/json (the protobuf encoding is not read). Spans without a model or any
token count are ignored, which is how non-AI spans in the same export are skipped. Conventions are still evolving, so both the older
`gen_ai.system` and the newer `gen_ai.provider.name` are read, and both `gen_ai.usage.cache_read.input_tokens` style names and the
Anthropic-style `...cache_read_input_tokens`.
"""
import datetime


def _attrs(lst):
    out = {}
    for a in lst or []:
        v = a.get("value") or {}
        for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if k in v:
                out[a.get("key")] = v[k]
                break
    return out


def _num(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _iso(nano):
    try:
        return datetime.datetime.fromtimestamp(int(nano) / 1e9, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_traces(doc):
    """Events (not yet validated) from an OTLP JSON traces document."""
    if not isinstance(doc, dict) or not isinstance(doc.get("resourceSpans"), list):
        raise ValueError("Not an OTLP JSON traces export: it has no 'resourceSpans' list.")
    events = []
    for rs in doc["resourceSpans"]:
        res = _attrs((rs.get("resource") or {}).get("attributes"))
        for ss in rs.get("scopeSpans") or []:
            for sp in ss.get("spans") or []:
                a = _attrs(sp.get("attributes"))
                model = a.get("gen_ai.response.model") or a.get("gen_ai.request.model")
                inp = _num(a.get("gen_ai.usage.input_tokens"))
                out = _num(a.get("gen_ai.usage.output_tokens"))
                if not model or not (inp or out):
                    continue
                start, end = _num(sp.get("startTimeUnixNano")), _num(sp.get("endTimeUnixNano"))
                events.append({
                    "ts": _iso(sp.get("startTimeUnixNano")), "model": model,
                    "provider": a.get("gen_ai.provider.name") or a.get("gen_ai.system"),
                    "application": res.get("service.name") or a.get("service.name"),
                    "team": a.get("quanta.team") or res.get("quanta.team") or a.get("team") or res.get("team"),
                    "user_ref": a.get("enduser.id") or a.get("user.id") or a.get("gen_ai.user.id"),
                    "input_tokens": inp, "output_tokens": out,
                    "cache_read_tokens": _num(a.get("gen_ai.usage.cache_read.input_tokens") or a.get("gen_ai.usage.cache_read_input_tokens")),
                    "cache_write_tokens": _num(a.get("gen_ai.usage.cache_creation.input_tokens") or a.get("gen_ai.usage.cache_creation_input_tokens")),
                    "latency_ms": int((end - start) / 1e6) if end > start else None,
                    "event_key": f"{sp.get('traceId')}:{sp.get('spanId')}" if sp.get("spanId") else None,
                })
    return events
