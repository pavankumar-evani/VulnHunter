"""
Runtime protection policies, expressed as data and handed to an endpoint YOU own.

Quanta never changes a WAF, gateway or any other customer system. A policy here is a record (what to watch, monitor or block, for which endpoints and data) that Quanta
can do two things with: (1) generate review artifacts in the rule formats of common edge services (remediation/apisec/waf.py), and (2) send it as a signed request to a
URL the customer owns (remediation/connectors/webhook_connector.py PolicyWebhook, the same signing as the SOAR response webhook), where the customer's own automation
decides whether and how to apply it. Every send is recorded (who, which version, what the endpoint answered), the customer's automation can report the edge result
back, and each result raises a change alert through the notification webhook and email when those are configured.

Safety rules, all enforced here:
  * a new policy is created in monitor mode unless block is asked for explicitly;
  * a policy in block mode can only be sent after a DIFFERENT administrator approved that exact version (config: policy.require_second_approver_for_block);
  * any edit creates a new version and voids earlier approvals, and a policy already sent shows as pending-push until it is sent again;
  * every create, edit, mode change, approval, send and reported result is an audit event.
"""
import datetime
import hashlib
import ipaddress
import json
import re

from sqlalchemy import delete, insert, select, update

from remediation.apisec import config, paths
from remediation.utils import db as db_module

KINDS = ("rate-limit", "malicious-source", "data-loss", "geo-restriction", "custom-signature")
MODES = ("monitor", "block")
KIND_LABELS = {"rate-limit": "Rate limit", "malicious-source": "Malicious sources", "data-loss": "Data-loss limit", "geo-restriction": "Geographic restriction", "custom-signature": "Custom signature"}
_ENDPOINT = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|\*) (/[A-Za-z0-9_\-./{}*~%:@]*)$")
_HEADER = re.compile(r"^[A-Za-z0-9-]{1,60}$")
_UNSUPPORTED_REGEX = re.compile(r"\(\?[=!<]|\\[1-9]|\(\?P=")


class PolicyError(ValueError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _j(v, default=None):
    try:
        return json.loads(v) if v else default
    except ValueError:
        return default


def _int(params, name, lo, hi):
    try:
        v = int(str(params.get(name)).strip())
    except (TypeError, ValueError):
        raise PolicyError(f"{name} must be a whole number") from None
    if not lo <= v <= hi:
        raise PolicyError(f"{name} must be between {lo:,} and {hi:,}")
    return v


def _check_scope(scope):
    scope = scope if isinstance(scope, dict) else {}
    services = [str(s).strip() for s in scope.get("services") or [] if str(s).strip()]
    endpoints = []
    for e in scope.get("endpoints") or []:
        e = str(e).strip()
        if not _ENDPOINT.match(e):
            raise PolicyError(f"Endpoint '{e}' must look like 'GET /users/{{id}}' (use * for any method, and a trailing * for a path prefix)")
        endpoints.append(e)
    if len(services) > 200 or len(endpoints) > 500:
        raise PolicyError("A scope may name at most 200 services and 500 endpoints")
    return {"services": sorted(set(services)), "endpoints": sorted(set(endpoints))}


def _check_params(kind, params, classes):
    p = params if isinstance(params, dict) else {}
    pol = config.load()["policy"]
    if kind == "rate-limit":
        window = _int(p, "window_seconds", 1, 86400)
        if window not in pol["rate_limit_windows_seconds"]:
            raise PolicyError(f"window_seconds must be one of {', '.join(map(str, pol['rate_limit_windows_seconds']))}")
        by = p.get("by", "ip")
        if by not in ("ip", "actor"):
            raise PolicyError("by must be ip or actor")
        out = {"limit": _int(p, "limit", pol["rate_limit_min"], pol["rate_limit_max"]), "window_seconds": window, "by": by}
        if by == "actor":
            hdr = str(p.get("actor_header") or "").strip()
            if not _HEADER.match(hdr):
                raise PolicyError("Counting by actor needs actor_header: the request header that carries the caller's identity")
            out["actor_header"] = hdr
        return out
    if kind == "malicious-source":
        nets = []
        for c in p.get("cidrs") or []:
            try:
                nets.append(str(ipaddress.ip_network(str(c).strip(), strict=False)))
            except ValueError:
                raise PolicyError(f"'{c}' is not an IP address or CIDR range") from None
        if not nets:
            raise PolicyError("Give at least one address or CIDR range")
        if len(nets) > pol["max_cidrs"]:
            raise PolicyError(f"At most {pol['max_cidrs']:,} ranges per policy")
        return {"cidrs": sorted(set(nets)), "reason": str(p.get("reason") or "")[:200]}
    if kind == "geo-restriction":
        cs = sorted({str(c).strip().upper() for c in p.get("countries") or [] if str(c).strip()})
        if not cs or any(not re.match(r"^[A-Z]{2}$", c) for c in cs):
            raise PolicyError("countries must be two-letter ISO 3166 codes, for example US, DE")
        if len(cs) > pol["max_countries"]:
            raise PolicyError("Too many countries")
        t = p.get("type", "deny")
        if t not in ("deny", "allow-only"):
            raise PolicyError("type must be deny or allow-only")
        out = {"countries": cs, "type": t}
        if p.get("data_class"):
            out["data_class"] = _class(p["data_class"], classes)
        return out
    if kind == "data-loss":
        out = {"by": p.get("by", "actor")}
        if out["by"] not in ("actor", "ip"):
            raise PolicyError("by must be actor or ip")
        window = _int(p, "window_seconds", 1, 10**7)
        if window not in pol["data_loss_windows_seconds"]:
            raise PolicyError(f"window_seconds must be one of {', '.join(map(str, pol['data_loss_windows_seconds']))}")
        out["window_seconds"] = window
        if p.get("max_records") not in (None, ""):
            out["max_records"] = _int(p, "max_records", 1, 10**9)
        if p.get("max_bytes") not in (None, ""):
            out["max_bytes"] = _int(p, "max_bytes", 1, 10**12)
        if "max_records" not in out and "max_bytes" not in out:
            raise PolicyError("Set max_records or max_bytes (or both)")
        if p.get("data_class"):
            out["data_class"] = _class(p["data_class"], classes)
        out["enforcement_note"] = "Needs an enforcement point that sees responses (a gateway or sidecar); edge request filters cannot count what leaves."
        return out
    if kind == "custom-signature":
        target, match = p.get("target"), p.get("match", "contains")
        if target not in pol["signature_targets"]:
            raise PolicyError(f"target must be one of {', '.join(pol['signature_targets'])}")
        if match not in ("contains", "exact", "starts_with", "regex"):
            raise PolicyError("match must be contains, exact, starts_with or regex")
        pat = str(p.get("pattern") or "")
        if not pat or len(pat) > pol["max_pattern_length"]:
            raise PolicyError(f"pattern must be 1 to {pol['max_pattern_length']} characters")
        out = {"target": target, "match": match, "pattern": pat}
        if target == "header":
            hdr = str(p.get("header_name") or "").strip()
            if not _HEADER.match(hdr):
                raise PolicyError("A header signature needs header_name")
            out["header_name"] = hdr
        if match == "regex":
            if _UNSUPPORTED_REGEX.search(pat):
                raise PolicyError("Lookarounds and backreferences are not supported by edge regex engines; use a simpler pattern")
            try:
                re.compile(pat)
            except re.error as exc:
                raise PolicyError(f"Not a valid regular expression: {exc}") from None
        return out
    raise PolicyError(f"kind must be one of {', '.join(KINDS)}")


def _class(name, classes):
    names = {c["name"] for c in classes or []}
    if classes is not None and str(name) not in names:
        raise PolicyError(f"'{name}' is not one of the classes in your data-classification framework")
    return str(name)


def clean(data, classes=None):
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 120:
        raise PolicyError("A name of 1 to 120 characters is required")
    kind = data.get("kind")
    if kind not in KINDS:
        raise PolicyError(f"kind must be one of {', '.join(KINDS)}")
    mode = data.get("mode") or "monitor"
    if mode not in MODES:
        raise PolicyError("mode must be monitor or block")
    return {"name": name, "kind": kind, "mode": mode, "enabled": bool(data.get("enabled", True)), "scope": _check_scope(data.get("scope")),
            "params": _check_params(kind, data.get("params"), classes), "description": str(data.get("description") or "")[:500] or None}


def _content(c):
    return json.dumps({k: c[k] for k in ("kind", "mode", "enabled", "scope", "params")}, sort_keys=True)


def _row(r):
    return {"id": r["id"], "name": r["name"], "kind": r["kind"], "mode": r["mode"], "enabled": bool(r["enabled"]), "scope": _j(r["scope_json"], {}), "params": _j(r["params_json"], {}),
            "description": r["description"], "version": r["version"], "approved_by": r["approved_by"], "approved_version": r["approved_version"], "push_state": r["push_state"],
            "last_push_id": r["last_push_id"], "created_by": r["created_by"], "created_at": r["created_at"], "updated_by": r["updated_by"], "updated_at": r["updated_at"],
            "approved": r["approved_version"] == r["version"] and bool(r["approved_by"])}


def _event(conn, policy_id, name, version, action, actor, detail=None):
    conn.execute(insert(db_module.api_policy_events), {"policy_id": policy_id, "policy_name": name, "version": version, "action": action, "actor": actor,
                                                       "detail_json": json.dumps(detail or {}), "at": _now()})


def get(pid, engine=None):
    engine, t = _engine(engine), db_module.api_policies
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(pid))).mappings().first()
    return _row(r) if r else None


def list_all(engine=None):
    engine, t = _engine(engine), db_module.api_policies
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def save(data, actor, policy_id=None, classes=None, engine=None):
    c = clean(data, classes)
    engine, t = _engine(engine), db_module.api_policies
    now = _now()
    with engine.begin() as conn:
        dup = conn.execute(select(t.c.id).where(t.c.name == c["name"])).first()
        if dup and dup[0] != policy_id:
            raise PolicyError("A policy with that name already exists")
        if policy_id is None:
            pid = conn.execute(insert(t), {"name": c["name"], "kind": c["kind"], "mode": c["mode"], "enabled": c["enabled"], "scope_json": json.dumps(c["scope"]),
                                           "params_json": json.dumps(c["params"]), "description": c["description"], "version": 1, "push_state": "draft", "created_by": actor,
                                           "created_at": now, "updated_by": actor, "updated_at": now}).inserted_primary_key[0]
            _event(conn, pid, c["name"], 1, "created", actor, {"kind": c["kind"], "mode": c["mode"]})
        else:
            cur = conn.execute(select(t).where(t.c.id == int(policy_id))).mappings().first()
            if not cur:
                raise KeyError("No such policy")
            old = _row(cur)
            if old["kind"] != c["kind"]:
                raise PolicyError("A policy's kind cannot be changed; create a new policy")
            pid = int(policy_id)
            if _content(old) == _content(c) and old["name"] == c["name"] and (old["description"] or None) == c["description"]:
                return old
            changed = _content(old) != _content(c)
            version = old["version"] + 1 if changed else old["version"]
            state = old["push_state"]
            if changed and state in ("sent", "applied", "failed", "rejected", "pending-push"):
                state = "pending-push"
            conn.execute(update(t).where(t.c.id == pid).values(name=c["name"], mode=c["mode"], enabled=c["enabled"], scope_json=json.dumps(c["scope"]), params_json=json.dumps(c["params"]),
                                                               description=c["description"], version=version, push_state=state, updated_by=actor, updated_at=now))
            if old["mode"] != c["mode"]:
                _event(conn, pid, c["name"], version, "mode-changed", actor, {"from": old["mode"], "to": c["mode"]})
            if old["enabled"] != c["enabled"]:
                _event(conn, pid, c["name"], version, "enabled" if c["enabled"] else "disabled", actor)
            if changed:
                _event(conn, pid, c["name"], version, "updated", actor, {"changed": [k for k in ("mode", "enabled", "scope", "params") if json.dumps(old[k], sort_keys=True) != json.dumps(c[k], sort_keys=True)]})
    return get(pid, engine)


def remove(pid, actor, engine=None):
    engine, t = _engine(engine), db_module.api_policies
    with engine.begin() as conn:
        cur = conn.execute(select(t.c.name, t.c.version).where(t.c.id == int(pid))).first()
        if not cur:
            return False
        conn.execute(delete(t).where(t.c.id == int(pid)))
        _event(conn, int(pid), cur[0], cur[1], "deleted", actor)
    return True


def approve(pid, actor, engine=None):
    """Records that `actor` reviewed this exact version. Blocking policies need an approver other than the person who last edited them."""
    engine, t = _engine(engine), db_module.api_policies
    p = get(pid, engine)
    if not p:
        raise KeyError("No such policy")
    if config.load()["policy"]["require_second_approver_for_block"] and p["updated_by"] == actor:
        raise PolicyError("A different administrator must approve this version: you made the last change")
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(pid)).values(approved_by=actor, approved_version=p["version"]))
        _event(conn, p["id"], p["name"], p["version"], "approved", actor)
    return get(pid, engine)


def can_push(p):
    if p["mode"] == "block" and p["enabled"] and config.load()["policy"]["require_second_approver_for_block"] and not p["approved"]:
        return False, "A policy in block mode must be approved by a second administrator before it can be sent. Approve this version first, or send it in monitor mode."
    return True, ""


def events(pid=None, limit=200, engine=None):
    engine, t = _engine(engine), db_module.api_policy_events
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if pid is not None:
        q = q.where(t.c.policy_id == int(pid))
    with engine.connect() as conn:
        return [{**dict(r), "detail": _j(r["detail_json"], {})} for r in conn.execute(q).mappings().all()]


def pushes(pid=None, limit=200, engine=None):
    engine, t = _engine(engine), db_module.api_policy_pushes
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if pid is not None:
        q = q.where(t.c.policy_id == int(pid))
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(q).mappings().all()]


# ---------------------------------------------------------------- sending
def payload(p, requested_by, approved_by, delivery_id):
    return {"type": "api-protection-policy", "delivery_id": delivery_id,
            "policy": {"id": p["id"], "name": p["name"], "version": p["version"], "kind": p["kind"], "mode": p["mode"], "enabled": p["enabled"], "scope": p["scope"],
                       "params": p["params"], "description": p["description"]},
            "requested_by": requested_by, "approved_by": approved_by if p["mode"] == "block" else None,
            "note": "Quanta does not apply this itself. Verify X-Quanta-Signature and the timestamp, then apply or reject it in your own change process."}


def digest(body):
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def send(pid, actor, connector, connection_id=None, engine=None):
    """Sends one policy to the customer's endpoint through `connector` (a PolicyWebhook) and records the outcome. The caller has already checked confirmation."""
    engine, t, pt = _engine(engine), db_module.api_policies, db_module.api_policy_pushes
    p = get(pid, engine)
    if not p:
        raise KeyError("No such policy")
    ok, why = can_push(p)
    if not ok:
        raise PolicyError(why)
    now = _now()
    with engine.begin() as conn:
        push_id = conn.execute(insert(pt), {"policy_id": p["id"], "policy_name": p["name"], "version": p["version"], "mode": p["mode"], "connection_id": connection_id, "status": "sending",
                                           "payload_sha256": "", "requested_by": actor, "approved_by": p["approved_by"] if p["mode"] == "block" else None, "sent_at": now}).inserted_primary_key[0]
    body = payload(p, actor, p["approved_by"], f"quanta-push-{push_id}")
    status, http, msg = "sent", None, "Delivered. The endpoint's own automation decides whether and how to apply it."
    try:
        res = connector.push(body)
        http = res.get("status")
    except Exception as exc:  # noqa: BLE001 - any failure to deliver is recorded, never lost
        status, msg = "failed", str(exc)[:300]
        http = getattr(getattr(exc, "response", None), "status_code", None)
    with engine.begin() as conn:
        conn.execute(update(pt).where(pt.c.id == push_id).values(status=status, http_status=http, message=msg, payload_sha256=digest(body)))
        conn.execute(update(t).where(t.c.id == p["id"]).values(push_state="sent" if status == "sent" else "failed", last_push_id=push_id))
        _event(conn, p["id"], p["name"], p["version"], "pushed" if status == "sent" else "push-failed", actor, {"push_id": push_id, "http_status": http, "mode": p["mode"]})
    return {**next(x for x in pushes(p["id"], engine=engine) if x["id"] == push_id), "policy_mode": p["mode"]}


def report_status(push_id, status, detail, reporter, engine=None):
    """The customer's automation reports what the edge service said: applied or rejected."""
    if status not in ("applied", "rejected"):
        raise PolicyError("status must be applied or rejected")
    engine, t, pt = _engine(engine), db_module.api_policies, db_module.api_policy_pushes
    with engine.begin() as conn:
        row = conn.execute(select(pt).where(pt.c.id == int(push_id))).mappings().first()
        if not row:
            raise KeyError("No such push")
        conn.execute(update(pt).where(pt.c.id == int(push_id)).values(status=status, reported_at=_now(), reported_by=reporter, message=str(detail or row["message"] or "")[:500]))
        pol = conn.execute(select(t.c.last_push_id).where(t.c.id == row["policy_id"])).first()
        if pol and pol[0] == int(push_id):
            conn.execute(update(t).where(t.c.id == row["policy_id"]).values(push_state=status))
        _event(conn, row["policy_id"], row["policy_name"], row["version"], f"edge-{status}", reporter, {"push_id": int(push_id), "detail": str(detail or "")[:300]})
    return next(x for x in pushes(row["policy_id"], engine=engine) if x["id"] == int(push_id))


def alert_text(push):
    state = {"sent": "was sent to your endpoint", "failed": "FAILED to send", "applied": "was APPLIED at the edge", "rejected": "was REJECTED at the edge"}.get(push["status"], push["status"])
    return (f"Quanta API protection: policy '{push['policy_name']}' (version {push['version']}, {push['mode']} mode) {state}"
            + (f" (HTTP {push['http_status']})" if push.get("http_status") else "") + (f". {push['message']}" if push.get("message") and push["status"] in ("failed", "rejected") else "."))


def notify(push, notify_webhook=None, send_email=None, recipients=()):
    """Raises the per-policy change alert on every configured channel. Returns [{channel, ok, error}]; one channel failing never stops the others."""
    text, out = alert_text(push), []
    if notify_webhook is not None:
        try:
            notify_webhook.send(text)
            out.append({"channel": "notification webhook", "ok": True})
        except Exception as exc:  # noqa: BLE001
            out.append({"channel": "notification webhook", "ok": False, "error": str(exc)[:200]})
    if send_email is not None and recipients:
        try:
            send_email(list(recipients), "Quanta API protection policy change", text)
            out.append({"channel": "email", "ok": True})
        except Exception as exc:  # noqa: BLE001
            out.append({"channel": "email", "ok": False, "error": str(exc)[:200]})
    return out


# ---------------------------------------------------------------- scope
def covers(p, service, method, path_key):
    """Does the policy's scope include this endpoint? An empty scope means every endpoint."""
    sc = p.get("scope") or {}
    if not sc.get("services") and not sc.get("endpoints"):
        return True
    if service in (sc.get("services") or []):
        return True
    for e in sc.get("endpoints") or []:
        m, _, pth = e.partition(" ")
        if m not in ("*", method):
            continue
        if pth.endswith("*"):
            if path_key.startswith(paths.key_of(pth[:-1] or "/").rstrip("/") or "/"):
                return True
        elif paths.key_of(pth) == path_key:
            return True
    return False


def has_active(policies, kind, service, method, path_key, block_only=False):
    return any(p["enabled"] and p["kind"] == kind and (not block_only or p["mode"] == "block") and covers(p, service, method, path_key) for p in policies)
