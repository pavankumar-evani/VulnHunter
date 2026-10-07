"""
The hunt engine: finalise generator output (data readiness, queries, score, learned history), refresh idempotently, list within a capacity, and move a hypothesis through
its lifecycle. Nothing here runs a search: `accept` creates an ordinary hunt record, and running a lead stays the existing confirm-gated action on that hunt.
"""
import datetime

from remediation.hunting import store as hunt_store, usecase_store, usecases
from remediation.hunting.engine import context as ctx_mod, generators, model as m, readiness, render, scoring, store
from remediation.hunting.engine.store import TransitionError  # noqa: F401  (re-exported for the API layer)

NOTE = ("A suggestion is a hypothesis to test, not a finding. Quanta suggests where to look from data it already holds, shows why, and never runs a search by itself; "
        "you run the leads in your own tools (or confirm a Splunk search) and record what you found.")


def finalise(h, ctx, lib=None):
    """Adds readiness, queries, tactics, coverage, effort, learned history and the score to a raw hypothesis."""
    lib = lib if lib is not None else render.library()
    wanted = list(dict.fromkeys(t.upper() for t in h.pop("techniques_wanted")))
    techs = [m.technique_entry(t, lib) for t in wanted]
    sc = h["scope"]
    hyp_text = h["hypothesis"]
    queries, missing = render.queries_for(wanted, sc["assets"], sc["identities"], lib, hyp_text=hyp_text)
    src_names = list(dict.fromkeys(ds for t in wanted for ds in (lib.get(t.split(".")[0]) or {}).get("data_sources", [])))
    ready = readiness.assess(src_names, ctx.connections)
    sig = h["signals"]
    if not sig.get("coverage"):
        if not ctx.rules or not wanted:
            sig["coverage"] = "unknown"
        else:
            cov = usecases.covered_techniques(ctx.rules)
            have = [t.split(".")[0] in cov for t in wanted]
            sig["coverage"] = "covered" if all(have) else "partial" if any(have) else "none"
    gaps = []
    if not wanted:
        gaps.append("No ATT&CK technique is tagged for this evidence, so no queries were generated; write them for your data model.")
    if missing:
        gaps.append("The hunt library has no queries for " + ", ".join(missing) + "; write them for your data model.")
    if h.get("source_note"):
        gaps.append(h["source_note"])
    eff = scoring.effort(sc["counts"], bool(queries), missing)
    stats = ctx.stats.get(h["pattern_key"]) or {"concluded": 0, "true_positive": 0, "benign": 0, "inconclusive": 0, "dismissed": 0}
    pts, note, suppressed = scoring.learned_adjust(stats, ctx.cfg)
    s = scoring.score(sig, eff, pts, note, ctx.cfg)
    tactics = list(dict.fromkeys(tc for t in techs for tc in t["tactics"]))
    plain = hyp_text + (" To test it: " + "; ".join(dict.fromkeys(q["description"] for q in queries)) if queries else " No ready-made queries exist for this behaviour; describe it to the analyst who owns your SIEM.")
    out = {**h, "techniques": techs, "tactics": tactics, "data_sources": ready["sources"], "data_readiness": ready["summary"], "queries": queries, "description": plain,
           "effort": eff, "expected_value": scoring.expected_value(s["score"], sig), "priority": s, "learned": {"points": pts, "note": note, "suppressed": suppressed, "stats": stats},
           "gaps": gaps, "evidence_refs": m.ev_refs(h["why_now"])}
    out["draft_detection"] = queries[0]["sigma"] if queries and h["generator"] in ("coverage-gap", "lessons-learned", "model-assisted") else None
    out.pop("source_note", None)
    return out


def run_generators(ctx):
    lib = render.library()
    items, gaps = [], []
    for name, fn in generators.GENERATORS:
        try:
            hs, g = fn(ctx, lib)
        except Exception as exc:  # noqa: BLE001 - a broken generator is reported, never allowed to hide the others
            hs, g = [], [f"The {name} generator failed ({type(exc).__name__}: {str(exc)[:160]}); its suggestions are missing from this refresh."]
        gaps += [{"generator": name, "note": n} for n in g]
        items += hs
    best = {}
    for h in (finalise(h, ctx, lib) for h in items):
        if h["id"] not in best or h["priority"]["score"] > best[h["id"]]["priority"]["score"]:
            best[h["id"]] = h
    return sorted(best.values(), key=lambda h: (-h["priority"]["score"], h["id"])), gaps


def refresh(findings, engine=None, actor="system", now=None, ctx=None):
    """Regenerates every suggestion from the data Quanta holds. Idempotent: running it twice on the same data changes nothing but the refresh record."""
    ctx = ctx or ctx_mod.load(findings, engine, now)
    ctx.stats = store.pattern_stats(engine)
    items, gaps = run_generators(ctx)
    synced = sync_with_hunts(engine, now)   # first, so a hunt that closed since the last refresh counts toward the learned history below
    counts = store.apply_refresh(items, ctx.cfg, actor, now, engine)
    with _engine(engine).begin() as conn:
        store.add_event(conn, "_engine", "refresh", actor, None, {**counts, "generated": len(items), "gaps": gaps, "synced": synced}, now)
    return {**counts, "generated": len(items), "gaps": gaps, "synced_from_hunts": synced}


def _engine(engine):
    from remediation.utils import db as db_module
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def refresh_if_due(findings, engine=None, now=None):
    cfg = ctx_mod.config()
    last = store.last_refresh(engine)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if last:
        try:
            if now - datetime.datetime.strptime(last["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) < datetime.timedelta(minutes=int(cfg["refresh_minutes"])):
                return None
        except ValueError:
            pass
    return refresh(findings, engine, now=now)


# ---------------------------------------------------------------- views
def listing(engine=None, status=None, hunt_type=None, tactic=None, include_suppressed=False, limit=None):
    cfg = ctx_mod.config()
    cap = int(cfg["max_suggestions"])
    rows = store.all_rows(engine)
    if status:
        rows = [r for r in rows if r["status"] == status]
        shown_cap = None
    else:
        rows = [r for r in rows if r["status"] == "suggested" and r["current"]]
        shown_cap = cap
    if hunt_type:
        rows = [r for r in rows if r["hunt_type"] == hunt_type]
    if tactic:
        rows = [r for r in rows if tactic.lower() in [t.lower() for t in r["tactics"]]]
    hidden = [r for r in rows if r["learned"]["suppressed"] and r["status"] == "suggested"]
    if not include_suppressed:
        rows = [r for r in rows if r not in hidden]
    total = len(rows)
    rows = rows[: min(limit, shown_cap) if limit and shown_cap else (limit or shown_cap or len(rows))]
    last = store.last_refresh(engine)
    return {"suggestions": rows, "total": total, "shown": len(rows), "cap": cap, "capped": total > len(rows), "suppressed_hidden": len(hidden) if not include_suppressed else 0,
            "gaps": (last or {}).get("gaps", []), "last_refresh": (last or {}).get("at"), "note": NOTE}


def detail(hid, engine=None):
    h = store.get(hid, engine)
    if not h:
        return None
    sync_with_hunts(engine)
    h = store.get(hid, engine)
    return {**h, "events": store.events(hid, engine), "hunt": hunt_store.get_hunt(h["hunt_id"], engine) if h.get("hunt_id") else None, "note": NOTE}


# ---------------------------------------------------------------- lifecycle
ORDER = {"accepted": 0, "running": 1, "evidence-recorded": 2, "concluded": 3}


def sync_with_hunts(engine=None, now=None):
    """Follows the linked hunt record: a hunt that has run becomes running, a lead with a recorded result becomes evidence-recorded, a closed hunt concludes the suggestion
    (confirmed -> true-positive, not-found -> benign, needs-data -> inconclusive). Moves forward only."""
    n = 0
    for h in store.all_rows(engine):
        if h["status"] not in ("accepted", "running", "evidence-recorded") or not h.get("hunt_id"):
            continue
        hunt = hunt_store.get_hunt(h["hunt_id"], engine)
        if not hunt:
            continue
        if hunt["status"] == "closed" and hunt["outcome"]:
            target, cols = "concluded", {"outcome": m.FROM_HUNT_OUTCOME[hunt["outcome"]], "outcome_notes": hunt.get("notes") or None}
        elif any(q.get("result") in ("hits", "no-hits") for q in hunt["queries"]):
            target, cols = "evidence-recorded", {}
        elif hunt["status"] == "active":
            target, cols = "running", {}
        else:
            continue
        if ORDER[target] > ORDER[h["status"]]:
            store.set_state(h["id"], target, "system", engine=engine, now=now, body="Followed the linked hunt", **cols)
            n += 1
    return n


def _prep_notes(h):
    lines = ["Why now:"] + [f"- {e['label']}" + (f" ({e['detail']})" if e["detail"] else "") for e in h["why_now"]]
    lines += ["", "Expected if malicious:"] + [f"- {x}" for x in h["expected_malicious"]] + ["", "Likely benign explanations:"] + [f"- {x}" for x in h["likely_benign"]]
    lines += ["", f"Scope and time box: {h['scoping']}", f"Next step: {h['next_step']}", "", "Data readiness: " + h["data_readiness"]["status"]]
    if h["scope"]["identities"]:
        lines.append("Identities in scope: " + ", ".join(h["scope"]["identities"][:30]))
    lines += [f"Gap: {g}" for g in h["gaps"]]
    return "\n".join(lines)


def accept(hid, actor, owner=None, engine=None):
    h = store.get(hid, engine)
    if not h:
        raise KeyError("No such suggestion")
    if h["status"] != "suggested":
        raise TransitionError(f"A suggestion that is {h['status']} cannot be accepted")
    spl = [{k: q[k] for k in ("technique", "name", "domain", "source", "language", "query", "result", "notes", "description", "kql", "sigma", "selection", "hosts", "index") if k in q} for q in h["queries"]]
    try:
        hunt = hunt_store.create_hunt({"title": h["title"], "hypothesis": h["hypothesis"], "source": "hypothesis", "source_ref": h["id"], "techniques": [{"technique_id": t["technique_id"], "technique_name": t["technique_name"]} for t in h["techniques"]],
                                       "assets": h["scope"]["assets"], "data_sources": [d["name"] for d in h["data_sources"]], "queries": spl, "notes": _prep_notes(h), "owner": owner}, actor, engine)
    except ValueError:
        hunt = next((x for x in hunt_store.list_hunts(engine) if x["source"] == "hypothesis" and x["source_ref"] == h["id"]), None)
        if not hunt:
            raise
    return store.set_state(h["id"], "accepted", actor, body=f"Created hunt {hunt['id']}", data={"hunt_id": hunt["id"]}, hunt_id=hunt["id"], engine=engine)


def dismiss(hid, reason, notes, actor, engine=None):
    if reason not in m.DISMISS_REASONS:
        raise ValueError(f"reason must be one of {', '.join(m.DISMISS_REASONS)}")
    if reason == "other" and not (notes or "").strip():
        raise ValueError("Say why in the notes when the reason is 'other'")
    return store.set_state(hid, "dismissed", actor, body=(notes or "").strip() or reason, data={"reason": reason}, dismissal_reason=reason, engine=engine)


def conclude(hid, outcome, notes, actor, engine=None):
    if outcome not in m.OUTCOMES:
        raise ValueError(f"outcome must be one of {', '.join(m.OUTCOMES)}")
    if not (notes or "").strip():
        raise ValueError("Write outcome notes: what you looked at and what you saw (or did not)")
    h = store.get(hid, engine)
    if not h:
        raise KeyError("No such suggestion")
    if h["status"] not in ("accepted", "running", "evidence-recorded"):
        raise TransitionError(f"A suggestion that is {h['status']} cannot be concluded")
    if h.get("hunt_id"):
        hunt = hunt_store.get_hunt(h["hunt_id"], engine)
        if hunt and hunt["status"] != "closed":
            hunt_store.update_hunt(h["hunt_id"], {"status": "closed", "outcome": m.HUNT_OUTCOME[outcome]}, engine)
    return store.set_state(hid, "concluded", actor, body=notes.strip(), data={"outcome": outcome}, outcome=outcome, outcome_notes=notes.strip(), engine=engine)


def promote(hid, actor, engine=None):
    h = store.get(hid, engine)
    if not h:
        raise KeyError("No such suggestion")
    if h["status"] != "concluded":
        raise TransitionError("Only a concluded hunt can be promoted to a detection")
    tids = [t["technique_id"] for t in h["techniques"]]
    key = "hunt-" + h["id"][4:]
    sigma = h.get("draft_detection") or (h["queries"][0]["sigma"] if h["queries"] else
                                         "# No library detection exists for this behaviour.\n# Write the selection from what the hunt found, then test it against recent data before enabling.\n")
    score = int(min(100, max(0, h["priority"]["score"])))
    case = {"key": key, "kind": "hunt-promotion", "title": f"Detect: {h['title']}", "hypothesis": h["hypothesis"], "techniques": tids, "data_sources": [d["name"] for d in h["data_sources"]],
            "evidence": {"hypothesis_id": h["id"], "outcome": h["outcome"], "outcome_notes": h["outcome_notes"], "reasons": [e["label"] for e in h["why_now"]][:6]}, "score": score, "sigma": sigma,
            "expected_false_positives": h["likely_benign"] or ["Test against recent data to find them."], "test_plan": usecases.test_plan(h["techniques"][0]["technique_name"] if h["techniques"] else "the behaviour", 30)}
    usecase_store.sync([case], engine)
    if h.get("hunt_id"):
        hunt_store.update_hunt(h["hunt_id"], {"detection_created": True}, engine)
    return store.set_state(hid, "promoted", actor, body=f"Created detection use case {key} (proposed; not counted as coverage until implemented)", data={"use_case": key}, promoted_key=key, engine=engine)
