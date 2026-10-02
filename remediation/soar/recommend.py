"""
Playbook recommendation: which playbook has worked on alerts like this one.

This is a small, transparent statistical model, not a neural network. For an alert it looks back over every past playbook run and weighs each by how
much its alert resembled this one:

  similarity = 0.35 * same ATT&CK technique + 0.30 * same detection rule + 0.20 * same alert category + 0.15 * same severity   (each 0 or 1)

For each playbook the evidence is the similarity-weighted number of past runs on similar alerts (only alerts with similarity >= 0.3 count) and how many of those:
  completed     the run finished (not failed, rejected or cancelled)
  resolved      the alert was then closed with a disposition (a person finished the job)
  hit-the-mark  the alert was closed true-positive, for playbooks that respond (those with a response step), or any closure, for the rest
The ranking score is a Laplace-smoothed completion rate:  (weighted completed + 0.5) / (weighted runs + 1),  scaled up a little by how much evidence there is:
score = rate * (1 - 1 / (1 + weighted runs)), so a playbook used once on a near-identical alert does not outrank one used twenty times.

With no usable history (a new install) it falls back to the playbooks' own triggers: the enabled on-alert playbooks that would match this alert, then manual
playbooks whose name or description mentions the alert's category. The basis ("history", "trigger" or "none") is always reported, with the numbers, so a
person can see why a playbook was suggested.

A recommendation never runs anything. Starting a playbook is the same dry-run-first, confirm-gated action as always, and a playbook with response steps still
needs a second person to approve.
"""
from remediation.hunting import soc
from remediation.soar import playbooks

WEIGHTS = {"technique": 0.35, "rule": 0.30, "category": 0.20, "severity": 0.15}
MIN_SIMILARITY = 0.3


def features(alert, cfg=None):
    return {"technique": (alert.get("technique") or "").upper().split(".")[0] or None, "rule": alert.get("rule_name") or None, "category": soc.classify(alert, cfg),
            "severity": alert.get("severity")}


def similarity(a, b):
    return round(sum(w for k, w in WEIGHTS.items() if a.get(k) and a.get(k) == b.get(k)), 2)


def responds(pb):
    return any(s["type"] == "response-action" for s in pb["steps"])


def history_stats(feat, past, cfg=None):
    """past: [{alert, run, playbook}] -> per-playbook weighted counts."""
    stats = {}
    for p in past:
        sim = similarity(feat, features(p["alert"], cfg))
        if sim < MIN_SIMILARITY:
            continue
        st = stats.setdefault(p["playbook"]["id"], {"playbook": p["playbook"], "w_runs": 0.0, "w_completed": 0.0, "w_resolved": 0.0, "w_hit": 0.0, "runs": 0, "best_sim": 0.0})
        st["w_runs"] += sim
        st["runs"] += 1
        st["best_sim"] = max(st["best_sim"], sim)
        done = p["run"]["status"] == "completed"
        closed = p["alert"].get("status") == "closed" and bool(p["alert"].get("disposition"))
        st["w_completed"] += sim if done else 0
        st["w_resolved"] += sim if (done and closed) else 0
        hit = (p["alert"].get("disposition") == "true-positive") if responds(p["playbook"]) else closed
        st["w_hit"] += sim if (done and hit) else 0
    return stats


def recommend(alert, playbooks_list, past, cfg=None, limit=5):
    feat = features(alert, cfg)
    live = {p["id"]: p for p in playbooks_list if p["enabled"]}
    stats = {k: v for k, v in history_stats(feat, [x for x in past if x["playbook"]["id"] in live], cfg).items()}
    out = []
    for pid, st in stats.items():
        rate = (st["w_completed"] + 0.5) / (st["w_runs"] + 1)
        score = rate * (1 - 1 / (1 + st["w_runs"]))
        pb = live[pid]
        out.append({"playbook_id": pid, "name": pb["name"], "score": round(score, 3), "basis": "history", "runs": st["runs"], "completed_rate": round(rate, 2), "closed_after": round(st["w_resolved"] / st["w_runs"], 2) if st["w_runs"] else None,
                    "best_similarity": st["best_sim"], "needs_second_person": responds(pb),
                    "why": f"Run {st['runs']} time(s) on similar alerts (best match {int(st['best_sim'] * 100)}% similar); {round(100 * rate)}% of runs completed."})
    if not out:
        for pb in live.values():
            if playbooks.matches_trigger(pb, alert):
                out.append({"playbook_id": pb["id"], "name": pb["name"], "score": 0.2, "basis": "trigger", "runs": 0, "completed_rate": None, "closed_after": None, "best_similarity": None,
                            "needs_second_person": responds(pb), "why": "Its own trigger matches this alert; there is no run history for similar alerts yet."})
        if not out:
            cat = feat["category"]
            for pb in live.values():
                text = (pb["name"] + " " + (pb.get("description") or "")).lower()
                if cat != "other" and cat in text:
                    out.append({"playbook_id": pb["id"], "name": pb["name"], "score": 0.1, "basis": "trigger", "runs": 0, "completed_rate": None, "closed_after": None, "best_similarity": None,
                                "needs_second_person": responds(pb), "why": f"Its name or description mentions {cat} alerts; there is no run history yet."})
    out.sort(key=lambda r: (-r["score"], r["name"]))
    return {"features": feat, "basis": out[0]["basis"] if out else "none", "recommendations": out[:limit],
            "note": "A suggestion from past runs. Nothing is started by it; a dry run comes first, and anything that changes your environment needs a second person."}
