"""
The secure design assistant: a short questionnaire in, a starting list of security requirements and the pipeline controls that enforce them out.

Deterministic: each rule in design_rules.yaml has an explicit condition on the answers, so the same answers always give the same list and every
requirement can be traced to the rule that raised it. It is a prompt for a design review (what a reviewer would ask), not a threat model and not a
compliance statement; the Threat Models page is where the design is then modelled in full.
"""
from pathlib import Path

import yaml

PATH = Path(__file__).with_name("design_rules.yaml")
STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
STRIDE_PROMPT = {"S": "Can someone pretend to be another user, service or device?", "T": "Can data or code be changed in transit, at rest or in the pipeline?",
                 "R": "Could an action be denied later because nothing recorded who did it?", "I": "Where could data reach someone who should not see it (responses, logs, errors, backups)?",
                 "D": "What can one caller do to make this unavailable to everyone else?", "E": "What would let a caller do more than they are allowed to?"}


def load(path=None):
    with open(path or PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def questions(spec=None):
    return (spec or load())["questions"]


def _match(cond, answers):
    def hit(term):
        q, v = term.split("=", 1)
        return str(answers.get(q, "")).lower() == v.lower()
    ok_all = all(hit(t) for t in cond.get("all") or [])
    ok_any = any(hit(t) for t in cond["any"]) if cond.get("any") else True
    return ok_all and ok_any and bool(cond.get("all") or cond.get("any"))


def validate_answers(answers, spec=None):
    """Clean answers: unknown questions are rejected, a missing one counts as not answered (never as no)."""
    qs = {q["id"]: q for q in questions(spec)}
    clean = {}
    for k, v in (answers or {}).items():
        if k not in qs:
            raise ValueError(f"Unknown question {k!r}")
        q = qs[k]
        v = str(v).strip().lower()
        if q["type"] == "yesno" and v not in ("yes", "no"):
            raise ValueError(f"{q['label']} must be yes or no")
        if q["type"] == "choice" and v not in q["options"]:
            raise ValueError(f"{q['label']} must be one of {', '.join(q['options'])}")
        clean[k] = v
    return clean


def assess(answers, lib, spec=None):
    """-> {requirements, controls, threat_prompts, unanswered}. `lib` is the control library (shipped plus custom) so each control shows its title and stage."""
    spec = spec or load()
    answers = validate_answers(answers, spec)
    by_id = {c["id"]: c for c in lib}
    reqs, controls = [], {}
    for r in spec["rules"]:
        if _match(r["when"], answers):
            ctrls = [{"id": c, "title": by_id[c]["title"], "stage": by_id[c]["stage"]} for c in r.get("controls") or [] if c in by_id]
            reqs.append({"id": r["id"], "priority": r["priority"], "requirement": r["requirement"], "why": r["why"], "asvs": r.get("asvs"), "stride": r.get("stride") or [], "controls": ctrls})
            for c in ctrls:
                controls.setdefault(c["id"], {**c, "needed_by": []})["needed_by"].append(r["id"])
    reqs.sort(key=lambda x: (x["priority"] != "must", x["id"]))
    stride = []
    for letter in "STRIDE":
        why = [r["id"] for r in reqs if letter in r["stride"]]
        if why:
            stride.append({"letter": letter, "name": STRIDE[letter], "prompt": STRIDE_PROMPT[letter], "raised_by": why})
    return {"answers": answers, "requirements": reqs, "controls": sorted(controls.values(), key=lambda c: (-len(c["needed_by"]), c["id"])), "threat_prompts": stride,
            "unanswered": [q["id"] for q in spec["questions"] if q["id"] not in answers],
            "note": "A starting list for a design review. It asks what a reviewer would ask; it is not a threat model and not a compliance statement."}


def to_markdown(name, result):
    L = [f"# Security requirements: {name}", "", "A starting list for the design review, from Quanta's secure design assistant. Review it, remove what does not apply, and keep what remains with the design.", ""]
    for pr, title in (("must", "Required"), ("should", "Recommended")):
        rs = [r for r in result["requirements"] if r["priority"] == pr]
        if rs:
            L += [f"## {title}", ""]
            for r in rs:
                L.append(f"- **{r['requirement']}**")
                L.append(f"  - Why: {r['why']}")
                if r["asvs"]:
                    L.append(f"  - Reference: OWASP ASVS 4.0, {r['asvs']}")
                if r["controls"]:
                    L.append("  - Enforced by: " + ", ".join(c["title"] for c in r["controls"]))
            L.append("")
    if result["threat_prompts"]:
        L += ["## Questions for the threat model", ""] + [f"- **{t['name']}**: {t['prompt']}" for t in result["threat_prompts"]] + [""]
    if result["controls"]:
        L += ["## Pipeline controls to put in place", ""] + [f"- {c['title']} ({c['stage']} stage)" for c in result["controls"]] + [""]
    L.append(result["note"])
    return "\n".join(L) + "\n"
