"""
TTP identification: from text (an alert, a log excerpt, an analyst's note), which ATT&CK techniques does it describe?

The model is a multinomial Naive Bayes classifier over word and word-pair features, trained on every call from three sources:
  1. the phrase lexicon (ttp_lexicon.yaml): short examples written for each technique;
  2. the hunt library: each technique's name and the strings in its detections (process names, command fragments, URL patterns);
  3. optionally, labelled history: the text of alerts an analyst closed as true positive, labelled with the technique the alert carried, so the model learns the
     wording of this environment.
Training is counting, so it takes milliseconds and the same inputs always give the same answer.

How a prediction is made. The text is split into lower-case tokens (keeping things like -enc and /c, dropping a trailing .exe and common endings, and ignoring filler words such as "by" and "the") and adjacent pairs. For each technique the model
adds up log P(token | technique), with add-alpha smoothing (alpha 0.1) so an unseen pairing does not zero a class, over the tokens the model knows (unknown tokens are
ignored, so noise does not matter). A token's contribution is capped at three occurrences so a repeated word cannot dominate, and is scaled by how specific the
token is: weight = ln(classes / classes containing the token) / ln(classes), so "user" (present in many techniques) counts for little and "procdump" (present in one) counts
in full. The scores become probabilities
with a softmax. The answer lists the top techniques with their probability and the tokens that pushed hardest toward each (the log-likelihood ratio against the
other techniques), so an analyst sees WHY.

An ATT&CK id written in the text (T1059, T1003.001) is reported as stated, not inferred.

Confidence. A prediction is called confident when the top probability is at least 0.5 and at least two distinct known tokens support it. Otherwise the answer
is still shown, labelled weak, because a weak lead to check is useful but must not be mistaken for an identification. If no token is known the answer is "no technique".

Limits, stated plainly: it recognises wording it has seen, not behaviour; an attacker who renames tools defeats it; the lexicon covers the techniques in
attack_tactics.yaml and nothing else; and probabilities are relative to those techniques only (a benign command is still assigned to its nearest technique if it shares
words). Treat the output as a prompt for an analyst, which is how the interface presents it.
"""
import math
import re
from pathlib import Path

import yaml

from remediation.hunting import generate, report

LEXICON_PATH = Path(__file__).with_name("ttp_lexicon.yaml")
ALPHA = 0.1
CAP = 3
TOKEN = re.compile(r"[-/]?[a-z0-9_][a-z0-9_.\-]*")
ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CACHE = {}


STOP = {"by", "the", "an", "of", "on", "to", "from", "with", "and", "in", "is", "was", "for", "at", "as", "or", "it", "be", "this", "that", "has", "had", "are", "were", "then"}


def _stem(tok):
    if tok.endswith(".exe"):
        tok = tok[:-4]
    for suffix in ("ing", "ed", "es", "s"):
        if len(tok) > len(suffix) + 3 and tok.endswith(suffix) and not tok.endswith("ss"):
            return tok[: -len(suffix)]
    return tok


def tokens(text):
    toks = [_stem(t.rstrip(".-")) for t in TOKEN.findall((text or "").lower())]
    toks = [t for t in toks if len(t) > 1 and t not in STOP]
    return toks + [f"{a} {b}" for a, b in zip(toks, toks[1:])]


def _strings(sel):
    out = []
    for v in sel.values():
        for x in v if isinstance(v, list) else [v]:
            if isinstance(x, str):
                out.append(x.replace("*", " ").replace("\\", " "))
    return out


def corpus(examples=()):
    """{technique: [documents]} from the lexicon, the hunt library and any labelled examples."""
    with open(LEXICON_PATH, encoding="utf-8") as fh:
        lex = yaml.safe_load(fh) or {}
    docs = {t: list(map(str, phrases)) for t, phrases in lex.items()}
    for tid, entry in generate.library().items():
        d = docs.setdefault(tid, [])
        d.append(entry.get("hunt", ""))
        for det in entry.get("detections", []):
            d += _strings(det["selection"])
    for tid, info in report.tactics().items():
        docs.setdefault(tid, []).append(info["name"])
    for text, tid in examples:
        docs.setdefault(str(tid).split(".")[0], []).append(text)
    return docs


def train(examples=()):
    key = (LEXICON_PATH.stat().st_mtime, tuple(sorted((t[:80], tid) for t, tid in examples)))
    if _CACHE.get("key") == key:
        return _CACHE["model"]
    counts, totals, vocab = {}, {}, set()
    for tid, docs in corpus(examples).items():
        c = counts.setdefault(tid, {})
        for d in docs:
            for t in tokens(d):
                c[t] = c.get(t, 0) + 1
                vocab.add(t)
        totals[tid] = sum(c.values())
    n = len(counts)
    df = {tok: sum(1 for c in counts.values() if tok in c) for tok in vocab}
    weight = {tok: (math.log(n / d) / math.log(n) if n > 1 else 1.0) for tok, d in df.items()}
    model = {"counts": counts, "totals": totals, "vocab": vocab, "classes": sorted(counts), "weight": weight}
    _CACHE.update(key=key, model=model)
    return model


def _logp(model, tid, tok):
    return math.log((model["counts"][tid].get(tok, 0) + ALPHA) / (model["totals"][tid] + ALPHA * len(model["vocab"])))


def classify(text, examples=(), top=3):
    """-> {techniques: [{id, name, tactic, probability, evidence, source}], confident, known_tokens}"""
    model = train(examples)
    stated = []
    for tid in dict.fromkeys(m.upper() for m in ATTACK_ID.findall(text or "")):
        info = report.technique_info(tid)
        stated.append({"id": tid, "name": info and info["name"], "tactic": info and info["tactic"], "probability": 1.0, "evidence": ["stated in the text"], "source": "stated"})
    toks = [t for t in tokens(text) if t in model["vocab"]]
    freq = {}
    for t in toks:
        freq[t] = min(CAP, freq.get(t, 0) + 1)
    if not freq:
        return {"techniques": stated, "confident": bool(stated), "known_tokens": 0}
    scores = {tid: sum(n * model["weight"][t] * _logp(model, tid, t) for t, n in freq.items()) for tid in model["classes"]}
    top_score = max(scores.values())
    exp = {tid: math.exp(s - top_score) for tid, s in scores.items()}
    z = sum(exp.values())
    ranked = sorted(((v / z, tid) for tid, v in exp.items()), reverse=True)[:top]
    out = []
    for p, tid in ranked:
        others = [o for o in model["classes"] if o != tid]
        contrib = []
        for t in freq:
            if model["counts"][tid].get(t):
                rest = sum((model["counts"][o].get(t, 0) + ALPHA) / (model["totals"][o] + ALPHA * len(model["vocab"])) for o in others) / len(others)
                contrib.append((model["weight"][t] * (_logp(model, tid, t) - math.log(rest)), t))
        contrib.sort(reverse=True)
        ev = [t for llr, t in contrib if llr > 0][:5]
        info = report.technique_info(tid)
        out.append({"id": tid, "name": info and info["name"], "tactic": info and info["tactic"], "probability": round(p, 3), "evidence": ev, "source": "model"})
    already = {s["id"].split(".")[0] for s in stated}
    out = [o for o in out if o["id"] not in already]
    best = out[0] if out else None
    confident = bool(stated) or bool(best and best["probability"] >= 0.5 and len(best["evidence"]) >= 2)
    return {"techniques": stated + out, "confident": confident, "known_tokens": len(freq)}
