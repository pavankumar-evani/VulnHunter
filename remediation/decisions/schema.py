"""
Typed questions and typed answers.

A decision asks named questions whose answer space is fixed in advance: Choice (one of a fixed option list), Score (one point on an ordered scale) or
YesNo. An evaluator returns an Answer for each question: a value inside that space, the probability of that value, a confidence, and the evidence
behind it. An answer outside the space is rejected, never coerced, so the code that branches on it never meets a value it was not written for.

Nothing here depends on any model. An Evaluator is anything with `name`, `version` and `evaluate(decision, state) -> {question name: Answer}`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

KINDS = ("choice", "score", "yesno")
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
MAX_EVIDENCE = 12
MAX_EVIDENCE_LEN = 300


class SchemaViolation(ValueError):
    """An answer, question or evaluator result that is outside the declared schema."""


@dataclass(frozen=True)
class Question:
    name: str
    kind: str
    options: tuple
    prompt: str = ""

    def __post_init__(self):
        if self.kind not in KINDS:
            raise SchemaViolation(f"question kind must be one of {', '.join(KINDS)}")
        if not NAME.match(self.name or ""):
            raise SchemaViolation("question name must be lowercase letters, digits, - or _")
        opts = tuple(self.options)
        if len(opts) < 2 or len(set(opts)) != len(opts):
            raise SchemaViolation("a question needs at least two distinct options")
        if self.kind == "yesno" and opts != ("yes", "no"):
            raise SchemaViolation("a yes/no question has exactly the options yes and no")
        object.__setattr__(self, "options", opts)

    def check(self, value):
        if value not in self.options:
            raise SchemaViolation(f"'{value}' is not an allowed answer to '{self.name}' (allowed: {', '.join(map(str, self.options))})")
        return value

    def rank(self, value):
        """Position on the scale (a Score's order is its meaning)."""
        return self.options.index(self.check(value))


def Choice(name, options, prompt=""):
    return Question(name, "choice", tuple(options), prompt)


def Score(name, scale, prompt=""):
    """`scale` is ordered from lowest to highest."""
    return Question(name, "score", tuple(scale), prompt)


def YesNo(name, prompt=""):
    return Question(name, "yesno", ("yes", "no"), prompt)


@dataclass(frozen=True)
class Answer:
    question: Question
    value: object
    probability: float            # probability of `value`
    confidence: float             # how far the evidence supports using that probability
    evidence: tuple = ()
    evaluator: str = ""
    version: str = ""
    distribution: dict = field(default_factory=dict)   # optional: probability of every option; must sum to 1

    def __post_init__(self):
        self.question.check(self.value)
        for label, v in (("probability", self.probability), ("confidence", self.confidence)):
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0.0 <= v <= 1.0:
                raise SchemaViolation(f"{label} must be a number between 0 and 1")
        ev = tuple(str(e)[:MAX_EVIDENCE_LEN] for e in self.evidence)[:MAX_EVIDENCE]
        object.__setattr__(self, "evidence", ev)
        if self.distribution:
            for k in self.distribution:
                self.question.check(k)
            if abs(sum(self.distribution.values()) - 1.0) > 1e-6:
                raise SchemaViolation("a distribution must sum to 1")

    @property
    def gate_confidence(self):
        return min(self.probability, self.confidence)

    def to_dict(self):
        return {"question": self.question.name, "value": self.value, "probability": round(self.probability, 4), "confidence": round(self.confidence, 4),
                "evidence": list(self.evidence), "evaluator": self.evaluator, "version": self.version,
                "distribution": {k: round(v, 4) for k, v in self.distribution.items()} or None}


class Evaluator(Protocol):
    name: str
    version: str

    def evaluate(self, decision, state: dict) -> dict:  # {question name: Answer}
        ...


def run(decision, evaluator, state):
    """Runs an evaluator and enforces the schema on whatever it returns: exactly the decision's questions, each answered inside its own answer space."""
    out = evaluator.evaluate(decision, state)
    if not isinstance(out, dict):
        raise SchemaViolation("an evaluator must return a dict of answers")
    want = {q.name: q for q in decision.questions}
    if set(out) != set(want):
        raise SchemaViolation(f"evaluator answered {sorted(out)}; the decision asks {sorted(want)}")
    for name, ans in out.items():
        if not isinstance(ans, Answer) or ans.question != want[name]:
            raise SchemaViolation(f"the answer to '{name}' does not belong to that question")
        want[name].check(ans.value)
    return out
