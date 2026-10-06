"""
A small deterministic "is a model needed?" router.

Quanta's decisions are made by code, so most of what a consumer might ask a language model for (an explanation of a verdict, a routing note) is
already available from the answer's evidence and a template. This helper says so, and counts it: each logged decision records whether generated
text was actually needed, so the AI Usage page can show how many model calls the gate avoided.

It decides nothing about the answer. `purpose` is what the consumer wants: "decide" (never needs a model), "explain" (the evidence is the
explanation when there is any) or "draft" (free-form prose the evidence cannot supply; a model, or a person, is needed). The count is a
counterfactual estimate (calls a design that asked a model every time would have made), not a measured saving.
"""
PURPOSES = ("decide", "explain", "draft")


def needs_generated_text(answers, route, purpose="decide"):
    """Returns {needs_model, reason}. Deterministic: depends only on the purpose, the evidence and the route."""
    if purpose not in PURPOSES:
        raise ValueError(f"purpose must be one of {', '.join(PURPOSES)}")
    if purpose == "decide":
        return {"needs_model": False, "reason": "The answer is a value in a fixed set, produced by code."}
    if purpose == "explain":
        if all(a.evidence for a in answers.values()):
            return {"needs_model": False, "reason": "Every answer carries its evidence, which is the explanation."}
        return {"needs_model": True, "reason": "An answer has no evidence to explain it from."}
    if route == "human":
        return {"needs_model": True, "reason": "Free-form text was asked for on a decision a person will make; a draft may help them."}
    return {"needs_model": True, "reason": "Free-form text cannot be built from fixed answers."}
