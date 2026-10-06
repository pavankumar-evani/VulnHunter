# Typed decisions, the confidence gate and calibration

`remediation/decisions/` is a vendor-neutral decision layer: a decision is a state plus named, typed questions with fixed answer spaces; an evaluator answers them in one pass with probabilities; code branches on the values; low confidence goes to a person. It calls no third-party model and depends on none. This is the "Decisions" row of `docs/AI_ENGINEERING_ROADMAP.md`.

## Pieces

| File | Role |
|---|---|
| `schema.py` | `Choice` (fixed options), `Score` (ordered scale), `YesNo`; `Answer(value, probability, confidence, evidence[], evaluator, version)`; the `Evaluator` protocol; `run()` rejects any evaluator result that is missing a question, answers a different question, or is outside the answer space (`SchemaViolation`). |
| `gate.py` + `config/decision_policy.yaml` | Thresholds per decision: `auto`, `review`, else `human`. The gate uses the lowest `min(probability, confidence)` over the decision's answers. |
| `registry.py` | The three registered decisions and their deterministic evaluators. |
| `calibration.py` | `decision_log` table, outcomes, reliability bins, Brier, ECE, override rate, recommendations. |
| `router.py` | Says whether generated text is needed; feeds the "model calls avoided" count. |
| `service.py` | `evaluate()` (dry), plus the two hooks the SOC code uses. |

## The rule that cannot be configured away

A decision is routed **auto** only if the policy file declares it `reversible: true` and `local: true` **and** the decision, as registered in code, has `touches_environment = False`. The code flag is not in the YAML. Anything touching a customer environment tops out at `review`, whatever its confidence or thresholds. A Critical alert is never closed as a likely false positive: the scoring (`soc.score`) already refuses it, and the decision's guard routes it to `human` even if another evaluator says otherwise. Both are tested.

## Registered decisions

| Decision | Question(s) | Evaluator (reuses) | Auto? |
|---|---|---|---|
| `soc-alert-triage` | `verdict`: likely-true-positive / likely-false-positive / escalate-l2 | `soc.score` on the investigation's signals; verdict is unchanged, the probability comes from the verdict's own confidence band (`band_probability`) | Eligible, but shipped priors (max 0.9) are below the 0.95 auto threshold, so it reaches `review` until calibration supports more |
| `finding-routing` | `fixer_domain` (windows-server, unix-server, iot-ot-device, application, none), `owner_known` (yes/no) | the finding's `remediation_domain` / asset type, the ownership map | Eligible (a queue assignment) |
| `change-approval-needed` | `needs_approval` (yes/no) | `remediation_policy_engine.policy_for_finding` (change type, auto-remediate, KEV emergency override) | Never |

## API

- `POST /api/decisions/evaluate` (login): `{decision, state, purpose?}`; dry, writes nothing. `state` for `soc-alert-triage` is `{signals, severity}`; for the other two `{finding, owners?, environment?}`.
- `GET /api/decisions/policy` (login): the decisions, their questions and options, thresholds and whether auto is allowed.
- `GET /api/decisions/calibration` (administrator): the report below.

Wired in existing code: each SOC investigation (manual or automatic) logs its verdict under `alert:<id>`; when an analyst sets a disposition, the logged verdict is judged: accepted if it agrees (true-positive vs likely-true-positive, benign or false-positive vs likely-false-positive), overridden if not. An `escalate-l2` verdict is a hand-off and is never judged. Logging failures never break an investigation. Nothing else is logged yet (`service.evaluate` + `calibration.record` are there for the other decisions' callers).

## Calibration

`decision_log` holds counts and outcomes only: decision, question, value, probability, confidence, route, evaluator, version, an opaque `ref`, the outcome and a count of model calls avoided. It never holds text, a prompt or a person. `ref` must match `[A-Za-z0-9_.:-]{1,64}`.

- Brier = mean((p - y)^2), y = 1 if accepted. ECE = sum over bins of n_bin/n x |accuracy - mean p|, equal-width bins (`bins`, default 5).
- Below `min_outcomes` judged rows (30) the report says `not-enough-outcomes` and shows no figure; a confidence band with fewer than `min_band_outcomes` (10) shows counts only. A decision is called calibrated only when ECE is within `ece_warn` (0.10).
- Recommendations (raise the auto threshold when the auto band's override rate exceeds `max_override_rate_auto_band`; consider lowering it when the review band is reliably accepted; do not trust probabilities when ECE is high) are advice. Nothing edits the policy.
- The panel is the **Decisions** tab of SOC Operations; the AI Usage page shows the "model calls avoided" count.

## Honest limits

- The shipped probabilities are stated priors, not measured ones, until outcomes accumulate. Only the SOC verdict has an outcome feed so far; routing and approval outcomes need their callers wired.
- The "model calls avoided" figure is a counterfactual estimate (each decision made by rules instead of a model call), not a measured saving, and it is a count on the decision log, not a row in `ai_usage_events`.
- The evaluators are rules and weights, not learned models; ECE on small samples is noisy.
- Quanta does not certify that a decision is correct; it records how often people agreed.
