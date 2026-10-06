# AI engineering patterns and what Quanta does with them

This page maps eleven current AI-engineering references (ontologies and knowledge graphs, typed-decision models, deep-learning architectures, production-AI tradeoffs, MCP security controls, agent architecture and harness design, model-improvement techniques, and a set of open-source tools) onto Quanta. For each it says what is adopted, what is adapted and what is deliberately left alone. Nothing here depends on a vendor product whose internals are unpublished.

## Decisions

| Reference | Decision | Where it lands |
|---|---|---|
| Ontology + knowledge graph | **Adopt.** Quanta already builds a relationship graph per module; the missing part is a written ontology that says which relations are legal, provenance on every fact, and multi-hop questions over the whole estate. | `remediation/ontology/` (schema, validation, provenance, multi-hop queries) |
| Typed questions, fixed answer space, confidence gate (the "Jev" pattern) | **Adapt, vendor-neutral.** The pattern (typed answers, probabilities, route by confidence) is sound; the product is a third-party model whose architecture, weights and calibration are not published, so Quanta does not call it. Quanta gets the pattern: a decision layer with fixed answer spaces, deterministic scorers today, a pluggable model later, a confidence gate (auto / review / human) and calibration tracking from analyst outcomes. | `remediation/decisions/` |
| MCP security controls (authenticate, authorize, scope tools, sandbox, audit, human approval) | **Adopt twice.** (1) As assessment rules in AI Security and the Posture Review, so a customer's MCP servers and agents are checked against the six controls. (2) As the design rules for Quanta's own read-only MCP endpoint. | `remediation/aisec/` rules, `remediation/mcp/` |
| Agentic architecture and harness (loop, tool registry, permissions, memory, sandbox, observability) | **Adopt as a checklist and as telemetry.** Customer agents are assessed against harness controls; Quanta's own AI calls already go through a confirm gate, budget cap and usage log. | AI Security checks, `ai-usage` metrics |
| Production-AI tradeoffs (prompt/model versioning, canary, rollback, offline vs online evals) | **Adopt as AIDLC checks** in the Posture Review and as fields on the AI register. Quanta's own release model already has dev/test/prod, rollback and feature flags. | Posture `aidlc`, AI register |
| Attack-surface management (discovery, ports, services, technologies, scheduled workflows, MCP assistant) | **Adopt by ingestion, not scanning.** Quanta never scans on its own; it imports the output of subfinder, httpx, naabu, dnsx and nuclei, keeps a continuously updated external inventory and reports what appeared, changed or disappeared. | `remediation/asm/` |
| Coordinated-disclosure feed | **Adopt** (public feed only, never leaked material). | `remediation/connectors/cvd_feed_connector.py` |
| Integrity, self-heal | **Adopt.** Verify code and configuration against a manifest, check store consistency, repair only what is safe to repair. | `remediation/integrity/` |
| Deep-learning architectures (ANN, CNN, RNN, LSTM, GRU, Transformer, autoencoder) | **Not now.** Quanta's models are classical and explainable on purpose (Naive Bayes technique classifier, z-scores, Monte Carlo). An autoencoder for anomaly detection is a candidate only after a customer has enough clean history; until then a simple baseline wins and is auditable. | none |
| Model-improvement techniques (data quality, features, tuning, regularisation, augmentation, transfer learning, ensembling) | **Adapt to what Quanta has.** The largest gain available today is data quality and calibration, not bigger models: duplicate and noisy findings, labels from analyst outcomes, held-out evaluation. | `remediation/decisions/` calibration |
| Open-source tool list (Transformers, PyTorch, PEFT, TRL, DeepSpeed, vLLM, llama.cpp, LangChain, LangGraph, Agent Framework, GraphRAG, Haystack, DSPy, smolagents, MLflow, Evidently, Promptfoo, ONNX Runtime, Lightning) | **Reference, not dependency.** Quanta keeps a small dependency set. Promptfoo, Evidently and MLflow are the useful ones to point customers at for evaluating and monitoring their own AI; the AI register records them as controls. | AI register fields |

## Principles that stay fixed

- Quanta gives evidence and drafts; a person decides. A confidence gate may route a decision to "auto" only for actions that are local and reversible, never for anything that changes a customer's environment.
- An unanswered question is a gap, never a pass. A model that cannot answer returns "unknown".
- Calibration is measured, not claimed: a probability is only shown as calibrated when analyst outcomes support it.
- No third-party model sees customer data unless the customer configured it and a person confirmed the call.

Status: this document is the plan. Each row names the module that implements it; a row is done only when that module is merged and documented.
