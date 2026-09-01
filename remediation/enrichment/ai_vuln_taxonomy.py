"""
AI/ML vulnerability taxonomy, keyword tagging, and an illustrative MITRE ATLAS
cross-reference.

The twelve categories below are real, established AI/ML security concepts (prompt
injection, training-data poisoning, model supply-chain compromise, etc.) - the same
substance covered by OWASP's Top 10 for LLM Applications and MITRE ATLAS
(https://atlas.mitre.org/), MITRE's real, published knowledge base of adversary
tactics/techniques against AI systems (ATLAS is to AI/ML attacks what ATT&CK is to
traditional IT attacks).

IMPORTANT — read before citing this anywhere formal: exactly like
attack_mapping.py's own ATT&CK tagging, the `atlas_tactic`/`atlas_technique_id`
fields here are an **illustrative cross-reference** built from this module's own
reading of published ATLAS documentation, not a verified, authoritative mapping
pulled from a live ATLAS API or maintained by MITRE. Confirm any specific
tactic/technique ID against https://atlas.mitre.org/ before citing it in a compliance
report or incident writeup. Same reasoning applies to `map_finding_to_ai_vuln()`'s
keyword heuristic below: it's a rough categorization aid, not a certified detection.

Honest scope note: VulnHunter's scanner does analyze AI/ML-specific code paths
(prompt construction, model loading, agent tool-calling) - see
.claude/agents/vuln-scanner.md's "AI/ML security" guidance for exactly what it looks
for. This is demonstrated against real code, not just documented: the demo app's
vulnerable-demo-app/ai_assistant.py plants a hardcoded LLM API key, an insecure
`pickle.load` on an uploaded model file, a prompt-injection-shaped string
concatenation, and an excessive-agency LLM-to-shell path, and a real vuln-scanner run
found all four (VULN-10 through VULN-13) - see vulnerable-demo-app/SECURITY_REPORT.md.
`map_finding_to_ai_vuln()`'s keyword heuristic correctly tags 3 of those 4 against this
taxonomy (prompt-injection, supply-chain, excessive-agency; the hardcoded-API-key
finding is a generic secrets issue, not AI/ML-specific, so it correctly does not tag).
See docs/FAQ.md for how this compares to the still-genuinely-zero-findings categories
(API Vulnerabilities, DAST) - those stay honestly at zero, this one no longer is.
"""
import re

# Each entry: id, display name, one-paragraph summary, remediation guidance, and an
# illustrative MITRE ATLAS tactic/technique cross-reference (see module docstring's
# caveat - verify against atlas.mitre.org before citing formally).
AI_VULNERABILITIES = [
    {
        "id": "prompt-injection",
        "name": "Prompt Injection",
        "summary": "Attacker-controlled input manipulates an LLM into ignoring its "
            "original instructions or system prompt - directly (the attacker's own "
            "input contains the injection) or indirectly (malicious instructions "
            "embedded in third-party content the model later reads, e.g. a poisoned "
            "webpage, document, or email the model summarizes).",
        "remediation": "Treat all LLM output as untrusted, the same as any other "
            "user-influenced data. Isolate the system prompt from user-controllable "
            "context where the underlying model API supports it. Never let a "
            "successful prompt bypass alone trigger a privileged action - require a "
            "human or policy gate for anything consequential (mirrors this repo's own "
            "dry-run/confirm design). Apply input/output filtering as a defense-in-depth "
            "layer, not the sole control.",
        "atlas_tactic": "Initial Access",
        "atlas_technique_id": "AML.T0051",
        "atlas_technique_name": "LLM Prompt Injection",
    },
    {
        "id": "sensitive-info-disclosure",
        "name": "Sensitive Information Disclosure",
        "summary": "A model reveals confidential data it shouldn't - memorized "
            "training data, a leaked system prompt, PII surfaced from a retrieval "
            "pipeline, or proprietary business logic embedded in its instructions.",
        "remediation": "Sanitize/anonymize training and retrieval-context data before "
            "it ever reaches the model. Apply output filtering/DLP-style scanning on "
            "responses. Keep system prompts free of anything that would be damaging if "
            "echoed back, and apply least-privilege data access to any RAG (retrieval-"
            "augmented generation) pipeline the model draws context from.",
        "atlas_tactic": "Exfiltration",
        "atlas_technique_id": "AML.T0057",
        "atlas_technique_name": "LLM Data Leakage",
    },
    {
        "id": "training-data-model-poisoning",
        "name": "Training Data / Model Poisoning",
        "summary": "An attacker manipulates training or fine-tuning data to plant a "
            "backdoor, bias, or degraded behavior that only activates under specific "
            "conditions - hard to catch with normal accuracy metrics since the model "
            "still performs well on typical inputs.",
        "remediation": "Version-control and vet every training/fine-tuning data source. "
            "Run anomaly detection over training data before use. Restrict who can "
            "contribute to a fine-tuning dataset. Validate model behavior against "
            "known-good benchmarks (and adversarial test cases) before every "
            "deployment, not just at initial release.",
        "atlas_tactic": "ML Attack Staging",
        "atlas_technique_id": "AML.T0020",
        "atlas_technique_name": "Poison Training Data",
    },
    {
        "id": "supply-chain",
        "name": "AI Supply Chain Compromise",
        "summary": "A pre-trained model, dataset, or ML library/plugin sourced from an "
            "untrusted party is itself malicious or compromised - e.g. a model file "
            "that executes arbitrary code on load via unsafe deserialization, or a "
            "popular open-source model repackaged with a hidden backdoor.",
        "remediation": "Source models and datasets only from verified, signed "
            "repositories. Scan model artifacts for unsafe deserialization (e.g. a "
            "PyTorch/pickle-format model that isn't loaded with `weights_only=True` or "
            "an equivalent safe loader). Maintain an SBOM covering ML "
            "libraries/models, not just traditional application dependencies. Pin and "
            "vet third-party ML library versions the same as any other dependency.",
        "atlas_tactic": "Resource Development",
        "atlas_technique_id": "AML.T0010",
        "atlas_technique_name": "ML Supply Chain Compromise",
    },
    {
        "id": "improper-output-handling",
        "name": "Improper Output Handling",
        "summary": "LLM output is passed downstream - rendered as HTML, executed as "
            "code, used to build a database query or shell command - without the same "
            "sanitization any other untrusted input would get, because it's easy to "
            "forget the model's output is attacker-influenceable too.",
        "remediation": "Treat LLM output exactly like user input: escape it before "
            "rendering as HTML (this repo's own `escapeHtml()` pattern), never `eval`/"
            "`exec` it, and parameterize any downstream query or command built from it "
            "rather than string-concatenating it in.",
        "atlas_tactic": "Execution",
        "atlas_technique_id": None,
        "atlas_technique_name": "No dedicated ATLAS technique - maps conceptually to "
            "standard injection/execution tactics applied to an AI-sourced input, "
            "rather than an AI-specific technique of its own.",
    },
    {
        "id": "excessive-agency",
        "name": "Excessive Agency",
        "summary": "An LLM-based agent is granted broader permissions, tool access, or "
            "autonomy than its task requires, so a successful prompt injection (or "
            "simple model error) can cascade into real-world impact - sending an "
            "email, modifying a file, approving a transaction - with no human "
            "checkpoint in between.",
        "remediation": "Apply least-privilege scoping to every tool/function an agent "
            "can call. Require human-in-the-loop confirmation for consequential "
            "actions (exactly this repo's own dry-run/confirm-checkbox safety model, "
            "applied to agentic tool use). Rate-limit and sandbox agent-invoked tools, "
            "and log every tool call for audit.",
        "atlas_tactic": "Impact",
        "atlas_technique_id": None,
        "atlas_technique_name": "No single dedicated ATLAS technique - the risk spans "
            "whatever downstream tactic the over-permissioned action enables (Impact, "
            "Exfiltration, etc.), rather than being its own technique.",
    },
    {
        "id": "unbounded-consumption",
        "name": "Unbounded Consumption (Model Denial of Service)",
        "summary": "Crafted input drives excessive resource consumption - an extremely "
            "long context, a deliberately expensive prompt, or an uncontrolled "
            "agent/tool-calling loop - degrading availability or running up real "
            "inference cost.",
        "remediation": "Enforce input length/complexity limits, per-user rate limiting "
            "and cost quotas, and hard timeouts/iteration caps on any agent or "
            "tool-calling loop. This repo's own `--max-budget-usd` spend cap on real "
            "pipeline runs is the same defensive pattern applied to a different cost "
            "surface.",
        "atlas_tactic": "Impact",
        "atlas_technique_id": "AML.T0034",
        "atlas_technique_name": "Cost Harvesting",
    },
    {
        "id": "model-theft",
        "name": "Model Theft / IP Extraction",
        "summary": "An attacker reconstructs a proprietary model's behavior or weights "
            "through repeated, systematic querying (a model-extraction attack), or "
            "exfiltrates the model artifact directly - either way, walking off with "
            "IP that took real investment to produce.",
        "remediation": "Rate-limit and monitor API query patterns for "
            "extraction-shaped behavior (high query volume, systematic input sweeps). "
            "Watermark model outputs where feasible. Restrict access to raw model "
            "artifacts to the same standard as any other high-value credential/secret.",
        "atlas_tactic": "Exfiltration",
        "atlas_technique_id": "AML.T0024",
        "atlas_technique_name": "Exfiltration via ML Inference API",
    },
    {
        "id": "misinformation",
        "name": "Misinformation / Overreliance",
        "summary": "A model confidently produces false or misleading output "
            "(hallucination) that a downstream process or human treats as fact without "
            "verification - a real risk whenever model output feeds an automated "
            "decision or is presented to a user as authoritative.",
        "remediation": "Never let unreviewed model output alone trigger an automated,"
            " consequential action. Surface confidence/uncertainty where the "
            "underlying model exposes it. Cite sources/evidence alongside generated "
            "claims where possible, and keep a human reviewer in the loop for "
            "anything presented as fact to an end user.",
        "atlas_tactic": "Impact",
        "atlas_technique_id": None,
        "atlas_technique_name": "No dedicated ATLAS technique - this is a model-quality/"
            "trust risk more than an adversarial-technique one, included here because "
            "it's a real, commonly-cited AI-specific risk (OWASP's LLM Top 10 lists it "
            "explicitly).",
    },
    {
        "id": "insecure-plugin-tool-design",
        "name": "Insecure Plugin/Tool Design",
        "summary": "A tool or plugin an LLM agent can invoke accepts free-form input "
            "from the model with no validation of its own - effectively extending "
            "prompt injection's reach into whatever system that plugin/tool touches "
            "(a file system, an internal API, a payment processor).",
        "remediation": "Validate and constrain every plugin/tool's inputs at the tool "
            "boundary itself, the same as any other untrusted-input API - don't rely "
            "on the model to only ever pass well-formed arguments. Scope each tool's "
            "own permissions independently of the agent's overall permissions "
            "(defense in depth alongside the Excessive Agency guidance above).",
        "atlas_tactic": "Execution",
        "atlas_technique_id": "AML.T0053",
        "atlas_technique_name": "LLM Plugin Compromise",
    },
    {
        "id": "mcp-tool-poisoning",
        "name": "MCP Tool Poisoning",
        "summary": "A tool exposed to an agent via the Model Context Protocol (MCP) - or "
            "any similar tool-description/schema mechanism - carries attacker-controlled "
            "instructions hidden in its own description, parameter names, or metadata, "
            "which the agent reads as trusted context and acts on, even though the "
            "tool's human-facing name looks benign. A close sibling of Prompt Injection "
            "above, specifically targeting tool-definition metadata rather than "
            "end-user input - OWASP's own 2025-2026 LLM guidance flags this as a "
            "critical, rapidly-growing risk as MCP adoption spreads.",
        "remediation": "Treat every MCP server's tool descriptions as untrusted input, "
            "not trusted configuration - review a tool's full schema/description text "
            "before connecting to it, not just its name. Pin MCP server versions/hashes "
            "rather than auto-updating. Prefer MCP servers from vetted, signed sources "
            "(same supply-chain discipline as AI Supply Chain Compromise above). Log and "
            "review what an agent actually invoked, not just what it was asked to do.",
        "atlas_tactic": "Initial Access",
        "atlas_technique_id": None,
        "atlas_technique_name": "No dedicated ATLAS technique yet - MCP-specific tool "
            "poisoning is newer than ATLAS's current published technique set; this is "
            "the same real risk as LLM Prompt Injection (AML.T0051) applied to "
            "tool-definition metadata instead of user-facing input.",
    },
    {
        "id": "shadow-ai-agents",
        "name": "Shadow AI Agents",
        "summary": "An LLM-based agent or automation is deployed with real production "
            "system access - a CRM, email, an internal API - without security/IT ever "
            "inventorying, reviewing, or governing it. The AI-specific analogue of "
            "shadow IT, except the unmanaged thing itself can also take autonomous "
            "action rather than just sitting there as an unpatched risk.",
        "remediation": "Maintain a real inventory of every agent with production system "
            "access - owner, granted tools/scopes, last review date. Require the same "
            "onboarding/approval gate for a new agent that a new service account or "
            "integration would get. Periodically audit API-key/OAuth-grant usage "
            "patterns for signs of an unregistered agent operating.",
        "atlas_tactic": "Persistence",
        "atlas_technique_id": None,
        "atlas_technique_name": "No dedicated ATLAS technique - this is an "
            "asset-visibility/governance gap (an unmanaged agent existing at all) "
            "rather than an attack technique against a known one. \"Persistence\" is "
            "the closest real ATLAS tactic: an ungoverned agent that nobody is tracking "
            "is, by definition, a long-lived, unmonitored foothold.",
    },
]

_BY_ID = {v["id"]: v for v in AI_VULNERABILITIES}

# Ordered (compiled pattern, vulnerability id) list - same "first match wins, order
# matters" design as attack_mapping.py's _PATTERNS. Deliberately conservative: these
# only fire on fairly unambiguous AI/ML-specific terminology, not generic words that
# could false-positive against an unrelated finding.
_PATTERNS = [
    (r"\bprompt injection\b|\bjailbreak(ing)?\b", "prompt-injection"),
    (r"\bsystem prompt\b.*\bleak", "sensitive-info-disclosure"),
    (r"\btraining data\b.*\bpoison|\bmodel poisoning\b|\bdata poisoning\b|\bbackdoor(ed)? model\b", "training-data-model-poisoning"),
    (r"\bmalicious (pre-trained )?model\b|\b(unsafe|insecure) (pickle|deserializ)", "supply-chain"),
    (r"\bllm output\b.*\b(unsanitized|unescaped)|\bmodel output\b.*\beval\b", "improper-output-handling"),
    (r"\bexcessive agency\b|\bagent\b.*\bunrestricted tool\b|\bagent\b.*\bno human\b", "excessive-agency"),
    (r"\bmodel (denial of service|dos)\b|\bunbounded (context|consumption)\b|\btoken flood", "unbounded-consumption"),
    (r"\bmodel extraction\b|\bmodel theft\b|\bmodel stealing\b", "model-theft"),
    (r"\bhallucinat|\bmisinformation\b.*\bmodel\b|\boverreliance\b", "misinformation"),
    (r"\bplugin\b.*\b(llm|agent)\b.*\bunvalidated\b|\btool.calling\b.*\bunvalidated\b", "insecure-plugin-tool-design"),
    (r"\bmcp\b.*\b(poison|malicious|compromis)|\btool poisoning\b", "mcp-tool-poisoning"),
    (r"\bshadow (ai |llm )?agents?\b|\bunmanaged agent\b|\bunregistered agent\b|\bungoverned agent\b", "shadow-ai-agents"),
]
_COMPILED = [(re.compile(pattern, re.IGNORECASE), vid) for pattern, vid in _PATTERNS]


def get_vulnerability(vuln_id):
    """Returns the full taxonomy entry for a vulnerability id, or None."""
    return _BY_ID.get(vuln_id)


def map_finding_to_ai_vuln(finding):
    """Returns the matching taxonomy entry (dict) for a finding's title/description
    text, or None if nothing matches - most findings in this repo's demo data won't
    match anything here, since none of it is AI/ML-specific, and that's expected
    (see module docstring)."""
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    for pattern, vid in _COMPILED:
        if pattern.search(text):
            return _BY_ID[vid]
    return None


def tag_findings(findings):
    """Returns a new list (doesn't mutate input) with an `ai_vulnerability` field
    (the matched taxonomy entry's `id`, or None) added to every finding - same
    immutable-tagging pattern as attack_mapping.tag_findings."""
    tagged = []
    for f in findings:
        f = dict(f)
        match = map_finding_to_ai_vuln(f)
        f["ai_vulnerability"] = match["id"] if match else None
        tagged.append(f)
    return tagged


def build_ai_atlas_heatmap(findings):
    """Returns one row per (atlas_tactic, atlas_technique_id) this taxonomy knows
    about - including zero-count rows and entries with no dedicated technique ID
    (technique_id=None), same "show the full known taxonomy, not just today's
    matches" design as attack_mapping.build_attack_heatmap. `findings` must already
    carry an `ai_vulnerability` field (see tag_findings)."""
    counts = {}
    for f in findings:
        vid = f.get("ai_vulnerability")
        if vid:
            counts[vid] = counts.get(vid, 0) + 1

    return [
        {
            "id": v["id"],
            "name": v["name"],
            "atlas_tactic": v["atlas_tactic"],
            "atlas_technique_id": v["atlas_technique_id"],
            "atlas_technique_name": v["atlas_technique_name"],
            "count": counts.get(v["id"], 0),
        }
        for v in AI_VULNERABILITIES
    ]
