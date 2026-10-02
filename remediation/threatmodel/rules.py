"""
Threat rules: STRIDE applied to the elements of a system model, as explicit, readable rules.

A threat model describes a system as components (processes, services, data stores, external actors, AI models), the data flows
between them and the trust zones they sit in. Each rule below says: for this kind of element, when this condition holds, this class
of attack is plausible. They are the rules a person doing STRIDE-per-element would apply, written down so the result is the same every
time and every threat can be traced to the rule and the facts that raised it.

A rule fires in one of two ways, and the threat says which:
  * confirmed   the model states the weakness (for example `authn: false`);
  * unconfirmed the model does not say (`authn` is missing), so the threat is raised for a person to confirm or dismiss. These
                are scored one step lower on likelihood.

Each rule carries the control classes that mitigate it (the same vocabulary as the controls inventory), the ATT&CK techniques and
CWE ids it relates to (which is how it is joined to live findings and to MITRE's mitigations), and a base likelihood and impact from 1 to 5.
The scores are a starting point for a conversation, not a measurement.
"""
SENSITIVE = {"pii", "credentials", "payment", "phi", "secrets", "keys", "personal", "health", "financial"}
STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
COMPONENT_TYPES = ("process", "service", "datastore", "external", "ai-model")


def _is(v, want):
    """True/False/None tri-state test: want=False matches an explicit False (confirmed) or a missing value (unconfirmed)."""
    if v is want:
        return "confirmed"
    if v is None:
        return "unconfirmed"
    return None


def _sensitive(items):
    return bool(SENSITIVE & {str(x).lower() for x in (items or [])})


def _incoming(model, el):
    return [f for f in model.get("data_flows", []) if f.get("to") == el["id"]]


def _zone_trust(model, comp):
    z = {z["id"]: z.get("trust", 1) for z in model.get("trust_zones", [])}
    return z.get(comp.get("trust_zone"), 0 if comp.get("internet_facing") else 1)


def _from_lower_trust(model, el):
    comps = {c["id"]: c for c in model.get("components", [])}
    mine = _zone_trust(model, el)
    for f in _incoming(model, el):
        src = comps.get(f.get("from"))
        if src and (src.get("type") == "external" or _zone_trust(model, src) < mine):
            return True
    return bool(el.get("internet_facing"))


# Each rule: id, stride, applies ("component"|"flow"), kinds, fires(el, model) -> "confirmed" | "unconfirmed" | None,
# title, text, controls, techniques, cwe, likelihood, impact.
RULES = [
    dict(id="TM-S01", stride="S", applies="component", kinds=("process", "service"), title="Impersonation of a user or caller",
         text="{name} can be reached from a less trusted zone and does not require authentication, so an attacker can act as a legitimate user or caller.",
         fires=lambda el, m: _is(el.get("authn"), False) if _from_lower_trust(m, el) else None,
         controls=["mfa", "access-restriction", "exploit-protection"], techniques=["T1190"], cwe=["CWE-306", "CWE-287"], likelihood=4, impact=4),
    dict(id="TM-T01", stride="T", applies="component", kinds=("process", "service"), title="Injection through unvalidated input",
         text="{name} takes input from a less trusted source without confirmed validation, so crafted input could change what it does (injection, scripting, traversal).",
         fires=lambda el, m: _is(el.get("input_validated"), False) if _from_lower_trust(m, el) else None,
         controls=["exploit-protection", "secure-development"], techniques=["T1190"], cwe=["CWE-89", "CWE-79", "CWE-78", "CWE-22"], likelihood=4, impact=4),
    dict(id="TM-R01", stride="R", applies="component", kinds=("process", "service", "datastore"), title="Actions cannot be traced",
         text="{name} does not keep confirmed audit logs, so a malicious or mistaken action could not be attributed or investigated afterwards.",
         fires=lambda el, m: _is(el.get("logging"), False), controls=["audit-logging"], techniques=[], cwe=["CWE-778"], likelihood=3, impact=3),
    dict(id="TM-I01", stride="I", applies="component", kinds=("datastore",), title="Sensitive data stored without encryption",
         text="{name} holds sensitive data ({data}) and is not confirmed to be encrypted at rest, so theft of the storage or a backup exposes it.",
         fires=lambda el, m: _is(el.get("encrypted_at_rest"), False) if _sensitive(el.get("handles")) else None,
         controls=["encryption", "least-privilege"], techniques=["T1552"], cwe=["CWE-311", "CWE-312"], likelihood=3, impact=5),
    dict(id="TM-D01", stride="D", applies="component", kinds=("process", "service"), title="Service can be overwhelmed",
         text="{name} is reachable from the internet without confirmed rate limiting or upstream protection, so a flood of requests could make it unavailable.",
         fires=lambda el, m: _is(el.get("rate_limited"), False) if el.get("internet_facing") else None,
         controls=["network-filtering", "exploit-protection"], techniques=["T1499"], cwe=["CWE-770"], likelihood=3, impact=3),
    dict(id="TM-E01", stride="E", applies="component", kinds=("process", "service"), title="Compromise gives administrative control",
         text="{name} runs with elevated privileges and can be reached from a less trusted zone, so a flaw in it would give an attacker administrator or root rights.",
         fires=lambda el, m: "confirmed" if (el.get("privileged") is True and _from_lower_trust(m, el)) else None,
         controls=["least-privilege", "sandboxing"], techniques=["T1068"], cwe=["CWE-250"], likelihood=3, impact=5),
    dict(id="TM-I03", stride="I", applies="component", kinds=("process", "service"), title="Secrets kept where they can be read",
         text="{name} keeps its credentials in {where}, not in a secrets vault, so anyone who can read the code, image or host can use them.",
         fires=lambda el, m: "confirmed" if str(el.get("secrets_management", "")).lower() in ("env", "file", "code", "config") else None,
         controls=["encryption", "secure-development"], techniques=["T1552"], cwe=["CWE-798"], likelihood=3, impact=4),
    dict(id="TM-T03", stride="T", applies="component", kinds=("process", "service", "ai-model"), title="Unvetted third-party component",
         text="{name} depends on third-party code or a hosted service and there is no confirmed software bill of materials or review of it, so a poisoned or vulnerable dependency would go unnoticed.",
         fires=lambda el, m: _is(el.get("sbom"), False) if el.get("third_party") else None,
         controls=["secure-development", "vuln-scanning", "app-control"], techniques=["T1195"], cwe=["CWE-1357"], likelihood=3, impact=4),
    dict(id="TM-I02", stride="I", applies="flow", kinds=("flow",), title="Data crosses the network unprotected",
         text="The flow {name} carries {data} and is not confirmed to be encrypted, so anyone on the path can read or alter it.",
         fires=lambda f, m: _is(f.get("encrypted"), False) if (_sensitive(f.get("data")) or f.get("crosses_zones")) else None,
         controls=["encryption", "network-segmentation"], techniques=[], cwe=["CWE-319"], likelihood=4, impact=4),
    dict(id="TM-S02", stride="S", applies="flow", kinds=("flow",), title="Caller is not verified",
         text="The flow {name} does not confirm who is calling, so another system or an attacker on the network could send the same requests.",
         fires=lambda f, m: _is(f.get("authenticated"), False) if f.get("to_type") in ("process", "service", "datastore") else None,
         controls=["least-privilege", "network-filtering", "mfa"], techniques=["T1190"], cwe=["CWE-306"], likelihood=3, impact=4),
    dict(id="TM-E02", stride="E", applies="flow", kinds=("flow",), title="Outside party reaches the data store directly",
         text="The flow {name} lets an external party talk to a data store without an application in between to enforce access rules.",
         fires=lambda f, m: "confirmed" if (f.get("from_type") == "external" and f.get("to_type") == "datastore") else None,
         controls=["network-segmentation", "access-restriction"], techniques=["T1190"], cwe=["CWE-284"], likelihood=3, impact=5),
    dict(id="TM-AI01", stride="T", applies="component", kinds=("ai-model",), title="Prompt injection",
         text="{name} acts on text from sources that can be controlled by an attacker, so hidden instructions in that text could redirect it (OWASP LLM01).",
         fires=lambda el, m: "confirmed" if _from_lower_trust(m, el) or any(f.get("untrusted_content") for f in _incoming(m, el)) else None,
         controls=["secure-development", "sandboxing", "least-privilege"], techniques=[], cwe=["CWE-1427"], likelihood=4, impact=4),
    dict(id="TM-AI02", stride="I", applies="component", kinds=("ai-model",), title="Sensitive data sent to an external model",
         text="{name} is a hosted or third-party model and receives sensitive data ({data}), which leaves your control and may be retained or exposed.",
         fires=lambda el, m: "confirmed" if (el.get("third_party") and any(_sensitive(f.get("data")) for f in _incoming(m, el))) else None,
         controls=["encryption", "access-restriction"], techniques=[], cwe=["CWE-200"], likelihood=3, impact=4),
    dict(id="TM-AI03", stride="E", applies="component", kinds=("ai-model",), title="Model can act without a person approving",
         text="{name} can call tools or take actions ({tools}) and there is no confirmed human approval for high-impact ones, so a manipulated model could cause real changes.",
         fires=lambda el, m: _is(el.get("human_approval"), False) if el.get("tools") else None,
         controls=["least-privilege", "audit-logging"], techniques=[], cwe=["CWE-269"], likelihood=3, impact=5),
]
BY_ID = {r["id"]: r for r in RULES}
