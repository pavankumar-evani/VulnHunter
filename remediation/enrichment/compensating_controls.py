"""
Compensating-control suggestions.

Same honesty pattern as attack_mapping.py: there is no single authoritative
"the" compensating control for a given vulnerability - only common, generally sound
mitigations security teams actually reach for while a real fix is pending. This is a
**keyword heuristic** against a finding's title/description text, useful as a starting
point on the Exceptions request form - not a certified control, and not a substitute for
a security engineer's own judgment about what's actually appropriate for a given asset
and environment. Treat every suggestion here as something to evaluate, not to copy-paste
into a compliance document as-is.

Reference for the mitigation categories themselves: CIS Controls v8 and NIST SP 800-53 -
this module doesn't map to specific control IDs from either framework (that mapping
would need to be verified against a real compliance program's control catalog), it just
draws on the same common, well-known mitigation families both frameworks describe.
"""
import re

_PATTERNS = [
    (r"\btelnet\b|\brdp\b|\bremote desktop\b|\bmanagement interface\b", [
        "Restrict access via network ACL/firewall to trusted management VLANs only",
        "Disable the exposed service if it isn't operationally required",
        "Require VPN or bastion-host access instead of direct exposure",
    ]),
    (r"\bsql injection\b|\bcommand injection\b|\beval\(|\bcode injection\b|\bshell\s*=\s*true\b", [
        "Deploy a WAF rule blocking the known-vulnerable request pattern",
        "Add input validation/parameterization at the application layer as an interim mitigation",
    ]),
    (r"\bhardcoded\b.*\b(secret|key|password|credential)\b|\bplaintext password\b|\bplaintext.*credential\b", [
        "Rotate the exposed credential immediately",
        "Move the secret to a vault/secrets manager and revoke the hardcoded value",
    ]),
    (r"\bauthentication bypass\b|\bunauthenticated access\b|\bwithout authentication\b", [
        "Require MFA or a compensating authentication proxy in front of the service",
        "Restrict network access to the service to known-good source IPs",
    ]),
    (r"\bcertificate\b.*\bexpir", [
        "Monitor certificate expiry with automated alerting until renewed",
        "Issue a short-lived replacement certificate as an interim fix",
    ]),
    (r"\bdenial of service\b|\binfinite loop\b|\bdos\b", [
        "Add rate-limiting/circuit-breaking in front of the affected service",
        "Increase monitoring/alerting for the resource-exhaustion symptom",
    ]),
    (r"\bdeprecated (tls|ssl)\b|\bweak cipher\b|\bssl.*protocol\b", [
        "Enforce modern TLS versions/ciphers at a reverse proxy/load balancer in front of the service",
    ]),
    (r"\bprivilege escalation\b|\bbuffer overflow\b|\bheap.based\b|\bpriv(ilege)? level 15\b", [
        "Restrict local access to the affected host to least-privilege accounts only",
        "Increase host-based monitoring/EDR alerting for the exploitation technique",
    ]),
    (r"\boutdated\b.*\bos version\b|\bmissing.*patch\b|\bunpinned\b|\boutdated base image\b", [
        "Pin to a known-good version/image digest until the update is validated and rolled out",
        "Isolate the affected asset on a restricted network segment pending the update",
    ]),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE), controls) for pattern, controls in _PATTERNS]

DEFAULT_CONTROLS = [
    "Increase monitoring/alerting on the affected asset until remediated",
    "Restrict network access to the asset to only what's operationally required",
]


def suggest_compensating_controls(finding):
    """Returns a list of suggested compensating controls (never empty - falls back to
    DEFAULT_CONTROLS) for one finding, based on its title/description text."""
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    for pattern, controls in _COMPILED:
        if pattern.search(text):
            return controls
    return DEFAULT_CONTROLS


def tag_compensating_controls(findings):
    """Returns a new list (doesn't mutate input) with a `compensating_controls` field
    added to every finding - same immutable-tagging pattern as attack_mapping.tag_findings
    and scan_type_mapping.tag_scan_types."""
    tagged = []
    for f in findings:
        f = dict(f)
        f["compensating_controls"] = suggest_compensating_controls(f)
        tagged.append(f)
    return tagged
