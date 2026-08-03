"""
Heuristic MITRE ATT&CK technique tagging.

IMPORTANT — read before trusting this output: there is no universal, authoritative
CVE-to-ATT&CK-technique mapping. What exists (e.g. MITRE's own CVE-to-ATT&CK efforts,
vendor threat intel platforms) is maintained by security researchers reviewing each
CVE's actual exploitation mechanics. This module is a **keyword heuristic** against a
finding's title/description text — useful for a rough tactical grouping on a dashboard,
not a substitute for real technique attribution. Treat every mapping here as a
suggestion to verify, not a fact to cite.

Reference: https://attack.mitre.org/
"""
import re

# Ordered list of (compiled pattern, technique_id, technique_name, tactic). Order
# matters - more specific patterns should come before general ones, since only the
# first match wins per finding (a finding can still match multiple if you use
# map_finding_to_attack's `all_matches=True`).
_PATTERNS = [
    (r"\bsql injection\b", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (r"\bcommand injection\b|\bshell\s*=\s*true\b", "T1059", "Command and Scripting Interpreter", "Execution"),
    (r"\bremote code execution\b|\brce\b", "T1210", "Exploitation of Remote Services", "Lateral Movement"),
    (r"\bprivilege escalation\b|\bbuffer overflow\b|\bheap.based\b", "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    (r"\bhardcoded\b.*\b(secret|key|password|credential)\b|\bhardcoded\b", "T1552", "Unsecured Credentials", "Credential Access"),
    (r"\bplaintext password\b|\bplaintext.*credential\b", "T1552", "Unsecured Credentials", "Credential Access"),
    (r"\bauthentication bypass\b|\bunauthenticated access\b|\bwithout authentication\b", "T1556", "Modify Authentication Process", "Defense Evasion"),
    (r"\btelnet\b|\brdp\b|\bremote desktop\b|\bssh\b.*expos", "T1021", "Remote Services", "Lateral Movement"),
    (r"\bdenial of service\b|\binfinite loop\b|\bdos\b", "T1499", "Endpoint Denial of Service", "Impact"),
    (r"\bdeprecated (tls|ssl)\b|\bweak cipher\b|\bssl.*protocol\b", "T1600", "Weaken Encryption", "Defense Evasion"),
    (r"\bcertificate expir", None, None, None),  # explicitly unmapped - lifecycle issue, not an attack technique
    (r"\bpriv(ilege)? level 15\b|\bweb ui\b.*privilege", "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    (r"\beval\(|\bcode injection\b", "T1059", "Command and Scripting Interpreter", "Execution"),
    (r"\boutdated\b.*\bos version\b|\bmissing.*patch", "T1195", "Supply Chain Compromise", "Initial Access"),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE), tid, tname, tactic) for pattern, tid, tname, tactic in _PATTERNS]


def map_finding_to_attack(finding, all_matches=False):
    """Returns a list of {technique_id, technique_name, tactic} dicts (possibly empty -
    not every finding maps to a known technique, and that's fine; don't force one).
    By default returns only the first (most specific) match; pass all_matches=True to
    return every pattern that matched."""
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    results = []
    for pattern, tid, tname, tactic in _COMPILED:
        if pattern.search(text):
            if tid is None:
                # Deliberately-unmapped pattern (e.g. cert expiry) - stop looking further
                # for this finding rather than falling through to a weaker match.
                break
            results.append({"technique_id": tid, "technique_name": tname, "tactic": tactic})
            if not all_matches:
                break
    return results


def tag_findings(findings):
    """Returns a new list (doesn't mutate input) with an `attack_techniques` field
    added to every finding."""
    tagged = []
    for f in findings:
        f = dict(f)
        f["attack_techniques"] = map_finding_to_attack(f)
        tagged.append(f)
    return tagged


# Every (tactic, technique_id, technique_name) this heuristic can possibly emit - built
# from _PATTERNS itself so it can never drift out of sync with what map_finding_to_attack
# actually produces. Excludes the deliberately-unmapped patterns (tid is None).
ALL_TACTIC_TECHNIQUES = sorted(
    {(tactic, tid, tname) for _, tid, tname, tactic in _PATTERNS if tid is not None},
)


def build_attack_heatmap(findings):
    """Returns one row per (tactic, technique) this heuristic knows about - including
    zero-count rows - so a dashboard heat map shows the full known taxonomy rather than
    only whatever happened to match today's findings. `findings` must already carry an
    `attack_techniques` field (see tag_findings) - this function doesn't re-run the
    heuristic itself, it just aggregates counts.

    Same non-authoritative caveat as the rest of this module: a technique showing 0
    findings means none of today's findings matched that keyword pattern, not that the
    technique is absent from the environment."""
    counts = {}
    for f in findings:
        for t in f.get("attack_techniques", []) or []:
            key = (t["tactic"], t["technique_id"])
            counts[key] = counts.get(key, 0) + 1

    return [
        {
            "tactic": tactic,
            "technique_id": tid,
            "technique_name": tname,
            "count": counts.get((tactic, tid), 0),
        }
        for tactic, tid, tname in ALL_TACTIC_TECHNIQUES
    ]
