"""
Attack-chain analysis: groups a finding's real ATT&CK tactic (already tagged by
attack_mapping.py) into an entry/pivot/impact stage, then chains findings that share an
asset into {entry, pivots, impact} objects - the same "which single fix breaks the most
attack paths" idea security teams already use kill-chain thinking for, applied to this
pipeline's own real, already-computed tactic data. A pivot finding is worth prioritizing
specifically because remediating it breaks every chain it sits in, even if the chain's
entry and impact findings both stay open.

IMPORTANT - what this is not: there is no CWE-to-CAPEC-to-ATT&CK dataset in this repo.
attack_mapping.py itself already chose a direct title/description-keyword-to-ATT&CK
heuristic over that heavier chain, and this module builds on that same choice rather than
introducing a second, inconsistent taxonomy. A chain here means "these findings, on this
asset, together plausibly span an attacker's path from getting in to causing impact,
based on their tagged tactics" - not a runtime-validated, proven-exploitable attack path.
Same "illustrative, verify yourself" caveat every heuristic taxonomy in this codebase
already carries (attack_mapping.py, compensating_controls.py, control_coverage.py).

Stage mapping (every tactic attack_mapping.py can ever produce, bucketed once here so
retuning it means editing this dict, not guessing):
    entry:  Initial Access
    pivot:  Execution, Privilege Escalation, Credential Access, Defense Evasion,
            Lateral Movement
    impact: Impact
A finding with no tagged technique (attack_mapping.tag_findings() gives it an empty
attack_techniques list) has no stage and never joins a chain - honest "doesn't map,"
never guessed into a bucket.
"""
from remediation.enrichment.attack_mapping import tag_findings

_ENTRY_TACTICS = {"Initial Access"}
_PIVOT_TACTICS = {"Execution", "Privilege Escalation", "Credential Access", "Defense Evasion", "Lateral Movement"}
_IMPACT_TACTICS = {"Impact"}


def _stage_for(tactic):
    if tactic in _ENTRY_TACTICS:
        return "entry"
    if tactic in _PIVOT_TACTICS:
        return "pivot"
    if tactic in _IMPACT_TACTICS:
        return "impact"
    return None


def _finding_stages(finding):
    """A finding could in principle carry more than one tagged technique
    (attack_mapping.map_finding_to_attack(..., all_matches=True)), though
    tag_findings() itself only keeps the first match by default - returns the set of
    real stages this finding's tagged technique(s) map to (usually 0 or 1 entries)."""
    stages = set()
    for t in finding.get("attack_techniques", []) or []:
        stage = _stage_for(t.get("tactic"))
        if stage:
            stages.add(stage)
    return stages


def build_chains(findings):
    """Groups findings by asset (tagging them with attack_techniques first if that
    field isn't already present) and returns one chain object per asset that has BOTH
    an entry-stage and an impact-stage finding:
        {asset_name, entry: [...], pivots: [...], impact: [...]}
    where each list holds {id, title, technique_id} - a real asset can have more than
    one finding at the same stage. Assets with no chain (missing entry or impact
    findings) are simply absent from the result, not returned as an empty/null chain."""
    if findings and "attack_techniques" not in findings[0]:
        findings = tag_findings(findings)

    by_asset = {}
    for f in findings:
        name = (f.get("asset") or {}).get("name")
        if not name:
            continue
        by_asset.setdefault(name, []).append(f)

    chains = []
    for asset_name, asset_findings in by_asset.items():
        staged = {"entry": [], "pivot": [], "impact": []}
        for f in asset_findings:
            for stage in _finding_stages(f):
                technique_id = next(
                    (t["technique_id"] for t in f["attack_techniques"] if _stage_for(t.get("tactic")) == stage),
                    None,
                )
                staged[stage].append({"id": f.get("id"), "title": f.get("title"), "technique_id": technique_id})
        if staged["entry"] and staged["impact"]:
            chains.append({
                "asset_name": asset_name,
                "entry": staged["entry"],
                "pivots": staged["pivot"],
                "impact": staged["impact"],
            })
    return chains
