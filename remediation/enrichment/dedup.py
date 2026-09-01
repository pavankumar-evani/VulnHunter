#!/usr/bin/env python3
"""
Cross-scanner deduplication: groups findings that most likely describe the same real
vulnerability reported more than once (e.g. Tenable and a future Prisma Cloud connector
both flagging the same CVE on the same asset) - see docs/VR_PLATFORM_COMPARISON.md for
why this was the highest-priority gap versus Nucleus/DefectDojo/Brinqa/ArmorCode, all of
which treat deduplication as a headline feature.

Matching, in priority order:
  1. Same `cve` + same `asset.name` - the strongest signal available without deeper
     analysis. Two findings citing the same CVE on the same host are the same real
     vulnerability regardless of which scanner reported it.
  2. Same normalized `title` + same `asset.name`, used ONLY when `cve` is null (~10% of
     real findings - Armis policy/config findings and certificate-lifecycle findings
     commonly have none, per remediation/schema/normalized-finding-schema.md).

Honest limitation, not silently assumed away: the title-based fallback is a real
heuristic with false-positive risk - a generic, reused title (e.g. "Outdated software
version detected") could legitimately describe two DIFFERENT underlying issues on the
same asset, and this module has no way to tell those apart from title text alone. This
is why every tagged finding carries `match_basis` ("cve+asset" or "title+asset") rather
than a single opaque "is a duplicate" flag - a "title+asset" group is a weaker signal
than a "cve+asset" one, and a consumer of this data should be able to tell the
difference.

Never deletes or hides data (this repo's own established honesty convention - see
kev_epss.py's `kev`/`epss` = null-vs-{"listed": false} distinction for the same
principle applied elsewhere): every finding stays in the output list, tagged with
whether it's the primary member of its duplicate group. Primary selection is
deterministic - earliest `first_seen`, tie-broken by lowest numeric id - so the same
input always produces the same primary regardless of the findings' original order.
"""
import argparse
import json
import re
from pathlib import Path


def _normalize_title_key(title):
    """Lowercase, whitespace-collapsed - catches "Open Telnet Service" vs "open telnet
    service" but deliberately not fuzzy/semantic matching (see module docstring)."""
    return re.sub(r"\s+", " ", (title or "").strip().lower())


def _finding_sort_key(f):
    """Earliest first_seen wins primary; lowest numeric FIND-N id is the final,
    fully-deterministic tie-break so re-running against the same input never picks a
    different primary."""
    first_seen = f.get("first_seen") or "9999-99-99"  # missing sorts last, never crashes
    fid = f.get("id") or ""
    try:
        id_num = int(fid.split("-")[-1])
    except (ValueError, IndexError):
        id_num = 0
    return (first_seen, id_num)


def _group_key(f):
    """Returns (match_basis, key) for a finding, or None if it can't be grouped at all
    (no asset name - never seen in real data per the schema, but handled rather than
    assumed)."""
    asset_name = (f.get("asset") or {}).get("name")
    if not asset_name:
        return None
    cve = f.get("cve")
    if cve:
        return ("cve+asset", (cve, asset_name))
    title_key = _normalize_title_key(f.get("title"))
    if not title_key:
        return None
    return ("title+asset", (title_key, asset_name))


def dedup_findings(findings):
    """Adds a `dedup` field to every finding - never mutates the input, never drops or
    reorders a finding. Shape, always present (same "always add the key" convention as
    every other field in the schema):

        {
          "group_id": "DEDUP-1" or None,   # None only for a singleton (no duplicates found)
          "group_size": 2,                  # how many findings share this identity key (>=1)
          "is_primary": True,               # exactly one True per group
          "duplicate_of": ["FIND-42"],      # ids of the OTHER findings in the same group
          "match_basis": "cve+asset",       # "cve+asset" | "title+asset" | None (singleton)
        }
    """
    groups = {}
    ungroupable_indices = []
    for i, f in enumerate(findings):
        key = _group_key(f)
        if key is None:
            ungroupable_indices.append(i)
            continue
        groups.setdefault(key, []).append(i)

    dedup_by_index = {}
    group_id_counter = 0
    for key, indices in groups.items():
        match_basis, _ = key
        members = [findings[i] for i in indices]
        primary_idx_in_members = min(range(len(members)), key=lambda m: _finding_sort_key(members[m]))
        primary_index = indices[primary_idx_in_members]
        group_id = None
        if len(indices) > 1:
            group_id_counter += 1
            group_id = f"DEDUP-{group_id_counter}"
        for pos, i in enumerate(indices):
            other_ids = [findings[j].get("id") for j in indices if j != i]
            dedup_by_index[i] = {
                "group_id": group_id,
                "group_size": len(indices),
                "is_primary": i == primary_index,
                "duplicate_of": other_ids,
                "match_basis": match_basis if len(indices) > 1 else None,
            }

    for i in ungroupable_indices:
        dedup_by_index[i] = {
            "group_id": None, "group_size": 1, "is_primary": True,
            "duplicate_of": [], "match_basis": None,
        }

    result = []
    for i, f in enumerate(findings):
        f = dict(f)
        f["dedup"] = dedup_by_index[i]
        result.append(f)
    return result


def dedup_file(findings_path, output_path=None):
    findings_path = Path(findings_path)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    deduped = dedup_findings(findings)
    output_path = Path(output_path) if output_path else findings_path
    output_path.write_text(json.dumps(deduped, indent=2), encoding="utf-8")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Tag normalized findings with cross-scanner duplicate-group metadata.")
    parser.add_argument("findings_path", help="Path to normalized-findings.json")
    parser.add_argument("--output", help="Output path (defaults to overwriting the input file)")
    args = parser.parse_args()
    out = dedup_file(args.findings_path, args.output)
    print(f"Deduplication metadata written to {out}")


if __name__ == "__main__":
    main()
