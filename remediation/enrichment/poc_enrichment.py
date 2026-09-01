#!/usr/bin/env python3
"""
Backfills two real, never-fabricated signals onto every CVE-bearing finding:

- `poc_available`: True if NVD itself tagged one of a CVE's own references as
  "Exploit" - a real, documented field of the NVD API 2.0 response
  (references[].tags), not a guess or a third-party scrape.
- `user_interaction_required`: True/False from NVD's own CVSS `userInteraction` metric -
  checks v4.0 first (three real values: NONE/PASSIVE/ACTIVE - PASSIVE and ACTIVE both
  count as "required" here, the same real-world meaning v3.x's binary REQUIRED/NONE
  captures), falling back to v3.1/v3.0 (REQUIRED/NONE) for CVEs NVD hasn't scored under
  v4.0 yet. `None` (not a guess) when a CVE only has CVSS v2 data, which carries no such
  metric.

Both come from data `remediation/sample-data/generate_bulk_findings.py` already fetched
and cached to disk under `bulk/_nvd_cache/` while sourcing this project's real CVEs -
this module re-reads that same cache rather than re-querying NVD, exactly like
`kev_epss.py` enriches from a live feed it already fetched once. The cache itself is
gitignored (a local performance cache, not committed - see its own .gitignore entry),
so this backfill is deliberately run as a one-time (and re-run-after-regeneration) step
that PERSISTS its result into normalized-findings.json, the same way `kev`/`epss` are
persisted - reading the cache live from the dashboard on every request would silently
degrade to "unknown for everything" on any fresh checkout that hasn't generated bulk
data locally.

Findings with a `cve` that ISN'T found in the local cache (e.g. the handful of original
hand-curated findings that predate the bulk generator) get `None`/`None` - an honest,
disclosed gap, the same treatment `eol_lookup.py` gives an unrecognized OS string.
"""
import argparse
import json
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "sample-data" / "bulk" / "_nvd_cache"


def poc_available(cve):
    return any("Exploit" in (ref.get("tags") or []) for ref in cve.get("references", []))


def user_interaction_required(cve):
    """True/False from the CVE's best-available CVSS userInteraction metric, None if
    only CVSS v2 data (or nothing) exists. Checks v4.0 first - its UI metric has three
    real values (NONE/PASSIVE/ACTIVE) rather than v3.x's two (NONE/REQUIRED); PASSIVE
    and ACTIVE both count as "required" here, matching v3.x's REQUIRED semantically."""
    metrics = cve.get("metrics", {})
    v40_entries = metrics.get("cvssMetricV40")
    if v40_entries:
        return v40_entries[0]["cvssData"].get("userInteraction") in ("PASSIVE", "ACTIVE")
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"].get("userInteraction") == "REQUIRED"
    return None


def build_nvd_signal_index(cache_dir=CACHE_DIR):
    """Scans every cached raw NVD response file once, returns
    {cve_id: {"poc_available": bool, "user_interaction_required": bool|None}}.
    Returns {} (not an error) if cache_dir doesn't exist - e.g. a fresh checkout that
    has never run generate_bulk_findings.py locally."""
    cache_dir = Path(cache_dir)
    index = {}
    if not cache_dir.is_dir():
        return index
    for cache_file in cache_dir.glob("*.json"):
        entries = json.loads(cache_file.read_text(encoding="utf-8"))
        for entry in entries:
            cve = entry.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in index:
                continue
            index[cve_id] = {
                "poc_available": poc_available(cve),
                "user_interaction_required": user_interaction_required(cve),
            }
    return index


def enrich_findings(findings, signal_index=None):
    """Adds `poc_available`/`user_interaction_required` to each finding with a `cve`.
    A finding whose CVE isn't in the local signal index (no cve at all, or a cve the
    cache never covered) gets None/None - honestly unknown, never guessed."""
    if signal_index is None:
        signal_index = build_nvd_signal_index()

    enriched = []
    for f in findings:
        f = dict(f)
        cve = f.get("cve")
        signal = signal_index.get(cve) if cve else None
        if signal:
            f["poc_available"] = signal["poc_available"]
            f["user_interaction_required"] = signal["user_interaction_required"]
        else:
            f["poc_available"] = None
            f["user_interaction_required"] = None
        enriched.append(f)
    return enriched


def enrich_file(findings_path, output_path=None, cache_dir=CACHE_DIR):
    findings_path = Path(findings_path)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    enriched = enrich_findings(findings, signal_index=build_nvd_signal_index(cache_dir))
    output_path = Path(output_path) if output_path else findings_path
    output_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Backfill real NVD-derived poc_available/user_interaction_required "
                    "signals onto normalized findings, from the already-cached NVD data.")
    parser.add_argument("findings_path", help="Path to normalized-findings.json")
    parser.add_argument("--output", help="Output path (defaults to overwriting the input file)")
    parser.add_argument("--cache-dir", default=str(CACHE_DIR),
                         help="Path to the cached raw NVD response directory")
    args = parser.parse_args()
    out = enrich_file(args.findings_path, args.output, cache_dir=args.cache_dir)
    print(f"POC/user-interaction signals backfilled, written to {out}")


if __name__ == "__main__":
    main()
