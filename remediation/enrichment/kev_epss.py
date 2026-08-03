#!/usr/bin/env python3
"""
Enriches normalized findings with two real, free, public, no-auth threat intelligence
sources - unlike the Tenable/Armis connectors, this module was verified against the
LIVE endpoints during development (see the docstring in tests/test_enrichment.py for
exactly what that verification covered and what's mocked for CI determinism).

- CISA KEV (Known Exploited Vulnerabilities catalog): a static JSON feed of CVEs CISA
  has confirmed are being actively exploited in the wild. The single highest-value
  binary signal in vulnerability prioritization - "is this actually being used against
  real targets right now," not a theoretical severity score.
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

- EPSS (Exploit Prediction Scoring System, FIRST.org): a probabilistic score (0-1) of
  the likelihood a CVE will be exploited in the next 30 days, plus its percentile rank
  against all scored CVEs. Complements KEV - KEV is "confirmed exploited already," EPSS
  is "how likely is exploitation soon," and the two can disagree (a CVE can have high
  EPSS without being KEV-listed yet, or vice versa).

Why this matters: CVSS alone measures theoretical severity, not real-world risk. Two
findings with an identical CVSS score can have wildly different real exploitation risk -
KEV/EPSS are exactly the signals that close that gap, and are why remediation-planner.md
uses them to override pure asset-criticality heuristics when a finding is actively
exploited.
"""
import argparse
import json
from pathlib import Path

import requests

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # keep well under any practical query-length limit


def fetch_cisa_kev(session=None, url=KEV_FEED_URL):
    """Returns {cve_id: {date_added, vulnerability_name, known_ransomware_campaign_use,
    due_date}} for every CVE in CISA's current KEV catalog."""
    session = session or requests
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        v["cveID"]: {
            "date_added": v.get("dateAdded"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "due_date": v.get("dueDate"),
        }
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }


def fetch_epss_scores(cve_ids, session=None, url=EPSS_API_URL):
    """Returns {cve_id: {score, percentile}} for every CVE FIRST.org has an EPSS score
    for. Not every CVE has a score (very new or very obscure CVEs may be absent) -
    callers must handle a missing key, not assume every requested CVE comes back."""
    session = session or requests
    unique_ids = sorted({c for c in cve_ids if c})
    scores = {}
    for i in range(0, len(unique_ids), EPSS_BATCH_SIZE):
        batch = unique_ids[i:i + EPSS_BATCH_SIZE]
        resp = session.get(url, params={"cve": ",".join(batch)}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for row in data.get("data", []):
            scores[row["cve"]] = {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
    return scores


def enrich_findings(findings, kev_data=None, epss_data=None, session=None):
    """Adds `kev` and `epss` fields to each finding. Findings with no CVE (common for
    certificate/config-lifecycle findings) get kev=None, epss=None - that's expected,
    not a bug: KEV/EPSS are inherently CVE-scoped, and plenty of real findings aren't."""
    cve_ids = [f.get("cve") for f in findings if f.get("cve")]

    if kev_data is None:
        kev_data = fetch_cisa_kev(session=session) if cve_ids else {}
    if epss_data is None:
        epss_data = fetch_epss_scores(cve_ids, session=session) if cve_ids else {}

    enriched = []
    for f in findings:
        f = dict(f)
        cve = f.get("cve")
        if cve:
            f["kev"] = {"listed": True, **kev_data[cve]} if cve in kev_data else {"listed": False}
            f["epss"] = epss_data.get(cve)
        else:
            f["kev"] = None
            f["epss"] = None
        enriched.append(f)
    return enriched


def enrich_file(findings_path, output_path=None, session=None):
    findings_path = Path(findings_path)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    enriched = enrich_findings(findings, session=session)
    output_path = Path(output_path) if output_path else findings_path
    output_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Enrich normalized findings with live CISA KEV + EPSS data.")
    parser.add_argument("findings_path", help="Path to normalized-findings.json")
    parser.add_argument("--output", help="Output path (defaults to overwriting the input file)")
    args = parser.parse_args()
    out = enrich_file(args.findings_path, args.output)
    print(f"Enriched findings written to {out}")


if __name__ == "__main__":
    main()
