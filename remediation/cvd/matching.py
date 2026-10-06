"""Matches CVD advisories to the estate: exact CVE against findings, then product name against the zero-day-watch vocabulary (a name match, not a version check)."""
from remediation.enrichment import zero_day_watch as zdw


def match_estate(advisories, findings, sbom_components=()):
    by_cve = {}
    for f in findings:
        if f.get("cve"):
            by_cve.setdefault(f["cve"].upper(), []).append(f.get("id"))
    vocab = zdw.vocabulary(findings, sbom_components)
    out = []
    for a in advisories:
        cve_hits = sorted({fid for c in a["cves"] for fid in by_cve.get(c.upper(), []) if fid})
        pw, vw = zdw._words(a["product"]), zdw._words(a["vendor"])
        name_ok = bool(pw) and all(w in vocab for w in pw) and (not vw or any(w in vocab for w in vw))
        if not cve_hits and not name_ok:
            continue
        words = pw | vw
        out.append({**a, "match_basis": (["cve"] if cve_hits else []) + (["name"] if name_ok else []), "finding_ids": cve_hits,
                    "matched_on": sorted(w for w in words if w in vocab) if name_ok else [], "seen_in": sorted({vocab[w] for w in words if w in vocab})[:5] if name_ok else []})
    out.sort(key=lambda m: m["published"], reverse=True)
    out.sort(key=lambda m: "cve" not in m["match_basis"])
    return out
