"""
Zero-day watch: newly exploited vulnerabilities in products you appear to run, that your scanners have not reported yet.

A scanner only reports a CVE once its signatures cover it; CISA adds a vulnerability to the Known Exploited Vulnerabilities (KEV) catalog the day
exploitation is confirmed. Between the two there is a gap. This compares the catalog's recent additions (vendor and product names) with the
vocabulary of your estate: operating systems and software named on assets, finding titles, and SBOM components.

  - A catalog entry is a "watch item" when its vendor name AND at least one product word appear in that vocabulary, and no finding for the CVE exists.
  - It is a name match, not a version check. It says "you run something with this name; check whether your version is affected". Your scanner and
    the vendor advisory are the authority.
  - Entries whose CVE already has a finding are counted as "already tracked" and not repeated.
Ransomware-linked entries and the newest additions come first. Needs the catalog from CISA; with no network it says so and shows nothing.
"""
import datetime
import re

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_STOP = {"the", "and", "for", "inc", "corp", "corporation", "ltd", "llc", "systems", "software", "project", "foundation", "group", "technologies", "technology", "products", "product",
         "server", "services", "service", "platform", "manager", "management", "web", "application", "applications", "suite", "enterprise", "edition", "framework", "library", "windows"}
_WORD = re.compile(r"[a-z0-9][a-z0-9.+-]{2,}")


def fetch_catalog(session=None, url=KEV_URL, timeout=30):
    resp = (session or requests).get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def _words(text):
    return {w.strip(".-+") for w in _WORD.findall((text or "").lower())} - _STOP


def vocabulary(findings, sbom_components=()):
    """{word: sample of where it was seen} from asset OS strings, finding titles and SBOM components."""
    vocab = {}

    def add(text, source):
        for w in _words(text):
            vocab.setdefault(w, source)

    for f in findings:
        a = f.get("asset") or {}
        add(a.get("os"), f"asset {a.get('name')}")
        add(f.get("title"), f"finding {f.get('id')}")
        dep = f.get("dependency") or {}
        add(dep.get("package"), f"finding {f.get('id')}")
    for c in sbom_components:
        add(c.get("name"), "SBOM")
        add(c.get("supplier") or c.get("group") or "", "SBOM")
    return vocab


def watch(catalog, findings, sbom_components=(), days=30, today=None, limit=100):
    today = today or datetime.date.today()
    since = (today - datetime.timedelta(days=days)).isoformat()
    tracked = {(f.get("cve") or "").upper() for f in findings if f.get("cve")}
    vocab = vocabulary(findings, sbom_components)
    items, already = [], 0
    for v in catalog:
        if (v.get("dateAdded") or "") < since:
            continue
        cve = (v.get("cveID") or "").upper()
        if cve in tracked:
            already += 1
            continue
        vendor_w, product_w = _words(v.get("vendorProject")), _words(v.get("product"))
        vendor_hit = sorted(w for w in vendor_w if w in vocab)
        product_hit = sorted(w for w in product_w if w in vocab)
        if vendor_hit and product_hit:
            items.append({"cve": cve, "vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"),
                          "due_date": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "required_action": v.get("requiredAction"),
                          "matched_on": sorted(set(vendor_hit + product_hit)), "seen_in": sorted({vocab[w] for w in vendor_hit + product_hit})[:5]})
    items.sort(key=lambda i: i["date_added"], reverse=True)
    items.sort(key=lambda i: not i["ransomware"])
    return {"window_days": days, "items": items[:limit], "total_matches": len(items), "already_tracked": already, "catalog_entries_in_window": sum(1 for v in catalog if (v.get("dateAdded") or "") >= since),
            "note": "A name match is not a version check: it says you appear to run something with this name. Check whether your version is affected; your scanner and the vendor advisory decide."}
