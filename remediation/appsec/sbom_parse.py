"""
Reads a software bill of materials into one internal shape, whatever format it arrived in.

Supported: CycloneDX JSON (1.3 to 1.6) and SPDX JSON (2.2 and 2.3). Tag-value and XML variants are not read; export JSON from your SCA tool.

The internal shape:
    {"format": "cyclonedx-1.5", "root": {"ref", "name", "version"} | None,
     "components": [{"ref", "name", "group", "version", "ecosystem", "purl", "type", "licenses", "scope", "direct_hint"}],
     "edges": [[parent_ref, child_ref], ...], "has_graph": bool}

`has_graph` says whether the document recorded who depends on whom. A flat list of components (a common export) has no graph, and then nothing here
pretends to know which packages are direct: that stays unknown rather than being guessed. `direct_hint` is set only when the document says so
(Quanta's own generated SBOMs mark declared dependencies, and a go.mod `// indirect` comment is honoured).
"""
import json
import re

MAX_COMPONENTS = 20000
_PURL = re.compile(r"^pkg:([a-z0-9.+-]+)/(?:([^@?#]+)/)?([^/@?#]+)(?:@([^?#]+))?", re.I)


class SbomError(ValueError):
    pass


def purl_parts(purl):
    """(ecosystem, group, name, version) from a Package URL, any part None when absent."""
    m = _PURL.match(purl or "")
    if not m:
        return None, None, None, None
    eco, ns, name, ver = m.groups()
    from urllib.parse import unquote
    return eco.lower(), unquote(ns) if ns else None, unquote(name), unquote(ver) if ver else None


def _licenses(c):
    out = []
    for item in c.get("licenses") or []:
        lic = item.get("license") if isinstance(item, dict) else None
        if lic:
            out.append(lic.get("id") or lic.get("name"))
        elif isinstance(item, dict) and item.get("expression"):
            out.append(item["expression"])
    return [x for x in out if x]


def _cdx_component(c, ref):
    eco, ns, pname, pver = purl_parts(c.get("purl"))
    hint = next((p.get("value") for p in c.get("properties") or [] if isinstance(p, dict) and p.get("name") == "quanta:direct"), None)
    return {"ref": ref, "name": c.get("name") or pname or ref, "group": c.get("group") or ns, "version": c.get("version") or pver,
            "ecosystem": eco, "purl": c.get("purl"), "type": c.get("type") or "library", "licenses": _licenses(c), "scope": c.get("scope"),
            "direct_hint": {"true": True, "false": False}.get(str(hint).lower())}


def _walk_cdx(components, out, seen):
    for c in components or []:
        if not isinstance(c, dict):
            continue
        ref = c.get("bom-ref") or c.get("purl") or f"{c.get('name')}@{c.get('version')}"
        if ref not in seen:
            seen.add(ref)
            out.append(_cdx_component(c, ref))
        _walk_cdx(c.get("components"), out, seen)  # components may be nested


def parse_cyclonedx(doc):
    comps, seen = [], set()
    root_c = (doc.get("metadata") or {}).get("component")
    root = None
    if isinstance(root_c, dict):
        rref = root_c.get("bom-ref") or f"root:{root_c.get('name')}"
        root = {"ref": rref, "name": root_c.get("name") or "application", "version": root_c.get("version")}
        seen.add(rref)
    _walk_cdx(doc.get("components"), comps, seen)
    if len(comps) > MAX_COMPONENTS:
        raise SbomError(f"The SBOM lists more than {MAX_COMPONENTS} components, which Quanta will not load")
    refs = seen
    edges = []
    for d in doc.get("dependencies") or []:
        if isinstance(d, dict) and d.get("ref"):
            for child in d.get("dependsOn") or []:
                if d["ref"] in refs and child in refs:
                    edges.append([d["ref"], child])
    return {"format": f"cyclonedx-{doc.get('specVersion', '?')}", "root": root, "components": comps, "edges": edges, "has_graph": bool(edges)}


def parse_spdx(doc):
    pkgs = {}
    for p in doc.get("packages") or []:
        if not isinstance(p, dict) or not p.get("SPDXID"):
            continue
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or [] if str(r.get("referenceType", "")).lower() == "purl"), None)
        eco, ns, pname, pver = purl_parts(purl)
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        pkgs[p["SPDXID"]] = {"ref": p["SPDXID"], "name": p.get("name") or pname or p["SPDXID"], "group": ns, "version": p.get("versionInfo") or pver, "ecosystem": eco,
                             "purl": purl, "type": "library", "licenses": [lic] if lic and lic not in ("NOASSERTION", "NONE") else [], "scope": None, "direct_hint": None}
    root_id = None
    edges = []
    describes = list(doc.get("documentDescribes") or [])
    for r in doc.get("relationships") or []:
        a, b, kind = r.get("spdxElementId"), r.get("relatedSpdxElement"), str(r.get("relationshipType", "")).upper()
        if kind == "DESCRIBES" and a == doc.get("SPDXID", "SPDXRef-DOCUMENT"):
            describes.append(b)
        elif kind in ("DEPENDS_ON", "CONTAINS", "STATIC_LINK", "DYNAMIC_LINK") and a in pkgs and b in pkgs:
            edges.append([a, b])
        elif kind == "DEPENDENCY_OF" and a in pkgs and b in pkgs:
            edges.append([b, a])
    root_id = next((d for d in describes if d in pkgs), None)
    root = None
    if root_id:
        r = pkgs.pop(root_id)
        root = {"ref": root_id, "name": r["name"], "version": r["version"]}
    comps = list(pkgs.values())
    if len(comps) > MAX_COMPONENTS:
        raise SbomError(f"The SBOM lists more than {MAX_COMPONENTS} components, which Quanta will not load")
    return {"format": f"spdx-{str(doc.get('spdxVersion', '?')).replace('SPDX-', '')}", "root": root, "components": comps, "edges": edges, "has_graph": bool(edges)}


def parse(data):
    """Bytes, text or an already-parsed dict -> the internal shape. Raises SbomError with a readable message."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8-sig", "replace")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise SbomError("That is not JSON. Export the SBOM as CycloneDX JSON or SPDX JSON.") from exc
    if not isinstance(data, dict):
        raise SbomError("An SBOM is a JSON object")
    if str(data.get("bomFormat", "")).lower() == "cyclonedx" or "components" in data and "specVersion" in data:
        return parse_cyclonedx(data)
    if str(data.get("spdxVersion", "")).startswith("SPDX-") or "packages" in data and "SPDXID" in data:
        return parse_spdx(data)
    raise SbomError("This is neither CycloneDX JSON (bomFormat) nor SPDX JSON (spdxVersion)")
