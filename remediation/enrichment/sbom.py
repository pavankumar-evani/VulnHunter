"""
CycloneDX SBOM parsing and dependency blast-radius calculation.

CycloneDX (https://cyclonedx.org/) is chosen because it's a real, open, ECMA
International-standardized SBOM format, not a single vendor's proprietary one. There is
no SBOM-generation or SBOM-scanning connector in this repo - this module reads an SBOM
file a caller already has (e.g. exported by an existing SCA tool such as Trivy or Syft,
or a build-time CycloneDX plugin), the same "manually-supplied input, not a live
integration" honesty already applied to remediation/sample-data/threat_intel.json.

Only the two fields every real CycloneDX 1.4+ document has are read: `components`
(name/version/purl per package) and `dependencies` (bom-ref -> the bom-refs it depends
on) - this module doesn't require or validate the full CycloneDX schema, and ignores
CycloneDX's own optional `vulnerabilities` block entirely (matching a finding's CVE to a
specific SBOM component is a judgment call left to vuln-ingest-normalizer.md's own LLM
reasoning, not this module - see that subagent's file for why).
"""
import json
import re
from pathlib import Path

DEFAULT_SBOM_PATH = Path(__file__).resolve().parent.parent / "sample-data" / "sbom.json"

_PURL_ECOSYSTEM_RE = re.compile(r"^pkg:([^/]+)/")


def load_sbom(path=None):
    path = Path(path) if path is not None else DEFAULT_SBOM_PATH
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _ecosystem_from_purl(purl):
    """Extracts the package-type segment of a Package URL (https://github.com/
    package-url/purl-spec), e.g. "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    -> "maven". Returns None if there's no purl, or it doesn't match the pkg: scheme -
    an honest "couldn't determine," never a guessed default ecosystem."""
    if not purl:
        return None
    m = _PURL_ECOSYSTEM_RE.match(purl)
    return m.group(1) if m else None


def _all_components(sbom):
    """Every real component in this document, including the BOM's own root/subject
    component - which CycloneDX stores separately under metadata.component, not inside
    the top-level `components` array. Both a name lookup and the blast-radius graph
    need to see the root too, since other components can (and typically do) depend on
    it."""
    components = list(sbom.get("components", []))
    root = (sbom.get("metadata") or {}).get("component")
    if root:
        components.append(root)
    return components


def find_component(sbom, package_name):
    """Case-insensitive match against a component's `name` (including the BOM's own
    root/subject component, see _all_components()) - returns the raw CycloneDX
    component dict, or None if no component in this SBOM has that name."""
    if not package_name:
        return None
    target = package_name.lower()
    for component in _all_components(sbom):
        if str(component.get("name", "")).lower() == target:
            return component
    return None


def component_info(component):
    """Flattens a raw CycloneDX component into {package, ecosystem, version} - the
    shape a Finding's `dependency` field uses (see
    remediation/schema/normalized-finding-schema.md). Returns None unchanged so a
    caller can chain find_component() -> component_info() and get an honest None
    for a package that isn't in the SBOM at all."""
    if component is None:
        return None
    return {
        "package": component.get("name"),
        "ecosystem": _ecosystem_from_purl(component.get("purl")),
        "version": component.get("version"),
    }


def compute_blast_radius(sbom, package_name):
    """Returns the sorted list of component names that depend - directly or
    transitively - on `package_name`, by walking CycloneDX's `dependencies` graph in
    reverse (each entry is {ref, dependsOn: [...]}, meaning "ref depends on everything
    in dependsOn"). Returns [] if the package isn't in this SBOM at all, or nothing in
    it depends on it - both honest "no blast radius to report," never guessed."""
    target = find_component(sbom, package_name)
    if target is None:
        return []
    target_ref = target.get("bom-ref")
    if not target_ref:
        return []

    ref_to_name = {c["bom-ref"]: c.get("name") for c in _all_components(sbom) if c.get("bom-ref")}
    # dependents_of[X] = every ref that lists X in its own dependsOn, i.e. every ref
    # directly depending on X - the reverse of how CycloneDX itself records the edge.
    dependents_of = {}
    for entry in sbom.get("dependencies", []):
        for dep_ref in entry.get("dependsOn", []):
            dependents_of.setdefault(dep_ref, set()).add(entry.get("ref"))

    visited = set()
    frontier = {target_ref}
    while frontier:
        next_frontier = set()
        for ref in frontier:
            for dependent_ref in dependents_of.get(ref, ()):
                if dependent_ref not in visited:
                    visited.add(dependent_ref)
                    next_frontier.add(dependent_ref)
        frontier = next_frontier

    return sorted(ref_to_name.get(ref, ref) for ref in visited)
