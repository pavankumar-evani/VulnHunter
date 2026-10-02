"""
Builds a CycloneDX SBOM from a repository's dependency files, for the (common) case where no SCA tool has produced one yet.

Supported files: requirements.txt, package.json, package-lock.json (v1, v2, v3), pom.xml and go.mod. Quanta reads text it is given; it never runs a
package manager, so it cannot resolve a dependency tree from a manifest that does not record one:
  - package-lock.json records the whole tree: direct and transitive packages, with the edges between them.
  - go.mod lists direct requirements and marks the rest `// indirect`; the edges between indirect modules are not recorded.
  - requirements.txt, package.json and pom.xml list only what the project declares. Their SBOM has direct dependencies and no transitive ones, and
    says so (`quanta:graph` = declared-only). Export a lock file or run your SCA tool for the full tree.
A declared range (^1.2.0, >=2.0) is recorded as the base version with the range kept in a property, because the version that is actually installed is
decided by the package manager. Matching vulnerabilities against it is therefore indicative until a lock file is used.
"""
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote

from remediation.appsec.sbom_parse import SbomError

MAX_FILE = 5_000_000


def _pypi(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _purl(eco, name, version, group=None):
    v = f"@{quote(version)}" if version else ""
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope, rest = name.split("/", 1)
        return f"pkg:npm/{quote(scope)}/{quote(rest)}{v}"
    if eco == "maven" and group:
        return f"pkg:maven/{quote(group)}/{quote(name)}{v}"
    return f"pkg:{eco}/{quote(name, safe='/')}{v}"


def _comp(eco, name, version, direct, group=None, scope=None, rng=None, from_file=None):
    purl = _purl(eco, name, version, group)
    props = [{"name": "quanta:direct", "value": "true" if direct else "false"}] if direct is not None else []
    if rng:
        props.append({"name": "quanta:declared-range", "value": rng})
    if from_file:
        props.append({"name": "quanta:source-file", "value": from_file})
    c = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
    if group:
        c["group"] = group
    if scope:
        c["scope"] = scope
    if props:
        c["properties"] = props
    return c


def _is_direct(comp):
    return any(p["name"] == "quanta:direct" and p["value"] == "true" for p in comp.get("properties", []))


def _base_version(spec):
    """The first concrete version inside a range like ^1.2.3, ~1.2, >=2.0,<3, 1.x. None if there is none."""
    m = re.search(r"\d+(?:\.\d+)*(?:[-.+]?[A-Za-z0-9.]+)?", spec or "")
    return m.group(0) if m else None


# ---------------------------------------------------------------- requirements.txt
def from_requirements(text, fname="requirements.txt"):
    out = []
    for line in text.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()  # environment markers
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, spec = _pypi(m.group(1)), m.group(2).strip()
        pinned = re.match(r"^===?\s*([0-9][A-Za-z0-9.!+_-]*)$", spec)
        version = pinned.group(1) if pinned else _base_version(spec)
        out.append(_comp("pypi", name, version, True, rng=None if pinned or not spec else spec, from_file=fname))
    return out, [], "declared-only"


# ---------------------------------------------------------------- package.json / package-lock.json
def from_package_json(text, fname="package.json"):
    doc = json.loads(text)
    out = []
    for key, scope in (("dependencies", None), ("devDependencies", "optional"), ("optionalDependencies", "optional")):
        for name, spec in (doc.get(key) or {}).items():
            spec = str(spec)
            if re.match(r"^(git|http|file|link|workspace)", spec):
                out.append(_comp("npm", name, None, True, scope=scope, rng=spec, from_file=fname))
            else:
                out.append(_comp("npm", name, _base_version(spec), True, scope=scope, rng=None if re.match(r"^\d", spec) else spec, from_file=fname))
    return out, [], "declared-only"


def from_package_lock(text, fname="package-lock.json"):
    doc = json.loads(text)
    pk = doc.get("packages")
    comps, edges = [], []
    if pk:  # lockfile v2 / v3
        root = pk.get("") or {}
        ref_of = {}
        for path, info in pk.items():
            if path and "node_modules/" in path:
                name = info.get("name") or path.rsplit("node_modules/", 1)[1]
                ref_of[path] = (name, _purl("npm", name, info.get("version")))

        def resolve(parent_path, dep):
            base = parent_path
            while True:
                cand = (base + "/" if base else "") + "node_modules/" + dep
                if cand in pk:
                    return cand
                if not base:
                    return None
                base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""
        direct = set()
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
            for dep in (root.get(dep_key) or {}):
                p = resolve("", dep)
                if p:
                    direct.add(p)
        seen = set()
        for path, (name, ref) in ref_of.items():
            info = pk[path]
            if ref not in seen:
                seen.add(ref)
                comps.append(_comp("npm", name, info.get("version"), path in direct, scope="optional" if info.get("dev") or info.get("optional") else None, from_file=fname))
            for dep in list(info.get("dependencies") or {}) + list(info.get("optionalDependencies") or {}):
                child = resolve(path, dep)
                if child in ref_of:
                    edges.append((ref, ref_of[child][1]))
        return comps, edges, "full", [ref_of[p][1] for p in direct], {"name": doc.get("name") or root.get("name"), "version": doc.get("version") or root.get("version")}

    def walk(deps, parent_ref, depth):  # lockfile v1: nested "dependencies"
        for name, info in (deps or {}).items():
            ref = _purl("npm", name, info.get("version"))
            comps.append(_comp("npm", name, info.get("version"), depth == 0, scope="optional" if info.get("dev") else None, from_file=fname))
            if parent_ref:
                edges.append((parent_ref, ref))
            walk(info.get("dependencies"), ref, depth + 1)
    walk(doc.get("dependencies"), None, 0)
    return comps, edges, "full", [c["bom-ref"] for c in comps if _is_direct(c)], {"name": doc.get("name"), "version": doc.get("version")}


# ---------------------------------------------------------------- pom.xml
def from_pom(text, fname="pom.xml"):
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise SbomError("pom.xml with a DOCTYPE or entity declaration is refused")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SbomError(f"pom.xml is not valid XML: {exc}") from exc

    def tag(e):
        return e.tag.rsplit("}", 1)[-1]

    def kid(e, name):
        for c in e:
            if tag(c) == name:
                return (c.text or "").strip()
        return None
    props = {}
    for pe in root:
        if tag(pe) == "properties":
            for p in pe:
                props[tag(p)] = (p.text or "").strip()
    for k in ("version", "groupId"):
        v = kid(root, k)
        if v:
            props[f"project.{k}"] = v

    def subst(v):
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v) if v else v
    managed = {}
    for dm in root:
        if tag(dm) == "dependencyManagement":
            for deps in dm:
                for d in deps:
                    managed[(kid(d, "groupId"), kid(d, "artifactId"))] = subst(kid(d, "version"))
    out = []
    for deps in root:
        if tag(deps) != "dependencies":
            continue
        for d in deps:
            g, a = kid(d, "groupId"), kid(d, "artifactId")
            if not a:
                continue
            v = subst(kid(d, "version")) or managed.get((g, a))
            if v and "${" in v:
                v = None
            sc = kid(d, "scope")
            out.append(_comp("maven", a, v, True, group=g, scope="optional" if sc in ("test", "provided") else None, from_file=fname))
    return out, [], "declared-only"


# ---------------------------------------------------------------- go.mod
def from_go_mod(text, fname="go.mod"):
    out, in_block = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        spec = line if in_block else (line[len("require "):] if line.startswith("require ") else None)
        if not spec or spec.startswith("//"):
            continue
        m = re.match(r"^(\S+)\s+(v\S+)(.*)$", spec)
        if m:
            out.append(_comp("golang", m.group(1), m.group(2), "// indirect" not in m.group(3), from_file=fname))
    return out, [], "declared-only"


HANDLERS = {"requirements.txt": from_requirements, "package.json": from_package_json, "package-lock.json": from_package_lock, "pom.xml": from_pom, "go.mod": from_go_mod}


def supported():
    return sorted(HANDLERS)


def generate(application, files, version=None):
    """files: {"path/to/package-lock.json": text, ...} -> (CycloneDX dict, notes). The file's base name picks the reader."""
    if not files:
        raise SbomError("Give at least one dependency file")
    comps, edges, notes, graph_kinds, direct_refs, meta = {}, [], [], [], [], {}
    for path, text in files.items():
        base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        fn = HANDLERS.get(base) or (from_requirements if re.match(r"^requirements.*\.txt$", base) else None)
        if not fn:
            raise SbomError(f"{path}: not a supported dependency file ({', '.join(supported())})")
        if len(text) > MAX_FILE:
            raise SbomError(f"{path}: the file is too large")
        try:
            res = fn(text, path)
        except SbomError:
            raise
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise SbomError(f"{path}: could not be read ({type(exc).__name__}: {exc})") from exc
        graph_kinds.append(res[2])
        edges += res[1]
        if len(res) > 3:
            direct_refs += res[3]
            meta = res[4] or meta
        for comp in res[0]:
            have = comps.get(comp["bom-ref"])
            if have is None or (_is_direct(comp) and not _is_direct(have)):
                comps[comp["bom-ref"]] = comp
    root_ref = f"app:{application}"
    root_edges = sorted({r for r, c in comps.items() if _is_direct(c)} | set(direct_refs))
    deps = {}
    for a, b in edges:
        deps.setdefault(a, set()).add(b)
    dependencies = [{"ref": root_ref, "dependsOn": root_edges}] + [{"ref": a, "dependsOn": sorted(b)} for a, b in sorted(deps.items())]
    full = all(k == "full" for k in graph_kinds)
    if not full:
        notes.append("Only declared dependencies were available for at least one file, so transitive dependencies are not in this SBOM. A lock file or your SCA tool's export gives the full tree.")
    unversioned = sum(1 for c in comps.values() if not c.get("version"))
    if unversioned:
        notes.append(f"{unversioned} dependenc{'y has' if unversioned == 1 else 'ies have'} no concrete version (a range, a git reference or a managed version), so they cannot be matched to vulnerabilities.")
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": {"type": "application", "bom-ref": root_ref, "name": application, "version": version or meta.get("version") or ""},
                        "properties": [{"name": "quanta:graph", "value": "full" if full else "declared-only"}, {"name": "quanta:generated-from", "value": ", ".join(sorted(files))}]},
           "components": list(comps.values()), "dependencies": dependencies}
    return doc, notes
