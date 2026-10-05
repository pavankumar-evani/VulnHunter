"""
Deterministic dependency-upgrade edits: given a manifest file's text, the package and the version to move to, return the edited text.

No model is involved and nothing is executed. The edit is small and the reviewer sees it as a diff:
  requirements.txt  the package's line gets `==<target>`; a package that is only pulled in transitively gets a new constraint line
  package.json      the declared range keeps its style (^, ~ or exact) at the new version; a transitive package gets an `overrides` entry
  pom.xml           the dependency's <version> (or the property it points at) changes; a managed or transitive package gets a <dependencyManagement> entry
  go.mod            the module's require line changes; a module not listed gets an `// indirect` require line
A lock file cannot be regenerated without running the package manager, which Quanta never does, so the pull request says the lock file must be refreshed.
"""
import json
import re
from collections import OrderedDict

from remediation.gitops import diffing


class PatchError(ValueError):
    pass


def _norm_py(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- requirements.txt
def patch_requirements(text, package, target, group=None, reason=""):
    lines = text.split("\n")
    want = _norm_py(package)
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)([^;#\n]*?)(\s*;[^#\n]*)?(\s*#.*)?$", line)
        if m and not line.lstrip().startswith(("#", "-")) and _norm_py(m.group(2)) == want:
            new = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={target}{m.group(6) or ''}{m.group(7) or ''}"
            if new == line:
                raise PatchError(f"{package} is already pinned to {target} in this file")
            lines[i] = new
            return "\n".join(lines), [f"{package}: {line.strip()} -> {new.strip()}"]
    sep = "" if text.endswith("\n") or not text else "\n"
    note = f"  # added by Quanta{(': ' + reason) if reason else ''}"
    return text + sep + f"{package}=={target}{note}\n", [f"{package}: not declared in this file (a transitive dependency); added a pin to {target}"]


# ---------------------------------------------------------------- package.json
def _indent(text):
    m = re.search(r"^([ \t]+)\"", text, re.M)
    return m.group(1) if m else "  "


def patch_package_json(text, package, target, group=None, reason=""):
    try:
        doc = json.loads(text, object_pairs_hook=OrderedDict)
    except ValueError as exc:
        raise PatchError(f"package.json is not valid JSON: {exc}") from exc
    changes = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = doc.get(key)
        if isinstance(deps, dict) and package in deps:
            old = deps[package]
            prefix = re.match(r"^(\^|~|>=|>)?", str(old)).group(1) or ""
            if re.match(r"^(git|http|file|link|workspace|npm:)", str(old)):
                raise PatchError(f"{package} is declared as {old!r}, which is not a registry version; change it by hand")
            deps[package] = prefix + target
            if deps[package] == old:
                raise PatchError(f"{package} is already {old} in package.json")
            changes.append(f"{key}.{package}: {old} -> {deps[package]}")
            break
    else:
        ov = doc.setdefault("overrides", OrderedDict())
        if not isinstance(ov, dict):
            raise PatchError("package.json has an `overrides` value that is not an object")
        ov[package] = target
        changes.append(f"overrides.{package}: {target} (transitive dependency; npm applies overrides to the whole tree)")
    ind = _indent(text)
    out = json.dumps(doc, indent=ind if ind != "\t" else "\t", ensure_ascii=False) + ("\n" if text.endswith("\n") else "")
    return out, changes


# ---------------------------------------------------------------- pom.xml
def _split_ga(package, group):
    if ":" in package:
        g, a = package.split(":", 1)
        return g, a
    return group, package


def patch_pom(text, package, target, group=None, reason=""):
    g, a = _split_ga(package, group)
    blocks = list(re.finditer(r"<dependency>.*?</dependency>", text, re.S))
    for b in blocks:
        blk = b.group(0)
        am = re.search(r"<artifactId>\s*" + re.escape(a) + r"\s*</artifactId>", blk)
        gm = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", blk)
        if not am or (g and gm and gm.group(1) != g):
            continue
        in_mgmt = text.rfind("<dependencyManagement>", 0, b.start()) > text.rfind("</dependencyManagement>", 0, b.start())
        vm = re.search(r"(<version>\s*)([^<]*?)(\s*</version>)", blk)
        if not vm:
            continue  # managed elsewhere: handled below
        ver = vm.group(2).strip()
        pm = re.match(r"^\$\{([^}]+)\}$", ver)
        if pm:
            prop = pm.group(1)
            rx = re.compile(r"(<" + re.escape(prop) + r">\s*)([^<]*?)(\s*</" + re.escape(prop) + r">)")
            if not rx.search(text):
                raise PatchError(f"The version is ${{{prop}}} but that property is not defined in this pom.xml (it may come from a parent)")
            old = rx.search(text).group(2)
            return rx.sub(lambda m: m.group(1) + target + m.group(3), text, count=1), [f"property {prop}: {old} -> {target} (used by {a})"]
        if ver == target:
            raise PatchError(f"{a} is already {target} in this pom.xml")
        new_blk = blk[:vm.start()] + vm.group(1) + target + vm.group(3) + blk[vm.end():]
        return text[:b.start()] + new_blk + text[b.end():], [f"{g or '?'}:{a}{' (dependencyManagement)' if in_mgmt else ''}: {ver} -> {target}"]
    if not g:
        raise PatchError(f"{a} is not declared with a version in this pom.xml and its groupId is not known; name it as groupId:artifactId")
    entry = f"<dependency>\n        <groupId>{g}</groupId>\n        <artifactId>{a}</artifactId>\n        <version>{target}</version>\n      </dependency>"
    note = f"{g}:{a}: added to dependencyManagement at {target} (managed or transitive dependency)"
    dm = re.search(r"(<dependencyManagement>\s*<dependencies>)", text)
    if dm:
        return text[:dm.end()] + "\n      " + entry + text[dm.end():], [note]
    section = f"  <dependencyManagement>\n    <dependencies>\n      {entry}\n    </dependencies>\n  </dependencyManagement>\n"
    end = text.rfind("</project>")
    if end < 0:
        raise PatchError("pom.xml has no closing </project>")
    return text[:end] + section + text[end:], [note]


# ---------------------------------------------------------------- go.mod
def patch_go_mod(text, package, target, group=None, reason=""):
    rx = re.compile(r"^(\s*(?:require\s+)?" + re.escape(package) + r"\s+)(v[^\s]+)(.*)$", re.M)
    m = rx.search(text)
    tgt = target if target.startswith("v") else "v" + target
    if m:
        if m.group(2) == tgt:
            raise PatchError(f"{package} is already {tgt} in go.mod")
        return rx.sub(lambda mm: mm.group(1) + tgt + mm.group(3), text, count=1), [f"{package}: {m.group(2)} -> {tgt}"]
    sep = "" if text.endswith("\n") else "\n"
    return text + sep + f"\nrequire {package} {tgt} // indirect\n", [f"{package}: not listed (a transitive module); added a require at {tgt}"]


HANDLERS = {"requirements": patch_requirements, "package.json": patch_package_json, "pom.xml": patch_pom, "go.mod": patch_go_mod}
ECOSYSTEM_OF = {"requirements": "pypi", "package.json": "npm", "pom.xml": "maven", "go.mod": "golang"}
LOCKFILES = {"npm": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"], "pypi": ["Pipfile.lock", "poetry.lock", "requirements.lock"], "golang": ["go.sum"], "maven": []}


def kind_of(path):
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base == "package.json" or base == "pom.xml" or base == "go.mod":
        return base
    return "requirements" if re.match(r"^requirements.*\.txt$", base) else None


def ecosystem_of_path(path):
    k = kind_of(path)
    return ECOSYSTEM_OF.get(k)


def patch_manifest(path, text, package, target, group=None, reason=""):
    """-> {"path", "new_text", "diff", "changes"}. Raises PatchError with a readable reason."""
    k = kind_of(path)
    if not k:
        raise PatchError(f"{path}: not a manifest Quanta can edit (requirements.txt, package.json, pom.xml, go.mod)")
    new, changes = HANDLERS[k](text, package, target, group, reason)
    return {"path": path, "new_text": new, "diff": diffing.unified(text, new, path), "changes": changes}


def declares(path, text, package, group=None):
    """True when the manifest itself names the package (so the change is a version bump, not an added pin)."""
    k = kind_of(path)
    if k == "requirements":
        return any(_norm_py(re.split(r"[\[<>=!~;\s#]", ln.strip(), maxsplit=1)[0]) == _norm_py(package) for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith(("#", "-")))
    if k == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return False
        return any(package in (doc.get(s) or {}) for s in ("dependencies", "devDependencies", "optionalDependencies"))
    if k == "pom.xml":
        g, a = _split_ga(package, group)
        return bool(re.search(r"<artifactId>\s*" + re.escape(a) + r"\s*</artifactId>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*?<version>", text))
    if k == "go.mod":
        return bool(re.search(r"^\s*(?:require\s+)?" + re.escape(package) + r"\s+v", text, re.M))
    return False
