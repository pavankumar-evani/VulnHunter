"""
The gitops policy (remediation/config/gitops_policy.yaml): branch naming, protected branches, what a change may touch, how the pull request is labelled,
and the process steps shown to reviewers. Every guard here is deterministic and runs before anything is sent to a Git host.
"""
import copy
import fnmatch
import posixpath
import re
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "gitops_policy.yaml"
_SECTIONS = ("branch", "commit", "pull_request", "approval", "files", "code_fix", "process", "verify_commands")


class PolicyError(ValueError):
    pass


def load(path=None):
    with open(path or PATH, encoding="utf-8") as fh:
        pol = yaml.safe_load(fh) or {}
    for s in _SECTIONS:
        if s not in pol:
            raise PolicyError(f"gitops_policy.yaml: the {s} section is missing")
    if "{id}" not in pol["branch"]["template"]:
        raise PolicyError("gitops_policy.yaml: the branch template must contain {id}, so two proposals never share a branch")
    return pol


def for_repo(policy, repo):
    """The policy with the first matching override merged in, section by section."""
    out = copy.deepcopy({k: v for k, v in policy.items() if k != "overrides"})
    for ov in policy.get("overrides") or []:
        if fnmatch.fnmatch((repo or "").lower(), str(ov.get("match", "")).lower()):
            for sec, vals in ov.items():
                if sec != "match" and isinstance(vals, dict):
                    out.setdefault(sec, {}).update(vals)
            break
    return out


def slug(text, limit=30):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:limit].strip("-")
    return s or "change"


def branch_name(pol, proposal_id, kind, subject, attempt=1):
    name = pol["branch"]["template"].format(id=proposal_id, kind="deps" if kind == "dependency-upgrade" else "code", slug=slug(subject))
    if attempt > 1:
        name += f"-r{attempt}"
    return name


def check_branch(pol, branch, base=None, default=None):
    """Raises PolicyError when the branch is one Quanta must not write to or is not a safe name."""
    if not re.match(r"^[A-Za-z0-9._/-]{3,150}$", branch or "") or ".." in branch or branch.endswith("/") or branch.startswith("/"):
        raise PolicyError("The branch name is not valid")
    for protected in [base, default] + list(pol["branch"].get("protected") or []):
        if protected and (branch == protected or fnmatch.fnmatch(branch, protected)):
            raise PolicyError(f"The branch {branch} matches the protected pattern {protected}; Quanta will not write to it")


def check_files(pol, files):
    """files: [{"path", "content"}]. Raises PolicyError for a path outside the repository, a denied path, or an oversized change."""
    fp = pol["files"]
    if not files:
        raise PolicyError("The change contains no files")
    if len(files) > fp["max_files"]:
        raise PolicyError(f"The change touches {len(files)} files; the policy allows {fp['max_files']}")
    for f in files:
        path = f["path"]
        if path.startswith("/") or ".." in path.split("/") or "\\" in path:
            raise PolicyError(f"{path}: must be a relative path inside the repository")
        for pat in fp.get("denied") or []:
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("x/" + path, pat):
                raise PolicyError(f"{path}: the policy does not allow Quanta to change files matching {pat}")
        if len(f["content"].encode("utf-8")) > fp["max_bytes_per_file"]:
            raise PolicyError(f"{path}: the file is larger than the policy allows")


def check_code_scope(pol, files, finding_file):
    scope = pol["code_fix"]["scope"]
    for f in files:
        path = f["path"]
        if path == finding_file:
            continue
        if scope == "same-directory" and finding_file and posixpath.dirname(path) == posixpath.dirname(finding_file):
            continue
        raise PolicyError(f"{path}: a code fix may change only {finding_file or 'the finding file'}" + (" and files beside it" if scope == "same-directory" else ""))
