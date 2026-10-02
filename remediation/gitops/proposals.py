"""
Fix proposals: a reviewable change to a customer's repository, from draft to merged to verified.

Lifecycle (status):  draft -> approved -> pr-opened -> in-review -> merged | closed;  failed (the host refused a step; the proposal can be retried);
discarded (abandoned before any pull request existed).
  draft       generated from a dependency file or a patch; nothing has left Quanta
  approved    an administrator reviewed the diff and the evidence (a different administrator if the policy says so)
  pr-opened   a branch of Quanta's making exists on the Git host with the change committed, and a pull request is open
  in-review   the host reports reviews requested, given or changes requested
  merged      a person merged it; Quanta only ever observes this, from the host or an inbound call
Verification is separate and is never claimed by a person: after a merge the next scan either stops reporting the findings (verified), still reports
them (still-present) or has not run yet (awaiting-rescan). It is evidence, not proof, and says so.

Quanta changes a repository in exactly one place, `open_pr` with confirm=True: it creates a new branch, commits the files already shown in the diff, and
opens a pull request. Every guard (protected branches, denied paths, size limits, approval) runs before any request is sent, and the dry run returns
the full plan with no request sent at all.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.appsec import versions
from remediation.devsecops import factory as dso_factory
from remediation.gitops import diffing, policy as pol_mod, prbody, upgrade
from remediation.utils import db as db_module

ACTIVE = ("draft", "approved", "pr-opened", "in-review", "failed")
TERMINAL = ("merged", "closed", "discarded")
STATUSES = ACTIVE + TERMINAL


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _row(r):
    d = dict(r)
    d["finding_ids"] = json.loads(d["finding_ids"])
    d["files"] = json.loads(d.pop("files_json"))
    d["summary"] = json.loads(d.pop("summary_json") or "{}")
    return d


def get(proposal_id, engine=None):
    engine, t = _engine(engine), db_module.fix_proposals
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(proposal_id))).mappings().first()
    return _row(r) if r else None


def list_proposals(application=None, status=None, engine=None):
    engine, t = _engine(engine), db_module.fix_proposals
    q = select(t).order_by(t.c.id.desc())
    if application:
        q = q.where(t.c.application == application)
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(q).mappings().all()]


def public(p, with_files=True):
    """A proposal as the API shows it: no snapshots of the application context, and file contents only on request."""
    out = {k: v for k, v in p.items() if k != "files"}
    out["summary"] = {k: v for k, v in p["summary"].items() if k != "ctx"}
    out["files"] = [{**{k: v for k, v in f.items() if k != "new_content"}} for f in p["files"]] if with_files else []
    return out


def _update(proposal_id, engine, **vals):
    engine, t = _engine(engine), db_module.fix_proposals
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(proposal_id)).values(**vals))


def _refresh_text(p, pol, engine):
    """Rebuild the pull request title and body (they name the approver, so they change when it is approved)."""
    ctx = p["summary"].get("ctx") or {}
    title = prbody.pr_title(pol, p["kind"], p["summary"], p["finding_ids"])
    text = prbody.body(pol, p, ctx.get("findings") or [], ctx.get("reach"), ctx.get("app") or {})
    _update(p["id"], engine, pr_title=title, pr_body=text)


def _duplicate(application, key, engine):
    for p in list_proposals(application, engine=engine):
        if p["status"] in ACTIVE and p["summary"].get("key") == key:
            raise ValueError(f"Proposal {p['id']} for the same change is still {p['status']}. Finish or discard it first.")


def _insert(application, kind, finding_ids, title, summary, files, app, actor, pol, engine):
    engine, t = _engine(engine), db_module.fix_proposals
    row = {"application": application, "kind": kind, "finding_ids": json.dumps(finding_ids), "title": title, "summary_json": json.dumps(summary), "provider": app.get("repo_provider"),
           "repo": app.get("repo"), "connection_id": app.get("connection_id"), "base_branch": app.get("default_branch"), "branch": None, "files_json": json.dumps(files),
           "pr_title": "", "pr_body": "", "test_command": None, "status": "draft", "created_by": actor, "created_at": _now()}
    with engine.begin() as conn:
        pid = conn.execute(insert(t), row).inserted_primary_key[0]
    _update(pid, engine, branch=pol_mod.branch_name(pol, pid, kind, summary.get("package") or title))
    _refresh_text(get(pid, engine), pol, engine)
    return get(pid, engine)


# ---------------------------------------------------------------- creating proposals
def create_dependency(app, item, findings, reach, manifests, actor, lockfiles=None, group=None, validation=None, policy=None, engine=None):
    """item: a dependency-upgrade work item (appsec.analysis); findings: its compact scored findings; manifests: {path: text} read from the repository
    or pasted. Edits only the files that name the package (or, for a transitive package, the first manifest of the right ecosystem)."""
    if item.get("kind") != "dependency-upgrade":
        raise ValueError("That work item is not a dependency upgrade")
    if not item.get("target_version"):
        raise ValueError("No fixed version is known for this package, so there is nothing safe to upgrade to. Watch the advisory or replace the package.")
    pol = pol_mod.for_repo(policy or pol_mod.load(), app.get("repo"))
    eco = item.get("ecosystem")
    cands = {p: t for p, t in manifests.items() if upgrade.kind_of(p) and (not eco or upgrade.ecosystem_of_path(p) == eco)}
    if not cands:
        raise ValueError(f"None of the files supplied is a {eco or 'supported'} dependency file ({', '.join(upgrade.HANDLERS)})")
    key = f"dep:{(item['package'] or '').lower()}:{item['target_version']}"
    _duplicate(app["name"], key, engine)
    pkg = item["package"]
    declaring = [p for p, t in cands.items() if upgrade.declares(p, t, pkg, group)]
    todo = declaring or [sorted(cands)[0]]
    files, errors = [], []
    cves = item.get("cves") or []
    for path in todo:
        try:
            r = upgrade.patch_manifest(path, cands[path], pkg, item["target_version"], group, reason=", ".join(cves[:3]))
            files.append({"path": path, "new_content": r["new_text"], "diff": r["diff"], "changes": r["changes"], "stats": diffing.stats(r["diff"])})
        except upgrade.PatchError as exc:
            errors.append(f"{path}: {exc}")
    if not files:
        raise ValueError("; ".join(errors))
    pol_mod.check_files(pol, [{"path": f["path"], "content": f["new_content"]} for f in files])
    locks = sorted(set(lockfiles or []))
    lock_note = None
    if locks:
        lock_note = f"This repository has {', '.join(locks)}. Quanta cannot regenerate it (it never runs a package manager), so refresh it on this branch before merging."
    else:
        lock_note = "If this project uses a lock file, refresh it on this branch before merging: Quanta edits the manifest only and never runs a package manager."
    summary = {"key": key, "package": pkg, "ecosystem": eco, "from": item.get("current_version"), "to": item["target_version"], "crosses_major": item.get("crosses_major"),
               "direct": item.get("direct"), "pulled_in_by": item.get("pulled_in_by") or [], "cves": cves, "resolves": item.get("resolves"), "tier": item.get("tier"), "score": item.get("score"),
               "lockfiles": locks, "lockfile_note": lock_note, "notes": errors, "manifests": [f["path"] for f in files], "validation": validation or {},
               "commit_body": f"Upgrade {pkg} from {item.get('current_version') or 'its current version'} to {item['target_version']} to fix " + (", ".join(cves) if cves else "known vulnerabilities") + ".",
               "ctx": {"findings": findings, "reach": reach, "app": {k: app.get(k) for k in ("environment", "business_criticality", "owner", "team")}}}
    title = f"Upgrade {pkg} to {item['target_version']}"
    return _insert(app["name"], "dependency-upgrade", item["finding_ids"], title, summary, files, app, actor, pol, engine)


def create_code(app, finding, compact, reach, originals, patches, explanation, validation, actor, policy=None, engine=None):
    """finding: the finding; compact: its scored view; originals: {path: current text}; patches: {path: unified diff} proposed by a person or by the
    code-fix subagent. Each diff is applied strictly to the current text; one that does not fit is refused."""
    pol = pol_mod.for_repo(policy or pol_mod.load(), app.get("repo"))
    key = f"code:{finding['id']}"
    _duplicate(app["name"], key, engine)
    loc = finding.get("location")
    finding_file = loc if isinstance(loc, str) else (loc or {}).get("file")
    files = []
    for path, diff in patches.items():
        if path not in originals:
            raise ValueError(f"{path}: the current content of the file was not supplied")
        try:
            new = diffing.apply(originals[path], diff)
        except diffing.PatchRefused as exc:
            raise ValueError(f"{path}: {exc}") from exc
        real = diffing.unified(originals[path], new, path)
        files.append({"path": path, "new_content": new, "diff": real, "changes": [], "stats": diffing.stats(real)})
    pol_mod.check_files(pol, [{"path": f["path"], "content": f["new_content"]} for f in files])
    try:
        pol_mod.check_code_scope(pol, files, finding_file)
    except pol_mod.PolicyError as exc:
        raise ValueError(str(exc)) from exc
    head = f"Fix {finding.get('title')}" + (f" in {finding_file}" if finding_file else "")
    summary = {"key": key, "headline": head, "explanation": (explanation or "")[:2000], "validation": validation or {}, "finding_file": finding_file, "tier": compact.get("tier"), "score": compact.get("score"),
               "commit_body": (explanation or head)[:600], "ctx": {"findings": [compact], "reach": reach, "app": {k: app.get(k) for k in ("environment", "business_criticality", "owner", "team")}}}
    return _insert(app["name"], "code-fix", [finding["id"]], head, summary, files, app, actor, pol, engine)


# ---------------------------------------------------------------- review
def approve(proposal_id, actor, engine=None, policy=None):
    p = get(proposal_id, engine)
    if not p:
        raise KeyError("No such proposal")
    if p["status"] != "draft":
        raise ValueError(f"Only a draft can be approved (this one is {p['status']})")
    pol = pol_mod.for_repo(policy or pol_mod.load(), p["repo"])
    if pol["approval"]["require_distinct_approver"] and actor == p["created_by"]:
        raise ValueError("The policy requires a different administrator to approve a proposal than the one who created it")
    _update(proposal_id, engine, status="approved", approved_by=actor, approved_at=_now())
    _refresh_text(get(proposal_id, engine), pol, engine)
    return get(proposal_id, engine)


def discard(proposal_id, actor, reason="", engine=None):
    p = get(proposal_id, engine)
    if not p:
        raise KeyError("No such proposal")
    if p["status"] not in ("draft", "approved", "failed"):
        raise ValueError("A pull request already exists for this proposal: close it on the Git host (Quanta will see it on the next sync)")
    _update(proposal_id, engine, status="discarded", closed_at=_now(), notes=(reason or "")[:500])
    return get(proposal_id, engine)


# ---------------------------------------------------------------- opening the pull request
def plan(p, pol):
    """What opening this proposal would do, step by step. Used for the dry run and shown again with the result."""
    base = p["base_branch"]
    draft = bool(pol["pull_request"]["draft"] or (pol["pull_request"].get("draft_when_lockfile_present") and p["summary"].get("lockfiles")))
    return {"provider": p["provider"], "repo": p["repo"], "base_branch": base, "branch": p["branch"], "draft": draft,
            "labels": pol["pull_request"].get("labels") or [], "reviewers": pol["pull_request"].get("reviewers") or [],
            "commit_message": prbody.commit_message(pol, p["kind"], p["summary"], p["finding_ids"], p.get("approved_by")), "pr_title": p["pr_title"], "pr_body": p["pr_body"],
            "files": [{"path": f["path"], **f["stats"]} for f in p["files"]],
            "steps": [f"Check the token can write to {p['repo']}", f"Create the branch {p['branch']} from {base or 'the default branch'}",
                      f"Commit {len(p['files'])} file(s) to {p['branch']} (never to {base or 'the default branch'})",
                      f"Open {'a draft ' if draft else 'a '}{'merge request' if p['provider'] == 'gitlab' else 'pull request'} from {p['branch']} into {base or 'the default branch'}",
                      "Stop. Quanta does not merge."]}


def open_pr(proposal_id, actor, confirm=False, connector=None, connection_name=None, findings=None, policy=None, engine=None):
    p = get(proposal_id, engine)
    if not p:
        raise KeyError("No such proposal")
    pol = pol_mod.for_repo(policy or pol_mod.load(), p["repo"])
    ok_states = ("approved", "failed") if pol["approval"]["require_before_open"] else ("draft", "approved", "failed")
    if p["status"] not in ok_states:
        raise ValueError(f"A proposal must be {' or '.join(ok_states)} to open a pull request (this one is {p['status']})")
    if not p["repo"] or not p["provider"]:
        raise ValueError("Set the repository and Git provider on the application first")
    attempt = 1 + int((p["summary"].get("attempts") or 0))
    branch = p["branch"] if attempt == 1 else pol_mod.branch_name(pol, p["id"], p["kind"], p["summary"].get("package") or p["title"], attempt)
    p = {**p, "branch": branch}
    pol_mod.check_branch(pol, branch, base=p["base_branch"])
    pol_mod.check_files(pol, [{"path": f["path"], "content": f["new_content"]} for f in p["files"]])
    pl = plan(p, pol)
    if not confirm:
        return {"preview_only": True, "connection": connection_name, "plan": pl,
                "message": "Nothing has been sent. Send confirm: true to create the branch, commit these files to it and open the pull request."}
    if connector is None:
        raise ValueError(f"No {p['provider']} connection is configured for this application. Add one on the Connections page and select it on the application.")
    base = p["base_branch"]
    try:
        info = connector.test_connection(p["repo"])
        if not info.get("can_write"):
            raise ValueError("The stored token cannot write to this repository (it needs Contents and Pull requests write access)")
        base = base or info["default_branch"]
        pol_mod.check_branch(pol, branch, base=base, default=info["default_branch"])
        if connector.branch_sha(p["repo"], branch) is not None:
            raise ValueError(f"The branch {branch} already exists in {p['repo']}. Quanta will not write to an existing branch; discard this proposal or delete the branch.")
    except ValueError as exc:
        _update(proposal_id, engine, status="failed", last_error=str(exc)[:500])
        raise
    except Exception as exc:  # noqa: BLE001 - the host's refusal is recorded on the proposal, not lost
        _update(proposal_id, engine, status="failed", last_error=str(exc)[:500])
        raise ValueError(f"The Git host refused before anything was changed: {exc}") from exc
    created = False
    try:
        connector.create_branch(p["repo"], branch, base)
        created = True
        connector.commit_files(p["repo"], branch, pl["commit_message"], [{"path": f["path"], "content": f["new_content"]} for f in p["files"]])
        pr = connector.open_change_request(p["repo"], branch, base, p["pr_title"], p["pr_body"], draft=pl["draft"], labels=pl["labels"] or None, reviewers=pl["reviewers"] or None)
    except Exception as exc:  # noqa: BLE001
        left = f" The branch {branch} was created and left in place; the next attempt uses a new name." if created else ""
        summary = {**p["summary"], "attempts": attempt}
        _update(proposal_id, engine, status="failed", last_error=(str(exc)[:400] + left)[:500], summary_json=json.dumps(summary))
        raise ValueError(f"The Git host stopped at a step: {str(exc)[:300]}.{left}") from exc
    summary = {**p["summary"], "attempts": attempt, "draft": pl["draft"], "warnings": pr.get("warnings") or []}
    _update(proposal_id, engine, status="pr-opened", branch=branch, base_branch=base, pr_number=pr["number"], pr_url=pr["url"], pr_state="open", opened_by=actor, opened_at=_now(),
            last_error=None, summary_json=json.dumps(summary))
    _link_queue(p, pr["url"], actor, findings, engine)
    return {"preview_only": False, "proposal": public(get(proposal_id, engine)), "pr_url": pr["url"], "warnings": pr.get("warnings") or []}


def _link_queue(p, url, actor, findings, engine, state="pr-opened"):
    """Keep the code fix queue in step: queue the findings if they are not there yet, then record the state and link. Never raises."""
    try:
        if findings is not None:
            dso_factory.queue(p["finding_ids"], findings, actor, engine)
        for fid in p["finding_ids"]:
            try:
                dso_factory.update_item(fid, {"state": state, **({"pr_url": url} if url else {})}, engine)
            except KeyError:
                pass
    except Exception:  # noqa: BLE001 - the queue is a convenience view; the proposal is the record
        pass


# ---------------------------------------------------------------- following the pull request
def apply_remote(p, remote, engine=None, actor="sync"):
    """Fold the host's view of the pull request into the proposal. `remote`: {state, merged_at, closed_at, review_state, checks_state, url}."""
    vals = {"pr_state": remote["state"], "review_state": remote.get("review_state"), "checks_state": remote.get("checks_state"), "last_synced_at": _now(), "last_error": None}
    if remote["state"] == "merged":
        vals.update(status="merged", merged_at=remote.get("merged_at") or p.get("merged_at") or _now(), closed_at=None)
    elif remote["state"] == "closed":
        vals.update(status="closed", closed_at=remote.get("closed_at") or _now())
    else:
        vals["status"] = "in-review" if remote.get("review_state") not in (None, "none") else "pr-opened"
    _update(p["id"], engine, **vals)
    if remote["state"] in ("merged", "closed"):
        _link_queue(p, None, actor, None, engine, state="merged" if remote["state"] == "merged" else "in-progress")
    return get(p["id"], engine)


def sync(connector_for, engine=None, only=None):
    """Poll the host for every proposal with an open pull request. connector_for(proposal) -> connector or None. Returns a per-proposal report;
    one failure never stops the rest."""
    report = []
    for p in list_proposals(engine=engine):
        if p["status"] not in ("pr-opened", "in-review") or not p["pr_number"] or (only and p["id"] not in only):
            continue
        conn = connector_for(p)
        if conn is None:
            report.append({"id": p["id"], "ok": False, "error": "No connection is configured for this application"})
            continue
        try:
            remote = conn.get_change_request(p["repo"], p["pr_number"])
            q = apply_remote(p, remote, engine)
            report.append({"id": p["id"], "ok": True, "status": q["status"], "review_state": q["review_state"], "checks_state": q["checks_state"]})
        except Exception as exc:  # noqa: BLE001
            _update(p["id"], engine, last_error=str(exc)[:300], last_synced_at=_now())
            report.append({"id": p["id"], "ok": False, "error": str(exc)[:200]})
    return report


def record_external(ref, state, merged_at, actor, engine=None):
    """An inbound call from the Git host (a webhook) or a CI job. `ref` is a proposal number or the pull request URL; `state` is open, merged or closed."""
    if state not in ("open", "merged", "closed"):
        raise ValueError("state must be open, merged or closed")
    p = next((x for x in list_proposals(engine=engine) if str(x["id"]) == str(ref) or (x["pr_url"] and x["pr_url"] == ref)), None)
    if not p:
        raise KeyError("No proposal matches that reference")
    if p["status"] in ("draft", "approved", "discarded"):
        raise ValueError("That proposal has no pull request yet")
    return apply_remote(p, {"state": state, "merged_at": merged_at, "closed_at": None, "review_state": p["review_state"], "checks_state": p["checks_state"]}, engine, actor)


# ---------------------------------------------------------------- closing the loop
def _date(v):
    try:
        return datetime.date.fromisoformat(str(v)[:10]) if v else None
    except ValueError:
        return None


def verify_one(p, by_id):
    """Per finding and overall, after a merge. Same rule as the infrastructure loop: gone from the latest scan = resolved; seen on or after the merge date =
    still present; otherwise nothing can be concluded yet."""
    if p["status"] != "merged":
        return {"state": "not-merged", "findings": {}, "detail": "Verification starts when the pull request is merged."}
    merged = _date(p["merged_at"])
    per = {}
    for fid in p["finding_ids"]:
        f = by_id.get(fid)
        if f is None or f.get("status") in ("resolved", "closed"):
            per[fid] = "resolved"
        elif merged and _date(f.get("last_seen")) and _date(f.get("last_seen")) >= merged:
            per[fid] = "still-present"
        else:
            per[fid] = "awaiting-rescan"
    vals = set(per.values())
    state = "verified" if vals == {"resolved"} else ("still-present" if "still-present" in vals else "awaiting-rescan")
    detail = {"verified": "No longer reported in the latest scan. Evidence the fix held; also consistent with the application leaving scan scope.",
              "still-present": "Still reported by a scan run after the merge. The fix did not remove the finding: check the merged change and the scanner's view.",
              "awaiting-rescan": "No scan has run since the merge, or only some findings have cleared."}[state]
    return {"state": state, "findings": per, "detail": detail}


def verify_all(findings, engine=None):
    by_id = {f["id"]: f for f in findings}
    out = []
    for p in list_proposals(engine=engine):
        if p["status"] != "merged":
            continue
        v = verify_one(p, by_id)
        if v["state"] != p["verified_state"]:
            _update(p["id"], engine, verified_state=v["state"], verified_at=_now() if v["state"] == "verified" else None)
        out.append({"id": p["id"], **v})
    return out
