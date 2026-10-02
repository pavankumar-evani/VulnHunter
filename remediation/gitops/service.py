"""
The glue between applications, stored Git connections and the proposal workflow: find the right connection, build its connector, and read the files a
proposal needs. Reading is the only thing done here; writing a repository happens in one place (proposals.open_pr), after confirmation.
"""
import posixpath

from remediation.connections import registry, store as conn_store
from remediation.gitops import upgrade


def find_connection(provider, connection_id=None, engine=None):
    """The stored connection to use: the one asked for (it must be of the provider's type), else the first enabled one of that type. (public, values) or (None, None)."""
    if connection_id:
        public, values = conn_store.get_values(int(connection_id), engine)
        return (public, values) if public and public["type"] == provider else (None, None)
    for c in conn_store.list_connections(engine):
        if c["type"] == provider and c["enabled"]:
            return conn_store.get_values(c["id"], engine)
    return None, None


def connector(provider, connection_id=None, engine=None):
    """(connector, public connection) or (None, None). The SSRF guard runs again on the stored base URL at the moment of use."""
    if provider not in ("github", "gitlab"):
        return None, None
    public, values = find_connection(provider, connection_id, engine)
    if not public:
        return None, None
    registry.split_values(provider, values)
    return registry.SPECS[provider]["build"](values), public


def connector_for_application(app, engine=None):
    return connector(app.get("repo_provider"), app.get("connection_id"), engine)


def connector_for_proposal(p, engine=None, cache=None):
    cache = cache if cache is not None else {}
    key = (p.get("provider"), p.get("connection_id"))
    if key not in cache:
        cache[key] = connector(p.get("provider"), p.get("connection_id"), engine)[0]
    return cache[key]


def base_branch(conn, app):
    return app.get("default_branch") or conn.test_connection(app["repo"])["default_branch"]


def fetch_manifests(conn, app, ecosystem=None):
    """Read the application's dependency files from its repository. Returns ({path: text}, lockfiles found, [problems]). Needs repo and manifest paths on the application."""
    if not app.get("repo") or not app.get("manifest_paths"):
        raise ValueError("Set the repository and the dependency file paths on the application first")
    ref = base_branch(conn, app)
    texts, locks, problems = {}, [], []
    for path in app["manifest_paths"]:
        eco = upgrade.ecosystem_of_path(path)
        if ecosystem and eco != ecosystem:
            continue
        try:
            got = conn.get_file(app["repo"], path, ref)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path}: {str(exc)[:150]}")
            continue
        if got is None:
            problems.append(f"{path}: not found on {ref}")
            continue
        texts[path] = got["content"]
        for lock in upgrade.LOCKFILES.get(eco, []):
            try:
                if conn.get_file(app["repo"], posixpath.join(posixpath.dirname(path), lock), ref) is not None:
                    locks.append(lock)
            except Exception:  # noqa: BLE001 - a lock file we cannot confirm is simply not reported
                pass
    return texts, sorted(set(locks)), problems


def fetch_files(conn, app, paths):
    """{path: text} for code-fix originals, or ValueError naming the file that could not be read."""
    ref = base_branch(conn, app)
    out = {}
    for path in paths:
        got = conn.get_file(app["repo"], path, ref)
        if got is None:
            raise ValueError(f"{path}: not found on {ref}")
        out[path] = got["content"]
    return out
