"""
The queue worker: pulls jobs and runs their handlers. Run any number of copies:

    python -m remediation.coordination.worker          (or: python cli/quanta_admin.py worker)

In Kubernetes this is the `worker` Deployment; scale it independently of the web tier. Without
one, the web process runs the same loop in a background thread (QUANTA_EMBEDDED_WORKER, on by
default), so a single container still works.

A handler is a function `fn(payload) -> result (JSON-serialisable)`. Raising marks the attempt
failed and retries with backoff. While a handler runs, a heartbeat thread keeps extending the
job's visibility timeout, so a long sync is not handed to another worker, and a worker that dies
is noticed when the heartbeat stops.
"""
import os
import signal
import threading
import time

from remediation.coordination import jobs

KIND_CONNECTION_SYNC = "connection.sync"
VISIBILITY = int(os.environ.get("QUANTA_JOB_VISIBILITY_SECONDS", "300"))
POLL = float(os.environ.get("QUANTA_WORKER_POLL_SECONDS", "2"))


def handle_connection_sync(payload):
    from remediation.connections import sync
    result = sync.run(int(payload["connection_id"]), payload.get("actor") or "scheduler")
    # "already running" is not a failure: another worker owns it and will record the outcome
    return {"ok": bool(result.get("ok")), "message": result.get("message"), "count": result.get("count")}


HANDLERS = {KIND_CONNECTION_SYNC: handle_connection_sync}


def new_worker_id():
    return f"{os.environ.get('HOSTNAME', 'worker')}-{os.getpid()}-{int(time.time())}"


def _heartbeat_loop(job_id, worker_id, stop, visibility, engine):
    while not stop.wait(max(visibility / 3, 1)):
        try:
            if not jobs.heartbeat(job_id, worker_id, visibility, engine):
                return
        except Exception:  # noqa: BLE001 - a missed heartbeat is retried on the next beat
            pass


def run_one(worker_id, handlers=None, visibility=VISIBILITY, engine=None, now=None):
    """Claims and runs a single job. Returns the finished job's id and outcome, or None if the
    queue was empty."""
    handlers = handlers or HANDLERS
    job = jobs.claim(worker_id, kinds=list(handlers), visibility=visibility, engine=engine, now=now)
    if not job:
        return None
    stop = threading.Event()
    beat = threading.Thread(target=_heartbeat_loop, args=(job["id"], worker_id, stop, visibility, engine), daemon=True)
    beat.start()
    try:
        result = handlers[job["kind"]](job["payload"])
        jobs.complete(job["id"], worker_id, result, engine)
        return {"id": job["id"], "kind": job["kind"], "outcome": "done"}
    except Exception as exc:  # noqa: BLE001 - one bad job must not stop the worker
        status = jobs.fail(job["id"], worker_id, f"{type(exc).__name__}: {exc}", engine)
        return {"id": job["id"], "kind": job["kind"], "outcome": status or "failed"}
    finally:
        stop.set()


def run_forever(stop_event=None, worker_id=None, handlers=None, poll=POLL):
    stop_event = stop_event or threading.Event()
    worker_id = worker_id or new_worker_id()
    while not stop_event.is_set():
        try:
            ran = run_one(worker_id, handlers)
        except Exception:  # noqa: BLE001 - database blip: back off and carry on
            ran = None
            stop_event.wait(poll * 2)
        if ran is None:
            stop_event.wait(poll)


def main():
    from remediation.utils import secret_files
    secret_files.load_file_env()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())  # finish the current job, then exit: a rolling update loses nothing
    print(f"Quanta worker {new_worker_id()} started", flush=True)
    run_forever(stop)
    print("Quanta worker stopped", flush=True)


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
