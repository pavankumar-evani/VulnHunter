"""
CLI entry point for the /vulnhunt --verify pipeline step to log a verification outcome
to the real activity log (remediation/audit/activity_log.py). Called via Bash from
vulnhunt.md's orchestrator - the same "markdown-driven pipeline step shells out to a
small Python script" pattern threat-intel-enricher.md already uses for
remediation/enrichment/kev_epss.py. vuln-verifier itself has no Write/DB access; it only
returns a JSON verdict in chat, and the orchestrator (which does have Bash) is the one
that persists it, the same separation-of-concerns every other subagent in this repo
already follows.
"""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log  # noqa: E402

VALID_STATUSES = ("resolved", "still-present", "inconclusive")


def record_verification(finding_id, branch, status, detail="", actor="vulnhunt-verify", engine=None):
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}, got {status!r}")
    return activity_log.record_activity(
        actor=actor,
        action="vulnhunt.verify",
        target=finding_id,
        details={"branch": branch, "status": status, "detail": detail},
        engine=engine,
    )


def main():
    parser = argparse.ArgumentParser(description="Log a /vulnhunt --verify outcome to the real activity log.")
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--status", required=True, choices=VALID_STATUSES)
    parser.add_argument("--detail", default="")
    parser.add_argument("--actor", default="vulnhunt-verify")
    args = parser.parse_args()

    record = record_verification(args.finding_id, args.branch, args.status, args.detail, args.actor)
    print(json.dumps({"logged": True, "activity_id": record["id"]}))


if __name__ == "__main__":
    main()
