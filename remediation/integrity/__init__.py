"""Integrity and self-heal: does the installed code match the release, are the stores consistent, and what can be repaired safely.

manifest.py  SHA-256 manifest of the application's own code and shipped config, built at release time and verified on demand.
checks.py    store consistency checks (schema, orphans, findings file, locks, snapshots, database, disk, clock, keys, licence).
heal.py      the few repairs that are safe to do automatically (dry run by default, one named action each, all audited).
service.py   glue used by the API, the CLI and the scheduler: run everything, summarise, alert once per distinct problem.
"""
