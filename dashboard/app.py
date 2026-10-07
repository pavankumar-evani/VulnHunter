"""
Quanta Dashboard - a FastAPI JSON API plus a hand-rolled vanilla-JS single-page
frontend (static/index.html + static/js/*.js) reading the real generated artifacts
from both pipelines. No Node/npm/build step - see dashboard/README.md for why, and
what a production version would add on top of this.

Run with: python dashboard/app.py
Then open https://127.0.0.1:5050 (first run auto-generates a local HTTPS cert - your
browser will show a one-time trust warning for it; see dashboard/README.md's "HTTPS"
section for why and how to get past it, or QUANTA_DISABLE_TLS=true to disable).
"""
import asyncio
import datetime
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import uvicorn
import yaml
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from sqlalchemy import func, select
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from typing import Optional

from pydantic import BaseModel, Field, field_validator

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_assist  # noqa: E402
import appsec_api  # noqa: E402
import investigation_api  # noqa: E402
import mcp_api  # noqa: E402
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
import reports  # noqa: E402
import quanta as cli  # noqa: E402
from auth import ad_directory, login_audit, oidc, rbac, sessions  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation import graphs as module_graphs  # noqa: E402
from remediation.ontology import estate as ontology_estate  # noqa: E402
from remediation.ontology import ontology as ontology_vocab  # noqa: E402
from remediation.ontology import provenance as ontology_provenance  # noqa: E402
from remediation.ontology import query as ontology_query  # noqa: E402
from remediation.ontology import validate as ontology_validate  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.integrity import heal as integrity_heal, service as integrity_service  # noqa: E402
from remediation.assignments import analytics as ownership_analytics  # noqa: E402
from remediation.assignments import store as assignments_store  # noqa: E402
import observability  # noqa: E402
import events as live_events  # noqa: E402
from remediation.apikeys import store as apikey_store  # noqa: E402
from remediation.connections import crypto as conn_crypto  # noqa: E402
from remediation.connections import links as conn_links  # noqa: E402
from remediation.ingest import api_findings, coverage as coverage_ingest, merge as findings_merge, sarif as sarif_ingest, scanner_csv  # noqa: E402
from remediation.connections import registry as conn_registry  # noqa: E402
from remediation.connections import store as conn_store  # noqa: E402
from remediation.connections import sync as conn_sync  # noqa: E402
from remediation.coordination import jobs as job_queue  # noqa: E402
from remediation.coordination import worker as job_worker  # noqa: E402
from remediation.coordination.leader import Leader  # noqa: E402
from remediation.guidance import engine as guidance_engine  # noqa: E402
from remediation.controls import store as controls_store  # noqa: E402
from remediation.connectors import reputation_connector as hunt_rep, siem_search_connector as sec_search  # noqa: E402
from remediation.hunting import intelwatch, search_base, translate as hunt_translate  # noqa: E402
from remediation.connectors import report_feed_connector  # noqa: E402
from remediation.connectors.webhook_connector import ACTIONS as webhook_actions  # noqa: E402
from remediation.soar import engine as soar_engine, playbooks as soar_playbooks  # noqa: E402
from remediation.risk import quant as quant_risk, store as risk_store  # noqa: E402
from remediation.aisec import rules as aisec_rules, rules_mcp as aisec_rules_mcp, store as aisec_store  # noqa: E402
from remediation.apisec import cicd as api_cicd, classify as api_classify, config as api_config, generate as api_generate, identity as api_identity, logs as api_logs  # noqa: E402
from remediation.apisec import metrics as api_metrics, openapi as api_openapi, policies as api_policies, rollout as api_rollout, rules as api_rules, store as api_store, waf as api_waf  # noqa: E402
from remediation import capabilities as capabilities_mod  # noqa: E402
from remediation.insights import ask as insights_ask, service as insights_service  # noqa: E402
from remediation.decisions import calibration as decision_calibration, registry as decision_registry, schema as decision_schema, service as decision_service  # noqa: E402
from remediation.licensing import license as licensing  # noqa: E402
from remediation.iam import model as iam_model, store as iam_store  # noqa: E402
from remediation.firewall import analysis as fw_analysis, model as fw_model, store as fw_store  # noqa: E402
from remediation.enrichment import network_reachability as network_reach  # noqa: E402
from remediation.devsecops import controls as dso_controls, factory as dso_factory, gates as dso_gates  # noqa: E402
from remediation.appsec import store as appsec_store  # noqa: E402
from remediation.gitops import service as gitops_service  # noqa: E402
from remediation.enrichment import sbom as sbom_mod, zero_day_watch as zero_day  # noqa: E402
from remediation.connectors import cvd_feed_connector  # noqa: E402
from remediation.cvd import store as cvd_store  # noqa: E402
from remediation.hunting import detection as hunt_detection, generate as hunt_generate, intel as hunt_intel, ocsf as hunt_ocsf, service as hunt_service  # noqa: E402
from remediation.hunting import soc as hunt_soc, store as hunt_store, triage as hunt_triage, verdict as hunt_verdict  # noqa: E402
from remediation.hunting import ttp as hunt_ttp  # noqa: E402
from remediation.hunting.engine import service as hunt_engine  # noqa: E402
from remediation.connectors import darkweb_connector as dw_connector  # noqa: E402
from remediation.darkweb import watch as dw_watch  # noqa: E402
from remediation.asm import findings as asm_findings, parsers as asm_parsers, store as asm_store, summary as asm_summary  # noqa: E402
from remediation.hunting import usecase_store as hunt_usecase_store, usecases as hunt_usecases  # noqa: E402
from remediation.soar import ai_draft as soar_ai_draft, recommend as soar_recommend  # noqa: E402
from remediation.soc import cases as soc_cases, loganalysis as soc_loganalysis, metrics as soc_metrics  # noqa: E402
from remediation.soc.incidents import roster as incident_roster, service as incident_service, store as incident_store, stream as incident_stream  # noqa: E402
from remediation.grc import catalog as grc_catalog, evidence as grc_evidence, policies as grc_policies, report as grc_report, risks as grc_risks  # noqa: E402
from remediation.threatmodel import engine as tm_engine, rules as tm_rules, seed as tm_seed, store as tm_store  # noqa: E402
from remediation.aiusage import analytics as ai_analytics, discovery as ai_discovery, otlp as ai_otlp, store as ai_store  # noqa: E402
from remediation.enrichment import client_controls  # noqa: E402
from remediation.utils import file_sync, secret_files  # noqa: E402
from remediation.support import analytics as support_analytics  # noqa: E402
from remediation.support import escalation as support_escalation  # noqa: E402
from remediation.support import routing as support_routing  # noqa: E402
from remediation.support import sla as support_sla  # noqa: E402
from remediation.support import store as support_store  # noqa: E402
from remediation.validation import playbook_lint  # noqa: E402
from remediation.verification import closed_loop  # noqa: E402
from remediation.audit import ai_usage_log  # noqa: E402
from remediation.config import ai_governance  # noqa: E402
from remediation.connectors.active_directory_connector import ActiveDirectoryConnector  # noqa: E402
from remediation.connectors.axonius_connector import AxoniusConnector  # noqa: E402
from remediation.connectors.cortex_xsiam_connector import CortexXsiamConnector  # noqa: E402
from remediation.connectors.generic_connector import (  # noqa: E402
    normalize_generic_finding, validate_generic_payload,
)
from remediation.connectors.infoblox_connector import InfobloxConnector  # noqa: E402
from remediation.connectors import live_data_store  # noqa: E402
from remediation.connectors.jira_connector import (  # noqa: E402
    DEFAULT_ISSUE_TYPE as JIRA_DEFAULT_ISSUE_TYPE, JiraConnector, build_issue_body,
)
from remediation.connectors.openvas_connector import OpenVasConnector  # noqa: E402
from remediation.connectors.prismacloud_connector import PrismaCloudConnector  # noqa: E402
from remediation.connectors.qualys_connector import QualysConnector  # noqa: E402
from remediation.connectors.servicenow_connector import (  # noqa: E402
    ServiceNowConnector, build_incident_body,
)
from remediation.connectors.splunk_connector import (  # noqa: E402
    DEFAULT_SOURCETYPE as SPLUNK_DEFAULT_SOURCETYPE, SplunkConnector, build_hec_event,
)
from remediation.connectors.tenable_connector import TenableConnector  # noqa: E402
from remediation.connectors.url_safety import UnsafeTargetError  # noqa: E402
from remediation.connectors import url_safety  # noqa: E402
from remediation.enrichment.ai_vuln_taxonomy import (  # noqa: E402
    AI_VULNERABILITIES, build_ai_atlas_heatmap, tag_findings as tag_ai_vulnerabilities,
)
from remediation.enrichment.attack_mapping import build_attack_heatmap  # noqa: E402
from remediation.enrichment import blast_radius  # noqa: E402
from remediation.enrichment import exploit_criteria  # noqa: E402
from remediation.enrichment import exposure_score  # noqa: E402
from remediation.enrichment import kev_epss  # noqa: E402
from remediation.enrichment import quantum_readiness  # noqa: E402
from remediation.enrichment import risk_scoring  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.inventory import asset_inventory, cmdb_import, pattern_recognition  # noqa: E402
from remediation.notifications import alert_checker, email_sender, report_scheduler  # noqa: E402
from remediation.remediation_approvals import store as remediation_approvals_store  # noqa: E402
from remediation.search import query_engine  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Quanta Dashboard API", version="1.0.0")

# Real process-uptime clock (monotonic, so a system clock change can't skew it) and a
# handle onto the background scheduler task, both purely for honest self-reporting in
# /api/status - neither is load-bearing for the app's own behavior.
_PROCESS_STARTED_AT = time.monotonic()
_scheduler_task: asyncio.Task | None = None


@app.middleware("http")
async def _no_cache_static_assets(request: Request, call_next):
    """Forces every /static/* response to revalidate (a real network round-trip
    checking If-None-Match against the file's current ETag) rather than let the
    browser silently reuse a cached copy for however long its own heuristic freshness
    lifetime decides - StaticFiles sends an ETag/Last-Modified but no Cache-Control at
    all by default, and this dev server has repeatedly hit real, hard-to-diagnose bugs
    from a browser serving stale JS after an edit. `no-cache` (not `no-store`) keeps
    the fast path: an unchanged file still gets a cheap 304, only a genuinely changed
    one pays for a real re-fetch."""
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# Real in-process sliding-window limiters (see dashboard/rate_limit.py) - a global,
# generous one for every /api/* route, and a stricter one specifically for
# POST /api/ingest/generic, which is both unauthenticated and (before this) completely
# unthrottled - the single most-exposed route in this app to a caller hammering it.
# Module-level singletons (not per-request) so counts actually accumulate across calls.
_GLOBAL_API_RATE_LIMITER = rate_limit.RateLimiter(
    max_requests=int(os.environ.get("QUANTA_RATE_LIMIT_MAX", "300")),
    window_seconds=int(os.environ.get("QUANTA_RATE_LIMIT_WINDOW_SECONDS", "60")),
)
_GENERIC_INGEST_RATE_LIMITER = rate_limit.RateLimiter(
    max_requests=int(os.environ.get("QUANTA_INGEST_RATE_LIMIT_MAX", "20")),
    window_seconds=int(os.environ.get("QUANTA_INGEST_RATE_LIMIT_WINDOW_SECONDS", "60")),
)


def _client_ip(request: Request):
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def _rate_limit_api(request: Request, call_next):
    """Real per-IP request throttling on every /api/* route - see
    dashboard/rate_limit.py's own module docstring for the single-node scope this is
    honestly limited to. POST /api/ingest/generic gets its own, stricter limiter on
    top of the global one (checked first, since it's the tighter constraint) since
    it's both unauthenticated and, unlike every other mutation route in this app,
    callable by a machine-to-machine webhook client with no session to revoke."""
    if request.url.path.startswith("/api/"):
        ip = _client_ip(request)
        if request.url.path == "/api/ingest/generic" and request.method == "POST":
            if not _GENERIC_INGEST_RATE_LIMITER.allow(ip):
                retry_after = _GENERIC_INGEST_RATE_LIMITER.retry_after_seconds(ip)
                return JSONResponse(
                    {"detail": "Rate limit exceeded for this endpoint. Try again later."},
                    status_code=429, headers={"Retry-After": str(retry_after)},
                )
        if not _GLOBAL_API_RATE_LIMITER.allow(ip):
            retry_after = _GLOBAL_API_RATE_LIMITER.retry_after_seconds(ip)
            return JSONResponse(
                {"detail": "Rate limit exceeded. Try again later."},
                status_code=429, headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


def _csp_enabled():
    # Same read-fresh-from-env convention as _require_login_for_reads_enabled() below,
    # for the same reason (tests toggle it with patch.dict(os.environ, ...)).
    # Explicit QUANTA_ENABLE_CSP wins either way; with nothing set, production turns it on.
    raw = os.environ.get("QUANTA_ENABLE_CSP", "").strip().lower()
    if raw in ("0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    return rbac.production_enabled()


def _cookie_secure(request):
    # Mark the session cookie Secure whenever the browser reached us over HTTPS (directly or via a proxy that says so).
    # Not forced on plain HTTP, where a Secure cookie would never be sent back and nobody could sign in locally.
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").split(",")[0].strip().lower()
    return proto == "https"


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Standard OWASP Secure Headers on every response. The first five are
    unconditional and cannot break this app - they only remove capabilities a same-
    origin, no-iframe, no-third-party-embed SPA never uses (clickjacking framing,
    MIME-sniffing, leaking the full referrer URL to other origins, camera/mic/geo
    access), plus Strict-Transport-Security, which browsers only ever honor on a
    response actually received over HTTPS in the first place (RFC 6797) - sending it
    unconditionally is inert, not risky, on this app's own default plain-HTTP dev
    server (`python dashboard/app.py`), and becomes real protection the moment a real
    deployment puts this behind TLS (see dashboard/README.md's "HTTPS" section for the
    recommended reverse-proxy setup) without needing a second flag to turn it on.
    Content-Security-Policy is opt-in (QUANTA_ENABLE_CSP=true, same off-by-default
    convention as QUANTA_REQUIRE_LOGIN_FOR_READS just below) rather than
    unconditional: this codebase's own inline `style="..."` attributes (see
    login.js/logout.js and others) need `style-src 'unsafe-inline'` to keep rendering,
    and a CSP is the one header here that fails closed - shipping it on by default and
    getting the allow-list wrong would break the whole UI, not just narrow an attack
    surface. script-src has no such exception: index.html loads exactly one
    same-origin module script and this codebase has zero inline
    onclick=/onload=-style handlers (checked directly), so 'self' with no
    'unsafe-inline' is safe today - if that ever changes, this policy must change with
    it."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if _csp_enabled():
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    return response


# Every /api/* route the login flow itself needs BEFORE a session exists - must stay
# reachable with no session even when QUANTA_REQUIRE_LOGIN_FOR_READS is on, or
# nobody could ever log in. Deliberately narrow: /api/auth/change-password and
# /api/directory/status are informational/mutation routes that already require (or
# can safely require) a real session, so they're not exempted here.
# Routes for machine callers. They are exempt from the browser-login gate ONLY because each one
# requires a valid API key with the right scope (require_api_key below); nothing else is exempt.
_API_KEY_PATH_PREFIXES = ("/api/ingest/", "/api/inbound/", "/api/export/", "/api/gate/")
_AUTH_FLOW_PATHS = frozenset({
    "/api/auth/login", "/api/auth/logout", "/api/auth/me",
    "/api/auth/oidc/config", "/api/auth/oidc/login", "/api/auth/oidc/callback",
})


def _require_login_for_reads_enabled():
    # Read fresh from the environment on every call (not cached at import time) so
    # tests can toggle this with patch.dict(os.environ, ...) without reloading the
    # whole app module.
    def flag(name):
        return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")
    # QUANTA_PRODUCTION makes the safe choice the default: every /api route needs a session
    # unless QUANTA_ALLOW_PUBLIC_READS is set on purpose.
    return flag("QUANTA_REQUIRE_LOGIN_FOR_READS") or (flag("QUANTA_PRODUCTION") and not flag("QUANTA_ALLOW_PUBLIC_READS"))


@app.middleware("http")
async def _require_login_for_api_reads(request: Request, call_next):
    """Opt-in, OFF by default - see dashboard/README.md's "What this is NOT (yet)":
    every GET/read API route is intentionally public in this MVP, by deliberate,
    disclosed choice (see KNOWLEDGE_TRANSFER.md §13.1). Set
    QUANTA_REQUIRE_LOGIN_FOR_READS=true for a real deployment that needs to close
    that gap: every /api/* route then requires a valid session except the login flow
    itself (_AUTH_FLOW_PATHS above). This is one middleware, not ~100 individual route
    changes - it closes both "anonymous reads see everything" AND "an anonymous
    request bypasses _scope_to_team()'s per-team filtering" in the same place, without
    touching a single existing route signature or the large existing test suite that
    calls these routes with no session (that suite exercises the OFF/default state,
    which is unaffected). See rbac.validate_production_requirements() - this flag also
    requires a real, stable QUANTA_SESSION_SECRET, checked at startup."""
    if (_require_login_for_reads_enabled() and request.url.path.startswith("/api/")
            and request.url.path not in _AUTH_FLOW_PATHS
            and not request.url.path.startswith(_API_KEY_PATH_PREFIXES)  # these routes check an API key themselves
            and rbac.get_current_user(request) is None):
        return JSONResponse({"detail": "Login required"}, status_code=401)
    return await call_next(request)


# In-process notification scheduler - checks scheduled reports (report_schedule_rules.yaml)
# and team alert subscriptions (alert_rules.yaml) on a timer, for as long as this server
# process stays running. Explicitly NOT a durable/guaranteed-delivery scheduler: a
# restart resets this timer (though never double-sends - see report_scheduler.py's own
# state-file dedup), and there is no retry-with-backoff beyond "try again next tick." For
# delivery that doesn't depend on server uptime, point a real external cron/Task
# Scheduler at POST /api/notification-settings/run-checks-now instead - same underlying
# check, callable on demand. Interval is configurable (mainly for tests) via
# NOTIFICATION_CHECK_INTERVAL_SECONDS; defaults to hourly, which is frequent enough for
# the shortest real cadence here (weekly) without hammering the SMTP relay.
_NOTIFICATION_CHECK_INTERVAL_SECONDS = int(os.environ.get("NOTIFICATION_CHECK_INTERVAL_SECONDS", "3600"))


# Every replica runs these loops but only the one holding the scheduler lease acts (see
# remediation/coordination/leader.py), so a report is sent once however many replicas run.
_leader = Leader()
_LEADER_CHECK_SECONDS = float(os.environ.get("QUANTA_LEADER_CHECK_SECONDS", "15"))
_leader_task = None
_worker_thread = None
_worker_stop = None


async def _leader_loop():
    while True:
        await asyncio.to_thread(_leader.check)
        await asyncio.to_thread(secret_files.reload_changed)   # a re-mounted key vault value, no restart
        await asyncio.to_thread(file_sync.sync_if_enabled)
        await asyncio.sleep(_LEADER_CHECK_SECONDS)


def _run_gitops_sync_if_due():
    """Hourly: follow open fix pull requests on their Git host and re-check merged ones against the latest scan. Off with QUANTA_GITOPS_SYNC=false. Does nothing
    (no connector is built) when no pull request is open."""
    if os.environ.get("QUANTA_GITOPS_SYNC", "true").strip().lower() in ("0", "false", "no"):
        return None
    if not gitops_service.has_open_pull_requests():
        return None
    return gitops_service.sync_and_verify(dashboard_data.load_live_queue())


def _run_hunt_suggestions_if_due():
    """Refreshes the proactive hunt suggestions at most every `refresh_minutes` (hunt_engine.yaml). Cheap and idempotent; never runs a search."""
    return hunt_engine.refresh_if_due(dashboard_data.load_live_queue())


def _run_integrity_checks_if_due():
    """Hourly: code baseline, store consistency and host checks. A new or changed set of problems is written once to the activity log and mailed to
    QUANTA_ALERT_EMAIL when SMTP is configured. Off with QUANTA_INTEGRITY_CHECKS=false. Never repairs anything: repairs are an admin action."""
    to = [a.strip() for a in os.environ.get("QUANTA_ALERT_EMAIL", "").split(",") if a.strip()]
    send = (lambda subject, body: email_sender.send_email(to, subject, body)) if to and email_sender.is_configured() else None
    return integrity_service.run_tick(send=send)


def _insights_inputs():
    """The unscoped scored queue (each finding annotated with its team) and the asset inventory: insights are computed once for everyone and
    filtered per person when read (admin-only ones hidden, team-limited ones shown only to that team)."""
    return _annotate_finding_teams(dashboard_data.load_live_queue()), [dict(a) for a in dashboard_data._load_scored_assets()[1]]


def _run_insights_if_due():
    """Hourly on the leader tick: runs the deterministic insight detectors. Off with QUANTA_INSIGHTS=false. Never raises, never calls a model."""
    return insights_service.run_tick(lambda: _insights_inputs()[0], lambda: _insights_inputs()[1])


def _run_incident_sweep():
    """Hourly (leader only): the incident sweep, so an owner who went off shift or a clock that is breaching is acted on without anyone opening the page."""
    return incident_service.sweep() if incident_store.enabled() else None


async def _notification_scheduler_loop():
    while True:
        await asyncio.sleep(_NOTIFICATION_CHECK_INTERVAL_SECONDS)
        if not _leader.is_leader:
            continue
        try:
            report_scheduler.check_and_send_due_reports(dashboard_data, reports, email_sender)
            alert_checker.check_and_send_alerts(dashboard_data, email_sender)
            _run_support_sla_escalations()
            _run_grc_evidence_if_due()
            _run_detection_assessment_if_due()
            _run_darkweb_if_due()
            _run_asm_stale_if_due()
            _run_cvd_if_due()
            _run_gitops_sync_if_due()
            _run_hunt_suggestions_if_due()
            _run_intel_watch_if_due()
            _run_integrity_checks_if_due()
            _run_insights_if_due()
            _run_incident_sweep()
        except Exception:  # noqa: BLE001 - a bad tick must never kill the whole loop
            import traceback
            traceback.print_exc()


DEMO_ACCOUNTS = ("admin@quanta.local", "analyst@quanta.local")
DEMO_PASSWORD = "ChangeMe123!"


def assert_no_demo_accounts():
    """In production, refuse to start while a seeded demo account still has its published
    password. Cheap, and it removes the most common way a demo becomes a breach."""
    if not rbac.production_enabled():
        return
    for email in DEMO_ACCOUNTS:
        if auth_users.verify_login(email, DEMO_PASSWORD):
            raise RuntimeError(
                f"QUANTA_PRODUCTION is set but the demo account {email} still has its published password. "
                "Delete it or change its password (python cli/quanta_admin.py reset-password), then restart.")


@app.on_event("startup")
async def _validate_production_requirements():
    from remediation.utils import environment as quanta_environment
    try:
        quanta_environment.name()
    except quanta_environment.EnvironmentError_ as exc:
        raise SystemExit(f"Quanta will not start: {exc}. Set QUANTA_ENV to dev, test or prod (or unset it).") from exc
    rbac.validate_production_requirements()
    observability.configure_logging()
    from remediation.utils import migrations
    migrations.apply(db_module.get_engine())
    assert_no_demo_accounts()


@app.middleware("http")
async def _file_sync_middleware(request: Request, call_next):
    """QUANTA_FILES_BACKEND=db: bring this replica's working files up to date before it serves a
    request and publish anything a state-changing request wrote (see remediation/utils/file_sync.py).
    A no-op, one environment lookup, when the backend is the default `file`."""
    if not file_sync.enabled() or request.url.path.startswith("/static/") or request.url.path in ("/healthz", "/readyz"):
        return await call_next(request)
    await asyncio.to_thread(file_sync.sync_if_enabled)
    response = await call_next(request)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        await asyncio.to_thread(file_sync.sync_if_enabled, True)
    return response


@app.middleware("http")
async def _observability_middleware(request: Request, call_next):
    return await observability.request_logging(request, call_next)


_CONNECTION_CHECK_SECONDS = int(os.environ.get("QUANTA_CONNECTION_CHECK_SECONDS", "60"))
_connection_task = None


async def _connection_scheduler_loop():
    """Runs every stored connection whose schedule has elapsed. Each sync runs in a worker
    thread so a slow source never blocks requests; results are stored on the connection."""
    while True:
        await asyncio.sleep(_CONNECTION_CHECK_SECONDS)
        if not _leader.is_leader:
            continue
        try:
            # queue the due syncs; a worker (this process's embedded one, or the worker Deployment) runs them
            await asyncio.to_thread(conn_sync.enqueue_due)
        except Exception:  # noqa: BLE001 - a bad tick must never kill the loop
            import traceback
            traceback.print_exc()


@app.on_event("startup")
async def _start_notification_scheduler():
    global _scheduler_task, _connection_task, _leader_task, _worker_thread, _worker_stop
    await asyncio.to_thread(_leader.check)
    _leader_task = asyncio.create_task(_leader_loop())
    _scheduler_task = asyncio.create_task(_notification_scheduler_loop())
    _connection_task = asyncio.create_task(_connection_scheduler_loop())
    if os.environ.get("QUANTA_EMBEDDED_WORKER", "true").strip().lower() not in ("0", "false", "no"):
        # Single-container default: run the queue worker inside this process. In Kubernetes the
        # chart turns this off and runs the worker as its own Deployment.
        import threading
        _worker_stop = threading.Event()
        _worker_thread = threading.Thread(target=job_worker.run_forever, args=(_worker_stop,), daemon=True, name="embedded-worker")
        _worker_thread.start()


@app.on_event("shutdown")
async def _stop_background():
    _leader.step_down()
    if _worker_stop is not None:
        _worker_stop.set()


# ---------------------------------------------------------------------------
# JSON API - the frontend's only source of data. Every function below stays a
# thin adapter over dashboard_data / cli / the ServiceNow connector; none of
# them contain business logic of their own (same rule the old Flask routes
# followed).
# ---------------------------------------------------------------------------

def _fast_json(payload):
    """Returning a plain dict/list from a route handler routes it through FastAPI's
    jsonable_encoder() before serializing - a recursive isinstance-check walk meant to
    coerce things like datetime/Enum into JSON-safe values. This dashboard's largest
    payloads are already 100% plain-JSON-safe (str/int/float/bool/None/list/dict, built
    from json.loads() plus arithmetic), so that walk is pure overhead - profiled at
    over 1s on /api/queue's ~14MB response alone. Building the Response directly with
    json.dumps() skips it. Only worth using on the few endpoints whose payload size
    actually makes the difference measurable; most routes stay plain dicts."""
    return Response(content=json.dumps(payload), media_type="application/json")

@app.get("/api/overview")
def api_overview():
    findings = dashboard_data.load_remediation_findings()
    vh = dashboard_data.load_quanta_scan_data()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()
    eligible = [f for f in findings if f.get("remediation_domain")]
    manual_only = [f for f in findings if not f.get("remediation_domain")]
    live_queue = dashboard_data.load_live_queue()

    # Shared, short-TTL-cached scoring pipeline (dashboard_data._load_scored_assets()) -
    # also used by /api/assets and load_live_queue(), so a single Overview page load
    # (which fetches all three) pays for this real computation once, not 2-3x
    # redundantly - see that function's own docstring for why sharing it here is safe.
    exploit_tagged, scored_assets = dashboard_data._load_scored_assets()
    exposure = exposure_score.compute_exposure_score(scored_assets, exploit_tagged)

    return {
        "sla": dashboard_data.sla_summary(live_queue),
        "kev_count": dashboard_data.count_kev_listed(findings),
        "high_epss_count": dashboard_data.count_high_epss(findings),
        "quanta_scan": {"total": vh.get("total", 0), "auto_fixable": vh.get("auto_fixable", 0)},
        "remediation": {
            "total": len(findings),
            "eligible": len(eligible),
            "manual_only": len(manual_only),
        },
        "playbook_count": len(playbooks),
        "plan": {
            "available": plan.get("available", False),
            "risk_tier_counts": plan.get("risk_tier_counts", {}),
        },
        "asset_type_breakdown": dashboard_data.asset_type_breakdown(findings),
        "priority_rules": dashboard_data.sla_and_priority_definitions(),
        # Live, not hardcoded - same "an admin who retunes this file sees the page
        # update too" rule priority_rules already gets above (risk_scoring.load_rules()
        # reads remediation/config/risk_scoring_rules.yaml fresh on every call).
        "risk_scoring_rules": risk_scoring.load_rules(),
        "exposure_score": exposure,
        "exposure_score_rules": exposure_score.load_rules(),
    }


@app.get("/api/quanta-scan")
def api_quanta_scan():
    return dashboard_data.load_quanta_scan_data()


@app.get("/api/remediate")
def api_remediate():
    findings = dashboard_data.load_remediation_findings()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()
    playbooks_by_finding = {p["finding_id"]: p["filename"] for p in playbooks if p["finding_id"]}
    return _fast_json({"findings": findings, "plan": plan, "playbooks_by_finding": playbooks_by_finding})


@app.get("/api/playbooks/{filename}")
def api_playbook_detail(filename: str):
    playbooks = {p["filename"]: p for p in dashboard_data.load_playbooks()}
    playbook = playbooks.get(filename)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {**playbook, "lint": playbook_lint.lint_playbook(playbook["content"])}


def _scope_to_team(rows, user, team_field="team"):
    """Real, server-side per-team RBAC for finding/asset-level views (Queue, Asset
    Inventory, Exceptions, Remediation Approvals) - NIST AC-3/AC-4/AC-6, OWASP
    API1:2023 BOLA. Derived entirely from `user` (the server-verified session from
    Depends(rbac.get_current_user)), never a client-supplied parameter.

    Team-scoping is opt-in NARROWING, not deny-by-default: it only takes effect once
    an admin has actually assigned a real user a real team (dashboard/auth/users.py's
    set_team(), via the Admin Settings "Team Management" section). No session
    (`user` is None), an admin, or a non-admin with no team assigned all see
    unfiltered rows - the same baseline this app's own documented "reads are
    intentionally public" MVP convention (dashboard/README.md) already gives an
    anonymous request, so "logged in but not yet assigned a team" is never a MORE
    restrictive state than "not logged in at all," which would be a confusing
    (and easy to accidentally trigger) UX regression for every existing account
    that predates this feature. Closing the anonymous-access gap entirely means
    making these routes login-required outright, a separate, larger change from
    team-scoping itself."""
    if user is None or user.get("role") == "admin" or not user.get("team"):
        return rows
    return [r for r in rows if r.get(team_field) == user["team"]]


def _team_by_asset_name():
    """{asset_name: team} from the real, current asset ownership data - the
    server-side equivalent of assetLookup.js's buildOwnerTeamMaps(), which every page
    needing a finding's team currently computes client-side (a finding carries no
    team of its own - see asset_inventory.build_asset_inventory()). Backed by the
    same short-TTL, mtime-keyed cache as /api/assets (_load_scored_assets()), so
    calling this on every /api/queue request is a cheap cache hit, not a
    recomputation."""
    _, assets = dashboard_data._load_scored_assets()
    return {a["name"]: a.get("team") for a in assets}


def _annotate_finding_teams(findings, team_by_asset_name=None, with_assignment=False):
    """Adds a real `team` field to each finding - the team a finding is *routed to*:
    its explicit assignment's team if it has one (the ITSM "assignment group"), else
    its asset's owning team. Mutates and returns `findings` in place (safe: see
    load_live_queue()'s per-call shallow copies). With `with_assignment=True` also
    attaches an `assignment` summary (None when unassigned) - callers pass that only
    for a logged-in viewer, since it names the assignee."""
    team_by_asset_name = team_by_asset_name if team_by_asset_name is not None else _team_by_asset_name()
    assignments = assignments_store.assignments_by_finding()
    for f in findings:
        asset = f.get("asset") or {}
        team = team_by_asset_name.get(asset.get("name"))
        a = assignments.get(f["id"])
        if a and a.get("assigned_team"):
            team = a["assigned_team"]
        f["team"] = team
        if with_assignment:
            f["assignment"] = (
                {"assignee_email": a["assignee_email"], "assigned_team": a["assigned_team"], "status": a["status"]}
                if a else None
            )
    return findings


def _require_asset_write(asset_name, user):
    """Write access to one asset's metadata. Administrators: unrestricted. A non-admin
    with a team: only assets that appear in findings routed to their team (the same
    team-scoped view /api/queue shows them). A non-admin with no team: no writes."""
    if user.get("role") == "admin":
        return
    if not user.get("team"):
        raise HTTPException(status_code=403, detail="Changing asset details needs an administrator or membership of a team that owns the asset.")
    scoped = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    if asset_name not in {(f.get("asset") or {}).get("name") for f in scoped}:
        raise HTTPException(status_code=403, detail="That asset is not in your team's scope.")


_CMDB_MAX_ENTRIES = 5000
_CMDB_MAX_FIELD = 200


def _validate_cmdb_entries(entries):
    if len(entries) > _CMDB_MAX_ENTRIES:
        raise HTTPException(status_code=400, detail=f"Too many entries (maximum {_CMDB_MAX_ENTRIES}).")
    for i, e in enumerate(entries, 1):
        name = e.get("asset_name")
        if not isinstance(name, str) or not name.strip() or len(name) > _CMDB_MAX_FIELD:
            raise HTTPException(status_code=400, detail=f"Entry {i}: asset_name must be a non-empty string of at most {_CMDB_MAX_FIELD} characters.")
        for field in ("owner", "team", "environment"):
            v = e.get(field, "")
            if v is not None and (not isinstance(v, str) or len(v) > _CMDB_MAX_FIELD):
                raise HTTPException(status_code=400, detail=f"Entry {i}: {field} must be a string of at most {_CMDB_MAX_FIELD} characters.")


def _finding_team_by_id(queue_findings, team_by_asset_name=None):
    """{finding_id: team} for every real finding in the live queue - the join
    exceptions/remediation-approvals need to team-scope their own records, since
    those are stored keyed by finding_id, not with a team (or asset) of their own.
    Honors an explicit assignment's team over the asset's, matching
    _annotate_finding_teams()."""
    team_by_asset_name = team_by_asset_name if team_by_asset_name is not None else _team_by_asset_name()
    assignments = assignments_store.assignments_by_finding()
    result = {}
    for f in queue_findings:
        asset = f.get("asset") or {}
        a = assignments.get(f["id"])
        result[f["id"]] = (a or {}).get("assigned_team") or team_by_asset_name.get(asset.get("name"))
    return result


@app.get("/api/queue")
def api_queue(user: dict = Depends(rbac.get_current_user)):
    scored = _scope_to_team(
        _annotate_finding_teams(dashboard_data.load_live_queue(), with_assignment=user is not None), user)
    if user is not None:
        counts = {}
        for t in support_store.list_tickets(status="open_all", limit=5000):
            if t.get("finding_id"):
                counts[t["finding_id"]] = counts.get(t["finding_id"], 0) + 1
        if counts:  # copy, never mutate: the scored findings may be a shared cached list
            scored = [{**f, "open_tickets": counts[f["id"]]} if f["id"] in counts else f for f in scored]
    return _fast_json({"findings": scored, "sla": dashboard_data.sla_summary(scored)})


@app.get("/api/attack-paths")
def api_attack_paths(user: dict = Depends(rbac.get_current_user)):
    scoped = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    return _fast_json({"chains": dashboard_data.get_attack_chains(scoped)})


@app.get("/api/posture")
def api_posture(request: Request, user: dict = Depends(rbac.get_current_user)):
    """The Security Posture Review (remediation/posture): ten frameworks assessed from recorded data. Administrator only, because it reads settings of this
    deployment as well as findings. Deterministic for the same recorded data; nothing is changed."""
    rbac.require_admin(request)
    findings = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    return _fast_json(posture_engine.assess(findings=findings, now=datetime.datetime.now(datetime.timezone.utc)))


_GRAPH_ADMIN_MODULES = {"soc", "appsec", "ai", "grc", "admin"}   # the pages these graphs summarise are administrator pages


@app.get("/api/graphs/{module}")
def api_module_graph(module: str, request: Request, user: dict = Depends(rbac.get_current_user)):
    """One module's relationship graph (remediation/graphs), built from that module's stored data and the findings the caller may see.
    Graph theory (clusters, choke points, single points of failure) is computed in the browser; this only says what is connected to what."""
    if module not in module_graphs.MODULES:
        raise HTTPException(status_code=404, detail="Unknown module")
    if module in _GRAPH_ADMIN_MODULES:
        rbac.require_admin(request)
    findings = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    return _fast_json(module_graphs.build(module, findings=findings))


class OntologyQueryBody(BaseModel):
    """Either a structured `pattern` (remediation/ontology/query.py) or the id of a named `question`; never free text."""
    pattern: Optional[dict] = None
    question: Optional[str] = Field(default=None, max_length=80)


def _ontology_module_graphs(findings):
    """Each module's graph for the ontology routes; a module whose data cannot be read is None (and named by the estate's `sources`)."""
    out = {}
    for m in module_graphs.MODULES:
        try:
            out[m] = module_graphs.build(m, findings=findings)
        except Exception:  # noqa: BLE001
            out[m] = None
    return out


@app.get("/api/ontology")
def api_ontology():
    """The ontology (remediation/config/ontology.yaml): classes, is-a, typed relations and how each module graph maps onto them. Public like the other
    reads: it describes the vocabulary, not anyone's data."""
    return _fast_json(ontology_vocab.load().describe())


@app.get("/api/ontology/questions")
def api_ontology_questions():
    """The named multi-hop questions (remediation/config/ontology_questions.yaml), each as its structured pattern and a readable line."""
    return {"questions": ontology_query.load_questions()}


@app.get("/api/ontology/validate")
def api_ontology_validate(request: Request, module: Optional[str] = None, user: dict = Depends(rbac.get_current_user)):
    """Check the module graphs and the whole-estate graph against the ontology (a SHACL-like report; nothing is changed or dropped), with how much of the
    estate's provenance is known. Administrator only: it builds every module's graph."""
    rbac.require_admin(request)
    if module is not None and module != "estate" and module not in module_graphs.MODULES:
        raise HTTPException(status_code=404, detail="Unknown module")
    findings = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    graphs = _ontology_module_graphs(findings)
    reports = {m: ontology_validate.validate(g, m) for m, g in sorted(graphs.items()) if g is not None and module in (None, "estate", m)}
    for r in reports.values():
        r["violations"] = r["violations"][:100]
    estate_graph = ontology_estate.build(findings=findings, graphs={m: g for m, g in graphs.items() if g is not None})
    estate_report = ontology_validate.validate(estate_graph, "estate")
    estate_report["violations"] = estate_report["violations"][:100]
    facts = ontology_provenance.facts(estate_graph, "estate")
    return _fast_json({"conforms": all(r["conforms"] for r in reports.values()) and estate_report["conforms"], "modules": reports, "estate": estate_report,
                       "provenance": ontology_provenance.coverage(facts), "sources": estate_graph["sources"],
                       "unavailable": sorted(m for m, g in graphs.items() if g is None)})


@app.post("/api/ontology/query")
def api_ontology_query(body: OntologyQueryBody, request: Request, user: dict = Depends(rbac.get_current_user)):
    """Run a structured multi-hop pattern, or a named question, over the whole-estate graph. Administrator only. The pattern is parsed against the ontology
    and bounded in depth, size and work; it is never evaluated as code."""
    rbac.require_admin(request)
    if (body.pattern is None) == (body.question is None):
        raise HTTPException(status_code=400, detail="Send exactly one of pattern or question")
    findings = _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)
    graphs = {m: g for m, g in _ontology_module_graphs(findings).items() if g is not None}
    estate_graph = ontology_estate.build(findings=findings, graphs=graphs)
    try:
        if body.question is not None:
            return _fast_json(ontology_query.run_question(estate_graph, body.question))
        return _fast_json(ontology_query.run(estate_graph, body.pattern))
    except ontology_query.QueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown question")


@app.get("/api/dependencies")
def api_dependencies(user: dict = Depends(rbac.get_current_user)):
    packages = dashboard_data.get_dependency_findings()
    for entry in packages:
        entry["findings"] = _scope_to_team(_annotate_finding_teams(entry["findings"]), user)
    return _fast_json({"packages": [p for p in packages if p["findings"]]})


@app.get("/api/threat-intel/freshness")
def api_threat_intel_freshness():
    return {
        **dashboard_data.load_threat_intel_freshness(),
        "recommended_cadence": yaml.safe_load(
            (dashboard_data.REPO_ROOT / "remediation" / "config" / "threat_intel_refresh_rules.yaml").read_text(encoding="utf-8"),
        ).get("recommended_cadence", {}),
    }


class ThreatIntelRefreshBody(BaseModel):
    confirm: bool = False


@app.post("/api/threat-intel/refresh-now")
def api_threat_intel_refresh_now(body: ThreatIntelRefreshBody, request: Request):
    """Re-fetches CISA KEV + FIRST.org EPSS live and re-enriches the real
    normalized-findings.json in place (remediation/enrichment/kev_epss.py's own
    enrich_file()) - the same real logic /remediate's enrichment stage runs, available
    on demand without re-running the whole pipeline. Unlike the AI-assist/run-pipeline
    confirm actions, this never spends Claude API usage - it's two free, public REST
    calls - but it's still a real network call and a real file mutation, so it keeps
    the same preview-then-confirm, admin-gated shape as every other one in this app."""
    findings = dashboard_data.load_remediation_findings()
    cve_count = sum(1 for f in findings if f.get("cve"))

    if not body.confirm:
        return {
            "dry_run": True,
            "message": (
                f"Dry run only (nothing fetched). Would re-fetch CISA KEV + FIRST.org EPSS "
                f"for {cve_count} CVE(s) and update remediation/output/normalized-findings.json. "
                f"Set confirm to actually run it."
            ),
        }

    user = rbac.require_admin(request)
    try:
        kev_epss.enrich_file(dashboard_data.REPO_ROOT / "remediation" / "output" / "normalized-findings.json")
    except Exception as exc:  # noqa: BLE001 - a real fetch failure must surface honestly, not look like success
        raise HTTPException(status_code=502, detail=f"Threat-intel refresh failed: {exc}") from exc

    activity_log.record_activity(user["email"], "threat_intel.refresh_now", None, {"cve_count": cve_count})
    freshness = dashboard_data.load_threat_intel_freshness()
    return {"dry_run": False, "message": f"Refreshed KEV/EPSS for {cve_count} CVE(s).", "freshness": freshness}


@app.get("/api/events")
async def api_events(request: Request, topics: str = "", once: bool = False, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """Server-Sent Events: a read-only live feed (dashboard/events.py). Topics are comma separated (empty = all). `once=true` sends the hello frame and
    closes (availability check). Resumes from Last-Event-ID. The stream carries event names and small counters, never finding or user detail; the page
    still reads the real data through the normal routes. A stream is recycled after 15 minutes and the browser reconnects by itself."""
    wanted = [t.strip() for t in topics.split(",") if t.strip()][:10]
    sub = live_events.hub.subscribe(wanted)
    if sub is None:
        raise HTTPException(status_code=503, detail="Too many live streams are open; the page will poll instead.")
    try:
        last_id = int(request.headers.get("last-event-id", "0") or 0)
    except ValueError:
        last_id = 0
    headers = {"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
    return StreamingResponse(live_events.stream(sub, last_id, once=once, max_seconds=900), media_type="text/event-stream", headers=headers)


from remediation.audit import activity_log as _activity_log_hook  # noqa: E402
_activity_log_hook.listener = lambda action: live_events.publish("activity", {"action": action})


@app.get("/api/notifications")
def api_notifications():
    scored = dashboard_data.load_live_queue()
    return {"notifications": dashboard_data.build_notifications(scored)}


@app.get("/api/priority-rules")
def api_get_priority_rules():
    return {"rules_text": dashboard_data.load_priority_rules_text()}


class PriorityRulesBody(BaseModel):
    rules_text: str


@app.post("/api/priority-rules")
def api_save_priority_rules(body: PriorityRulesBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_priority_rules_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {
        "message": "Priority rules saved. The live queue and SLA dashboard now reflect "
                    "these weights.",
    }


@app.get("/api/remediation-policy")
def api_get_remediation_policy():
    return {"rules_text": dashboard_data.load_remediation_policy_text()}


class RemediationPolicyBody(BaseModel):
    rules_text: str


@app.post("/api/remediation-policy")
def api_save_remediation_policy(body: RemediationPolicyBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_remediation_policy_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {"message": "Remediation policy saved. The live queue now reflects these cadence/approval/window rules."}


@app.get("/api/remediation-approvals")
def api_list_remediation_approvals(user: dict = Depends(rbac.get_current_user)):
    # Joins in each finding's real generated-playbook rollback procedure (ISO/IEC
    # 27002:2022 §8.32) - a real "# Rollback: ..." comment the fixer subagent wrote for
    # that specific fix (see dashboard_data.load_playbooks()'s _parse_rollback_plan()),
    # surfaced where the approval decision actually happens instead of only inside the
    # generated playbook file. None when no playbook has been generated for this
    # finding yet - stays honest rather than fabricating a procedure.
    approvals = remediation_approvals_store.list_approvals_with_status()
    playbooks_by_finding = {p["finding_id"]: p for p in dashboard_data.load_playbooks() if p["finding_id"]}
    verification = {v["approval_id"]: v for v in closed_loop.verify_all(approvals, dashboard_data.load_remediation_findings())["results"]}
    for a in approvals:
        playbook = playbooks_by_finding.get(a["finding_id"])
        a["rollback_plan"] = playbook["rollback_plan"] if playbook else None
        if playbook:
            lint = playbook_lint.lint_playbook(playbook["content"])
            a["playbook_lint"] = {"passed": lint["passed"], "errors": len(lint["errors"]), "warnings": len(lint["warnings"])}
        else:
            a["playbook_lint"] = None
        a["verification"] = verification.get(a["id"])
    if user is not None and user.get("role") != "admin":
        team_by_finding = _finding_team_by_id(dashboard_data.load_live_queue())
        for a in approvals:
            a["team"] = team_by_finding.get(a["finding_id"])
        approvals = _scope_to_team(approvals, user)
    return {"approvals": approvals}


@app.get("/api/remediation-verification")
def api_remediation_verification(user: dict = Depends(rbac.get_current_user)):  # noqa: ARG001
    """Closed-loop outcome of every triggered remediation (remediation/verification/closed_loop.py)."""
    return closed_loop.verify_all(remediation_approvals_store.list_approvals_with_status(),
                                  dashboard_data.load_remediation_findings())


@app.get("/api/remediation-metrics")
def api_remediation_metrics(user: dict = Depends(rbac.get_current_user)):  # noqa: ARG001
    approvals = remediation_approvals_store.list_approvals_with_status()
    verification = closed_loop.verify_all(approvals, dashboard_data.load_remediation_findings())
    return {**closed_loop.outcome_metrics(approvals, verification["results"]), "verification": verification["summary"]}


@app.get("/api/remediation-approvals/{approval_id}/evidence")
def api_remediation_evidence(approval_id: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Audit-ready evidence pack for one remediation: finding, approval trail, reviewed
    artifact + its lint result, and the closed-loop outcome."""
    approval = next((a for a in remediation_approvals_store.list_approvals_with_status() if a["id"] == approval_id), None)
    if not approval:
        raise HTTPException(status_code=404, detail=f"No approval request with id {approval_id!r}")
    findings = dashboard_data.load_remediation_findings()
    finding = next((f for f in findings if f.get("id") == approval["finding_id"]), None)
    playbook = next((p for p in dashboard_data.load_playbooks() if p["finding_id"] == approval["finding_id"]), None)
    return closed_loop.evidence_pack(
        approval, finding, playbook["content"] if playbook else None,
        playbook_lint.lint_playbook(playbook["content"]) if playbook else None,
        closed_loop.verify_all([approval], findings)["results"][0])


class RemediationApprovalRequestBody(BaseModel):
    finding_id: str
    requested_by: str = ""  # accepted for compatibility, ignored: the signed-in user is always the requester


@app.post("/api/remediation-approvals")
def api_create_remediation_approval(body: RemediationApprovalRequestBody, user: dict = Depends(rbac.require_login)):
    findings = {f["id"]: f for f in dashboard_data.load_live_queue()}
    finding = findings.get(body.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"No finding with id {body.finding_id!r}")
    scheduled_window = finding["remediation_policy"]["next_window"]
    try:
        return remediation_approvals_store.create_approval_request(body.finding_id, user["email"], scheduled_window)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class RemediationApprovalDecisionBody(BaseModel):
    decided_by: str = ""  # accepted for compatibility, ignored: the signed-in administrator is always the decider
    reason: str = ""


@app.post("/api/remediation-approvals/{approval_id}/approve")
def api_approve_remediation(approval_id: str, body: RemediationApprovalDecisionBody, user: dict = Depends(rbac.require_admin)):
    approvals = {a["id"]: a for a in remediation_approvals_store.load_approvals()}
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail=f"No approval request with id {approval_id!r}")
    decided_by = user["email"]
    if (approval.get("requested_by") or "").strip().lower() == decided_by.strip().lower():
        raise HTTPException(status_code=403, detail="Separation of duties: you requested this change, so a different administrator must approve it.")

    findings = {f["id"]: f for f in dashboard_data.load_live_queue()}
    finding = findings.get(approval["finding_id"])
    required_group = ((finding or {}).get("remediation_policy") or {}).get("requires_approval_group")

    ad_group_validated = None
    if required_group and ad_directory.is_configured():
        try:
            ad_group_validated = ad_directory.is_member_of_group(decided_by, required_group)
        except Exception as exc:  # noqa: BLE001 - a real AD failure must not silently look like "validated"
            raise HTTPException(status_code=502, detail=f"AD group lookup failed: {exc}") from exc

    # Hard gate: a generated playbook that fails the deterministic safety lint (no rollback,
    # literal credentials, targets every host, ...) cannot be approved until it is regenerated.
    playbook = next((p for p in dashboard_data.load_playbooks() if p["finding_id"] == approval["finding_id"]), None)
    if playbook:
        lint = playbook_lint.lint_playbook(playbook["content"])
        if not lint["passed"]:
            raise HTTPException(status_code=400, detail="Playbook failed the safety lint and cannot be approved: "
                                + "; ".join(f"{i['rule']} {i['message']}" for i in lint["errors"]))

    try:
        result = remediation_approvals_store.approve(approval_id, decided_by, ad_group_validated)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "approval": result,
        "ad_configured": ad_directory.is_configured(),
        "message": (
            "Approved." if not required_group else
            "Approved - AD not configured, group membership not validated." if not ad_directory.is_configured() else
            f"Approved - verified member of {required_group}." if ad_group_validated else
            f"Approved - WARNING: {decided_by} is NOT a verified member of {required_group}."
        ),
    }


@app.post("/api/remediation-approvals/{approval_id}/reject")
def api_reject_remediation(approval_id: str, body: RemediationApprovalDecisionBody, user: dict = Depends(rbac.require_admin)):
    try:
        result = remediation_approvals_store.reject(approval_id, user["email"], body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"approval": result, "message": "Rejected."}


class StagingValidatedBody(BaseModel):
    validated_by: str = ""  # accepted for compatibility, ignored: the signed-in administrator is recorded


@app.post("/api/remediation-approvals/{approval_id}/staging-validated")
def api_mark_staging_validated(approval_id: str, body: StagingValidatedBody, user: dict = Depends(rbac.require_admin)):
    try:
        result = remediation_approvals_store.mark_staging_validated(approval_id, user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"approval": result, "message": "Staging validation recorded."}


class RemediationSendCommunicationBody(BaseModel):
    recipient: str = ""
    confirm: bool = False


@app.post("/api/remediation-approvals/{approval_id}/send-communication")
def api_send_remediation_communication(approval_id: str, body: RemediationSendCommunicationBody, request: Request):
    """Sends the finding's already-rendered downtime-communication text (see
    remediation_policy_engine.render_communication(), merged onto every finding in
    load_live_queue() as remediation_policy.rendered_communication) to a real recipient -
    same dry-run-preview-then-confirm shape as /api/notification-settings/send-test,
    reusing the same real SMTP sender, no new email-sending code."""
    approvals = {a["id"]: a for a in remediation_approvals_store.load_approvals()}
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail=f"No approval request with id {approval_id!r}")

    findings = {f["id"]: f for f in dashboard_data.load_live_queue()}
    finding = findings.get(approval["finding_id"])
    if not finding:
        raise HTTPException(status_code=404, detail=f"No finding with id {approval['finding_id']!r}")

    policy = finding.get("remediation_policy") or {}
    subject = f"Remediation communication: {finding.get('title', finding['id'])} ({finding['id']})"
    body_text = policy.get("rendered_communication") or ""

    if not body.confirm:
        return {"preview_only": True, "message": "Preview only (no email sent). Check confirm and provide a real recipient to actually send.", "subject": subject, "body_text": body_text}

    rbac.require_admin(request)
    if not email_sender.is_configured():
        raise HTTPException(
            status_code=503,
            detail="SMTP is not configured on this server (set SMTP_HOST/SMTP_PORT/SMTP_FROM_ADDRESS "
                   "environment variables).",
        )
    if not body.recipient:
        raise HTTPException(status_code=400, detail="recipient is required to actually send.")

    try:
        email_sender.send_email([body.recipient], subject, body_text)
    except Exception as exc:  # noqa: BLE001 - surface any real SMTP failure to the caller
        raise HTTPException(status_code=502, detail=f"Send failed: {exc}") from exc

    return {"preview_only": False, "message": f"Communication sent to {body.recipient}.", "subject": subject, "body_text": body_text}


@app.get("/api/exploit-criteria")
def api_get_exploit_criteria():
    return {"rules_text": dashboard_data.load_exploit_criteria_rules_text()}


class ExploitCriteriaRulesBody(BaseModel):
    rules_text: str


@app.post("/api/exploit-criteria")
def api_save_exploit_criteria(body: ExploitCriteriaRulesBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_exploit_criteria_rules_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {
        "message": "Exploit criteria rules saved. Every CVE-bearing finding's "
                    "exploit_criteria_matches now reflects these rules.",
    }


@app.post("/api/exploit-criteria/preview")
def api_preview_exploit_criteria(body: ExploitCriteriaRulesBody):
    """Read-only: how many CURRENT findings would match each rule in the submitted
    (not-yet-saved) YAML text - lets the /exploit-criteria editor show a live match
    count as an admin edits a rule, before committing it with Save."""
    try:
        parsed = yaml.safe_load(body.rules_text) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc
    rules = parsed.get("rules", [])
    findings = dashboard_data.load_remediation_findings()
    return {"counts": exploit_criteria.count_matches_per_rule(findings, rules)}


# ---------------------------------------------------------------------------
# Notification Settings - scheduled reports (sub-domain/team-wise, weekly through
# yearly) and critical/zero-day/threat-intel team email alerts. Same
# YAML-text-editor-plus-admin-gated-save pattern as priority-rules/exploit-criteria
# above; same dry-run-preview-by-default/explicit-confirm-to-spend pattern as
# ai-assist/servicenow/jira for the actual send. Real SMTP delivery
# (remediation/notifications/email_sender.py) is env-var-configured and optional - every
# route below still works (as preview/config-only) without it configured.
# ---------------------------------------------------------------------------

@app.get("/api/report-schedule")
def api_get_report_schedule():
    return {"rules_text": dashboard_data.load_report_schedule_text()}


class ReportScheduleBody(BaseModel):
    rules_text: str


@app.post("/api/report-schedule")
def api_save_report_schedule(body: ReportScheduleBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_report_schedule_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {"message": "Report schedule saved."}


@app.get("/api/alert-rules")
def api_get_alert_rules():
    return {"rules_text": dashboard_data.load_alert_rules_text()}


class AlertRulesBody(BaseModel):
    rules_text: str


@app.post("/api/alert-rules")
def api_save_alert_rules(body: AlertRulesBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_alert_rules_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {"message": "Alert rules saved."}


@app.get("/api/notification-settings/status")
def api_notification_settings_status():
    return {
        "smtp_configured": email_sender.is_configured(),
        "from_address": email_sender.from_address() if email_sender.is_configured() else None,
        "check_interval_seconds": _NOTIFICATION_CHECK_INTERVAL_SECONDS,
    }


class NotificationPreviewBody(BaseModel):
    kind: str  # "report" | "alert"
    scope: str = "all"
    team: str = ""
    period: str = "weekly"       # report only
    alert_type: str = "critical"  # alert only


def _build_preview(body: NotificationPreviewBody):
    if body.kind == "report":
        report = reports.generate_report_data(
            body.period, dashboard_data, scope=body.scope, team=body.team or None,
        )
        return {
            "subject": reports.report_title(report),
            "body_text": reports.render_report_text(report),
            "body_html": reports.render_report_html(report),
        }
    if body.kind == "alert":
        findings = dashboard_data.load_live_queue()
        ownership = asset_inventory.load_ownership()
        sub = {"alert_type": body.alert_type, "scope": body.scope, "team": body.team or None}
        matched = alert_checker.matching_findings(sub, findings, ownership)
        return {
            "subject": alert_checker.build_subject(sub),
            "body_text": alert_checker.build_alert_body_text(sub, matched),
            "body_html": alert_checker.build_alert_body_html(sub, matched),
            "matched_count": len(matched),
        }
    raise HTTPException(status_code=400, detail='kind must be "report" or "alert"')


@app.post("/api/notification-settings/preview")
def api_notification_preview(body: NotificationPreviewBody):
    try:
        return _build_preview(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class NotificationSendTestBody(NotificationPreviewBody):
    recipient: str = ""
    confirm: bool = False


@app.post("/api/notification-settings/send-test")
def api_notification_send_test(body: NotificationSendTestBody, request: Request):
    try:
        preview = _build_preview(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not body.confirm:
        return {"preview_only": True, "message": "Preview only (no email sent). Check confirm and provide a real recipient to actually send.", **preview}

    rbac.require_admin(request)
    if not email_sender.is_configured():
        raise HTTPException(
            status_code=503,
            detail="SMTP is not configured on this server (set SMTP_HOST/SMTP_PORT/SMTP_FROM_ADDRESS "
                   "environment variables).",
        )
    if not body.recipient:
        raise HTTPException(status_code=400, detail="recipient is required to actually send a test email.")

    try:
        email_sender.send_email([body.recipient], preview["subject"], preview["body_text"], preview["body_html"])
    except Exception as exc:  # noqa: BLE001 - surface any real SMTP failure to the caller
        raise HTTPException(status_code=502, detail=f"Send failed: {exc}") from exc

    return {"preview_only": False, "message": f"Test email sent to {body.recipient}.", **preview}


@app.post("/api/notification-settings/run-checks-now")
def api_notification_run_checks_now(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """The real, cron-callable alternative to the in-process scheduler loop below - an
    external Task Scheduler/cron job can POST here on its own real schedule for delivery
    that doesn't depend on this server process staying up. Runs both scheduled-report
    and alert checks immediately and returns what happened (sent/skipped/error per
    subscription), same as the background loop does silently."""
    report_results = report_scheduler.check_and_send_due_reports(dashboard_data, reports, email_sender)
    alert_results = alert_checker.check_and_send_alerts(dashboard_data, email_sender)
    return {"report_results": report_results, "alert_results": alert_results}


def _require_safe_target(value, field_name):
    """SSRF guardrail (see remediation/connectors/url_safety.py) - call this on every
    admin-supplied host/URL field right before constructing a connector with it, same
    place the existing "these fields are all required" checks already sit."""
    try:
        url_safety.assert_safe_target(value)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=f"{field_name}: {exc}") from exc


def _require_safe_instance_label(value, field_name):
    """Same guardrail, for fields (ServiceNow's `instance`) that this app interpolates
    into a fixed URL template rather than accepting a free URL - see
    url_safety.assert_safe_instance_label()'s own docstring for the specific bypass
    this closes."""
    try:
        url_safety.assert_safe_instance_label(value, field_name=field_name)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/servicenow/preview")
def api_servicenow_preview():
    findings = dashboard_data.load_remediation_findings()
    return {"previews": [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]}


class ServiceNowSendBody(BaseModel):
    instance: str = ""
    username: str = ""
    password: str = ""
    table: str = "incident"
    confirm: bool = False


@app.post("/api/servicenow/send")
def api_servicenow_send(body: ServiceNowSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    previews = [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to ServiceNow). Check confirm and "
                       "provide real credentials to actually create incidents.",
            "previews": previews,
            "results": None,
        }

    # Only the real-send path (confirm=True) requires login - preview is exactly as
    # open as the read-only /api/queue data it's built from, so it stays ungated.
    rbac.require_admin(request)

    if not body.instance or not body.username or not body.password:
        raise HTTPException(
            status_code=400,
            detail="Instance, username, and password are all required to actually push to ServiceNow.",
        )
    _require_safe_instance_label(body.instance, "instance")

    conn = ServiceNowConnector(body.instance, body.username, body.password, table=body.table)
    try:
        results = conn.create_incidents_for_findings(findings)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"ServiceNow request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} incident(s) against "
                   f"{body.instance}.service-now.com/{body.table}.",
        "previews": previews,
        "results": results,
    }


# A placeholder project key used only so /api/jira/preview can show a real, well-formed
# issue body with zero credentials required - build_issue_body() has no default project
# key of its own since a real send always needs the caller's actual one.
_JIRA_PREVIEW_PROJECT_KEY = "VULN"


@app.get("/api/jira/preview")
def api_jira_preview():
    findings = dashboard_data.load_remediation_findings()
    return {
        "previews": [
            {"finding_id": f["id"], "body": build_issue_body(f, _JIRA_PREVIEW_PROJECT_KEY)}
            for f in findings
        ],
    }


class JiraSendBody(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = JIRA_DEFAULT_ISSUE_TYPE
    confirm: bool = False


@app.post("/api/jira/send")
def api_jira_send(body: JiraSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    preview_key = body.project_key or _JIRA_PREVIEW_PROJECT_KEY
    previews = [
        {"finding_id": f["id"], "body": build_issue_body(f, preview_key, body.issue_type)}
        for f in findings
    ]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to Jira). Check confirm and provide "
                       "a real site URL, email, API token, and project key to actually create issues.",
            "previews": previews,
            "results": None,
        }

    rbac.require_admin(request)

    if not body.base_url or not body.email or not body.api_token or not body.project_key:
        raise HTTPException(
            status_code=400,
            detail="Site URL, email, API token, and project key are all required to actually push to Jira.",
        )
    _require_safe_target(body.base_url, "base_url")

    conn = JiraConnector(body.base_url, body.email, body.api_token, body.project_key)
    try:
        results = conn.create_issues_for_findings(findings)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"Jira request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} issue(s) against {body.base_url} ({body.project_key}).",
        "previews": previews,
        "results": results,
    }


@app.get("/api/splunk/preview")
def api_splunk_preview():
    findings = dashboard_data.load_remediation_findings()
    return {
        "previews": [
            {"finding_id": f["id"], "body": build_hec_event(f)}
            for f in findings
        ],
    }


class SplunkSendBody(BaseModel):
    hec_url: str = ""
    hec_token: str = ""
    sourcetype: str = SPLUNK_DEFAULT_SOURCETYPE
    index: str = ""
    confirm: bool = False


@app.post("/api/splunk/send")
def api_splunk_send(body: SplunkSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    index = body.index or None
    previews = [
        {"finding_id": f["id"], "body": build_hec_event(f, sourcetype=body.sourcetype, index=index)}
        for f in findings
    ]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to Splunk). Check confirm and provide "
                       "a real HEC URL and token to actually send events.",
            "previews": previews,
            "results": None,
        }

    rbac.require_admin(request)

    if not body.hec_url or not body.hec_token:
        raise HTTPException(
            status_code=400,
            detail="HEC URL and token are both required to actually send events to Splunk.",
        )
    _require_safe_target(body.hec_url, "hec_url")

    conn = SplunkConnector(body.hec_url, body.hec_token)
    try:
        results = conn.send_events_for_findings(findings, sourcetype=body.sourcetype, index=index)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"Splunk HEC request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} event(s) against {body.hec_url}.",
        "previews": previews,
        "results": results,
    }



# ---------------------------------------------------------------------------
# Tenable / Qualys / Prisma Cloud / Cortex XSIAM / Infoblox / Axonius / Active
# Directory - "Test Connection" + "Fetch" actions for the pull connectors that,
# unlike ServiceNow/Jira/Splunk, have no "preview what would be sent" concept (there's
# nothing to preview without first pulling real data). Every one of these:
#   - takes credentials fresh on every request, exactly like ServiceNow/Jira/Splunk -
#     never written to disk or a database (see adaptors.js's connectionSettingsHtml()).
#   - gates the real network call behind rbac.require_admin, same as every other
#     real-credentialed action in this file.
#   - test-connection makes one cheap, real, read-only call (see each connector's own
#     test_connection() for what that call actually is) - no confirm checkbox, since
#     there's no bulk/destructive action to scale-warn about.
#   - fetch is confirm-gated like ServiceNow/Jira/Splunk's real send, because it's a
#     real, potentially slow (Tenable/Qualys can be minutes for a large tenant) call
#     against a real production system.
#
# What "fetch" actually produces differs by source, and each route says so honestly:
#   - Tenable/Qualys are CVE-scoped host-vulnerability sources - fetch writes a raw
#     export file to remediation/live-data/ and the response says plainly that
#     `/remediate <file>` (an interactive, agent-driven step - see docs/GOING_LIVE.md
#     for why asset-type classification needs that, not a deterministic script) is
#     still required to actually see it reflected on this dashboard's own pages.
#   - Prisma Cloud/Cortex XSIAM are already-normalized Finding-schema sources (no
#     classification judgment needed, see their connectors' own docstrings) - fetch
#     writes normalized findings straight to remediation/live-data/, ID-sequenced the
#     same way the generic ingest adapter's _next_finding_id already is, but - like
#     that adapter's own explicit, disclosed choice - deliberately NOT auto-merged into
#     remediation/output/normalized-findings.json or the live queue.
#   - Infoblox/Axonius/Active Directory are asset-inventory sources - fetch reconciles
#     real ip/mac ground truth directly into asset_ownership.json via
#     asset_inventory.reconcile_pulled_assets(), the same real, bounded action
#     cmdb_import's CSV upload already performs, and the same honest scope limit
#     applies: an asset with no existing findings against it won't appear on the Asset
#     Inventory table until one does, since that table is built from findings, not a
#     separate asset registry.
# ---------------------------------------------------------------------------

def _next_finding_id_for(existing_findings):
    """Same FIND-N sequencing generic_connector.py's own ingest route already uses -
    duplicated here (2 lines) rather than imported, since it's private to that module
    and this is the same small, well-understood pattern, not a shared abstraction
    worth introducing across an unrelated file."""
    existing = [int(f["id"].split("-")[1]) for f in existing_findings if f.get("id", "").startswith("FIND-")]
    return f"FIND-{max(existing, default=0) + 1}"


LIVE_DATA_DIR = dashboard_data.REPO_ROOT / "remediation" / "live-data"


class TenableTestConnectionBody(BaseModel):
    access_key: str = ""
    secret_key: str = ""


@app.post("/api/tenable/test-connection")
def api_tenable_test_connection(body: TenableTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.access_key or not body.secret_key:
        raise HTTPException(status_code=400, detail="Access key and secret key are both required.")
    conn = TenableConnector(body.access_key, body.secret_key)
    try:
        result = conn.test_connection()
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"Tenable connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to Tenable.io as {result.get('username') or result.get('email') or 'an authenticated user'}."}


class TenableFetchBody(BaseModel):
    access_key: str = ""
    secret_key: str = ""
    confirm: bool = False


@app.post("/api/tenable/fetch")
def api_tenable_fetch(body: TenableFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch a live Tenable vulnerability export.", "written_to": None, "count": None}
    rbac.require_admin(request)
    if not body.access_key or not body.secret_key:
        raise HTTPException(status_code=400, detail="Access key and secret key are both required to fetch live data.")
    conn = TenableConnector(body.access_key, body.secret_key)
    out_path = LIVE_DATA_DIR / "tenable_export.csv"
    try:
        conn.fetch_and_write_csv(out_path)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Tenable export failed: {exc}") from exc
    with out_path.open(encoding="utf-8") as f:
        count = max(sum(1 for _ in f) - 1, 0)
    return {
        "preview_only": False,
        "message": f"Wrote {count} row(s) to remediation/live-data/tenable_export.csv. Run "
                   f"`/remediate remediation/live-data/tenable_export.csv` in an interactive Claude "
                   f"Code session to bring this into the dashboard - see docs/GOING_LIVE.md.",
        "written_to": "remediation/live-data/tenable_export.csv",
        "count": count,
    }


class QualysTestConnectionBody(BaseModel):
    username: str = ""
    password: str = ""
    platform_url: str = ""


@app.post("/api/qualys/test-connection")
def api_qualys_test_connection(body: QualysTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.username or not body.password or not body.platform_url:
        raise HTTPException(status_code=400, detail="Username, password, and platform URL are all required.")
    _require_safe_target(body.platform_url, "platform_url")
    conn = QualysConnector(body.username, body.password, platform_url=body.platform_url)
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Qualys connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.platform_url}."}


class QualysFetchBody(BaseModel):
    username: str = ""
    password: str = ""
    platform_url: str = ""
    confirm: bool = False


@app.post("/api/qualys/fetch")
def api_qualys_fetch(body: QualysFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch a live Qualys host-detection export.", "written_to": None, "count": None}
    rbac.require_admin(request)
    if not body.username or not body.password or not body.platform_url:
        raise HTTPException(status_code=400, detail="Username, password, and platform URL are all required to fetch live data.")
    _require_safe_target(body.platform_url, "platform_url")
    conn = QualysConnector(body.username, body.password, platform_url=body.platform_url)
    out_path = LIVE_DATA_DIR / "qualys_export.csv"
    try:
        conn.fetch_and_write_csv(out_path)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Qualys export failed: {exc}") from exc
    with out_path.open(encoding="utf-8") as f:
        count = max(sum(1 for _ in f) - 1, 0)
    return {
        "preview_only": False,
        "message": f"Wrote {count} row(s) to remediation/live-data/qualys_export.csv. Run "
                   f"`/remediate remediation/live-data/qualys_export.csv` in an interactive Claude "
                   f"Code session to bring this into the dashboard - see docs/GOING_LIVE.md.",
        "written_to": "remediation/live-data/qualys_export.csv",
        "count": count,
    }


class PrismaCloudTestConnectionBody(BaseModel):
    access_key_id: str = ""
    secret_key: str = ""
    base_url: str = ""


@app.post("/api/prismacloud/test-connection")
def api_prismacloud_test_connection(body: PrismaCloudTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.access_key_id or not body.secret_key or not body.base_url:
        raise HTTPException(status_code=400, detail="Access key ID, secret key, and base URL are all required.")
    _require_safe_target(body.base_url, "base_url")
    conn = PrismaCloudConnector(body.access_key_id, body.secret_key, base_url=body.base_url)
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Prisma Cloud connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.base_url}."}


class PrismaCloudFetchBody(BaseModel):
    access_key_id: str = ""
    secret_key: str = ""
    base_url: str = ""
    confirm: bool = False


@app.post("/api/prismacloud/fetch")
def api_prismacloud_fetch(body: PrismaCloudFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch live Prisma Cloud alerts.", "written_to": None, "count": None}
    rbac.require_admin(request)
    if not body.access_key_id or not body.secret_key or not body.base_url:
        raise HTTPException(status_code=400, detail="Access key ID, secret key, and base URL are all required to fetch live data.")
    _require_safe_target(body.base_url, "base_url")
    conn = PrismaCloudConnector(body.access_key_id, body.secret_key, base_url=body.base_url)
    try:
        findings = conn.fetch_and_normalize_alerts()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Prisma Cloud fetch failed: {exc}") from exc

    # Locked for the full read-existing/assign-ids/write cycle - see
    # live_data_store.with_lock()'s own docstring for why.
    with live_data_store.with_lock():
        existing = live_data_store.load_findings(live_data_store.SOURCE_PRISMACLOUD)
        real_findings = dashboard_data.load_remediation_findings()
        for finding in findings:
            finding["id"] = _next_finding_id_for(real_findings + existing)
            existing.append(finding)
        live_data_store.append_findings(live_data_store.SOURCE_PRISMACLOUD, findings)

    return {
        "preview_only": False,
        "message": f"Wrote {len(findings)} normalized finding(s) to the shared database "
                   f"(remediation/connectors/live_data_store.py). Like the generic ingest adapter's own "
                   f"output, this is deliberately not auto-merged into the live queue - see "
                   f"docs/INTEGRATIONS.md.",
        "written_to": "remediation/quanta.db (source=prismacloud)",
        "count": len(findings),
    }


class CortexXsiamTestConnectionBody(BaseModel):
    api_key: str = ""
    api_key_id: str = ""
    base_url: str = ""


@app.post("/api/cortex-xsiam/test-connection")
def api_cortex_xsiam_test_connection(body: CortexXsiamTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.api_key or not body.api_key_id or not body.base_url:
        raise HTTPException(status_code=400, detail="API key, API key ID, and base URL are all required.")
    _require_safe_target(body.base_url, "base_url")
    conn = CortexXsiamConnector(body.api_key, body.api_key_id, base_url=body.base_url)
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Cortex XSIAM connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.base_url}."}


class CortexXsiamFetchBody(BaseModel):
    api_key: str = ""
    api_key_id: str = ""
    base_url: str = ""
    confirm: bool = False


@app.post("/api/cortex-xsiam/fetch")
def api_cortex_xsiam_fetch(body: CortexXsiamFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch live Cortex XSIAM incidents.", "written_to": None, "count": None}
    rbac.require_admin(request)
    if not body.api_key or not body.api_key_id or not body.base_url:
        raise HTTPException(status_code=400, detail="API key, API key ID, and base URL are all required to fetch live data.")
    _require_safe_target(body.base_url, "base_url")
    conn = CortexXsiamConnector(body.api_key, body.api_key_id, base_url=body.base_url)
    try:
        findings = conn.fetch_and_normalize_incidents()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Cortex XSIAM fetch failed: {exc}") from exc

    # Locked for the full read-existing/assign-ids/write cycle - see
    # live_data_store.with_lock()'s own docstring for why.
    with live_data_store.with_lock():
        existing = live_data_store.load_findings(live_data_store.SOURCE_CORTEX_XSIAM)
        real_findings = dashboard_data.load_remediation_findings()
        for finding in findings:
            finding["id"] = _next_finding_id_for(real_findings + existing)
            existing.append(finding)
        live_data_store.append_findings(live_data_store.SOURCE_CORTEX_XSIAM, findings)

    return {
        "preview_only": False,
        "message": f"Wrote {len(findings)} normalized finding(s) to the shared database "
                   f"(remediation/connectors/live_data_store.py). Like the generic ingest adapter's own "
                   f"output, this is deliberately not auto-merged into the live queue - see "
                   f"docs/INTEGRATIONS.md.",
        "written_to": "remediation/quanta.db (source=cortex-xsiam)",
        "count": len(findings),
    }


class InfobloxTestConnectionBody(BaseModel):
    grid_master: str = ""
    username: str = ""
    password: str = ""


@app.post("/api/infoblox/test-connection")
def api_infoblox_test_connection(body: InfobloxTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.grid_master or not body.username or not body.password:
        raise HTTPException(status_code=400, detail="Grid master, username, and password are all required.")
    _require_safe_target(body.grid_master, "grid_master")
    conn = InfobloxConnector(body.grid_master, body.username, body.password)
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Infoblox connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.grid_master}."}


class InfobloxFetchBody(BaseModel):
    grid_master: str = ""
    username: str = ""
    password: str = ""
    confirm: bool = False


@app.post("/api/infoblox/fetch")
def api_infoblox_fetch(body: InfobloxFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch and reconcile live Infoblox host records.", "matched": None, "unmatched": None, "skipped": None}
    rbac.require_admin(request)
    if not body.grid_master or not body.username or not body.password:
        raise HTTPException(status_code=400, detail="Grid master, username, and password are all required to fetch live data.")
    _require_safe_target(body.grid_master, "grid_master")
    conn = InfobloxConnector(body.grid_master, body.username, body.password)
    try:
        assets = conn.fetch_and_normalize_hosts()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Infoblox fetch failed: {exc}") from exc
    known_names = [a["name"] for a in asset_inventory.build_asset_inventory(dashboard_data.load_remediation_findings())]
    result = asset_inventory.reconcile_pulled_assets(assets, known_names)
    return {
        "preview_only": False,
        "message": f"Fetched {len(assets)} host record(s): {len(result['matched'])} matched an existing asset "
                   f"(ip/mac updated), {len(result['unmatched'])} had no existing findings yet (ip/mac stored, will "
                   f"appear on Asset Inventory once one does), {len(result['skipped'])} skipped.",
        **result,
    }


class AxoniusTestConnectionBody(BaseModel):
    base_url: str = ""
    api_key: str = ""
    api_secret: str = ""


@app.post("/api/axonius/test-connection")
def api_axonius_test_connection(body: AxoniusTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.base_url or not body.api_key or not body.api_secret:
        raise HTTPException(status_code=400, detail="Base URL, API key, and API secret are all required.")
    _require_safe_target(body.base_url, "base_url")
    conn = AxoniusConnector(body.base_url, body.api_key, body.api_secret)
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Axonius connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.base_url}."}


class AxoniusFetchBody(BaseModel):
    base_url: str = ""
    api_key: str = ""
    api_secret: str = ""
    confirm: bool = False


@app.post("/api/axonius/fetch")
def api_axonius_fetch(body: AxoniusFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide real credentials to fetch and reconcile live Axonius device records.", "matched": None, "unmatched": None, "skipped": None}
    rbac.require_admin(request)
    if not body.base_url or not body.api_key or not body.api_secret:
        raise HTTPException(status_code=400, detail="Base URL, API key, and API secret are all required to fetch live data.")
    _require_safe_target(body.base_url, "base_url")
    conn = AxoniusConnector(body.base_url, body.api_key, body.api_secret)
    try:
        assets = conn.fetch_and_normalize_devices()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Axonius fetch failed: {exc}") from exc
    known_names = [a["name"] for a in asset_inventory.build_asset_inventory(dashboard_data.load_remediation_findings())]
    result = asset_inventory.reconcile_pulled_assets(assets, known_names)
    return {
        "preview_only": False,
        "message": f"Fetched {len(assets)} device record(s): {len(result['matched'])} matched an existing asset "
                   f"(ip/mac updated), {len(result['unmatched'])} had no existing findings yet (ip/mac stored, will "
                   f"appear on Asset Inventory once one does), {len(result['skipped'])} skipped.",
        **result,
    }


class ActiveDirectoryTestConnectionBody(BaseModel):
    server: str = ""
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    use_ssl: bool = False


@app.post("/api/active-directory/test-connection")
def api_active_directory_test_connection(body: ActiveDirectoryTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.server or not body.base_dn:
        raise HTTPException(status_code=400, detail="Server and base DN are both required.")
    _require_safe_target(body.server, "server")
    conn = ActiveDirectoryConnector(
        body.server, body.base_dn,
        bind_dn=body.bind_dn or None, bind_password=body.bind_password or None, use_ssl=body.use_ssl,
    )
    try:
        conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Active Directory connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {body.server}."}


class ActiveDirectoryFetchBody(BaseModel):
    server: str = ""
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    use_ssl: bool = False
    confirm: bool = False


@app.post("/api/active-directory/fetch")
def api_active_directory_fetch(body: ActiveDirectoryFetchBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm and provide a real server/base DN to fetch and reconcile live AD computer objects.", "matched": None, "unmatched": None, "skipped": None}
    rbac.require_admin(request)
    if not body.server or not body.base_dn:
        raise HTTPException(status_code=400, detail="Server and base DN are both required to fetch live data.")
    _require_safe_target(body.server, "server")
    conn = ActiveDirectoryConnector(
        body.server, body.base_dn,
        bind_dn=body.bind_dn or None, bind_password=body.bind_password or None, use_ssl=body.use_ssl,
    )
    try:
        assets = conn.fetch_and_normalize_computers()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Active Directory fetch failed: {exc}") from exc
    known_names = [a["name"] for a in asset_inventory.build_asset_inventory(dashboard_data.load_remediation_findings())]
    result = asset_inventory.reconcile_pulled_assets(assets, known_names)
    return {
        "preview_only": False,
        "message": f"Fetched {len(assets)} computer object(s) from Active Directory. AD computer objects carry no "
                   f"ip/mac (see active_directory_connector.py's module docstring), so there is nothing to "
                   f"reconcile into asset_ownership.json from this source alone: {len(result['skipped'])} skipped "
                   f"for that reason. Use Tenable/Qualys/Infoblox/Axonius to establish real ip/mac ground truth.",
        **result,
    }


def _openvas_connector(body):
    if body.hostname:
        _require_safe_target(body.hostname, "hostname")
    return OpenVasConnector(
        hostname=body.hostname or None, port=body.port,
        username=body.username or None, password=body.password or None,
        socket_path=body.socket_path or None,
        **({"scan_config_id": body.scan_config_id} if getattr(body, "scan_config_id", "") else {}),
        **({"scanner_id": body.scanner_id} if getattr(body, "scanner_id", "") else {}),
    )


class OpenVasTestConnectionBody(BaseModel):
    hostname: str = ""
    port: int = 9390
    username: str = ""
    password: str = ""
    socket_path: str = ""


@app.post("/api/openvas/test-connection")
def api_openvas_test_connection(body: OpenVasTestConnectionBody, request: Request):
    rbac.require_admin(request)
    if not body.socket_path and not body.hostname:
        raise HTTPException(status_code=400, detail="Either a hostname or a local socket path is required.")
    if not body.username or not body.password:
        raise HTTPException(status_code=400, detail="Username and password are both required.")
    conn = _openvas_connector(body)
    try:
        result = conn.test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenVAS/GVM connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected (GMP {result.get('gmp_version') or 'unknown version'}).", **result}


class OpenVasScanStartBody(OpenVasTestConnectionBody):
    target_name: str = ""
    hosts: str = ""
    scan_config_id: str = ""
    scanner_id: str = ""
    confirm: bool = False


@app.post("/api/openvas/scan/start")
def api_openvas_scan_start(body: OpenVasScanStartBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm, provide real GVM credentials and at least one "
                                                  "target, and this will launch a real authenticated scan against "
                                                  "the network you name below.", "task_id": None}
    rbac.require_admin(request)
    if not body.username or not body.password:
        raise HTTPException(status_code=400, detail="Username and password are both required.")
    hosts = [h.strip() for h in body.hosts.replace(",", "\n").splitlines() if h.strip()]
    if not hosts:
        raise HTTPException(status_code=400, detail="At least one target host, CIDR range, or hostname is required.")
    conn = _openvas_connector(body)
    try:
        task_id = conn.create_and_start_scan(body.target_name or f"Quanta target ({hosts[0]})", hosts)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenVAS/GVM scan launch failed: {exc}") from exc
    return {
        "preview_only": False,
        "task_id": task_id,
        "message": f"Scan launched against {len(hosts)} target(s) as GVM task {task_id}. A real authenticated "
                   f"network scan can take anywhere from minutes to hours depending on scope - poll status below, "
                   f"then import once it reports Done.",
    }


class OpenVasScanStatusBody(OpenVasTestConnectionBody):
    task_id: str = ""


@app.post("/api/openvas/scan/status")
def api_openvas_scan_status(body: OpenVasScanStatusBody, request: Request):
    rbac.require_admin(request)
    if not body.task_id:
        raise HTTPException(status_code=400, detail="task_id is required.")
    conn = _openvas_connector(body)
    try:
        status = conn.get_task_status(body.task_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenVAS/GVM status check failed: {exc}") from exc
    return {"ok": True, **status}


class OpenVasScanImportBody(OpenVasTestConnectionBody):
    task_id: str = ""
    confirm: bool = False


@app.post("/api/openvas/scan/import")
def api_openvas_scan_import(body: OpenVasScanImportBody, request: Request):
    if not body.confirm:
        return {"preview_only": True, "message": "Check confirm to pull this task's real results into a live export file.", "written_to": None, "count": None}
    rbac.require_admin(request)
    if not body.task_id:
        raise HTTPException(status_code=400, detail="task_id is required.")
    conn = _openvas_connector(body)
    out_path = LIVE_DATA_DIR / "openvas_export.csv"
    try:
        conn.fetch_and_write_csv(out_path, task_id=body.task_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenVAS/GVM result import failed: {exc}") from exc
    with out_path.open(encoding="utf-8") as f:
        count = max(sum(1 for _ in f) - 1, 0)
    return {
        "preview_only": False,
        "message": f"Wrote {count} row(s) to remediation/live-data/openvas_export.csv. Run "
                   f"`/remediate remediation/live-data/openvas_export.csv` in an interactive Claude "
                   f"Code session to bring this into the dashboard - see docs/GOING_LIVE.md.",
        "written_to": "remediation/live-data/openvas_export.csv",
        "count": count,
    }


@app.get("/api/run")
def api_run_get():
    return {
        "audit_log": dashboard_data.load_cli_audit_log_summaries(),
        "default_budget": cli.DEFAULT_MAX_BUDGET_USD,
    }


class RunBody(BaseModel):
    pipeline: str
    fix_or_generate: bool = False
    path: str = "vulnerable-demo-app"
    max_budget_usd: str = cli.DEFAULT_MAX_BUDGET_USD
    confirm: bool = False

    @field_validator("max_budget_usd")
    @classmethod
    def _max_budget_usd_is_a_sane_positive_number(cls, value):
        """Unbounded-consumption guardrail (OWASP LLM Top 10 2026 #6) - this field used
        to flow straight from an unvalidated <input type="text"> to a real subprocess
        arg with zero range/type checking. $500 is a generous ceiling relative to the
        $2.00 default - enough headroom for a real large batch run, not so much that a
        typo or a malicious value turns into an open-ended spend."""
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"max_budget_usd must be a number, got {value!r}") from None
        if not (0 < parsed <= 500):
            raise ValueError(f"max_budget_usd must be between 0 and 500, got {parsed}")
        return value
    # Scopes a "remediate" run to one already-approved finding instead of the full
    # batch pipeline - see cli/quanta.py's remediate_prompt() and
    # .claude/commands/remediate.md's own --finding-id handling. Used by the
    # "Trigger Remediation" button on an approved finding in
    # dashboard/static/js/pages/remediationApprovals.js.
    finding_id: str | None = None

    @field_validator("finding_id")
    @classmethod
    def _finding_id_has_the_expected_shape(cls, value):
        """finding_id is interpolated into a prompt for an agent that can write files."""
        if value is not None and not re.fullmatch(r"(FIND|VULN)-[0-9]+", value):
            raise ValueError("finding_id must look like FIND-123 or VULN-123")
        return value

    @field_validator("path")
    @classmethod
    def _path_stays_inside_the_repository(cls, value):
        """path is interpolated into a prompt for an agent that can edit files and push
        branches: keep it a plain, short, single-token path that resolves inside the
        repository root. (Registered applications record only a Git repository name, not
        a local directory, so the repository root is the only allowed base today.)"""
        if not value or len(value) > 300:
            raise ValueError("path must be between 1 and 300 characters")
        if re.search(r"\s", value) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("path must not contain whitespace or control characters")
        if value.startswith("-"):
            raise ValueError("path must not start with '-'")
        if "\\" in value or re.match(r"[A-Za-z]:", value):
            raise ValueError("path must be a plain relative or absolute POSIX path, without backslashes or drive letters")
        if ".." in value:
            raise ValueError("path must not contain '..'")
        root = Path(cli.REPO_ROOT).resolve()
        target = Path(value)
        resolved = (target if target.is_absolute() else root / target).resolve()
        if resolved != root and root not in resolved.parents:
            raise ValueError("path must be inside the Quanta repository")
        return value


@app.post("/api/run")
def api_run_post(body: RunBody, request: Request):
    if body.pipeline == "scan":
        prompt = cli.scan_prompt(body.path, fix=body.fix_or_generate)
        pipeline_name = "quanta_scan"
    elif body.pipeline == "remediate":
        prompt = cli.remediate_prompt(generate=body.fix_or_generate, finding_id=body.finding_id)
        pipeline_name = "remediate"
    else:
        raise HTTPException(status_code=400, detail="Unknown pipeline selected.")

    dry_run = not body.confirm
    user = None
    governance = ai_governance.load_governance()
    if not dry_run:
        user = rbac.require_admin(request)
        _enforce_ai_usage_limit(user["email"])

    def _record_pipeline_usage(result):
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = {}
        model, usage, total_cost_usd, extraction_ok = ai_usage_log.extract_usage(parsed)
        ai_usage_log.record_usage(user["email"], pipeline_name, model, usage, total_cost_usd, extraction_ok)

    exit_code = cli.run(
        prompt, pipeline_name, dry_run=dry_run, max_budget_usd=body.max_budget_usd,
        model=governance.get("default_model"),
        on_result=_record_pipeline_usage if not dry_run else None,
    )

    if dry_run:
        message = ("Dry run only (nothing was executed, no API usage spent). "
                    "Set confirm to actually run it.")
    elif exit_code == 0:
        message = f"{pipeline_name} run completed. Reload the relevant page to see updated results."
        if body.finding_id:
            approval = remediation_approvals_store.approvals_by_finding().get(body.finding_id)
            if approval:
                try:
                    remediation_approvals_store.mark_remediation_triggered(approval["id"], actor=user["email"])
                    message += f" Approval {approval['id']} marked as remediation-triggered."
                except ValueError as exc:
                    message += f" (Approval status not updated: {exc})"
    else:
        message = f"{pipeline_name} run failed (exit code {exit_code}). Check the audit log for details."

    return {"dry_run": dry_run, "exit_code": exit_code, "message": message}


def _find_any_finding(finding_id):
    """Looks up a finding by ID across both pipelines' output - the remediation
    findings (FIND-N) and the code-scan findings (VULN-N), reshaped into a common
    minimal shape so ai_assist.build_ai_assist_prompt() can treat either uniformly."""
    for f in dashboard_data.load_remediation_findings():
        if f.get("id") == finding_id:
            return f
    vh = dashboard_data.load_quanta_scan_data()
    for f in vh.get("findings", []):
        if f.get("ID") == finding_id:
            return {
                "id": f.get("ID"),
                "title": f.get("Title"),
                "severity": f.get("Severity"),
                "cve": None,
                "asset": {"name": f.get("File"), "type": "source-code"},
                "description": f"{f.get('CWE', '')} finding in {f.get('File', '')}".strip(),
            }
    return None


def _enforce_ai_usage_limit(actor):
    """Real, server-side check - never trusts a client-supplied usage figure - called
    right before every real (confirm=True) AI-spending route below actually spends
    anything. Raises 429 if the admin-configured daily per-user token cap
    (remediation/config/ai_governance.yaml) has already been reached."""
    governance = ai_governance.load_governance()
    exceeded, limit, used = ai_usage_log.would_exceed_limit(actor, governance)
    if exceeded:
        raise HTTPException(
            status_code=429,
            detail=f"Daily AI token limit reached ({used:,}/{limit:,} tokens used today) - "
                    "contact an admin to raise it on the Admin Settings page.",
        )
    return governance


# Unbounded-consumption guardrail (OWASP LLM Top 10 2026 #6): unlike /api/run's
# RunBody.max_budget_usd (client-supplied, now range-validated - see RunBody above),
# AI Assist/AI trend analysis are single, small, per-finding asks, not a batch pipeline
# run - they never accepted a client-supplied budget at all before this, and the
# subprocess call itself never passed --max-budget-usd, relying solely on the daily
# token-limit pre-flight check (_enforce_ai_usage_limit) to bound spend. That check is
# real and enforced (see its own docstring), but it's a per-day ceiling, not a per-call
# one - a fixed, tight per-call cap closes that gap without needing a new client field.
_AI_ASSIST_MAX_BUDGET_USD = "1.00"


def _run_ai_call_and_record_usage(prompt, route, actor, governance):
    """Shared by /api/ai-assist and /api/ai-trend-analysis: calls the real claude CLI
    with the admin-configured model, parses its --output-format json response, records
    real usage (remediation/audit/ai_usage_log.py) regardless of whether extraction
    succeeds, and returns the plain-text response. Uses --output-format json (not the
    "text" this used before AI governance existed) specifically so real usage/cost can
    be read at all - see ai_usage_log.py's own docstring on why that parsing is
    deliberately defensive rather than assuming one fixed schema."""
    try:
        claude_bin = cli.find_claude_binary()
    except cli.ClaudeBinaryNotFound as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    command = [
        claude_bin, "-p", prompt, "--output-format", "json",
        "--max-budget-usd", _AI_ASSIST_MAX_BUDGET_USD,
    ]
    if governance.get("default_model"):
        command += ["--model", governance["default_model"]]

    result = subprocess.run(  # noqa: S603 - fixed binary + a prompt string, no shell
        command, cwd=cli.REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
    )
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"AI call failed: {result.stderr.strip()[:500]}")

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        parsed = {}
    model, usage, total_cost_usd, extraction_ok = ai_usage_log.extract_usage(parsed)
    ai_usage_log.record_usage(actor, route, model, usage, total_cost_usd, extraction_ok)

    response_text = parsed.get("result") if isinstance(parsed, dict) else None
    return response_text if response_text is not None else result.stdout.strip()


class AiAssistBody(BaseModel):
    finding_id: str
    action: str = "explain"
    confirm: bool = False


@app.post("/api/ai-assist")
def api_ai_assist(body: AiAssistBody, request: Request):
    """Same dry-run-preview-by-default / explicit-confirm-to-spend pattern as /api/run
    and /api/servicenow/send: without confirm, this only builds and returns the prompt
    text, at zero cost. With confirm, it calls the real `claude` CLI (same binary
    discovery as cli/quanta.py) and spends real API usage/credits.

    Guardrail (OWASP LLM Top 10 2026 #2/#3 - sensitive info disclosure / excessive
    permissions via inconsistent authorization): the confirm-gated real API call was
    already admin-only, but the free dry-run preview below had no team-scoping check
    at all - a logged-in, team-scoped user could enumerate sequential finding IDs
    (FIND-1, FIND-2, ...) through this endpoint and read another team's finding detail
    in the returned prompt text, bypassing the same team-scoping /api/queue already
    enforces. Reusing _scope_to_team() here (the same real, server-side check every
    other finding-level view uses) closes that gap without inventing new logic."""
    finding = _find_any_finding(body.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {body.finding_id} not found")
    _annotate_finding_teams([finding])
    if not _scope_to_team([finding], rbac.get_current_user(request)):
        raise HTTPException(status_code=404, detail=f"Finding {body.finding_id} not found")
    if body.action not in ai_assist.ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of {ai_assist.ACTIONS}, got {body.action!r}",
        )

    prompt = ai_assist.build_ai_assist_prompt(finding, body.action)

    if not body.confirm:
        return {
            "dry_run": True,
            "prompt": prompt,
            "message": "Preview only (no API call made). Set confirm to actually ask "
                       "the AI - this spends real API usage/credits.",
        }

    user = rbac.require_admin(request)
    governance = _enforce_ai_usage_limit(user["email"])
    response = _run_ai_call_and_record_usage(prompt, "ai-assist", user["email"], governance)
    return {"dry_run": False, "prompt": prompt, "response": response.strip() if isinstance(response, str) else response}


class AiTrendAnalysisBody(BaseModel):
    scope: str
    stats: dict
    confirm: bool = False


@app.post("/api/ai-trend-analysis")
def api_ai_trend_analysis(body: AiTrendAnalysisBody, request: Request):
    """Same dry-run-preview-by-default / explicit-confirm-to-spend pattern as
    /api/ai-assist above - a real Claude Code call over a real, already-computed
    stats snapshot the calling dashboard page passes in (never re-fetched or
    invented server-side), not a fabricated "AI insight". No caching/budget cap here
    either, matching /api/ai-assist - each click is a genuine, confirm-gated spend,
    same as that endpoint."""
    prompt = ai_assist.build_trend_analysis_prompt(body.scope, body.stats)

    if not body.confirm:
        return {
            "dry_run": True,
            "prompt": prompt,
            "message": "Preview only (no API call made). Set confirm to actually ask "
                       "the AI - this spends real API usage/credits.",
        }

    user = rbac.require_admin(request)
    governance = _enforce_ai_usage_limit(user["email"])
    response = _run_ai_call_and_record_usage(prompt, "ai-trend-analysis", user["email"], governance)
    return {"dry_run": False, "prompt": prompt, "response": response.strip() if isinstance(response, str) else response}


@app.get("/api/admin/ai-governance")
def api_get_ai_governance(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return ai_governance.load_governance()


class AiGovernanceBody(BaseModel):
    default_model: str | None = None
    daily_token_limit_per_user: int | None = None
    per_user_overrides: dict[str, int | None] = {}


@app.post("/api/admin/ai-governance")
def api_save_ai_governance(body: AiGovernanceBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        data = ai_governance.save_governance(
            body.default_model, body.daily_token_limit_per_user, body.per_user_overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "AI governance policy saved - takes effect on the next real AI call.", **data}


def _rollup(by_user):
    """Sums a usage_by_user()-shaped dict across every actor into one real total -
    the aggregate row Admin's spend-vs-budget view needs, computed from the same
    per-user figures the table below it already shows (no separate estimate)."""
    return {
        "call_count": sum(u["call_count"] for u in by_user.values()),
        "total_tokens": sum(u["total_tokens"] for u in by_user.values()),
        "total_cost_usd": sum(u["total_cost_usd"] for u in by_user.values()),
        "unknown_cost_calls": sum(u["unknown_cost_calls"] for u in by_user.values()),
    }


@app.get("/api/admin/ai-usage")
def api_get_ai_usage(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Real per-user AI usage totals for the Admin Settings page - every figure comes
    straight from remediation/audit/ai_usage_log.py's own recorded calls, nothing
    computed here. `today_by_user` is the same-shaped subset used for daily-limit
    context (how close each user is to today's cap, if one is configured). `budget`
    is the real aggregate spend/token rollup (today/7d/30d/all-time) plus the actual
    per-call spend cap this app passes to every real Claude Code invocation
    (cli.DEFAULT_MAX_BUDGET_USD) - there is no subscription/invoice concept in this
    app, so this is the only honest "billing" figure there is to show."""
    governance = ai_governance.load_governance()
    now = datetime.datetime.now(datetime.timezone.utc)
    today_start = datetime.datetime.combine(now.date(), datetime.time.min, tzinfo=datetime.timezone.utc)
    since_7d = now - datetime.timedelta(days=7)
    since_30d = now - datetime.timedelta(days=30)
    today_by_user = ai_usage_log.usage_by_user(since=today_start)
    return {
        "all_time_by_user": ai_usage_log.usage_by_user(),
        "today_by_user": today_by_user,
        "governance": governance,
        "recent_calls": ai_usage_log.list_usage(limit=50),
        "budget": {
            "max_cost_usd_per_call": float(cli.DEFAULT_MAX_BUDGET_USD),
            "today": _rollup(today_by_user),
            "last_7_days": _rollup(ai_usage_log.usage_by_user(since=since_7d)),
            "last_30_days": _rollup(ai_usage_log.usage_by_user(since=since_30d)),
            "all_time": _rollup(ai_usage_log.usage_by_user()),
        },
    }


@app.get("/api/admin/users")
def api_list_users(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Real user accounts (never a password hash) - the Admin Settings "Team
    Management" section's data source. A user's `team` here is exactly what
    _scope_to_team() enforces on Queue/Assets/Exceptions/Remediation Approvals."""
    return {"users": auth_users.list_users()}


class CreateUserBody(BaseModel):
    email: str
    password: str
    name: str
    role: str = "user"
    team: str | None = None


@app.post("/api/admin/users")
def api_create_user(body: CreateUserBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return auth_users.create_user(body.email, body.password, body.name, role=body.role, team=body.team)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class SetUserTeamBody(BaseModel):
    team: str | None = None


@app.post("/api/admin/users/{email}/team")
def api_set_user_team(email: str, body: SetUserTeamBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return auth_users.set_team(email, body.team)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


class SetUserRoleBody(BaseModel):
    role: str


@app.post("/api/admin/users/{email}/role")
def api_set_user_role(email: str, body: SetUserRoleBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return auth_users.set_role(email, body.role)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ------------------------------------------------- ownership & assignment (ITSM layer)
#
# Who owns each finding, which team it is routed to, and how far along the owner is -
# plus the admin-side team records and the analytics over all of it. Storage and rules
# live in remediation/assignments/; this section is only the HTTP surface and the access
# checks. Every route here requires a login (assignee emails are personal data, so unlike
# the public-by-default finding reads these never answer an anonymous caller), and every
# finding lookup goes through the caller's team scope, so an out-of-scope finding is
# indistinguishable from one that doesn't exist (404, never 403).

ASSIGNMENT_VIEWS = ("mine", "team", "needs_owner", "unowned", "all")
_PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _explicit_and_known_team_names():
    names = {u["team"] for u in auth_users.list_users() if u.get("team")}
    names.update(t for t in _team_by_asset_name().values() if t)
    return names


def _team_catalog():
    return assignments_store.list_teams(known_team_names=_explicit_and_known_team_names())


def _canonical_team(name):
    """The catalog's own spelling of `name` (case-insensitive), or None if it isn't a
    team that exists. Keeps "platform" and "Platform" from becoming two teams."""
    wanted = (name or "").strip().lower()
    return next((t["name"] for t in _team_catalog() if t["name"].lower() == wanted), None)


def _visible_finding(finding_id, user):
    """The finding with this id as the caller is allowed to see it (team-scoped), or a
    404. Annotated with its routing team."""
    findings = _scope_to_team(
        _annotate_finding_teams(dashboard_data.load_live_queue(), with_assignment=True), user)
    found = next((f for f in findings if f["id"] == finding_id), None)
    if not found:
        raise HTTPException(status_code=404, detail="Finding not found")
    return found


def _assignment_view(a, users_by_email):
    if not a:
        return None
    u = users_by_email.get((a.get("assignee_email") or "").lower())
    return {**a, "assignee_name": (u or {}).get("name")}


@app.get("/api/teams")
def api_list_teams(user: dict = Depends(rbac.require_login)):
    users = auth_users.list_users()
    assignments = assignments_store.load_assignments()
    members, assigned = {}, {}
    for u in users:
        if u.get("team"):
            members[u["team"].lower()] = members.get(u["team"].lower(), 0) + 1
    for a in assignments:
        if a.get("assigned_team") and a["status"] != "resolved":
            assigned[a["assigned_team"].lower()] = assigned.get(a["assigned_team"].lower(), 0) + 1
    teams = _team_catalog()
    if user.get("role") != "admin" and user.get("team"):
        teams = [t for t in teams if t["name"] == user["team"]]
    return {"teams": [
        {**t, "members": members.get(t["name"].lower(), 0), "open_assignments": assigned.get(t["name"].lower(), 0)}
        for t in teams
    ]}


class TeamBody(BaseModel):
    name: str | None = None
    description: str | None = None
    manager_email: str | None = None


def _validated_manager(email):
    email = (email or "").strip().lower()
    if email and not auth_users.find_user(email):
        raise HTTPException(status_code=400, detail=f"Manager {email!r} is not an existing user account")
    return email or None


@app.post("/api/admin/teams")
def api_create_team(body: TeamBody, user: dict = Depends(rbac.require_admin)):
    try:
        return assignments_store.create_team(
            body.name, user["email"], description=body.description, manager_email=_validated_manager(body.manager_email))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.put("/api/admin/teams/{name}")
def api_update_team(name: str, body: TeamBody, user: dict = Depends(rbac.require_admin)):
    try:
        return assignments_store.update_team(
            name, user["email"], description=body.description, manager_email=_validated_manager(body.manager_email))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc


@app.delete("/api/admin/teams/{name}")
def api_delete_team(name: str, user: dict = Depends(rbac.require_admin)):
    key = name.lower()
    in_use = sum(1 for u in auth_users.list_users() if (u.get("team") or "").lower() == key)
    in_use += sum(1 for a in assignments_store.load_assignments()
                  if (a.get("assigned_team") or "").lower() == key and a["status"] != "resolved")
    try:
        return assignments_store.delete_team(name, user["email"], in_use_count=in_use)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc






# --------------------------------------------------------------------------- health + metrics
# Outside /api on purpose: load balancers and orchestrators probe these without a session.
# /healthz = the process is up. /readyz = it can actually serve (database, schema, data).


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    checks, ok = {}, True
    try:
        from sqlalchemy import text
        engine = db_module.get_engine()
        db_module.ensure_schema(engine)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {type(exc).__name__}"
        ok = False
    findings = dashboard_data.REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    checks["findings_file"] = "ok" if findings.exists() else "missing (no data ingested yet)"
    last = integrity_service.last_summary()
    # informational only: integrity warnings never make the instance not-ready (that would restart a pod over a stale lock file)
    checks["integrity"] = ("not checked yet" if last is None else ("ok" if not last["problems"] else f"{last['status']}: {len(last['problems'])} issue(s) - see /api/integrity"))
    checks["scheduler"] = "ok" if (_scheduler_task is not None and not _scheduler_task.done()) else "not running"
    return JSONResponse({"status": "ready" if ok else "not-ready", "checks": checks}, status_code=200 if ok else 503)


class IntegrityHealBody(BaseModel):
    actions: list[str] | None = None
    confirm: bool = False


@app.get("/api/integrity")
def api_integrity(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Code baseline (modified/missing/unexpected files vs the build-time manifest; 'no-baseline' when none exists) plus store consistency checks and the
    safe repairs currently available. Read-only. See docs/INTEGRITY.md."""
    report = integrity_service.full_report()
    report["heal_actions"] = {name: {"title": spec["title"], "why": spec["why"]} for name, spec in integrity_heal.ACTIONS.items()}
    return report


@app.post("/api/integrity/heal")
def api_integrity_heal(body: IntegrityHealBody, user: dict = Depends(rbac.require_admin)):
    """Safe repairs only (stale locks, findings file from .bak, missing tables, file snapshots). Preview unless confirm=true; each executed action is written to
    the activity log. Never deletes customer data."""
    unknown = [a for a in (body.actions or []) if a not in integrity_heal.ACTIONS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown action(s): {', '.join(unknown)}")
    result = integrity_heal.run(actions=body.actions, confirm=body.confirm, actor=user["email"])
    integrity_service.full_report()   # refresh the summary /readyz shows
    return result


@app.get("/metrics")
def metrics(request: Request):
    token = os.environ.get("QUANTA_METRICS_TOKEN", "").strip()
    if not token:
        raise HTTPException(status_code=404, detail="Not found")  # metrics are off unless a token is configured
    import hmac
    if not hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {token}"):
        raise HTTPException(status_code=401, detail="Bad or missing bearer token")
    findings = dashboard_data.load_remediation_findings()
    tickets = support_store.list_tickets(status="open_all", limit=5000)
    conns = conn_store.list_connections()
    gauges = {
        "quanta_findings_total": ("Findings in the system of record", len(findings)),
        "quanta_support_tickets_open": ("Open support tickets", len(tickets)),
        "quanta_support_tickets_sla_breached": ("Open support tickets past their SLA", sum(1 for t in tickets if t["sla"]["breached"])),
        "quanta_connections_total": ("Configured connections", len(conns)),
        "quanta_connections_failing": ("Connections whose last sync failed", sum(1 for c in conns if c["last_status"] == "error")),
        "quanta_scheduler_leader": ("1 if this replica currently holds the scheduler lease", 1 if _leader.is_leader else 0),
        "quanta_jobs_queued": ("Jobs waiting in the queue", job_queue.stats().get("queued", 0)),
        "quanta_jobs_dead": ("Jobs that exhausted their retries", job_queue.stats().get("dead", 0)),
        "quanta_scheduler_alive": ("1 if the notification scheduler task is running", 1 if (_scheduler_task is not None and not _scheduler_task.done()) else 0),
    }
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(observability.metrics_text(gauges), media_type="text/plain; version=0.0.4")



# --------------------------------------------------------------------------- integration API
# How other systems call INTO Quanta: scanners, SOAR playbooks, CI jobs and ticketing systems
# authenticate with a Quanta API key (Authorization: Bearer qk_..., or X-API-Key). Keys are
# issued by an admin, carry scopes, can expire and be revoked, and are stored only as a hash.
# See docs/INTEGRATION_API.md.

_API_KEY_RATE_LIMITER = rate_limit.RateLimiter(int(os.environ.get("QUANTA_API_KEY_RATE_MAX", "600")), 60)
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def _api_key_token(request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def require_api_key(scope):
    def dependency(request: Request):
        rec = apikey_store.verify(_api_key_token(request), scope)
        if not rec:
            raise HTTPException(status_code=401, detail="A valid API key with the required scope is needed",
                                headers={"WWW-Authenticate": "Bearer"})
        if not _API_KEY_RATE_LIMITER.allow(f"key:{rec['id']}"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded for this API key",
                                headers={"Retry-After": str(_API_KEY_RATE_LIMITER.retry_after_seconds(f"key:{rec['id']}"))})
        return rec
    return dependency


class ApiKeyBody(BaseModel):
    name: str
    scopes: list[str]
    expires_days: int | None = None
    team: str | None = None   # optional: binds an `mcp:read` key's results to this team


@app.get("/api/api-keys")
def api_list_api_keys(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"keys": apikey_store.list_keys(), "scopes": list(apikey_store.SCOPES)}


@app.post("/api/api-keys")
def api_create_api_key(body: ApiKeyBody, user: dict = Depends(rbac.require_admin)):
    """Creates a key. The response contains the full key exactly once; it cannot be shown again."""
    try:
        record, token = apikey_store.create(body.name, body.scopes, user["email"], body.expires_days, team=body.team)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"key": token, "record": record, "warning": "Copy this key now. It is not stored and cannot be shown again."}


@app.delete("/api/api-keys/{key_id}")
def api_revoke_api_key(key_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        return {"revoked": apikey_store.revoke(key_id, user["email"])}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such key") from exc


def _enrich_in_background(background):
    def run():
        try:
            from remediation.enrichment import kev_epss
            kev_epss.enrich_file(findings_merge.DEFAULT_PATH)
            file_sync.sync_if_enabled(force=True)
        except Exception:  # noqa: BLE001 - enrichment is best effort
            pass
    background.add_task(run)


class IngestFindingsBody(BaseModel):
    source: str
    findings: list[dict]  # checked one by one, so a bad record is reported by index instead of rejecting the batch
    reconcile: bool = False
    enrich: bool = True


@app.post("/api/ingest/findings")
def api_ingest_findings(body: IngestFindingsBody, background: BackgroundTasks, key: dict = Depends(require_api_key("ingest:write"))):
    """Push findings into the queue. A finding's identity is source + asset + source_ref (or title)
    + CVE, so re-sending updates it instead of adding a duplicate. `reconcile: true` declares this
    request a COMPLETE export for `source`: that source's findings missing from it are removed
    (this is how fixed vulnerabilities leave the queue). Bad records are reported by index and do
    not reject the rest."""
    try:
        api_findings.check_source(body.source)
        findings, errors = api_findings.normalise_batch(body.findings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if body.reconcile and errors:
        raise HTTPException(status_code=400, detail={"message": "reconcile needs every record to be valid; nothing was changed", "errors": errors[:20]})
    result = findings_merge.merge(findings, body.source, reconcile=body.reconcile)
    activity_log.record_activity(f"apikey:{key['name']}", "ingest.findings", body.source,
                                 {"received": len(body.findings), "rejected": len(errors), **result})
    if body.enrich and (result["added"] or result["updated"]):
        _enrich_in_background(background)
    return {"source": body.source, "received": len(body.findings), "rejected": len(errors), "errors": errors[:50], **result}


async def _read_upload(request: Request):
    too_large = HTTPException(status_code=413, detail="File too large (50 MB maximum)")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise too_large
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise too_large
        chunks.append(chunk)
    return b"".join(chunks)


def _ingest_csv_bytes(data, source, reconcile, actor):
    import tempfile
    try:
        api_findings.check_source(source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    fd, tmp = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        Path(tmp).write_bytes(data)
        try:
            findings, skipped = scanner_csv.parse_csv(tmp, source)
        except (UnicodeDecodeError, KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Could not read this as a scanner CSV export: {exc}") from exc
    finally:
        Path(tmp).unlink(missing_ok=True)
    if not findings and not skipped:
        raise HTTPException(status_code=400, detail="The file has no rows. Expected a Tenable-style CSV with a header row (Plugin ID, CVE, Risk, Host, Name, ...).")
    result = findings_merge.merge(findings, source, reconcile=reconcile)
    activity_log.record_activity(actor, "ingest.csv", source, {"rows": len(findings), "skipped": skipped, **result})
    return {"source": source, "parsed": len(findings), "skipped": skipped, **result}


@app.post("/api/ingest/scanner-csv")
async def api_ingest_scanner_csv(request: Request, background: BackgroundTasks, source: str = "scanner", reconcile: bool = False,
                                 key: dict = Depends(require_api_key("ingest:write"))):
    """Upload a scanner export as the raw request body (curl --data-binary @export.csv). Same
    Tenable-style column set the connectors flatten into. `source` names where it came from."""
    out = _ingest_csv_bytes(await _read_upload(request), source, reconcile, f"apikey:{key['name']}")
    if out["added"] or out["updated"]:
        _enrich_in_background(background)
    return out


@app.post("/api/connections/import-file")
async def api_import_file(request: Request, background: BackgroundTasks, source: str = "import", reconcile: bool = False,
                          user: dict = Depends(rbac.require_admin)):
    """The same import for a signed-in admin (the Connections page's file upload), for sources
    that cannot be reached by API: export a CSV from the scanner and drop it in."""
    data = await _read_upload(request)
    if data.lstrip()[:1] == b"{":  # a SARIF file rather than a scanner CSV
        out = _ingest_sarif_bytes(data, source, "", "", reconcile, user["email"])
    else:
        out = _ingest_csv_bytes(data, source, reconcile, user["email"])
    if out["added"] or out["updated"]:
        _enrich_in_background(background)
    return out


def _merge_scanner_findings(findings, source, reconcile, actor, kind, extra=None):
    result = findings_merge.merge(findings, source, reconcile=reconcile)
    activity_log.record_activity(actor, kind, source, {"parsed": len(findings), **(extra or {}), **result})
    return {"source": source, "parsed": len(findings), **(extra or {}), **result}


def _ingest_sarif_bytes(data, source, scan_type, asset, reconcile, actor):
    try:
        api_findings.check_source(source)
        findings, skipped = sarif_ingest.parse(data, source, scan_type=scan_type or None, asset=asset or None)
        runs = sarif_ingest.summarize(data, scan_type=scan_type or None)
    except (ValueError, sarif_ingest.SarifError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not runs:
        raise HTTPException(status_code=400, detail="The SARIF file names no tool, so it cannot be a scan result.")
    for r in runs:  # a clean scan is still evidence that the scan runs
        dso_controls.record_scan_run(asset or None, r["scan_type"], r["tool"], source, r["results"], actor)
    if not findings:
        activity_log.record_activity(actor, "ingest.sarif", source, {"parsed": 0, "clean_scan": True, **skipped})
        return {"source": source, "parsed": 0, "clean_scan": True, "added": 0, "updated": 0, "removed": 0, "skipped": skipped,
                **({"reconcile_note": "A clean scan was recorded; existing findings from this source were not removed. Send reconcile=true with a complete result set to remove fixed ones."} if reconcile else {})}
    return _merge_scanner_findings(findings, source, reconcile, actor, "ingest.sarif", {"skipped": skipped})


@app.post("/api/ingest/sarif")
async def api_ingest_sarif(request: Request, background: BackgroundTasks, source: str = "sarif", scan_type: str = "", asset: str = "",
                           reconcile: bool = False, key: dict = Depends(require_api_key("ingest:write"))):
    """Upload a SARIF 2.1.0 file as the request body: Semgrep, CodeQL, ZAP, Trivy, Checkov, gitleaks, Hadolint and others.
    `scan_type` (sast, dast, sca, secrets, iac, container, cicd) is inferred from the tool when omitted; `asset` names
    the repository or application. `reconcile=true` says this is the complete current result for that source."""
    out = _ingest_sarif_bytes(await _read_upload(request), source, scan_type, asset, reconcile, f"apikey:{key['name']}")
    if out["added"] or out["updated"]:
        _enrich_in_background(background)
    return out


@app.post("/api/ingest/coverage")
async def api_ingest_coverage(request: Request, source: str = "coverage", asset: str = "", fmt: str = "", threshold: float = 60.0,
                              reconcile: bool = True, key: dict = Depends(require_api_key("ingest:write"))):
    """Upload a Cobertura, JaCoCo or lcov report. Only security-relevant files (authentication, cryptography, validation,
    payments...) below `threshold` percent become findings; the response also reports the overall coverage."""
    data = await _read_upload(request)
    try:
        api_findings.check_source(source)
        findings, summary = coverage_ingest.analyse(data.decode("utf-8", "replace"), fmt or None, threshold, source, asset or None)
    except (ValueError, coverage_ingest.CoverageError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    dso_controls.record_scan_run(asset or None, "coverage", "coverage report", source, len(findings), f"apikey:{key['name']}")
    return _merge_scanner_findings(findings, source, reconcile, f"apikey:{key['name']}", "ingest.coverage", {"coverage": summary})


class TicketStatusBody(BaseModel):
    finding_id: str
    system: str = "servicenow"
    state: str
    external_ref: str | None = None


@app.post("/api/inbound/ticket-status")
def api_inbound_ticket_status(body: TicketStatusBody, key: dict = Depends(require_api_key("tickets:update"))):
    """For a ticketing system to report a ticket's state change: ServiceNow (incident state 1-8,
    or a word), Jira (status category or name) or any system sending open / in_progress /
    blocked / resolved. The finding records the ticket and, when it has an assignment, mirrors
    the status. A resolved ticket marks the assignment resolved; the next scan confirms it."""
    if body.system not in ("servicenow", "jira", "other"):
        raise HTTPException(status_code=400, detail="system must be servicenow, jira or other")
    if not any(f["id"] == body.finding_id for f in findings_merge.load()):
        raise HTTPException(status_code=404, detail="No such finding")
    try:
        return conn_links.report_state(body.finding_id, body.system, body.state, f"apikey:{key['name']}", external_ref=body.external_ref)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/export/findings")
def api_export_findings(source: str | None = None, severity: str | None = None, kev: bool | None = None, limit: int = 1000,
                        offset: int = 0, key: dict = Depends(require_api_key("read:findings"))):  # noqa: ARG001
    """Read-only findings export for BI tools and data pipelines, paged and filterable."""
    limit = max(1, min(limit, 5000))
    rows = findings_merge.load()
    if source:
        rows = [f for f in rows if f.get("source") == source]
    if severity:
        rows = [f for f in rows if (f.get("severity") or "").lower() == severity.lower()]
    if kev is not None:
        rows = [f for f in rows if bool((f.get("kev") or {}).get("listed")) == kev]
    return {"total": len(rows), "offset": offset, "limit": limit, "findings": rows[offset:offset + limit]}


@app.get("/api/findings/{finding_id}/links")
def api_finding_links(finding_id: str, user: dict = Depends(rbac.require_login)):
    _visible_finding(finding_id, user)
    return {"links": conn_links.for_finding(finding_id)}


@app.get("/api/connections/schema")
def api_connection_schema(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Machine-readable description of every connection type, as JSON Schema, so an integrator or
    an infrastructure-as-code tool knows exactly what to supply."""
    out = {}
    for item in conn_registry.public_catalog():
        props, required = {}, []
        for f in item["fields"]:
            p = {"type": "boolean" if f["type"] == "checkbox" else "string", "title": f["label"], "writeOnly": bool(f["secret"])}
            if f.get("options"):
                p["enum"] = f["options"]
            if f.get("placeholder"):
                p["examples"] = [f["placeholder"]]
            props[f["name"]] = p
            if f["required"]:
                required.append(f["name"])
        out[item["type"]] = {"title": item["label"], "category": item["category"], "kind": item["kind"], "provides": item["output"],
                             "schema": {"type": "object", "properties": props, "required": required, "additionalProperties": False}}
    return {"types": out}


# --------------------------------------------------------------------------- connections
# Stored connector connections with encrypted credentials and scheduled sync
# (remediation/connections/). Admin only. Credentials are accepted on write and never
# returned; storing them needs QUANTA_ENCRYPTION_KEY, otherwise creation is refused with a
# clear message and the per-request connector pages keep working as before.


class ConnectionBody(BaseModel):
    name: str
    type: str
    values: dict = {}
    enabled: bool = True
    schedule_minutes: int = 0


class ConnectionUpdateBody(BaseModel):
    name: str | None = None
    values: dict | None = None
    enabled: bool | None = None
    schedule_minutes: int | None = None


class ConnectionTestBody(BaseModel):
    type: str
    values: dict = {}
    connection_id: int | None = None


def _conn_error(exc):
    if isinstance(exc, conn_crypto.EncryptionNotConfigured):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail="Connection not found")
    return HTTPException(status_code=400, detail=str(exc))


@app.get("/api/connections")
def api_list_connections(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"connections": conn_store.list_connections(), "catalog": conn_registry.public_catalog(),
            "encryption_available": conn_crypto.available(),
            "min_schedule_minutes": conn_store.MIN_SCHEDULE_MINUTES}


@app.post("/api/connections")
def api_create_connection(body: ConnectionBody, user: dict = Depends(rbac.require_admin)):
    try:
        return conn_store.create(body.name, body.type, body.values, user["email"], enabled=body.enabled,
                                 schedule_minutes=body.schedule_minutes)
    except (ValueError, conn_crypto.EncryptionNotConfigured) as exc:
        raise _conn_error(exc) from exc


@app.put("/api/connections/{connection_id}")
def api_update_connection(connection_id: int, body: ConnectionUpdateBody, user: dict = Depends(rbac.require_admin)):
    try:
        return conn_store.update_connection(connection_id, user["email"], values=body.values, name=body.name,
                                            enabled=body.enabled, schedule_minutes=body.schedule_minutes)
    except (ValueError, KeyError, conn_crypto.EncryptionNotConfigured, conn_crypto.DecryptionFailed) as exc:
        raise _conn_error(exc) from exc


@app.delete("/api/connections/{connection_id}")
def api_delete_connection(connection_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        conn_store.delete_connection(connection_id, user["email"])
    except KeyError as exc:
        raise _conn_error(exc) from exc
    return {"deleted": True}


@app.post("/api/connections/test")
def api_test_connection(body: ConnectionTestBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Checks credentials with the source's cheapest authenticated call. For an existing
    connection, blank secret fields fall back to the stored ones."""
    spec = conn_registry.SPECS.get(body.type)
    if not spec:
        raise HTTPException(status_code=400, detail=f"Unknown connector type {body.type!r}")
    values = dict(body.values)
    if body.connection_id is not None:
        try:
            public, stored = conn_store.get_values(body.connection_id)
        except (conn_crypto.EncryptionNotConfigured, conn_crypto.DecryptionFailed) as exc:
            raise _conn_error(exc) from exc
        if not public:
            raise HTTPException(status_code=404, detail="Connection not found")
        for k, v in stored.items():
            if values.get(k) in (None, ""):
                values[k] = v
    try:
        conn_registry.split_values(body.type, values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        conn_sync.test_connection(body.type, values)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"{spec['label']} connection failed: {exc}") from exc
    return {"ok": True, "message": f"Connected to {spec['label']}."}


@app.post("/api/connections/{connection_id}/sync")
def api_sync_connection(connection_id: int, user: dict = Depends(rbac.require_admin)):
    """Starts a sync in the background and returns at once; poll GET /api/connections for the
    outcome (status, message, count are stored on the connection)."""
    if not conn_store.get_public(connection_id):
        raise HTTPException(status_code=404, detail="Connection not found")
    job_id = job_queue.enqueue(job_worker.KIND_CONNECTION_SYNC, {"connection_id": connection_id, "actor": user["email"]},
                               dedupe_key=f"sync:{connection_id}")
    return {"started": True, "job": job_id}


@app.get("/api/admin/jobs")
def api_jobs(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Queue depth and the most recent jobs, for operators."""
    return {"stats": job_queue.stats(), "recent": job_queue.recent(50), "leader": _leader.is_leader}


# --------------------------------------------------------------------------- support
# In-app helpdesk (remediation/support/). Tickets live in the deployment's own database -
# never a public tracker. ITSM model: priority = impact x urgency, routed to a team queue,
# SLA clocks derived from remediation/config/support_sla.yaml. Three roles per ticket:
#   requester - sees their own ticket and public replies
#   agent     - a member of the team the ticket is routed to: works the queue (reply,
#               internal notes, status, assignee, resolution); cannot change priority,
#               team, or escalate outside the deployment
#   admin     - everything, including priority/team changes, analytics for all teams and
#               optional email escalation to the vendor


class TicketCreateBody(BaseModel):
    kind: str
    subject: str
    description: str
    severity: str = "normal"
    impact: str = "individual"
    finding_id: str | None = None


class TicketCommentBody(BaseModel):
    body: str
    internal: bool = False


class TicketUpdateBody(BaseModel):
    status: str | None = None
    severity: str | None = None
    impact: str | None = None
    team: str | None = None
    assignee_email: str | None = None
    clear_assignee: bool = False
    resolution: str | None = None


class TicketEscalateBody(BaseModel):
    confirm: bool = False


def _ticket_role(ticket, user):
    if user.get("role") == "admin":
        return "admin"
    team = (user.get("team") or "").lower()
    if team and (ticket.get("team") or "").lower() == team:
        return "agent"
    if ticket["requester_email"] == user["email"].lower():
        return "requester"
    return None


def _ticket_or_404(ref_value, user):
    try:
        ticket = support_store.get_ticket(support_store.parse_ref(ref_value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    role = _ticket_role(ticket, user) if ticket else None
    # 404, not 403: a user must not be able to probe which ticket numbers exist
    if not role:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket, role


def _ticket_detail(ticket, role):
    staff = role in ("admin", "agent")
    out = {**ticket, "role": role, "comments": support_store.list_comments(ticket["id"], include_internal=staff)}
    if staff:
        teams_by_name = {t["name"].lower(): t for t in _team_catalog()}
        out["escalation"] = support_escalation.escalation_view(
            ticket, teams_by_name.get((ticket.get("team") or "").lower()), auth_users.list_users())
    return out


def _visible_tickets(user, **filters):
    """Every ticket this user may see: all (admin), else own requests plus their team's queue."""
    if user.get("role") == "admin":
        return support_store.list_tickets(**filters)
    own = support_store.list_tickets(requester_email=user["email"], **filters)
    team = user.get("team")
    queue = support_store.list_tickets(team=team, **filters) if team else []
    seen, merged = set(), []
    for t in own + queue:
        if t["id"] not in seen:
            seen.add(t["id"])
            merged.append(t)
    return sorted(merged, key=lambda t: -t["id"])


@app.post("/api/support/tickets")
def api_create_ticket(body: TicketCreateBody, user: dict = Depends(rbac.require_login)):
    if body.finding_id:
        _visible_finding(body.finding_id.strip(), user)  # 404 for a finding the caller cannot see
    try:
        return support_store.create_ticket(
            user["email"], body.kind, body.subject, body.description, body.severity, impact=body.impact,
            finding_id=body.finding_id, team_names=[t["name"] for t in _team_catalog()])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/support/tickets")
def api_list_tickets(status: str | None = None, mine: bool = False, team: str | None = None, breached: bool | None = None,
                     user: dict = Depends(rbac.require_login)):
    is_admin = user.get("role") == "admin"
    filters = {"status": status, "breached": breached}
    if mine:
        tickets = support_store.list_tickets(requester_email=user["email"], **filters)
    else:
        tickets = _visible_tickets(user, **filters)
    if team:
        tickets = [t for t in tickets if (t.get("team") or "").lower() == team.lower()]
    out = {"tickets": tickets, "is_admin": is_admin, "is_agent": bool(user.get("team")), "team": user.get("team")}
    if is_admin or user.get("team"):
        scope = tickets if is_admin else [t for t in tickets if (t.get("team") or "").lower() == user["team"].lower()]
        out["summary"] = support_store.summary(scope)
    if is_admin:
        out["escalation_configured"] = bool(os.environ.get("QUANTA_SUPPORT_EMAIL")) and email_sender.is_configured()
        out["teams"] = [t["name"] for t in _team_catalog()]
    return out


@app.get("/api/support/analytics")
def api_support_analytics(user: dict = Depends(rbac.require_login)):
    """Admin: the whole desk. A team member: their own team's queue. Anyone else: 403."""
    if user.get("role") == "admin":
        tickets = support_store.list_tickets(limit=5000)
        scope = "all teams"
    elif user.get("team"):
        tickets = support_store.list_tickets(team=user["team"], limit=5000)
        scope = user["team"]
    else:
        raise HTTPException(status_code=403, detail="Support analytics are for team members and admins")
    return {"scope": scope, **support_analytics.compute(tickets)}


@app.get("/api/support/policy")
def api_support_policy(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """The live SLA targets and routing rules, so the UI can show what governs a ticket."""
    return {"sla": support_sla.load_policy(), "routing": support_routing.load_rules()}


@app.get("/api/findings/{finding_id}/tickets")
def api_finding_tickets(finding_id: str, user: dict = Depends(rbac.require_login)):
    _visible_finding(finding_id, user)
    return {"tickets": _visible_tickets(user, finding_id=finding_id)}


@app.get("/api/support/tickets/{ref}")
def api_get_ticket(ref: str, user: dict = Depends(rbac.require_login)):
    ticket, role = _ticket_or_404(ref, user)
    return _ticket_detail(ticket, role)


@app.post("/api/support/tickets/{ref}/comments")
def api_comment_ticket(ref: str, body: TicketCommentBody, user: dict = Depends(rbac.require_login)):
    ticket, role = _ticket_or_404(ref, user)
    internal = body.internal and role in ("admin", "agent")
    try:
        support_store.add_comment(ticket["id"], user["email"], body.body, internal=internal)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ticket_detail(support_store.get_ticket(ticket["id"]), role)


@app.post("/api/support/tickets/{ref}/update")
def api_update_ticket(ref: str, body: TicketUpdateBody, user: dict = Depends(rbac.require_login)):
    ticket, role = _ticket_or_404(ref, user)
    if role not in ("admin", "agent"):
        raise HTTPException(status_code=403, detail="Only the assigned team or an administrator can triage a ticket")
    if role == "agent" and (body.severity is not None or body.impact is not None or body.team is not None):
        raise HTTPException(status_code=403, detail="Priority and team changes need an administrator")
    if body.team:
        canonical = _canonical_team(body.team)
        if not canonical:
            raise HTTPException(status_code=400, detail=f"No team named {body.team!r}")
        body.team = canonical
    try:
        updated = support_store.update_ticket(
            ticket["id"], user["email"], status=body.status, severity=body.severity, impact=body.impact, team=body.team,
            assignee_email=body.assignee_email, clear_assignee=body.clear_assignee, resolution=body.resolution)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ticket_detail(updated, role)


class TicketCsatBody(BaseModel):
    score: int
    comment: str | None = None


@app.post("/api/support/tickets/{ref}/csat")
def api_rate_ticket(ref: str, body: TicketCsatBody, user: dict = Depends(rbac.require_login)):
    ticket, role = _ticket_or_404(ref, user)
    try:
        updated = support_store.rate_ticket(ticket["id"], user["email"], body.score, body.comment)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ticket_detail(updated, role)


class SlaEscalationRunBody(BaseModel):
    confirm: bool = False


def _sla_escalation_inputs():
    tickets = support_store.list_tickets(status="open_all", limit=5000)
    return tickets, {t["name"].lower(): t for t in _team_catalog()}, auth_users.list_users()


@app.post("/api/support/escalations/run")
def api_run_sla_escalations(body: SlaEscalationRunBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Preview (default) or raise the pending SLA alerts: one per ticket per level, to the
    assignee / team manager / admins, emailed only if SMTP is configured."""
    tickets, teams_by_name, users = _sla_escalation_inputs()
    alerts = support_escalation.run(tickets, teams_by_name, users, email_sender, send=body.confirm)
    return {"preview_only": not body.confirm, "alerts": alerts, "smtp_configured": email_sender.is_configured()}


def _run_support_sla_escalations():
    tickets, teams_by_name, users = _sla_escalation_inputs()
    return support_escalation.run(tickets, teams_by_name, users, email_sender, send=True)


@app.post("/api/support/tickets/{ref}/escalate")
def api_escalate_ticket(ref: str, body: TicketEscalateBody, user: dict = Depends(rbac.require_admin)):
    """Optional hand-off to the vendor's support desk by email. Preview by default; sends
    only with confirm=true AND a configured QUANTA_SUPPORT_EMAIL + SMTP relay. Public
    comments only - internal notes never leave the deployment."""
    ticket, _role = _ticket_or_404(ref, user)
    to_addr = os.environ.get("QUANTA_SUPPORT_EMAIL", "").strip()
    comments = support_store.list_comments(ticket["id"], include_internal=False)
    subject = f"[Quanta support {ticket['ref']}] {ticket['subject']}"
    lines = [f"Ticket: {ticket['ref']}", f"Type: {ticket['kind']}   Priority: {ticket.get('priority')}   Severity: {ticket['severity']}",
             f"Requester: {ticket['requester_email']}", "", ticket["description"]]
    for c in comments:
        lines += ["", f"--- {c['author_email']} at {c['created_at']}", c["body"]]
    body_text = chr(10).join(lines)
    if not body.confirm:
        return {"preview_only": True, "to": to_addr or None, "subject": subject, "body": body_text,
                "configured": bool(to_addr) and email_sender.is_configured()}
    if not to_addr:
        raise HTTPException(status_code=400, detail="QUANTA_SUPPORT_EMAIL is not set on this server")
    if not email_sender.is_configured():
        raise HTTPException(status_code=400, detail="SMTP is not configured on this server")
    try:
        email_sender.send_email([to_addr], subject, body_text)
    except Exception as exc:  # delivery failures are surfaced, never swallowed
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}") from exc
    support_store.add_comment(ticket["id"], user["email"], f"Escalated to {to_addr} by email.", internal=True)
    return {"sent": True, "to": to_addr}

@app.get("/api/assignable-users")
def api_assignable_users(user: dict = Depends(rbac.require_login)):
    """Who the caller may assign work to: everyone for an admin, otherwise their own
    team's members (or just themselves if they have no team)."""
    users = auth_users.list_users()
    if user.get("role") != "admin":
        users = [u for u in users if u["email"] == user["email"]
                 or (user.get("team") and u.get("team") == user["team"])]
    return {"users": [{"email": u["email"], "name": u["name"], "team": u.get("team")} for u in users]}


@app.get("/api/assignments")
def api_list_assignments(view: str = "mine", status: str = "", team: str = "", priority: str = "",
                         include_resolved: bool = False, limit: int = 250,
                         user: dict = Depends(rbac.require_login)):
    """The ITSM work queue. `view`: mine (assigned to me), team (routed to my team),
    needs_owner (no individual assignee yet), unowned (no person AND no team), all.
    Counts for every view are returned alongside the rows so the tabs can badge them."""
    if view not in ASSIGNMENT_VIEWS:
        raise HTTPException(status_code=400, detail=f"view must be one of {ASSIGNMENT_VIEWS}")
    limit = max(1, min(limit, 1000))
    findings = _scope_to_team(
        _annotate_finding_teams(dashboard_data.load_live_queue(), with_assignment=True), user)
    by_assignment = assignments_store.assignments_by_finding()
    users_by_email = {u["email"]: u for u in auth_users.list_users()}
    me, my_team = user["email"].lower(), user.get("team")
    counts = dict.fromkeys(ASSIGNMENT_VIEWS, 0)
    rows = []
    for f in findings:
        a = by_assignment.get(f["id"])
        if a and a["status"] == "resolved" and not include_resolved:
            continue
        state = ownership_analytics.ownership_state(f, a)
        eff = ownership_analytics.effective_team(f, a)
        member_of = {
            "mine": bool(a and (a.get("assignee_email") or "") == me),
            "team": bool(my_team and eff == my_team),
            "needs_owner": state != "assigned",
            "unowned": state == "unowned",
            "all": True,
        }
        for v, ok in member_of.items():
            counts[v] += ok
        if not member_of[view]:
            continue
        if status and (a["status"] if a else "unassigned") != status:
            continue
        if team and eff != team:
            continue
        if priority and f.get("priority") != priority:
            continue
        rows.append((f, a, state, eff))
    rows.sort(key=lambda r: (
        0 if (r[0].get("sla") or {}).get("breached") else 1,
        _PRIORITY_ORDER.get(r[0].get("priority"), 9), -(r[0].get("score") or 0), r[0]["id"]))
    total = len(rows)
    return _fast_json({
        "view": view, "counts": counts, "total": total, "truncated": total > limit,
        "rows": [{
            "id": f["id"], "title": f.get("title"), "priority": f.get("priority"), "severity": f.get("severity"),
            "asset": (f.get("asset") or {}).get("name"), "cve": f.get("cve"), "first_seen": f.get("first_seen"),
            "sla": f.get("sla"), "team": eff, "ownership_state": state,
            "assignment": _assignment_view(a, users_by_email),
        } for f, a, state, eff in rows[:limit]],
    })


@app.get("/api/findings/{finding_id}/assignment")
def api_finding_assignment(finding_id: str, user: dict = Depends(rbac.require_login)):
    finding = _visible_finding(finding_id, user)
    users_by_email = {u["email"]: u for u in auth_users.list_users()}
    a = assignments_store.get_assignment(finding_id)
    return {
        "finding_id": finding_id, "team": finding.get("team"),
        "assignment": _assignment_view(a, users_by_email),
        "ownership_state": ownership_analytics.ownership_state(finding, a),
        "history": assignments_store.assignment_history(finding_id),
    }


class AssignBody(BaseModel):
    assignee_email: str | None = None
    team: str | None = None
    notes: str | None = None


def _resolve_assignment_target(body, user):
    """Validates who/where a caller wants to assign to and applies the access rules:
    an admin may assign anyone to any team; a team member only within their own team;
    a user with no team only to themselves. A bare assignee inherits their own team
    (the ITSM default - the work stays with the assignee's group)."""
    is_admin = user.get("role") == "admin"
    assignee = (body.assignee_email or "").strip().lower() or None
    target = None
    if assignee:
        target = auth_users.find_user(assignee)
        if not target:
            raise HTTPException(status_code=400, detail=f"No user account {assignee!r}")
    team = None
    if (body.team or "").strip():
        team = _canonical_team(body.team)
        if not team:
            raise HTTPException(status_code=400, detail=f"No team named {body.team.strip()!r} - create it first")
    elif target:
        team = target.get("team")
    if not is_admin:
        my_team = user.get("team")
        if my_team:
            if team and team != my_team:
                raise HTTPException(status_code=403, detail="You can only assign within your own team")
            if assignee and assignee != user["email"].lower() and (target or {}).get("team") != my_team:
                raise HTTPException(status_code=403, detail="That person is not on your team")
            team = team or my_team
        elif assignee != user["email"].lower() or body.team:
            raise HTTPException(status_code=403, detail="Without a team you can only assign a finding to yourself")
    return assignee, team


@app.post("/api/findings/{finding_id}/assign")
def api_assign_finding(finding_id: str, body: AssignBody, user: dict = Depends(rbac.require_login)):
    _visible_finding(finding_id, user)
    assignee, team = _resolve_assignment_target(body, user)
    try:
        record = assignments_store.assign(finding_id, user["email"], assignee_email=assignee, team=team, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _assignment_view(record, {u["email"]: u for u in auth_users.list_users()})


class AssignmentStatusBody(BaseModel):
    status: str
    notes: str | None = None


def _can_update_status(user, assignment):
    if user.get("role") == "admin":
        return True
    email = user["email"].lower()
    if assignment.get("assignee_email") == email:
        return True
    team = assignment.get("assigned_team")
    if not assignment.get("assignee_email") and team and user.get("team") == team:
        return True
    record = next((t for t in assignments_store.load_teams() if t["name"] == team), None)
    return bool(record and record.get("manager_email") == email)


@app.post("/api/findings/{finding_id}/assignment/status")
def api_set_assignment_status(finding_id: str, body: AssignmentStatusBody, user: dict = Depends(rbac.require_login)):
    _visible_finding(finding_id, user)
    current = assignments_store.get_assignment(finding_id)
    if not current:
        raise HTTPException(status_code=404, detail="That finding isn't assigned yet")
    if not _can_update_status(user, current):
        raise HTTPException(status_code=403, detail="Only the assignee, their team's manager, or an admin can change this")
    try:
        record = assignments_store.set_status(finding_id, body.status, user["email"], notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _assignment_view(record, {u["email"]: u for u in auth_users.list_users()})


@app.delete("/api/findings/{finding_id}/assignment")
def api_unassign_finding(finding_id: str, user: dict = Depends(rbac.require_admin)):
    try:
        assignments_store.unassign(finding_id, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    return {"unassigned": finding_id}


class BulkAssignBody(BaseModel):
    finding_ids: list[str]
    assignee_email: str | None = None
    team: str | None = None
    notes: str | None = None


MAX_BULK_ASSIGN = 2000


@app.post("/api/assignments/bulk")
def api_bulk_assign(body: BulkAssignBody, user: dict = Depends(rbac.require_admin)):
    if not body.finding_ids:
        raise HTTPException(status_code=400, detail="Select at least one finding")
    if len(body.finding_ids) > MAX_BULK_ASSIGN:
        raise HTTPException(status_code=400, detail=f"At most {MAX_BULK_ASSIGN} findings per request")
    assignee, team = _resolve_assignment_target(body, user)
    known = {f["id"] for f in dashboard_data.load_live_queue()}
    unknown = [fid for fid in body.finding_ids if fid not in known]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown finding id(s): {', '.join(unknown[:5])}")
    try:
        n = assignments_store.bulk_assign(body.finding_ids, user["email"], assignee_email=assignee,
                                          team=team, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"assigned": n}


class AutoAssignBody(BaseModel):
    confirm: bool = False


@app.post("/api/assignments/auto-assign")
def api_auto_assign(body: AutoAssignBody, user: dict = Depends(rbac.require_admin)):
    """The assignment rule: route every still-unassigned finding to the team that owns
    its asset. Preview by default (counts only); `confirm: true` applies it. Never
    overwrites an existing assignment."""
    findings = _annotate_finding_teams(dashboard_data.load_live_queue())
    return assignments_store.auto_assign_from_assets(findings, user["email"], dry_run=not body.confirm)


@app.get("/api/analytics/ownership")
def api_ownership_analytics(user: dict = Depends(rbac.require_login)):
    findings = _scope_to_team(
        _annotate_finding_teams(dashboard_data.load_live_queue(), with_assignment=True), user)
    visible_ids = {f["id"] for f in findings}
    assignments = [a for a in assignments_store.load_assignments() if a["finding_id"] in visible_ids]
    users = auth_users.list_users()
    teams = _team_catalog()
    if user.get("role") != "admin" and user.get("team"):
        users = [u for u in users if u.get("team") == user["team"]]
        teams = [t for t in teams if t["name"] == user["team"]]
    return _fast_json(ownership_analytics.ownership_analytics(findings, assignments, users, teams))


@app.get("/api/reports/generate")
def api_generate_report(period: str = "weekly", scope: str = "all", team: str = ""):
    try:
        return reports.generate_report_data(period, dashboard_data, scope=scope, team=team or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/reports/generate.html", response_class=HTMLResponse)
def api_generate_report_html(period: str = "weekly", scope: str = "all", team: str = "", download: bool = False):
    try:
        data = reports.generate_report_data(period, dashboard_data, scope=scope, team=team or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    html_body = reports.render_report_html(data)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="quanta-{period}-report.html"'
    return HTMLResponse(content=html_body, headers=headers)


@app.get("/api/exceptions")
def api_list_exceptions(user: dict = Depends(rbac.get_current_user)):
    exceptions = exceptions_store.list_exceptions_with_status()
    if user is not None and user.get("role") != "admin":
        team_by_finding = _finding_team_by_id(dashboard_data.load_live_queue())
        for e in exceptions:
            e["team"] = team_by_finding.get(e["finding_id"])
        exceptions = _scope_to_team(exceptions, user)
    return {"exceptions": exceptions}


class ExceptionCreateBody(BaseModel):
    finding_id: str
    reason: str
    requested_by: str = ""
    approved_by: str
    expires_on: str


MAX_EXCEPTION_DAYS = 365


@app.post("/api/exceptions")
def api_create_exception(body: ExceptionCreateBody, user: dict = Depends(rbac.require_admin)):
    requested_by = (body.requested_by or "").strip().lower() or user["email"].strip().lower()
    approved_by = (body.approved_by or "").strip().lower()
    if requested_by != user["email"].strip().lower() and not auth_users.find_user(requested_by):
        raise HTTPException(status_code=400, detail=f"requested_by {requested_by!r} is not an existing user account.")
    approver = auth_users.find_user(approved_by) if approved_by else None
    if not approver or approver.get("role") != "admin":
        raise HTTPException(status_code=400, detail="approved_by must be an existing administrator account.")
    if approved_by == requested_by:
        raise HTTPException(status_code=403, detail="Separation of duties: the approver must be a different person from the requester.")
    if body.finding_id not in {f["id"] for f in dashboard_data.load_live_queue()}:
        raise HTTPException(status_code=400, detail=f"No live finding with id {body.finding_id!r}.")
    try:
        expires = datetime.date.fromisoformat(body.expires_on)
    except (TypeError, ValueError):
        expires = None  # the store reports the malformed date with its own message
    if expires and expires > datetime.date.today() + datetime.timedelta(days=MAX_EXCEPTION_DAYS):
        raise HTTPException(status_code=400, detail=f"expires_on cannot be more than {MAX_EXCEPTION_DAYS} days ahead.")
    try:
        record = exceptions_store.create_exception(
            body.finding_id, body.reason, requested_by, approved_by, body.expires_on,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record


@app.post("/api/exceptions/{exception_id}/revoke")
def api_revoke_exception(exception_id: str, user: dict = Depends(rbac.require_admin)):
    try:
        return exceptions_store.revoke_exception(exception_id, revoked_by=user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/assets")
def api_list_assets(user: dict = Depends(rbac.get_current_user)):
    # Shared, short-TTL-cached scoring pipeline (see dashboard_data._load_scored_assets()'s
    # own docstring) - also used by /api/overview and load_live_queue().
    _, cached_rows = dashboard_data._load_scored_assets()
    # Shallow-copy each row before mutating it below - `cached_rows` is the shared
    # cache's own list, and writing `suggestion` directly onto it would leak this
    # route-specific field into every other caller's view of the same cached rows.
    rows = [dict(r) for r in cached_rows]
    # A pattern-matching (not ML - see pattern_recognition.py's module docstring)
    # suggested owner/team for assets that don't have one yet, so the "Edit owner"
    # form isn't always starting from a blank slate. `known` only ever includes
    # already-owned assets - never used to suggest an owner for itself.
    known = [r for r in rows if r.get("owner")]
    for row in rows:
        row["suggestion"] = None if row.get("owner") else pattern_recognition.suggest_owner_team(row, known)
    return _fast_json({"assets": _scope_to_team(rows, user)})


class SearchAskBody(BaseModel):
    query: str


@app.post("/api/search/ask")
def api_search_ask(body: SearchAskBody):
    """Real, deterministic "ask your data" search - no external API call, no LLM, see
    remediation/search/query_engine.py's own module docstring for the full honesty
    rationale. Same no-login-required convention as /api/queue and /api/assets above
    (a read-only query over the same data those already expose without auth)."""
    queue_findings = dashboard_data.load_live_queue()
    vh = dashboard_data.load_quanta_scan_data()
    _, assets = dashboard_data._load_scored_assets()
    return query_engine.answer_query(
        body.query,
        queue_findings=queue_findings,
        quanta_scan_findings=vh.get("findings") if vh.get("available") else [],
        assets=assets,
    )


@app.get("/api/ml-insights/anomalies")
def api_ml_asset_anomalies():
    rows = dashboard_data.load_asset_anomalies()
    anomalies = [r for r in rows if r.get("is_anomaly")]
    anomalies.sort(key=lambda r: r.get("anomaly_score", 0))
    return _fast_json({"anomalies": anomalies, "total_assets": len(rows)})


@app.get("/api/ml-insights/clusters")
def api_ml_finding_clusters():
    tagged, summaries = dashboard_data.load_finding_clusters()
    return _fast_json({"clusters": summaries, "total_findings": len(tagged)})


@app.get("/api/ml-insights/clusters/{cluster_id}/members")
def api_ml_finding_cluster_members(cluster_id: int):
    members, total = dashboard_data.load_finding_cluster_members(cluster_id)
    return _fast_json({"members": members, "total": total})


@app.get("/api/ml-insights/similar/{finding_id}")
def api_ml_similar_findings(finding_id: str):
    return _fast_json({"similar": dashboard_data.find_similar_findings(finding_id)})


@app.get("/api/findings/{finding_id}/control-coverage")
def api_control_coverage(finding_id: str):
    coverage = dashboard_data.get_control_coverage(finding_id)
    if coverage is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _fast_json(coverage)


@app.get("/api/findings/{finding_id}/guidance")
def api_finding_guidance(finding_id: str, user: dict | None = Depends(rbac.get_current_user)):
    """Step-by-step how-to-fix for one finding: curated guidance for its class of problem, tailored with
    what Quanta knows about this finding (package and fixed version, OS, KEV, SLA, the client's own
    controls). See remediation/guidance/engine.py."""
    return _fast_json(guidance_engine.build(_visible_finding(finding_id, user)))


# --------------------------------------------------------------------------- security controls inventory
# Which controls protect which assets (remediation/controls/store.py). Compensating-control advice is only as specific as this.
class ControlBody(BaseModel):
    asset_name: str
    control_class: str
    name: str
    state: str = "claimed"
    detail: str | None = None


class ControlsPushBody(BaseModel):
    source: str = "connector"
    controls: list[dict]


@app.get("/api/controls")
def api_controls(asset: str = "", user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    return {"controls": controls_store.list_controls(asset or None), "classes": controls_store.control_classes()}


@app.post("/api/controls")
def api_add_control(body: ControlBody, user: dict = Depends(rbac.require_admin)):
    try:
        return controls_store.upsert(body.asset_name, body.control_class, body.name, body.state, "manual", user["email"], detail=body.detail)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/controls/{control_id}")
def api_delete_control(control_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if not controls_store.delete_control(control_id):
        raise HTTPException(status_code=404, detail="No such control")
    return {"deleted": True}


@app.post("/api/controls/import")
async def api_import_controls(request: Request, user: dict = Depends(rbac.require_admin)):
    """CSV with asset_name, control_class, name, state (optional), detail (optional)."""
    done, errors = controls_store.import_csv((await _read_upload(request)).decode("utf-8", "replace"), user["email"])
    activity_log.record_activity(user["email"], "controls.import", None, {"imported": done, "rejected": len(errors)})
    return {"imported": done, "errors": errors[:50]}


@app.post("/api/ingest/controls")
def api_ingest_controls(body: ControlsPushBody, key: dict = Depends(require_api_key("controls:write"))):
    """For an EDR, firewall or cloud-posture integration to report the controls it OBSERVES (recorded as verified)."""
    done, errors = 0, []
    for i, c in enumerate(body.controls[:5000]):
        try:
            controls_store.upsert(c.get("asset_name"), c.get("control_class"), c.get("name"), "verified", body.source, f"apikey:{key['name']}", detail=c.get("detail"))
            done += 1
        except (ValueError, AttributeError) as exc:
            errors.append({"index": i, "error": str(exc)})
    activity_log.record_activity(f"apikey:{key['name']}", "controls.push", body.source, {"recorded": done, "rejected": len(errors)})
    return {"recorded": done, "rejected": len(errors), "errors": errors[:50]}


@app.get("/api/findings/{finding_id}/compensating-controls")
def api_finding_compensating_controls(finding_id: str, user: dict | None = Depends(rbac.get_current_user)):
    """Compensating controls for this finding from the ATT&CK mitigations for the techniques it enables, checked against the
    controls recorded for its asset: which are verified, claimed, absent, or unknown."""
    return _fast_json(client_controls.assess(_visible_finding(finding_id, user)))


# --------------------------------------------------------------------------- governance, risk and compliance
# Framework catalogs (built-in subsets, OSCAL import), the risk register, automated control evidence, attestations and policies
# (remediation/grc/). Quanta supplies evidence and workflow; it does not certify compliance. Admin only, except that any signed-in user can read the
# active policies and acknowledge them.
class RiskBody(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    owner: str | None = None
    status: str | None = None
    inherent_likelihood: int | None = None
    inherent_impact: int | None = None
    residual_likelihood: int | None = None
    residual_impact: int | None = None
    treatment: str | None = None
    treatment_plan: str | None = None
    due_date: str | None = None
    review_date: str | None = None


class SuggestionBody(BaseModel):
    source: str
    source_ref: str


class AttestBody(BaseModel):
    result: str
    statement: str
    valid_until: str | None = None


class PolicyBody(BaseModel):
    title: str | None = None
    body: str | None = None
    owner: str | None = None
    status: str | None = None
    review_date: str | None = None


def _grc_context():
    return grc_evidence.Context(dashboard_data.load_live_queue())


def _grc_suggestions():
    analyses = []
    for m in tm_store.list_models():
        try:
            analyses.append(tm_store.analyse(m["id"], dashboard_data.load_live_queue()))
        except Exception:  # noqa: BLE001 - one unreadable model must not hide the other suggestions
            continue
    return grc_risks.suggestions(dashboard_data.load_live_queue(), analyses)


def _run_detection_assessment_if_due():
    """Once a week, record a detection-health snapshot so the trend between runs is real. Skipped when there are no alerts."""
    try:
        latest = hunt_detection.list_assessments(limit=1)
        if latest and (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(latest[0]["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)).days < 7:
            return
        alerts = hunt_store.list_alerts()
        if alerts:
            hunt_detection.save_assessment(hunt_detection.assess(alerts, hunt_detection.list_rules(), dashboard_data.load_live_queue()), "scheduler")
    except Exception:  # noqa: BLE001 - a failed snapshot must never stop the scheduler
        logging.getLogger("quanta.scheduler").exception("detection assessment failed")


def _run_grc_evidence_if_due():
    """Called by the leader's hourly tick: collects control evidence about once a day so the history builds up without anyone remembering."""
    latest = grc_evidence.latest()
    newest = max((r["collected_at"] for r in latest.values()), default="")
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if newest < cutoff:
        grc_evidence.run_all(_grc_context())


def _grc_400(exc):
    return HTTPException(status_code=404, detail=str(exc).strip("'\"")) if isinstance(exc, KeyError) else HTTPException(status_code=400, detail=str(exc))


@app.get("/api/grc/overview")
def api_grc_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    grc_catalog.ensure_builtin()
    latest = grc_evidence.latest()
    counts = {r: sum(1 for t in latest.values() if t["result"] == r) for r in ("pass", "fail", "warn", "na", "error")}
    fws = []
    for f in grc_catalog.list_frameworks():
        rep = grc_report.framework_report(f["id"])
        fws.append({"id": f["id"], "name": f["name"], "source": f["source"], "total": rep["total"], "evidenced_pct": rep["evidenced_pct"], "counts": rep["counts"]})
    risks = grc_risks.list_risks()
    return {"frameworks": fws, "evidence": counts, "evidence_collected_at": max((t["collected_at"] for t in latest.values()), default=None),
            "risks": grc_risks.summary(risks), "policies_needing_attention": sum(1 for p in grc_policies.list_policies() if p["status"] == "active" and (p["review_overdue"]))}


@app.get("/api/grc/frameworks")
def api_grc_frameworks(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    grc_catalog.ensure_builtin()
    return {"frameworks": grc_catalog.list_frameworks()}


@app.post("/api/grc/frameworks/import")
async def api_grc_import(request: Request, id: str, name: str = "", user: dict = Depends(rbac.require_admin)):
    """Upload an OSCAL catalog (NIST publishes SP 800-53 and CSF in this form) as the request body."""
    try:
        n = grc_catalog.import_oscal(id, await _read_upload(request), name or None)
    except (ValueError, grc_catalog.CatalogError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "grc.framework.import", id, {"controls": n})
    return {"id": id, "controls": n}


@app.delete("/api/grc/frameworks/{framework_id}")
def api_grc_delete_framework(framework_id: str, user: dict = Depends(rbac.require_admin)):
    if not grc_catalog.delete_framework(framework_id):
        raise HTTPException(status_code=404, detail="No such framework")
    activity_log.record_activity(user["email"], "grc.framework.delete", framework_id, {})
    return {"deleted": True}


@app.get("/api/grc/frameworks/{framework_id}/report")
def api_grc_report(framework_id: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    grc_catalog.ensure_builtin()
    try:
        return _fast_json(grc_report.framework_report(framework_id))
    except KeyError as exc:
        raise _grc_400(exc) from exc


@app.get("/api/grc/frameworks/{framework_id}/oscal")
def api_grc_oscal(framework_id: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    grc_catalog.ensure_builtin()
    try:
        return JSONResponse(grc_report.to_oscal(framework_id), headers={"Content-Disposition": f'attachment; filename="{framework_id}-assessment-results.json"'})
    except KeyError as exc:
        raise _grc_400(exc) from exc


@app.post("/api/grc/frameworks/{framework_id}/controls/{control_id}/attest")
def api_grc_attest(framework_id: str, control_id: str, body: AttestBody, user: dict = Depends(rbac.require_admin)):
    try:
        grc_report.attest(framework_id, control_id, body.result, body.statement, user["email"], body.valid_until)
    except (ValueError, KeyError) as exc:
        raise _grc_400(exc) from exc
    activity_log.record_activity(user["email"], "grc.attest", f"{framework_id}:{control_id}", {"result": body.result})
    return {"attested": True}


@app.get("/api/grc/evidence")
def api_grc_evidence(test_id: str = "", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if test_id:
        return {"history": grc_evidence.history(test_id)}
    return {"tests": list(grc_evidence.latest().values()), "available": {k: v[0] for k, v in grc_evidence.TESTS.items()}}


@app.post("/api/grc/evidence/run")
def api_grc_run(user: dict = Depends(rbac.require_admin)):
    results = grc_evidence.run_all(_grc_context())
    activity_log.record_activity(user["email"], "grc.evidence.run", None, {"tests": len(results)})
    return {"results": results}


@app.get("/api/grc/risks")
def api_grc_risks(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    risks = grc_risks.list_risks()
    return {"risks": risks, "summary": grc_risks.summary(risks), "suggestions": _grc_suggestions()}


@app.post("/api/grc/risks")
def api_grc_add_risk(body: RiskBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = grc_risks.create(body.model_dump(exclude_none=True), user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "grc.risk.create", str(r["id"]), {"title": r["title"]})
    return r


@app.post("/api/grc/risks/from-suggestion")
def api_grc_from_suggestion(body: SuggestionBody, user: dict = Depends(rbac.require_admin)):
    s = next((x for x in _grc_suggestions() if x["source"] == body.source and x["source_ref"] == body.source_ref), None)
    if not s:
        raise HTTPException(status_code=404, detail="That suggestion is no longer current")
    r = grc_risks.create({k: s[k] for k in ("title", "description", "category", "inherent_likelihood", "inherent_impact")}, user["email"], source=s["source"], source_ref=s["source_ref"])
    activity_log.record_activity(user["email"], "grc.risk.create", str(r["id"]), {"title": r["title"], "from": s["source"]})
    return r


@app.put("/api/grc/risks/{risk_id}")
def api_grc_update_risk(risk_id: int, body: RiskBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = grc_risks.update_risk(risk_id, body.model_dump(exclude_unset=True))
    except (ValueError, KeyError) as exc:
        raise _grc_400(exc) from exc
    activity_log.record_activity(user["email"], "grc.risk.update", str(risk_id), {"status": r["status"]})
    return r


@app.delete("/api/grc/risks/{risk_id}")
def api_grc_delete_risk(risk_id: int, user: dict = Depends(rbac.require_admin)):
    if not grc_risks.delete_risk(risk_id):
        raise HTTPException(status_code=404, detail="No such risk")
    activity_log.record_activity(user["email"], "grc.risk.delete", str(risk_id), {})
    return {"deleted": True}


@app.get("/api/grc/policies")
def api_grc_policies(user: dict = Depends(rbac.require_login)):
    is_admin = user.get("role") == "admin"
    pols = grc_policies.list_policies(users=auth_users.list_users() if is_admin else None)
    if not is_admin:
        pols = [{**p, "acknowledged_by_me": user["email"] in p["acknowledged_by"], "acknowledged_by": []} for p in pols if p["status"] == "active"]
    return {"policies": pols}


@app.post("/api/grc/policies")
def api_grc_add_policy(body: PolicyBody, user: dict = Depends(rbac.require_admin)):
    try:
        p = grc_policies.create(body.title, body.body, body.owner, user["email"], body.status or "draft", body.review_date)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "grc.policy.create", str(p["id"]), {"title": p["title"]})
    return p


@app.put("/api/grc/policies/{policy_id}")
def api_grc_update_policy(policy_id: int, body: PolicyBody, user: dict = Depends(rbac.require_admin)):
    try:
        p = grc_policies.update_policy(policy_id, user["email"], body.title, body.body, body.owner, body.status, body.review_date)
    except (ValueError, KeyError) as exc:
        raise _grc_400(exc) from exc
    activity_log.record_activity(user["email"], "grc.policy.update", str(policy_id), {"version": p["version"]})
    return p


@app.post("/api/grc/policies/{policy_id}/acknowledge")
def api_grc_ack(policy_id: int, user: dict = Depends(rbac.require_login)):
    try:
        grc_policies.acknowledge(policy_id, user["email"])
    except (ValueError, KeyError) as exc:
        raise _grc_400(exc) from exc
    activity_log.record_activity(user["email"], "grc.policy.ack", str(policy_id), {})
    return {"acknowledged": True}


# --------------------------------------------------------------------------- threat models
# Systems described as components, data flows and trust zones; STRIDE rules raise threats; each is joined to live findings and the
# controls inventory (remediation/threatmodel/). A security-team feature: admin only.
class ThreatModelBody(BaseModel):
    name: str | None = None
    description: str | None = None
    model: dict | None = None


class ThreatSeedBody(BaseModel):
    patterns: list[str] = []


class ThreatReviewBody(BaseModel):
    key: str
    status: str
    note: str | None = None


def _tm_404(exc):
    return HTTPException(status_code=404, detail="No such threat model") if isinstance(exc, KeyError) else HTTPException(status_code=400, detail=str(exc))


@app.get("/api/threat-models/rules")
def api_threat_rules(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"stride": tm_rules.STRIDE, "component_types": list(tm_rules.COMPONENT_TYPES), "rules": [
        {k: r[k] for k in ("id", "stride", "applies", "kinds", "title", "controls", "techniques", "cwe", "likelihood", "impact")} for r in tm_rules.RULES]}


@app.get("/api/threat-models")
def api_threat_models(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"models": tm_store.list_models()}


@app.post("/api/threat-models")
def api_create_threat_model(body: ThreatModelBody, user: dict = Depends(rbac.require_admin)):
    try:
        rec = tm_store.create(body.name, body.description, body.model, user["email"])
    except (ValueError, tm_engine.ModelError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "threatmodel.create", rec["name"], {"id": rec["id"]})
    return {"id": rec["id"]}


@app.get("/api/threat-models/{model_id}")
def api_threat_model(model_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return _fast_json(tm_store.analyse(model_id, dashboard_data.load_live_queue()))
    except (KeyError, ValueError) as exc:
        raise _tm_404(exc) from exc


@app.put("/api/threat-models/{model_id}")
def api_update_threat_model(model_id: int, body: ThreatModelBody, user: dict = Depends(rbac.require_admin)):
    try:
        tm_store.update_model(model_id, user["email"], body.name, body.description, body.model)
    except (KeyError, ValueError, tm_engine.ModelError) as exc:
        raise _tm_404(exc) from exc
    activity_log.record_activity(user["email"], "threatmodel.update", str(model_id), {})
    return {"updated": True}


@app.delete("/api/threat-models/{model_id}")
def api_delete_threat_model(model_id: int, user: dict = Depends(rbac.require_admin)):
    if not tm_store.delete_model(model_id):
        raise HTTPException(status_code=404, detail="No such threat model")
    activity_log.record_activity(user["email"], "threatmodel.delete", str(model_id), {})
    return {"deleted": True}


@app.post("/api/threat-models/{model_id}/seed")
def api_seed_threat_model(model_id: int, body: ThreatSeedBody, user: dict = Depends(rbac.require_admin)):
    """Adds draft components (marked inferred) for the assets in the findings, optionally only those matching name patterns.
    Components already in the model are left alone."""
    rec = tm_store.get(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="No such threat model")
    draft = tm_seed.from_findings(dashboard_data.load_live_queue(), body.patterns or None)
    model = rec["model"]
    have = {c["id"] for c in model.get("components", [])}
    added = [c for c in draft["components"] if c["id"] not in have]
    model["components"] = model.get("components", []) + added
    model["data_flows"] = model.get("data_flows", []) + [f for f in draft["data_flows"] if f["to"] in {c["id"] for c in added} or f["from"] not in have]
    zones = {z["id"] for z in model.get("trust_zones", [])}
    model["trust_zones"] = model.get("trust_zones", []) + [z for z in draft["trust_zones"] if z["id"] not in zones]
    try:
        tm_store.update_model(model_id, user["email"], model=model)
    except (ValueError, tm_engine.ModelError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"added": len(added)}


@app.post("/api/threat-models/{model_id}/review")
def api_review_threat(model_id: int, body: ThreatReviewBody, user: dict = Depends(rbac.require_admin)):
    try:
        tm_store.set_review(model_id, body.key, body.status, body.note, user["email"])
    except (KeyError, ValueError) as exc:
        raise _tm_404(exc) from exc
    activity_log.record_activity(user["email"], "threatmodel.review", f"{model_id}:{body.key}", {"status": body.status})
    return {"reviewed": True}


# --------------------------------------------------------------------------- AI usage analytics
# Organization-wide AI usage: spend and tokens by team, application and model, budgets, unusual days, and AI applications nobody
# reviewed. Counts only; no prompt or response text is ever stored. Admin only. See remediation/aiusage/.
class AiBudgetBody(BaseModel):
    scope: str = "org"
    scope_value: str | None = None
    period: str = "month"
    limit_usd: float | None = None
    limit_tokens: int | None = None
    alert_pct: int = 80


class AiAppBody(BaseModel):
    name: str | None = None
    domain: str | None = None
    status: str = "unreviewed"
    owner: str | None = None
    note: str | None = None


class AiUsageBody(BaseModel):
    source: str = "api"
    events: list[dict]


@app.get("/api/ai-usage/summary")
def api_ai_usage_summary(days: int = 30, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return _fast_json(ai_analytics.summary(days=max(1, min(days, 365))))


@app.post("/api/ai-usage/budgets")
def api_ai_add_budget(body: AiBudgetBody, user: dict = Depends(rbac.require_admin)):
    try:
        return {"id": ai_analytics.add_budget(body.scope, body.scope_value, body.period, body.limit_usd, body.limit_tokens, body.alert_pct, user["email"])}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/ai-usage/budgets/{budget_id}")
def api_ai_delete_budget(budget_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if not ai_analytics.delete_budget(budget_id):
        raise HTTPException(status_code=404, detail="No such budget")
    return {"deleted": True}


@app.get("/api/ai-usage/apps")
def api_ai_apps(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"apps": ai_discovery.list_apps(), "known_services": len(ai_discovery.services())}


@app.post("/api/ai-usage/apps")
def api_ai_add_app(body: AiAppBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return {"id": ai_discovery.add_app(body.name, body.domain, status=body.status)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.put("/api/ai-usage/apps/{app_id}")
def api_ai_set_app(app_id: int, body: AiAppBody, user: dict = Depends(rbac.require_admin)):
    try:
        ai_discovery.set_status(app_id, body.status, body.owner, body.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such application") from exc
    activity_log.record_activity(user["email"], "ai.app.status", str(app_id), {"status": body.status})
    return {"updated": True}


@app.post("/api/ai-usage/discovery")
async def api_ai_discovery(request: Request, source: str = "proxy-log", user: dict = Depends(rbac.require_admin)):
    """Upload a proxy, DNS or CASB export (CSV with domain[,user,count] or any text log). Known AI services found become
    applications to review."""
    try:
        found = ai_discovery.parse_log((await _read_upload(request)).decode("utf-8", "replace"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    out = ai_discovery.record(found, source[:60])
    activity_log.record_activity(user["email"], "ai.discovery", source, out)
    return out


@app.post("/api/ingest/ai-usage")
def api_ingest_ai_usage(body: AiUsageBody, key: dict = Depends(require_api_key("ai-usage:write"))):
    """Events from a gateway, proxy or script: {model, input_tokens, output_tokens, ts, team, application, user_ref, cost_usd, ...}.
    Counts only. Re-sending an event_key updates it."""
    try:
        out = ai_store.record(body.events, "gateway" if body.source == "gateway" else "api")
    except ai_store.UsageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(f"apikey:{key['name']}", "ai.usage.push", body.source, {k: out[k] for k in ("recorded", "updated", "rejected")})
    return out


@app.post("/api/ingest/otlp/v1/traces")
async def api_ingest_otlp(request: Request, key: dict = Depends(require_api_key("ai-usage:write"))):
    """OpenTelemetry GenAI spans, OTLP/HTTP JSON (set OTEL_EXPORTER_OTLP_PROTOCOL=http/json). Non-AI spans are ignored."""
    try:
        events = ai_otlp.parse_traces(json.loads((await _read_upload(request)) or b"{}"))
        out = ai_store.record(events, "otel")
    except (ValueError, ai_store.UsageError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"partialSuccess": {"rejectedSpans": out["rejected"]}, **out}


@app.get("/api/guidance")
def api_guidance_lookup(cwe: str = "", title: str = "", description: str = "", scan_type: str = "", file: str = "",
                        fix_hint: str = "", severity: str = "", auto_fixable: str = ""):
    """The same guidance for a finding that is not in the queue, such as a row from the code scan report
    (/quanta-scan), identified by its CWE, title and file."""
    finding = {"cwe": cwe, "title": title[:300], "description": description[:2000], "file": file[:300], "recommended_fix": fix_hint[:2000],
               "severity": severity, "auto_fixable": auto_fixable, "scan_type": scan_type or "sast", "asset": {}}
    return _fast_json(guidance_engine.build(finding, client_controls=False))


@app.get("/api/assets/{asset_name}/network-path")
def api_network_path(asset_name: str):
    return _fast_json(dashboard_data.get_network_path(asset_name))


class AssetOwnerBody(BaseModel):
    owner: str = ""
    team: str = ""


@app.post("/api/assets/{asset_name}/owner")
def api_set_asset_owner(asset_name: str, body: AssetOwnerBody, user: dict = Depends(rbac.require_login)):
    _require_asset_write(asset_name, user)
    return asset_inventory.set_owner(asset_name, body.owner, body.team, actor=user["email"])


class AssetFacingBody(BaseModel):
    facing: str


@app.post("/api/assets/{asset_name}/facing")
def api_set_asset_facing(asset_name: str, body: AssetFacingBody, user: dict = Depends(rbac.require_login)):
    _require_asset_write(asset_name, user)
    try:
        return asset_inventory.set_facing(asset_name, body.facing, actor=user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class AssetEnvironmentBody(BaseModel):
    environment: str


@app.post("/api/assets/{asset_name}/environment")
def api_set_asset_environment(asset_name: str, body: AssetEnvironmentBody, user: dict = Depends(rbac.require_login)):
    _require_asset_write(asset_name, user)
    try:
        return asset_inventory.set_environment(asset_name, body.environment, actor=user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class AssetNetworkInfoBody(BaseModel):
    ip: str = ""
    mac: str = ""


@app.post("/api/assets/{asset_name}/network-info")
def api_set_asset_network_info(asset_name: str, body: AssetNetworkInfoBody, user: dict = Depends(rbac.require_login)):
    _require_asset_write(asset_name, user)
    try:
        return asset_inventory.set_network_info(asset_name, body.ip, body.mac, actor=user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class AssetRemediationScheduleBody(BaseModel):
    cadence: str | None = None
    maintenance_window: dict | None = None


@app.post("/api/assets/{asset_name}/remediation-schedule")
def api_set_asset_remediation_schedule(asset_name: str, body: AssetRemediationScheduleBody, user: dict = Depends(rbac.require_login)):
    _require_asset_write(asset_name, user)
    try:
        return asset_inventory.set_remediation_schedule(
            asset_name, body.cadence, body.maintenance_window, actor=user["email"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class CmdbImportPreviewBody(BaseModel):
    csv_text: str
    column_mapping: dict | None = None


@app.post("/api/assets/cmdb-import/preview")
def api_cmdb_import_preview(body: CmdbImportPreviewBody):
    """Read-only - parses and reconciles the uploaded CSV against the real,
    finding-derived asset list but writes nothing. See cmdb_import.py's module
    docstring for why this is CSV, not a fabricated .xlsx binary parser."""
    headers, rows = cmdb_import.parse_csv_text(body.csv_text)
    mapping = body.column_mapping or cmdb_import.suggest_column_mapping(headers)
    known_names = [a["name"] for a in asset_inventory.build_asset_inventory(dashboard_data.load_remediation_findings())]
    reconciled = cmdb_import.reconcile_rows(rows, mapping, known_names)
    return {"headers": headers, "column_mapping": mapping, **reconciled}


class CmdbImportApplyBody(BaseModel):
    entries: list[dict]


@app.post("/api/assets/cmdb-import/apply")
def api_cmdb_import_apply(body: CmdbImportApplyBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    _validate_cmdb_entries(body.entries)
    return cmdb_import.apply_import(body.entries)


@app.get("/api/asset-policy")
def api_get_asset_policy():
    return {"rules_text": dashboard_data.load_asset_policy_text()}


class AssetPolicyRulesBody(BaseModel):
    rules_text: str


@app.post("/api/asset-policy")
def api_save_asset_policy(body: AssetPolicyRulesBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_asset_policy_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {"message": "Asset policy rules saved. Use Preview & Apply below to run them against the current real asset inventory."}


@app.post("/api/asset-policy/preview")
def api_preview_asset_policy(body: AssetPolicyRulesBody):
    """Read-only: which REAL assets each rule in the submitted (not-yet-saved) YAML
    text would match, and what it would set - writes nothing. Same
    preview-before-you-commit pattern as /api/exploit-criteria/preview."""
    try:
        return {"rules": dashboard_data.preview_asset_policy(body.rules_text)}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc


@app.post("/api/asset-policy/apply")
def api_apply_asset_policy(user: dict = Depends(rbac.require_admin)):
    """Applies the real, currently-SAVED asset_policy_rules.yaml (not an unsaved edit -
    save first, then apply) against the current real asset inventory. Every changed
    field is written through asset_inventory.py's own real setters and recorded in the
    real activity log with this admin as the actor."""
    return dashboard_data.apply_asset_policy(actor=user["email"])


@app.get("/api/activity-log")
def api_activity_log(actor: str | None = None, action: str | None = None, limit: int = 500):
    """Real, unified who/what/when feed (remediation/audit/activity_log.py) - every
    asset edit, exception revocation, approval decision, login attempt, bulk-policy
    apply, and remediation trigger elsewhere in this app writes here. `limit` defaults
    to 500 (newest first) so a long-running demo doesn't ship an unbounded response."""
    return {"entries": activity_log.list_activity(actor=actor, action=action, limit=limit)}


@app.get("/api/activity-log/insights")
def api_activity_log_insights():
    return dashboard_data.load_activity_insights()


@app.get("/api/risk/attack-heatmap")
def api_risk_attack_heatmap():
    queue = dashboard_data.load_live_queue()
    return {"heatmap": build_attack_heatmap(queue)}


@app.get("/api/risk/blast-radius")
def api_risk_blast_radius():
    """Real per-asset Blast Radius scoring (remediation/enrichment/blast_radius.py) -
    reuses the same shared, cached scored-asset rows as /api/assets/Overview (see
    dashboard_data._load_scored_assets()'s own docstring), so kev_count/likelihood_score
    are already real and computed, not re-derived here. `profiling_coverage` is a
    static, honest disclosure of what this actually measures - render it, don't bury
    it in a footnote."""
    _, scored_assets = dashboard_data._load_scored_assets()
    scored = blast_radius.score_blast_radius(scored_assets)
    immediate_risks = blast_radius.cross_reference_immediate_risks(scored)
    return {
        "assets": scored,
        "immediate_risks": immediate_risks,
        "profiling_coverage": blast_radius.PROFILING_COVERAGE,
    }


@app.get("/api/ai-vulnerabilities")
def api_ai_vulnerabilities():
    """Real findings tagged against the AI/ML vulnerability taxonomy (illustrative
    MITRE ATLAS cross-reference - see ai_vuln_taxonomy.py's module docstring), plus
    the full taxonomy reference (summary/remediation per category) regardless of
    whether any finding matched it. Checks both pipelines' findings: the remediation
    queue (Tenable/Armis-style asset scanning - never AI/ML-specific) and /quanta-scan's
    own SAST findings, where vulnerable-demo-app/ai_assistant.py's genuinely planted
    AI/ML issues (hardcoded LLM key, insecure model deserialization, prompt injection,
    excessive agency) actually live."""
    remediation_findings = dashboard_data.load_remediation_findings()
    vh = dashboard_data.load_quanta_scan_data()
    # quanta_scan findings come from a parsed markdown table (capitalized column names:
    # "Title", not "title") - normalize just the two fields map_finding_to_ai_vuln()
    # actually reads, rather than changing that function's contract for one caller.
    quanta_scan_findings = [
        {"id": f.get("ID"), "title": f.get("Title", ""), "description": ""}
        for f in (vh.get("findings") or [])
    ] if vh.get("available") else []
    findings = tag_ai_vulnerabilities(remediation_findings + quanta_scan_findings)
    return {"vulnerabilities": AI_VULNERABILITIES, "heatmap": build_ai_atlas_heatmap(findings)}


@app.get("/api/quantum-readiness")
def api_quantum_readiness():
    """Real findings already tagged by remediation/enrichment/quantum_readiness.py
    (via load_live_queue()'s content-enrichment pass) whose title names classical
    asymmetric crypto (RSA/ECDSA/Diffie-Hellman - the genuinely quantum-relevant case)
    or a legacy TLS/cipher weakness. Every finding here is real, already-normalized
    data - nothing generated for this endpoint specifically."""
    scored = dashboard_data.load_live_queue()
    matched = [f for f in scored if f.get("quantum_readiness")]
    asymmetric = [f for f in matched if f["quantum_readiness"]["category"] == "asymmetric-crypto"]
    legacy = [f for f in matched if f["quantum_readiness"]["category"] == "legacy-protocol"]
    return {
        "findings": matched,
        "summary": {
            "total": len(matched),
            "asymmetric_crypto": len(asymmetric),
            "legacy_protocol": len(legacy),
        },
        "nist_ir_8547": {
            "deprecated_by": quantum_readiness.NIST_IR_8547_DEPRECATED_BY,
            "disallowed_by": quantum_readiness.NIST_IR_8547_DISALLOWED_BY,
        },
    }


class GenericIngestBody(BaseModel):
    findings: list[dict]


@app.post("/api/ingest/generic")
def api_ingest_generic(body: GenericIngestBody, request: Request):
    """The vendor-agnostic 'bring your own XDR/EDR/SIEM' webhook receiver - see
    remediation/connectors/generic_connector.py's module docstring for why this is a
    generic validated-payload adapter rather than N bespoke vendor connectors.
    Deliberately does NOT merge into remediation/output/normalized-findings.json or
    the live queue - consistent with how live Tenable/Armis connector output also
    isn't auto-merged (see KNOWLEDGE_TRANSFER.md); it writes to the shared
    remediation/quanta.db (see remediation/connectors/live_data_store.py), same
    "pending review, not auto-merged" status as those.

    Deliberately NOT gated behind session login, unlike the mutation routes below -
    this is a machine-to-machine webhook receiver a SIEM/XDR would call directly, not
    something a logged-in browser session submits. A real deployment should protect it
    with a webhook-specific API key or HMAC request signature instead of cookie auth -
    that's a real follow-up, not implemented here. Being unauthenticated also means
    there's no cap on how often it's called or how much data it can accumulate - a
    real deployment needs request throttling/a size cap alongside the auth mentioned
    above, not implemented here either."""
    if rbac.production_enabled():
        # in a production deployment this webhook is no longer open: it needs an ingest:write API key
        require_api_key("ingest:write")(request)
    # Locked for the full read-existing/assign-ids/write cycle: two concurrent
    # ingests could otherwise both compute the same "next" FIND-N id from the same
    # stale read and collide - see live_data_store.with_lock()'s own docstring.
    with live_data_store.with_lock():
        existing = live_data_store.load_findings(live_data_store.SOURCE_GENERIC_INGEST)

        # IDs continue from the real pipeline's FIND-N sequence (not just this
        # source's own), even though this data isn't merged into the queue - so an
        # ingested finding's ID never collides with a real one if this ever does get
        # merged later.
        real_findings = dashboard_data.load_remediation_findings()

        accepted = []
        rejected = []
        for i, payload in enumerate(body.findings):
            errors = validate_generic_payload(payload)
            if errors:
                rejected.append({"index": i, "errors": errors})
                continue
            finding = normalize_generic_finding(payload, real_findings + existing + accepted)
            accepted.append(finding)

        live_data_store.append_findings(live_data_store.SOURCE_GENERIC_INGEST, accepted)

    return {"accepted": len(accepted), "rejected": rejected, "findings": accepted}


# ---------------------------------------------------------------------------
# Auth - local login MVP + OIDC-ready SSO. See dashboard/auth/__init__.py for the full
# design (PBKDF2 password hashing, signed-cookie sessions, the OIDC client) and the
# scope decision on which routes above actually require login (Depends(rbac.require_*)
# or an inline rbac.require_*(request) call on the confirm=True branch only).
# ---------------------------------------------------------------------------

class LoginBody(BaseModel):
    email: str
    password: str


# Failed sign-ins only: a successful sign-in never uses up the quota. One limiter per account-from-an-address (guessing one
# password list) and one per address (trying many accounts), so neither a single account nor a single source can be ground down.
_LOGIN_FAIL_PER_ACCOUNT = rate_limit.RateLimiter(
    max_requests=int(os.environ.get("QUANTA_LOGIN_FAIL_MAX", "8")),
    window_seconds=int(os.environ.get("QUANTA_LOGIN_FAIL_WINDOW_SECONDS", "600")),
)
_LOGIN_FAIL_PER_ADDRESS = rate_limit.RateLimiter(
    max_requests=int(os.environ.get("QUANTA_LOGIN_FAIL_ADDRESS_MAX", "40")),
    window_seconds=int(os.environ.get("QUANTA_LOGIN_FAIL_WINDOW_SECONDS", "600")),
)


@app.post("/api/auth/login")
def api_auth_login(body: LoginBody, request: Request, response: Response):
    ip = _client_ip(request)
    account_key = f"{ip}|{(body.email or '').strip().lower()}"
    if _LOGIN_FAIL_PER_ACCOUNT.blocked(account_key) or _LOGIN_FAIL_PER_ADDRESS.blocked(ip):
        wait = max(_LOGIN_FAIL_PER_ACCOUNT.retry_after_seconds(account_key), _LOGIN_FAIL_PER_ADDRESS.retry_after_seconds(ip), 1)
        login_audit.record_login_attempt(body.email, success=False)
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again later.", headers={"Retry-After": str(wait)})
    user = auth_users.verify_login(body.email, body.password)
    if not user:
        _LOGIN_FAIL_PER_ACCOUNT.record(account_key)
        _LOGIN_FAIL_PER_ADDRESS.record(ip)
        login_audit.record_login_attempt(body.email, success=False)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    _LOGIN_FAIL_PER_ACCOUNT.reset(account_key)
    login_audit.record_login_attempt(body.email, success=True)
    cookie_value = sessions.create_session_cookie(user, rbac.SESSION_SECRET)
    response.set_cookie(
        rbac.SESSION_COOKIE_NAME, cookie_value, httponly=True, samesite="lax", secure=_cookie_secure(request),
        max_age=sessions.DEFAULT_MAX_AGE_SECONDS,
    )
    return {"user": user}


@app.post("/api/auth/logout")
def api_auth_logout(response: Response):
    response.delete_cookie(rbac.SESSION_COOKIE_NAME)
    return {"message": "Logged out."}


@app.get("/api/auth/me")
def api_auth_me(request: Request):
    return {"user": rbac.get_current_user(request)}


class ChangePasswordBody(BaseModel):
    new_password: str


@app.post("/api/auth/change-password")
def api_auth_change_password(body: ChangePasswordBody, user: dict = Depends(rbac.require_login)):
    try:
        auth_users.set_password(user["email"], body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Password changed."}


@app.get("/api/auth/oidc/config")
def api_auth_oidc_config():
    """Tells the login page whether to show a "Sign in with SSO" button at all - see
    oidc.py's module docstring for why this stays disabled until a real provider's
    credentials are configured via environment variables."""
    configured = oidc.is_configured()
    return {"enabled": configured, "provider_name": oidc.provider_name() if configured else None}


@app.get("/api/directory/status")
def api_directory_status():
    """Tells the Remediation Approvals page whether AD group-membership validation is
    actually available - see ad_directory.py's module docstring for why this stays
    disabled (read-only, never fabricated as validated) until a real AD_SERVER/
    AD_BASE_DN are configured via environment variables."""
    return {"configured": ad_directory.is_configured()}


# state -> (PKCE code_verifier, expiry), in-memory only. Fine for a single-process dev
# server; a real multi-worker deployment needs this in a shared store (Redis, a DB row)
# instead. Entries expire after 10 minutes and the dict is capped at 1000 entries.
_oidc_pending_logins = {}
OIDC_PENDING_TTL_SECONDS = 600
OIDC_PENDING_MAX = 1000
OIDC_STATE_COOKIE = "quanta_oidc_state"
OIDC_GENERIC_ERROR = "Sign-in failed. Try again or contact your administrator."


def _oidc_prune_pending(now=None):
    now = now if now is not None else time.time()
    for st in [k for k, (_, exp) in _oidc_pending_logins.items() if exp <= now]:
        _oidc_pending_logins.pop(st, None)
    while len(_oidc_pending_logins) >= OIDC_PENDING_MAX:  # dicts keep insertion order: drop the oldest
        _oidc_pending_logins.pop(next(iter(_oidc_pending_logins)))


@app.get("/api/auth/oidc/login")
def api_auth_oidc_login(request: Request):
    if not oidc.is_configured():
        raise HTTPException(status_code=503, detail="OIDC is not configured on this server.")
    _oidc_prune_pending()
    state = secrets.token_urlsafe(24)
    verifier, challenge = oidc.generate_pkce_pair()
    _oidc_pending_logins[state] = (verifier, time.time() + OIDC_PENDING_TTL_SECONDS)
    redirect = RedirectResponse(oidc.build_authorize_url(state, challenge))
    # Binds the state to this browser: the callback must present the same value back.
    redirect.set_cookie(OIDC_STATE_COOKIE, state, httponly=True, samesite="lax", secure=_cookie_secure(request),
                        max_age=OIDC_PENDING_TTL_SECONDS)
    return redirect


@app.get("/api/auth/oidc/callback")
def api_auth_oidc_callback(code: str, state: str, request: Request):
    if not oidc.is_configured():
        raise HTTPException(status_code=503, detail="OIDC is not configured on this server.")
    _oidc_prune_pending()
    entry = _oidc_pending_logins.pop(state, None)
    cookie_state = request.cookies.get(OIDC_STATE_COOKIE) or ""
    if not entry or not secrets.compare_digest(cookie_state.encode(), state.encode()):
        raise HTTPException(
            status_code=400,
            detail="Unknown or expired OIDC login attempt - please try signing in again.",
        )
    verifier = entry[0]
    try:
        token_response = oidc.exchange_code_for_token(code, verifier)
        userinfo = oidc.fetch_userinfo(token_response["access_token"])
    except Exception:  # noqa: BLE001 - any provider/network failure; detail goes to the log, not the browser
        logging.getLogger("quanta.oidc").exception("OIDC token exchange or userinfo request failed")
        raise HTTPException(status_code=502, detail=OIDC_GENERIC_ERROR) from None

    if userinfo.get("email_verified") in (False, "false", "False"):
        logging.getLogger("quanta.oidc").warning("OIDC sign-in refused: provider reports the email as unverified")
        raise HTTPException(status_code=403, detail=OIDC_GENERIC_ERROR)
    email = (userinfo.get("email") or "").strip().lower()
    if not email:
        logging.getLogger("quanta.oidc").warning("OIDC provider did not return an email claim")
        raise HTTPException(status_code=502, detail=OIDC_GENERIC_ERROR)
    # Every OIDC-authenticated user lands as role "user", never "admin" - there's no
    # reliable, provider-agnostic way to know someone's real org role from a generic
    # userinfo claim set. A real deployment would map the IdP's own group/role claims
    # (which vary per provider) onto Quanta's admin/user roles; that mapping isn't
    # implemented here.
    user = {"email": email, "name": userinfo.get("name", email), "role": "user"}
    cookie_value = sessions.create_session_cookie(user, rbac.SESSION_SECRET)
    redirect = RedirectResponse("/")
    redirect.set_cookie(
        rbac.SESSION_COOKIE_NAME, cookie_value, httponly=True, samesite="lax", secure=_cookie_secure(request),
        max_age=sessions.DEFAULT_MAX_AGE_SECONDS,
    )
    redirect.delete_cookie(OIDC_STATE_COOKIE)
    return redirect


def _db_table_fact(table):
    """Real, cheap facts about one of the shared SQLite DB's tables (exceptions,
    approvals, activity log, AI usage log) - exists/last-modified/record-count, so
    Admin can see real data freshness instead of a guess. Never raises: a DB read
    failure reports its own error string instead of taking down the whole health
    check.

    `last_modified` is the shared DB *file's* own mtime, not a per-table timestamp -
    all four stores now live in one physical file (see remediation/utils/db.py), so
    they will always report the same last_modified as each other; that's the honest
    fact about the new shared-file architecture, not a bug. `exists` reports whether
    the DB file itself has been created yet (it's created lazily on first write).

    The path is read off the real engine (`engine.url.database`), not the separate
    db_module.DEFAULT_DB_PATH constant - tests patch db_module.get_engine() to an
    isolated file for isolation, and reading DEFAULT_DB_PATH here directly would
    silently drift from whatever engine.get_engine() actually returns in that case."""
    engine = db_module.get_engine()
    db_path = Path(engine.url.database)
    if not db_path.exists():
        return {"exists": False, "last_modified": None, "record_count": None}
    try:
        db_module.ensure_schema(engine)
        with engine.connect() as conn:
            record_count = conn.execute(select(func.count()).select_from(table)).scalar_one()
        error = None
    except Exception as exc:  # noqa: BLE001 - report the read failure, don't crash /api/status
        record_count, error = None, str(exc)
    fact = {
        "exists": True,
        "last_modified": datetime.datetime.fromtimestamp(
            db_path.stat().st_mtime, tz=datetime.timezone.utc,
        ).isoformat(),
        "record_count": record_count,
    }
    if error:
        fact["error"] = error
    return fact


def _safe_check(fn, default):
    """Runs one independent health check, catching any exception so one broken check
    (e.g. a corrupted findings file) can't take down the whole health report or hide
    the other checks' real results - each check's own failure is reported honestly
    instead. Returns (value, error_str_or_None)."""
    try:
        return fn(), None
    except Exception as exc:  # noqa: BLE001 - a health check must never itself crash
        return default, str(exc)


def _environment_info():
    from remediation.utils import environment as quanta_environment
    try:
        return quanta_environment.info()
    except quanta_environment.EnvironmentError_ as exc:
        return {"environment": "invalid", "error": str(exc), "version": quanta_environment.version(),
                "build_sha": None, "build_time": None, "simulation_allowed": False}


@app.get("/api/features")
def api_features(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """Which feature flags are on in this environment (remediation/config/features.yaml plus the QUANTA_FEATURES_ON/OFF overrides)."""
    from remediation.utils import features
    return features.snapshot()


@app.get("/api/status")
def api_status():
    """A real machine-readable health/status endpoint - every field below is an actual
    checked fact, not a hardcoded claim. `status` is "degraded" only when something
    genuinely load-bearing (the findings file itself) can't be read - SMTP/a real
    session secret not being configured are expected, documented, optional-by-default
    states in this MVP, not degradation, so they're reported honestly but don't flip
    `status`.

    `data_stores` is deliberately computed FIRST, before anything else below - vh's own
    load_quanta_scan_data() reads activity_log for verification status, and that read (like
    any table read) unconditionally runs ensure_schema() first, which lazily creates the
    shared DB file if it doesn't exist yet. Computing data_stores after that call would
    make every store sharing that physical file (see _db_table_fact's own docstring)
    report exists:true just because this same request happened to touch a different
    table first - an honest existence check must not be contaminated by what the rest
    of the same request does."""
    data_stores = {
        "exceptions": _db_table_fact(db_module.exceptions),
        "remediation_approvals": _db_table_fact(db_module.remediation_approvals),
        "activity_log": _db_table_fact(db_module.activity_log),
        "ai_usage_log": _db_table_fact(db_module.ai_usage_log),
    }
    vh = dashboard_data.load_quanta_scan_data()
    findings, findings_error = _safe_check(dashboard_data.load_remediation_findings, [])
    playbooks, playbooks_error = _safe_check(dashboard_data.load_playbooks, [])
    threat_intel, threat_intel_error = _safe_check(
        dashboard_data.load_threat_intel_freshness, {"available": False},
    )
    if threat_intel_error:
        threat_intel = {**threat_intel, "error": threat_intel_error}

    return {
        "status": "degraded" if (findings_error or playbooks_error) else "ok",
        "app_version": app.version,
        "quanta_scan_available": vh.get("available", False),
        "quanta_scan_findings": vh.get("total", 0),
        "remediation_findings": len(findings),
        "remediation_findings_error": findings_error,
        "remediation_playbooks": len(playbooks),
        "smtp_configured": email_sender.is_configured(),
        "session_secret_configured": bool(os.environ.get("QUANTA_SESSION_SECRET")),
        "threat_intel": threat_intel,
        "uptime_seconds": round(time.monotonic() - _PROCESS_STARTED_AT, 1),
        "notification_scheduler_alive": _scheduler_task is not None and not _scheduler_task.done(),
        "data_stores": data_stores,
        "environment": _environment_info(),
    }


# ---------------------------------------------------------------------------
# HTML shell - a single static/index.html served for every page route. All of
# these routes return byte-identical HTML; static/js/app.js reads
# window.location.pathname client-side and renders the right page by calling
# the JSON API above. This is what lets the frontend be a real SPA (client
# routing, no full-page reloads between pages) without any Node/npm/webpack -
# see "Why FastAPI + vanilla JS" in dashboard/README.md.
# ---------------------------------------------------------------------------

def _serve_shell():
    return FileResponse(STATIC_DIR / "index.html")


for _route in (
    "/", "/quanta-scan", "/remediate", "/run", "/queue", "/priority-rules", "/servicenow",
    "/jira", "/splunk", "/xdr", "/infoblox", "/axonius", "/ai-assist", "/reports", "/support", "/faq",
    "/exceptions", "/assets", "/appsec", "/infrastructure", "/inbox", "/risk", "/ai-vulnerabilities", "/login", "/profile",
    "/adaptors", "/vulnerability-mapping", "/asset-mapping", "/exploit-criteria",
    "/compensating-controls", "/threat-intel", "/notification-settings",
    "/remediation-policy", "/remediation-approvals",
):
    app.api_route(_route, methods=["GET", "HEAD"], include_in_schema=False)(_serve_shell)


@app.api_route("/playbooks/{filename}", methods=["GET", "HEAD"], include_in_schema=False)
def playbook_page(filename: str):  # noqa: ARG001 - filename is read client-side from the URL
    return _serve_shell()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------- threat hunting and SOC triage
class HuntBody(BaseModel):
    title: str | None = None
    hypothesis: str | None = None
    techniques: list[dict] | None = None
    assets: list[str] | None = None
    data_sources: list[str] | None = None
    queries: list[dict] | None = None
    notes: str | None = None
    follow_ups: str | None = None
    owner: str | None = None
    status: str | None = None
    outcome: str | None = None
    detection_created: bool | None = None


class HuntProposalBody(BaseModel):
    source_ref: str


class AlertBody(BaseModel):
    source: str = "api"
    external_id: str
    title: str
    severity: str = "Medium"
    asset: str | None = None
    technique: str | None = None
    detail: str | None = None
    occurred_at: str | None = None
    rule_name: str | None = None
    entities: dict | None = None


class AlertsPushBody(BaseModel):
    alerts: list[AlertBody]


class AlertUpdateBody(BaseModel):
    status: str | None = None
    disposition: str | None = None
    assignee: str | None = None
    notes: str | None = None


def _hunt_400(exc):
    return HTTPException(status_code=404 if isinstance(exc, KeyError) else 400, detail=str(exc.args[0]) if isinstance(exc, KeyError) else str(exc))


def _owner_map():
    from remediation.inventory import asset_inventory
    return {name.lower(): (o.get("owner") or o.get("team")) for name, o in asset_inventory.load_ownership().items() if o.get("owner") or o.get("team")}


def _hunt_proposals():
    return hunt_generate.propose(dashboard_data.load_live_queue(), hunt_store.existing_refs())


@app.get("/api/hunting/overview")
def api_hunting_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    findings = dashboard_data.load_live_queue()
    hunts, alerts = hunt_store.list_hunts(), hunt_store.list_alerts()
    m = hunt_triage.metrics(hunts, alerts, findings, hunt_generate.library())
    return {"metrics": m, "proposals": len(hunt_generate.propose(findings, hunt_store.existing_refs()))}


@app.get("/api/hunting/attack-matrix")
def api_hunting_attack_matrix(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """The ATT&CK matrix: every technique Quanta knows, with detection coverage, hunts, open findings/alerts and live suggestions joined. Read only; see remediation/hunting/matrix.py."""
    from remediation.hunting import matrix as hunt_matrix
    return hunt_matrix.build(rules=hunt_detection.list_rules(), findings=dashboard_data.load_live_queue(), alerts=hunt_store.list_alerts(), hunts=hunt_store.list_hunts(),
                             suggestions=hunt_engine.listing(include_suppressed=True)["suggestions"], library=hunt_generate.library())


@app.get("/api/hunting/proposals")
def api_hunting_proposals(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"proposals": _hunt_proposals()[:100], "note": "A proposed hunt means the exposure makes it worth looking, not that anything happened."}


@app.post("/api/hunting/proposals/accept")
def api_hunting_accept(body: HuntProposalBody, user: dict = Depends(rbac.require_admin)):
    p = next((x for x in _hunt_proposals() if x["source_ref"] == body.source_ref), None)
    if not p:
        raise HTTPException(status_code=404, detail="No such proposal (it may already be a hunt)")
    try:
        h = hunt_store.create_hunt(p, user["email"])
    except ValueError as exc:
        raise _hunt_400(exc) from exc
    activity_log.record_activity(user["email"], "hunt.create", str(h["id"]), {"title": h["title"], "source": "generated"})
    return h


class SuggestionDismissBody(BaseModel):
    reason: str
    notes: str | None = None


class SuggestionAcceptBody(BaseModel):
    owner: str | None = None


class SuggestionConcludeBody(BaseModel):
    outcome: str
    notes: str


def _suggestion_error(exc):
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail="No such suggestion")
    return HTTPException(status_code=409 if isinstance(exc, hunt_engine.TransitionError) else 400, detail=str(exc))


@app.get("/api/hunting/suggestions")
def api_hunting_suggestions(type: str | None = None, tactic: str | None = None, status: str | None = None, include_suppressed: bool = False, limit: int | None = None,
                            user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    hunt_engine.sync_with_hunts()
    return hunt_engine.listing(status=status, hunt_type=type, tactic=tactic, include_suppressed=include_suppressed, limit=limit)


@app.post("/api/hunting/suggestions/refresh")
def api_hunting_suggestions_refresh(user: dict = Depends(rbac.require_admin)):
    result = hunt_engine.refresh(dashboard_data.load_live_queue(), actor=user["email"])
    activity_log.record_activity(user["email"], "hunt.suggestions.refresh", "", {k: v for k, v in result.items() if k != "gaps"})
    return result


@app.get("/api/hunting/suggestions/{hid}")
def api_hunting_suggestion(hid: str, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    d = hunt_engine.detail(hid)
    if not d:
        raise HTTPException(status_code=404, detail="No such suggestion")
    return d


@app.post("/api/hunting/suggestions/{hid}/accept")
def api_hunting_suggestion_accept(hid: str, body: SuggestionAcceptBody | None = None, user: dict = Depends(rbac.require_admin)):
    try:
        r = hunt_engine.accept(hid, user["email"], owner=body.owner if body else None)
    except (KeyError, ValueError) as exc:
        raise _suggestion_error(exc) from exc
    activity_log.record_activity(user["email"], "hunt.suggestion.accept", hid, {"hunt_id": r["hunt_id"]})
    return r


@app.post("/api/hunting/suggestions/{hid}/dismiss")
def api_hunting_suggestion_dismiss(hid: str, body: SuggestionDismissBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = hunt_engine.dismiss(hid, body.reason, body.notes, user["email"])
    except (KeyError, ValueError) as exc:
        raise _suggestion_error(exc) from exc
    activity_log.record_activity(user["email"], "hunt.suggestion.dismiss", hid, {"reason": body.reason})
    return r


@app.post("/api/hunting/suggestions/{hid}/conclude")
def api_hunting_suggestion_conclude(hid: str, body: SuggestionConcludeBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = hunt_engine.conclude(hid, body.outcome, body.notes, user["email"])
    except (KeyError, ValueError) as exc:
        raise _suggestion_error(exc) from exc
    activity_log.record_activity(user["email"], "hunt.suggestion.conclude", hid, {"outcome": body.outcome})
    return r


@app.post("/api/hunting/suggestions/{hid}/promote")
def api_hunting_suggestion_promote(hid: str, user: dict = Depends(rbac.require_admin)):
    try:
        r = hunt_engine.promote(hid, user["email"])
    except (KeyError, ValueError) as exc:
        raise _suggestion_error(exc) from exc
    activity_log.record_activity(user["email"], "hunt.suggestion.promote", hid, {"use_case": r["promoted_key"]})
    return r


@app.get("/api/hunting/hunts")
def api_hunting_list(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    rules = hunt_detection.list_rules()
    return {"hunts": [_hunt_out(h, rules) for h in hunt_store.list_hunts()]}


@app.post("/api/hunting/hunts")
def api_hunting_create(body: HuntBody, user: dict = Depends(rbac.require_admin)):
    try:
        h = hunt_store.create_hunt(body.model_dump(exclude_none=True) | {"source": "manual"}, user["email"])
    except ValueError as exc:
        raise _hunt_400(exc) from exc
    activity_log.record_activity(user["email"], "hunt.create", str(h["id"]), {"title": h["title"], "source": "manual"})
    return h


@app.get("/api/hunting/hunts/{hunt_id}")
def api_hunting_get(hunt_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    h = hunt_store.get_hunt(hunt_id)
    if not h:
        raise HTTPException(status_code=404, detail="No such hunt")
    return _hunt_out(h)


@app.put("/api/hunting/hunts/{hunt_id}")
def api_hunting_update(hunt_id: int, body: HuntBody, user: dict = Depends(rbac.require_admin)):
    try:
        h = hunt_store.update_hunt(hunt_id, body.model_dump(exclude_unset=True))
    except (ValueError, KeyError) as exc:
        raise _hunt_400(exc) from exc
    activity_log.record_activity(user["email"], "hunt.update", str(hunt_id), {"status": h["status"], "outcome": h["outcome"]})
    return _hunt_out(h)


@app.post("/api/ingest/alerts")
def api_ingest_alerts(body: AlertsPushBody, key: dict = Depends(require_api_key("soc:write"))):
    """Alerts from a SIEM, XDR or SOAR: {external_id, title, severity, asset, technique (ATT&CK id), detail, occurred_at}. A repeat is ignored."""
    created, repeats, errors = 0, 0, []
    auto = _AutoInvestigator()
    for i, a in enumerate(body.alerts[:2000]):
        try:
            row, new = hunt_store.receive_alert(a.model_dump() | {"source": a.source if a.source != "api" else f"apikey:{key['name']}"})
            created += new
            if new:
                auto.run(row)
                _soar_auto(row)
            repeats += not new
        except ValueError as exc:
            errors.append({"index": i, "error": str(exc)})
    activity_log.record_activity(f"apikey:{key['name']}", "soc.alerts.push", None, {"created": created, "repeats": repeats, "rejected": len(errors)})
    return {"created": created, "already_known": repeats, "rejected": len(errors), "errors": errors[:50], "investigated": auto.done}


@app.get("/api/soc/alerts")
def api_soc_alerts(status: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    findings, owners, books = dashboard_data.load_live_queue(), _owner_map(), hunt_triage.runbooks()
    rows = hunt_store.list_alerts(status=status)
    for a in rows:
        e = hunt_triage.enrich(a, findings, owners, books)
        a["context"] = {k: e[k] for k in ("priority", "reasons", "owner", "open_findings", "kev_findings")}
    rows.sort(key=lambda a: (a["status"] == "closed", -a["context"]["priority"]))
    return {"alerts": rows}


@app.get("/api/soc/alerts/{alert_id}")
def api_soc_alert(alert_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    a = hunt_store.get_alert(alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="No such alert")
    a["context"] = hunt_triage.enrich(a, dashboard_data.load_live_queue(), _owner_map())
    return a


@app.put("/api/soc/alerts/{alert_id}")
def api_soc_alert_update(alert_id: int, body: AlertUpdateBody, user: dict = Depends(rbac.require_admin)):
    try:
        a = hunt_store.update_alert(alert_id, body.model_dump(exclude_unset=True))
    except (ValueError, KeyError) as exc:
        raise _hunt_400(exc) from exc
    activity_log.record_activity(user["email"], "soc.alert.update", str(alert_id), {"status": a["status"], "disposition": a["disposition"]})
    if body.disposition:
        decision_service.judge_soc_disposition(alert_id, a["disposition"])
    return a


# ---------------------------------------------------------------- typed decisions: evaluate (dry), policy, calibration (docs/DECISIONS.md)
class DecisionEvaluateBody(BaseModel):
    decision: str
    state: dict = {}
    purpose: str = "decide"


@app.post("/api/decisions/evaluate")
def api_decisions_evaluate(body: DecisionEvaluateBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """Dry: evaluates one decision and returns the typed answers, the gate's route and whether a model would be needed. Writes nothing."""
    try:
        return decision_service.public(decision_service.evaluate(body.decision, body.state, purpose=body.purpose))
    except decision_schema.SchemaViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/decisions/policy")
def api_decisions_policy(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    from remediation.decisions import gate as decision_gate
    pol = decision_gate.load_policy()
    decs = []
    for name, d in decision_registry.DECISIONS.items():
        dp = (pol.get("decisions") or {}).get(name) or {}
        decs.append({"name": name, "title": d.title, "questions": [{"name": q.name, "kind": q.kind, "options": list(q.options), "prompt": q.prompt} for q in d.questions],
                     "reversible": dp.get("reversible"), "local": dp.get("local"), "touches_environment": d.touches_environment,
                     "auto_allowed": decision_gate.auto_allowed(d, dp), "thresholds": dp.get("thresholds")})
    return {"decisions": decs, "calibration": pol.get("calibration")}


@app.get("/api/decisions/calibration")
def api_decisions_calibration(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return decision_calibration.report()


# ---------------------------------------------------------------- insights and structured ask (docs/INSIGHTS.md)
class InsightStateBody(BaseModel):
    reason: str | None = None
    days: int | None = None


class InsightSettingsBody(BaseModel):
    settings: dict


@app.get("/api/insights")
def api_insights(role: str | None = None, limit: int = 10, include_closed: bool = False, user: dict = Depends(rbac.require_login)):
    if not insights_service.enabled():
        return {"enabled": False, "insights": [], "last_refresh": None}
    items = insights_service.list_insights(user, role=role, limit=max(1, min(limit, 50)), include_closed=include_closed)
    return {"enabled": True, "role": role if role in ("admin", "analyst", "appsec", "exec") else insights_service.default_role(user),
            "insights": items, "last_refresh": insights_service.last_refresh()}


@app.post("/api/insights/refresh")
def api_insights_refresh(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if not insights_service.enabled():
        raise HTTPException(status_code=409, detail="Insights are switched off (QUANTA_INSIGHTS=false).")
    findings, assets = _insights_inputs()
    return insights_service.refresh(findings=findings, assets=assets)


@app.get("/api/insights/settings")
def api_insights_settings(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return insights_service.settings_view()


@app.put("/api/insights/settings")
def api_insights_settings_put(body: InsightSettingsBody, user: dict = Depends(rbac.require_admin)):
    try:
        insights_service.update_config(body.settings)
    except insights_service.SettingsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "insights.settings", None, {"keys": sorted(body.settings)})
    return insights_service.settings_view()


@app.get("/api/insights/{insight_id}")
def api_insight_get(insight_id: str, role: str | None = None, user: dict = Depends(rbac.require_login)):
    ins = insights_service.get_insight(insight_id, user, role=role)
    if ins is None:
        raise HTTPException(status_code=404, detail="Insight not found")
    return ins


def _insight_state(insight_id, state, body, user):
    try:
        ins = insights_service.set_state(insight_id, state, user, reason=body.reason, snooze_days=body.days)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Insight not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], f"insights.{state}", insight_id, {"detector": ins["detector"]})
    return ins


@app.post("/api/insights/{insight_id}/snooze")
def api_insight_snooze(insight_id: str, body: InsightStateBody, user: dict = Depends(rbac.require_login)):
    return _insight_state(insight_id, "snoozed", body, user)


@app.post("/api/insights/{insight_id}/dismiss")
def api_insight_dismiss(insight_id: str, body: InsightStateBody, user: dict = Depends(rbac.require_login)):
    return _insight_state(insight_id, "dismissed", body, user)


@app.post("/api/insights/{insight_id}/acted")
def api_insight_acted(insight_id: str, body: InsightStateBody, user: dict = Depends(rbac.require_login)):
    return _insight_state(insight_id, "acted", body, user)


class AskStructuredBody(BaseModel):
    query: str


@app.post("/api/ask/structured")
def api_ask_structured(body: AskStructuredBody, user: dict = Depends(rbac.require_login)):
    """Deterministic grammar over the existing read data, run with the asker's own permissions (team-scoped findings; cases and hunts admin only).
    Returns the exact structured query it ran, or suggestions when the sentence fits no shape. No model is called."""
    is_admin = user.get("role") == "admin"

    def findings():
        return _scope_to_team(_annotate_finding_teams(dashboard_data.load_live_queue()), user)

    def assets():
        return _scope_to_team([dict(a) for a in dashboard_data._load_scored_assets()[1]], user)

    def sbom():
        out = []
        for name in appsec_store.sbom_summaries():
            g = (appsec_store.get_sbom(name) or {}).get("graph") or {}
            comps = g.get("components") or []
            comps = comps.values() if isinstance(comps, dict) else comps
            out.extend({"application": name, "name": c.get("name"), "version": c.get("version")} for c in comps)
        return out

    today = datetime.datetime.now(datetime.timezone.utc).date()
    ctx = insights_ask.Context(
        user=user, findings=findings, assets=assets, today=today,
        cases=(lambda: soc_cases.list_cases(open_only=False)) if is_admin else None,
        hunts=hunt_store.list_hunts if is_admin else None,
        sbom_components=sbom,
        insights=lambda n: insights_service.list_insights(user, limit=n),
        activity=lambda since: sum(1 for e in activity_log.list_activity(limit=2000) if str(e.get("timestamp", ""))[:10] >= since))
    out = insights_ask.ask(body.query, ctx)
    if out.get("forbidden"):
        raise HTTPException(status_code=403, detail=out["forbidden"])
    return out


# ---------------------------------------------------------------- SOC agents: hunt execution, threat intel, investigation, detection engineering
class HuntRunBody(BaseModel):
    connection_id: int | None = None
    earliest: str = "-24h"
    confirm: bool = False
    justification: str | None = None


class RunAllBody(BaseModel):
    connection_id: int | None = None
    earliest: str = "-24h"
    confirm: bool = False
    justification: str | None = None
    only_unrun: bool = True


class FollowUpBody(BaseModel):
    kind: str
    value: str
    siem: bool = False
    siem_connection_id: int | None = None
    confirm: bool = False


class IntelBody(BaseModel):
    content: str
    title: str | None = None
    source: str | None = None


class InvestigateBody(BaseModel):
    confirm: bool = False
    reputation: bool = False
    siem: bool = False
    reputation_connection_id: int | None = None
    siem_connection_id: int | None = None
    lookback_days: int | None = None
    justification: str | None = None


class RuleBody(BaseModel):
    name: str
    platform: str | None = None
    logic: str | None = None
    techniques: list[str] = []
    enabled: bool = True


class RuleEnabledBody(BaseModel):
    enabled: bool


_EARLIEST = re.compile(r"^-\d{1,4}[mhd]$")


def _hunt_out(h, rules=None):
    h = dict(h)
    h["verdict"] = hunt_verdict.hunt_verdict(h)
    h["summary"] = hunt_verdict.summary(h, hunt_detection.list_rules() if rules is None else rules)
    return h


def _identity_map():
    """Who holds privileged access, from the access-governance records: {user or account (lower case): {privileged, systems}}; None when nothing is loaded."""
    rows = iam_store.entitlements()
    if not rows:
        return None
    out = {}
    for r in rows:
        if r.get("status") == "disabled":
            continue
        for key in {str(r["user"]).lower(), str(r.get("account") or "").lower()} - {""}:
            e = out.setdefault(key, {"privileged": False, "systems": set()})
            if r["privileged"]:
                e["privileged"] = True
                e["systems"].add(r["system"])
    return out


def _earliest_days(earliest):
    n, unit = int(earliest[1:-1]), earliest[-1]
    return max(1, -(-n // 1440) if unit == "m" else -(-n // 24) if unit == "h" else n)


def _lookback_cfg(days, justification, actor, subject):
    """The triage config with the look-back ceiling set for this request. Past max_lookback_days a written justification is required (kept in the activity
    log) and the ceiling is extended_lookback_days. Raises 400 otherwise."""
    cfg = dict(hunt_soc.config())
    base, ext = cfg.get("max_lookback_days", 90), cfg.get("extended_lookback_days", 365)
    if days is None:
        return cfg
    if days < 1:
        raise HTTPException(status_code=400, detail="The look-back must be at least 1 day")
    if days > ext:
        raise HTTPException(status_code=400, detail=f"The look-back cannot exceed {ext} days")
    if days > base:
        if len((justification or "").strip()) < 20:
            raise HTTPException(status_code=400, detail=f"Looking back more than {base} days needs a written justification of at least 20 characters")
        activity_log.record_activity(actor, "soc.lookback.extended", subject, {"days": days, "justification": justification.strip()[:500]})
    cfg["max_lookback_days"] = days
    return cfg


def _route_investigated_alert(alert, inv, ctx=None):
    """An investigated alert goes to the incident layer (group, summarise, route) when it is on; otherwise the older one-case-per-alert rule applies."""
    if incident_store.enabled():
        findings = ctx["findings"] if ctx else dashboard_data.load_live_queue()
        owners = ctx["owners"] if ctx else _owner_map()
        return incident_service.ingest(alert, inv, incident_service.Context(findings, owners))
    return soc_cases.auto_case(alert, inv)


class _AutoInvestigator:
    """Investigates new alerts as they arrive: locally and free (no reputation lookup, no SIEM search), so the report is waiting when an analyst opens the alert.
    Context is loaded once per request, and at most max_per_request alerts are investigated in one call. Never raises."""

    def __init__(self):
        self.cfg = hunt_soc.config()
        self.opts = self.cfg.get("auto_investigate") or {}
        self.ctx = None
        self.done = 0

    def run(self, alert):
        if not self.opts.get("enabled"):
            return None
        try:
            sev = soc_cases.SEVERITIES
            if alert["severity"] not in sev or sev.index(alert["severity"]) > sev.index(self.opts.get("min_severity", "Low")) or self.done >= self.opts.get("max_per_request", 200):
                return None
            if self.ctx is None:
                self.ctx = {"alerts": hunt_store.list_alerts(), "findings": dashboard_data.load_live_queue(), "owners": _owner_map(), "identity": _identity_map(),
                            "playbooks": soar_playbooks.list_all()}
            c = self.ctx
            inv = hunt_soc.investigate(alert, c["alerts"], c["findings"], c["owners"], cfg=self.cfg, identity=c["identity"], playbooks=c["playbooks"])
            hunt_service.save_investigation(inv, hunt_soc.render_markdown(alert, inv), "system")
            decision_service.log_soc_verdict(alert, inv)
            case = _route_investigated_alert(alert, inv, c)
            self.done += 1
            if alert["id"] not in {a["id"] for a in c["alerts"]}:
                c["alerts"].append(alert)
            return case
        except Exception:  # noqa: BLE001 - an automatic investigation must never lose the alert
            logging.getLogger("quanta.soc").exception("automatic investigation failed")
            return None


def _hunt_from_intel(rec, actor):
    """Creates the hunt for a stored threat-intelligence report and links it. Raises ValueError when the hunt cannot be created."""
    ex = rec["extracted"]
    score, prio, reasons, matches = hunt_intel.relevance(ex, dashboard_data.load_live_queue())
    proposal = hunt_intel.propose_hunt(ex, (score, prio, reasons, matches), matches["hosts"])
    proposal["source_ref"] = f"intel-{rec['id']}"
    h = hunt_store.create_hunt(proposal, actor)
    hunt_service.link_intel_hunt(rec["id"], h["id"])
    activity_log.record_activity(actor, "hunt.create", str(h["id"]), {"title": h["title"], "source": "intel"})
    return h


def _intel_out(r):
    out = {k: r[k] for k in ("id", "title", "source", "relevance", "priority", "reasons", "extracted", "hunt_id", "received_at", "received_by")}
    out.update({k: r.get(k) for k in ("published_at", "fetched_at", "source_id", "url")})
    out["why_triggered"] = r.get("trigger")
    return out


def _store_intel(content, title, source, actor):
    ex = hunt_intel.extract(content)
    if title:
        ex["title"] = title[:160]
    findings = dashboard_data.load_live_queue()
    score, prio, reasons, matches = hunt_intel.relevance(ex, findings)
    rid, created = hunt_service.save_intel(ex["title"], source, hunt_intel.content_hash(content), ex, score, prio, reasons, actor)
    return hunt_service.get_intel(rid), created, matches


@app.post("/api/hunting/intel")
def api_hunting_intel_add(body: IntelBody, user: dict = Depends(rbac.require_admin)):
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="Paste the report text or a STIX bundle")
    if len(body.content) > 2_000_000:
        raise HTTPException(status_code=413, detail="The report is too large (limit 2 MB)")
    rec, created, matches = _store_intel(body.content, body.title, body.source, user["email"])
    if created:
        activity_log.record_activity(user["email"], "intel.add", str(rec["id"]), {"title": rec["title"], "priority": rec["priority"]})
    return {**_intel_out(rec), "created": created, "matches": matches}


@app.post("/api/ingest/threat-intel")
def api_ingest_threat_intel(body: IntelBody, key: dict = Depends(require_api_key("soc:write"))):
    """A threat-intelligence report (text or a STIX 2.1 bundle) from a feed, SOAR playbook or script. A repeat of the same content is ignored."""
    if len(body.content) > 2_000_000:
        raise HTTPException(status_code=413, detail="The report is too large (limit 2 MB)")
    rec, created, _ = _store_intel(body.content, body.title, body.source or f"apikey:{key['name']}", f"apikey:{key['name']}")
    activity_log.record_activity(f"apikey:{key['name']}", "intel.push", str(rec["id"]), {"created": created, "priority": rec["priority"]})
    hunt_id = rec["hunt_id"]
    floor = ((hunt_soc.config().get("hunting") or {}).get("auto_create_hunt_at_or_above") or "").lower()
    order = {"low": 0, "medium": 1, "high": 2}
    if created and not hunt_id and floor in order and order[rec["priority"]] >= order[floor]:
        try:
            hunt_id = _hunt_from_intel(rec, f"apikey:{key['name']}")["id"]
        except ValueError:
            hunt_id = None  # a hunt for this already exists, or the report gave nothing to hunt; the report is still stored
    return {"id": rec["id"], "created": created, "relevance": rec["relevance"], "priority": rec["priority"], "hunt_id": hunt_id}


# ---------------------------------------------------------------- the report watcher (report sources on the Threat Intelligence page)
class IntelSourceBody(BaseModel):
    name: str
    kind: str                       # feed or taxii
    url: str | None = None          # feed address (https)
    connection_id: int | None = None   # a stored taxii connection
    collection_id: str | None = None


class IntelPollBody(BaseModel):
    confirm: bool = False


class IntelEnabledBody(BaseModel):
    enabled: bool


def _intel_watch_deps():
    def build_taxii(source):
        c, _ = hunt_service.connector("taxii", source["connection_id"])
        if not c:
            raise ValueError("The TAXII connection for this source is missing or disabled")
        return c
    return intelwatch.Deps(findings=dashboard_data.load_live_queue, make_hunt=lambda rec, actor: _hunt_from_intel(rec, actor), refresh_engine=hunt_engine.refresh,
                           hunt_floor=lambda: ((hunt_soc.config().get("hunting") or {}).get("auto_create_hunt_at_or_above") or ""),
                           build_feed=lambda s: report_feed_connector.ReportFeedConnector(s["url"], max_bytes=intelwatch.config()["max_bytes"], max_items=intelwatch.config()["max_items_per_poll"]),
                           build_taxii=build_taxii)


def _run_intel_watch_if_due():
    """Leader tick: polls each enabled report source that is due (interval in config/intel_watch.yaml). Does nothing with no source added, or with
    QUANTA_INTEL_WATCH=false. Never runs a search on a SIEM; never raises."""
    try:
        return intelwatch.poll_due(_intel_watch_deps())
    except Exception:  # noqa: BLE001
        logging.getLogger("quanta.scheduler").warning("report watcher tick failed")
        return None


def _source_out(s):
    out = {k: s[k] for k in ("id", "name", "kind", "url", "connection_id", "collection_id", "enabled", "last_poll_at", "last_status", "last_error", "last_new", "total_reports", "created_by", "created_at")}
    return out


@app.get("/api/hunting/intel/sources")
def api_intel_sources(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    cfg = intelwatch.config()
    return {"sources": [_source_out(s) for s in hunt_service.list_sources()], "watch_enabled": intelwatch.enabled(), "interval_minutes": cfg["interval_minutes"],
            "hunt_threshold": ((hunt_soc.config().get("hunting") or {}).get("auto_create_hunt_at_or_above") or None),
            "note": "The watcher only reads reports. It never runs a search on a SIEM: a hunt it creates waits for a person to accept it and confirm any run."}


@app.post("/api/hunting/intel/sources")
def api_intel_source_add(body: IntelSourceBody, user: dict = Depends(rbac.require_admin)):
    name = body.name.strip()
    if not (1 <= len(name) <= 80):
        raise HTTPException(status_code=400, detail="Give the source a name of 1 to 80 characters")
    if body.kind == "feed":
        try:
            report_feed_connector.ReportFeedConnector(body.url or "")   # https only and the SSRF guard
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        url, conn_id, coll = body.url.strip(), None, None
    elif body.kind == "taxii":
        public = hunt_service.find_connection("taxii", body.connection_id)[0] if body.connection_id else None
        if not public:
            raise HTTPException(status_code=400, detail="Choose a stored TAXII connection (add one on the Connections page)")
        if not (body.collection_id or "").strip():
            raise HTTPException(status_code=400, detail="Give the collection id to poll (the Test button lists the collections the account can read)")
        url, conn_id, coll = None, public["id"], body.collection_id.strip()
    else:
        raise HTTPException(status_code=400, detail="kind must be feed or taxii")
    try:
        s = hunt_service.add_source(name, body.kind, url, user["email"], conn_id, coll)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "intel.source.add", str(s["id"]), {"name": name, "kind": body.kind})
    return _source_out(s)


def _source_or_404(source_id):
    s = hunt_service.get_source(source_id)
    if not s:
        raise HTTPException(status_code=404, detail="No such report source")
    return s


@app.post("/api/hunting/intel/sources/{source_id}/test")
def api_intel_source_test(source_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Reads the source once and reports what it found; stores nothing and creates no hunt."""
    s = _source_or_404(source_id)
    try:
        deps = _intel_watch_deps()
        if s["kind"] == "feed":
            return {"ok": True, **deps.build_feed(s).test_connection()}
        c = deps.build_taxii(s)
        return {"ok": True, **c.test_connection(), "collections": c.collections()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"The source could not be read ({type(exc).__name__}: {str(exc)[:160]})") from exc


@app.post("/api/hunting/intel/sources/{source_id}/poll")
def api_intel_source_poll(source_id: int, body: IntelPollBody, user: dict = Depends(rbac.require_admin)):
    s = _source_or_404(source_id)
    if not body.confirm:
        return {"preview_only": True, "source": s["name"], "message": "This reads the source (a GET only), stores new reports and creates hunts for the relevant ones. It runs no search on your SIEM. Send confirm: true to poll now."}
    res = intelwatch.poll_source(s, _intel_watch_deps(), actor=user["email"])
    activity_log.record_activity(user["email"], "intel.source.poll", str(source_id), {"status": res["status"], "new": res["new"], "hunts": res["hunts_created"]})
    return {"preview_only": False, **res}


@app.post("/api/hunting/intel/sources/{source_id}/enabled")
def api_intel_source_enabled(source_id: int, body: IntelEnabledBody, user: dict = Depends(rbac.require_admin)):
    _source_or_404(source_id)
    hunt_service.update_source(source_id, {"enabled": 1 if body.enabled else 0})
    activity_log.record_activity(user["email"], "intel.source.enable" if body.enabled else "intel.source.disable", str(source_id), {})
    return _source_out(_source_or_404(source_id))


@app.delete("/api/hunting/intel/sources/{source_id}")
def api_intel_source_delete(source_id: int, user: dict = Depends(rbac.require_admin)):
    s = _source_or_404(source_id)
    hunt_service.delete_source(source_id)   # the reports it stored stay; only the source and its poll state go
    activity_log.record_activity(user["email"], "intel.source.delete", str(source_id), {"name": s["name"]})
    return {"deleted": True}


@app.get("/api/hunting/intel")
def api_hunting_intel_list(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"reports": [_intel_out(r) for r in hunt_service.list_intel()]}


@app.post("/api/hunting/intel/{report_id}/hunt")
def api_hunting_intel_hunt(report_id: int, user: dict = Depends(rbac.require_admin)):
    rec = hunt_service.get_intel(report_id)
    if not rec:
        raise HTTPException(status_code=404, detail="No such report")
    if rec["hunt_id"]:
        raise HTTPException(status_code=400, detail="A hunt was already started from this report")
    try:
        h = _hunt_from_intel(rec, user["email"])
    except ValueError as exc:
        raise _hunt_400(exc) from exc
    return _hunt_out(h)


@app.post("/api/hunting/hunts/{hunt_id}/queries/{index}/run")
def api_hunting_run_query(hunt_id: int, index: int, body: HuntRunBody, user: dict = Depends(rbac.require_admin)):
    """Runs one lead in the customer's SIEM (a stored Splunk search connection). Read-only; asks for confirmation first."""
    h = hunt_store.get_hunt(hunt_id)
    if not h:
        raise HTTPException(status_code=404, detail="No such hunt")
    if index < 0 or index >= len(h["queries"]):
        raise HTTPException(status_code=404, detail="No such query")
    if not _EARLIEST.match(body.earliest):
        raise HTTPException(status_code=400, detail="earliest must look like -24h, -7d or -30m")
    try:
        conn, public = hunt_service.search_connector(body.connection_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not conn:
        raise HTTPException(status_code=400, detail="No read-only search connection (Splunk, Sentinel, Google SecOps, Elastic or CrowdStrike) is configured. Add one on the Connections page.")
    q = h["queries"][index]
    language = hunt_service.language_of(conn)
    try:
        shown, _ = hunt_service.prepare_lead(q, language)
        why = None
    except hunt_translate.NotExpressible as exc:
        shown, why = None, str(exc)
    if not body.confirm:
        return {"preview_only": True, "query": shown, "language": language, "not_expressible": why, "connection": public["name"], "earliest": body.earliest,
                "message": "This read-only search will run in your SIEM. Send confirm: true to run it." if not why else f"This lead cannot be written in {language}: {why}"}
    _lookback_cfg(_earliest_days(body.earliest), body.justification, user["email"], f"hunt {hunt_id}")
    try:
        res = hunt_service.run_hunt_query(hunt_id, index, conn, body.earliest, connection_name=public["name"])
    except sec_search.SearchRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"The search failed: {str(exc)[:200]}") from exc
    activity_log.record_activity(user["email"], "hunt.query.run", str(hunt_id), {"index": index, "count": res["count"], "connection": public["name"], "language": language})
    return {"query": res, "hunt": _hunt_out(hunt_store.get_hunt(hunt_id))}


@app.get("/api/hunting/hunts/{hunt_id}/run-plan")
def api_hunting_run_plan(hunt_id: int, earliest: str = "-24h", connection_id: int | None = None, only_unrun: bool = True, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """The dry-run plan for run-all: which leads would run, written in which language, in which connection and over which window. Contacts nothing: no connector is built."""
    h = hunt_store.get_hunt(hunt_id)
    if not h:
        raise HTTPException(status_code=404, detail="No such hunt")
    if not _EARLIEST.match(earliest):
        raise HTTPException(status_code=400, detail="earliest must look like -24h, -7d or -30m")
    try:
        public = hunt_service.find_search_connection(connection_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cap = int(((hunt_soc.config().get("hunting") or {}).get("max_trial_hits_per_run")) or 30)
    if not public:
        return {"connection": None, "message": "No read-only search connection is configured, so nothing could run. Showing the leads in Splunk SPL for reference.", **hunt_service.plan_hunt(h, "splunk-spl", earliest, cap, only_unrun)}
    language = hunt_service.connection_language(public)
    return {"connection": {"id": public["id"], "name": public["name"], "type": public["type"], "enabled": public["enabled"]}, "contacts_siem": False,
            "look_back_ceiling_days": int(hunt_soc.config().get("max_lookback_days", 90)), "window_days": _earliest_days(earliest),
            "needs_justification": _earliest_days(earliest) > int(hunt_soc.config().get("max_lookback_days", 90)), "message": f"Plan only: nothing was sent to {public['name']}.", **hunt_service.plan_hunt(h, language, earliest, cap, only_unrun)}


@app.post("/api/hunting/hunts/{hunt_id}/run-all")
def api_hunting_run_all(hunt_id: int, body: RunAllBody, user: dict = Depends(rbac.require_admin)):
    """Runs every lead of a hunt in turn, read-only, in the customer's SIEM. At most max_trial_hits_per_run leads per call; a look-back past the ceiling needs a
    written justification. Previews first; one failing lead is recorded on that lead and the rest still run."""
    h = hunt_store.get_hunt(hunt_id)
    if not h:
        raise HTTPException(status_code=404, detail="No such hunt")
    if not _EARLIEST.match(body.earliest):
        raise HTTPException(status_code=400, detail="earliest must look like -24h, -7d or -30m")
    try:
        conn, public = hunt_service.search_connector(body.connection_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not conn:
        raise HTTPException(status_code=400, detail="No read-only search connection (Splunk, Sentinel, Google SecOps, Elastic or CrowdStrike) is configured. Add one on the Connections page.")
    cap = int(((hunt_soc.config().get("hunting") or {}).get("max_trial_hits_per_run")) or 30)
    language = hunt_service.language_of(conn)
    todo = [i for i, q in enumerate(h["queries"]) if (q.get("query") or q.get("selection")) and not (body.only_unrun and q.get("result") in ("hits", "no-hits"))]
    chosen, skipped = todo[:cap], max(0, len(todo) - cap)
    if not body.confirm:
        plan = hunt_service.plan_hunt(h, language, body.earliest, cap, body.only_unrun)
        return {"preview_only": True, "connection": public["name"], "language": language, "earliest": body.earliest,
                "leads": [{"index": i, "name": h["queries"][i]["name"], "technique": h["queries"][i].get("technique")} for i in chosen],
                "plan": plan["leads"], "not_run_because_of_the_cap": skipped, "cap": cap,
                "message": f"{len(chosen)} read-only search(es) will run in {public['name']} ({language}) over {body.earliest}; {sum(1 for r in plan['leads'] if r['state'] == 'not-expressible')} lead(s) cannot be written in this language and will be recorded as not expressible. Send confirm: true to run them."}
    _lookback_cfg(_earliest_days(body.earliest), body.justification, user["email"], f"hunt {hunt_id}")
    results = []
    for i in chosen:
        try:
            r = hunt_service.run_hunt_query(hunt_id, i, conn, body.earliest, connection_name=public["name"])
            results.append({"index": i, "name": h["queries"][i]["name"], "count": r["count"], "error": None, "state": r["result"], "language": r.get("language_run"),
                            "query": r.get("query_run"), "reason": r.get("not_expressible_reason")})
        except Exception as exc:  # noqa: BLE001 - recorded on the lead by run_hunt_query; the rest still run
            results.append({"index": i, "name": h["queries"][i]["name"], "count": None, "error": str(exc)[:200], "state": "error", "language": language, "query": None, "reason": None})
    activity_log.record_activity(user["email"], "hunt.run_all", str(hunt_id), {"language": language, "leads": len(chosen), "failed": sum(1 for r in results if r["error"]), "connection": public["name"], "earliest": body.earliest})
    return {"preview_only": False, "ran": len(chosen), "failed": sum(1 for r in results if r["error"]), "not_run_because_of_the_cap": skipped, "results": results, "hunt": _hunt_out(hunt_store.get_hunt(hunt_id))}


@app.post("/api/soc/alerts/{alert_id}/follow-up")
def api_soc_follow_up(alert_id: int, body: FollowUpBody, user: dict = Depends(rbac.require_admin)):
    """A question asked after the first report (similar alerts, an entity's history, where an indicator was seen), answered from the data Quanta holds and
    optionally one read-only SIEM search. The answer is merged into the stored investigation and its report."""
    alert = hunt_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    stored = hunt_service.latest_investigation(alert_id)
    if not stored:
        raise HTTPException(status_code=400, detail="Investigate the alert first; a follow-up adds to its report")
    siem_run = None
    if body.siem:
        try:
            sconn, spub = hunt_service.search_connector(body.siem_connection_id)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not sconn:
            raise HTTPException(status_code=400, detail="No read-only search connection (Splunk, Sentinel, Google SecOps, Elastic or CrowdStrike) is configured. Add one on the Connections page.")
        if not body.confirm:
            return {"preview_only": True, "siem_connection": spub["name"], "message": "One read-only search will run in your SIEM for this value. Send confirm: true to run it."}
        siem_run = search_base.Runner(sconn)
    try:
        ans = hunt_soc.follow_up(alert, stored["investigation"], body.kind, body.value, hunt_store.list_alerts(), dashboard_data.load_live_queue(), siem_run=siem_run)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    inv = stored["investigation"]
    inv["report"]["followups"] = (inv["report"].get("followups") or [])[-19:] + [{"question": ans["question"], "answer": ans["answer"], "asked": ans["asked"]}]
    md = hunt_soc.render_markdown(alert, inv)
    iid = hunt_service.save_investigation(inv, md, user["email"])
    activity_log.record_activity(user["email"], "soc.alert.follow_up", str(alert_id), {"kind": body.kind, "siem": bool(siem_run)})
    return {"id": iid, **ans, "investigation": inv, "report_md": md}


@app.post("/api/ingest/alerts/ocsf")
async def api_ingest_alerts_ocsf(request: Request, key: dict = Depends(require_api_key("soc:write"))):
    """OCSF Detection Finding events (class_uid 2004): one JSON object, a list, or {"events": [...]}."""
    try:
        data = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="The body must be JSON") from exc
    events = data.get("events") if isinstance(data, dict) and "events" in data else data
    events = events if isinstance(events, list) else [events]
    created, repeats, errors = 0, 0, []
    auto = _AutoInvestigator()
    for i, ev in enumerate(events[:2000]):
        try:
            a = hunt_ocsf.map_detection_finding(ev)
            row, new = hunt_store.receive_alert({**a, "source": f"apikey:{key['name']}"})
            created += new
            if new:
                auto.run(row)
                _soar_auto(row)
            repeats += not new
        except ValueError as exc:
            errors.append({"index": i, "error": str(exc)})
    activity_log.record_activity(f"apikey:{key['name']}", "soc.alerts.push", "ocsf", {"created": created, "repeats": repeats, "rejected": len(errors)})
    return {"created": created, "already_known": repeats, "rejected": len(errors), "errors": errors[:50], "investigated": auto.done}


@app.post("/api/soc/alerts/{alert_id}/investigate")
def api_soc_investigate(alert_id: int, body: InvestigateBody, user: dict = Depends(rbac.require_admin)):
    """Runs the L1 investigation. Local by default; reputation lookups and SIEM searches only happen with confirm: true."""
    alert = hunt_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    lookup = siem_run = None
    rep_name = siem_name = None
    if body.reputation or body.siem:
        if body.reputation:
            try:
                rconn, rpub = hunt_service.connector("reputation", body.reputation_connection_id)
            except (ValueError, KeyError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if not rconn:
                raise HTTPException(status_code=400, detail="No reputation connection is configured. Add one on the Connections page.")
            rep_name, lookup = rpub["name"], rconn.lookup
        if body.siem:
            try:
                sconn, spub = hunt_service.search_connector(body.siem_connection_id)
            except (ValueError, KeyError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if not sconn:
                raise HTTPException(status_code=400, detail="No read-only search connection (Splunk, Sentinel, Google SecOps, Elastic or CrowdStrike) is configured. Add one on the Connections page.")
            siem_name = spub["name"]
            siem_run = search_base.Runner(sconn)
        if not body.confirm:
            sendable = [i["value"] for i in hunt_soc.indicators(alert) if hunt_rep.classify(i["value"])[0]] if body.reputation else []
            return {"preview_only": True, "reputation_connection": rep_name, "indicators_that_would_be_sent": sendable, "siem_connection": siem_name,
                    "message": "Only the public indicators listed are sent to the reputation service; the SIEM searches are read-only. Send confirm: true to run."}
    cfg = _lookback_cfg(body.lookback_days, body.justification, user["email"], f"alert {alert_id}")
    inv = hunt_soc.investigate(alert, hunt_store.list_alerts(), dashboard_data.load_live_queue(), _owner_map(), lookup=lookup, siem_run=siem_run, cfg=cfg,
                               identity=_identity_map(), playbooks=soar_playbooks.list_all())
    md = hunt_soc.render_markdown(alert, inv)
    iid = hunt_service.save_investigation(inv, md, user["email"])
    decision_service.log_soc_verdict(alert, inv)
    auto = _route_investigated_alert(alert, inv)
    incident_id = None
    if auto and "case_id" in auto:   # the incident layer answered: report its case (if it has one) and the incident itself
        incident_id, auto = auto["id"], ({"id": auto["case_id"]} if auto["case_id"] else None)
    activity_log.record_activity(user["email"], "soc.alert.investigate", str(alert_id), {"verdict": inv["verdict"], "confidence": inv["confidence"],
                                                                                         "reputation": bool(lookup), "siem": bool(siem_run)})
    return {"id": iid, "investigation": inv, "report_md": md, "case_id": auto["id"] if auto else None, "incident_id": incident_id}


@app.get("/api/soc/alerts/{alert_id}/investigation")
def api_soc_investigation(alert_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    r = hunt_service.latest_investigation(alert_id)
    if not r:
        raise HTTPException(status_code=404, detail="This alert has not been investigated yet")
    return r


# ---------------------------------------------------------------- SOC operations: cases, queues, escalation, metrics, log investigation, TTP identification
class CaseOpenBody(BaseModel):
    title: str
    severity: str = "Medium"
    impact: str | None = None
    assets: list[str] = []
    techniques: list[dict] = []
    alert_ids: list[int] = []
    summary: str | None = None
    assignee: str | None = None
    tier: int = 1


class CaseActionBody(BaseModel):
    note: str | None = None
    summary: str | None = None
    assignee: str | None = None
    resolution: str | None = None
    to_tier: int | None = None
    impact: str | None = None
    alert_id: int | None = None
    reason: str | None = None
    techniques: list[dict] | None = None


class AnalystBody(BaseModel):
    email: str
    tier: int


class LogBody(BaseModel):
    text: str


class TtpBody(BaseModel):
    text: str
    learn: bool = True


def _case_400(exc):
    return HTTPException(status_code=404 if isinstance(exc, KeyError) else 400, detail=str(exc.args[0]) if isinstance(exc, KeyError) else str(exc))


def _ttp_examples():
    """Labelled history for the TTP classifier: alerts an analyst closed as true positive, with the technique each carried."""
    return [(f"{a['title']} {a.get('detail') or ''}", a["technique"]) for a in hunt_store.list_alerts() if a["disposition"] == "true-positive" and a.get("technique")][:500]


@app.get("/api/soc/cases")
def api_soc_cases(tier: int | None = None, status: str | None = None, assignee: str | None = None, priority: str | None = None, open_only: bool = False,
                  user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    soc_cases.sweep()
    return {"cases": soc_cases.list_cases(tier=tier, status=status, assignee=assignee, priority=priority, open_only=open_only), "policy": {"tiers": soc_cases.policy()["tiers"],
            "targets": soc_cases.policy()["targets"], "resolution_codes": soc_cases.policy()["resolution_codes"]}}


@app.post("/api/soc/cases")
def api_soc_case_open(body: CaseOpenBody, user: dict = Depends(rbac.require_admin)):
    try:
        c = soc_cases.open_case(body.model_dump(exclude_none=True), user["email"])
    except (ValueError, KeyError) as exc:
        raise _case_400(exc) from exc
    activity_log.record_activity(user["email"], "soc.case.open", str(c["id"]), {"priority": c["priority"], "tier": c["tier"]})
    return c


@app.get("/api/soc/cases/{case_id}")
def api_soc_case(case_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    c = soc_cases.get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="No such case")
    c["alerts"] = [a for a in (hunt_store.get_alert(i) for i in c["alert_ids"]) if a]
    c["generated_summary"] = soc_cases.summarise(c, c["alerts"])
    c["suggested_assignee"] = soc_cases.suggest_assignee(c["tier"])
    return c


@app.post("/api/soc/cases/{case_id}/analyse-logs")
def api_soc_case_logs(case_id: int, body: LogBody, user: dict = Depends(rbac.require_admin)):
    """Analyses pasted log lines locally and records a short finding on the case. No data leaves Quanta."""
    if not soc_cases.get_case(case_id, detail=False):
        raise HTTPException(status_code=404, detail="No such case")
    res = soc_loganalysis.analyse(body.text, _ttp_examples())
    bits = []
    if res.get("beaconing"):
        bits.append(f"{len(res['beaconing'])} regular-interval pair(s)")
    if res.get("bursts"):
        bits.append(f"{len(res['bursts'])} burst(s)")
    if res.get("auth_pattern"):
        bits.append("failures followed by a success")
    if res.get("techniques"):
        bits.append("techniques " + ", ".join(t["id"] for t in res["techniques"]))
    try:
        soc_cases.add_note(case_id, f"Log analysis of {res.get('lines', 0)} lines: " + ("; ".join(bits) if bits else "nothing notable") + ".", user["email"], kind="evidence")
    except ValueError:
        pass
    activity_log.record_activity(user["email"], "soc.case.logs", str(case_id), {"lines": res.get("lines", 0)})
    return res


@app.post("/api/soc/cases/{case_id}/{action}")
def api_soc_case_action(case_id: int, action: str, body: CaseActionBody, user: dict = Depends(rbac.require_admin)):
    me = user["email"]
    try:
        if action == "note":
            c = soc_cases.add_note(case_id, body.note, me)
        elif action == "assign":
            c = soc_cases.assign(case_id, body.assignee or me, me)
        elif action == "acknowledge":
            c = soc_cases.acknowledge(case_id, me)
        elif action == "pending":
            c = soc_cases.set_pending(case_id, body.reason, me)
        elif action == "escalate":
            c = soc_cases.escalate(case_id, body.summary, me, to_tier=body.to_tier)
        elif action == "resolve":
            c = soc_cases.resolve(case_id, body.resolution, body.summary, me)
        elif action == "close":
            c = soc_cases.close(case_id, body.summary, me)
        elif action == "reopen":
            c = soc_cases.reopen(case_id, body.reason, me)
        elif action == "impact":
            c = soc_cases.set_impact(case_id, body.impact, me)
        elif action == "link-alert":
            c = soc_cases.link_alert(case_id, body.alert_id, me)
        elif action == "techniques":
            c = soc_cases.set_techniques(case_id, body.techniques or [], me)
        else:
            raise HTTPException(status_code=404, detail="Unknown case action")
    except (ValueError, KeyError) as exc:
        raise _case_400(exc) from exc
    activity_log.record_activity(me, f"soc.case.{action}", str(case_id), {"status": c["status"], "tier": c["tier"]})
    return c


@app.post("/api/soc/analyse-logs")
def api_soc_analyse_logs(body: LogBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return soc_loganalysis.analyse(body.text, _ttp_examples())


@app.post("/api/soc/ttp")
def api_soc_ttp(body: TtpBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return hunt_ttp.classify(body.text[:20000], _ttp_examples() if body.learn else ())


@app.get("/api/soc/metrics")
def api_soc_metrics(days: int = 30, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    soc_cases.sweep()
    return soc_metrics.compute(days=max(1, min(days, 365)))


@app.get("/api/soc/analysts")
def api_soc_analysts(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    extra = {r["email"]: r for r in incident_roster.list_roster()}
    return {"analysts": [{**a, **{k: v for k, v in extra.get(a["email"], {}).items() if k not in a}} for a in soc_cases.list_analysts()]}


class AnalystUpdateBody(BaseModel):
    email: str
    tier: int | None = None
    skills: list[str] | None = None
    available: bool | None = None
    shift_start: str | None = None
    shift_end: str | None = None
    on_call: bool | None = None
    capacity: int | None = None


@app.put("/api/soc/analysts")
def api_soc_analyst_update(body: AnalystUpdateBody, user: dict = Depends(rbac.require_admin)):
    """Sets an analyst's routing attributes: specialties, availability, shift (UTC HH:MM), on-call, capacity and (optionally) tier. Only the fields sent change.
    When the change means the analyst no longer qualifies for incidents they own, those are re-routed with the reason recorded."""
    fields = body.model_dump(exclude_unset=True)
    email = fields.pop("email")
    try:
        a = incident_roster.update_analyst(email, fields)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    moved = incident_service.rebalance_analyst(a["email"]) if incident_store.enabled() else []
    activity_log.record_activity(user["email"], "soc.analyst.update", a["email"], {k: v for k, v in fields.items() if k != "skills"} | {"skills": a["skills"], "rerouted": len(moved)})
    return {"analyst": a, "rerouted_incident_ids": moved}


@app.post("/api/soc/analysts")
def api_soc_analyst_add(body: AnalystBody, user: dict = Depends(rbac.require_admin)):
    try:
        out = soc_cases.add_analyst(body.email, body.tier)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soc.analyst.set", body.email, {"tier": body.tier})
    return {"analysts": out}


@app.delete("/api/soc/analysts/{email}")
def api_soc_analyst_remove(email: str, user: dict = Depends(rbac.require_admin)):
    activity_log.record_activity(user["email"], "soc.analyst.remove", email, None)
    return {"analysts": soc_cases.remove_analyst(email)}


# ---------------------------------------------------------------- SOC incidents: automatic grouping, routing and the analyst's work queue (docs/SOC_INCIDENTS.md)
class IncidentActionBody(BaseModel):
    note: str | None = None
    summary: str | None = None
    assignee: str | None = None
    verdict: str | None = None
    to_tier: int | None = None
    reason: str | None = None
    status: str | None = None
    source_id: int | None = None
    alert_ids: list[int] | None = None


class ManualIncidentBody(BaseModel):
    title: str
    reason: str
    severity: str = "Medium"
    assets: list[str] = []
    alert_ids: list[int] = []
    summary: str | None = None


class IncidentAiBody(BaseModel):
    confirm: bool = False
    save: bool = False


def _incident_err(exc):
    return HTTPException(status_code=404 if isinstance(exc, KeyError) else 400, detail=str(exc.args[0]) if isinstance(exc, KeyError) else str(exc))


def _incident_ctx():
    return incident_service.Context(dashboard_data.load_live_queue(), _owner_map())


@app.get("/api/soc/incidents/stream")
def api_soc_incidents_stream(request: Request, after: int | None = None, max_seconds: int | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Server-Sent Events: incident.created / incident.assigned / incident.updated plus heartbeat comments. Read-only. Resumes from the Last-Event-ID header (or ?after=)."""
    last = request.headers.get("last-event-id")
    after_id = int(last) if last and last.isdigit() else after
    cap = incident_store.policy()["stream"]["max_seconds"]
    return StreamingResponse(incident_stream.generate(after_id=after_id, max_seconds=min(cap, max_seconds) if max_seconds is not None else cap), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/soc/incidents")
def api_soc_incidents(assignee: str | None = None, queue: str | None = None, status: str | None = None, severity: str | None = None, tier: int | None = None,
                      mine: bool = False, unassigned: bool = False, open_only: bool = False, user: dict = Depends(rbac.require_admin)):
    rows = incident_store.list_incidents(assignee=assignee, queue=queue, status=status, severity=severity, tier=tier, mine=user["email"] if mine else None,
                                         open_only=open_only, unassigned=unassigned)
    if status != "merged":
        rows = [r for r in rows if r["status"] != "merged"]
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"incidents": rows, "counts": counts, "enabled": incident_store.enabled(), "statuses": list(incident_store.STATUSES), "verdicts": list(incident_store.VERDICTS)}


@app.get("/api/soc/incidents/{incident_id}")
def api_soc_incident(incident_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    inc = incident_store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="No such incident")
    pbs = soar_playbooks.list_all()
    by_id = {p["id"]: p for p in pbs}
    past = []
    for run in soar_engine.list_runs(limit=300):
        a, p = hunt_store.get_alert(run["alert_id"]), by_id.get(run["playbook_id"])
        if a and p and not run["dry_run"]:
            past.append({"alert": a, "run": run, "playbook": p})
    inc["recommended"] = incident_service.recommended_actions(incident_id, pbs, past)
    inc["related_incidents"] = incident_service.related_incidents(incident_id)
    inc["alert_count"] = len(inc["alerts"])
    return inc


@app.post("/api/soc/incidents/manual")
def api_soc_incident_manual(body: ManualIncidentBody, user: dict = Depends(rbac.require_admin)):
    """The exception path (overflow menu): create an incident by hand. A reason is required and audited. Routed by the same rules as any other."""
    try:
        return incident_service.create_manual(body.model_dump(exclude={"reason"}), user["email"], body.reason)
    except (ValueError, KeyError) as exc:
        raise _incident_err(exc) from exc


@app.post("/api/soc/incidents/sweep")
def api_soc_incident_sweep(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """Runs the periodic sweep now (the leader tick runs it hourly): sync tiers, escalate at-risk clocks, re-route owners who no longer qualify, retry queued ones."""
    return incident_service.sweep()


@app.get("/api/soc/routing/preview")
def api_soc_routing_preview(alert_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """What would happen to an alert: which incident it would join (and why) or that it would start one, and who it would be routed to (and why). Writes nothing."""
    alert = hunt_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    r = hunt_service.latest_investigation(alert_id)
    return incident_service.preview(alert, inv=r["investigation"] if r else None, ctx=_incident_ctx())


@app.post("/api/soc/incidents/{incident_id}/ai-summary")
def api_soc_incident_ai_summary(incident_id: int, body: IncidentAiBody, user: dict = Depends(rbac.require_admin)):
    """Optional model-written summary beside the deterministic one. Counts and labels only are sent; confirm-gated; saved only when save is true."""
    from remediation.soc.incidents import summary as incident_summary
    inc = incident_store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="No such incident")
    prompt = incident_summary.ai_prompt({**inc, "alert_count": len(inc["alerts"])})
    if not body.confirm:
        return {"dry_run": True, "prompt": prompt, "message": "Preview only. Nothing was sent. The prompt has counts and labels, never alert text, host or account names. Send confirm: true to ask the model; this spends API usage."}
    governance = _enforce_ai_usage_limit(user["email"])
    text = _run_ai_call_and_record_usage(prompt, "incident-summary", user["email"], governance)
    text = text.strip() if isinstance(text, str) else str(text)
    if body.save:
        incident_store.write(incident_id, {"summary_ai": text})
        incident_store.add_event(incident_id, "ai_summary", user["email"], "A model-written summary was saved beside the deterministic one", None)
    activity_log.record_activity(user["email"], "soc.incident.ai_summary", str(incident_id), {"saved": body.save})
    return {"dry_run": False, "summary_ai": text, "saved": body.save, "note": "A suggestion. The deterministic summary stays the record."}


# Investigation reports (docs/INVESTIGATION_REPORTS.md). Included here, before the generic /api/soc/incidents/{id}/{action} route, so its "follow-up" is not taken as an action.
app.include_router(investigation_api.build_router(require_api_key=require_api_key, identity_map=lambda: _identity_map(), lookback_cfg=lambda *a, **k: _lookback_cfg(*a, **k),
                                                  auto_investigator=lambda: _AutoInvestigator(), soar_auto=lambda row: _soar_auto(row)))


@app.post("/api/soc/incidents/{incident_id}/{action}")
def api_soc_incident_action(incident_id: int, action: str, body: IncidentActionBody, user: dict = Depends(rbac.require_admin)):
    me = user["email"]
    try:
        if action == "accept":
            out = incident_service.accept(incident_id, me)
        elif action == "advance":
            out = incident_service.advance(incident_id, body.status, me, note=body.note)
        elif action == "reassign":
            out = incident_service.reassign(incident_id, body.assignee, me, body.reason)
        elif action == "escalate":
            out = incident_service.escalate(incident_id, body.summary, me, to_tier=body.to_tier)
        elif action == "resolve":
            out = incident_service.resolve(incident_id, body.verdict, body.summary or "", me)
        elif action == "reopen":
            out = incident_service.reopen(incident_id, body.reason, me)
        elif action == "merge":
            if not body.source_id:
                raise ValueError("Give source_id: the incident to merge into this one")
            out = incident_service.merge(incident_id, body.source_id, me)
        elif action == "split":
            out = incident_service.split(incident_id, body.alert_ids or [], me)
        elif action == "undo-auto-close":
            out = incident_service.undo_auto_close(incident_id, me, body.reason)
        elif action == "note":
            if not (body.note or "").strip():
                raise ValueError("A note cannot be empty")
            if not incident_store.raw_incident(incident_id):
                raise KeyError("No such incident")
            incident_store.add_event(incident_id, "note", me, body.note.strip())
            out = incident_store.get_incident(incident_id)
        else:
            raise HTTPException(status_code=404, detail=f"No such action '{action}'")
    except (ValueError, KeyError) as exc:
        raise _incident_err(exc) from exc
    activity_log.record_activity(me, f"soc.incident.{action}", str(incident_id), {"verdict": body.verdict, "assignee": body.assignee, "to_tier": body.to_tier})
    return out


class UseCaseStatusBody(BaseModel):
    status: str
    note: str | None = None


class ConfirmBody(BaseModel):
    confirm: bool = False


class DraftPlaybookBody(BaseModel):
    alert_id: int
    confirm: bool = False


def _usecases():
    cases = hunt_usecases.generate_all(dashboard_data.load_live_queue(), hunt_store.list_alerts(), hunt_store.list_hunts(), hunt_service.list_intel(),
                                       hunt_detection.list_rules(), hunt_detection.policy())
    return hunt_usecase_store.sync(cases)


@app.get("/api/detections/usecases")
def api_detection_usecases(status: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    rows = _usecases()
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"use_cases": [r for r in rows if not status or r["status"] == status], "counts": counts,
            "note": "Proposals for a detection engineer, built from your findings, intelligence, hunts and alerts. Nothing is deployed, and a draft is not counted as coverage."}


@app.post("/api/detections/usecases/{key}/status")
def api_detection_usecase_status(key: str, body: UseCaseStatusBody, user: dict = Depends(rbac.require_admin)):
    try:
        out = hunt_usecase_store.set_status(key, body.status, body.note, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such use case") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "detections.usecase", key, {"status": body.status})
    return out


@app.post("/api/detections/usecases/{key}/ai-refine")
def api_detection_usecase_refine(key: str, body: ConfirmBody, user: dict = Depends(rbac.require_admin)):
    """Optional model suggestion beside a use case: sharper hypothesis, evasions, false-positive sources, test ideas. Counts and ids only are sent; confirm-gated."""
    case = hunt_usecase_store.get(key)
    if not case:
        raise HTTPException(status_code=404, detail="No such use case")
    prompt = soar_ai_draft.usecase_prompt(case)
    if not body.confirm:
        return {"dry_run": True, "prompt": prompt, "message": "Preview only. Nothing was sent. Send confirm: true to ask the model; this spends API usage."}
    governance = _enforce_ai_usage_limit(user["email"])
    text = _run_ai_call_and_record_usage(prompt, "usecase-refine", user["email"], governance)
    out = hunt_usecase_store.set_ai(key, text.strip() if isinstance(text, str) else str(text))
    activity_log.record_activity(user["email"], "detections.usecase.ai", key, {})
    return {"dry_run": False, "use_case": out}


@app.get("/api/soc/alerts/{alert_id}/recommend-playbook")
def api_soc_recommend_playbook(alert_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    alert = hunt_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    pbs = soar_playbooks.list_all()
    by_id = {p["id"]: p for p in pbs}
    past = []
    for run in soar_engine.list_runs(limit=500):
        a, p = hunt_store.get_alert(run["alert_id"]), by_id.get(run["playbook_id"])
        if a and p and not run["dry_run"] and run["alert_id"] != alert_id:
            past.append({"alert": a, "run": run, "playbook": p})
    return soar_recommend.recommend(alert, pbs, past)


@app.post("/api/soar/draft-playbook")
def api_soar_draft_playbook(body: DraftPlaybookBody, user: dict = Depends(rbac.require_admin)):
    """A model drafts a playbook for an alert type. The draft is run through the same validator as any playbook and is returned, never saved or run."""
    alert = hunt_store.get_alert(body.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    prompt = soar_ai_draft.playbook_prompt(soar_recommend.features(alert))
    if not body.confirm:
        return {"dry_run": True, "prompt": prompt, "message": "Preview only. The prompt has the alert's category, technique and rule, never its free text. Send confirm: true to ask the model."}
    governance = _enforce_ai_usage_limit(user["email"])
    text = _run_ai_call_and_record_usage(prompt, "playbook-draft", user["email"], governance)
    draft = soar_ai_draft.check_draft(text)
    activity_log.record_activity(user["email"], "soar.playbook.draft", str(body.alert_id), {"ok": draft["ok"]})
    return {"dry_run": False, "draft": draft, "note": "A draft. Edit it, then save it yourself; it has not been saved and nothing has run."}


# ---------------------------------------------------------------- Dark Web Watch: leak-site feeds, credential-exposure lookups, imported crawler output
class WatchTermsBody(BaseModel):
    domains: list[str] = []
    brands: list[str] = []
    vendors: list[str] = []
    keywords: list[str] = []
    settings: dict | None = None


class DarkwebEnableBody(BaseModel):
    enabled: bool


class DarkwebRunBody(BaseModel):
    confirm: bool = False


class DarkwebImportBody(BaseModel):
    source: str
    text: str


class DarkwebHitBody(BaseModel):
    status: str
    note: str | None = None


def _darkweb_connected():
    return {c["type"] for c in conn_store.list_connections() if c["enabled"] and c["type"] in dw_connector.LOOKUPS}


def _run_darkweb_source(source_id):
    """Runs one source now. Feeds are public reads; a lookup needs its stored connection."""
    if source_id in dw_connector.FEEDS:
        return dw_watch.run_feed(source_id, dw_connector.FEEDS[source_id]())
    if source_id in dw_connector.LOOKUPS:
        conn, _public = hunt_service.connector(source_id)
        if not conn:
            raise ValueError(f"No {source_id} connection is configured. Add one on the Connections page.")
        return dw_watch.run_lookup(source_id, conn)
    raise ValueError("This source is not fetched by Quanta; use Import")


def _run_darkweb_if_due():
    """Leader tick: reads enabled free feeds every poll_minutes and enabled credential lookups every lookup_hours. Never raises."""
    try:
        cfg = dw_watch.config()
        if not dw_watch.has_terms(cfg):
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        for s in dw_watch.sources(connected=_darkweb_connected()):
            if not s["enabled"] or s["mode"] not in ("feed", "lookup"):
                continue
            gap = datetime.timedelta(minutes=cfg["settings"]["poll_minutes"]) if s["mode"] == "feed" else datetime.timedelta(hours=cfg["settings"]["lookup_hours"])
            if s["last_run_at"] and now - datetime.datetime.strptime(s["last_run_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) < gap:
                continue
            try:
                _run_darkweb_source(s["id"])
            except Exception:  # noqa: BLE001 - recorded on the source by the runner; one bad source must not stop the others
                logging.getLogger("quanta.scheduler").warning("dark web source %s failed", s["id"])
    except Exception:  # noqa: BLE001
        logging.getLogger("quanta.scheduler").exception("dark web watch tick failed")


@app.get("/api/darkweb/overview")
def api_darkweb_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    cfg = dw_watch.config()
    hits = dw_watch.list_hits()
    counts = {}
    for h in hits:
        counts[h["status"]] = counts.get(h["status"], 0) + 1
    return {"sources": dw_watch.sources(connected=_darkweb_connected()), "terms": {k: cfg[k] for k in ("domains", "brands", "vendors", "keywords")}, "settings": cfg["settings"],
            "has_terms": dw_watch.has_terms(cfg), "hit_counts": counts, "hits": hits[:100]}


@app.put("/api/darkweb/watch-terms")
def api_darkweb_terms(body: WatchTermsBody, user: dict = Depends(rbac.require_admin)):
    def clean(xs):
        out = []
        for x in xs[:200]:
            x = str(x).strip()
            if x and len(x) <= 120 and x.lower() not in [o.lower() for o in out]:
                out.append(x)
        return out
    cur = dw_watch.config()
    settings = dict(cur["settings"])
    for k, v in (body.settings or {}).items():
        if k in settings:
            settings[k] = v
    data = {"domains": [d.lower() for d in clean(body.domains)], "brands": clean(body.brands), "vendors": clean(body.vendors), "keywords": clean(body.keywords), "settings": settings}
    dw_watch.WATCH_PATH.write_text("# Dark Web Watch terms (edited in the app). See the header of the shipped file for what each setting does.\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    activity_log.record_activity(user["email"], "darkweb.terms", None, {k: len(data[k]) for k in ("domains", "brands", "vendors", "keywords")})
    return {"terms": {k: data[k] for k in ("domains", "brands", "vendors", "keywords")}, "settings": settings}


@app.post("/api/darkweb/sources/{source_id}/enable")
def api_darkweb_enable(source_id: str, body: DarkwebEnableBody, user: dict = Depends(rbac.require_admin)):
    try:
        dw_watch.set_enabled(source_id, body.enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such source") from exc
    activity_log.record_activity(user["email"], "darkweb.source.enable", source_id, {"enabled": body.enabled})
    return {"sources": dw_watch.sources(connected=_darkweb_connected())}


@app.post("/api/darkweb/sources/{source_id}/run")
def api_darkweb_run(source_id: str, body: DarkwebRunBody, user: dict = Depends(rbac.require_admin)):
    """A free feed runs at once. A credential lookup sends your domains to that service, so it previews first and needs confirm: true."""
    if source_id in dw_connector.LOOKUPS and not body.confirm:
        return {"preview_only": True, "service": source_id, "domains_that_would_be_sent": dw_watch.config()["domains"][:20],
                "message": "Only these domains are sent to the service. Identifiers in the answer are masked and no password is kept. Send confirm: true to run."}
    try:
        res = _run_darkweb_source(source_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except dw_connector.DarkWebError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "darkweb.source.run", source_id, {k: v for k, v in res.items() if isinstance(v, int)})
    return res


@app.post("/api/darkweb/import")
def api_darkweb_import(body: DarkwebImportBody, user: dict = Depends(rbac.require_admin)):
    try:
        res = dw_watch.run_import(body.source, body.text)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such source") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "darkweb.import", body.source, {"new": res["new"]})
    return res


@app.post("/api/ingest/darkweb")
def api_ingest_darkweb(body: DarkwebImportBody, key: dict = Depends(require_api_key("darkweb:write"))):
    """Output from a crawler or a monitoring platform, posted by your pipeline. Matched against the watch terms; the rest is discarded."""
    try:
        res = dw_watch.run_import(body.source, body.text)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown source id; see the catalog on Dark Web Watch") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(f"apikey:{key['name']}", "darkweb.import", body.source, {"new": res["new"]})
    return res


@app.get("/api/darkweb/hits")
def api_darkweb_hits(status: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"hits": dw_watch.list_hits(status=status)}


@app.post("/api/darkweb/hits/{hit_id}/status")
def api_darkweb_hit_status(hit_id: int, body: DarkwebHitBody, user: dict = Depends(rbac.require_admin)):
    try:
        h = dw_watch.set_hit_status(hit_id, body.status, body.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such hit") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "darkweb.hit", str(hit_id), {"status": body.status})
    return h


@app.get("/api/detections/overview")
def api_detections_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    a = hunt_detection.assess(hunt_store.list_alerts(), hunt_detection.list_rules(), dashboard_data.load_live_queue())
    return {**a, "history": hunt_detection.list_assessments()}


@app.post("/api/detections/assess")
def api_detections_assess(user: dict = Depends(rbac.require_admin)):
    a = hunt_detection.assess(hunt_store.list_alerts(), hunt_detection.list_rules(), dashboard_data.load_live_queue())
    hunt_detection.save_assessment(a, user["email"])
    activity_log.record_activity(user["email"], "detections.assess", None, {"rules": a["totals"]["rules"], "alerts": a["totals"]["alerts"]})
    return {**a, "history": hunt_detection.list_assessments()}


@app.get("/api/detections/rules")
def api_detections_rules(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"rules": hunt_detection.list_rules()}


@app.post("/api/detections/rules")
def api_detections_add_rule(body: RuleBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = hunt_detection.upsert_rule(body.name, body.platform, body.logic, body.techniques, "text", body.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "detections.rule.save", r["name"], {})
    return r


@app.post("/api/detections/rules/import")
async def api_detections_import(request: Request, user: dict = Depends(rbac.require_admin)):
    """Sigma rules as YAML (several documents allowed) in the request body."""
    raw = (await request.body()).decode("utf-8", "replace")
    if len(raw) > 2_000_000:
        raise HTTPException(status_code=413, detail="The file is too large (limit 2 MB)")
    try:
        rules = hunt_detection.import_sigma(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "detections.rule.import", None, {"count": len(rules)})
    return {"imported": len(rules), "rules": [r["name"] for r in rules]}


@app.put("/api/detections/rules/{rule_id}")
def api_detections_enable(rule_id: int, body: RuleEnabledBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return hunt_detection.set_enabled(rule_id, body.enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such rule") from exc


@app.delete("/api/detections/rules/{rule_id}")
def api_detections_delete(rule_id: int, user: dict = Depends(rbac.require_admin)):
    if not hunt_detection.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="No such rule")
    activity_log.record_activity(user["email"], "detections.rule.delete", str(rule_id), {})
    return {"ok": True}


@app.get("/api/detections/report")
def api_detections_report(rule: str | None = None, format: str = "md", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    a = hunt_detection.assess(hunt_store.list_alerts(), hunt_detection.list_rules(), dashboard_data.load_live_queue())
    if rule:
        r = next((x for x in a["rules"] if x["rule"] == rule), None)
        if not r:
            raise HTTPException(status_code=404, detail="No such rule")
        md, title, fname = hunt_detection.rule_report_md(r), f"Detection tuning: {rule}", "tuning"
    else:
        md, title, fname = hunt_detection.summary_md(a), "Detection engineering summary", "detection-summary"
    if format == "html":
        return HTMLResponse(hunt_detection.to_html(md, title), headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    return PlainTextResponse(md, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})


# ---------------------------------------------------------------- SOAR playbooks
class PlaybookBody(BaseModel):
    name: str
    description: str | None = None
    trigger: dict | None = None
    steps: list[dict]
    enabled: bool = True


class PlaybookRunBody(BaseModel):
    alert_id: int
    dry_run: bool = True
    confirm: bool = False


class RunDecisionBody(BaseModel):
    reason: str = ""


def _soar_providers():
    """What a real playbook run can reach, from the connections an administrator stored. Anything not configured is simply absent."""
    def conn(kind):
        try:
            c, _ = hunt_service.connector(kind)
            return c
        except Exception:  # noqa: BLE001
            return None
    rep = conn("reputation")
    try:
        spl, _ = hunt_service.search_connector()
    except Exception:  # noqa: BLE001
        spl = None
    email = (lambda to, subject, body: email_sender.send_email(to, subject, body)) if email_sender.is_configured() else None
    return soar_engine.Providers(lookup=rep.lookup if rep else None, siem_run=search_base.Runner(spl) if spl else None,
                                 notify_webhook=conn("notify-webhook"), send_email=email, response=conn("response-webhook"), findings=dashboard_data.load_live_queue(),
                                 owners=_owner_map(), save_investigation=lambda inv, md: hunt_service.save_investigation(inv, md, "playbook"))


def _soar_auto(alert_row):
    try:
        soar_engine.auto_run(alert_row, _soar_providers)
    except Exception:  # noqa: BLE001 - an automation failure must never lose the alert
        logging.getLogger("quanta.soar").exception("automatic playbook run failed")


@app.get("/api/soar/playbooks")
def api_soar_playbooks(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    pol = soar_playbooks.policy()
    return {"playbooks": soar_playbooks.list_all(), "templates": soar_playbooks.templates(), "step_types": soar_playbooks.STEP_TYPES,
            "actions": {k: {"label": v[0], "destructive": v[1], "allowed": k in (pol.get("allowed_response_actions") or [])} for k, v in webhook_actions.items()},
            "policy": {k: pol.get(k) for k in ("require_second_person", "max_steps", "auto_runs_per_hour")}}


@app.post("/api/soar/playbooks")
def api_soar_playbook_add(body: PlaybookBody, user: dict = Depends(rbac.require_admin)):
    try:
        pb = soar_playbooks.save(body.name, body.description, body.trigger, body.steps, user["email"], body.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soar.playbook.save", pb["name"], {"steps": len(pb["steps"]), "mode": pb["trigger"]["mode"]})
    return pb


@app.put("/api/soar/playbooks/{playbook_id}")
def api_soar_playbook_update(playbook_id: int, body: PlaybookBody, user: dict = Depends(rbac.require_admin)):
    try:
        pb = soar_playbooks.save(body.name, body.description, body.trigger, body.steps, user["email"], body.enabled, playbook_id=playbook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such playbook") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soar.playbook.save", pb["name"], {"steps": len(pb["steps"]), "mode": pb["trigger"]["mode"]})
    return pb


@app.delete("/api/soar/playbooks/{playbook_id}")
def api_soar_playbook_delete(playbook_id: int, user: dict = Depends(rbac.require_admin)):
    if not soar_playbooks.remove(playbook_id):
        raise HTTPException(status_code=404, detail="No such playbook")
    activity_log.record_activity(user["email"], "soar.playbook.delete", str(playbook_id), {})
    return {"ok": True}


@app.post("/api/soar/playbooks/{playbook_id}/run")
def api_soar_run(playbook_id: int, body: PlaybookRunBody, user: dict = Depends(rbac.require_admin)):
    """Starts a playbook on an alert. A dry run (the default) contacts nothing outside Quanta; a real run needs confirm: true."""
    pb = soar_playbooks.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="No such playbook")
    alert = hunt_store.get_alert(body.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No such alert")
    if not body.dry_run and not body.confirm:
        return {"preview_only": True, "steps": [{"type": s["type"], "params": s["params"]} for s in pb["steps"]],
                "message": "A real run changes things and can contact other systems. Send confirm: true to run it, or run it as a dry run first."}
    run = soar_engine.start(pb, alert, user["email"], dry_run=body.dry_run, providers=_soar_providers() if not body.dry_run else soar_engine.Providers(findings=dashboard_data.load_live_queue(), owners=_owner_map()))
    activity_log.record_activity(user["email"], "soar.run.start", str(run["id"]), {"playbook": pb["name"], "alert_id": alert["id"], "dry_run": body.dry_run, "status": run["status"]})
    return run


@app.get("/api/soar/runs")
def api_soar_runs(alert_id: int | None = None, status: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"runs": soar_engine.list_runs(alert_id=alert_id, status=status)}


@app.get("/api/soar/runs/{run_id}")
def api_soar_run_get(run_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    r = soar_engine.get_run(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="No such run")
    return r


@app.post("/api/soar/runs/{run_id}/approve")
def api_soar_approve(run_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        run = soar_engine.approve(run_id, user["email"], _soar_providers())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such run") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soar.run.approve", str(run_id), {"status": run["status"]})
    return run


@app.post("/api/soar/runs/{run_id}/reject")
def api_soar_reject(run_id: int, body: RunDecisionBody, user: dict = Depends(rbac.require_admin)):
    try:
        run = soar_engine.reject(run_id, user["email"], body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such run") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soar.run.reject", str(run_id), {"reason": body.reason[:200]})
    return run


@app.post("/api/soar/runs/{run_id}/cancel")
def api_soar_cancel(run_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        run = soar_engine.cancel(run_id, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such run") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "soar.run.cancel", str(run_id), {})
    return run


# ---------------------------------------------------------------- cyber risk quantification and health
class ScenarioBody(BaseModel):
    name: str
    description: str | None = None
    asset_scope: str | None = None
    category: str = "other"
    tef_min: float
    tef_likely: float
    tef_max: float
    loss_min: float
    loss_likely: float
    loss_max: float
    options: list[dict] = []
    status: str = "active"
    owner: str | None = None
    risk_id: int | None = None


def _risk_400(exc):
    return HTTPException(status_code=404 if isinstance(exc, KeyError) else 400, detail=str(exc.args[0]) if isinstance(exc, KeyError) else str(exc))


@app.get("/api/cyber-risk/overview")
def api_cyber_risk_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    findings = dashboard_data.load_live_queue()
    pol = risk_store.policy()
    port = risk_store.portfolio(risk_store.list_all(), findings, pol)
    h = risk_store.health(grc_evidence.latest(), hunt_detection.latest_assessment(), pol)
    return {"health": h, "portfolio": port, "categories": risk_store.CATEGORIES}


@app.get("/api/cyber-risk/scenarios")
def api_cyber_risk_scenarios(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"scenarios": risk_store.list_all(), "categories": risk_store.CATEGORIES, "policy": risk_store.policy()}


@app.post("/api/cyber-risk/scenarios")
def api_cyber_risk_add(body: ScenarioBody, user: dict = Depends(rbac.require_admin)):
    try:
        s = risk_store.save(body.model_dump(), user["email"])
    except quant_risk.ScenarioError as exc:
        raise _risk_400(exc) from exc
    activity_log.record_activity(user["email"], "cyber-risk.scenario.save", str(s["id"]), {"name": s["name"]})
    return s


@app.put("/api/cyber-risk/scenarios/{scenario_id}")
def api_cyber_risk_update(scenario_id: int, body: ScenarioBody, user: dict = Depends(rbac.require_admin)):
    try:
        s = risk_store.save(body.model_dump(), user["email"], scenario_id=scenario_id)
    except (quant_risk.ScenarioError, KeyError) as exc:
        raise _risk_400(exc) from exc
    activity_log.record_activity(user["email"], "cyber-risk.scenario.save", str(s["id"]), {"name": s["name"]})
    return s


@app.delete("/api/cyber-risk/scenarios/{scenario_id}")
def api_cyber_risk_delete(scenario_id: int, user: dict = Depends(rbac.require_admin)):
    if not risk_store.remove(scenario_id):
        raise HTTPException(status_code=404, detail="No such scenario")
    activity_log.record_activity(user["email"], "cyber-risk.scenario.delete", str(scenario_id), {})
    return {"ok": True}


@app.get("/api/cyber-risk/scenarios/{scenario_id}/analysis")
def api_cyber_risk_analysis(scenario_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    s = risk_store.get(scenario_id)
    if not s:
        raise HTTPException(status_code=404, detail="No such scenario")
    pol = risk_store.policy()
    res = quant_risk.evaluate_options(s, pol.get("trials", 10000), s["id"], pol.get("scenario_tolerance"))
    return {"scenario": s, **res, "signals": risk_store.signals(s, dashboard_data.load_live_queue()), "currency": pol.get("currency", "USD"),
            "tolerance": pol.get("scenario_tolerance")}


@app.post("/api/cyber-risk/simulate")
def api_cyber_risk_simulate(body: ScenarioBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    """What-if without saving: simulates the numbers as typed."""
    pol = risk_store.policy()
    try:
        data = body.model_dump()
        data["options"] = risk_store._clean_options(data.get("options"))
        return quant_risk.evaluate_options(data, pol.get("trials", 10000), 0, pol.get("scenario_tolerance"))
    except quant_risk.ScenarioError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------- DevSecOps control library, remediation queue, zero-day watch
class ControlStateBody(BaseModel):
    asset: str
    control_id: str
    state: str
    note: str = ""


class PolicyTextBody(BaseModel):
    text: str


class FactoryQueueBody(BaseModel):
    finding_ids: list[str]


class FactoryUpdateBody(BaseModel):
    state: str | None = None
    assignee: str | None = None
    pr_url: str | None = None
    notes: str | None = None


def _devsecops_inputs():
    return dso_controls.scan_runs(), dso_controls.states(), dashboard_data.load_live_queue(), len(tm_store.list_models())


def _devsecops_extras():
    """What Quanta itself holds that some controls are evidenced by: stored SBOMs and release-gate evaluations, by lower-case application name."""
    sboms = {k.strip().lower(): v for k, v in appsec_store.sbom_summaries().items()}
    return {"sboms": sboms, "gate_runs": dso_gates.last_by_application()}


@app.get("/api/devsecops/overview")
def api_devsecops_overview(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    runs, rec, findings, tms = _devsecops_inputs()
    return dso_controls.overview(runs, rec, findings, tms, extras=_devsecops_extras(), lib=dso_controls.full_library())


@app.get("/api/devsecops/repos")
def api_devsecops_repo(asset: str, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    runs, rec, findings, tms = _devsecops_inputs()
    return dso_controls.repo_report(asset, dso_controls.full_library(), runs, rec, findings, tms, extras=_devsecops_extras())


@app.post("/api/devsecops/state")
def api_devsecops_set_state(body: ControlStateBody, user: dict = Depends(rbac.require_admin)):
    try:
        dso_controls.set_state(body.asset, body.control_id, body.state, body.note, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such control") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "devsecops.state", f"{body.asset}:{body.control_id}", {"state": body.state})
    return {"ok": True}


@app.delete("/api/devsecops/state")
def api_devsecops_clear_state(asset: str, control_id: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if not dso_controls.clear_state(asset, control_id):
        raise HTTPException(status_code=404, detail="Nothing was recorded for that control")
    return {"ok": True}


@app.post("/api/devsecops/policy-check")
def api_devsecops_policy(body: PolicyTextBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    if len(body.text) > 200_000:
        raise HTTPException(status_code=413, detail="The policy text is too large")
    return dso_controls.map_policy(body.text, dso_controls.full_library())


@app.get("/api/devsecops/factory")
def api_devsecops_factory(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    f = dashboard_data.load_live_queue()
    return {"items": dso_factory.items(f), "candidates": dso_factory.candidates(f), "summary": dso_factory.summary(f), "states": dso_factory.STATES}


@app.post("/api/devsecops/factory/queue")
def api_devsecops_factory_queue(body: FactoryQueueBody, user: dict = Depends(rbac.require_admin)):
    out = dso_factory.queue(body.finding_ids, dashboard_data.load_live_queue(), user["email"])
    activity_log.record_activity(user["email"], "devsecops.factory.queue", None, {"queued": len(out["queued"]), "skipped": len(out["skipped"])})
    return out


@app.put("/api/devsecops/factory/{finding_id}")
def api_devsecops_factory_update(finding_id: str, body: FactoryUpdateBody, user: dict = Depends(rbac.require_admin)):
    try:
        row = dso_factory.update_item(finding_id, body.model_dump(exclude_unset=True))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "devsecops.factory.update", finding_id, {"state": row["state"]})
    return row


@app.get("/api/devsecops/factory/{finding_id}/brief")
def api_devsecops_factory_brief(finding_id: str, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    f = next((x for x in dashboard_data.load_live_queue() if x["id"] == finding_id), None)
    if not f or not dso_factory.is_code(f):
        raise HTTPException(status_code=404, detail="No such code-level finding")
    return PlainTextResponse(dso_factory.brief(f), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="fix-{finding_id}.md"'})


app.include_router(appsec_api.build_router(require_api_key=require_api_key, scope_findings=lambda rows, user: _scope_to_team(_annotate_finding_teams(rows), user),
                                           read_upload=_read_upload, enrich_in_background=_enrich_in_background,
                                           queue_rescan_job=lambda connection_id, actor: job_queue.enqueue(job_worker.KIND_CONNECTION_SYNC, {"connection_id": connection_id, "actor": actor},
                                                                                                          dedupe_key=f"sync:{connection_id}")))
app.include_router(mcp_api.build_router(
    load_findings=lambda: dashboard_data.load_live_queue(), load_assets=lambda: [dict(r) for r in dashboard_data._load_scored_assets()[1]],
    scope_findings=lambda rows, user: _scope_to_team(_annotate_finding_teams(rows), user), scope_assets=lambda rows, user: _scope_to_team(rows, user),
    attack_chains=lambda findings: dashboard_data.get_attack_chains(findings),
    posture=lambda findings: posture_engine.assess(findings=findings, now=datetime.datetime.now(datetime.timezone.utc))))  # read-only MCP endpoint; see dashboard/mcp_api.py
app.include_router(__import__("simulation_api").build_router())  # demonstration data through the real connector code; see dashboard/simulation_api.py


@app.get("/api/zero-day-watch")
def api_zero_day_watch(days: int = 30, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    days = max(1, min(int(days), 365))
    try:
        catalog = zero_day.fetch_catalog()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"The CISA catalog could not be fetched ({type(exc).__name__}). Try again when this server can reach cisa.gov.") from exc
    comps = []
    try:
        sb = sbom_mod.load_sbom()
        comps = [sbom_mod.component_info(c) for c in sbom_mod._all_components(sb)] if sb else []
    except Exception:  # noqa: BLE001 - the SBOM is optional
        comps = []
    return zero_day.watch(catalog, dashboard_data.load_live_queue(), comps, days)


# ---------------------------------------------------------------- external attack surface (imported discovery output; Quanta never scans)
class AsmScopeBody(BaseModel):
    domains: list[str] = []
    cidrs: list[str] = []


class AsmPublishBody(BaseModel):
    confirm: bool = False


class AsmSettingsBody(BaseModel):
    expected_cadence_hours: float | None = None


def _run_asm_stale_if_due():
    """Leader tick: if no import arrived within the expected cadence, raises one 'stale attack-surface data' SOC alert per episode. Never raises."""
    try:
        alert = asm_store.check_stale()
        if alert:
            activity_log.record_activity("system", "asm.stale", "attack-surface", {"alert_id": alert.get("id")})
    except Exception:  # noqa: BLE001 - a bad check must never stop the tick
        pass


def _asm_state():
    """The evaluation of the stored surface, judged against the asset inventory the queue and ownership records give."""
    queue = findings_merge.load()
    return asm_findings.evaluate(asm_store.all_assets(), asm_findings.known_assets(queue, asm_store.ownership()))


def _asm_publish(actor, background):
    res = _asm_state()
    items = asm_findings.to_queue_items(res["findings"])
    findings, errors = api_findings.normalise_batch(items)
    result = findings_merge.merge(findings, "asm", reconcile=True)
    activity_log.record_activity(actor, "asm.publish", "asm", {"findings": len(findings), "rejected": len(errors), **result})
    if result["added"] or result["updated"]:
        _enrich_in_background(background)
    return {"published": len(findings), "rejected": len(errors), **result}


def _asm_import(tool, data, scope, complete, publish, actor, allow_seeds, background):
    try:
        text = data.decode("utf-8", "replace")
        out = asm_store.import_text(tool, text, scope_label=scope or None, complete=complete, actor=actor, allow_seeds=allow_seeds)
    except asm_parsers.ParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(actor, "asm.import", tool, {k: out[k] for k in ("records", "new", "changed", "disappeared", "out_of_scope", "skipped")})
    if publish and tool != "seeds":
        out["queue"] = _asm_publish(actor, background)
    return out


@app.post("/api/ingest/asm")
async def api_ingest_asm(request: Request, background: BackgroundTasks, tool: str, scope: str = "", complete: bool = False, publish: bool = False, key: dict = Depends(require_api_key("asm:write"))):
    """The raw output of subfinder, dnsx, httpx, naabu or nuclei as the request body (JSON lines or a JSON array). `complete=true` says the file is the whole answer for `scope`
    (a domain or range), so assets it omits are marked disappeared. The scope itself cannot be changed here."""
    return _asm_import(tool, await _read_upload(request), scope, complete, publish, f"apikey:{key['name']}", False, background)


@app.post("/api/asm/import")
async def api_asm_import(request: Request, background: BackgroundTasks, tool: str, scope: str = "", complete: bool = False, publish: bool = False, user: dict = Depends(rbac.require_admin)):
    """The same import from the page. `tool=seeds` takes a CSV of domains and ranges and declares them as your scope."""
    return _asm_import(tool, await _read_upload(request), scope, complete, publish, user["email"], True, background)


@app.get("/api/asm/summary")
def api_asm_summary(days: int = 7, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return asm_summary.build(queue_findings=findings_merge.load(), days=max(1, min(days, 365)))


@app.get("/api/asm/assets")
def api_asm_assets(kind: str | None = None, status: str | None = None, in_scope: bool | None = None, q: str | None = None, tag: str | None = None, tool: str | None = None,
                   limit: int = 500, offset: int = 0, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    out = asm_store.list_assets(kind=kind, status=status, in_scope=in_scope, q=q, tag=tag, tool=tool, limit=limit, offset=max(0, offset))
    out["data_age"] = asm_store.data_age()
    return out


@app.get("/api/asm/changes")
def api_asm_changes(days: int | None = None, change: str | None = None, limit: int = 500, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"changes": asm_store.list_changes(days=days, change=change, limit=limit), "runs": asm_store.list_runs(limit=20), "data_age": asm_store.data_age()}


@app.get("/api/asm/scope")
def api_asm_scope(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    s = asm_store.get_scope()
    return {**s, "declared": bool(s["domains"] or s["cidrs"]), "expected_cadence_hours": asm_store.get_cadence_hours(),
            "note": "Anything outside this scope is recorded and flagged, never silently included, and never raises a finding. With nothing declared, everything is treated as in scope."}


@app.put("/api/asm/scope")
def api_asm_set_scope(body: AsmScopeBody, user: dict = Depends(rbac.require_admin)):
    try:
        out = asm_store.set_scope(body.domains, body.cidrs, actor=user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "asm.scope", None, {"domains": len(out["domains"]), "cidrs": len(out["cidrs"]), "rescoped": out["rescoped"]})
    return out


@app.put("/api/asm/settings")
def api_asm_settings(body: AsmSettingsBody, user: dict = Depends(rbac.require_admin)):
    try:
        h = asm_store.set_cadence_hours(body.expected_cadence_hours)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "asm.settings", None, {"expected_cadence_hours": h})
    return {"expected_cadence_hours": h, "data_age": asm_store.data_age()}


@app.get("/api/asm/findings")
def api_asm_findings(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    res = _asm_state()
    return {**res, "rules": asm_findings.RULES, "data_age": asm_store.data_age(),
            "note": "Findings are raised by explicit rules from imported tool output. A rule with no data to judge raises nothing, and the gaps list says what is missing."}


@app.post("/api/asm/publish")
def api_asm_publish(body: AsmPublishBody, background: BackgroundTasks, user: dict = Depends(rbac.require_admin)):
    """Sends the current attack-surface findings to the main queue (source asm). It is the complete set, so findings the data no longer shows are removed."""
    if not body.confirm:
        items = asm_findings.to_queue_items(_asm_state()["findings"])
        return {"preview_only": True, "findings": len(items), "message": "This replaces the asm findings in the main queue with the current set. Send confirm: true to publish."}
    return _asm_publish(user["email"], background)


@app.get("/api/asm/how-to-feed")
def api_asm_how_to_feed(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"examples": asm_parsers.EXAMPLES, "post_example": asm_parsers.POST_EXAMPLE, "safety": asm_parsers.SAFETY, "tools": list(asm_parsers.TOOLS)}
# ---------------------------------------------------------------- Anthropic CVD feed (public coordinated-disclosure payload, a threat-intel source)
def cvd_connector_factory():
    return cvd_feed_connector.CvdFeedConnector()


def _cvd_refresh():
    return cvd_store.upsert(cvd_connector_factory().fetch())


_CVD_LAST_RUN = {"at": None}


def _run_cvd_if_due():
    """Leader tick: refreshes the public CVD feed at most hourly. OFF unless QUANTA_CVD_FEED_REFRESH=true. Never raises."""
    if os.environ.get("QUANTA_CVD_FEED_REFRESH", "").lower() != "true":
        return
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        if _CVD_LAST_RUN["at"] and now - _CVD_LAST_RUN["at"] < datetime.timedelta(hours=1):
            return
        _CVD_LAST_RUN["at"] = now
        _cvd_refresh()
    except Exception:  # noqa: BLE001
        logging.getLogger("quanta.scheduler").warning("CVD feed refresh failed")


@app.post("/api/cvd/test-connection")
def api_cvd_test_connection(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        cvd_connector_factory().test_connection()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"The CVD feed could not be reached ({type(exc).__name__}: {exc})") from exc
    return {"ok": True, "source": cvd_feed_connector.PAGE_URL}


@app.post("/api/cvd/fetch")
def api_cvd_fetch(body: ConfirmBody, user: dict = Depends(rbac.require_admin)):
    if not body.confirm:
        return {"preview_only": True, "source": cvd_feed_connector.DEFAULT_URL,
                "message": "Would read Anthropic's public CVD payload (read only, nothing about your estate is sent) and store its records. Send confirm=true to proceed."}
    try:
        result = _cvd_refresh()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"The CVD feed could not be read ({type(exc).__name__}: {exc})") from exc
    activity_log.record_activity(user["email"], "cvd.fetch", None, result)
    return result


@app.get("/api/cvd/advisories")
def api_cvd_advisories(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    comps = []
    try:
        sb = sbom_mod.load_sbom()
        comps = [sbom_mod.component_info(c) for c in sbom_mod._all_components(sb)] if sb else []
    except Exception:  # noqa: BLE001 - the SBOM is optional
        comps = []
    advisories = cvd_store.list_advisories()
    return {**cvd_store.summary(advisories, dashboard_data.load_live_queue(), comps), "advisories": advisories[:500], "source": cvd_feed_connector.PAGE_URL}


# ---------------------------------------------------------------- firewall rules management
class FwCertifyBody(BaseModel):
    device: str
    key: str
    decision: str
    note: str = ""


class FwRequestBody(BaseModel):
    sources: list[str]
    destinations: list[str]
    services: list[str]
    days: int | None = None
    justification: str
    src_zone: str | None = None
    dst_zone: str | None = None


class FwDecisionBody(BaseModel):
    status: str
    note: str = ""


def _fw_topology():
    try:
        return network_reach.load_topology()
    except Exception:  # noqa: BLE001 - topology is optional context
        return None


@app.post("/api/firewall/import")
async def api_firewall_import(request: Request, device: str, format: str = "", user: dict = Depends(rbac.require_admin)):
    """A firewall's rules as the request body: CSV, JSON, PAN-OS configuration XML or FortiGate policy text. Replaces that device's rules."""
    raw = (await request.body()).decode("utf-8", "replace")
    if len(raw) > 30_000_000:
        raise HTTPException(status_code=413, detail="The file is too large (limit 30 MB)")
    try:
        out = fw_store.import_rules(device, raw, format or None, user["email"])
    except fw_model.RuleFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "firewall.import", device, {k: out[k] for k in ("format", "rules", "added", "removed")})
    return out


@app.get("/api/firewall/overview")
def api_firewall_overview(device: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    rs = fw_store.rules(device)
    f = fw_analysis.analyse(rs)
    return {"summary": fw_analysis.summary(rs, f), "findings": f[:500], "exposure": fw_analysis.exposure(rs), "recert": fw_store.recert_status(rs),
            "devices": fw_store.devices(), "requests": fw_store.request_metrics(fw_store.list_requests())}


@app.get("/api/firewall/rules")
def api_firewall_rules(device: str | None = None, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"rules": fw_store.rules(device)}


@app.delete("/api/firewall/devices/{device}")
def api_firewall_delete_device(device: str, user: dict = Depends(rbac.require_admin)):
    if not fw_store.delete_device(device):
        raise HTTPException(status_code=404, detail="No such device")
    activity_log.record_activity(user["email"], "firewall.delete", device, {})
    return {"ok": True}


@app.post("/api/firewall/certify")
def api_firewall_certify(body: FwCertifyBody, user: dict = Depends(rbac.require_admin)):
    try:
        fw_store.certify(body.device, body.key, body.decision, body.note, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such rule") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "firewall.certify", f"{body.device}:{body.key}", {"decision": body.decision})
    return {"ok": True}


@app.post("/api/firewall/requests")
def api_firewall_request(body: FwRequestBody, user: dict = Depends(rbac.require_login)):
    """Anyone signed in can ask for access. The request is checked against the rules Quanta holds when it is submitted."""
    try:
        r = fw_store.submit_request(user["email"], body.sources, body.destinations, body.services, body.days, body.justification, fw_store.rules(), topology=_fw_topology(),
                                  src_zone=body.src_zone, dst_zone=body.dst_zone)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "firewall.request", str(r["id"]), {"verdict": r["check"]["verdict"], "risk": r["check"]["risk"]})
    return r


@app.get("/api/firewall/requests")
def api_firewall_requests(user: dict = Depends(rbac.require_login)):
    rs = fw_store.list_requests()
    if user.get("role") != "admin":
        rs = [r for r in rs if r["requester"] == user["email"]]
    return {"requests": rs, "metrics": fw_store.request_metrics(rs)}


@app.post("/api/firewall/requests/{request_id}/decide")
def api_firewall_decide(request_id: int, body: FwDecisionBody, user: dict = Depends(rbac.require_admin)):
    try:
        r = fw_store.decide_request(request_id, body.status, user["email"], body.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such request") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "firewall.request.decide", str(request_id), {"status": r["status"]})
    return r


# ---------------------------------------------------------------- AI security posture
class AiAssetBody(BaseModel):
    model_config = {"extra": "allow"}
    name: str
    kind: str


class AiPublishBody(BaseModel):
    confirm: bool = False


def _ai_meta():
    return {"kinds": aisec_rules.KINDS, "environments": aisec_rules.ENVIRONMENTS, "hosting": aisec_rules.HOSTING, "scopes": aisec_rules.SCOPES, "provenance": aisec_rules.PROVENANCE,
            "serialization": aisec_rules.SERIALIZATION, "data_classes": aisec_rules.DATA_CLASSES, "questions": aisec_rules.QUESTIONS, "tri": aisec_rules.TRI,
            "agent": {"transports": aisec_rules_mcp.TRANSPORTS, "auth": aisec_rules_mcp.AUTH, "side_effects": aisec_rules_mcp.SIDE_EFFECTS, "categories": aisec_rules_mcp.CATEGORIES,
                      "memory": aisec_rules_mcp.MEMORY, "eval_suites": aisec_rules_mcp.EVAL_SUITES, "server_questions": aisec_rules_mcp.SERVER_QUESTIONS, "asset_questions": aisec_rules_mcp.ASSET_QUESTIONS,
                      "server_tri": aisec_rules_mcp.SERVER_TRI, "release": aisec_rules_mcp.RELEASE_TRI, "observability": aisec_rules_mcp.OBS_TRI, "audit_log": aisec_rules_mcp.AUDIT_TRI}}


@app.get("/api/ai-security/overview")
def api_ai_security_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    assets = aisec_store.list_all()
    return {"assets": assets, "assessment": aisec_store.assess(assets), "meta": _ai_meta()}


@app.post("/api/ai-security/assets")
def api_ai_security_add(body: AiAssetBody, user: dict = Depends(rbac.require_admin)):
    try:
        a = aisec_store.save(body.model_dump(), user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "ai-security.asset.save", a["name"], {"kind": a["kind"]})
    return a


@app.put("/api/ai-security/assets/{asset_id}")
def api_ai_security_update(asset_id: int, body: AiAssetBody, user: dict = Depends(rbac.require_admin)):
    try:
        a = aisec_store.save(body.model_dump(), user["email"], asset_id=asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such asset") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "ai-security.asset.save", a["name"], {"kind": a["kind"]})
    return a


@app.delete("/api/ai-security/assets/{asset_id}")
def api_ai_security_delete(asset_id: int, user: dict = Depends(rbac.require_admin)):
    if not aisec_store.remove(asset_id):
        raise HTTPException(status_code=404, detail="No such asset")
    activity_log.record_activity(user["email"], "ai-security.asset.delete", str(asset_id), {})
    return {"ok": True}


@app.post("/api/ai-security/import-discovered")
def api_ai_security_import(user: dict = Depends(rbac.require_admin)):
    added = aisec_store.import_discovered(actor=user["email"])
    activity_log.record_activity(user["email"], "ai-security.import", None, {"added": len(added)})
    return {"added": added}


@app.post("/api/ai-security/publish")
def api_ai_security_publish(body: AiPublishBody, background: BackgroundTasks, user: dict = Depends(rbac.require_admin)):
    """Sends the current AI security findings to the main queue (source ai-security). It is the complete set, so findings the record no longer shows are removed."""
    a = aisec_store.assess(aisec_store.list_all())
    items = aisec_store.to_queue_items(a["findings"])
    if not body.confirm:
        return {"preview_only": True, "findings": len(items), "message": "This replaces the ai-security findings in the main queue with the current set. Send confirm: true to publish."}
    findings, errors = api_findings.normalise_batch(items)
    result = findings_merge.merge(findings, "ai-security", reconcile=True)
    activity_log.record_activity(user["email"], "ai-security.publish", "ai-security", {"findings": len(findings), "rejected": len(errors), **result})
    if result["added"] or result["updated"]:
        _enrich_in_background(background)
    return {"published": len(findings), "rejected": len(errors), **result}


# ---------------------------------------------------------------- API security
# Inventory, OWASP API Top 10 findings, caller activity, classification, protection policies, metrics and rollout. Admin only, except the routes a machine calls with an
# API key (scope api:write). Quanta reads exports and pushed records; it never sniffs traffic and never changes a WAF: a policy is a signed request to a URL the customer owns.
_api_http_get = None  # tests inject a fake; None means requests.get


class ApiSpecBody(BaseModel):
    content: str
    service: str | None = None


class ApiSpecFetchBody(BaseModel):
    url: str
    service: str | None = None
    confirm: bool = False


class ApiTrafficBody(BaseModel):
    records: list[dict]
    service: str | None = None
    source: str = "api-traffic"


class ApiEndpointBody(BaseModel):
    owner: str | None = None
    exposure: str | None = None
    status: str | None = None
    notes: str | None = None


class ApiPolicyBody(BaseModel):
    name: str
    kind: str
    mode: str = "monitor"
    enabled: bool = True
    scope: dict = {}
    params: dict = {}
    description: str | None = None


class ApiPushBody(BaseModel):
    confirm: bool = False
    connection_id: int | None = None


class ApiPolicyStatusBody(BaseModel):
    push_id: int
    status: str
    detail: str = ""


class ApiRolloutBody(BaseModel):
    done: bool
    note: str = ""


class ApiClassificationBody(BaseModel):
    content: str
    format: str | None = None
    replace: bool = True


def _api_state(today=None):
    eps, specs, classes = api_store.list_endpoints(), api_store.list_specs(), api_store.list_classes()
    pols = api_policies.list_all()
    actors = api_store.actor_rows()
    views, findings, gaps = api_rules.run(eps, specs, classes, actors, api_store.dependencies(), pols, today)
    return {"endpoints": eps, "specs": specs, "classes": classes, "policies": pols, "actors": actors, "views": views, "findings": findings, "gaps": gaps}


def _api_summary(st):
    v = st["views"]
    cnt = lambda key: {k: sum(1 for x in v if x[key] == k) for k in sorted({x[key] for x in v})}  # noqa: E731
    return {"endpoints": len(v), "services": len({x["service"] for x in v}), "by_state": cnt("state"), "by_exposure": cnt("exposure"), "by_auth": cnt("auth_state"),
            "sensitive_endpoints": sum(1 for x in v if x["sensitive"]), "without_owner": sum(1 for x in v if not x["owner"]),
            "findings": len(st["findings"]), "by_severity": {s: sum(1 for f in st["findings"] if f["severity"] == s) for s in api_rules.SEV_WEIGHT},
            "by_rule": {r: sum(1 for f in st["findings"] if f["rule"] == r) for r in api_rules.OWASP if any(f["rule"] == r for f in st["findings"])},
            "gaps": len(st["gaps"]), "classes": len(st["classes"]), "policies": len(st["policies"])}


def _api_notify_targets():
    def conn(kind):
        try:
            c, _ = hunt_service.connector(kind)
            return c
        except Exception:  # noqa: BLE001
            return None
    to = [a.strip() for a in os.environ.get("QUANTA_ALERT_EMAIL", "").split(",") if a.strip()]
    mail = (lambda addrs, subject, body: email_sender.send_email(addrs, subject, body)) if email_sender.is_configured() and to else None
    return conn("notify-webhook"), mail, to


@app.get("/api/api-security/overview")
def api_apisec_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    facts, manual = api_rollout.gather(db_module.get_engine(), unclassified=sum(1 for g in st["gaps"] if g["kind"] == "unclassified-data"),
                                       owners_missing=sum(1 for v in st["views"] if v["exposure"] == "external" and not v["owner"]), smtp_configured=email_sender.is_configured())
    rb = api_rollout.build(facts, manual)
    return {"summary": _api_summary(st), "specs": st["specs"], "services": sorted({v["service"] for v in st["views"]}), "gaps": st["gaps"], "dependencies": api_store.dependencies()[:50],
            "rollout": {"done": rb["done"], "total": rb["total"]}, "limits": ["Quanta reads exports and pushed records. It cannot see traffic nobody gives it.",
                                                                                   "Everything here is built against public documentation and tests with sample data; it has not been run against a live gateway, WAF or traffic source."]}


@app.get("/api/api-security/endpoints")
def api_apisec_endpoints(service: str = "", state: str = "", exposure: str = "", auth: str = "", q: str = "", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    out = [v for v in st["views"] if (not service or v["service"] == service) and (not state or v["state"] == state) and (not exposure or v["exposure"] == exposure)
           and (not auth or v["auth_state"] == auth) and (not q or q.lower() in (v["template"] + " " + v["service"]).lower())]
    return {"endpoints": out[:3000], "total": len(out), "services": sorted({v["service"] for v in st["views"]}), "states": ["documented", "shadow", "undocumented", "spec-only"],
            "exposures": list(api_store.EXPOSURES), "statuses": list(api_store.STATUSES)}


@app.get("/api/api-security/endpoints/{endpoint_id}")
def api_apisec_endpoint(endpoint_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    v = next((x for x in st["views"] if x["id"] == endpoint_id), None)
    if not v:
        raise HTTPException(status_code=404, detail="No such endpoint")
    ep = next(e for e in st["endpoints"] if e["id"] == endpoint_id)
    rows = api_store.metrics_rows(endpoint_id=endpoint_id)
    actors = {}
    for a in st["actors"]:
        if a["endpoint_id"] == endpoint_id:
            x = actors.setdefault(a["actor"], {"actor": a["actor"], "calls": 0, "bytes_out": 0, "max_distinct_objects": 0})
            x["calls"] += a["calls"]
            x["bytes_out"] += a["bytes_out"]
            x["max_distinct_objects"] = max(x["max_distinct_objects"], a["distinct_objects"])
    return {"endpoint": v, "spec": ep.get("spec"), "observed": {k: ep["obs"][k] for k in ("query_params", "request_fields", "response_fields", "detected", "auth_counts", "status_counts", "jwt", "rules")},
            "findings": [f for f in st["findings"] if f["endpoint_id"] == endpoint_id], "series": api_metrics.series(rows), "trend": api_metrics.trend(rows),
            "callers": sorted(actors.values(), key=lambda x: -x["calls"])[:25], "policies": [{"id": p["id"], "name": p["name"], "kind": p["kind"], "mode": p["mode"]} for p in st["policies"]
                                                                                              if p["enabled"] and api_policies.covers(p, v["service"], v["method"], v["path_key"])]}


@app.patch("/api/api-security/endpoints/{endpoint_id}")
def api_apisec_endpoint_update(endpoint_id: int, body: ApiEndpointBody, user: dict = Depends(rbac.require_admin)):
    fields = set(body.model_fields_set)
    try:
        ep = api_store.update_endpoint(endpoint_id, owner=body.owner, exposure=body.exposure, status=body.status, notes=body.notes, fields=fields)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such endpoint") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "api-security.endpoint.update", f"{ep['method']} {ep['template']}", {"fields": sorted(fields), "service": ep["service"]})
    return {"id": ep["id"], "owner": ep["owner"], "exposure_override": ep["exposure_override"], "status": ep["status"], "notes": ep["notes"]}


# ---- specifications and traffic
def _api_spec_import(text, service, source, actor, source_ref=None):
    try:
        out = api_store.import_spec(text, service, source, actor, source_ref=source_ref)
    except api_openapi.SpecError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    out["drift"] = api_store.drift(out["service"])
    activity_log.record_activity(actor, "api-security.spec", out["service"], {"operations": out["operations"], "source": source})
    return out


@app.get("/api/api-security/specs")
def api_apisec_specs(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"specs": api_store.list_specs()}


@app.post("/api/api-security/specs")
def api_apisec_spec_upload(body: ApiSpecBody, user: dict = Depends(rbac.require_admin)):
    return _api_spec_import(body.content, body.service, "upload", user["email"])


@app.post("/api/api-security/specs/fetch")
def api_apisec_spec_fetch(body: ApiSpecFetchBody, user: dict = Depends(rbac.require_admin)):
    """Fetches a specification from a URL. An outbound request, so it needs confirm: true; the destination is checked with the SSRF guard and redirects are not followed."""
    url = body.url.strip()
    if not re.match(r"^https?://", url, re.I):
        raise HTTPException(status_code=400, detail="The URL must start with http:// or https://")
    try:
        url_safety.assert_safe_target(url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=f"url: {exc}") from exc
    if not body.confirm:
        return {"preview_only": True, "url": url, "message": "This makes an outbound request from the Quanta server to that URL. Send confirm: true to fetch it."}
    import requests as _rq
    get = _api_http_get or _rq.get
    try:
        resp = get(url, timeout=20, allow_redirects=False, headers={"Accept": "application/json, application/yaml, text/yaml, */*"}, stream=True)
        if resp.status_code in (301, 302, 303, 307, 308):
            raise HTTPException(status_code=400, detail="The URL redirects. Redirects are not followed; use the final address.")
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"The server answered {resp.status_code}")
        data = b""
        for chunk in resp.iter_content(65536):
            data += chunk
            if len(data) > api_openapi.MAX_BYTES:
                break
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Could not fetch the specification: {str(exc)[:150]}") from exc
    if len(data) > api_openapi.MAX_BYTES:
        raise HTTPException(status_code=400, detail="A specification may be at most 5 MB")
    return _api_spec_import(data.decode("utf-8", "replace"), body.service, "url", user["email"], source_ref=re.sub(r"\?.*$", "", url)[:300])


@app.delete("/api/api-security/specs/{service}")
def api_apisec_spec_delete(service: str, user: dict = Depends(rbac.require_admin)):
    if not api_store.delete_spec(service):
        raise HTTPException(status_code=404, detail="No such specification")
    activity_log.record_activity(user["email"], "api-security.spec.delete", service, {})
    return {"ok": True}


@app.get("/api/api-security/generated-spec")
def api_apisec_generated_spec(service: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    doc = api_generate.build(service, api_store.list_endpoints(), api_store.list_classes(), api_store.list_specs())
    if not doc:
        raise HTTPException(status_code=404, detail="No observed traffic for that service")
    return doc


@app.get("/api/api-security/drift")
def api_apisec_drift(service: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return api_store.drift(service)


def _api_traffic(records, service, source, actor, stats=None):
    if len(records) > api_config.threshold("max_records_per_import"):
        raise HTTPException(status_code=413, detail=f"At most {api_config.threshold('max_records_per_import'):,} records per import")
    out = api_store.ingest_records(records, default_service=service, source=source)
    activity_log.record_activity(actor, "api-security.traffic", source, {"records": out["records"], "endpoints": out["endpoints"], "new": out["new_endpoints"]})
    return {**out, **({"read": stats} if stats else {}), "drift": {s: api_store.drift(s) for s in out["services"][:20]}}


@app.post("/api/api-security/import-logs")
async def api_apisec_import_logs(request: Request, service: str = "", format: str = "", source: str = "log-import", user: dict = Depends(rbac.require_admin)):
    """An access-log export as the raw request body: JSON lines, a JSON array, common/combined log format or CSV."""
    data = await _read_upload(request)
    try:
        api_findings.check_source(source)
        records, stats = api_logs.parse(data, format or None, default_host=None, max_records=api_config.threshold("max_records_per_import"))
    except (ValueError, api_logs.LogError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _api_traffic(records, service or None, source, user["email"], stats)


@app.post("/api/ingest/api-traffic")
def api_ingest_api_traffic(body: ApiTrafficBody, key: dict = Depends(require_api_key("api:write"))):
    """Request records pushed by a log shipper, gateway plugin or WAF export: {"service": "...", "records": [{method, path, status, latency_ms, bytes_out, actor, client_ip, auth, ...}]}."""
    try:
        api_findings.check_source(body.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    good, bad = [], 0
    for raw in body.records:
        try:
            good.append(api_logs.normalise(raw))
        except api_logs.LogError:
            bad += 1
    if not good:
        raise HTTPException(status_code=400, detail="No request records could be read (each needs a method and a path)")
    return _api_traffic(good, body.service, body.source, f"apikey:{key['name']}", {"read": len(body.records), "skipped": bad})


@app.post("/api/ingest/openapi")
async def api_ingest_openapi(request: Request, service: str = "", key: dict = Depends(require_api_key("api:write"))):
    """An OpenAPI or Swagger document as the raw request body, typically from a pipeline. The response includes the drift against observed traffic."""
    data = await _read_upload(request)
    return _api_spec_import(data.decode("utf-8", "replace"), service or None, "ci", f"apikey:{key['name']}")


@app.post("/api/ingest/api-test-results")
def api_ingest_api_test_results(body: dict, background: BackgroundTasks, reconcile: bool = False, fail_on: str = "", report_only: bool = False,
                                key: dict = Depends(require_api_key("api:write"))):
    """Results from an API security test run in CI. Failures become findings; the response carries the pass/fail gate for the pipeline."""
    actor = f"apikey:{key['name']}"
    try:
        up = api_cicd.parse(body)
        gate = api_cicd.gate(up["results"], fail_on or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not up["results"]:
        raise HTTPException(status_code=400, detail="No usable results" + (f": {up['errors'][0]['error']}" if up["errors"] else ""))
    api_cicd.record_run(up, actor)
    source = api_cicd.source_for(up["repository"])
    findings, errors = api_findings.normalise_batch(api_cicd.to_queue_items(up))
    result = findings_merge.merge(findings, source, reconcile=reconcile) if (findings or reconcile) else {"added": 0, "updated": 0, "removed": 0}
    activity_log.record_activity(actor, "api-security.ci-results", up["repository"], {"results": len(up["results"]), "failed": gate["failed"], "gate_passed": gate["passed"], **result})
    if result["added"] or result["updated"]:
        _enrich_in_background(background)
    if report_only:
        gate = {**gate, "reported_only": True, "message": gate["message"] + " (report-only: the pipeline is told to pass)"}
        gate["passed"] = True
    return {"source": source, "gate": gate, "findings": {"published": len(findings), "rejected": len(errors), **result}, "invalid_results": up["errors"][:20]}


# ---- findings
@app.get("/api/api-security/findings")
def api_apisec_findings(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    return {"findings": st["findings"], "gaps": st["gaps"], "summary": _api_summary(st), "owasp": api_rules.OWASP,
            "note": "Findings are indicators raised by explicit rules from the records Quanta holds. A rule that lacks the data it needs raises nothing; the gaps list says what is missing."}


@app.post("/api/api-security/publish")
def api_apisec_publish(body: AiPublishBody, background: BackgroundTasks, user: dict = Depends(rbac.require_admin)):
    """Sends the current API findings to the main queue (source api-security, scan type dast). It is the complete set, so findings the data no longer shows are removed."""
    st = _api_state()
    items = api_rules.to_queue_items(st["findings"], st["specs"])
    if not body.confirm:
        return {"preview_only": True, "findings": len(items), "message": "This replaces the api-security findings in the main queue with the current set. Send confirm: true to publish."}
    findings, errors = api_findings.normalise_batch(items)
    result = findings_merge.merge(findings, "api-security", reconcile=True)
    activity_log.record_activity(user["email"], "api-security.publish", "api-security", {"findings": len(findings), "rejected": len(errors), **result})
    if result["added"] or result["updated"]:
        _enrich_in_background(background)
    return {"published": len(findings), "rejected": len(errors), **result}


# ---- callers
@app.get("/api/api-security/callers")
def api_apisec_callers(days: int = 30, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    since = (datetime.date.today() - datetime.timedelta(days=max(1, min(days, 365)) - 1)).isoformat()
    byid = {v["id"]: v for v in st["views"]}
    return {"callers": api_identity.listing(st["actors"], byid, since=since), "days": days, "thresholds": {k: api_config.threshold(k) for k in ("scraping_calls_per_actor_day", "exfil_bytes_per_actor_day", "bola_distinct_objects_per_actor_day")},
            "actor_handling": api_config.threshold("actor_handling")}


@app.get("/api/api-security/callers/detail")
def api_apisec_caller(actor: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    out = api_identity.investigate(actor, st["actors"], {v["id"]: v for v in st["views"]})
    if not out:
        raise HTTPException(status_code=404, detail="No activity recorded for that caller")
    return out


# ---- your data classification framework
@app.get("/api/api-security/classification")
def api_apisec_classification(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    seen = {}
    for v in st["views"]:
        for d in v["data"]["unclassified"]:
            seen[d] = seen.get(d, 0) + 1
    return {"classes": st["classes"], "detectors": [{"id": d["id"], "label": d["label"]} for d in api_classify.detectors()], "unclassified": seen,
            "endpoints_by_class": {c["name"]: sum(1 for v in st["views"] if any(x["name"] == c["name"] for x in v["data"]["classes"])) for c in st["classes"]},
            "format": "JSON {\"classes\": [{\"name\", \"priority\" (1 = most sensitive), \"description\", \"detectors\": [...], \"field_patterns\": [...]}]} or CSV with those columns (lists separated by ;).",
            "note": "Quanta ships no framework. Until you import yours, data seen in APIs is reported as unclassified: never assumed sensitive and never assumed harmless."}


@app.post("/api/api-security/classification")
def api_apisec_classification_import(body: ApiClassificationBody, user: dict = Depends(rbac.require_admin)):
    try:
        classes = api_store.import_classes(body.content, user["email"], fmt=body.format, replace=body.replace)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "api-security.classification.import", None, {"classes": len(classes), "replace": body.replace})
    return {"classes": classes}


@app.delete("/api/api-security/classification")
def api_apisec_classification_clear(user: dict = Depends(rbac.require_admin)):
    n = api_store.clear_classes()
    activity_log.record_activity(user["email"], "api-security.classification.clear", None, {"removed": n})
    return {"removed": n}


# ---- metrics
@app.get("/api/api-security/metrics")
def api_apisec_metrics(days: int = 30, service: str = "", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    days = max(1, min(days, 365))
    eps = [e for e in api_store.list_endpoints() if not service or e["service"] == service]
    ids = {e["id"] for e in eps}
    rows = [r for r in api_store.metrics_rows() if r["endpoint_id"] in ids]
    return api_metrics.overview(eps, rows, [a for a in api_store.actor_rows() if a["endpoint_id"] in ids], days=days)


# ---- runtime protection policies
def _api_policy_meta():
    return {"kinds": [{"id": k, "label": api_policies.KIND_LABELS[k]} for k in api_policies.KINDS], "modes": list(api_policies.MODES), "targets": api_waf.TARGETS,
            "limits": api_config.load()["policy"], "classes": [c["name"] for c in api_store.list_classes()]}


def _api_policy_or_404(pid):
    p = api_policies.get(pid)
    if not p:
        raise HTTPException(status_code=404, detail="No such policy")
    return p


@app.get("/api/api-security/policies")
def api_apisec_policies(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"policies": api_policies.list_all(), "meta": _api_policy_meta(), "log": {"events": api_policies.events(limit=100), "pushes": api_policies.pushes(limit=100)},
            "note": "Quanta does not change any firewall, gateway or WAF. A policy is a record that can be sent as a signed request to an endpoint you own, or turned into a rule for you to review and apply yourself."}


@app.post("/api/api-security/policies")
def api_apisec_policy_create(body: ApiPolicyBody, user: dict = Depends(rbac.require_admin)):
    try:
        p = api_policies.save(body.model_dump(), user["email"], classes=api_store.list_classes())
    except api_policies.PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "api-security.policy.create", p["name"], {"kind": p["kind"], "mode": p["mode"]})
    return p


@app.put("/api/api-security/policies/{policy_id}")
def api_apisec_policy_update(policy_id: int, body: ApiPolicyBody, user: dict = Depends(rbac.require_admin)):
    try:
        p = api_policies.save(body.model_dump(), user["email"], policy_id=policy_id, classes=api_store.list_classes())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such policy") from exc
    except api_policies.PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "api-security.policy.update", p["name"], {"version": p["version"], "mode": p["mode"]})
    return p


@app.delete("/api/api-security/policies/{policy_id}")
def api_apisec_policy_delete(policy_id: int, user: dict = Depends(rbac.require_admin)):
    if not api_policies.remove(policy_id, user["email"]):
        raise HTTPException(status_code=404, detail="No such policy")
    activity_log.record_activity(user["email"], "api-security.policy.delete", str(policy_id), {})
    return {"ok": True}


@app.post("/api/api-security/policies/{policy_id}/approve")
def api_apisec_policy_approve(policy_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        p = api_policies.approve(policy_id, user["email"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such policy") from exc
    except api_policies.PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "api-security.policy.approve", p["name"], {"version": p["version"]})
    return p


@app.get("/api/api-security/policies/{policy_id}/artifact")
def api_apisec_policy_artifact(policy_id: int, target: str = "aws-waf", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    p = _api_policy_or_404(policy_id)
    try:
        return api_waf.generate(p, target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/api-security/policies/{policy_id}/history")
def api_apisec_policy_history(policy_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    _api_policy_or_404(policy_id)
    return {"events": api_policies.events(policy_id), "pushes": api_policies.pushes(policy_id)}


@app.post("/api/api-security/policies/{policy_id}/push")
def api_apisec_policy_push(policy_id: int, body: ApiPushBody, user: dict = Depends(rbac.require_admin)):
    """Sends the policy, signed, to the customer's endpoint (connection type api-policy-endpoint). Confirm-gated. Quanta applies nothing itself."""
    p = _api_policy_or_404(policy_id)
    ok, why = api_policies.can_push(p)
    if not ok:
        raise HTTPException(status_code=409, detail=why)
    try:
        connector, public = hunt_service.connector("api-policy-endpoint", body.connection_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"The policy endpoint connection could not be used: {str(exc)[:150]}") from exc
    if connector is None:
        raise HTTPException(status_code=400, detail="No API protection policy endpoint is connected. Add one on the Connections page (type: API protection policy endpoint).")
    payload = api_policies.payload(p, user["email"], p["approved_by"], "quanta-push-preview")
    if not body.confirm:
        return {"preview_only": True, "connection": public["name"] if public else None, "payload": payload, "payload_sha256": api_policies.digest(payload),
                "message": "This sends the policy, signed, to the endpoint above. Your automation decides whether to apply it. Send confirm: true to send."}
    push = api_policies.send(policy_id, user["email"], connector, connection_id=public["id"] if public else None)
    hook, mail, to = _api_notify_targets()
    alerts = api_policies.notify(push, hook, mail, to)
    activity_log.record_activity(user["email"], "api-security.policy.push", p["name"], {"version": p["version"], "mode": p["mode"], "status": push["status"], "http_status": push["http_status"]})
    return {"push": push, "alerts": alerts}


@app.get("/api/api-security/policy-log")
def api_apisec_policy_log(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"events": api_policies.events(limit=300), "pushes": api_policies.pushes(limit=300)}


@app.post("/api/inbound/api-policy-status")
def api_inbound_policy_status(body: ApiPolicyStatusBody, key: dict = Depends(require_api_key("api:write"))):
    """The customer's automation reports what the edge service said about a policy it was sent: applied or rejected. Raises the per-policy change alert."""
    try:
        push = api_policies.report_status(body.push_id, body.status, body.detail, f"apikey:{key['name']}")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such push") from exc
    except api_policies.PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    hook, mail, to = _api_notify_targets()
    alerts = api_policies.notify(push, hook, mail, to)
    activity_log.record_activity(f"apikey:{key['name']}", "api-security.policy.edge-result", push["policy_name"], {"push_id": push["id"], "status": push["status"]})
    return {"push": push, "alerts": alerts}


# ---- rollout and CI
@app.get("/api/api-security/rollout")
def api_apisec_rollout(track: str = "", user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    st = _api_state()
    facts, manual = api_rollout.gather(db_module.get_engine(), unclassified=sum(1 for g in st["gaps"] if g["kind"] == "unclassified-data"),
                                       owners_missing=sum(1 for v in st["views"] if v["exposure"] == "external" and not v["owner"]), smtp_configured=email_sender.is_configured())
    return api_rollout.build(facts, manual, track or None)


@app.post("/api/api-security/rollout/{item_id}")
def api_apisec_rollout_set(item_id: str, body: ApiRolloutBody, user: dict = Depends(rbac.require_admin)):
    try:
        api_rollout.set_item(item_id, body.done, body.note, user["email"], db_module.get_engine())
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc.args[0])) from exc
    activity_log.record_activity(user["email"], "api-security.rollout", item_id, {"done": body.done})
    return {"ok": True}


@app.get("/api/api-security/ci-templates")
def api_apisec_ci_templates(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"templates": api_cicd.TEMPLATES, "gate": api_config.load()["ci"], "note": "Starting points. Pin every action and image to a version you have reviewed, and keep the API key in your CI secret store."}


# ---------------------------------------------------------------- identity and access governance
class IamCampaignBody(BaseModel):
    name: str
    due_date: str
    privileged_only: bool = False
    systems: list[str] = []


class IamDecisionBody(BaseModel):
    decision: str
    note: str = ""


class IamReassignBody(BaseModel):
    reviewer: str


class IamPrecheckBody(BaseModel):
    user: str
    system: str
    entitlement: str


@app.post("/api/iam/import")
async def api_iam_import(request: Request, source: str, format: str = "", user: dict = Depends(rbac.require_admin)):
    """Entitlements as the request body (CSV or JSON). Replaces what was loaded earlier from the same source."""
    raw = (await request.body()).decode("utf-8", "replace")
    if len(raw) > 60_000_000:
        raise HTTPException(status_code=413, detail="The file is too large (limit 60 MB)")
    try:
        out = iam_store.import_entitlements(source, raw, format or None, user["email"])
    except iam_model.IamFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "iam.import", source, out)
    return out


@app.post("/api/iam/roster")
async def api_iam_roster(request: Request, user: dict = Depends(rbac.require_admin)):
    """The HR roster (CSV: user, status, manager, department, end date). Replaces the previous one."""
    try:
        out = iam_store.import_roster((await request.body()).decode("utf-8", "replace"))
    except iam_model.IamFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "iam.roster", None, out)
    return out


@app.delete("/api/iam/data")
def api_iam_clear(user: dict = Depends(rbac.require_admin)):
    iam_store.clear()
    activity_log.record_activity(user["email"], "iam.clear", None, {})
    return {"ok": True}


@app.get("/api/iam/overview")
def api_iam_overview(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    ents, ros = iam_store.entitlements(), iam_store.roster()
    f = iam_model.analyse(ents, ros)
    return {"summary": iam_model.summary(ents, f, ros), "findings": f[:500], "campaigns": [{k: c[k] for k in ("id", "name", "status", "due_date", "total", "decided", "pct", "revoke")} for c in iam_store.list_campaigns()]}


@app.post("/api/iam/precheck")
def api_iam_precheck(body: IamPrecheckBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """Before access is requested: would this entitlement create a separation-of-duties conflict or add privilege?"""
    return iam_model.precheck(body.user, body.system, body.entitlement, iam_store.entitlements())


@app.post("/api/iam/campaigns")
def api_iam_campaign_add(body: IamCampaignBody, user: dict = Depends(rbac.require_admin)):
    try:
        c = iam_store.create_campaign(body.name, {"privileged_only": body.privileged_only, "systems": body.systems}, body.due_date, user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "iam.campaign.create", str(c["id"]), {"items": c["total"]})
    return c


@app.get("/api/iam/campaigns")
def api_iam_campaigns(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    return {"campaigns": iam_store.list_campaigns()}


@app.get("/api/iam/campaigns/{campaign_id}")
def api_iam_campaign(campaign_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    c = iam_store.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="No such campaign")
    return {**c, "items": iam_store.items_for(campaign_id)}


@app.get("/api/iam/my-reviews")
def api_iam_my_reviews(user: dict = Depends(rbac.require_login)):
    out = []
    for c in iam_store.list_campaigns():
        if c["status"] == "open":
            mine = iam_store.items_for(c["id"], reviewer=user["email"].lower())
            if mine:
                out.append({"campaign": {k: c[k] for k in ("id", "name", "due_date")}, "items": mine})
    return {"reviews": out}


@app.post("/api/iam/items/{item_id}/decide")
def api_iam_decide(item_id: int, body: IamDecisionBody, user: dict = Depends(rbac.require_login)):
    try:
        iam_store.decide(item_id, body.decision, user["email"], body.note, is_admin=user.get("role") == "admin")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such review item") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    activity_log.record_activity(user["email"], "iam.review.decide", str(item_id), {"decision": body.decision})
    return {"ok": True}


@app.post("/api/iam/items/{item_id}/reassign")
def api_iam_reassign(item_id: int, body: IamReassignBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        iam_store.reassign(item_id, body.reviewer)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/api/iam/campaigns/{campaign_id}/close")
def api_iam_close(campaign_id: int, user: dict = Depends(rbac.require_admin)):
    try:
        c = iam_store.close_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    activity_log.record_activity(user["email"], "iam.campaign.close", str(campaign_id), {"revoke": c["revoke"]})
    return c


@app.get("/api/iam/campaigns/{campaign_id}/revocations")
def api_iam_revocations(campaign_id: int, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    if not iam_store.get_campaign(campaign_id):
        raise HTTPException(status_code=404, detail="No such campaign")
    return {"revocations": iam_store.revocations(campaign_id), "note": "These are decisions recorded in Quanta. The identity team removes the access; Quanta changes no account."}


# ---------------------------------------------------------------- capabilities
@app.get("/api/capabilities")
def api_capabilities(user: dict = Depends(rbac.require_login)):
    """The eight modules, what Quanta does in each, and what each currently holds. Administrator-only pages are left out for everyone else. Each module says whether the licence covers it."""
    st = licensing.status()
    areas = capabilities_mod.build(dashboard_data.load_live_queue(), user.get("role") == "admin")
    for a in areas:
        a["licensed"] = a["id"] in st["modules"] or not st["enforced"]
    return {"areas": areas, "license": st}


@app.get("/api/license")
def api_license(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    """What the licence covers: mode (off, warn, enforce), state, customer, end date and the entitled modules. Reads the licence from QUANTA_LICENSE or QUANTA_LICENSE_FILE; nothing is sent anywhere."""
    st = licensing.status()
    return {**st, "all_modules": [{"id": m, "licensed": m in st["modules"] or not st["enforced"]} for m in licensing.MODULE_IDS]}


@app.middleware("http")
async def _enforce_module_license(request: Request, call_next):
    """In enforce mode a route of a module the licence does not cover answers 403. Core routes (sign-in, the findings store, support, administration) are never blocked; with the mode off
    (the default) this does nothing at all. See docs/LICENSING.md."""
    path = request.url.path
    if path.startswith("/api/"):
        st = licensing.status()
        if st["enforced"]:
            ok, mids = licensing.check(path, st)
            if not ok:
                return JSONResponse({"detail": f"This part of Quanta ({', '.join(mids)}) is not covered by your licence.", "modules": mids, "license_state": st["state"]}, status_code=403)
    return await call_next(request)


@app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
def spa_fallback(full_path: str):
    """Anything not matched above (a stale bookmark, a typo'd URL) still gets the SPA
    shell - static/js/app.js's router renders a styled "Page not found" instead of a
    bare {"detail":"Not Found"} JSON blob. Registered last, so /static/* (StaticFiles'
    own 404) already wins by mount precedence; /api/* is excluded explicitly below so an
    unknown API path still gets a real JSON 404, not HTML."""
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not Found")
    return _serve_shell()


def _ensure_dev_tls_cert(certs_dir):
    """Returns (keyfile, certfile) as strings, generating a local self-signed cert into
    certs_dir via the system `openssl` binary if key.pem/cert.pem aren't already there -
    the exact command documented in dashboard/README.md's "HTTPS" section, run for you
    once instead of copy-pasted. Never regenerates an existing pair, so a real cert
    someone drops in here isn't silently overwritten on the next restart. Returns
    (None, None) if openssl isn't available or generation fails for any reason - the
    caller falls back to plain HTTP for that run rather than crashing the whole app
    over a missing dev tool."""
    keyfile = certs_dir / "key.pem"
    certfile = certs_dir / "cert.pem"
    if keyfile.is_file() and certfile.is_file():
        return str(keyfile), str(certfile)
    certs_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(keyfile), "-out", str(certfile),
             "-days", "365", "-subj", "/CN=localhost"],
            check=True, capture_output=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"Could not auto-generate a local HTTPS cert (openssl unavailable or failed: {exc}) "
              f"- falling back to plain HTTP for this run. See dashboard/README.md's \"HTTPS\" "
              f"section for the manual command, or set QUANTA_DISABLE_TLS=true to silence this.")
        return None, None
    print(f"Generated a new local self-signed HTTPS cert at {certs_dir} (one-time - every future run reuses it).")
    return str(keyfile), str(certfile)



if __name__ == "__main__":
    import os

    # HTTPS is ON by default for this app, not opt-in: dashboard/certs/{key,cert}.pem
    # (gitignored - a private key must never be committed) is auto-generated on first
    # run if it doesn't exist yet, and reused on every run after that. "Remember to set
    # an env var if you want encryption" is exactly how a security default gets skipped
    # in practice, so this app doesn't ask you to remember it.
    #
    # Set SSL_KEYFILE/SSL_CERTFILE explicitly to use a different cert instead (e.g. a
    # real CA-issued one for a real deployment). Set QUANTA_DISABLE_TLS=true to
    # serve plain HTTP unconditionally - the one real reason to do that is a
    # reverse-proxy deployment that already terminates TLS in front of this process
    # (see dashboard/README.md's nginx/Let's Encrypt example); never disable this for a
    # deployment reachable from anywhere but 127.0.0.1.
    ssl_keyfile = os.environ.get("SSL_KEYFILE")
    ssl_certfile = os.environ.get("SSL_CERTFILE")
    disable_tls = os.environ.get("QUANTA_DISABLE_TLS", "").strip().lower() in ("1", "true", "yes")

    if not ssl_keyfile and not ssl_certfile and not disable_tls:
        ssl_keyfile, ssl_certfile = _ensure_dev_tls_cert(Path(__file__).resolve().parent / "certs")

    if ssl_keyfile and ssl_certfile:
        print(f"HTTPS enabled - serving with {ssl_certfile} (self-signed: browsers show a one-time "
              f"trust warning until you install a real cert or trust this one locally; see "
              f"dashboard/README.md's \"HTTPS\" section for exactly what that warning means and how "
              f"to get past it).")
    elif disable_tls:
        print("HTTPS disabled via QUANTA_DISABLE_TLS - serving plain HTTP. Only do this behind a "
              "reverse proxy that already terminates TLS.")

    uvicorn.run(
        app, host=os.environ.get("QUANTA_HOST", "127.0.0.1"), port=int(os.environ.get("QUANTA_PORT", "5050")),
        ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile,
        # behind a trusted proxy/ingress, honour X-Forwarded-For so rate limits and the audit log see real client IPs
        forwarded_allow_ips=os.environ.get("QUANTA_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )
