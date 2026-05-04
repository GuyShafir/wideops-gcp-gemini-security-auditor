"""
GCP Gemini Security Auditor.

Scans accessible GCP projects for API keys that can call the Generative
Language API (Gemini), and reports their quota posture. Read-only.

Exit codes:
    0  - Ran successfully, no CRITICAL findings.
    1  - Ran successfully, CRITICAL findings present.
    2  - Tool error (auth failure, invalid args, etc.).

Usage:
    gcloud auth application-default login
    python audit_gemini.py [--output report.csv] [--workers 15] [--project PROJECT_ID]
"""

import argparse
import csv
import logging
import sys
import threading
import concurrent.futures
from typing import Optional

from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError

GEMINI_SERVICE = "generativelanguage.googleapis.com"

log = logging.getLogger("gemini-audit")

# Each thread gets its own discovery clients. googleapiclient's HTTP objects
# are not thread-safe; sharing them across a ThreadPoolExecutor produces
# intermittent failures at scale.
_thread_local = threading.local()


def _clients():
    """Return per-thread discovery clients, building them on first access."""
    if not hasattr(_thread_local, "clients"):
        creds, _ = default()
        _thread_local.clients = {
            "crm": discovery.build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False),
            "service_usage": discovery.build("serviceusage", "v1", credentials=creds, cache_discovery=False),
            "apikeys": discovery.build("apikeys", "v2", credentials=creds, cache_discovery=False),
        }
    return _thread_local.clients


def get_quota_info(p_id: str) -> str:
    """
    Summarize the *effective* Gemini quota limits for a project.

    Returns a pipe-separated string of "metric: limit (source)" entries, where
    source indicates whether the limit comes from a consumer override (an
    explicitly-set circuit breaker) or the Google-published default.
    """
    service_usage = _clients()["service_usage"]
    parent = f"projects/{p_id}/services/{GEMINI_SERVICE}"

    summaries = []
    page_token: Optional[str] = None
    try:
        while True:
            req = service_usage.services().consumerQuotaMetrics().list(
                parent=parent,
                view="FULL",  # FULL view includes consumerOverrides
                pageToken=page_token,
            )
            resp = req.execute()

            for metric in resp.get("metrics", []):
                metric_name = metric.get("displayName", "Unknown")
                for limit in metric.get("consumerQuotaLimits", []):
                    # Each limit has buckets; the override bucket (if any) reflects
                    # what the project has actually configured.
                    buckets = limit.get("quotaBuckets", [])
                    if not buckets:
                        continue
                    # Take the bucket with the most specific dimensions (usually [0]).
                    bucket = buckets[0]
                    override = bucket.get("consumerOverride", {}).get("overrideValue")
                    default_val = bucket.get("defaultLimit", "Unlimited")
                    if override is not None:
                        summaries.append(f"{metric_name}: {override} (override)")
                    else:
                        summaries.append(f"{metric_name}: {default_val} (default)")

            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        if not summaries:
            return "No quota metrics returned"
        # Flag if no overrides exist at all — i.e., no circuit breaker set.
        if not any("(override)" in s for s in summaries):
            return "DEFAULTS ONLY (no circuit breaker) | " + " | ".join(summaries)
        return " | ".join(summaries)
    except HttpError as e:
        log.warning("Quota fetch failed for %s: %s", p_id, e.reason)
        return f"Unable to fetch quotas: {e.reason}"


def _list_keys(p_id: str) -> list:
    """List all API keys in a project, paginated."""
    apikeys = _clients()["apikeys"]
    # 'global' is currently the only valid location for API keys.
    parent = f"projects/{p_id}/locations/global"
    keys = []
    page_token: Optional[str] = None
    while True:
        resp = apikeys.projects().locations().keys().list(
            parent=parent, pageToken=page_token
        ).execute()
        keys.extend(resp.get("keys", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return keys


def audit_project(project: dict) -> list:
    """
    Audit a single project. Returns a list of finding dicts (possibly empty).

    A finding is produced for each API key that is either fully unrestricted
    or explicitly scoped to allow Gemini.
    """
    p_id = project["projectId"]
    results: list = []
    service_usage = _clients()["service_usage"]

    try:
        status = service_usage.services().get(
            name=f"projects/{p_id}/services/{GEMINI_SERVICE}"
        ).execute()
    except HttpError as e:
        log.warning("Cannot read service status for %s: %s", p_id, e.reason)
        return results

    if status.get("state") != "ENABLED":
        return results

    quota_summary = get_quota_info(p_id)

    try:
        keys = _list_keys(p_id)
    except HttpError as e:
        log.warning("Cannot list API keys for %s: %s", p_id, e.reason)
        return results

    for key in keys:
        display_name = key.get("displayName", "Unnamed Key")
        restrictions = key.get("restrictions", {})
        api_targets = restrictions.get("apiTargets", [])
        has_browser_or_ip_restriction = any(
            k in restrictions for k in (
                "browserKeyRestrictions",
                "serverKeyRestrictions",
                "androidKeyRestrictions",
                "iosKeyRestrictions",
            )
        )

        is_unrestricted_api = len(api_targets) == 0
        allows_gemini = any(
            t.get("service") == GEMINI_SERVICE for t in api_targets
        )

        if is_unrestricted_api:
            risk = (
                "CRITICAL (Unrestricted APIs, partial referrer/IP restriction)"
                if has_browser_or_ip_restriction
                else "CRITICAL (Fully Unrestricted)"
            )
        elif allows_gemini:
            risk = "HIGH (Gemini Scoped)"
        else:
            continue  # Key cannot reach Gemini; skip.

        results.append({
            "project_id": p_id,
            "key_name": display_name,
            "risk_level": risk,
            "quotas": quota_summary,
        })

    return results


def list_projects(single_project: Optional[str]) -> list:
    """List active projects, or wrap a single project ID for targeted audits."""
    crm = _clients()["crm"]
    if single_project:
        proj = crm.projects().get(projectId=single_project).execute()
        return [proj] if proj.get("lifecycleState") == "ACTIVE" else []

    projects = []
    request = crm.projects().list()
    while request:
        response = request.execute()
        projects.extend(
            p for p in response.get("projects", [])
            if p.get("lifecycleState") == "ACTIVE"
        )
        request = crm.projects().list_next(request, response)
    return projects


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit GCP projects for API keys that can call Gemini."
    )
    p.add_argument("--output", default="gemini_security_report.csv",
                   help="Output CSV path (default: gemini_security_report.csv)")
    p.add_argument("--workers", type=int, default=15,
                   help="Parallel project audits (default: 15)")
    p.add_argument("--project", default=None,
                   help="Audit a single project instead of all accessible projects")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        # Trigger credential resolution early so auth errors fail fast.
        default()
    except DefaultCredentialsError as e:
        log.error("No credentials found. Run `gcloud auth application-default login`. (%s)", e)
        return 2

    log.info("Initializing Gemini security audit...")
    try:
        projects = list_projects(args.project)
    except HttpError as e:
        log.error("Failed to list projects: %s", e.reason)
        return 2
    log.info("Discovered %d active project(s).", len(projects))

    all_findings: list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(audit_project, p): p for p in projects}
        for future in concurrent.futures.as_completed(futures):
            project = futures[future]
            try:
                all_findings.extend(future.result())
            except Exception:
                # Real bugs (not API errors) — log with traceback so they're visible.
                log.exception("Unexpected error auditing %s", project.get("projectId"))

    if not all_findings:
        log.info("No vulnerable keys found.")
        return 0

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["project_id", "key_name", "risk_level", "quotas"]
        )
        writer.writeheader()
        writer.writerows(all_findings)

    critical = sum(1 for r in all_findings if r["risk_level"].startswith("CRITICAL"))
    high = len(all_findings) - critical
    log.info(
        "Found %d finding(s): %d CRITICAL, %d HIGH. Report saved to %s",
        len(all_findings), critical, high, args.output,
    )
    return 1 if critical > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
