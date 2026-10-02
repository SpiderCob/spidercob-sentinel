"""
GitHub App webhook server — runs the scanner + triage engine on every PR,
posts a Check Run and inline review comments, and opens an autofix PR into
the PR's own branch for anything with a mechanical fix available.

Self-hosted: you register your own GitHub App (see the README's "Register
your own GitHub App" section) pointing its webhook at wherever you deploy
this. There is no Spidercob-run instance of this — every deployment is
independent, same as the rest of this project.

Requires the `github-app` extra: `pip install spidercob-sentinel[github-app]`
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .autofix import apply_fixes, autofixable
from .models import Finding, ScanReport
from .scan import scan_file
from .triage import triage

logger = logging.getLogger(__name__)

# Imported lazily (only needed for the `github-app` extra) but at MODULE
# level, not inside create_app() — this file has `from __future__ import
# annotations`, which turns `request: Request` into the string "Request" to
# be resolved later via typing.get_type_hints() against this module's
# globals. If FastAPI/Request were only ever bound as a local inside
# create_app(), that resolution would fail to find them (they'd never be in
# this module's __dict__) and FastAPI would silently misinterpret the
# parameter as an unrecognized type requiring a query arg named "request" —
# a real, non-obvious failure mode this project hit once already.
try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = Request = JSONResponse = None  # type: ignore[assignment,misc]

GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_PRIVATE_KEY = os.environ.get("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
MAX_FILES = int(os.environ.get("SENTINEL_MAX_PR_FILES", "50"))
MIN_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(
    os.environ.get("SENTINEL_MIN_SEVERITY", "HIGH"), 2
)

_API = "https://api.github.com"
_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "Unreachable": "⚪"}

configured = bool(GITHUB_APP_ID and GITHUB_PRIVATE_KEY and GITHUB_WEBHOOK_SECRET)
if not configured:
    missing = [
        name for name, val in [
            ("GITHUB_APP_ID", GITHUB_APP_ID),
            ("GITHUB_PRIVATE_KEY", GITHUB_PRIVATE_KEY),
            ("GITHUB_WEBHOOK_SECRET", GITHUB_WEBHOOK_SECRET),
        ] if not val
    ]
    logger.warning("GitHub App not configured — missing: %s. Webhook requests will be rejected until these are set.", ", ".join(missing))


# ── Signature verification ──────────────────────────────────────────────

def verify_signature(payload: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Verify an `X-Hub-Signature-256` header against the raw request body.
    `hmac.compare_digest` for the actual comparison — never a plain `==`
    on secret-derived bytes."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)


# ── GitHub App auth ──────────────────────────────────────────────────────

def _app_jwt() -> str:
    import jwt  # PyJWT — only imported when actually needed (github-app extra)
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": GITHUB_APP_ID}
    return jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")


def _installation_token(installation_id: int) -> str:
    data = _api_request(
        "POST", f"/app/installations/{installation_id}/access_tokens",
        token=_app_jwt(), token_prefix="Bearer",
    )
    return data["token"]


# ── Thin REST client (stdlib only — no octokit equivalent needed) ───────

def _api_request(
    method: str, path: str, *, token: str, token_prefix: str = "token",
    json_body: Optional[Dict[str, Any]] = None, accept: str = "application/vnd.github+json",
) -> Any:
    url = path if path.startswith("http") else f"{_API}{path}"
    body = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"{token_prefix} {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "spidercob-sentinel",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="ignore")
        logger.error("GitHub API %s %s -> %s: %s", method, path, e.code, body_text[:300])
        raise


def _fetch_file_content(token: str, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
    try:
        data = _api_request(
            "GET", f"/repos/{owner}/{repo}/contents/{path}?ref={ref}",
            token=token, accept="application/vnd.github.raw+json",
        )
    except urllib.error.HTTPError:
        return None
    if isinstance(data, (bytes, str)):
        return data if isinstance(data, str) else data.decode("utf-8", errors="ignore")
    # Some proxies/caches ignore the raw accept header and return the
    # contents-API JSON shape instead — handle both.
    content = data.get("content") if isinstance(data, dict) else None
    if content is None:
        return None
    return base64.b64decode(content).decode("utf-8", errors="ignore")


def _get_pr_files(token: str, owner: str, repo: str, pull_number: int) -> List[Dict[str, Any]]:
    data = _api_request("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}/files?per_page={MAX_FILES}", token=token)
    return [f for f in data if f.get("status") != "removed"]


# ── Check Run + review comment formatting ───────────────────────────────

def _build_summary(report: ScanReport, triage_result) -> str:
    blocking = report.blocking
    if not blocking:
        return "**Spidercob Sentinel** scanned this PR and found no issues worth blocking on. ✅"

    explained = {id(tf.finding): tf.explanation for tf in (triage_result.ranked if triage_result else []) if tf.explanation}

    lines = [f"**Spidercob Sentinel** found **{len(blocking)} finding(s)** in this PR.\n"]
    if triage_result and triage_result.llm_used:
        lines.append("Top findings, ranked and explained:\n")
        for tf in triage_result.ranked:
            f = tf.finding
            loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
            lines.append(f"- {_SEVERITY_EMOJI.get(f.severity, '')} **{f.type}** ({loc}) — {tf.explanation or f.description}")
        lines.append("")

    lines += ["| File | Severity | Finding | Location |", "|------|----------|---------|----------|"]
    for f in sorted(blocking, key=lambda f: f.rank(), reverse=True):
        loc = f"Line {f.line}" if f.line else "—"
        lines.append(f"| `{f.file}` | {_SEVERITY_EMOJI.get(f.severity, '')} {f.severity} | {f.type} | {loc} |")

    lines.append("\n> Scan powered by [spidercob-sentinel](https://github.com/SpiderCob/spidercob-sentinel) — self-hosted, runs fully offline except for the OSV.dev dependency-CVE lookup and (if configured) your own LLM key.")
    return "\n".join(lines)


def _build_review_comments(report: ScanReport) -> List[Dict[str, Any]]:
    comments = []
    for f in report.blocking:
        if f.line is None:
            continue  # dependency findings aren't tied to a diff line
        body = f"{_SEVERITY_EMOJI.get(f.severity, '')} **Spidercob Sentinel [{f.severity}]**: {f.type}\n\n{f.description}\n\n**Fix:** {f.remediation}"
        if f.autofix_available:
            body += "\n\n_A mechanical fix is available — see the autofix PR opened against this branch, if one was opened._"
        comments.append({"path": f.file, "line": max(1, f.line), "side": "RIGHT", "body": body})
    return comments


def _post_review_comments(token: str, owner: str, repo: str, pull_number: int, commit_sha: str, comments: List[Dict[str, Any]]) -> None:
    for i in range(0, len(comments), 10):  # GitHub limits a review to 10 comments/request
        chunk = comments[i:i + 10]
        try:
            _api_request("POST", f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews", token=token, json_body={
                "commit_id": commit_sha, "event": "COMMENT", "comments": chunk,
            })
        except urllib.error.HTTPError as e:
            logger.error("Failed to post review comments: %s", e)


# ── Autofix PR ────────────────────────────────────────────────────────────

def _open_autofix_pr(token: str, owner: str, repo: str, pr: Dict[str, Any], files_content: Dict[str, str], fixable: List[Finding]) -> Optional[str]:
    """Create a branch off the PR's head, commit mechanical fixes to it via
    the Contents API, and open a PR targeting the *original PR's own
    branch* (not the repo's default branch) — a suggestion the PR author
    can merge into their own work, same pattern Dependabot/Renovate-style
    bots use. Returns the new PR's html_url, or None if nothing was
    actually fixed (e.g. every fix's stored offset no longer matched)."""
    by_file: Dict[str, List[Finding]] = {}
    for f in fixable:
        by_file.setdefault(f.file, []).append(f)

    head_sha = pr["head"]["sha"]
    base_branch = pr["head"]["ref"]
    branch = f"sentinel-autofix/pr-{pr['number']}-{head_sha[:7]}"

    try:
        _api_request("POST", f"/repos/{owner}/{repo}/git/refs", token=token, json_body={
            "ref": f"refs/heads/{branch}", "sha": head_sha,
        })
    except urllib.error.HTTPError as e:
        if e.code != 422:  # 422 = ref already exists, e.g. a retried webhook delivery
            logger.error("Could not create autofix branch: %s", e)
            return None

    changed_any = False
    for file_path, findings in by_file.items():
        original = files_content.get(file_path)
        if original is None:
            continue
        patched = apply_fixes(original, findings)
        if patched == original:
            continue

        try:
            existing = _api_request("GET", f"/repos/{owner}/{repo}/contents/{file_path}?ref={branch}", token=token)
            file_sha = existing["sha"]
        except urllib.error.HTTPError:
            continue

        try:
            _api_request("PUT", f"/repos/{owner}/{repo}/contents/{file_path}", token=token, json_body={
                "message": f"Autofix: {len(findings)} finding(s) in {file_path}",
                "content": base64.b64encode(patched.encode("utf-8")).decode("ascii"),
                "sha": file_sha,
                "branch": branch,
            })
            changed_any = True
        except urllib.error.HTTPError as e:
            logger.error("Could not commit autofix for %s: %s", file_path, e)

    if not changed_any:
        return None

    try:
        result = _api_request("POST", f"/repos/{owner}/{repo}/pulls", token=token, json_body={
            "title": f"Spidercob Sentinel: {len(fixable)} autofix(es) for PR #{pr['number']}",
            "head": branch,
            "base": base_branch,
            "body": (
                "Mechanical fixes only — a Semgrep rule's own vetted `fix:` snippet, "
                "or a dependency version bump to a known-patched release. Nothing here "
                "was written by an LLM; review and merge if it looks right.\n\n"
                f"Opened by [spidercob-sentinel](https://github.com/SpiderCob/spidercob-sentinel) for #{pr['number']}."
            ),
        })
        return result.get("html_url")
    except urllib.error.HTTPError as e:
        logger.error("Could not open autofix PR: %s", e)
        return None


# ── Main PR handler ───────────────────────────────────────────────────────

async def handle_pull_request(payload: Dict[str, Any]) -> None:
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return

    pr = payload["pull_request"]
    repo_full = payload["repository"]
    owner = repo_full["owner"]["login"]
    repo = repo_full["name"]
    pull_number = pr["number"]
    head_sha = pr["head"]["sha"]
    installation_id = payload["installation"]["id"]

    token = _installation_token(installation_id)

    check_run = _api_request("POST", f"/repos/{owner}/{repo}/check-runs", token=token, json_body={
        "name": "Spidercob Sentinel", "head_sha": head_sha, "status": "in_progress",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output": {"title": "Scanning…", "summary": "Spidercob Sentinel is scanning the changed files."},
    })

    report = ScanReport()
    files_content: Dict[str, str] = {}

    try:
        for f in _get_pr_files(token, owner, repo, pull_number):
            if not f.get("patch") and f.get("changes", 0) > 0:
                continue  # no textual patch usually means a binary file
            content = _fetch_file_content(token, owner, repo, f["filename"], head_sha)
            if content is None:
                continue
            files_content[f["filename"]] = content
            # scan_file() reads from disk by path — write the PR's version
            # of the file to a temp path so the in-process scanner (same
            # function the CLI uses) can run against it directly, no HTTP
            # round-trip to a separate service.
            import tempfile
            suffix = os.path.splitext(f["filename"])[1] or ".txt"
            with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                findings = await scan_file(tmp_path)
            finally:
                os.unlink(tmp_path)
            for finding in findings:
                finding.file = f["filename"]  # report the real path, not the temp one
            report.findings.extend(findings)

        triage_result = None
        if os.environ.get("SENTINEL_LLM_PROVIDER"):
            triage_result = triage(report.blocking)

        if report.blocking:
            _post_review_comments(token, owner, repo, pull_number, head_sha, _build_review_comments(report))

        autofix_url = None
        fixable = [f for f in autofixable(report.blocking)]
        if fixable:
            autofix_url = _open_autofix_pr(token, owner, repo, pr, files_content, fixable)

        summary = _build_summary(report, triage_result)
        if autofix_url:
            summary += f"\n\n🔧 Opened an autofix PR: {autofix_url}"

        conclusion = "success" if not report.blocking else "failure"
        annotations = [
            {
                "path": f.file, "start_line": max(1, f.line or 1), "end_line": max(1, f.end_line or f.line or 1),
                "annotation_level": "warning" if f.severity in ("MEDIUM", "LOW") else "failure",
                "message": f"[{f.severity}] {f.type}: {f.description}", "title": f.type,
            }
            for f in report.blocking if f.line
        ][:50]  # GitHub's own cap

        _api_request("PATCH", f"/repos/{owner}/{repo}/check-runs/{check_run['id']}", token=token, json_body={
            "status": "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "conclusion": conclusion,
            "output": {
                "title": "No blocking findings" if not report.blocking else f"{len(report.blocking)} finding(s)",
                "summary": summary,
                "annotations": annotations,
            },
        })
    except Exception as e:  # noqa: BLE001 - never leave a Check Run stuck "in_progress"
        logger.exception("Error processing PR #%s", pull_number)
        try:
            _api_request("PATCH", f"/repos/{owner}/{repo}/check-runs/{check_run['id']}", token=token, json_body={
                "status": "completed",
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "conclusion": "neutral",
                "output": {"title": "Scan error", "summary": f"spidercob-sentinel encountered an error: {e}"},
            })
        except Exception:
            pass


# ── FastAPI app ───────────────────────────────────────────────────────────

def create_app():
    if FastAPI is None:
        raise RuntimeError(
            "fastapi is not installed — run `pip install spidercob-sentinel[github-app]` "
            "to use the webhook server."
        )

    app = FastAPI(title="spidercob-sentinel GitHub App")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok" if configured else "unconfigured", "configured": configured}

    @app.post("/github/webhooks")
    async def webhooks(request: Request):
        if not configured:
            return JSONResponse(status_code=503, content={"error": "GitHub App not configured"})

        body = await request.body()
        if not verify_signature(body, request.headers.get("X-Hub-Signature-256"), GITHUB_WEBHOOK_SECRET):
            return JSONResponse(status_code=401, content={"error": "invalid signature"})

        event = request.headers.get("X-GitHub-Event")
        payload = json.loads(body)

        if event == "pull_request":
            await handle_pull_request(payload)

        return {"ok": True}

    return app


def run() -> None:
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(create_app(), host="0.0.0.0", port=port)
