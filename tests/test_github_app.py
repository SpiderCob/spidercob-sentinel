import hashlib
import hmac
import json
from unittest.mock import patch

from spidercob_sentinel.github_app import (
    _build_review_comments,
    _build_summary,
    create_app,
    verify_signature,
)
from spidercob_sentinel.models import Finding, ScanReport
from spidercob_sentinel.triage import TriagedFinding, TriageResult


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_signature_accepts_correct_hmac():
    body = b'{"hello": "world"}'
    sig = _sign("my-secret", body)
    assert verify_signature(body, sig, "my-secret") is True


def test_verify_signature_rejects_wrong_secret():
    body = b'{"hello": "world"}'
    sig = _sign("my-secret", body)
    assert verify_signature(body, sig, "wrong-secret") is False


def test_verify_signature_rejects_tampered_body():
    body = b'{"hello": "world"}'
    sig = _sign("my-secret", body)
    assert verify_signature(b'{"hello": "mallory"}', sig, "my-secret") is False


def test_verify_signature_rejects_missing_or_malformed_header():
    body = b"x"
    assert verify_signature(body, None, "secret") is False
    assert verify_signature(body, "not-sha256-prefixed", "secret") is False


def _finding(**kw):
    defaults = dict(category="VULNERABILITY", type="SQL Injection", description="d",
                     severity="HIGH", file="app.py", remediation="use params", line=10)
    defaults.update(kw)
    return Finding(**defaults)


def test_build_summary_clean_scan():
    report = ScanReport()
    summary = _build_summary(report, None)
    assert "no issues" in summary.lower()


def test_build_summary_lists_blocking_findings_in_table():
    report = ScanReport(findings=[_finding(), _finding(severity="Unreachable")])
    summary = _build_summary(report, None)
    assert "1 finding(s)" in summary
    assert "app.py" in summary
    assert "SQL Injection" in summary


def test_build_summary_includes_triage_explanations_when_llm_used():
    f = _finding()
    report = ScanReport(findings=[f])
    result = TriageResult(ranked=[TriagedFinding(finding=f, explanation="an attacker could dump your users table")], llm_used=True)
    summary = _build_summary(report, result)
    assert "an attacker could dump your users table" in summary


def test_build_review_comments_skips_findings_without_a_line():
    report = ScanReport(findings=[_finding(line=5), _finding(line=None)])
    comments = _build_review_comments(report)
    assert len(comments) == 1
    assert comments[0]["line"] == 5
    assert comments[0]["path"] == "app.py"


def test_webhook_rejects_bad_signature():
    with patch("spidercob_sentinel.github_app.configured", True), \
         patch("spidercob_sentinel.github_app.GITHUB_WEBHOOK_SECRET", "right-secret"):
        from fastapi.testclient import TestClient
        client = TestClient(create_app())
        resp = client.post(
            "/github/webhooks",
            content=b'{"action": "opened"}',
            headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 401


def test_webhook_unconfigured_returns_503():
    with patch("spidercob_sentinel.github_app.configured", False):
        from fastapi.testclient import TestClient
        client = TestClient(create_app())
        resp = client.post("/github/webhooks", content=b"{}", headers={"X-Hub-Signature-256": "sha256=x"})
        assert resp.status_code == 503


def test_healthz():
    from fastapi.testclient import TestClient
    client = TestClient(create_app())
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "status" in resp.json()
