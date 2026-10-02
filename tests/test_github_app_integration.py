"""
End-to-end test of handle_pull_request() with every GitHub API call and the
scanner mocked out — verifies the orchestration logic itself (fetch files,
scan, post comments, open an autofix PR, complete the Check Run) without
hitting the network or needing a real GitHub App.
"""
import pytest
from unittest.mock import AsyncMock, patch

from spidercob_sentinel.github_app import handle_pull_request
from spidercob_sentinel.models import Finding

PAYLOAD = {
    "action": "opened",
    "repository": {"owner": {"login": "acme"}, "name": "widgets"},
    "pull_request": {"number": 42, "head": {"sha": "abc1234567", "ref": "feature-branch"}},
    "installation": {"id": 999},
}


def _api_request_router(calls_log):
    """Returns a side_effect function for _api_request that logs every call
    and returns a plausible canned response per (method, path-prefix)."""
    def _route(method, path, *, token=None, token_prefix=None, json_body=None, accept=None):
        calls_log.append((method, path, json_body))
        if method == "POST" and "/check-runs" in path and "/check-runs/" not in path:
            return {"id": 555}
        if method == "GET" and "/pulls/42/files" in path:
            return [{"filename": "app.py", "status": "modified", "patch": "@@ -1 +1 @@", "changes": 1}]
        if method == "GET" and "/git/refs" in path:
            return {}
        if method == "POST" and "/git/refs" in path:
            return {}
        if method == "GET" and "/contents/app.py" in path:
            return {"sha": "blobsha123"}
        if method == "PUT" and "/contents/app.py" in path:
            return {}
        if method == "POST" and path.endswith("/pulls"):
            return {"html_url": "https://github.com/acme/widgets/pull/43"}
        if method == "PATCH" and "/check-runs/" in path:
            return {}
        if method == "POST" and "/reviews" in path:
            return {}
        return {}
    return _route


@pytest.mark.asyncio
async def test_handle_pull_request_full_flow_with_autofix():
    calls = []
    fake_finding = Finding(
        category="VULNERABILITY", type="SQL Injection", description="bad",
        severity="HIGH", file="__tmp__", remediation="use params", line=3,
        end_offset=10, start_offset=5, fix_snippet="safe_call()",
    )

    with patch("spidercob_sentinel.github_app._installation_token", return_value="fake-token"), \
         patch("spidercob_sentinel.github_app._api_request", side_effect=_api_request_router(calls)), \
         patch("spidercob_sentinel.github_app._fetch_file_content", return_value="print('hi')\n"), \
         patch("spidercob_sentinel.github_app.scan_file", new=AsyncMock(return_value=[fake_finding])):
        await handle_pull_request(PAYLOAD)

    methods_paths = [(m, p) for m, p, _ in calls]

    assert ("POST", "/repos/acme/widgets/check-runs") in methods_paths
    assert any(m == "GET" and "/pulls/42/files" in p for m, p in methods_paths)
    assert any(m == "POST" and "/reviews" in p for m, p in methods_paths)
    assert any(m == "POST" and p.endswith("/git/refs") for m, p in methods_paths)
    assert any(m == "PUT" and "/contents/app.py" in p for m, p in methods_paths)
    assert any(m == "POST" and p.endswith("/pulls") for m, p in methods_paths)

    patch_calls = [body for m, p, body in calls if m == "PATCH" and "/check-runs/" in p]
    assert len(patch_calls) == 1
    assert patch_calls[0]["conclusion"] == "failure"
    assert "autofix" in patch_calls[0]["output"]["summary"].lower() or "pull/43" in patch_calls[0]["output"]["summary"]


@pytest.mark.asyncio
async def test_handle_pull_request_ignores_non_pr_relevant_actions():
    with patch("spidercob_sentinel.github_app._installation_token") as mock_token:
        await handle_pull_request({**PAYLOAD, "action": "closed"})
        mock_token.assert_not_called()


@pytest.mark.asyncio
async def test_handle_pull_request_clean_scan_never_calls_reviews_or_autofix():
    calls = []
    with patch("spidercob_sentinel.github_app._installation_token", return_value="fake-token"), \
         patch("spidercob_sentinel.github_app._api_request", side_effect=_api_request_router(calls)), \
         patch("spidercob_sentinel.github_app._fetch_file_content", return_value="print('hi')\n"), \
         patch("spidercob_sentinel.github_app.scan_file", new=AsyncMock(return_value=[])):
        await handle_pull_request(PAYLOAD)

    methods_paths = [(m, p) for m, p, _ in calls]
    assert not any(m == "POST" and "/reviews" in p for m, p in methods_paths)
    assert not any(m == "POST" and p.endswith("/git/refs") for m, p in methods_paths)

    patch_calls = [body for m, p, body in calls if m == "PATCH" and "/check-runs/" in p]
    assert patch_calls[0]["conclusion"] == "success"


@pytest.mark.asyncio
async def test_handle_pull_request_never_leaves_check_run_in_progress_on_error():
    calls = []
    with patch("spidercob_sentinel.github_app._installation_token", return_value="fake-token"), \
         patch("spidercob_sentinel.github_app._api_request", side_effect=_api_request_router(calls)), \
         patch("spidercob_sentinel.github_app._get_pr_files", side_effect=RuntimeError("GitHub API down")):
        await handle_pull_request(PAYLOAD)

    patch_calls = [body for m, p, body in calls if m == "PATCH" and "/check-runs/" in p]
    assert len(patch_calls) == 1
    assert patch_calls[0]["conclusion"] == "neutral"
    assert "error" in patch_calls[0]["output"]["summary"].lower()
