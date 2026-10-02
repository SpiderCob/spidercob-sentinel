import os
from unittest.mock import patch

from spidercob_sentinel.models import Finding
from spidercob_sentinel.triage import triage


def _finding(severity):
    return Finding(category="VULNERABILITY", type="t", description="d", severity=severity,
                    file="app.py", remediation="r")


def test_no_provider_configured_falls_back_to_severity_order(monkeypatch):
    monkeypatch.delenv("SENTINEL_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SENTINEL_LLM_API_KEY", raising=False)

    findings = [_finding("LOW"), _finding("CRITICAL"), _finding("MEDIUM")]
    result = triage(findings)

    assert result.llm_used is False
    assert result.llm_error is None
    assert [tf.finding.severity for tf in result.ranked] == ["CRITICAL", "MEDIUM", "LOW"]
    assert all(tf.explanation is None for tf in result.ranked)


def test_unknown_provider_degrades_with_error():
    findings = [_finding("HIGH")]
    result = triage(findings, provider="not-a-real-provider", api_key="x")
    assert result.llm_used is False
    assert "Unknown" in result.llm_error


def test_openai_provider_success_path():
    findings = [_finding("HIGH"), _finding("LOW")]

    with patch("spidercob_sentinel.triage._call_openai", return_value='[{"index": 0, "explanation": "this matters because X"}]'):
        result = triage(findings, provider="openai", api_key="sk-fake")

    assert result.llm_used is True
    assert result.llm_error is None
    assert result.ranked[0].explanation == "this matters because X"
    assert result.ranked[1].explanation is None


def test_llm_call_failure_degrades_gracefully():
    findings = [_finding("HIGH")]
    with patch("spidercob_sentinel.triage._call_openai", side_effect=RuntimeError("network down")):
        result = triage(findings, provider="openai", api_key="sk-fake")

    assert result.llm_used is False
    assert "network down" in result.llm_error
    assert result.ranked[0].explanation is None
