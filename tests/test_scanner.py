import os

import pytest

from spidercob_sentinel.scanner import ReachabilityAnalyzer, _finding_type_from_cwe, scan_code_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_reachability_decorated_function_is_entry_point():
    import ast
    tree = ast.parse(
        "@app.route('/x')\n"
        "def handler():\n"
        "    pass\n"
        "def helper():\n"
        "    pass\n"
    )
    analyzer = ReachabilityAnalyzer()
    analyzer.visit(tree)
    assert "handler" in analyzer.entry_point_functions
    assert "helper" not in analyzer.entry_point_functions
    assert "helper" not in analyzer.called_functions


def test_finding_type_from_cwe_parenthetical():
    assert _finding_type_from_cwe({"cwe": "CWE-89: Improper Neutralization ('SQL Injection')"}) == "SQL Injection"


def test_finding_type_from_cwe_no_parenthetical():
    assert _finding_type_from_cwe({"cwe": "CWE-287: Improper Authentication"}) == "Improper Authentication"


def test_finding_type_from_cwe_missing():
    assert _finding_type_from_cwe({}) == "Static Analysis Finding"


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_WITH_SEMGREP"), reason="requires semgrep binary + vendored rules; set SENTINEL_TEST_WITH_SEMGREP=1 to run")
@pytest.mark.asyncio
async def test_scan_code_file_detects_sql_injection_and_marks_dead_code():
    path = os.path.join(FIXTURES, "vulnerable_view.py")
    findings = await scan_code_file(path)

    assert any(f.severity == "HIGH" and "SQL" in f.type for f in findings), findings
    assert any(f.severity == "Unreachable" for f in findings), "dead helper should be demoted"
    reachable_sql = [f for f in findings if f.severity == "HIGH"]
    assert all(f.remediation and "parameteris" in f.remediation.lower() for f in reachable_sql)


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_WITH_SEMGREP"), reason="requires semgrep binary + vendored rules")
@pytest.mark.asyncio
async def test_semgrep_fix_snippet_captured_for_rule_with_fix():
    path = os.path.join(FIXTURES, "jwt_unsafe.py")
    findings = await scan_code_file(path)
    assert any(f.fix_snippet for f in findings), "unverified-jwt-decode rule ships a fix: — should be captured"
