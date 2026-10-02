from spidercob_sentinel.autofix import apply_dependency_fix, apply_fix, apply_semgrep_fix, autofixable, generate_diff
from spidercob_sentinel.models import Finding


def _dep_finding(**kw):
    defaults = dict(
        category="DEPENDENCY", type="CVE-2024-1", description="d", severity="HIGH",
        file="requirements.txt", remediation="r", package="flask",
        recommended_fix_version="2.2.5",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _vuln_finding(**kw):
    defaults = dict(
        category="VULNERABILITY", type="t", description="d", severity="HIGH",
        file="app.py", remediation="r", fix_snippet="True",
        start_offset=10, end_offset=15,
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_apply_dependency_fix_bumps_pinned_version():
    content = "requests==2.25.0\nflask==1.1.0\n"
    patched = apply_dependency_fix(content, _dep_finding())
    assert patched == "requests==2.25.0\nflask==2.2.5\n"


def test_apply_dependency_fix_no_match_returns_none():
    content = "requests==2.25.0\n"
    assert apply_dependency_fix(content, _dep_finding(package="flask")) is None


def test_apply_dependency_fix_non_txt_manifest_not_supported():
    f = _dep_finding(file="package.json")
    assert apply_dependency_fix('{"flask": "1.1.0"}', f) is None


def test_apply_semgrep_fix_replaces_exact_span_only():
    content = "xxxxxFalsexxxxx"
    f = _vuln_finding(start_offset=5, end_offset=10)  # exactly "False"
    patched = apply_semgrep_fix(content, f)
    assert patched == "xxxxxTruexxxxx"


def test_apply_semgrep_fix_missing_offsets_returns_none():
    f = _vuln_finding(start_offset=None, end_offset=None)
    assert apply_semgrep_fix("anything", f) is None


def test_apply_fix_dispatches_by_category():
    assert apply_fix("flask==1.1.0\n", _dep_finding()) == "flask==2.2.5\n"
    assert apply_fix("xFalsex", _vuln_finding(start_offset=1, end_offset=6)) == "xTruex"


def test_autofixable_filters_to_findings_with_a_fix():
    findings = [_dep_finding(), _vuln_finding(), _dep_finding(recommended_fix_version=None)]
    assert len(autofixable(findings)) == 2


def test_generate_diff_shape():
    diff = generate_diff("a\n", "b\n", "file.txt")
    assert "--- a/file.txt" in diff
    assert "+++ b/file.txt" in diff
    assert "-a" in diff
    assert "+b" in diff
