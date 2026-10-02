from spidercob_sentinel.autofix import apply_dependency_fix, apply_fix, apply_fixes, apply_semgrep_fix, autofixable, generate_diff
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


def test_apply_fixes_two_offset_fixes_in_same_file_dont_corrupt_each_other():
    # Two "False" occurrences -- a naive left-to-right apply would shift the
    # second match's stored offsets out from under it the moment the first
    # replacement changes the text length (here, it wouldn't even matter
    # since "True" and "False" differ in length; the point is this must
    # hold in general, so the implementation doesn't get to assume same
    # length).
    content = "aFalseb" + "c" * 10 + "dFalsee"
    first_start = content.index("False")
    second_start = content.index("False", first_start + 1)

    f1 = _vuln_finding(start_offset=first_start, end_offset=first_start + 5)
    f2 = _vuln_finding(start_offset=second_start, end_offset=second_start + 5)

    patched = apply_fixes(content, [f1, f2])
    assert patched == "aTrueb" + "c" * 10 + "dTruee"


def test_apply_fixes_mixes_vuln_and_dependency_findings():
    content = "xFalsex\nflask==1.1.0\n"
    vuln = _vuln_finding(start_offset=1, end_offset=6)
    dep = _dep_finding()
    patched = apply_fixes(content, [vuln, dep])
    assert patched == "xTruex\nflask==2.2.5\n"


def test_generate_diff_shape():
    diff = generate_diff("a\n", "b\n", "file.txt")
    assert "--- a/file.txt" in diff
    assert "+++ b/file.txt" in diff
    assert "-a" in diff
    assert "+b" in diff
