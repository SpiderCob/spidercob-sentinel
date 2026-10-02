from unittest.mock import patch

from osv_scan import PackageFinding, ScanResult, Vulnerability

from spidercob_sentinel.deps import detect_ecosystem, is_manifest, scan_manifest


def test_detect_ecosystem():
    assert detect_ecosystem("requirements.txt") == "PyPI"
    assert detect_ecosystem("package.json") == "npm"
    assert detect_ecosystem("go.mod") == "Go"
    assert detect_ecosystem("README.md") is None


def test_is_manifest():
    assert is_manifest("/some/path/requirements.txt")
    assert not is_manifest("/some/path/app.py")


def _fake_result():
    vuln_with_summary = Vulnerability(
        id="GHSA-xxxx", cve="CVE-2024-11111", aliases=[], summary="Real summary",
        details="", severity="HIGH", fixed_versions=["2.31.0"], published="",
    )
    vuln_dup_no_summary = Vulnerability(
        id="PYSEC-2024-1", cve="CVE-2024-11111", aliases=[], summary="",
        details="", severity="MEDIUM", fixed_versions=["2.31.0"], published="",
    )
    pkg = PackageFinding(package="requests", version="2.25.0", ecosystem="PyPI",
                          vulnerabilities=[vuln_with_summary, vuln_dup_no_summary])
    return ScanResult(source="requirements.txt", ecosystem="PyPI", packages_scanned=1,
                       findings=[pkg], elapsed_ms=1)


def test_scan_manifest_dedupes_same_cve_from_multiple_advisories(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.25.0\n")

    with patch("spidercob_sentinel.deps.osv_scan.scan", return_value=_fake_result()):
        findings = scan_manifest(str(req))

    assert len(findings) == 1, "same CVE from two advisories should collapse to one finding"
    f = findings[0]
    assert f.type == "CVE-2024-11111"
    assert f.description == "requests 2.25.0: Real summary", "should prefer the advisory with an actual summary"
    assert f.package == "requests"
    assert f.recommended_fix_version == "2.31.0"
    assert f.autofix_available


def test_scan_manifest_non_manifest_file_returns_empty(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("print('hi')\n")
    assert scan_manifest(str(f)) == []
