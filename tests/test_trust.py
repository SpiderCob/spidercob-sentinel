from unittest.mock import patch

from osv_scan import PackageFinding, ScanResult, Vulnerability

from spidercob_sentinel.trust import (
    _levenshtein,
    _npm_age_signal,
    _npm_install_script_signal,
    _npm_maintainer_signal,
    _overall_risk,
    _pypi_age_signal,
    _typosquat_signal,
    check_package,
    normalize_ecosystem,
)
from spidercob_sentinel.models import Finding


def test_normalize_ecosystem_aliases():
    assert normalize_ecosystem("pypi") == "PyPI"
    assert normalize_ecosystem("PyPI") == "PyPI"
    assert normalize_ecosystem("pip") == "PyPI"
    assert normalize_ecosystem("python") == "PyPI"
    assert normalize_ecosystem("npm") == "npm"
    assert normalize_ecosystem("node") == "npm"
    assert normalize_ecosystem("rust") is None


def test_levenshtein_basic():
    assert _levenshtein("abc", "abc") == 0
    assert _levenshtein("abc", "") == 3
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("colorama", "coloramaa") == 1
    assert _levenshtein("colorama", "colorana") == 1
    assert _levenshtein("kitten", "sitting") == 3


def test_typosquat_flags_close_match_to_real_popular_package():
    s = _typosquat_signal("PyPI", "coloramaa")
    assert s.status == "risk"
    assert "colorama" in s.detail


def test_typosquat_ok_for_the_popular_package_itself():
    s = _typosquat_signal("PyPI", "colorama")
    assert s.status == "ok"


def test_typosquat_ok_for_unrelated_name():
    s = _typosquat_signal("PyPI", "totally-unrelated-name-xyz-123")
    assert s.status == "ok"


def test_pypi_age_signal_new_package():
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    meta = {"releases": {"0.1.0": [{"upload_time_iso_8601": recent}]}}
    s = _pypi_age_signal(meta)
    assert s.status == "warning"
    assert "5 day" in s.detail


def test_pypi_age_signal_established_package():
    meta = {"releases": {"0.1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]}}
    s = _pypi_age_signal(meta)
    assert s.status == "ok"


def test_pypi_age_signal_skips_empty_release_lists():
    # Yanked/removed releases show up as an empty list in the real API --
    # must not crash indexing into them.
    meta = {"releases": {"0.0.1": [], "0.1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]}}
    s = _pypi_age_signal(meta)
    assert s.status == "ok"


def test_pypi_age_signal_no_data():
    s = _pypi_age_signal({"releases": {}})
    assert s.status == "unknown"


def test_npm_maintainer_signal_single_vs_multiple():
    assert _npm_maintainer_signal({"maintainers": [{"name": "a"}]}).status == "warning"
    assert _npm_maintainer_signal({"maintainers": [{"name": "a"}, {"name": "b"}]}).status == "ok"
    assert _npm_maintainer_signal({"maintainers": []}).status == "unknown"


def test_npm_install_script_signal():
    meta = {"versions": {"1.0.0": {"scripts": {"postinstall": "node install.js"}}}}
    s = _npm_install_script_signal(meta, "1.0.0")
    assert s.status == "warning"
    assert "postinstall" in s.detail

    meta_clean = {"versions": {"1.0.0": {"scripts": {"test": "jest"}}}}
    assert _npm_install_script_signal(meta_clean, "1.0.0").status == "ok"


def test_npm_age_signal():
    assert _npm_age_signal({"time": {"created": "2015-01-01T00:00:00.000Z"}}).status == "ok"
    assert _npm_age_signal({"time": {}}).status == "unknown"


def _finding(severity):
    return Finding(category="DEPENDENCY", type="CVE-X", description="d", severity=severity,
                    file="f", remediation="r")


def test_overall_risk_critical_on_high_cve():
    from spidercob_sentinel.trust import TrustSignal
    risk = _overall_risk([TrustSignal("x", "ok", "")], [_finding("HIGH")], found=True)
    assert risk == "CRITICAL"


def test_overall_risk_critical_on_typosquat():
    from spidercob_sentinel.trust import TrustSignal
    signals = [TrustSignal("typosquat", "risk", "looks fake")]
    assert _overall_risk(signals, [], found=True) == "CRITICAL"


def test_overall_risk_single_weak_signal_is_only_medium():
    # A lone single-maintainer warning shouldn't read as high risk on its own.
    from spidercob_sentinel.trust import TrustSignal
    signals = [TrustSignal("maintainers", "warning", "single maintainer"), TrustSignal("typosquat", "ok", "")]
    assert _overall_risk(signals, [], found=True) == "MEDIUM"


def test_overall_risk_two_weak_signals_escalate_to_high():
    from spidercob_sentinel.trust import TrustSignal
    signals = [
        TrustSignal("maintainers", "warning", "single maintainer"),
        TrustSignal("install_script", "warning", "runs code on install"),
        TrustSignal("typosquat", "ok", ""),
    ]
    assert _overall_risk(signals, [], found=True) == "HIGH"


def test_overall_risk_clean_package_is_low():
    from spidercob_sentinel.trust import TrustSignal
    signals = [TrustSignal("maintainers", "ok", ""), TrustSignal("typosquat", "ok", "")]
    assert _overall_risk(signals, [], found=True) == "LOW"


def test_overall_risk_not_found_is_medium_not_low():
    assert _overall_risk([], [], found=False) == "MEDIUM"


def test_check_package_unsupported_ecosystem():
    report = check_package("rust", "serde")
    assert report.found is False
    assert report.overall == "LOW"
    assert report.signals[0].name == "ecosystem"


def test_check_package_pypi_not_found():
    with patch("spidercob_sentinel.trust._pypi_metadata", return_value=None):
        report = check_package("pypi", "this-package-does-not-exist-xyz")
    assert report.found is False
    assert report.overall == "MEDIUM"


def test_check_package_pypi_full_flow_with_cve():
    meta = {
        "info": {"version": "1.0.0"},
        "releases": {"1.0.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]},
    }
    vuln = Vulnerability(id="GHSA-x", cve="CVE-2024-1", aliases=[], summary="bad stuff",
                          details="", severity="HIGH", fixed_versions=["1.0.1"], published="")
    pkg = PackageFinding(package="fakepkg", version="1.0.0", ecosystem="PyPI", vulnerabilities=[vuln])
    fake_result = ScanResult(source="<text>", ecosystem="PyPI", packages_scanned=1, findings=[pkg], elapsed_ms=1)

    with patch("spidercob_sentinel.trust._pypi_metadata", return_value=meta), \
         patch("osv_scan.scan_text", return_value=fake_result):
        report = check_package("pypi", "fakepkg")

    assert report.found is True
    assert report.version == "1.0.0"
    assert report.overall == "CRITICAL"
    assert len(report.cve_findings) == 1
    assert report.cve_findings[0].type == "CVE-2024-1"
    assert report.cve_findings[0].recommended_fix_version == "1.0.1"


def test_check_package_npm_full_flow_clean():
    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "time": {"created": "2015-01-01T00:00:00.000Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "versions": {"1.0.0": {"scripts": {}}},
    }
    empty_result = ScanResult(source="<text>", ecosystem="npm", packages_scanned=1, findings=[], elapsed_ms=1)

    with patch("spidercob_sentinel.trust._npm_metadata", return_value=meta), \
         patch("osv_scan.scan_text", return_value=empty_result):
        report = check_package("npm", "totally-clean-package-xyz")

    assert report.found is True
    assert report.overall == "LOW"
    assert report.cve_findings == []


def test_report_to_dict_roundtrips_cleanly():
    report = check_package("rust", "serde")  # unsupported -> no network, deterministic
    d = report.to_dict()
    assert d["ecosystem"] == "rust"
    assert d["found"] is False
    assert isinstance(d["signals"], list)
    assert d["signals"][0]["name"] == "ecosystem"
