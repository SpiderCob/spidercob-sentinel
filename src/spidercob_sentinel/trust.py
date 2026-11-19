"""
Package trust check — "is this dependency safe to add?" without installing
anything. Pulls known CVEs (osv-scan), a typosquat check against the most
popular packages in the ecosystem, and whatever age/maintainer/install-script
signals the public registry actually exposes.

Deliberately rule-based, never LLM-scored — same reasoning as autofix.py's
refusal to let an LLM write security patches: a supply-chain risk verdict
needs to be inspectable and reproducible, not a model's guess. If you want
prose explanation layered on top, that's triage.py's job elsewhere in this
project, not this module's.

Network calls are all best-effort: a registry being unreachable degrades a
signal to "unknown," it never raises out of check_package(). This has to
work as a 2-second answer on a public web page with no retry UX.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding
from .remediation import get_remediation

_DATA_DIR = Path(__file__).parent / "data"
_UA = "spidercob-sentinel-trust-check/0.1 (+https://github.com/SpiderCob/spidercob-sentinel)"
_TIMEOUT_S = 8

# Canonical ecosystem names, matching osv-scan's own ECOSYSTEM_MAP values.
_ECOSYSTEM_ALIASES = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "npm": "npm", "node": "npm", "javascript": "npm",
}


def normalize_ecosystem(ecosystem: str) -> Optional[str]:
    return _ECOSYSTEM_ALIASES.get((ecosystem or "").strip().lower())


def _load_top_packages(ecosystem: str) -> List[str]:
    filename = "top_packages_pypi.json" if ecosystem == "PyPI" else "top_packages_npm.json"
    try:
        with open(_DATA_DIR / filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + (ca != cb),  # substitution
            )
        prev = cur
    return prev[-1]


def _http_get_json(url: str) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


@dataclass
class TrustSignal:
    name: str
    status: str  # "ok" | "warning" | "risk" | "unknown"
    detail: str


@dataclass
class TrustReport:
    ecosystem: str
    package: str
    version: Optional[str] = None
    found: bool = True
    signals: List[TrustSignal] = field(default_factory=list)
    cve_findings: List[Finding] = field(default_factory=list)
    overall: str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "found": self.found,
            "overall": self.overall,
            "signals": [s.__dict__ for s in self.signals],
            "cve_findings": [f.to_dict() for f in self.cve_findings],
        }


def _pypi_metadata(name: str) -> Optional[Dict[str, Any]]:
    return _http_get_json(f"https://pypi.org/pypi/{name}/json")


def _npm_metadata(name: str) -> Optional[Dict[str, Any]]:
    # npm registry 404s on unknown packages -- that's a real "not found"
    # signal, not a transient failure, but _http_get_json collapses both
    # to None. Good enough for v1: either way we can't say anything about
    # the package, and the caller treats None as "couldn't look it up."
    return _http_get_json(f"https://registry.npmjs.org/{name}")


def _pypi_age_signal(meta: Dict[str, Any]) -> TrustSignal:
    times: List[str] = []
    for files in meta.get("releases", {}).values():
        for f in files:
            t = f.get("upload_time_iso_8601")
            if t:
                times.append(t)
    if not times:
        return TrustSignal("package_age", "unknown", "No release timestamps available.")

    times.sort()
    first = datetime.fromisoformat(times[0].replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - first).days

    if age_days < 30:
        return TrustSignal("package_age", "warning", f"First published {age_days} day(s) ago — very new.")
    return TrustSignal("package_age", "ok", f"First published {age_days} day(s) ago.")


def _npm_age_signal(meta: Dict[str, Any]) -> TrustSignal:
    created = meta.get("time", {}).get("created")
    if not created:
        return TrustSignal("package_age", "unknown", "No creation timestamp available.")
    first = datetime.fromisoformat(created.replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - first).days
    if age_days < 30:
        return TrustSignal("package_age", "warning", f"First published {age_days} day(s) ago — very new.")
    return TrustSignal("package_age", "ok", f"First published {age_days} day(s) ago.")


def _npm_maintainer_signal(meta: Dict[str, Any]) -> TrustSignal:
    maintainers = meta.get("maintainers", [])
    count = len(maintainers)
    if count == 0:
        return TrustSignal("maintainers", "unknown", "No maintainer data available.")
    if count == 1:
        return TrustSignal("maintainers", "warning", "Single maintainer — a compromised or departed account has no second line of defense.")
    return TrustSignal("maintainers", "ok", f"{count} maintainers on the registry.")


def _npm_install_script_signal(meta: Dict[str, Any], version: str) -> TrustSignal:
    versions = meta.get("versions", {})
    v = versions.get(version, {})
    scripts = v.get("scripts", {})
    risky = [k for k in ("preinstall", "install", "postinstall") if scripts.get(k)]
    if risky:
        return TrustSignal(
            "install_script", "warning",
            f"Runs code on install ({', '.join(risky)}) — not inherently malicious (native builds commonly need this), but it's exactly how several real npm supply-chain compromises (event-stream, ua-parser-js) shipped.",
        )
    return TrustSignal("install_script", "ok", "No preinstall/install/postinstall script.")


def _typosquat_signal(ecosystem: str, name: str) -> TrustSignal:
    top = _load_top_packages(ecosystem)
    if not top:
        return TrustSignal("typosquat", "unknown", "Reference package list unavailable.")

    name_lower = name.lower()
    if name_lower in (p.lower() for p in top):
        return TrustSignal("typosquat", "ok", "This is itself one of the most popular packages in this ecosystem.")

    for popular in top:
        dist = _levenshtein(name_lower, popular.lower())
        if 0 < dist <= 2 and len(popular) > 3:
            return TrustSignal(
                "typosquat", "risk",
                f"Name is very close to '{popular}' (edit distance {dist}), one of the most popular {ecosystem} packages, but isn't it. Classic typosquat pattern — double-check you meant to type this exact name.",
            )
    return TrustSignal("typosquat", "ok", "No suspiciously-close match to a popular package name.")


def _cve_findings(ecosystem: str, name: str, version: str) -> List[Finding]:
    try:
        import osv_scan
    except ImportError:
        return []

    manifest = f"{name}=={version}" if ecosystem == "PyPI" else json.dumps({"dependencies": {name: version}})
    try:
        result = osv_scan.scan_text(manifest, ecosystem=ecosystem, source="<trust-check>")
    except Exception:
        return []

    findings: List[Finding] = []
    for pkg in result.findings:
        best_by_cve: Dict[str, Any] = {}
        for vuln in pkg.vulnerabilities:
            cve_id = vuln.cve or vuln.id
            existing = best_by_cve.get(cve_id)
            if existing is None or (not existing.summary and vuln.summary):
                best_by_cve[cve_id] = vuln
        for cve_id, vuln in best_by_cve.items():
            findings.append(Finding(
                category="DEPENDENCY",
                type=cve_id or "CVE_UNKNOWN",
                description=f"{pkg.package} {pkg.version}: {vuln.summary}" if vuln.summary else f"Known vulnerability in {pkg.package} {pkg.version}",
                severity=vuln.severity if vuln.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
                file=f"{ecosystem}:{name}",
                fixed_versions=vuln.fixed_versions,
                package=pkg.package,
                installed_version=pkg.version,
                recommended_fix_version=(pkg.fix_versions[0] if pkg.fix_versions else None),
                remediation=(
                    f"Upgrade {pkg.package} to {pkg.fix_versions[0]}." if pkg.fix_versions
                    else get_remediation("known_vulnerability")
                ),
            ))
    return findings


def _overall_risk(signals: List[TrustSignal], cve_findings: List[Finding], found: bool) -> str:
    """Deterministic rule table -- combine signals, don't let any single weak
    one dominate. A legitimate single-maintainer indie package with nothing
    else wrong shouldn't read as HIGH risk just for that."""
    if not found:
        return "MEDIUM"  # unknown package -- not proof of anything, but not nothing either

    by_name = {s.name: s for s in signals}

    if any(f.severity in ("CRITICAL", "HIGH") for f in cve_findings):
        return "CRITICAL"
    if by_name.get("typosquat", TrustSignal("", "ok", "")).status == "risk":
        return "CRITICAL"
    if any(f.severity == "MEDIUM" for f in cve_findings):
        return "HIGH"

    warnings = sum(1 for s in signals if s.status == "warning")
    if warnings >= 2:
        return "HIGH"
    if warnings == 1:
        return "MEDIUM"
    return "LOW"


def check_package(ecosystem: str, name: str, version: Optional[str] = None) -> TrustReport:
    """Check one package. `ecosystem` accepts common aliases (pypi, pip,
    npm, node, ...). `version` defaults to the registry's current latest
    if not given."""
    canonical = normalize_ecosystem(ecosystem)
    if canonical is None:
        return TrustReport(
            ecosystem=ecosystem, package=name, found=False, overall="LOW",
            signals=[TrustSignal("ecosystem", "unknown", f"Unsupported ecosystem '{ecosystem}' -- only PyPI and npm are checked today.")],
        )

    if canonical == "PyPI":
        meta = _pypi_metadata(name)
        if meta is None:
            return TrustReport(ecosystem=canonical, package=name, found=False, overall="MEDIUM",
                                signals=[TrustSignal("lookup", "unknown", "Package not found on PyPI, or PyPI was unreachable.")])
        resolved_version = version or meta["info"]["version"]
        signals = [_pypi_age_signal(meta), _typosquat_signal(canonical, name)]
    else:
        meta = _npm_metadata(name)
        if meta is None:
            return TrustReport(ecosystem=canonical, package=name, found=False, overall="MEDIUM",
                                signals=[TrustSignal("lookup", "unknown", "Package not found on npm, or the registry was unreachable.")])
        resolved_version = version or meta.get("dist-tags", {}).get("latest")
        signals = [
            _npm_age_signal(meta),
            _npm_maintainer_signal(meta),
            _npm_install_script_signal(meta, resolved_version) if resolved_version else TrustSignal("install_script", "unknown", "No version resolved."),
            _typosquat_signal(canonical, name),
        ]

    cve_findings = _cve_findings(canonical, name, resolved_version) if resolved_version else []
    overall = _overall_risk(signals, cve_findings, found=True)

    return TrustReport(
        ecosystem=canonical, package=name, version=resolved_version, found=True,
        signals=signals, cve_findings=cve_findings, overall=overall,
    )
