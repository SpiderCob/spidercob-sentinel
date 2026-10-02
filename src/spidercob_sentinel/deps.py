"""
Dependency CVE scanning — thin wrapper around the `osv-scan` OSS library
(free OSV.dev API, no key required), mapped into the unified Finding model.
"""
from __future__ import annotations

import os
from typing import List, Optional

import osv_scan

from .models import Finding
from .remediation import get_remediation

# Manifest filename -> OSV.dev ecosystem name. Mirrors the detection already
# proven out in spider-snoop's own code_security.py route.
_MANIFEST_ECOSYSTEMS = {
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
    "pipfile.lock": "PyPI",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "package.json": "npm",
    "go.mod": "Go",
    "cargo.toml": "crates.io",
    "cargo.lock": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "gemfile.lock": "RubyGems",
    "gemfile": "RubyGems",
    "composer.lock": "Packagist",
    "composer.json": "Packagist",
}


def detect_ecosystem(filename: str) -> Optional[str]:
    return _MANIFEST_ECOSYSTEMS.get(os.path.basename(filename).lower())


def is_manifest(filename: str) -> bool:
    return detect_ecosystem(filename) is not None


def scan_manifest(file_path: str) -> List[Finding]:
    """Scan a dependency manifest for known CVEs via OSV.dev. Returns a list
    of DEPENDENCY Findings — empty if the file isn't a recognized manifest
    type, or if OSV.dev is unreachable (best-effort, matches the posture of
    the other two scanners: a network hiccup degrades results, never crashes
    the whole scan)."""
    if not is_manifest(file_path):
        return []

    try:
        result = osv_scan.scan(file_path)
    except Exception:
        return []

    findings: List[Finding] = []
    for pkg in result.findings:
        # OSV.dev often carries the same real-world vulnerability under more
        # than one advisory record (e.g. a GHSA entry and a PYSEC entry that
        # both alias the same CVE) — osv-scan surfaces each as a separate
        # Vulnerability. Without deduping, a user sees the same CVE twice
        # with different severities/descriptions, which undermines the
        # whole "tell me what actually matters" pitch. Keep one entry per
        # (package, cve_id), preferring whichever has an actual summary.
        best_by_cve: dict = {}
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
                file=file_path,
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
