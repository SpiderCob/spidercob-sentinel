"""
Top-level scan orchestration — walks a file or directory, routing each file
to the right engine(s): Semgrep (scanner.py) + secrets (secrets.py) for
source files, osv-scan (deps.py) for dependency manifests.
"""
from __future__ import annotations

import os
from typing import List

from .deps import is_manifest, scan_manifest
from .models import Finding, ScanReport
from .scanner import SCANNABLE_EXTS, scan_code_file
from .secrets import scan_secrets

# Directories never worth walking into — noise, generated output, or huge
# dependency trees that would make a scan slow for no security value.
# "semgrep_rules" is this tool's own vendored rule set (see
# scripts/fetch_rules.sh / the Dockerfile) — the upstream repo ships
# hundreds of .py/.js *test fixture* files alongside the rule YAMLs
# (one or more worked examples per rule), which previously made a scan of
# this very project's own repo spawn 500+ needless semgrep subprocesses
# and take minutes instead of seconds. Exclude it by the same name
# whenever this tool scans its own working tree.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".next",
    "vendor", "target", "semgrep_rules",
}

# Secrets can leak in config/env/yaml files just as easily as source code —
# unlike the Semgrep/dependency passes, the secrets pass runs on every file
# except these unambiguously-binary extensions (scanning them as text would
# be wasted work at best, a decode error at worst).
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf",
    ".zip", ".tar", ".gz", ".whl", ".so", ".dylib", ".dll", ".exe",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
}
_MAX_FILE_BYTES = 2_000_000  # skip anything bigger — not a source/config file


async def scan_file(file_path: str) -> List[Finding]:
    """Scan one file with every engine that applies to it. A file can be
    both a source file and get a secrets pass (e.g. a .py file with a
    hardcoded key) — those aren't mutually exclusive, so both run."""
    if is_manifest(file_path):
        return scan_manifest(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []

    findings = scan_secrets(file_path, content)

    ext = os.path.splitext(file_path)[1].lower()
    if ext in SCANNABLE_EXTS:
        findings += await scan_code_file(file_path, content)

    return findings


async def scan_path(path: str, *, max_files: int = 500) -> ScanReport:
    """Scan a single file or walk a directory. `max_files` is a safety cap
    for accidentally pointing this at something enormous (e.g. a monorepo
    with its node_modules not excluded elsewhere) — raise it explicitly for
    a deliberately large scan."""
    report = ScanReport()

    if os.path.isfile(path):
        report.findings.extend(await scan_file(path))
        return report

    scanned = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if scanned >= max_files:
                return report
            ext = os.path.splitext(name)[1].lower()
            if ext in _BINARY_EXTS:
                continue
            file_path = os.path.join(root, name)
            try:
                if os.path.getsize(file_path) > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            report.findings.extend(await scan_file(file_path))
            scanned += 1

    return report
