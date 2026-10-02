"""
Secret scanning — thin wrapper around the `dlp-patterns` OSS library,
mapped into the unified Finding model.
"""
from __future__ import annotations

from typing import List

import dlp_patterns

from .models import Finding
from .remediation import get_remediation


def _char_offset_to_line(text: str, offset: int) -> int:
    """dlp-patterns reports positions as a character offset ("char 10-30");
    Semgrep and this tool's own CLI output report line numbers — convert so
    every Finding has a comparable `.line`, regardless of source engine."""
    return text.count("\n", 0, offset) + 1


def scan_secrets(file_path: str, content: str) -> List[Finding]:
    """Scan `content` for secrets/PII using dlp-patterns. Returns a list of
    SECRET Findings. Never raises — dlp-patterns is a pure zero-dependency
    regex engine, but a malformed/binary file could still produce odd input;
    callers should still treat this as best-effort like the Semgrep pass."""
    result = dlp_patterns.scan(content, secrets_only=True)

    findings: List[Finding] = []
    for bucket in (result.critical, result.high, result.medium, result.low):
        for item in bucket:
            line = None
            if item.position and item.position.startswith("char "):
                try:
                    start_str = item.position[len("char "):].split("-")[0]
                    line = _char_offset_to_line(content, int(start_str))
                except (ValueError, IndexError):
                    line = None

            findings.append(Finding(
                category="SECRET",
                type=item.type,
                description=item.description,
                severity=item.severity,
                file=file_path,
                line=line,
                masked_value=item.value,
                remediation=get_remediation(item.type),
            ))

    return findings
