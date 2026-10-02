"""
Unified finding model shared across the three scanning sources (Semgrep
vulnerabilities, dlp-patterns secrets, osv-scan dependency CVEs) so the
triage and autofix layers don't need to know which engine produced a
finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Matches spider-snoop's existing convention (and Semgrep's own severity
# vocabulary) — keep these in sync if either changes.
SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "Unreachable": -1}


@dataclass
class Finding:
    category: str          # "SECRET" | "VULNERABILITY" | "DEPENDENCY"
    type: str               # e.g. "sql_injection", "aws_access_key", "CVE-2024-12345"
    description: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / Unreachable
    file: str
    remediation: str
    line: Optional[int] = None
    end_line: Optional[int] = None
    check_id: Optional[str] = None       # Semgrep rule id, VULNERABILITY only
    start_offset: Optional[int] = None    # character offset, for precise autofix
    end_offset: Optional[int] = None      # (Semgrep's fix: can target a sub-line span)
    masked_value: Optional[str] = None    # redacted secret value, SECRET only
    fixed_versions: List[str] = field(default_factory=list)  # DEPENDENCY only
    package: Optional[str] = None          # DEPENDENCY only
    installed_version: Optional[str] = None  # DEPENDENCY only
    recommended_fix_version: Optional[str] = None  # DEPENDENCY only — nearest real upgrade
    fix_snippet: Optional[str] = None     # Semgrep rule's own `fix:` text, if any
    reachable: Optional[bool] = None      # Python-only AST reachability signal

    @property
    def autofix_available(self) -> bool:
        """True if autofix.py can mechanically produce a patch for this
        finding — a vetted Semgrep `fix:` snippet, or a known-good
        dependency upgrade version. Never true for an LLM-authored patch;
        v1 deliberately never writes code via the LLM (see triage.py)."""
        return bool(self.fix_snippet) or bool(self.recommended_fix_version)

    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["autofix_available"] = self.autofix_available
        return d


@dataclass
class ScanReport:
    """All findings for one invocation (one file, one repo walk, one PR)."""
    findings: List[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def blocking(self) -> List[Finding]:
        """Findings worth a human's attention — excludes dead/unreachable
        code, matching the same semantics the rest of the Spidercob
        ecosystem uses for this term."""
        return [f for f in self.findings if f.severity != "Unreachable"]

    @property
    def autofixable(self) -> List[Finding]:
        return [f for f in self.findings if f.autofix_available]

    def sorted_by_severity(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.rank(), reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "findings": [f.to_dict() for f in self.findings],
        }
