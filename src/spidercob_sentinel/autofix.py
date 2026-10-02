"""
Mechanical, deterministic autofix — deliberately narrow for v1.

Two sources only, both vetted/deterministic, never LLM-authored:
  1. A Semgrep rule's own `fix:` snippet (community-maintained, reviewed —
     this tool just applies it, it doesn't invent it).
  2. A dependency version bump to a known-patched release (from osv-scan).

A security tool that writes its own security patches via a
hallucination-prone LLM is a credibility risk the moment it's wrong once.
`triage.py` is where the LLM lives, and it only ever produces prose
(explanation + priority) — never a diff. If you want broader autofix
coverage later, grow this file's deterministic rule set; don't wire an LLM
into it.
"""
from __future__ import annotations

import difflib
import re
from typing import List, Optional

from .models import Finding


def autofixable(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.autofix_available]


def apply_semgrep_fix(content: str, finding: Finding) -> Optional[str]:
    """Replace the exact matched span with the rule's own fix snippet, using
    character offsets rather than whole-line reconstruction — a Semgrep
    match (especially with `focus-metavariable`) is very often a sub-line
    span (e.g. just the `False` in `verify_signature": False`), and
    replacing the whole line would silently destroy the surrounding
    code/indentation. Returns None if this finding has no fix_snippet, no
    offsets, or the offsets no longer fit `content` (e.g. the file changed
    since the scan ran — never guess at a different location)."""
    if not finding.fix_snippet:
        return None
    if finding.start_offset is None or finding.end_offset is None:
        return None
    start, end = finding.start_offset, finding.end_offset
    if start < 0 or end > len(content) or start > end:
        return None

    return content[:start] + finding.fix_snippet.rstrip("\n") + content[end:]


_PIN_RE_TEMPLATE = r"(?m)^(\s*{pkg}\s*(?:==|>=|~=)\s*)[^\s#;]+"


def apply_dependency_fix(content: str, finding: Finding) -> Optional[str]:
    """Bump a pinned version in a requirements.txt-style line. Scoped to
    this one manifest format for v1 — package.json/go.mod/etc. CVEs are
    still detected and explained, just not auto-patched yet; that's an
    honest, documented limitation, not a silent gap."""
    if not finding.package or not finding.recommended_fix_version:
        return None
    if not finding.file.lower().endswith(".txt"):
        return None

    pattern = re.compile(_PIN_RE_TEMPLATE.format(pkg=re.escape(finding.package)), re.IGNORECASE)
    new_content, count = pattern.subn(rf"\g<1>{finding.recommended_fix_version}", content, count=1)
    if count == 0:
        return None
    return new_content


def apply_fix(content: str, finding: Finding) -> Optional[str]:
    """Dispatch to the right fixer for this finding's category. Returns the
    patched file content, or None if no mechanical fix could be applied."""
    if finding.category == "VULNERABILITY":
        return apply_semgrep_fix(content, finding)
    if finding.category == "DEPENDENCY":
        return apply_dependency_fix(content, finding)
    return None


def apply_fixes(content: str, findings: List[Finding]) -> str:
    """Apply every fixable finding in `findings` (which must all belong to
    the same file) to `content`, returning the final patched text.

    VULNERABILITY fixes use absolute character offsets captured at scan
    time — applying them left-to-right would invalidate every later
    offset the moment one replacement changes the text length, so those
    are applied in descending start_offset order (last match in the file
    first) so earlier offsets stay valid. DEPENDENCY fixes re-locate their
    target by package name on each call rather than a stored offset, so
    they're order-independent and applied afterwards."""
    vuln_findings = sorted(
        (f for f in findings if f.category == "VULNERABILITY" and f.autofix_available),
        key=lambda f: f.start_offset if f.start_offset is not None else -1,
        reverse=True,
    )
    dep_findings = [f for f in findings if f.category == "DEPENDENCY" and f.autofix_available]

    for f in vuln_findings:
        patched = apply_semgrep_fix(content, f)
        if patched is not None:
            content = patched

    for f in dep_findings:
        patched = apply_dependency_fix(content, f)
        if patched is not None:
            content = patched

    return content


def generate_diff(original: str, patched: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    ))
