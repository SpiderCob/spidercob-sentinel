"""
Vulnerability scanner — Semgrep-backed AST/dataflow static analysis, plus a
Python AST reachability pass to demote findings in genuinely dead code.

Real AST-based structural matching + intraprocedural taint tracking (a
tainted variable flowing from a source like request.args into a sink a few
lines away, within one function) — not a regex dictionary. This is NOT full
interprocedural/cross-file taint tracking (that's Semgrep Pro, a paid
product): a source and sink split across two different functions or files
still won't be connected, and IDOR/race conditions (a missing check, not a
bad pattern present in the text) are out of scope entirely. That gap is
real and is the honest ceiling here — not something this tool closes.

Rules are vendored at build/install time from github.com/semgrep/semgrep-rules
(see the Dockerfile and `scripts/fetch_rules.sh`) rather than pulled from the
registry at scan time, so scanning stays fully offline.
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from .models import Finding
from .remediation import get_remediation

logger = logging.getLogger(__name__)

SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
SEMGREP_RULES_DIR = os.environ.get(
    "SEMGREP_RULES_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "semgrep_rules"),
)
SEMGREP_TIMEOUT_S = int(os.environ.get("SEMGREP_TIMEOUT_S", "30"))

# Extension -> vendored rule subdirectories to load. Scoped to the file's own
# language (rather than loading every vendored language every time) — Semgrep's
# per-invocation cost is dominated by rule *loading*, not matching, so this
# both avoids irrelevant findings and keeps latency down.
LANG_DIRS = {
    ".py":  ("python",),
    ".js":  ("javascript",),
    ".jsx": ("javascript",),
    ".mjs": ("javascript",),
    ".ts":  ("typescript", "javascript"),
    ".tsx": ("typescript", "javascript"),
    ".java": ("java",),
    ".php": ("php",),
    ".go":  ("go",),
}

SEVERITY_RANK = {"ERROR": 2, "WARNING": 1, "INFO": 0}

# Source-file extensions this scanner knows how to parse at all. Used by
# cli.py / github_app.py to decide what to hand to scan_file() vs. deps.py.
SCANNABLE_EXTS = frozenset(LANG_DIRS.keys())


class ReachabilityAnalyzer(ast.NodeVisitor):
    """Walks a Python AST, tracking which functions are called in-file and
    which are decorated (route handlers, Celery tasks, CLI commands, pytest
    fixtures, etc. are all invoked by their framework, never by an in-file
    call — treating "no visible caller" as unreachable for these would
    silently demote real vulnerabilities sitting in the most common place
    they actually live)."""

    def __init__(self):
        self.called_functions = set()
        self.defined_functions = set()
        self.func_ranges: Dict[str, tuple] = {}
        self.entry_point_functions = set()

    def visit_FunctionDef(self, node):
        self.defined_functions.add(node.name)
        end_lineno = getattr(node, "end_lineno", node.lineno)
        self.func_ranges[node.name] = (node.lineno, end_lineno)
        if node.decorator_list:
            self.entry_point_functions.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            self.called_functions.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.called_functions.add(node.func.attr)
        self.generic_visit(node)


def _finding_type_from_cwe(metadata: dict) -> str:
    """Derive a human-readable category from a Semgrep rule's CWE metadata,
    e.g. "CWE-89: Improper Neutralization ... ('SQL Injection')" -> "SQL
    Injection". Vendored (offline) rules only reliably carry `cwe`/`owasp`
    metadata, not the registry-enriched `vulnerability_class` field (that's
    filled in server-side by semgrep.dev, unavailable to a local --config
    path) — so CWE is the actual signal available here."""
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, str):
        m = re.search(r"\('([^']+)'\)\s*$", cwe)
        if m:
            return m.group(1)
        m2 = re.match(r"CWE-\d+:\s*(.+)", cwe)
        if m2:
            return m2.group(1).split(" (")[0].strip()
        return cwe
    return "Static Analysis Finding"


async def _run_semgrep(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Run vendored Semgrep rules against `content` and return deduplicated,
    per-line raw results. Returns [] (never raises) for unsupported
    languages, a missing semgrep binary, a scan timeout, or any parse
    failure — static analysis is best-effort, not something that should
    take the whole scan down if it's unavailable."""
    ext = os.path.splitext(file_path or "")[1].lower()
    lang_dirs = LANG_DIRS.get(ext)
    if not lang_dirs:
        return []

    config_args = []
    for d in lang_dirs:
        rules_path = os.path.join(SEMGREP_RULES_DIR, d)
        if os.path.isdir(rules_path):
            config_args += ["--config", rules_path]
    if not config_args:
        logger.warning(
            "No vendored semgrep rules found under %s for %s — run "
            "scripts/fetch_rules.sh, or scanning will skip static analysis",
            SEMGREP_RULES_DIR, ext,
        )
        return []

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        proc = await asyncio.create_subprocess_exec(
            SEMGREP_BIN, *config_args,
            "--json", "--metrics=off", "--timeout", str(SEMGREP_TIMEOUT_S), "--quiet",
            tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SEMGREP_TIMEOUT_S + 5)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("semgrep timed out scanning %s", file_path)
            return []

        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        except json.JSONDecodeError:
            logger.warning("semgrep produced non-JSON output for %s: %s", file_path, stderr.decode(errors="ignore")[:300])
            return []

        results = data.get("results", [])
    except FileNotFoundError:
        logger.warning("semgrep binary (%s) not found — static analysis pass skipped", SEMGREP_BIN)
        return []
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Multiple rules commonly fire on the same line (e.g. three different
    # subprocess-shell-true variants) — keep the highest-severity one per
    # line instead of reporting near-duplicates for the same real issue.
    by_line: Dict[int, tuple] = {}
    for r in results:
        line = r.get("start", {}).get("line")
        if line is None:
            continue
        severity = r.get("extra", {}).get("severity", "")
        rank = SEVERITY_RANK.get(severity, 0)
        if line not in by_line or rank > by_line[line][0]:
            by_line[line] = (rank, r)

    return [r for _, (_, r) in sorted(by_line.items())]


async def scan_code_file(file_path: str, content: Optional[str] = None) -> List[Finding]:
    """Scan one file for real vulnerabilities (not secrets — see secrets.py
    for that). Returns a list of VULNERABILITY Findings."""
    if content is None:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    reachable_functions: set = set()
    func_ranges: Dict[str, tuple] = {}
    is_python = bool(file_path) and file_path.endswith(".py")
    if is_python:
        try:
            tree = ast.parse(content)
            analyzer = ReachabilityAnalyzer()
            analyzer.visit(tree)
            reachable_functions = analyzer.called_functions | analyzer.entry_point_functions
            func_ranges = analyzer.func_ranges
        except SyntaxError:
            pass

    findings: List[Finding] = []
    for raw in await _run_semgrep(file_path, content):
        line_no = raw.get("start", {}).get("line")
        end_line = raw.get("end", {}).get("line", line_no)
        extra = raw.get("extra", {})
        metadata = extra.get("metadata", {})
        finding_type = _finding_type_from_cwe(metadata)
        description = (extra.get("message") or raw.get("check_id") or "Static analysis finding")[:300]

        is_reachable = True
        if is_python and func_ranges:
            enclosing_func = None
            for fname, (f_start, f_end) in func_ranges.items():
                if f_start <= line_no <= f_end:
                    enclosing_func = fname
                    break
            if enclosing_func and enclosing_func not in reachable_functions:
                if not enclosing_func.startswith("test_") and enclosing_func not in ("__init__", "main"):
                    is_reachable = False

        severity = "HIGH" if is_reachable else "Unreachable"

        findings.append(Finding(
            category="VULNERABILITY",
            type=finding_type,
            description=description,
            severity=severity,
            file=file_path,
            line=line_no,
            end_line=end_line,
            check_id=raw.get("check_id"),
            start_offset=raw.get("start", {}).get("offset"),
            end_offset=raw.get("end", {}).get("offset"),
            # Semgrep includes extra.fix in the JSON result whenever the
            # matched rule carries a `fix:` field, independent of whether
            # --autofix was passed — this is the vetted-safe autofix
            # candidate autofix.py applies, never an LLM-authored patch.
            fix_snippet=extra.get("fix"),
            reachable=is_reachable,
            # Some CWE labels (e.g. "Improperly Controlled Modification of
            # Dynamically-Determined Object Attributes" for what's really a
            # SQL-string-building rule) don't contain any of the keyword
            # fallbacks' substrings on their own — the Semgrep check_id
            # almost always does (e.g. "...injection.tainted-sql-string"),
            # so fold it into the lookup key rather than relying on the
            # human-readable CWE label alone.
            remediation=get_remediation(f"{finding_type} {raw.get('check_id', '')}"),
        ))

    return findings
