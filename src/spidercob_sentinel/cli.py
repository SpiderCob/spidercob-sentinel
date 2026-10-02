"""
CLI entry point — sentinel

Usage:
    sentinel scan path/to/file.py
    sentinel scan path/to/project/
    sentinel scan . --json
    sentinel scan . --min-severity HIGH
    sentinel scan . --explain                      # needs SENTINEL_LLM_* env vars
    sentinel scan . --autofix-diff                  # print unified diffs, never writes files
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from . import __version__
from .autofix import apply_fix, autofixable, generate_diff
from .models import SEVERITY_RANK, Finding, ScanReport
from .scan import scan_path
from .triage import triage

_SEVERITY_LABEL = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "Unreachable": "unreachable (dead code)",
}


def _print_human(report: ScanReport, *, min_rank: int, explain: bool, triage_result=None) -> None:
    shown = [f for f in report.sorted_by_severity() if f.rank() >= min_rank]

    if not shown:
        print("No findings at or above the requested severity. ✅" if min_rank > SEVERITY_RANK["Unreachable"] else "No findings. ✅")
        return

    print(f"{len(shown)} finding(s) ({report.total} total, {len(report.blocking)} not dead code)\n")

    # Finding is a plain (unhashable) dataclass, so match by object identity
    # rather than using it directly as a dict key.
    explained = {}
    if triage_result is not None:
        explained = {id(tf.finding): tf.explanation for tf in triage_result.ranked if tf.explanation}
        if not triage_result.llm_used and triage_result.llm_error:
            print(f"(triage LLM call failed, falling back to severity order: {triage_result.llm_error})\n", file=sys.stderr)

    for f in shown:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"[{_SEVERITY_LABEL.get(f.severity, f.severity)}] {f.type} — {loc}")
        print(f"  {f.description}")
        if id(f) in explained:
            print(f"  Why it matters: {explained[id(f)]}")
        print(f"  Fix: {f.remediation}")
        if f.autofix_available and f.severity != "Unreachable":
            print("  (autofix available — rerun with --autofix-diff to see the patch)")
        print()


def _cmd_scan(args: argparse.Namespace) -> int:
    report = asyncio.run(scan_path(args.path, max_files=args.max_files))

    min_rank = SEVERITY_RANK.get(args.min_severity, SEVERITY_RANK["LOW"]) if args.min_severity else -999

    triage_result = None
    if args.explain:
        triage_result = triage(
            report.blocking,
            provider=args.llm_provider,
            api_key=args.llm_api_key,
            model=args.llm_model,
        )

    if args.as_json:
        out = report.to_dict()
        if triage_result is not None:
            out["triage"] = {
                "llm_used": triage_result.llm_used,
                "llm_error": triage_result.llm_error,
                "explanations": {
                    i: tf.explanation for i, tf in enumerate(triage_result.ranked) if tf.explanation
                },
            }
        print(json.dumps(out, indent=2))
    else:
        _print_human(report, min_rank=min_rank, explain=args.explain, triage_result=triage_result)

    if args.autofix_diff:
        # Dead-code findings aren't "what matters" by this tool's own
        # pitch — don't offer fixes for code that's never reached.
        fixable = autofixable(report.blocking)
        if not fixable:
            print("No findings with an available mechanical fix.", file=sys.stderr)
        # Multiple findings commonly point at the same fix (e.g. 5 CVEs all
        # patched by one version bump of the same package) — one diff per
        # distinct (file, package-or-line) target, not one per finding.
        seen = set()
        deduped = []
        for f in fixable:
            dedup_key = (f.file, f.package) if f.category == "DEPENDENCY" else (f.file, f.line)
            if dedup_key not in seen:
                seen.add(dedup_key)
                deduped.append(f)
        for f in deduped:
            try:
                with open(f.file, "r", encoding="utf-8", errors="ignore") as fh:
                    original = fh.read()
            except OSError as e:
                print(f"-- could not read {f.file} to generate a fix diff: {e}", file=sys.stderr)
                continue
            patched = apply_fix(original, f)
            if patched is None:
                continue
            print(generate_diff(original, patched, f.file))

    has_blocking = any(f.rank() >= min_rank for f in report.blocking)
    return 1 if (args.fail_on_findings and has_blocking) else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Security triage & autofix agent.")
    parser.add_argument("--version", action="version", version=f"spidercob-sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", help="File or directory to scan")
    scan_p.add_argument("--json", action="store_true", dest="as_json", help="Output findings as JSON")
    scan_p.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
                         help="Only show findings at or above this severity (default: all, including unreachable)")
    scan_p.add_argument("--explain", action="store_true",
                         help="Rank + explain the top findings with an LLM (needs SENTINEL_LLM_PROVIDER/SENTINEL_LLM_API_KEY, or pass --llm-*)")
    scan_p.add_argument("--llm-provider", choices=["openai", "anthropic", "ollama"], default=None)
    scan_p.add_argument("--llm-api-key", default=None)
    scan_p.add_argument("--llm-model", default=None)
    scan_p.add_argument("--autofix-diff", action="store_true",
                         help="Print a unified diff for every finding with a mechanical fix available — never writes files")
    scan_p.add_argument("--max-files", type=int, default=500, help="Safety cap when scanning a directory (default: 500)")
    scan_p.add_argument("--fail-on-findings", action="store_true",
                         help="Exit 1 if any non-dead-code finding at/above --min-severity was found (for CI)")
    scan_p.set_defaults(func=_cmd_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
