"""
spidercob-sentinel — open-source security triage & autofix agent for startups.

Quick start::

    import asyncio
    from spidercob_sentinel import scan_path

    report = asyncio.run(scan_path("./my-project"))
    print(report.total, "findings;", len(report.blocking), "worth a look")
    for f in report.sorted_by_severity():
        print(f.severity, f.type, f.file, f.line, "-", f.remediation)

Full docs: https://github.com/SpiderCob/spidercob-sentinel
"""
from .autofix import apply_dependency_fix, apply_fix, apply_semgrep_fix, autofixable, generate_diff
from .deps import scan_manifest
from .models import Finding, ScanReport
from .scan import scan_file, scan_path
from .scanner import scan_code_file
from .secrets import scan_secrets
from .triage import TriagedFinding, TriageResult, triage

__version__ = "0.1.0"
__all__ = [
    "Finding",
    "ScanReport",
    "scan_path",
    "scan_file",
    "scan_code_file",
    "scan_secrets",
    "scan_manifest",
    "triage",
    "TriageResult",
    "TriagedFinding",
    "apply_fix",
    "apply_semgrep_fix",
    "apply_dependency_fix",
    "autofixable",
    "generate_diff",
    "__version__",
]
