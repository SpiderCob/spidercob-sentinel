# spidercob-sentinel

Open-source security triage & autofix agent for startups.

Free scanners (Dependabot, Semgrep OSS, free Snyk tiers) already tell you
*what's wrong*. The actual problem for a team with no dedicated security
headcount is **noise**: forty findings a week, no idea which three matter,
and nobody with time to write the fix PR.

```bash
pip install spidercob-sentinel
sentinel scan .
```

```
3 finding(s) (12 total, 9 not dead code)

[HIGH] SQL Injection — app/views.py:42
  User-controlled data from a request is passed to 'execute()'.
  Fix: Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Never interpolate user input into SQL strings.

[CRITICAL] aws_access_key — config/settings.py:8
  AWS Access Key ID
  Fix: Rotate key immediately via AWS IAM console. Store in AWS Secrets Manager or as environment variables — never in source code.
  (autofix available — rerun with --autofix-diff to see the patch)

[HIGH] CVE-2024-XXXXX — requirements.txt
  requests 2.25.0: known vulnerability
  Fix: Upgrade requests to 2.31.0.
  (autofix available — rerun with --autofix-diff to see the patch)
```

## What it does

Three scanners, one unified output:

- **Secrets & PII** — via [`dlp-patterns`](https://github.com/SpiderCob/dlp-patterns), zero-dependency regex engine.
- **Real vulnerabilities** — Semgrep-backed AST/dataflow static analysis
  (SQLi, SSRF, command injection, path traversal, ...), plus a Python-AST
  reachability pass so dead code doesn't get reported at the same severity
  as something actually reachable from a route handler.
- **Known CVEs in your dependencies** — via [`dep-scanner`](https://github.com/SpiderCob/dep-scanner) (`osv-scan`), the free OSV.dev API.

Then the part that's actually new: **triage**. Point it at an LLM key you
already have (OpenAI, Anthropic, or a local Ollama) and it ranks the pile of
findings down to the handful that matter, with a plain-English paragraph on
each — not a textbook CWE definition, an answer to "do I need to care about
this today." No key configured? It still works, just severity-sorted with
no prose — nothing here requires an API key or sends your code anywhere.

## Autofix — deliberately narrow

Two sources only, both deterministic, **never LLM-generated**:

1. A Semgrep rule's own vetted `fix:` snippet, if the rule that matched ships one.
2. A dependency version bump to a known-patched release.

A security tool that writes its own security patches via a
hallucination-prone LLM is a credibility risk the moment it's wrong once.
The LLM here only ever writes prose (the triage explanation) — never a diff.
`sentinel scan . --autofix-diff` prints a unified diff for everything it can
fix; it never edits files in place or opens anything on its own in v1.

## What this honestly doesn't do

- **No interprocedural/cross-file taint tracking.** A source and sink split
  across two functions or files won't be connected — that's Semgrep Pro,
  a paid product. This tool doesn't pretend otherwise.
- **No IDOR or race-condition detection.** Both are about a *missing* check,
  not a bad pattern present in the text — outside what static analysis can
  prove at all.
- **Autofix coverage is real but modest** — only the subset of vendored
  Semgrep rules that ship a `fix:`, plus `requirements.txt`-style dependency
  bumps (other manifest formats are detected and explained, not yet
  auto-patched).
- **Directory scans are slow today.** Each file gets its own `semgrep`
  subprocess invocation, and loading the vendored rule set costs ~9s *per
  invocation* on its own (measured against the Python rule set alone) —
  scanning N files costs roughly N × 9s, not a one-time fixed cost. Fine for
  `sentinel scan path/to/one_file.py` in a pre-commit hook; a full-repo or
  whole-PR scan with many changed files will visibly add up. Batching all
  files of one language into a single `semgrep` invocation (it natively
  accepts multiple paths) would amortize that cost instead of paying it per
  file — tracked as a roadmap item, not yet done.

## Install

```bash
pip install spidercob-sentinel
```

Needs the `semgrep` CLI and a one-time rule fetch:

```bash
./scripts/fetch_rules.sh   # sparse-clones github.com/semgrep/semgrep-rules into ./semgrep_rules
```

## CLI

```bash
sentinel scan <path>                 # file or directory
sentinel scan . --json
sentinel scan . --min-severity HIGH
sentinel scan . --explain            # needs SENTINEL_LLM_PROVIDER / SENTINEL_LLM_API_KEY
sentinel scan . --autofix-diff       # print diffs, never writes files
sentinel scan . --fail-on-findings   # exit 1 if anything at/above --min-severity (for CI)
```

Environment variables for `--explain` (or pass `--llm-provider`/`--llm-api-key` directly):

| Variable | Values |
|---|---|
| `SENTINEL_LLM_PROVIDER` | `openai` \| `anthropic` \| `ollama` |
| `SENTINEL_LLM_API_KEY` | your key (not needed for `ollama`) |
| `SENTINEL_LLM_MODEL` | optional, defaults to a sensible per-provider model |
| `SENTINEL_OLLAMA_URL` | optional, defaults to `http://localhost:11434` |

## Library

```python
import asyncio
from spidercob_sentinel import scan_path

report = asyncio.run(scan_path("./my-project"))
print(report.total, "findings,", len(report.blocking), "worth a look")
for f in report.sorted_by_severity():
    print(f.severity, f.type, f.file, f.line, "-", f.remediation)
```

## Roadmap

- [x] Semgrep + reachability + secrets + dependency-CVE scanning, unified
- [x] CLI with JSON output, CI exit codes
- [x] LLM triage layer (bring your own key)
- [x] Deterministic autofix diffs (Semgrep `fix:` + dependency bumps)
- [ ] GitHub App: runs on every PR, posts a Check Run + review comments,
      opens autofix PRs for mechanical fixes
- [ ] Docker image / `docker compose up` self-hosting
- [ ] Slack Q&A ("are we exposed to CVE-XXXX?")
- [ ] Broader autofix coverage (more manifest formats)
- [ ] Batch Semgrep invocations per language instead of one process per file

Not planned: cloud/infra config scanning, cross-file taint tracking,
LLM-generated code patches.

## License

Apache-2.0
