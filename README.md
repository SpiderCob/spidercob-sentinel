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

## GitHub App: runs on every PR

The webhook server (`sentinel-github-app`) runs the full scan + triage
pipeline on every `pull_request` event, posts a Check Run and inline review
comments, and opens an autofix PR into the PR's own branch for anything with
a mechanical fix. There's no Spidercob-run instance of this to install from
a marketplace — you register your own GitHub App, same as any other
self-hosted integration.

### Deploy it somewhere reachable

```bash
cp .env.example .env     # fill in after the next step
docker compose up --build -d
```

It needs a public URL GitHub can reach for the webhook (your own domain,
a reverse-proxied box, an ngrok tunnel for testing — anything that resolves
to `http://localhost:8000` from the outside).

### Register your own GitHub App (manifest flow — no form-filling)

GitHub's [app manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
lets you create a fully-configured app with one click instead of filling in
a dozen fields by hand. Save this as `register.html`, replace
`YOUR_DOMAIN_HERE`, open it in a browser while logged into GitHub, and click
through:

```html
<!doctype html>
<form id="f" action="https://github.com/settings/apps/new" method="post">
  <input type="hidden" name="manifest" id="manifest">
</form>
<script>
  const manifest = {
    name: "My Spidercob Sentinel",
    url: "https://YOUR_DOMAIN_HERE",
    hook_attributes: { url: "https://YOUR_DOMAIN_HERE/github/webhooks" },
    redirect_url: "https://YOUR_DOMAIN_HERE/",
    public: false,
    default_events: ["pull_request"],
    default_permissions: {
      contents: "read", pull_requests: "write", checks: "write", metadata: "read",
    },
  };
  document.getElementById('manifest').value = JSON.stringify(manifest);
  document.getElementById('f').submit();
</script>
```

After you click "Create GitHub App" on GitHub's confirmation screen, it
redirects to `redirect_url` with `?code=...` in the address bar. Exchange
that code once (it's single-use) for your real credentials:

```bash
curl -s -X POST https://api.github.com/app-manifests/THE_CODE_FROM_THE_URL/conversions \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('GITHUB_APP_ID='+str(d['id'])); print('GITHUB_WEBHOOK_SECRET='+d['webhook_secret']); print('GITHUB_PRIVATE_KEY<<<'); print(d['pem'])"
```

Put `id` → `GITHUB_APP_ID`, `webhook_secret` → `GITHUB_WEBHOOK_SECRET`, and
`pem` → `GITHUB_PRIVATE_KEY` (with `\n` for newlines, or your platform's
multi-line env var syntax) into `.env`, then restart the container and
install the app on whichever repos you want it watching (Settings → your
app → Install App).

## Roadmap

- [x] Semgrep + reachability + secrets + dependency-CVE scanning, unified
- [x] CLI with JSON output, CI exit codes
- [x] LLM triage layer (bring your own key)
- [x] Deterministic autofix diffs (Semgrep `fix:` + dependency bumps)
- [x] GitHub App: runs on every PR, posts a Check Run + review comments,
      opens autofix PRs for mechanical fixes
- [x] Docker image / `docker compose up` self-hosting
- [ ] Slack Q&A ("are we exposed to CVE-XXXX?")
- [ ] Broader autofix coverage (more manifest formats)
- [ ] Batch Semgrep invocations per language instead of one process per file

Not planned: cloud/infra config scanning, cross-file taint tracking,
LLM-generated code patches.

## License

Apache-2.0
