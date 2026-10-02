"""
Triage — the one genuinely new layer this project adds on top of what's
already free elsewhere (Dependabot, Semgrep OSS, free Snyk tiers all already
scan code). The actual pain for a startup with no security headcount isn't
"what did the scanner find," it's "which of these 40 things do I actually
need to deal with today, and why."

This module only ever produces *prose* — a priority ranking and a one
-paragraph plain-English explanation per finding. It never generates a code
patch; see autofix.py for why that's a deliberate line, not an oversight.

Bring-your-own-key: works with OpenAI, Anthropic, or a local Ollama server.
With no key configured, degrades to a plain severity-sorted list with no
LLM call at all — the rest of this tool must be fully usable offline.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from .models import Finding

DEFAULT_TOP_N = 5

_SYSTEM_PROMPT = (
    "You are a pragmatic security engineer triaging static-analysis findings "
    "for a startup with no dedicated security team. For the findings you are "
    "given, pick the ones that most deserve attention first and explain each "
    "in one short, plain-English paragraph a non-security engineer can act "
    "on — what the risk actually is in practice, not a textbook definition. "
    "Do not suggest a code fix or write any code; that is handled elsewhere. "
    "Respond with ONLY a JSON array, no prose outside it, where each element "
    "is {\"index\": <int, the finding's position in the input list>, "
    "\"explanation\": <string>}."
)


@dataclass
class TriagedFinding:
    finding: Finding
    explanation: Optional[str] = None  # None if no LLM was available


@dataclass
class TriageResult:
    ranked: List[TriagedFinding] = field(default_factory=list)
    llm_used: bool = False
    llm_error: Optional[str] = None


def _build_prompt(findings: List[Finding]) -> str:
    lines = []
    for i, f in enumerate(findings):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{i}] category={f.category} type={f.type} severity={f.severity} location={loc}\n    {f.description}")
    return "\n".join(lines)


def _call_openai(api_key: str, model: str, prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0,
    )
    return resp.choices[0].message.content or "[]"


def _call_anthropic(api_key: str, model: str, prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in resp.content if hasattr(block, "text"))


def _call_ollama(base_url: str, model: str, prompt: str) -> str:
    import urllib.request

    body = json.dumps({
        "model": model,
        "prompt": f"{_SYSTEM_PROMPT}\n\n{prompt}",
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8")).get("response", "[]")


def triage(
    findings: List[Finding],
    *,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    ollama_url: Optional[str] = None,
    top_n: int = DEFAULT_TOP_N,
) -> TriageResult:
    """Rank `findings` and explain the top `top_n`. Reads
    SENTINEL_LLM_PROVIDER / SENTINEL_LLM_API_KEY / SENTINEL_LLM_MODEL /
    SENTINEL_OLLAMA_URL from the environment if the matching argument isn't
    passed explicitly. Falls back to plain severity ranking with no
    `explanation` set if no provider/key is configured, or if the LLM call
    fails for any reason — this must never be the thing that makes the tool
    unusable in CI."""
    provider = provider or os.environ.get("SENTINEL_LLM_PROVIDER")
    api_key = api_key or os.environ.get("SENTINEL_LLM_API_KEY")
    ollama_url = ollama_url or os.environ.get("SENTINEL_OLLAMA_URL")

    ranked_findings = sorted(findings, key=lambda f: f.rank(), reverse=True)[:top_n]

    if not provider or (provider != "ollama" and not api_key):
        return TriageResult(
            ranked=[TriagedFinding(finding=f) for f in ranked_findings],
            llm_used=False,
        )

    prompt = _build_prompt(ranked_findings)
    try:
        if provider == "openai":
            raw = _call_openai(api_key, model or "gpt-4o-mini", prompt)
        elif provider == "anthropic":
            raw = _call_anthropic(api_key, model or "claude-sonnet-5", prompt)
        elif provider == "ollama":
            raw = _call_ollama(ollama_url or "http://localhost:11434", model or "llama3", prompt)
        else:
            return TriageResult(
                ranked=[TriagedFinding(finding=f) for f in ranked_findings],
                llm_used=False,
                llm_error=f"Unknown SENTINEL_LLM_PROVIDER: {provider!r} (expected openai, anthropic, or ollama)",
            )

        start = raw.find("[")
        end = raw.rfind("]")
        parsed = json.loads(raw[start:end + 1]) if start != -1 and end != -1 else []
        explanations = {item["index"]: item["explanation"] for item in parsed if "index" in item}

        return TriageResult(
            ranked=[
                TriagedFinding(finding=f, explanation=explanations.get(i))
                for i, f in enumerate(ranked_findings)
            ],
            llm_used=True,
        )
    except Exception as e:  # noqa: BLE001 - any LLM/network failure degrades, never crashes
        return TriageResult(
            ranked=[TriagedFinding(finding=f) for f in ranked_findings],
            llm_used=False,
            llm_error=str(e),
        )
