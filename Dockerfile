# ─── Semgrep rules stage ──────────────────────────────────────────────────
# Sparse, depth-1, blob-filtered clone — same pattern as scripts/fetch_rules.sh,
# just baked into the image instead of run by hand. Keeps it to the handful
# of languages this tool supports (~9MB) instead of the full upstream repo,
# and a separate stage means git never ships in the runtime image.
FROM alpine/git:latest AS semgrep-rules
WORKDIR /rules
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/semgrep/semgrep-rules.git . && \
    git sparse-checkout set python javascript typescript java php go && \
    rm -rf .git

# ─── Runtime ───────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[github-app]"

COPY --from=semgrep-rules /rules /app/semgrep_rules
ENV SEMGREP_RULES_DIR=/app/semgrep_rules

EXPOSE 8000
CMD ["sentinel-github-app"]
