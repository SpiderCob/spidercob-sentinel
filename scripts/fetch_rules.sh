#!/usr/bin/env bash
# Sparse, depth-1, blob-filtered clone of the community Semgrep rules repo —
# keeps it to the handful of languages this tool supports (~9MB) instead of
# the full upstream repo. Same pattern used in the Dockerfile's build stage;
# this script is for local/dev use outside Docker.
set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/semgrep_rules"
LANGS="python javascript typescript java php go"

rm -rf "$DEST"
git clone --depth 1 --filter=blob:none --sparse https://github.com/semgrep/semgrep-rules.git "$DEST"
(cd "$DEST" && git sparse-checkout set $LANGS && rm -rf .git)

echo "Vendored semgrep rules into $DEST ($(find "$DEST" -name '*.yaml' | wc -l | tr -d ' ') rule files)"
