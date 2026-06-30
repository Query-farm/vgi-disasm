#!/usr/bin/env bash
# Build the vgi-disasm VGI worker and run the SQLLogic tests against it using the
# haybarn DuckDB distribution's unittest runner (which ships the `vgi` extension
# via the community repository).
#
# Prerequisites (one-time):
#   uv tool install haybarn-unittest      # the DuckDB unittest binary
#   echo "INSTALL vgi FROM community;" | uvx haybarn-cli   # install the vgi ext
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

UNITTEST="${VGI_UNITTEST:-$(command -v haybarn-unittest || true)}"
if [[ -z "$UNITTEST" || ! -x "$UNITTEST" ]]; then
    echo "ERROR: haybarn-unittest not found. Install it with:" >&2
    echo "       uv tool install haybarn-unittest" >&2
    exit 1
fi

echo "==> Building disasm-worker (release)"
cargo build --release --bin disasm-worker

WORKER="$REPO_ROOT/target/release/disasm-worker"
export HAYBARN_UNITTEST="$UNITTEST"
export WORKER_BIN="$WORKER"
export TRANSPORT="${TRANSPORT:-subprocess}"

echo "==> Running SQLLogic tests (transport: $TRANSPORT)"
exec "$REPO_ROOT/ci/run-integration.sh"
