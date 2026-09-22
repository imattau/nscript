#!/usr/bin/env bash
# Builds the NScript compiler for wasm32 and runs the conformance corpus
# through the wasm ABI with Node. Requires the wasm32 target and Node.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

if ! rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
    echo "wasm32-unknown-unknown target not installed; skipping wasm conformance" >&2
    exit 0
fi

cargo build -p nscript-wasm --target wasm32-unknown-unknown --release

if ! command -v node >/dev/null 2>&1; then
    echo "node not found; skipping wasm conformance" >&2
    exit 0
fi

node crates/nscript-wasm/tests/node/conformance.mjs