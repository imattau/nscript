#!/usr/bin/env bash
# Builds the nscript .npk archive and its standalone manifest for npack.
#
# Usage: packaging/build-npk.sh VERSION PUBLISHER NSCRIPT_BIN NPACK_BIN OUT_DIR
#   VERSION      release version without a leading "v", e.g. 0.1.0
#   PUBLISHER    the Nostr publisher key (npub or hex) that will sign the release
#   NSCRIPT_BIN  the built `nscript` binary
#   NPACK_BIN    the `npack` binary used to pack and describe the archive
#   OUT_DIR      where the .npk, manifest and SHA256SUMS are written
#
# Needs jq.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  sed -n '2,11p' "$0" >&2
  exit 2
fi
VERSION=$1
PUBLISHER=$2
NSCRIPT=$(realpath "$3")
NPACK=$(realpath "$4")
mkdir -p "$5"
OUT=$(cd "$5" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)

[[ -x "$NSCRIPT" ]] || { echo "missing $NSCRIPT" >&2; exit 1; }
[[ -x "$NPACK" ]] || { echo "missing $NPACK" >&2; exit 1; }
command -v jq > /dev/null || { echo "jq is required" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

ARTIFACT="nscript-${VERSION}-linux-x86_64.npk"
root=$WORK/root
mkdir -p "$root/bin" "$root/share/doc/nscript" "$root/.npack"
install -m 0755 "$NSCRIPT" "$root/bin/nscript"
install -m 0644 "$ROOT/README.md" "$ROOT/LICENSE" "$root/share/doc/nscript/"

needed=$("$NPACK" inspect "$NSCRIPT" \
  | awk '/^needed: / { sub(/^needed: /, ""); if ($0 != "none") print }' \
  | jq -R -s 'split("\n") | map(select(length > 0))')

jq -n \
  --arg publisher "$PUBLISHER" --arg version "$VERSION" --arg artifact "$ARTIFACT" \
  --argjson runtime_requires "$needed" \
  '{publisher:$publisher,name:"nscript",version:$version,artifact:$artifact,sha256:"",
    dependencies:[],conflicts:[],os:"linux",arch:"x86_64",format:"npk",
    runtime_requires:$runtime_requires,provides:[]}' > "$root/.npack/manifest.json"

"$NPACK" pack "$root" --output "$OUT/$ARTIFACT" --strict > /dev/null
"$NPACK" manifest "$OUT/$ARTIFACT" --output "$OUT/nscript-${VERSION}.manifest.json" > /dev/null
(cd "$OUT" && sha256sum "$ARTIFACT" > SHA256SUMS)
echo "Built $OUT/$ARTIFACT"
