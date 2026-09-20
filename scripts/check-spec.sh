#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

status=0

if git grep -nI -E '[[:blank:]]+$' -- '*.md' '*.ns' '*.json' '*.ebnf'; then
    echo "error: trailing whitespace found" >&2
    status=1
fi

while IFS= read -r -d '' fixture; do
    first_line=$(sed -n '1p' "$fixture")
    if [[ ! $first_line =~ ^//\ error:\ E[0-9]{4}\ [a-z0-9-]+$ ]]; then
        echo "error: $fixture has no normalized error header" >&2
        status=1
    fi
done < <(find conformance/invalid -type f -name '*.ns' -print0 | sort -z)

while IFS= read -r -d '' fixture; do
    first_line=$(sed -n '1p' "$fixture")
    if [[ ! $first_line =~ ^//\ error:\ E[0-9]{4}\ [a-z0-9-]+$ ]]; then
        echo "error: $fixture has no normalized error header" >&2
        status=1
    fi
done < <(find conformance/modules/invalid -type f -name '*.nsm' -print0 | sort -z)

while IFS= read -r -d '' vector; do
    if ! jq empty "$vector"; then
        echo "error: malformed JSON vector: $vector" >&2
        status=1
    fi
done < <(find conformance/vectors -type f -name '*.json' -print0 | sort -z)

while IFS= read -r path; do
    if [[ ! -e $path ]]; then
        echo "error: README links to missing local path: $path" >&2
        status=1
    fi
done < <(sed -nE 's/.*\]\(([^)#]+)(#[^)]+)?\).*/\1/p' README.md | grep -vE '^(https?|mailto):' || true)

if (( status != 0 )); then
    exit "$status"
fi

echo "specification checks passed"
