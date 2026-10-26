#!/usr/bin/env bash
# Checks this project end to end, in simulation: nothing here touches a
# network or a key. Set NSCRIPT to use a binary that is not on your PATH.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
nscript=${NSCRIPT:-nscript}

"$nscript" check bot.ns
"$nscript" package verify bot.ns --lock nscript.lock.json

# Each events/<name>.expect holds a line the output must contain. If
# events/<name>.json exists it is delivered to the bot as the event; if not,
# the bot is run with no event (a schedule runs at startup).
status=0
for expect in events/*.expect; do
    name=${expect%.expect}
    if [[ -f "$name.json" ]]; then
        output=$("$nscript" run bot.ns --event "$(cat "$name.json")")
    else
        output=$("$nscript" run bot.ns)
    fi
    if grep -qF -- "$(cat "$expect")" <<<"$output"; then
        echo "ok   $name"
    else
        echo "FAIL $name: expected output to contain: $(cat "$expect")"
        status=1
    fi
done
exit $status
