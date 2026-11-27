# `@nscript/napplet`

Embeddable checked NScript "lens" runtime for napplets. The first adapter
profile supports read-only `Note` handlers through the shell's `outbox`
domain, optional `identity` for `me`-scoped rules, and optional `storage` in
the enclosing applet.

```js
import { createNScriptNapplet } from "@nscript/napplet";

const nscript = createNScriptNapplet({
  napplet: window.napplet,
  compiler, // `loadWasmBytes(...)` from the NScript browser ABI
  capabilityCeiling: ["outbox", "identity", "storage"],
});

const review = nscript.check(source, { principal });
if (!review.checked) showDiagnostics(review.diagnostics);
showScope(review.scope);
showFilters(review.subscriptions);

const lens = await nscript.start(source, {
  principal,
  onDecision({ event, decisions, logs, failures }) {
    // decisions: hide / label / pin / flag
  },
  onError(error) {
    showError(error.message);
  },
});

// On replacement or applet shutdown:
lens.stop();
```

`check` returns diagnostics, the capability footprint, required/optional NAP
domains, a `principal_required` flag, the derived outbox filters, and a
human-readable scope (`mentions`, `following`, `custom`, or `principal`).
`start` opens a cached WASM session (when the compiler supports it), checks the
program and capability ceiling again, fails if a required shell domain is
absent, opens the derived outbox query/subscription, and returns a `stop()`
handle. It deduplicates and bounds pending events, event size, and execution
rate.

The script never receives the NAP namespace. The adapter never exposes
publishing, signing, storage, schedules, scalar inputs, keys, or module
operations other than the `lens` presentation module. The shell remains
authoritative for grants.

A lens may declare identity-backed lists:

```nostr
input follows: List<PubKey> from identity.follows
input mutes: List<PubKey> from identity.mutes
```

`start` resolves those through the shell's `identity` domain
(`getFollows`, `getMutes`, `getBlocked`) before opening the session, and the
review marks `identity` as required. Use the exported `resolveInputs(review,
identity)` helper to resolve the same lists yourself, or pass pre-resolved
`inputs` to `start`. Missing data is an activation error, not an empty list.

A lens may read wall time with `now` if its source grants `clock`. The adapter
supplies `Math.floor(Date.now() / 1000)` for each evaluation by default; pass a
`now` function to `createNScriptNapplet` to use another clock.

`start` reports every matching event through `onDecision`, including an empty
`decisions` array for notes that should stay visible. Evaluation failures are
reported in `failures`; callers should keep the note visible and show the
error rather than hiding it.

This package is a prototype. New NAP domains must not be advertised until their
operation mappings and runtime implementations are added.

Run its unit tests with `npm test`.
