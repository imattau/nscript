# NScript Lens napplet

A read-only napplet that applies a checked NScript rule to notes from the
shell's `outbox` domain. The rule decides both **what is read** and **what is
shown**:

- `on Note where tags.p contains me` becomes an outbox `#p` mention query.
- `on Note where tags.t contains "nostr"` becomes a `#t` query.
- A plain `on Note` uses the shell's outbox/following feed.
- `lens.hide(reason)`, `lens.label(name, value)`, `lens.pin(reason)`, and
  `lens.flag(reason)` become local presentation decisions.

The script never receives `window.napplet`, keys, relays, or storage. It can
read Note events, log locally, and call the four `lens` operations. Publishing,
signing, storage, schedules, inputs, keys, and third-party module operations are
rejected before activation.

## Presets

| Preset | Scope | What it demonstrates |
| --- | --- | --- |
| Quiet mentions | `#p` mention filter | Hide promotion and link-only replies, label topics, flag off-platform pushes, pin priority people. |
| Following lens | shell outbox feed | Hide promotion and tag spam, label topics, pin priority people. |
| Nostr topic | `#t` tag filter | A narrow query with a local label and hide rule. |
| Blank mentions | `#p` mention filter | A minimal starting point. |

Replace the placeholder `<your-priority-pubkey>` with a hex pubkey to try pinning.

## Develop and build

```sh
npm install
npm run test       # decision-reduction tests
npm run dev        # Vite dev server
npm run build      # builds the browser WASM and single-file artifact
npm run verify     # tests, requirements, build, and napplet conformance
```

`npm run build` builds `nscript-wasm` with the size-oriented `wasm-release`
profile, derives `nscript-napplet.json` from `filter.ns`, and emits
`dist/index.html` plus the NIP-5D manifest sidecar.

The default `filter.ns` is the mentions rule used by the build-time
requirements check. The app boots the same preset from `presets/mentions.ns`.
Both declare `outbox` as required and `identity`/`storage` as optional.

## Run it in a shell

Open the Vite URL inside a compatible napplet shell (Kehto/Paja) with the
`outbox` domain enabled. Mentions presets also need `identity` and a connected
signer. `storage` is optional; without it the rule lasts for the session.

If the shell omits `outbox`, the app shows an explicit unavailable state and
does not fall back to `fetch`, WebSockets, or direct storage.

## Review model

Before activation the app shows:

- the checked capability footprint;
- the exact outbox filters derived from the handlers;
- required and optional shell domains;
- diagnostics with line numbers.

A rule that needs `me` without a connected signer stays checked but cannot be
activated. An event that fails during evaluation is shown with a `rule error`
badge rather than being silently hidden.
