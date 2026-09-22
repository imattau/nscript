# NScript Studio

A browser authoring surface for NScript. The compiler runs entirely in the
browser: the front end is compiled to `wasm32-unknown-unknown` and driven
through a small JSON ABI (`crates/nscript-wasm`). No server is involved.

```text
studio/                     Vite + Monaco editor
    │  (fetch ./nscript_wasm.wasm)
crates/nscript-wasm         JSON-in/JSON-out wasm ABI
    │
crates/nscript-lang         editor analysis: symbols, completions, hover
crates/nscript-syntax …     parser / checker / IR / fake-host runtime
```

## What works

- Monaco editor with NScript highlighting, inline diagnostics, and the
  permission footprint panel rendered live as you type (a `zap …` call flips
  Payments to `⚠` immediately).
- Completions (`use nip…`, `nip17.`, `event.` on a typed handler) and hover
  cards, both computed from the module graph by `nscript-lang`.
- A "Test Event" preview that injects a synthetic event through
  `Runtime::simulate_event` (the evaluator), showing matched handlers, log
  records, simulated module calls, storage, and handler failures.
- The New Script template gallery (each template checks clean).

## Run

```bash
# build the compiler for wasm once (also done by `npm run wasm`)
cargo build -p nscript-wasm --target wasm32-unknown-unknown --release

cd studio
npm install
npm run dev
```

`npm test` runs the node harness (`tests/core.test.mjs`), which drives the real
wasm artifact through the same glue the editor uses and checks the panel logic.

## What's not here yet

Publishing/installing through npack/Nostr, the lowering/protocol inspector, the
browser-extension host, and AI-assisted authoring. The wasm `compile` and `ir`
ops already exist for the build panel.