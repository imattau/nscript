# Product roadmap

This roadmap describes the work after the initial Draft 0.1 implementation. It
is intentionally narrower than `PLAN.md`, which preserves the design and
implementation history. Draft 0.1 is feature-frozen for new NIP breadth while
these priorities are underway.

## Direction

Use a Concord moderation bot as the proving ground for NScript's main promise:
an author can inspect a script's authority, test its decisions, and run it
against real Nostr infrastructure without giving the script ambient key or
network access.

The bot is a strong vertical slice because the repository already has typed
stream handling, CORD-04 authority checks, real cryptographic hosts, simulated
event previews, and end-to-end Rust tests. The remaining work is to join those
pieces into a supported operator workflow and verify interoperability outside
this implementation.

## Phase 1: make the Concord bot operable

**Current state:** the source example and conformance fixture now capture the
stream-based bot, and `docs/CONCORD-BOT.md` separates safe simulation from the
real-host test coverage. `nscript inspect` now reports the resolved module
versions, canonical descriptor hashes, and origins for preflight review. The
moderation host can merge a newly verified same-community authority fold
before handling more events. The controlled live runner and independent-client
verification are still open.

- Provide a documented, reproducible path from a checked NScript source file to
  a running bot with an explicitly provisioned identity, community, channel,
  and relay set.
- Connect the real Concord stream reader and moderation host to a controlled
  deployment entry point. Do not silently treat the generic `deploy` command's
  simulated module operations as real moderation.
- Refresh the verified Control Plane fold before dispatching new messages, so
  grant revocations and role changes reach the moderation gate promptly.
- Make startup inspection show the resolved module versions, event source,
  requested and granted capabilities, identity, and community scope before the
  event loop begins.
- Exercise the workflow against a disposable community and confirm the
  resulting stream and moderation state with an independent Concord client.

**Exit criteria:** a maintainer can follow one checked-in guide to run the bot
in simulation, inspect the exact authority it requests, run it against a
disposable community, and independently verify the observed event and action.
The guide must clearly distinguish simulated and live effects.

## Phase 2: make release claims executable

- Reconcile every row in `conformance/MATRIX.md` with an executable fixture,
  deterministic runtime scenario, or explicitly documented external test.
- Make the scenario runner and CI report identify uncovered release-blocker
  cells; avoid relying on prose that says a vector exists when only a test name
  or manual procedure exists.
- Freeze the Draft 0.1 grammar, module descriptor behavior, diagnostic codes,
  and IR compatibility contract for a release candidate.
- Publish one support statement that separates tested protocol behavior,
  external interoperability evidence, and known limitations.

**Exit criteria:** every release-blocker cell has a named automated or
reproducible manual check, CI runs all automated checks, and no doc describes a
planned feature as implemented.

## Phase 3: complete the authoring-to-running loop

- Add the missing lowering/protocol inspector to Studio so users can see how
  source intent maps to Nostr events, tags, filters, and capability calls.
- Connect the Studio preview and CLI inspection to the same manifest format,
  then document package creation and lockfile verification as one workflow.
- Decide whether browser-extension hosting belongs in this project or in a
  separate host adapter before implementing it.

**Exit criteria:** a user can edit, inspect permissions and protocol lowering,
simulate events, create reproducible package metadata, and hand the result to a
documented runtime host without relying on undocumented Rust APIs.

## Phase 4: community conventions (NCC)

Incorporate Nostr Community Conventions from
[`imattau/nostr-community-conventions`](https://github.com/imattau/nostr-community-conventions)
(pinned in [`NCC-PLAN.md`](NCC-PLAN.md)) as ordinary typed modules, each one
shipped with the workflow and conformance coverage this roadmap requires of
protocol breadth.

- Land NCC-07 (capability manifest) first as the smallest end-to-end slice,
  then NCC-00 (document lifecycle), then the service cluster NCC-02, NCC-05,
  NCC-06, then NCC-08 (identity handover), then the post-pin additions
  NCC-09 (scoped operator authority), NCC-10 (operational state) and NCC-11
  (portable trust policy) with the three-column tag support they need, then
  NCC-13 (software package release profile), a further post-pin addition
  that profiles NIP-51/94/34 rather than owning new kinds; NCC-03 landed
  last, scoped to its normative core (§4-7).
- Build the real record-fields-to-wire-tags lowering path for declared events,
  so `publish <record>` statements emit correct kinds and tags on real relays.
  Module operation calls remain simulated until a host is wired in.
- Every landed NCC ships a module, valid and invalid fixtures, a wire vector,
  a matrix row, a `spec/nostr.md` subsection, and either a documented
  infrastructure adoption (capability publication, service records, identity-
  first resolution, identity rotation, operator authority, operational state,
  trust policy) or an explicit non-adoption note.

**Exit criteria:** each landed NCC meets the recipe above, the pinned NCC
commit is recorded, and no doc describes a convention as implemented while its
publication path is still simulated.

## Phase 5: adoption (scaffold, then editor support)

**Status:** implemented. This phase added no NIP breadth and no Layer 3
keywords, so it did not conflict with the Draft 0.1 feature freeze. The two
parts were ordered: the scaffold came first because its templates became the
test material for the language server.

### 5a: `nscript new` scaffold and starter templates

`nscript new <template> <directory>` writes a checked, runnable project:
`bot.ns`, a `README.md`, sample events with expected output, a `test.sh`, and a
lockfile. `nscript new --list` names the templates. Templates live in
[`templates/`](templates/) and are embedded in the binary.

- **Templates:** `moderation-bot`, `scheduled-poster`, `relay-monitor`.
- **Each template** declares the narrowest permissions that work with a comment
  naming why each is needed, runs to a meaningful result in simulation, and
  states in its README which effects are simulated and which are live. A CI
  test scaffolds every template, runs its generated `test.sh` (check, lockfile
  verification, every sample event), and requires `inspect --json` to succeed.
- **`moderation-bot` is simulation-only.** `nscript deploy` does not yet
  connect a real Concord moderation host (Phase 1), and the template and its
  README say so.
- **`relay-monitor` reads NCC-10 operational-state events** that services
  publish about themselves. NIP-66 declares a record and a publish operation
  but no event a script can read, and inventing one would be new protocol
  surface, so the template does not read NIP-66 relay status. It publishes
  nothing, probes nothing, and reports operator-published states as
  unverified.

**Exit criteria met:** a new user can run `nscript new`, then `check`, `inspect`
and `test-event` on the result without reading any Rust source, and every
template is covered by a CI-run fixture.

### 5b: language server and editor integration

`nscript-lsp` is an LSP server over `nscript-lang` and the same checker the CLI
uses: diagnostics, completions, hover, outline, and an authority summary shown
as a lens while editing. [`editors/vscode/`](editors/vscode/) is a thin VS Code
client. [`docs/EDITORS.md`](docs/EDITORS.md) covers setup, limits and what has
been verified.

- **One front end.** The server has no parser of its own. A test runs
  `nscript check` and the server over every source in `conformance/`,
  `examples/` and `templates/` and requires identical diagnostics (code,
  message and position); a deliberate divergence makes it fail.
- **Tested** without an editor: protocol behaviour, a real stdio session
  against the built binary, UTF-16 positions, grammar coverage of the
  language's keywords, and the extension's logic with the editor stubbed.
- **Not yet verified:** the extension running in a real VS Code, and the
  documented Neovim configuration in a real Neovim. Zed and similar editors
  need their own extension, which is not provided.
- **Limits:** built-in modules only (`-M` directories are not loaded), no
  go-to-definition, rename, references or formatting, single-file analysis.

**Exit criteria met, with the caveat above:** diagnostics, completions and hover
in the templates agree with the CLI and are exercised by automated tests. That
they appear correctly in a real editor is unconfirmed.

### Sequencing and dependencies

- Live-effect templates stay simulation-only until the Phase 1 live runner
  exists.
- Neither part depended on the Phase 2 grammar freeze, but both will need
  revisiting if the grammar or diagnostic codes change after it.

## Explicitly deferred

- Adding more NIP descriptors or Layer 3 keywords without a concrete workflow
  and conformance need.
- A general-purpose production host for all module operations. Real operation
  hosts should be added by workflow and capability, with their live behavior
  made visible to users.
- Live moderation against a community with real members. Interoperability work
  should use a disposable community and identities whose owners have agreed to
  the test.
- A production Concord broker or SFU service; the protocol library does not
  imply that service is part of the NScript runtime.

## Current constraints

- `nscript deploy` supports real relay connections and NIP-46 signer sessions,
  but module operation calls remain simulated unless a real host is connected.
- Concord's real host behavior is exercised through Rust integration tests and
  interop examples, not through a configured `nscript deploy` workflow.
- Some Concord scoped-grant syntax currently checks the declared scope but
  does not yet bind host authority to that scope. Treat it as a language check,
  not as a runtime isolation boundary.
- The checked-in examples and docs cover more features than the release
  conformance matrix currently proves. Matrix coverage must be audited before
  calling Draft 0.1 a release candidate.
